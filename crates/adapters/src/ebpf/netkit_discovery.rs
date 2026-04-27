//! Kubernetes pod netkit interface discovery and hot-plug.
//!
//! Discovers netkit interfaces via `/sys/class/net/` polling and
//! pod network namespaces via `/proc/*/ns/net` scanning. When a new
//! netkit device appears, the callback is invoked with the new device
//! name and any pod namespaces that appeared in the same poll cycle,
//! so the agent can attach BPF programs and correlate them with pods.
//!
//! This module is Kubernetes-aware but runtime-agnostic: it works
//! with any CNI that creates netkit devices (Cilium 1.16+).

use std::collections::HashSet;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use tracing::{debug, info};

/// Context about a pod network namespace discovered during a
/// watcher poll cycle. Used to correlate new netkit devices with
/// the pods they belong to.
#[derive(Debug, Clone)]
pub struct PodContext {
    /// PID of a process in the pod's network namespace.
    pub pid: u32,
    /// Inode of the pod's network namespace (`/proc/{pid}/ns/net`).
    pub ns_inode: u64,
}

/// Snapshot of all current netkit interfaces on the host.
pub fn discover_netkit_interfaces() -> Vec<String> {
    super::netkit::list_netkit_devices()
}

/// Discover pod network namespaces by scanning `/proc/*/ns/net`.
/// Returns a list of `(pid, ns_inode)` pairs, deduplicated by inode
/// (pods sharing a network namespace only appear once).
///
/// This is a best-effort scan — processes may exit between listing
/// and reading. Errors are silently skipped.
pub fn discover_pod_network_namespaces() -> Vec<(u32, u64)> {
    let proc_dir = Path::new("/proc");
    let Ok(entries) = std::fs::read_dir(proc_dir) else {
        return Vec::new();
    };

    let mut result = Vec::new();
    let mut seen_inodes = HashSet::new();

    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        let Ok(pid) = name_str.parse::<u32>() else {
            continue;
        };

        let ns_path = format!("/proc/{pid}/ns/net");
        let Ok(metadata) = std::fs::symlink_metadata(&ns_path) else {
            continue;
        };

        let inode = metadata.ino();
        if seen_inodes.insert(inode) {
            result.push((pid, inode));
        }
    }

    result
}

/// Read the peer ifindex of a network device from sysfs.
/// For netkit/veth devices, `iflink` points to the peer interface
/// inside the pod's network namespace.
pub fn iface_peer_ifindex(iface: &str) -> Option<u32> {
    let path = format!("/sys/class/net/{iface}/iflink");
    let content = std::fs::read_to_string(&path).ok()?;
    content.trim().parse::<u32>().ok()
}

/// Callback signature for new netkit device events.
/// Receives the interface name and any pod namespaces that appeared
/// in the same poll cycle (useful for correlation).
pub type OnNetkitDevice = Box<dyn Fn(&str, &[PodContext]) + Send + Sync>;

/// Long-running poller that watches for new netkit devices by
/// scanning `/sys/class/net/` periodically. Simultaneously tracks
/// pod network namespaces via `/proc/*/ns/net` to correlate new
/// devices with their owning pods.
///
/// When a new netkit interface appears, calls
/// `on_new_device(iface_name, new_pod_contexts)` where
/// `new_pod_contexts` contains any pod namespaces that appeared
/// since the last tick.
///
/// Uses polling instead of rtnetlink `NEWLINK` for simplicity and
/// portability. The poll interval (default 5s) is acceptable for
/// pod lifecycle events.
pub async fn watch_netkit_devices(
    on_new_device: OnNetkitDevice,
    poll_interval: Duration,
    cancel: CancellationToken,
) {
    let mut known_ifaces: HashSet<String> = discover_netkit_interfaces().into_iter().collect();
    let mut known_ns_inodes: HashSet<u64> = discover_pod_network_namespaces()
        .into_iter()
        .map(|(_, ino)| ino)
        .collect();
    info!(
        initial_ifaces = known_ifaces.len(),
        initial_namespaces = known_ns_inodes.len(),
        "netkit device watcher started"
    );

    let mut ticker = tokio::time::interval(poll_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            () = cancel.cancelled() => {
                debug!("netkit device watcher cancelled");
                break;
            }
            _ = ticker.tick() => {
                let current_ifaces: HashSet<String> =
                    discover_netkit_interfaces().into_iter().collect();

                // Scan pod namespaces for correlation.
                let current_nss = discover_pod_network_namespaces();
                let new_pods: Vec<PodContext> = current_nss
                    .iter()
                    .filter(|(_, ino)| !known_ns_inodes.contains(ino))
                    .map(|(pid, ino)| PodContext {
                        pid: *pid,
                        ns_inode: *ino,
                    })
                    .collect();

                if !new_pods.is_empty() {
                    debug!(
                        count = new_pods.len(),
                        "new pod network namespaces detected"
                    );
                }

                // New netkit devices — attach + correlate with pods.
                for iface in current_ifaces.difference(&known_ifaces) {
                    let peer = iface_peer_ifindex(iface);
                    info!(
                        iface,
                        peer_ifindex = peer,
                        new_pod_ns_count = new_pods.len(),
                        "new netkit device detected"
                    );
                    on_new_device(iface, &new_pods);
                }

                // Removed devices (log only — link fd drop handles detach).
                for iface in known_ifaces.difference(&current_ifaces) {
                    debug!(iface, "netkit device removed");
                }

                // Removed namespaces (pod deleted).
                let current_ns_inodes: HashSet<u64> =
                    current_nss.iter().map(|(_, ino)| *ino).collect();
                let removed_ns = known_ns_inodes
                    .difference(&current_ns_inodes)
                    .count();
                if removed_ns > 0 {
                    debug!(count = removed_ns, "pod network namespaces removed");
                }

                known_ifaces = current_ifaces;
                known_ns_inodes = current_ns_inodes;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discover_netkit_returns_list() {
        let devices = discover_netkit_interfaces();
        // On a standard host without Cilium, this is empty. No panic.
        let _ = devices;
    }

    #[test]
    fn discover_pod_namespaces_includes_init_ns() {
        let nss = discover_pod_network_namespaces();
        // pid 1 always exists and has a network namespace.
        assert!(!nss.is_empty(), "should find at least init NS");
    }

    #[test]
    fn discover_pod_namespaces_deduplicates_by_inode() {
        let nss = discover_pod_network_namespaces();
        let mut inodes: Vec<u64> = nss.iter().map(|(_, ino)| *ino).collect();
        let before_dedup = inodes.len();
        inodes.sort_unstable();
        inodes.dedup();
        assert_eq!(inodes.len(), before_dedup, "should already be unique");
    }

    #[test]
    fn iface_peer_ifindex_loopback_self_ref() {
        // Loopback iflink == ifindex (points to itself).
        let peer = iface_peer_ifindex("lo");
        assert!(peer.is_some(), "lo should have iflink");
    }

    #[test]
    fn iface_peer_ifindex_nonexistent() {
        assert!(iface_peer_ifindex("nonexistent_xyz").is_none());
    }

    #[tokio::test]
    async fn watcher_starts_and_stops() {
        let cancel = CancellationToken::new();
        let cancel2 = cancel.clone();
        let handle = tokio::spawn(async move {
            watch_netkit_devices(
                Box::new(|iface, pods| {
                    let _ = (iface, pods);
                }),
                Duration::from_millis(50),
                cancel2,
            )
            .await;
        });
        // Let it run 2 ticks then cancel.
        tokio::time::sleep(Duration::from_millis(120)).await;
        cancel.cancel();
        handle.await.unwrap();
    }
}
