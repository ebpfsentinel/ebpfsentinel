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

use std::collections::{HashMap, HashSet};
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
/// This is a best-effort scan - processes may exit between listing
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

/// Callback signature for a netkit device that has gone away.
pub type OnNetkitRemoved = Box<dyn Fn(&str) + Send + Sync>;

/// Every netkit device on the host, by name, with its ifindex.
///
/// The ifindex is part of the identity: a pod recreated between two polls
/// can come back under the same name on a new device, and a diff on names
/// alone would take it for the one it replaced and never attach to it.
fn netkit_devices_by_ifindex() -> HashMap<String, u32> {
    discover_netkit_interfaces()
        .into_iter()
        .filter_map(|name| {
            let ifindex = std::fs::read_to_string(format!("/sys/class/net/{name}/ifindex"))
                .ok()?
                .trim()
                .parse()
                .ok()?;
            Some((name, ifindex))
        })
        .collect()
}

/// `(added, removed)` between two device snapshots. A name whose ifindex
/// changed is both: the old device is gone and a new one took its name.
fn diff_devices(
    known: &HashMap<String, u32>,
    current: &HashMap<String, u32>,
) -> (Vec<String>, Vec<String>) {
    let mut added: Vec<String> = current
        .iter()
        .filter(|(name, idx)| known.get(*name) != Some(*idx))
        .map(|(name, _)| name.clone())
        .collect();
    let mut removed: Vec<String> = known
        .iter()
        .filter(|(name, idx)| current.get(*name) != Some(*idx))
        .map(|(name, _)| name.clone())
        .collect();
    added.sort_unstable();
    removed.sort_unstable();
    (added, removed)
}

/// Long-running poller that watches for new netkit devices by
/// scanning `/sys/class/net/` periodically. Simultaneously tracks
/// devices with their owning pods.
///
/// The devices present when the watcher starts are handed to
/// `on_new_device` straight away: they are the pods that were already
/// running when the agent (re)started, and they need the programs as much
/// as the ones scheduled afterwards. After that, a device that appears is
/// handed to `on_new_device(iface_name, new_pod_contexts)`, where
/// `new_pod_contexts` holds any pod namespaces that appeared since the last
/// tick, and a device that disappears is handed to `on_removed`.
///
/// Uses polling instead of rtnetlink `NEWLINK` for simplicity and
/// portability. The poll interval (default 5s) is acceptable for
/// pod lifecycle events.
pub async fn watch_netkit_devices(
    on_new_device: OnNetkitDevice,
    on_removed: OnNetkitRemoved,
    poll_interval: Duration,
    cancel: CancellationToken,
) {
    let mut known_ifaces: HashMap<String, u32> = HashMap::new();
    let mut known_ns_inodes: HashSet<u64> = discover_pod_network_namespaces()
        .into_iter()
        .map(|(_, ino)| ino)
        .collect();
    info!(
        initial_namespaces = known_ns_inodes.len(),
        "netkit device watcher started"
    );

    // The first tick fires at once, so the devices already present are
    // attached before the first interval elapses.
    let mut ticker = tokio::time::interval(poll_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            () = cancel.cancelled() => {
                debug!("netkit device watcher cancelled");
                break;
            }
            _ = ticker.tick() => {
                let current_ifaces = netkit_devices_by_ifindex();

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

                let (added, removed) = diff_devices(&known_ifaces, &current_ifaces);

                // Removals first: a name reused by a new device must release
                // the old device's links before the new set is recorded.
                for iface in &removed {
                    debug!(iface, "netkit device removed");
                    on_removed(iface);
                }

                for iface in &added {
                    let peer = iface_peer_ifindex(iface);
                    info!(
                        iface,
                        peer_ifindex = peer,
                        new_pod_ns_count = new_pods.len(),
                        "new netkit device detected"
                    );
                    on_new_device(iface, &new_pods);
                }

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

    fn devices(entries: &[(&str, u32)]) -> HashMap<String, u32> {
        entries
            .iter()
            .map(|(n, i)| ((*n).to_string(), *i))
            .collect()
    }

    #[test]
    fn every_device_is_new_to_an_empty_snapshot() {
        let (added, removed) =
            diff_devices(&HashMap::new(), &devices(&[("lxc-b", 12), ("lxc-a", 11)]));
        assert_eq!(added, vec!["lxc-a", "lxc-b"]);
        assert!(removed.is_empty());
    }

    #[test]
    fn a_device_that_left_is_removed() {
        let (added, removed) = diff_devices(
            &devices(&[("lxc-a", 11), ("lxc-b", 12)]),
            &devices(&[("lxc-a", 11)]),
        );
        assert!(added.is_empty());
        assert_eq!(removed, vec!["lxc-b"]);
    }

    #[test]
    fn a_name_reused_by_a_new_device_is_both_removed_and_added() {
        let (added, removed) = diff_devices(&devices(&[("lxc-a", 11)]), &devices(&[("lxc-a", 40)]));
        assert_eq!(added, vec!["lxc-a"]);
        assert_eq!(removed, vec!["lxc-a"]);
    }

    #[test]
    fn an_unchanged_snapshot_is_quiet() {
        let snap = devices(&[("lxc-a", 11)]);
        let (added, removed) = diff_devices(&snap, &snap);
        assert!(added.is_empty() && removed.is_empty());
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
                Box::new(|iface| {
                    let _ = iface;
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
