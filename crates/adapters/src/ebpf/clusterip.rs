//! Resolving a Service's cluster address at `connect()` for the workloads an
//! operator opted in.
//!
//! Six programs on a cgroup: `connect4`/`connect6` send a selected task's
//! connection to a cluster address straight to one of its backends,
//! `getpeername4`/`getpeername6` and `recvmsg4`/`recvmsg6` answer with the
//! cluster address afterwards. The reverse hooks attach first, so no socket
//! is ever translated before its peer can be read back as the address the
//! task asked for.
//!
//! The object is loaded with maps of its own, pinned nowhere and shared with
//! no other object, so the links and maps exist only while the agent holds
//! their descriptors: turning the feature off, or stopping the agent, leaves
//! nothing of it in the kernel, and every connection goes through kube-proxy
//! again.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{OwnedFd, RawFd};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock, PoisonError};

use aya::maps::{HashMap as AyaHashMap, MapData};
use domain::clusterip::ClusterIpPlan;
use domain::common::error::DomainError;
use ebpf_common::clusterip::{
    CLUSTERIP_FAMILY_IPV4, CLUSTERIP_FAMILY_IPV6, CLUSTERIP_MAX_CGROUPS, ClusterIpBackend,
    ClusterIpKey, ClusterIpReady, ClusterIpService, ClusterIpSlot,
};
use ports::secondary::clusterip_map_port::{ClusterIpApplied, ClusterIpMapPort};
use tracing::{info, warn};

use super::kfunc_attach;
use super::loader::EbpfLoader;
use crate::ebpf::map_store::MapStore;

/// `BPF_CGROUP_INET4_CONNECT` from `enum bpf_attach_type`.
pub const BPF_CGROUP_INET4_CONNECT: u32 = 10;
/// `BPF_CGROUP_INET6_CONNECT` from `enum bpf_attach_type`.
pub const BPF_CGROUP_INET6_CONNECT: u32 = 11;
/// `BPF_CGROUP_UDP4_RECVMSG` from `enum bpf_attach_type`.
pub const BPF_CGROUP_UDP4_RECVMSG: u32 = 19;
/// `BPF_CGROUP_UDP6_RECVMSG` from `enum bpf_attach_type`.
pub const BPF_CGROUP_UDP6_RECVMSG: u32 = 20;
/// `BPF_CGROUP_INET4_GETPEERNAME` from `enum bpf_attach_type`.
pub const BPF_CGROUP_INET4_GETPEERNAME: u32 = 29;
/// `BPF_CGROUP_INET6_GETPEERNAME` from `enum bpf_attach_type`.
pub const BPF_CGROUP_INET6_GETPEERNAME: u32 = 30;

/// The programs of the object, with the attach type each one is loaded for,
/// in the order they are attached: every reverse hook before the first
/// translation.
pub const CLUSTERIP_HOOKS: &[(&str, u32)] = &[
    ("clusterip_getpeername4", BPF_CGROUP_INET4_GETPEERNAME),
    ("clusterip_getpeername6", BPF_CGROUP_INET6_GETPEERNAME),
    ("clusterip_recvmsg4", BPF_CGROUP_UDP4_RECVMSG),
    ("clusterip_recvmsg6", BPF_CGROUP_UDP6_RECVMSG),
    ("clusterip_connect4", BPF_CGROUP_INET4_CONNECT),
    ("clusterip_connect6", BPF_CGROUP_INET6_CONNECT),
];

/// What the agent can say about the cluster address hooks.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClusterIpStatus {
    /// Every hook is attached.
    pub attached: bool,
    /// The cgroup the hooks sit on.
    pub cgroup: String,
    /// The hooks that did attach, in attach order.
    pub hooks: Vec<String>,
    /// Why resolution is off, in one sentence. `None` when every hook
    /// attached.
    pub reason: Option<String>,
    /// The attach went through the warden rather than being issued here.
    pub brokered: bool,
}

static STATUS: OnceLock<Mutex<ClusterIpStatus>> = OnceLock::new();

fn status_cell() -> &'static Mutex<ClusterIpStatus> {
    STATUS.get_or_init(|| Mutex::new(ClusterIpStatus::default()))
}

/// Publish what the agent can say about the cluster address hooks.
pub fn publish_status(status: ClusterIpStatus) {
    *status_cell().lock().unwrap_or_else(PoisonError::into_inner) = status;
}

/// What the agent can currently say about the cluster address hooks.
#[must_use]
pub fn status() -> ClusterIpStatus {
    status_cell()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

/// Holds the cgroup links alive. Dropping it detaches every hook, which
/// returns every selected workload to kube-proxy.
#[derive(Default)]
pub struct ClusterIpAttacher {
    links: Vec<OwnedFd>,
    warden_sock: Option<PathBuf>,
    warden: Option<Mutex<ebpfsentinel_warden_client::ReconnectingClient>>,
}

impl ClusterIpAttacher {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Route the privileged `BPF_LINK_CREATE` through the warden at `sock`.
    #[must_use]
    pub fn with_warden_socket(mut self, sock: impl Into<PathBuf>) -> Self {
        let sock = sock.into();
        self.warden = Some(crate::warden::attribution::client_for(&sock));
        self.warden_sock = Some(sock);
        self
    }

    /// Attach every hook of `loader` to `cgroup`, all or none, publishing
    /// what happened.
    pub fn attach_all(&mut self, loader: &EbpfLoader, cgroup: &str) -> ClusterIpStatus {
        let brokered = self.warden_sock.is_some();
        let mut hooks = Vec::with_capacity(CLUSTERIP_HOOKS.len());
        for (program, attach_type) in CLUSTERIP_HOOKS {
            match self.attach_one(loader, cgroup, program, *attach_type) {
                Ok(link) => {
                    self.links.push(link);
                    hooks.push((*program).to_string());
                }
                Err(reason) => {
                    // A translation without its reverse hooks is a socket
                    // reporting a peer the task never asked for.
                    self.links.clear();
                    warn!(
                        program,
                        cgroup, reason, "cluster ip resolution off: the cgroup attach was refused"
                    );
                    let status = ClusterIpStatus {
                        attached: false,
                        cgroup: cgroup.to_owned(),
                        hooks: Vec::new(),
                        reason: Some(reason),
                        brokered,
                    };
                    publish_status(status.clone());
                    return status;
                }
            }
        }
        info!(
            cgroup,
            hooks = hooks.len(),
            brokered,
            "cluster ip resolution attached"
        );
        let status = ClusterIpStatus {
            attached: true,
            cgroup: cgroup.to_owned(),
            hooks,
            reason: None,
            brokered,
        };
        publish_status(status.clone());
        status
    }

    fn attach_one(
        &self,
        loader: &EbpfLoader,
        cgroup: &str,
        program: &str,
        attach_type: u32,
    ) -> Result<OwnedFd, String> {
        let prog_fd: RawFd = loader
            .program_fd(program)
            .ok_or_else(|| format!("program `{program}` is not in the loaded object"))?;
        match &self.warden {
            Some(client) => {
                crate::warden::attribution::attach_via_warden(client, prog_fd, cgroup, attach_type)
                    .map_err(|e| e.to_string())
            }
            None => kfunc_attach::attach_cgroup(program, prog_fd, cgroup, attach_type)
                .map_err(|e| e.to_string()),
        }
    }

    /// How many hooks this attacher currently holds a link for.
    #[must_use]
    pub fn attached(&self) -> usize {
        self.links.len()
    }
}

/// One service port as it stands in the kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Installed {
    service: ClusterIpService,
    backends: Vec<ClusterIpBackend>,
}

/// The tables the connect hooks read, kept equal to the last plan.
pub struct ClusterIpMaps {
    services: AyaHashMap<MapData, ClusterIpKey, ClusterIpService>,
    backends: AyaHashMap<MapData, ClusterIpSlot, ClusterIpBackend>,
    ready: AyaHashMap<MapData, ClusterIpReady, u8>,
    cgroups: AyaHashMap<MapData, u64, u8>,
    installed: HashMap<ClusterIpKey, Installed>,
    stable: HashMap<ClusterIpKey, u32>,
    next_stable: u32,
    next_revision: u32,
    selected: BTreeSet<u64>,
}

impl ClusterIpMaps {
    /// Take the tables out of a loaded cluster address object.
    ///
    /// # Errors
    ///
    /// Returns an error when a map is missing from the object or has another
    /// shape than the one declared here.
    pub fn new(ebpf: &mut dyn MapStore) -> anyhow::Result<Self> {
        let take = |ebpf: &mut dyn MapStore, name: &str| {
            ebpf.take_map(name)
                .ok_or_else(|| anyhow::anyhow!("map '{name}' not found"))
        };
        Ok(Self {
            services: AyaHashMap::try_from(take(ebpf, "CLUSTERIP_SERVICES")?)?,
            backends: AyaHashMap::try_from(take(ebpf, "CLUSTERIP_BACKENDS")?)?,
            ready: AyaHashMap::try_from(take(ebpf, "CLUSTERIP_READY")?)?,
            cgroups: AyaHashMap::try_from(take(ebpf, "CLUSTERIP_CGROUPS")?)?,
            installed: HashMap::new(),
            stable: HashMap::new(),
            next_stable: 1,
            next_revision: 1,
            selected: BTreeSet::new(),
        })
    }

    fn stable_for(&mut self, key: ClusterIpKey) -> u32 {
        *self.stable.entry(key).or_insert_with(|| {
            let id = self.next_stable;
            self.next_stable = self.next_stable.wrapping_add(1).max(1);
            id
        })
    }

    fn revision(&mut self) -> u32 {
        let id = self.next_revision;
        self.next_revision = self.next_revision.wrapping_add(1).max(1);
        id
    }

    /// Take a service port out: its entry first, so no connection reads a
    /// list that is being removed, then the list and the ready set.
    fn remove(&mut self, key: &ClusterIpKey) {
        let Some(old) = self.installed.remove(key) else {
            return;
        };
        let _ = self.services.remove(key);
        self.drop_list(&old, &BTreeSet::new());
    }

    /// Remove `old`'s slots, and its ready entries but those in `keep`.
    fn drop_list(&mut self, old: &Installed, keep: &BTreeSet<ClusterIpBackend>) {
        for slot in 0..old.service.count {
            let _ = self.backends.remove(&ClusterIpSlot {
                revision: old.service.revision,
                slot,
            });
        }
        for backend in &old.backends {
            if !keep.contains(backend) {
                let _ = self.ready.remove(&ClusterIpReady {
                    stable: old.service.stable,
                    backend: *backend,
                });
            }
        }
    }

    /// Write one service port under a new revision and point its entry at
    /// it, then remove what the previous revision left.
    fn install(
        &mut self,
        key: ClusterIpKey,
        affinity_secs: u32,
        backends: Vec<ClusterIpBackend>,
    ) -> Result<(), DomainError> {
        let stable = self.stable_for(key);
        let previous = self.installed.get(&key).cloned();
        if previous.as_ref().is_some_and(|old| {
            old.backends == backends && old.service.affinity_secs == affinity_secs
        }) {
            return Ok(());
        }
        let count = u32::try_from(backends.len()).map_err(|_| {
            DomainError::InvalidConfig("more backends than one entry carries".into())
        })?;
        let service = ClusterIpService {
            stable,
            revision: self.revision(),
            count,
            affinity_secs,
        };
        let write = |e: aya::maps::MapError, map: &str| {
            DomainError::EngineError(format!("{map} write failed: {e}"))
        };
        for (slot, backend) in (0u32..).zip(&backends) {
            self.backends
                .insert(
                    &ClusterIpSlot {
                        revision: service.revision,
                        slot,
                    },
                    backend,
                    0,
                )
                .map_err(|e| write(e, "CLUSTERIP_BACKENDS"))?;
        }
        for backend in &backends {
            self.ready
                .insert(
                    &ClusterIpReady {
                        stable,
                        backend: *backend,
                    },
                    &1u8,
                    0,
                )
                .map_err(|e| write(e, "CLUSTERIP_READY"))?;
        }
        self.services
            .insert(&key, &service, 0)
            .map_err(|e| write(e, "CLUSTERIP_SERVICES"))?;
        let keep: BTreeSet<ClusterIpBackend> = backends.iter().copied().collect();
        self.installed.insert(key, Installed { service, backends });
        if let Some(old) = previous {
            self.drop_list(&old, &keep);
        }
        Ok(())
    }

    fn select(
        &mut self,
        plan: &ClusterIpPlan,
        cgroups: &BTreeMap<u64, String>,
    ) -> Result<(usize, usize), DomainError> {
        let mut wanted: Vec<u64> = cgroups
            .iter()
            .filter(|(_, uid)| plan.selected_pods.contains(*uid))
            .map(|(id, _)| *id)
            .collect();
        let limit = CLUSTERIP_MAX_CGROUPS as usize;
        let dropped = wanted.len().saturating_sub(limit);
        wanted.truncate(limit);
        let wanted: BTreeSet<u64> = wanted.into_iter().collect();
        for id in self.selected.difference(&wanted) {
            let _ = self.cgroups.remove(id);
        }
        for id in wanted.difference(&self.selected) {
            self.cgroups.insert(id, &1u8, 0).map_err(|e| {
                DomainError::EngineError(format!("CLUSTERIP_CGROUPS write failed: {e}"))
            })?;
        }
        let count = wanted.len();
        self.selected = wanted;
        Ok((count, dropped))
    }
}

impl ClusterIpMapPort for ClusterIpMaps {
    fn apply(
        &mut self,
        plan: &ClusterIpPlan,
        cgroups: &BTreeMap<u64, String>,
    ) -> Result<ClusterIpApplied, DomainError> {
        let mut wanted: HashMap<ClusterIpKey, (u32, Vec<ClusterIpBackend>)> = HashMap::new();
        for entry in &plan.entries {
            let key = cluster_key(entry.cluster_ip, entry.port, entry.protocol.number());
            let backends = entry.backends.iter().map(|b| backend_of(*b)).collect();
            wanted.insert(key, (entry.affinity_secs, backends));
        }
        // Services that left the plan go before any is written, so the
        // backend table has the room the new lists need.
        let gone: Vec<ClusterIpKey> = self
            .installed
            .keys()
            .filter(|key| !wanted.contains_key(key))
            .copied()
            .collect();
        for key in &gone {
            self.remove(key);
        }
        let mut backends = 0;
        for (key, (affinity_secs, list)) in wanted {
            backends += list.len();
            self.install(key, affinity_secs, list)?;
        }
        let (selected, dropped) = self.select(plan, cgroups)?;
        Ok(ClusterIpApplied {
            services: self.installed.len(),
            backends,
            cgroups: selected,
            cgroups_dropped: dropped,
        })
    }
}

/// The key the connect hooks build for `ip`, `port` and `proto`.
#[must_use]
pub fn cluster_key(ip: IpAddr, port: u16, proto: u8) -> ClusterIpKey {
    let (addr, family) = words(ip);
    ClusterIpKey {
        addr,
        port,
        proto,
        family,
    }
}

/// A backend in the encoding the connect hooks write back.
#[must_use]
pub fn backend_of(addr: SocketAddr) -> ClusterIpBackend {
    let (words, family) = words(addr.ip());
    ClusterIpBackend {
        addr: words,
        port: addr.port(),
        family,
        _pad: 0,
    }
}

/// An address in host-order words and its family. A mapped IPv4 address is
/// IPv4, because the hooks unmap it too.
fn words(ip: IpAddr) -> ([u32; 4], u8) {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 @ IpAddr::V4(_) => v4,
    };
    match ip {
        IpAddr::V4(v4) => ([u32::from(v4), 0, 0, 0], CLUSTERIP_FAMILY_IPV4),
        IpAddr::V6(v6) => {
            let o = v6.octets();
            (
                [
                    u32::from_be_bytes([o[0], o[1], o[2], o[3]]),
                    u32::from_be_bytes([o[4], o[5], o[6], o[7]]),
                    u32::from_be_bytes([o[8], o[9], o[10], o[11]]),
                    u32::from_be_bytes([o[12], o[13], o[14], o[15]]),
                ],
                CLUSTERIP_FAMILY_IPV6,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_reverse_hook_attaches_before_the_first_translation() {
        let first_connect = CLUSTERIP_HOOKS
            .iter()
            .position(|(name, _)| name.contains("connect"))
            .unwrap_or(0);
        assert!(
            CLUSTERIP_HOOKS[..first_connect]
                .iter()
                .all(|(name, _)| name.contains("getpeername") || name.contains("recvmsg"))
        );
        assert_eq!(first_connect, 4);
        let mut names: Vec<&str> = CLUSTERIP_HOOKS.iter().map(|(n, _)| *n).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), CLUSTERIP_HOOKS.len());
    }

    #[test]
    fn keys_carry_host_order_words_and_unmap_a_mapped_address() {
        let key = cluster_key("10.96.0.10".parse().unwrap_or(IpAddr::from([0; 4])), 80, 6);
        assert_eq!(key.addr, [0x0a60_000a, 0, 0, 0]);
        assert_eq!(key.family, CLUSTERIP_FAMILY_IPV4);
        let mapped = cluster_key(
            "::ffff:10.96.0.10"
                .parse()
                .unwrap_or(IpAddr::from([0u16; 8])),
            80,
            6,
        );
        assert_eq!(mapped, key);
        let v6 = backend_of(
            "[fd00:96::10]:8080"
                .parse()
                .unwrap_or(SocketAddr::from(([0; 4], 0))),
        );
        assert_eq!(v6.addr, [0xfd00_0096, 0, 0, 0x10]);
        assert_eq!(v6.family, CLUSTERIP_FAMILY_IPV6);
        assert_eq!(v6.port, 8080);
    }
}
