//! The kernel's own drop reasons, counted by a raw tracepoint on
//! `kfree_skb`.
//!
//! Everything the program needs to know about the running kernel is read
//! from its BTF before the hook attaches: where `sk_buff` keeps its device
//! and its input interface, where `net_device` keeps its index and its name,
//! and which value of `enum skb_drop_reason` is the first one that means a
//! drop. The reason names come from the same enumeration, so a kernel that
//! adds a reason is counted under that reason's own name.
//!
//! The same object also counts the drops of the workloads somebody is
//! watching, under each one's cgroup, which takes where a socket keeps its
//! state and its cgroup and where the cgroup keeps its id.

use std::collections::HashMap;
use std::os::fd::{OwnedFd, RawFd};
use std::sync::{Mutex, OnceLock, PoisonError};

use aya::maps::{Array, HashMap as AyaHashMap, MapData, PerCpuArray, PerCpuHashMap, PerCpuValues};
use domain::common::error::DomainError;
use domain::drops::RawDrop;
use ebpf_common::drop_reason::{
    DROP_METRIC_KEYS_FULL, DROP_METRIC_UNCONFIGURED, DROP_WATCH_MAX, DropReasonConfig,
    DropReasonKey, DropWorkloadKey,
};
use ports::secondary::drop_counter_port::DropCounterPort;
use tracing::{info, warn};

use super::kfunc::{vmlinux_enum_members, vmlinux_struct_member_offsets};
use super::kfunc_attach;
use super::loader::EbpfLoader;
use super::map_store::MapStore;

/// The program of the drop reason object.
pub const DROP_REASON_PROGRAM: &str = "drop_reason_kfree_skb";
/// The raw tracepoint it attaches to.
pub const DROP_REASON_TRACEPOINT: &str = "kfree_skb";

const DROP_ENUM: &str = "skb_drop_reason";
const DROP_PREFIX: &str = "SKB_DROP_REASON_";
const SUBSYS_ENUM: &str = "skb_drop_reason_subsys";
const SUBSYS_PREFIX: &str = "SKB_DROP_REASON_SUBSYS_";
/// The first reason that means a drop: the two below it say the packet was
/// consumed or has not been dropped yet.
const FIRST_DROP: &str = "SKB_DROP_REASON_NOT_SPECIFIED";
/// Where a subsystem's reasons start in the reason's value.
const SUBSYS_SHIFT: u32 = 16;

/// What the agent can say about the drop counter.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DropReasonStatus {
    /// The tracepoint is attached and drops are counted.
    pub attached: bool,
    /// Why it is off, in one sentence. `None` when it is on.
    pub reason: Option<String>,
}

static STATUS: OnceLock<Mutex<DropReasonStatus>> = OnceLock::new();

fn status_cell() -> &'static Mutex<DropReasonStatus> {
    STATUS.get_or_init(|| Mutex::new(DropReasonStatus::default()))
}

/// Publish what the agent can say about the drop counter.
pub fn publish_status(status: DropReasonStatus) {
    *status_cell().lock().unwrap_or_else(PoisonError::into_inner) = status;
}

/// What the agent can currently say about the drop counter.
#[must_use]
pub fn status() -> DropReasonStatus {
    status_cell()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

/// The reasons the running kernel defines, by value.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReasonNames {
    /// The first value that means a drop.
    pub first_drop: u32,
    names: HashMap<u32, String>,
}

impl ReasonNames {
    /// Name the reasons from the two enumerations' members.
    ///
    /// Returns `None` when the drop enumeration has no `NOT_SPECIFIED`
    /// member, which is a kernel the counter cannot tell drops from
    /// deliveries on.
    #[must_use]
    pub fn from_members(drops: &[(String, i64)], subsystems: &[(String, i64)]) -> Option<Self> {
        let first_drop = drops
            .iter()
            .find(|(name, _)| name == FIRST_DROP)
            .and_then(|(_, value)| u32::try_from(*value).ok())
            .filter(|value| *value > 0)?;
        let mut names = HashMap::new();
        for (name, value) in drops {
            let Ok(value) = u32::try_from(*value) else {
                continue;
            };
            if value < first_drop || name.ends_with("_MAX") {
                continue;
            }
            names.insert(
                value,
                name.strip_prefix(DROP_PREFIX).unwrap_or(name).to_owned(),
            );
        }
        for (name, value) in subsystems {
            // Subsystem zero is the core, whose reasons are named above, and
            // the last member is the count.
            let Ok(value) = u32::try_from(*value) else {
                continue;
            };
            if value == 0 || name.ends_with("_NUM") || value >= 1 << SUBSYS_SHIFT {
                continue;
            }
            names.insert(
                value << SUBSYS_SHIFT,
                format!(
                    "SUBSYS_{}",
                    name.strip_prefix(SUBSYS_PREFIX).unwrap_or(name)
                ),
            );
        }
        Some(Self { first_drop, names })
    }

    /// The name of a counted reason, `UNKNOWN_<value>` when this kernel's
    /// enumeration does not name it.
    #[must_use]
    pub fn name(&self, value: u32) -> String {
        self.names
            .get(&value)
            .cloned()
            .unwrap_or_else(|| format!("UNKNOWN_{value}"))
    }
}

/// Read the layout and the reasons off the running kernel's BTF.
///
/// # Errors
///
/// Returns why the counter cannot run on this kernel, in one sentence.
pub fn resolve_from_btf() -> Result<(DropReasonConfig, ReasonNames), String> {
    let drops = vmlinux_enum_members(DROP_ENUM)
        .map_err(|e| format!("the kernel names no drop reasons: {e}"))?;
    // Kernels before the subsystem split have no second enumeration, and
    // every reason they give is a core one.
    let subsystems = vmlinux_enum_members(SUBSYS_ENUM).unwrap_or_default();
    let names = ReasonNames::from_members(&drops, &subsystems)
        .ok_or_else(|| format!("`enum {DROP_ENUM}` has no `{FIRST_DROP}`"))?;
    let skb = vmlinux_struct_member_offsets("sk_buff", &["dev", "skb_iif", "sk"])
        .map_err(|e| format!("`struct sk_buff` could not be read: {e}"))?;
    let dev = vmlinux_struct_member_offsets("net_device", &["ifindex", "name"])
        .map_err(|e| format!("`struct net_device` could not be read: {e}"))?;
    let (Some(skb_dev), Some(skb_iif), Some(skb_sk)) = (skb[0], skb[1], skb[2]) else {
        return Err("`struct sk_buff` has no `dev`, no `skb_iif` or no `sk`".to_owned());
    };
    let (Some(dev_ifindex), Some(dev_name)) = (dev[0], dev[1]) else {
        return Err("`struct net_device` has no `ifindex` or no `name`".to_owned());
    };
    let socket = socket_layout()?;
    Ok((
        DropReasonConfig {
            first_drop: names.first_drop,
            skb_dev,
            skb_iif,
            dev_ifindex,
            dev_name,
            skb_sk,
            sk_state: socket[0],
            sk_cgrp_data: socket[1],
            cgrp_data_cgroup: socket[2],
            cgroup_kn: socket[3],
            kn_id: socket[4],
        },
        names,
    ))
}

/// Where a socket keeps its state and its cgroup, and where the cgroup keeps
/// its id: `[sk_state, sk_cgrp_data, cgrp_data_cgroup, cgroup_kn, kn_id]`.
fn socket_layout() -> Result<[u32; 5], String> {
    let one = |name: &str, members: &[&str]| -> Result<Vec<u32>, String> {
        let found = vmlinux_struct_member_offsets(name, members)
            .map_err(|e| format!("`struct {name}` could not be read: {e}"))?;
        members
            .iter()
            .zip(found)
            .map(|(member, offset)| {
                offset.ok_or_else(|| format!("`struct {name}` has no `{member}`"))
            })
            .collect()
    };
    let sock = one("sock", &["__sk_common", "sk_cgrp_data"])?;
    let common = one("sock_common", &["skc_state"])?;
    let data = one("sock_cgroup_data", &["cgroup"])?;
    let cgroup = one("cgroup", &["kn"])?;
    let kn = one("kernfs_node", &["id"])?;
    Ok([sock[0] + common[0], sock[1], data[0], cgroup[0], kn[0]])
}

/// The maps of the drop reason object.
pub struct DropReasonCounter {
    counts: PerCpuHashMap<MapData, DropReasonKey, u64>,
    metrics: PerCpuArray<MapData, u64>,
    watching: Array<MapData, u32>,
    watched: AyaHashMap<MapData, u64, u8>,
    workloads: PerCpuHashMap<MapData, DropWorkloadKey, u64>,
    names: ReasonNames,
}

impl DropReasonCounter {
    /// Take the maps out of a loaded object and write the configuration the
    /// program reads, before anything attaches.
    ///
    /// # Errors
    ///
    /// Returns an error when a map is missing or the configuration write is
    /// refused.
    pub fn new(
        ebpf: &mut dyn MapStore,
        config: DropReasonConfig,
        names: ReasonNames,
    ) -> Result<Self, anyhow::Error> {
        let mut config_map: Array<MapData, DropReasonConfig> = Array::try_from(
            ebpf.take_map("DROP_CONFIG")
                .ok_or_else(|| anyhow::anyhow!("map 'DROP_CONFIG' not found"))?,
        )?;
        config_map.set(0, &config, 0)?;
        let counts = PerCpuHashMap::try_from(
            ebpf.take_map("DROP_COUNTS")
                .ok_or_else(|| anyhow::anyhow!("map 'DROP_COUNTS' not found"))?,
        )?;
        let metrics = PerCpuArray::try_from(
            ebpf.take_map("DROP_METRICS")
                .ok_or_else(|| anyhow::anyhow!("map 'DROP_METRICS' not found"))?,
        )?;
        let watching = Array::try_from(
            ebpf.take_map("DROP_WATCHING")
                .ok_or_else(|| anyhow::anyhow!("map 'DROP_WATCHING' not found"))?,
        )?;
        let watched = AyaHashMap::try_from(
            ebpf.take_map("DROP_WATCHED")
                .ok_or_else(|| anyhow::anyhow!("map 'DROP_WATCHED' not found"))?,
        )?;
        let workloads = PerCpuHashMap::try_from(
            ebpf.take_map("DROP_WORKLOADS")
                .ok_or_else(|| anyhow::anyhow!("map 'DROP_WORKLOADS' not found"))?,
        )?;
        Ok(Self {
            counts,
            metrics,
            watching,
            watched,
            workloads,
            names,
        })
    }

    /// Start counting the drops of the workload under `cgroup`, from zero.
    ///
    /// # Errors
    ///
    /// Returns why the kernel refused the write, or that the watch set is
    /// full.
    pub fn watch(&mut self, cgroup: u64) -> Result<(), DomainError> {
        self.forget(cgroup)?;
        let watched = self.watched_count();
        if self.watched.get(&cgroup, 0).is_err() && watched >= DROP_WATCH_MAX {
            return Err(DomainError::EngineError(format!(
                "{DROP_WATCH_MAX} workloads are already watched"
            )));
        }
        self.watched
            .insert(&cgroup, &1, 0)
            .map_err(|e| DomainError::EngineError(format!("DROP_WATCHED write failed: {e}")))?;
        self.publish_watching()
    }

    /// Stop counting the drops of the workload under `cgroup` and remove
    /// what was counted for it.
    ///
    /// # Errors
    ///
    /// Returns why the kernel refused the write.
    pub fn unwatch(&mut self, cgroup: u64) -> Result<(), DomainError> {
        // Absent already is the state asked for.
        let _ = self.watched.remove(&cgroup);
        self.publish_watching()?;
        self.forget(cgroup)
    }

    /// How many workloads are watched.
    #[must_use]
    pub fn watched_count(&self) -> u32 {
        u32::try_from(self.watched.keys().flatten().count()).unwrap_or(u32::MAX)
    }

    /// The drops counted for the workload under `cgroup` since it was
    /// watched, per reason name, largest first.
    ///
    /// # Errors
    ///
    /// Returns why the map could not be read.
    pub fn read_workload(&self, cgroup: u64) -> Result<Vec<(String, u64)>, DomainError> {
        let mut rows: Vec<(String, u64)> = Vec::new();
        for entry in &self.workloads {
            let (key, values) = entry.map_err(|e| {
                DomainError::EngineError(format!("DROP_WORKLOADS read failed: {e}"))
            })?;
            if key.cgroup == cgroup {
                rows.push((self.names.name(key.reason), values.iter().sum()));
            }
        }
        rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        Ok(rows)
    }

    fn publish_watching(&mut self) -> Result<(), DomainError> {
        let count = self.watched_count();
        self.watching
            .set(0, &count, 0)
            .map_err(|e| DomainError::EngineError(format!("DROP_WATCHING write failed: {e}")))
    }

    fn forget(&mut self, cgroup: u64) -> Result<(), DomainError> {
        let stale: Vec<DropWorkloadKey> = self
            .workloads
            .keys()
            .filter_map(Result::ok)
            .filter(|key| key.cgroup == cgroup)
            .collect();
        for key in stale {
            self.workloads.remove(&key).map_err(|e| {
                DomainError::EngineError(format!("DROP_WORKLOADS delete failed: {e}"))
            })?;
        }
        Ok(())
    }

    fn metric(&self, slot: u32) -> u64 {
        self.metrics
            .get(&slot, 0)
            .map_or(0, |values: PerCpuValues<u64>| values.iter().sum())
    }
}

/// The device name a key carries, up to its first NUL.
fn key_name(name: &[u8]) -> String {
    let end = name.iter().position(|b| *b == 0).unwrap_or(name.len());
    String::from_utf8_lossy(&name[..end]).into_owned()
}

impl DropCounterPort for DropReasonCounter {
    fn read(&self) -> Result<(Vec<RawDrop>, u64), DomainError> {
        let mut raw = Vec::new();
        for entry in &self.counts {
            let (key, values) = entry
                .map_err(|e| DomainError::EngineError(format!("DROP_COUNTS read failed: {e}")))?;
            raw.push(RawDrop {
                reason: self.names.name(key.reason),
                ifindex: key.ifindex,
                name: key_name(&key.name),
                packets: values.iter().sum(),
            });
        }
        let uncounted = self
            .metric(DROP_METRIC_KEYS_FULL)
            .saturating_add(self.metric(DROP_METRIC_UNCONFIGURED));
        Ok((raw, uncounted))
    }
}

/// Holds the tracepoint link alive.
#[derive(Default)]
pub struct DropReasonAttacher {
    link: Option<OwnedFd>,
}

impl DropReasonAttacher {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach the tracepoint of `loader`, publishing what happened.
    pub fn attach(&mut self, loader: &EbpfLoader) -> DropReasonStatus {
        let status = match Self::attach_one(loader) {
            Ok(link) => {
                self.link = Some(link);
                info!(
                    tracepoint = DROP_REASON_TRACEPOINT,
                    "kernel drop reasons counted"
                );
                DropReasonStatus {
                    attached: true,
                    reason: None,
                }
            }
            Err(reason) => {
                warn!(
                    tracepoint = DROP_REASON_TRACEPOINT,
                    reason, "kernel drop reasons not counted: the tracepoint attach was refused"
                );
                DropReasonStatus {
                    attached: false,
                    reason: Some(reason),
                }
            }
        };
        publish_status(status.clone());
        status
    }

    /// Attach for a caller that owns the link's lifetime itself, such as an
    /// investigation, without reporting it as the node's drop counter.
    ///
    /// # Errors
    ///
    /// Returns why the kernel refused the attach.
    pub fn attach_scoped(&mut self, loader: &EbpfLoader) -> Result<(), String> {
        self.link = Some(Self::attach_one(loader)?);
        Ok(())
    }

    fn attach_one(loader: &EbpfLoader) -> Result<OwnedFd, String> {
        let prog_fd: RawFd = loader.program_fd(DROP_REASON_PROGRAM).ok_or_else(|| {
            format!("program `{DROP_REASON_PROGRAM}` is not in the loaded object")
        })?;
        kfunc_attach::attach_raw_tracepoint(DROP_REASON_PROGRAM, prog_fd, DROP_REASON_TRACEPOINT)
            .map_err(|e| e.to_string())
    }

    /// Whether this attacher holds the link.
    #[must_use]
    pub fn attached(&self) -> bool {
        self.link.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn members(list: &[(&str, i64)]) -> Vec<(String, i64)> {
        list.iter().map(|(n, v)| ((*n).to_owned(), *v)).collect()
    }

    #[test]
    fn reasons_are_named_from_the_first_drop_on() {
        let names = ReasonNames::from_members(
            &members(&[
                ("SKB_NOT_DROPPED_YET", 0),
                ("SKB_CONSUMED", 1),
                ("SKB_DROP_REASON_NOT_SPECIFIED", 2),
                ("SKB_DROP_REASON_NO_SOCKET", 3),
                ("SKB_DROP_REASON_MAX", 4),
            ]),
            &members(&[
                ("SKB_DROP_REASON_SUBSYS_CORE", 0),
                ("SKB_DROP_REASON_SUBSYS_OPENVSWITCH", 3),
                ("SKB_DROP_REASON_SUBSYS_NUM", 4),
            ]),
        )
        .expect("NOT_SPECIFIED is present");
        assert_eq!(names.first_drop, 2);
        assert_eq!(names.name(3), "NO_SOCKET");
        assert_eq!(names.name(2), "NOT_SPECIFIED");
        assert_eq!(names.name(3 << 16), "SUBSYS_OPENVSWITCH");
        assert_eq!(names.name(4), "UNKNOWN_4");
        assert_eq!(names.name(1), "UNKNOWN_1");
    }

    #[test]
    fn a_kernel_without_a_first_drop_is_refused() {
        assert!(ReasonNames::from_members(&members(&[("SKB_CONSUMED", 1)]), &[]).is_none());
    }

    #[test]
    fn a_device_name_stops_at_its_first_nul() {
        let mut name = [0_u8; 16];
        name[..4].copy_from_slice(b"eth0");
        assert_eq!(key_name(&name), "eth0");
        assert_eq!(key_name(&[0_u8; 16]), "");
    }

    #[test]
    fn the_socket_walk_resolves_on_the_running_kernel() {
        // Every host this agent supports publishes its BTF; a build machine
        // without it has no kernel layout to check against.
        if !std::path::Path::new("/sys/kernel/btf/vmlinux").exists() {
            return;
        }
        let [state, cgrp_data, cgroup, kn, id] =
            socket_layout().expect("sock, cgroup and kernfs_node carry the walked members");
        // None of these members opens its struct.
        assert!(state > 0 && cgrp_data > 0 && kn > 0);
        // The id sits past the kernfs node's counters, and the cgroup
        // pointer may lead its own struct.
        assert!(id > 0);
        assert!(cgroup < 64);
    }

    #[test]
    fn the_hook_is_the_kernels_own_drop_point() {
        assert_eq!(DROP_REASON_TRACEPOINT, "kfree_skb");
        assert_eq!(DROP_REASON_PROGRAM, "drop_reason_kfree_skb");
    }
}
