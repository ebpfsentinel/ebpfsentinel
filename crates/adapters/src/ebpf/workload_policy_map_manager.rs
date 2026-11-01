//! Writing the workload policy the cgroup hooks read.
//!
//! Three maps, written as one. `WORKLOAD_RULES` is the policy in priority
//! order; `WORKLOAD_CGROUP_SELECTORS` says which selectors a cgroup
//! satisfies, and `WORKLOAD_TASK_SELECTORS` the same for one task. The
//! kernel ORs the two masks and compares integers, which is the whole reason
//! this layer exists: a path, a unit name and a container id are resolved
//! here, where there is a filesystem to read, and the hook never sees a
//! string.
//!
//! A selector's bit is its position in the policy's own list of distinct
//! selectors, so two rules about the same workload share a bit. Publishing a
//! policy therefore invalidates every recorded mask - the bit that meant one
//! workload may mean another one afterwards - and the manager clears both
//! tables rather than leaving a task carrying the previous numbering.
//!
//! Two more maps serve rules naming their destinations by DNS name:
//! `WORKLOAD_FQDN_ALLOWED` holds each address a cgroup was answered, under
//! the slot of the rule that named it, until the record's lifetime runs out,
//! and `WORKLOAD_DNS_CAPTURE` turns on the reading of the workloads' DNS
//! packets that fills it. Grants are keyed by slot too, so a publish clears
//! them for the same reason it clears the masks.
//!
//! The last two serve selectors naming a parent or an ancestor, which no mask
//! can carry: a task is under `nginx` because of the chain above it at the
//! moment it connects, and that chain is the kernel's to read.
//! `WORKLOAD_LINEAGE_EXES` maps each named executable, by inode and device,
//! to the selectors it satisfies, and `WORKLOAD_LINEAGE_CONFIG` says which
//! selectors are gated on the walk and where in the running kernel's
//! structures the walk reads.

use aya::maps::{Array, HashMap as AyaHashMap, MapData, PerCpuArray, PerCpuValues};
use domain::common::error::DomainError;
use std::collections::BTreeMap;
use std::net::IpAddr;

use domain::firewall::entity::IpNetwork;
use domain::firewall::fqdn::FqdnGrantKey;
use domain::firewall::workload::{WorkloadPolicy, WorkloadRule, WorkloadSelector};
use ebpf_common::exec_network::ExecNetKey;
use ebpf_common::workload_policy::{
    WORKLOAD_ACTION_ALLOW, WORKLOAD_ACTION_DENY, WORKLOAD_FAMILY_ANY, WORKLOAD_FAMILY_IPV4,
    WORKLOAD_FAMILY_IPV6, WORKLOAD_MODE_ENFORCE, WORKLOAD_MODE_OBSERVE, WORKLOAD_POLICY_MAX_RULES,
    WORKLOAD_RULE_FQDN, WORKLOAD_RULE_PEER, WorkloadExeKey, WorkloadFqdnKey, WorkloadLineageBits,
    WorkloadLineageConfig, WorkloadPeerKey, WorkloadRuleEntry,
};
use ports::secondary::workload_policy_map_port::WorkloadPolicyMapPort;
use tracing::{info, warn};

use crate::ebpf::map_store::MapStore;
use crate::ebpf::{exec_network, process_attach};

/// Holds the three maps of the workload firewall object.
pub struct WorkloadPolicyMapManager {
    rules: Array<MapData, WorkloadRuleEntry>,
    cgroups: AyaHashMap<MapData, u64, u64>,
    tasks: AyaHashMap<MapData, u32, u64>,
    denials: PerCpuArray<MapData, u64>,
    fqdn: AyaHashMap<MapData, WorkloadFqdnKey, u64>,
    capture: Array<MapData, u32>,
    lineage_exes: AyaHashMap<MapData, WorkloadExeKey, WorkloadLineageBits>,
    lineage_config: Array<MapData, WorkloadLineageConfig>,
    peer_destinations: AyaHashMap<MapData, WorkloadPeerKey, u64>,
    peer_sources: AyaHashMap<MapData, WorkloadPeerKey, u64>,
    peer_targets: AyaHashMap<MapData, u64, u64>,
    /// The offsets the walk reads, or why the running kernel's BTF did not
    /// give them.
    offsets: Result<WorkloadLineageConfig, String>,
    /// The paths the policy in force names as a parent or an ancestor, with
    /// the selectors each satisfies, so an exec can be checked against them.
    lineage_paths: BTreeMap<String, WorkloadLineageBits>,
}

/// What a policy asks of the lineage walk.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct LineagePlan {
    /// Bits of the selectors naming a parent or an ancestor.
    pub lineage: u64,
    /// Bits of those naming nothing else.
    pub unconditional: u64,
    /// Each named path, with the selectors it satisfies as a parent and as
    /// an ancestor.
    pub paths: BTreeMap<String, WorkloadLineageBits>,
}

/// The lineage half of `selectors`, by bit, a selector's bit being its
/// position in the list.
#[must_use]
pub fn lineage_plan(selectors: &[WorkloadSelector]) -> LineagePlan {
    let mut plan = LineagePlan::default();
    for (index, selector) in selectors.iter().enumerate() {
        let bit = 1u64 << (index & 63);
        let (path, as_parent) = match (&selector.parent, &selector.ancestor) {
            (Some(path), _) => (path, true),
            (None, Some(path)) => (path, false),
            (None, None) => continue,
        };
        plan.lineage |= bit;
        if selector.lineage_only() {
            plan.unconditional |= bit;
        }
        let bits = plan.paths.entry(path.clone()).or_default();
        if as_parent {
            bits.parent |= bit;
        } else {
            bits.ancestor |= bit;
        }
    }
    plan
}

/// The offsets the walk reads, from the running kernel's BTF.
///
/// # Errors
///
/// The struct or member the kernel's BTF does not describe.
fn lineage_offsets() -> Result<WorkloadLineageConfig, String> {
    let exe = exec_network::resolve_offsets()?;
    let task = process_attach::resolve_layout()?;
    Ok(WorkloadLineageConfig {
        task_real_parent: task.task_real_parent,
        task_mm: exe.task_mm,
        mm_exe_file: exe.mm_exe_file,
        file_inode: exe.file_inode,
        inode_ino: exe.inode_ino,
        inode_sb: exe.inode_sb,
        sb_dev: exe.sb_dev,
        valid: 1,
        ..WorkloadLineageConfig::default()
    })
}

fn exe_key(key: ExecNetKey) -> WorkloadExeKey {
    WorkloadExeKey {
        ino: key.ino,
        dev: key.dev,
        _pad: 0,
    }
}

impl WorkloadPolicyMapManager {
    /// Take every map out of a loaded workload firewall object.
    ///
    /// All of them or none: a manager holding the rules without the selector
    /// tables would publish a policy whose every bit is unset, which is a
    /// policy that decides nothing while reporting itself loaded.
    ///
    /// # Errors
    ///
    /// Returns an error when a map is missing from the object or has another
    /// shape than the one declared here.
    pub fn new(ebpf: &mut dyn MapStore) -> Result<Self, anyhow::Error> {
        let rules = Array::try_from(
            ebpf.take_map("WORKLOAD_RULES")
                .ok_or_else(|| anyhow::anyhow!("map 'WORKLOAD_RULES' not found"))?,
        )?;
        let cgroups = AyaHashMap::try_from(
            ebpf.take_map("WORKLOAD_CGROUP_SELECTORS")
                .ok_or_else(|| anyhow::anyhow!("map 'WORKLOAD_CGROUP_SELECTORS' not found"))?,
        )?;
        let tasks = AyaHashMap::try_from(
            ebpf.take_map("WORKLOAD_TASK_SELECTORS")
                .ok_or_else(|| anyhow::anyhow!("map 'WORKLOAD_TASK_SELECTORS' not found"))?,
        )?;
        let denials = PerCpuArray::try_from(
            ebpf.take_map("WORKLOAD_RULE_DENIALS")
                .ok_or_else(|| anyhow::anyhow!("map 'WORKLOAD_RULE_DENIALS' not found"))?,
        )?;
        let fqdn = AyaHashMap::try_from(
            ebpf.take_map("WORKLOAD_FQDN_ALLOWED")
                .ok_or_else(|| anyhow::anyhow!("map 'WORKLOAD_FQDN_ALLOWED' not found"))?,
        )?;
        let capture = Array::try_from(
            ebpf.take_map("WORKLOAD_DNS_CAPTURE")
                .ok_or_else(|| anyhow::anyhow!("map 'WORKLOAD_DNS_CAPTURE' not found"))?,
        )?;
        let lineage_exes = AyaHashMap::try_from(
            ebpf.take_map("WORKLOAD_LINEAGE_EXES")
                .ok_or_else(|| anyhow::anyhow!("map 'WORKLOAD_LINEAGE_EXES' not found"))?,
        )?;
        let lineage_config = Array::try_from(
            ebpf.take_map("WORKLOAD_LINEAGE_CONFIG")
                .ok_or_else(|| anyhow::anyhow!("map 'WORKLOAD_LINEAGE_CONFIG' not found"))?,
        )?;
        let peer_destinations = AyaHashMap::try_from(
            ebpf.take_map("WORKLOAD_PEER_DESTINATIONS")
                .ok_or_else(|| anyhow::anyhow!("map 'WORKLOAD_PEER_DESTINATIONS' not found"))?,
        )?;
        let peer_sources = AyaHashMap::try_from(
            ebpf.take_map("WORKLOAD_PEER_SOURCES")
                .ok_or_else(|| anyhow::anyhow!("map 'WORKLOAD_PEER_SOURCES' not found"))?,
        )?;
        let peer_targets = AyaHashMap::try_from(
            ebpf.take_map("WORKLOAD_PEER_TARGETS")
                .ok_or_else(|| anyhow::anyhow!("map 'WORKLOAD_PEER_TARGETS' not found"))?,
        )?;
        info!("workload policy tables acquired");
        Ok(Self {
            rules,
            cgroups,
            tasks,
            denials,
            fqdn,
            capture,
            lineage_exes,
            lineage_config,
            peer_destinations,
            peer_sources,
            peer_targets,
            offsets: lineage_offsets(),
            lineage_paths: BTreeMap::new(),
        })
    }

    /// Every key currently in a selector table, so it can be removed.
    ///
    /// Collected before the first removal because the iterator borrows the
    /// map, and an entry the kernel evicted mid-walk is not an error: it is
    /// an LRU doing its job.
    fn keys<K: aya::Pod + Copy, V: aya::Pod>(map: &AyaHashMap<MapData, K, V>) -> Vec<K> {
        map.keys().filter_map(Result::ok).collect()
    }

    /// Write what `selectors` ask of the lineage walk.
    ///
    /// The executables go in before the configuration that gates on them, so
    /// a hook never reads a gate whose table is still being filled. A named
    /// path that does not exist on this node is said once and left out: a
    /// policy shared across a fleet names binaries some nodes do not carry,
    /// and the exec of one installed later is recorded when it happens.
    fn publish_lineage(&mut self, selectors: &[WorkloadSelector]) -> Result<(), DomainError> {
        let plan = lineage_plan(selectors);
        for key in Self::keys(&self.lineage_exes) {
            let _ = self.lineage_exes.remove(&key);
        }
        let mut missing = Vec::new();
        let mut links = Vec::new();
        let mut keys: BTreeMap<(u64, u32), WorkloadLineageBits> = BTreeMap::new();
        for (path, bits) in &plan.paths {
            if let Some(target) = through_link(path) {
                links.push(format!("{path} -> {target}"));
                continue;
            }
            match exec_network::key_of(path) {
                Ok(key) => {
                    let held = keys.entry((key.ino, key.dev)).or_default();
                    held.parent |= bits.parent;
                    held.ancestor |= bits.ancestor;
                }
                Err(_) => missing.push(path.as_str()),
            }
        }
        for ((ino, dev), bits) in &keys {
            let key = WorkloadExeKey {
                ino: *ino,
                dev: *dev,
                _pad: 0,
            };
            self.lineage_exes.insert(&key, bits, 0).map_err(|e| {
                DomainError::EngineError(format!("WORKLOAD_LINEAGE_EXES insert failed: {e}"))
            })?;
        }
        if !missing.is_empty() {
            warn!(
                paths = %missing.join(","),
                "workload rules name a parent or an ancestor not installed on this node: \
                 no task is under it until it is executed"
            );
        }
        if !links.is_empty() {
            warn!(
                paths = %links.join(","),
                "workload rules name a parent or an ancestor through a link: a process is \
                 known by the file it runs, so those rules match no task until they name it"
            );
        }
        let mut config = WorkloadLineageConfig::default();
        if plan.lineage != 0 {
            match &self.offsets {
                Ok(offsets) => config = *offsets,
                Err(reason) => warn!(
                    reason,
                    "workload rules name a parent or an ancestor and the kernel's BTF does \
                     not describe the parent chain: those rules match no task"
                ),
            }
        }
        config.lineage = plan.lineage;
        config.unconditional = plan.unconditional;
        self.lineage_config.set(0, &config, 0).map_err(|e| {
            DomainError::EngineError(format!("WORKLOAD_LINEAGE_CONFIG write failed: {e}"))
        })?;
        self.lineage_paths = plan.paths;
        Ok(())
    }
}

/// The file `path` reaches, when it reaches it through a link.
///
/// A process is known by the file it runs, under the path the kernel reports
/// for it, which is never a link: `/usr/bin/python3` runs as
/// `/usr/bin/python3.12`, and on a merged `/usr` `/bin/bash` runs as
/// `/usr/bin/bash`. A lineage path reaching its file through a link would
/// match in the kernel, which compares files, and nowhere the agent answers
/// from, which compares paths, so it is named and left out, the way an `exe`
/// naming a link matches nothing.
fn through_link(path: &str) -> Option<String> {
    let target = std::fs::canonicalize(path).ok()?;
    (target.as_os_str() != path).then(|| target.display().to_string())
}

impl WorkloadPolicyMapPort for WorkloadPolicyMapManager {
    fn publish_policy(&mut self, policy: &WorkloadPolicy) -> Result<(), DomainError> {
        let selectors: Vec<_> = policy.selectors().cloned().collect();
        let mut written = 0usize;
        for rule in policy.rules().iter().filter(|rule| rule.enabled) {
            let Some(bit) = selectors.iter().position(|one| one == &rule.selector) else {
                continue;
            };
            let entry = entry_for(rule, bit);
            self.rules.set(written as u32, &entry, 0).map_err(|e| {
                DomainError::EngineError(format!("WORKLOAD_RULES write failed: {e}"))
            })?;
            written += 1;
        }
        // Everything past the last rule is disabled rather than left alone:
        // the kernel stops its walk at the first disabled slot, so a leftover
        // from a longer policy would be a rule nobody configured, still in
        // force, and still ahead of the walk's end.
        for index in written..WORKLOAD_POLICY_MAX_RULES {
            self.rules
                .set(index as u32, &WorkloadRuleEntry::default(), 0)
                .map_err(|e| {
                    DomainError::EngineError(format!("WORKLOAD_RULES clear failed: {e}"))
                })?;
        }
        self.clear_selectors()?;
        self.publish_lineage(&selectors)?;
        for key in Self::keys(&self.fqdn) {
            let _ = self.fqdn.remove(&key);
        }
        self.replace_peer_addresses(&[], &[])?;
        for key in Self::keys(&self.peer_targets) {
            let _ = self.peer_targets.remove(&key);
        }
        self.capture
            .set(0, &u32::from(policy.names_destinations()), 0)
            .map_err(|e| {
                DomainError::EngineError(format!("WORKLOAD_DNS_CAPTURE write failed: {e}"))
            })?;
        info!(
            rules = written,
            selectors = selectors.len(),
            "workload policy published"
        );
        Ok(())
    }

    fn rule_denials(&self) -> Result<Vec<u64>, DomainError> {
        let mut counts = Vec::with_capacity(WORKLOAD_POLICY_MAX_RULES);
        for index in 0..WORKLOAD_POLICY_MAX_RULES {
            let values: PerCpuValues<u64> = self.denials.get(&(index as u32), 0).map_err(|e| {
                DomainError::EngineError(format!("WORKLOAD_RULE_DENIALS read failed: {e}"))
            })?;
            counts.push(values.iter().sum());
        }
        Ok(counts)
    }

    fn set_cgroup_selectors(&mut self, cgroup_id: u64, mask: u64) -> Result<(), DomainError> {
        if mask == 0 {
            // A key that was never there is the ordinary case: every cgroup on
            // the node is offered and most match nothing, so the removal is
            // attempted and its outcome deliberately dropped.
            let _ = self.cgroups.remove(&cgroup_id);
            return Ok(());
        }
        self.cgroups.insert(&cgroup_id, &mask, 0).map_err(|e| {
            DomainError::EngineError(format!("WORKLOAD_CGROUP_SELECTORS insert failed: {e}"))
        })
    }

    fn set_task_selectors(&mut self, tgid: u32, mask: u64) -> Result<(), DomainError> {
        if mask == 0 {
            return self.forget_task(tgid);
        }
        self.tasks.insert(&tgid, &mask, 0).map_err(|e| {
            DomainError::EngineError(format!("WORKLOAD_TASK_SELECTORS insert failed: {e}"))
        })
    }

    fn forget_task(&mut self, tgid: u32) -> Result<(), DomainError> {
        // A miss is not an error here either: the task may never have been
        // written, and an LRU may have evicted it before it exited.
        let _ = self.tasks.remove(&tgid);
        Ok(())
    }

    fn clear_selectors(&mut self) -> Result<(), DomainError> {
        for key in Self::keys(&self.cgroups) {
            let _ = self.cgroups.remove(&key);
        }
        for key in Self::keys(&self.tasks) {
            let _ = self.tasks.remove(&key);
        }
        Ok(())
    }

    fn replace_peer_addresses(
        &mut self,
        destinations: &[(IpAddr, u64)],
        sources: &[(IpAddr, u64)],
    ) -> Result<usize, DomainError> {
        let mut refused = 0;
        for (map, wanted, name) in [
            (
                &mut self.peer_destinations,
                destinations,
                "WORKLOAD_PEER_DESTINATIONS",
            ),
            (&mut self.peer_sources, sources, "WORKLOAD_PEER_SOURCES"),
        ] {
            let keep: BTreeMap<_, _> = wanted
                .iter()
                .filter(|(_, mask)| *mask != 0)
                .map(|(addr, mask)| (host_words(*addr), (peer_key(*addr), *mask)))
                .collect();
            for key in map.keys().filter_map(Result::ok).collect::<Vec<_>>() {
                if !keep.contains_key(&(key.addr, key.family)) {
                    let _ = map.remove(&key);
                }
            }
            for (key, mask) in keep.values() {
                if map.get(key, 0).ok() == Some(*mask) {
                    continue;
                }
                match map.insert(key, mask, 0) {
                    Ok(()) => {}
                    Err(aya::maps::MapError::SyscallError(ref e))
                        if e.io_error.raw_os_error() == Some(libc::E2BIG) =>
                    {
                        refused += 1;
                    }
                    Err(e) => {
                        return Err(DomainError::EngineError(format!(
                            "{name} insert failed: {e}"
                        )));
                    }
                }
            }
        }
        if refused > 0 {
            warn!(
                refused,
                "remote workload tables full, addresses left unnamed"
            );
        }
        Ok(refused)
    }

    fn set_peer_targets(&mut self, cgroup_id: u64, mask: u64) -> Result<(), DomainError> {
        if mask == 0 {
            let _ = self.peer_targets.remove(&cgroup_id);
            return Ok(());
        }
        self.peer_targets.insert(&cgroup_id, &mask, 0).map_err(|e| {
            DomainError::EngineError(format!("WORKLOAD_PEER_TARGETS insert failed: {e}"))
        })
    }

    fn grant_fqdn(&mut self, key: &FqdnGrantKey, expires_ns: u64) -> Result<(), DomainError> {
        self.fqdn
            .insert(&fqdn_key(key), &expires_ns, 0)
            .map_err(|e| {
                DomainError::EngineError(format!("WORKLOAD_FQDN_ALLOWED insert failed: {e}"))
            })
    }

    fn revoke_fqdn(&mut self, key: &FqdnGrantKey) -> Result<(), DomainError> {
        let _ = self.fqdn.remove(&fqdn_key(key));
        Ok(())
    }

    fn note_lineage_executable(
        &mut self,
        path: &str,
        dev: u64,
        inode: u64,
    ) -> Result<(), DomainError> {
        let Some(bits) = self.lineage_paths.get(path).copied() else {
            return Ok(());
        };
        let key = exe_key(exec_network::key_from_stat(dev, inode));
        let held = self.lineage_exes.get(&key, 0).unwrap_or_default();
        let merged = WorkloadLineageBits {
            parent: held.parent | bits.parent,
            ancestor: held.ancestor | bits.ancestor,
        };
        if merged == held {
            return Ok(());
        }
        self.lineage_exes.insert(&key, &merged, 0).map_err(|e| {
            DomainError::EngineError(format!("WORKLOAD_LINEAGE_EXES insert failed: {e}"))
        })
    }
}

/// A grant in the shape the hook looks it up by.
///
/// The address is written the way the hook reads the socket's own: host
/// order words, and an IPv4-mapped IPv6 address folded down to IPv4, since a
/// dual-stack socket connecting to an IPv4 peer presents it in that form.
#[must_use]
pub fn fqdn_key(key: &FqdnGrantKey) -> WorkloadFqdnKey {
    let (addr, family) = host_words(key.addr);
    WorkloadFqdnKey {
        cgroup_id: key.cgroup_id,
        addr,
        family,
        slot: u8::try_from(key.slot).unwrap_or(u8::MAX),
        _pad: [0; 6],
    }
}

/// A remote address in the shape the hooks look it up by: the same words
/// and family a grant carries.
#[must_use]
pub fn peer_key(addr: IpAddr) -> WorkloadPeerKey {
    let (addr, family) = host_words(addr);
    WorkloadPeerKey {
        addr,
        family,
        _pad: [0; 3],
    }
}

fn host_words(addr: IpAddr) -> ([u32; 4], u8) {
    match addr {
        IpAddr::V4(v4) => ([u32::from(v4), 0, 0, 0], WORKLOAD_FAMILY_IPV4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => ([u32::from(v4), 0, 0, 0], WORKLOAD_FAMILY_IPV4),
            None => (
                IpNetwork::v6_addr_to_u32x4(&v6.octets()),
                WORKLOAD_FAMILY_IPV6,
            ),
        },
    }
}

/// One rule in the shape the kernel walks, with the bit its selector owns.
///
/// Addresses go out as host-order words because that is how the rest of the
/// firewall stores them and how the hook reads the socket's own address back.
#[must_use]
pub fn entry_for(rule: &WorkloadRule, bit: usize) -> WorkloadRuleEntry {
    let (dst_addr, prefix_len, family) = match rule.dst_ip {
        Some(IpNetwork::V4 { addr, prefix_len }) => {
            ([addr, 0, 0, 0], prefix_len, WORKLOAD_FAMILY_IPV4)
        }
        Some(IpNetwork::V6 { addr, prefix_len }) => (
            IpNetwork::v6_addr_to_u32x4(&addr),
            prefix_len,
            WORKLOAD_FAMILY_IPV6,
        ),
        // A rule naming its destinations by DNS name carries no address:
        // the hook looks the learned grants up instead, in either family.
        None => ([0; 4], 0, WORKLOAD_FAMILY_ANY),
    };
    let (port_start, port_end) = rule
        .dst_port
        .map_or((0, 0), |range| (range.start, range.end));
    WorkloadRuleEntry {
        dst_addr,
        port_start,
        port_end,
        selector: u8::try_from(bit).unwrap_or(u8::MAX),
        prefix_len,
        family,
        protocol: rule.protocol.to_u8(),
        action: if rule.refuses() {
            WORKLOAD_ACTION_DENY
        } else {
            WORKLOAD_ACTION_ALLOW
        },
        mode: if rule.mode.enforces() {
            WORKLOAD_MODE_ENFORCE
        } else {
            WORKLOAD_MODE_OBSERVE
        },
        enabled: 1,
        fqdn: if rule.dst_peer.is_some() {
            WORKLOAD_RULE_PEER
        } else if rule.dst_fqdn.is_empty() {
            0
        } else {
            WORKLOAD_RULE_FQDN
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::common::entity::Protocol;
    use domain::common::entity::RuleId;
    use domain::firewall::entity::{FirewallAction, PortRange};
    use domain::firewall::workload::{WorkloadMode, WorkloadSelector};

    fn rule(action: FirewallAction, mode: WorkloadMode) -> WorkloadRule {
        WorkloadRule {
            dst_peer: None,
            id: RuleId("one".to_string()),
            priority: 10,
            action,
            mode,
            selector: WorkloadSelector::new(Some("/usr/bin/curl".to_string()), None, None, None)
                .expect("a selector naming one executable is valid"),
            protocol: Protocol::Tcp,
            dst_ip: Some(IpNetwork::V4 {
                addr: 0x0a00_0000,
                prefix_len: 8,
            }),
            dst_port: Some(PortRange {
                start: 443,
                end: 443,
            }),
            dst_fqdn: Vec::new(),
            enabled: true,
        }
    }

    #[test]
    fn a_refusing_rule_in_enforce_mode_reaches_the_kernel_as_one() {
        let entry = entry_for(&rule(FirewallAction::Deny, WorkloadMode::Enforce), 3);
        assert_eq!(entry.action, WORKLOAD_ACTION_DENY);
        assert_eq!(entry.mode, WORKLOAD_MODE_ENFORCE);
        assert_eq!(entry.selector, 3);
        assert_eq!(entry.enabled, 1);
        assert_eq!(entry.dst_addr, [0x0a00_0000, 0, 0, 0]);
        assert_eq!(entry.prefix_len, 8);
        assert_eq!(entry.family, WORKLOAD_FAMILY_IPV4);
        assert_eq!(entry.protocol, 6);
        assert_eq!((entry.port_start, entry.port_end), (443, 443));
    }

    #[test]
    fn the_same_rule_observing_carries_the_refusal_and_not_the_enforcement() {
        // The distinction is the whole of the observe mode: the kernel is
        // told what the rule says and told not to act on it, which is what
        // lets the counter answer "how often would this have refused".
        let entry = entry_for(&rule(FirewallAction::Deny, WorkloadMode::Observe), 0);
        assert_eq!(entry.action, WORKLOAD_ACTION_DENY);
        assert_eq!(entry.mode, WORKLOAD_MODE_OBSERVE);
    }

    #[test]
    fn a_rule_naming_no_destination_is_about_everywhere_and_every_family() {
        let mut bare = rule(FirewallAction::Allow, WorkloadMode::Observe);
        bare.dst_ip = None;
        bare.dst_port = None;
        bare.protocol = Protocol::Any;
        let entry = entry_for(&bare, 1);
        assert_eq!(entry.dst_addr, [0; 4]);
        assert_eq!(entry.prefix_len, 0);
        assert_eq!(entry.family, WORKLOAD_FAMILY_ANY);
        assert_eq!(entry.protocol, 0);
        assert_eq!((entry.port_start, entry.port_end), (0, 0));
        assert_eq!(entry.action, WORKLOAD_ACTION_ALLOW);
    }

    #[test]
    fn an_ipv6_rule_goes_out_as_four_host_order_words() {
        let mut v6 = rule(FirewallAction::Deny, WorkloadMode::Enforce);
        let mut addr = [0u8; 16];
        addr[0] = 0x20;
        addr[1] = 0x01;
        addr[15] = 0x01;
        v6.dst_ip = Some(IpNetwork::V6 {
            addr,
            prefix_len: 64,
        });
        let entry = entry_for(&v6, 0);
        assert_eq!(entry.family, WORKLOAD_FAMILY_IPV6);
        assert_eq!(entry.dst_addr[0], 0x2001_0000);
        assert_eq!(entry.dst_addr[3], 1);
        assert_eq!(entry.prefix_len, 64);
    }

    #[test]
    fn a_rule_naming_a_name_goes_out_with_no_address_and_the_fqdn_flag() {
        let mut named = rule(FirewallAction::Allow, WorkloadMode::Enforce);
        named.dst_ip = None;
        named.dst_fqdn = vec![
            domain::firewall::fqdn::FqdnPattern::parse("api.example.com")
                .expect("an exact name is valid"),
        ];
        let entry = entry_for(&named, 0);
        assert_eq!(entry.fqdn, WORKLOAD_RULE_FQDN);
        assert_eq!(entry.family, WORKLOAD_FAMILY_ANY);
        assert_eq!(entry.prefix_len, 0);
        assert_eq!(
            entry_for(&rule(FirewallAction::Deny, WorkloadMode::Enforce), 0).fqdn,
            0
        );
    }

    fn lineage(
        parent: Option<&str>,
        ancestor: Option<&str>,
        exe: Option<&str>,
    ) -> WorkloadSelector {
        WorkloadSelector::with_lineage(
            exe.map(str::to_string),
            None,
            None,
            None,
            domain::firewall::workload::KubernetesMatchers::default(),
            domain::firewall::workload::LineageMatchers {
                parent: parent.map(str::to_string),
                ancestor: ancestor.map(str::to_string),
            },
        )
        .expect("a lineage selector is valid")
    }

    #[test]
    fn a_policy_naming_no_lineage_asks_nothing_of_the_walk() {
        let plain = WorkloadSelector::new(Some("/usr/bin/curl".to_string()), None, None, None)
            .expect("valid");
        assert_eq!(lineage_plan(&[plain]), LineagePlan::default());
    }

    #[test]
    fn each_lineage_selector_gates_its_own_bit_under_the_path_it_names() {
        let plain = WorkloadSelector::new(Some("/usr/bin/curl".to_string()), None, None, None)
            .expect("valid");
        let selectors = [
            plain,
            lineage(Some("/usr/sbin/nginx"), None, Some("/usr/bin/curl")),
            lineage(None, Some("/usr/sbin/nginx"), None),
            lineage(None, Some("/usr/sbin/sshd"), None),
        ];
        let plan = lineage_plan(&selectors);
        assert_eq!(plan.lineage, 0b1110);
        // Only the selectors naming nothing but a lineage are unconditional:
        // the one also naming curl stays behind its task mask.
        assert_eq!(plan.unconditional, 0b1100);
        assert_eq!(
            plan.paths.get("/usr/sbin/nginx"),
            Some(&WorkloadLineageBits {
                parent: 0b0010,
                ancestor: 0b0100
            })
        );
        assert_eq!(
            plan.paths.get("/usr/sbin/sshd"),
            Some(&WorkloadLineageBits {
                parent: 0,
                ancestor: 0b1000
            })
        );
    }

    #[test]
    fn a_lineage_path_reaching_its_file_through_a_link_is_named_with_the_file() {
        let dir = std::env::temp_dir().join(format!("lineage-link-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let file = dir.join("python3.12");
        let link = dir.join("python3");
        std::fs::write(&file, b"").expect("file");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&file, &link).expect("link");
        let file = std::fs::canonicalize(&file).expect("canonical");
        let file = file.to_str().expect("utf-8");
        let link = dir.canonicalize().expect("canonical").join("python3");

        assert_eq!(through_link(file), None);
        assert_eq!(
            through_link(link.to_str().expect("utf-8")).as_deref(),
            Some(file)
        );
        // A path that does not resolve is not a link: it is missing, and
        // said so elsewhere.
        assert_eq!(through_link("/nonexistent/lineage/path"), None);
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn a_grant_is_keyed_the_way_the_hook_reads_the_socket() {
        use std::net::{Ipv4Addr, Ipv6Addr};
        let v4 = fqdn_key(&FqdnGrantKey {
            cgroup_id: 7,
            addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            slot: 3,
        });
        assert_eq!(v4.addr, [0xc000_0201, 0, 0, 0]);
        assert_eq!(v4.family, WORKLOAD_FAMILY_IPV4);
        assert_eq!((v4.cgroup_id, v4.slot), (7, 3));

        let mapped = fqdn_key(&FqdnGrantKey {
            cgroup_id: 7,
            addr: IpAddr::V6(Ipv4Addr::new(192, 0, 2, 1).to_ipv6_mapped()),
            slot: 3,
        });
        assert_eq!(mapped, v4);

        let v6 = fqdn_key(&FqdnGrantKey {
            cgroup_id: 7,
            addr: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            slot: 3,
        });
        assert_eq!(v6.addr, [0x2001_0db8, 0, 0, 1]);
        assert_eq!(v6.family, WORKLOAD_FAMILY_IPV6);
    }

    #[test]
    fn a_remote_address_is_keyed_the_way_the_ingress_hook_reads_the_packet() {
        use std::net::Ipv4Addr;
        let v4 = peer_key(IpAddr::V4(Ipv4Addr::new(10, 1, 0, 5)));
        assert_eq!(v4.addr, [0x0a01_0005, 0, 0, 0]);
        assert_eq!(v4.family, WORKLOAD_FAMILY_IPV4);
        assert_eq!(
            peer_key(IpAddr::V6(Ipv4Addr::new(10, 1, 0, 5).to_ipv6_mapped())),
            v4
        );
        let v6 = peer_key("2001:db8::5".parse().expect("an address"));
        assert_eq!(v6.addr, [0x2001_0db8, 0, 0, 5]);
        assert_eq!(v6.family, WORKLOAD_FAMILY_IPV6);
    }

    #[test]
    fn a_rule_naming_a_remote_workload_goes_out_with_the_peer_flag() {
        let mut named = rule(FirewallAction::Allow, WorkloadMode::Enforce);
        named.dst_ip = None;
        named.dst_peer = Some(domain::firewall::workload_peer::PeerSelector {
            service_account: Some("db".to_string()),
            ..Default::default()
        });
        let entry = entry_for(&named, 0);
        assert_eq!(entry.fqdn, WORKLOAD_RULE_PEER);
        assert_eq!(entry.family, WORKLOAD_FAMILY_ANY);
    }
}
