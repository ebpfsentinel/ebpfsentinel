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

use aya::maps::{Array, HashMap as AyaHashMap, MapData};
use domain::common::error::DomainError;
use domain::firewall::entity::IpNetwork;
use domain::firewall::workload::{WorkloadPolicy, WorkloadRule};
use ebpf_common::workload_policy::{
    WORKLOAD_ACTION_ALLOW, WORKLOAD_ACTION_DENY, WORKLOAD_FAMILY_ANY, WORKLOAD_FAMILY_IPV4,
    WORKLOAD_FAMILY_IPV6, WORKLOAD_MODE_ENFORCE, WORKLOAD_MODE_OBSERVE, WORKLOAD_POLICY_MAX_RULES,
    WorkloadRuleEntry,
};
use ports::secondary::workload_policy_map_port::WorkloadPolicyMapPort;
use tracing::info;

use crate::ebpf::map_store::MapStore;

/// Holds the three maps of the workload firewall object.
pub struct WorkloadPolicyMapManager {
    rules: Array<MapData, WorkloadRuleEntry>,
    cgroups: AyaHashMap<MapData, u64, u64>,
    tasks: AyaHashMap<MapData, u32, u64>,
}

impl WorkloadPolicyMapManager {
    /// Take all three maps out of a loaded workload firewall object.
    ///
    /// All three or none: a manager holding the rules without the selector
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
        info!("workload policy tables acquired");
        Ok(Self {
            rules,
            cgroups,
            tasks,
        })
    }

    /// Every key currently in a selector table, so it can be removed.
    ///
    /// Collected before the first removal because the iterator borrows the
    /// map, and an entry the kernel evicted mid-walk is not an error: it is
    /// an LRU doing its job.
    fn keys<K: aya::Pod + Copy>(map: &AyaHashMap<MapData, K, u64>) -> Vec<K> {
        map.keys().filter_map(Result::ok).collect()
    }
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
            self.rules.set(written as u32, entry, 0).map_err(|e| {
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
                .set(index as u32, WorkloadRuleEntry::default(), 0)
                .map_err(|e| {
                    DomainError::EngineError(format!("WORKLOAD_RULES clear failed: {e}"))
                })?;
        }
        self.clear_selectors()?;
        info!(
            rules = written,
            selectors = selectors.len(),
            "workload policy published"
        );
        Ok(())
    }

    fn set_cgroup_selectors(&mut self, cgroup_id: u64, mask: u64) -> Result<(), DomainError> {
        if mask == 0 {
            // A key that was never there is the ordinary case: every cgroup on
            // the node is offered and most match nothing, so the removal is
            // attempted and its outcome deliberately dropped.
            let _ = self.cgroups.remove(&cgroup_id);
            return Ok(());
        }
        self.cgroups.insert(cgroup_id, mask, 0).map_err(|e| {
            DomainError::EngineError(format!("WORKLOAD_CGROUP_SELECTORS insert failed: {e}"))
        })
    }

    fn set_task_selectors(&mut self, tgid: u32, mask: u64) -> Result<(), DomainError> {
        if mask == 0 {
            return self.forget_task(tgid);
        }
        self.tasks.insert(tgid, mask, 0).map_err(|e| {
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
        _pad: 0,
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
}
