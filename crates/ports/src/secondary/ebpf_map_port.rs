use domain::common::error::DomainError;
use domain::trace::RulePlacement;
use ebpf_common::firewall::{
    FirewallRuleEntry, FirewallRuleEntryV6, ShadowFlowKey, ShadowRuleStats, ShadowSample,
};

/// What the datapath counted for the shadow rules, as read from the kernel.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ShadowCounts {
    /// Per IPv4 shadow slot, summed across CPUs, in load order.
    pub v4: Vec<ShadowRuleStats>,
    /// Per IPv6 shadow slot, summed across CPUs, in load order.
    pub v6: Vec<ShadowRuleStats>,
    /// The sampled flows, each keyed by the slot of the rule that saw it.
    /// Stamps are already converted to nanoseconds since the Unix epoch.
    pub sample: Vec<(ShadowFlowKey, ShadowSample)>,
}

/// Secondary port for array-based eBPF firewall map operations.
///
/// Provides a bulk-load interface to the kernel `FIREWALL_RULES` and
/// `FIREWALL_RULES_V6` `Array` maps. A load is all or nothing per family:
/// the rules are written beside the ones in force and published by one
/// write, so on an error the previous set is still the one enforced.
///
/// The CIDR-only LPM Trie rules (country blocks, large alias sets) are
/// written by the LPM coordinator, not through this port.
///
/// Implemented by `FirewallMapManager` in the adapter layer.
pub trait FirewallArrayMapPort: Send + Sync {
    /// Bulk-load IPv4 rules into the `FIREWALL_RULES` array.
    /// Rules must already be sorted by priority (lowest index = highest priority).
    /// Returns where each rule went, one placement per rule in order, so a
    /// trace can name the rule behind an array slot or a fast-path hit.
    fn load_v4_rules(
        &mut self,
        rules: &[FirewallRuleEntry],
    ) -> Result<Vec<RulePlacement>, DomainError>;

    /// Bulk-load IPv6 rules into the `FIREWALL_RULES_V6` array, returning
    /// where each rule went.
    fn load_v6_rules(
        &mut self,
        rules: &[FirewallRuleEntryV6],
    ) -> Result<Vec<RulePlacement>, DomainError>;

    /// Set the default policy applied when no rule matches.
    fn set_default_policy(&mut self, policy: u8) -> Result<(), DomainError>;

    /// Return the total number of rules currently loaded (V4 + V6).
    fn rule_count(&self) -> Result<usize, DomainError>;

    /// Load the rules the datapath reads after its verdict and never acts on.
    ///
    /// Loading the same entries again changes nothing and keeps what they
    /// have counted, so a reload that leaves the shadow rules alone does not
    /// reset them. Any other load starts every counter and the sample afresh,
    /// since a slot then names another rule. Returns whether anything changed.
    fn load_shadow_rules(
        &mut self,
        v4: &[FirewallRuleEntry],
        v6: &[FirewallRuleEntryV6],
    ) -> Result<bool, DomainError>;

    /// Read what the shadow rules have counted since they were loaded.
    fn read_shadow(&self) -> Result<ShadowCounts, DomainError>;

    /// Say whether a per-source connection ceiling is in force, so the
    /// datapath keeps reading the conntrack state it counts flows by. A map
    /// without such a gate has nothing to record.
    fn set_source_limits(&mut self, _enforced: bool) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time check: `FirewallArrayMapPort` must be object-safe so it
    /// can be used as `dyn FirewallArrayMapPort` behind a Box or Arc.
    #[allow(dead_code)]
    fn assert_object_safe(_: &dyn FirewallArrayMapPort) {}

    #[test]
    fn firewall_array_map_port_is_object_safe() {
        // If this compiles, the trait is object-safe.
        fn _check(port: &dyn FirewallArrayMapPort) {
            let _ = port.rule_count();
        }
    }
}
