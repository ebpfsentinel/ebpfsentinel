use domain::common::error::DomainError;
use ebpf_common::firewall::{FirewallRuleEntry, FirewallRuleEntryV6};

/// Secondary port for array-based eBPF firewall map operations.
///
/// Provides a bulk-load interface to the kernel `FIREWALL_RULES` and
/// `FIREWALL_RULES_V6` `Array` maps. Rules are loaded atomically by
/// writing count=0, entries, then count=n.
///
/// CIDR-only LPM Trie rules (e.g. `GeoIP` blocking) are handled by the
/// separate `GeoIpLpmPort` trait.
///
/// Implemented by `FirewallMapManager` in the adapter layer.
pub trait FirewallArrayMapPort: Send + Sync {
    /// Bulk-load IPv4 rules into the `FIREWALL_RULES` array.
    /// Rules must already be sorted by priority (lowest index = highest priority).
    fn load_v4_rules(&mut self, rules: &[FirewallRuleEntry]) -> Result<(), DomainError>;

    /// Bulk-load IPv6 rules into the `FIREWALL_RULES_V6` array.
    fn load_v6_rules(&mut self, rules: &[FirewallRuleEntryV6]) -> Result<(), DomainError>;

    /// Set the default policy applied when no rule matches.
    fn set_default_policy(&mut self, policy: u8) -> Result<(), DomainError>;

    /// Return the total number of rules currently loaded (V4 + V6).
    fn rule_count(&self) -> Result<usize, DomainError>;
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
