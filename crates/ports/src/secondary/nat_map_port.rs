use domain::common::error::DomainError;
use ebpf_common::nat::NatRuleEntry;

/// Secondary port for NAT eBPF map operations.
///
/// Provides bulk-load access to the kernel `NAT_DNAT_RULES`,
/// `NAT_SNAT_RULES`, and NAT configuration maps.
///
/// Implemented by a NAT map adapter in the adapter layer.
pub trait NatMapPort: Send + Sync {
    /// Bulk-load DNAT rules into the `NAT_DNAT_RULES` array map.
    fn load_dnat_rules(&mut self, rules: &[NatRuleEntry]) -> Result<(), DomainError>;

    /// Bulk-load SNAT rules into the `NAT_SNAT_RULES` array map.
    fn load_snat_rules(&mut self, rules: &[NatRuleEntry]) -> Result<(), DomainError>;

    /// Enable or disable NAT processing globally.
    fn set_enabled(&mut self, enabled: bool) -> Result<(), DomainError>;

    /// Return the total number of active NAT rules (DNAT + SNAT).
    fn rule_count(&self) -> Result<usize, DomainError>;
}

/// Secondary port for firewall IP set map operations.
///
/// Manages the `FW_IPSET_V4`/`FW_IPSET_V6` and `FW_PORTSET` eBPF maps
/// used for large alias matching (`GeoIP` blocklists, etc.).
pub trait IpSetMapPort: Send + Sync {
    /// Load entries for a given set ID into the IPv4 IP set map.
    /// Replaces any existing entries for this set ID.
    fn load_ipset_v4(&mut self, set_id: u8, addrs: &[u32]) -> Result<(), DomainError>;

    /// Clear all entries for a given set ID from the IPv4 IP set map.
    fn clear_ipset_v4(&mut self, set_id: u8) -> Result<(), DomainError>;

    /// Return the total number of entries across all IP sets.
    fn ipset_entry_count(&self) -> Result<usize, DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nat_map_port_is_object_safe() {
        fn _check(port: &dyn NatMapPort) {
            let _ = port.rule_count();
        }
    }

    #[test]
    fn ipset_map_port_is_object_safe() {
        fn _check(port: &dyn IpSetMapPort) {
            let _ = port.ipset_entry_count();
        }
    }
}
