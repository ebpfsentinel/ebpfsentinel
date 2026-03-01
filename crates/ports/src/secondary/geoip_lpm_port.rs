use domain::common::error::DomainError;
use ebpf_common::firewall::{FirewallLpmEntryV4, FirewallLpmEntryV6};

/// Secondary port for loading `GeoIP` CIDR blocks into eBPF LPM Trie maps.
///
/// Separated from `FirewallArrayMapPort` because `GeoIP` rules are CIDR-only
/// (no port, protocol, or VLAN matching) and benefit from O(log n)
/// longest-prefix-match lookup in kernel space.
pub trait GeoIpLpmPort: Send + Sync {
    /// Load IPv4 CIDR rules into LPM Trie maps (src + dst).
    fn load_lpm_v4_rules(
        &mut self,
        src_rules: &[FirewallLpmEntryV4],
        dst_rules: &[FirewallLpmEntryV4],
    ) -> Result<(), DomainError>;

    /// Load IPv6 CIDR rules into LPM Trie maps (src + dst).
    fn load_lpm_v6_rules(
        &mut self,
        src_rules: &[FirewallLpmEntryV6],
        dst_rules: &[FirewallLpmEntryV6],
    ) -> Result<(), DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time check: `GeoIpLpmPort` must be object-safe.
    #[test]
    fn geoip_lpm_port_is_object_safe() {
        fn _check(_port: &dyn GeoIpLpmPort) {}
    }
}
