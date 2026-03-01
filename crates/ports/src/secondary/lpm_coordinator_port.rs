use domain::common::error::DomainError;
use ebpf_common::firewall::{FirewallLpmEntryV4, FirewallLpmEntryV6};

/// Secondary port for coordinated access to the firewall LPM Trie maps.
///
/// Multiple subsystems (alias/`GeoIP`, `DDoS` auto-block, IPS subnet block)
/// share the same 4 LPM Trie maps. The coordinator tracks the provenance
/// of each entry so that reloading one source does not erase entries owned
/// by another.
///
/// Sources are identified by string tags:
/// - `"alias"` — `GeoIP` country-block aliases
/// - `"ddos:<CC>"` — `DDoS` auto-block for a specific country
/// - `"ips"` — IPS /24 subnet blocks
pub trait LpmCoordinatorPort: Send + Sync {
    /// Replace all entries for `source` with new ones.
    ///
    /// Removes only entries previously inserted under `source`, then
    /// inserts the new entries. Other sources are untouched.
    fn replace_source_entries(
        &self,
        source: &str,
        src_v4: &[FirewallLpmEntryV4],
        dst_v4: &[FirewallLpmEntryV4],
        src_v6: &[FirewallLpmEntryV6],
        dst_v6: &[FirewallLpmEntryV6],
    ) -> Result<(), DomainError>;

    /// Add entries for `source` (additive, no removal).
    fn insert_entries(
        &self,
        source: &str,
        src_v4: &[FirewallLpmEntryV4],
        src_v6: &[FirewallLpmEntryV6],
    ) -> Result<(), DomainError>;

    /// Remove specific entries previously inserted under `source`.
    fn remove_entries(
        &self,
        source: &str,
        src_v4: &[FirewallLpmEntryV4],
        src_v6: &[FirewallLpmEntryV6],
    ) -> Result<(), DomainError>;

    /// Remove ALL entries belonging to `source`.
    fn remove_all_for_source(&self, source: &str) -> Result<(), DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time check: `LpmCoordinatorPort` must be object-safe.
    #[test]
    fn lpm_coordinator_port_is_object_safe() {
        fn _check(_port: &dyn LpmCoordinatorPort) {}
    }
}
