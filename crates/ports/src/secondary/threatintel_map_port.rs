use domain::common::entity::DomainMode;
use domain::common::error::DomainError;
use domain::threatintel::entity::Ioc;
use ebpf_common::threatintel::{ThreatIntelKey, ThreatIntelValue};

/// Secondary port for threat intelligence eBPF map operations.
///
/// Provides a typed interface to the kernel `THREATINTEL_IOCS` `HashMap`.
/// Implemented by a map manager in the adapter layer.
pub trait ThreatIntelMapPort: Send + Sync {
    /// Insert or update an IOC in the eBPF map.
    fn insert_ioc(
        &mut self,
        key: &ThreatIntelKey,
        value: &ThreatIntelValue,
    ) -> Result<(), DomainError>;

    /// Remove an IOC from the eBPF map.
    fn remove_ioc(&mut self, key: &ThreatIntelKey) -> Result<(), DomainError>;

    /// Remove all IOCs from the eBPF map.
    fn clear_iocs(&mut self) -> Result<(), DomainError>;

    /// Return the number of IOCs currently in the eBPF map.
    fn ioc_count(&self) -> Result<usize, DomainError>;

    /// Bulk-reload all IOCs into the eBPF maps.
    ///
    /// Clears existing entries, then inserts each IOC under the mode it is
    /// paired with. The mode is per IOC rather than per reload because a feed
    /// may override the global one: a list somebody is still evaluating stays
    /// on `Alert` while the rest of the estate blocks, and a feed of known-bad
    /// infrastructure blocks while the agent is being rolled out in
    /// observation.
    fn load_all_iocs(&mut self, iocs: &[(Ioc, DomainMode)]) -> Result<(), DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threatintel_map_port_is_object_safe() {
        fn _check(port: &dyn ThreatIntelMapPort) {
            let _ = port.ioc_count();
        }
    }
}
