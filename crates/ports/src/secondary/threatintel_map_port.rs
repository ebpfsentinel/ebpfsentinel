use domain::common::error::DomainError;
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
