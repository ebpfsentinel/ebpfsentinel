use domain::common::entity::DomainMode;
use domain::common::error::DomainError;
use domain::threatintel::entity::Ioc;

/// Secondary port for the kernel copy of the threat-intelligence set.
///
/// Implemented by a map manager in the adapter layer.
pub trait ThreatIntelMapPort: Send + Sync {
    /// Indicators the kernel tables hold, feeds and injected addresses
    /// together.
    fn ioc_count(&self) -> Result<usize, DomainError>;

    /// Replace the whole set the datapath matches against.
    ///
    /// The replacement is atomic for the datapath: a packet is matched
    /// against the previous set or this one, never a mix. A set the tables
    /// cannot hold is refused before anything is written, and the previous
    /// set stays in force.
    ///
    /// The mode is per indicator rather than per reload because a feed may
    /// override the global one: a list somebody is still evaluating stays on
    /// `Alert` while the rest of the estate blocks, and a feed of known-bad
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
