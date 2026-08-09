//! Secondary port for programming the security-zone eBPF maps.
//!
//! Zoning is only a posture until the datapath knows which interface belongs
//! to which zone. Every change to the zone configuration therefore has to be
//! pushed down here, otherwise the API keeps reporting zones no packet is
//! ever evaluated against.

use domain::common::error::DomainError;
use domain::zone::entity::ZoneConfig;

/// Writes the zone maps the firewall datapath consults.
pub trait ZoneMapPort: Send + Sync {
    /// Replace the contents of the zone maps with `config`.
    ///
    /// Zone ids are positional, so removing a zone renumbers every zone after
    /// it: implementations clear before they write rather than merging, and
    /// an empty config leaves the maps empty, which the datapath reads as
    /// "no interface is zoned".
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::EngineError`] when a map operation fails.
    fn sync(&mut self, config: &ZoneConfig) -> Result<(), DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Noop;

    impl ZoneMapPort for Noop {
        fn sync(&mut self, _config: &ZoneConfig) -> Result<(), DomainError> {
            Ok(())
        }
    }

    #[test]
    fn zone_map_port_is_object_safe() {
        let mut port: Box<dyn ZoneMapPort> = Box::new(Noop);
        assert!(
            port.sync(&ZoneConfig {
                zones: Vec::new(),
                zone_policies: Vec::new(),
            })
            .is_ok()
        );
    }
}
