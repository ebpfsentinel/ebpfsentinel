//! Default-route programming port.
//!
//! Multi-WAN health probes elect a gateway, but an election only becomes a
//! failover once the kernel actually forwards through the elected next hop.
//! This port is that last step: it hands the selected gateway to whatever can
//! write the routing table (the warden for a rootless agent, `ip route` for a
//! privileged one).

use domain::common::error::DomainError;

/// Installs the elected multi-WAN gateway as the host default route.
pub trait DefaultRoutePort: Send + Sync {
    /// Point the default route at `gateway_ip` over `interface`.
    ///
    /// Implementations replace the existing default route rather than adding a
    /// second one, so repeated calls converge instead of stacking next hops.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::EngineError`] when the route cannot be written
    /// (missing `CAP_NET_ADMIN`, unreachable warden, unknown interface).
    fn replace_default_route(&self, gateway_ip: &str, interface: &str) -> Result<(), DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    struct Noop;

    impl DefaultRoutePort for Noop {
        fn replace_default_route(
            &self,
            _gateway_ip: &str,
            _interface: &str,
        ) -> Result<(), DomainError> {
            Ok(())
        }
    }

    #[test]
    fn the_port_is_object_safe() {
        let port: Arc<dyn DefaultRoutePort> = Arc::new(Noop);
        assert!(port.replace_default_route("10.0.0.1", "eth0").is_ok());
    }
}
