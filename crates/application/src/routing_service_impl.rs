use std::collections::HashMap;

use domain::routing::entity::{Gateway, GatewayId, GatewayState, GatewayStatus};
use domain::routing::error::RoutingError;

/// Application-level gateway monitoring and multi-WAN routing service.
///
/// Manages gateway definitions, tracks health-check results, and provides
/// gateway selection logic for policy routing rules.
pub struct RoutingAppService {
    gateways: HashMap<GatewayId, GatewayState>,
    enabled: bool,
}

impl Default for RoutingAppService {
    fn default() -> Self {
        Self::new()
    }
}

impl RoutingAppService {
    pub fn new() -> Self {
        Self {
            gateways: HashMap::new(),
            enabled: false,
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Reload gateways from configuration.
    pub fn reload_gateways(&mut self, gateways: Vec<Gateway>) -> Result<(), RoutingError> {
        let mut new_map = HashMap::new();
        for gw in gateways {
            if new_map.contains_key(&gw.id) {
                return Err(RoutingError::DuplicateGateway { id: gw.id });
            }
            // Preserve existing state if the gateway was already tracked.
            let id = gw.id;
            let state = match self.gateways.remove(&id) {
                Some(mut existing) => {
                    existing.gateway = gw;
                    existing
                }
                None => GatewayState::new(gw),
            };
            new_map.insert(state.gateway.id, state);
        }
        self.gateways = new_map;
        Ok(())
    }

    /// Record a health-check success for a gateway.
    pub fn record_probe_success(&mut self, id: GatewayId) -> Result<(), RoutingError> {
        let state = self
            .gateways
            .get_mut(&id)
            .ok_or(RoutingError::GatewayNotFound { id })?;
        let threshold = state
            .gateway
            .health_check
            .as_ref()
            .map_or(2, |hc| hc.recovery_threshold);
        state.record_success(threshold);
        Ok(())
    }

    /// Record a health-check failure for a gateway.
    pub fn record_probe_failure(&mut self, id: GatewayId) -> Result<(), RoutingError> {
        let state = self
            .gateways
            .get_mut(&id)
            .ok_or(RoutingError::GatewayNotFound { id })?;
        let threshold = state
            .gateway
            .health_check
            .as_ref()
            .map_or(3, |hc| hc.failure_threshold);
        state.record_failure(threshold);
        Ok(())
    }

    /// Get the status of a specific gateway.
    pub fn gateway_status(&self, id: GatewayId) -> Option<GatewayStatus> {
        self.gateways.get(&id).map(|s| s.status)
    }

    /// List all gateway states.
    pub fn list_gateways(&self) -> Vec<&GatewayState> {
        let mut gws: Vec<_> = self.gateways.values().collect();
        gws.sort_by_key(|s| s.gateway.priority);
        gws
    }

    /// Select the best usable gateway (lowest priority that is healthy + enabled).
    pub fn select_gateway(&self) -> Option<&GatewayState> {
        self.list_gateways().into_iter().find(|s| s.is_usable())
    }

    /// Get gateway count.
    pub fn gateway_count(&self) -> usize {
        self.gateways.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::routing::entity::Gateway;

    fn make_gateway(id: u8, priority: u32) -> Gateway {
        Gateway {
            id,
            name: format!("gw-{id}"),
            interface: format!("eth{id}"),
            gateway_ip: format!("10.0.{id}.1"),
            priority,
            enabled: true,
            health_check: None,
        }
    }

    #[test]
    fn reload_gateways() {
        let mut svc = RoutingAppService::new();
        svc.reload_gateways(vec![make_gateway(1, 10), make_gateway(2, 20)])
            .unwrap();
        assert_eq!(svc.gateway_count(), 2);
    }

    #[test]
    fn duplicate_gateway_fails() {
        let mut svc = RoutingAppService::new();
        let result = svc.reload_gateways(vec![make_gateway(1, 10), make_gateway(1, 20)]);
        assert!(result.is_err());
    }

    #[test]
    fn select_gateway_prefers_lowest_priority() {
        let mut svc = RoutingAppService::new();
        svc.reload_gateways(vec![make_gateway(2, 20), make_gateway(1, 10)])
            .unwrap();
        let best = svc.select_gateway().unwrap();
        assert_eq!(best.gateway.id, 1);
    }

    #[test]
    fn failover_on_gateway_down() {
        let mut svc = RoutingAppService::new();
        svc.reload_gateways(vec![make_gateway(1, 10), make_gateway(2, 20)])
            .unwrap();

        // Take gateway 1 down
        for _ in 0..3 {
            svc.record_probe_failure(1).unwrap();
        }
        assert_eq!(svc.gateway_status(1), Some(GatewayStatus::Down));

        // Should failover to gateway 2
        let best = svc.select_gateway().unwrap();
        assert_eq!(best.gateway.id, 2);
    }

    #[test]
    fn recovery_restores_primary() {
        let mut svc = RoutingAppService::new();
        svc.reload_gateways(vec![make_gateway(1, 10), make_gateway(2, 20)])
            .unwrap();

        // Take down and recover
        for _ in 0..3 {
            svc.record_probe_failure(1).unwrap();
        }
        for _ in 0..2 {
            svc.record_probe_success(1).unwrap();
        }

        let best = svc.select_gateway().unwrap();
        assert_eq!(best.gateway.id, 1); // Primary restored
    }

    #[test]
    fn no_healthy_gateway_returns_none() {
        let mut svc = RoutingAppService::new();
        svc.reload_gateways(vec![make_gateway(1, 10)]).unwrap();
        for _ in 0..3 {
            svc.record_probe_failure(1).unwrap();
        }
        assert!(svc.select_gateway().is_none());
    }

    #[test]
    fn reload_preserves_state() {
        let mut svc = RoutingAppService::new();
        svc.reload_gateways(vec![make_gateway(1, 10)]).unwrap();

        // Take down
        for _ in 0..3 {
            svc.record_probe_failure(1).unwrap();
        }
        assert_eq!(svc.gateway_status(1), Some(GatewayStatus::Down));

        // Reload with same gateway — state should be preserved
        svc.reload_gateways(vec![make_gateway(1, 10)]).unwrap();
        assert_eq!(svc.gateway_status(1), Some(GatewayStatus::Down));
    }

    #[test]
    fn probe_nonexistent_gateway_fails() {
        let mut svc = RoutingAppService::new();
        assert!(svc.record_probe_success(99).is_err());
        assert!(svc.record_probe_failure(99).is_err());
    }

    #[test]
    fn enabled_toggle() {
        let mut svc = RoutingAppService::new();
        assert!(!svc.enabled());
        svc.set_enabled(true);
        assert!(svc.enabled());
    }
}
