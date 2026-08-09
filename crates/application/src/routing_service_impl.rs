use std::collections::HashMap;
use std::sync::Arc;

use domain::routing::entity::{Gateway, GatewayId, GatewayState, GatewayStatus};
use domain::routing::error::RoutingError;
use ports::secondary::default_route_port::DefaultRoutePort;
use ports::secondary::metrics_port::MetricsPort;

/// Application-level gateway monitoring and multi-WAN routing service.
///
/// Manages gateway definitions, tracks health-check results, elects the best
/// usable gateway, and installs that election as the host default route so a
/// failover moves packets instead of only moving a status field.
pub struct RoutingAppService {
    gateways: HashMap<GatewayId, GatewayState>,
    metrics: Option<Arc<dyn MetricsPort>>,
    /// Programs the default route. Absent leaves the election advisory, which
    /// is what the API-only and unit-test paths want.
    route: Option<Arc<dyn DefaultRoutePort>>,
    /// Gateway the default route currently points at, so an unchanged election
    /// costs nothing and a failed install is retried on the next probe.
    routed_via: Option<GatewayId>,
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
            metrics: None,
            route: None,
            routed_via: None,
            enabled: false,
        }
    }

    /// Set the metrics port for recording routing metrics.
    pub fn set_metrics(&mut self, metrics: Arc<dyn MetricsPort>) {
        self.metrics = Some(metrics);
    }

    /// Set the port that installs the elected gateway as the default route.
    pub fn set_route_port(&mut self, route: Arc<dyn DefaultRoutePort>) {
        self.route = Some(route);
        // A port arriving after the gateways were loaded still has to program
        // the current election, otherwise nothing moves until the first probe.
        self.apply_selected_route();
    }

    /// Install the currently elected gateway as the host default route.
    ///
    /// A no-op when routing is disabled, when no route port is wired, or when
    /// the election is unchanged. A failed install leaves `routed_via` alone so
    /// the next probe retries it.
    fn apply_selected_route(&mut self) {
        if !self.enabled || self.route.is_none() {
            return;
        }
        let Some(selected) = self.select_gateway() else {
            // Every gateway is down: the last programmed route is the least-bad
            // path left, and the all-down alert already carries the news.
            return;
        };
        let (id, gateway_ip, interface, name) = (
            selected.gateway.id,
            selected.gateway.gateway_ip.clone(),
            selected.gateway.interface.clone(),
            selected.gateway.name.clone(),
        );
        if self.routed_via == Some(id) {
            return;
        }
        let Some(ref route) = self.route else {
            return;
        };
        match route.replace_default_route(&gateway_ip, &interface) {
            Ok(()) => {
                self.routed_via = Some(id);
                tracing::info!(gateway = %name, %gateway_ip, %interface, "default route now points at the elected gateway");
            }
            Err(e) => {
                tracing::warn!(gateway = %name, error = %e, "could not program the default route, retrying on the next probe");
            }
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        tracing::info!(enabled, "routing service toggled");
        self.apply_selected_route();
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
        let count = self.gateways.len();
        if let Some(ref m) = self.metrics {
            m.set_routing_gateways_total(count as u64);
        }
        tracing::info!(count, "routing gateways reloaded");
        self.apply_selected_route();
        Ok(())
    }

    /// Add a new gateway, auto-assigning the lowest free identifier (0-255).
    ///
    /// Returns the assigned [`GatewayId`]. Errors with [`RoutingError::Full`]
    /// when all 256 identifiers are in use.
    pub fn add_gateway(&mut self, mut gateway: Gateway) -> Result<GatewayId, RoutingError> {
        let id = (0..=u8::MAX)
            .find(|candidate| !self.gateways.contains_key(candidate))
            .ok_or(RoutingError::Full { max: 256 })?;
        gateway.id = id;
        self.gateways.insert(id, GatewayState::new(gateway));
        if let Some(ref m) = self.metrics {
            m.set_routing_gateways_total(self.gateways.len() as u64);
        }
        tracing::info!(id, count = self.gateways.len(), "routing gateway added");
        self.apply_selected_route();
        Ok(id)
    }

    /// Remove a gateway by identifier.
    pub fn remove_gateway(&mut self, id: GatewayId) -> Result<(), RoutingError> {
        self.gateways
            .remove(&id)
            .ok_or(RoutingError::GatewayNotFound { id })?;
        if let Some(ref m) = self.metrics {
            m.set_routing_gateways_total(self.gateways.len() as u64);
        }
        tracing::info!(id, count = self.gateways.len(), "routing gateway removed");
        if self.routed_via == Some(id) {
            // The programmed next hop is gone: force a fresh install.
            self.routed_via = None;
        }
        self.apply_selected_route();
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
        let was_down = state.status == GatewayStatus::Down;
        state.record_success(threshold);
        if let Some(ref m) = self.metrics {
            m.set_routing_gateway_status(&state.gateway.name, true);
        }
        if was_down && state.status != GatewayStatus::Down {
            tracing::info!(gateway = %state.gateway.name, "gateway recovered");
        }
        tracing::debug!(gateway = %state.gateway.name, status = ?state.status, "probe success");
        self.apply_selected_route();
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
        let was_up = state.status != GatewayStatus::Down;
        state.record_failure(threshold);
        if was_up && state.status == GatewayStatus::Down {
            if let Some(ref m) = self.metrics {
                m.set_routing_gateway_status(&state.gateway.name, false);
                m.record_routing_failover();
            }
            tracing::warn!(gateway = %state.gateway.name, "gateway went down, failover triggered");
        }
        tracing::debug!(gateway = %state.gateway.name, status = ?state.status, "probe failure");
        self.apply_selected_route();
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

    /// Gateway the default route currently points at, if one was programmed.
    pub fn routed_via(&self) -> Option<GatewayId> {
        self.routed_via
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::common::error::DomainError;
    use domain::routing::entity::Gateway;
    use std::sync::Mutex;

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

    /// Records every install, and can be told to fail them.
    #[derive(Default)]
    struct RecordingRoute {
        installs: Mutex<Vec<(String, String)>>,
        fail: Mutex<bool>,
    }

    impl RecordingRoute {
        fn installs(&self) -> Vec<(String, String)> {
            self.installs.lock().unwrap().clone()
        }
    }

    impl DefaultRoutePort for RecordingRoute {
        fn replace_default_route(
            &self,
            gateway_ip: &str,
            interface: &str,
        ) -> Result<(), DomainError> {
            if *self.fail.lock().unwrap() {
                return Err(DomainError::EngineError("no CAP_NET_ADMIN".into()));
            }
            self.installs
                .lock()
                .unwrap()
                .push((gateway_ip.to_owned(), interface.to_owned()));
            Ok(())
        }
    }

    fn routed_service(route: &Arc<RecordingRoute>) -> RoutingAppService {
        let mut svc = RoutingAppService::new();
        svc.set_enabled(true);
        svc.set_route_port(Arc::clone(route) as Arc<dyn DefaultRoutePort>);
        svc
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

    #[test]
    fn add_gateway_assigns_free_id() {
        let mut svc = RoutingAppService::new();
        svc.reload_gateways(vec![make_gateway(0, 10)]).unwrap();
        let id = svc.add_gateway(make_gateway(0, 20)).unwrap();
        assert_eq!(id, 1); // 0 taken, lowest free is 1
        assert_eq!(svc.gateway_count(), 2);
    }

    #[test]
    fn the_elected_gateway_becomes_the_default_route() {
        let route = Arc::new(RecordingRoute::default());
        let mut svc = routed_service(&route);
        svc.reload_gateways(vec![make_gateway(1, 10), make_gateway(2, 20)])
            .unwrap();
        assert_eq!(route.installs(), vec![("10.0.1.1".into(), "eth1".into())]);
        assert_eq!(svc.routed_via(), Some(1));
    }

    #[test]
    fn a_failover_reprograms_the_default_route_and_a_recovery_puts_it_back() {
        let route = Arc::new(RecordingRoute::default());
        let mut svc = routed_service(&route);
        svc.reload_gateways(vec![make_gateway(1, 10), make_gateway(2, 20)])
            .unwrap();

        for _ in 0..3 {
            svc.record_probe_failure(1).unwrap();
        }
        assert_eq!(svc.routed_via(), Some(2));

        for _ in 0..2 {
            svc.record_probe_success(1).unwrap();
        }
        assert_eq!(
            route.installs(),
            vec![
                ("10.0.1.1".into(), "eth1".into()),
                ("10.0.2.1".into(), "eth2".into()),
                ("10.0.1.1".into(), "eth1".into()),
            ]
        );
        assert_eq!(svc.routed_via(), Some(1));
    }

    #[test]
    fn an_unchanged_election_programs_nothing() {
        let route = Arc::new(RecordingRoute::default());
        let mut svc = routed_service(&route);
        svc.reload_gateways(vec![make_gateway(1, 10), make_gateway(2, 20)])
            .unwrap();
        // Probes that never cross a threshold must not rewrite the route.
        for _ in 0..5 {
            svc.record_probe_success(1).unwrap();
        }
        assert_eq!(route.installs().len(), 1);
    }

    #[test]
    fn a_failed_install_is_retried_on_the_next_probe() {
        let route = Arc::new(RecordingRoute::default());
        *route.fail.lock().unwrap() = true;
        let mut svc = routed_service(&route);
        svc.reload_gateways(vec![make_gateway(1, 10)]).unwrap();
        assert_eq!(svc.routed_via(), None);
        assert!(route.installs().is_empty());

        *route.fail.lock().unwrap() = false;
        svc.record_probe_success(1).unwrap();
        assert_eq!(route.installs(), vec![("10.0.1.1".into(), "eth1".into())]);
        assert_eq!(svc.routed_via(), Some(1));
    }

    #[test]
    fn a_disabled_service_programs_nothing() {
        let route = Arc::new(RecordingRoute::default());
        let mut svc = RoutingAppService::new();
        svc.set_route_port(Arc::clone(&route) as Arc<dyn DefaultRoutePort>);
        svc.reload_gateways(vec![make_gateway(1, 10)]).unwrap();
        assert!(route.installs().is_empty());
    }

    #[test]
    fn remove_gateway_drops_and_errors_when_absent() {
        let mut svc = RoutingAppService::new();
        let id = svc.add_gateway(make_gateway(0, 10)).unwrap();
        assert_eq!(svc.gateway_count(), 1);
        svc.remove_gateway(id).unwrap();
        assert_eq!(svc.gateway_count(), 0);
        assert!(svc.remove_gateway(id).is_err());
    }
}
