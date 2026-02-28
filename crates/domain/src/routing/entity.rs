use serde::{Deserialize, Serialize};

/// Unique gateway identifier (0-255).
pub type GatewayId = u8;

/// Gateway status as observed by the health-check monitor.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum GatewayStatus {
    /// Gateway is reachable and healthy.
    #[default]
    Healthy,
    /// Gateway is reachable but experiencing packet loss.
    Degraded { loss_percent: u8 },
    /// Gateway is unreachable.
    Down,
}

/// Health-check probe protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthCheckProto {
    Icmp,
    Tcp { port: u16 },
}

/// Health-check configuration for a gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    /// Probe target address (IPv4 string, e.g. `"8.8.8.8"`).
    pub target: String,
    /// Protocol to use for probes.
    pub protocol: HealthCheckProto,
    /// Probe interval in seconds.
    pub interval_secs: u32,
    /// Probe timeout in seconds.
    pub timeout_secs: u32,
    /// Number of consecutive failures before declaring gateway down.
    pub failure_threshold: u32,
    /// Number of consecutive successes before declaring gateway healthy.
    pub recovery_threshold: u32,
}

impl Default for HealthCheck {
    fn default() -> Self {
        Self {
            target: "8.8.8.8".to_string(),
            protocol: HealthCheckProto::Icmp,
            interval_secs: 10,
            timeout_secs: 5,
            failure_threshold: 3,
            recovery_threshold: 2,
        }
    }
}

/// A multi-WAN gateway definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Gateway {
    /// Unique identifier (0-255).
    pub id: GatewayId,
    /// Human-readable name.
    pub name: String,
    /// Egress interface name (e.g. `"eth1"`).
    pub interface: String,
    /// Gateway IPv4 address (e.g. `"203.0.113.1"`).
    pub gateway_ip: String,
    /// Priority (lower = preferred). Used for failover ordering.
    pub priority: u32,
    /// Whether this gateway is administratively enabled.
    pub enabled: bool,
    /// Health-check configuration.
    pub health_check: Option<HealthCheck>,
}

/// Runtime gateway state tracked by the monitoring service.
#[derive(Debug, Clone)]
pub struct GatewayState {
    pub gateway: Gateway,
    pub status: GatewayStatus,
    /// Consecutive probe failures.
    pub failure_count: u32,
    /// Consecutive probe successes (after being down).
    pub success_count: u32,
}

impl GatewayState {
    pub fn new(gateway: Gateway) -> Self {
        Self {
            gateway,
            status: GatewayStatus::Healthy,
            failure_count: 0,
            success_count: 0,
        }
    }

    /// Record a successful health-check probe.
    pub fn record_success(&mut self, recovery_threshold: u32) {
        self.failure_count = 0;
        self.success_count += 1;
        if self.status != GatewayStatus::Healthy && self.success_count >= recovery_threshold {
            self.status = GatewayStatus::Healthy;
            self.success_count = 0;
        }
    }

    /// Record a failed health-check probe.
    pub fn record_failure(&mut self, failure_threshold: u32) {
        self.success_count = 0;
        self.failure_count += 1;
        if self.failure_count >= failure_threshold {
            self.status = GatewayStatus::Down;
        }
    }

    /// Whether this gateway is usable for routing (healthy + enabled).
    pub fn is_usable(&self) -> bool {
        self.gateway.enabled && self.status != GatewayStatus::Down
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_gateway(id: u8) -> Gateway {
        Gateway {
            id,
            name: format!("gw-{id}"),
            interface: format!("eth{id}"),
            gateway_ip: format!("10.0.{id}.1"),
            priority: id as u32 * 10,
            enabled: true,
            health_check: None,
        }
    }

    #[test]
    fn new_gateway_is_healthy() {
        let state = GatewayState::new(test_gateway(1));
        assert_eq!(state.status, GatewayStatus::Healthy);
        assert!(state.is_usable());
    }

    #[test]
    fn failure_threshold_triggers_down() {
        let mut state = GatewayState::new(test_gateway(1));
        state.record_failure(3);
        assert_ne!(state.status, GatewayStatus::Down);
        state.record_failure(3);
        assert_ne!(state.status, GatewayStatus::Down);
        state.record_failure(3);
        assert_eq!(state.status, GatewayStatus::Down);
        assert!(!state.is_usable());
    }

    #[test]
    fn recovery_threshold_restores_healthy() {
        let mut state = GatewayState::new(test_gateway(1));
        // Take down
        for _ in 0..3 {
            state.record_failure(3);
        }
        assert_eq!(state.status, GatewayStatus::Down);

        // Recover
        state.record_success(2);
        assert_eq!(state.status, GatewayStatus::Down); // Not yet
        state.record_success(2);
        assert_eq!(state.status, GatewayStatus::Healthy);
    }

    #[test]
    fn success_resets_failure_count() {
        let mut state = GatewayState::new(test_gateway(1));
        state.record_failure(3);
        state.record_failure(3);
        state.record_success(2);
        assert_eq!(state.failure_count, 0);
        // Should not go down on next failure (count reset)
        state.record_failure(3);
        assert_ne!(state.status, GatewayStatus::Down);
    }

    #[test]
    fn disabled_gateway_not_usable() {
        let mut gw = test_gateway(1);
        gw.enabled = false;
        let state = GatewayState::new(gw);
        assert!(!state.is_usable());
    }
}
