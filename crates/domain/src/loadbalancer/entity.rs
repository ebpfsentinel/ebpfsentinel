use std::collections::HashSet;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::common::entity::RuleId;
use crate::routing::entity::HealthCheck;

use super::error::LbError;

/// Load balancer protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LbProtocol {
    Tcp,
    Udp,
    TlsPassthrough,
}

impl LbProtocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::TlsPassthrough => "tls_passthrough",
        }
    }
}

impl std::fmt::Display for LbProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Load balancing algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LbAlgorithm {
    RoundRobin,
    Weighted,
    IpHash,
    LeastConn,
}

impl LbAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RoundRobin => "round_robin",
            Self::Weighted => "weighted",
            Self::IpHash => "ip_hash",
            Self::LeastConn => "least_conn",
        }
    }
}

impl std::fmt::Display for LbAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A backend server in a load balancer service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LbBackend {
    /// Unique backend identifier within the service.
    pub id: String,
    /// Backend IP address.
    pub addr: IpAddr,
    /// Backend port.
    pub port: u16,
    /// Weight for weighted balancing (higher = more traffic).
    pub weight: u32,
    /// Whether this backend is administratively enabled.
    pub enabled: bool,
}

/// A load balancer service definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LbService {
    /// Unique service identifier.
    pub id: RuleId,
    /// Human-readable name.
    pub name: String,
    /// Protocol to load balance.
    pub protocol: LbProtocol,
    /// Port to listen on for incoming traffic.
    pub listen_port: u16,
    /// Balancing algorithm.
    pub algorithm: LbAlgorithm,
    /// Backend servers.
    pub backends: Vec<LbBackend>,
    /// Whether this service is enabled.
    pub enabled: bool,
    /// Optional health check configuration for backends.
    pub health_check: Option<HealthCheck>,
}

impl LbService {
    /// Validate the service configuration.
    pub fn validate(&self) -> Result<(), LbError> {
        self.id
            .validate()
            .map_err(|e| LbError::InvalidService(e.to_string()))?;

        if self.listen_port == 0 {
            return Err(LbError::InvalidService(
                "listen_port must not be 0".to_string(),
            ));
        }

        if self.backends.is_empty() {
            return Err(LbError::InvalidService(
                "service must have at least one backend".to_string(),
            ));
        }

        let mut seen_ids = HashSet::new();
        for backend in &self.backends {
            if backend.id.is_empty() {
                return Err(LbError::InvalidBackend(
                    "backend ID must not be empty".to_string(),
                ));
            }
            if !seen_ids.insert(&backend.id) {
                return Err(LbError::InvalidBackend(format!(
                    "duplicate backend ID: {}",
                    backend.id
                )));
            }
            if backend.port == 0 {
                return Err(LbError::InvalidBackend(format!(
                    "backend '{}' port must not be 0",
                    backend.id
                )));
            }
            if backend.weight == 0 {
                return Err(LbError::InvalidBackend(format!(
                    "backend '{}' weight must be > 0",
                    backend.id
                )));
            }
        }

        Ok(())
    }
}

/// Health status of a backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LbBackendStatus {
    Healthy,
    Unhealthy,
    Draining,
}

impl LbBackendStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Unhealthy => "unhealthy",
            Self::Draining => "draining",
        }
    }
}

impl std::fmt::Display for LbBackendStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Runtime state for a backend, tracked by the engine.
#[derive(Debug, Clone)]
pub struct LbBackendState {
    pub backend: LbBackend,
    pub status: LbBackendStatus,
    pub active_connections: u64,
    pub failure_count: u32,
    pub success_count: u32,
}

impl LbBackendState {
    pub fn new(backend: LbBackend) -> Self {
        Self {
            backend,
            status: LbBackendStatus::Healthy,
            active_connections: 0,
            failure_count: 0,
            success_count: 0,
        }
    }

    /// Record a successful health probe.
    pub fn record_success(&mut self, recovery_threshold: u32) {
        self.failure_count = 0;
        self.success_count += 1;
        if self.status == LbBackendStatus::Unhealthy && self.success_count >= recovery_threshold {
            self.status = LbBackendStatus::Healthy;
            self.success_count = 0;
        }
    }

    /// Record a failed health probe.
    pub fn record_failure(&mut self, failure_threshold: u32) {
        self.success_count = 0;
        self.failure_count += 1;
        if self.failure_count >= failure_threshold {
            self.status = LbBackendStatus::Unhealthy;
        }
    }

    /// Whether this backend can receive traffic.
    pub fn is_healthy(&self) -> bool {
        self.backend.enabled && self.status == LbBackendStatus::Healthy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_backend(id: &str) -> LbBackend {
        LbBackend {
            id: id.to_string(),
            addr: IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            port: 8080,
            weight: 1,
            enabled: true,
        }
    }

    fn test_service(backends: Vec<LbBackend>) -> LbService {
        LbService {
            id: RuleId("svc-1".to_string()),
            name: "test-service".to_string(),
            protocol: LbProtocol::Tcp,
            listen_port: 443,
            algorithm: LbAlgorithm::RoundRobin,
            backends,
            enabled: true,
            health_check: None,
        }
    }

    #[test]
    fn valid_service() {
        let svc = test_service(vec![test_backend("be-1"), test_backend("be-2")]);
        assert!(svc.validate().is_ok());
    }

    #[test]
    fn reject_empty_backends() {
        let svc = test_service(vec![]);
        assert!(svc.validate().is_err());
    }

    #[test]
    fn reject_duplicate_backend_ids() {
        let svc = test_service(vec![test_backend("be-1"), test_backend("be-1")]);
        assert!(svc.validate().is_err());
    }

    #[test]
    fn reject_zero_listen_port() {
        let mut svc = test_service(vec![test_backend("be-1")]);
        svc.listen_port = 0;
        assert!(svc.validate().is_err());
    }

    #[test]
    fn reject_zero_backend_port() {
        let mut be = test_backend("be-1");
        be.port = 0;
        let svc = test_service(vec![be]);
        assert!(svc.validate().is_err());
    }

    #[test]
    fn reject_zero_weight() {
        let mut be = test_backend("be-1");
        be.weight = 0;
        let svc = test_service(vec![be]);
        assert!(svc.validate().is_err());
    }

    #[test]
    fn reject_empty_backend_id() {
        let svc = test_service(vec![test_backend("")]);
        assert!(svc.validate().is_err());
    }

    #[test]
    fn backend_state_new_is_healthy() {
        let state = LbBackendState::new(test_backend("be-1"));
        assert_eq!(state.status, LbBackendStatus::Healthy);
        assert!(state.is_healthy());
        assert_eq!(state.active_connections, 0);
    }

    #[test]
    fn backend_failure_threshold_triggers_unhealthy() {
        let mut state = LbBackendState::new(test_backend("be-1"));
        state.record_failure(3);
        assert_eq!(state.status, LbBackendStatus::Healthy);
        state.record_failure(3);
        assert_eq!(state.status, LbBackendStatus::Healthy);
        state.record_failure(3);
        assert_eq!(state.status, LbBackendStatus::Unhealthy);
        assert!(!state.is_healthy());
    }

    #[test]
    fn backend_recovery_threshold_restores_healthy() {
        let mut state = LbBackendState::new(test_backend("be-1"));
        for _ in 0..3 {
            state.record_failure(3);
        }
        assert_eq!(state.status, LbBackendStatus::Unhealthy);

        state.record_success(2);
        assert_eq!(state.status, LbBackendStatus::Unhealthy);
        state.record_success(2);
        assert_eq!(state.status, LbBackendStatus::Healthy);
    }

    #[test]
    fn success_resets_failure_count() {
        let mut state = LbBackendState::new(test_backend("be-1"));
        state.record_failure(3);
        state.record_failure(3);
        state.record_success(2);
        assert_eq!(state.failure_count, 0);
        state.record_failure(3);
        assert_eq!(state.status, LbBackendStatus::Healthy);
    }

    #[test]
    fn disabled_backend_not_healthy() {
        let mut be = test_backend("be-1");
        be.enabled = false;
        let state = LbBackendState::new(be);
        assert!(!state.is_healthy());
    }

    #[test]
    fn protocol_display() {
        assert_eq!(format!("{}", LbProtocol::Tcp), "tcp");
        assert_eq!(format!("{}", LbProtocol::Udp), "udp");
        assert_eq!(format!("{}", LbProtocol::TlsPassthrough), "tls_passthrough");
    }

    #[test]
    fn algorithm_display() {
        assert_eq!(format!("{}", LbAlgorithm::RoundRobin), "round_robin");
        assert_eq!(format!("{}", LbAlgorithm::Weighted), "weighted");
        assert_eq!(format!("{}", LbAlgorithm::IpHash), "ip_hash");
        assert_eq!(format!("{}", LbAlgorithm::LeastConn), "least_conn");
    }
}
