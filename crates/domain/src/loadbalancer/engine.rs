use std::collections::HashMap;

use crate::common::entity::RuleId;
use crate::common::error::DomainError;

use super::entity::{LbAlgorithm, LbBackend, LbBackendState, LbService};
use super::error::LbError;

/// Maximum number of services tracked.
const MAX_SERVICES: usize = 64;

/// Internal state for a running service.
#[derive(Debug)]
struct ServiceState {
    service: LbService,
    backends: Vec<LbBackendState>,
    /// Round-robin counter (used by `RoundRobin` and as fallback for `LeastConn` in eBPF).
    rr_index: usize,
}

/// L4 load balancer engine.
///
/// Manages services and backends, selects backends according to the configured
/// algorithm, and tracks connection counts for `LeastConn`.
#[derive(Debug, Default)]
pub struct LbEngine {
    states: HashMap<String, ServiceState>,
}

impl LbEngine {
    pub fn new() -> Self {
        Self {
            states: HashMap::new(),
        }
    }

    // ── Service CRUD ──────────────────────────────────────────────

    /// Add a new service. Validates and rejects duplicates.
    pub fn add_service(&mut self, service: LbService) -> Result<(), DomainError> {
        service.validate()?;

        if self.states.contains_key(&service.id.0) {
            return Err(LbError::DuplicateService {
                id: service.id.to_string(),
            }
            .into());
        }

        if self.states.len() >= MAX_SERVICES {
            return Err(
                LbError::InvalidService("maximum service count reached".to_string()).into(),
            );
        }

        let id = service.id.0.clone();
        let backends = service
            .backends
            .iter()
            .map(|b| LbBackendState::new(b.clone()))
            .collect();

        self.states.insert(
            id,
            ServiceState {
                service,
                backends,
                rr_index: 0,
            },
        );
        Ok(())
    }

    /// Remove a service by ID.
    pub fn remove_service(&mut self, id: &RuleId) -> Result<(), DomainError> {
        self.states
            .remove(&id.0)
            .map(|_| ())
            .ok_or_else(|| LbError::ServiceNotFound { id: id.to_string() }.into())
    }

    /// Replace all services atomically.
    pub fn reload(&mut self, services: Vec<LbService>) -> Result<(), DomainError> {
        for service in &services {
            service.validate()?;
        }

        // Check for duplicate IDs
        for (i, service) in services.iter().enumerate() {
            if services[i + 1..].iter().any(|s| s.id == service.id) {
                return Err(LbError::DuplicateService {
                    id: service.id.to_string(),
                }
                .into());
            }
        }

        if services.len() > MAX_SERVICES {
            return Err(
                LbError::InvalidService("maximum service count reached".to_string()).into(),
            );
        }

        let mut new_states = HashMap::new();
        for service in services {
            let id = service.id.0.clone();
            let backends = service
                .backends
                .iter()
                .map(|b| LbBackendState::new(b.clone()))
                .collect();
            new_states.insert(
                id,
                ServiceState {
                    service,
                    backends,
                    rr_index: 0,
                },
            );
        }
        self.states = new_states;
        Ok(())
    }

    /// Return all loaded services.
    pub fn services(&self) -> Vec<&LbService> {
        self.states.values().map(|s| &s.service).collect()
    }

    /// Return the number of loaded services.
    pub fn service_count(&self) -> usize {
        self.states.len()
    }

    /// Return backend states for a service.
    pub fn backend_states(&self, service_id: &str) -> Option<&[LbBackendState]> {
        self.states.get(service_id).map(|s| s.backends.as_slice())
    }

    // ── Backend Selection ─────────────────────────────────────────

    /// Select the next backend for a service according to its algorithm.
    ///
    /// Returns `None` if no healthy backend is available.
    pub fn select_backend(
        &mut self,
        service_id: &str,
        client_addr: [u32; 4],
    ) -> Option<&LbBackend> {
        let state = self.states.get_mut(service_id)?;

        if !state.service.enabled {
            return None;
        }

        let healthy_indices: Vec<usize> = state
            .backends
            .iter()
            .enumerate()
            .filter(|(_, b)| b.is_healthy())
            .map(|(i, _)| i)
            .collect();

        if healthy_indices.is_empty() {
            return None;
        }

        let selected_idx = match state.service.algorithm {
            LbAlgorithm::RoundRobin => {
                let idx = state.rr_index % healthy_indices.len();
                state.rr_index = state.rr_index.wrapping_add(1);
                healthy_indices[idx]
            }
            LbAlgorithm::Weighted => {
                let idx = select_weighted(
                    &state.backends,
                    &healthy_indices,
                    state.rr_index,
                    client_addr,
                );
                state.rr_index = state.rr_index.wrapping_add(1);
                idx.unwrap_or(healthy_indices[0])
            }
            LbAlgorithm::IpHash => {
                let hash = fnv1a_hash(&client_addr);
                let idx = (hash as usize) % healthy_indices.len();
                healthy_indices[idx]
            }
            LbAlgorithm::LeastConn => select_least_conn(&state.backends, &healthy_indices),
        };

        Some(&state.backends[selected_idx].backend)
    }

    // ── Connection Tracking ───────────────────────────────────────

    /// Record a new connection to a backend.
    pub fn record_connection(
        &mut self,
        service_id: &str,
        backend_id: &str,
    ) -> Result<(), DomainError> {
        let state = self
            .states
            .get_mut(service_id)
            .ok_or_else(|| LbError::ServiceNotFound {
                id: service_id.to_string(),
            })?;

        let backend = state
            .backends
            .iter_mut()
            .find(|b| b.backend.id == backend_id)
            .ok_or_else(|| LbError::BackendNotFound {
                id: backend_id.to_string(),
            })?;

        backend.active_connections = backend.active_connections.saturating_add(1);
        Ok(())
    }

    /// Release a connection from a backend.
    pub fn release_connection(
        &mut self,
        service_id: &str,
        backend_id: &str,
    ) -> Result<(), DomainError> {
        let state = self
            .states
            .get_mut(service_id)
            .ok_or_else(|| LbError::ServiceNotFound {
                id: service_id.to_string(),
            })?;

        let backend = state
            .backends
            .iter_mut()
            .find(|b| b.backend.id == backend_id)
            .ok_or_else(|| LbError::BackendNotFound {
                id: backend_id.to_string(),
            })?;

        backend.active_connections = backend.active_connections.saturating_sub(1);
        Ok(())
    }

    // ── Backend Health ────────────────────────────────────────────

    /// Update backend health based on a probe result.
    pub fn update_backend_health(
        &mut self,
        service_id: &str,
        backend_id: &str,
        healthy: bool,
        threshold: u32,
    ) -> Result<(), DomainError> {
        let state = self
            .states
            .get_mut(service_id)
            .ok_or_else(|| LbError::ServiceNotFound {
                id: service_id.to_string(),
            })?;

        let backend = state
            .backends
            .iter_mut()
            .find(|b| b.backend.id == backend_id)
            .ok_or_else(|| LbError::BackendNotFound {
                id: backend_id.to_string(),
            })?;

        if healthy {
            backend.record_success(threshold);
        } else {
            backend.record_failure(threshold);
        }
        Ok(())
    }
}

// ── Algorithm Helpers ─────────────────────────────────────────────

/// FNV-1a hash of client address bytes.
fn fnv1a_hash(addr: &[u32; 4]) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for word in addr {
        for byte in word.to_le_bytes() {
            hash ^= u32::from(byte);
            hash = hash.wrapping_mul(0x0100_0193);
        }
    }
    hash
}

/// Weighted selection using cumulative weight + deterministic pseudo-random.
fn select_weighted(
    backends: &[LbBackendState],
    healthy_indices: &[usize],
    counter: usize,
    client_addr: [u32; 4],
) -> Option<usize> {
    let total_weight: u64 = healthy_indices
        .iter()
        .map(|&i| u64::from(backends[i].backend.weight))
        .sum();

    if total_weight == 0 {
        return None;
    }

    // Deterministic pseudo-random: mix counter with client addr
    #[allow(clippy::cast_possible_truncation)]
    let seed = (counter as u32) ^ client_addr[0] ^ client_addr[1];
    let pick = u64::from(seed) % total_weight;

    let mut cumulative: u64 = 0;
    for &idx in healthy_indices {
        cumulative += u64::from(backends[idx].backend.weight);
        if pick < cumulative {
            return Some(idx);
        }
    }

    Some(healthy_indices[healthy_indices.len() - 1])
}

/// Select the healthy backend with the fewest active connections.
fn select_least_conn(backends: &[LbBackendState], healthy_indices: &[usize]) -> usize {
    let mut best_idx = healthy_indices[0];
    let mut best_conns = backends[best_idx].active_connections;

    for &idx in &healthy_indices[1..] {
        if backends[idx].active_connections < best_conns {
            best_conns = backends[idx].active_connections;
            best_idx = idx;
        }
    }
    best_idx
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loadbalancer::entity::{
        LbAlgorithm, LbBackend, LbBackendStatus, LbProtocol, LbService,
    };
    use std::net::{IpAddr, Ipv4Addr};

    fn make_backend(id: &str, port: u16, weight: u32) -> LbBackend {
        LbBackend {
            id: id.to_string(),
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, port as u8)),
            port,
            weight,
            enabled: true,
        }
    }

    fn make_service(id: &str, algorithm: LbAlgorithm, backends: Vec<LbBackend>) -> LbService {
        LbService {
            id: RuleId(id.to_string()),
            name: format!("test-{id}"),
            protocol: LbProtocol::Tcp,
            listen_port: 443,
            algorithm,
            backends,
            enabled: true,
            health_check: None,
        }
    }

    fn client_addr(a: u8) -> [u32; 4] {
        [u32::from_le_bytes([192, 168, 1, a]), 0, 0, 0]
    }

    // ── Service CRUD ──────────────────────────────────────────

    #[test]
    fn engine_new_is_empty() {
        let engine = LbEngine::new();
        assert_eq!(engine.service_count(), 0);
        assert!(engine.services().is_empty());
    }

    #[test]
    fn add_and_remove_service() {
        let mut engine = LbEngine::new();
        let svc = make_service(
            "svc-1",
            LbAlgorithm::RoundRobin,
            vec![make_backend("be-1", 8080, 1)],
        );

        engine.add_service(svc).unwrap();
        assert_eq!(engine.service_count(), 1);

        engine.remove_service(&RuleId("svc-1".to_string())).unwrap();
        assert_eq!(engine.service_count(), 0);
    }

    #[test]
    fn reject_duplicate_service() {
        let mut engine = LbEngine::new();
        let svc = make_service(
            "svc-1",
            LbAlgorithm::RoundRobin,
            vec![make_backend("be-1", 8080, 1)],
        );

        engine.add_service(svc.clone()).unwrap();
        assert!(engine.add_service(svc).is_err());
    }

    #[test]
    fn remove_nonexistent_service() {
        let mut engine = LbEngine::new();
        assert!(engine.remove_service(&RuleId("nope".to_string())).is_err());
    }

    #[test]
    fn reload_services() {
        let mut engine = LbEngine::new();
        engine
            .add_service(make_service(
                "old",
                LbAlgorithm::RoundRobin,
                vec![make_backend("be-1", 8080, 1)],
            ))
            .unwrap();

        let new_services = vec![
            make_service(
                "new-1",
                LbAlgorithm::RoundRobin,
                vec![make_backend("be-1", 8080, 1)],
            ),
            make_service(
                "new-2",
                LbAlgorithm::IpHash,
                vec![make_backend("be-2", 8081, 1)],
            ),
        ];
        engine.reload(new_services).unwrap();
        assert_eq!(engine.service_count(), 2);
    }

    #[test]
    fn reload_rejects_duplicates() {
        let mut engine = LbEngine::new();
        let services = vec![
            make_service(
                "dup",
                LbAlgorithm::RoundRobin,
                vec![make_backend("be-1", 8080, 1)],
            ),
            make_service(
                "dup",
                LbAlgorithm::IpHash,
                vec![make_backend("be-2", 8081, 1)],
            ),
        ];
        assert!(engine.reload(services).is_err());
    }

    // ── RoundRobin ────────────────────────────────────────────

    #[test]
    fn round_robin_cycles_backends() {
        let mut engine = LbEngine::new();
        let svc = make_service(
            "svc-1",
            LbAlgorithm::RoundRobin,
            vec![
                make_backend("be-1", 8080, 1),
                make_backend("be-2", 8081, 1),
                make_backend("be-3", 8082, 1),
            ],
        );
        engine.add_service(svc).unwrap();

        let addr = client_addr(1);
        let b1 = engine.select_backend("svc-1", addr).unwrap().id.clone();
        let b2 = engine.select_backend("svc-1", addr).unwrap().id.clone();
        let b3 = engine.select_backend("svc-1", addr).unwrap().id.clone();
        let b4 = engine.select_backend("svc-1", addr).unwrap().id.clone();

        assert_eq!(b1, "be-1");
        assert_eq!(b2, "be-2");
        assert_eq!(b3, "be-3");
        assert_eq!(b4, "be-1"); // wraps around
    }

    #[test]
    fn round_robin_skips_unhealthy() {
        let mut engine = LbEngine::new();
        let svc = make_service(
            "svc-1",
            LbAlgorithm::RoundRobin,
            vec![make_backend("be-1", 8080, 1), make_backend("be-2", 8081, 1)],
        );
        engine.add_service(svc).unwrap();

        // Mark be-1 as unhealthy
        engine
            .update_backend_health("svc-1", "be-1", false, 1)
            .unwrap();

        let addr = client_addr(1);
        let b1 = engine.select_backend("svc-1", addr).unwrap().id.clone();
        let b2 = engine.select_backend("svc-1", addr).unwrap().id.clone();
        assert_eq!(b1, "be-2");
        assert_eq!(b2, "be-2"); // only be-2 is healthy
    }

    // ── IpHash ────────────────────────────────────────────────

    #[test]
    fn ip_hash_sticky_same_client() {
        let mut engine = LbEngine::new();
        let svc = make_service(
            "svc-1",
            LbAlgorithm::IpHash,
            vec![
                make_backend("be-1", 8080, 1),
                make_backend("be-2", 8081, 1),
                make_backend("be-3", 8082, 1),
            ],
        );
        engine.add_service(svc).unwrap();

        let addr = client_addr(42);
        let b1 = engine.select_backend("svc-1", addr).unwrap().id.clone();
        let b2 = engine.select_backend("svc-1", addr).unwrap().id.clone();
        let b3 = engine.select_backend("svc-1", addr).unwrap().id.clone();

        // Same client always gets same backend
        assert_eq!(b1, b2);
        assert_eq!(b2, b3);
    }

    #[test]
    fn ip_hash_different_clients_may_differ() {
        let mut engine = LbEngine::new();
        let svc = make_service(
            "svc-1",
            LbAlgorithm::IpHash,
            vec![
                make_backend("be-1", 8080, 1),
                make_backend("be-2", 8081, 1),
                make_backend("be-3", 8082, 1),
            ],
        );
        engine.add_service(svc).unwrap();

        // With 3 backends, at least some of many different clients should hit different backends
        let mut selected = std::collections::HashSet::new();
        for i in 0..=255u8 {
            let id = engine
                .select_backend("svc-1", client_addr(i))
                .unwrap()
                .id
                .clone();
            selected.insert(id);
        }
        // With 256 clients and 3 backends, all 3 should be hit
        assert!(selected.len() > 1);
    }

    // ── LeastConn ─────────────────────────────────────────────

    #[test]
    fn least_conn_picks_lowest() {
        let mut engine = LbEngine::new();
        let svc = make_service(
            "svc-1",
            LbAlgorithm::LeastConn,
            vec![make_backend("be-1", 8080, 1), make_backend("be-2", 8081, 1)],
        );
        engine.add_service(svc).unwrap();

        // Add connections to be-1
        engine.record_connection("svc-1", "be-1").unwrap();
        engine.record_connection("svc-1", "be-1").unwrap();
        engine.record_connection("svc-1", "be-1").unwrap();

        // be-2 has 0 connections, should be selected
        let selected = engine.select_backend("svc-1", client_addr(1)).unwrap();
        assert_eq!(selected.id, "be-2");
    }

    #[test]
    fn least_conn_picks_first_on_tie() {
        let mut engine = LbEngine::new();
        let svc = make_service(
            "svc-1",
            LbAlgorithm::LeastConn,
            vec![make_backend("be-1", 8080, 1), make_backend("be-2", 8081, 1)],
        );
        engine.add_service(svc).unwrap();

        // Both have 0 connections — should pick first healthy
        let selected = engine.select_backend("svc-1", client_addr(1)).unwrap();
        assert_eq!(selected.id, "be-1");
    }

    // ── Weighted ──────────────────────────────────────────────

    #[test]
    fn weighted_respects_weight_ratio() {
        let mut engine = LbEngine::new();
        let svc = make_service(
            "svc-1",
            LbAlgorithm::Weighted,
            vec![
                make_backend("heavy", 8080, 90),
                make_backend("light", 8081, 10),
            ],
        );
        engine.add_service(svc).unwrap();

        let mut heavy_count = 0u32;
        let mut light_count = 0u32;

        for i in 0..=255u8 {
            // Vary both counter (via repeated calls) and client addr
            let addr = client_addr(i);
            let selected = engine.select_backend("svc-1", addr).unwrap();
            if selected.id == "heavy" {
                heavy_count += 1;
            } else {
                light_count += 1;
            }
        }

        // Heavy should get significantly more traffic
        assert!(
            heavy_count > light_count,
            "heavy={heavy_count}, light={light_count}"
        );
    }

    // ── All backends unhealthy ─────────────────────────────────

    #[test]
    fn no_healthy_backend_returns_none() {
        let mut engine = LbEngine::new();
        let svc = make_service(
            "svc-1",
            LbAlgorithm::RoundRobin,
            vec![make_backend("be-1", 8080, 1), make_backend("be-2", 8081, 1)],
        );
        engine.add_service(svc).unwrap();

        engine
            .update_backend_health("svc-1", "be-1", false, 1)
            .unwrap();
        engine
            .update_backend_health("svc-1", "be-2", false, 1)
            .unwrap();

        assert!(engine.select_backend("svc-1", client_addr(1)).is_none());
    }

    #[test]
    fn disabled_service_returns_none() {
        let mut engine = LbEngine::new();
        let mut svc = make_service(
            "svc-1",
            LbAlgorithm::RoundRobin,
            vec![make_backend("be-1", 8080, 1)],
        );
        svc.enabled = false;
        engine.add_service(svc).unwrap();

        assert!(engine.select_backend("svc-1", client_addr(1)).is_none());
    }

    #[test]
    fn nonexistent_service_returns_none() {
        let mut engine = LbEngine::new();
        assert!(engine.select_backend("nope", client_addr(1)).is_none());
    }

    // ── Connection Tracking ───────────────────────────────────

    #[test]
    fn record_and_release_connection() {
        let mut engine = LbEngine::new();
        let svc = make_service(
            "svc-1",
            LbAlgorithm::RoundRobin,
            vec![make_backend("be-1", 8080, 1)],
        );
        engine.add_service(svc).unwrap();

        engine.record_connection("svc-1", "be-1").unwrap();
        engine.record_connection("svc-1", "be-1").unwrap();
        assert_eq!(
            engine.backend_states("svc-1").unwrap()[0].active_connections,
            2
        );

        engine.release_connection("svc-1", "be-1").unwrap();
        assert_eq!(
            engine.backend_states("svc-1").unwrap()[0].active_connections,
            1
        );
    }

    #[test]
    fn release_below_zero_saturates() {
        let mut engine = LbEngine::new();
        let svc = make_service(
            "svc-1",
            LbAlgorithm::RoundRobin,
            vec![make_backend("be-1", 8080, 1)],
        );
        engine.add_service(svc).unwrap();

        engine.release_connection("svc-1", "be-1").unwrap();
        assert_eq!(
            engine.backend_states("svc-1").unwrap()[0].active_connections,
            0
        );
    }

    #[test]
    fn record_connection_unknown_service() {
        let mut engine = LbEngine::new();
        assert!(engine.record_connection("nope", "be-1").is_err());
    }

    #[test]
    fn record_connection_unknown_backend() {
        let mut engine = LbEngine::new();
        let svc = make_service(
            "svc-1",
            LbAlgorithm::RoundRobin,
            vec![make_backend("be-1", 8080, 1)],
        );
        engine.add_service(svc).unwrap();
        assert!(engine.record_connection("svc-1", "nope").is_err());
    }

    // ── Backend Health ────────────────────────────────────────

    #[test]
    fn update_backend_health_transitions() {
        let mut engine = LbEngine::new();
        let svc = make_service(
            "svc-1",
            LbAlgorithm::RoundRobin,
            vec![make_backend("be-1", 8080, 1)],
        );
        engine.add_service(svc).unwrap();

        // Take down
        for _ in 0..3 {
            engine
                .update_backend_health("svc-1", "be-1", false, 3)
                .unwrap();
        }
        assert_eq!(
            engine.backend_states("svc-1").unwrap()[0].status,
            LbBackendStatus::Unhealthy
        );

        // Recover
        for _ in 0..2 {
            engine
                .update_backend_health("svc-1", "be-1", true, 2)
                .unwrap();
        }
        assert_eq!(
            engine.backend_states("svc-1").unwrap()[0].status,
            LbBackendStatus::Healthy
        );
    }

    #[test]
    fn update_health_unknown_service() {
        let mut engine = LbEngine::new();
        assert!(
            engine
                .update_backend_health("nope", "be-1", true, 1)
                .is_err()
        );
    }

    #[test]
    fn update_health_unknown_backend() {
        let mut engine = LbEngine::new();
        let svc = make_service(
            "svc-1",
            LbAlgorithm::RoundRobin,
            vec![make_backend("be-1", 8080, 1)],
        );
        engine.add_service(svc).unwrap();
        assert!(
            engine
                .update_backend_health("svc-1", "nope", true, 1)
                .is_err()
        );
    }

    // ── FNV-1a Hash ───────────────────────────────────────────

    #[test]
    fn fnv1a_deterministic() {
        let addr = client_addr(42);
        assert_eq!(fnv1a_hash(&addr), fnv1a_hash(&addr));
    }

    #[test]
    fn fnv1a_different_inputs_differ() {
        let a = fnv1a_hash(&client_addr(1));
        let b = fnv1a_hash(&client_addr(2));
        assert_ne!(a, b);
    }
}
