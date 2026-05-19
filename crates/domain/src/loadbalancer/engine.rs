use std::collections::HashMap;

use crate::common::entity::RuleId;
use crate::common::error::DomainError;

use super::entity::{LbAlgorithm, LbBackend, LbBackendState, LbService};
use super::error::LbError;

/// Maximum number of services tracked.
const MAX_SERVICES: usize = 64;

/// Maglev ring size. Prime, sufficiently larger than the max backend
/// count so the permutation fills every slot. Mirrors
/// `ebpf_common::loadbalancer::MAGLEV_RING_SIZE` (the adapter asserts
/// equality when converting — domain stays free of internal deps).
pub const MAGLEV_RING_SIZE: usize = 65537;

/// FNV-1a offset basis for the Maglev `offset` permutation component.
const MAGLEV_BASIS_OFFSET: u32 = 0x811c_9dc5;
/// Independent basis for the Maglev `skip` permutation component
/// (golden-ratio constant) — decorrelates the two hashes.
const MAGLEV_BASIS_SKIP: u32 = 0x9e37_79b1;

/// Cached Maglev lookup table plus the healthy-backend signature it was
/// built from. Rebuilt only when the signature changes.
#[derive(Debug)]
struct MaglevCache {
    /// Ordered backend IDs of the healthy set this table was built for.
    sig: Vec<String>,
    /// Ring of `MAGLEV_RING_SIZE` entries; each value is an index into
    /// `ServiceState::backends` (always a currently-healthy backend).
    table: Vec<u16>,
}

/// Internal state for a running service.
#[derive(Debug)]
struct ServiceState {
    service: LbService,
    backends: Vec<LbBackendState>,
    /// Round-robin counter (used by `RoundRobin` and as fallback for `LeastConn` in eBPF).
    rr_index: usize,
    /// Lazily-built Maglev table (only when algorithm is `Maglev`).
    maglev: Option<MaglevCache>,
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
                maglev: None,
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
                    maglev: None,
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
            LbAlgorithm::Maglev => {
                refresh_maglev_cache(state, &healthy_indices);
                match &state.maglev {
                    Some(c) if !c.table.is_empty() => {
                        let slot = (fnv1a_hash(&client_addr) as usize) % MAGLEV_RING_SIZE;
                        c.table[slot] as usize
                    }
                    // Unreachable in practice (healthy set non-empty here),
                    // but stay total without a panic.
                    _ => healthy_indices[0],
                }
            }
        };

        Some(&state.backends[selected_idx].backend)
    }

    /// Return the Maglev lookup ring for a service, rebuilding it from the
    /// current healthy backend set if stale. Entries are indices into the
    /// service's backend list (`0..backend_count`), matching the eBPF
    /// `backend_start_id` window. `None` if the service is unknown,
    /// disabled, not using Maglev, or has no healthy backend.
    ///
    /// Live producer for the `LB_MAGLEV` eBPF map (consumed by the
    /// loadbalancer map adapter — no dead code).
    pub fn maglev_table(&mut self, service_id: &str) -> Option<&[u16]> {
        let state = self.states.get_mut(service_id)?;
        if !state.service.enabled || state.service.algorithm != LbAlgorithm::Maglev {
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
        refresh_maglev_cache(state, &healthy_indices);
        state.maglev.as_ref().map(|c| c.table.as_slice())
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

/// Seeded FNV-1a over UTF-8 bytes of a backend identity string.
fn fnv1a_str(s: &str, basis: u32) -> u32 {
    let mut hash = basis;
    for b in s.as_bytes() {
        hash ^= u32::from(*b);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

/// Build the Maglev permutation lookup ring over the healthy backend set.
///
/// `healthy_indices[j]` is the backend-list index of the `j`-th healthy
/// backend; `keys[j]` its stable identity (used for the per-backend
/// permutation). Returns a ring of `MAGLEV_RING_SIZE` entries, each an
/// index into the backend list. With ≥1 backend every slot is filled
/// (ring size is prime and larger than any backend count).
fn build_maglev_table(healthy_indices: &[usize], keys: &[String]) -> Vec<u16> {
    const UNSET: u16 = u16::MAX;
    let m = MAGLEV_RING_SIZE;
    let n = healthy_indices.len();
    if n == 0 {
        return Vec::new();
    }

    let mut perm_offset = Vec::with_capacity(n);
    let mut perm_skip = Vec::with_capacity(n);
    for key in keys {
        let h1 = fnv1a_str(key, MAGLEV_BASIS_OFFSET) as usize;
        let h2 = fnv1a_str(key, MAGLEV_BASIS_SKIP) as usize;
        perm_offset.push(h1 % m);
        perm_skip.push(h2 % (m - 1) + 1);
    }

    let mut entry = vec![UNSET; m];
    let mut next = vec![0usize; n];
    let mut filled = 0usize;

    loop {
        for j in 0..n {
            let mut c = (perm_offset[j] + next[j] * perm_skip[j]) % m;
            while entry[c] != UNSET {
                next[j] += 1;
                c = (perm_offset[j] + next[j] * perm_skip[j]) % m;
            }
            #[allow(clippy::cast_possible_truncation)]
            {
                entry[c] = healthy_indices[j] as u16;
            }
            next[j] += 1;
            filled += 1;
            if filled == m {
                return entry;
            }
        }
    }
}

/// Rebuild the cached Maglev table iff the healthy-backend signature
/// changed since the last build (deterministic, minimal-disruption).
fn refresh_maglev_cache(state: &mut ServiceState, healthy_indices: &[usize]) {
    let sig: Vec<String> = healthy_indices
        .iter()
        .map(|&i| state.backends[i].backend.id.clone())
        .collect();
    let stale = state.maglev.as_ref().is_none_or(|c| c.sig != sig);
    if stale {
        let table = build_maglev_table(healthy_indices, &sig);
        state.maglev = Some(MaglevCache { sig, table });
    }
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

    #[allow(clippy::cast_possible_truncation)]
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

    // ── Maglev ────────────────────────────────────────────────

    fn maglev_service(id: &str, n: usize) -> LbService {
        let backends = (0..n)
            .map(|i| make_backend(&format!("be-{i}"), 8080 + i as u16, 1))
            .collect();
        make_service(id, LbAlgorithm::Maglev, backends)
    }

    #[test]
    fn maglev_table_fully_populated_no_sentinel() {
        let table = build_maglev_table(&[0, 1, 2], &["a".into(), "b".into(), "c".into()]);
        assert_eq!(table.len(), MAGLEV_RING_SIZE);
        assert!(table.iter().all(|&e| (e as usize) < 3));
    }

    #[test]
    fn maglev_table_empty_when_no_backends() {
        assert!(build_maglev_table(&[], &[]).is_empty());
    }

    #[test]
    fn maglev_deterministic_regeneration() {
        let idx = [0, 1, 2, 3, 4];
        let keys: Vec<String> = (0..5).map(|i| format!("be-{i}")).collect();
        let a = build_maglev_table(&idx, &keys);
        let b = build_maglev_table(&idx, &keys);
        assert_eq!(a, b);
    }

    #[test]
    fn maglev_single_backend_maps_everything() {
        let table = build_maglev_table(&[7], &["solo".into()]);
        assert_eq!(table.len(), MAGLEV_RING_SIZE);
        assert!(table.iter().all(|&e| e == 7));
    }

    #[test]
    #[allow(clippy::cast_precision_loss)]
    fn maglev_distribution_is_balanced() {
        let n = 5;
        let idx: Vec<usize> = (0..n).collect();
        let keys: Vec<String> = (0..n).map(|i| format!("be-{i}")).collect();
        let table = build_maglev_table(&idx, &keys);

        let mut counts = vec![0usize; n];
        for &e in &table {
            counts[e as usize] += 1;
        }
        let ideal = MAGLEV_RING_SIZE as f64 / n as f64;
        for (i, &c) in counts.iter().enumerate() {
            let dev = (c as f64 - ideal).abs() / ideal;
            assert!(dev < 0.01, "backend {i}: count={c} dev={dev:.4} > 1%");
        }
    }

    #[test]
    #[allow(clippy::cast_precision_loss)]
    fn maglev_minimal_disruption_on_backend_removal() {
        let n = 8;
        let idx: Vec<usize> = (0..n).collect();
        let keys: Vec<String> = (0..n).map(|i| format!("be-{i}")).collect();
        let before = build_maglev_table(&idx, &keys);

        // Remove the last backend (be-7): rebuild over the remaining set.
        let idx2: Vec<usize> = (0..n - 1).collect();
        let keys2: Vec<String> = (0..n - 1).map(|i| format!("be-{i}")).collect();
        let after = build_maglev_table(&idx2, &keys2);

        let removed = (n - 1) as u16;
        let mut moved_unrelated = 0usize;
        let mut still_present = 0usize;
        for slot in 0..MAGLEV_RING_SIZE {
            if before[slot] == removed {
                continue; // these MUST move — the ~1/N share
            }
            still_present += 1;
            if before[slot] != after[slot] {
                moved_unrelated += 1;
            }
        }
        let churn = moved_unrelated as f64 / still_present as f64;
        // Maglev reshuffles only a small fraction beyond the removed share.
        assert!(churn < 0.05, "unrelated churn {churn:.4} too high");
    }

    #[test]
    fn maglev_select_is_sticky_per_client() {
        let mut engine = LbEngine::new();
        engine.add_service(maglev_service("svc-1", 4)).unwrap();

        let addr = client_addr(99);
        let b1 = engine.select_backend("svc-1", addr).unwrap().id.clone();
        let b2 = engine.select_backend("svc-1", addr).unwrap().id.clone();
        let b3 = engine.select_backend("svc-1", addr).unwrap().id.clone();
        assert_eq!(b1, b2);
        assert_eq!(b2, b3);
    }

    #[test]
    fn maglev_spreads_clients_across_backends() {
        let mut engine = LbEngine::new();
        engine.add_service(maglev_service("svc-1", 4)).unwrap();

        let mut seen = std::collections::HashSet::new();
        for i in 0..=255u8 {
            seen.insert(
                engine
                    .select_backend("svc-1", client_addr(i))
                    .unwrap()
                    .id
                    .clone(),
            );
        }
        assert_eq!(seen.len(), 4, "all 4 backends should receive traffic");
    }

    #[test]
    fn maglev_skips_unhealthy_and_returns_none_when_all_down() {
        let mut engine = LbEngine::new();
        engine.add_service(maglev_service("svc-1", 3)).unwrap();

        engine
            .update_backend_health("svc-1", "be-0", false, 1)
            .unwrap();
        // Selected backend is always one of the remaining healthy ones.
        for i in 0..=64u8 {
            let id = engine
                .select_backend("svc-1", client_addr(i))
                .unwrap()
                .id
                .clone();
            assert_ne!(id, "be-0");
        }

        engine
            .update_backend_health("svc-1", "be-1", false, 1)
            .unwrap();
        engine
            .update_backend_health("svc-1", "be-2", false, 1)
            .unwrap();
        assert!(engine.select_backend("svc-1", client_addr(1)).is_none());
    }

    #[test]
    fn maglev_table_accessor_tracks_health() {
        let mut engine = LbEngine::new();
        engine.add_service(maglev_service("svc-1", 3)).unwrap();

        let t = engine.maglev_table("svc-1").unwrap();
        assert_eq!(t.len(), MAGLEV_RING_SIZE);
        assert!(t.iter().all(|&e| (e as usize) < 3));

        // Non-Maglev / unknown / disabled => None.
        engine
            .add_service(make_service(
                "rr",
                LbAlgorithm::RoundRobin,
                vec![make_backend("b", 8080, 1)],
            ))
            .unwrap();
        assert!(engine.maglev_table("rr").is_none());
        assert!(engine.maglev_table("nope").is_none());

        // All unhealthy => None.
        for be in ["be-0", "be-1", "be-2"] {
            engine.update_backend_health("svc-1", be, false, 1).unwrap();
        }
        assert!(engine.maglev_table("svc-1").is_none());
    }

    #[test]
    fn maglev_cache_rebuilds_on_health_change() {
        let mut engine = LbEngine::new();
        engine.add_service(maglev_service("svc-1", 4)).unwrap();

        let before: Vec<u16> = engine.maglev_table("svc-1").unwrap().to_vec();
        engine
            .update_backend_health("svc-1", "be-3", false, 1)
            .unwrap();
        let after = engine.maglev_table("svc-1").unwrap();
        assert_ne!(before, after, "table must rebuild when health changes");
        // be-3 (index 3) no longer appears.
        assert!(after.iter().all(|&e| e != 3));
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
