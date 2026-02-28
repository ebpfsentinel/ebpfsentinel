use std::net::IpAddr;
use std::sync::Arc;

use domain::common::error::DomainError;
use domain::loadbalancer::engine::LbEngine;
use domain::loadbalancer::entity::{LbAlgorithm, LbBackend, LbProtocol, LbService};
use ebpf_common::loadbalancer::{
    LB_ALG_IP_HASH, LB_ALG_LEAST_CONN, LB_ALG_ROUND_ROBIN, LB_ALG_WEIGHTED, LB_MAX_BACKENDS,
    LbBackendEntry, LbServiceConfig, LbServiceKey,
};
use ports::secondary::loadbalancer_map_port::LoadBalancerMapPort;
use ports::secondary::metrics_port::MetricsPort;

/// Application-level load balancer service.
///
/// Orchestrates the LB domain engine, optional eBPF map sync, and metrics
/// updates. Designed to be wrapped in `RwLock` for shared access.
pub struct LbAppService {
    engine: LbEngine,
    map_port: Option<Box<dyn LoadBalancerMapPort + Send>>,
    metrics: Arc<dyn MetricsPort>,
    enabled: bool,
}

impl LbAppService {
    pub fn new(engine: LbEngine, metrics: Arc<dyn MetricsPort>) -> Self {
        Self {
            engine,
            map_port: None,
            metrics,
            enabled: false,
        }
    }

    /// Set the eBPF map port and perform an initial sync.
    pub fn set_map_port(&mut self, port: Box<dyn LoadBalancerMapPort + Send>) {
        self.map_port = Some(port);
        self.sync_ebpf_maps();
    }

    /// Return whether the load balancer is enabled.
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Set the enabled state.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Reload all services atomically.
    pub fn reload_services(&mut self, services: Vec<LbService>) -> Result<(), DomainError> {
        self.engine.reload(services)?;
        self.sync_ebpf_maps();
        self.update_metrics();
        Ok(())
    }

    /// Add a service.
    pub fn add_service(&mut self, service: LbService) -> Result<(), DomainError> {
        self.engine.add_service(service)?;
        self.sync_ebpf_maps();
        self.update_metrics();
        Ok(())
    }

    /// Remove a service by ID.
    pub fn remove_service(
        &mut self,
        id: &domain::common::entity::RuleId,
    ) -> Result<(), DomainError> {
        self.engine.remove_service(id)?;
        self.sync_ebpf_maps();
        self.update_metrics();
        Ok(())
    }

    /// Return all loaded services.
    pub fn services(&self) -> Vec<&LbService> {
        self.engine.services()
    }

    /// Return the number of loaded services.
    pub fn service_count(&self) -> usize {
        self.engine.service_count()
    }

    /// Return backend states for a given service.
    pub fn backend_states(
        &self,
        service_id: &str,
    ) -> Option<&[domain::loadbalancer::entity::LbBackendState]> {
        self.engine.backend_states(service_id)
    }

    /// Update a backend's health status and sync the eBPF map.
    pub fn update_backend_health(
        &mut self,
        service_id: &str,
        backend_id: &str,
        healthy: bool,
        threshold: u32,
    ) -> Result<(), DomainError> {
        self.engine
            .update_backend_health(service_id, backend_id, healthy, threshold)?;

        // Sync just the health flag in the eBPF map if available
        if let Some(ref mut port) = self.map_port
            && let Some(states) = self.engine.backend_states(service_id)
            && let Some(pos) = states.iter().position(|s| s.backend.id == backend_id)
        {
            #[allow(clippy::cast_possible_truncation)]
            let ebpf_id = pos as u32;
            if let Err(e) = port.update_backend_health(ebpf_id, healthy) {
                tracing::warn!(
                    service = service_id,
                    backend = backend_id,
                    "failed to sync backend health to eBPF: {e}"
                );
            }
        }

        Ok(())
    }

    /// Full-reload sync: push all engine state to eBPF maps.
    fn sync_ebpf_maps(&mut self) {
        let Some(ref mut port) = self.map_port else {
            return;
        };

        // Clear existing entries
        if let Err(e) = port.clear_all() {
            tracing::warn!("failed to clear LB eBPF maps: {e}");
            return;
        }

        // Sync all services and backends
        for service in self.engine.services() {
            if !service.enabled {
                continue;
            }

            let key = service_to_ebpf_key(service);
            let config = service_to_ebpf_config(service);

            if let Err(e) = port.sync_service(&key, &config) {
                tracing::warn!(
                    service = %service.id,
                    "failed to sync LB service to eBPF: {e}"
                );
                continue;
            }

            // Sync backends
            for (idx, backend) in service.backends.iter().enumerate() {
                let entry = backend_to_ebpf_entry(backend);
                #[allow(clippy::cast_possible_truncation)]
                let backend_id = idx as u32;
                if let Err(e) = port.sync_backend(backend_id, &entry) {
                    tracing::warn!(
                        backend = %backend.id,
                        "failed to sync LB backend to eBPF: {e}"
                    );
                }
            }
        }
    }

    fn update_metrics(&self) {
        self.metrics
            .set_rules_loaded("loadbalancer", self.engine.service_count() as u64);
    }
}

// ── Domain → eBPF Conversion ──────────────────────────────────────

fn service_to_ebpf_key(service: &LbService) -> LbServiceKey {
    let protocol = match service.protocol {
        LbProtocol::Tcp | LbProtocol::TlsPassthrough => 6, // TCP
        LbProtocol::Udp => 17,                             // UDP
    };
    LbServiceKey {
        protocol,
        _pad: 0,
        port: service.listen_port,
    }
}

fn service_to_ebpf_config(service: &LbService) -> LbServiceConfig {
    let algorithm = match service.algorithm {
        LbAlgorithm::RoundRobin => LB_ALG_ROUND_ROBIN,
        LbAlgorithm::Weighted => LB_ALG_WEIGHTED,
        LbAlgorithm::IpHash => LB_ALG_IP_HASH,
        LbAlgorithm::LeastConn => LB_ALG_LEAST_CONN,
    };

    #[allow(clippy::cast_possible_truncation)]
    let backend_count = service.backends.len().min(LB_MAX_BACKENDS) as u8;

    let mut backend_ids = [0u32; LB_MAX_BACKENDS];
    for (i, _) in service.backends.iter().enumerate().take(LB_MAX_BACKENDS) {
        #[allow(clippy::cast_possible_truncation)]
        {
            backend_ids[i] = i as u32;
        }
    }

    LbServiceConfig {
        algorithm,
        backend_count,
        _pad: [0; 2],
        backend_ids,
    }
}

fn backend_to_ebpf_entry(backend: &LbBackend) -> LbBackendEntry {
    let (addr_v4, addr_v6, is_ipv6) = match backend.addr {
        IpAddr::V4(v4) => (u32::from(v4), [0u32; 4], 0u8),
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            let addr = [
                u32::from_be_bytes([octets[0], octets[1], octets[2], octets[3]]),
                u32::from_be_bytes([octets[4], octets[5], octets[6], octets[7]]),
                u32::from_be_bytes([octets[8], octets[9], octets[10], octets[11]]),
                u32::from_be_bytes([octets[12], octets[13], octets[14], octets[15]]),
            ];
            (0u32, addr, 1u8)
        }
    };

    #[allow(clippy::cast_possible_truncation)]
    let weight = backend.weight.min(u32::from(u16::MAX)) as u16;

    LbBackendEntry {
        addr_v4,
        addr_v6,
        port: backend.port,
        weight,
        healthy: u8::from(backend.enabled),
        is_ipv6,
        _pad: [0; 2],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::common::entity::RuleId;
    use domain::loadbalancer::entity::{LbAlgorithm, LbBackend, LbProtocol, LbService};
    use ports::test_utils::NoopMetrics;
    use std::net::Ipv4Addr;

    fn make_service() -> LbAppService {
        LbAppService::new(LbEngine::new(), Arc::new(NoopMetrics))
    }

    fn make_backend(id: &str, port: u16) -> LbBackend {
        LbBackend {
            id: id.to_string(),
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            port,
            weight: 1,
            enabled: true,
        }
    }

    fn make_lb_service(id: &str, port: u16) -> LbService {
        LbService {
            id: RuleId(id.to_string()),
            name: format!("test-{id}"),
            protocol: LbProtocol::Tcp,
            listen_port: port,
            algorithm: LbAlgorithm::RoundRobin,
            backends: vec![make_backend("be-1", 8080), make_backend("be-2", 8081)],
            enabled: true,
            health_check: None,
        }
    }

    #[test]
    fn new_service_is_empty_disabled() {
        let svc = make_service();
        assert!(!svc.enabled());
        assert_eq!(svc.service_count(), 0);
    }

    #[test]
    fn add_service_succeeds() {
        let mut svc = make_service();
        assert!(svc.add_service(make_lb_service("svc-1", 443)).is_ok());
        assert_eq!(svc.service_count(), 1);
    }

    #[test]
    fn remove_service_succeeds() {
        let mut svc = make_service();
        svc.add_service(make_lb_service("svc-1", 443)).unwrap();
        assert!(svc.remove_service(&RuleId("svc-1".to_string())).is_ok());
        assert_eq!(svc.service_count(), 0);
    }

    #[test]
    fn reload_updates_services() {
        let mut svc = make_service();
        svc.add_service(make_lb_service("old", 443)).unwrap();
        assert_eq!(svc.service_count(), 1);

        svc.reload_services(vec![
            make_lb_service("new-1", 443),
            make_lb_service("new-2", 8443),
        ])
        .unwrap();
        assert_eq!(svc.service_count(), 2);
    }

    #[test]
    fn reload_empty_clears() {
        let mut svc = make_service();
        svc.add_service(make_lb_service("svc-1", 443)).unwrap();
        svc.reload_services(vec![]).unwrap();
        assert_eq!(svc.service_count(), 0);
    }

    #[test]
    fn enabled_toggle() {
        let mut svc = make_service();
        assert!(!svc.enabled());
        svc.set_enabled(true);
        assert!(svc.enabled());
        svc.set_enabled(false);
        assert!(!svc.enabled());
    }

    #[test]
    fn add_duplicate_fails() {
        let mut svc = make_service();
        svc.add_service(make_lb_service("svc-1", 443)).unwrap();
        assert!(svc.add_service(make_lb_service("svc-1", 443)).is_err());
    }

    #[test]
    fn backend_states_accessible() {
        let mut svc = make_service();
        svc.add_service(make_lb_service("svc-1", 443)).unwrap();
        let states = svc.backend_states("svc-1").unwrap();
        assert_eq!(states.len(), 2);
    }

    #[test]
    fn backend_states_unknown_service() {
        let svc = make_service();
        assert!(svc.backend_states("nope").is_none());
    }

    // ── Conversion Tests ──────────────────────────────────────────

    #[test]
    fn service_to_ebpf_key_tcp() {
        let svc = make_lb_service("svc-1", 443);
        let key = service_to_ebpf_key(&svc);
        assert_eq!(key.protocol, 6);
        assert_eq!(key.port, 443);
    }

    #[test]
    fn service_to_ebpf_key_udp() {
        let mut svc = make_lb_service("svc-1", 53);
        svc.protocol = LbProtocol::Udp;
        let key = service_to_ebpf_key(&svc);
        assert_eq!(key.protocol, 17);
        assert_eq!(key.port, 53);
    }

    #[test]
    fn service_to_ebpf_config_round_robin() {
        let svc = make_lb_service("svc-1", 443);
        let config = service_to_ebpf_config(&svc);
        assert_eq!(config.algorithm, LB_ALG_ROUND_ROBIN);
        assert_eq!(config.backend_count, 2);
        assert_eq!(config.backend_ids[0], 0);
        assert_eq!(config.backend_ids[1], 1);
    }

    #[test]
    fn backend_to_ebpf_entry_v4() {
        let be = make_backend("be-1", 8080);
        let entry = backend_to_ebpf_entry(&be);
        assert_eq!(entry.addr_v4, u32::from(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(entry.port, 8080);
        assert_eq!(entry.weight, 1);
        assert_eq!(entry.healthy, 1);
        assert_eq!(entry.is_ipv6, 0);
    }

    #[test]
    fn backend_to_ebpf_entry_v6() {
        let be = LbBackend {
            id: "be-v6".to_string(),
            addr: IpAddr::V6("2001:db8::1".parse().unwrap()),
            port: 8080,
            weight: 10,
            enabled: true,
        };
        let entry = backend_to_ebpf_entry(&be);
        assert_eq!(entry.addr_v4, 0);
        assert_eq!(entry.is_ipv6, 1);
        assert_eq!(entry.port, 8080);
        assert_eq!(entry.weight, 10);
    }

    #[test]
    fn backend_disabled_sets_healthy_zero() {
        let mut be = make_backend("be-1", 8080);
        be.enabled = false;
        let entry = backend_to_ebpf_entry(&be);
        assert_eq!(entry.healthy, 0);
    }
}
