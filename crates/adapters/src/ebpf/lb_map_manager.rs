use aya::Ebpf;
use aya::maps::{HashMap, MapData};
use domain::common::error::DomainError;
use ebpf_common::loadbalancer::{LbBackendEntry, LbServiceConfig, LbServiceKey};
use ports::secondary::loadbalancer_map_port::LoadBalancerMapPort;
use tracing::info;

/// Manages the load balancer eBPF maps: `LB_SERVICES` and `LB_BACKENDS`.
///
/// Provides typed wrappers for inserting, updating, and removing service
/// and backend entries. The `LB_RR_STATE` and `LB_METRICS` maps are managed
/// by the kernel program; userspace only pushes config.
pub struct LbMapManager {
    services_map: HashMap<MapData, LbServiceKey, LbServiceConfig>,
    backends_map: HashMap<MapData, u32, LbBackendEntry>,
}

impl LbMapManager {
    /// Create a new `LbMapManager` by taking ownership of the
    /// `LB_SERVICES` and `LB_BACKENDS` maps from the loaded eBPF program.
    pub fn new(ebpf: &mut Ebpf) -> Result<Self, anyhow::Error> {
        let svc_map = ebpf
            .take_map("LB_SERVICES")
            .ok_or_else(|| anyhow::anyhow!("map 'LB_SERVICES' not found in eBPF object"))?;
        let services_map = HashMap::try_from(svc_map)?;

        let be_map = ebpf
            .take_map("LB_BACKENDS")
            .ok_or_else(|| anyhow::anyhow!("map 'LB_BACKENDS' not found in eBPF object"))?;
        let backends_map = HashMap::try_from(be_map)?;

        info!("LB_SERVICES and LB_BACKENDS maps acquired");
        Ok(Self {
            services_map,
            backends_map,
        })
    }

    /// Insert or update a service entry.
    pub fn sync_service(
        &mut self,
        key: &LbServiceKey,
        config: &LbServiceConfig,
    ) -> Result<(), anyhow::Error> {
        self.services_map
            .insert(*key, *config, 0)
            .map_err(|e| anyhow::anyhow!("LB_SERVICES insert failed: {e}"))?;
        Ok(())
    }

    /// Remove a service entry.
    pub fn remove_service(&mut self, key: &LbServiceKey) -> Result<(), anyhow::Error> {
        self.services_map
            .remove(key)
            .map_err(|e| anyhow::anyhow!("LB_SERVICES remove failed: {e}"))?;
        Ok(())
    }

    /// Insert or update a backend entry.
    pub fn sync_backend(
        &mut self,
        backend_id: u32,
        entry: &LbBackendEntry,
    ) -> Result<(), anyhow::Error> {
        self.backends_map
            .insert(backend_id, *entry, 0)
            .map_err(|e| anyhow::anyhow!("LB_BACKENDS insert failed: {e}"))?;
        Ok(())
    }

    /// Remove a backend entry.
    pub fn remove_backend(&mut self, backend_id: u32) -> Result<(), anyhow::Error> {
        self.backends_map
            .remove(&backend_id)
            .map_err(|e| anyhow::anyhow!("LB_BACKENDS remove failed: {e}"))?;
        Ok(())
    }

    /// Update only the `healthy` field of a backend entry.
    pub fn update_backend_health(
        &mut self,
        backend_id: u32,
        healthy: bool,
    ) -> Result<(), anyhow::Error> {
        let existing = self
            .backends_map
            .get(&backend_id, 0)
            .map_err(|e| anyhow::anyhow!("LB_BACKENDS get failed for id {backend_id}: {e}"))?;
        let mut updated = existing;
        updated.healthy = u8::from(healthy);
        self.backends_map
            .insert(backend_id, updated, 0)
            .map_err(|e| anyhow::anyhow!("LB_BACKENDS health update failed: {e}"))?;
        Ok(())
    }

    /// Remove all service and backend entries.
    pub fn clear_all(&mut self) -> Result<(), anyhow::Error> {
        let svc_keys: Vec<LbServiceKey> = self.services_map.keys().filter_map(Result::ok).collect();
        for key in &svc_keys {
            self.services_map
                .remove(key)
                .map_err(|e| anyhow::anyhow!("LB_SERVICES clear failed: {e}"))?;
        }

        let be_keys: Vec<u32> = self.backends_map.keys().filter_map(Result::ok).collect();
        for key in &be_keys {
            self.backends_map
                .remove(key)
                .map_err(|e| anyhow::anyhow!("LB_BACKENDS clear failed: {e}"))?;
        }

        Ok(())
    }

    /// Return the number of service entries in the map.
    pub fn service_count(&self) -> usize {
        self.services_map.keys().filter_map(Result::ok).count()
    }
}

impl LoadBalancerMapPort for LbMapManager {
    fn sync_service(
        &mut self,
        key: &LbServiceKey,
        config: &LbServiceConfig,
    ) -> Result<(), DomainError> {
        self.sync_service(key, config)
            .map_err(|e| DomainError::EngineError(format!("lb service sync failed: {e}")))
    }

    fn remove_service(&mut self, key: &LbServiceKey) -> Result<(), DomainError> {
        self.remove_service(key)
            .map_err(|e| DomainError::EngineError(format!("lb service remove failed: {e}")))
    }

    fn sync_backend(&mut self, backend_id: u32, entry: &LbBackendEntry) -> Result<(), DomainError> {
        self.sync_backend(backend_id, entry)
            .map_err(|e| DomainError::EngineError(format!("lb backend sync failed: {e}")))
    }

    fn remove_backend(&mut self, backend_id: u32) -> Result<(), DomainError> {
        self.remove_backend(backend_id)
            .map_err(|e| DomainError::EngineError(format!("lb backend remove failed: {e}")))
    }

    fn update_backend_health(&mut self, backend_id: u32, healthy: bool) -> Result<(), DomainError> {
        self.update_backend_health(backend_id, healthy)
            .map_err(|e| DomainError::EngineError(format!("lb backend health update failed: {e}")))
    }

    fn clear_all(&mut self) -> Result<(), DomainError> {
        self.clear_all()
            .map_err(|e| DomainError::EngineError(format!("lb clear failed: {e}")))
    }

    fn service_count(&self) -> Result<usize, DomainError> {
        Ok(self.service_count())
    }
}
