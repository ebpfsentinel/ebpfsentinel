use aya::Ebpf;
use aya::maps::{DevMap, HashMap, MapData};
use domain::common::error::DomainError;
use ebpf_common::loadbalancer::{LbBackendEntry, LbServiceConfigV2, LbServiceKey};
use ports::secondary::loadbalancer_map_port::LoadBalancerMapPort;
use tracing::{debug, info};

/// Manages the load balancer eBPF maps: `LB_SERVICES` and `LB_BACKENDS`.
///
/// Provides typed wrappers for inserting, updating, and removing service
/// and backend entries. The `LB_RR_STATE` and `LB_METRICS` maps are managed
/// by the kernel program; userspace only pushes config.
pub struct LbMapManager {
    services_map: HashMap<MapData, LbServiceKey, LbServiceConfigV2>,
    backends_map: HashMap<MapData, u32, LbBackendEntry>,
    /// DevMap for XDP redirect to backend interfaces.
    /// When populated, the eBPF program uses `redirect()` for wire-speed
    /// forwarding instead of MAC swap + XDP_TX.
    devmap: Option<DevMap<MapData>>,
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

        // DevMap is optional — only present in xdp-loadbalancer programs.
        let devmap = ebpf
            .take_map("LB_DEVMAP")
            .and_then(|m| DevMap::try_from(m).ok());
        if devmap.is_some() {
            info!("LB_DEVMAP acquired for XDP redirect forwarding");
        }

        info!("LB_SERVICES and LB_BACKENDS maps acquired");
        Ok(Self {
            services_map,
            backends_map,
            devmap,
        })
    }

    /// Insert or update a service entry.
    pub fn sync_service(
        &mut self,
        key: &LbServiceKey,
        config: &LbServiceConfigV2,
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
    /// Also populates the DevMap with the backend's resolved ifindex if available.
    pub fn sync_backend(
        &mut self,
        backend_id: u32,
        entry: &LbBackendEntry,
    ) -> Result<(), anyhow::Error> {
        self.backends_map
            .insert(backend_id, *entry, 0)
            .map_err(|e| anyhow::anyhow!("LB_BACKENDS insert failed: {e}"))?;

        // Populate DevMap for XDP redirect. Resolve ifindex from the backend IP.
        // If resolution fails, the eBPF program falls back to MAC swap + XDP_TX.
        if let Some(ref mut dm) = self.devmap {
            match resolve_ifindex_for_ip(entry.addr_v4, entry.is_ipv6 == 1) {
                Some(ifindex) => {
                    if let Err(e) = dm.set(backend_id, ifindex, None, 0) {
                        debug!(backend_id, error = %e, "LB_DEVMAP set failed (fallback to XDP_TX)");
                    }
                }
                None => {
                    debug!(
                        backend_id,
                        "no ifindex resolved for backend (fallback to XDP_TX)"
                    );
                }
            }
        }

        Ok(())
    }

    /// Remove a backend entry and its DevMap redirect.
    pub fn remove_backend(&mut self, backend_id: u32) -> Result<(), anyhow::Error> {
        self.backends_map
            .remove(&backend_id)
            .map_err(|e| anyhow::anyhow!("LB_BACKENDS remove failed: {e}"))?;
        // Clean up DevMap entry
        if let Some(ref mut dm) = self.devmap {
            let _ = dm.set(backend_id, 0, None, 0); // setting ifindex 0 effectively disables redirect
        }
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
        config: &LbServiceConfigV2,
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

/// Resolve the network interface index for a given backend IP address.
/// Uses the system routing table to determine which interface would be used
/// to reach the backend. Returns `None` if resolution fails.
fn resolve_ifindex_for_ip(addr_v4: u32, is_ipv6: bool) -> Option<u32> {
    if is_ipv6 {
        // IPv6 ifindex resolution would require parsing /proc/net/ipv6_route
        // or using netlink. For now, skip DevMap redirect for IPv6 backends.
        return None;
    }
    if addr_v4 == 0 {
        return None;
    }

    // Convert host-order u32 to IP string for route lookup
    let ip = std::net::Ipv4Addr::from(addr_v4);

    // Use `ip route get` to resolve the output interface
    let output = std::process::Command::new("ip")
        .args(["route", "get", &ip.to_string()])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Parse "... dev eth0 ..." from the output
    let dev_name = stdout
        .split_whitespace()
        .zip(stdout.split_whitespace().skip(1))
        .find(|(key, _)| *key == "dev")
        .map(|(_, val)| val)?;

    // Resolve interface name to ifindex
    let ifindex_str = std::fs::read_to_string(format!("/sys/class/net/{dev_name}/ifindex")).ok()?;
    ifindex_str.trim().parse::<u32>().ok()
}
