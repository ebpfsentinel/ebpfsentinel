use domain::common::error::DomainError;
use ebpf_common::loadbalancer::{LbBackendEntry, LbServiceConfigV2, LbServiceKey};

/// Secondary port for load balancer eBPF map operations.
///
/// Provides a typed interface to the kernel `LB_SERVICES`, `LB_BACKENDS`,
/// and `LB_METRICS` maps. Implemented by `LbMapManager` in the adapter layer.
pub trait LoadBalancerMapPort: Send + Sync {
    /// Insert or update a service entry in the `LB_SERVICES` map.
    fn sync_service(
        &mut self,
        key: &LbServiceKey,
        config: &LbServiceConfigV2,
    ) -> Result<(), DomainError>;

    /// Remove a service entry from the `LB_SERVICES` map.
    fn remove_service(&mut self, key: &LbServiceKey) -> Result<(), DomainError>;

    /// Insert or update a backend entry in the `LB_BACKENDS` map.
    fn sync_backend(&mut self, backend_id: u32, entry: &LbBackendEntry) -> Result<(), DomainError>;

    /// Remove a backend entry from the `LB_BACKENDS` map.
    fn remove_backend(&mut self, backend_id: u32) -> Result<(), DomainError>;

    /// Update only the `healthy` field of a backend in the `LB_BACKENDS` map.
    fn update_backend_health(&mut self, backend_id: u32, healthy: bool) -> Result<(), DomainError>;

    /// Insert or update a service's Maglev lookup ring in the
    /// `LB_MAGLEV` map. `table` length must equal the Maglev ring size;
    /// each entry is a backend slot index within the service window.
    fn sync_maglev_table(&mut self, svc_index: u32, table: &[u16]) -> Result<(), DomainError>;

    /// Remove a service's Maglev ring from the `LB_MAGLEV` map.
    fn remove_maglev_table(&mut self, svc_index: u32) -> Result<(), DomainError>;

    /// Insert or update a backend's resolved MAC in the `LB_BACKEND_MAC`
    /// map (used by L2 DSR forwarding). `mac` is the 6-byte Ethernet
    /// address resolved via neighbor/ARP/ND lookup.
    fn sync_backend_mac(&mut self, backend_id: u32, mac: [u8; 6]) -> Result<(), DomainError>;

    /// Remove a backend's MAC from the `LB_BACKEND_MAC` map.
    fn remove_backend_mac(&mut self, backend_id: u32) -> Result<(), DomainError>;

    /// Remove all service and backend entries from the maps.
    fn clear_all(&mut self) -> Result<(), DomainError>;

    /// Return the number of service entries currently in the map.
    fn service_count(&self) -> Result<usize, DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loadbalancer_map_port_is_object_safe() {
        fn _check(port: &dyn LoadBalancerMapPort) {
            let _ = port.service_count();
        }
    }
}
