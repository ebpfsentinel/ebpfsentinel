use crate::ebpf::map_store::MapStore;
use aya::maps::{HashMap, MapData};
use tracing::info;

/// Manages `TENANT_IFINDEX_MAP` eBPF `HashMap` maps across multiple programs.
///
/// Each eBPF program that resolves a tenant carries a `TENANT_IFINDEX_MAP`
/// (key = ifindex, value = `tenant_id`), consulted after the VLAN map and
/// before the subnet tries. It is deliberately separate from
/// `INTERFACE_GROUPS`, which shares the same key but whose value is a group
/// bitmask: reading a bitmask as a tenant id attributes traffic on an
/// interface in group 2 to tenant 2.
pub struct TenantIfindexMapManager {
    maps: Vec<HashMap<MapData, u32, u32>>,
}

impl TenantIfindexMapManager {
    /// Create a new, empty `TenantIfindexMapManager`.
    pub fn new() -> Self {
        Self { maps: Vec::new() }
    }

    /// Take the `TENANT_IFINDEX_MAP` map from the loaded eBPF program and
    /// register it for tenant interface updates. No-op if the map does not
    /// exist in the program.
    pub fn add_map(&mut self, ebpf: &mut dyn MapStore) {
        if let Some(map) = ebpf.take_map("TENANT_IFINDEX_MAP") {
            match HashMap::try_from(map) {
                Ok(hm) => {
                    self.maps.push(hm);
                    info!("TENANT_IFINDEX_MAP map acquired");
                }
                Err(e) => {
                    tracing::warn!("TENANT_IFINDEX_MAP map conversion failed: {e}");
                }
            }
        }
    }

    /// Set tenant interface mappings for all registered maps.
    ///
    /// `entries` is a slice of `(ifindex, tenant_id)` pairs. Every registered
    /// map receives every pair, overwriting whatever an earlier call left
    /// behind for the same ifindex.
    pub fn set_tenant_interfaces(&mut self, entries: &[(u32, u32)]) -> Result<(), anyhow::Error> {
        for map in &mut self.maps {
            for &(ifindex, tenant_id) in entries {
                map.insert(ifindex, tenant_id, 0)
                    .map_err(|e| anyhow::anyhow!("TENANT_IFINDEX_MAP insert failed: {e}"))?;
            }
        }
        if !entries.is_empty() {
            info!(
                map_count = self.maps.len(),
                interface_count = entries.len(),
                "TENANT_IFINDEX_MAP updated"
            );
        }
        Ok(())
    }

    /// Drop one interface attribution from every registered map.
    ///
    /// An interface that leaves a tenant must stop resolving to it, otherwise
    /// its traffic keeps matching that tenant's rules until the agent restarts.
    /// A key that was never present is not an error.
    pub fn remove_interface(&mut self, ifindex: u32) -> Result<(), anyhow::Error> {
        for map in &mut self.maps {
            match map.remove(&ifindex) {
                Ok(()) => {}
                Err(e) => {
                    tracing::debug!(ifindex, "TENANT_IFINDEX_MAP remove skipped: {e}");
                }
            }
        }
        Ok(())
    }

    /// Return the number of registered maps.
    pub fn map_count(&self) -> usize {
        self.maps.len()
    }
}

impl Default for TenantIfindexMapManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_creates_empty_manager() {
        let mgr = TenantIfindexMapManager::new();
        assert_eq!(mgr.map_count(), 0);
    }

    #[test]
    fn default_creates_empty_manager() {
        let mgr = TenantIfindexMapManager::default();
        assert_eq!(mgr.map_count(), 0);
    }

    #[test]
    fn set_tenant_interfaces_empty_entries_is_noop() {
        let mut mgr = TenantIfindexMapManager::new();
        assert!(mgr.set_tenant_interfaces(&[]).is_ok());
    }

    #[test]
    fn set_tenant_interfaces_without_maps_succeeds() {
        let mut mgr = TenantIfindexMapManager::new();
        assert!(mgr.set_tenant_interfaces(&[(2, 1), (3, 2)]).is_ok());
    }

    #[test]
    fn removing_an_interface_without_maps_succeeds() {
        let mut mgr = TenantIfindexMapManager::new();
        assert!(mgr.remove_interface(2).is_ok());
    }
}
