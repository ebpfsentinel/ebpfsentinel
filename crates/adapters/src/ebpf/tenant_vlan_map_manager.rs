use aya::Ebpf;
use aya::maps::{HashMap, MapData};
use tracing::info;

/// Manages `TENANT_VLAN_MAP` eBPF `HashMap` maps across multiple programs.
///
/// Each eBPF program that supports VLAN-based tenant identification has a
/// `TENANT_VLAN_MAP` map (key = `vlan_id` as `u32`, value = `tenant_id` as `u32`).
/// This manager collects all such maps and provides a single method
/// to update them when tenant VLAN configuration changes.
pub struct TenantVlanMapManager {
    maps: Vec<HashMap<MapData, u32, u32>>,
}

impl TenantVlanMapManager {
    /// Create a new, empty `TenantVlanMapManager`.
    pub fn new() -> Self {
        Self { maps: Vec::new() }
    }

    /// Take the `TENANT_VLAN_MAP` map from the loaded eBPF program and
    /// register it for tenant VLAN updates. No-op if the map does
    /// not exist in the program (e.g., programs that do not support
    /// VLAN-based tenant identification).
    pub fn add_map(&mut self, ebpf: &mut Ebpf) {
        if let Some(map) = ebpf.take_map("TENANT_VLAN_MAP") {
            match HashMap::try_from(map) {
                Ok(hm) => {
                    self.maps.push(hm);
                    info!("TENANT_VLAN_MAP map acquired");
                }
                Err(e) => {
                    tracing::warn!("TENANT_VLAN_MAP map conversion failed: {e}");
                }
            }
        }
    }

    /// Set tenant VLAN mappings for all registered maps.
    ///
    /// `entries` is a slice of `(vlan_id, tenant_id)` pairs.
    /// Each map is updated with every pair (existing entries are overwritten).
    /// The `vlan_id` is stored as `u32` to match the eBPF map key type,
    /// even though VLAN IDs are 12-bit values (0-4095).
    pub fn set_tenant_vlans(&mut self, entries: &[(u16, u32)]) -> Result<(), anyhow::Error> {
        for map in &mut self.maps {
            for &(vlan_id, tenant_id) in entries {
                map.insert(u32::from(vlan_id), tenant_id, 0)
                    .map_err(|e| anyhow::anyhow!("TENANT_VLAN_MAP insert failed: {e}"))?;
            }
        }
        if !entries.is_empty() {
            info!(
                map_count = self.maps.len(),
                vlan_count = entries.len(),
                "TENANT_VLAN_MAP updated"
            );
        }
        Ok(())
    }

    /// Return the number of registered maps.
    pub fn map_count(&self) -> usize {
        self.maps.len()
    }
}

impl Default for TenantVlanMapManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_creates_empty_manager() {
        let mgr = TenantVlanMapManager::new();
        assert_eq!(mgr.map_count(), 0);
    }

    #[test]
    fn default_creates_empty_manager() {
        let mgr = TenantVlanMapManager::default();
        assert_eq!(mgr.map_count(), 0);
    }

    #[test]
    fn set_tenant_vlans_empty_entries_is_noop() {
        let mut mgr = TenantVlanMapManager::new();
        // No maps registered, empty entries — should succeed without error.
        let result = mgr.set_tenant_vlans(&[]);
        assert!(result.is_ok());
    }

    #[test]
    fn set_tenant_vlans_no_maps_succeeds() {
        let mut mgr = TenantVlanMapManager::new();
        // Non-empty entries but no maps — loop body never executes.
        let result = mgr.set_tenant_vlans(&[(100, 1), (200, 2)]);
        assert!(result.is_ok());
    }
}
