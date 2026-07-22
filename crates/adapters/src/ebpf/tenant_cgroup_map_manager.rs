use crate::ebpf::map_store::MapStore;
use aya::maps::{HashMap, MapData};
use tracing::info;

/// Manages `TENANT_CGROUP_MAP` eBPF `HashMap` maps across multiple programs.
///
/// Programs that resolve a tenant from the originating cgroup carry a
/// `TENANT_CGROUP_MAP` map (key = cgroup v2 id as `u64`, value = `tenant_id`
/// as `u32`). This manager collects all such maps and provides a single place
/// to update them as containers come and go.
///
/// Cgroup identification is the last resort in the kernel's resolution order
/// (VLAN → interface → subnet → cgroup), and it only yields a non-zero cgroup
/// id on the egress path, where the originating socket is still bound to the
/// skb. Ingress runs in softirq with no owning task, so an entry here never
/// affects inbound classification.
///
/// Unlike VLANs and subnets, a cgroup id is not a stable identifier: the
/// kernel reuses ids once a cgroup is destroyed. Callers own the lifecycle and
/// must drop an entry when its container goes away — hence
/// [`remove_tenant_cgroup`](Self::remove_tenant_cgroup) — otherwise a recycled
/// id would attribute a new container's traffic to the previous tenant.
pub struct TenantCgroupMapManager {
    maps: Vec<HashMap<MapData, u64, u32>>,
}

impl TenantCgroupMapManager {
    /// Create a new, empty `TenantCgroupMapManager`.
    pub fn new() -> Self {
        Self { maps: Vec::new() }
    }

    /// Take the `TENANT_CGROUP_MAP` map from the loaded eBPF program and
    /// register it for tenant cgroup updates. No-op if the map does not exist
    /// in the program (e.g. programs that do not resolve tenants by cgroup).
    pub fn add_map(&mut self, ebpf: &mut dyn MapStore) {
        if let Some(map) = ebpf.take_map("TENANT_CGROUP_MAP") {
            match HashMap::try_from(map) {
                Ok(hm) => {
                    self.maps.push(hm);
                    info!("TENANT_CGROUP_MAP map acquired");
                }
                Err(e) => {
                    tracing::warn!("TENANT_CGROUP_MAP map conversion failed: {e}");
                }
            }
        }
    }

    /// Set tenant cgroup mappings for all registered maps.
    ///
    /// `entries` is a slice of `(cgroup_id, tenant_id)` pairs. Each map is
    /// updated with every pair (existing entries are overwritten).
    ///
    /// # Errors
    ///
    /// Returns an error if an eBPF map write fails.
    pub fn set_tenant_cgroups(&mut self, entries: &[(u64, u32)]) -> Result<(), anyhow::Error> {
        for map in &mut self.maps {
            for &(cgroup_id, tenant_id) in entries {
                map.insert(cgroup_id, tenant_id, 0)
                    .map_err(|e| anyhow::anyhow!("TENANT_CGROUP_MAP insert failed: {e}"))?;
            }
        }
        if !entries.is_empty() {
            info!(
                map_count = self.maps.len(),
                cgroup_count = entries.len(),
                "TENANT_CGROUP_MAP updated"
            );
        }
        Ok(())
    }

    /// Drop one cgroup mapping from all registered maps.
    ///
    /// Call this when the container owning `cgroup_id` exits. A missing key is
    /// not an error: the entry may already be gone from a program loaded after
    /// the mapping was set, and the caller cannot tell the two cases apart.
    ///
    /// # Errors
    ///
    /// Never returns an error today — the signature mirrors
    /// [`set_tenant_cgroups`](Self::set_tenant_cgroups) so callers can handle
    /// both uniformly.
    pub fn remove_tenant_cgroup(&mut self, cgroup_id: u64) -> Result<(), anyhow::Error> {
        for map in &mut self.maps {
            // `remove` fails with ENOENT when the key was never there.
            let _ = map.remove(&cgroup_id);
        }
        info!(
            map_count = self.maps.len(),
            cgroup_id, "TENANT_CGROUP_MAP entry removed"
        );
        Ok(())
    }

    /// Return the number of registered maps.
    pub fn map_count(&self) -> usize {
        self.maps.len()
    }
}

impl Default for TenantCgroupMapManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_creates_empty_manager() {
        let mgr = TenantCgroupMapManager::new();
        assert_eq!(mgr.map_count(), 0);
    }

    #[test]
    fn default_creates_empty_manager() {
        let mgr = TenantCgroupMapManager::default();
        assert_eq!(mgr.map_count(), 0);
    }

    #[test]
    fn set_tenant_cgroups_empty_entries_is_noop() {
        let mut mgr = TenantCgroupMapManager::new();
        // No maps registered, empty entries — should succeed without error.
        let result = mgr.set_tenant_cgroups(&[]);
        assert!(result.is_ok());
    }

    #[test]
    fn set_tenant_cgroups_no_maps_succeeds() {
        let mut mgr = TenantCgroupMapManager::new();
        // Non-empty entries but no maps — loop body never executes.
        let result = mgr.set_tenant_cgroups(&[(4_294_967_296, 1), (4_294_967_297, 2)]);
        assert!(result.is_ok());
    }

    #[test]
    fn remove_tenant_cgroup_no_maps_succeeds() {
        let mut mgr = TenantCgroupMapManager::new();
        let result = mgr.remove_tenant_cgroup(4_294_967_296);
        assert!(result.is_ok());
    }
}
