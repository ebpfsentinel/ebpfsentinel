use std::net::Ipv6Addr;

use aya::Ebpf;
use aya::maps::MapData;
use aya::maps::lpm_trie::{Key, LpmTrie};
use tracing::info;

/// Manages `TENANT_SUBNET_V4` and `TENANT_SUBNET_V6` eBPF LPM trie maps
/// across multiple programs.
///
/// Each eBPF program that supports subnet-based tenant identification has
/// `TENANT_SUBNET_V4` and `TENANT_SUBNET_V6` LPM tries. This manager
/// collects all such maps and provides methods to update them when tenant
/// subnet configuration changes.
pub struct TenantSubnetMapManager {
    maps: Vec<LpmTrie<MapData, [u8; 4], u32>>,
    v6_maps: Vec<LpmTrie<MapData, [u8; 16], u32>>,
}

impl TenantSubnetMapManager {
    /// Create a new, empty `TenantSubnetMapManager`.
    pub fn new() -> Self {
        Self {
            maps: Vec::new(),
            v6_maps: Vec::new(),
        }
    }

    /// Take the `TENANT_SUBNET_V4` map from the loaded eBPF program and
    /// register it for tenant subnet updates. No-op if the map does
    /// not exist in the program.
    pub fn add_map(&mut self, ebpf: &mut Ebpf) {
        if let Some(map) = ebpf.take_map("TENANT_SUBNET_V4") {
            match LpmTrie::try_from(map) {
                Ok(trie) => {
                    self.maps.push(trie);
                    info!("TENANT_SUBNET_V4 map acquired");
                }
                Err(e) => {
                    tracing::warn!("TENANT_SUBNET_V4 map conversion failed: {e}");
                }
            }
        }
    }

    /// Take the `TENANT_SUBNET_V6` map from the loaded eBPF program and
    /// register it for IPv6 tenant subnet updates. No-op if the map does
    /// not exist in the program.
    pub fn add_v6_map(&mut self, ebpf: &mut Ebpf) {
        if let Some(map) = ebpf.take_map("TENANT_SUBNET_V6") {
            match LpmTrie::try_from(map) {
                Ok(trie) => {
                    self.v6_maps.push(trie);
                    info!("TENANT_SUBNET_V6 map acquired");
                }
                Err(e) => {
                    tracing::warn!("TENANT_SUBNET_V6 map conversion failed: {e}");
                }
            }
        }
    }

    /// Set tenant subnet mappings for all registered IPv4 maps.
    ///
    /// `entries` is a slice of `(ip_network_order, prefix_len, tenant_id)` tuples.
    /// - `ip_network_order`: IPv4 address in network byte order (`u32`)
    /// - `prefix_len`: CIDR prefix length (e.g. 16 for /16)
    /// - `tenant_id`: numeric tenant identifier
    ///
    /// Each map is updated with every entry (existing entries are overwritten).
    pub fn set_tenant_subnets(&mut self, entries: &[(u32, u8, u32)]) -> Result<(), anyhow::Error> {
        for map in &mut self.maps {
            for &(ip_nbo, prefix_len, tenant_id) in entries {
                let key = Key::new(u32::from(prefix_len), ip_nbo.to_be_bytes());
                map.insert(&key, tenant_id, 0)
                    .map_err(|e| anyhow::anyhow!("TENANT_SUBNET_V4 insert failed: {e}"))?;
            }
        }
        if !entries.is_empty() {
            info!(
                map_count = self.maps.len(),
                subnet_count = entries.len(),
                "TENANT_SUBNET_V4 updated"
            );
        }
        Ok(())
    }

    /// Set tenant subnet mappings for all registered IPv6 maps.
    ///
    /// `entries` is a slice of `(ipv6_addr, prefix_len, tenant_id)` tuples.
    /// - `ipv6_addr`: IPv6 address
    /// - `prefix_len`: CIDR prefix length (e.g. 64 for /64)
    /// - `tenant_id`: numeric tenant identifier
    ///
    /// Each map is updated with every entry (existing entries are overwritten).
    pub fn set_tenant_subnets_v6(
        &mut self,
        entries: &[(Ipv6Addr, u8, u32)],
    ) -> Result<(), anyhow::Error> {
        for map in &mut self.v6_maps {
            for &(addr, prefix_len, tenant_id) in entries {
                let key = Key::new(u32::from(prefix_len), addr.octets());
                map.insert(&key, tenant_id, 0)
                    .map_err(|e| anyhow::anyhow!("TENANT_SUBNET_V6 insert failed: {e}"))?;
            }
        }
        if !entries.is_empty() {
            info!(
                map_count = self.v6_maps.len(),
                subnet_count = entries.len(),
                "TENANT_SUBNET_V6 updated"
            );
        }
        Ok(())
    }

    /// Return the number of registered IPv4 maps.
    pub fn map_count(&self) -> usize {
        self.maps.len()
    }

    /// Return the number of registered IPv6 maps.
    pub fn v6_map_count(&self) -> usize {
        self.v6_maps.len()
    }
}

impl Default for TenantSubnetMapManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_creates_empty_manager() {
        let mgr = TenantSubnetMapManager::new();
        assert_eq!(mgr.map_count(), 0);
        assert_eq!(mgr.v6_map_count(), 0);
    }

    #[test]
    fn default_creates_empty_manager() {
        let mgr = TenantSubnetMapManager::default();
        assert_eq!(mgr.map_count(), 0);
        assert_eq!(mgr.v6_map_count(), 0);
    }

    #[test]
    fn set_tenant_subnets_empty_entries_is_noop() {
        let mut mgr = TenantSubnetMapManager::new();
        let result = mgr.set_tenant_subnets(&[]);
        assert!(result.is_ok());
    }

    #[test]
    fn set_tenant_subnets_no_maps_succeeds() {
        let mut mgr = TenantSubnetMapManager::new();
        // Non-empty entries but no maps -- loop body never executes.
        let result = mgr.set_tenant_subnets(&[(0x0A010000, 16, 1), (0xC0A80000, 24, 2)]);
        assert!(result.is_ok());
    }

    #[test]
    fn set_tenant_subnets_v6_empty_entries_is_noop() {
        let mut mgr = TenantSubnetMapManager::new();
        let result = mgr.set_tenant_subnets_v6(&[]);
        assert!(result.is_ok());
    }

    #[test]
    fn set_tenant_subnets_v6_no_maps_succeeds() {
        let mut mgr = TenantSubnetMapManager::new();
        // Non-empty entries but no V6 maps -- loop body never executes.
        let addr1: Ipv6Addr = "2001:db8::".parse().unwrap();
        let addr2: Ipv6Addr = "fd00::".parse().unwrap();
        let result = mgr.set_tenant_subnets_v6(&[(addr1, 32, 1), (addr2, 48, 2)]);
        assert!(result.is_ok());
    }
}
