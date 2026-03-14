use aya::Ebpf;
use aya::maps::{Array, HashMap, MapData};
use ebpf_common::config_flags::ConfigFlags;
use ebpf_common::ddos::SyncookieSecret;
use ebpf_common::scrub::ScrubFlags;
use tracing::info;

/// Manages a `CONFIG_FLAGS` eBPF `Array` map.
///
/// Each eBPF program with a `CONFIG_FLAGS` map gets its own instance.
/// Stores a single `ConfigFlags` struct at index 0.
pub struct ConfigFlagsManager {
    flags_map: Array<MapData, ConfigFlags>,
}

impl ConfigFlagsManager {
    /// Create a new `ConfigFlagsManager` by taking ownership of the
    /// `CONFIG_FLAGS` map from the loaded eBPF program.
    pub fn new(ebpf: &mut Ebpf) -> Result<Self, anyhow::Error> {
        let map = ebpf
            .take_map("CONFIG_FLAGS")
            .ok_or_else(|| anyhow::anyhow!("map 'CONFIG_FLAGS' not found in eBPF object"))?;
        let flags_map = Array::try_from(map)?;
        info!("CONFIG_FLAGS map acquired");
        Ok(Self { flags_map })
    }

    /// Write the full `ConfigFlags` struct to index 0.
    pub fn set_flags(&mut self, flags: &ConfigFlags) -> Result<(), anyhow::Error> {
        self.flags_map
            .set(0, *flags, 0)
            .map_err(|e| anyhow::anyhow!("CONFIG_FLAGS set failed: {e}"))?;
        info!("CONFIG_FLAGS updated");
        Ok(())
    }

    /// Read the `ConfigFlags` struct from index 0.
    pub fn get_flags(&self) -> Result<ConfigFlags, anyhow::Error> {
        self.flags_map
            .get(&0, 0)
            .map_err(|e| anyhow::anyhow!("CONFIG_FLAGS get failed: {e}"))
    }
}

/// Manages a `SCRUB_CONFIG` eBPF `Array` map.
///
/// Stores a single `ScrubFlags` struct at index 0, controlling
/// the tc-scrub packet normalization behavior.
pub struct ScrubConfigManager {
    flags_map: Array<MapData, ScrubFlags>,
}

impl ScrubConfigManager {
    /// Create a new `ScrubConfigManager` by taking ownership of the
    /// `SCRUB_CONFIG` map from the loaded eBPF program.
    pub fn new(ebpf: &mut Ebpf) -> Result<Self, anyhow::Error> {
        let map = ebpf
            .take_map("SCRUB_CONFIG")
            .ok_or_else(|| anyhow::anyhow!("map 'SCRUB_CONFIG' not found in eBPF object"))?;
        let flags_map = Array::try_from(map)?;
        info!("SCRUB_CONFIG map acquired");
        Ok(Self { flags_map })
    }

    /// Write the `ScrubFlags` struct to index 0.
    pub fn set_flags(&mut self, flags: &ScrubFlags) -> Result<(), anyhow::Error> {
        self.flags_map
            .set(0, *flags, 0)
            .map_err(|e| anyhow::anyhow!("SCRUB_CONFIG set failed: {e}"))?;
        info!("SCRUB_CONFIG updated");
        Ok(())
    }
}

/// Manages the `SYNCOOKIE_SECRET` eBPF `Array` map.
///
/// Stores a 32-byte random key used by xdp-ratelimit for SYN cookie
/// generation and validation.
pub struct SyncookieSecretManager {
    secret_map: Array<MapData, SyncookieSecret>,
}

impl SyncookieSecretManager {
    /// Create a new manager by taking ownership of the `SYNCOOKIE_SECRET` map.
    pub fn new(ebpf: &mut Ebpf) -> Result<Self, anyhow::Error> {
        let map = ebpf
            .take_map("SYNCOOKIE_SECRET")
            .ok_or_else(|| anyhow::anyhow!("map 'SYNCOOKIE_SECRET' not found in eBPF object"))?;
        let secret_map = Array::try_from(map)?;
        info!("SYNCOOKIE_SECRET map acquired");
        Ok(Self { secret_map })
    }

    /// Write a random secret key to index 0.
    pub fn set_secret(&mut self, secret: &SyncookieSecret) -> Result<(), anyhow::Error> {
        self.secret_map
            .set(0, *secret, 0)
            .map_err(|e| anyhow::anyhow!("SYNCOOKIE_SECRET set failed: {e}"))?;
        info!("SYN cookie secret initialized");
        Ok(())
    }
}

/// Manages `INTERFACE_GROUPS` eBPF `HashMap` maps across multiple programs.
///
/// Each eBPF program that supports interface group scoping has an
/// `INTERFACE_GROUPS` map (key = ifindex, value = group bitmask).
/// This manager collects all such maps and provides a single method
/// to update them atomically when interface group configuration changes.
pub struct InterfaceGroupsManager {
    maps: Vec<HashMap<MapData, u32, u32>>,
}

impl InterfaceGroupsManager {
    /// Create a new, empty `InterfaceGroupsManager`.
    pub fn new() -> Self {
        Self { maps: Vec::new() }
    }

    /// Take the `INTERFACE_GROUPS` map from the loaded eBPF program and
    /// register it for group membership updates. No-op if the map does
    /// not exist in the program (e.g., programs that do not support groups).
    pub fn add_map(&mut self, ebpf: &mut Ebpf) {
        if let Some(map) = ebpf.take_map("INTERFACE_GROUPS") {
            match HashMap::try_from(map) {
                Ok(hm) => {
                    self.maps.push(hm);
                    info!("INTERFACE_GROUPS map acquired");
                }
                Err(e) => {
                    tracing::warn!("INTERFACE_GROUPS map conversion failed: {e}");
                }
            }
        }
    }

    /// Set interface group membership for all registered maps.
    ///
    /// `memberships` is a slice of `(ifindex, group_bitmask)` pairs.
    /// Each map is updated with every pair (existing entries are overwritten).
    pub fn set_interface_groups(
        &mut self,
        memberships: &[(u32, u32)],
    ) -> Result<(), anyhow::Error> {
        for map in &mut self.maps {
            for &(ifindex, groups) in memberships {
                map.insert(ifindex, groups, 0)
                    .map_err(|e| anyhow::anyhow!("INTERFACE_GROUPS insert failed: {e}"))?;
            }
        }
        if !memberships.is_empty() {
            info!(
                map_count = self.maps.len(),
                iface_count = memberships.len(),
                "INTERFACE_GROUPS updated"
            );
        }
        Ok(())
    }

    /// Return the number of registered maps.
    pub fn map_count(&self) -> usize {
        self.maps.len()
    }
}

impl Default for InterfaceGroupsManager {
    fn default() -> Self {
        Self::new()
    }
}
