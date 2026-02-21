use aya::Ebpf;
use aya::maps::{Array, MapData};
use ebpf_common::config_flags::ConfigFlags;
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
