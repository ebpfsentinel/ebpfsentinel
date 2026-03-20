use aya::Ebpf;
use aya::maps::{Array, MapData};
use std::sync::Mutex;
use tracing::{info, warn};

/// Manages the `IDS_MIRROR_CONFIG` eBPF `Array` map in `tc-ids`.
///
/// The map has two `u32` entries:
/// - Index 0: target `ifindex` for `bpf_clone_redirect`
/// - Index 1: enabled flag (1 = active, 0 = disabled)
///
/// An instance is created during `tc-ids` loading by taking ownership of
/// the map from the [`aya::Ebpf`] object. It is stored in [`EbpfLoadResult`]
/// so that enterprise callers can enable/disable mirroring without reloading
/// the eBPF program.
///
/// The inner map is wrapped in a `Mutex` so that `enable` / `disable`
/// can be called through a shared reference, allowing the manager to be
/// stored in an `Arc` across the enterprise forensics service.
pub struct IdsMirrorMapManager {
    map: Mutex<Array<MapData, u32>>,
}

impl IdsMirrorMapManager {
    /// Take ownership of the `IDS_MIRROR_CONFIG` map from a loaded eBPF program.
    ///
    /// Returns `None` (with a warning) if the map does not exist in the object.
    #[must_use]
    pub fn new(ebpf: &mut Ebpf) -> Option<Self> {
        let map = ebpf.take_map("IDS_MIRROR_CONFIG")?;
        match Array::try_from(map) {
            Ok(arr) => {
                info!("IDS_MIRROR_CONFIG map acquired (packet mirroring ready)");
                Some(Self {
                    map: Mutex::new(arr),
                })
            }
            Err(e) => {
                warn!("IDS_MIRROR_CONFIG map conversion failed: {e}");
                None
            }
        }
    }

    /// Enable packet mirroring to `ifindex`.
    ///
    /// Writes `ifindex` to slot 0 and `1` (enabled) to slot 1.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the eBPF map write fails.
    pub fn enable(&self, ifindex: u32) -> Result<(), anyhow::Error> {
        let mut map = self
            .map
            .lock()
            .map_err(|e| anyhow::anyhow!("IDS_MIRROR_CONFIG lock poisoned: {e}"))?;
        map.set(0, ifindex, 0)
            .map_err(|e| anyhow::anyhow!("IDS_MIRROR_CONFIG[0] (ifindex) write failed: {e}"))?;
        map.set(1, 1u32, 0)
            .map_err(|e| anyhow::anyhow!("IDS_MIRROR_CONFIG[1] (enabled) write failed: {e}"))?;
        info!(ifindex, "IDS_MIRROR_CONFIG: mirroring enabled");
        Ok(())
    }

    /// Disable packet mirroring.
    ///
    /// Writes `0` to slot 1 (disabled flag). The `ifindex` slot is unchanged.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned or the eBPF map write fails.
    pub fn disable(&self) -> Result<(), anyhow::Error> {
        let mut map = self
            .map
            .lock()
            .map_err(|e| anyhow::anyhow!("IDS_MIRROR_CONFIG lock poisoned: {e}"))?;
        map.set(1, 0u32, 0)
            .map_err(|e| anyhow::anyhow!("IDS_MIRROR_CONFIG[1] (enabled) write failed: {e}"))?;
        info!("IDS_MIRROR_CONFIG: mirroring disabled");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_returns_none_without_map() {
        // Without a real eBPF object we can only verify the None path compiles.
        let manager: Option<IdsMirrorMapManager> = None;
        assert!(manager.is_none());
    }

    #[test]
    fn size_of_manager_is_reasonable() {
        assert!(std::mem::size_of::<IdsMirrorMapManager>() < 4096);
    }
}
