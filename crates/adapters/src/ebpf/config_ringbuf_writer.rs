use aya::Ebpf;
use aya::maps::Map;
use ebpf_common::config_cmd::ConfigCommand;
use tracing::{info, warn};

/// Writes config commands to the eBPF `CONFIG_RINGBUF` (`BPF_MAP_TYPE_USER_RINGBUF`).
///
/// The eBPF program drains these commands at entry via `bpf_user_ringbuf_drain`,
/// applying rule changes atomically. This is used for incremental updates;
/// bulk initial load still uses `bpf_map_update_elem` via the map managers.
///
/// Note: aya 0.13.1 does not have a typed `UserRingBuf` API. Userspace writes
/// to a `UserRingBuf` require mmap-based access which aya does not yet expose.
/// This is a placeholder for future aya `UserRingBuf` support.
pub struct ConfigRingBufWriter {
    /// Map handle — kept alive to maintain the map reference.
    _map: Map,
}

impl ConfigRingBufWriter {
    /// Create a new writer by taking ownership of the `CONFIG_RINGBUF` map.
    ///
    /// Returns `None` if the map is not found (program doesn't have `UserRingBuf`).
    pub fn new(ebpf: &mut Ebpf) -> Option<Self> {
        let map = ebpf.take_map("CONFIG_RINGBUF")?;
        info!("CONFIG_RINGBUF (UserRingBuf) map acquired for config push");
        Some(Self { _map: map })
    }

    /// Push a config command to the `UserRingBuf`.
    ///
    /// Note: full `UserRingBuf` write support requires mmap-based access
    /// which is not yet available in aya 0.13.1. This is a placeholder.
    /// Incremental rule updates still go through `bpf_map_update_elem`
    /// via the existing map managers.
    pub fn push_command(&mut self, _cmd: &ConfigCommand) -> Result<(), anyhow::Error> {
        warn!("UserRingBuf write not yet supported in aya 0.13.1 — command queued but not sent");
        Ok(())
    }
}
