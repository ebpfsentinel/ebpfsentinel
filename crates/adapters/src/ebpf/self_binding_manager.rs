use std::net::IpAddr;

use aya::Ebpf;
use aya::maps::{HashMap, MapData};
use domain::common::error::DomainError;
use domain::l2::L2Binding;
use ebpf_common::vip::SelfBinding;
use ports::secondary::l2_binding_port::L2BindingPort;
use tracing::{debug, info};

/// Manages the `SELF_OWNED_BINDINGS` eBPF map of the `xdp-vip-announcer`
/// object.
///
/// Keyed by the VIP IPv4 as a big-endian numeric `u32` — the same key
/// space the kernel responder derives from `arp.tpa` and `VIP_SET`.
/// Only the elected speaker writes here; on speaker loss the caller
/// clears every entry so a standby node owns nothing (split-brain safe).
pub struct SelfBindingManager {
    bindings: HashMap<MapData, u32, SelfBinding>,
}

impl SelfBindingManager {
    /// Take ownership of the `SELF_OWNED_BINDINGS` map from the loaded
    /// `xdp-vip-announcer` object.
    pub fn new(ebpf: &mut Ebpf) -> Result<Self, anyhow::Error> {
        let bindings =
            HashMap::try_from(ebpf.take_map("SELF_OWNED_BINDINGS").ok_or_else(|| {
                anyhow::anyhow!("map 'SELF_OWNED_BINDINGS' not found in eBPF object")
            })?)?;
        info!("SELF_OWNED_BINDINGS map acquired");
        Ok(Self { bindings })
    }

    /// Map key for an address. ARP is IPv4-only; IPv6 returns `None`
    /// and is skipped (mirrors `VipMapManager::vip_key`).
    fn key(addr: IpAddr) -> Option<u32> {
        match addr {
            IpAddr::V4(v4) => Some(u32::from_be_bytes(v4.octets())),
            IpAddr::V6(_) => None,
        }
    }
}

impl L2BindingPort for SelfBindingManager {
    fn register_binding(&mut self, binding: &L2Binding) -> Result<(), DomainError> {
        let Some(key) = Self::key(binding.ip()) else {
            debug!(ip = %binding.ip(), "self binding: IPv6 skipped (ARP is IPv4-only)");
            return Ok(());
        };
        self.bindings
            .insert(key, SelfBinding::new(binding.mac()), 0)
            .map_err(|e| {
                DomainError::EngineError(format!("SELF_OWNED_BINDINGS insert failed: {e}"))
            })
    }

    fn deregister_binding(&mut self, ip: IpAddr) -> Result<(), DomainError> {
        let Some(key) = Self::key(ip) else {
            return Ok(());
        };
        if let Err(e) = self.bindings.remove(&key) {
            debug!(%ip, error = %e, "SELF_OWNED_BINDINGS remove (entry absent)");
        }
        Ok(())
    }

    fn clear_bindings(&mut self) -> Result<(), DomainError> {
        let keys: Vec<u32> = self.bindings.keys().filter_map(Result::ok).collect();
        for key in &keys {
            self.bindings.remove(key).map_err(|e| {
                DomainError::EngineError(format!("SELF_OWNED_BINDINGS clear failed: {e}"))
            })?;
        }
        Ok(())
    }
}
