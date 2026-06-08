use std::net::IpAddr;

use crate::ebpf::map_store::MapStore;
use aya::maps::{HashMap, MapData, PerCpuHashMap, PerCpuValues};
use domain::common::error::DomainError;
use ebpf_common::vip::{IfaceMac, VipEntry};
use ports::secondary::vip_announcer_port::VipMapPort;
use tracing::{debug, info};

/// Manages the bounded XDP VIP announcer's eBPF maps.
///
/// * `VIP_SET` — owned VIPs keyed by the IPv4 address as a big-endian
///   numeric `u32` (same key the kernel program derives from `arp.tpa`).
/// * `IFACE_MAC` — resolved NIC MAC keyed by ifindex.
/// * `VIP_ARP_REPLIES` — per-CPU forged-reply counter keyed like `VIP_SET`.
///
/// Split-brain safety is enforced by the caller: `VIP_SET` is only
/// populated while this node is the elected speaker.
pub struct VipMapManager {
    vip_set: HashMap<MapData, u32, VipEntry>,
    iface_mac: HashMap<MapData, u32, IfaceMac>,
    arp_replies: PerCpuHashMap<MapData, u32, u64>,
}

impl VipMapManager {
    /// Take ownership of the `VIP_SET`, `IFACE_MAC`, and
    /// `VIP_ARP_REPLIES` maps from the loaded `xdp-vip-announcer` object.
    pub fn new(ebpf: &mut dyn MapStore) -> Result<Self, anyhow::Error> {
        let vip_set = HashMap::try_from(
            ebpf.take_map("VIP_SET")
                .ok_or_else(|| anyhow::anyhow!("map 'VIP_SET' not found in eBPF object"))?,
        )?;
        let iface_mac = HashMap::try_from(
            ebpf.take_map("IFACE_MAC")
                .ok_or_else(|| anyhow::anyhow!("map 'IFACE_MAC' not found in eBPF object"))?,
        )?;
        let arp_replies =
            PerCpuHashMap::try_from(ebpf.take_map("VIP_ARP_REPLIES").ok_or_else(|| {
                anyhow::anyhow!("map 'VIP_ARP_REPLIES' not found in eBPF object")
            })?)?;
        info!("VIP_SET, IFACE_MAC, VIP_ARP_REPLIES maps acquired");
        Ok(Self {
            vip_set,
            iface_mac,
            arp_replies,
        })
    }

    /// `VIP_SET` key for an address. Only IPv4 is announceable via ARP;
    /// IPv6 VIPs (ND territory) return `None` and are skipped.
    fn vip_key(addr: IpAddr) -> Option<u32> {
        match addr {
            IpAddr::V4(v4) => Some(u32::from_be_bytes(v4.octets())),
            IpAddr::V6(_) => None,
        }
    }
}

impl VipMapPort for VipMapManager {
    fn sync_vip(&mut self, addr: IpAddr) -> Result<(), DomainError> {
        let Some(key) = Self::vip_key(addr) else {
            debug!(%addr, "vip announcer: IPv6 VIP skipped (ARP is IPv4-only)");
            return Ok(());
        };
        self.vip_set
            .insert(key, VipEntry::new(), 0)
            .map_err(|e| DomainError::EngineError(format!("VIP_SET insert failed: {e}")))
    }

    fn remove_vip(&mut self, addr: IpAddr) -> Result<(), DomainError> {
        let Some(key) = Self::vip_key(addr) else {
            return Ok(());
        };
        if let Err(e) = self.vip_set.remove(&key) {
            debug!(%addr, error = %e, "VIP_SET remove (entry absent)");
        }
        Ok(())
    }

    fn clear_vips(&mut self) -> Result<(), DomainError> {
        let keys: Vec<u32> = self.vip_set.keys().filter_map(Result::ok).collect();
        for key in &keys {
            self.vip_set
                .remove(key)
                .map_err(|e| DomainError::EngineError(format!("VIP_SET clear failed: {e}")))?;
        }
        Ok(())
    }

    fn sync_iface_mac(&mut self, ifindex: u32, mac: [u8; 6]) -> Result<(), DomainError> {
        self.iface_mac
            .insert(ifindex, IfaceMac::new(mac), 0)
            .map_err(|e| DomainError::EngineError(format!("IFACE_MAC insert failed: {e}")))
    }

    fn arp_replies(&self, addr: IpAddr) -> Result<u64, DomainError> {
        let Some(key) = Self::vip_key(addr) else {
            return Ok(0);
        };
        match self.arp_replies.get(&key, 0) {
            Ok(values) => {
                let v: PerCpuValues<u64> = values;
                Ok(v.iter().sum())
            }
            // A VIP that has never been queried has no entry yet.
            Err(_) => Ok(0),
        }
    }

    fn vip_count(&self) -> Result<usize, DomainError> {
        Ok(self.vip_set.keys().filter_map(Result::ok).count())
    }
}
