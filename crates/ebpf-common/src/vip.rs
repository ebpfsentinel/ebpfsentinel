//! Shared `#[repr(C)]` types for the L2 VIP announcer (ARP responder).
//!
//! The announcer is a small, bounded XDP path — kept separate from the LB
//! hot path — that answers ARP requests for configured virtual IPs when
//! this node is the elected speaker. Userspace populates [`VIP_SET`] with
//! the owned VIPs **only while this node is the speaker**, so a standby
//! node has an empty set and never answers (split-brain safe). The node's
//! per-ifindex NIC MAC is resolved in userspace and pushed to `IFACE_MAC`.
//!
//! Map names (created by the `xdp-vip-announcer` program):
//! - `VIP_SET`     — `HashMap<u32 vip_be, VipEntry>`
//! - `IFACE_MAC`   — `HashMap<u32 ifindex, IfaceMac>`
//! - `VIP_METRICS` — `PerCpuArray<u64>` ([`VIP_METRIC_COUNT`] slots)

/// Maximum number of VIPs the announcer can own.
pub const MAX_VIPS: u32 = 256;

/// Maximum number of interfaces with a resolved NIC MAC.
pub const MAX_IFACE_MAC: u32 = 64;

/// ARP operation: request.
pub const ARP_OP_REQUEST: u16 = 1;
/// ARP operation: reply.
pub const ARP_OP_REPLY: u16 = 2;
/// ARP hardware type: Ethernet.
pub const ARP_HW_ETHERNET: u16 = 1;
/// Length of an Ethernet/IPv4 ARP header in bytes.
pub const ARP_HDR_LEN: usize = 28;

/// Per-CPU metric indices for the `VIP_METRICS` map.
pub const VIP_METRIC_ARP_SEEN: u32 = 0;
pub const VIP_METRIC_ARP_REPLIES: u32 = 1;
/// Number of `VIP_METRICS` slots.
pub const VIP_METRIC_COUNT: u32 = 2;

/// Value stored in `VIP_SET`. Presence of the key is what matters; the
/// struct carries a small flags byte for forward compatibility and to
/// keep a stable 4-byte ABI.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VipEntry {
    /// Reserved flags (0 today). Reserved for future per-VIP options.
    pub flags: u8,
    pub _pad: [u8; 3],
}

impl VipEntry {
    /// Construct an entry with no flags set.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            flags: 0,
            _pad: [0; 3],
        }
    }
}

/// Resolved NIC MAC for an interface, keyed by ifindex in `IFACE_MAC`.
/// Dedicated 8-byte type (mirrors `loadbalancer::BackendMac`) so aya's
/// `Pod` bound is satisfied without relying on a blanket impl for
/// `[u8; 6]`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IfaceMac {
    /// 6-byte Ethernet address of the interface.
    pub mac: [u8; 6],
    pub _pad: [u8; 2],
}

impl IfaceMac {
    /// Construct from a 6-byte MAC.
    #[must_use]
    pub const fn new(mac: [u8; 6]) -> Self {
        Self { mac, _pad: [0; 2] }
    }
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for VipEntry {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for IfaceMac {}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn vip_entry_layout() {
        assert_eq!(mem::size_of::<VipEntry>(), 4);
        assert_eq!(mem::align_of::<VipEntry>(), 1);
        assert_eq!(VipEntry::new(), VipEntry::default());
    }

    #[test]
    fn iface_mac_layout() {
        assert_eq!(mem::size_of::<IfaceMac>(), 8);
        assert_eq!(mem::align_of::<IfaceMac>(), 1);
        let m = IfaceMac::new([1, 2, 3, 4, 5, 6]);
        assert_eq!(m.mac, [1, 2, 3, 4, 5, 6]);
        assert_eq!(m._pad, [0, 0]);
    }

    #[test]
    fn arp_constants() {
        assert_eq!(ARP_OP_REQUEST, 1);
        assert_eq!(ARP_OP_REPLY, 2);
        assert_eq!(ARP_HDR_LEN, 28);
        assert_eq!(VIP_METRIC_COUNT, 2);
    }
}
