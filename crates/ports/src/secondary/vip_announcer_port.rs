use std::net::IpAddr;

use domain::common::error::DomainError;
use domain::loadbalancer::vip::Vip;

/// Secondary port for the bounded XDP VIP announcer's eBPF maps.
///
/// Provides a typed interface to the kernel `VIP_SET` and `IFACE_MAC`
/// maps and the per-VIP `VIP_ARP_REPLIES` counter. Implemented by
/// `VipMapManager` in the adapter layer.
///
/// Split-brain safety: callers push the VIP set **only** while this node
/// is the elected speaker. A standby node leaves `VIP_SET` empty so the
/// XDP responder stays silent.
pub trait VipMapPort: Send + Sync {
    /// Insert or update an owned VIP in the `VIP_SET` map, keyed by the
    /// IPv4 address as a big-endian numeric `u32`.
    fn sync_vip(&mut self, addr: IpAddr) -> Result<(), DomainError>;

    /// Remove a VIP from the `VIP_SET` map.
    fn remove_vip(&mut self, addr: IpAddr) -> Result<(), DomainError>;

    /// Remove every entry from the `VIP_SET` map (used when this node
    /// transitions to standby/disabled — guarantees split-brain safety).
    fn clear_vips(&mut self) -> Result<(), DomainError>;

    /// Insert or update an interface's resolved NIC MAC in the
    /// `IFACE_MAC` map, keyed by ifindex.
    fn sync_iface_mac(&mut self, ifindex: u32, mac: [u8; 6]) -> Result<(), DomainError>;

    /// Read the cumulative forged-ARP-reply count for a VIP address
    /// (summed across CPUs). Returns 0 if the VIP has no entry yet.
    fn arp_replies(&self, addr: IpAddr) -> Result<u64, DomainError>;

    /// Number of VIP entries currently in the `VIP_SET` map.
    fn vip_count(&self) -> Result<usize, DomainError>;
}

/// Secondary port for resolving an interface's NIC MAC and ifindex.
///
/// Implemented in the adapter layer via netlink-equivalent kernel
/// queries. Reused by L2 DSR and the binding model.
pub trait IfaceMacResolverPort: Send + Sync {
    /// Resolve the ifindex of a named interface (e.g. `eth0`).
    fn ifindex(&self, interface: &str) -> Result<u32, DomainError>;

    /// Resolve the 6-byte Ethernet hardware address of a named interface.
    fn mac(&self, interface: &str) -> Result<[u8; 6], DomainError>;
}

/// Secondary port for emitting gratuitous ARP from userspace.
///
/// On speaker takeover the agent broadcasts a gratuitous ARP for every
/// owned VIP so upstream switches/hosts relearn the MAC immediately.
/// This is a rare event and intentionally never runs in eBPF.
pub trait GratuitousArpPort: Send + Sync {
    /// Broadcast a gratuitous ARP for `vip` on `interface`, sourced from
    /// `src_mac` (this node's NIC MAC). A no-op-equivalent for non-IPv4
    /// VIPs is acceptable (IPv6 uses unsolicited NA, out of scope here).
    fn send_gratuitous_arp(
        &self,
        interface: &str,
        src_mac: [u8; 6],
        vip: &Vip,
    ) -> Result<(), DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vip_announcer_ports_are_object_safe() {
        fn _m(p: &dyn VipMapPort) {
            let _ = p.vip_count();
        }
        fn _r(p: &dyn IfaceMacResolverPort) {
            let _ = p.ifindex("eth0");
        }
        fn _g(_p: &dyn GratuitousArpPort) {}
    }
}
