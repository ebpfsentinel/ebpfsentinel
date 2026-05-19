//! Bounded XDP ARP responder for load-balancer virtual IPs (VIPs).
//!
//! Kept deliberately separate from the LB hot path: it is tail-called
//! from `xdp-firewall` (slot 3) only for ARP frames. When an ARP request
//! targets an owned VIP and this node is the elected speaker, it forges
//! an ARP reply (`sha` = this node's NIC MAC) and `XDP_TX`s it back out
//! the receiving interface. No loops, fixed 28-byte ARP rewrite.
//!
//! Split-brain safety: userspace populates `VIP_SET` **only** while this
//! node is the speaker, so a standby node has an empty set and never
//! answers. Gratuitous ARP on takeover is emitted from userspace (a rare
//! event) via a raw socket — never from eBPF.

#![no_std]
#![no_main]
#![cfg_attr(target_arch = "bpf", feature(asm_experimental_arch))]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap, PerCpuArray, PerCpuHashMap},
    programs::XdpContext,
};
use ebpf_common::vip::{
    ARP_HW_ETHERNET, ARP_OP_REPLY, ARP_OP_REQUEST, IfaceMac, MAX_IFACE_MAC, MAX_SELF_BINDINGS,
    MAX_VIPS, SelfBinding, VIP_METRIC_ARP_REPLIES, VIP_METRIC_ARP_SEEN, VIP_METRIC_COUNT, VipEntry,
};
use ebpf_helpers::net::{ETH_P_8021AD, ETH_P_8021Q, ETH_P_ARP, ETH_P_IP, VLAN_HDR_LEN, VlanHdr};
use ebpf_helpers::xdp::ptr_at_mut;
use ebpf_helpers::{copy_4b_asm, copy_mac_asm, increment_metric};
use network_types::eth::EthHdr;

/// Ethernet/IPv4 ARP header (28 bytes).
#[repr(C)]
struct ArpHdr {
    htype: u16,
    ptype: u16,
    hlen: u8,
    plen: u8,
    oper: u16,
    sha: [u8; 6],
    spa: [u8; 4],
    tha: [u8; 6],
    tpa: [u8; 4],
}

/// Owned VIPs, keyed by the VIP IPv4 as a big-endian numeric `u32`.
/// Populated by userspace only while this node is the elected speaker.
#[map]
static VIP_SET: HashMap<u32, VipEntry> = HashMap::with_max_entries(MAX_VIPS, 0);

/// Resolved NIC MAC per ifindex (filled by userspace via netlink).
#[map]
static IFACE_MAC: HashMap<u32, IfaceMac> = HashMap::with_max_entries(MAX_IFACE_MAC, 0);

/// Self-owned (VIP → NIC MAC) bindings, keyed like [`VIP_SET`]. Filled
/// by userspace only while this node is the elected speaker and cleared
/// on speaker loss. Authoritative source for the forged reply's `sha`
/// (per-VIP, so multi-homed VIPs answer with the right MAC); falls back
/// to [`IFACE_MAC`] when a VIP has no explicit binding yet. The later
/// ARP-guard epic reads the same map to ignore our own gratuitous ARP.
#[map]
static SELF_OWNED_BINDINGS: HashMap<u32, SelfBinding> =
    HashMap::with_max_entries(MAX_SELF_BINDINGS, 0);

/// Aggregate per-CPU counters (ARP frames seen / replies forged).
#[map]
static VIP_METRICS: PerCpuArray<u64> = PerCpuArray::with_max_entries(VIP_METRIC_COUNT, 0);

/// Per-VIP ARP reply counter for the Prometheus `{vip}` label. Same key
/// space as [`VIP_SET`].
#[map]
static VIP_ARP_REPLIES: PerCpuHashMap<u32, u64> = PerCpuHashMap::with_max_entries(MAX_VIPS, 0);

#[xdp]
pub fn xdp_vip_announcer(ctx: XdpContext) -> u32 {
    match try_announce(&ctx) {
        Ok(action) => action,
        // Default to pass on any internal error: ARP must still reach
        // the host normally.
        Err(()) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn try_announce(ctx: &XdpContext) -> Result<u32, ()> {
    let eth: *mut EthHdr = unsafe { ptr_at_mut(ctx, 0)? };
    let mut ether_type = u16::from_be(unsafe { (*eth).ether_type });
    let mut arp_off = EthHdr::LEN;

    // VLAN / QinQ unwrap (single + double tag).
    if ether_type == ETH_P_8021Q || ether_type == ETH_P_8021AD {
        let vhdr: *const VlanHdr = unsafe { ptr_at_mut(ctx, arp_off)? };
        ether_type = u16::from_be(unsafe { (*vhdr).ether_type });
        arp_off += VLAN_HDR_LEN;
        if ether_type == ETH_P_8021Q || ether_type == ETH_P_8021AD {
            let vhdr2: *const VlanHdr = unsafe { ptr_at_mut(ctx, arp_off)? };
            ether_type = u16::from_be(unsafe { (*vhdr2).ether_type });
            arp_off += VLAN_HDR_LEN;
        }
    }

    if ether_type != ETH_P_ARP {
        return Ok(xdp_action::XDP_PASS);
    }

    increment_metric!(VIP_METRICS, VIP_METRIC_ARP_SEEN);

    let arp: *mut ArpHdr = unsafe { ptr_at_mut(ctx, arp_off)? };
    // Validate Ethernet/IPv4 ARP request.
    if u16::from_be(unsafe { (*arp).htype }) != ARP_HW_ETHERNET
        || u16::from_be(unsafe { (*arp).ptype }) != ETH_P_IP
        || unsafe { (*arp).hlen } != 6
        || unsafe { (*arp).plen } != 4
        || u16::from_be(unsafe { (*arp).oper }) != ARP_OP_REQUEST
    {
        return Ok(xdp_action::XDP_PASS);
    }

    // Target protocol address (the queried IP) as a big-endian numeric u32.
    let vip_key = u32::from_be_bytes(unsafe { (*arp).tpa });

    // Not an owned VIP, or this node is standby (userspace only fills
    // VIP_SET while elected speaker) → stay silent (split-brain safe).
    if unsafe { VIP_SET.get(&vip_key) }.is_none() {
        return Ok(xdp_action::XDP_PASS);
    }

    // Resolve the MAC to answer with: prefer the per-VIP self-owned
    // binding (authoritative, set by userspace while speaker), fall
    // back to this interface's NIC MAC.
    let ifindex = unsafe { (*ctx.ctx).ingress_ifindex };
    let nic_mac = match unsafe { SELF_OWNED_BINDINGS.get(&vip_key) } {
        Some(b) => b.mac,
        None => match unsafe { IFACE_MAC.get(&ifindex) } {
            Some(m) => m.mac,
            None => return Ok(xdp_action::XDP_PASS),
        },
    };

    // ── Forge the ARP reply in place (bounded, no loop) ──
    let mut req_sha = [0u8; 6];
    let mut req_spa = [0u8; 4];
    let mut vip_pa = [0u8; 4];
    let mut eth_src = [0u8; 6];

    let arp_p = arp as *mut u8;
    let eth_p = eth as *mut u8;

    unsafe {
        // Snapshot requester identity + the queried VIP.
        copy_mac_asm!(req_sha.as_mut_ptr(), arp_p.add(8)); // sha
        copy_4b_asm!(req_spa.as_mut_ptr(), arp_p.add(14)); // spa
        copy_4b_asm!(vip_pa.as_mut_ptr(), arp_p.add(24)); // tpa (VIP)
        copy_mac_asm!(eth_src.as_mut_ptr(), eth_p.add(6)); // eth.src

        // Ethernet: dst = requester, src = our NIC MAC.
        copy_mac_asm!(eth_p, eth_src.as_ptr());
        copy_mac_asm!(eth_p.add(6), nic_mac.as_ptr());

        // ARP oper = REPLY (big-endian).
        let rep = ARP_OP_REPLY.to_be_bytes();
        *arp_p.add(6) = rep[0];
        *arp_p.add(7) = rep[1];

        // sha = our NIC MAC, spa = the VIP (was tpa).
        copy_mac_asm!(arp_p.add(8), nic_mac.as_ptr());
        copy_4b_asm!(arp_p.add(14), vip_pa.as_ptr());

        // tha = requester MAC, tpa = requester IP.
        copy_mac_asm!(arp_p.add(18), req_sha.as_ptr());
        copy_4b_asm!(arp_p.add(24), req_spa.as_ptr());
    }

    increment_metric!(VIP_METRICS, VIP_METRIC_ARP_REPLIES);
    match VIP_ARP_REPLIES.get_ptr_mut(&vip_key) {
        Some(c) => unsafe { *c += 1 },
        None => {
            let _ = VIP_ARP_REPLIES.insert(&vip_key, &1u64, 0);
        }
    }

    Ok(xdp_action::XDP_TX)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
