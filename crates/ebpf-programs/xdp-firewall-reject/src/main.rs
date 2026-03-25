//! XDP firewall reject program — tail-called from `xdp-firewall` (slot 1).
//!
//! Forges TCP RST or ICMP/ICMPv6 Unreachable responses for packets matching
//! `ACTION_REJECT` rules. Runs in its own XDP entry point with a fresh
//! 512-byte stack budget, avoiding the combined-stack overflow that prevents
//! this code from running as a subprogram of `xdp-firewall`.
//!
//! Reads the `PKT_CTX` PerCpuArray (shared via BPF filesystem pinning) to
//! determine protocol, address family, and header offsets.

#![no_std]
#![no_main]
#![cfg_attr(target_arch = "bpf", feature(asm_experimental_arch))]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_xdp_adjust_tail,
    macros::{map, xdp},
    maps::PerCpuArray,
    programs::XdpContext,
};
use ebpf_common::firewall::{FIREWALL_METRIC_REJECTED, PacketCtx};
use ebpf_common::event::FLAG_IPV6;
use ebpf_helpers::checksum::{
    compute_icmp_csum, compute_icmpv6_csum, compute_ipv4_csum, compute_tcp_csum_v4,
    compute_tcp_csum_v6,
};
use ebpf_helpers::net::{Ipv6Hdr, PROTO_ICMPV6, PROTO_TCP};
use ebpf_helpers::xdp::{ptr_at, ptr_at_mut};
use ebpf_helpers::{barrier, copy_mac_asm};
use network_types::{
    eth::EthHdr,
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
};

// ── Maps (shared with xdp-firewall via BPF filesystem pinning) ──────

#[map]
static PKT_CTX: PerCpuArray<PacketCtx> = PerCpuArray::with_max_entries(1, 0);

#[map]
static FIREWALL_METRICS: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(FIREWALL_METRIC_REJECTED + 1, 0);

/// Per-CPU scratch buffer for ICMP/ICMPv6 payload (original header bytes).
/// Stored in a map instead of the stack to stay under the 512-byte limit.
/// Max 48 bytes needed (40 IPv6 + 8 L4).
#[repr(C)]
#[derive(Clone, Copy)]
struct ScratchBuf {
    data: [u8; 48],
}

#[map]
static REJECT_SCRATCH: PerCpuArray<ScratchBuf> = PerCpuArray::with_max_entries(1, 0);

// ── Entry point ─────────────────────────────────────────────────────

#[xdp]
pub fn xdp_firewall_reject(ctx: XdpContext) -> u32 {
    match try_reject(&ctx) {
        Ok(action) => action,
        Err(()) => xdp_action::XDP_DROP, // fallback: still drop on error
    }
}

#[inline(always)]
fn try_reject(ctx: &XdpContext) -> Result<u32, ()> {
    let pkt = match PKT_CTX.get_ptr(0) {
        Some(p) => p,
        None => return Err(()),
    };
    let protocol = unsafe { (*pkt).protocol };
    let flags = unsafe { (*pkt).flags };
    let is_ipv6 = (flags & FLAG_IPV6) != 0;

    // Read original offsets for READING from the incoming packet.
    let l3_off = (unsafe { (*pkt).l3_offset } as usize) & 0x3F;
    let l4_off = (unsafe { (*pkt).l4_offset } as usize) & 0x7F;

    // The reject functions read headers at original offsets, then rebuild
    // the packet at FIXED offsets (14 for L3, 14+20/40 for L4) to avoid
    // variable-offset writes that the verifier rejects.
    let result = if protocol == PROTO_TCP {
        if is_ipv6 {
            send_tcp_rst_v6(ctx, l3_off, l4_off)
        } else {
            send_tcp_rst_v4(ctx, l3_off, l4_off)
        }
    } else if is_ipv6 {
        send_icmpv6_unreachable(ctx, l3_off, l4_off)
    } else {
        send_icmp_unreachable_v4(ctx, l3_off, l4_off)
    };

    if result.is_ok() {
        increment_metric(FIREWALL_METRIC_REJECTED);
    }
    result
}

// ── Metric helper ───────────────────────────────────────────────────

#[inline(always)]
fn increment_metric(index: u32) {
    if let Some(cnt) = FIREWALL_METRICS.get_ptr_mut(index) {
        unsafe { *cnt += 1 };
    }
}

// ── TCP RST (IPv4) ──────────────────────────────────────────────────

/// Forge a TCP RST for an IPv4 packet and send via XDP_TX.
///
/// `#[inline(never)]` gives each reject variant its own stack frame so they
/// don't accumulate (only one runs per packet). The combined stack stays
/// under the 512-byte limit: entry(~24) + one reject function(~120-160).
#[inline(never)]
fn send_tcp_rst_v4(ctx: &XdpContext, l3_off: usize, l4_off: usize) -> Result<u32, ()> {
    // Step 1: Read incoming fields in ascending offset order.
    // Use copy_mac_asm! for [u8; 6] to prevent LLVM memcpy outlining.
    let ethhdr: *const EthHdr = unsafe { ptr_at(ctx, 0)? };
    let mut in_src_mac = [0u8; 6];
    let mut in_dst_mac = [0u8; 6];
    unsafe {
        let p = ethhdr as *const u8;
        copy_mac_asm!(in_dst_mac.as_mut_ptr(), p);
        copy_mac_asm!(in_src_mac.as_mut_ptr(), p.add(6));
    }

    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(ctx, l3_off)? };
    let in_src_addr = unsafe { (*ipv4hdr).src_addr };
    let in_dst_addr = unsafe { (*ipv4hdr).dst_addr };

    let tcphdr: *const TcpHdr = unsafe { ptr_at(ctx, l4_off)? };
    let in_src_port = unsafe { (*tcphdr).source };
    let in_dst_port = unsafe { (*tcphdr).dest };
    let in_seq = unsafe { (*tcphdr).seq };
    let in_ack_seq = unsafe { (*tcphdr).ack_seq };
    let in_flags: u8 = unsafe { *(tcphdr as *const u8).add(13) };

    // Step 2: Truncate to fixed Eth(14) + IP(20) + TCP(20) = 54 bytes.
    // VLAN tag (if any) is stripped — the response is a clean packet.
    const RST4_LEN: usize = 14 + 20 + 20;
    let current_len = ctx.data_end().saturating_sub(ctx.data());
    let delta = RST4_LEN as i32 - current_len as i32;
    if delta != 0 {
        let ret = unsafe { bpf_xdp_adjust_tail(ctx.ctx, delta) };
        if ret != 0 {
            return Err(());
        }
    }
    unsafe { barrier() };

    // Step 3: Re-derive pointers at CONSTANT offsets (verifier-provable).
    let eth: *mut EthHdr = unsafe { ptr_at_mut(ctx, 0)? };
    let ip: *mut Ipv4Hdr = unsafe { ptr_at_mut(ctx, 14)? };
    let tcp: *mut TcpHdr = unsafe { ptr_at_mut(ctx, 34)? };

    // Step 4: Swap MACs + set ether_type (in case original had VLAN tags).
    unsafe {
        let p = eth as *mut u8;
        copy_mac_asm!(p, in_src_mac.as_ptr());         // dst = original src
        copy_mac_asm!(p.add(6), in_dst_mac.as_ptr());  // src = original dst
        (*eth).ether_type = 0x0008u16; // ETH_P_IP in network byte order
    }

    // Step 5: Build IPv4 header (IHL=5, 20 bytes, no options).
    unsafe {
        (*ip).set_vihl(4, 20);
        (*ip).tos = 0;
        (*ip).set_tot_len(40); // 20 IP + 20 TCP
        (*ip).set_id(0);
        (*ip).set_frags(0x02, 0); // DF
        (*ip).ttl = 64;
        (*ip).proto = IpProto::Tcp;
        (*ip).src_addr = in_dst_addr; // swap
        (*ip).dst_addr = in_src_addr;
        (*ip).check = [0, 0];
        let csum = compute_ipv4_csum(ip as *const u8);
        (*ip).set_checksum(csum);
    }

    // Step 6: Build TCP RST.
    let tcp_flags_ack = in_flags & 0x10;
    let tcp_flags_syn = in_flags & 0x02;
    unsafe {
        (*tcp).source = in_dst_port;
        (*tcp).dest = in_src_port;
        if tcp_flags_ack != 0 {
            (*tcp).seq = in_ack_seq;
            (*tcp).ack_seq = [0, 0, 0, 0];
            *(tcp as *mut u8).add(13) = 0x04; // RST
        } else {
            (*tcp).seq = [0, 0, 0, 0];
            let seq_val =
                u32::from_be_bytes(in_seq).wrapping_add(if tcp_flags_syn != 0 { 1 } else { 0 });
            (*tcp).ack_seq = seq_val.to_be_bytes();
            *(tcp as *mut u8).add(13) = 0x14; // RST+ACK
        }
        *(tcp as *mut u8).add(12) = 0x50; // data offset = 5
        (*tcp).window = [0, 0];
        (*tcp).urg_ptr = [0, 0];
        (*tcp).check = [0, 0];
        let csum = compute_tcp_csum_v4(&in_dst_addr, &in_src_addr, tcp as *const u8);
        (*tcp).check = csum.to_be_bytes();
    }

    Ok(xdp_action::XDP_TX)
}

// ── TCP RST (IPv6) ──────────────────────────────────────────────────

#[inline(never)]
fn send_tcp_rst_v6(ctx: &XdpContext, l3_off: usize, l4_off: usize) -> Result<u32, ()> {
    // Step 1: Read incoming fields (ascending offset).
    let ethhdr: *const EthHdr = unsafe { ptr_at(ctx, 0)? };
    let mut in_src_mac = [0u8; 6];
    let mut in_dst_mac = [0u8; 6];
    unsafe {
        let p = ethhdr as *const u8;
        copy_mac_asm!(in_dst_mac.as_mut_ptr(), p);
        copy_mac_asm!(in_src_mac.as_mut_ptr(), p.add(6));
    }

    let ipv6hdr: *const Ipv6Hdr = unsafe { ptr_at(ctx, l3_off)? };
    let in_src_addr: [u8; 16] = unsafe { (*ipv6hdr).src_addr };
    let in_dst_addr: [u8; 16] = unsafe { (*ipv6hdr).dst_addr };

    let tcphdr: *const TcpHdr = unsafe { ptr_at(ctx, l4_off)? };
    let in_src_port = unsafe { (*tcphdr).source };
    let in_dst_port = unsafe { (*tcphdr).dest };
    let in_seq = unsafe { (*tcphdr).seq };
    let in_ack_seq = unsafe { (*tcphdr).ack_seq };
    let in_flags: u8 = unsafe { *(tcphdr as *const u8).add(13) };

    // Step 2: Truncate to fixed Eth(14) + IPv6(40) + TCP(20) = 74 bytes.
    const RST6_LEN: usize = 14 + 40 + 20;
    let current_len = ctx.data_end().saturating_sub(ctx.data());
    let delta = RST6_LEN as i32 - current_len as i32;
    if delta != 0 {
        let ret = unsafe { bpf_xdp_adjust_tail(ctx.ctx, delta) };
        if ret != 0 {
            return Err(());
        }
    }
    unsafe { barrier() };

    // Step 3: Re-derive pointers at CONSTANT offsets + swap MACs.
    let eth: *mut EthHdr = unsafe { ptr_at_mut(ctx, 0)? };
    unsafe {
        let p = eth as *mut u8;
        copy_mac_asm!(p, in_src_mac.as_ptr());
        copy_mac_asm!(p.add(6), in_dst_mac.as_ptr());
        (*eth).ether_type = 0xDD86u16; // ETH_P_IPV6 in network byte order
    }
    let ip6: *mut Ipv6Hdr = unsafe { ptr_at_mut(ctx, 14)? };
    let tcp: *mut TcpHdr = unsafe { ptr_at_mut(ctx, 54)? };

    // Step 4: Build IPv6 header.
    unsafe {
        (*ip6)._vtcfl = (6u32 << 28).to_be();
        (*ip6)._payload_len = 20u16.to_be();
        (*ip6).next_hdr = PROTO_TCP;
        (*ip6).hop_limit = 64;
        (*ip6).src_addr = in_dst_addr; // swap
        (*ip6).dst_addr = in_src_addr;
    }

    // Step 5: Build TCP RST.
    let tcp_flags_ack = in_flags & 0x10;
    let tcp_flags_syn = in_flags & 0x02;
    unsafe {
        (*tcp).source = in_dst_port;
        (*tcp).dest = in_src_port;
        if tcp_flags_ack != 0 {
            (*tcp).seq = in_ack_seq;
            (*tcp).ack_seq = [0, 0, 0, 0];
            *(tcp as *mut u8).add(13) = 0x04;
        } else {
            (*tcp).seq = [0, 0, 0, 0];
            let seq_val =
                u32::from_be_bytes(in_seq).wrapping_add(if tcp_flags_syn != 0 { 1 } else { 0 });
            (*tcp).ack_seq = seq_val.to_be_bytes();
            *(tcp as *mut u8).add(13) = 0x14;
        }
        *(tcp as *mut u8).add(12) = 0x50;
        (*tcp).window = [0, 0];
        (*tcp).urg_ptr = [0, 0];
        (*tcp).check = [0, 0];
        let csum = compute_tcp_csum_v6(&in_dst_addr, &in_src_addr, tcp as *const u8);
        (*tcp).check = csum.to_be_bytes();
    }

    Ok(xdp_action::XDP_TX)
}

// ── ICMP Destination Unreachable (IPv4) ─────────────────────────────

#[inline(never)]
fn send_icmp_unreachable_v4(
    ctx: &XdpContext,
    l3_off: usize,
    _l4_off: usize,
) -> Result<u32, ()> {
    // Step 1: Save original IP header + first 8 bytes of L4 (28 bytes)
    // into a PerCpuArray scratch buffer (not the stack) to stay under 512B.
    let scratch = match REJECT_SCRATCH.get_ptr_mut(0) {
        Some(p) => p,
        None => return Err(()),
    };
    let start = ctx.data();
    let end = ctx.data_end();
    let base = start + l3_off;
    if base + 28 > end {
        return Err(());
    }
    let base_ptr = base as *const u8;
    let mut i: usize = 0;
    while i < 28 {
        unsafe { (*scratch).data[i] = *base_ptr.add(i) };
        i += 1;
    }

    // Read MACs and IP addresses (ascending offset).
    let ethhdr: *const EthHdr = unsafe { ptr_at(ctx, 0)? };
    let mut in_src_mac = [0u8; 6];
    let mut in_dst_mac = [0u8; 6];
    unsafe {
        let p = ethhdr as *const u8;
        copy_mac_asm!(in_dst_mac.as_mut_ptr(), p);
        copy_mac_asm!(in_src_mac.as_mut_ptr(), p.add(6));
    }

    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(ctx, l3_off)? };
    let orig_src = unsafe { (*ipv4hdr).src_addr };
    let orig_dst = unsafe { (*ipv4hdr).dst_addr };

    // Step 2: Truncate to fixed Eth(14) + IP(20) + ICMP(8) + payload(28) = 70.
    const ICMP4_LEN: usize = 14 + 20 + 8 + 28;
    let current_len = ctx.data_end().saturating_sub(ctx.data());
    let delta = ICMP4_LEN as i32 - current_len as i32;
    if delta != 0 {
        let ret = unsafe { bpf_xdp_adjust_tail(ctx.ctx, delta) };
        if ret != 0 {
            return Err(());
        }
    }
    unsafe { barrier() };

    // Step 3: Re-derive at CONSTANT offsets.
    let eth: *mut EthHdr = unsafe { ptr_at_mut(ctx, 0)? };
    let ip: *mut Ipv4Hdr = unsafe { ptr_at_mut(ctx, 14)? };
    let _end: *const u8 = unsafe { ptr_at(ctx, 14 + 20 + 35)? };
    let icmp: *mut u8 = unsafe { ptr_at_mut(ctx, 34)? };

    // Step 4: Swap MACs + set ether_type.
    unsafe {
        let p = eth as *mut u8;
        copy_mac_asm!(p, in_src_mac.as_ptr());
        copy_mac_asm!(p.add(6), in_dst_mac.as_ptr());
        (*eth).ether_type = 0x0008u16; // ETH_P_IP
    }

    // Step 5: Build IPv4 header.
    unsafe {
        (*ip).set_vihl(4, 20);
        (*ip).tos = 0;
        (*ip).set_tot_len(56);
        (*ip).set_id(0);
        (*ip).set_frags(0, 0);
        (*ip).ttl = 64;
        (*ip).proto = IpProto::Icmp;
        (*ip).src_addr = orig_dst;
        (*ip).dst_addr = orig_src;
        (*ip).check = [0, 0];
        let csum = compute_ipv4_csum(ip as *const u8);
        (*ip).set_checksum(csum);
    }

    // Step 6: Build ICMP header (Type 3 = Dest Unreachable, Code 3 = Port Unreachable).
    unsafe {
        *icmp = 3;
        *icmp.add(1) = 3;
        *icmp.add(2) = 0;
        *icmp.add(3) = 0;
        *icmp.add(4) = 0;
        *icmp.add(5) = 0;
        *icmp.add(6) = 0;
        *icmp.add(7) = 0;
    }

    // Step 7: Write saved 28 bytes as ICMP payload from scratch buffer.
    let mut j: usize = 0;
    while j < 28 {
        unsafe { *icmp.add(8 + j) = (*scratch).data[j] };
        j += 1;
    }

    // Step 8: Compute ICMP checksum over 36 bytes.
    unsafe {
        let csum = compute_icmp_csum(icmp);
        let csum_be = csum.to_be_bytes();
        *icmp.add(2) = csum_be[0];
        *icmp.add(3) = csum_be[1];
    }

    Ok(xdp_action::XDP_TX)
}

// ── ICMPv6 Destination Unreachable (IPv6) ───────────────────────────

#[inline(never)]
fn send_icmpv6_unreachable(
    ctx: &XdpContext,
    l3_off: usize,
    _l4_off: usize,
) -> Result<u32, ()> {
    // Step 1: Save original IPv6 header (40) + first 8 bytes of L4 = 48 bytes
    // into scratch buffer (not stack) to stay under 512B.
    let scratch = match REJECT_SCRATCH.get_ptr_mut(0) {
        Some(p) => p,
        None => return Err(()),
    };
    let start = ctx.data();
    let end = ctx.data_end();
    let base = start + l3_off;
    if base + 48 > end {
        return Err(());
    }
    let base_ptr = base as *const u8;
    let mut i: usize = 0;
    while i < 48 {
        unsafe { (*scratch).data[i] = *base_ptr.add(i) };
        i += 1;
    }

    // Read MACs and IPv6 addresses (ascending offset).
    let ethhdr: *const EthHdr = unsafe { ptr_at(ctx, 0)? };
    let mut in_src_mac = [0u8; 6];
    let mut in_dst_mac = [0u8; 6];
    unsafe {
        let p = ethhdr as *const u8;
        copy_mac_asm!(in_dst_mac.as_mut_ptr(), p);
        copy_mac_asm!(in_src_mac.as_mut_ptr(), p.add(6));
    }

    let ipv6hdr: *const Ipv6Hdr = unsafe { ptr_at(ctx, l3_off)? };
    let orig_src: [u8; 16] = unsafe { (*ipv6hdr).src_addr };
    let orig_dst: [u8; 16] = unsafe { (*ipv6hdr).dst_addr };

    // Step 2: Truncate to fixed Eth(14) + IPv6(40) + ICMPv6(8) + payload(48) = 110.
    const ICMP6_LEN: usize = 14 + 40 + 8 + 48;
    let current_len = ctx.data_end().saturating_sub(ctx.data());
    let delta = ICMP6_LEN as i32 - current_len as i32;
    if delta != 0 {
        let ret = unsafe { bpf_xdp_adjust_tail(ctx.ctx, delta) };
        if ret != 0 {
            return Err(());
        }
    }
    unsafe { barrier() };

    // Step 3: Re-derive at CONSTANT offsets.
    let eth: *mut EthHdr = unsafe { ptr_at_mut(ctx, 0)? };
    let ip6: *mut Ipv6Hdr = unsafe { ptr_at_mut(ctx, 14)? };
    let _end: *const u8 = unsafe { ptr_at(ctx, 54 + 55)? };
    let icmp6: *mut u8 = unsafe { ptr_at_mut(ctx, 54)? };

    // Step 4: Swap MACs + set ether_type.
    unsafe {
        let p = eth as *mut u8;
        copy_mac_asm!(p, in_src_mac.as_ptr());
        copy_mac_asm!(p.add(6), in_dst_mac.as_ptr());
        (*eth).ether_type = 0xDD86u16; // ETH_P_IPV6
    }

    // Step 5: Build IPv6 header.
    unsafe {
        (*ip6)._vtcfl = (6u32 << 28).to_be();
        (*ip6)._payload_len = 56u16.to_be(); // 8 ICMPv6 hdr + 48 payload
        (*ip6).next_hdr = PROTO_ICMPV6;
        (*ip6).hop_limit = 64;
        (*ip6).src_addr = orig_dst;
        (*ip6).dst_addr = orig_src;
    }

    // Step 6: Build ICMPv6 header (Type 1 = Dest Unreachable, Code 4 = Port Unreachable).
    unsafe {
        *icmp6 = 1;
        *icmp6.add(1) = 4;
        *icmp6.add(2) = 0;
        *icmp6.add(3) = 0;
        *icmp6.add(4) = 0;
        *icmp6.add(5) = 0;
        *icmp6.add(6) = 0;
        *icmp6.add(7) = 0;
    }

    // Step 7: Write saved 48 bytes as ICMPv6 payload from scratch buffer.
    let mut j: usize = 0;
    while j < 48 {
        unsafe { *icmp6.add(8 + j) = (*scratch).data[j] };
        j += 1;
    }

    // Step 8: Compute ICMPv6 checksum (with pseudo-header).
    unsafe {
        let csum = compute_icmpv6_csum(&orig_dst, &orig_src, icmp6);
        let csum_be = csum.to_be_bytes();
        *icmp6.add(2) = csum_be[0];
        *icmp6.add(3) = csum_be[1];
    }

    Ok(xdp_action::XDP_TX)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
