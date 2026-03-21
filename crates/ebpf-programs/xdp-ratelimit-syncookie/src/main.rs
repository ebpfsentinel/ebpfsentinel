//! XDP SYN cookie forging program — tail-called from `xdp-ratelimit`.
//!
//! Forges SYN+ACK responses with SYN cookies for detected SYN floods.
//! Runs in its own XDP entry point with a fresh 512-byte stack budget.
//!
//! Reads `SYNCOOKIE_CTX` (PerCpuArray, shared via pinning) for packet
//! fields and `SYNCOOKIE_SECRET` for the cookie key.

#![no_std]
#![no_main]
#![cfg_attr(target_arch = "bpf", feature(asm_experimental_arch))]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_xdp_adjust_tail,
    macros::{map, xdp},
    maps::{Array, PerCpuArray},
    programs::XdpContext,
};
use aya_ebpf_bindings::helpers::bpf_ktime_get_boot_ns;
use ebpf_common::ddos::{
    DDOS_METRIC_COUNT, DDOS_METRIC_SYNCOOKIE_SENT, SYNCOOKIE_MSS_TABLE, SyncookieCtx,
    SyncookieSecret,
};
use ebpf_common::event::FLAG_IPV6;
use ebpf_helpers::checksum::{compute_ipv4_csum, compute_tcp_csum_v4_24, compute_tcp_csum_v6_24};
use ebpf_helpers::net::{IPV6_HDR_LEN, Ipv6Hdr, PROTO_TCP};
use ebpf_helpers::xdp::{ptr_at, ptr_at_mut};
use ebpf_helpers::{barrier, copy_mac_asm};
use network_types::{
    eth::EthHdr,
    ip::Ipv4Hdr,
};

// ── Maps (shared via pinning) ───────────────────────────────────────

#[map]
static SYNCOOKIE_CTX: PerCpuArray<SyncookieCtx> = PerCpuArray::with_max_entries(1, 0);

#[map]
static SYNCOOKIE_SECRET: Array<SyncookieSecret> = Array::with_max_entries(1, 0);

#[map]
static DDOS_METRICS: PerCpuArray<u64> = PerCpuArray::with_max_entries(DDOS_METRIC_COUNT, 0);

// ── Entry point ─────────────────────────────────────────────────────

#[xdp]
pub fn xdp_ratelimit_syncookie(ctx: XdpContext) -> u32 {
    match try_syncookie(&ctx) {
        Ok(action) => action,
        Err(()) => xdp_action::XDP_DROP,
    }
}

#[inline(always)]
fn try_syncookie(ctx: &XdpContext) -> Result<u32, ()> {
    let sctx = match SYNCOOKIE_CTX.get_ptr(0) {
        Some(p) => p,
        None => return Err(()),
    };
    let is_ipv6 = (unsafe { (*sctx).flags } & FLAG_IPV6) != 0;

    let result = if is_ipv6 {
        send_syn_ack_v6(ctx, sctx)
    } else {
        send_syn_ack_v4(ctx, sctx)
    };

    if result.is_ok() {
        increment_ddos_metric(DDOS_METRIC_SYNCOOKIE_SENT);
    }
    result
}

#[inline(always)]
fn increment_ddos_metric(index: u32) {
    if let Some(cnt) = DDOS_METRICS.get_ptr_mut(index) {
        unsafe { *cnt += 1 };
    }
}

// ── Cookie computation ──────────────────────────────────────────────

#[inline(always)]
fn syncookie_hash(
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    ts_counter: u32,
    secret: &[u32; 8],
) -> u32 {
    let mut h: u32 = 0x811c_9dc5; // FNV offset basis
    h ^= src_ip;
    h = h.wrapping_mul(0x0100_0193);
    h ^= dst_ip;
    h = h.wrapping_mul(0x0100_0193);
    h ^= ((src_port as u32) << 16) | (dst_port as u32);
    h = h.wrapping_mul(0x0100_0193);
    h ^= ts_counter;
    h = h.wrapping_mul(0x0100_0193);
    let mut i = 0u32;
    while i < 8 {
        h ^= secret[i as usize];
        h = h.wrapping_mul(0x0100_0193);
        i += 1;
    }
    h
}

#[inline(always)]
fn make_syncookie(
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    mss_idx: u8,
    secret: &[u32; 8],
) -> u32 {
    let ts = (unsafe { bpf_ktime_get_boot_ns() } / 60_000_000_000) as u32;
    let hash = syncookie_hash(src_ip, dst_ip, src_port, dst_port, ts, secret);
    (hash & 0xFFFF_FFF8) | ((mss_idx & 0x07) as u32)
}

// ── SYN+ACK Forging (IPv4) ─────────────────────────────────────────

#[inline(never)]
fn send_syn_ack_v4(ctx: &XdpContext, sctx: *const SyncookieCtx) -> Result<u32, ()> {
    let src_ip = unsafe { (*sctx).src_ip };
    let dst_ip = unsafe { (*sctx).dst_ip };
    let src_port = unsafe { (*sctx).src_port };
    let dst_port = unsafe { (*sctx).dst_port };
    let in_seq = unsafe { (*sctx).in_seq };
    let in_src_port_be = unsafe { (*sctx).in_src_port_be };
    let in_dst_port_be = unsafe { (*sctx).in_dst_port_be };
    let mss_idx = unsafe { (*sctx).mss_idx };

    // Read MACs from packet at constant offset 0.
    let ethhdr: *const EthHdr = unsafe { ptr_at(ctx, 0)? };
    let mut in_src_mac = [0u8; 6];
    let mut in_dst_mac = [0u8; 6];
    unsafe {
        let p = ethhdr as *const u8;
        copy_mac_asm!(in_dst_mac.as_mut_ptr(), p);
        copy_mac_asm!(in_src_mac.as_mut_ptr(), p.add(6));
    }

    // Compute cookie.
    let secret = match SYNCOOKIE_SECRET.get(0) {
        Some(s) => s,
        None => return Err(()),
    };
    let cookie = make_syncookie(src_ip, dst_ip, src_port, dst_port, mss_idx, &secret.key);

    // Truncate to fixed Eth(14) + IP(20) + TCP(24) = 58 bytes.
    const PKT_LEN: usize = 14 + 20 + 24;
    let current_len = ctx.data_end() - ctx.data();
    let delta = PKT_LEN as i32 - current_len as i32;
    if delta != 0 {
        let ret = unsafe { bpf_xdp_adjust_tail(ctx.ctx, delta) };
        if ret != 0 {
            return Err(());
        }
    }
    unsafe { barrier() };

    // Re-derive at CONSTANT offsets.
    let eth: *mut EthHdr = unsafe { ptr_at_mut(ctx, 0)? };
    let ip: *mut Ipv4Hdr = unsafe { ptr_at_mut(ctx, 14)? };
    // Bounds check for full TCP(24) at offset 34.
    let _end: *const u8 = unsafe { ptr_at(ctx, 34 + 23)? };
    let tcp_out: *mut u8 = unsafe { ptr_at_mut(ctx, 34)? };

    // Swap MACs + set ether_type.
    unsafe {
        let p = eth as *mut u8;
        copy_mac_asm!(p, in_src_mac.as_ptr());
        copy_mac_asm!(p.add(6), in_dst_mac.as_ptr());
        (*eth).ether_type = 0x0008u16; // ETH_P_IP
    }

    // Build IPv4 header (IHL=5, 20 bytes).
    unsafe {
        let ver_ihl = ip as *mut u8;
        *ver_ihl = 0x45;
        (*ip).tos = 0;
        (*ip).set_tot_len(44); // 20 IP + 24 TCP
        (*ip).set_id(0);
        (*ip).set_frags(0x02, 0); // DF
        (*ip).ttl = 64;
        (*ip).proto = network_types::ip::IpProto::Tcp;
        (*ip).src_addr = unsafe { core::mem::transmute(dst_ip.to_be()) };
        (*ip).dst_addr = unsafe { core::mem::transmute(src_ip.to_be()) };
        (*ip).check = [0, 0];
        let csum = compute_ipv4_csum(ip as *const u8);
        (*ip).set_checksum(csum);
    }

    // Build TCP SYN+ACK with MSS option.
    unsafe {
        let port_ptr = tcp_out as *mut u16;
        *port_ptr = in_dst_port_be;       // src = original dst
        *port_ptr.add(1) = in_src_port_be; // dst = original src
        let seq_ptr = tcp_out.add(4) as *mut u32;
        *seq_ptr = cookie.to_be();
        let ack_ptr = tcp_out.add(8) as *mut u32;
        *ack_ptr = (in_seq + 1).to_be();
        *tcp_out.add(12) = 0x60; // data offset = 6 (24 bytes)
        *tcp_out.add(13) = 0x12; // SYN+ACK
        let win_ptr = tcp_out.add(14) as *mut u16;
        *win_ptr = 65535u16.to_be();
        let csum_ptr = tcp_out.add(16) as *mut u16;
        *csum_ptr = 0;
        let urg_ptr = tcp_out.add(18) as *mut u16;
        *urg_ptr = 0;
        // MSS option: kind=2, len=4, value.
        let mss_val = SYNCOOKIE_MSS_TABLE[mss_idx as usize & 0x07];
        *tcp_out.add(20) = 2;
        *tcp_out.add(21) = 4;
        let mss_ptr = tcp_out.add(22) as *mut u16;
        *mss_ptr = mss_val.to_be();
        // Compute TCP checksum with pseudo-header.
        let new_src_ip = (*ip).src_addr;
        let new_dst_ip = (*ip).dst_addr;
        let csum = compute_tcp_csum_v4_24(&new_src_ip, &new_dst_ip, tcp_out);
        let csum_be = csum.to_be_bytes();
        *tcp_out.add(16) = csum_be[0];
        *tcp_out.add(17) = csum_be[1];
    }

    Ok(xdp_action::XDP_TX)
}

// ── SYN+ACK Forging (IPv6) ─────────────────────────────────────────

#[inline(never)]
fn send_syn_ack_v6(ctx: &XdpContext, sctx: *const SyncookieCtx) -> Result<u32, ()> {
    let src_ip = unsafe { (*sctx).src_ip };
    let dst_ip = unsafe { (*sctx).dst_ip };
    let src_port = unsafe { (*sctx).src_port };
    let dst_port = unsafe { (*sctx).dst_port };
    let in_seq = unsafe { (*sctx).in_seq };
    let in_src_port_be = unsafe { (*sctx).in_src_port_be };
    let in_dst_port_be = unsafe { (*sctx).in_dst_port_be };
    let mss_idx = unsafe { (*sctx).mss_idx };

    // Read MACs and IPv6 addresses from packet at constant offsets.
    let ethhdr: *const EthHdr = unsafe { ptr_at(ctx, 0)? };
    let mut in_src_mac = [0u8; 6];
    let mut in_dst_mac = [0u8; 6];
    unsafe {
        let p = ethhdr as *const u8;
        copy_mac_asm!(in_dst_mac.as_mut_ptr(), p);
        copy_mac_asm!(in_src_mac.as_mut_ptr(), p.add(6));
    }

    // Read IPv6 addresses from original packet (l3_off may vary, but we
    // read from the PKT_CTX map instead to avoid variable offsets).
    // For the SYN+ACK, we need the IPv6 src/dst to swap them.
    // We use src_ip/dst_ip (XOR-folded) for the cookie, but need the
    // raw 16-byte addresses for the response header. Read them from the
    // original packet at a known-good offset: xdp-ratelimit already
    // proved bounds for these. Since this is a tail call, the packet is
    // still valid. Read from the constant Ethernet offset (14).
    let ipv6hdr: *const Ipv6Hdr = unsafe { ptr_at(ctx, 14)? };
    let in_src_addr: [u8; 16] = unsafe { (*ipv6hdr).src_addr };
    let in_dst_addr: [u8; 16] = unsafe { (*ipv6hdr).dst_addr };

    // Compute cookie.
    let secret = match SYNCOOKIE_SECRET.get(0) {
        Some(s) => s,
        None => return Err(()),
    };
    let cookie = make_syncookie(src_ip, dst_ip, src_port, dst_port, mss_idx, &secret.key);

    // Truncate to fixed Eth(14) + IPv6(40) + TCP(24) = 78 bytes.
    const PKT_LEN: usize = 14 + IPV6_HDR_LEN + 24;
    let current_len = ctx.data_end() - ctx.data();
    let delta = PKT_LEN as i32 - current_len as i32;
    if delta != 0 {
        let ret = unsafe { bpf_xdp_adjust_tail(ctx.ctx, delta) };
        if ret != 0 {
            return Err(());
        }
    }
    unsafe { barrier() };

    // Re-derive at CONSTANT offsets.
    let eth: *mut EthHdr = unsafe { ptr_at_mut(ctx, 0)? };
    unsafe {
        let p = eth as *mut u8;
        copy_mac_asm!(p, in_src_mac.as_ptr());
        copy_mac_asm!(p.add(6), in_dst_mac.as_ptr());
        (*eth).ether_type = 0xDD86u16; // ETH_P_IPV6
    }
    let ip6: *mut Ipv6Hdr = unsafe { ptr_at_mut(ctx, 14)? };
    let _end: *const u8 = unsafe { ptr_at(ctx, 54 + 23)? };
    let tcp_out: *mut u8 = unsafe { ptr_at_mut(ctx, 54)? };

    // Build IPv6 header.
    unsafe {
        (*ip6)._vtcfl = (6u32 << 28).to_be();
        (*ip6)._payload_len = 24u16.to_be(); // TCP with MSS option
        (*ip6).next_hdr = PROTO_TCP;
        (*ip6).hop_limit = 64;
        (*ip6).src_addr = in_dst_addr; // swap
        (*ip6).dst_addr = in_src_addr;
    }

    // Build TCP SYN+ACK with MSS option.
    unsafe {
        let port_ptr = tcp_out as *mut u16;
        *port_ptr = in_dst_port_be;
        *port_ptr.add(1) = in_src_port_be;
        let seq_ptr = tcp_out.add(4) as *mut u32;
        *seq_ptr = cookie.to_be();
        let ack_ptr = tcp_out.add(8) as *mut u32;
        *ack_ptr = (in_seq + 1).to_be();
        *tcp_out.add(12) = 0x60;
        *tcp_out.add(13) = 0x12;
        let win_ptr = tcp_out.add(14) as *mut u16;
        *win_ptr = 65535u16.to_be();
        let csum_ptr = tcp_out.add(16) as *mut u16;
        *csum_ptr = 0;
        let urg_ptr = tcp_out.add(18) as *mut u16;
        *urg_ptr = 0;
        let mss_val = SYNCOOKIE_MSS_TABLE[mss_idx as usize & 0x07];
        *tcp_out.add(20) = 2;
        *tcp_out.add(21) = 4;
        let mss_ptr = tcp_out.add(22) as *mut u16;
        *mss_ptr = mss_val.to_be();
        let csum = compute_tcp_csum_v6_24(&in_dst_addr, &in_src_addr, tcp_out);
        let csum_be = csum.to_be_bytes();
        *tcp_out.add(16) = csum_be[0];
        *tcp_out.add(17) = csum_be[1];
    }

    Ok(xdp_action::XDP_TX)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
