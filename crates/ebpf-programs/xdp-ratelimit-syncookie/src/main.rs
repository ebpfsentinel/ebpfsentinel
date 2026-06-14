//! XDP SYN cookie forging program — tail-called from `xdp-ratelimit`.
//!
//! Forges SYN+ACK responses with **kernel-issued** SYN cookies for detected
//! SYN floods, via the `bpf_tcp_raw_gen_syncookie_ipv4/ipv6` helpers. Because
//! the cookie comes from the kernel's own algorithm, a legitimate client that
//! completes the handshake produces an ACK the kernel can validate and turn
//! into an established socket (with `net.ipv4.tcp_syncookies` enabled), so real
//! connections survive the flood while spoofed sources cannot.
//!
//! Reads `SYNCOOKIE_CTX` (PerCpuArray, shared via pinning) for the swapped
//! reply addresses/ports captured by the ratelimit program.

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
use aya_ebpf_bindings::bindings::{iphdr, ipv6hdr, tcphdr};
use aya_ebpf_bindings::helpers::{bpf_tcp_raw_gen_syncookie_ipv4, bpf_tcp_raw_gen_syncookie_ipv6};
use ebpf_common::ddos::{DDOS_METRIC_COUNT, DDOS_METRIC_SYNCOOKIE_SENT, SyncookieCtx};
use ebpf_common::event::FLAG_IPV6;
use ebpf_helpers::checksum::{compute_ipv4_csum, compute_tcp_csum_v4_24, compute_tcp_csum_v6_24};
use ebpf_helpers::net::{IPV6_HDR_LEN, Ipv6Hdr, PROTO_TCP};
use ebpf_helpers::xdp::{ptr_at, ptr_at_mut};
use ebpf_helpers::{barrier, copy_mac_asm};
use network_types::{eth::EthHdr, ip::Ipv4Hdr, tcp::TcpHdr};

#[map]
static SYNCOOKIE_CTX: PerCpuArray<SyncookieCtx> = PerCpuArray::with_max_entries(1, 0);

#[map]
static DDOS_METRICS: PerCpuArray<u64> = PerCpuArray::with_max_entries(DDOS_METRIC_COUNT, 0);

/// Base TCP header length passed to the cookie generator. Passing the fixed
/// base header (no options) keeps the verifier bounds check a constant size;
/// the kernel still issues a valid cookie that round-trips via `tcp_syncookies`.
const TH_BASE_LEN: u32 = 20;

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

#[inline(never)]
fn send_syn_ack_v4(ctx: &XdpContext, sctx: *const SyncookieCtx) -> Result<u32, ()> {
    let in_seq = unsafe { (*sctx).in_seq };
    let in_src_port_be = unsafe { (*sctx).in_src_port_be };
    let in_dst_port_be = unsafe { (*sctx).in_dst_port_be };
    let reply_src_ip = unsafe { (*sctx).dst_ip }; // reply src = original dst
    let reply_dst_ip = unsafe { (*sctx).src_ip }; // reply dst = original src

    let ethhdr: *const EthHdr = unsafe { ptr_at(ctx, 0)? };
    let mut in_src_mac = [0u8; 6];
    let mut in_dst_mac = [0u8; 6];
    unsafe {
        let p = ethhdr as *const u8;
        copy_mac_asm!(in_dst_mac.as_mut_ptr(), p);
        copy_mac_asm!(in_src_mac.as_mut_ptr(), p.add(6));
    }

    // Issue a kernel SYN cookie from the *original* SYN headers before the
    // packet is rewritten. Pointers are bounds-checked against the packet.
    let iph_in: *const Ipv4Hdr = unsafe { ptr_at(ctx, 14)? };
    let th_in: *const TcpHdr = unsafe { ptr_at(ctx, 34)? };
    let value = unsafe {
        bpf_tcp_raw_gen_syncookie_ipv4(iph_in as *mut iphdr, th_in as *mut tcphdr, TH_BASE_LEN)
    };
    if value < 0 {
        return Err(());
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let cookie = value as u32;
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let mss = (value >> 32) as u16;

    const PKT_LEN: usize = 14 + 20 + 24;
    let current_len = ctx.data_end().saturating_sub(ctx.data());
    let delta = PKT_LEN as i32 - current_len as i32;
    if delta != 0 {
        let ret = unsafe { bpf_xdp_adjust_tail(ctx.ctx, delta) };
        if ret != 0 {
            return Err(());
        }
    }
    unsafe { barrier() };

    let eth: *mut EthHdr = unsafe { ptr_at_mut(ctx, 0)? };
    let ip: *mut Ipv4Hdr = unsafe { ptr_at_mut(ctx, 14)? };
    let _end: *const u8 = unsafe { ptr_at(ctx, 34 + 23)? };
    let tcp_out: *mut u8 = unsafe { ptr_at_mut(ctx, 34)? };

    unsafe {
        let p = eth as *mut u8;
        copy_mac_asm!(p, in_src_mac.as_ptr());
        copy_mac_asm!(p.add(6), in_dst_mac.as_ptr());
        (*eth).ether_type = 0x0008u16; // ETH_P_IP
    }

    unsafe {
        let ver_ihl = ip as *mut u8;
        *ver_ihl = 0x45;
        (*ip).tos = 0;
        (*ip).set_tot_len(44); // 20 IP + 24 TCP
        (*ip).set_id(0);
        (*ip).set_frags(0x02, 0); // DF
        (*ip).ttl = 64;
        (*ip).proto = network_types::ip::IpProto::Tcp as u8;
        (*ip).src_addr = reply_src_ip.to_be().to_ne_bytes();
        (*ip).dst_addr = reply_dst_ip.to_be().to_ne_bytes();
        (*ip).check = [0, 0];
        let csum = compute_ipv4_csum(ip as *const u8);
        (*ip).set_checksum(csum);
    }

    unsafe {
        let port_ptr = tcp_out as *mut u16;
        *port_ptr = in_dst_port_be; // src = original dst
        *port_ptr.add(1) = in_src_port_be; // dst = original src
        let seq_ptr = tcp_out.add(4) as *mut u32;
        *seq_ptr = cookie.to_be();
        let ack_ptr = tcp_out.add(8) as *mut u32;
        *ack_ptr = in_seq.wrapping_add(1).to_be();
        *tcp_out.add(12) = 0x60; // data offset = 6 (24 bytes)
        *tcp_out.add(13) = 0x12; // SYN+ACK
        let win_ptr = tcp_out.add(14) as *mut u16;
        *win_ptr = 65535u16.to_be();
        let csum_ptr = tcp_out.add(16) as *mut u16;
        *csum_ptr = 0;
        let urg_ptr = tcp_out.add(18) as *mut u16;
        *urg_ptr = 0;
        *tcp_out.add(20) = 2;
        *tcp_out.add(21) = 4;
        let mss_ptr = tcp_out.add(22) as *mut u16;
        *mss_ptr = mss.to_be();
        let new_src_ip = (*ip).src_addr;
        let new_dst_ip = (*ip).dst_addr;
        let csum = compute_tcp_csum_v4_24(&new_src_ip, &new_dst_ip, tcp_out);
        let csum_be = csum.to_be_bytes();
        *tcp_out.add(16) = csum_be[0];
        *tcp_out.add(17) = csum_be[1];
    }

    Ok(xdp_action::XDP_TX)
}

#[inline(never)]
fn send_syn_ack_v6(ctx: &XdpContext, sctx: *const SyncookieCtx) -> Result<u32, ()> {
    let in_seq = unsafe { (*sctx).in_seq };
    let in_src_port_be = unsafe { (*sctx).in_src_port_be };
    let in_dst_port_be = unsafe { (*sctx).in_dst_port_be };
    let in_src_addr: [u8; 16] = unsafe { (*sctx).in_src_addr };
    let in_dst_addr: [u8; 16] = unsafe { (*sctx).in_dst_addr };

    let ethhdr: *const EthHdr = unsafe { ptr_at(ctx, 0)? };
    let mut in_src_mac = [0u8; 6];
    let mut in_dst_mac = [0u8; 6];
    unsafe {
        let p = ethhdr as *const u8;
        copy_mac_asm!(in_dst_mac.as_mut_ptr(), p);
        copy_mac_asm!(in_src_mac.as_mut_ptr(), p.add(6));
    }

    // Issue a kernel SYN cookie from the original IPv6 SYN headers (offset 54
    // = 14 eth + 40 IPv6) before the packet is rewritten.
    let iph_in: *const Ipv6Hdr = unsafe { ptr_at(ctx, 14)? };
    let th_in: *const TcpHdr = unsafe { ptr_at(ctx, 54)? };
    let value = unsafe {
        bpf_tcp_raw_gen_syncookie_ipv6(iph_in as *mut ipv6hdr, th_in as *mut tcphdr, TH_BASE_LEN)
    };
    if value < 0 {
        return Err(());
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let cookie = value as u32;
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let mss = (value >> 32) as u16;

    const PKT_LEN: usize = 14 + IPV6_HDR_LEN + 24;
    let current_len = ctx.data_end().saturating_sub(ctx.data());
    let delta = PKT_LEN as i32 - current_len as i32;
    if delta != 0 {
        let ret = unsafe { bpf_xdp_adjust_tail(ctx.ctx, delta) };
        if ret != 0 {
            return Err(());
        }
    }
    unsafe { barrier() };

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

    unsafe {
        (*ip6)._vtcfl = (6u32 << 28).to_be();
        (*ip6)._payload_len = 24u16.to_be(); // TCP with MSS option
        (*ip6).next_hdr = PROTO_TCP;
        (*ip6).hop_limit = 64;
        (*ip6).src_addr = in_dst_addr; // swap
        (*ip6).dst_addr = in_src_addr;
    }

    unsafe {
        let port_ptr = tcp_out as *mut u16;
        *port_ptr = in_dst_port_be;
        *port_ptr.add(1) = in_src_port_be;
        let seq_ptr = tcp_out.add(4) as *mut u32;
        *seq_ptr = cookie.to_be();
        let ack_ptr = tcp_out.add(8) as *mut u32;
        *ack_ptr = in_seq.wrapping_add(1).to_be();
        *tcp_out.add(12) = 0x60;
        *tcp_out.add(13) = 0x12;
        let win_ptr = tcp_out.add(14) as *mut u16;
        *win_ptr = 65535u16.to_be();
        let csum_ptr = tcp_out.add(16) as *mut u16;
        *csum_ptr = 0;
        let urg_ptr = tcp_out.add(18) as *mut u16;
        *urg_ptr = 0;
        *tcp_out.add(20) = 2;
        *tcp_out.add(21) = 4;
        let mss_ptr = tcp_out.add(22) as *mut u16;
        *mss_ptr = mss.to_be();
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
