#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext,
    bindings::{__sk_buff, TC_ACT_OK},
    cty::c_void,
    helpers::{bpf_get_prandom_u32, bpf_l3_csum_replace, bpf_l4_csum_replace, bpf_loop},
    macros::{classifier, map},
    maps::{Array, PerCpuArray},
    programs::TcContext,
};
use ebpf_common::scrub::{
    SCRUB_METRIC_COUNT, SCRUB_METRIC_DF_CLEARED, SCRUB_METRIC_ECN_STRIPPED, SCRUB_METRIC_ERRORS,
    SCRUB_METRIC_HOP_FIXED, SCRUB_METRIC_IPID_RANDOMIZED, SCRUB_METRIC_MSS_CLAMPED,
    SCRUB_METRIC_PACKETS, SCRUB_METRIC_TCP_FLAGS_SCRUBBED, SCRUB_METRIC_TCP_TS_STRIPPED,
    SCRUB_METRIC_TOS_NORMALIZED, SCRUB_METRIC_TOTAL_SEEN, SCRUB_METRIC_TTL_FIXED, ScrubFlags,
};
use ebpf_helpers::increment_metric;
use ebpf_helpers::net::{
    ETH_P_8021AD, ETH_P_8021Q, ETH_P_IP, ETH_P_IPV6, IPV6_HDR_LEN, Ipv6Hdr, PROTO_TCP,
    VLAN_HDR_LEN, VlanHdr,
};
use ebpf_helpers::tc::{ptr_at, skip_ipv6_ext_headers};
use network_types::{eth::EthHdr, ip::Ipv4Hdr};

// ── Constants ───────────────────────────────────────────────────────
// Network constants and header structs imported from ebpf_helpers.

/// IPv4 flags field offset within Ipv4Hdr (frag_off contains flags + fragment offset).
/// DF = bit 14 (0x4000 in network byte order).
const IP_DF: u16 = 0x4000; // Don't Fragment flag in host byte order

/// TCP option kind: MSS.
const TCP_OPT_MSS: u8 = 2;
/// TCP option kind: End of options.
const TCP_OPT_EOL: u8 = 0;
/// TCP option kind: NOP.
const TCP_OPT_NOP: u8 = 1;
/// TCP option kind: Timestamp (kind=8, len=10).
const TCP_OPT_TIMESTAMP: u8 = 8;
/// TCP timestamp option length.
const TCP_OPT_TIMESTAMP_LEN: u8 = 10;

/// TCP SYN flag.
const TCP_SYN: u8 = 0x02;

/// Iteration bound for the TCP option walk, passed to `bpf_loop`. The TCP
/// options area is at most 40 bytes (a 60-byte TCP header minus the 20-byte
/// fixed header), and every step advances by at least one byte, so 40 steps
/// always covers the whole area.
const MAX_TCP_OPT_SCAN: u32 = 40;

// ── Maps ────────────────────────────────────────────────────────────

/// Scrub configuration (single entry at index 0).
#[map]
static SCRUB_CONFIG: Array<ScrubFlags> = Array::with_max_entries(1, 0);

/// Per-CPU scrub metrics.
#[map]
static SCRUB_METRICS: PerCpuArray<u64> = PerCpuArray::with_max_entries(SCRUB_METRIC_COUNT, 0);

// ── Entry point ─────────────────────────────────────────────────────

#[classifier]
pub fn tc_scrub(mut ctx: TcContext) -> i32 {
    increment_metric(SCRUB_METRIC_TOTAL_SEEN);
    let action = match try_tc_scrub(&mut ctx) {
        Ok(action) => action,
        Err(()) => {
            increment_metric(SCRUB_METRIC_ERRORS);
            TC_ACT_OK
        }
    };
    // Under TCX (kernel >= 6.6) returning TC_ACT_OK terminates the program
    // chain on this hook; translate a "pass" verdict to TCX_NEXT (-1) so other
    // tc programs on the same interface still run. Terminal verdicts pass through.
    if action == TC_ACT_OK { -1 } else { action }
}

// ── Helpers ─────────────────────────────────────────────────────────

// ptr_at, skip_ipv6_ext_headers imported from ebpf_helpers::tc

#[inline(always)]
fn increment_metric(index: u32) {
    increment_metric!(SCRUB_METRICS, index);
}

#[inline(always)]
fn get_config() -> Option<ScrubFlags> {
    SCRUB_CONFIG.get(0).copied()
}

// ── Packet processing ───────────────────────────────────────────────

#[inline(always)]
fn try_tc_scrub(ctx: &mut TcContext) -> Result<i32, ()> {
    let cfg = match get_config() {
        Some(cfg) if cfg.enabled != 0 => cfg,
        _ => return Ok(TC_ACT_OK),
    };

    let ethhdr: *const EthHdr = unsafe { ptr_at(ctx, 0)? };
    let mut ether_type = u16::from_be(unsafe { (*ethhdr).ether_type });
    let mut l3_offset = EthHdr::LEN;

    // 802.1Q VLAN tag
    if ether_type == ETH_P_8021Q || ether_type == ETH_P_8021AD {
        let vhdr: *const VlanHdr = unsafe { ptr_at(ctx, l3_offset)? };
        ether_type = u16::from_be(unsafe { (*vhdr).ether_type });
        l3_offset += VLAN_HDR_LEN;

        // QinQ: parse second VLAN tag if present
        if ether_type == ETH_P_8021Q || ether_type == ETH_P_8021AD {
            let vhdr2: *const VlanHdr = unsafe { ptr_at(ctx, l3_offset)? };
            ether_type = u16::from_be(unsafe { (*vhdr2).ether_type });
            l3_offset += VLAN_HDR_LEN;
        }
    }

    if ether_type == ETH_P_IP {
        scrub_ipv4(ctx, &cfg, l3_offset)?;
        increment_metric(SCRUB_METRIC_PACKETS);
    } else if ether_type == ETH_P_IPV6 {
        scrub_ipv6(ctx, &cfg, l3_offset)?;
        increment_metric(SCRUB_METRIC_PACKETS);
    }

    Ok(TC_ACT_OK)
}

/// Apply scrub operations to an IPv4 packet.
#[inline(always)]
fn scrub_ipv4(ctx: &mut TcContext, cfg: &ScrubFlags, l3_offset: usize) -> Result<(), ()> {
    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(ctx, l3_offset)? };
    let protocol = unsafe { (*ipv4hdr).proto } as u8;
    let ihl = unsafe { (*ipv4hdr).ihl() } as usize;
    let l4_offset = l3_offset + ihl;

    // Snapshot every mutable IPv4 header field up front. The scrub helpers below
    // call bpf_skb_store_bytes / bpf_l3_csum_replace, which invalidate direct
    // packet pointers, so each field must be read before the first mutation —
    // re-dereferencing `ipv4hdr` afterwards is a verifier-rejected scalar access.
    let ttl = unsafe { (*ipv4hdr).ttl };
    let frag_off = u16::from_be_bytes(unsafe { (*ipv4hdr).frags });
    let old_id = u16::from_be_bytes(unsafe { (*ipv4hdr).id });

    // ── TTL normalization ───────────────────────────────────────
    if cfg.min_ttl > 0 && ttl < cfg.min_ttl {
        scrub_fix_ttl(ctx, l3_offset, ttl, cfg.min_ttl)?;
        increment_metric(SCRUB_METRIC_TTL_FIXED);
    }

    // ── Clear DF bit ────────────────────────────────────────────
    if cfg.clear_df != 0 && frag_off & IP_DF != 0 {
        scrub_clear_df(ctx, l3_offset, frag_off)?;
        increment_metric(SCRUB_METRIC_DF_CLEARED);
    }

    // ── Randomize IP ID ─────────────────────────────────────────
    if cfg.random_ip_id != 0 {
        let new_id = (unsafe { bpf_get_prandom_u32() } & 0xFFFF) as u16;
        if old_id != new_id {
            scrub_random_ip_id(ctx, l3_offset, old_id, new_id)?;
            increment_metric(SCRUB_METRIC_IPID_RANDOMIZED);
        }
    }

    // ── TCP option scrubbing: MSS clamp + timestamp strip (one pass) ──
    if protocol == PROTO_TCP && (cfg.max_mss > 0 || cfg.strip_tcp_timestamps != 0) {
        scrub_tcp_options(ctx, cfg, l4_offset)?;
    }

    // ── TCP reserved flag scrubbing ────────────────────────────
    if cfg.scrub_tcp_flags != 0 && protocol == PROTO_TCP {
        scrub_tcp_reserved_flags(ctx, l4_offset)?;
    }

    // ── ECN stripping (IPv4) ───────────────────────────────────
    if cfg.strip_ecn != 0 {
        scrub_strip_ecn_v4(ctx, l3_offset)?;
    }

    // ── TOS normalization (IPv4) ───────────────────────────────
    if cfg.normalize_tos != 0 {
        scrub_normalize_tos_v4(ctx, l3_offset, cfg.tos_value)?;
    }

    Ok(())
}

/// Apply scrub operations to an IPv6 packet.
///
/// IPv6 has no header checksum, no DF bit, and no IP ID field.
/// Only hop limit normalization and MSS clamping apply.
#[inline(never)]
fn scrub_ipv6(ctx: &mut TcContext, cfg: &ScrubFlags, l3_offset: usize) -> Result<(), ()> {
    let ipv6hdr: *const Ipv6Hdr = unsafe { ptr_at(ctx, l3_offset)? };
    let raw_protocol = unsafe { (*ipv6hdr).next_hdr };

    // Skip IPv6 extension headers to find the actual L4 protocol.
    let (protocol, l4_offset) =
        skip_ipv6_ext_headers(ctx, l3_offset + IPV6_HDR_LEN, raw_protocol).ok_or(())?;

    // ── Hop Limit normalization (IPv6 equivalent of TTL) ────────
    if cfg.min_hop_limit > 0 {
        let hop_limit = unsafe { (*ipv6hdr).hop_limit };
        if hop_limit < cfg.min_hop_limit {
            // Hop Limit is at offset 7 in the IPv6 header.
            // IPv6 has no header checksum, so just write the byte.
            let hop_offset = l3_offset + 7;
            ctx.store(hop_offset, &cfg.min_hop_limit, 0)
                .map_err(|_| ())?;
            increment_metric(SCRUB_METRIC_HOP_FIXED);
        }
    }

    // ── TCP option scrubbing: MSS clamp + timestamp strip (one pass) ──
    // TCP options are L4-agnostic, reuse the same function.
    if protocol == PROTO_TCP && (cfg.max_mss > 0 || cfg.strip_tcp_timestamps != 0) {
        scrub_tcp_options(ctx, cfg, l4_offset)?;
    }

    // ── TCP reserved flag scrubbing ────────────────────────────
    if cfg.scrub_tcp_flags != 0 && protocol == PROTO_TCP {
        scrub_tcp_reserved_flags(ctx, l4_offset)?;
    }

    // ── ECN stripping (IPv6 Traffic Class) ─────────────────────
    if cfg.strip_ecn != 0 {
        scrub_strip_ecn_v6(ctx, l3_offset)?;
    }

    // ── TOS normalization (IPv6 Traffic Class) ─────────────────
    if cfg.normalize_tos != 0 {
        scrub_normalize_tos_v6(ctx, l3_offset, cfg.tos_value)?;
    }

    Ok(())
}

/// Rewrite TTL field and update IPv4 header checksum.
#[inline(always)]
fn scrub_fix_ttl(
    ctx: &mut TcContext,
    l3_offset: usize,
    old_ttl: u8,
    new_ttl: u8,
) -> Result<(), ()> {
    // TTL is at offset 8 in the IPv4 header
    let ttl_offset = l3_offset + 8;
    let csum_offset = (l3_offset + 10) as u32; // check field at offset 10

    // Write the new TTL byte
    ctx.store(ttl_offset, &new_ttl, 0).map_err(|_| ())?;

    // Update L3 checksum: old value in upper bits of u16 at offset 8 (TTL + Proto)
    // Use incremental checksum update
    let old_val = (old_ttl as u32) << 8;
    let new_val = (new_ttl as u32) << 8;
    unsafe {
        bpf_l3_csum_replace(
            ctx.as_ptr() as *mut _,
            csum_offset,
            old_val as u64,
            new_val as u64,
            2,
        );
    }
    Ok(())
}

/// Clear the DF bit in IPv4 flags and update checksum.
#[inline(always)]
fn scrub_clear_df(ctx: &mut TcContext, l3_offset: usize, old_frag_off: u16) -> Result<(), ()> {
    let new_frag_off = old_frag_off & !IP_DF;
    let frag_offset = l3_offset + 6; // frag_off at offset 6 in IPv4 header
    let csum_offset = (l3_offset + 10) as u32;

    let new_frag_be = new_frag_off.to_be();
    ctx.store(frag_offset, &new_frag_be, 0).map_err(|_| ())?;

    unsafe {
        bpf_l3_csum_replace(
            ctx.as_ptr() as *mut _,
            csum_offset,
            old_frag_off as u64,
            new_frag_off as u64,
            2,
        );
    }
    Ok(())
}

/// Randomize IP ID and update checksum.
#[inline(always)]
fn scrub_random_ip_id(
    ctx: &mut TcContext,
    l3_offset: usize,
    old_id: u16,
    new_id: u16,
) -> Result<(), ()> {
    let id_offset = l3_offset + 4; // id at offset 4 in IPv4 header
    let csum_offset = (l3_offset + 10) as u32;

    let new_id_be = new_id.to_be();
    ctx.store(id_offset, &new_id_be, 0).map_err(|_| ())?;

    unsafe {
        bpf_l3_csum_replace(
            ctx.as_ptr() as *mut _,
            csum_offset,
            old_id as u64,
            new_id as u64,
            2,
        );
    }
    Ok(())
}

/// Overwrite one 2-byte pair of a TCP timestamp option with NOP/NOP (0x0101),
/// updating the TCP checksum only when the pair actually changes.
#[inline(always)]
fn strip_ts_pair(ctx: &mut TcContext, pos: usize, tcp_csum_offset: u32) -> Result<(), ()> {
    let old_hi: u8 = ctx.load(pos).map_err(|_| ())?;
    let old_lo: u8 = ctx.load(pos + 1).map_err(|_| ())?;
    let old_val = ((old_hi as u16) << 8) | (old_lo as u16);
    let new_val: u16 = 0x0101; // NOP NOP
    if old_val != new_val {
        ctx.store(pos, &TCP_OPT_NOP, 0).map_err(|_| ())?;
        ctx.store(pos + 1, &TCP_OPT_NOP, 0).map_err(|_| ())?;
        unsafe {
            bpf_l4_csum_replace(
                ctx.as_ptr() as *mut _,
                tcp_csum_offset,
                old_val as u64,
                new_val as u64,
                2,
            );
        }
    }
    Ok(())
}

/// Context threaded through `bpf_loop` for the single-pass TCP option walk.
///
/// The walk advances by a packet-derived, variable stride each step. Carried
/// through an in-line `while` loop, that running offset mints a fresh,
/// ever-widening scalar every iteration, so no two loop states match, nothing
/// is pruned, and the program blows past the 1M instruction-complexity limit.
/// `bpf_loop` makes the verifier analyse the step callback exactly once,
/// sidestepping the blow-up while still covering the whole option area at
/// runtime. The option reads/writes go through `bpf_skb_load_bytes` /
/// `bpf_skb_store_bytes` (runtime-bounds-checked), so the unknown running
/// offset needs no static bound.
#[repr(C)]
struct ScrubOptCtx {
    /// Packet handle, re-wrapped as a `TcContext` inside the callback.
    skb: *mut __sk_buff,
    /// Byte offset of the first TCP option.
    opts_start: u32,
    /// Length of the option area (TCP header length − 20).
    opts_len: u32,
    /// Running byte offset into the option area; advances each step.
    scanned: u32,
    /// TCP checksum field offset for incremental checksum updates.
    tcp_csum_offset: u32,
    /// MSS clamp ceiling (host byte order).
    max_mss: u16,
    /// 1 when MSS clamping applies to this packet (configured and SYN).
    mss_active: u8,
    /// 1 when timestamp stripping is configured.
    do_ts: u8,
}

/// Clamp a TCP MSS option in place and update the TCP checksum.
#[inline(always)]
fn clamp_mss(ctx: &mut TcContext, pos: usize, tcp_csum_offset: u32, max_mss: u16) {
    let mss_hi: u8 = match ctx.load(pos + 2) {
        Ok(v) => v,
        Err(_) => return,
    };
    let mss_lo: u8 = match ctx.load(pos + 3) {
        Ok(v) => v,
        Err(_) => return,
    };
    let current_mss = ((mss_hi as u16) << 8) | (mss_lo as u16);
    if current_mss <= max_mss {
        return;
    }
    let new_mss_be = max_mss.to_be_bytes();
    if ctx.store(pos + 2, &new_mss_be[0], 0).is_err()
        || ctx.store(pos + 3, &new_mss_be[1], 0).is_err()
    {
        return;
    }
    unsafe {
        bpf_l4_csum_replace(
            ctx.as_ptr() as *mut _,
            tcp_csum_offset,
            current_mss as u64,
            max_mss as u64,
            2,
        );
    }
    increment_metric(SCRUB_METRIC_MSS_CLAMPED);
}

/// One step of the TCP option walk, invoked by `bpf_loop`.
///
/// Returns 1 to stop (end of options or a parse error), 0 to continue. MSS
/// clamp applies only when `mss_active` is set; timestamp strip applies when
/// `do_ts` is set. Both options are handled in the single walk.
#[inline(never)]
unsafe extern "C" fn scrub_opt_step(_index: u32, ctx: *mut c_void) -> i64 {
    unsafe {
        let lctx = &mut *(ctx as *mut ScrubOptCtx);
        let scanned = lctx.scanned as usize;
        let opts_len = lctx.opts_len as usize;
        if scanned >= opts_len {
            return 1;
        }

        let mut tctx = TcContext::new(lctx.skb);
        let pos = lctx.opts_start as usize + scanned;

        let kind: u8 = match tctx.load(pos) {
            Ok(k) => k,
            Err(_) => return 1,
        };
        if kind == TCP_OPT_EOL {
            return 1;
        }
        if kind == TCP_OPT_NOP {
            lctx.scanned = (scanned + 1) as u32;
            return 0;
        }

        // Multi-byte option: a length byte must follow.
        if scanned + 1 >= opts_len {
            return 1;
        }
        let opt_len: u8 = match tctx.load(pos + 1) {
            Ok(l) => l,
            Err(_) => return 1,
        };
        if opt_len < 2 {
            return 1; // invalid
        }

        if lctx.mss_active != 0 && kind == TCP_OPT_MSS && opt_len == 4 && scanned + 4 <= opts_len {
            clamp_mss(&mut tctx, pos, lctx.tcp_csum_offset, lctx.max_mss);
        } else if lctx.do_ts != 0
            && kind == TCP_OPT_TIMESTAMP
            && opt_len == TCP_OPT_TIMESTAMP_LEN
            && scanned + 10 <= opts_len
        {
            // Overwrite all 10 bytes (5 fixed 2-byte pairs) with NOP (kind=1).
            let _ = strip_ts_pair(&mut tctx, pos, lctx.tcp_csum_offset);
            let _ = strip_ts_pair(&mut tctx, pos + 2, lctx.tcp_csum_offset);
            let _ = strip_ts_pair(&mut tctx, pos + 4, lctx.tcp_csum_offset);
            let _ = strip_ts_pair(&mut tctx, pos + 6, lctx.tcp_csum_offset);
            let _ = strip_ts_pair(&mut tctx, pos + 8, lctx.tcp_csum_offset);
            increment_metric(SCRUB_METRIC_TCP_TS_STRIPPED);
        }

        lctx.scanned = (scanned + opt_len as usize) as u32;
        0
    }
}

/// Walk the TCP option area once via `bpf_loop`, applying both MSS clamping and
/// timestamp stripping in a single pass.
///
/// MSS clamp applies only to SYN packets when `cfg.max_mss > 0`; timestamp
/// strip applies when `cfg.strip_tcp_timestamps != 0`.
#[inline(never)]
fn scrub_tcp_options(ctx: &mut TcContext, cfg: &ScrubFlags, l4_offset: usize) -> Result<(), ()> {
    let do_mss = cfg.max_mss > 0;
    let do_ts = cfg.strip_tcp_timestamps != 0;

    // MSS clamp is SYN-only; read the flags byte (offset 13) once.
    let flags: u8 = ctx.load(l4_offset + 13).map_err(|_| ())?;
    let is_syn = flags & TCP_SYN != 0;

    // TCP data offset (header length in 32-bit words).
    let doff_byte: u8 = ctx.load(l4_offset + 12).map_err(|_| ())?;
    let tcp_hdr_len = ((doff_byte >> 4) as usize) * 4;
    if tcp_hdr_len <= 20 {
        return Ok(()); // No options
    }

    let opts_len = tcp_hdr_len - 20;

    let mut opt_ctx = ScrubOptCtx {
        skb: ctx.skb.skb,
        opts_start: (l4_offset + 20) as u32,
        opts_len: opts_len as u32,
        scanned: 0,
        tcp_csum_offset: (l4_offset + 16) as u32,
        max_mss: cfg.max_mss,
        mss_active: u8::from(do_mss && is_syn),
        do_ts: u8::from(do_ts),
    };

    unsafe {
        bpf_loop(
            MAX_TCP_OPT_SCAN,
            scrub_opt_step as *mut c_void,
            &mut opt_ctx as *mut ScrubOptCtx as *mut c_void,
            0,
        );
    }

    Ok(())
}

// ── New scrubbing functions ─────────────────────────────────────────

/// Clear TCP reserved bits (NS) and, on non-SYN packets, CWR/ECE flags.
///
/// Byte at `l4_offset + 12`: upper 4 bits = data offset, bit 0 = NS.
/// Byte at `l4_offset + 13`: CWR (0x80), ECE (0x40), then URG/ACK/PSH/RST/SYN/FIN.
///
/// We preserve ECN negotiation by only clearing CWR/ECE on non-SYN packets.
#[inline(always)]
fn scrub_tcp_reserved_flags(ctx: &mut TcContext, l4_offset: usize) -> Result<(), ()> {
    let tcp_csum_offset = (l4_offset + 16) as u32;

    // Read the doff/reserved/NS byte (offset 12) and flags byte (offset 13)
    let byte12: u8 = ctx.load(l4_offset + 12).map_err(|_| ())?;
    let byte13: u8 = ctx.load(l4_offset + 13).map_err(|_| ())?;

    // Clear reserved bits and NS (bit 0) in byte 12.
    // Upper 4 bits are data offset (must keep), lower 4 bits are reserved+NS.
    // Bits 3-1 are reserved (should be 0), bit 0 is NS.
    let new_byte12 = byte12 & 0xF0; // keep only data offset nibble

    // For non-SYN packets, also clear CWR (0x80) and ECE (0x40) in byte 13.
    let is_syn = byte13 & TCP_SYN != 0;
    let new_byte13 = if is_syn {
        byte13 // preserve CWR/ECE on SYN for ECN negotiation
    } else {
        byte13 & !0xC0 // clear CWR (0x80) and ECE (0x40)
    };

    if new_byte12 == byte12 && new_byte13 == byte13 {
        return Ok(()); // nothing to change
    }

    // Build old and new 16-bit values for checksum update (bytes 12-13).
    let old_val = ((byte12 as u16) << 8) | (byte13 as u16);
    let new_val = ((new_byte12 as u16) << 8) | (new_byte13 as u16);

    if new_byte12 != byte12 {
        ctx.store(l4_offset + 12, &new_byte12, 0).map_err(|_| ())?;
    }
    if new_byte13 != byte13 {
        ctx.store(l4_offset + 13, &new_byte13, 0).map_err(|_| ())?;
    }

    // Update TCP checksum
    unsafe {
        bpf_l4_csum_replace(
            ctx.as_ptr() as *mut _,
            tcp_csum_offset,
            old_val as u64,
            new_val as u64,
            2,
        );
    }

    increment_metric(SCRUB_METRIC_TCP_FLAGS_SCRUBBED);
    Ok(())
}

/// Strip ECN bits (2 LSBs) from IPv4 TOS field.
///
/// TOS is at IPv4 header offset 1. ECN occupies the 2 least significant bits.
#[inline(always)]
fn scrub_strip_ecn_v4(ctx: &mut TcContext, l3_offset: usize) -> Result<(), ()> {
    let tos: u8 = ctx.load(l3_offset + 1).map_err(|_| ())?;
    if tos & 0x03 == 0 {
        return Ok(()); // ECN bits already clear
    }
    let new_tos = tos & !0x03;
    ctx.store(l3_offset + 1, &new_tos, 0).map_err(|_| ())?;

    // Update L3 checksum. TOS is in the high byte of the first 16-bit word
    // at offset 0 (version/IHL + TOS). We update using the TOS byte position.
    let csum_offset = (l3_offset + 10) as u32;
    let old_val = (tos as u32) << 8;
    let new_val = (new_tos as u32) << 8;
    unsafe {
        bpf_l3_csum_replace(
            ctx.as_ptr() as *mut _,
            csum_offset,
            old_val as u64,
            new_val as u64,
            2,
        );
    }

    increment_metric(SCRUB_METRIC_ECN_STRIPPED);
    Ok(())
}

/// Strip ECN bits from IPv6 Traffic Class.
///
/// The IPv6 Traffic Class (8 bits) spans two bytes:
///   - byte 0: upper nibble = version (4), lower nibble = TC bits 7-4
///   - byte 1: upper nibble = TC bits 3-0, lower nibble = Flow Label bits 19-16
///
/// ECN is the 2 least significant bits of the Traffic Class (bits 1-0),
/// which reside in bits 5-4 of byte 1.
///
/// IPv6 has no header checksum, so no checksum update is needed.
#[inline(always)]
fn scrub_strip_ecn_v6(ctx: &mut TcContext, l3_offset: usize) -> Result<(), ()> {
    let byte1: u8 = ctx.load(l3_offset + 1).map_err(|_| ())?;
    // ECN bits are bits 5-4 of byte 1 (TC bits 1-0 mapped into byte 1).
    if byte1 & 0x30 == 0 {
        return Ok(()); // ECN bits already clear
    }
    let new_byte1 = byte1 & !0x30;
    ctx.store(l3_offset + 1, &new_byte1, 0).map_err(|_| ())?;

    increment_metric(SCRUB_METRIC_ECN_STRIPPED);
    Ok(())
}

/// Normalize IPv4 TOS/DSCP field to a specified value.
///
/// TOS is at IPv4 header offset 1. Writes `tos_value` and updates L3 checksum.
#[inline(always)]
fn scrub_normalize_tos_v4(ctx: &mut TcContext, l3_offset: usize, tos_value: u8) -> Result<(), ()> {
    let tos: u8 = ctx.load(l3_offset + 1).map_err(|_| ())?;
    if tos == tos_value {
        return Ok(()); // already at target value
    }
    ctx.store(l3_offset + 1, &tos_value, 0).map_err(|_| ())?;

    let csum_offset = (l3_offset + 10) as u32;
    let old_val = (tos as u32) << 8;
    let new_val = (tos_value as u32) << 8;
    unsafe {
        bpf_l3_csum_replace(
            ctx.as_ptr() as *mut _,
            csum_offset,
            old_val as u64,
            new_val as u64,
            2,
        );
    }

    increment_metric(SCRUB_METRIC_TOS_NORMALIZED);
    Ok(())
}

/// Normalize IPv6 Traffic Class to a specified value.
///
/// The Traffic Class spans bytes 0 and 1 of the IPv6 header:
///   - byte 0: bits 3-0 hold TC bits 7-4
///   - byte 1: bits 7-4 hold TC bits 3-0
///
/// IPv6 has no header checksum.
#[inline(always)]
fn scrub_normalize_tos_v6(ctx: &mut TcContext, l3_offset: usize, tos_value: u8) -> Result<(), ()> {
    let byte0: u8 = ctx.load(l3_offset).map_err(|_| ())?;
    let byte1: u8 = ctx.load(l3_offset + 1).map_err(|_| ())?;

    // Extract current Traffic Class:
    //   TC[7:4] = byte0[3:0], TC[3:0] = byte1[7:4]
    let current_tc = ((byte0 & 0x0F) << 4) | ((byte1 & 0xF0) >> 4);
    if current_tc == tos_value {
        return Ok(());
    }

    // Write new Traffic Class:
    //   byte0[3:0] = tos_value[7:4] (keep byte0[7:4] = version)
    //   byte1[7:4] = tos_value[3:0] (keep byte1[3:0] = flow label MSBs)
    let new_byte0 = (byte0 & 0xF0) | ((tos_value >> 4) & 0x0F);
    let new_byte1 = ((tos_value & 0x0F) << 4) | (byte1 & 0x0F);

    ctx.store(l3_offset, &new_byte0, 0).map_err(|_| ())?;
    ctx.store(l3_offset + 1, &new_byte1, 0).map_err(|_| ())?;

    increment_metric(SCRUB_METRIC_TOS_NORMALIZED);
    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
