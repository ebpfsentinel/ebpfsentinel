#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_OK,
    helpers::{bpf_get_prandom_u32, bpf_l3_csum_replace, bpf_l4_csum_replace},
    macros::{classifier, map},
    maps::{Array, PerCpuArray},
    programs::TcContext,
    EbpfContext,
};
use core::mem;
use ebpf_common::scrub::{
    ScrubFlags, SCRUB_METRIC_COUNT, SCRUB_METRIC_DF_CLEARED, SCRUB_METRIC_ERRORS,
    SCRUB_METRIC_HOP_FIXED, SCRUB_METRIC_IPID_RANDOMIZED, SCRUB_METRIC_MSS_CLAMPED,
    SCRUB_METRIC_PACKETS, SCRUB_METRIC_TOTAL_SEEN, SCRUB_METRIC_TTL_FIXED,
};
use network_types::{eth::EthHdr, ip::Ipv4Hdr};

// ── Constants ───────────────────────────────────────────────────────

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const ETH_P_8021Q: u16 = 0x8100;
const VLAN_HDR_LEN: usize = 4;
const IPV6_HDR_LEN: usize = 40;
const PROTO_TCP: u8 = 6;

/// IPv4 flags field offset within Ipv4Hdr (frag_off contains flags + fragment offset).
/// DF = bit 14 (0x4000 in network byte order).
const IP_DF: u16 = 0x4000; // Don't Fragment flag in host byte order

/// TCP option kind: MSS.
const TCP_OPT_MSS: u8 = 2;
/// TCP option kind: End of options.
const TCP_OPT_EOL: u8 = 0;
/// TCP option kind: NOP.
const TCP_OPT_NOP: u8 = 1;

/// TCP SYN flag.
const TCP_SYN: u8 = 0x02;

/// Maximum TCP options bytes to scan (prevents unbounded loops).
const MAX_TCP_OPT_SCAN: usize = 40;

// ── Inline header types ─────────────────────────────────────────────

#[repr(C)]
struct VlanHdr {
    _tci: u16,
    ether_type: u16,
}

/// IPv6 fixed header (40 bytes).
#[repr(C)]
struct Ipv6Hdr {
    _vtcfl: u32,
    _payload_len: u16,
    next_hdr: u8,
    hop_limit: u8,
    _src_addr: [u8; 16],
    _dst_addr: [u8; 16],
}

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
    match try_tc_scrub(&mut ctx) {
        Ok(action) => action,
        Err(()) => {
            increment_metric(SCRUB_METRIC_ERRORS);
            TC_ACT_OK
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

#[inline(always)]
fn increment_metric(index: u32) {
    if let Some(counter) = SCRUB_METRICS.get_ptr_mut(index) {
        unsafe {
            *counter += 1;
        }
    }
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &TcContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();
    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
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
    if ether_type == ETH_P_8021Q {
        let vhdr: *const VlanHdr = unsafe { ptr_at(ctx, l3_offset)? };
        ether_type = u16::from_be(unsafe { (*vhdr).ether_type });
        l3_offset += VLAN_HDR_LEN;
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

    // ── TTL normalization ───────────────────────────────────────
    if cfg.min_ttl > 0 {
        let ttl = unsafe { (*ipv4hdr).ttl };
        if ttl < cfg.min_ttl {
            scrub_fix_ttl(ctx, l3_offset, ttl, cfg.min_ttl)?;
            increment_metric(SCRUB_METRIC_TTL_FIXED);
        }
    }

    // ── Clear DF bit ────────────────────────────────────────────
    if cfg.clear_df != 0 {
        let frag_off = u16::from_be_bytes(unsafe { (*ipv4hdr).frags });
        if frag_off & IP_DF != 0 {
            scrub_clear_df(ctx, l3_offset, frag_off)?;
            increment_metric(SCRUB_METRIC_DF_CLEARED);
        }
    }

    // ── Randomize IP ID ─────────────────────────────────────────
    if cfg.random_ip_id != 0 {
        let old_id = u16::from_be_bytes(unsafe { (*ipv4hdr).id });
        let new_id = (unsafe { bpf_get_prandom_u32() } & 0xFFFF) as u16;
        if old_id != new_id {
            scrub_random_ip_id(ctx, l3_offset, old_id, new_id)?;
            increment_metric(SCRUB_METRIC_IPID_RANDOMIZED);
        }
    }

    // ── MSS clamping (TCP SYN only) ─────────────────────────────
    if cfg.max_mss > 0 && protocol == PROTO_TCP {
        scrub_mss_clamp(ctx, cfg.max_mss, l3_offset, l4_offset)?;
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
    let protocol = unsafe { (*ipv6hdr).next_hdr };
    let l4_offset = l3_offset + IPV6_HDR_LEN;

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

    // ── MSS clamping (TCP SYN only) ─────────────────────────────
    // TCP options are L4-agnostic, reuse the same function.
    if cfg.max_mss > 0 && protocol == PROTO_TCP {
        scrub_mss_clamp(ctx, cfg.max_mss, l3_offset, l4_offset)?;
    }

    Ok(())
}

/// Rewrite TTL field and update IPv4 header checksum.
#[inline(always)]
fn scrub_fix_ttl(ctx: &mut TcContext, l3_offset: usize, old_ttl: u8, new_ttl: u8) -> Result<(), ()> {
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
        bpf_l3_csum_replace(ctx.as_ptr() as *mut _, csum_offset, old_val as u64, new_val as u64, 2);
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
            new_id_be as u64,
            2,
        );
    }
    Ok(())
}

/// Clamp MSS option in TCP SYN packets if MSS > max_mss.
///
/// Scans TCP options looking for MSS (kind=2, len=4), rewrites in-place.
#[inline(always)]
fn scrub_mss_clamp(
    ctx: &mut TcContext,
    max_mss: u16,
    _l3_offset: usize,
    l4_offset: usize,
) -> Result<(), ()> {
    // Read TCP flags to check if SYN
    let flags_offset = l4_offset + 13;
    let flags: u8 = ctx.load(flags_offset).map_err(|_| ())?;
    if flags & TCP_SYN == 0 {
        return Ok(()); // Not a SYN — nothing to clamp
    }

    // TCP data offset (header length in 32-bit words)
    let doff_byte: u8 = ctx.load(l4_offset + 12).map_err(|_| ())?;
    let tcp_hdr_len = ((doff_byte >> 4) as usize) * 4;
    if tcp_hdr_len <= 20 {
        return Ok(()); // No options
    }

    let opts_start = l4_offset + 20;
    let opts_end = l4_offset + tcp_hdr_len;
    let mut pos = opts_start;

    // Scan TCP options (bounded loop)
    let mut i = 0usize;
    while i < MAX_TCP_OPT_SCAN && pos < opts_end {
        let kind: u8 = ctx.load(pos).map_err(|_| ())?;

        if kind == TCP_OPT_EOL {
            break;
        }
        if kind == TCP_OPT_NOP {
            pos += 1;
            i += 1;
            continue;
        }

        // Read option length
        if pos + 1 >= opts_end {
            break;
        }
        let opt_len: u8 = ctx.load(pos + 1).map_err(|_| ())?;
        if opt_len < 2 {
            break; // Invalid
        }

        if kind == TCP_OPT_MSS && opt_len == 4 && pos + 4 <= opts_end {
            // Read current MSS (network byte order)
            let mss_hi: u8 = ctx.load(pos + 2).map_err(|_| ())?;
            let mss_lo: u8 = ctx.load(pos + 3).map_err(|_| ())?;
            let current_mss = ((mss_hi as u16) << 8) | (mss_lo as u16);

            if current_mss > max_mss {
                // Clamp MSS
                let new_mss_be = max_mss.to_be_bytes();
                let old_mss_val = current_mss as u32;
                let new_mss_val = max_mss as u32;

                ctx.store(pos + 2, &new_mss_be[0], 0).map_err(|_| ())?;
                ctx.store(pos + 3, &new_mss_be[1], 0).map_err(|_| ())?;

                // Update TCP checksum (offset 16 in TCP header)
                let tcp_csum_offset = (l4_offset + 16) as u32;
                unsafe {
                    bpf_l4_csum_replace(
                        ctx.as_ptr() as *mut _,
                        tcp_csum_offset,
                        old_mss_val as u64,
                        new_mss_val as u64,
                        2,
                    );
                }

                increment_metric(SCRUB_METRIC_MSS_CLAMPED);
            }
            break; // Only one MSS option expected
        }

        pos += opt_len as usize;
        i += 1;
    }

    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
