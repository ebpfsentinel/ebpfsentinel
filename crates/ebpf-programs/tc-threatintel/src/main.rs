#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_OK,
    bindings::TC_ACT_SHOT,
    helpers::{
        bpf_get_smp_processor_id, bpf_ktime_get_boot_ns, bpf_skb_vlan_pop, bpf_skb_vlan_push,
    },
    macros::{classifier, map},
    maps::{Array, HashMap, PerCpuArray, RingBuf, bloom_filter::BloomFilter},
    programs::TcContext,
};
use aya_log_ebpf::info;
use core::mem;
use ebpf_common::{
    event::{
        EVENT_TYPE_THREATINTEL, FLAG_IPV6, FLAG_VLAN, META_FLAG_PRESENT, PacketEvent, XdpMetadata,
    },
    threatintel::{
        THREATINTEL_ACTION_DROP, THREATINTEL_MAX_ENTRIES, THREATINTEL_METRIC_DROPPED,
        THREATINTEL_METRIC_ERRORS, THREATINTEL_METRIC_EVENTS_DROPPED, THREATINTEL_METRIC_MATCHED,
        ThreatIntelKey, ThreatIntelKeyV6, ThreatIntelValue,
    },
};
use network_types::{
    eth::EthHdr,
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

// ── Constants ───────────────────────────────────────────────────────

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const ETH_P_8021Q: u16 = 0x8100;
const VLAN_HDR_LEN: usize = 4;
const IPV6_HDR_LEN: usize = 40;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;

// ── Inline IPv6 / VLAN header types ─────────────────────────────────

/// IPv6 fixed header (40 bytes).
#[repr(C)]
struct Ipv6Hdr {
    _vtcfl: u32,
    _payload_len: u16,
    next_hdr: u8,
    _hop_limit: u8,
    src_addr: [u8; 16],
    dst_addr: [u8; 16],
}

/// 802.1Q VLAN tag (4 bytes after EthHdr when ether_type == 0x8100).
#[repr(C)]
struct VlanHdr {
    tci: u16,
    ether_type: u16,
}

// ── Maps ────────────────────────────────────────────────────────────

/// Threat intel IOC lookup: IPv4 address → action + feed metadata.
/// Supports 1M+ entries (NFR22).
#[map]
static THREATINTEL_IOCS: HashMap<ThreatIntelKey, ThreatIntelValue> =
    HashMap::with_max_entries(THREATINTEL_MAX_ENTRIES, 0);

/// Threat intel IOC lookup: IPv6 address → action + feed metadata.
#[map]
static THREATINTEL_IOCS_V6: HashMap<ThreatIntelKeyV6, ThreatIntelValue> =
    HashMap::with_max_entries(THREATINTEL_MAX_ENTRIES, 0);

/// Bloom filter pre-check for IPv4 IOCs (kernel 5.16+).
/// Eliminates ~98% of HashMap lookups for non-matching packets.
#[map]
static mut THREATINTEL_BLOOM_V4: BloomFilter<ThreatIntelKey> =
    BloomFilter::with_max_entries(THREATINTEL_MAX_ENTRIES, 0);

/// Bloom filter pre-check for IPv6 IOCs (kernel 5.16+).
#[map]
static mut THREATINTEL_BLOOM_V6: BloomFilter<ThreatIntelKeyV6> =
    BloomFilter::with_max_entries(THREATINTEL_MAX_ENTRIES, 0);

/// Per-CPU counters. Index: 0=matched, 1=dropped, 2=errors, 3=events_dropped.
#[map]
static THREATINTEL_METRICS: PerCpuArray<u64> = PerCpuArray::with_max_entries(4, 0);

/// Shared kernel→userspace event ring buffer (1 MB).
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 4096, 0);

/// Feature enable/disable flags (shared across programs).
#[map]
static CONFIG_FLAGS: Array<u32> = Array::with_max_entries(1, 0);

// ── Backpressure constants ───────────────────────────────────────────

/// RingBuf total size in bytes (must match EVENTS map declaration).
const EVENTS_RINGBUF_SIZE: u64 = 256 * 4096;

/// Backpressure threshold: skip emission when >75% of RingBuf is consumed.
const BACKPRESSURE_THRESHOLD: u64 = EVENTS_RINGBUF_SIZE * 3 / 4;

/// `BPF_RB_AVAIL_DATA` flag for `bpf_ringbuf_query`.
const BPF_RB_AVAIL_DATA: u64 = 0;

/// Returns `true` if the EVENTS RingBuf has backpressure (>75% full).
#[inline(always)]
fn ringbuf_has_backpressure() -> bool {
    EVENTS.query(BPF_RB_AVAIL_DATA) > BACKPRESSURE_THRESHOLD
}

// ── Entry point ─────────────────────────────────────────────────────

/// TC classifier entry point. Delegates to try_tc_threatintel; any error
/// returns TC_ACT_OK (NFR15: default-to-pass on internal error).
#[classifier]
pub fn tc_threatintel(ctx: TcContext) -> i32 {
    match try_tc_threatintel(&ctx) {
        Ok(action) => action,
        Err(()) => {
            increment_metric(THREATINTEL_METRIC_ERRORS);
            TC_ACT_OK
        }
    }
}

// ── Helpers: byte conversion ────────────────────────────────────────

#[inline(always)]
fn u32_from_be_bytes(b: [u8; 4]) -> u32 {
    u32::from_be_bytes(b)
}

#[inline(always)]
fn u16_from_be_bytes(b: [u8; 2]) -> u16 {
    u16::from_be_bytes(b)
}

/// Convert a 16-byte IPv6 address to `[u32; 4]` in network byte order.
#[inline(always)]
fn ipv6_addr_to_u32x4(addr: &[u8; 16]) -> [u32; 4] {
    [
        u32_from_be_bytes([addr[0], addr[1], addr[2], addr[3]]),
        u32_from_be_bytes([addr[4], addr[5], addr[6], addr[7]]),
        u32_from_be_bytes([addr[8], addr[9], addr[10], addr[11]]),
        u32_from_be_bytes([addr[12], addr[13], addr[14], addr[15]]),
    ]
}

// ── XDP metadata reading ────────────────────────────────────────────

/// Read XDP metadata (firewall verdict) prepended by `bpf_xdp_adjust_meta`.
#[inline(always)]
#[allow(dead_code)]
fn read_xdp_metadata(ctx: &TcContext) -> Option<XdpMetadata> {
    let data_meta = unsafe { (*ctx.skb.skb).data_meta as usize };
    let data = ctx.data();
    if data_meta + mem::size_of::<XdpMetadata>() > data {
        return None;
    }
    let meta_ptr = data_meta as *const XdpMetadata;
    let meta = unsafe { *meta_ptr };
    if meta.meta_flags & META_FLAG_PRESENT == 0 {
        return None;
    }
    Some(meta)
}

// ── Packet processing ───────────────────────────────────────────────

#[inline(always)]
fn try_tc_threatintel(ctx: &TcContext) -> Result<i32, ()> {
    // Check if threat intel is enabled via config flags (0 = disabled).
    if let Some(flags) = CONFIG_FLAGS.get(0) {
        if *flags == 0 {
            return Ok(TC_ACT_OK);
        }
    }

    // Parse Ethernet header
    let ethhdr: *const EthHdr = unsafe { ptr_at(ctx, 0)? };
    let mut ether_type = u16::from_be(unsafe { (*ethhdr).ether_type });
    let mut l3_offset = EthHdr::LEN;
    let mut vlan_id: u16 = 0;
    let mut pkt_flags: u8 = 0;

    // Check for 802.1Q VLAN tag
    if ether_type == ETH_P_8021Q {
        let vhdr: *const VlanHdr = unsafe { ptr_at(ctx, l3_offset)? };
        let tci = u16::from_be(unsafe { (*vhdr).tci });
        vlan_id = tci & 0x0FFF;
        ether_type = u16::from_be(unsafe { (*vhdr).ether_type });
        l3_offset += VLAN_HDR_LEN;
        pkt_flags |= FLAG_VLAN;
    }

    if ether_type == ETH_P_IP {
        process_threatintel_v4(ctx, l3_offset, vlan_id, pkt_flags)
    } else if ether_type == ETH_P_IPV6 {
        process_threatintel_v6(ctx, l3_offset, vlan_id, pkt_flags | FLAG_IPV6)
    } else {
        Ok(TC_ACT_OK)
    }
}

/// IPv4 threat intel processing.
#[inline(always)]
fn process_threatintel_v4(
    ctx: &TcContext,
    l3_offset: usize,
    vlan_id: u16,
    flags: u8,
) -> Result<i32, ()> {
    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(ctx, l3_offset)? };
    let src_ip = u32_from_be_bytes(unsafe { (*ipv4hdr).src_addr });
    let dst_ip = u32_from_be_bytes(unsafe { (*ipv4hdr).dst_addr });
    let protocol = unsafe { (*ipv4hdr).proto };

    // ihl() returns the header length in bytes (already multiplied by 4)
    let ihl = unsafe { (*ipv4hdr).ihl() } as usize;
    let l4_offset = l3_offset + ihl;

    // Parse L4 ports
    let (src_port, dst_port) = match protocol {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = unsafe { ptr_at(ctx, l4_offset)? };
            (
                u16_from_be_bytes(unsafe { (*tcphdr).source }),
                u16_from_be_bytes(unsafe { (*tcphdr).dest }),
            )
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr = unsafe { ptr_at(ctx, l4_offset)? };
            (
                u16_from_be_bytes(unsafe { (*udphdr).src }),
                u16_from_be_bytes(unsafe { (*udphdr).dst }),
            )
        }
        _ => (0u16, 0u16),
    };

    // IOC lookup: bloom filter pre-check avoids HashMap lookups for
    // ~98% of non-matching packets (kernel 5.16+).
    let src_key = ThreatIntelKey { ip: src_ip };
    let dst_key = ThreatIntelKey { ip: dst_ip };

    let src_maybe = unsafe {
        (*core::ptr::addr_of_mut!(THREATINTEL_BLOOM_V4))
            .contains(&src_key)
            .is_ok()
    };
    let dst_maybe = unsafe {
        (*core::ptr::addr_of_mut!(THREATINTEL_BLOOM_V4))
            .contains(&dst_key)
            .is_ok()
    };

    if !src_maybe && !dst_maybe {
        return Ok(TC_ACT_OK); // guaranteed no match
    }

    let src_match = if src_maybe {
        unsafe { THREATINTEL_IOCS.get(&src_key) }
    } else {
        None
    };
    let dst_match = if dst_maybe {
        unsafe { THREATINTEL_IOCS.get(&dst_key) }
    } else {
        None
    };

    let matched = match (src_match, dst_match) {
        (None, None) => return Ok(TC_ACT_OK), // bloom false positive
        (Some(v), None) | (None, Some(v)) => v,
        (Some(s), Some(d)) => {
            if d.action > s.action {
                d
            } else {
                s
            }
        }
    };

    let src_addr = [src_ip, 0, 0, 0];
    let dst_addr = [dst_ip, 0, 0, 0];
    apply_threatintel_action(
        ctx,
        matched,
        &src_addr,
        &dst_addr,
        src_port,
        dst_port,
        protocol as u8,
        flags,
        vlan_id,
    )
}

/// IPv6 threat intel processing.
#[inline(always)]
fn process_threatintel_v6(
    ctx: &TcContext,
    l3_offset: usize,
    vlan_id: u16,
    flags: u8,
) -> Result<i32, ()> {
    let ipv6hdr: *const Ipv6Hdr = unsafe { ptr_at(ctx, l3_offset)? };
    let src_addr = ipv6_addr_to_u32x4(unsafe { &(*ipv6hdr).src_addr });
    let dst_addr = ipv6_addr_to_u32x4(unsafe { &(*ipv6hdr).dst_addr });
    let next_hdr = unsafe { (*ipv6hdr).next_hdr };

    let l4_offset = l3_offset + IPV6_HDR_LEN;

    // Parse L4 ports
    let (src_port, dst_port) = if next_hdr == PROTO_TCP {
        let tcphdr: *const TcpHdr = unsafe { ptr_at(ctx, l4_offset)? };
        (
            u16_from_be_bytes(unsafe { (*tcphdr).source }),
            u16_from_be_bytes(unsafe { (*tcphdr).dest }),
        )
    } else if next_hdr == PROTO_UDP {
        let udphdr: *const UdpHdr = unsafe { ptr_at(ctx, l4_offset)? };
        (
            u16_from_be_bytes(unsafe { (*udphdr).src }),
            u16_from_be_bytes(unsafe { (*udphdr).dst }),
        )
    } else {
        (0u16, 0u16)
    };

    // IOC lookup: bloom filter pre-check for IPv6.
    let src_key = ThreatIntelKeyV6 { ip: src_addr };
    let dst_key = ThreatIntelKeyV6 { ip: dst_addr };

    let src_maybe = unsafe {
        (*core::ptr::addr_of_mut!(THREATINTEL_BLOOM_V6))
            .contains(&src_key)
            .is_ok()
    };
    let dst_maybe = unsafe {
        (*core::ptr::addr_of_mut!(THREATINTEL_BLOOM_V6))
            .contains(&dst_key)
            .is_ok()
    };

    if !src_maybe && !dst_maybe {
        return Ok(TC_ACT_OK); // guaranteed no match
    }

    let src_match = if src_maybe {
        unsafe { THREATINTEL_IOCS_V6.get(&src_key) }
    } else {
        None
    };
    let dst_match = if dst_maybe {
        unsafe { THREATINTEL_IOCS_V6.get(&dst_key) }
    } else {
        None
    };

    let matched = match (src_match, dst_match) {
        (None, None) => return Ok(TC_ACT_OK), // bloom false positive
        (Some(v), None) | (None, Some(v)) => v,
        (Some(s), Some(d)) => {
            if d.action > s.action {
                d
            } else {
                s
            }
        }
    };

    apply_threatintel_action(
        ctx, matched, &src_addr, &dst_addr, src_port, dst_port, next_hdr, flags, vlan_id,
    )
}

/// Apply threat intel action (shared by v4/v6 paths).
#[inline(always)]
fn apply_threatintel_action(
    ctx: &TcContext,
    matched: &ThreatIntelValue,
    src_addr: &[u32; 4],
    dst_addr: &[u32; 4],
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    flags: u8,
    vlan_id: u16,
) -> Result<i32, ()> {
    increment_metric(THREATINTEL_METRIC_MATCHED);
    emit_event(
        src_addr, dst_addr, src_port, dst_port, protocol, matched, flags, vlan_id,
    );

    if matched.action == THREATINTEL_ACTION_DROP {
        info!(
            ctx,
            "THREATINTEL DROP {:i} -> {:i}:{}", src_addr[0], dst_addr[0], dst_port
        );
        increment_metric(THREATINTEL_METRIC_DROPPED);
        Ok(TC_ACT_SHOT)
    } else {
        info!(
            ctx,
            "THREATINTEL ALERT {:i} -> {:i}:{}", src_addr[0], dst_addr[0], dst_port
        );
        Ok(TC_ACT_OK)
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Bounds-checked pointer access. Critical for eBPF verifier compliance:
/// every memory access must be validated against data_end.
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

/// Increment a per-CPU metric counter.
#[inline(always)]
fn increment_metric(index: u32) {
    if let Some(counter) = THREATINTEL_METRICS.get_ptr_mut(index) {
        unsafe {
            *counter += 1;
        }
    }
}

/// Emit a PacketEvent to the EVENTS RingBuf. Skips emission under
/// backpressure (>75% full). If the buffer is full, increment the
/// events_dropped metric — never block the hot path.
#[inline(always)]
fn emit_event(
    src_addr: &[u32; 4],
    dst_addr: &[u32; 4],
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    matched: &ThreatIntelValue,
    flags: u8,
    vlan_id: u16,
) {
    if ringbuf_has_backpressure() {
        increment_metric(THREATINTEL_METRIC_EVENTS_DROPPED);
        return;
    }
    if let Some(mut entry) = EVENTS.reserve::<PacketEvent>(0) {
        let ptr = entry.as_mut_ptr();
        unsafe {
            (*ptr).timestamp_ns = bpf_ktime_get_boot_ns();
            (*ptr).src_addr = *src_addr;
            (*ptr).dst_addr = *dst_addr;
            (*ptr).src_port = src_port;
            (*ptr).dst_port = dst_port;
            (*ptr).protocol = protocol;
            (*ptr).event_type = EVENT_TYPE_THREATINTEL;
            (*ptr).action = matched.action;
            (*ptr).flags = flags;
            (*ptr).rule_id = matched.feed_id as u32;
            (*ptr).vlan_id = vlan_id;
            (*ptr).cpu_id = bpf_get_smp_processor_id() as u16;
            (*ptr).socket_cookie = 0;
        }
        entry.submit(0);
    } else {
        increment_metric(THREATINTEL_METRIC_EVENTS_DROPPED);
    }
}

// ── VLAN rewriting helpers (F15) ─────────────────────────────────────

/// 802.1Q EtherType in big-endian (network byte order): 0x8100 stored as 0x0081.
#[allow(dead_code)]
const ETH_P_8021Q_BE: u16 = 0x0081;

/// Push a VLAN tag onto a packet (e.g. quarantine VLAN).
///
/// Uses `bpf_skb_vlan_push` to insert an 802.1Q header with the given
/// `vlan_id`. The `vlan_proto` is always 802.1Q (0x8100).
#[inline(always)]
#[allow(dead_code)]
fn push_quarantine_vlan(ctx: &TcContext, vlan_id: u16) -> Result<(), i64> {
    let ret = unsafe { bpf_skb_vlan_push(ctx.skb.skb as *mut _, ETH_P_8021Q_BE, vlan_id) };
    if ret == 0 { Ok(()) } else { Err(ret) }
}

/// Pop the outermost VLAN tag from a packet.
///
/// Uses `bpf_skb_vlan_pop` to strip the 802.1Q header.
#[inline(always)]
#[allow(dead_code)]
fn pop_vlan(ctx: &TcContext) -> Result<(), i64> {
    let ret = unsafe { bpf_skb_vlan_pop(ctx.skb.skb as *mut _) };
    if ret == 0 { Ok(()) } else { Err(ret) }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
