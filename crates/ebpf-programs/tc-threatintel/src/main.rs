#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::BPF_F_NO_PREALLOC,
    bindings::TC_ACT_OK,
    bindings::TC_ACT_SHOT,
    btf_maps::{Array, HashMap, LpmTrie, PerCpuArray, RingBuf, lpm_trie::Key},
    macros::{btf_map, classifier},
    programs::TcContext,
};
use ebpf_common::{
    config_flags::ConfigFlags,
    event::{EVENT_TYPE_THREATINTEL, PacketEvent},
    firewall::{
        FW_EMPTY_THREAT_IOCS_V4, FW_EMPTY_THREAT_IOCS_V6, FW_EMPTY_THREAT_NETS_V4,
        FW_EMPTY_THREAT_NETS_V6,
    },
    threatintel::{
        THREATINTEL_ACTION_DROP, THREATINTEL_MAX_ENTRIES, THREATINTEL_METRIC_DROPPED,
        THREATINTEL_METRIC_ERRORS, THREATINTEL_METRIC_EVENTS_DROPPED, THREATINTEL_METRIC_MATCHED,
        THREATINTEL_METRIC_TOTAL_SEEN, THREATINTEL_SLOT_B, ThreatIntelKey, ThreatIntelKeyV6,
        ThreatIntelValue,
    },
};
use ebpf_helpers::net::{
    IPV6_HDR_LEN, Ipv6Hdr, PROTO_TCP, PROTO_UDP, ipv6_addr_to_u32x4, u16_from_be_bytes,
    u32_from_be_bytes,
};
use ebpf_helpers::pktmeta;
use ebpf_helpers::tc::{ptr_at, skip_ipv6_ext_headers};
use ebpf_helpers::trace::{self, reason, stage};
use ebpf_helpers::{emit_packet_event, increment_metric};
use network_types::{
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

// ── The indicator tables ────────────────────────────────────────────
//
// Two slots, A and B, each an address table and a range trie per family.
// The datapath reads the slot `THREATINTEL_SLOT` names; a reload writes the
// other one whole, flips the selector, then empties the one it left, so a
// packet sees the old set or the new set and never a set half written.
//
// The address tables are plain hash maps, never LRU: a full table refuses an
// insert, and userspace refuses a set larger than the table before writing
// any of it, so an indicator is never evicted to make room for another. They
// are created with `BPF_F_NO_PREALLOC`, as a trie always is, so an entry is
// allocated when it is written: the second slot costs memory only while a
// reload fills it, and a capacity sized for the feeds costs nothing until
// they fill it.

const ON_INSERT: usize = BPF_F_NO_PREALLOC as usize;
const MAX: usize = THREATINTEL_MAX_ENTRIES as usize;

/// Which slot the datapath reads: `THREATINTEL_SLOT_A` (0) or
/// `THREATINTEL_SLOT_B` (1). Unwritten, it reads slot A.
#[btf_map]
static THREATINTEL_SLOT: Array<u32, 1> = Array::new();

/// IPv4 address (host order) to action and feed, slot A.
#[btf_map]
static THREATINTEL_IOCS_A: HashMap<ThreatIntelKey, ThreatIntelValue, MAX, ON_INSERT> =
    HashMap::new();
/// IPv4 address to action and feed, slot B.
#[btf_map]
static THREATINTEL_IOCS_B: HashMap<ThreatIntelKey, ThreatIntelValue, MAX, ON_INSERT> =
    HashMap::new();
/// IPv6 address to action and feed, slot A.
#[btf_map]
static THREATINTEL_IOCS_V6_A: HashMap<ThreatIntelKeyV6, ThreatIntelValue, MAX, ON_INSERT> =
    HashMap::new();
/// IPv6 address to action and feed, slot B.
#[btf_map]
static THREATINTEL_IOCS_V6_B: HashMap<ThreatIntelKeyV6, ThreatIntelValue, MAX, ON_INSERT> =
    HashMap::new();

/// IPv4 range (network byte order) to action and feed, slot A.
#[btf_map]
static THREATINTEL_NETS_A: LpmTrie<[u8; 4], ThreatIntelValue, MAX> = LpmTrie::new();
/// IPv4 range to action and feed, slot B.
#[btf_map]
static THREATINTEL_NETS_B: LpmTrie<[u8; 4], ThreatIntelValue, MAX> = LpmTrie::new();
/// IPv6 range (network byte order) to action and feed, slot A.
#[btf_map]
static THREATINTEL_NETS_V6_A: LpmTrie<[u8; 16], ThreatIntelValue, MAX> = LpmTrie::new();
/// IPv6 range to action and feed, slot B.
#[btf_map]
static THREATINTEL_NETS_V6_B: LpmTrie<[u8; 16], ThreatIntelValue, MAX> = LpmTrie::new();

#[inline(always)]
fn reads_slot_b() -> bool {
    match THREATINTEL_SLOT.get(0) {
        Some(&slot) => slot == THREATINTEL_SLOT_B,
        None => false,
    }
}

/// The indicator deciding for one IPv4 address: the address itself when it
/// is listed, otherwise the longest range holding it.
#[inline(always)]
fn lookup_v4(slot_b: bool, gates: u32, ip: u32) -> Option<ThreatIntelValue> {
    if !feature_empty(gates, FW_EMPTY_THREAT_IOCS_V4) {
        let key = ThreatIntelKey { ip };
        let hit = if slot_b {
            unsafe { THREATINTEL_IOCS_B.get(&key) }
        } else {
            unsafe { THREATINTEL_IOCS_A.get(&key) }
        };
        if let Some(v) = hit {
            return Some(*v);
        }
    }
    if !feature_empty(gates, FW_EMPTY_THREAT_NETS_V4) {
        let key = Key::new(32, ip.to_be_bytes());
        let hit = if slot_b {
            THREATINTEL_NETS_B.get(&key)
        } else {
            THREATINTEL_NETS_A.get(&key)
        };
        if let Some(v) = hit {
            return Some(*v);
        }
    }
    None
}

/// The indicator deciding for one IPv6 address; see [`lookup_v4`].
#[inline(always)]
fn lookup_v6(slot_b: bool, gates: u32, addr: &[u8; 16]) -> Option<ThreatIntelValue> {
    if !feature_empty(gates, FW_EMPTY_THREAT_IOCS_V6) {
        let key = ThreatIntelKeyV6 {
            ip: ipv6_addr_to_u32x4(addr),
        };
        let hit = if slot_b {
            unsafe { THREATINTEL_IOCS_V6_B.get(&key) }
        } else {
            unsafe { THREATINTEL_IOCS_V6_A.get(&key) }
        };
        if let Some(v) = hit {
            return Some(*v);
        }
    }
    if !feature_empty(gates, FW_EMPTY_THREAT_NETS_V6) {
        let key = Key::new(128, *addr);
        let hit = if slot_b {
            THREATINTEL_NETS_V6_B.get(&key)
        } else {
            THREATINTEL_NETS_V6_A.get(&key)
        };
        if let Some(v) = hit {
            return Some(*v);
        }
    }
    None
}

/// The stronger of the two ends' verdicts: a drop wins over an alert.
#[inline(always)]
fn stronger(
    src: Option<ThreatIntelValue>,
    dst: Option<ThreatIntelValue>,
) -> Option<ThreatIntelValue> {
    match (src, dst) {
        (None, None) => None,
        (Some(v), None) | (None, Some(v)) => Some(v),
        (Some(s), Some(d)) => Some(if d.action > s.action { d } else { s }),
    }
}

/// Per-CPU counters. Index: 0=matched, 1=dropped, 2=errors, 3=events_dropped, 4=total_seen.
#[btf_map]
static THREATINTEL_METRICS: PerCpuArray<u64, 5> = PerCpuArray::new();

/// Kernel->userspace event ring buffer, 1 MiB: about 7,500 packet events
/// before backpressure refuses new ones (sizing in `ebpf_helpers::ringbuf`).
#[btf_map]
static EVENTS: RingBuf<PacketEvent, { 256 * 4096 }> = RingBuf::new();

/// Feature enable/disable flags (shared across programs).
///
/// The value type has to be `ConfigFlags` and not a bare integer: userspace
/// writes the whole struct through `ConfigFlagsManager`, and aya refuses to
/// bind a typed map handle whose value size disagrees with the map, so a
/// narrower type here means the map is never acquired and the flags stay zero.
#[btf_map]
static CONFIG_FLAGS: Array<ConfigFlags, 1> = Array::new();

/// Which optional tables userspace has loaded nothing into.
///
/// The same map the firewall, the rate limiter and the classifier gate on,
/// shared by pin. Userspace publishes a bit per empty feature and the lookup
/// is skipped. The sense is inverted on purpose: an unwritten map, or an
/// object loaded by a userspace that never heard of it, reads 0 and every
/// lookup still happens, so a stale value can only be slower, never wrong.
#[btf_map]
static FW_EMPTY_FEATURES: Array<u32, 1> = Array::new();

#[inline(always)]
fn empty_features() -> u32 {
    match FW_EMPTY_FEATURES.get(0) {
        Some(&mask) => mask,
        None => 0,
    }
}

#[inline(always)]
fn feature_empty(gates: u32, bit: u32) -> bool {
    (gates & bit) != 0
}

// ── Entry point ─────────────────────────────────────────────────────

/// TC classifier entry point. Delegates to try_tc_threatintel; any error
/// returns TC_ACT_OK (NFR15: default-to-pass on internal error).
#[classifier]
pub fn tc_threatintel(ctx: TcContext) -> i32 {
    // A traced packet is decided like any other, moves no counter and
    // raises no event.
    let traced = trace::tc(&ctx);
    increment_metric(traced, THREATINTEL_METRIC_TOTAL_SEEN);
    let action = match try_tc_threatintel(&ctx) {
        Ok(action) => action,
        Err(()) => {
            increment_metric(traced, THREATINTEL_METRIC_ERRORS);
            trace::tc_record(&ctx, stage::THREATINTEL, reason::MALFORMED, 0, 0);
            TC_ACT_OK
        }
    };
    // Under TCX (kernel >= 6.6) returning TC_ACT_OK terminates the program
    // chain on this hook; translate a "pass" verdict to TCX_NEXT (-1) so other
    // tc programs on the same interface still run. Terminal verdicts pass through.
    if action == TC_ACT_OK { -1 } else { action }
}

// ── Packet processing ───────────────────────────────────────────────

#[inline(always)]
fn try_tc_threatintel(ctx: &TcContext) -> Result<i32, ()> {
    // Check if threat intel is enabled via config flags (0 = disabled).
    if let Some(flags) = CONFIG_FLAGS.get(0) {
        if flags.threatintel_enabled == 0 {
            trace::tc_record(ctx, stage::THREATINTEL, reason::DISABLED, 0, 0);
            return Ok(TC_ACT_OK);
        }
    }

    // A table userspace left empty is not looked up, and when every table
    // of both families is empty nothing below this point would fire,
    // including the parse.
    // The slot is read before the gates: a reload clears the gates of the
    // tables it is about to fill before it flips the selector, and sets the
    // ones its new slot left empty after, so a packet reading the new slot
    // never finds a gate closed over a table holding indicators.
    let slot_b = reads_slot_b();
    let gates = empty_features();
    let v4_empty = feature_empty(gates, FW_EMPTY_THREAT_IOCS_V4)
        && feature_empty(gates, FW_EMPTY_THREAT_NETS_V4);
    let v6_empty = feature_empty(gates, FW_EMPTY_THREAT_IOCS_V6)
        && feature_empty(gates, FW_EMPTY_THREAT_NETS_V6);
    if v4_empty && v6_empty {
        trace::tc_record(ctx, stage::THREATINTEL, reason::DEFAULT, 0, 0);
        return Ok(TC_ACT_OK);
    }

    let meta = pktmeta::resolve(ctx)?;
    let pkt_flags = meta.event_flags();

    if meta.is_ipv4() {
        if v4_empty {
            trace::tc_record(ctx, stage::THREATINTEL, reason::DEFAULT, 0, 0);
            return Ok(TC_ACT_OK);
        }
        process_threatintel_v4(ctx, slot_b, gates, meta.l3(), meta.vlan_id, pkt_flags)
    } else if meta.is_ipv6() {
        if v6_empty {
            trace::tc_record(ctx, stage::THREATINTEL, reason::DEFAULT, 0, 0);
            return Ok(TC_ACT_OK);
        }
        process_threatintel_v6(ctx, slot_b, gates, meta.l3(), meta.vlan_id, pkt_flags)
    } else {
        trace::tc_record(ctx, stage::THREATINTEL, reason::MALFORMED, 0, 0);
        Ok(TC_ACT_OK)
    }
}

/// IPv4 threat intel processing.
#[inline(always)]
fn process_threatintel_v4(
    ctx: &TcContext,
    slot_b: bool,
    gates: u32,
    l3_offset: usize,
    vlan_id: u16,
    flags: u8,
) -> Result<i32, ()> {
    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(ctx, l3_offset)? };
    let src_ip = u32_from_be_bytes(unsafe { (*ipv4hdr).src_addr });
    let dst_ip = u32_from_be_bytes(unsafe { (*ipv4hdr).dst_addr });
    let protocol = unsafe { (*ipv4hdr).proto() }.unwrap_or(IpProto::Reserved);

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

    // Source and destination: the address table, then the range trie, in
    // the slot read above; the stronger action of the two wins.
    let Some(matched) = stronger(
        lookup_v4(slot_b, gates, src_ip),
        lookup_v4(slot_b, gates, dst_ip),
    ) else {
        trace::tc_record(ctx, stage::THREATINTEL, reason::DEFAULT, 0, 0);
        return Ok(TC_ACT_OK);
    };

    let src_addr = [src_ip, 0, 0, 0];
    let dst_addr = [dst_ip, 0, 0, 0];
    apply_threatintel_action(
        ctx,
        &matched,
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
    slot_b: bool,
    gates: u32,
    l3_offset: usize,
    vlan_id: u16,
    flags: u8,
) -> Result<i32, ()> {
    let ipv6hdr: *const Ipv6Hdr = unsafe { ptr_at(ctx, l3_offset)? };
    let src_raw: [u8; 16] = unsafe { (*ipv6hdr).src_addr };
    let dst_raw: [u8; 16] = unsafe { (*ipv6hdr).dst_addr };
    let raw_next_hdr = unsafe { (*ipv6hdr).next_hdr };

    // Skip IPv6 extension headers to find the actual L4 protocol.
    let (next_hdr, l4_offset) =
        skip_ipv6_ext_headers(ctx, l3_offset + IPV6_HDR_LEN, raw_next_hdr).ok_or(())?;

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
    let Some(matched) = stronger(
        lookup_v6(slot_b, gates, &src_raw),
        lookup_v6(slot_b, gates, &dst_raw),
    ) else {
        trace::tc_record(ctx, stage::THREATINTEL, reason::DEFAULT, 0, 0);
        return Ok(TC_ACT_OK);
    };

    let src_addr = ipv6_addr_to_u32x4(&src_raw);
    let dst_addr = ipv6_addr_to_u32x4(&dst_raw);
    apply_threatintel_action(
        ctx, &matched, &src_addr, &dst_addr, src_port, dst_port, next_hdr, flags, vlan_id,
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
    let traced = trace::tc(ctx);
    trace::tc_record(
        ctx,
        stage::THREATINTEL,
        reason::LIST,
        matched.feed_id as u32,
        u32::from(matched.action),
    );
    increment_metric(traced, THREATINTEL_METRIC_MATCHED);
    if !traced {
        (|| {
            emit_packet_event!(EVENTS, THREATINTEL_METRICS, THREATINTEL_METRIC_EVENTS_DROPPED,
                src_addr, dst_addr, src_port, dst_port, protocol,
                EVENT_TYPE_THREATINTEL, matched.action, matched.feed_id as u32, flags, vlan_id; tc ctx);
        })();
    }

    if matched.action == THREATINTEL_ACTION_DROP {
        increment_metric(traced, THREATINTEL_METRIC_DROPPED);
        Ok(TC_ACT_SHOT)
    } else {
        Ok(TC_ACT_OK)
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

// ptr_at, skip_ipv6_ext_headers imported from ebpf_helpers::tc

/// Increment a per-CPU metric counter.
#[inline(always)]
fn increment_metric(traced: bool, index: u32) {
    if !traced {
        increment_metric!(THREATINTEL_METRICS, index);
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
