#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_for_each_map_elem, bpf_get_smp_processor_id, bpf_ktime_get_boot_ns},
    macros::{map, xdp},
    maps::{Array, HashMap, LruPerCpuHashMap, PerCpuArray, RingBuf},
    programs::XdpContext,
};
use aya_log_ebpf::info;
use core::mem;
use ebpf_common::{
    ddos::{
        AmpProtectConfig, AmpProtectKey, ConnTrackConfig, ConnTrackKey, ConnTrackValue,
        DdosSynConfig, FloodCounterKey, IcmpConfig, SynRateState, CONNTRACK_SUB_ACK_FLOOD,
        CONNTRACK_SUB_FIN_FLOOD, CONNTRACK_SUB_HALF_OPEN, CONNTRACK_SUB_RST_FLOOD,
        CONN_ESTABLISHED, CONN_NEW, DDOS_ACTION_DROP, DDOS_ACTION_SYNCOOKIE,
        DDOS_METRIC_ACK_FLOOD_DROPS, DDOS_METRIC_AMP_DROPPED, DDOS_METRIC_AMP_PASSED,
        DDOS_METRIC_CONN_TRACKED, DDOS_METRIC_COUNT, DDOS_METRIC_EVENTS_DROPPED,
        DDOS_METRIC_FIN_FLOOD_DROPS, DDOS_METRIC_HALF_OPEN_DROPS, DDOS_METRIC_ICMP_DROPPED,
        DDOS_METRIC_ICMP_PASSED, DDOS_METRIC_OVERSIZED_ICMP, DDOS_METRIC_RST_FLOOD_DROPS,
        DDOS_METRIC_SYNCOOKIES_SENT, DDOS_METRIC_SYN_RECEIVED, EVENT_TYPE_DDOS_AMP,
        EVENT_TYPE_DDOS_CONNTRACK, EVENT_TYPE_DDOS_ICMP, EVENT_TYPE_DDOS_SYN, FLOOD_TYPE_ACK,
        FLOOD_TYPE_FIN, FLOOD_TYPE_RST,
    },
    event::{PacketEvent, EVENT_TYPE_RATELIMIT, FLAG_IPV6, FLAG_VLAN},
    ratelimit::{
        FixedWindowValue, LeakyBucketValue, RateLimitConfig, RateLimitKey, RateLimitValue,
        SlidingWindowValue, ALGO_FIXED_WINDOW, ALGO_LEAKY_BUCKET, ALGO_SLIDING_WINDOW,
        RATELIMIT_ACTION_DROP, SLIDING_WINDOW_NUM_SLOTS,
    },
};
use network_types::{
    eth::EthHdr,
    ip::Ipv4Hdr,
};

// ── Constants ───────────────────────────────────────────────────────

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const ETH_P_8021Q: u16 = 0x8100;
const VLAN_HDR_LEN: usize = 4;
const IPV6_HDR_LEN: usize = 40;
const PROTO_ICMP: u8 = 1;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_ICMPV6: u8 = 58;

/// ICMP Echo Request type (IPv4).
const ICMP_ECHO_REQUEST: u8 = 8;
/// ICMPv6 Echo Request type.
const ICMPV6_ECHO_REQUEST: u8 = 128;
/// ICMP header size (type + code + checksum + id + seq).
const ICMP_HDR_LEN: usize = 8;

/// TCP flag masks.
const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_ACK: u8 = 0x10;
const TCP_FLAG_RST: u8 = 0x04;
const TCP_FLAG_FIN: u8 = 0x01;

/// 1 second in nanoseconds.
const NS_PER_SEC: u64 = 1_000_000_000;

/// Fixed/sliding window duration: 1 second.
const WINDOW_NS: u64 = NS_PER_SEC;

/// Sliding window slot duration: 125ms (1s / 8 slots).
const SLOT_NS: u64 = WINDOW_NS / SLIDING_WINDOW_NUM_SLOTS as u64;

/// Maximum elapsed time considered for leaky bucket drain (10 seconds).
/// Prevents overflow for very long idle periods.
const LEAKY_MAX_ELAPSED_NS: u64 = 10 * NS_PER_SEC;

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

/// Inline TCP header for SYN detection (20 bytes minimum).
#[repr(C)]
struct TcpHdr {
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    /// Data offset (top 4 bits) + reserved (bottom 4 bits).
    doff_reserved: u8,
    /// TCP flags byte (FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08, ACK=0x10).
    flags: u8,
    window: u16,
    checksum: u16,
    urgent_ptr: u16,
}

/// ICMP header (8 bytes).
#[repr(C)]
struct IcmpHdr {
    icmp_type: u8,
    code: u8,
    checksum: u16,
    /// Identifier (for echo) or unused.
    id: u16,
    /// Sequence number (for echo) or unused.
    seq: u16,
}

// ── Maps ────────────────────────────────────────────────────────────

/// Per-source-IP rate limit configuration. Key `{ src_ip: 0 }` = global default.
#[map]
static RATELIMIT_CONFIG: HashMap<RateLimitKey, RateLimitConfig> =
    HashMap::with_max_entries(10240, 0);

/// Per-source-IP token bucket state. Per-CPU LRU eliminates cross-CPU
/// contention; each CPU maintains independent counters (effective rate
/// scales with CPU count — acceptable for DDoS mitigation).
#[map]
static RATELIMIT_BUCKETS: LruPerCpuHashMap<RateLimitKey, RateLimitValue> =
    LruPerCpuHashMap::with_max_entries(65536, 0);

/// Per-source-IP fixed window state (per-CPU).
#[map]
static FIXED_WINDOW_BUCKETS: LruPerCpuHashMap<RateLimitKey, FixedWindowValue> =
    LruPerCpuHashMap::with_max_entries(65536, 0);

/// Per-source-IP sliding window state (per-CPU).
#[map]
static SLIDING_WINDOW_BUCKETS: LruPerCpuHashMap<RateLimitKey, SlidingWindowValue> =
    LruPerCpuHashMap::with_max_entries(65536, 0);

/// Per-source-IP leaky bucket state (per-CPU).
#[map]
static LEAKY_BUCKET_BUCKETS: LruPerCpuHashMap<RateLimitKey, LeakyBucketValue> =
    LruPerCpuHashMap::with_max_entries(65536, 0);

/// Per-CPU counters. Index: 0=passed, 1=throttled, 2=errors, 3=events_dropped.
#[map]
static RATELIMIT_METRICS: PerCpuArray<u64> = PerCpuArray::with_max_entries(4, 0);

/// Shared kernel→userspace event ring buffer (1 MB).
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 4096, 0);

// ── DDoS Protection Maps ────────────────────────────────────────────

/// SYN flood protection configuration (single entry, index 0).
#[map]
static DDOS_SYN_CONFIG: Array<DdosSynConfig> = Array::with_max_entries(1, 0);

/// Per-source SYN rate tracking for threshold mode (per-CPU LRU).
#[map]
static SYN_RATE_TRACKER: LruPerCpuHashMap<RateLimitKey, SynRateState> =
    LruPerCpuHashMap::with_max_entries(65536, 0);

/// ICMP flood protection configuration (single entry, index 0).
#[map]
static ICMP_CONFIG: Array<IcmpConfig> = Array::with_max_entries(1, 0);

/// Per-source ICMP rate tracking (per-CPU LRU, fixed window).
#[map]
static ICMP_RATE_BUCKETS: LruPerCpuHashMap<RateLimitKey, FixedWindowValue> =
    LruPerCpuHashMap::with_max_entries(65536, 0);

/// UDP amplification protection config per service port.
#[map]
static AMP_PROTECT_CONFIG: HashMap<AmpProtectKey, AmpProtectConfig> =
    HashMap::with_max_entries(64, 0);

/// Per-source-per-port UDP amplification rate tracking.
/// Key is a hash of (src_ip, src_port) packed as u64.
#[map]
static AMP_RATE_BUCKETS: LruPerCpuHashMap<u64, FixedWindowValue> =
    LruPerCpuHashMap::with_max_entries(65536, 0);

/// DDoS-specific per-CPU metrics (14 indices, see `DDOS_METRIC_*` constants).
#[map]
static DDOS_METRICS: PerCpuArray<u64> = PerCpuArray::with_max_entries(DDOS_METRIC_COUNT, 0);

// ── Connection Tracking Maps ─────────────────────────────────────────

/// Connection tracking configuration (single entry, index 0).
#[map]
static CONNTRACK_CONFIG: Array<ConnTrackConfig> = Array::with_max_entries(1, 0);

/// Lightweight connection tracking table (per-CPU LRU).
/// Tracks TCP connections with 3 states: NEW, ESTABLISHED, CLOSING.
#[map]
static CONN_TABLE: LruPerCpuHashMap<ConnTrackKey, ConnTrackValue> =
    LruPerCpuHashMap::with_max_entries(131072, 0);

/// Per-source half-open connection counter (per-CPU LRU).
/// Counts SYNs without matching ACKs per source IP.
#[map]
static HALF_OPEN_COUNTERS: LruPerCpuHashMap<u32, u64> =
    LruPerCpuHashMap::with_max_entries(65536, 0);

/// Per-source per-flood-type rate counter (per-CPU LRU, fixed window).
/// Tracks RST/FIN/ACK flood rates.
#[map]
static FLOOD_COUNTERS: LruPerCpuHashMap<FloodCounterKey, FixedWindowValue> =
    LruPerCpuHashMap::with_max_entries(65536, 0);

// ── Metric indices ──────────────────────────────────────────────────

const METRIC_PASSED: u32 = 0;
const METRIC_THROTTLED: u32 = 1;
const METRIC_ERRORS: u32 = 2;
const METRIC_EVENTS_DROPPED: u32 = 3;

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

/// Increment a DDoS-specific per-CPU metric counter.
#[inline(always)]
fn increment_ddos_metric(index: u32) {
    if let Some(counter) = DDOS_METRICS.get_ptr_mut(index) {
        unsafe {
            *counter += 1;
        }
    }
}

// ── Entry point ─────────────────────────────────────────────────────

/// XDP entry point. Default-to-pass on internal error (NFR15).
#[xdp]
pub fn xdp_ratelimit(ctx: XdpContext) -> u32 {
    match try_xdp_ratelimit(&ctx) {
        Ok(action) => action,
        Err(()) => {
            increment_metric(METRIC_ERRORS);
            xdp_action::XDP_PASS
        }
    }
}

// ── Helpers: byte conversion ────────────────────────────────────────

#[inline(always)]
fn u32_from_be_bytes(b: [u8; 4]) -> u32 {
    u32::from_be_bytes(b)
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

/// Hash an IPv6 source address to a u32 for rate limit bucket lookup.
/// Uses XOR folding which gives reasonable distribution for rate limiting.
#[inline(always)]
fn hash_ipv6_src(addr: &[u32; 4]) -> u32 {
    addr[0] ^ addr[1] ^ addr[2] ^ addr[3]
}

// ── Packet processing ───────────────────────────────────────────────

#[inline(always)]
fn try_xdp_ratelimit(ctx: &XdpContext) -> Result<u32, ()> {
    // Parse Ethernet header
    let ethhdr: *const EthHdr = unsafe { ptr_at(ctx, 0)? };
    let mut ether_type = u16::from_be(unsafe { (*ethhdr).ether_type });
    let mut l3_offset = EthHdr::LEN;
    let mut vlan_id: u16 = 0;
    let mut flags: u8 = 0;

    // Check for 802.1Q VLAN tag
    if ether_type == ETH_P_8021Q {
        let vhdr: *const VlanHdr = unsafe { ptr_at(ctx, l3_offset)? };
        let tci = u16::from_be(unsafe { (*vhdr).tci });
        vlan_id = tci & 0x0FFF;
        ether_type = u16::from_be(unsafe { (*vhdr).ether_type });
        l3_offset += VLAN_HDR_LEN;
        flags |= FLAG_VLAN;
    }

    if ether_type == ETH_P_IP {
        process_ratelimit_v4(ctx, l3_offset, vlan_id, flags)
    } else if ether_type == ETH_P_IPV6 {
        process_ratelimit_v6(ctx, l3_offset, vlan_id, flags | FLAG_IPV6)
    } else {
        increment_metric(METRIC_PASSED);
        Ok(xdp_action::XDP_PASS)
    }
}

/// IPv4 rate limit processing with DDoS protection checks.
#[inline(always)]
fn process_ratelimit_v4(
    ctx: &XdpContext,
    l3_offset: usize,
    vlan_id: u16,
    flags: u8,
) -> Result<u32, ()> {
    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(ctx, l3_offset)? };
    let src_ip = u32_from_be_bytes(unsafe { (*ipv4hdr).src_addr });
    let dst_ip = u32_from_be_bytes(unsafe { (*ipv4hdr).dst_addr });
    let proto_raw = unsafe { (*ipv4hdr).proto };
    let protocol = proto_raw as u8;
    let ihl = unsafe { (*ipv4hdr).ihl() } as usize;
    let l4_offset = l3_offset + ihl;

    // ── DDoS: ICMP flood protection ────────────────────────────────
    if protocol == PROTO_ICMP {
        return process_icmp_v4(ctx, l4_offset, src_ip, dst_ip, flags, vlan_id);
    }

    // ── DDoS: SYN flood detection ──────────────────────────────────
    if protocol == PROTO_TCP {
        if let Some(action) = check_syn_flood_v4(ctx, l4_offset, src_ip, dst_ip, flags, vlan_id) {
            return Ok(action);
        }
        // Connection tracking & flood detection (RST/FIN/ACK floods, half-open SYNs)
        if let Some(action) = process_conntrack_v4(ctx, l4_offset, src_ip, dst_ip, flags, vlan_id) {
            return Ok(action);
        }
    }

    // ── DDoS: UDP amplification protection ─────────────────────────
    if protocol == PROTO_UDP {
        if let Some(action) = check_udp_amplification(ctx, l4_offset, src_ip, dst_ip, flags, vlan_id) {
            return Ok(action);
        }
    }

    // ── Existing: generic rate limiting ────────────────────────────
    let key = RateLimitKey { src_ip };
    let config = lookup_config(&key)?;

    let now = unsafe { bpf_ktime_get_boot_ns() };
    let passed = dispatch_algorithm(&key, config, now);

    if passed {
        increment_metric(METRIC_PASSED);
        Ok(xdp_action::XDP_PASS)
    } else {
        let src_addr = [src_ip, 0, 0, 0];
        let dst_addr = [dst_ip, 0, 0, 0];
        let (src_port, dst_port) = read_l4_ports_v4(ctx, l4_offset);

        emit_ratelimit_event(
            &src_addr, &dst_addr, src_port, dst_port, protocol, flags, vlan_id,
        );
        increment_metric(METRIC_THROTTLED);
        info!(ctx, "RATELIMIT {:i} throttled", src_ip);
        Ok(xdp_action::XDP_DROP)
    }
}

/// IPv6 rate limit processing with DDoS protection checks.
#[inline(always)]
fn process_ratelimit_v6(
    ctx: &XdpContext,
    l3_offset: usize,
    vlan_id: u16,
    flags: u8,
) -> Result<u32, ()> {
    let ipv6hdr: *const Ipv6Hdr = unsafe { ptr_at(ctx, l3_offset)? };
    let src_addr = ipv6_addr_to_u32x4(unsafe { &(*ipv6hdr).src_addr });
    let dst_addr = ipv6_addr_to_u32x4(unsafe { &(*ipv6hdr).dst_addr });
    let next_hdr = unsafe { (*ipv6hdr).next_hdr };
    let l4_offset = l3_offset + IPV6_HDR_LEN;

    // Hash IPv6 src to u32 for rate limit bucket (avoids needing duplicate maps)
    let src_hash = hash_ipv6_src(&src_addr);

    // ── DDoS: ICMPv6 flood protection ──────────────────────────────
    if next_hdr == PROTO_ICMPV6 {
        return process_icmp_v6(ctx, l4_offset, &src_addr, &dst_addr, src_hash, flags, vlan_id);
    }

    // ── DDoS: SYN flood detection (IPv6) ───────────────────────────
    if next_hdr == PROTO_TCP {
        if let Some(action) = check_syn_flood_v6(ctx, l4_offset, &src_addr, &dst_addr, src_hash, flags, vlan_id) {
            return Ok(action);
        }
        // Connection tracking & flood detection (IPv6)
        if let Some(action) = process_conntrack_v6(ctx, l4_offset, &src_addr, &dst_addr, src_hash, flags, vlan_id) {
            return Ok(action);
        }
    }

    // ── DDoS: UDP amplification (IPv6) ─────────────────────────────
    if next_hdr == PROTO_UDP {
        if let Some(action) = check_udp_amp_v6(ctx, l4_offset, &src_addr, &dst_addr, src_hash, flags, vlan_id) {
            return Ok(action);
        }
    }

    // ── Existing: generic rate limiting ────────────────────────────
    let key = RateLimitKey { src_ip: src_hash };
    let config = lookup_config(&key)?;

    let now = unsafe { bpf_ktime_get_boot_ns() };
    let passed = dispatch_algorithm(&key, config, now);

    if passed {
        increment_metric(METRIC_PASSED);
        Ok(xdp_action::XDP_PASS)
    } else {
        let (src_port, dst_port) = read_l4_ports_raw(ctx, l4_offset, next_hdr);

        emit_ratelimit_event(
            &src_addr, &dst_addr, src_port, dst_port, next_hdr, flags, vlan_id,
        );
        increment_metric(METRIC_THROTTLED);
        info!(ctx, "RATELIMIT6 {:i} throttled", src_addr[0]);
        Ok(xdp_action::XDP_DROP)
    }
}

/// Look up rate limit config: per-source-IP first, then global default.
/// Returns Err(()) if no config is found (no rate limit → pass).
#[inline(always)]
fn lookup_config(key: &RateLimitKey) -> Result<&'static RateLimitConfig, ()> {
    let config = match unsafe { RATELIMIT_CONFIG.get(key) } {
        Some(cfg) => cfg,
        None => {
            let default_key = RateLimitKey { src_ip: 0 };
            match unsafe { RATELIMIT_CONFIG.get(&default_key) } {
                Some(cfg) => cfg,
                None => {
                    increment_metric(METRIC_PASSED);
                    return Err(());
                }
            }
        }
    };

    // Disabled config (ns_per_token == 0) → pass
    if config.ns_per_token == 0 {
        increment_metric(METRIC_PASSED);
        return Err(());
    }

    Ok(config)
}

/// Dispatch to the appropriate rate limiting algorithm.
#[inline(always)]
fn dispatch_algorithm(key: &RateLimitKey, config: &RateLimitConfig, now: u64) -> bool {
    match config.algorithm {
        ALGO_FIXED_WINDOW => check_fixed_window(key, config, now),
        ALGO_SLIDING_WINDOW => check_sliding_window(key, config, now),
        ALGO_LEAKY_BUCKET => check_leaky_bucket(key, config, now),
        _ => check_token_bucket(key, config, now),
    }
}

/// Read L4 ports from an IPv4 packet (best-effort, 0 if unavailable).
#[inline(always)]
fn read_l4_ports_v4(ctx: &XdpContext, l4_offset: usize) -> (u16, u16) {
    if let Ok(ports) = unsafe { ptr_at::<[u8; 4]>(ctx, l4_offset) } {
        let ports = unsafe { &*ports };
        (
            u16::from_be_bytes([ports[0], ports[1]]),
            u16::from_be_bytes([ports[2], ports[3]]),
        )
    } else {
        (0u16, 0u16)
    }
}

/// Read L4 ports from a raw protocol byte (IPv6 next_hdr).
#[inline(always)]
fn read_l4_ports_raw(ctx: &XdpContext, l4_offset: usize, protocol: u8) -> (u16, u16) {
    if protocol == PROTO_TCP || protocol == PROTO_UDP {
        if let Ok(ports) = unsafe { ptr_at::<[u8; 4]>(ctx, l4_offset) } {
            let ports = unsafe { &*ports };
            return (
                u16::from_be_bytes([ports[0], ports[1]]),
                u16::from_be_bytes([ports[2], ports[3]]),
            );
        }
    }
    (0u16, 0u16)
}

// ── DDoS: SYN Flood Protection ──────────────────────────────────────

/// Check if a TCP packet is a SYN flood candidate (IPv4).
/// Returns `Some(action)` if DDoS protection handled the packet, `None` to
/// fall through to generic rate limiting.
#[inline(always)]
fn check_syn_flood_v4(
    ctx: &XdpContext,
    l4_offset: usize,
    src_ip: u32,
    dst_ip: u32,
    flags: u8,
    vlan_id: u16,
) -> Option<u32> {
    let cfg = DDOS_SYN_CONFIG.get(0)?;
    if cfg.enabled == 0 {
        return None;
    }

    let tcphdr: *const TcpHdr = unsafe { ptr_at(ctx, l4_offset).ok()? };
    let tcp_flags = unsafe { (*tcphdr).flags };

    // Only intercept pure SYN packets (SYN=1, ACK=0, RST=0, FIN=0)
    if tcp_flags & (TCP_FLAG_SYN | TCP_FLAG_ACK | TCP_FLAG_RST | TCP_FLAG_FIN) != TCP_FLAG_SYN {
        return None;
    }

    increment_ddos_metric(DDOS_METRIC_SYN_RECEIVED);

    let src_port = u16::from_be(unsafe { (*tcphdr).src_port });
    let dst_port = u16::from_be(unsafe { (*tcphdr).dst_port });

    // Threshold mode: only activate when SYN rate exceeds threshold
    if cfg.threshold_mode != 0 {
        let now = unsafe { bpf_ktime_get_boot_ns() };
        let key = RateLimitKey { src_ip };
        if !syn_rate_exceeds_threshold(&key, cfg.threshold_pps, now) {
            return None; // Below threshold — let kernel handle normally
        }
    }

    // SYN cookie protection: drop the SYN and emit event.
    // NOTE: Full SYN+ACK forging via XDP_TX requires packet rewriting
    // (swap MACs, swap IPs, build SYN+ACK TCP header with cookie).
    // For now, we DROP the SYN and emit an event for userspace detection.
    // Future: implement full XDP_TX SYN+ACK when bpf_tcp_gen_syncookie
    // is available in the aya-ebpf bindings.
    let src_addr = [src_ip, 0, 0, 0];
    let dst_addr = [dst_ip, 0, 0, 0];
    emit_ddos_event(
        &src_addr,
        &dst_addr,
        src_port,
        dst_port,
        PROTO_TCP,
        EVENT_TYPE_DDOS_SYN,
        DDOS_ACTION_SYNCOOKIE,
        flags,
        vlan_id,
    );
    increment_ddos_metric(DDOS_METRIC_SYNCOOKIES_SENT);
    Some(xdp_action::XDP_DROP)
}

/// Check if a TCP packet is a SYN flood candidate (IPv6).
#[inline(always)]
fn check_syn_flood_v6(
    ctx: &XdpContext,
    l4_offset: usize,
    src_addr: &[u32; 4],
    dst_addr: &[u32; 4],
    src_hash: u32,
    flags: u8,
    vlan_id: u16,
) -> Option<u32> {
    let cfg = DDOS_SYN_CONFIG.get(0)?;
    if cfg.enabled == 0 {
        return None;
    }

    let tcphdr: *const TcpHdr = unsafe { ptr_at(ctx, l4_offset).ok()? };
    let tcp_flags = unsafe { (*tcphdr).flags };

    if tcp_flags & (TCP_FLAG_SYN | TCP_FLAG_ACK | TCP_FLAG_RST | TCP_FLAG_FIN) != TCP_FLAG_SYN {
        return None;
    }

    increment_ddos_metric(DDOS_METRIC_SYN_RECEIVED);

    let src_port = u16::from_be(unsafe { (*tcphdr).src_port });
    let dst_port = u16::from_be(unsafe { (*tcphdr).dst_port });

    if cfg.threshold_mode != 0 {
        let now = unsafe { bpf_ktime_get_boot_ns() };
        let key = RateLimitKey { src_ip: src_hash };
        if !syn_rate_exceeds_threshold(&key, cfg.threshold_pps, now) {
            return None;
        }
    }

    emit_ddos_event(
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        PROTO_TCP,
        EVENT_TYPE_DDOS_SYN,
        DDOS_ACTION_SYNCOOKIE,
        flags,
        vlan_id,
    );
    increment_ddos_metric(DDOS_METRIC_SYNCOOKIES_SENT);
    Some(xdp_action::XDP_DROP)
}

/// Check if the SYN rate for a source exceeds the configured threshold.
/// Uses a fixed 1-second window per source IP.
#[inline(always)]
fn syn_rate_exceeds_threshold(key: &RateLimitKey, threshold_pps: u64, now: u64) -> bool {
    if let Some(state) = SYN_RATE_TRACKER.get_ptr_mut(key) {
        let state = unsafe { &mut *state };
        if now.saturating_sub(state.window_start) >= NS_PER_SEC {
            // New window
            state.count = 1;
            state.window_start = now;
            false
        } else {
            state.count += 1;
            state.count >= threshold_pps
        }
    } else {
        let new_state = SynRateState {
            count: 1,
            window_start: now,
        };
        let _ = SYN_RATE_TRACKER.insert(key, &new_state, 0);
        false
    }
}

// ── DDoS: ICMP Flood Protection ────────────────────────────────────

/// Process ICMP packets (IPv4). Rate limits echo requests per source.
#[inline(always)]
fn process_icmp_v4(
    ctx: &XdpContext,
    l4_offset: usize,
    src_ip: u32,
    dst_ip: u32,
    flags: u8,
    vlan_id: u16,
) -> Result<u32, ()> {
    let cfg = match ICMP_CONFIG.get(0) {
        Some(c) => c,
        None => {
            // No ICMP config → pass through to generic rate limiting
            increment_metric(METRIC_PASSED);
            return Ok(xdp_action::XDP_PASS);
        }
    };

    if cfg.enabled == 0 {
        increment_metric(METRIC_PASSED);
        return Ok(xdp_action::XDP_PASS);
    }

    let icmphdr: *const IcmpHdr = unsafe { ptr_at(ctx, l4_offset)? };
    let icmp_type = unsafe { (*icmphdr).icmp_type };

    // Only rate limit echo requests — pass other ICMP types through
    if icmp_type != ICMP_ECHO_REQUEST {
        increment_metric(METRIC_PASSED);
        return Ok(xdp_action::XDP_PASS);
    }

    // Check payload size — drop oversized ICMP echo
    let payload_start = l4_offset + ICMP_HDR_LEN;
    let pkt_end = ctx.data_end();
    let pkt_start = ctx.data();
    let payload_len = pkt_end.saturating_sub(pkt_start + payload_start);
    if payload_len > cfg.max_payload_size as usize {
        let src_addr = [src_ip, 0, 0, 0];
        let dst_addr = [dst_ip, 0, 0, 0];
        emit_ddos_event(
            &src_addr, &dst_addr, 0, 0, PROTO_ICMP,
            EVENT_TYPE_DDOS_ICMP, DDOS_ACTION_DROP, flags, vlan_id,
        );
        increment_ddos_metric(DDOS_METRIC_OVERSIZED_ICMP);
        return Ok(xdp_action::XDP_DROP);
    }

    // Per-source rate limiting for ICMP echo
    let now = unsafe { bpf_ktime_get_boot_ns() };
    let key = RateLimitKey { src_ip };
    if icmp_rate_check(&key, cfg.max_pps as u64, now) {
        increment_ddos_metric(DDOS_METRIC_ICMP_PASSED);
        Ok(xdp_action::XDP_PASS)
    } else {
        let src_addr = [src_ip, 0, 0, 0];
        let dst_addr = [dst_ip, 0, 0, 0];
        emit_ddos_event(
            &src_addr, &dst_addr, 0, 0, PROTO_ICMP,
            EVENT_TYPE_DDOS_ICMP, DDOS_ACTION_DROP, flags, vlan_id,
        );
        increment_ddos_metric(DDOS_METRIC_ICMP_DROPPED);
        Ok(xdp_action::XDP_DROP)
    }
}

/// Process ICMPv6 packets. Rate limits echo requests per source.
#[inline(always)]
fn process_icmp_v6(
    ctx: &XdpContext,
    l4_offset: usize,
    src_addr: &[u32; 4],
    dst_addr: &[u32; 4],
    src_hash: u32,
    flags: u8,
    vlan_id: u16,
) -> Result<u32, ()> {
    let cfg = match ICMP_CONFIG.get(0) {
        Some(c) => c,
        None => {
            increment_metric(METRIC_PASSED);
            return Ok(xdp_action::XDP_PASS);
        }
    };

    if cfg.enabled == 0 {
        increment_metric(METRIC_PASSED);
        return Ok(xdp_action::XDP_PASS);
    }

    let icmphdr: *const IcmpHdr = unsafe { ptr_at(ctx, l4_offset)? };
    let icmp_type = unsafe { (*icmphdr).icmp_type };

    // Only rate limit ICMPv6 echo requests (type 128)
    if icmp_type != ICMPV6_ECHO_REQUEST {
        increment_metric(METRIC_PASSED);
        return Ok(xdp_action::XDP_PASS);
    }

    // Oversized payload check
    let payload_start = l4_offset + ICMP_HDR_LEN;
    let pkt_end = ctx.data_end();
    let pkt_start = ctx.data();
    let payload_len = pkt_end.saturating_sub(pkt_start + payload_start);
    if payload_len > cfg.max_payload_size as usize {
        emit_ddos_event(
            src_addr, dst_addr, 0, 0, PROTO_ICMPV6,
            EVENT_TYPE_DDOS_ICMP, DDOS_ACTION_DROP, flags, vlan_id,
        );
        increment_ddos_metric(DDOS_METRIC_OVERSIZED_ICMP);
        return Ok(xdp_action::XDP_DROP);
    }

    let now = unsafe { bpf_ktime_get_boot_ns() };
    let key = RateLimitKey { src_ip: src_hash };
    if icmp_rate_check(&key, cfg.max_pps as u64, now) {
        increment_ddos_metric(DDOS_METRIC_ICMP_PASSED);
        Ok(xdp_action::XDP_PASS)
    } else {
        emit_ddos_event(
            src_addr, dst_addr, 0, 0, PROTO_ICMPV6,
            EVENT_TYPE_DDOS_ICMP, DDOS_ACTION_DROP, flags, vlan_id,
        );
        increment_ddos_metric(DDOS_METRIC_ICMP_DROPPED);
        Ok(xdp_action::XDP_DROP)
    }
}

/// Fixed-window rate check for ICMP. Returns `true` if under limit.
#[inline(always)]
fn icmp_rate_check(key: &RateLimitKey, max_pps: u64, now: u64) -> bool {
    if let Some(bucket) = ICMP_RATE_BUCKETS.get_ptr_mut(key) {
        let bucket = unsafe { &mut *bucket };
        if now.saturating_sub(bucket.window_start) >= NS_PER_SEC {
            bucket.pkt_count = 1;
            bucket.window_start = now;
            true
        } else if bucket.pkt_count >= max_pps {
            false
        } else {
            bucket.pkt_count += 1;
            true
        }
    } else {
        let new_val = FixedWindowValue {
            pkt_count: 1,
            window_start: now,
        };
        let _ = ICMP_RATE_BUCKETS.insert(key, &new_val, 0);
        true
    }
}

// ── DDoS: UDP Amplification Protection ─────────────────────────────

/// Check if a UDP packet originates from a known amplification port (IPv4).
/// Returns `Some(action)` if dropped, `None` to continue processing.
#[inline(always)]
fn check_udp_amplification(
    ctx: &XdpContext,
    l4_offset: usize,
    src_ip: u32,
    dst_ip: u32,
    flags: u8,
    vlan_id: u16,
) -> Option<u32> {
    let ports = unsafe { ptr_at::<[u8; 4]>(ctx, l4_offset).ok()? };
    let ports = unsafe { &*ports };
    let src_port = u16::from_be_bytes([ports[0], ports[1]]);
    let dst_port = u16::from_be_bytes([ports[2], ports[3]]);

    // Look up if the source port is a known amplification vector
    let amp_key = AmpProtectKey {
        port: src_port,
        protocol: PROTO_UDP,
        _pad: 0,
    };
    let amp_cfg = unsafe { AMP_PROTECT_CONFIG.get(&amp_key)? };
    if amp_cfg.enabled == 0 {
        return None;
    }

    // Per-source-per-port rate limiting
    let bucket_key = amp_bucket_key(src_ip, src_port);
    let now = unsafe { bpf_ktime_get_boot_ns() };

    if amp_rate_check(bucket_key, amp_cfg.max_pps as u64, now) {
        increment_ddos_metric(DDOS_METRIC_AMP_PASSED);
        None // Under limit — fall through
    } else {
        let src_addr = [src_ip, 0, 0, 0];
        let dst_addr = [dst_ip, 0, 0, 0];
        emit_ddos_event(
            &src_addr, &dst_addr, src_port, dst_port, PROTO_UDP,
            EVENT_TYPE_DDOS_AMP, DDOS_ACTION_DROP, flags, vlan_id,
        );
        increment_ddos_metric(DDOS_METRIC_AMP_DROPPED);
        Some(xdp_action::XDP_DROP)
    }
}

/// Check UDP amplification for IPv6. Returns `Some(action)` if dropped.
#[inline(always)]
fn check_udp_amp_v6(
    ctx: &XdpContext,
    l4_offset: usize,
    src_addr: &[u32; 4],
    dst_addr: &[u32; 4],
    src_hash: u32,
    flags: u8,
    vlan_id: u16,
) -> Option<u32> {
    let ports = unsafe { ptr_at::<[u8; 4]>(ctx, l4_offset).ok()? };
    let ports = unsafe { &*ports };
    let src_port = u16::from_be_bytes([ports[0], ports[1]]);
    let dst_port = u16::from_be_bytes([ports[2], ports[3]]);

    let amp_key = AmpProtectKey {
        port: src_port,
        protocol: PROTO_UDP,
        _pad: 0,
    };
    let amp_cfg = unsafe { AMP_PROTECT_CONFIG.get(&amp_key)? };
    if amp_cfg.enabled == 0 {
        return None;
    }

    let bucket_key = amp_bucket_key(src_hash, src_port);
    let now = unsafe { bpf_ktime_get_boot_ns() };

    if amp_rate_check(bucket_key, amp_cfg.max_pps as u64, now) {
        increment_ddos_metric(DDOS_METRIC_AMP_PASSED);
        None
    } else {
        emit_ddos_event(
            src_addr, dst_addr, src_port, dst_port, PROTO_UDP,
            EVENT_TYPE_DDOS_AMP, DDOS_ACTION_DROP, flags, vlan_id,
        );
        increment_ddos_metric(DDOS_METRIC_AMP_DROPPED);
        Some(xdp_action::XDP_DROP)
    }
}

/// Create a composite key for per-source-per-port amplification tracking.
#[inline(always)]
fn amp_bucket_key(src_ip: u32, src_port: u16) -> u64 {
    ((src_ip as u64) << 16) | (src_port as u64)
}

/// Fixed-window rate check for amplification. Returns `true` if under limit.
#[inline(always)]
fn amp_rate_check(key: u64, max_pps: u64, now: u64) -> bool {
    if let Some(bucket) = AMP_RATE_BUCKETS.get_ptr_mut(&key) {
        let bucket = unsafe { &mut *bucket };
        if now.saturating_sub(bucket.window_start) >= NS_PER_SEC {
            bucket.pkt_count = 1;
            bucket.window_start = now;
            true
        } else if bucket.pkt_count >= max_pps {
            false
        } else {
            bucket.pkt_count += 1;
            true
        }
    } else {
        let new_val = FixedWindowValue {
            pkt_count: 1,
            window_start: now,
        };
        let _ = AMP_RATE_BUCKETS.insert(&key, &new_val, 0);
        true
    }
}

// ── DDoS: Connection Tracking & Flood Detection ────────────────────

/// Process TCP connection tracking and flood detection (IPv4).
/// Returns `Some(action)` if the packet should be dropped, `None` to continue.
#[inline(always)]
fn process_conntrack_v4(
    ctx: &XdpContext,
    l4_offset: usize,
    src_ip: u32,
    dst_ip: u32,
    flags: u8,
    vlan_id: u16,
) -> Option<u32> {
    let cfg = CONNTRACK_CONFIG.get(0)?;
    if cfg.enabled == 0 {
        return None;
    }

    let tcphdr: *const TcpHdr = unsafe { ptr_at(ctx, l4_offset).ok()? };
    let tcp_flags = unsafe { (*tcphdr).flags };
    let src_port = u16::from_be(unsafe { (*tcphdr).src_port });
    let dst_port = u16::from_be(unsafe { (*tcphdr).dst_port });
    let now = unsafe { bpf_ktime_get_boot_ns() };

    let src_addr = [src_ip, 0, 0, 0];
    let dst_addr = [dst_ip, 0, 0, 0];

    process_conntrack_tcp(
        cfg, tcp_flags, src_ip, dst_ip, src_port, dst_port, now,
        &src_addr, &dst_addr, PROTO_TCP, flags, vlan_id,
    )
}

/// Process TCP connection tracking and flood detection (IPv6).
#[inline(always)]
fn process_conntrack_v6(
    ctx: &XdpContext,
    l4_offset: usize,
    src_addr: &[u32; 4],
    dst_addr: &[u32; 4],
    src_hash: u32,
    flags: u8,
    vlan_id: u16,
) -> Option<u32> {
    let cfg = CONNTRACK_CONFIG.get(0)?;
    if cfg.enabled == 0 {
        return None;
    }

    let tcphdr: *const TcpHdr = unsafe { ptr_at(ctx, l4_offset).ok()? };
    let tcp_flags = unsafe { (*tcphdr).flags };
    let src_port = u16::from_be(unsafe { (*tcphdr).src_port });
    let dst_port = u16::from_be(unsafe { (*tcphdr).dst_port });
    let now = unsafe { bpf_ktime_get_boot_ns() };

    // Use XOR-hashed src for IPv6 (same approach as rate limiting)
    let dst_hash = hash_ipv6_src(dst_addr);

    process_conntrack_tcp(
        cfg, tcp_flags, src_hash, dst_hash, src_port, dst_port, now,
        src_addr, dst_addr, PROTO_TCP, flags, vlan_id,
    )
}

/// Core connection tracking state machine and flood detection.
/// Shared between IPv4 and IPv6 paths.
#[inline(always)]
fn process_conntrack_tcp(
    cfg: &ConnTrackConfig,
    tcp_flags: u8,
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    now: u64,
    src_addr: &[u32; 4],
    dst_addr: &[u32; 4],
    protocol: u8,
    flags: u8,
    vlan_id: u16,
) -> Option<u32> {
    let is_syn = tcp_flags & TCP_FLAG_SYN != 0 && tcp_flags & TCP_FLAG_ACK == 0;
    let is_ack = tcp_flags & TCP_FLAG_ACK != 0 && tcp_flags & TCP_FLAG_SYN == 0;
    let is_rst = tcp_flags & TCP_FLAG_RST != 0;
    let is_fin = tcp_flags & TCP_FLAG_FIN != 0;

    // ── RST flood detection ──────────────────────────────────────
    if is_rst {
        if check_flood_rate(src_ip, FLOOD_TYPE_RST, cfg.rst_threshold as u64, now) {
            emit_ddos_event(
                src_addr, dst_addr, src_port, dst_port, protocol,
                EVENT_TYPE_DDOS_CONNTRACK, CONNTRACK_SUB_RST_FLOOD, flags, vlan_id,
            );
            increment_ddos_metric(DDOS_METRIC_RST_FLOOD_DROPS);
            return Some(xdp_action::XDP_DROP);
        }
        // Remove connection entry on RST
        let key = ConnTrackKey { src_ip, dst_ip, src_port, dst_port };
        let _ = CONN_TABLE.remove(&key);
        return None;
    }

    // ── FIN flood detection ──────────────────────────────────────
    if is_fin {
        if check_flood_rate(src_ip, FLOOD_TYPE_FIN, cfg.fin_threshold as u64, now) {
            emit_ddos_event(
                src_addr, dst_addr, src_port, dst_port, protocol,
                EVENT_TYPE_DDOS_CONNTRACK, CONNTRACK_SUB_FIN_FLOOD, flags, vlan_id,
            );
            increment_ddos_metric(DDOS_METRIC_FIN_FLOOD_DROPS);
            return Some(xdp_action::XDP_DROP);
        }
        // Remove connection entry on FIN
        let key = ConnTrackKey { src_ip, dst_ip, src_port, dst_port };
        let _ = CONN_TABLE.remove(&key);
        return None;
    }

    // ── SYN: create NEW connection entry, track half-open ────────
    if is_syn {
        // Check half-open threshold before adding
        if let Some(count) = HALF_OPEN_COUNTERS.get_ptr_mut(&src_ip) {
            let count = unsafe { &mut *count };
            if *count >= cfg.half_open_threshold as u64 {
                // Too many half-open connections from this source
                emit_ddos_event(
                    src_addr, dst_addr, src_port, dst_port, protocol,
                    EVENT_TYPE_DDOS_CONNTRACK, CONNTRACK_SUB_HALF_OPEN, flags, vlan_id,
                );
                increment_ddos_metric(DDOS_METRIC_HALF_OPEN_DROPS);
                return Some(xdp_action::XDP_DROP);
            }
            *count += 1;
        } else {
            let initial: u64 = 1;
            let _ = HALF_OPEN_COUNTERS.insert(&src_ip, &initial, 0);
        }

        // Insert NEW connection
        let key = ConnTrackKey { src_ip, dst_ip, src_port, dst_port };
        let val = ConnTrackValue {
            state: CONN_NEW,
            _pad: [0; 7],
            first_seen_ns: now,
            last_seen_ns: now,
        };
        let _ = CONN_TABLE.insert(&key, &val, 0);
        increment_ddos_metric(DDOS_METRIC_CONN_TRACKED);
        return None;
    }

    // ── ACK: transition NEW→ESTABLISHED or detect ACK flood ─────
    if is_ack {
        let key = ConnTrackKey { src_ip, dst_ip, src_port, dst_port };
        // Also check reverse direction (server-side ACK)
        let rev_key = ConnTrackKey {
            src_ip: dst_ip,
            dst_ip: src_ip,
            src_port: dst_port,
            dst_port: src_port,
        };

        // Try forward key first, then reverse
        let found_forward = if let Some(entry) = CONN_TABLE.get_ptr_mut(&key) {
            let entry = unsafe { &mut *entry };
            entry.last_seen_ns = now;
            if entry.state == CONN_NEW {
                entry.state = CONN_ESTABLISHED;
                // Decrement half-open counter
                if let Some(count) = HALF_OPEN_COUNTERS.get_ptr_mut(&src_ip) {
                    let count = unsafe { &mut *count };
                    *count = count.saturating_sub(1);
                }
            }
            true
        } else {
            false
        };

        if !found_forward {
            // Check reverse direction
            if let Some(entry) = CONN_TABLE.get_ptr_mut(&rev_key) {
                let entry = unsafe { &mut *entry };
                entry.last_seen_ns = now;
                if entry.state == CONN_NEW {
                    entry.state = CONN_ESTABLISHED;
                    // Decrement half-open counter for the original SYN sender
                    if let Some(count) = HALF_OPEN_COUNTERS.get_ptr_mut(&dst_ip) {
                        let count = unsafe { &mut *count };
                        *count = count.saturating_sub(1);
                    }
                }
            } else {
                // ACK to non-existent connection — potential ACK flood
                if check_flood_rate(src_ip, FLOOD_TYPE_ACK, cfg.ack_threshold as u64, now) {
                    emit_ddos_event(
                        src_addr, dst_addr, src_port, dst_port, protocol,
                        EVENT_TYPE_DDOS_CONNTRACK, CONNTRACK_SUB_ACK_FLOOD, flags, vlan_id,
                    );
                    increment_ddos_metric(DDOS_METRIC_ACK_FLOOD_DROPS);
                    return Some(xdp_action::XDP_DROP);
                }
            }
        }

        return None;
    }

    // Other TCP packets: update last_seen_ns if connection exists
    let key = ConnTrackKey { src_ip, dst_ip, src_port, dst_port };
    if let Some(entry) = CONN_TABLE.get_ptr_mut(&key) {
        let entry = unsafe { &mut *entry };
        entry.last_seen_ns = now;
    }

    None
}

/// Check if a flood rate threshold is exceeded for a given source and flood type.
/// Uses fixed 1-second window. Returns `true` if rate exceeds threshold (should drop).
#[inline(always)]
fn check_flood_rate(src_ip: u32, flood_type: u8, threshold: u64, now: u64) -> bool {
    if threshold == 0 {
        return false; // Disabled
    }

    let key = FloodCounterKey {
        src_ip,
        flood_type,
        _pad: [0; 3],
    };

    if let Some(bucket) = FLOOD_COUNTERS.get_ptr_mut(&key) {
        let bucket = unsafe { &mut *bucket };
        if now.saturating_sub(bucket.window_start) >= NS_PER_SEC {
            // New window
            bucket.pkt_count = 1;
            bucket.window_start = now;
            false
        } else if bucket.pkt_count >= threshold {
            true // Threshold exceeded
        } else {
            bucket.pkt_count += 1;
            false
        }
    } else {
        let new_val = FixedWindowValue {
            pkt_count: 1,
            window_start: now,
        };
        let _ = FLOOD_COUNTERS.insert(&key, &new_val, 0);
        false
    }
}

// ── DDoS Event Emission ────────────────────────────────────────────

/// Emit a DDoS-specific event to the EVENTS RingBuf.
/// Sampled during floods to avoid overwhelming the ring buffer.
#[inline(always)]
fn emit_ddos_event(
    src_addr: &[u32; 4],
    dst_addr: &[u32; 4],
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    event_type: u8,
    action: u8,
    flags: u8,
    vlan_id: u16,
) {
    if ringbuf_has_backpressure() {
        increment_ddos_metric(DDOS_METRIC_EVENTS_DROPPED);
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
            (*ptr).event_type = event_type;
            (*ptr).action = action;
            (*ptr).flags = flags;
            (*ptr).rule_id = 0;
            (*ptr).vlan_id = vlan_id;
            (*ptr).cpu_id = bpf_get_smp_processor_id() as u16;
            (*ptr).socket_cookie = 0;
        }
        entry.submit(0);
    } else {
        increment_ddos_metric(DDOS_METRIC_EVENTS_DROPPED);
    }
}

// ── Token Bucket ────────────────────────────────────────────────────

/// Token bucket algorithm: refill tokens based on elapsed time, consume 1.
/// Returns `true` if packet should pass, `false` if throttled.
#[inline(always)]
fn check_token_bucket(key: &RateLimitKey, config: &RateLimitConfig, now: u64) -> bool {
    if let Some(bucket) = RATELIMIT_BUCKETS.get_ptr_mut(key) {
        let bucket = unsafe { &mut *bucket };
        token_bucket_check(bucket, config, now)
    } else {
        let new_bucket = RateLimitValue {
            tokens: config.burst.saturating_sub(1),
            last_refill_ns: now,
        };
        let _ = RATELIMIT_BUCKETS.insert(key, &new_bucket, 0);
        true
    }
}

/// Token bucket core logic.
#[inline(always)]
fn token_bucket_check(bucket: &mut RateLimitValue, config: &RateLimitConfig, now: u64) -> bool {
    let elapsed = now.saturating_sub(bucket.last_refill_ns);
    let new_tokens = elapsed / config.ns_per_token;

    if new_tokens > 0 {
        bucket.tokens = core::cmp::min(config.burst, bucket.tokens.saturating_add(new_tokens));
        bucket.last_refill_ns = now;
    }

    if bucket.tokens > 0 {
        bucket.tokens -= 1;
        true
    } else {
        false
    }
}

// ── Fixed Window ────────────────────────────────────────────────────

#[inline(always)]
fn check_fixed_window(key: &RateLimitKey, config: &RateLimitConfig, now: u64) -> bool {
    let limit = config.ns_per_token;

    if let Some(bucket) = FIXED_WINDOW_BUCKETS.get_ptr_mut(key) {
        let bucket = unsafe { &mut *bucket };

        if now.saturating_sub(bucket.window_start) >= WINDOW_NS {
            bucket.pkt_count = 1;
            bucket.window_start = now;
            return true;
        }

        if bucket.pkt_count >= limit {
            return false;
        }
        bucket.pkt_count += 1;
        true
    } else {
        let new_val = FixedWindowValue {
            pkt_count: 1,
            window_start: now,
        };
        let _ = FIXED_WINDOW_BUCKETS.insert(key, &new_val, 0);
        true
    }
}

// ── Sliding Window ──────────────────────────────────────────────────

#[inline(always)]
fn check_sliding_window(key: &RateLimitKey, config: &RateLimitConfig, now: u64) -> bool {
    let max_packets = config.ns_per_token;

    if let Some(bucket) = SLIDING_WINDOW_BUCKETS.get_ptr_mut(key) {
        let bucket = unsafe { &mut *bucket };
        sliding_window_update(bucket, now);

        if bucket.window_total >= max_packets {
            return false;
        }

        let slot_idx = bucket.current_slot as usize;
        if slot_idx < SLIDING_WINDOW_NUM_SLOTS {
            bucket.slots[slot_idx] += 1;
        }
        bucket.window_total += 1;
        true
    } else {
        let mut new_val = SlidingWindowValue {
            slots: [0; SLIDING_WINDOW_NUM_SLOTS],
            current_slot: 0,
            _pad: 0,
            slot_start_ns: now,
            window_total: 1,
        };
        new_val.slots[0] = 1;
        let _ = SLIDING_WINDOW_BUCKETS.insert(key, &new_val, 0);
        true
    }
}

#[inline(always)]
fn sliding_window_update(bucket: &mut SlidingWindowValue, now: u64) {
    let elapsed = now.saturating_sub(bucket.slot_start_ns);
    let slots_elapsed = elapsed / SLOT_NS;

    if slots_elapsed == 0 {
        return;
    }

    if slots_elapsed >= SLIDING_WINDOW_NUM_SLOTS as u64 {
        let mut i: usize = 0;
        while i < SLIDING_WINDOW_NUM_SLOTS {
            bucket.slots[i] = 0;
            i += 1;
        }
        bucket.window_total = 0;
        bucket.current_slot = 0;
        bucket.slot_start_ns = now;
        return;
    }

    let mut cleared: u64 = 0;
    while cleared < slots_elapsed && cleared < SLIDING_WINDOW_NUM_SLOTS as u64 {
        let next_slot =
            (bucket.current_slot + 1 + cleared as u32) as usize % SLIDING_WINDOW_NUM_SLOTS;
        if next_slot < SLIDING_WINDOW_NUM_SLOTS {
            bucket.window_total =
                bucket.window_total.saturating_sub(bucket.slots[next_slot] as u64);
            bucket.slots[next_slot] = 0;
        }
        cleared += 1;
    }

    bucket.current_slot =
        (bucket.current_slot + slots_elapsed as u32) % SLIDING_WINDOW_NUM_SLOTS as u32;
    bucket.slot_start_ns += slots_elapsed * SLOT_NS;
}

// ── Leaky Bucket ────────────────────────────────────────────────────

#[inline(always)]
fn check_leaky_bucket(key: &RateLimitKey, config: &RateLimitConfig, now: u64) -> bool {
    let drain_rate = config.ns_per_token;
    let capacity = config.burst;

    if let Some(bucket) = LEAKY_BUCKET_BUCKETS.get_ptr_mut(key) {
        let bucket = unsafe { &mut *bucket };

        let elapsed_ns = now.saturating_sub(bucket.last_update_ns);

        if elapsed_ns >= LEAKY_MAX_ELAPSED_NS {
            bucket.level = 0;
        } else {
            let drained = elapsed_ns * drain_rate / NS_PER_SEC;
            bucket.level = bucket.level.saturating_sub(drained);
        }
        bucket.last_update_ns = now;

        if bucket.level + 1 > capacity {
            return false;
        }
        bucket.level += 1;
        true
    } else {
        let new_val = LeakyBucketValue {
            level: 1,
            last_update_ns: now,
        };
        let _ = LEAKY_BUCKET_BUCKETS.insert(key, &new_val, 0);
        true
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Bounds-checked pointer access for eBPF verifier compliance.
#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
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
    if let Some(counter) = RATELIMIT_METRICS.get_ptr_mut(index) {
        unsafe {
            *counter += 1;
        }
    }
}

/// Emit a rate-limit event to the EVENTS RingBuf. Skips emission under
/// backpressure (>75% full).
#[inline(always)]
fn emit_ratelimit_event(
    src_addr: &[u32; 4],
    dst_addr: &[u32; 4],
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    flags: u8,
    vlan_id: u16,
) {
    if ringbuf_has_backpressure() {
        increment_metric(METRIC_EVENTS_DROPPED);
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
            (*ptr).event_type = EVENT_TYPE_RATELIMIT;
            (*ptr).action = RATELIMIT_ACTION_DROP;
            (*ptr).flags = flags;
            (*ptr).rule_id = 0;
            (*ptr).vlan_id = vlan_id;
            (*ptr).cpu_id = bpf_get_smp_processor_id() as u16;
            (*ptr).socket_cookie = 0; // Not available in XDP context
        }
        entry.submit(0);
    } else {
        increment_metric(METRIC_EVENTS_DROPPED);
    }
}

// ── Map iteration infrastructure (F14) ──────────────────────────────
//
// `bpf_for_each_map_elem` (kernel 5.13+) is available for kernel-side map
// iteration, useful for garbage-collecting expired rate limit entries.
//
// Callback signature: `(map: *mut c_void, key: *const K, value: *const V,
//                       ctx: *mut c_void) -> i64`
//   Return 0 to continue iteration, 1 to stop.
//
// Import verified above; the helper is ready for future use in cleanup
// callbacks for `RATELIMIT_BUCKETS`, `FIXED_WINDOW_BUCKETS`, etc.

/// Suppress the unused import warning for `bpf_for_each_map_elem`.
/// This helper is imported as infrastructure for future kernel-side
/// map cleanup callbacks.
#[allow(dead_code)]
const _BPF_FOR_EACH_MAP_ELEM_AVAILABLE: unsafe fn(
    *mut aya_ebpf::cty::c_void,
    *mut aya_ebpf::cty::c_void,
    *mut aya_ebpf::cty::c_void,
    u64,
) -> i64 = bpf_for_each_map_elem;

// ── bpf_timer infrastructure (F21) ──────────────────────────────────
//
// `bpf_timer` (kernel 5.15+) enables periodic kernel-side operations
// without userspace intervention. The timer must live inside a map value.
//
// Use cases:
// - Expire stale rate limit buckets (garbage collection)
// - Emit periodic heartbeat events to userspace
// - Refresh cached configuration
//
// Timer lifecycle:
// 1. `bpf_timer_init(&timer, &map, CLOCK_MONOTONIC)` — initialize timer
// 2. `bpf_timer_set_callback(&timer, callback_fn)` — set callback
// 3. `bpf_timer_start(&timer, nsecs, 0)` — arm the timer
// 4. Callback fires after `nsecs` ns; re-arm for periodic operation

/// Map value containing a `bpf_timer`. Must live inside an `Array` map.
/// The timer is opaque (16 bytes) and managed by the kernel.
#[repr(C)]
struct TimerMapValue {
    timer: aya_ebpf::bindings::bpf_timer,
}

/// Array map holding a single `bpf_timer` for periodic maintenance.
/// Index 0: the maintenance timer (initialized by userspace trigger).
#[map]
#[allow(dead_code)]
static MAINTENANCE_TIMER: Array<TimerMapValue> = Array::with_max_entries(1, 0);

/// Maintenance timer interval: 10 seconds in nanoseconds.
#[allow(dead_code)]
const MAINTENANCE_INTERVAL_NS: u64 = 10 * NS_PER_SEC;

/// `CLOCK_MONOTONIC` flag for `bpf_timer_init`.
#[allow(dead_code)]
const CLOCK_MONOTONIC: u64 = 1;

/// Initialize and arm the maintenance timer. Called once from a triggered
/// eBPF program path (e.g. first packet) or from userspace via a config write.
///
/// The timer callback will use `bpf_for_each_map_elem` to iterate over
/// rate limit buckets and expire stale entries, then re-arm itself.
#[inline(always)]
#[allow(dead_code)]
fn init_maintenance_timer() -> Result<(), i64> {
    let val = MAINTENANCE_TIMER
        .get_ptr_mut(0)
        .ok_or(-1i64)?;

    let timer_ptr = unsafe { &mut (*val).timer as *mut aya_ebpf::bindings::bpf_timer };

    // Initialize the timer with CLOCK_MONOTONIC
    let ret = unsafe {
        aya_ebpf::helpers::r#gen::bpf_timer_init(
            timer_ptr,
            &MAINTENANCE_TIMER as *const _ as *mut _,
            CLOCK_MONOTONIC,
        )
    };
    if ret != 0 {
        return Err(ret);
    }

    // Set the callback
    let ret = unsafe {
        aya_ebpf::helpers::r#gen::bpf_timer_set_callback(
            timer_ptr,
            maintenance_timer_callback as *mut _,
        )
    };
    if ret != 0 {
        return Err(ret);
    }

    // Arm the timer
    let ret = unsafe {
        aya_ebpf::helpers::r#gen::bpf_timer_start(timer_ptr, MAINTENANCE_INTERVAL_NS, 0)
    };
    if ret != 0 {
        return Err(ret);
    }

    Ok(())
}

/// Timer callback for periodic maintenance. Re-arms itself for continuous
/// operation. Future: use `bpf_for_each_map_elem` to iterate and expire
/// stale rate limit entries.
#[allow(dead_code)]
unsafe extern "C" fn maintenance_timer_callback(
    _map: *mut aya_ebpf::cty::c_void,
    _key: *mut aya_ebpf::cty::c_void,
    value: *mut aya_ebpf::cty::c_void,
) -> i64 {
    // Re-arm the timer for the next interval
    unsafe {
        let val = value as *mut TimerMapValue;
        let timer_ptr = &mut (*val).timer as *mut aya_ebpf::bindings::bpf_timer;
        let _ = aya_ebpf::helpers::r#gen::bpf_timer_start(
            timer_ptr,
            MAINTENANCE_INTERVAL_NS,
            0,
        );
    }

    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
