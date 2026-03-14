#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_get_smp_processor_id, bpf_ktime_get_boot_ns, bpf_xdp_adjust_tail},
    macros::{map, xdp},
    maps::{
        Array, HashMap, LpmTrie, LruPerCpuHashMap, PerCpuArray, RingBuf,
        lpm_trie::Key,
    },
    programs::XdpContext,
};
#[cfg(debug_assertions)]
use aya_log_ebpf::info;
use ebpf_helpers::net::{
    ETH_P_8021AD, ETH_P_8021Q, ETH_P_IP, ETH_P_IPV6, IPV6_HDR_LEN, Ipv6Hdr, PROTO_ICMP,
    PROTO_ICMPV6, PROTO_TCP, PROTO_UDP, VLAN_HDR_LEN, VlanHdr, ipv6_addr_to_u32x4,
    u32_from_be_bytes,
};
use ebpf_helpers::xdp::{ptr_at, ptr_at_mut, skip_ipv6_ext_headers};
use ebpf_helpers::{increment_metric, ringbuf_has_backpressure};
use ebpf_common::{
    ddos::{
        AmpProtectConfig, AmpProtectKey, DdosConnTrackConfig, DdosConnTrackKey, DdosConnTrackValue,
        DdosSynConfig, FloodCounterKey, IcmpConfig, SyncookieSecret, SynRateState,
        CONNTRACK_SUB_ACK_FLOOD, CONNTRACK_SUB_FIN_FLOOD, CONNTRACK_SUB_HALF_OPEN,
        CONNTRACK_SUB_RST_FLOOD, CONN_ESTABLISHED, CONN_NEW, DDOS_ACTION_DROP,
        DDOS_ACTION_SYNCOOKIE, DDOS_METRIC_ACK_FLOOD_DROPS, DDOS_METRIC_AMP_DROPPED,
        DDOS_METRIC_AMP_PASSED, DDOS_METRIC_CONN_TRACKED, DDOS_METRIC_COUNT,
        DDOS_METRIC_EVENTS_DROPPED, DDOS_METRIC_FIN_FLOOD_DROPS, DDOS_METRIC_HALF_OPEN_DROPS,
        DDOS_METRIC_ICMP_DROPPED, DDOS_METRIC_ICMP_PASSED, DDOS_METRIC_OVERSIZED_ICMP,
        DDOS_METRIC_RST_FLOOD_DROPS, DDOS_METRIC_SYN_FLOOD_DROPS, DDOS_METRIC_SYN_RECEIVED,
        DDOS_METRIC_SYNCOOKIE_INVALID, DDOS_METRIC_SYNCOOKIE_SENT, DDOS_METRIC_SYNCOOKIE_VALID,
        EVENT_TYPE_DDOS_AMP, EVENT_TYPE_DDOS_CONNTRACK, EVENT_TYPE_DDOS_ICMP,
        EVENT_TYPE_DDOS_SYN, FLOOD_TYPE_ACK, FLOOD_TYPE_FIN, FLOOD_TYPE_RST,
        SYNCOOKIE_MSS_TABLE,
    },
    event::{PacketEvent, EVENT_TYPE_RATELIMIT, FLAG_IPV6, FLAG_VLAN},
    ratelimit::{
        FixedWindowValue, LeakyBucketValue, RateLimitConfig, RateLimitKey, RateLimitTierValue,
        RateLimitValue, SlidingWindowValue, ALGO_FIXED_WINDOW, ALGO_LEAKY_BUCKET,
        ALGO_SLIDING_WINDOW, MAX_RL_LPM_ENTRIES, MAX_RL_TIERS, RATELIMIT_ACTION_DROP,
        SLIDING_WINDOW_NUM_SLOTS,
    },
};
use network_types::{
    eth::EthHdr,
    ip::Ipv4Hdr,
};

// ── Constants ───────────────────────────────────────────────────────
// Network constants and header structs imported from ebpf_helpers.

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

// ── Inline program-specific header types ─────────────────────────────

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

/// Per-CPU counters. Index: 0=passed, 1=throttled, 2=errors, 3=events_dropped, 4=total_seen.
#[map]
static RATELIMIT_METRICS: PerCpuArray<u64> = PerCpuArray::with_max_entries(5, 0);

/// Shared kernel→userspace event ring buffer (1 MB).
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 4096, 0);

// ── Country-Tier LPM Maps ──────────────────────────────────────────

/// IPv4 source LPM Trie for country-tier rate limiting.
/// Maps CIDR prefixes to tier IDs.
#[map]
static RL_LPM_SRC_V4: LpmTrie<[u8; 4], RateLimitTierValue> =
    LpmTrie::with_max_entries(MAX_RL_LPM_ENTRIES, 0);

/// IPv6 source LPM Trie for country-tier rate limiting.
#[map]
static RL_LPM_SRC_V6: LpmTrie<[u8; 16], RateLimitTierValue> =
    LpmTrie::with_max_entries(MAX_RL_LPM_ENTRIES, 0);

/// Tier configuration array. Index = tier_id (0-15).
#[map]
static RL_TIER_CONFIG: Array<RateLimitConfig> = Array::with_max_entries(MAX_RL_TIERS, 0);

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

/// DDoS-specific per-CPU metrics (see `DDOS_METRIC_*` constants).
#[map]
static DDOS_METRICS: PerCpuArray<u64> = PerCpuArray::with_max_entries(DDOS_METRIC_COUNT, 0);

/// SYN cookie secret key (32 bytes), set by userspace.
#[map]
static SYNCOOKIE_SECRET: Array<SyncookieSecret> = Array::with_max_entries(1, 0);

// ── Connection Tracking Maps ─────────────────────────────────────────

/// Connection tracking configuration (single entry, index 0).
#[map]
static CONNTRACK_CONFIG: Array<DdosConnTrackConfig> = Array::with_max_entries(1, 0);

/// Lightweight connection tracking table (per-CPU LRU).
/// Tracks TCP connections with 3 states: NEW, ESTABLISHED, CLOSING.
#[map]
static CONN_TABLE: LruPerCpuHashMap<DdosConnTrackKey, DdosConnTrackValue> =
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
const METRIC_TOTAL_SEEN: u32 = 4;

/// Returns `true` if the EVENTS RingBuf has backpressure (>75% full).
#[inline(always)]
fn ringbuf_has_backpressure() -> bool {
    ringbuf_has_backpressure!(EVENTS)
}

/// Per-interface group membership bitmask. Key = ifindex (u32), Value = group bitmask (u32).
#[map]
static INTERFACE_GROUPS: HashMap<u32, u32> = HashMap::with_max_entries(64, 0);

/// Increment a DDoS-specific per-CPU metric counter.
#[inline(always)]
fn increment_ddos_metric(index: u32) {
    increment_metric!(DDOS_METRICS, index);
}

/// Get the interface group membership for the current packet's ingress interface.
#[inline(always)]
fn get_iface_groups(ctx: &XdpContext) -> u32 {
    let ifindex = unsafe { (*ctx.ctx).ingress_ifindex };
    match unsafe { INTERFACE_GROUPS.get(&ifindex) } {
        Some(&groups) => groups,
        None => 0,
    }
}

/// Check if a rule's `group_mask` matches the interface's group membership.
#[inline(always)]
fn group_matches(rule_group_mask: u32, iface_groups: u32) -> bool {
    let mask = rule_group_mask & 0x7FFF_FFFF;
    if mask == 0 {
        return true;
    }
    let hit = (mask & iface_groups) != 0;
    let invert = (rule_group_mask & 0x8000_0000) != 0;
    hit != invert
}

// ── Entry point ─────────────────────────────────────────────────────

/// XDP entry point. Default-to-pass on internal error (NFR15).
#[xdp]
pub fn xdp_ratelimit(ctx: XdpContext) -> u32 {
    increment_metric(METRIC_TOTAL_SEEN);
    match try_xdp_ratelimit(&ctx) {
        Ok(action) => action,
        Err(()) => {
            increment_metric(METRIC_ERRORS);
            xdp_action::XDP_PASS
        }
    }
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
    if ether_type == ETH_P_8021Q || ether_type == ETH_P_8021AD {
        let vhdr: *const VlanHdr = unsafe { ptr_at(ctx, l3_offset)? };
        let tci = u16::from_be(unsafe { (*vhdr).tci });
        vlan_id = tci & 0x0FFF;
        ether_type = u16::from_be(unsafe { (*vhdr).ether_type });
        l3_offset += VLAN_HDR_LEN;
        flags |= FLAG_VLAN;

        // QinQ: parse second VLAN tag if present
        if ether_type == ETH_P_8021Q || ether_type == ETH_P_8021AD {
            let vhdr2: *const VlanHdr = unsafe { ptr_at(ctx, l3_offset)? };
            vlan_id = u16::from_be(unsafe { (*vhdr2).tci }) & 0x0FFF;
            ether_type = u16::from_be(unsafe { (*vhdr2).ether_type });
            l3_offset += VLAN_HDR_LEN;
        }
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

    // ── DDoS: SYN cookie ACK validation + SYN flood detection ─────
    if protocol == PROTO_TCP {
        // If this is a bare ACK, check if it completes a SYN cookie handshake
        if let Some(action) = validate_syncookie_ack_v4(ctx, l3_offset, l4_offset) {
            return Ok(action);
        }
        if let Some(action) = check_syn_flood_v4(ctx, l3_offset, l4_offset, src_ip, dst_ip, flags, vlan_id) {
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

    // ── Country-tier LPM lookup (before per-IP) ────────────────────
    let lpm_key = Key::new(32, src_ip.to_be_bytes());
    if let Some(tier_val) = RL_LPM_SRC_V4.get(&lpm_key) {
        if let Some(tier_cfg) = RL_TIER_CONFIG.get(tier_val.tier_id as u32) {
            if tier_cfg.ns_per_token > 0 {
                let key = RateLimitKey { src_ip };
                let now = unsafe { bpf_ktime_get_boot_ns() };
                let passed = dispatch_algorithm(&key, tier_cfg, now);
                if passed {
                    increment_metric(METRIC_PASSED);
                    return Ok(xdp_action::XDP_PASS);
                }
                let src_addr = [src_ip, 0, 0, 0];
                let dst_addr = [dst_ip, 0, 0, 0];
                let (src_port, dst_port) = read_l4_ports_v4(ctx, l4_offset);
                emit_ratelimit_event(
                    &src_addr, &dst_addr, src_port, dst_port, protocol, flags, vlan_id,
                );
                increment_metric(METRIC_THROTTLED);
                return Ok(xdp_action::XDP_DROP);
            }
        }
    }

    // ── Existing: generic rate limiting ────────────────────────────
    let key = RateLimitKey { src_ip };
    let config = lookup_config(&key)?;

    // Check interface group membership before applying rate limit.
    let iface_groups = get_iface_groups(ctx);
    if !group_matches(config.group_mask, iface_groups) {
        increment_metric(METRIC_PASSED);
        return Ok(xdp_action::XDP_PASS);
    }

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
        #[cfg(debug_assertions)]
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
    let raw_next_hdr = unsafe { (*ipv6hdr).next_hdr };

    // Skip IPv6 extension headers to find the actual L4 protocol.
    let (next_hdr, l4_offset) = skip_ipv6_ext_headers(ctx, l3_offset + IPV6_HDR_LEN, raw_next_hdr)
        .ok_or(())?;

    // Hash IPv6 src to u32 for rate limit bucket (avoids needing duplicate maps)
    let src_hash = hash_ipv6_src(&src_addr);

    // ── DDoS: ICMPv6 flood protection ──────────────────────────────
    if next_hdr == PROTO_ICMPV6 {
        return process_icmp_v6(ctx, l4_offset, &src_addr, &dst_addr, src_hash, flags, vlan_id);
    }

    // ── DDoS: SYN cookie ACK validation + SYN flood detection (IPv6)
    if next_hdr == PROTO_TCP {
        // If this is a bare ACK, check if it completes a SYN cookie handshake
        if let Some(action) = validate_syncookie_ack_v6(ctx, l3_offset, l4_offset) {
            return Ok(action);
        }
        if let Some(action) = check_syn_flood_v6(ctx, l3_offset, l4_offset, &src_addr, &dst_addr, src_hash, flags, vlan_id) {
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

    // ── Country-tier LPM lookup (IPv6, before per-IP) ──────────────
    let src_bytes = unsafe { (*ipv6hdr).src_addr };
    let lpm_key_v6 = Key::new(128, src_bytes);
    if let Some(tier_val) = RL_LPM_SRC_V6.get(&lpm_key_v6) {
        if let Some(tier_cfg) = RL_TIER_CONFIG.get(tier_val.tier_id as u32) {
            if tier_cfg.ns_per_token > 0 {
                let key = RateLimitKey { src_ip: src_hash };
                let now = unsafe { bpf_ktime_get_boot_ns() };
                let passed = dispatch_algorithm(&key, tier_cfg, now);
                if passed {
                    increment_metric(METRIC_PASSED);
                    return Ok(xdp_action::XDP_PASS);
                }
                let (src_port, dst_port) = read_l4_ports_raw(ctx, l4_offset, next_hdr);
                emit_ratelimit_event(
                    &src_addr, &dst_addr, src_port, dst_port, next_hdr, flags, vlan_id,
                );
                increment_metric(METRIC_THROTTLED);
                return Ok(xdp_action::XDP_DROP);
            }
        }
    }

    // ── Existing: generic rate limiting ────────────────────────────
    let key = RateLimitKey { src_ip: src_hash };
    let config = lookup_config(&key)?;

    // Check interface group membership before applying rate limit.
    let iface_groups = get_iface_groups(ctx);
    if !group_matches(config.group_mask, iface_groups) {
        increment_metric(METRIC_PASSED);
        return Ok(xdp_action::XDP_PASS);
    }

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
        #[cfg(debug_assertions)]
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
///
/// When a SYN flood is detected, forges a SYN+ACK with a SYN cookie via
/// `XDP_TX` instead of dropping. The client must complete the handshake
/// with a valid ACK (validated by `validate_syncookie_ack_v4`).
#[inline(always)]
fn check_syn_flood_v4(
    ctx: &XdpContext,
    l3_offset: usize,
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

    // SYN flood detected: forge SYN+ACK with SYN cookie via XDP_TX.
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

    match send_syn_ack_cookie_v4(ctx, l3_offset, l4_offset) {
        Ok(action) => {
            increment_ddos_metric(DDOS_METRIC_SYNCOOKIE_SENT);
            Some(action)
        }
        Err(()) => {
            increment_ddos_metric(DDOS_METRIC_SYN_FLOOD_DROPS);
            Some(xdp_action::XDP_DROP)
        }
    }
}

/// Check if a TCP packet is a SYN flood candidate (IPv6).
/// Forges a SYN+ACK with SYN cookie via `XDP_TX` when flood is detected.
#[inline(always)]
fn check_syn_flood_v6(
    ctx: &XdpContext,
    l3_offset: usize,
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

    match send_syn_ack_cookie_v6(ctx, l3_offset, l4_offset) {
        Ok(action) => {
            increment_ddos_metric(DDOS_METRIC_SYNCOOKIE_SENT);
            Some(action)
        }
        Err(()) => {
            increment_ddos_metric(DDOS_METRIC_SYN_FLOOD_DROPS);
            Some(xdp_action::XDP_DROP)
        }
    }
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
    cfg: &DdosConnTrackConfig,
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
        let key = DdosConnTrackKey { src_ip, dst_ip, src_port, dst_port };
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
        let key = DdosConnTrackKey { src_ip, dst_ip, src_port, dst_port };
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
        let key = DdosConnTrackKey { src_ip, dst_ip, src_port, dst_port };
        let val = DdosConnTrackValue {
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
        let key = DdosConnTrackKey { src_ip, dst_ip, src_port, dst_port };
        // Also check reverse direction (server-side ACK)
        let rev_key = DdosConnTrackKey {
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
    let key = DdosConnTrackKey { src_ip, dst_ip, src_port, dst_port };
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

// ── SYN Cookie Helpers ──────────────────────────────────────────────

/// FNV-1a hash of 4-tuple + timestamp counter + secret.
/// Returns a 32-bit cookie value.
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
    // Mix source IP
    h ^= src_ip;
    h = h.wrapping_mul(0x0100_0193); // FNV prime
    // Mix dest IP
    h ^= dst_ip;
    h = h.wrapping_mul(0x0100_0193);
    // Mix ports (combined as u32)
    h ^= ((src_port as u32) << 16) | (dst_port as u32);
    h = h.wrapping_mul(0x0100_0193);
    // Mix timestamp counter
    h ^= ts_counter;
    h = h.wrapping_mul(0x0100_0193);
    // Mix secret (8 u32 words)
    let mut i = 0u32;
    while i < 8 {
        h ^= secret[i as usize];
        h = h.wrapping_mul(0x0100_0193);
        i += 1;
    }
    h
}

/// Build a SYN cookie: hash with MSS index in lower 3 bits.
#[inline(always)]
fn make_syncookie(
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    mss_idx: u8,
    secret: &[u32; 8],
) -> u32 {
    let ts = (unsafe { bpf_ktime_get_boot_ns() } / 60_000_000_000) as u32; // minute counter
    let hash = syncookie_hash(src_ip, dst_ip, src_port, dst_port, ts, secret);
    (hash & 0xFFFF_FFF8) | ((mss_idx & 0x07) as u32)
}

/// Validate a cookie (check current minute and previous minute).
#[inline(always)]
fn validate_syncookie(
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    cookie: u32,
    secret: &[u32; 8],
) -> bool {
    let mss_bits = cookie & 0x07;
    let ts = (unsafe { bpf_ktime_get_boot_ns() } / 60_000_000_000) as u32;
    // Check current minute
    let h0 = syncookie_hash(src_ip, dst_ip, src_port, dst_port, ts, secret);
    if (h0 & 0xFFFF_FFF8) | mss_bits == cookie {
        return true;
    }
    // Check previous minute (for clock boundary)
    let h1 = syncookie_hash(src_ip, dst_ip, src_port, dst_port, ts.wrapping_sub(1), secret);
    (h1 & 0xFFFF_FFF8) | mss_bits == cookie
}

/// Parse TCP MSS option from SYN packet and return the MSS table index (0-7).
#[inline(always)]
fn parse_mss_index(ctx: &XdpContext, l4_offset: usize) -> u8 {
    // Read data offset byte to find options length
    let doff_ptr: *const u8 = match unsafe { ptr_at::<u8>(ctx, l4_offset + 12) } {
        Ok(p) => p,
        Err(_) => return 4, // default: 1460
    };
    let doff_byte = unsafe { *doff_ptr };
    let tcp_hdr_len = ((doff_byte >> 4) as usize) * 4;
    if tcp_hdr_len <= 20 {
        return 4; // no options, default 1460
    }

    let opts_start = l4_offset + 20;
    let opts_end = l4_offset + tcp_hdr_len;
    let mut pos = opts_start;
    let mut i = 0usize;
    while i < 40 && pos < opts_end {
        let kind_ptr: *const u8 = match unsafe { ptr_at::<u8>(ctx, pos) } {
            Ok(p) => p,
            Err(_) => break,
        };
        let kind = unsafe { *kind_ptr };
        if kind == 0 {
            break;
        } // EOL
        if kind == 1 {
            pos += 1;
            i += 1;
            continue;
        } // NOP
        let len_ptr: *const u8 = match unsafe { ptr_at::<u8>(ctx, pos + 1) } {
            Ok(p) => p,
            Err(_) => break,
        };
        let opt_len = unsafe { *len_ptr };
        if opt_len < 2 {
            break;
        }
        if kind == 2 && opt_len == 4 && pos + 4 <= opts_end {
            // MSS option
            if let Ok(hi_ptr) = unsafe { ptr_at::<u8>(ctx, pos + 2) } {
                if let Ok(lo_ptr) = unsafe { ptr_at::<u8>(ctx, pos + 3) } {
                    let mss = ((unsafe { *hi_ptr } as u16) << 8) | (unsafe { *lo_ptr } as u16);
                    // Find closest MSS table entry (largest entry <= mss)
                    let mut best = 0u8;
                    let mut j = 0u8;
                    while j < 8 {
                        if SYNCOOKIE_MSS_TABLE[j as usize] <= mss {
                            best = j;
                        }
                        j += 1;
                    }
                    return best;
                }
            }
        }
        pos += opt_len as usize;
        i += 1;
    }
    4 // default: 1460
}

// ── SYN Cookie: SYN+ACK Forging (IPv4) ─────────────────────────────

/// Forge a SYN+ACK with SYN cookie and send via `XDP_TX` (IPv4).
///
/// Rewrites the incoming SYN packet in-place: swaps MACs, swaps IPs,
/// sets seq=cookie, ack=in_seq+1, includes MSS option.
#[inline(never)]
fn send_syn_ack_cookie_v4(
    ctx: &XdpContext,
    l3_off: usize,
    l4_off: usize,
) -> Result<u32, ()> {
    // 1. Read incoming packet fields BEFORE modifying anything
    let iphdr: *const Ipv4Hdr = unsafe { ptr_at(ctx, l3_off)? };
    let src_ip = u32_from_be_bytes(unsafe { (*iphdr).src_addr });
    let dst_ip = u32_from_be_bytes(unsafe { (*iphdr).dst_addr });

    let tcphdr: *const TcpHdr = unsafe { ptr_at(ctx, l4_off)? };
    let in_seq = u32::from_be(unsafe { (*tcphdr).seq_num });
    let in_src_port = unsafe { (*tcphdr).src_port }; // network byte order
    let in_dst_port = unsafe { (*tcphdr).dst_port };
    let src_port = u16::from_be(in_src_port);
    let dst_port = u16::from_be(in_dst_port);

    let ethhdr: *const EthHdr = unsafe { ptr_at(ctx, 0)? };
    let in_src_mac = unsafe { (*ethhdr).src_addr };
    let in_dst_mac = unsafe { (*ethhdr).dst_addr };

    // 2. Parse MSS from incoming SYN
    let mss_idx = parse_mss_index(ctx, l4_off);

    // 3. Get secret
    let secret = match SYNCOOKIE_SECRET.get(0) {
        Some(s) => s,
        None => return Err(()),
    };

    // 4. Compute cookie
    let cookie = make_syncookie(src_ip, dst_ip, src_port, dst_port, mss_idx, &secret.key);

    // 5. Truncate to Eth + IP(IHL*4) + TCP(24 = 20 base + 4 MSS option)
    let tcp_len = 24usize;
    let desired_end = l4_off + tcp_len;
    let current_len = ctx.data_end() - ctx.data();
    let delta = desired_end as i32 - current_len as i32;
    if delta != 0 {
        let ret = unsafe { bpf_xdp_adjust_tail(ctx.ctx, delta) };
        if ret != 0 {
            return Err(());
        }
    }

    // 6. Re-read pointers (all invalidated by adjust_tail)
    // Swap Ethernet MACs
    let eth_out: *mut EthHdr = unsafe { ptr_at_mut(ctx, 0)? };
    unsafe {
        (*eth_out).dst_addr = in_src_mac;
        (*eth_out).src_addr = in_dst_mac;
    }

    // 7. Swap IP addresses, update header
    let iphdr_out: *mut Ipv4Hdr = unsafe { ptr_at_mut(ctx, l3_off)? };
    let ip_hdr_len: usize;
    unsafe {
        let tmp = (*iphdr_out).src_addr;
        (*iphdr_out).src_addr = (*iphdr_out).dst_addr;
        (*iphdr_out).dst_addr = tmp;
        // ihl() returns IHL in bytes already
        ip_hdr_len = (*iphdr_out).ihl() as usize;
        // Set total_len = IP header + TCP (24)
        (*iphdr_out).set_tot_len((ip_hdr_len + tcp_len) as u16);
        (*iphdr_out).ttl = 64;
        (*iphdr_out).check = [0, 0];
        let csum = compute_ipv4_csum(iphdr_out as *const u8, ip_hdr_len);
        (*iphdr_out).set_checksum(csum);
    }

    // 8. Build TCP SYN+ACK with MSS option
    let tcp_out: *mut u8 = unsafe { ptr_at_mut(ctx, l4_off)? };
    // Verify we can write all 24 bytes
    let _end_check: *const u8 = unsafe { ptr_at(ctx, l4_off + tcp_len - 1)? };

    // Read new src/dst IP addresses for TCP checksum pseudo-header
    let new_src_ip = unsafe { (*iphdr_out).src_addr };
    let new_dst_ip = unsafe { (*iphdr_out).dst_addr };

    unsafe {
        // Swap ports: source = original dst, dest = original src
        let port_ptr = tcp_out as *mut u16;
        *port_ptr = in_dst_port;
        *port_ptr.add(1) = in_src_port;

        // Seq = cookie, Ack = in_seq + 1
        let seq_ptr = tcp_out.add(4) as *mut u32;
        *seq_ptr = cookie.to_be();
        let ack_ptr = tcp_out.add(8) as *mut u32;
        *ack_ptr = (in_seq + 1).to_be();

        // Data offset = 6 (24 bytes), flags = SYN+ACK (0x12)
        *tcp_out.add(12) = 0x60; // data offset = 6
        *tcp_out.add(13) = 0x12; // SYN+ACK

        // Window size = 65535
        let win_ptr = tcp_out.add(14) as *mut u16;
        *win_ptr = 65535u16.to_be();

        // Checksum = 0 (will compute), Urgent pointer = 0
        let csum_ptr = tcp_out.add(16) as *mut u16;
        *csum_ptr = 0;
        let urg_ptr = tcp_out.add(18) as *mut u16;
        *urg_ptr = 0;

        // MSS option: kind=2, len=4, MSS value
        let mss_val = SYNCOOKIE_MSS_TABLE[mss_idx as usize];
        *tcp_out.add(20) = 2; // kind
        *tcp_out.add(21) = 4; // length
        let mss_ptr = tcp_out.add(22) as *mut u16;
        *mss_ptr = mss_val.to_be();

        // Compute TCP checksum (returned in host order, write as big-endian)
        let csum = compute_tcp_csum_v4(&new_src_ip, &new_dst_ip, tcp_out, tcp_len);
        let csum_be = csum.to_be_bytes();
        *tcp_out.add(16) = csum_be[0];
        *tcp_out.add(17) = csum_be[1];
    }

    Ok(xdp_action::XDP_TX)
}

// ── SYN Cookie: SYN+ACK Forging (IPv6) ─────────────────────────────

/// Forge a SYN+ACK with SYN cookie and send via `XDP_TX` (IPv6).
#[inline(never)]
fn send_syn_ack_cookie_v6(
    ctx: &XdpContext,
    l3_off: usize,
    l4_off: usize,
) -> Result<u32, ()> {
    // 1. Read incoming packet fields
    let ipv6hdr: *const Ipv6Hdr = unsafe { ptr_at(ctx, l3_off)? };
    let in_src_addr: [u8; 16] = unsafe { (*ipv6hdr).src_addr };
    let in_dst_addr: [u8; 16] = unsafe { (*ipv6hdr).dst_addr };

    // For cookie hashing, XOR-fold IPv6 addresses to u32
    let src_u32 = ipv6_addr_to_u32x4(&in_src_addr);
    let src_ip_hash = src_u32[0] ^ src_u32[1] ^ src_u32[2] ^ src_u32[3];
    let dst_u32 = ipv6_addr_to_u32x4(&in_dst_addr);
    let dst_ip_hash = dst_u32[0] ^ dst_u32[1] ^ dst_u32[2] ^ dst_u32[3];

    let tcphdr: *const TcpHdr = unsafe { ptr_at(ctx, l4_off)? };
    let in_seq = u32::from_be(unsafe { (*tcphdr).seq_num });
    let in_src_port = unsafe { (*tcphdr).src_port };
    let in_dst_port = unsafe { (*tcphdr).dst_port };
    let src_port = u16::from_be(in_src_port);
    let dst_port = u16::from_be(in_dst_port);

    let ethhdr: *const EthHdr = unsafe { ptr_at(ctx, 0)? };
    let in_src_mac = unsafe { (*ethhdr).src_addr };
    let in_dst_mac = unsafe { (*ethhdr).dst_addr };

    // 2. Parse MSS
    let mss_idx = parse_mss_index(ctx, l4_off);

    // 3. Get secret
    let secret = match SYNCOOKIE_SECRET.get(0) {
        Some(s) => s,
        None => return Err(()),
    };

    // 4. Compute cookie
    let cookie = make_syncookie(
        src_ip_hash,
        dst_ip_hash,
        src_port,
        dst_port,
        mss_idx,
        &secret.key,
    );

    // 5. Truncate to Eth + IPv6(40) + TCP(24)
    let tcp_len = 24usize;
    let desired_end = l4_off + tcp_len;
    let current_len = ctx.data_end() - ctx.data();
    let delta = desired_end as i32 - current_len as i32;
    if delta != 0 {
        let ret = unsafe { bpf_xdp_adjust_tail(ctx.ctx, delta) };
        if ret != 0 {
            return Err(());
        }
    }

    // 6. Re-read pointers
    let eth_out: *mut EthHdr = unsafe { ptr_at_mut(ctx, 0)? };
    unsafe {
        (*eth_out).dst_addr = in_src_mac;
        (*eth_out).src_addr = in_dst_mac;
    }

    // 7. Build IPv6 header
    let ip6_out: *mut Ipv6Hdr = unsafe { ptr_at_mut(ctx, l3_off)? };
    unsafe {
        // Version=6, traffic class=0, flow label=0
        (*ip6_out)._vtcfl = (6u32 << 28).to_be();
        // Payload length = TCP header (24 bytes)
        (*ip6_out)._payload_len = (tcp_len as u16).to_be();
        (*ip6_out).next_hdr = PROTO_TCP;
        (*ip6_out).hop_limit = 64;
        // Swap src/dst addresses
        (*ip6_out).src_addr = in_dst_addr;
        (*ip6_out).dst_addr = in_src_addr;
    }

    // 8. Build TCP SYN+ACK with MSS option
    let tcp_out: *mut u8 = unsafe { ptr_at_mut(ctx, l4_off)? };
    let _end_check: *const u8 = unsafe { ptr_at(ctx, l4_off + tcp_len - 1)? };

    unsafe {
        // Swap ports
        let port_ptr = tcp_out as *mut u16;
        *port_ptr = in_dst_port;
        *port_ptr.add(1) = in_src_port;

        // Seq = cookie, Ack = in_seq + 1
        let seq_ptr = tcp_out.add(4) as *mut u32;
        *seq_ptr = cookie.to_be();
        let ack_ptr = tcp_out.add(8) as *mut u32;
        *ack_ptr = (in_seq + 1).to_be();

        // Data offset = 6 (24 bytes), flags = SYN+ACK (0x12)
        *tcp_out.add(12) = 0x60;
        *tcp_out.add(13) = 0x12;

        // Window size = 65535
        let win_ptr = tcp_out.add(14) as *mut u16;
        *win_ptr = 65535u16.to_be();

        // Checksum = 0, Urgent pointer = 0
        let csum_ptr = tcp_out.add(16) as *mut u16;
        *csum_ptr = 0;
        let urg_ptr = tcp_out.add(18) as *mut u16;
        *urg_ptr = 0;

        // MSS option
        let mss_val = SYNCOOKIE_MSS_TABLE[mss_idx as usize];
        *tcp_out.add(20) = 2;
        *tcp_out.add(21) = 4;
        let mss_ptr = tcp_out.add(22) as *mut u16;
        *mss_ptr = mss_val.to_be();

        // Compute TCP checksum with IPv6 pseudo-header (host order → big-endian)
        let csum = compute_tcp_csum_v6(&in_dst_addr, &in_src_addr, tcp_out, tcp_len);
        let csum_be = csum.to_be_bytes();
        *tcp_out.add(16) = csum_be[0];
        *tcp_out.add(17) = csum_be[1];
    }

    Ok(xdp_action::XDP_TX)
}

// ── SYN Cookie: ACK Validation ──────────────────────────────────────

/// Check if an incoming ACK completes a SYN cookie handshake (IPv4).
/// Returns `Some(XDP_PASS)` if valid, `None` if not a cookie ACK.
#[inline(never)]
fn validate_syncookie_ack_v4(
    ctx: &XdpContext,
    l3_off: usize,
    l4_off: usize,
) -> Option<u32> {
    // Only check bare ACK (no SYN, no FIN, no RST)
    let flags_ptr: *const u8 = unsafe { ptr_at::<u8>(ctx, l4_off + 13).ok()? };
    let flags = unsafe { *flags_ptr };
    if flags != TCP_FLAG_ACK {
        return None;
    } // Must be pure ACK

    let tcphdr: *const TcpHdr = unsafe { ptr_at(ctx, l4_off).ok()? };
    let ack_no = u32::from_be(unsafe { (*tcphdr).ack_num });
    let cookie = ack_no.wrapping_sub(1); // cookie = ack - 1

    let iphdr: *const Ipv4Hdr = unsafe { ptr_at(ctx, l3_off).ok()? };
    let src_ip = u32_from_be_bytes(unsafe { (*iphdr).src_addr });
    let dst_ip = u32_from_be_bytes(unsafe { (*iphdr).dst_addr });
    let src_port = u16::from_be(unsafe { (*tcphdr).src_port });
    let dst_port = u16::from_be(unsafe { (*tcphdr).dst_port });

    let secret = SYNCOOKIE_SECRET.get(0)?;

    if validate_syncookie(src_ip, dst_ip, src_port, dst_port, cookie, &secret.key) {
        increment_ddos_metric(DDOS_METRIC_SYNCOOKIE_VALID);
        Some(xdp_action::XDP_PASS) // let it through to kernel
    } else {
        increment_ddos_metric(DDOS_METRIC_SYNCOOKIE_INVALID);
        None // not our cookie, continue normal processing
    }
}

/// Check if an incoming ACK completes a SYN cookie handshake (IPv6).
/// Returns `Some(XDP_PASS)` if valid, `None` if not a cookie ACK.
#[inline(never)]
fn validate_syncookie_ack_v6(
    ctx: &XdpContext,
    l3_off: usize,
    l4_off: usize,
) -> Option<u32> {
    // Only check bare ACK
    let flags_ptr: *const u8 = unsafe { ptr_at::<u8>(ctx, l4_off + 13).ok()? };
    let flags = unsafe { *flags_ptr };
    if flags != TCP_FLAG_ACK {
        return None;
    }

    let tcphdr: *const TcpHdr = unsafe { ptr_at(ctx, l4_off).ok()? };
    let ack_no = u32::from_be(unsafe { (*tcphdr).ack_num });
    let cookie = ack_no.wrapping_sub(1);

    let ipv6hdr: *const Ipv6Hdr = unsafe { ptr_at(ctx, l3_off).ok()? };
    let src_addr_bytes: [u8; 16] = unsafe { (*ipv6hdr).src_addr };
    let dst_addr_bytes: [u8; 16] = unsafe { (*ipv6hdr).dst_addr };

    // XOR-fold for cookie validation (same as in forging)
    let src_u32 = ipv6_addr_to_u32x4(&src_addr_bytes);
    let src_ip_hash = src_u32[0] ^ src_u32[1] ^ src_u32[2] ^ src_u32[3];
    let dst_u32 = ipv6_addr_to_u32x4(&dst_addr_bytes);
    let dst_ip_hash = dst_u32[0] ^ dst_u32[1] ^ dst_u32[2] ^ dst_u32[3];

    let src_port = u16::from_be(unsafe { (*tcphdr).src_port });
    let dst_port = u16::from_be(unsafe { (*tcphdr).dst_port });

    let secret = SYNCOOKIE_SECRET.get(0)?;

    if validate_syncookie(
        src_ip_hash,
        dst_ip_hash,
        src_port,
        dst_port,
        cookie,
        &secret.key,
    ) {
        increment_ddos_metric(DDOS_METRIC_SYNCOOKIE_VALID);
        Some(xdp_action::XDP_PASS)
    } else {
        increment_ddos_metric(DDOS_METRIC_SYNCOOKIE_INVALID);
        None
    }
}

// ── Checksum Helpers ────────────────────────────────────────────────

/// Compute the IPv4 header checksum (ones' complement of the ones'
/// complement sum of the header u16 words).
///
/// The checksum field in the header must be zeroed before calling.
#[inline(always)]
unsafe fn compute_ipv4_csum(hdr: *const u8, len: usize) -> u16 {
    unsafe {
        let mut sum: u32 = 0;
        let mut i: usize = 0;
        while i + 1 < len {
            let word = ((*hdr.add(i) as u32) << 8) | (*hdr.add(i + 1) as u32);
            sum += word;
            i += 2;
        }
        // Fold 32-bit sum into 16 bits.
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }
}

/// Compute TCP checksum with IPv4 pseudo-header.
///
/// The checksum field in the TCP header must be zeroed before calling.
/// Returns the checksum in host byte order.
#[inline(always)]
unsafe fn compute_tcp_csum_v4(
    src_ip: &[u8; 4],
    dst_ip: &[u8; 4],
    tcp_hdr: *const u8,
    tcp_len: usize,
) -> u16 {
    unsafe {
        let mut sum: u32 = 0;

        // Pseudo-header: src_ip (4 bytes) + dst_ip (4 bytes) + zero + proto + tcp_len
        sum += ((src_ip[0] as u32) << 8) | (src_ip[1] as u32);
        sum += ((src_ip[2] as u32) << 8) | (src_ip[3] as u32);
        sum += ((dst_ip[0] as u32) << 8) | (dst_ip[1] as u32);
        sum += ((dst_ip[2] as u32) << 8) | (dst_ip[3] as u32);
        sum += PROTO_TCP as u32; // 0x0006
        sum += tcp_len as u32;

        // Sum TCP header bytes as 16-bit words.
        let mut i: usize = 0;
        while i + 1 < tcp_len {
            let word = ((*tcp_hdr.add(i) as u32) << 8) | (*tcp_hdr.add(i + 1) as u32);
            sum += word;
            i += 2;
        }
        // Handle odd byte.
        if i < tcp_len {
            sum += (*tcp_hdr.add(i) as u32) << 8;
        }

        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }
}

/// Compute TCP checksum with IPv6 pseudo-header.
///
/// Returns the checksum in host byte order.
#[inline(always)]
unsafe fn compute_tcp_csum_v6(
    src_ip: &[u8; 16],
    dst_ip: &[u8; 16],
    tcp_hdr: *const u8,
    tcp_len: usize,
) -> u16 {
    unsafe {
        let mut sum: u32 = 0;

        // Pseudo-header: src (16) + dst (16) + upper-layer length (4) + zero(3) + next_hdr(1)
        let mut i: usize = 0;
        while i < 16 {
            sum += ((src_ip[i] as u32) << 8) | (src_ip[i + 1] as u32);
            i += 2;
        }
        i = 0;
        while i < 16 {
            sum += ((dst_ip[i] as u32) << 8) | (dst_ip[i + 1] as u32);
            i += 2;
        }
        sum += tcp_len as u32; // Upper-layer packet length
        sum += PROTO_TCP as u32; // Next header = 6

        // Sum TCP header/data.
        i = 0;
        while i + 1 < tcp_len {
            let word = ((*tcp_hdr.add(i) as u32) << 8) | (*tcp_hdr.add(i + 1) as u32);
            sum += word;
            i += 2;
        }
        if i < tcp_len {
            sum += (*tcp_hdr.add(i) as u32) << 8;
        }

        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
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

// ptr_at, skip_ipv6_ext_headers imported from ebpf_helpers::xdp

/// Increment a per-CPU metric counter.
#[inline(always)]
fn increment_metric(index: u32) {
    increment_metric!(RATELIMIT_METRICS, index);
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

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
