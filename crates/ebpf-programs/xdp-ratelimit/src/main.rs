#![no_std]
#![no_main]
#![cfg_attr(target_arch = "bpf", feature(asm_experimental_arch))]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_get_smp_processor_id, bpf_ktime_get_boot_ns},
    macros::{map, xdp},
    maps::{
        Array, HashMap, LpmTrie, LruPerCpuHashMap, PerCpuArray, ProgramArray, RingBuf,
        lpm_trie::Key,
    },
    programs::XdpContext,
};
// bpf_ktime_get_coarse_ns: ~10x faster than bpf_ktime_get_boot_ns by reading
// the coarse-grained kernel clock (CLOCK_MONOTONIC_COARSE, ~1-4ms precision).
// Sufficient for rate limiting (window checks, token bucket refill) where
// sub-millisecond precision is not required. Syncookie generation and event
// timestamps continue to use bpf_ktime_get_boot_ns for monotonic accuracy.
use aya_ebpf_bindings::helpers::bpf_ktime_get_coarse_ns;
#[cfg(debug_assertions)]
use aya_log_ebpf::info;
use ebpf_helpers::net::{
    ETH_P_8021AD, ETH_P_8021Q, ETH_P_IP, ETH_P_IPV6, IPV6_HDR_LEN, Ipv6Hdr, PROTO_ICMP,
    PROTO_ICMPV6, PROTO_TCP, PROTO_UDP, VLAN_HDR_LEN, VlanHdr, ipv6_addr_to_u32x4,
    u32_from_be_bytes,
};
use ebpf_helpers::xdp::{ptr_at, skip_ipv6_ext_headers};
use ebpf_helpers::{copy_16b_asm, copy_mac_asm, increment_metric, ringbuf_has_backpressure};
use ebpf_common::{
    ddos::{
        AmpProtectConfig, AmpProtectKey, DdosConnTrackConfig, DdosConnTrackKey, DdosConnTrackValue,
        DdosSynConfig, FloodCounterKey, IcmpConfig, SyncookieCtx, SyncookieSecret, SynRateState,
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
        FixedWindowValue, LeakyBucketValue, RateLimitBucketUnion, RateLimitConfig, RateLimitKey,
        RateLimitTierValue, RateLimitValue, SlidingWindowValue, ALGO_FIXED_WINDOW,
        ALGO_LEAKY_BUCKET, ALGO_SLIDING_WINDOW, ALGO_TOKEN_BUCKET, MAX_RL_BUCKET_ENTRIES,
        MAX_RL_LPM_ENTRIES, MAX_RL_TIERS, RATELIMIT_ACTION_DROP, SLIDING_WINDOW_NUM_SLOTS,
    },
    tenant::{MAX_TENANT_SUBNET_LPM_ENTRIES, MAX_TENANT_SUBNET_V6_LPM_ENTRIES},
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

/// Consolidated per-source-IP bucket state for all algorithms.
/// Per-CPU LRU eliminates cross-CPU contention; each CPU maintains
/// independent counters (effective rate scales with CPU count).
/// Replaces 4 separate per-algorithm maps with a single discriminated union.
#[map]
static RL_BUCKETS: LruPerCpuHashMap<RateLimitKey, RateLimitBucketUnion> =
    LruPerCpuHashMap::with_max_entries(MAX_RL_BUCKET_ENTRIES, 0);

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

/// Per-CPU context for passing packet fields to the syncookie tail-call
/// program (`xdp-ratelimit-syncookie`). Shared via BPF filesystem pinning.
#[map]
static SYNCOOKIE_CTX: PerCpuArray<SyncookieCtx> = PerCpuArray::with_max_entries(1, 0);

/// XDP program array for tail-call chaining (ratelimit → syncookie).
/// Index 0: syncookie program fd (set by userspace if DDoS SYN protection is enabled).
#[map]
static RL_PROG_ARRAY: ProgramArray = ProgramArray::with_max_entries(4, 0);

const PROG_IDX_SYNCOOKIE: u32 = 0;
/// Index of the loadbalancer in `RL_PROG_ARRAY`.
const PROG_IDX_LOADBALANCER: u32 = 1;

/// Sentinel value returned by `check_syn_flood_v4/v6` to signal the
/// entry point to tail-call into `xdp-ratelimit-syncookie`.
const XDP_ACTION_SYNCOOKIE: u32 = 0xFE;

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

// Local asm macros removed — using ebpf_helpers::copy_mac_asm! and copy_16b_asm!.

/// Returns `true` if the EVENTS RingBuf has backpressure (>75% full).
#[inline(always)]
fn ringbuf_has_backpressure() -> bool {
    ringbuf_has_backpressure!(EVENTS)
}

/// Per-interface group membership bitmask. Key = ifindex (u32), Value = group bitmask (u32).
#[map]
static INTERFACE_GROUPS: HashMap<u32, u32> = HashMap::with_max_entries(64, 0);

/// Tenant resolution: VLAN ID -> tenant_id.
#[map]
static TENANT_VLAN_MAP: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

/// LPM trie for subnet-based tenant resolution (IPv4).
#[map]
static TENANT_SUBNET_V4: LpmTrie<[u8; 4], u32> =
    LpmTrie::with_max_entries(MAX_TENANT_SUBNET_LPM_ENTRIES, 0);

/// LPM trie for subnet-based tenant resolution (IPv6).
#[map]
static TENANT_SUBNET_V6: LpmTrie<[u8; 16], u32> =
    LpmTrie::with_max_entries(MAX_TENANT_SUBNET_V6_LPM_ENTRIES, 0);

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

/// Resolve the tenant ID for the current packet.
/// Priority: VLAN-based > interface-based > subnet (LPM) > default (0).
#[inline(always)]
unsafe fn resolve_tenant_id(ifindex: u32, vlan_id: u16, src_ip: u32) -> u32 {
    unsafe {
        // Priority 1: VLAN-based (if packet has VLAN tag)
        if vlan_id != 0 {
            let vlan_key = vlan_id as u32;
            if let Some(&tid) = TENANT_VLAN_MAP.get(&vlan_key) {
                return tid;
            }
        }
        // Priority 2: Interface-based
        if let Some(&tid) = INTERFACE_GROUPS.get(&ifindex) {
            return tid;
        }
        // Priority 3: Subnet-based (LPM trie on src_ip)
        if src_ip != 0 {
            let key = Key::new(32, src_ip.to_be_bytes());
            if let Some(&tid) = TENANT_SUBNET_V4.get(&key) {
                return tid;
            }
        }
        // Default tenant
        0
    }
}

/// Resolve the tenant ID for an IPv6 packet.
/// Priority: VLAN-based > interface-based > subnet V6 (LPM) > default (0).
#[inline(always)]
unsafe fn resolve_tenant_id_v6(ifindex: u32, vlan_id: u16, src_addr: &[u32; 4]) -> u32 {
    unsafe {
        // Priority 1: VLAN-based (if packet has VLAN tag)
        if vlan_id != 0 {
            let vlan_key = vlan_id as u32;
            if let Some(&tid) = TENANT_VLAN_MAP.get(&vlan_key) {
                return tid;
            }
        }
        // Priority 2: Interface-based
        if let Some(&tid) = INTERFACE_GROUPS.get(&ifindex) {
            return tid;
        }
        // Priority 3: Subnet-based (LPM trie on IPv6 src_addr)
        let addr_bytes: [u8; 16] = core::mem::transmute(*src_addr);
        let key = Key::new(128, addr_bytes);
        if let Some(&tid) = TENANT_SUBNET_V6.get(&key) {
            return tid;
        }
        // Default tenant
        0
    }
}

// ── Entry point ─────────────────────────────────────────────────────

/// XDP entry point. Default-to-pass on internal error (NFR15).
#[xdp]
pub fn xdp_ratelimit(ctx: XdpContext) -> u32 {
    increment_metric(METRIC_TOTAL_SEEN);
    let action = match try_xdp_ratelimit(&ctx) {
        Ok(action) => action,
        Err(()) => {
            increment_metric(METRIC_ERRORS);
            xdp_action::XDP_PASS
        }
    };
    // Tail calls must happen in the XDP entry point (kernel 6.17+).
    if action == XDP_ACTION_SYNCOOKIE {
        // SYNCOOKIE_CTX already populated by check_syn_flood_v4/v6.
        // Falls back to DROP if the syncookie program is not loaded.
        unsafe {
            let _ = RL_PROG_ARRAY.tail_call(&ctx, PROG_IDX_SYNCOOKIE);
        }
        return xdp_action::XDP_DROP;
    }
    // Chain: on PASS, tail-call to loadbalancer (slot 1).
    // No-op if LB is not loaded (slot empty).
    if action == xdp_action::XDP_PASS {
        unsafe {
            let _ = RL_PROG_ARRAY.tail_call(&ctx, PROG_IDX_LOADBALANCER);
        }
    }
    action
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
                let now = unsafe { bpf_ktime_get_coarse_ns() };
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

    // Check tenant isolation.
    let ifindex = unsafe { (*ctx.ctx).ingress_ifindex };
    let tenant_id = unsafe { resolve_tenant_id(ifindex, vlan_id, src_ip) };
    if config.tenant_id != 0 && config.tenant_id != tenant_id {
        increment_metric(METRIC_PASSED);
        return Ok(xdp_action::XDP_PASS);
    }

    let now = unsafe { bpf_ktime_get_coarse_ns() };
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
                let now = unsafe { bpf_ktime_get_coarse_ns() };
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

    // Check tenant isolation.
    let ifindex = unsafe { (*ctx.ctx).ingress_ifindex };
    let tenant_id = unsafe { resolve_tenant_id_v6(ifindex, vlan_id, &src_addr) };
    if config.tenant_id != 0 && config.tenant_id != tenant_id {
        increment_metric(METRIC_PASSED);
        return Ok(xdp_action::XDP_PASS);
    }

    let now = unsafe { bpf_ktime_get_coarse_ns() };
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
        let now = unsafe { bpf_ktime_get_coarse_ns() };
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

    // Populate context for the syncookie tail-call program.
    let in_seq = u32::from_be(unsafe { (*tcphdr).seq_num });
    if let Some(sctx) = SYNCOOKIE_CTX.get_ptr_mut(0) {
        unsafe {
            (*sctx).src_ip = src_ip;
            (*sctx).dst_ip = dst_ip;
            (*sctx).src_port = src_port;
            (*sctx).dst_port = dst_port;
            (*sctx).in_seq = in_seq;
            (*sctx).in_src_port_be = (*tcphdr).src_port;
            (*sctx).in_dst_port_be = (*tcphdr).dst_port;
            (*sctx).mss_idx = 4; // default MSS 1460
            (*sctx).flags = flags;
        }
    }
    // Return sentinel — the entry point will tail-call to syncookie program.
    Some(XDP_ACTION_SYNCOOKIE)
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
        let now = unsafe { bpf_ktime_get_coarse_ns() };
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

    // Populate context for the syncookie tail-call program.
    let in_seq = u32::from_be(unsafe { (*tcphdr).seq_num });
    if let Some(sctx) = SYNCOOKIE_CTX.get_ptr_mut(0) {
        unsafe {
            (*sctx).src_ip = src_hash; // XOR-folded IPv6 src
            (*sctx).dst_ip = dst_addr[0] ^ dst_addr[1] ^ dst_addr[2] ^ dst_addr[3];
            (*sctx).src_port = src_port;
            (*sctx).dst_port = dst_port;
            (*sctx).in_seq = in_seq;
            (*sctx).in_src_port_be = (*tcphdr).src_port;
            (*sctx).in_dst_port_be = (*tcphdr).dst_port;
            (*sctx).mss_idx = 4;
            (*sctx).flags = flags | FLAG_IPV6;
        }
    }
    Some(XDP_ACTION_SYNCOOKIE)
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
    let now = unsafe { bpf_ktime_get_coarse_ns() };
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

    let now = unsafe { bpf_ktime_get_coarse_ns() };
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
    let now = unsafe { bpf_ktime_get_coarse_ns() };

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
    let now = unsafe { bpf_ktime_get_coarse_ns() };

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
    let now = unsafe { bpf_ktime_get_coarse_ns() };

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
    let now = unsafe { bpf_ktime_get_coarse_ns() };

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
///
/// On kernel 6.17+, the BPF verifier rejects variable-offset packet access
/// in the TCP options parsing loop (`pkt + var_off` with r=0). As a
/// workaround, return the default MSS index (1460 bytes) which is correct
/// for the vast majority of connections.
// TODO: re-enable once the verifier supports variable-offset pkt access
#[inline(always)]
fn parse_mss_index(_ctx: &XdpContext, _l4_offset: usize) -> u8 {
    4 // 1460 bytes — default MSS
}

// Syncookie forging + checksum helpers moved to xdp-ratelimit-syncookie and ebpf-helpers.

// ── SYN Cookie: ACK Validation ──────────────────────────────────────

/// Check if an incoming ACK completes a SYN cookie handshake (IPv4).
/// Returns `Some(XDP_PASS)` if valid, `None` if not a cookie ACK.
#[inline(always)]
fn validate_syncookie_ack_v4(
    ctx: &XdpContext,
    l3_off: usize,
    l4_off: usize,
) -> Option<u32> {
    let flags_ptr: *const u8 = unsafe { ptr_at::<u8>(ctx, l4_off + 13).ok()? };
    let flags = unsafe { *flags_ptr };
    if flags != TCP_FLAG_ACK {
        return None;
    }

    let tcphdr: *const TcpHdr = unsafe { ptr_at(ctx, l4_off).ok()? };
    let ack_no = u32::from_be(unsafe { (*tcphdr).ack_num });
    let cookie = ack_no.wrapping_sub(1);

    let iphdr: *const Ipv4Hdr = unsafe { ptr_at(ctx, l3_off).ok()? };
    let src_ip = u32_from_be_bytes(unsafe { (*iphdr).src_addr });
    let dst_ip = u32_from_be_bytes(unsafe { (*iphdr).dst_addr });
    let src_port = u16::from_be(unsafe { (*tcphdr).src_port });
    let dst_port = u16::from_be(unsafe { (*tcphdr).dst_port });

    let secret = SYNCOOKIE_SECRET.get(0)?;

    if validate_syncookie(src_ip, dst_ip, src_port, dst_port, cookie, &secret.key) {
        increment_ddos_metric(DDOS_METRIC_SYNCOOKIE_VALID);
        Some(xdp_action::XDP_PASS)
    } else {
        increment_ddos_metric(DDOS_METRIC_SYNCOOKIE_INVALID);
        None
    }
}

/// Check if an incoming ACK completes a SYN cookie handshake (IPv6).
/// Returns `Some(XDP_PASS)` if valid, `None` if not a cookie ACK.
#[inline(always)]
fn validate_syncookie_ack_v6(
    ctx: &XdpContext,
    l3_off: usize,
    l4_off: usize,
) -> Option<u32> {
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

    let src_u32 = ipv6_addr_to_u32x4(&src_addr_bytes);
    let src_ip_hash = src_u32[0] ^ src_u32[1] ^ src_u32[2] ^ src_u32[3];
    let dst_u32 = ipv6_addr_to_u32x4(&dst_addr_bytes);
    let dst_ip_hash = dst_u32[0] ^ dst_u32[1] ^ dst_u32[2] ^ dst_u32[3];

    let src_port = u16::from_be(unsafe { (*tcphdr).src_port });
    let dst_port = u16::from_be(unsafe { (*tcphdr).dst_port });

    let secret = SYNCOOKIE_SECRET.get(0)?;

    if validate_syncookie(src_ip_hash, dst_ip_hash, src_port, dst_port, cookie, &secret.key) {
        increment_ddos_metric(DDOS_METRIC_SYNCOOKIE_VALID);
        Some(xdp_action::XDP_PASS)
    } else {
        increment_ddos_metric(DDOS_METRIC_SYNCOOKIE_INVALID);
        None
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
    if let Some(union_ptr) = RL_BUCKETS.get_ptr_mut(key) {
        let union_bucket = unsafe { &mut *union_ptr };
        // If algorithm changed, treat as new bucket
        if union_bucket.algorithm != ALGO_TOKEN_BUCKET {
            let val = RateLimitValue {
                tokens: config.burst.saturating_sub(1),
                last_refill_ns: now,
            };
            let new_bucket = RateLimitBucketUnion::new_token_bucket(&val);
            let _ = RL_BUCKETS.insert(key, &new_bucket, 0);
            return true;
        }
        let bucket = unsafe { &mut *(union_bucket.data.as_mut_ptr() as *mut RateLimitValue) };
        token_bucket_check(bucket, config, now)
    } else {
        let val = RateLimitValue {
            tokens: config.burst.saturating_sub(1),
            last_refill_ns: now,
        };
        let new_bucket = RateLimitBucketUnion::new_token_bucket(&val);
        let _ = RL_BUCKETS.insert(key, &new_bucket, 0);
        true
    }
}

/// Token bucket core logic.
#[inline(always)]
fn token_bucket_check(bucket: &mut RateLimitValue, config: &RateLimitConfig, now: u64) -> bool {
    let elapsed = now.saturating_sub(bucket.last_refill_ns);
    // Guard against divide-by-zero: Rust emits panic_const_div_by_zero
    // which the BPF linker places at address 0 (overlapping the entry
    // wrapper), causing the verifier to follow a recursive call path.
    if config.ns_per_token == 0 {
        return false;
    }
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

    if let Some(union_ptr) = RL_BUCKETS.get_ptr_mut(key) {
        let union_bucket = unsafe { &mut *union_ptr };
        if union_bucket.algorithm != ALGO_FIXED_WINDOW {
            let val = FixedWindowValue {
                pkt_count: 1,
                window_start: now,
            };
            let new_bucket = RateLimitBucketUnion::new_fixed_window(&val);
            let _ = RL_BUCKETS.insert(key, &new_bucket, 0);
            return true;
        }
        let bucket = unsafe { &mut *(union_bucket.data.as_mut_ptr() as *mut FixedWindowValue) };

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
        let val = FixedWindowValue {
            pkt_count: 1,
            window_start: now,
        };
        let new_bucket = RateLimitBucketUnion::new_fixed_window(&val);
        let _ = RL_BUCKETS.insert(key, &new_bucket, 0);
        true
    }
}

// ── Sliding Window ──────────────────────────────────────────────────

#[inline(always)]
fn check_sliding_window(key: &RateLimitKey, config: &RateLimitConfig, now: u64) -> bool {
    let max_packets = config.ns_per_token;

    if let Some(union_ptr) = RL_BUCKETS.get_ptr_mut(key) {
        let union_bucket = unsafe { &mut *union_ptr };
        if union_bucket.algorithm != ALGO_SLIDING_WINDOW {
            let mut sw = SlidingWindowValue {
                slots: [0; SLIDING_WINDOW_NUM_SLOTS],
                current_slot: 0,
                _pad: 0,
                slot_start_ns: now,
                window_total: 1,
            };
            sw.slots[0] = 1;
            let mut new_bucket = RateLimitBucketUnion {
                algorithm: ALGO_SLIDING_WINDOW,
                _pad: [0; 7],
                data: [0u64; 7],
            };
            // SAFETY: SlidingWindowValue is 56 bytes, fits in data (56 bytes), aligned to 8.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    &sw as *const SlidingWindowValue as *const u8,
                    new_bucket.data.as_mut_ptr() as *mut u8,
                    core::mem::size_of::<SlidingWindowValue>(),
                );
            }
            let _ = RL_BUCKETS.insert(key, &new_bucket, 0);
            return true;
        }
        let bucket =
            unsafe { &mut *(union_bucket.data.as_mut_ptr() as *mut SlidingWindowValue) };
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
        let mut sw = SlidingWindowValue {
            slots: [0; SLIDING_WINDOW_NUM_SLOTS],
            current_slot: 0,
            _pad: 0,
            slot_start_ns: now,
            window_total: 1,
        };
        sw.slots[0] = 1;
        let mut new_bucket = RateLimitBucketUnion {
            algorithm: ALGO_SLIDING_WINDOW,
            _pad: [0; 7],
            data: [0u64; 7],
        };
        unsafe {
            core::ptr::copy_nonoverlapping(
                &sw as *const SlidingWindowValue as *const u8,
                new_bucket.data.as_mut_ptr() as *mut u8,
                core::mem::size_of::<SlidingWindowValue>(),
            );
        }
        let _ = RL_BUCKETS.insert(key, &new_bucket, 0);
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

    if let Some(union_ptr) = RL_BUCKETS.get_ptr_mut(key) {
        let union_bucket = unsafe { &mut *union_ptr };
        if union_bucket.algorithm != ALGO_LEAKY_BUCKET {
            let val = LeakyBucketValue {
                level: 1,
                last_update_ns: now,
            };
            let new_bucket = RateLimitBucketUnion::new_leaky_bucket(&val);
            let _ = RL_BUCKETS.insert(key, &new_bucket, 0);
            return true;
        }
        let bucket = unsafe { &mut *(union_bucket.data.as_mut_ptr() as *mut LeakyBucketValue) };

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
        let val = LeakyBucketValue {
            level: 1,
            last_update_ns: now,
        };
        let new_bucket = RateLimitBucketUnion::new_leaky_bucket(&val);
        let _ = RL_BUCKETS.insert(key, &new_bucket, 0);
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
