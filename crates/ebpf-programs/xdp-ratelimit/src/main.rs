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
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;

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

/// IPv4 rate limit processing.
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
    let protocol = unsafe { (*ipv4hdr).proto };

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

        // Extract L4 ports for the event
        // ihl() returns the header length in bytes (already multiplied by 4)
        let ihl = unsafe { (*ipv4hdr).ihl() } as usize;
        let l4_offset = l3_offset + ihl;
        let (src_port, dst_port) = read_l4_ports_v4(ctx, l4_offset);

        emit_ratelimit_event(
            &src_addr, &dst_addr, src_port, dst_port, protocol as u8, flags, vlan_id,
        );
        increment_metric(METRIC_THROTTLED);
        info!(ctx, "RATELIMIT {:i} throttled", src_ip);
        Ok(xdp_action::XDP_DROP)
    }
}

/// IPv6 rate limit processing. Hashes the IPv6 source address to a u32
/// for bucket lookup, reusing the IPv4 maps.
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

    // Hash IPv6 src to u32 for rate limit bucket (avoids needing duplicate maps)
    let src_hash = hash_ipv6_src(&src_addr);
    let key = RateLimitKey { src_ip: src_hash };
    let config = lookup_config(&key)?;

    let now = unsafe { bpf_ktime_get_boot_ns() };
    let passed = dispatch_algorithm(&key, config, now);

    if passed {
        increment_metric(METRIC_PASSED);
        Ok(xdp_action::XDP_PASS)
    } else {
        let l4_offset = l3_offset + IPV6_HDR_LEN;
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
