/// Maximum entries in the rate limit LPM Trie maps for country tiers.
pub const MAX_RL_LPM_ENTRIES: u32 = 131_072;
/// Maximum number of rate limit tier configurations.
pub const MAX_RL_TIERS: u32 = 16;

/// Value stored in rate limit LPM Trie maps.
/// Maps a CIDR prefix to a tier ID that indexes into the tier config array.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitTierValue {
    /// Tier ID (1-15, 0 reserved for default).
    pub tier_id: u8,
    pub _padding: [u8; 3],
}

/// Action: pass the packet (rate limit not exceeded).
pub const RATELIMIT_ACTION_PASS: u8 = 0;
/// Action: drop the packet (rate limit exceeded).
pub const RATELIMIT_ACTION_DROP: u8 = 1;

/// Algorithm: token bucket (default).
pub const ALGO_TOKEN_BUCKET: u8 = 0;
/// Algorithm: fixed window.
pub const ALGO_FIXED_WINDOW: u8 = 1;
/// Algorithm: sliding window (8 slots).
pub const ALGO_SLIDING_WINDOW: u8 = 2;
/// Algorithm: leaky bucket.
pub const ALGO_LEAKY_BUCKET: u8 = 3;
/// Algorithm: SYN cookie (XDP-based SYN flood mitigation).
pub const ALGO_SYNCOOKIE: u8 = 4;

/// Number of slots in the sliding window algorithm.
pub const SLIDING_WINDOW_NUM_SLOTS: usize = 8;

/// Key for the `RATELIMIT_CONFIG` and `RATELIMIT_BUCKETS` `HashMap`s (IPv4).
/// Key `{ src_ip: 0 }` is the global default config.
/// Size: 4 bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitKey {
    pub src_ip: u32,
}

/// Key for the `RATELIMIT_CONFIG_V6` and `RATELIMIT_BUCKETS_V6` `HashMap`s (IPv6).
/// Key `{ src_addr: [0; 4] }` is the global default config.
/// Size: 16 bytes (aligned to 4 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitKeyV6 {
    pub src_addr: [u32; 4],
}

/// Token bucket state for a source IP.
/// Managed exclusively by the eBPF program (in-place updates).
/// Size: 16 bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RateLimitValue {
    /// Current token count.
    pub tokens: u64,
    /// Last refill timestamp from `bpf_ktime_get_ns()`.
    pub last_refill_ns: u64,
}

/// Per-source-IP rate limit configuration.
/// Written by userspace, read by eBPF.
/// Size: 24 bytes (aligned to 8 bytes due to u64 fields).
///
/// Field reinterpretation per algorithm:
/// - Token Bucket: `ns_per_token = 1e9/rate`, `burst = max_tokens`
/// - Fixed Window: `ns_per_token = rate (pps limit)`, `burst = 0`
/// - Sliding Window: `ns_per_token = max_packets/window`, `burst = 0`
/// - Leaky Bucket: `ns_per_token = drain_rate/s`, `burst = capacity`
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitConfig {
    /// Token Bucket: nanoseconds per token = 1_000_000_000 / rate. 0 = disabled.
    /// Fixed/Sliding Window: max packets per window.
    /// Leaky Bucket: drain rate (packets/second).
    pub ns_per_token: u64,
    /// Token Bucket: maximum tokens (bucket size).
    /// Leaky Bucket: capacity.
    /// Fixed/Sliding Window: unused (0).
    pub burst: u64,
    /// Action when rate exceeded: `RATELIMIT_ACTION_DROP` or `RATELIMIT_ACTION_PASS`.
    pub action: u8,
    /// Algorithm selector: `ALGO_TOKEN_BUCKET`, `ALGO_FIXED_WINDOW`, etc.
    pub algorithm: u8,
    pub _padding: [u8; 2],
    /// Interface group bitmask (0 = floating/all interfaces).
    /// Bits 0-30: group membership, bit 31: invert flag.
    pub group_mask: u32,
    /// Tenant ID (0 = floating rule, applies to all tenants).
    pub tenant_id: u32,
}

/// Fixed window bucket state. Size: 16 bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FixedWindowValue {
    /// Number of packets in the current window.
    pub pkt_count: u64,
    /// Timestamp (ns) when the current window started.
    pub window_start: u64,
}

/// Sliding window bucket state (8 slots). Size: 56 bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SlidingWindowValue {
    /// Per-slot packet counts.
    pub slots: [u32; SLIDING_WINDOW_NUM_SLOTS],
    /// Index of the current active slot (0..7).
    pub current_slot: u32,
    pub _pad: u32,
    /// Timestamp (ns) when the current slot started.
    pub slot_start_ns: u64,
    /// Cached total across all slots.
    pub window_total: u64,
}

/// Leaky bucket state. Size: 16 bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LeakyBucketValue {
    /// Current water level (number of queued packets).
    pub level: u64,
    /// Timestamp (ns) of last drain update.
    pub last_update_ns: u64,
}

/// Maximum bucket map entries (single consolidated map replacing 4 per-algorithm maps).
pub const MAX_RL_BUCKET_ENTRIES: u32 = 262_144;

/// Consolidated bucket union for all rate-limit algorithms.
///
/// Stores the discriminant (`algorithm`) and a data region large enough
/// for the biggest variant (`SlidingWindowValue`, 56 bytes). The eBPF
/// program casts `data` to the correct typed pointer based on `algorithm`.
///
/// Size: 64 bytes (aligned to 8 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RateLimitBucketUnion {
    /// Algorithm discriminant: `ALGO_TOKEN_BUCKET`, `ALGO_FIXED_WINDOW`, etc.
    pub algorithm: u8,
    pub _pad: [u8; 7],
    /// Raw data region — reinterpreted as the correct value type.
    /// Use [`Self::as_token_bucket`], [`Self::as_fixed_window`], etc.
    pub data: [u64; 7],
}

impl RateLimitBucketUnion {
    /// Create a new union bucket for token bucket algorithm.
    pub const fn new_token_bucket(val: &RateLimitValue) -> Self {
        let mut data = [0u64; 7];
        data[0] = val.tokens;
        data[1] = val.last_refill_ns;
        Self {
            algorithm: ALGO_TOKEN_BUCKET,
            _pad: [0; 7],
            data,
        }
    }

    /// Create a new union bucket for fixed window algorithm.
    pub const fn new_fixed_window(val: &FixedWindowValue) -> Self {
        let mut data = [0u64; 7];
        data[0] = val.pkt_count;
        data[1] = val.window_start;
        Self {
            algorithm: ALGO_FIXED_WINDOW,
            _pad: [0; 7],
            data,
        }
    }

    /// Create a new union bucket for leaky bucket algorithm.
    pub const fn new_leaky_bucket(val: &LeakyBucketValue) -> Self {
        let mut data = [0u64; 7];
        data[0] = val.level;
        data[1] = val.last_update_ns;
        Self {
            algorithm: ALGO_LEAKY_BUCKET,
            _pad: [0; 7],
            data,
        }
    }
}

// SAFETY: All types are #[repr(C)], Copy, 'static, and contain only primitive types
// with explicit padding. Safe for zero-copy eBPF map operations via aya.
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for RateLimitTierValue {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for RateLimitKey {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for RateLimitKeyV6 {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for RateLimitValue {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for RateLimitConfig {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for FixedWindowValue {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for SlidingWindowValue {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for LeakyBucketValue {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for RateLimitBucketUnion {}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn ratelimit_tier_value_size() {
        assert_eq!(mem::size_of::<RateLimitTierValue>(), 4);
    }

    #[test]
    fn ratelimit_key_size() {
        assert_eq!(mem::size_of::<RateLimitKey>(), 4);
    }

    #[test]
    fn ratelimit_value_size() {
        assert_eq!(mem::size_of::<RateLimitValue>(), 16);
    }

    #[test]
    fn ratelimit_config_size() {
        assert_eq!(mem::size_of::<RateLimitConfig>(), 32);
    }

    #[test]
    fn ratelimit_config_alignment() {
        assert_eq!(mem::align_of::<RateLimitConfig>(), 8);
    }

    #[test]
    fn action_constants() {
        assert_eq!(RATELIMIT_ACTION_PASS, 0);
        assert_eq!(RATELIMIT_ACTION_DROP, 1);
    }

    #[test]
    fn algorithm_constants() {
        assert_eq!(ALGO_TOKEN_BUCKET, 0);
        assert_eq!(ALGO_FIXED_WINDOW, 1);
        assert_eq!(ALGO_SLIDING_WINDOW, 2);
        assert_eq!(ALGO_LEAKY_BUCKET, 3);
    }

    #[test]
    fn ratelimit_key_v6_size() {
        assert_eq!(mem::size_of::<RateLimitKeyV6>(), 16);
    }

    #[test]
    fn ratelimit_key_v6_alignment() {
        assert_eq!(mem::align_of::<RateLimitKeyV6>(), 4);
    }

    #[test]
    fn ratelimit_key_field_offsets() {
        assert_eq!(mem::offset_of!(RateLimitKey, src_ip), 0);
    }

    #[test]
    fn ratelimit_value_field_offsets() {
        assert_eq!(mem::offset_of!(RateLimitValue, tokens), 0);
        assert_eq!(mem::offset_of!(RateLimitValue, last_refill_ns), 8);
    }

    #[test]
    fn ratelimit_config_field_offsets() {
        assert_eq!(mem::offset_of!(RateLimitConfig, ns_per_token), 0);
        assert_eq!(mem::offset_of!(RateLimitConfig, burst), 8);
        assert_eq!(mem::offset_of!(RateLimitConfig, action), 16);
        assert_eq!(mem::offset_of!(RateLimitConfig, algorithm), 17);
        assert_eq!(mem::offset_of!(RateLimitConfig, group_mask), 20);
        assert_eq!(mem::offset_of!(RateLimitConfig, tenant_id), 24);
    }

    #[test]
    fn fixed_window_value_size() {
        assert_eq!(mem::size_of::<FixedWindowValue>(), 16);
    }

    #[test]
    fn fixed_window_value_alignment() {
        assert_eq!(mem::align_of::<FixedWindowValue>(), 8);
    }

    #[test]
    fn fixed_window_value_field_offsets() {
        assert_eq!(mem::offset_of!(FixedWindowValue, pkt_count), 0);
        assert_eq!(mem::offset_of!(FixedWindowValue, window_start), 8);
    }

    #[test]
    fn sliding_window_value_size() {
        assert_eq!(mem::size_of::<SlidingWindowValue>(), 56);
    }

    #[test]
    fn sliding_window_value_alignment() {
        assert_eq!(mem::align_of::<SlidingWindowValue>(), 8);
    }

    #[test]
    fn sliding_window_value_field_offsets() {
        assert_eq!(mem::offset_of!(SlidingWindowValue, slots), 0);
        assert_eq!(mem::offset_of!(SlidingWindowValue, current_slot), 32);
        assert_eq!(mem::offset_of!(SlidingWindowValue, _pad), 36);
        assert_eq!(mem::offset_of!(SlidingWindowValue, slot_start_ns), 40);
        assert_eq!(mem::offset_of!(SlidingWindowValue, window_total), 48);
    }

    #[test]
    fn leaky_bucket_value_size() {
        assert_eq!(mem::size_of::<LeakyBucketValue>(), 16);
    }

    #[test]
    fn leaky_bucket_value_alignment() {
        assert_eq!(mem::align_of::<LeakyBucketValue>(), 8);
    }

    #[test]
    fn leaky_bucket_value_field_offsets() {
        assert_eq!(mem::offset_of!(LeakyBucketValue, level), 0);
        assert_eq!(mem::offset_of!(LeakyBucketValue, last_update_ns), 8);
    }

    #[test]
    fn bucket_union_size() {
        assert_eq!(mem::size_of::<RateLimitBucketUnion>(), 64);
    }

    #[test]
    fn bucket_union_alignment() {
        assert_eq!(mem::align_of::<RateLimitBucketUnion>(), 8);
    }

    #[test]
    fn bucket_union_field_offsets() {
        assert_eq!(mem::offset_of!(RateLimitBucketUnion, algorithm), 0);
        assert_eq!(mem::offset_of!(RateLimitBucketUnion, _pad), 1);
        assert_eq!(mem::offset_of!(RateLimitBucketUnion, data), 8);
    }

    #[test]
    fn bucket_union_data_fits_all_variants() {
        // data region (56 bytes) must fit the largest variant
        let data_size = mem::size_of::<[u64; 7]>();
        assert!(data_size >= mem::size_of::<RateLimitValue>());
        assert!(data_size >= mem::size_of::<FixedWindowValue>());
        assert!(data_size >= mem::size_of::<SlidingWindowValue>());
        assert!(data_size >= mem::size_of::<LeakyBucketValue>());
    }

    #[test]
    fn bucket_union_data_alignment_compatible() {
        // data starts at offset 8, which must be compatible with all variant alignments
        let data_offset = mem::offset_of!(RateLimitBucketUnion, data);
        assert_eq!(data_offset % mem::align_of::<RateLimitValue>(), 0);
        assert_eq!(data_offset % mem::align_of::<FixedWindowValue>(), 0);
        assert_eq!(data_offset % mem::align_of::<SlidingWindowValue>(), 0);
        assert_eq!(data_offset % mem::align_of::<LeakyBucketValue>(), 0);
    }

    #[test]
    fn bucket_union_constructors() {
        let tb = RateLimitBucketUnion::new_token_bucket(&RateLimitValue {
            tokens: 42,
            last_refill_ns: 100,
        });
        assert_eq!(tb.algorithm, ALGO_TOKEN_BUCKET);
        assert_eq!(tb.data[0], 42);
        assert_eq!(tb.data[1], 100);

        let fw = RateLimitBucketUnion::new_fixed_window(&FixedWindowValue {
            pkt_count: 10,
            window_start: 200,
        });
        assert_eq!(fw.algorithm, ALGO_FIXED_WINDOW);
        assert_eq!(fw.data[0], 10);
        assert_eq!(fw.data[1], 200);

        let lb = RateLimitBucketUnion::new_leaky_bucket(&LeakyBucketValue {
            level: 5,
            last_update_ns: 300,
        });
        assert_eq!(lb.algorithm, ALGO_LEAKY_BUCKET);
        assert_eq!(lb.data[0], 5);
        assert_eq!(lb.data[1], 300);
    }

    #[test]
    fn backward_compatible_default_config() {
        // A config with algorithm=0 and _padding=[0;6] should behave identically
        // to the old layout with _padding=[0;7], since ALGO_TOKEN_BUCKET == 0.
        let config = RateLimitConfig {
            ns_per_token: 1_000_000,
            burst: 2000,
            action: RATELIMIT_ACTION_DROP,
            algorithm: ALGO_TOKEN_BUCKET,
            _padding: [0; 2],
            group_mask: 0,
            tenant_id: 0,
        };
        assert_eq!(config.algorithm, 0);
    }
}
