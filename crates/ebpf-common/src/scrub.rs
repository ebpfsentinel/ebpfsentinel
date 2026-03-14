//! Packet normalization / scrub shared types for kernel (eBPF) and userspace.
//!
//! Used by: `tc-scrub` (packet rewriting) and userspace config reload.

/// Scrub configuration, stored in a single-element `Array` map.
///
/// Loaded by userspace, read by the TC scrub program on every packet.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScrubFlags {
    /// Master enable flag (0 = disabled, 1 = enabled).
    pub enabled: u8,
    /// Minimum TTL to enforce. If packet TTL is below this, set it to `min_ttl`.
    /// 0 means no minimum TTL enforcement.
    pub min_ttl: u8,
    /// Clear the DF (Don't Fragment) bit in IPv4 flags (0 = no, 1 = yes).
    pub clear_df: u8,
    /// Randomize IPv4 IP ID field (0 = no, 1 = yes).
    pub random_ip_id: u8,
    /// Maximum MSS to clamp on TCP SYN packets. 0 = no clamping.
    pub max_mss: u16,
    /// Minimum IPv6 Hop Limit to enforce. 0 means no enforcement.
    pub min_hop_limit: u8,
    /// Clear TCP reserved bits (NS/CWR/ECE) to prevent OS fingerprinting
    /// and covert channels. CWR/ECE only cleared on non-SYN packets to
    /// preserve ECN negotiation. (0 = no, 1 = yes).
    pub scrub_tcp_flags: u8,
    /// Clear ECN bits (2 LSBs) in IPv4 TOS / IPv6 Traffic Class (0 = no, 1 = yes).
    pub strip_ecn: u8,
    /// Normalize TOS/DSCP field to `tos_value` (0 = no, 1 = yes).
    pub normalize_tos: u8,
    /// Target TOS value when `normalize_tos` is enabled (default 0 = best effort).
    pub tos_value: u8,
    /// Remove TCP timestamp option (kind=8, len=10) by overwriting with NOP bytes.
    /// Prevents OS fingerprinting via TCP timestamp analysis. (0 = no, 1 = yes).
    pub strip_tcp_timestamps: u8,
    /// Padding for 2-byte alignment.
    pub _pad: [u8; 2],
}

impl ScrubFlags {
    /// Default disabled configuration.
    pub const fn defaults() -> Self {
        Self {
            enabled: 0,
            min_ttl: 0,
            clear_df: 0,
            random_ip_id: 0,
            max_mss: 0,
            min_hop_limit: 0,
            scrub_tcp_flags: 0,
            strip_ecn: 0,
            normalize_tos: 0,
            tos_value: 0,
            strip_tcp_timestamps: 0,
            _pad: [0; 2],
        }
    }
}

// ── Metric indices ──────────────────────────────────────────────────

/// Packets inspected by scrub.
pub const SCRUB_METRIC_PACKETS: u32 = 0;
/// TTL values corrected (raised to `min_ttl`).
pub const SCRUB_METRIC_TTL_FIXED: u32 = 1;
/// MSS options clamped on SYN packets.
pub const SCRUB_METRIC_MSS_CLAMPED: u32 = 2;
/// DF bits cleared.
pub const SCRUB_METRIC_DF_CLEARED: u32 = 3;
/// IP ID fields randomized.
pub const SCRUB_METRIC_IPID_RANDOMIZED: u32 = 4;
/// Processing errors.
pub const SCRUB_METRIC_ERRORS: u32 = 5;
/// IPv6 Hop Limit values corrected (raised to `min_hop_limit`).
pub const SCRUB_METRIC_HOP_FIXED: u32 = 6;
/// Metric index: total packets seen (unconditional, first instruction).
pub const SCRUB_METRIC_TOTAL_SEEN: u32 = 7;
/// TCP reserved/CWR/ECE flags scrubbed.
pub const SCRUB_METRIC_TCP_FLAGS_SCRUBBED: u32 = 8;
/// ECN bits stripped from IP header.
pub const SCRUB_METRIC_ECN_STRIPPED: u32 = 9;
/// TOS/DSCP field normalized.
pub const SCRUB_METRIC_TOS_NORMALIZED: u32 = 10;
/// TCP timestamp options stripped.
pub const SCRUB_METRIC_TCP_TS_STRIPPED: u32 = 11;
/// Total metric slots.
pub const SCRUB_METRIC_COUNT: u32 = 12;

// ── Pod impl ────────────────────────────────────────────────────────

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for ScrubFlags {}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn scrub_flags_size() {
        assert_eq!(mem::size_of::<ScrubFlags>(), 14);
    }

    #[test]
    fn scrub_flags_alignment() {
        assert_eq!(mem::align_of::<ScrubFlags>(), 2);
    }

    #[test]
    fn scrub_flags_field_offsets() {
        assert_eq!(mem::offset_of!(ScrubFlags, enabled), 0);
        assert_eq!(mem::offset_of!(ScrubFlags, min_ttl), 1);
        assert_eq!(mem::offset_of!(ScrubFlags, clear_df), 2);
        assert_eq!(mem::offset_of!(ScrubFlags, random_ip_id), 3);
        assert_eq!(mem::offset_of!(ScrubFlags, max_mss), 4);
        assert_eq!(mem::offset_of!(ScrubFlags, min_hop_limit), 6);
        assert_eq!(mem::offset_of!(ScrubFlags, scrub_tcp_flags), 7);
        assert_eq!(mem::offset_of!(ScrubFlags, strip_ecn), 8);
        assert_eq!(mem::offset_of!(ScrubFlags, normalize_tos), 9);
        assert_eq!(mem::offset_of!(ScrubFlags, tos_value), 10);
        assert_eq!(mem::offset_of!(ScrubFlags, strip_tcp_timestamps), 11);
    }

    #[test]
    fn scrub_flags_defaults() {
        let flags = ScrubFlags::defaults();
        assert_eq!(flags.enabled, 0);
        assert_eq!(flags.min_ttl, 0);
        assert_eq!(flags.max_mss, 0);
        assert_eq!(flags.clear_df, 0);
        assert_eq!(flags.random_ip_id, 0);
        assert_eq!(flags.scrub_tcp_flags, 0);
        assert_eq!(flags.strip_ecn, 0);
        assert_eq!(flags.normalize_tos, 0);
        assert_eq!(flags.tos_value, 0);
        assert_eq!(flags.strip_tcp_timestamps, 0);
    }

    #[test]
    fn metric_indices_unique() {
        let indices = [
            SCRUB_METRIC_PACKETS,
            SCRUB_METRIC_TTL_FIXED,
            SCRUB_METRIC_MSS_CLAMPED,
            SCRUB_METRIC_DF_CLEARED,
            SCRUB_METRIC_IPID_RANDOMIZED,
            SCRUB_METRIC_ERRORS,
            SCRUB_METRIC_HOP_FIXED,
            SCRUB_METRIC_TOTAL_SEEN,
            SCRUB_METRIC_TCP_FLAGS_SCRUBBED,
            SCRUB_METRIC_ECN_STRIPPED,
            SCRUB_METRIC_TOS_NORMALIZED,
            SCRUB_METRIC_TCP_TS_STRIPPED,
        ];
        for (i, &a) in indices.iter().enumerate() {
            for &b in &indices[i + 1..] {
                assert_ne!(a, b, "metric indices {a} and {b} collide");
            }
        }
    }
}
