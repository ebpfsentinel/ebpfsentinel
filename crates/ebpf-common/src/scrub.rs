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
/// Total metric slots.
pub const SCRUB_METRIC_COUNT: u32 = 6;

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
        assert_eq!(mem::size_of::<ScrubFlags>(), 8);
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
    }

    #[test]
    fn scrub_flags_defaults() {
        let flags = ScrubFlags::defaults();
        assert_eq!(flags.enabled, 0);
        assert_eq!(flags.min_ttl, 0);
        assert_eq!(flags.max_mss, 0);
        assert_eq!(flags.clear_df, 0);
        assert_eq!(flags.random_ip_id, 0);
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
        ];
        for (i, &a) in indices.iter().enumerate() {
            for &b in &indices[i + 1..] {
                assert_ne!(a, b, "metric indices {a} and {b} collide");
            }
        }
    }
}
