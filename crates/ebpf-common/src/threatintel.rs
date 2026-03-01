/// Threat intel action constants — used in `ThreatIntelValue.action`
pub const THREATINTEL_ACTION_ALERT: u8 = 0; // Log event, pass packet (TC_ACT_OK)
pub const THREATINTEL_ACTION_DROP: u8 = 1; // Log event, drop packet (TC_ACT_SHOT)
pub const THREATINTEL_ACTION_QUARANTINE: u8 = 2; // Re-tag into quarantine VLAN

/// Threat type constants — extensible categorization of IOCs.
pub const THREAT_TYPE_OTHER: u8 = 0;
pub const THREAT_TYPE_MALWARE: u8 = 1;
pub const THREAT_TYPE_C2: u8 = 2;
pub const THREAT_TYPE_SCANNER: u8 = 3;
pub const THREAT_TYPE_SPAM: u8 = 4;

/// Max entries for the THREATINTEL_IOCS HashMap (NFR22: 1M+ IOCs).
pub const THREATINTEL_MAX_ENTRIES: u32 = 1_048_576;

/// Metric indices for THREATINTEL_METRICS PerCpuArray.
pub const THREATINTEL_METRIC_MATCHED: u32 = 0;
pub const THREATINTEL_METRIC_DROPPED: u32 = 1;
pub const THREATINTEL_METRIC_ERRORS: u32 = 2;
pub const THREATINTEL_METRIC_EVENTS_DROPPED: u32 = 3;
/// Metric index: total packets seen (unconditional, first instruction).
pub const THREATINTEL_METRIC_TOTAL_SEEN: u32 = 4;

/// Key for the `THREATINTEL_IOCS` `HashMap` (IPv4).
/// Matches on a single IPv4 address (network byte-order u32).
/// Size: 4 bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreatIntelKey {
    pub ip: u32,
}

/// Key for the `THREATINTEL_IOCS_V6` `HashMap` (IPv6).
/// Matches on a single 128-bit IPv6 address.
/// Size: 16 bytes (aligned to 4 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreatIntelKeyV6 {
    pub ip: [u32; 4],
}

/// Value for the THREATINTEL_IOCS HashMap.
/// Encodes the action, feed source, confidence, and threat category.
/// Size: 4 bytes (aligned to 1 byte).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreatIntelValue {
    /// Action: THREATINTEL_ACTION_ALERT (0) or THREATINTEL_ACTION_DROP (1).
    pub action: u8,
    /// Feed index (0-255) mapping to userspace FeedConfig vec.
    pub feed_id: u8,
    /// Confidence score (0-100) from the originating feed.
    pub confidence: u8,
    /// Threat category: THREAT_TYPE_* constant.
    pub threat_type: u8,
}

// SAFETY: Both types are #[repr(C)], Copy, 'static, and contain only primitive
// types. Safe for zero-copy eBPF map operations via aya.
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for ThreatIntelKey {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for ThreatIntelKeyV6 {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for ThreatIntelValue {}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn threat_intel_key_size() {
        assert_eq!(mem::size_of::<ThreatIntelKey>(), 4);
    }

    #[test]
    fn threat_intel_value_size() {
        assert_eq!(mem::size_of::<ThreatIntelValue>(), 4);
    }

    #[test]
    fn threat_intel_key_alignment() {
        assert_eq!(mem::align_of::<ThreatIntelKey>(), 4);
    }

    #[test]
    fn threat_intel_key_v6_size() {
        assert_eq!(mem::size_of::<ThreatIntelKeyV6>(), 16);
    }

    #[test]
    fn threat_intel_key_v6_alignment() {
        assert_eq!(mem::align_of::<ThreatIntelKeyV6>(), 4);
    }

    #[test]
    fn threat_intel_value_alignment() {
        assert_eq!(mem::align_of::<ThreatIntelValue>(), 1);
    }

    #[test]
    fn action_constants() {
        assert_eq!(THREATINTEL_ACTION_ALERT, 0);
        assert_eq!(THREATINTEL_ACTION_DROP, 1);
    }

    #[test]
    fn threat_type_constants() {
        assert_eq!(THREAT_TYPE_OTHER, 0);
        assert_eq!(THREAT_TYPE_MALWARE, 1);
        assert_eq!(THREAT_TYPE_C2, 2);
        assert_eq!(THREAT_TYPE_SCANNER, 3);
        assert_eq!(THREAT_TYPE_SPAM, 4);
    }

    #[test]
    fn max_entries_is_one_million() {
        assert!(THREATINTEL_MAX_ENTRIES >= 1_000_000);
    }

    #[test]
    fn metric_indices_are_distinct() {
        let indices = [
            THREATINTEL_METRIC_MATCHED,
            THREATINTEL_METRIC_DROPPED,
            THREATINTEL_METRIC_ERRORS,
            THREATINTEL_METRIC_EVENTS_DROPPED,
        ];
        for (i, a) in indices.iter().enumerate() {
            for (j, b) in indices.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b);
                }
            }
        }
    }
}
