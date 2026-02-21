/// IDS action constants — used in `IdsPatternValue.action`.
pub const IDS_ACTION_ALERT: u8 = 0; // Log event, pass packet (TC_ACT_OK)
pub const IDS_ACTION_DROP: u8 = 1; // Log event, drop packet (TC_ACT_SHOT)

/// L7 protocol detection constants — used by kernel-side payload inspection.
pub const L7_PROTO_UNKNOWN: u8 = 0;
pub const L7_PROTO_HTTP: u8 = 1;
pub const L7_PROTO_TLS: u8 = 2;
pub const L7_PROTO_SSH: u8 = 3;
pub const L7_PROTO_DNS: u8 = 4;

/// IDS sampling mode constants — used in `IdsSamplingConfig.mode`.
pub const IDS_SAMPLING_NONE: u8 = 0; // No sampling — emit all events
pub const IDS_SAMPLING_RANDOM: u8 = 1; // Random sampling via `bpf_get_prandom_u32`

/// Kernel-side IDS sampling configuration.
/// Stored in a single-entry Array map (`IDS_SAMPLING_CONFIG`).
/// Size: 8 bytes (aligned to 4 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdsSamplingConfig {
    /// Sampling mode: `IDS_SAMPLING_NONE` or `IDS_SAMPLING_RANDOM`.
    pub mode: u8,
    pub _padding: [u8; 3],
    /// For `IDS_SAMPLING_RANDOM`: threshold in `0..=u32::MAX`.
    /// A packet is emitted when `bpf_get_prandom_u32() <= rate_threshold`.
    /// 0 = drop all events, `u32::MAX` = emit all events.
    /// To sample at N%, set to `(N / 100.0 * u32::MAX as f64) as u32`.
    pub rate_threshold: u32,
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for IdsSamplingConfig {}

/// Legacy event struct (unused by current eBPF programs; events use PacketEvent).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IdsEvent {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub rule_id: u32,
    pub _padding: [u8; 3],
}

/// Key for the IDS_PATTERNS HashMap.
/// Matches on destination port + protocol for kernel fast-path detection.
/// Size: 4 bytes (aligned to 2 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdsPatternKey {
    pub dst_port: u16,
    pub protocol: u8,
    pub _padding: u8,
}

/// Value for the IDS_PATTERNS HashMap.
/// Encodes the action, severity, and rule_id for matched packets.
/// Size: 8 bytes (aligned to 4 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdsPatternValue {
    pub action: u8,
    pub severity: u8,
    pub _padding: [u8; 2],
    pub rule_id: u32,
}

// SAFETY: Both types are #[repr(C)], Copy, 'static, and contain only primitive types
// with explicit padding. Safe for zero-copy eBPF map operations via aya.
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for IdsPatternKey {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for IdsPatternValue {}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn test_ids_pattern_key_size() {
        assert_eq!(mem::size_of::<IdsPatternKey>(), 4);
    }

    #[test]
    fn test_ids_pattern_key_alignment() {
        assert_eq!(mem::align_of::<IdsPatternKey>(), 2);
    }

    #[test]
    fn test_ids_pattern_value_size() {
        assert_eq!(mem::size_of::<IdsPatternValue>(), 8);
    }

    #[test]
    fn test_ids_pattern_value_alignment() {
        assert_eq!(mem::align_of::<IdsPatternValue>(), 4);
    }

    #[test]
    fn test_ids_action_constants() {
        assert_eq!(IDS_ACTION_ALERT, 0);
        assert_eq!(IDS_ACTION_DROP, 1);
    }

    #[test]
    fn test_ids_sampling_config_size() {
        assert_eq!(mem::size_of::<IdsSamplingConfig>(), 8);
    }

    #[test]
    fn test_ids_sampling_config_alignment() {
        assert_eq!(mem::align_of::<IdsSamplingConfig>(), 4);
    }

    #[test]
    fn test_ids_sampling_constants() {
        assert_eq!(IDS_SAMPLING_NONE, 0);
        assert_eq!(IDS_SAMPLING_RANDOM, 1);
    }

    #[test]
    fn test_l7_proto_constants() {
        assert_eq!(L7_PROTO_UNKNOWN, 0);
        assert_eq!(L7_PROTO_HTTP, 1);
        assert_eq!(L7_PROTO_TLS, 2);
        assert_eq!(L7_PROTO_SSH, 3);
        assert_eq!(L7_PROTO_DNS, 4);
    }
}
