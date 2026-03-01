/// DDoS event type constants — stored as u8 in `PacketEvent.event_type`.
pub const EVENT_TYPE_DDOS_SYN: u8 = 10;
pub const EVENT_TYPE_DDOS_ICMP: u8 = 11;
pub const EVENT_TYPE_DDOS_AMP: u8 = 12;
pub const EVENT_TYPE_DDOS_CONNTRACK: u8 = 13;

/// DDoS action constants for `PacketEvent.action`.
pub const DDOS_ACTION_SYNCOOKIE: u8 = 10;
pub const DDOS_ACTION_DROP: u8 = 11;
pub const DDOS_ACTION_PASS: u8 = 12;

// ── SYN Protection Config ────────────────────────────────────────

/// Configuration flags for DDoS SYN protection.
/// Written by userspace, read by eBPF. Stored in `DDOS_SYN_CONFIG` Array map.
///
/// Size: 16 bytes (aligned to 8 bytes due to `threshold_pps` u64).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DdosSynConfig {
    /// 1 = SYN cookie protection enabled, 0 = disabled.
    pub enabled: u8,
    /// 0 = always generate cookies, 1 = threshold mode (cookies only when rate >= threshold).
    pub threshold_mode: u8,
    pub _pad: [u8; 6],
    /// SYN packets per second threshold to activate cookies (only in threshold mode).
    pub threshold_pps: u64,
}

/// Per-source SYN rate tracking state for threshold mode.
/// Managed by eBPF in `SYN_RATE_TRACKER` LRU map.
///
/// Size: 16 bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SynRateState {
    /// SYN packet count in the current 1-second window.
    pub count: u64,
    /// Timestamp (ns) when the current window started.
    pub window_start: u64,
}

// ── ICMP Protection Config ───────────────────────────────────────

/// Configuration for ICMP flood protection.
/// Written by userspace, read by eBPF. Stored in `ICMP_CONFIG` Array map.
///
/// Size: 8 bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcmpConfig {
    /// 1 = ICMP protection enabled, 0 = disabled.
    pub enabled: u8,
    pub _pad: u8,
    /// Maximum ICMP payload size in bytes (packets exceeding this are dropped).
    pub max_payload_size: u16,
    /// Maximum ICMP echo requests per second per source IP.
    pub max_pps: u32,
}

// ── UDP Amplification Protection ─────────────────────────────────

/// Key for the `AMP_PROTECT_CONFIG` HashMap — identifies a service port.
///
/// Size: 4 bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AmpProtectKey {
    /// UDP source port (the reflected port from the amplifier).
    pub port: u16,
    /// IP protocol (17 = UDP).
    pub protocol: u8,
    pub _pad: u8,
}

/// Configuration for a specific amplification vector.
/// Written by userspace, read by eBPF.
///
/// Size: 8 bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AmpProtectConfig {
    /// 1 = protection enabled for this port, 0 = disabled.
    pub enabled: u8,
    pub _pad: [u8; 3],
    /// Maximum packets per second from this source port per destination IP.
    pub max_pps: u32,
}

// ── Connection Tracking ──────────────────────────────────────────

/// Connection tracking configuration.
/// Written by userspace, read by eBPF.
///
/// Size: 32 bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnTrackConfig {
    /// 1 = connection tracking enabled, 0 = disabled.
    pub enabled: u8,
    pub _pad: [u8; 3],
    /// Max half-open connections per source before dropping new SYNs.
    pub half_open_threshold: u32,
    /// Max RST packets per source per second before dropping.
    pub rst_threshold: u32,
    /// Max FIN packets per source per second before dropping.
    pub fin_threshold: u32,
    /// Max ACK packets (to non-existent connections) per source per second.
    pub ack_threshold: u32,
    pub _pad2: [u8; 4],
    /// Timeout for connection entries in nanoseconds.
    pub timeout_ns: u64,
}

/// Connection tracking 4-tuple key (IPv4).
///
/// Size: 12 bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnTrackKey {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
}

/// Connection tracking state value.
///
/// Size: 24 bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ConnTrackValue {
    /// Connection state: `CONN_NEW`, `CONN_ESTABLISHED`, `CONN_CLOSING`.
    pub state: u8,
    pub _pad: [u8; 7],
    /// Timestamp when connection was first seen.
    pub first_seen_ns: u64,
    /// Timestamp of last packet on this connection.
    pub last_seen_ns: u64,
}

/// Connection state: SYN received, awaiting ACK.
pub const CONN_NEW: u8 = 0;
/// Connection state: SYN+ACK exchange complete.
pub const CONN_ESTABLISHED: u8 = 1;
/// Connection state: FIN or RST received.
pub const CONN_CLOSING: u8 = 2;

/// Flood counter key — tracks per-source per-flood-type rate.
///
/// Size: 8 bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FloodCounterKey {
    pub src_ip: u32,
    /// Flood type: 0=RST, 1=FIN, 2=ACK.
    pub flood_type: u8,
    pub _pad: [u8; 3],
}

/// Flood type constants.
pub const FLOOD_TYPE_RST: u8 = 0;
pub const FLOOD_TYPE_FIN: u8 = 1;
pub const FLOOD_TYPE_ACK: u8 = 2;

/// Conntrack event sub-type: half-open SYN threshold exceeded.
pub const CONNTRACK_SUB_HALF_OPEN: u8 = 0;
/// Conntrack event sub-type: RST flood detected.
pub const CONNTRACK_SUB_RST_FLOOD: u8 = 1;
/// Conntrack event sub-type: FIN flood detected.
pub const CONNTRACK_SUB_FIN_FLOOD: u8 = 2;
/// Conntrack event sub-type: ACK flood detected.
pub const CONNTRACK_SUB_ACK_FLOOD: u8 = 3;

// ── DDoS Metric Indices ──────────────────────────────────────────

/// Metric index: SYN packets received.
pub const DDOS_METRIC_SYN_RECEIVED: u32 = 0;
/// Metric index: SYN cookies sent.
pub const DDOS_METRIC_SYNCOOKIES_SENT: u32 = 1;
/// Metric index: ICMP packets passed.
pub const DDOS_METRIC_ICMP_PASSED: u32 = 2;
/// Metric index: ICMP packets dropped.
pub const DDOS_METRIC_ICMP_DROPPED: u32 = 3;
/// Metric index: UDP amplification packets passed.
pub const DDOS_METRIC_AMP_PASSED: u32 = 4;
/// Metric index: UDP amplification packets dropped.
pub const DDOS_METRIC_AMP_DROPPED: u32 = 5;
/// Metric index: oversized ICMP packets dropped.
pub const DDOS_METRIC_OVERSIZED_ICMP: u32 = 6;
/// Metric index: errors.
pub const DDOS_METRIC_ERRORS: u32 = 7;
/// Metric index: events dropped (RingBuf backpressure).
pub const DDOS_METRIC_EVENTS_DROPPED: u32 = 8;
/// Metric index: connections tracked (inserted into CONN_TABLE).
pub const DDOS_METRIC_CONN_TRACKED: u32 = 9;
/// Metric index: half-open SYN drops (per-source threshold exceeded).
pub const DDOS_METRIC_HALF_OPEN_DROPS: u32 = 10;
/// Metric index: RST flood drops.
pub const DDOS_METRIC_RST_FLOOD_DROPS: u32 = 11;
/// Metric index: FIN flood drops.
pub const DDOS_METRIC_FIN_FLOOD_DROPS: u32 = 12;
/// Metric index: ACK flood drops (ACK to non-existent connection).
pub const DDOS_METRIC_ACK_FLOOD_DROPS: u32 = 13;
/// Metric index: total packets seen (unconditional, first instruction).
pub const DDOS_METRIC_TOTAL_SEEN: u32 = 14;
/// Total number of DDoS metric slots.
pub const DDOS_METRIC_COUNT: u32 = 15;

// ── Pod impls ────────────────────────────────────────────────────

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for DdosSynConfig {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for SynRateState {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for IcmpConfig {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for AmpProtectKey {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for AmpProtectConfig {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for ConnTrackConfig {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for ConnTrackKey {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for ConnTrackValue {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for FloodCounterKey {}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn ddos_syn_config_size() {
        assert_eq!(mem::size_of::<DdosSynConfig>(), 16);
    }

    #[test]
    fn ddos_syn_config_alignment() {
        assert_eq!(mem::align_of::<DdosSynConfig>(), 8);
    }

    #[test]
    fn ddos_syn_config_field_offsets() {
        assert_eq!(mem::offset_of!(DdosSynConfig, enabled), 0);
        assert_eq!(mem::offset_of!(DdosSynConfig, threshold_mode), 1);
        assert_eq!(mem::offset_of!(DdosSynConfig, threshold_pps), 8);
    }

    #[test]
    fn syn_rate_state_size() {
        assert_eq!(mem::size_of::<SynRateState>(), 16);
    }

    #[test]
    fn syn_rate_state_field_offsets() {
        assert_eq!(mem::offset_of!(SynRateState, count), 0);
        assert_eq!(mem::offset_of!(SynRateState, window_start), 8);
    }

    #[test]
    fn icmp_config_size() {
        assert_eq!(mem::size_of::<IcmpConfig>(), 8);
    }

    #[test]
    fn icmp_config_field_offsets() {
        assert_eq!(mem::offset_of!(IcmpConfig, enabled), 0);
        assert_eq!(mem::offset_of!(IcmpConfig, max_payload_size), 2);
        assert_eq!(mem::offset_of!(IcmpConfig, max_pps), 4);
    }

    #[test]
    fn amp_protect_key_size() {
        assert_eq!(mem::size_of::<AmpProtectKey>(), 4);
    }

    #[test]
    fn amp_protect_config_size() {
        assert_eq!(mem::size_of::<AmpProtectConfig>(), 8);
    }

    #[test]
    fn amp_protect_config_field_offsets() {
        assert_eq!(mem::offset_of!(AmpProtectConfig, enabled), 0);
        assert_eq!(mem::offset_of!(AmpProtectConfig, max_pps), 4);
    }

    #[test]
    fn conntrack_config_size() {
        assert_eq!(mem::size_of::<ConnTrackConfig>(), 32);
    }

    #[test]
    fn conntrack_config_alignment() {
        assert_eq!(mem::align_of::<ConnTrackConfig>(), 8);
    }

    #[test]
    fn conntrack_config_field_offsets() {
        assert_eq!(mem::offset_of!(ConnTrackConfig, enabled), 0);
        assert_eq!(mem::offset_of!(ConnTrackConfig, half_open_threshold), 4);
        assert_eq!(mem::offset_of!(ConnTrackConfig, rst_threshold), 8);
        assert_eq!(mem::offset_of!(ConnTrackConfig, fin_threshold), 12);
        assert_eq!(mem::offset_of!(ConnTrackConfig, ack_threshold), 16);
        assert_eq!(mem::offset_of!(ConnTrackConfig, timeout_ns), 24);
    }

    #[test]
    fn conntrack_key_size() {
        assert_eq!(mem::size_of::<ConnTrackKey>(), 12);
    }

    #[test]
    fn conntrack_value_size() {
        assert_eq!(mem::size_of::<ConnTrackValue>(), 24);
    }

    #[test]
    fn conntrack_value_field_offsets() {
        assert_eq!(mem::offset_of!(ConnTrackValue, state), 0);
        assert_eq!(mem::offset_of!(ConnTrackValue, first_seen_ns), 8);
        assert_eq!(mem::offset_of!(ConnTrackValue, last_seen_ns), 16);
    }

    #[test]
    fn flood_counter_key_size() {
        assert_eq!(mem::size_of::<FloodCounterKey>(), 8);
    }

    #[test]
    fn event_type_constants() {
        assert_eq!(EVENT_TYPE_DDOS_SYN, 10);
        assert_eq!(EVENT_TYPE_DDOS_ICMP, 11);
        assert_eq!(EVENT_TYPE_DDOS_AMP, 12);
        assert_eq!(EVENT_TYPE_DDOS_CONNTRACK, 13);
    }

    #[test]
    fn ddos_metric_indices() {
        assert_eq!(DDOS_METRIC_SYN_RECEIVED, 0);
        assert_eq!(DDOS_METRIC_SYNCOOKIES_SENT, 1);
        assert_eq!(DDOS_METRIC_ICMP_PASSED, 2);
        assert_eq!(DDOS_METRIC_ICMP_DROPPED, 3);
        assert_eq!(DDOS_METRIC_AMP_PASSED, 4);
        assert_eq!(DDOS_METRIC_AMP_DROPPED, 5);
        assert_eq!(DDOS_METRIC_OVERSIZED_ICMP, 6);
        assert_eq!(DDOS_METRIC_ERRORS, 7);
        assert_eq!(DDOS_METRIC_EVENTS_DROPPED, 8);
        assert_eq!(DDOS_METRIC_CONN_TRACKED, 9);
        assert_eq!(DDOS_METRIC_HALF_OPEN_DROPS, 10);
        assert_eq!(DDOS_METRIC_RST_FLOOD_DROPS, 11);
        assert_eq!(DDOS_METRIC_FIN_FLOOD_DROPS, 12);
        assert_eq!(DDOS_METRIC_ACK_FLOOD_DROPS, 13);
        assert_eq!(DDOS_METRIC_COUNT, 15);
    }

    #[test]
    fn conn_state_constants() {
        assert_eq!(CONN_NEW, 0);
        assert_eq!(CONN_ESTABLISHED, 1);
        assert_eq!(CONN_CLOSING, 2);
    }

    #[test]
    fn flood_type_constants() {
        assert_eq!(FLOOD_TYPE_RST, 0);
        assert_eq!(FLOOD_TYPE_FIN, 1);
        assert_eq!(FLOOD_TYPE_ACK, 2);
    }

    #[test]
    fn conntrack_sub_type_constants() {
        assert_eq!(CONNTRACK_SUB_HALF_OPEN, 0);
        assert_eq!(CONNTRACK_SUB_RST_FLOOD, 1);
        assert_eq!(CONNTRACK_SUB_FIN_FLOOD, 2);
        assert_eq!(CONNTRACK_SUB_ACK_FLOOD, 3);
    }
}
