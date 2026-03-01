/// Load balancer event type constant — stored as u8 in `PacketEvent.event_type`.
pub const EVENT_TYPE_LB: u8 = 14;

/// LB action constants for `PacketEvent.action`.
pub const LB_ACTION_FORWARD: u8 = 0;
pub const LB_ACTION_NO_BACKEND: u8 = 1;

/// Algorithm constants.
pub const LB_ALG_ROUND_ROBIN: u8 = 0;
pub const LB_ALG_WEIGHTED: u8 = 1;
pub const LB_ALG_IP_HASH: u8 = 2;
pub const LB_ALG_LEAST_CONN: u8 = 3;

/// Maximum backends per service.
pub const LB_MAX_BACKENDS: usize = 16;

// ── Service Key ────────────────────────────────────────────────

/// Key for the `LB_SERVICES` `HashMap`.
/// Keyed by (protocol, listen_port) to identify a load-balanced service.
///
/// Size: 4 bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LbServiceKey {
    /// IP protocol (6 = TCP, 17 = UDP).
    pub protocol: u8,
    pub _pad: u8,
    /// Listen port in host byte order.
    pub port: u16,
}

// ── Service Config ─────────────────────────────────────────────

/// Value for the `LB_SERVICES` `HashMap`.
/// Written by userspace, read by eBPF.
///
/// Size: 72 bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LbServiceConfig {
    /// Balancing algorithm: `LB_ALG_ROUND_ROBIN`, etc.
    pub algorithm: u8,
    /// Number of active backends (0..=16).
    pub backend_count: u8,
    pub _pad: [u8; 2],
    /// Backend IDs indexed into `LB_BACKENDS` map.
    pub backend_ids: [u32; LB_MAX_BACKENDS],
}

// ── Backend Entry ──────────────────────────────────────────────

/// Value for the `LB_BACKENDS` `HashMap`.
/// Written by userspace, read by eBPF.
///
/// Size: 28 bytes (aligned to 4 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LbBackendEntry {
    /// Backend IPv4 address (host byte order). 0 if IPv6.
    pub addr_v4: u32,
    /// Backend IPv6 address (network byte order).
    pub addr_v6: [u32; 4],
    /// Backend port (host byte order).
    pub port: u16,
    /// Weight for weighted balancing.
    pub weight: u16,
    /// 1 = healthy, 0 = unhealthy.
    pub healthy: u8,
    /// 1 = IPv6 backend, 0 = IPv4.
    pub is_ipv6: u8,
    pub _pad: [u8; 2],
}

// ── Metrics ────────────────────────────────────────────────────

/// Metric index constants for `LB_METRICS` `PerCpuArray`.
pub const LB_METRIC_PACKETS_FORWARDED: u32 = 0;
pub const LB_METRIC_PACKETS_NO_BACKEND: u32 = 1;
pub const LB_METRIC_BYTES_FORWARDED: u32 = 2;
pub const LB_METRIC_EVENTS_DROPPED: u32 = 3;
/// Metric index: total packets seen (unconditional, first instruction).
pub const LB_METRIC_TOTAL_SEEN: u32 = 4;
pub const LB_METRIC_COUNT: u32 = 5;

// SAFETY: All types are #[repr(C)], Copy, 'static, and contain only primitive types
// with explicit padding. Safe for zero-copy eBPF map operations via aya.
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for LbServiceKey {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for LbServiceConfig {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for LbBackendEntry {}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn lb_service_key_size() {
        assert_eq!(mem::size_of::<LbServiceKey>(), 4);
    }

    #[test]
    fn lb_service_key_alignment() {
        assert_eq!(mem::align_of::<LbServiceKey>(), 2);
    }

    #[test]
    fn lb_service_key_offsets() {
        assert_eq!(mem::offset_of!(LbServiceKey, protocol), 0);
        assert_eq!(mem::offset_of!(LbServiceKey, _pad), 1);
        assert_eq!(mem::offset_of!(LbServiceKey, port), 2);
    }

    #[test]
    fn lb_service_config_size() {
        assert_eq!(mem::size_of::<LbServiceConfig>(), 68);
    }

    #[test]
    fn lb_service_config_alignment() {
        assert_eq!(mem::align_of::<LbServiceConfig>(), 4);
    }

    #[test]
    fn lb_service_config_offsets() {
        assert_eq!(mem::offset_of!(LbServiceConfig, algorithm), 0);
        assert_eq!(mem::offset_of!(LbServiceConfig, backend_count), 1);
        assert_eq!(mem::offset_of!(LbServiceConfig, _pad), 2);
        assert_eq!(mem::offset_of!(LbServiceConfig, backend_ids), 4);
    }

    #[test]
    fn lb_backend_entry_size() {
        assert_eq!(mem::size_of::<LbBackendEntry>(), 28);
    }

    #[test]
    fn lb_backend_entry_alignment() {
        assert_eq!(mem::align_of::<LbBackendEntry>(), 4);
    }

    #[test]
    fn lb_backend_entry_offsets() {
        assert_eq!(mem::offset_of!(LbBackendEntry, addr_v4), 0);
        assert_eq!(mem::offset_of!(LbBackendEntry, addr_v6), 4);
        assert_eq!(mem::offset_of!(LbBackendEntry, port), 20);
        assert_eq!(mem::offset_of!(LbBackendEntry, weight), 22);
        assert_eq!(mem::offset_of!(LbBackendEntry, healthy), 24);
        assert_eq!(mem::offset_of!(LbBackendEntry, is_ipv6), 25);
        assert_eq!(mem::offset_of!(LbBackendEntry, _pad), 26);
    }

    #[test]
    fn algorithm_constants() {
        assert_eq!(LB_ALG_ROUND_ROBIN, 0);
        assert_eq!(LB_ALG_WEIGHTED, 1);
        assert_eq!(LB_ALG_IP_HASH, 2);
        assert_eq!(LB_ALG_LEAST_CONN, 3);
    }

    #[test]
    fn metric_constants() {
        assert_eq!(LB_METRIC_PACKETS_FORWARDED, 0);
        assert_eq!(LB_METRIC_PACKETS_NO_BACKEND, 1);
        assert_eq!(LB_METRIC_BYTES_FORWARDED, 2);
        assert_eq!(LB_METRIC_EVENTS_DROPPED, 3);
        assert_eq!(LB_METRIC_COUNT, 5);
    }

    #[test]
    fn event_and_action_constants() {
        assert_eq!(EVENT_TYPE_LB, 14);
        assert_eq!(LB_ACTION_FORWARD, 0);
        assert_eq!(LB_ACTION_NO_BACKEND, 1);
    }
}
