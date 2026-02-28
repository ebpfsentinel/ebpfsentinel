//! Connection tracking shared types for kernel (eBPF) and userspace.
//!
//! Used by: tc-conntrack (state update), xdp-firewall (fast-path read),
//! tc-nat-ingress/egress (NAT integration), and userspace monitoring.

/// Maximum conntrack table entries (IPv4).
pub const CT_MAX_ENTRIES_V4: u32 = 262_144;

/// Maximum per-source state counter entries.
pub const CT_SRC_COUNTER_MAX: u32 = 65_536;

/// Maximum conntrack table entries (IPv6).
pub const CT_MAX_ENTRIES_V6: u32 = 65_536;

/// Conntrack metric indices (PerCpuArray).
pub const CT_METRIC_NEW: u32 = 0;
pub const CT_METRIC_ESTABLISHED: u32 = 1;
pub const CT_METRIC_CLOSED: u32 = 2;
pub const CT_METRIC_INVALID: u32 = 3;
pub const CT_METRIC_EVICTED: u32 = 4;
pub const CT_METRIC_ERRORS: u32 = 5;
pub const CT_METRIC_LOOKUPS: u32 = 6;
pub const CT_METRIC_HITS: u32 = 7;
pub const CT_METRIC_COUNT: u32 = 8;

// ── Connection states ────────────────────────────────────────────────

pub const CT_STATE_NEW: u8 = 0;
pub const CT_STATE_ESTABLISHED: u8 = 1;
pub const CT_STATE_RELATED: u8 = 2;
pub const CT_STATE_INVALID: u8 = 3;
pub const CT_STATE_SYN_SENT: u8 = 4;
pub const CT_STATE_SYN_RECV: u8 = 5;
pub const CT_STATE_FIN_WAIT: u8 = 6;
pub const CT_STATE_CLOSE_WAIT: u8 = 7;
pub const CT_STATE_TIME_WAIT: u8 = 8;

// ── Connection flags ─────────────────────────────────────────────────

pub const CT_FLAG_SEEN_REPLY: u8 = 0x01;
pub const CT_FLAG_ASSURED: u8 = 0x02;
pub const CT_FLAG_NAT_SRC: u8 = 0x04;
pub const CT_FLAG_NAT_DST: u8 = 0x08;

// ── Conntrack key (IPv4) — 16 bytes ─────────────────────────────────

/// Normalized 5-tuple key for IPv4 connections.
///
/// The key is normalized so that the lower IP:port pair is always "src",
/// ensuring both directions of a connection map to the same entry.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnKey {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub _pad: [u8; 3],
}

// ── Conntrack key (IPv6) — 40 bytes ─────────────────────────────────

/// Normalized 5-tuple key for IPv6 connections.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnKeyV6 {
    pub src_addr: [u32; 4],
    pub dst_addr: [u32; 4],
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub _pad: [u8; 3],
}

// ── Conntrack value — 48 bytes ──────────────────────────────────────

/// Connection state and counters stored in the conntrack table.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnValue {
    /// Current connection state (CT_STATE_*).
    pub state: u8,
    /// Connection flags (CT_FLAG_*).
    pub flags: u8,
    /// NAT type: 0=none, 1=SNAT, 2=DNAT.
    pub nat_type: u8,
    pub _pad: u8,
    /// Forward direction packet count.
    pub packets_fwd: u32,
    /// Reverse direction packet count.
    pub packets_rev: u32,
    /// Forward direction byte count.
    pub bytes_fwd: u32,
    /// Reverse direction byte count.
    pub bytes_rev: u32,
    /// Timestamp of first packet (ktime_get_boot_ns).
    pub first_seen_ns: u64,
    /// Timestamp of most recent packet.
    pub last_seen_ns: u64,
    /// NAT translated address (Phase 4).
    pub nat_addr: u32,
    /// NAT translated port (Phase 4).
    pub nat_port: u16,
    pub _pad2: [u8; 2],
}

// ── Conntrack value (IPv6) — 64 bytes ──────────────────────────────

/// Connection state and counters for IPv6 connections.
///
/// Identical layout to `ConnValue` for the first 40 bytes (`state`..`last_seen_ns`)
/// so the TCP state machine works on both. The `nat_addr` field is widened to
/// 128-bit (`[u32; 4]`) for IPv6 NAT addresses.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnValueV6 {
    /// Current connection state (CT_STATE_*).
    pub state: u8,
    /// Connection flags (CT_FLAG_*).
    pub flags: u8,
    /// NAT type: 0=none, 1=SNAT, 2=DNAT.
    pub nat_type: u8,
    pub _pad: u8,
    /// Forward direction packet count.
    pub packets_fwd: u32,
    /// Reverse direction packet count.
    pub packets_rev: u32,
    /// Forward direction byte count.
    pub bytes_fwd: u32,
    /// Reverse direction byte count.
    pub bytes_rev: u32,
    /// Timestamp of first packet (ktime_get_boot_ns).
    pub first_seen_ns: u64,
    /// Timestamp of most recent packet.
    pub last_seen_ns: u64,
    /// NAT translated IPv6 address.
    pub nat_addr: [u32; 4],
    /// NAT translated port.
    pub nat_port: u16,
    pub _pad2: [u8; 2],
}

// ── Conntrack configuration — 80 bytes ──────────────────────────────

/// Global conntrack configuration, stored in a single-element Array map.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnTrackConfig {
    /// Master enable flag (0=disabled, 1=enabled).
    pub enabled: u8,
    pub _pad: [u8; 3],
    /// Max concurrent connections per source (0 = unlimited).
    pub max_src_states: u32,
    /// TCP ESTABLISHED timeout in nanoseconds (default: 432000s = 5 days).
    pub tcp_established_timeout_ns: u64,
    /// TCP SYN timeout in nanoseconds (default: 120s).
    pub tcp_syn_timeout_ns: u64,
    /// TCP FIN/TIME_WAIT timeout in nanoseconds (default: 120s).
    pub tcp_fin_timeout_ns: u64,
    /// UDP timeout in nanoseconds (default: 30s).
    pub udp_timeout_ns: u64,
    /// UDP "stream" (bidirectional) timeout in nanoseconds (default: 120s).
    pub udp_stream_timeout_ns: u64,
    /// ICMP timeout in nanoseconds (default: 30s).
    pub icmp_timeout_ns: u64,
    /// Max connection rate per source within `conn_rate_window_secs` (0 = unlimited).
    pub max_src_conn_rate: u32,
    /// Rate window duration in seconds (default: 5).
    pub conn_rate_window_secs: u32,
}

impl ConnTrackConfig {
    /// Default timeouts matching Linux nf_conntrack defaults.
    pub const fn defaults() -> Self {
        Self {
            enabled: 1,
            _pad: [0; 3],
            max_src_states: 0,
            tcp_established_timeout_ns: 432_000 * 1_000_000_000, // 5 days
            tcp_syn_timeout_ns: 120 * 1_000_000_000,             // 120s
            tcp_fin_timeout_ns: 120 * 1_000_000_000,             // 120s
            udp_timeout_ns: 30 * 1_000_000_000,                  // 30s
            udp_stream_timeout_ns: 120 * 1_000_000_000,          // 120s
            icmp_timeout_ns: 30 * 1_000_000_000,                 // 30s
            max_src_conn_rate: 0,
            conn_rate_window_secs: 5,
        }
    }
}

// ── Per-source state counter (Epic 25) ──────────────────────────────

/// Per-source-IP connection counter for overload protection.
///
/// Tracks concurrent connections and connection rate per source.
/// Stored in `CT_SRC_COUNTERS` HashMap, keyed by source IPv4 address (u32).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SrcStateCounter {
    /// Current concurrent connection count for this source.
    pub conn_count: u32,
    /// Connections opened within the current rate window.
    pub conn_rate: u32,
    /// Window start timestamp in nanoseconds (`bpf_ktime_get_boot_ns`).
    pub window_start_ns: u64,
    /// Flags: 0x01 = overloaded (source added to blacklist).
    pub flags: u8,
    pub _pad: [u8; 7],
}

/// Flag indicating the source has been added to the overload table.
pub const SRC_COUNTER_FLAG_OVERLOADED: u8 = 0x01;

/// Reserved IP set ID for the overload blacklist.
pub const OVERLOAD_SET_ID: u8 = 255;

// ── Key normalization helper ─────────────────────────────────────────

/// Normalize a 5-tuple so the lower IP:port is always "src".
/// This ensures both directions of a connection use the same key.
#[inline]
pub const fn normalize_key_v4(
    ip_a: u32,
    ip_b: u32,
    port_a: u16,
    port_b: u16,
    protocol: u8,
) -> ConnKey {
    if ip_a < ip_b || (ip_a == ip_b && port_a <= port_b) {
        ConnKey {
            src_ip: ip_a,
            dst_ip: ip_b,
            src_port: port_a,
            dst_port: port_b,
            protocol,
            _pad: [0; 3],
        }
    } else {
        ConnKey {
            src_ip: ip_b,
            dst_ip: ip_a,
            src_port: port_b,
            dst_port: port_a,
            protocol,
            _pad: [0; 3],
        }
    }
}

/// Normalize an IPv6 5-tuple.
#[inline]
pub fn normalize_key_v6(
    addr_a: &[u32; 4],
    addr_b: &[u32; 4],
    port_a: u16,
    port_b: u16,
    protocol: u8,
) -> ConnKeyV6 {
    let a_lower = ipv6_less_than(addr_a, addr_b) || (*addr_a == *addr_b && port_a <= port_b);
    if a_lower {
        ConnKeyV6 {
            src_addr: *addr_a,
            dst_addr: *addr_b,
            src_port: port_a,
            dst_port: port_b,
            protocol,
            _pad: [0; 3],
        }
    } else {
        ConnKeyV6 {
            src_addr: *addr_b,
            dst_addr: *addr_a,
            src_port: port_b,
            dst_port: port_a,
            protocol,
            _pad: [0; 3],
        }
    }
}

/// Lexicographic comparison of two IPv6 addresses stored as `[u32; 4]`.
#[inline]
fn ipv6_less_than(a: &[u32; 4], b: &[u32; 4]) -> bool {
    let mut i = 0;
    while i < 4 {
        if a[i] < b[i] {
            return true;
        }
        if a[i] > b[i] {
            return false;
        }
        i += 1;
    }
    false
}

// ── Pod impls ────────────────────────────────────────────────────────

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for ConnKey {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for ConnKeyV6 {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for ConnValue {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for ConnValueV6 {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for ConnTrackConfig {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for SrcStateCounter {}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn conn_key_size() {
        assert_eq!(mem::size_of::<ConnKey>(), 16);
    }

    #[test]
    fn conn_key_alignment() {
        assert_eq!(mem::align_of::<ConnKey>(), 4);
    }

    #[test]
    fn conn_key_v6_size() {
        assert_eq!(mem::size_of::<ConnKeyV6>(), 40);
    }

    #[test]
    fn conn_key_v6_alignment() {
        assert_eq!(mem::align_of::<ConnKeyV6>(), 4);
    }

    #[test]
    fn conn_value_size() {
        assert_eq!(mem::size_of::<ConnValue>(), 48);
    }

    #[test]
    fn conn_value_alignment() {
        assert_eq!(mem::align_of::<ConnValue>(), 8);
    }

    #[test]
    fn conn_value_v6_size() {
        assert_eq!(mem::size_of::<ConnValueV6>(), 64);
    }

    #[test]
    fn conn_value_v6_alignment() {
        assert_eq!(mem::align_of::<ConnValueV6>(), 8);
    }

    #[test]
    fn conn_value_v6_field_offsets() {
        assert_eq!(mem::offset_of!(ConnValueV6, state), 0);
        assert_eq!(mem::offset_of!(ConnValueV6, flags), 1);
        assert_eq!(mem::offset_of!(ConnValueV6, nat_type), 2);
        assert_eq!(mem::offset_of!(ConnValueV6, packets_fwd), 4);
        assert_eq!(mem::offset_of!(ConnValueV6, packets_rev), 8);
        assert_eq!(mem::offset_of!(ConnValueV6, bytes_fwd), 12);
        assert_eq!(mem::offset_of!(ConnValueV6, bytes_rev), 16);
        assert_eq!(mem::offset_of!(ConnValueV6, first_seen_ns), 24);
        assert_eq!(mem::offset_of!(ConnValueV6, last_seen_ns), 32);
        assert_eq!(mem::offset_of!(ConnValueV6, nat_addr), 40);
        assert_eq!(mem::offset_of!(ConnValueV6, nat_port), 56);
    }

    #[test]
    fn conn_value_v6_state_same_offset_as_v4() {
        // Ensures TCP state machine works on both types
        assert_eq!(
            mem::offset_of!(ConnValue, state),
            mem::offset_of!(ConnValueV6, state)
        );
        assert_eq!(
            mem::offset_of!(ConnValue, flags),
            mem::offset_of!(ConnValueV6, flags)
        );
    }

    #[test]
    fn conn_track_config_size() {
        assert_eq!(mem::size_of::<ConnTrackConfig>(), 64);
    }

    #[test]
    fn conn_track_config_alignment() {
        assert_eq!(mem::align_of::<ConnTrackConfig>(), 8);
    }

    #[test]
    fn src_state_counter_size() {
        assert_eq!(mem::size_of::<SrcStateCounter>(), 24);
    }

    #[test]
    fn src_state_counter_alignment() {
        assert_eq!(mem::align_of::<SrcStateCounter>(), 8);
    }

    #[test]
    fn src_state_counter_field_offsets() {
        assert_eq!(mem::offset_of!(SrcStateCounter, conn_count), 0);
        assert_eq!(mem::offset_of!(SrcStateCounter, conn_rate), 4);
        assert_eq!(mem::offset_of!(SrcStateCounter, window_start_ns), 8);
        assert_eq!(mem::offset_of!(SrcStateCounter, flags), 16);
    }

    #[test]
    fn conn_key_field_offsets() {
        assert_eq!(mem::offset_of!(ConnKey, src_ip), 0);
        assert_eq!(mem::offset_of!(ConnKey, dst_ip), 4);
        assert_eq!(mem::offset_of!(ConnKey, src_port), 8);
        assert_eq!(mem::offset_of!(ConnKey, dst_port), 10);
        assert_eq!(mem::offset_of!(ConnKey, protocol), 12);
    }

    #[test]
    fn conn_value_field_offsets() {
        assert_eq!(mem::offset_of!(ConnValue, state), 0);
        assert_eq!(mem::offset_of!(ConnValue, flags), 1);
        assert_eq!(mem::offset_of!(ConnValue, nat_type), 2);
        assert_eq!(mem::offset_of!(ConnValue, packets_fwd), 4);
        assert_eq!(mem::offset_of!(ConnValue, packets_rev), 8);
        assert_eq!(mem::offset_of!(ConnValue, bytes_fwd), 12);
        assert_eq!(mem::offset_of!(ConnValue, bytes_rev), 16);
        assert_eq!(mem::offset_of!(ConnValue, first_seen_ns), 24);
        assert_eq!(mem::offset_of!(ConnValue, last_seen_ns), 32);
        assert_eq!(mem::offset_of!(ConnValue, nat_addr), 40);
        assert_eq!(mem::offset_of!(ConnValue, nat_port), 44);
    }

    #[test]
    fn normalize_key_v4_lower_first() {
        let k = normalize_key_v4(1, 2, 100, 200, 6);
        assert_eq!(k.src_ip, 1);
        assert_eq!(k.dst_ip, 2);
        assert_eq!(k.src_port, 100);
        assert_eq!(k.dst_port, 200);
    }

    #[test]
    fn normalize_key_v4_higher_first() {
        let k = normalize_key_v4(2, 1, 200, 100, 6);
        assert_eq!(k.src_ip, 1);
        assert_eq!(k.dst_ip, 2);
        assert_eq!(k.src_port, 100);
        assert_eq!(k.dst_port, 200);
    }

    #[test]
    fn normalize_key_v4_same_ip_port_order() {
        let k = normalize_key_v4(5, 5, 300, 100, 17);
        assert_eq!(k.src_ip, 5);
        assert_eq!(k.src_port, 100);
        assert_eq!(k.dst_port, 300);
    }

    #[test]
    fn normalize_key_v4_symmetric() {
        let k1 = normalize_key_v4(0xC0A80001, 0x0A000001, 12345, 80, 6);
        let k2 = normalize_key_v4(0x0A000001, 0xC0A80001, 80, 12345, 6);
        assert_eq!(k1, k2);
    }

    #[test]
    fn normalize_key_v6_symmetric() {
        let a = [1, 0, 0, 0];
        let b = [2, 0, 0, 0];
        let k1 = normalize_key_v6(&a, &b, 100, 200, 6);
        let k2 = normalize_key_v6(&b, &a, 200, 100, 6);
        assert_eq!(k1, k2);
    }

    #[test]
    fn state_constants_distinct() {
        let states = [
            CT_STATE_NEW,
            CT_STATE_ESTABLISHED,
            CT_STATE_RELATED,
            CT_STATE_INVALID,
            CT_STATE_SYN_SENT,
            CT_STATE_SYN_RECV,
            CT_STATE_FIN_WAIT,
            CT_STATE_CLOSE_WAIT,
            CT_STATE_TIME_WAIT,
        ];
        for (i, &a) in states.iter().enumerate() {
            for &b in &states[i + 1..] {
                assert_ne!(a, b, "states {a} and {b} collide");
            }
        }
    }

    #[test]
    fn flag_bits_distinct() {
        let flags = [
            CT_FLAG_SEEN_REPLY,
            CT_FLAG_ASSURED,
            CT_FLAG_NAT_SRC,
            CT_FLAG_NAT_DST,
        ];
        for (i, &a) in flags.iter().enumerate() {
            for &b in &flags[i + 1..] {
                assert_eq!(a & b, 0, "flags 0x{a:02x} and 0x{b:02x} overlap");
            }
        }
    }

    #[test]
    fn default_config_values() {
        let cfg = ConnTrackConfig::defaults();
        assert_eq!(cfg.enabled, 1);
        assert_eq!(cfg.tcp_established_timeout_ns, 432_000_000_000_000);
        assert_eq!(cfg.tcp_syn_timeout_ns, 120_000_000_000);
        assert_eq!(cfg.udp_timeout_ns, 30_000_000_000);
        assert_eq!(cfg.icmp_timeout_ns, 30_000_000_000);
    }
}
