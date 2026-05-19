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
/// Maglev consistent hashing: O(1) lookup into a precomputed permutation
/// ring, minimal flow disruption (~1/N) on backend set change.
pub const LB_ALG_MAGLEV: u8 = 4;

/// Forwarding-mode constants for `LbServiceConfigV2.mode`.
/// DNAT (default): rewrite dst IP/port + recompute L3/L4 checksums.
pub const LB_MODE_DNAT: u8 = 0;
/// L2 Direct Server Return: rewrite only dst MAC, leave dst IP = VIP and
/// L3/L4 checksums untouched; backend replies directly to the client.
pub const LB_MODE_L2DSR: u8 = 1;

/// Maximum backends per service (legacy, used by `LbServiceConfig`).
pub const LB_MAX_BACKENDS: usize = 16;

/// Maximum backends per service (V2 two-level architecture).
pub const LB_MAX_BACKENDS_V2: u32 = 256;
/// Maximum LB services (V2).
pub const MAX_LB_SERVICES: u32 = 4096;
/// Maximum total backends in the `LB_BACKENDS` map (V2).
pub const MAX_LB_BACKENDS_TOTAL: u32 = 65536;

// ── Shared service index hash ──────────────────────────────────

/// FNV-1a hash of a `u32` — shared by the eBPF data plane and userspace
/// so both derive an identical per-service index (single source of
/// truth, no drift between `LB_RR_STATE` / `LB_MAGLEV` keys).
#[must_use]
pub fn lb_fnv1a_u32(val: u32) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for byte in val.to_le_bytes() {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

/// Per-service index in `0..MAX_LB_SERVICES`, keyed by (protocol, port).
/// Used as the `LB_RR_STATE` and `LB_MAGLEV` map key.
#[must_use]
pub fn lb_service_index(protocol: u8, port: u16) -> u32 {
    let combined = (u32::from(protocol) << 16) | u32::from(port);
    lb_fnv1a_u32(combined) % MAX_LB_SERVICES
}

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
/// Size: 68 bytes.
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

// ── Service Config V2 (Two-Level) ──────────────────────────────

/// Compact service config for the two-level LB architecture.
///
/// Backend IDs are no longer embedded — instead, `backend_start_id`
/// points into the global `LB_BACKENDS` map. The eBPF program iterates
/// `backend_start_id..backend_start_id + backend_count` to find a
/// healthy backend.
///
/// Size: 8 bytes (vs 68 bytes for `LbServiceConfig`).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LbServiceConfigV2 {
    /// Balancing algorithm: `LB_ALG_ROUND_ROBIN`, etc.
    pub algorithm: u8,
    /// Number of active backends (0..=255).
    pub backend_count: u8,
    /// Forwarding mode: `LB_MODE_DNAT` (default) or `LB_MODE_L2DSR`.
    pub mode: u8,
    pub _pad: u8,
    /// First backend ID in the global `LB_BACKENDS` map.
    /// Backends are at IDs `backend_start_id..backend_start_id + backend_count`.
    pub backend_start_id: u32,
}

// ── Maglev Lookup Table ────────────────────────────────────────

/// Maglev ring size. Prime, per the Maglev paper (Eisenbud et al., NSDI'16):
/// must be a prime sufficiently larger than the max backend count so the
/// permutation fills every slot. 65537 is the smallest prime > 65536.
pub const MAGLEV_RING_SIZE: usize = 65537;

/// Sentinel stored in an unpopulated ring slot (no healthy backend).
/// Slots only stay empty if a service has zero healthy backends.
pub const MAGLEV_EMPTY: u16 = u16::MAX;

/// Maximum number of services that may use the Maglev algorithm
/// concurrently. Each table is ~128 KiB so the map is capped well
/// below `MAX_LB_SERVICES` to bound kernel memory.
pub const MAX_MAGLEV_SERVICES: u32 = 256;

/// Value for the `LB_MAGLEV` `HashMap`, keyed by service slot index.
///
/// Built by userspace (pure domain table generator), read by eBPF with
/// a single `entries[hash(5-tuple) % MAGLEV_RING_SIZE]` index — no
/// per-packet state write. Each entry is a slot index into the
/// service's backend window (`0..backend_count`), or `MAGLEV_EMPTY`.
///
/// Size: 131074 bytes (65537 × u16).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaglevLookup {
    /// Ring entries: backend slot index within the service window.
    pub entries: [u16; MAGLEV_RING_SIZE],
}

impl MaglevLookup {
    /// A fully-empty table (every slot = `MAGLEV_EMPTY`).
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            entries: [MAGLEV_EMPTY; MAGLEV_RING_SIZE],
        }
    }
}

impl Default for MaglevLookup {
    fn default() -> Self {
        Self::empty()
    }
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

// ── Backend MAC (L2 DSR) ───────────────────────────────────────

/// Value for the `LB_BACKEND_MAC` `HashMap`, keyed by backend ID.
///
/// Populated by userspace neighbor/ARP/ND resolution in the eBPF loader
/// adapter. Read by the eBPF data plane only when a service is in
/// `LB_MODE_L2DSR` — the destination Ethernet address is rewritten to
/// `mac` and the packet is L2-redirected with no L3/L4 mutation.
///
/// A dedicated 8-byte struct (not a bare `[u8; 6]`) so the type is a
/// well-defined `aya::Pod` with explicit padding.
///
/// Size: 8 bytes (aligned to 1 byte; padded to 8 for map-value stability).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendMac {
    /// Resolved backend MAC address.
    pub mac: [u8; 6],
    pub _pad: [u8; 2],
}

impl BackendMac {
    /// Construct from a resolved 6-byte MAC.
    #[must_use]
    pub const fn new(mac: [u8; 6]) -> Self {
        Self { mac, _pad: [0; 2] }
    }
}

/// Maximum entries in the `LB_BACKEND_MAC` map (one per backend, V2).
pub const MAX_LB_BACKEND_MAC: u32 = MAX_LB_BACKENDS_TOTAL;

// ── Metrics ────────────────────────────────────────────────────

/// Metric index constants for `LB_METRICS` `PerCpuArray`.
pub const LB_METRIC_PACKETS_FORWARDED: u32 = 0;
pub const LB_METRIC_PACKETS_NO_BACKEND: u32 = 1;
pub const LB_METRIC_BYTES_FORWARDED: u32 = 2;
pub const LB_METRIC_EVENTS_DROPPED: u32 = 3;
/// Metric index: total packets seen (unconditional, first instruction).
pub const LB_METRIC_TOTAL_SEEN: u32 = 4;
/// Metric index: packets dropped because they exceeded the output interface MTU.
/// Incremented by `bpf_check_mtu` guard before XDP_TX/XDP_REDIRECT forwarding.
pub const LB_METRIC_MTU_EXCEEDED: u32 = 5;
pub const LB_METRIC_COUNT: u32 = 6;

// SAFETY: All types are #[repr(C)], Copy, 'static, and contain only primitive types
// with explicit padding. Safe for zero-copy eBPF map operations via aya.
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for LbServiceKey {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for LbServiceConfig {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for LbBackendEntry {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for LbServiceConfigV2 {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for MaglevLookup {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for BackendMac {}

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
    fn lb_service_config_v2_size() {
        assert_eq!(mem::size_of::<LbServiceConfigV2>(), 8);
    }

    #[test]
    fn lb_service_config_v2_alignment() {
        assert_eq!(mem::align_of::<LbServiceConfigV2>(), 4);
    }

    #[test]
    fn lb_service_config_v2_offsets() {
        assert_eq!(mem::offset_of!(LbServiceConfigV2, algorithm), 0);
        assert_eq!(mem::offset_of!(LbServiceConfigV2, backend_count), 1);
        assert_eq!(mem::offset_of!(LbServiceConfigV2, mode), 2);
        assert_eq!(mem::offset_of!(LbServiceConfigV2, _pad), 3);
        assert_eq!(mem::offset_of!(LbServiceConfigV2, backend_start_id), 4);
    }

    #[test]
    fn lb_mode_constants() {
        assert_eq!(LB_MODE_DNAT, 0);
        assert_eq!(LB_MODE_L2DSR, 1);
    }

    #[test]
    fn backend_mac_layout() {
        assert_eq!(mem::size_of::<BackendMac>(), 8);
        assert_eq!(mem::align_of::<BackendMac>(), 1);
        assert_eq!(mem::offset_of!(BackendMac, mac), 0);
        assert_eq!(mem::offset_of!(BackendMac, _pad), 6);
        assert_eq!(MAX_LB_BACKEND_MAC, MAX_LB_BACKENDS_TOTAL);
        let bm = BackendMac::new([1, 2, 3, 4, 5, 6]);
        assert_eq!(bm.mac, [1, 2, 3, 4, 5, 6]);
        assert_eq!(bm._pad, [0, 0]);
    }

    #[test]
    fn lb_v2_capacity_constants() {
        assert_eq!(LB_MAX_BACKENDS_V2, 256);
        assert_eq!(MAX_LB_SERVICES, 4096);
        assert_eq!(MAX_LB_BACKENDS_TOTAL, 65536);
    }

    #[test]
    fn algorithm_constants() {
        assert_eq!(LB_ALG_ROUND_ROBIN, 0);
        assert_eq!(LB_ALG_WEIGHTED, 1);
        assert_eq!(LB_ALG_IP_HASH, 2);
        assert_eq!(LB_ALG_LEAST_CONN, 3);
        assert_eq!(LB_ALG_MAGLEV, 4);
    }

    #[test]
    fn maglev_ring_is_prime_and_larger_than_max_backends() {
        assert_eq!(MAGLEV_RING_SIZE, 65537);
        let n = MAGLEV_RING_SIZE as u64;
        let mut d = 2u64;
        while d * d <= n {
            assert!(!n.is_multiple_of(d), "MAGLEV_RING_SIZE must be prime");
            d += 1;
        }
        assert!(MAGLEV_RING_SIZE > LB_MAX_BACKENDS_V2 as usize);
    }

    #[test]
    fn maglev_lookup_size() {
        assert_eq!(mem::size_of::<MaglevLookup>(), 131_074);
    }

    #[test]
    fn maglev_lookup_alignment() {
        assert_eq!(mem::align_of::<MaglevLookup>(), 2);
    }

    #[test]
    fn maglev_lookup_offsets() {
        assert_eq!(mem::offset_of!(MaglevLookup, entries), 0);
    }

    #[test]
    fn maglev_lookup_empty_is_all_sentinel() {
        let t = MaglevLookup::empty();
        assert_eq!(MAGLEV_EMPTY, u16::MAX);
        assert!(t.entries.iter().all(|&e| e == MAGLEV_EMPTY));
        assert_eq!(MAX_MAGLEV_SERVICES, 256);
    }

    #[test]
    fn metric_constants() {
        assert_eq!(LB_METRIC_PACKETS_FORWARDED, 0);
        assert_eq!(LB_METRIC_PACKETS_NO_BACKEND, 1);
        assert_eq!(LB_METRIC_BYTES_FORWARDED, 2);
        assert_eq!(LB_METRIC_EVENTS_DROPPED, 3);
        assert_eq!(LB_METRIC_MTU_EXCEEDED, 5);
        assert_eq!(LB_METRIC_COUNT, 6);
    }

    #[test]
    fn event_and_action_constants() {
        assert_eq!(EVENT_TYPE_LB, 14);
        assert_eq!(LB_ACTION_FORWARD, 0);
        assert_eq!(LB_ACTION_NO_BACKEND, 1);
    }
}
