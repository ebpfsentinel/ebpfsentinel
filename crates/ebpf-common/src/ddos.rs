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

// ── SYN Cookie Secret ────────────────────────────────────────────

/// SYN cookie secret key (32 bytes), stored in Array map, set by userspace.
///
/// Size: 32 bytes (8 × u32), align 4.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SyncookieSecret {
    pub key: [u32; 8],
}

/// Common MSS values for SYN cookie encoding (3-bit index to MSS value).
pub const SYNCOOKIE_MSS_TABLE: [u16; 8] = [536, 1220, 1440, 1452, 1460, 4312, 8960, 65535];

// ── SYN Cookie Keyed PRF (SipHash-2-4) ───────────────────────────

/// One SipHash round — the ARX permutation `SIPROUND`.
#[inline(always)]
fn sipround(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = v1.rotate_left(13);
    *v1 ^= *v0;
    *v0 = v0.rotate_left(32);
    *v2 = v2.wrapping_add(*v3);
    *v3 = v3.rotate_left(16);
    *v3 ^= *v2;
    *v0 = v0.wrapping_add(*v3);
    *v3 = v3.rotate_left(21);
    *v3 ^= *v0;
    *v2 = v2.wrapping_add(*v1);
    *v1 = v1.rotate_left(17);
    *v1 ^= *v2;
    *v2 = v2.rotate_left(32);
}

/// SipHash-2-4 over `N` little-endian 64-bit message words, keyed by the
/// 128-bit key `(k0, k1)`. `total_len` is the message length in bytes
/// folded into the finalization block (equals `8 * N` for full-word
/// messages).
///
/// SipHash is a keyed pseudo-random function: without the key, recovering
/// it or forging an output for a fresh input costs on the order of `2^128`
/// work. That property is what the SYN-cookie scheme relies on — see
/// [`syncookie_prf`]. The const generic `N` keeps the compression loop
/// fully unrollable, so the BPF verifier accepts it as a bounded program.
#[inline(always)]
fn siphash_2_4<const N: usize>(k0: u64, k1: u64, words: &[u64; N], total_len: u64) -> u64 {
    let mut v0 = k0 ^ 0x736f_6d65_7073_6575;
    let mut v1 = k1 ^ 0x646f_7261_6e64_6f6d;
    let mut v2 = k0 ^ 0x6c79_6765_6e65_7261;
    let mut v3 = k1 ^ 0x7465_6462_7974_6573;

    let mut i = 0usize;
    while i < N {
        let m = words[i];
        v3 ^= m;
        // c = 2 compression rounds per message word.
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= m;
        i += 1;
    }

    // Finalization block carries the message length in its top byte.
    let b = (total_len & 0xff) << 56;
    v3 ^= b;
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= b;

    v2 ^= 0xff;
    // d = 4 finalization rounds.
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);

    v0 ^ v1 ^ v2 ^ v3
}

/// Keyed SYN-cookie pseudo-random function (SipHash-2-4).
///
/// Computes a 32-bit value over the connection 4-tuple and the
/// minute-granularity time counter, keyed by the 256-bit per-boot secret.
/// All 256 secret bits contribute: 128 bits form the SipHash key, the
/// other 128 are prepended to the message as a secret prefix. Because
/// SipHash is a keyed PRF, an attacker who observes cookies (e.g. via the
/// forged SYN+ACK sequence number) cannot recover the secret nor forge a
/// cookie for a spoofed tuple without ~`2^128` work — unlike a plain
/// non-keyed hash, whose secret is recoverable from a few observed pairs.
#[inline(always)]
#[must_use]
pub fn syncookie_prf(
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    ts_counter: u32,
    secret: &[u32; 8],
) -> u32 {
    let k0 = u64::from(secret[0]) | (u64::from(secret[1]) << 32);
    let k1 = u64::from(secret[2]) | (u64::from(secret[3]) << 32);
    let words: [u64; 4] = [
        u64::from(secret[4]) | (u64::from(secret[5]) << 32),
        u64::from(secret[6]) | (u64::from(secret[7]) << 32),
        (u64::from(src_ip) << 32) | u64::from(dst_ip),
        (u64::from(src_port) << 48) | (u64::from(dst_port) << 32) | u64::from(ts_counter),
    ];
    let h = siphash_2_4(k0, k1, &words, 32);
    // Fold the 64-bit PRF output down to the 32 bits the cookie carries.
    u32::try_from((h ^ (h >> 32)) & 0xFFFF_FFFF).unwrap_or(0)
}

/// Per-CPU context passed from `xdp-ratelimit` to `xdp-ratelimit-syncookie`
/// via a shared `PerCpuArray` map. Contains all packet fields needed to
/// forge the SYN+ACK response without re-reading from the packet.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SyncookieCtx {
    /// Source IP (u32 for IPv4, XOR-folded hash for IPv6).
    pub src_ip: u32,
    /// Destination IP (u32 for IPv4, XOR-folded hash for IPv6).
    pub dst_ip: u32,
    /// Source port (host byte order).
    pub src_port: u16,
    /// Destination port (host byte order).
    pub dst_port: u16,
    /// Incoming TCP sequence number (host byte order).
    pub in_seq: u32,
    /// Source port (network byte order, for header write).
    pub in_src_port_be: u16,
    /// Destination port (network byte order, for header write).
    pub in_dst_port_be: u16,
    /// MSS table index (0-7).
    pub mss_idx: u8,
    /// Flags: FLAG_IPV6 if IPv6 packet.
    pub flags: u8,
    pub _pad: [u8; 2],
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
pub struct DdosConnTrackConfig {
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
pub struct DdosConnTrackKey {
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
pub struct DdosConnTrackValue {
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
/// Metric index: SYN flood drops (SYN packets dropped by flood protection).
pub const DDOS_METRIC_SYN_FLOOD_DROPS: u32 = 1;
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
/// Metric index: SYN+ACK cookies forged and sent via `XDP_TX`.
pub const DDOS_METRIC_SYNCOOKIE_SENT: u32 = 15;
/// Metric index: ACKs with valid SYN cookies (handshake completed).
pub const DDOS_METRIC_SYNCOOKIE_VALID: u32 = 16;
/// Metric index: ACKs with invalid SYN cookies.
pub const DDOS_METRIC_SYNCOOKIE_INVALID: u32 = 17;
/// Total number of DDoS metric slots.
pub const DDOS_METRIC_COUNT: u32 = 18;

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
unsafe impl aya::Pod for DdosConnTrackConfig {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for DdosConnTrackKey {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for DdosConnTrackValue {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for FloodCounterKey {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for SyncookieSecret {}

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
    fn ddos_conntrack_config_size() {
        assert_eq!(mem::size_of::<DdosConnTrackConfig>(), 32);
    }

    #[test]
    fn ddos_conntrack_config_alignment() {
        assert_eq!(mem::align_of::<DdosConnTrackConfig>(), 8);
    }

    #[test]
    fn ddos_conntrack_config_field_offsets() {
        assert_eq!(mem::offset_of!(DdosConnTrackConfig, enabled), 0);
        assert_eq!(mem::offset_of!(DdosConnTrackConfig, half_open_threshold), 4);
        assert_eq!(mem::offset_of!(DdosConnTrackConfig, rst_threshold), 8);
        assert_eq!(mem::offset_of!(DdosConnTrackConfig, fin_threshold), 12);
        assert_eq!(mem::offset_of!(DdosConnTrackConfig, ack_threshold), 16);
        assert_eq!(mem::offset_of!(DdosConnTrackConfig, timeout_ns), 24);
    }

    #[test]
    fn ddos_conntrack_key_size() {
        assert_eq!(mem::size_of::<DdosConnTrackKey>(), 12);
    }

    #[test]
    fn ddos_conntrack_value_size() {
        assert_eq!(mem::size_of::<DdosConnTrackValue>(), 24);
    }

    #[test]
    fn ddos_conntrack_value_field_offsets() {
        assert_eq!(mem::offset_of!(DdosConnTrackValue, state), 0);
        assert_eq!(mem::offset_of!(DdosConnTrackValue, first_seen_ns), 8);
        assert_eq!(mem::offset_of!(DdosConnTrackValue, last_seen_ns), 16);
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
    fn syncookie_secret_size() {
        assert_eq!(mem::size_of::<SyncookieSecret>(), 32);
    }

    #[test]
    fn syncookie_secret_alignment() {
        assert_eq!(mem::align_of::<SyncookieSecret>(), 4);
    }

    #[test]
    fn syncookie_mss_table_len() {
        assert_eq!(SYNCOOKIE_MSS_TABLE.len(), 8);
        assert_eq!(SYNCOOKIE_MSS_TABLE[4], 1460);
    }

    #[test]
    fn siphash_2_4_matches_reference_vectors() {
        // Published SipHash-2-4 vectors: key = 00 01 .. 0f (little-endian
        // words), message = 00 01 .. (len-1).
        let k0 = 0x0706_0504_0302_0100u64;
        let k1 = 0x0f0e_0d0c_0b0a_0908u64;
        // Empty message.
        let empty: [u64; 0] = [];
        assert_eq!(siphash_2_4(k0, k1, &empty, 0), 0x726f_db47_dd0e_0e31);
        // 8-byte message → exactly one little-endian word.
        let one = [0x0706_0504_0302_0100u64];
        assert_eq!(siphash_2_4(k0, k1, &one, 8), 0x93f5_f579_9a93_2462);
    }

    #[test]
    fn syncookie_prf_is_deterministic() {
        let secret = [1, 2, 3, 4, 5, 6, 7, 8];
        let a = syncookie_prf(0x0a00_0001, 0x0a00_0002, 1234, 80, 42, &secret);
        let b = syncookie_prf(0x0a00_0001, 0x0a00_0002, 1234, 80, 42, &secret);
        assert_eq!(a, b);
    }

    #[test]
    fn syncookie_prf_depends_on_every_input_field() {
        let secret = [
            0x1111_1111,
            0x2222_2222,
            0x3333_3333,
            0x4444_4444,
            0x5555_5555,
            0x6666_6666,
            0x7777_7777,
            0x8888_8888,
        ];
        let base = syncookie_prf(0x0a00_0001, 0x0a00_0002, 1234, 80, 42, &secret);
        assert_ne!(
            base,
            syncookie_prf(0x0a00_0011, 0x0a00_0002, 1234, 80, 42, &secret),
            "src_ip"
        );
        assert_ne!(
            base,
            syncookie_prf(0x0a00_0001, 0x0a00_0012, 1234, 80, 42, &secret),
            "dst_ip"
        );
        assert_ne!(
            base,
            syncookie_prf(0x0a00_0001, 0x0a00_0002, 1235, 80, 42, &secret),
            "src_port"
        );
        assert_ne!(
            base,
            syncookie_prf(0x0a00_0001, 0x0a00_0002, 1234, 81, 42, &secret),
            "dst_port"
        );
        assert_ne!(
            base,
            syncookie_prf(0x0a00_0001, 0x0a00_0002, 1234, 80, 43, &secret),
            "ts_counter"
        );
    }

    #[test]
    fn syncookie_prf_depends_on_full_secret() {
        let base_secret = [1, 2, 3, 4, 5, 6, 7, 8];
        let base = syncookie_prf(0x0a00_0001, 0x0a00_0002, 1234, 80, 42, &base_secret);
        // Flipping a bit in any of the 8 secret words must change the output,
        // proving the whole 256-bit key is keyed in.
        for i in 0..8 {
            let mut s = base_secret;
            s[i] ^= 1;
            assert_ne!(
                base,
                syncookie_prf(0x0a00_0001, 0x0a00_0002, 1234, 80, 42, &s),
                "secret word {i} did not affect output"
            );
        }
    }

    #[test]
    fn ddos_metric_indices() {
        assert_eq!(DDOS_METRIC_SYN_RECEIVED, 0);
        assert_eq!(DDOS_METRIC_SYN_FLOOD_DROPS, 1);
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
        assert_eq!(DDOS_METRIC_TOTAL_SEEN, 14);
        assert_eq!(DDOS_METRIC_SYNCOOKIE_SENT, 15);
        assert_eq!(DDOS_METRIC_SYNCOOKIE_VALID, 16);
        assert_eq!(DDOS_METRIC_SYNCOOKIE_INVALID, 17);
        assert_eq!(DDOS_METRIC_COUNT, 18);
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
