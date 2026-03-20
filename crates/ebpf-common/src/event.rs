/// Event type constants — stored as u8 in PacketEvent.event_type
pub const EVENT_TYPE_FIREWALL: u8 = 0;
pub const EVENT_TYPE_IDS: u8 = 1;
pub const EVENT_TYPE_IPS: u8 = 2;
pub const EVENT_TYPE_DLP: u8 = 3;
pub const EVENT_TYPE_RATELIMIT: u8 = 4;
pub const EVENT_TYPE_THREATINTEL: u8 = 5;
pub const EVENT_TYPE_L7: u8 = 6;
pub const EVENT_TYPE_DNS: u8 = 7;
pub const EVENT_TYPE_QOS: u8 = 8;

/// Maximum L7 payload bytes captured by eBPF and sent via RingBuf.
pub const MAX_L7_PAYLOAD: usize = 512;

/// Small L7 payload tier (128 bytes) — covers HTTP method lines, TLS record
/// headers, SSH banners, and most protocol signatures. Used when the packet's
/// TCP payload is ≤ 128 bytes, saving 384 bytes per RingBuf entry (67%).
pub const SMALL_L7_PAYLOAD: usize = 128;

/// Flag bit: packet is IPv6 (otherwise IPv4).
pub const FLAG_IPV6: u8 = 0x01;
/// Flag bit: packet had an 802.1Q VLAN tag.
pub const FLAG_VLAN: u8 = 0x02;
/// Flag bit: DNS event captured over TCP (payload has 2-byte length prefix).
pub const FLAG_TCP: u8 = 0x04;

/// XDP-to-TC metadata passed via `bpf_xdp_adjust_meta`.
///
/// The XDP firewall prepends this struct before `xdp_md->data` so that
/// TC programs can read the firewall verdict without re-parsing packets.
/// 8 bytes, aligned to 4 bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XdpMetadata {
    /// Firewall rule ID that matched (0 = no match / default policy).
    pub rule_id: u32,
    /// Firewall action (`ACTION_PASS`, `ACTION_DROP`, `ACTION_LOG`).
    pub action: u8,
    /// Ratelimit status (0 = not checked, 1 = passed, 2 = throttled).
    pub ratelimit_status: u8,
    /// Miscellaneous XDP metadata flags.
    pub meta_flags: u8,
    pub _pad: u8,
}

/// Flag: XDP metadata is present in `skb->data_meta`.
pub const META_FLAG_PRESENT: u8 = 0x01;

/// Returns `true` if the packet is IPv6.
#[inline]
pub const fn is_ipv6(flags: u8) -> bool {
    flags & FLAG_IPV6 != 0
}

/// Returns `true` if the packet had a VLAN tag.
#[inline]
pub const fn has_vlan(flags: u8) -> bool {
    flags & FLAG_VLAN != 0
}

/// Returns `true` if the DNS event was captured over TCP.
#[inline]
pub const fn is_tcp(flags: u8) -> bool {
    flags & FLAG_TCP != 0
}

/// Packet event emitted from eBPF programs to userspace via RingBuf.
/// All eBPF programs share this event format through the EVENTS RingBuf.
///
/// Addresses are stored as `[u32; 4]`:
/// - IPv4: `[v4_addr, 0, 0, 0]`
/// - IPv6: full 128-bit address in network order
///
/// Size: 64 bytes (aligned to 8 bytes due to `timestamp_ns` u64).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketEvent {
    pub timestamp_ns: u64,
    pub src_addr: [u32; 4],
    pub dst_addr: [u32; 4],
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub event_type: u8,
    pub action: u8,
    /// Bit flags: `FLAG_IPV6` (0x01), `FLAG_VLAN` (0x02).
    pub flags: u8,
    pub rule_id: u32,
    /// 802.1Q VLAN ID (0 = no VLAN).
    pub vlan_id: u16,
    /// CPU ID from `bpf_get_smp_processor_id` (NUMA-aware analysis).
    pub cpu_id: u16,
    /// Per-socket identifier from `bpf_get_socket_cookie` (F20).
    /// 0 = not available (e.g. XDP programs, non-TCP/UDP traffic).
    /// Correlates events across the same connection.
    pub socket_cookie: u64,
}

// SAFETY: Both types are #[repr(C)], Copy, 'static, and contain only primitive
// types with explicit padding. Safe for zero-copy eBPF map/RingBuf operations via aya.
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for PacketEvent {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for XdpMetadata {}

impl PacketEvent {
    /// Extract the source IPv4 address (first element of `src_addr`).
    #[inline]
    pub const fn src_ip(&self) -> u32 {
        self.src_addr[0]
    }

    /// Extract the destination IPv4 address (first element of `dst_addr`).
    #[inline]
    pub const fn dst_ip(&self) -> u32 {
        self.dst_addr[0]
    }

    /// Returns `true` if the packet is IPv6.
    #[inline]
    pub const fn is_ipv6(&self) -> bool {
        is_ipv6(self.flags)
    }

    /// Returns `true` if the packet had a VLAN tag.
    #[inline]
    pub const fn has_vlan(&self) -> bool {
        has_vlan(self.flags)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn test_packet_event_size() {
        assert_eq!(mem::size_of::<PacketEvent>(), 64);
    }

    #[test]
    fn test_packet_event_alignment() {
        assert_eq!(mem::align_of::<PacketEvent>(), 8);
    }

    #[test]
    fn test_xdp_metadata_size() {
        assert_eq!(mem::size_of::<XdpMetadata>(), 8);
    }

    #[test]
    fn test_xdp_metadata_alignment() {
        assert_eq!(mem::align_of::<XdpMetadata>(), 4);
    }

    #[test]
    fn test_event_type_constants() {
        assert_eq!(EVENT_TYPE_FIREWALL, 0);
        assert_eq!(EVENT_TYPE_IDS, 1);
        assert_eq!(EVENT_TYPE_IPS, 2);
        assert_eq!(EVENT_TYPE_DLP, 3);
        assert_eq!(EVENT_TYPE_RATELIMIT, 4);
        assert_eq!(EVENT_TYPE_THREATINTEL, 5);
        assert_eq!(EVENT_TYPE_L7, 6);
        assert_eq!(EVENT_TYPE_DNS, 7);
        assert_eq!(EVENT_TYPE_QOS, 8);
        assert_eq!(MAX_L7_PAYLOAD, 512);
        assert_eq!(SMALL_L7_PAYLOAD, 128);
        assert!(SMALL_L7_PAYLOAD < MAX_L7_PAYLOAD);
    }

    #[test]
    fn test_flag_constants() {
        assert_eq!(FLAG_IPV6, 0x01);
        assert_eq!(FLAG_VLAN, 0x02);
        assert_eq!(FLAG_TCP, 0x04);
    }

    #[test]
    fn test_flag_helpers() {
        assert!(!is_ipv6(0));
        assert!(is_ipv6(FLAG_IPV6));
        assert!(is_ipv6(FLAG_IPV6 | FLAG_VLAN));
        assert!(!has_vlan(0));
        assert!(has_vlan(FLAG_VLAN));
        assert!(has_vlan(FLAG_IPV6 | FLAG_VLAN));
        assert!(!is_tcp(0));
        assert!(is_tcp(FLAG_TCP));
        assert!(is_tcp(FLAG_TCP | FLAG_IPV6));
        assert!(!is_tcp(FLAG_IPV6 | FLAG_VLAN));
    }

    #[test]
    fn test_packet_event_field_offsets() {
        assert_eq!(mem::offset_of!(PacketEvent, timestamp_ns), 0);
        assert_eq!(mem::offset_of!(PacketEvent, src_addr), 8);
        assert_eq!(mem::offset_of!(PacketEvent, dst_addr), 24);
        assert_eq!(mem::offset_of!(PacketEvent, src_port), 40);
        assert_eq!(mem::offset_of!(PacketEvent, dst_port), 42);
        assert_eq!(mem::offset_of!(PacketEvent, protocol), 44);
        assert_eq!(mem::offset_of!(PacketEvent, event_type), 45);
        assert_eq!(mem::offset_of!(PacketEvent, action), 46);
        assert_eq!(mem::offset_of!(PacketEvent, flags), 47);
        assert_eq!(mem::offset_of!(PacketEvent, rule_id), 48);
        assert_eq!(mem::offset_of!(PacketEvent, vlan_id), 52);
        assert_eq!(mem::offset_of!(PacketEvent, cpu_id), 54);
        assert_eq!(mem::offset_of!(PacketEvent, socket_cookie), 56);
    }

    #[test]
    fn test_ipv4_accessors() {
        let event = PacketEvent {
            timestamp_ns: 0,
            src_addr: [0xC0A8_0001, 0, 0, 0],
            dst_addr: [0x0A00_0001, 0, 0, 0],
            src_port: 80,
            dst_port: 443,
            protocol: 6,
            event_type: EVENT_TYPE_FIREWALL,
            action: 0,
            flags: 0,
            rule_id: 0,
            vlan_id: 0,
            cpu_id: 0,
            socket_cookie: 0,
        };
        assert_eq!(event.src_ip(), 0xC0A8_0001);
        assert_eq!(event.dst_ip(), 0x0A00_0001);
        assert!(!event.is_ipv6());
        assert!(!event.has_vlan());
    }

    #[test]
    fn test_ipv6_flag() {
        let event = PacketEvent {
            timestamp_ns: 0,
            src_addr: [0x2001_0db8, 0, 0, 1],
            dst_addr: [0xfe80_0000, 0, 0, 1],
            src_port: 80,
            dst_port: 443,
            protocol: 6,
            event_type: EVENT_TYPE_IDS,
            action: 0,
            flags: FLAG_IPV6,
            rule_id: 0,
            vlan_id: 0,
            cpu_id: 0,
            socket_cookie: 0,
        };
        assert!(event.is_ipv6());
        assert!(!event.has_vlan());
    }

    #[test]
    fn event_type_constants_are_unique() {
        // All EVENT_TYPE_* constants across all modules: event(0-8), ddos(10-13), lb(14).
        // Gap at 9 is intentional (reserved for future use).
        let types: [u8; 14] = [
            0,  // EVENT_TYPE_FIREWALL
            1,  // EVENT_TYPE_IDS
            2,  // EVENT_TYPE_IPS
            3,  // EVENT_TYPE_DLP
            4,  // EVENT_TYPE_RATELIMIT
            5,  // EVENT_TYPE_THREATINTEL
            6,  // EVENT_TYPE_L7
            7,  // EVENT_TYPE_DNS
            8,  // EVENT_TYPE_QOS
            10, // EVENT_TYPE_DDOS_SYN
            11, // EVENT_TYPE_DDOS_ICMP
            12, // EVENT_TYPE_DDOS_AMP
            13, // EVENT_TYPE_DDOS_CONNTRACK
            14, // EVENT_TYPE_LB
        ];
        for i in 0..types.len() {
            for j in (i + 1)..types.len() {
                assert_ne!(
                    types[i], types[j],
                    "EVENT_TYPE collision at indices {i} and {j}"
                );
            }
        }
    }

    #[test]
    fn test_vlan_flag() {
        let event = PacketEvent {
            timestamp_ns: 0,
            src_addr: [0xC0A8_0001, 0, 0, 0],
            dst_addr: [0x0A00_0001, 0, 0, 0],
            src_port: 80,
            dst_port: 443,
            protocol: 6,
            event_type: EVENT_TYPE_FIREWALL,
            action: 0,
            flags: FLAG_VLAN,
            rule_id: 0,
            vlan_id: 100,
            cpu_id: 0,
            socket_cookie: 0,
        };
        assert!(!event.is_ipv6());
        assert!(event.has_vlan());
        assert_eq!(event.vlan_id, 100);
    }
}
