// Re-export EVENT_TYPE_DNS from the canonical location in event.rs
// for backward compatibility with code that imports it from dns::.
pub use crate::event::EVENT_TYPE_DNS;

/// DNS direction: packet is a query (dst_port == 53).
pub const DNS_DIRECTION_QUERY: u8 = 0;
/// DNS direction: packet is a response (src_port == 53).
pub const DNS_DIRECTION_RESPONSE: u8 = 1;

/// Maximum DNS payload bytes captured per event (standard UDP DNS).
pub const DNS_MAX_PAYLOAD: usize = 512;

/// DNS port number.
pub const DNS_PORT: u16 = 53;

/// DNS metric indices for the DNS_METRICS PerCpuArray.
pub const DNS_METRIC_PACKETS_INSPECTED: u32 = 0;
pub const DNS_METRIC_EVENTS_EMITTED: u32 = 1;
pub const DNS_METRIC_ERRORS: u32 = 2;
pub const DNS_METRIC_EVENTS_DROPPED: u32 = 3;

/// DNS event header emitted from the tc-dns eBPF program to userspace
/// via the DNS_EVENTS RingBuf.
///
/// The actual DNS payload follows immediately after this header in the
/// RingBuf entry. Use `dns_payload_len` to determine how many payload
/// bytes are valid.
///
/// Addresses are stored as `[u32; 4]`:
/// - IPv4: `[v4_addr, 0, 0, 0]`
/// - IPv6: full 128-bit address in network order
///
/// Size: 48 bytes (aligned to 8 bytes due to `timestamp_ns` u64).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsEvent {
    pub timestamp_ns: u64,
    pub src_addr: [u32; 4],
    pub dst_addr: [u32; 4],
    /// Number of valid DNS payload bytes following this header.
    pub dns_payload_len: u16,
    /// Offset from the start of this struct to the payload (always 48).
    pub dns_payload_offset: u16,
    /// `DNS_DIRECTION_QUERY` (0) or `DNS_DIRECTION_RESPONSE` (1).
    pub direction: u8,
    /// Bit flags: `FLAG_IPV6` (0x01), `FLAG_VLAN` (0x02).
    pub flags: u8,
    /// 802.1Q VLAN ID (0 = no VLAN).
    pub vlan_id: u16,
}

/// Fixed-size buffer for DNS events in the RingBuf: header + raw payload.
/// Userspace extracts the DNS payload from bytes[48..48+dns_payload_len].
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DnsEventBuf {
    pub header: DnsEvent,
    pub payload: [u8; DNS_MAX_PAYLOAD],
}

// SAFETY: Both types are #[repr(C)], Copy, 'static, and contain only primitive
// types. Safe for zero-copy eBPF RingBuf operations via aya.
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for DnsEvent {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for DnsEventBuf {}

impl DnsEvent {
    /// Size of the DnsEvent header in bytes (payload offset).
    pub const HEADER_SIZE: u16 = 48;
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn test_dns_event_size() {
        assert_eq!(mem::size_of::<DnsEvent>(), 48);
    }

    #[test]
    fn test_dns_event_alignment() {
        assert_eq!(mem::align_of::<DnsEvent>(), 8);
    }

    #[test]
    fn test_dns_event_buf_size() {
        assert_eq!(mem::size_of::<DnsEventBuf>(), 48 + DNS_MAX_PAYLOAD);
        assert_eq!(mem::size_of::<DnsEventBuf>(), 560);
    }

    #[test]
    fn test_dns_event_field_offsets() {
        assert_eq!(mem::offset_of!(DnsEvent, timestamp_ns), 0);
        assert_eq!(mem::offset_of!(DnsEvent, src_addr), 8);
        assert_eq!(mem::offset_of!(DnsEvent, dst_addr), 24);
        assert_eq!(mem::offset_of!(DnsEvent, dns_payload_len), 40);
        assert_eq!(mem::offset_of!(DnsEvent, dns_payload_offset), 42);
        assert_eq!(mem::offset_of!(DnsEvent, direction), 44);
        assert_eq!(mem::offset_of!(DnsEvent, flags), 45);
        assert_eq!(mem::offset_of!(DnsEvent, vlan_id), 46);
    }

    #[test]
    fn test_dns_event_header_size_constant() {
        assert_eq!(DnsEvent::HEADER_SIZE as usize, mem::size_of::<DnsEvent>());
    }

    #[test]
    fn test_dns_direction_constants() {
        assert_eq!(DNS_DIRECTION_QUERY, 0);
        assert_eq!(DNS_DIRECTION_RESPONSE, 1);
    }

    #[test]
    fn test_dns_metric_indices() {
        assert_eq!(DNS_METRIC_PACKETS_INSPECTED, 0);
        assert_eq!(DNS_METRIC_EVENTS_EMITTED, 1);
        assert_eq!(DNS_METRIC_ERRORS, 2);
        assert_eq!(DNS_METRIC_EVENTS_DROPPED, 3);
    }

    #[test]
    fn test_dns_max_payload() {
        assert_eq!(DNS_MAX_PAYLOAD, 512);
    }

    #[test]
    fn test_event_type_dns() {
        assert_eq!(EVENT_TYPE_DNS, 7);
    }
}
