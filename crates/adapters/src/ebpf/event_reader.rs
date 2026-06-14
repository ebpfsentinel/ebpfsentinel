#![allow(unsafe_code)] // Required for eBPF RingBuf event parsing (read_unaligned)

use crate::ebpf::map_store::MapStore;
use aya::maps::{MapData, RingBuf};
use domain::common::agent_event::AgentEvent;
use ebpf_common::event::{EVENT_TYPE_L7, PacketEvent};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info};

/// Reads packet events from the eBPF EVENTS `RingBuf`.
///
/// Uses `AsyncFd` for epoll-based async notification and drains
/// all available events in batch (never one-at-a-time).
/// Events are sent to a bounded mpsc channel; on backpressure
/// events are dropped with a debug log.
pub struct EventReader {
    ring_buf: AsyncFd<RingBuf<MapData>>,
}

impl EventReader {
    /// Create a new `EventReader` by taking ownership of the EVENTS map.
    pub fn new(ebpf: &mut dyn MapStore) -> Result<Self, anyhow::Error> {
        let map = ebpf
            .take_map("EVENTS")
            .ok_or_else(|| anyhow::anyhow!("map 'EVENTS' not found in eBPF object"))?;
        let ring_buf = RingBuf::try_from(map)?;
        let async_fd = AsyncFd::with_interest(ring_buf, tokio::io::Interest::READABLE)?;
        info!("EVENTS RingBuf reader initialized");
        Ok(Self { ring_buf: async_fd })
    }

    /// Run the event reader loop, sending parsed events to `tx`.
    ///
    /// This is a long-running async task. It exits when the `RingBuf`
    /// encounters an unrecoverable error, the `cancel` token is triggered,
    /// or the runtime shuts down.
    pub async fn run(self, tx: mpsc::Sender<AgentEvent>, cancel: CancellationToken) {
        let mut async_fd = self.ring_buf;

        loop {
            // Wait for kernel to signal data available, or cancellation
            let mut guard = tokio::select! {
                () = cancel.cancelled() => {
                    info!("event reader cancelled");
                    break;
                }
                result = async_fd.readable_mut() => {
                    match result {
                        Ok(guard) => guard,
                        Err(e) => {
                            error!("RingBuf readable error: {e}");
                            break;
                        }
                    }
                }
            };

            // Batch drain: read all available events
            let rb = guard.get_inner_mut();
            while let Some(item) = rb.next() {
                if let Some(agent_event) = decode_event(&item) {
                    // Backpressure: drop on full channel
                    if tx.try_send(agent_event).is_err() {
                        debug!("event channel full, dropping event");
                    }
                }
            }

            guard.clear_ready();
        }
    }
}

/// Decode one `RingBuf` record into an [`AgentEvent`].
///
/// Returns `None` when the record is too short to hold a [`PacketEvent`].
/// For L7 events the kernel reserves a fixed-size buffer (512 or 2048 B)
/// but only fills `header.rule_id` bytes via `bpf_skb_load_bytes`; the
/// remaining bytes are uninitialised kernel memory. The payload is trimmed
/// to that captured length so downstream parsers never read — nor leak —
/// the stale tail.
fn decode_event(bytes: &[u8]) -> Option<AgentEvent> {
    let header_len = std::mem::size_of::<PacketEvent>();
    if bytes.len() < header_len {
        return None;
    }
    // SAFETY: PacketEvent is #[repr(C)] with a known layout the kernel
    // writes verbatim. The length is checked above; read_unaligned copes
    // with any alignment.
    let event = unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<PacketEvent>()) };

    if event.event_type == EVENT_TYPE_L7 && bytes.len() > header_len {
        let raw = &bytes[header_len..];
        let real_len = (event.rule_id as usize).min(raw.len());
        Some(AgentEvent::L7 {
            header: event,
            payload: raw[..real_len].to_vec(),
        })
    } else {
        Some(AgentEvent::L4(event))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_event_byte_parsing() {
        // Construct known bytes matching the 96-byte PacketEvent layout
        // (80 bytes + rss_hash u32 + rss_hash_type u32 + rx_hw_timestamp_ns u64).
        let mut bytes = [0u8; 96];

        // timestamp_ns at offset 0 (u64 LE)
        let ts: u64 = 1_000_000_000;
        bytes[0..8].copy_from_slice(&ts.to_ne_bytes());

        // src_addr at offset 8 ([u32; 4] = 16 bytes)
        let src_ip: u32 = 0xC0A8_0001; // 192.168.0.1
        bytes[8..12].copy_from_slice(&src_ip.to_ne_bytes());
        // src_addr[1..3] remain zero (IPv4)

        // dst_addr at offset 24 ([u32; 4] = 16 bytes)
        let dst_ip: u32 = 0x0A00_0001; // 10.0.0.1
        bytes[24..28].copy_from_slice(&dst_ip.to_ne_bytes());
        // dst_addr[1..3] remain zero (IPv4)

        // src_port at offset 40 (u16)
        let src_port: u16 = 12345;
        bytes[40..42].copy_from_slice(&src_port.to_ne_bytes());

        // dst_port at offset 42 (u16)
        let dst_port: u16 = 80;
        bytes[42..44].copy_from_slice(&dst_port.to_ne_bytes());

        // protocol at offset 44 (u8)
        bytes[44] = 6; // TCP

        // event_type at offset 45 (u8)
        bytes[45] = 0; // FIREWALL

        // action at offset 46 (u8)
        bytes[46] = 1; // DROP

        // flags at offset 47 (u8)
        bytes[47] = 0;

        // rule_id at offset 48 (u32)
        let rule_id: u32 = 42;
        bytes[48..52].copy_from_slice(&rule_id.to_ne_bytes());

        // vlan_id at offset 52 (u16)
        bytes[52..54].copy_from_slice(&0u16.to_ne_bytes());

        // cpu_id at offset 54 (u16)
        let cpu_id: u16 = 3;
        bytes[54..56].copy_from_slice(&cpu_id.to_ne_bytes());

        // socket_cookie at offset 56 (u64)
        let cookie: u64 = 0xDEAD_BEEF_CAFE_BABE;
        bytes[56..64].copy_from_slice(&cookie.to_ne_bytes());

        // cgroup_id at offset 64 (u64)
        let cgroup_id: u64 = 0x1234_5678_9ABC_DEF0;
        bytes[64..72].copy_from_slice(&cgroup_id.to_ne_bytes());

        // cgroup1_id at offset 72 (u64)
        let cgroup1_id: u64 = 0xABCD_EF01_2345_6789;
        bytes[72..80].copy_from_slice(&cgroup1_id.to_ne_bytes());

        // rss_hash at offset 80 (u32)
        let rss_hash: u32 = 0xDEAD_BEEF;
        bytes[80..84].copy_from_slice(&rss_hash.to_ne_bytes());

        // rss_hash_type at offset 84 (u32) — L3_IPV4 | L4 | L4_TCP
        let rss_type: u32 = 1 | 8 | 16;
        bytes[84..88].copy_from_slice(&rss_type.to_ne_bytes());

        // rx_hw_timestamp_ns at offset 88 (u64)
        let hw_ts: u64 = 1_700_000_000_123_456_789;
        bytes[88..96].copy_from_slice(&hw_ts.to_ne_bytes());

        // Parse the event
        let event: PacketEvent =
            unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<PacketEvent>()) };

        assert_eq!(event.timestamp_ns, 1_000_000_000);
        assert_eq!(event.src_ip(), 0xC0A8_0001);
        assert_eq!(event.dst_ip(), 0x0A00_0001);
        assert_eq!(event.src_port, 12345);
        assert_eq!(event.dst_port, 80);
        assert_eq!(event.protocol, 6);
        assert_eq!(event.event_type, 0);
        assert_eq!(event.action, 1);
        assert_eq!(event.rule_id, 42);
        assert_eq!(event.vlan_id, 0);
        assert_eq!(event.socket_cookie, 0xDEAD_BEEF_CAFE_BABE);
        assert_eq!(event.cgroup_id, 0x1234_5678_9ABC_DEF0);
        assert_eq!(event.cgroup1_id, 0xABCD_EF01_2345_6789);
        assert_eq!(event.rss_hash, 0xDEAD_BEEF);
        assert_eq!(event.rss_hash_type, rss_type);
        assert_eq!(event.rx_hw_timestamp_ns, 1_700_000_000_123_456_789);
        assert!(event.has_hw_rss_hash());
        assert!(event.has_hw_timestamp());
    }

    #[test]
    fn packet_event_size_is_96_bytes() {
        // 80-byte layout grew to 96 when the rss_hash + rss_hash_type
        // + rx_hw_timestamp_ns fields were appended for the
        // bpf_xdp_metadata_rx_hash / _rx_timestamp kfuncs (kernel 6.3+).
        assert_eq!(std::mem::size_of::<PacketEvent>(), 96);
    }

    #[test]
    fn short_bytes_rejected() {
        // Verify that our length check would reject short data
        let short_bytes = [0u8; 16];
        assert!(short_bytes.len() < std::mem::size_of::<PacketEvent>());
        assert!(decode_event(&short_bytes).is_none());
    }

    #[test]
    fn l7_payload_trimmed_to_captured_length() {
        let header_len = std::mem::size_of::<PacketEvent>();
        let real = [0x16u8, 0x03, 0x01, 0x00, 0x05];
        let mut bytes = vec![0u8; header_len];
        bytes[45] = EVENT_TYPE_L7; // event_type
        bytes[48..52].copy_from_slice(&(real.len() as u32).to_ne_bytes()); // rule_id = captured len
        bytes.extend_from_slice(&real);
        // Fixed small-tier buffer tail (512 B) of uninitialised garbage.
        bytes.extend_from_slice(&[0xFFu8; 512 - 5]);

        match decode_event(&bytes) {
            Some(AgentEvent::L7 { payload, .. }) => {
                assert_eq!(payload.len(), real.len(), "must trim to captured length");
                assert_eq!(payload, real, "must not leak the stale tail");
            }
            _ => panic!("expected an L7 event"),
        }
    }

    #[test]
    fn l7_payload_len_clamped_to_available() {
        // A captured length larger than the buffer must clamp, not panic.
        let header_len = std::mem::size_of::<PacketEvent>();
        let mut bytes = vec![0u8; header_len];
        bytes[45] = EVENT_TYPE_L7;
        bytes[48..52].copy_from_slice(&9999u32.to_ne_bytes());
        bytes.extend_from_slice(&[0xABu8; 10]);

        match decode_event(&bytes) {
            Some(AgentEvent::L7 { payload, .. }) => assert_eq!(payload.len(), 10),
            _ => panic!("expected an L7 event"),
        }
    }
}
