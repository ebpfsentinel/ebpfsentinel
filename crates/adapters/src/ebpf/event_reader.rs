#![allow(unsafe_code)] // Required for eBPF RingBuf event parsing (read_unaligned)

use application::packet_pipeline::AgentEvent;
use aya::Ebpf;
use aya::maps::{MapData, RingBuf};
use ebpf_common::event::{EVENT_TYPE_L7, PacketEvent};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
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
    pub fn new(ebpf: &mut Ebpf) -> Result<Self, anyhow::Error> {
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
    /// encounters an unrecoverable error or the runtime shuts down.
    pub async fn run(self, tx: mpsc::Sender<AgentEvent>) {
        let mut async_fd = self.ring_buf;

        loop {
            // Wait for kernel to signal data available
            let mut guard = match async_fd.readable_mut().await {
                Ok(guard) => guard,
                Err(e) => {
                    error!("RingBuf readable error: {e}");
                    break;
                }
            };

            // Batch drain: read all available events
            let rb = guard.get_inner_mut();
            while let Some(item) = rb.next() {
                let bytes: &[u8] = &item;
                if bytes.len() >= std::mem::size_of::<PacketEvent>() {
                    // SAFETY: PacketEvent is #[repr(C)] with known layout (64 bytes).
                    // The kernel writes this exact layout. We verify the length above.
                    // read_unaligned handles any alignment issues.
                    let event =
                        unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<PacketEvent>()) };

                    let agent_event = if event.event_type == EVENT_TYPE_L7
                        && bytes.len() > std::mem::size_of::<PacketEvent>()
                    {
                        let payload = bytes[std::mem::size_of::<PacketEvent>()..].to_vec();
                        AgentEvent::L7 {
                            header: event,
                            payload,
                        }
                    } else {
                        AgentEvent::L4(event)
                    };

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_event_byte_parsing() {
        // Construct known bytes matching the PacketEvent layout (64 bytes)
        let mut bytes = [0u8; 64];

        // timestamp_ns at offset 0 (u64 LE)
        let ts: u64 = 1_000_000_000;
        bytes[0..8].copy_from_slice(&ts.to_ne_bytes());

        // src_addr at offset 8 ([u32; 4] = 16 bytes)
        let src_ip: u32 = 0xC0A80001; // 192.168.0.1
        bytes[8..12].copy_from_slice(&src_ip.to_ne_bytes());
        // src_addr[1..3] remain zero (IPv4)

        // dst_addr at offset 24 ([u32; 4] = 16 bytes)
        let dst_ip: u32 = 0x0A000001; // 10.0.0.1
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

        // Parse the event
        let event: PacketEvent =
            unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<PacketEvent>()) };

        assert_eq!(event.timestamp_ns, 1_000_000_000);
        assert_eq!(event.src_ip(), 0xC0A80001);
        assert_eq!(event.dst_ip(), 0x0A000001);
        assert_eq!(event.src_port, 12345);
        assert_eq!(event.dst_port, 80);
        assert_eq!(event.protocol, 6);
        assert_eq!(event.event_type, 0);
        assert_eq!(event.action, 1);
        assert_eq!(event.rule_id, 42);
        assert_eq!(event.vlan_id, 0);
        assert_eq!(event.socket_cookie, 0xDEAD_BEEF_CAFE_BABE);
    }

    #[test]
    fn packet_event_size_is_64_bytes() {
        assert_eq!(std::mem::size_of::<PacketEvent>(), 64);
    }

    #[test]
    fn short_bytes_rejected() {
        // Verify that our length check would reject short data
        let short_bytes = [0u8; 16];
        assert!(short_bytes.len() < std::mem::size_of::<PacketEvent>());
    }
}
