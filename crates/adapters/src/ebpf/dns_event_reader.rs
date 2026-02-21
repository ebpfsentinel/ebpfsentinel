#![allow(unsafe_code)] // Required for eBPF RingBuf event parsing (read_unaligned)

use application::packet_pipeline::AgentEvent;
use aya::Ebpf;
use aya::maps::{MapData, RingBuf};
use ebpf_common::dns::DnsEvent;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tracing::{debug, error, info};

/// Reads DNS events from the eBPF `DNS_EVENTS` `RingBuf`.
///
/// Uses `AsyncFd` for epoll-based async notification. DNS events
/// consist of a 48-byte `DnsEvent` header followed by a variable-length
/// DNS payload (up to 512 bytes).
pub struct DnsEventReader {
    ring_buf: AsyncFd<RingBuf<MapData>>,
}

impl DnsEventReader {
    /// Create a new `DnsEventReader` by taking ownership of the `DNS_EVENTS` map.
    pub fn new(ebpf: &mut Ebpf) -> Result<Self, anyhow::Error> {
        let map = ebpf
            .take_map("DNS_EVENTS")
            .ok_or_else(|| anyhow::anyhow!("map 'DNS_EVENTS' not found in eBPF object"))?;
        let ring_buf = RingBuf::try_from(map)?;
        let async_fd = AsyncFd::with_interest(ring_buf, tokio::io::Interest::READABLE)?;
        info!("DNS_EVENTS RingBuf reader initialized");
        Ok(Self { ring_buf: async_fd })
    }

    /// Run the DNS event reader loop, sending parsed events to `tx`.
    pub async fn run(self, tx: mpsc::Sender<AgentEvent>) {
        let mut async_fd = self.ring_buf;

        loop {
            let mut guard = match async_fd.readable_mut().await {
                Ok(guard) => guard,
                Err(e) => {
                    error!("DNS RingBuf readable error: {e}");
                    break;
                }
            };

            let rb = guard.get_inner_mut();
            while let Some(item) = rb.next() {
                let bytes: &[u8] = &item;
                let header_size = std::mem::size_of::<DnsEvent>();
                if bytes.len() >= header_size {
                    // SAFETY: DnsEvent is #[repr(C)] with known layout (48 bytes).
                    // The kernel writes this exact layout. We verify the length above.
                    let header =
                        unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<DnsEvent>()) };

                    let payload_len = header.dns_payload_len as usize;
                    let payload_end = header_size + payload_len;
                    let payload = if payload_end <= bytes.len() {
                        bytes[header_size..payload_end].to_vec()
                    } else {
                        // Partial payload — take what we have
                        bytes[header_size..].to_vec()
                    };

                    let event = AgentEvent::Dns { header, payload };
                    if tx.try_send(event).is_err() {
                        debug!("DNS event channel full, dropping event");
                    }
                }
            }

            guard.clear_ready();
        }
    }
}
