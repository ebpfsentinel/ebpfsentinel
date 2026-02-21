#![allow(unsafe_code)] // Required for eBPF RingBuf event parsing (read_unaligned)

use application::packet_pipeline::AgentEvent;
use aya::Ebpf;
use aya::maps::{MapData, RingBuf};
use ebpf_common::dlp::DlpEvent;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tracing::{debug, error, info};

/// Reads DLP events from the eBPF `EVENTS` `RingBuf` of the uprobe-dlp program.
///
/// Uses `AsyncFd` for epoll-based async notification. DLP events are
/// 4120-byte `DlpEvent` structs containing SSL plaintext excerpts.
///
/// Note: this reader takes the `EVENTS` map from a *separate* `Ebpf` instance
/// (uprobe-dlp), so there is no conflict with the main `EventReader`.
pub struct DlpEventReader {
    ring_buf: AsyncFd<RingBuf<MapData>>,
}

impl DlpEventReader {
    /// Create a new `DlpEventReader` by taking ownership of the `EVENTS` map
    /// from the uprobe-dlp eBPF instance.
    pub fn new(ebpf: &mut Ebpf) -> Result<Self, anyhow::Error> {
        let map = ebpf
            .take_map("EVENTS")
            .ok_or_else(|| anyhow::anyhow!("map 'EVENTS' not found in uprobe-dlp eBPF object"))?;
        let ring_buf = RingBuf::try_from(map)?;
        let async_fd = AsyncFd::with_interest(ring_buf, tokio::io::Interest::READABLE)?;
        info!("DLP EVENTS RingBuf reader initialized");
        Ok(Self { ring_buf: async_fd })
    }

    /// Run the DLP event reader loop, sending parsed events to `tx`.
    pub async fn run(self, tx: mpsc::Sender<AgentEvent>) {
        let mut async_fd = self.ring_buf;

        loop {
            let mut guard = match async_fd.readable_mut().await {
                Ok(guard) => guard,
                Err(e) => {
                    error!("DLP RingBuf readable error: {e}");
                    break;
                }
            };

            let rb = guard.get_inner_mut();
            while let Some(item) = rb.next() {
                let bytes: &[u8] = &item;
                if bytes.len() >= std::mem::size_of::<DlpEvent>() {
                    // SAFETY: DlpEvent is #[repr(C)] with known layout (4120 bytes).
                    // The kernel writes this exact layout. We verify the length above.
                    let event =
                        unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<DlpEvent>()) };

                    if tx.try_send(AgentEvent::Dlp(Box::new(event))).is_err() {
                        debug!("DLP event channel full, dropping event");
                    }
                }
            }

            guard.clear_ready();
        }
    }
}
