#![allow(unsafe_code)] // Required for eBPF RingBuf event parsing (read_unaligned)

use crate::ebpf::map_store::MapStore;
use aya::maps::{MapData, RingBuf};
use domain::common::agent_event::AgentEvent;
use ebpf_common::dlp::{DLP_MAX_EXCERPT, DlpEvent};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
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
    pub fn new(ebpf: &mut dyn MapStore) -> Result<Self, anyhow::Error> {
        let map = ebpf
            .take_map("EVENTS")
            .ok_or_else(|| anyhow::anyhow!("map 'EVENTS' not found in uprobe-dlp eBPF object"))?;
        let ring_buf = RingBuf::try_from(map)?;
        let async_fd = AsyncFd::with_interest(ring_buf, tokio::io::Interest::READABLE)?;
        info!("DLP EVENTS RingBuf reader initialized");
        Ok(Self { ring_buf: async_fd })
    }

    /// Create a `DlpEventReader` from a ring-buffer map fd received from the
    /// warden (rootless deployment). The warden serves the uprobe-dlp ring buffer
    /// under a distinct key (its raw map name `EVENTS` collides with the packet
    /// ring buffer), rather than from an in-process loader's map.
    pub fn from_ringbuf_fd(fd: std::os::fd::OwnedFd) -> Result<Self, anyhow::Error> {
        let ring_buf = crate::ebpf::event_reader::ringbuf_from_fd(fd)?;
        info!("DLP EVENTS RingBuf reader initialized from warden fd");
        Ok(Self { ring_buf })
    }

    /// Run the DLP event reader loop, sending parsed events to `tx`.
    ///
    /// Exits when the `cancel` token is triggered, the `RingBuf` errors, or
    /// the runtime shuts down.
    pub async fn run(self, tx: mpsc::Sender<AgentEvent>, cancel: CancellationToken) {
        let mut async_fd = self.ring_buf;

        loop {
            let mut guard = tokio::select! {
                () = cancel.cancelled() => {
                    info!("DLP event reader cancelled");
                    break;
                }
                result = async_fd.readable_mut() => {
                    match result {
                        Ok(guard) => guard,
                        Err(e) => {
                            error!("DLP RingBuf readable error: {e}");
                            break;
                        }
                    }
                }
            };

            let rb = guard.get_inner_mut();
            // pid(4) + tgid(4) + timestamp_ns(8) + cgroup_id(8) + data_len(4) + direction(1) + padding(3)
            let header_size = 32_usize;
            while let Some(item) = rb.next() {
                let bytes: &[u8] = &item;
                // Accept both small (288 bytes) and full (4128 bytes) DLP events.
                // Both share the same header layout; only the excerpt buffer size differs.
                // We reconstruct a full DlpEvent with zero-padded excerpt for uniform handling.
                if bytes.len() >= header_size {
                    let mut event = DlpEvent {
                        pid: 0,
                        tgid: 0,
                        timestamp_ns: 0,
                        cgroup_id: 0,
                        data_len: 0,
                        direction: 0,
                        _padding: [0; 3],
                        data_excerpt: [0; DLP_MAX_EXCERPT],
                    };
                    // SAFETY: header fields are at known offsets, verified by length check.
                    // Both DlpEvent and DlpEventSmall share identical header layout (32 bytes).
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            bytes.as_ptr(),
                            core::ptr::addr_of_mut!(event).cast::<u8>(),
                            header_size.min(bytes.len()),
                        );
                    }
                    // Copy available excerpt data (may be 256 or 4096 bytes)
                    let excerpt_bytes = &bytes[header_size..];
                    let copy_len = excerpt_bytes.len().min(DLP_MAX_EXCERPT);
                    event.data_excerpt[..copy_len].copy_from_slice(&excerpt_bytes[..copy_len]);

                    if tx.try_send(AgentEvent::Dlp(Box::new(event))).is_err() {
                        debug!("DLP event channel full, dropping event");
                    }
                }
            }

            guard.clear_ready();
        }
    }
}
