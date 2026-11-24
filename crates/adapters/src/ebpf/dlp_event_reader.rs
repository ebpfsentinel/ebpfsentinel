#![allow(unsafe_code)] // Required for eBPF RingBuf event parsing (read_unaligned)

use crate::ebpf::event_reader::{drain_tick, watch_ringbuf};
use crate::ebpf::map_store::MapStore;
use crate::ebpf::ringbuf_observer::{DrainTrigger, RingBufObserver};
use aya::maps::{MapData, RingBuf};
use domain::common::agent_event::AgentEvent;
use ebpf_common::dlp::{DLP_EVENT_HEADER_SIZE, DLP_MAX_EXCERPT, DlpEvent, DlpSocket};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info};

/// Reads DLP events from the eBPF `EVENTS` `RingBuf` of the uprobe-dlp program.
///
/// Uses `AsyncFd` for epoll-based async notification. DLP events are
/// `DlpEvent` structs carrying the process, the socket the probe could
/// account for and an SSL plaintext excerpt.
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
        let async_fd = watch_ringbuf(ring_buf)?;
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
    /// `observer` accounts for what this loop drains and for what it throws
    /// away on a full channel.
    pub async fn run(
        self,
        tx: mpsc::Sender<AgentEvent>,
        cancel: CancellationToken,
        observer: RingBufObserver,
    ) {
        let mut async_fd = self.ring_buf;
        let mut tick = drain_tick();

        loop {
            tokio::select! {
                () = cancel.cancelled() => {
                    info!("DLP event reader cancelled");
                    break;
                }
                result = async_fd.readable_mut() => {
                    match result {
                        Ok(mut guard) => {
                            let drained = drain(guard.get_inner_mut(), &tx, &observer);
                            guard.clear_ready();
                            observer.drain_pass(DrainTrigger::Wakeup, drained);
                        }
                        Err(e) => {
                            error!("DLP RingBuf readable error: {e}");
                            break;
                        }
                    }
                }
                _ = tick.tick() => {
                    // Records the producer committed without waking us,
                    // because the backlog never reached the threshold.
                    let drained = drain(async_fd.get_mut(), &tx, &observer);
                    observer.drain_pass(DrainTrigger::Tick, drained);
                }
            }
        }
    }
}

/// Drain every record currently in `rb`, returning how many were read.
///
/// One clock read per batch, not per record.
fn drain(
    rb: &mut RingBuf<MapData>,
    tx: &mpsc::Sender<AgentEvent>,
    observer: &RingBufObserver,
) -> usize {
    let now_ns = observer.now_ns();
    let mut drained = 0usize;
    while let Some(item) = rb.next() {
        drained += 1;
        let Some(mut event) = decode(&item) else {
            observer.dropped("truncated_record");
            continue;
        };
        observer.accept(now_ns, &mut event);
        if tx.try_send(event).is_err() {
            observer.dropped("channel_full");
            debug!("DLP event channel full, dropping event");
        }
    }

    drained
}

/// One ring buffer record as the event it carries, `None` when it is shorter
/// than the header.
///
/// A payload past the excerpt a `DlpEvent` holds is a whole record the probe
/// read straight into the ring buffer, and travels as it was read; anything
/// shorter is the bounded copy.
fn decode(bytes: &[u8]) -> Option<AgentEvent> {
    // The header is read off the type rather than written out: it grew when
    // the event gained its socket block, and a reader carrying its own copy
    // of the number is a reader that silently slices the excerpt wrong.
    let header_size = DLP_EVENT_HEADER_SIZE;
    if bytes.len() < header_size {
        return None;
    }
    let mut event = DlpEvent {
        pid: 0,
        tgid: 0,
        timestamp_ns: 0,
        cgroup_id: 0,
        data_len: 0,
        direction: 0,
        _padding: [0; 3],
        flow: DlpSocket::default(),
        data_excerpt: [0; DLP_MAX_EXCERPT],
    };
    // SAFETY: `bytes` holds at least `header_size` bytes, checked above, and
    // the header is a prefix of the `#[repr(C)]` `DlpEvent` the destination
    // is, made of plain integers for which every bit pattern is valid.
    unsafe {
        core::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            core::ptr::addr_of_mut!(event).cast::<u8>(),
            header_size,
        );
    }
    let payload = &bytes[header_size..];
    if payload.len() > DLP_MAX_EXCERPT {
        return Some(AgentEvent::DlpRecord {
            header: Box::new(event),
            record: payload.to_vec(),
        });
    }
    event.data_excerpt[..payload.len()].copy_from_slice(payload);
    Some(AgentEvent::Dlp(Box::new(event)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(data_len: u32, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0u8; DLP_EVENT_HEADER_SIZE];
        bytes[..4].copy_from_slice(&7u32.to_ne_bytes());
        // `data_len` follows pid, tgid, timestamp_ns and cgroup_id.
        bytes[24..28].copy_from_slice(&data_len.to_ne_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    #[test]
    fn a_record_shorter_than_the_header_is_dropped() {
        assert!(decode(&[0u8; DLP_EVENT_HEADER_SIZE - 1]).is_none());
    }

    #[test]
    fn the_bounded_copy_is_an_excerpt() {
        let Some(AgentEvent::Dlp(event)) = decode(&record(5, b"hello")) else {
            panic!("an excerpt");
        };
        assert_eq!(event.pid, 7);
        assert_eq!(event.data_len, 5);
        assert_eq!(&event.data_excerpt[..5], b"hello");
    }

    #[test]
    fn a_full_excerpt_is_still_the_bounded_copy() {
        let payload = vec![b'a'; DLP_MAX_EXCERPT];
        assert!(matches!(
            decode(&record(20_000, &payload)),
            Some(AgentEvent::Dlp(_))
        ));
    }

    #[test]
    fn a_payload_past_the_excerpt_travels_whole() {
        let payload = vec![b'r'; 16_384];
        let Some(AgentEvent::DlpRecord { header, record }) = decode(&record(16_384, &payload))
        else {
            panic!("a whole record");
        };
        assert_eq!(header.pid, 7);
        assert_eq!(header.data_len, 16_384);
        assert_eq!(record.len(), 16_384);
        assert!(header.data_excerpt.iter().all(|b| *b == 0));
    }
}
