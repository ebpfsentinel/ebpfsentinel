#![allow(unsafe_code)] // Required for eBPF RingBuf record parsing (read_unaligned)

use crate::ebpf::event_reader::drain_tick;
use crate::ebpf::map_store::MapStore;
use crate::ebpf::ringbuf_observer::{DrainTrigger, RingBufObserver};
use aya::maps::{MapData, RingBuf};
use domain::process::entity::{ProcessEventKind, ProcessLifecycleEvent};
use ebpf_common::process::{PROCESS_EVENT_EXEC, PROCESS_EVENT_EXIT, ProcessEvent};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info};

/// The source name this reader's records are counted under.
pub const RINGBUF_SOURCE: &str = "process";

/// Reads exec and exit records from the `PROCESS_EVENTS` ring buffer of the
/// tracepoint-process object.
///
/// Every record is fixed size and self-describing: the kernel half writes one
/// `ProcessEvent` and nothing else, so there is no header arithmetic here and
/// a record of the wrong length is counted as a loss rather than parsed on a
/// guess.
pub struct ProcessEventReader {
    ring_buf: AsyncFd<RingBuf<MapData>>,
}

impl ProcessEventReader {
    /// Take the `PROCESS_EVENTS` map from the loaded tracepoint object.
    pub fn new(ebpf: &mut dyn MapStore) -> Result<Self, anyhow::Error> {
        let map = ebpf.take_map("PROCESS_EVENTS").ok_or_else(|| {
            anyhow::anyhow!("map 'PROCESS_EVENTS' not found in tracepoint-process eBPF object")
        })?;
        let ring_buf = RingBuf::try_from(map)?;
        let async_fd = AsyncFd::with_interest(ring_buf, tokio::io::Interest::READABLE)?;
        info!("PROCESS_EVENTS RingBuf reader initialized");
        Ok(Self { ring_buf: async_fd })
    }

    /// Drain the ring buffer into `tx` until `cancel` fires or the buffer
    /// errors.
    pub async fn run(
        self,
        tx: mpsc::Sender<ProcessLifecycleEvent>,
        cancel: CancellationToken,
        observer: RingBufObserver,
    ) {
        let mut async_fd = self.ring_buf;
        let mut tick = drain_tick();

        loop {
            tokio::select! {
                () = cancel.cancelled() => {
                    info!("process event reader cancelled");
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
                            error!("process RingBuf readable error: {e}");
                            break;
                        }
                    }
                }
                _ = tick.tick() => {
                    let drained = drain(async_fd.get_mut(), &tx, &observer);
                    observer.drain_pass(DrainTrigger::Tick, drained);
                }
            }
        }
    }
}

/// Drain every record currently in `rb`, returning how many were read.
fn drain(
    rb: &mut RingBuf<MapData>,
    tx: &mpsc::Sender<ProcessLifecycleEvent>,
    observer: &RingBufObserver,
) -> usize {
    let now_ns = observer.now_ns();
    let mut drained = 0usize;
    while let Some(item) = rb.next() {
        drained += 1;
        let bytes: &[u8] = &item;
        if bytes.len() < size_of::<ProcessEvent>() {
            // Counted rather than skipped: an unreadable record is a process
            // the table will never know about, and silence would hide it.
            observer.dropped("truncated_record");
            continue;
        }
        // SAFETY: the length is checked above and the kernel half writes one
        // `ProcessEvent`; the pointer may be unaligned inside the ring buffer.
        let raw = unsafe { bytes.as_ptr().cast::<ProcessEvent>().read_unaligned() };
        let Some(event) = parse(&raw) else {
            observer.dropped("unknown_kind");
            continue;
        };
        observer.drained(now_ns, raw.at_ns);
        if tx.try_send(event).is_err() {
            observer.dropped("channel_full");
            debug!("process event channel full, dropping event");
        }
    }
    drained
}

/// Turn a kernel record into the domain event, or nothing when the record
/// carries a kind this build does not know.
#[must_use]
fn parse(raw: &ProcessEvent) -> Option<ProcessLifecycleEvent> {
    let kind = match raw.kind {
        PROCESS_EVENT_EXEC => ProcessEventKind::Exec,
        PROCESS_EVENT_EXIT => ProcessEventKind::Exit,
        _ => return None,
    };
    Some(ProcessLifecycleEvent {
        kind,
        pid: raw.pid,
        tgid: raw.tgid,
        uid: raw.uid,
        gid: raw.gid,
        cgroup_id: raw.cgroup_id,
        comm: comm_to_string(&raw.comm),
        at_ns: raw.at_ns,
    })
}

/// The kernel's `comm`, cut at its first NUL.
///
/// The kernel pads the field with NULs and truncates at sixteen bytes, so the
/// string is a hint rather than a name: `systemd-journald` arrives whole and
/// `some-very-long-daemon` does not.
#[must_use]
fn comm_to_string(comm: &[u8]) -> String {
    let end = comm.iter().position(|b| *b == 0).unwrap_or(comm.len());
    String::from_utf8_lossy(&comm[..end]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ebpf_common::process::PROCESS_COMM_LEN;

    fn raw(kind: u8) -> ProcessEvent {
        let mut comm = [0u8; PROCESS_COMM_LEN];
        comm[..4].copy_from_slice(b"curl");
        ProcessEvent {
            at_ns: 1_000,
            cgroup_id: 777,
            pid: 42,
            tgid: 42,
            uid: 1000,
            gid: 1000,
            comm,
            kind,
            _pad: [0u8; 7],
        }
    }

    #[test]
    fn an_exec_record_becomes_an_exec_event() {
        let event = parse(&raw(PROCESS_EVENT_EXEC)).unwrap();
        assert_eq!(event.kind, ProcessEventKind::Exec);
        assert_eq!(event.tgid, 42);
        assert_eq!(event.comm, "curl");
        assert_eq!(event.cgroup_id, 777);
    }

    #[test]
    fn an_exit_record_becomes_an_exit_event() {
        let event = parse(&raw(PROCESS_EVENT_EXIT)).unwrap();
        assert_eq!(event.kind, ProcessEventKind::Exit);
    }

    #[test]
    fn a_record_of_an_unknown_kind_is_refused_rather_than_guessed() {
        assert!(parse(&raw(99)).is_none());
    }

    #[test]
    fn a_full_comm_keeps_all_sixteen_bytes() {
        let comm = *b"systemd-journal\0";
        assert_eq!(comm_to_string(&comm), "systemd-journal");
        let full = *b"sixteen-char-com";
        assert_eq!(comm_to_string(&full), "sixteen-char-com");
    }

    #[test]
    fn a_comm_with_invalid_utf8_still_yields_a_string() {
        let mut comm = [0u8; PROCESS_COMM_LEN];
        comm[0] = 0xff;
        comm[1] = b'a';
        assert!(comm_to_string(&comm).ends_with('a'));
    }
}
