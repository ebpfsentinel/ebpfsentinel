#![allow(unsafe_code)] // mmap pointer reads required for zero-copy arena events.

//! Zero-copy event reader from a `BPF_MAP_TYPE_ARENA` mmap'd region.
//!
//! Polls the `ArenaEventHeader.sequence` field at the base of the
//! arena. When a new sequence number is observed (monotonically
//! increasing), the header + payload are read directly from the
//! mmap'd pointer — no copy, no syscall. Events are forwarded into
//! a bounded mpsc channel consumed by the application layer.
//!
//! This is the userspace consumer counterpart to a BPF program that
//! writes `ArenaEventHeader` + payload bytes into the arena.

use std::time::Duration;

use ebpf_common::arena::{ARENA_EVENT_HEADER_SIZE, ArenaEventHeader};
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace};

use super::arena::ArenaMap;

/// Reads events from an arena mmap'd region by polling the sequence
/// counter. Zero-copy: the event data is read directly from the
/// shared mmap pointer.
pub struct ArenaEventReader {
    arena: ArenaMap,
    last_sequence: u64,
}

impl ArenaEventReader {
    /// Create a reader over the given arena.
    pub fn new(arena: ArenaMap) -> Self {
        Self {
            arena,
            last_sequence: 0,
        }
    }

    /// Poll the arena for new events. Returns `Some(header, payload_slice)`
    /// when a new event is available (`sequence > last_sequence`).
    /// Returns `None` when no new event is ready.
    ///
    /// The returned payload slice points directly into the mmap'd
    /// region — zero-copy. The caller must process it before the
    /// next poll (the BPF program may overwrite the region).
    pub fn try_read(&mut self) -> Option<(ArenaEventHeader, &[u8])> {
        let header: ArenaEventHeader = unsafe { self.arena.read_at(0) };
        if header.sequence <= self.last_sequence {
            return None;
        }
        self.last_sequence = header.sequence;

        let payload_len = header.payload_len as usize;
        if payload_len == 0 || ARENA_EVENT_HEADER_SIZE + payload_len > self.arena.size() {
            return Some((header, &[]));
        }

        // SAFETY: payload starts after the header; bounds checked above.
        let payload = unsafe {
            let ptr = self.arena.as_ptr().add(ARENA_EVENT_HEADER_SIZE);
            core::slice::from_raw_parts(ptr, payload_len)
        };
        Some((header, payload))
    }

    /// Long-running async poll loop. Checks for new events every
    /// `poll_interval` and sends them to `tx`. Stops on cancellation.
    pub async fn run(
        mut self,
        tx: tokio::sync::mpsc::Sender<(ArenaEventHeader, Vec<u8>)>,
        poll_interval: Duration,
        cancel: CancellationToken,
    ) {
        let mut ticker = tokio::time::interval(poll_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        debug!("arena event reader started");

        loop {
            tokio::select! {
                () = cancel.cancelled() => {
                    debug!("arena event reader cancelled");
                    break;
                }
                _ = ticker.tick() => {
                    if let Some((header, payload)) = self.try_read() {
                        trace!(
                            seq = header.sequence,
                            event_type = header.event_type,
                            payload_len = header.payload_len,
                            "arena event received"
                        );
                        // Copy payload for send (the mmap region may be
                        // overwritten by the BPF program on next write).
                        let payload_owned = payload.to_vec();
                        if tx.try_send((header, payload_owned)).is_err() {
                            debug!("arena event channel full, dropping");
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_read_returns_none_when_no_new_event() {
        let arena = match ArenaMap::create(1, "reader_test") {
            Ok(a) => a,
            Err(_) => {
                eprintln!("skip: no CAP_BPF");
                return;
            }
        };
        let mut reader = ArenaEventReader::new(arena);
        assert!(reader.try_read().is_none());
    }

    #[test]
    fn try_read_returns_event_after_write() {
        let arena = match ArenaMap::create(1, "reader_test2") {
            Ok(a) => a,
            Err(_) => {
                eprintln!("skip: no CAP_BPF");
                return;
            }
        };

        // Simulate BPF write: header + payload.
        let header = ArenaEventHeader {
            sequence: 1,
            timestamp_ns: 42,
            payload_len: 8,
            event_type: 3,
            _pad: [0; 3],
        };
        unsafe { arena.write_at(0, header) };
        // Write 8 bytes of payload after the header.
        unsafe { arena.write_at(ARENA_EVENT_HEADER_SIZE, 0xDEAD_BEEF_CAFE_BABEu64) };

        let mut reader = ArenaEventReader::new(arena);
        let (hdr, payload) = reader.try_read().expect("should have event");
        assert_eq!(hdr.sequence, 1);
        assert_eq!(hdr.event_type, 3);
        assert_eq!(payload.len(), 8);

        // Second read with same sequence → None.
        assert!(reader.try_read().is_none());
    }
}
