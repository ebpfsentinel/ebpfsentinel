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

use std::os::fd::AsFd;
use std::time::Duration;

use application::packet_pipeline::AgentEvent;
use aya::Ebpf;
use aya::maps::Map;
use ebpf_common::arena::{
    ARENA_EVENT_HEADER_SIZE, ArenaEventHeader, DLP_ARENA_FIXED_VA, DLP_ARENA_PAGES, DLP_SLOT_COUNT,
    DLP_WRITE_SEQ_OFFSET, DNS_ARENA_FIXED_VA, DNS_ARENA_PAGES, DNS_SLOT_COUNT,
    DNS_WRITE_SEQ_OFFSET, IDS_ARENA_FIXED_VA, IDS_ARENA_PAGES, IDS_SLOT_COUNT,
    IDS_WRITE_SEQ_OFFSET, dlp_slot_offset, dns_slot_offset, ids_slot_offset,
};
use ebpf_common::dlp::{DLP_MAX_EXCERPT, DLP_SMALL_EXCERPT, DlpEvent, DlpEventSmall};
use ebpf_common::dns::{DNS_MAX_PAYLOAD, DnsEvent};
use ebpf_common::event::{MAX_L7_PAYLOAD, PacketEvent};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace, warn};

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

/// Reader for the DLP arena ring layout written by the
/// `uprobe-dlp` BPF program. The arena is laid out as a 64 B header
/// (with `write_seq` at offset 0) followed by `DLP_SLOT_COUNT` fixed
/// slots; each slot holds an `ArenaEventHeader` plus a
/// `DlpEventSmall`. The reader polls `write_seq`, drains every
/// unseen sequence and forwards them as `AgentEvent::Dlp` (with the
/// truncated excerpt promoted into the standard `DlpEvent` shape).
pub struct DlpArenaReader {
    arena: ArenaMap,
    last_sequence: u64,
}

impl DlpArenaReader {
    /// Wrap a DLP arena. Initial `write_seq` of the arena is captured
    /// so we don't replay events that arrived before the reader was
    /// installed (typical for an agent restart with a still-alive
    /// kernel-side BPF program).
    #[must_use]
    pub fn new(arena: ArenaMap) -> Self {
        // SAFETY: write_seq lives at offset 0 of the mmap'd arena.
        let initial = unsafe { arena.read_at::<u64>(DLP_WRITE_SEQ_OFFSET) };
        Self {
            arena,
            last_sequence: initial,
        }
    }

    /// Drain newly-published slots into a vector of `DlpEvent`. Returns
    /// an empty vector when no new event is ready.
    pub fn drain(&mut self) -> Vec<DlpEvent> {
        // SAFETY: write_seq is a u64 at offset 0 of the arena.
        let write_seq = unsafe { self.arena.read_at::<u64>(DLP_WRITE_SEQ_OFFSET) };
        if write_seq <= self.last_sequence {
            return Vec::new();
        }

        // Cap the drain to one ring lap to keep the BPF writer from
        // moving us into stale slots while we iterate.
        let lag = write_seq.saturating_sub(self.last_sequence);
        let drained = lag.min(DLP_SLOT_COUNT as u64);
        let start_seq = write_seq - drained + 1;

        #[allow(clippy::cast_possible_truncation)]
        let mut out = Vec::with_capacity(drained as usize);
        for seq in start_seq..=write_seq {
            #[allow(clippy::cast_possible_truncation)]
            let slot_idx = ((seq - 1) as usize) % DLP_SLOT_COUNT;
            let slot_offset = dlp_slot_offset(slot_idx);

            // SAFETY: slot_offset + slot_size <= arena.size() by
            // construction (DLP_SLOT_COUNT is sized to fit).
            let header: ArenaEventHeader = unsafe { self.arena.read_at(slot_offset) };
            if header.sequence != seq {
                // Slot was overwritten by the BPF writer between our
                // write_seq snapshot and the slot read — skip it.
                continue;
            }
            // SAFETY: same bounds as above; body sits right after header.
            let small: DlpEventSmall =
                unsafe { self.arena.read_at(slot_offset + ARENA_EVENT_HEADER_SIZE) };
            out.push(promote_small_to_full(&small));
        }

        self.last_sequence = write_seq;
        out
    }

    /// Long-running poll loop. Forwards each drained event as
    /// `AgentEvent::Dlp` so it joins the same downstream pipeline as
    /// the `RingBuf`-based `DlpEventReader`.
    pub async fn run(
        mut self,
        tx: mpsc::Sender<AgentEvent>,
        poll_interval: Duration,
        cancel: CancellationToken,
    ) {
        let mut ticker = tokio::time::interval(poll_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        debug!(
            poll_ms = poll_interval.as_millis(),
            "DLP arena reader started"
        );

        loop {
            tokio::select! {
                () = cancel.cancelled() => {
                    debug!("DLP arena reader cancelled");
                    break;
                }
                _ = ticker.tick() => {
                    for event in self.drain() {
                        trace!(
                            pid = event.pid,
                            data_len = event.data_len,
                            "DLP arena event drained"
                        );
                        if tx.try_send(AgentEvent::Dlp(Box::new(event))).is_err() {
                            debug!("DLP arena event channel full, dropping");
                        }
                    }
                }
            }
        }
    }
}

/// Adopt the BPF-loaded `DLP_ARENA` map fd from the supplied
/// `aya::Ebpf` instance, mmap it at `DLP_ARENA_FIXED_VA`, and wrap
/// the result in a `DlpArenaReader`. Returns `None` when the map is
/// missing, the kernel rejects the fixed VA, or the map appears
/// under an unexpected `aya` variant — the caller then keeps `RingBuf`
/// as the sole DLP delivery channel.
#[must_use]
pub fn mmap_dlp_arena(ebpf: &mut Ebpf) -> Option<DlpArenaReader> {
    let map = ebpf.map("DLP_ARENA")?;
    let map_data = match map {
        Map::Unsupported(md) => md,
        other => {
            warn!(
                kind = ?core::mem::discriminant(other),
                "DLP_ARENA loaded as a typed aya map; expected Unsupported(MapData)"
            );
            return None;
        }
    };

    let fd = map_data.fd().as_fd();
    match ArenaMap::from_aya_fd(fd, DLP_ARENA_PAGES, DLP_ARENA_FIXED_VA) {
        Ok(arena) => {
            info!(
                fixed_va = format_args!("{DLP_ARENA_FIXED_VA:#x}"),
                pages = DLP_ARENA_PAGES,
                "DLP_ARENA mmap'd; BPF arena zero-copy delivery active"
            );
            Some(DlpArenaReader::new(arena))
        }
        Err(e) => {
            warn!(
                error = %e,
                "DLP_ARENA mmap failed; falling back to RingBuf-only delivery"
            );
            None
        }
    }
}

/// Raw body stored in each IDS arena slot — a `PacketEvent` header
/// followed by the full L7 payload. Mirrors `L7EventBuf` in the
/// `tc-ids` BPF program.
#[repr(C)]
#[derive(Copy, Clone)]
struct IdsArenaBody {
    header: PacketEvent,
    payload: [u8; MAX_L7_PAYLOAD],
}

/// Reader for the IDS arena ring layout written by the `tc-ids`
/// BPF program. Layout mirrors DLP: 64 B ring header (with
/// `write_seq` at offset 0) then `IDS_SLOT_COUNT` fixed slots of
/// `ArenaEventHeader` + `L7EventBuf`. Drained events are forwarded
/// as `AgentEvent::L7`.
pub struct IdsArenaReader {
    arena: ArenaMap,
    last_sequence: u64,
}

impl IdsArenaReader {
    /// Wrap an IDS arena. Captures the current `write_seq` so replays
    /// after an agent restart are avoided.
    #[must_use]
    pub fn new(arena: ArenaMap) -> Self {
        // SAFETY: write_seq lives at offset 0 of the mmap'd arena.
        let initial = unsafe { arena.read_at::<u64>(IDS_WRITE_SEQ_OFFSET) };
        Self {
            arena,
            last_sequence: initial,
        }
    }

    /// Drain newly-published slots into a vector of `AgentEvent::L7`.
    pub fn drain(&mut self) -> Vec<AgentEvent> {
        // SAFETY: write_seq is a u64 at offset 0 of the arena.
        let write_seq = unsafe { self.arena.read_at::<u64>(IDS_WRITE_SEQ_OFFSET) };
        if write_seq <= self.last_sequence {
            return Vec::new();
        }

        let lag = write_seq.saturating_sub(self.last_sequence);
        let drained = lag.min(IDS_SLOT_COUNT as u64);
        let start_seq = write_seq - drained + 1;

        #[allow(clippy::cast_possible_truncation)]
        let mut out = Vec::with_capacity(drained as usize);
        for seq in start_seq..=write_seq {
            #[allow(clippy::cast_possible_truncation)]
            let slot_idx = ((seq - 1) as usize) % IDS_SLOT_COUNT;
            let slot_offset = ids_slot_offset(slot_idx);

            // SAFETY: slot bounds guaranteed by IDS_SLOT_COUNT sizing.
            let header: ArenaEventHeader = unsafe { self.arena.read_at(slot_offset) };
            if header.sequence != seq {
                continue;
            }
            // SAFETY: body sits right after the slot header.
            let body: IdsArenaBody =
                unsafe { self.arena.read_at(slot_offset + ARENA_EVENT_HEADER_SIZE) };
            out.push(AgentEvent::L7 {
                header: body.header,
                payload: body.payload.to_vec(),
            });
        }

        self.last_sequence = write_seq;
        out
    }

    /// Long-running poll loop mirroring `DlpArenaReader::run`.
    pub async fn run(
        mut self,
        tx: mpsc::Sender<AgentEvent>,
        poll_interval: Duration,
        cancel: CancellationToken,
    ) {
        let mut ticker = tokio::time::interval(poll_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        debug!(
            poll_ms = poll_interval.as_millis(),
            "IDS arena reader started"
        );

        loop {
            tokio::select! {
                () = cancel.cancelled() => {
                    debug!("IDS arena reader cancelled");
                    break;
                }
                _ = ticker.tick() => {
                    for event in self.drain() {
                        trace!("IDS arena event drained");
                        if tx.try_send(event).is_err() {
                            debug!("IDS arena event channel full, dropping");
                        }
                    }
                }
            }
        }
    }
}

/// Adopt the BPF-loaded `IDS_ARENA` map fd from the supplied
/// `aya::Ebpf` instance, mmap it at `IDS_ARENA_FIXED_VA`, and wrap
/// the result in an `IdsArenaReader`. Returns `None` when the map
/// is missing or the kernel rejects the fixed VA.
#[must_use]
pub fn mmap_ids_arena(ebpf: &mut Ebpf) -> Option<IdsArenaReader> {
    let map = ebpf.map("IDS_ARENA")?;
    let map_data = match map {
        Map::Unsupported(md) => md,
        other => {
            warn!(
                kind = ?core::mem::discriminant(other),
                "IDS_ARENA loaded as a typed aya map; expected Unsupported(MapData)"
            );
            return None;
        }
    };

    let fd = map_data.fd().as_fd();
    match ArenaMap::from_aya_fd(fd, IDS_ARENA_PAGES, IDS_ARENA_FIXED_VA) {
        Ok(arena) => {
            info!(
                fixed_va = format_args!("{IDS_ARENA_FIXED_VA:#x}"),
                pages = IDS_ARENA_PAGES,
                "IDS_ARENA mmap'd; BPF arena zero-copy delivery active"
            );
            Some(IdsArenaReader::new(arena))
        }
        Err(e) => {
            warn!(
                error = %e,
                "IDS_ARENA mmap failed; falling back to RingBuf-only delivery"
            );
            None
        }
    }
}

/// Raw body stored in each DNS arena slot — mirrors `DnsEventBuf` in
/// the `tc-dns` BPF program.
#[repr(C)]
#[derive(Copy, Clone)]
struct DnsArenaBody {
    header: DnsEvent,
    payload: [u8; DNS_MAX_PAYLOAD],
}

/// Reader for the DNS arena ring layout written by the `tc-dns`
/// BPF program. Drained events are forwarded as `AgentEvent::Dns`.
pub struct DnsArenaReader {
    arena: ArenaMap,
    last_sequence: u64,
}

impl DnsArenaReader {
    #[must_use]
    pub fn new(arena: ArenaMap) -> Self {
        // SAFETY: write_seq at offset 0 of the mmap'd arena.
        let initial = unsafe { arena.read_at::<u64>(DNS_WRITE_SEQ_OFFSET) };
        Self {
            arena,
            last_sequence: initial,
        }
    }

    pub fn drain(&mut self) -> Vec<AgentEvent> {
        // SAFETY: write_seq at offset 0 of the arena.
        let write_seq = unsafe { self.arena.read_at::<u64>(DNS_WRITE_SEQ_OFFSET) };
        if write_seq <= self.last_sequence {
            return Vec::new();
        }

        let lag = write_seq.saturating_sub(self.last_sequence);
        let drained = lag.min(DNS_SLOT_COUNT as u64);
        let start_seq = write_seq - drained + 1;

        #[allow(clippy::cast_possible_truncation)]
        let mut out = Vec::with_capacity(drained as usize);
        for seq in start_seq..=write_seq {
            #[allow(clippy::cast_possible_truncation)]
            let slot_idx = ((seq - 1) as usize) % DNS_SLOT_COUNT;
            let slot_offset = dns_slot_offset(slot_idx);

            // SAFETY: slot bounds guaranteed by DNS_SLOT_COUNT sizing.
            let header: ArenaEventHeader = unsafe { self.arena.read_at(slot_offset) };
            if header.sequence != seq {
                continue;
            }
            // SAFETY: body sits right after the slot header.
            let body: DnsArenaBody =
                unsafe { self.arena.read_at(slot_offset + ARENA_EVENT_HEADER_SIZE) };
            let payload_len = (body.header.dns_payload_len as usize).min(DNS_MAX_PAYLOAD);
            out.push(AgentEvent::Dns {
                header: body.header,
                payload: body.payload[..payload_len].to_vec(),
            });
        }

        self.last_sequence = write_seq;
        out
    }

    pub async fn run(
        mut self,
        tx: mpsc::Sender<AgentEvent>,
        poll_interval: Duration,
        cancel: CancellationToken,
    ) {
        let mut ticker = tokio::time::interval(poll_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        debug!(
            poll_ms = poll_interval.as_millis(),
            "DNS arena reader started"
        );

        loop {
            tokio::select! {
                () = cancel.cancelled() => {
                    debug!("DNS arena reader cancelled");
                    break;
                }
                _ = ticker.tick() => {
                    for event in self.drain() {
                        trace!("DNS arena event drained");
                        if tx.try_send(event).is_err() {
                            debug!("DNS arena event channel full, dropping");
                        }
                    }
                }
            }
        }
    }
}

/// Adopt the BPF-loaded `DNS_ARENA` map fd, mmap it at
/// `DNS_ARENA_FIXED_VA`, and wrap the result in a `DnsArenaReader`.
#[must_use]
pub fn mmap_dns_arena(ebpf: &mut Ebpf) -> Option<DnsArenaReader> {
    let map = ebpf.map("DNS_ARENA")?;
    let map_data = match map {
        Map::Unsupported(md) => md,
        other => {
            warn!(
                kind = ?core::mem::discriminant(other),
                "DNS_ARENA loaded as a typed aya map; expected Unsupported(MapData)"
            );
            return None;
        }
    };

    let fd = map_data.fd().as_fd();
    match ArenaMap::from_aya_fd(fd, DNS_ARENA_PAGES, DNS_ARENA_FIXED_VA) {
        Ok(arena) => {
            info!(
                fixed_va = format_args!("{DNS_ARENA_FIXED_VA:#x}"),
                pages = DNS_ARENA_PAGES,
                "DNS_ARENA mmap'd; BPF arena zero-copy delivery active"
            );
            Some(DnsArenaReader::new(arena))
        }
        Err(e) => {
            warn!(
                error = %e,
                "DNS_ARENA mmap failed; falling back to RingBuf-only delivery"
            );
            None
        }
    }
}

/// Promote a 288 B `DlpEventSmall` into the full 4128 B `DlpEvent`
/// shape used by the rest of the agent pipeline. The trailing
/// excerpt bytes are zero-padded.
fn promote_small_to_full(small: &DlpEventSmall) -> DlpEvent {
    let mut full = DlpEvent {
        pid: small.pid,
        tgid: small.tgid,
        timestamp_ns: small.timestamp_ns,
        cgroup_id: small.cgroup_id,
        data_len: small.data_len,
        direction: small.direction,
        _padding: small._padding,
        data_excerpt: [0; DLP_MAX_EXCERPT],
    };
    let copy_len = DLP_SMALL_EXCERPT.min(DLP_MAX_EXCERPT);
    full.data_excerpt[..copy_len].copy_from_slice(&small.data_excerpt[..copy_len]);
    full
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_read_returns_none_when_no_new_event() {
        let Ok(arena) = ArenaMap::create(1, "reader_test") else {
            eprintln!("skip: no CAP_BPF");
            return;
        };
        let mut reader = ArenaEventReader::new(arena);
        assert!(reader.try_read().is_none());
    }

    #[test]
    fn try_read_returns_event_after_write() {
        let Ok(arena) = ArenaMap::create(1, "reader_test2") else {
            eprintln!("skip: no CAP_BPF");
            return;
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

    fn fake_small(seq_marker: u8) -> DlpEventSmall {
        let mut excerpt = [0u8; DLP_SMALL_EXCERPT];
        excerpt[0] = seq_marker;
        DlpEventSmall {
            pid: u32::from(seq_marker),
            tgid: u32::from(seq_marker) + 1,
            timestamp_ns: 100,
            cgroup_id: 200,
            data_len: 4,
            direction: 1,
            _padding: [0; 3],
            data_excerpt: excerpt,
        }
    }

    fn write_dlp_slot(arena: &ArenaMap, seq: u64, marker: u8) {
        let slot_idx = ((seq - 1) as usize) % DLP_SLOT_COUNT;
        let off = dlp_slot_offset(slot_idx);
        let header = ArenaEventHeader {
            sequence: seq,
            timestamp_ns: 100,
            payload_len: core::mem::size_of::<DlpEventSmall>() as u32,
            event_type: 3,
            _pad: [0; 3],
        };
        unsafe { arena.write_at(off, header) };
        unsafe { arena.write_at(off + ARENA_EVENT_HEADER_SIZE, fake_small(marker)) };
    }

    #[test]
    fn dlp_arena_reader_drains_published_slot() {
        let Ok(arena) = ArenaMap::create(4, "dlp_drain") else {
            eprintln!("skip: no CAP_BPF");
            return;
        };

        write_dlp_slot(&arena, 1, 0xAB);
        unsafe { arena.write_at::<u64>(DLP_WRITE_SEQ_OFFSET, 1) };

        let mut reader = DlpArenaReader::new(arena);
        // The reader was constructed AFTER write_seq=1 was published —
        // it captures that as the baseline and refuses to replay.
        assert!(reader.drain().is_empty());
    }

    #[test]
    fn dlp_arena_reader_drains_new_events() {
        let Ok(arena) = ArenaMap::create(4, "dlp_new") else {
            eprintln!("skip: no CAP_BPF");
            return;
        };

        let mut reader = DlpArenaReader::new(arena);

        // Publish two events after the reader is in place.
        let arena_ref = &reader.arena;
        write_dlp_slot(arena_ref, 1, 0x11);
        write_dlp_slot(arena_ref, 2, 0x22);
        unsafe { arena_ref.write_at::<u64>(DLP_WRITE_SEQ_OFFSET, 2) };

        let drained = reader.drain();
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].pid, 0x11);
        assert_eq!(drained[0].data_excerpt[0], 0x11);
        assert_eq!(drained[1].pid, 0x22);
        assert_eq!(drained[1].data_excerpt[0], 0x22);

        // Second drain with no new events → empty.
        assert!(reader.drain().is_empty());
    }

    #[test]
    fn dlp_arena_reader_caps_lag_to_one_lap() {
        let Ok(arena) = ArenaMap::create(4, "dlp_lap") else {
            eprintln!("skip: no CAP_BPF");
            return;
        };

        let mut reader = DlpArenaReader::new(arena);
        // Simulate a writer that lapped the ring: only the most recent
        // DLP_SLOT_COUNT events are recoverable.
        let last_seq = (DLP_SLOT_COUNT as u64) * 3;
        for seq in (last_seq - DLP_SLOT_COUNT as u64 + 1)..=last_seq {
            #[allow(clippy::cast_possible_truncation)]
            write_dlp_slot(&reader.arena, seq, (seq & 0xFF) as u8);
        }
        unsafe { reader.arena.write_at::<u64>(DLP_WRITE_SEQ_OFFSET, last_seq) };

        let drained = reader.drain();
        assert_eq!(drained.len(), DLP_SLOT_COUNT);
    }

    #[test]
    fn dlp_arena_reader_skips_torn_slot() {
        let Ok(arena) = ArenaMap::create(4, "dlp_torn") else {
            eprintln!("skip: no CAP_BPF");
            return;
        };

        let mut reader = DlpArenaReader::new(arena);
        // Slot 1 carries a stale sequence (was overwritten by a wrap).
        write_dlp_slot(&reader.arena, 99, 0x99);
        // But we publish write_seq=1 — body says 99, header expects 1.
        unsafe { reader.arena.write_at::<u64>(DLP_WRITE_SEQ_OFFSET, 1) };

        let drained = reader.drain();
        assert!(drained.is_empty(), "torn slot must be skipped");
    }

    #[test]
    fn promote_small_to_full_zero_pads_excerpt() {
        let mut small = fake_small(0xFE);
        small.data_excerpt[10] = 0xCD;
        let full = promote_small_to_full(&small);
        assert_eq!(full.pid, 0xFE);
        assert_eq!(full.data_excerpt[0], 0xFE);
        assert_eq!(full.data_excerpt[10], 0xCD);
        // Tail is zero-padded.
        assert_eq!(full.data_excerpt[DLP_SMALL_EXCERPT], 0);
        assert_eq!(full.data_excerpt[DLP_MAX_EXCERPT - 1], 0);
    }

    fn fake_ids_body(marker: u8) -> IdsArenaBody {
        let header = PacketEvent {
            timestamp_ns: 0,
            src_addr: [0; 4],
            dst_addr: [0; 4],
            src_port: u16::from(marker),
            dst_port: u16::from(marker).wrapping_add(1),
            protocol: 6,
            event_type: 6,
            action: 0,
            flags: 0,
            rule_id: 0,
            vlan_id: 0,
            cpu_id: 0,
            socket_cookie: 0,
            cgroup_id: 0,
            cgroup1_id: 0,
            rss_hash: 0,
            rss_hash_type: 0,
            rx_hw_timestamp_ns: 0,
        };
        let mut payload = [0u8; MAX_L7_PAYLOAD];
        payload[0] = marker;
        payload[MAX_L7_PAYLOAD - 1] = marker.wrapping_add(0xAA);
        IdsArenaBody { header, payload }
    }

    fn write_ids_slot(arena: &ArenaMap, seq: u64, marker: u8) {
        #[allow(clippy::cast_possible_truncation)]
        let slot_idx = ((seq - 1) as usize) % IDS_SLOT_COUNT;
        let off = ids_slot_offset(slot_idx);
        unsafe { arena.write_at(off + ARENA_EVENT_HEADER_SIZE, fake_ids_body(marker)) };
        let header = ArenaEventHeader {
            sequence: seq,
            timestamp_ns: 100,
            payload_len: core::mem::size_of::<IdsArenaBody>() as u32,
            event_type: 6,
            _pad: [0; 3],
        };
        unsafe { arena.write_at(off, header) };
    }

    #[test]
    fn ids_arena_reader_drains_new_events() {
        let Ok(arena) = ArenaMap::create(IDS_ARENA_PAGES, "ids_new") else {
            eprintln!("skip: no CAP_BPF");
            return;
        };

        let mut reader = IdsArenaReader::new(arena);

        write_ids_slot(&reader.arena, 1, 0x11);
        write_ids_slot(&reader.arena, 2, 0x22);
        unsafe { reader.arena.write_at::<u64>(IDS_WRITE_SEQ_OFFSET, 2) };

        let drained = reader.drain();
        assert_eq!(drained.len(), 2);
        for (i, event) in drained.iter().enumerate() {
            let marker = if i == 0 { 0x11 } else { 0x22 };
            match event {
                AgentEvent::L7 { header, payload } => {
                    assert_eq!(header.src_port, u16::from(marker));
                    assert_eq!(payload[0], marker);
                    assert_eq!(payload.len(), MAX_L7_PAYLOAD);
                }
                _ => panic!("expected AgentEvent::L7"),
            }
        }

        assert!(reader.drain().is_empty());
    }

    #[test]
    fn ids_arena_reader_skips_torn_slot() {
        let Ok(arena) = ArenaMap::create(IDS_ARENA_PAGES, "ids_torn") else {
            eprintln!("skip: no CAP_BPF");
            return;
        };

        let mut reader = IdsArenaReader::new(arena);
        write_ids_slot(&reader.arena, 99, 0x99);
        unsafe { reader.arena.write_at::<u64>(IDS_WRITE_SEQ_OFFSET, 1) };

        assert!(reader.drain().is_empty(), "torn slot must be skipped");
    }

    fn fake_dns_body(marker: u8, dns_len: u16) -> DnsArenaBody {
        let mut header = DnsEvent {
            timestamp_ns: 0,
            src_addr: [0; 4],
            dst_addr: [0; 4],
            dns_payload_len: dns_len,
            dns_payload_offset: DnsEvent::HEADER_SIZE,
            direction: 0,
            flags: 0,
            vlan_id: 0,
            _padding: [0; 8],
            cgroup_id: 0,
        };
        header.src_addr[0] = u32::from(marker);
        let mut payload = [0u8; DNS_MAX_PAYLOAD];
        payload[0] = marker;
        payload[(dns_len as usize)
            .saturating_sub(1)
            .min(DNS_MAX_PAYLOAD - 1)] = marker ^ 0xFF;
        DnsArenaBody { header, payload }
    }

    fn write_dns_slot(arena: &ArenaMap, seq: u64, marker: u8, dns_len: u16) {
        #[allow(clippy::cast_possible_truncation)]
        let slot_idx = ((seq - 1) as usize) % DNS_SLOT_COUNT;
        let off = dns_slot_offset(slot_idx);
        unsafe {
            arena.write_at(
                off + ARENA_EVENT_HEADER_SIZE,
                fake_dns_body(marker, dns_len),
            );
        };
        let header = ArenaEventHeader {
            sequence: seq,
            timestamp_ns: 100,
            payload_len: core::mem::size_of::<DnsArenaBody>() as u32,
            event_type: 7,
            _pad: [0; 3],
        };
        unsafe { arena.write_at(off, header) };
    }

    #[test]
    fn dns_arena_reader_drains_new_events() {
        let Ok(arena) = ArenaMap::create(DNS_ARENA_PAGES, "dns_new") else {
            eprintln!("skip: no CAP_BPF");
            return;
        };

        let mut reader = DnsArenaReader::new(arena);

        write_dns_slot(&reader.arena, 1, 0xAA, 32);
        write_dns_slot(&reader.arena, 2, 0xBB, 128);
        unsafe { reader.arena.write_at::<u64>(DNS_WRITE_SEQ_OFFSET, 2) };

        let drained = reader.drain();
        assert_eq!(drained.len(), 2);
        match &drained[0] {
            AgentEvent::Dns { header, payload } => {
                assert_eq!(header.src_addr[0], 0xAA);
                assert_eq!(payload.len(), 32);
                assert_eq!(payload[0], 0xAA);
            }
            _ => panic!("expected AgentEvent::Dns"),
        }
        match &drained[1] {
            AgentEvent::Dns { header, payload } => {
                assert_eq!(header.src_addr[0], 0xBB);
                assert_eq!(payload.len(), 128);
                assert_eq!(payload[0], 0xBB);
            }
            _ => panic!("expected AgentEvent::Dns"),
        }

        assert!(reader.drain().is_empty());
    }

    #[test]
    fn dns_arena_reader_clamps_payload_len() {
        let Ok(arena) = ArenaMap::create(DNS_ARENA_PAGES, "dns_clamp") else {
            eprintln!("skip: no CAP_BPF");
            return;
        };

        let mut reader = DnsArenaReader::new(arena);
        // Overreport dns_payload_len — reader must clamp to DNS_MAX_PAYLOAD.
        write_dns_slot(&reader.arena, 1, 0xCD, 0xFFFF);
        unsafe { reader.arena.write_at::<u64>(DNS_WRITE_SEQ_OFFSET, 1) };

        let drained = reader.drain();
        match &drained[0] {
            AgentEvent::Dns { payload, .. } => assert_eq!(payload.len(), DNS_MAX_PAYLOAD),
            _ => panic!("expected AgentEvent::Dns"),
        }
    }
}
