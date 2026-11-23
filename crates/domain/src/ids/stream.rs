//! A TCP connection's two byte streams, placed by sequence number, and the
//! moments Suricata 8 inspects them.
//!
//! Each side's data is kept by its offset from the side's first byte, the
//! one after its SYN. A segment arriving out of order waits for the bytes
//! before it; one overlapping data already held keeps the bytes that came
//! first; a retransmission adds nothing. Bytes are inspected once, in
//! windows that never overlap:
//!
//! - when the side has `CHUNK` bytes acknowledged and not yet inspected,
//!   up to what the other side acknowledged;
//! - once the side closed with a FIN, or the connection was reset by the
//!   other side, up to what was acknowledged;
//! - on a RST the side sends, everything it sent, acknowledged or not;
//! - when the flow ends, everything left;
//! - when the application layer asks for it, on the side's next packet, up
//!   to what was acknowledged.
//!
//! Bytes the other side acknowledged are also handed, in order, to the
//! application layer.
//!
//! Each window is inspected on a packet the side itself sends, as Suricata
//! does. A hole in the sequence space splits a window into blocks that are
//! inspected apart, never joined over the missing bytes. Data past `DEPTH`
//! bytes of a side is not kept, nor any once the connection was reset.
//!
//! These rules are held to Suricata by
//! `tests/fixtures/suricata/stream-verdicts.txt`.

use std::collections::BTreeMap;

/// Acknowledged bytes a side holds before they are inspected without a
/// close, Suricata's `stream.reassembly.toserver-chunk-size` and
/// `toclient-chunk-size` default.
pub const CHUNK: u64 = 2560;

/// Bytes of each side that are inspected, Suricata's
/// `stream.reassembly.depth` default.
pub const DEPTH: u64 = 1 << 20;

/// Bytes every connection together may hold waiting for inspection, as
/// Suricata's `stream.reassembly.memcap`. Past it a segment is dropped and
/// its bytes are a hole.
pub const MEMCAP: u64 = 256 << 20;

const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const ACK: u8 = 0x10;

/// What a TCP segment tells its connection's streams.
#[derive(Debug, Clone, Copy)]
pub struct Segment<'a> {
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub data: &'a [u8],
}

/// One direction of the connection.
#[derive(Debug, Default)]
struct Side {
    /// A sequence number and the offset it stands at, `None` before the
    /// side's SYN. It follows the highest byte so that a stream longer than
    /// half the sequence space still places its segments.
    anchor: Option<(u32, u64)>,
    /// One past the highest byte sent.
    high: u64,
    /// Bytes not yet inspected, by offset, never overlapping.
    segments: BTreeMap<u64, Vec<u8>>,
    /// One past the highest byte the other side acknowledged.
    acked: u64,
    /// One past the last byte inspected.
    inspected: u64,
    /// Whether the side sent a FIN.
    fin: bool,
    /// Whether that FIN counts in the side's size, from the packet after it.
    fin_counted: bool,
    /// One past the last byte handed to the application layer.
    app: u64,
    /// Whether the side's next packet inspects what was acknowledged, as
    /// the application layer asked.
    inspect: bool,
}

impl Side {
    fn offset(&self, seq: u32) -> Option<u64> {
        let (at, offset) = self.anchor?;
        let ahead = seq.wrapping_sub(at);
        if ahead < 1 << 31 {
            Some(offset + u64::from(ahead))
        } else {
            offset.checked_sub(u64::from(at.wrapping_sub(seq)))
        }
    }

    /// The side's `stream_size`: its SYN, every byte up to the highest, and
    /// its FIN once counted. A side whose SYN was not seen counts nothing.
    fn size(&self) -> u64 {
        if self.anchor.is_none() {
            return 0;
        }
        self.high + 1 + u64::from(self.fin_counted)
    }

    /// Keep the bytes of a segment at `at` that no earlier segment brought,
    /// within the inspected depth and the memory left. Returns the bytes
    /// newly held.
    fn insert(&mut self, seq: u32, at: u64, data: &[u8], held: &mut u64) -> u64 {
        let len = data.len() as u64;
        let end = at + len;
        if end > self.high {
            self.high = end;
            self.anchor = Some((seq.wrapping_add(len as u32), end));
        }
        let lo = at.max(self.inspected);
        let hi = end.min(DEPTH);
        if lo >= hi {
            return 0;
        }
        let mut taken: Vec<(u64, u64)> = Vec::new();
        if let Some((&start, bytes)) = self.segments.range(..lo).next_back() {
            taken.push((start, start + bytes.len() as u64));
        }
        taken.extend(
            self.segments
                .range(lo..hi)
                .map(|(&start, bytes)| (start, start + bytes.len() as u64)),
        );
        let mut gaps = Vec::new();
        let mut pos = lo;
        for (start, stop) in taken {
            if start > pos {
                gaps.push((pos, start.min(hi)));
            }
            pos = pos.max(stop);
            if pos >= hi {
                break;
            }
        }
        if pos < hi {
            gaps.push((pos, hi));
        }
        let mut added = 0;
        for (from, to) in gaps {
            let size = to - from;
            if *held + size > MEMCAP {
                break;
            }
            let skip = usize::try_from(from - at).unwrap_or(usize::MAX);
            let take = usize::try_from(size).unwrap_or(usize::MAX);
            let Some(bytes) = data.get(skip..skip.saturating_add(take)) else {
                break;
            };
            self.segments.insert(from, bytes.to_vec());
            *held += size;
            added += size;
        }
        added
    }

    /// Hand over the bytes up to `end` not yet inspected, as the blocks the
    /// holes leave, and forget them. Returns the blocks and the bytes freed.
    fn take(&mut self, end: u64) -> (Vec<Vec<u8>>, u64) {
        if end <= self.inspected {
            return (Vec::new(), 0);
        }
        let mut blocks: Vec<Vec<u8>> = Vec::new();
        let mut freed = 0;
        let mut next: Option<u64> = None;
        while let Some(entry) = self.segments.first_entry() {
            let start = *entry.key();
            if start >= end {
                break;
            }
            let mut bytes = entry.remove();
            let stop = start + bytes.len() as u64;
            if stop > end {
                let keep = bytes.split_off(usize::try_from(end - start).unwrap_or(usize::MAX));
                self.segments.insert(end, keep);
            }
            freed += bytes.len() as u64;
            match blocks.last_mut() {
                Some(last) if next == Some(start) => last.extend_from_slice(&bytes),
                _ => blocks.push(bytes),
            }
            next = Some(stop.min(end));
        }
        self.inspected = end;
        (blocks, freed)
    }

    fn held(&self) -> u64 {
        self.segments.values().map(|b| b.len() as u64).sum()
    }

    /// The acknowledged bytes not yet handed to the application layer, in
    /// order, a hole skipped.
    fn acked_since(&mut self) -> Vec<u8> {
        let from = self.app.max(self.inspected);
        let mut out = Vec::new();
        for (&start, bytes) in self.segments.range(..self.acked) {
            let stop = start + bytes.len() as u64;
            let lo = start.max(from);
            let hi = stop.min(self.acked);
            if lo < hi {
                let skip = usize::try_from(lo - start).unwrap_or(usize::MAX);
                let take = usize::try_from(hi - lo).unwrap_or(usize::MAX);
                if let Some(slice) = bytes.get(skip..skip.saturating_add(take)) {
                    out.extend_from_slice(slice);
                }
            }
        }
        self.app = from.max(self.acked);
        out
    }
}

/// Both streams of a TCP connection whose SYN was seen.
#[derive(Debug, Default)]
pub struct Streams {
    /// The client's stream, then the server's.
    sides: [Side; 2],
    /// Whether either side reset the connection.
    reset: bool,
}

/// What one segment changed.
#[derive(Debug, Default)]
pub struct Observed {
    /// Each side's `stream_size` with the segment's data counted.
    pub sizes: [u64; 2],
    /// The sending side's bytes this segment has inspected.
    pub blocks: Vec<Vec<u8>>,
    /// The other side's bytes this segment newly acknowledged, for the
    /// application layer.
    pub acked: Vec<u8>,
}

impl Streams {
    /// Place a segment the client (`side` 0) or the server sent, and hand
    /// over what it has Suricata inspect. `held` is the memory every
    /// connection holds, which the segment's bytes add to and the inspected
    /// ones free.
    pub fn observe(&mut self, side: usize, segment: Segment<'_>, held: &mut u64) -> Observed {
        let other = 1 - side;
        let flags = segment.flags;
        if flags & SYN != 0 && self.sides[side].anchor.is_none() {
            self.sides[side].anchor = Some((segment.seq.wrapping_add(1), 0));
        }
        let was_reset = self.reset;
        let mut acked = Vec::new();
        if !was_reset {
            let me = &mut self.sides[side];
            if !segment.data.is_empty()
                && flags & SYN == 0
                && let Some(at) = me.offset(segment.seq)
            {
                me.insert(segment.seq, at, segment.data, held);
            }
            if flags & FIN != 0 {
                me.fin = true;
            }
            if flags & ACK != 0 {
                let peer = &mut self.sides[other];
                if let Some(at) = peer.offset(segment.ack) {
                    peer.acked = peer.acked.max(at.min(peer.high));
                }
                acked = peer.acked_since();
            }
            if flags & RST != 0 {
                self.reset = true;
            }
        }
        let sizes = [self.sides[0].size(), self.sides[1].size()];
        if !was_reset && flags & FIN != 0 {
            self.sides[side].fin_counted = true;
        }
        let me = &mut self.sides[side];
        let asked = std::mem::take(&mut me.inspect);
        let end = if !was_reset && flags & RST != 0 {
            Some(me.high)
        } else if me.fin || self.reset || asked || me.acked.saturating_sub(me.inspected) >= CHUNK {
            Some(me.acked)
        } else {
            None
        };
        let blocks = match end {
            Some(end) => {
                let (blocks, freed) = me.take(end);
                *held = held.saturating_sub(freed);
                blocks
            }
            None => Vec::new(),
        };
        Observed {
            sizes,
            blocks,
            acked,
        }
    }

    /// Have the side's next packet inspect what was acknowledged of it, as
    /// an application parser asks once it holds a whole message.
    pub fn inspect_next(&mut self, side: usize) {
        self.sides[side].inspect = true;
    }

    /// Each side's `stream_size` as it stands.
    #[must_use]
    pub fn sizes(&self) -> [u64; 2] {
        [self.sides[0].size(), self.sides[1].size()]
    }

    /// Hand over everything not yet inspected, the client's then the
    /// server's, as when the flow ends.
    pub fn drain(&mut self, held: &mut u64) -> [Vec<Vec<u8>>; 2] {
        let mut out: [Vec<Vec<u8>>; 2] = [Vec::new(), Vec::new()];
        for (side, blocks) in self.sides.iter_mut().zip(out.iter_mut()) {
            let (taken, freed) = side.take(side.high);
            *held = held.saturating_sub(freed);
            *blocks = taken;
        }
        out
    }

    /// Whether any byte waits for inspection.
    #[must_use]
    pub fn pending(&self) -> bool {
        self.sides.iter().any(|s| !s.segments.is_empty())
    }

    /// The bytes held waiting for inspection.
    #[must_use]
    pub fn held(&self) -> u64 {
        self.sides.iter().map(Side::held).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT: usize = 0;
    const SERVER: usize = 1;

    fn seg(seq: u32, ack: u32, flags: u8, data: &[u8]) -> Segment<'_> {
        Segment {
            seq,
            ack,
            flags,
            data,
        }
    }

    /// A connection after its handshake, the client's first byte at
    /// sequence 1001 and the server's at 5001.
    fn opened(held: &mut u64) -> Streams {
        let mut s = Streams::default();
        s.observe(CLIENT, seg(1000, 0, SYN, b""), held);
        s.observe(SERVER, seg(5000, 1001, SYN | ACK, b""), held);
        s.observe(CLIENT, seg(1001, 5001, ACK, b""), held);
        s
    }

    #[test]
    fn reordered_overlapping_and_repeated_segments_read_as_sent_first() {
        let mut held = 0;
        let mut s = opened(&mut held);
        s.observe(CLIENT, seg(1006, 5001, ACK, b"FGHIJ"), &mut held);
        s.observe(CLIENT, seg(1001, 5001, ACK, b"ABCDE"), &mut held);
        s.observe(CLIENT, seg(1004, 5001, ACK, b"xxxxx"), &mut held);
        s.observe(CLIENT, seg(1001, 5001, ACK, b"ABCDE"), &mut held);
        assert_eq!(s.sizes()[CLIENT], 11);
        s.observe(SERVER, seg(5001, 1011, ACK, b""), &mut held);
        let out = s.observe(CLIENT, seg(1011, 5001, FIN | ACK, b""), &mut held);
        assert_eq!(out.blocks, vec![b"ABCDEFGHIJ".to_vec()]);
        assert_eq!(held, 0);
    }

    #[test]
    fn a_hole_splits_the_window_and_nothing_is_inspected_twice() {
        let mut held = 0;
        let mut s = opened(&mut held);
        s.observe(CLIENT, seg(1001, 5001, ACK, b"ABC"), &mut held);
        s.observe(CLIENT, seg(1006, 5001, ACK, b"FG"), &mut held);
        s.observe(SERVER, seg(5001, 1008, ACK, b""), &mut held);
        let out = s.observe(CLIENT, seg(1008, 5001, FIN | ACK, b""), &mut held);
        assert_eq!(out.blocks, vec![b"ABC".to_vec(), b"FG".to_vec()]);
        let again = s.observe(CLIENT, seg(1009, 5001, ACK, b""), &mut held);
        assert!(again.blocks.is_empty());
    }

    #[test]
    fn a_chunk_is_inspected_once_acknowledged_and_no_further() {
        let mut held = 0;
        let mut s = opened(&mut held);
        let data = vec![b'a'; 600];
        let mut seq = 1001u32;
        let mut flushed = Vec::new();
        for _ in 0..6 {
            let out = s.observe(CLIENT, seg(seq, 5001, ACK, &data), &mut held);
            flushed.extend(out.blocks.iter().map(Vec::len));
            seq += 600;
            s.observe(SERVER, seg(5001, seq, ACK, b""), &mut held);
        }
        assert_eq!(flushed, vec![3000]);
    }

    #[test]
    fn a_reset_hands_over_unacknowledged_bytes_and_stops_the_count() {
        let mut held = 0;
        let mut s = opened(&mut held);
        s.observe(CLIENT, seg(1001, 5001, ACK, b"ABC"), &mut held);
        let out = s.observe(CLIENT, seg(1004, 5001, RST | ACK, b""), &mut held);
        assert_eq!(out.blocks, vec![b"ABC".to_vec()]);
        let late = s.observe(CLIENT, seg(1004, 5001, ACK, b"late"), &mut held);
        assert!(late.blocks.is_empty());
        assert_eq!(late.sizes[CLIENT], 4);
    }

    #[test]
    fn sequence_numbers_wrap() {
        let mut held = 0;
        let mut s = Streams::default();
        let isn = u32::MAX - 2;
        s.observe(CLIENT, seg(isn, 0, SYN, b""), &mut held);
        s.observe(
            SERVER,
            seg(5000, isn.wrapping_add(1), SYN | ACK, b""),
            &mut held,
        );
        s.observe(
            CLIENT,
            seg(isn.wrapping_add(1), 5001, ACK, b"ABCDEF"),
            &mut held,
        );
        s.observe(SERVER, seg(5001, isn.wrapping_add(7), ACK, b""), &mut held);
        let out = s.observe(
            CLIENT,
            seg(isn.wrapping_add(7), 5001, FIN | ACK, b""),
            &mut held,
        );
        assert_eq!(out.blocks, vec![b"ABCDEF".to_vec()]);
    }
}
