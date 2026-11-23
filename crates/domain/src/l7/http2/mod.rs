//! Reading the client side of cleartext HTTP/2 connections (RFC 9113),
//! header blocks decoded with HPACK (RFC 7541).
//!
//! A connection is read from its first segment, the one that carries the
//! client preface. Every header block is decoded in order, because HPACK's
//! dynamic table is shared by all the blocks of one direction; the payload
//! of every other frame is skipped without being kept.
//!
//! The capture hands over at most a prefix of each segment, and a segment
//! may be lost, repeated or reordered. [`L7Segment`] carries the sequence
//! number and the length on the wire, so the reader knows which bytes it
//! did not see. Bytes missing from a frame it skips cost nothing; bytes
//! missing from a frame header or a header block leave the dynamic table
//! unknown, and the connection is no longer read.

mod hpack;
mod huffman;
mod huffman_table;

use std::num::NonZeroUsize;

use ebpf_common::event::L7Segment;
use lru::LruCache;

use super::entity::{GrpcRequest, HttpRequest, ParsedProtocol};
use super::reassembler::FlowId;
pub use hpack::HpackError;

/// The client connection preface (RFC 9113, section 3.4).
pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Length of a frame header.
const FRAME_HEADER_LEN: usize = 9;

const FRAME_HEADERS: u8 = 0x1;
const FRAME_CONTINUATION: u8 = 0x9;

const FLAG_END_HEADERS: u8 = 0x4;
const FLAG_PADDED: u8 = 0x8;
const FLAG_PRIORITY: u8 = 0x20;

/// Largest header block, all its frames together, kept for decoding. A
/// client's default limit is a few kilobytes; a block past this is refused
/// rather than buffered.
pub const MAX_HEADER_BLOCK: usize = 16 * 1024;

/// Connections read at once. The least recently seen is dropped past it.
pub const MAX_CONNECTIONS: usize = 1024;

/// Why a connection stopped being read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unreadable {
    /// Bytes of a frame header or header block were not captured.
    LostBytes,
    /// A header block did not decode.
    Hpack(HpackError),
    /// A header block larger than [`MAX_HEADER_BLOCK`].
    TooLarge,
    /// A frame out of place: a continuation with nothing to continue, or
    /// another frame inside a header block, or padding past the frame.
    BadFrame,
}

impl Unreadable {
    /// Stable label for metrics.
    pub fn label(self) -> &'static str {
        match self {
            Self::LostBytes => "lost_bytes",
            Self::Hpack(_) => "hpack",
            Self::TooLarge => "too_large",
            Self::BadFrame => "bad_frame",
        }
    }
}

/// One request read from a HEADERS block that names a method and a path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Http2Request {
    pub stream_id: u32,
    pub method: String,
    pub path: String,
    pub authority: Option<String>,
    pub content_type: Option<String>,
    /// Regular fields, pseudo-header fields left out.
    pub headers: Vec<(String, String)>,
}

impl Http2Request {
    /// Service and method, when the request is gRPC: its content type
    /// starts with `application/grpc` and its path is `/service/method`.
    pub fn grpc(&self) -> Option<GrpcRequest> {
        let content_type = self.content_type.as_deref()?;
        if !content_type
            .get(..16)
            .is_some_and(|p| p.eq_ignore_ascii_case("application/grpc"))
        {
            return None;
        }
        grpc_path(&self.path)
    }

    /// What the L7 rules evaluate: a gRPC call, or an HTTP request.
    pub fn into_parsed(self) -> ParsedProtocol {
        if let Some(grpc) = self.grpc() {
            return ParsedProtocol::Grpc(grpc);
        }
        ParsedProtocol::Http(HttpRequest {
            method: self.method,
            path: self.path,
            version: "HTTP/2".to_string(),
            host: self.authority,
            content_type: self.content_type,
            headers: self.headers,
        })
    }
}

/// Split `/package.Service/Method` into service and method.
pub fn grpc_path(path: &str) -> Option<GrpcRequest> {
    let (service, method) = path.strip_prefix('/')?.split_once('/')?;
    if service.is_empty() || method.is_empty() || method.contains('/') {
        return None;
    }
    Some(GrpcRequest {
        service: service.to_string(),
        method: method.to_string(),
    })
}

/// Where the reader stands inside the current frame.
#[derive(Debug, Clone)]
enum Frame {
    /// Between frames, `header` holding the part of the next frame header
    /// read so far.
    Header(Vec<u8>),
    /// Inside a payload not kept: bytes left.
    Skip(usize),
    /// Inside a HEADERS or CONTINUATION payload, kept whole.
    Keep {
        kind: u8,
        flags: u8,
        stream_id: u32,
        len: usize,
        bytes: Vec<u8>,
    },
}

/// The client side of one connection.
#[derive(Debug, Clone)]
pub struct Connection {
    /// Sequence number of the segment that carried the preface.
    first_seq: Option<u32>,
    /// Sequence number of the next byte not yet accounted for.
    next_seq: Option<u32>,
    /// Bytes of the preface still to pass.
    preface_left: usize,
    frame: Frame,
    /// A header block waiting for its CONTINUATION frames.
    block: Option<(u32, Vec<u8>)>,
    hpack: hpack::Decoder,
    /// Set once the connection can no longer be read.
    failed: Option<Unreadable>,
}

impl Default for Connection {
    fn default() -> Self {
        Self::new()
    }
}

impl Connection {
    /// A connection whose next byte is the first byte of the preface.
    pub fn new() -> Self {
        Self {
            first_seq: None,
            next_seq: None,
            preface_left: PREFACE.len(),
            frame: Frame::Header(Vec::with_capacity(FRAME_HEADER_LEN)),
            block: None,
            hpack: hpack::Decoder::new(),
            failed: None,
        }
    }

    /// Why the connection is no longer read, if it is not.
    pub fn failed(&self) -> Option<Unreadable> {
        self.failed
    }

    /// Read one captured segment. Without `segment`, `payload` is taken to
    /// follow the previous one with nothing missing.
    ///
    /// The first failure is returned once; the connection then reads nothing.
    pub fn read_segment(
        &mut self,
        segment: Option<L7Segment>,
        payload: &[u8],
        out: &mut Vec<Http2Request>,
    ) -> Result<(), Unreadable> {
        if self.failed.is_some() {
            return Ok(());
        }
        let result = self.place(segment, payload, out);
        if let Err(reason) = result {
            self.failed = Some(reason);
            self.block = None;
            self.frame = Frame::Skip(0);
        }
        result
    }

    fn place(
        &mut self,
        segment: Option<L7Segment>,
        payload: &[u8],
        out: &mut Vec<Http2Request>,
    ) -> Result<(), Unreadable> {
        let Some(segment) = segment else {
            return self.read(payload, out);
        };
        let captured = u32::try_from(payload.len()).unwrap_or(u32::MAX);
        let wire_len = segment.wire_len.max(captured);
        let next = *self.next_seq.get_or_insert(segment.tcp_seq);
        self.first_seq.get_or_insert(segment.tcp_seq);
        let end = segment.tcp_seq.wrapping_add(wire_len);
        // Sequence numbers wrap, so compare by signed distance.
        if end.wrapping_sub(next).cast_signed() <= 0 {
            // A repeat of bytes already accounted for.
            return Ok(());
        }
        let start = segment.tcp_seq.wrapping_sub(next).cast_signed();
        let already = if start > 0 {
            self.lose(start.unsigned_abs() as usize)?;
            0
        } else {
            start.unsigned_abs() as usize
        };
        let lost_tail = if already < payload.len() {
            self.read(&payload[already..], out)?;
            (wire_len - captured) as usize
        } else {
            end.wrapping_sub(next) as usize
        };
        self.lose(lost_tail)?;
        self.next_seq = Some(end);
        Ok(())
    }

    /// Account for `n` bytes that were on the wire but not captured.
    fn lose(&mut self, n: usize) -> Result<(), Unreadable> {
        if n == 0 {
            return Ok(());
        }
        match &mut self.frame {
            Frame::Skip(left) if self.preface_left == 0 && n <= *left => {
                *left -= n;
                if *left == 0 {
                    self.frame = Frame::Header(Vec::with_capacity(FRAME_HEADER_LEN));
                }
                Ok(())
            }
            _ => Err(Unreadable::LostBytes),
        }
    }

    /// Read contiguous bytes.
    fn read(&mut self, mut data: &[u8], out: &mut Vec<Http2Request>) -> Result<(), Unreadable> {
        if self.preface_left > 0 {
            let n = self.preface_left.min(data.len());
            self.preface_left -= n;
            data = &data[n..];
        }
        while !data.is_empty() {
            match &mut self.frame {
                Frame::Skip(left) => {
                    let n = (*left).min(data.len());
                    *left -= n;
                    data = &data[n..];
                    if *left == 0 {
                        self.frame = Frame::Header(Vec::with_capacity(FRAME_HEADER_LEN));
                    }
                }
                Frame::Header(header) => {
                    let n = (FRAME_HEADER_LEN - header.len()).min(data.len());
                    header.extend_from_slice(&data[..n]);
                    data = &data[n..];
                    if header.len() == FRAME_HEADER_LEN {
                        let header = std::mem::take(header);
                        self.start_frame(&header, out)?;
                    }
                }
                Frame::Keep { len, bytes, .. } => {
                    let n = (*len - bytes.len()).min(data.len());
                    bytes.extend_from_slice(&data[..n]);
                    data = &data[n..];
                    if bytes.len() == *len {
                        self.end_kept_frame(out)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn start_frame(
        &mut self,
        header: &[u8],
        out: &mut Vec<Http2Request>,
    ) -> Result<(), Unreadable> {
        let len =
            usize::from(header[0]) << 16 | usize::from(header[1]) << 8 | usize::from(header[2]);
        let kind = header[3];
        let flags = header[4];
        let stream_id =
            u32::from_be_bytes([header[5], header[6], header[7], header[8]]) & 0x7fff_ffff;
        let in_block = self.block.as_ref().map(|(id, _)| *id);
        match kind {
            FRAME_HEADERS if in_block.is_none() => {}
            FRAME_CONTINUATION if in_block == Some(stream_id) => {}
            FRAME_HEADERS | FRAME_CONTINUATION => return Err(Unreadable::BadFrame),
            _ if in_block.is_some() => return Err(Unreadable::BadFrame),
            _ => {
                self.frame = if len == 0 {
                    Frame::Header(Vec::with_capacity(FRAME_HEADER_LEN))
                } else {
                    Frame::Skip(len)
                };
                return Ok(());
            }
        }
        let kept = self.block.as_ref().map_or(0, |(_, b)| b.len());
        if kept + len > MAX_HEADER_BLOCK + 256 {
            return Err(Unreadable::TooLarge);
        }
        self.frame = Frame::Keep {
            kind,
            flags,
            stream_id,
            len,
            bytes: Vec::with_capacity(len),
        };
        if len == 0 {
            self.end_kept_frame(out)?;
        }
        Ok(())
    }

    fn end_kept_frame(&mut self, out: &mut Vec<Http2Request>) -> Result<(), Unreadable> {
        let frame = std::mem::replace(
            &mut self.frame,
            Frame::Header(Vec::with_capacity(FRAME_HEADER_LEN)),
        );
        let Frame::Keep {
            kind,
            flags,
            stream_id,
            bytes,
            ..
        } = frame
        else {
            return Ok(());
        };
        let fragment = if kind == FRAME_HEADERS {
            headers_fragment(&bytes, flags)?
        } else {
            &bytes[..]
        };
        let mut block = match self.block.take() {
            Some((_, mut block)) => {
                block.extend_from_slice(fragment);
                block
            }
            None => fragment.to_vec(),
        };
        if block.len() > MAX_HEADER_BLOCK {
            return Err(Unreadable::TooLarge);
        }
        if flags & FLAG_END_HEADERS == 0 {
            self.block = Some((stream_id, block));
            return Ok(());
        }
        let fields = self.hpack.decode(&block).map_err(Unreadable::Hpack)?;
        block.clear();
        if let Some(request) = request_from(stream_id, fields) {
            out.push(request);
        }
        Ok(())
    }
}

/// The header block fragment of a HEADERS payload, padding and priority
/// removed.
fn headers_fragment(payload: &[u8], flags: u8) -> Result<&[u8], Unreadable> {
    let mut start = 0usize;
    let mut end = payload.len();
    if flags & FLAG_PADDED != 0 {
        let pad = usize::from(*payload.first().ok_or(Unreadable::BadFrame)?);
        start = 1;
        end = end.checked_sub(pad).ok_or(Unreadable::BadFrame)?;
    }
    if flags & FLAG_PRIORITY != 0 {
        start += 5;
    }
    payload.get(start..end).ok_or(Unreadable::BadFrame)
}

/// A request from decoded fields, when they carry a method and a path;
/// trailers carry neither.
fn request_from(stream_id: u32, fields: Vec<hpack::Field>) -> Option<Http2Request> {
    let mut method = None;
    let mut path = None;
    let mut authority = None;
    let mut content_type = None;
    let mut headers = Vec::new();
    for (name, value) in fields {
        let name = String::from_utf8_lossy(&name).into_owned();
        let value = String::from_utf8_lossy(&value).into_owned();
        match name.as_str() {
            ":method" => method = Some(value),
            ":path" => path = Some(value),
            ":authority" => authority = Some(value),
            n if n.starts_with(':') => {}
            n => {
                if n == "content-type" {
                    content_type = Some(value.clone());
                }
                if n == "host" && authority.is_none() {
                    authority = Some(value.clone());
                }
                headers.push((name, value));
            }
        }
    }
    Some(Http2Request {
        stream_id,
        method: method?,
        path: path?,
        authority,
        content_type,
        headers,
    })
}

/// Read every request in one buffer that starts with the preface, as if it
/// were the whole of a connection's first bytes. Stops at the first frame
/// that does not read.
pub fn read_buffer(payload: &[u8]) -> Vec<Http2Request> {
    let mut out = Vec::new();
    if payload.starts_with(PREFACE) {
        let _unread = Connection::new().read_segment(None, payload, &mut out);
    }
    out
}

/// What [`Http2Connections::offer`] made of one segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Offer {
    /// No HTTP/2 connection known on this flow, and the segment does not
    /// open one.
    Untracked,
    /// The segment belongs to a connection being read.
    Tracked {
        /// Requests whose header block ended in this segment.
        requests: Vec<Http2Request>,
        /// Set the one time the connection stops being read.
        failed: Option<Unreadable>,
        /// Another connection was dropped to make room for this one.
        evicted: bool,
    },
}

/// The client sides of the HTTP/2 connections being read, keyed by flow.
pub struct Http2Connections {
    connections: LruCache<FlowId, Connection>,
}

impl Default for Http2Connections {
    fn default() -> Self {
        Self::new(MAX_CONNECTIONS)
    }
}

impl Http2Connections {
    pub fn new(capacity: usize) -> Self {
        Self {
            connections: LruCache::new(NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::MIN)),
        }
    }

    /// Connections being read.
    pub fn len(&self) -> usize {
        self.connections.len()
    }

    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
    }

    /// Read one segment sent from the client of `flow`.
    pub fn offer(&mut self, flow: FlowId, segment: Option<L7Segment>, payload: &[u8]) -> Offer {
        let opens = payload.starts_with(PREFACE);
        let known = self.connections.get(&flow).map(|c| c.first_seq);
        // The same flow opening again is a new connection on a reused port,
        // unless the segment repeats the one that opened the current one.
        let fresh = match known {
            None => opens,
            Some(first_seq) => {
                opens && (segment.is_none() || segment.map(|s| s.tcp_seq) != first_seq)
            }
        };
        let mut evicted = false;
        if fresh {
            evicted = self
                .connections
                .push(flow, Connection::new())
                .is_some_and(|(old, _)| old != flow);
        } else if known.is_none() {
            return Offer::Untracked;
        }
        let Some(connection) = self.connections.get_mut(&flow) else {
            return Offer::Untracked;
        };
        let mut requests = Vec::new();
        let failed = connection
            .read_segment(segment, payload, &mut requests)
            .err();
        Offer::Tracked {
            requests,
            failed,
            evicted,
        }
    }
}

#[cfg(test)]
mod tests;
