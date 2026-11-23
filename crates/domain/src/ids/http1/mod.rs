//! HTTP/1 as Suricata reads it: each request and its response one
//! transaction, and the buffers its `http.*` keywords inspect filled the
//! way Suricata fills them.
//!
//! The parser is fed each direction's bytes in order, as the peer
//! acknowledges them, and hands back the transactions whose headers or
//! body it has just completed. What each buffer holds is held to Suricata
//! by `tests/fixtures/suricata/http-verdicts.txt`.

pub mod uri;

use std::io::Read;
use std::sync::Arc;

/// The most of a body Suricata keeps for inspection, its default
/// `request-body-limit` and `response-body-limit`.
pub const BODY_LIMIT: usize = 100 * 1024;

/// The longest header block or start line the parser waits for. A message
/// whose head runs past it is no HTTP the parser follows.
const HEAD_LIMIT: usize = 64 * 1024;

/// The buffers of one side of a transaction: each name once, or once per
/// instance for a buffer holding several (`http.request_header`).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Fields {
    entries: Vec<(&'static str, Vec<u8>)>,
}

impl Fields {
    fn put(&mut self, name: &'static str, bytes: Vec<u8>) {
        if !bytes.is_empty() {
            self.entries.push((name, bytes));
        }
    }

    /// The `index`th instance of a buffer.
    #[must_use]
    pub fn get(&self, name: &str, index: usize) -> Option<&[u8]> {
        self.entries
            .iter()
            .filter(|(n, _)| *n == name)
            .nth(index)
            .map(|(_, b)| b.as_slice())
    }

    /// Whether the side holds this buffer.
    #[must_use]
    pub fn has(&self, name: &str) -> bool {
        self.entries.iter().any(|(n, _)| *n == name)
    }
}

/// A transaction side ready for inspection.
#[derive(Debug, Clone)]
pub struct Ready {
    /// The transaction's number on its connection, from 0.
    pub id: u64,
    /// 0 for the request, 1 for the response.
    pub side: usize,
    pub fields: Arc<Fields>,
}

/// A header as it reads after folding, duplicates merged.
#[derive(Debug, Clone)]
struct Header {
    name: Vec<u8>,
    value: Vec<u8>,
}

/// How a body ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Framing {
    /// After this many more bytes.
    Length(u64),
    /// Chunk by chunk.
    Chunked(Chunk),
    /// When the connection closes.
    Close,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Chunk {
    /// Waiting for a chunk-size line.
    Size,
    /// Inside a chunk, this many bytes left.
    Data(u64),
    /// Waiting for the line end after a chunk.
    End,
    /// After the last chunk, reading trailer lines up to an empty one.
    Trailer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Waiting for a start line.
    Line,
    /// Waiting for the end of the header block.
    Headers,
    Body(Framing),
    /// The bytes are no HTTP the parser follows.
    Lost,
}

/// One direction of the connection.
#[derive(Debug, Clone)]
struct Direction {
    pending: Vec<u8>,
    state: State,
    /// The transaction this direction's message belongs to.
    tx: u64,
    /// The start line, without its line end.
    line: Vec<u8>,
    /// The start line's line end.
    line_end: Vec<u8>,
    fields: Fields,
    body: Vec<u8>,
    /// The `Content-Encoding` the body is decompressed from.
    encoding: Option<Encoding>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Encoding {
    Gzip,
    Deflate,
}

impl Direction {
    fn new() -> Self {
        Self {
            pending: Vec::new(),
            state: State::Line,
            tx: 0,
            line: Vec::new(),
            line_end: Vec::new(),
            fields: Fields::default(),
            body: Vec::new(),
            encoding: None,
        }
    }
}

/// What the request told the response's parser.
#[derive(Debug, Clone, Copy, Default)]
struct Asked {
    head: bool,
    connect: bool,
}

/// An HTTP/1 connection's two directions.
#[derive(Debug, Clone)]
pub struct Http1 {
    dirs: [Direction; 2],
    /// What each request still waiting for its response asked, oldest
    /// first, by transaction.
    asked: std::collections::VecDeque<(u64, Asked)>,
    /// The number the next request takes.
    next_tx: u64,
    /// The transaction the next response answers.
    next_response: u64,
}

impl Default for Http1 {
    fn default() -> Self {
        Self::new()
    }
}

/// The index of the line end starting at or after `from`, and its length.
fn line_end(bytes: &[u8], from: usize) -> Option<(usize, usize)> {
    let at = from + bytes.get(from..)?.iter().position(|&b| b == b'\n')?;
    if at > 0 && bytes[at - 1] == b'\r' {
        Some((at - 1, 2))
    } else {
        Some((at, 1))
    }
}

/// Where the header block ends: the index after its empty line.
fn head_end(bytes: &[u8]) -> Option<usize> {
    let mut from = 0;
    loop {
        let (at, len) = line_end(bytes, from)?;
        if at == from {
            return Some(at + len);
        }
        from = at + len;
    }
}

fn is_space(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

/// Parse a header block (its lines, the empty line excluded): each line
/// `Name: value`, a line opening with a space or a tab continuing the one
/// before, values trimmed, and a name met again merged into the first with
/// `, `.
fn parse_headers(block: &[u8]) -> Vec<Header> {
    let mut lines: Vec<Vec<u8>> = Vec::new();
    let mut from = 0;
    while let Some((at, len)) = line_end(block, from) {
        let line = &block[from..at];
        from = at + len;
        if line.first().copied().is_some_and(is_space)
            && let Some(last) = lines.last_mut()
        {
            last.extend_from_slice(line);
            continue;
        }
        lines.push(line.to_vec());
    }
    let mut headers: Vec<Header> = Vec::new();
    for line in lines {
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        let name = line[..colon].trim_ascii().to_vec();
        let value = line[colon + 1..].trim_ascii().to_vec();
        if name.is_empty() {
            continue;
        }
        match headers
            .iter_mut()
            .find(|h| h.name.eq_ignore_ascii_case(&name))
        {
            Some(existing) if !name.eq_ignore_ascii_case(b"content-length") => {
                existing.value.extend_from_slice(b", ");
                existing.value.extend_from_slice(&value);
            }
            Some(_) => {}
            None => headers.push(Header { name, value }),
        }
    }
    headers
}

fn header<'h>(headers: &'h [Header], name: &str) -> Option<&'h [u8]> {
    headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(name.as_bytes()))
        .map(|h| h.value.as_slice())
}

fn contains_nocase(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle))
}

/// The buffers both sides fill from their header block.
fn header_fields(
    fields: &mut Fields,
    headers: &[Header],
    raw: &[u8],
    line: &[u8],
    cookie: &str,
    per_header: &'static str,
) {
    let mut joined = Vec::new();
    let mut start = Vec::new();
    let mut names = b"\r\n".to_vec();
    for h in headers {
        let mut one = h.name.clone();
        one.extend_from_slice(b": ");
        one.extend_from_slice(&h.value);
        start.extend_from_slice(&one);
        start.extend_from_slice(b"\r\n");
        names.extend_from_slice(&h.name);
        names.extend_from_slice(b"\r\n");
        if !h.name.eq_ignore_ascii_case(cookie.as_bytes()) {
            joined.extend_from_slice(&one);
            joined.extend_from_slice(b"\r\n");
        }
    }
    names.extend_from_slice(b"\r\n");
    let mut whole = line.to_vec();
    whole.extend_from_slice(&start);
    whole.extend_from_slice(b"\r\n");
    fields.put("http.start", whole);
    fields.put("http.header", joined);
    fields.put("http.header.raw", raw.to_vec());
    if !headers.is_empty() {
        fields.put("http.header_names", names);
    }
    if let Some(v) = header(headers, cookie) {
        fields.put("http.cookie", v.to_vec());
    }
    for (name, key) in [
        ("http.connection", "connection"),
        ("http.content_type", "content-type"),
        ("http.content_len", "content-length"),
    ] {
        if let Some(v) = header(headers, key) {
            fields.put(name, v.to_vec());
        }
    }
    for h in headers {
        let mut one = h.name.clone();
        one.extend_from_slice(b": ");
        one.extend_from_slice(&h.value);
        fields.put(per_header, one);
    }
}

/// The request line's method, URI and protocol, split on spaces.
fn split_request_line(line: &[u8]) -> (&[u8], &[u8], &[u8]) {
    let method_end = line.iter().position(|&b| is_space(b)).unwrap_or(line.len());
    let method = &line[..method_end];
    let mut rest = &line[method_end..];
    while rest.first().copied().is_some_and(is_space) {
        rest = &rest[1..];
    }
    let uri_end = rest.iter().position(|&b| is_space(b)).unwrap_or(rest.len());
    let uri = &rest[..uri_end];
    let mut protocol = &rest[uri_end..];
    while protocol.first().copied().is_some_and(is_space) {
        protocol = &protocol[1..];
    }
    (method, uri, protocol.trim_ascii_end())
}

/// A `Host` value as `http.host` holds it: the name before any port,
/// lowercased.
fn host_name(value: &[u8]) -> Vec<u8> {
    let mut rest = value;
    while let Some(after) = rest.strip_prefix(b" ") {
        rest = after;
    }
    let end = if rest.starts_with(b"[") {
        rest.iter()
            .position(|&b| b == b']')
            .map_or(rest.len(), |c| c + 1)
    } else {
        rest.iter()
            .position(|&b| b"/?#:".contains(&b))
            .unwrap_or(rest.len())
    };
    let mut host = rest[..end].trim_ascii_end().to_vec();
    host.make_ascii_lowercase();
    host
}

fn decompress(encoding: Encoding, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let limit = u64::try_from(BODY_LIMIT).unwrap_or(u64::MAX);
    match encoding {
        Encoding::Gzip => {
            let _ = flate2::read::MultiGzDecoder::new(body)
                .take(limit)
                .read_to_end(&mut out);
        }
        Encoding::Deflate => {
            if flate2::read::ZlibDecoder::new(body)
                .take(limit)
                .read_to_end(&mut out)
                .is_err()
                && out.is_empty()
            {
                let _ = flate2::read::DeflateDecoder::new(body)
                    .take(limit)
                    .read_to_end(&mut out);
            }
        }
    }
    out
}

impl Http1 {
    #[must_use]
    pub fn new() -> Self {
        Self {
            dirs: [Direction::new(), Direction::new()],
            asked: std::collections::VecDeque::new(),
            next_tx: 0,
            next_response: 0,
        }
    }

    /// Parse the next bytes of one direction, 0 the client's, and return
    /// the transaction sides they completed.
    pub fn feed(&mut self, side: usize, bytes: &[u8]) -> Vec<Ready> {
        let mut ready = Vec::new();
        if self.dirs[side].state == State::Lost {
            return ready;
        }
        self.dirs[side].pending.extend_from_slice(bytes);
        while self.step(side, &mut ready) {}
        ready
    }

    /// The direction's peer closed it: a body running to the close ends.
    pub fn close(&mut self, side: usize) -> Vec<Ready> {
        let mut ready = Vec::new();
        if self.dirs[side].state == State::Body(Framing::Close) {
            self.finish(side, &mut ready);
        }
        ready
    }

    /// One step of parsing; `false` once more bytes are needed.
    fn step(&mut self, side: usize, ready: &mut Vec<Ready>) -> bool {
        match self.dirs[side].state {
            State::Lost => false,
            State::Line => self.start_line(side),
            State::Headers => self.headers(side, ready),
            State::Body(framing) => self.body(side, framing, ready),
        }
    }

    fn start_line(&mut self, side: usize) -> bool {
        let dir = &mut self.dirs[side];
        // Empty lines before a start line are skipped.
        while let Some(rest) = dir
            .pending
            .strip_prefix(b"\r\n")
            .or_else(|| dir.pending.strip_prefix(b"\n"))
        {
            dir.pending = rest.to_vec();
        }
        let Some((at, len)) = line_end(&dir.pending, 0) else {
            if dir.pending.len() > HEAD_LIMIT {
                dir.state = State::Lost;
            }
            return false;
        };
        dir.line = dir.pending[..at].to_vec();
        dir.line_end = dir.pending[at..at + len].to_vec();
        dir.pending.drain(..at + len);
        dir.state = State::Headers;
        true
    }

    fn headers(&mut self, side: usize, ready: &mut Vec<Ready>) -> bool {
        let Some(end) = head_end(&self.dirs[side].pending) else {
            if self.dirs[side].pending.len() > HEAD_LIMIT {
                self.dirs[side].state = State::Lost;
            }
            return false;
        };
        let raw: Vec<u8> = self.dirs[side].pending.drain(..end).collect();
        let headers = parse_headers(&raw);
        if side == 0 {
            self.request_head(&raw, &headers, ready);
        } else {
            self.response_head(&raw, &headers, ready);
        }
        true
    }

    fn request_head(&mut self, raw: &[u8], headers: &[Header], ready: &mut Vec<Ready>) {
        let tx = self.next_tx;
        self.next_tx += 1;
        let dir = &mut self.dirs[0];
        dir.tx = tx;
        let line = std::mem::take(&mut dir.line);
        let (method, target, protocol) = split_request_line(&line);
        let mut fields = Fields::default();
        fields.put("http.method", method.to_vec());
        fields.put("http.uri.raw", target.to_vec());
        fields.put("http.uri", uri::normalized(target));
        fields.put("http.request_line", line.clone());
        fields.put("http.protocol", protocol.to_vec());
        let mut start_line = line.clone();
        start_line.extend_from_slice(b"\r\n");
        header_fields(
            &mut fields,
            headers,
            raw,
            &start_line,
            "cookie",
            "http.request_header",
        );
        let host = uri::uri_host(target).or_else(|| header(headers, "host").map(host_name));
        if let Some(host) = host {
            fields.put("http.host", host);
        }
        if let Some(v) = header(headers, "host") {
            fields.put("http.host.raw", v.to_vec());
        }
        for (name, key) in [
            ("http.user_agent", "user-agent"),
            ("http.accept", "accept"),
            ("http.accept_enc", "accept-encoding"),
            ("http.accept_lang", "accept-language"),
            ("http.referer", "referer"),
        ] {
            if let Some(v) = header(headers, key) {
                fields.put(name, v.to_vec());
            }
        }
        dir.fields = fields;
        dir.encoding = None;
        let framing = if header(headers, "transfer-encoding")
            .is_some_and(|v| contains_nocase(v, b"chunked"))
        {
            Some(Framing::Chunked(Chunk::Size))
        } else {
            header(headers, "content-length")
                .and_then(|v| std::str::from_utf8(v).ok()?.trim().parse::<u64>().ok())
                .filter(|&n| n > 0)
                .map(Framing::Length)
        };
        self.asked.push_back((
            tx,
            Asked {
                head: method.eq_ignore_ascii_case(b"HEAD"),
                connect: method.eq_ignore_ascii_case(b"CONNECT"),
            },
        ));
        self.open_body(0, framing, ready);
    }

    fn response_head(&mut self, raw: &[u8], headers: &[Header], ready: &mut Vec<Ready>) {
        let line = std::mem::take(&mut self.dirs[1].line);
        let line_end = std::mem::take(&mut self.dirs[1].line_end);
        let mut parts = line.splitn(2, |&b| is_space(b));
        let protocol = parts.next().unwrap_or_default().to_vec();
        let rest = parts.next().unwrap_or_default().trim_ascii_start();
        let code_end = rest.iter().position(|&b| is_space(b)).unwrap_or(rest.len());
        let code = &rest[..code_end];
        let message = rest[code_end..].trim_ascii();
        let status: u16 = std::str::from_utf8(code)
            .ok()
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        let mut fields = Fields::default();
        fields.put("http.protocol", protocol);
        fields.put("http.stat_code", code.to_vec());
        fields.put("http.stat_msg", message.to_vec());
        let mut response_line = line.clone();
        response_line.extend_from_slice(&line_end);
        fields.put("http.response_line", response_line.clone());
        // Suricata's `http.start` puts a line end of its own after the
        // response line, which already carries one.
        let mut start_line = response_line;
        start_line.extend_from_slice(b"\r\n");
        header_fields(
            &mut fields,
            headers,
            raw,
            &start_line,
            "set-cookie",
            "http.response_header",
        );
        for (name, key) in [("http.server", "server"), ("http.location", "location")] {
            if let Some(v) = header(headers, key) {
                fields.put(name, v.to_vec());
            }
        }
        let tx = self.next_response;
        if (100..200).contains(&status) && status != 101 {
            // An interim response is read as the response of its request
            // until the final one follows and takes its place.
            self.dirs[1].state = State::Line;
            ready.push(Ready {
                id: tx,
                side: 1,
                fields: Arc::new(fields),
            });
            return;
        }
        self.next_response += 1;
        let asked = match self.asked.front() {
            Some(&(id, asked)) if id == tx => {
                self.asked.pop_front();
                asked
            }
            _ => {
                // A response nobody asked for opens a transaction of its own.
                self.next_tx = self.next_tx.max(tx + 1);
                Asked::default()
            }
        };
        let dir = &mut self.dirs[1];
        dir.tx = tx;
        dir.fields = fields;
        dir.encoding = header(headers, "content-encoding").and_then(|v| {
            let v = v.trim_ascii();
            if v.eq_ignore_ascii_case(b"gzip") || v.eq_ignore_ascii_case(b"x-gzip") {
                Some(Encoding::Gzip)
            } else if v.eq_ignore_ascii_case(b"deflate") {
                Some(Encoding::Deflate)
            } else {
                None
            }
        });
        let no_body = asked.head
            || status == 204
            || status == 304
            || (asked.connect && (200..300).contains(&status));
        let framing = if no_body {
            None
        } else if header(headers, "transfer-encoding")
            .is_some_and(|v| contains_nocase(v, b"chunked"))
        {
            Some(Framing::Chunked(Chunk::Size))
        } else if let Some(v) = header(headers, "content-length") {
            std::str::from_utf8(v)
                .ok()
                .and_then(|v| v.trim().parse::<u64>().ok())
                .filter(|&n| n > 0)
                .map(Framing::Length)
        } else {
            Some(Framing::Close)
        };
        self.open_body(1, framing, ready);
        if asked.connect && (200..300).contains(&status) {
            self.dirs[0].state = State::Lost;
            self.dirs[1].state = State::Lost;
        }
    }

    /// The head is parsed: hand it over, then read the body if one follows.
    fn open_body(&mut self, side: usize, framing: Option<Framing>, ready: &mut Vec<Ready>) {
        let dir = &mut self.dirs[side];
        dir.body.clear();
        if let Some(framing) = framing {
            ready.push(Ready {
                id: dir.tx,
                side,
                fields: Arc::new(dir.fields.clone()),
            });
            dir.state = State::Body(framing);
        } else {
            dir.state = State::Body(Framing::Length(0));
            self.finish(side, ready);
        }
    }

    fn keep(dir: &mut Direction, bytes: &[u8]) {
        let room = BODY_LIMIT.saturating_sub(dir.body.len());
        dir.body.extend_from_slice(&bytes[..bytes.len().min(room)]);
    }

    fn body(&mut self, side: usize, framing: Framing, ready: &mut Vec<Ready>) -> bool {
        let dir = &mut self.dirs[side];
        match framing {
            Framing::Length(left) => {
                let take = usize::try_from(left)
                    .unwrap_or(usize::MAX)
                    .min(dir.pending.len());
                let bytes: Vec<u8> = dir.pending.drain(..take).collect();
                Self::keep(dir, &bytes);
                let left = left - take as u64;
                if left == 0 {
                    self.finish(side, ready);
                    true
                } else {
                    dir.state = State::Body(Framing::Length(left));
                    false
                }
            }
            Framing::Close => {
                let bytes = std::mem::take(&mut dir.pending);
                Self::keep(dir, &bytes);
                false
            }
            Framing::Chunked(chunk) => self.chunk(side, chunk, ready),
        }
    }

    fn chunk(&mut self, side: usize, chunk: Chunk, ready: &mut Vec<Ready>) -> bool {
        let dir = &mut self.dirs[side];
        match chunk {
            Chunk::Size => {
                let Some((at, len)) = line_end(&dir.pending, 0) else {
                    if dir.pending.len() > HEAD_LIMIT {
                        dir.state = State::Lost;
                    }
                    return false;
                };
                let line: Vec<u8> = dir.pending.drain(..at + len).collect();
                let digits = line[..at]
                    .split(|&b| b == b';')
                    .next()
                    .unwrap_or_default()
                    .trim_ascii();
                let Some(size) = std::str::from_utf8(digits)
                    .ok()
                    .and_then(|d| u64::from_str_radix(d, 16).ok())
                else {
                    dir.state = State::Lost;
                    return false;
                };
                dir.state = State::Body(Framing::Chunked(if size == 0 {
                    Chunk::Trailer
                } else {
                    Chunk::Data(size)
                }));
                true
            }
            Chunk::Data(left) => {
                let take = usize::try_from(left)
                    .unwrap_or(usize::MAX)
                    .min(dir.pending.len());
                let bytes: Vec<u8> = dir.pending.drain(..take).collect();
                Self::keep(dir, &bytes);
                let left = left - take as u64;
                dir.state = State::Body(Framing::Chunked(if left == 0 {
                    Chunk::End
                } else {
                    Chunk::Data(left)
                }));
                left == 0
            }
            Chunk::End => {
                let Some((at, len)) = line_end(&dir.pending, 0) else {
                    return false;
                };
                dir.pending.drain(..at + len);
                dir.state = State::Body(Framing::Chunked(Chunk::Size));
                true
            }
            Chunk::Trailer => {
                let Some((at, len)) = line_end(&dir.pending, 0) else {
                    return false;
                };
                dir.pending.drain(..at + len);
                if at == 0 {
                    self.finish(side, ready);
                }
                true
            }
        }
    }

    /// The message is whole: hand the side over with its body.
    fn finish(&mut self, side: usize, ready: &mut Vec<Ready>) {
        let dir = &mut self.dirs[side];
        let body = std::mem::take(&mut dir.body);
        let body = match dir.encoding {
            Some(encoding) if !body.is_empty() => decompress(encoding, &body),
            _ => body,
        };
        let mut fields = std::mem::take(&mut dir.fields);
        if side == 0 {
            fields.put("http.request_body", body.clone());
        } else {
            fields.put("http.response_body", body.clone());
        }
        fields.put("file.data", body);
        ready.push(Ready {
            id: dir.tx,
            side,
            fields: Arc::new(fields),
        });
        dir.state = State::Line;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn last(ready: &[Ready]) -> &Fields {
        &ready.last().expect("a side is ready").fields
    }

    #[test]
    fn a_request_fills_the_request_buffers() {
        let mut http = Http1::new();
        let ready = http.feed(
            0,
            b"GET /a/../b%41?x=1 HTTP/1.1\r\nHost: Example.COM:8080\r\nUser-Agent:  curl \r\nCookie: a=1\r\nX-A: v1\r\nx-a: v2\r\n\r\n",
        );
        assert_eq!(ready.len(), 1);
        let f = last(&ready);
        assert_eq!(f.get("http.method", 0), Some(&b"GET"[..]));
        assert_eq!(f.get("http.uri", 0), Some(&b"/bA?x=1"[..]));
        assert_eq!(f.get("http.uri.raw", 0), Some(&b"/a/../b%41?x=1"[..]));
        assert_eq!(f.get("http.host", 0), Some(&b"example.com"[..]));
        assert_eq!(f.get("http.host.raw", 0), Some(&b"Example.COM:8080"[..]));
        assert_eq!(f.get("http.user_agent", 0), Some(&b"curl"[..]));
        assert_eq!(f.get("http.cookie", 0), Some(&b"a=1"[..]));
        assert_eq!(
            f.get("http.header", 0),
            Some(&b"Host: Example.COM:8080\r\nUser-Agent: curl\r\nX-A: v1, v2\r\n"[..])
        );
        assert_eq!(
            f.get("http.header_names", 0),
            Some(&b"\r\nHost\r\nUser-Agent\r\nCookie\r\nX-A\r\n\r\n"[..])
        );
        assert_eq!(f.get("http.request_header", 3), Some(&b"X-A: v1, v2"[..]));
        assert_eq!(f.get("http.protocol", 0), Some(&b"HTTP/1.1"[..]));
        assert!(!f.has("http.request_body"));
    }

    #[test]
    fn a_response_fills_the_response_buffers() {
        let mut http = Http1::new();
        http.feed(0, b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
        let ready = http.feed(
            1,
            b"HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nX-A:  v1 \r\n  folded\r\nContent-Length: 2\r\n\r\nhi",
        );
        let f = last(&ready);
        assert_eq!(f.get("http.stat_code", 0), Some(&b"200"[..]));
        assert_eq!(f.get("http.stat_msg", 0), Some(&b"OK"[..]));
        assert_eq!(
            f.get("http.response_line", 0),
            Some(&b"HTTP/1.1 200 OK\r\n"[..])
        );
        assert_eq!(f.get("http.cookie", 0), Some(&b"a=1, b=2"[..]));
        assert_eq!(
            f.get("http.start", 0),
            Some(
                &b"HTTP/1.1 200 OK\r\n\r\nSet-Cookie: a=1, b=2\r\nX-A: v1   folded\r\nContent-Length: 2\r\n\r\n"[..]
            )
        );
        assert_eq!(f.get("http.response_body", 0), Some(&b"hi"[..]));
        assert_eq!(f.get("file.data", 0), Some(&b"hi"[..]));
    }

    #[test]
    fn bodies_end_by_length_chunks_or_close_and_are_decompressed() {
        let mut http = Http1::new();
        http.feed(0, b"POST /u HTTP/1.1\r\nContent-Length: 5\r\n\r\nab");
        let ready = http.feed(0, b"cde");
        assert_eq!(
            last(&ready).get("http.request_body", 0),
            Some(&b"abcde"[..])
        );

        let ready = http.feed(
            1,
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2;x\r\nde\r\n0\r\n\r\n",
        );
        assert_eq!(
            last(&ready).get("http.response_body", 0),
            Some(&b"abcde"[..])
        );

        http.feed(0, b"GET / HTTP/1.0\r\n\r\n");
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut gz, b"zipped").expect("write");
        let zipped = gz.finish().expect("finish");
        let mut response = b"HTTP/1.0 200 OK\r\nContent-Encoding: gzip\r\n\r\n".to_vec();
        response.extend_from_slice(&zipped);
        assert_eq!(http.feed(1, &response).len(), 1);
        let ready = http.close(1);
        assert_eq!(ready[0].id, 1);
        assert_eq!(
            last(&ready).get("http.response_body", 0),
            Some(&b"zipped"[..])
        );
    }

    #[test]
    fn a_head_request_is_answered_without_a_body() {
        let mut http = Http1::new();
        http.feed(0, b"HEAD / HTTP/1.1\r\n\r\nGET /2 HTTP/1.1\r\n\r\n");
        let ready = http.feed(
            1,
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nHTTP/1.1 404 No\r\nContent-Length: 0\r\n\r\n",
        );
        let ids: Vec<u64> = ready.iter().map(|r| r.id).collect();
        assert_eq!(ids, [0, 0, 1]);
        assert_eq!(ready[0].fields.get("http.stat_code", 0), Some(&b"100"[..]));
        assert_eq!(ready[2].fields.get("http.stat_code", 0), Some(&b"404"[..]));
    }
}
