//! The files a mail carries over SMTP, read as Suricata 8 reads them for
//! `file.data`.
//!
//! What the client sends after `DATA` up to the line holding a lone dot is
//! the message. A part of it is a file when its `Content-Disposition` names
//! a `filename` or its `Content-Type` a `name`, at any depth of nested
//! multiparts; a text body, an inline part and an unnamed part are not, nor
//! is a message with no MIME structure. A file's content is decoded from
//! base64 or quoted-printable, and ends before the line break that precedes
//! the next boundary. Dot stuffed lines are read as they travelled.
//!
//! The files of a message are inspected once, when the server answers the
//! message, on the client's side, one transaction per message.
//!
//! These rules are held to Suricata by
//! `tests/fixtures/suricata/smtp-verdicts.txt`.

use std::sync::Arc;

use super::tx::{Fields, Ready};

/// The most bytes of one message read for its files: past it, the rest of
/// the message is not read.
const MESSAGE_LIMIT: usize = 1024 * 1024;

/// The longest command line waited on.
const LINE_LIMIT: usize = 4096;

/// How deep multiparts nest before the parts below are no longer read.
const NESTING_LIMIT: usize = 8;

/// What a connection said in SMTP, as far as its messages go.
#[derive(Debug, Clone, Default)]
pub struct Smtp {
    /// The client's bytes not yet a whole line.
    pending: Vec<u8>,
    /// Whether the client is sending a message.
    data: bool,
    message: Vec<u8>,
    /// The files of the last message, waiting for the server's answer.
    files: Option<Vec<Vec<u8>>>,
    /// The messages read so far.
    messages: u64,
}

impl Smtp {
    /// Take the bytes `side` sent, in order, and hand back the client side
    /// of a message the server just answered, when it carried files.
    pub fn feed(&mut self, side: usize, bytes: &[u8]) -> Vec<Ready> {
        if side == 1 {
            return self.answered();
        }
        self.pending.extend_from_slice(bytes);
        let mut at = 0;
        while let Some(end) = self.pending[at..].iter().position(|&b| b == b'\n') {
            let line = self.pending[at..=at + end].to_vec();
            at += end + 1;
            self.line(&line);
        }
        self.pending.drain(..at);
        if self.pending.len() > LINE_LIMIT && !self.data {
            self.pending.clear();
        }
        if self.data && !self.pending.is_empty() && self.message.len() > MESSAGE_LIMIT {
            self.pending.clear();
        }
        Vec::new()
    }

    /// One line from the client, its line end included.
    fn line(&mut self, line: &[u8]) {
        let text = line.strip_suffix(b"\n").unwrap_or(line);
        let text = text.strip_suffix(b"\r").unwrap_or(text);
        if !self.data {
            if text.eq_ignore_ascii_case(b"DATA") {
                self.data = true;
                self.message.clear();
            }
            return;
        }
        if text == b"." {
            self.data = false;
            self.messages += 1;
            let message = std::mem::take(&mut self.message);
            self.files = Some(files(&message));
            return;
        }
        let room = MESSAGE_LIMIT.saturating_sub(self.message.len());
        self.message
            .extend_from_slice(&line[..line.len().min(room)]);
    }

    fn answered(&mut self) -> Vec<Ready> {
        let Some(files) = self.files.take() else {
            return Vec::new();
        };
        let mut fields = Fields::default();
        for file in files {
            fields.put("file.data", file);
        }
        if !fields.has("file.data") {
            return Vec::new();
        }
        vec![Ready {
            id: self.messages - 1,
            side: 0,
            fields: Arc::new(fields),
            payload: Arc::from(&[][..]),
            whole: false,
            latest: true,
            last: true,
        }]
    }
}

/// The files of a message, decoded, in the order they appear.
fn files(message: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    entity(message, 0, &mut out);
    out
}

/// One entity: its headers, a blank line, its body.
fn entity(bytes: &[u8], depth: usize, out: &mut Vec<Vec<u8>>) {
    let (head, body) = split_head(bytes);
    let headers = unfold(head);
    let header = |name: &str| {
        headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name.as_bytes()))
            .map(|(_, v)| v.as_slice())
    };
    let kind = header("content-type").unwrap_or_default();
    if kind.len() >= 10 && kind[..10].eq_ignore_ascii_case(b"multipart/") {
        if let Some(boundary) = param(kind, "boundary")
            && depth < NESTING_LIMIT
        {
            for part in parts(body, &boundary) {
                entity(part, depth + 1, out);
            }
        }
        return;
    }
    let named = header("content-disposition")
        .and_then(|d| param(d, "filename"))
        .is_some()
        || param(kind, "name").is_some();
    if !named {
        return;
    }
    let encoding = header("content-transfer-encoding").unwrap_or_default();
    let encoding = trim(encoding);
    out.push(if encoding.eq_ignore_ascii_case(b"base64") {
        base64(body)
    } else if encoding.eq_ignore_ascii_case(b"quoted-printable") {
        quoted_printable(body)
    } else {
        body.to_vec()
    });
}

/// The headers of an entity and its body, split at the first blank line.
fn split_head(bytes: &[u8]) -> (&[u8], &[u8]) {
    let mut at = 0;
    while at < bytes.len() {
        let end = bytes[at..]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(bytes.len(), |e| at + e + 1);
        let line = &bytes[at..end];
        if line == b"\r\n" || line == b"\n" {
            return (&bytes[..at], &bytes[end..]);
        }
        at = end;
    }
    (bytes, &[])
}

/// Header lines, continuation lines joined, as name and value.
fn unfold(head: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut headers: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for line in head.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        if matches!(line[0], b' ' | b'\t') {
            if let Some((_, value)) = headers.last_mut() {
                value.push(b' ');
                value.extend_from_slice(trim(line));
            }
            continue;
        }
        if let Some(colon) = line.iter().position(|&b| b == b':') {
            headers.push((
                trim(&line[..colon]).to_vec(),
                trim(&line[colon + 1..]).to_vec(),
            ));
        }
    }
    headers
}

fn trim(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map_or(start, |e| e + 1);
    &bytes[start..end]
}

/// The value of a header parameter, its quotes removed.
fn param(value: &[u8], name: &str) -> Option<Vec<u8>> {
    value.split(|&b| b == b';').skip(1).find_map(|p| {
        let eq = p.iter().position(|&b| b == b'=')?;
        if !trim(&p[..eq]).eq_ignore_ascii_case(name.as_bytes()) {
            return None;
        }
        let v = trim(&p[eq + 1..]);
        let v = v
            .strip_prefix(b"\"")
            .and_then(|v| v.strip_suffix(b"\""))
            .unwrap_or(v);
        Some(v.to_vec())
    })
}

/// The parts of a multipart body: what lies between its boundary lines,
/// the line break before each boundary left out, up to the closing one.
fn parts<'a>(body: &'a [u8], boundary: &[u8]) -> Vec<&'a [u8]> {
    let mut delimiter = b"--".to_vec();
    delimiter.extend_from_slice(boundary);
    let mut out = Vec::new();
    let mut start: Option<usize> = None;
    let mut at = 0;
    while at < body.len() {
        let end = body[at..]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(body.len(), |e| at + e + 1);
        let line = trim(&body[at..end]);
        if let Some(rest) = line.strip_prefix(delimiter.as_slice()) {
            if let Some(from) = start {
                let mut to = at;
                if to > from && body[to - 1] == b'\n' {
                    to -= 1;
                    if to > from && body[to - 1] == b'\r' {
                        to -= 1;
                    }
                }
                out.push(&body[from..to.max(from)]);
            }
            if rest.starts_with(b"--") {
                return out;
            }
            start = Some(end);
        }
        at = end;
    }
    if let Some(from) = start {
        out.push(&body[from..]);
    }
    out
}

/// Base64 decoded, any byte outside the alphabet skipped.
fn base64(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &b in bytes {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            _ => continue,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

/// Quoted-printable decoded: `=XX` a byte, `=` at a line end a soft break.
fn quoted_printable(bytes: &[u8]) -> Vec<u8> {
    let hex = |b: u8| char::from(b).to_digit(16);
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] != b'=' {
            out.push(bytes[at]);
            at += 1;
            continue;
        }
        match bytes.get(at + 1..at + 3) {
            Some(b"\r\n") => at += 3,
            Some([b'\n', ..]) => at += 2,
            Some(&[h, l]) if hex(h).is_some() && hex(l).is_some() => {
                out.push((hex(h).unwrap_or(0) * 16 + hex(l).unwrap_or(0)) as u8);
                at += 3;
            }
            _ => {
                out.push(b'=');
                at += 1;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const MESSAGE: &[u8] =
        b"Subject: x\r\nContent-Type: multipart/mixed;\r\n boundary=\"B\"\r\n\r\n\
preamble\r\n--B\r\nContent-Type: text/plain\r\n\r\nbody text\r\n--B\r\n\
Content-Disposition: attachment; filename=\"a.bin\"\r\nContent-Transfer-Encoding: base64\r\n\r\n\
aGVsbG8g\r\nd29ybGQ=\r\n--B\r\nContent-Type: text/plain; name=q.txt\r\n\
Content-Transfer-Encoding: quoted-printable\r\n\r\na=3Db=\r\nc\r\n--B--\r\n";

    #[test]
    fn named_parts_are_files_decoded_and_text_bodies_are_not() {
        assert_eq!(
            files(MESSAGE),
            vec![b"hello world".to_vec(), b"a=bc".to_vec()]
        );
    }

    #[test]
    fn a_message_without_mime_carries_no_file() {
        assert!(files(b"Subject: x\r\n\r\nplain\r\n").is_empty());
    }

    #[test]
    fn the_files_are_inspected_when_the_server_answers_the_message() {
        let mut smtp = Smtp::default();
        assert!(
            smtp.feed(0, b"EHLO x\r\nMAIL FROM:<a@b>\r\nDATA\r\n")
                .is_empty()
        );
        assert!(smtp.feed(1, b"354 go\r\n").is_empty());
        let cut = MESSAGE.len() / 2;
        assert!(smtp.feed(0, &MESSAGE[..cut]).is_empty());
        assert!(smtp.feed(0, &MESSAGE[cut..]).is_empty());
        assert!(smtp.feed(0, b".\r\n").is_empty());
        let ready = smtp.feed(1, b"250 queued\r\n");
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].side, 0);
        assert_eq!(
            ready[0].fields.get("file.data", 0),
            Some(&b"hello world"[..])
        );
        assert_eq!(ready[0].fields.get("file.data", 1), Some(&b"a=bc"[..]));
        assert!(smtp.feed(1, b"221 bye\r\n").is_empty());
    }

    #[test]
    fn dot_stuffed_lines_are_read_as_they_travelled() {
        let mut smtp = Smtp::default();
        smtp.feed(0, b"DATA\r\n");
        smtp.feed(0, b"Content-Type: text/plain; name=a\r\n\r\n..x\r\n.\r\n");
        let ready = smtp.feed(1, b"250 ok\r\n");
        assert_eq!(ready[0].fields.get("file.data", 0), Some(&b"..x\r\n"[..]));
    }
}
