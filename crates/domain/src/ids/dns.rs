//! DNS as Suricata reads it: each message a transaction side, and the
//! buffers and fields its `dns.*` keywords inspect filled the way Suricata
//! fills them.
//!
//! A name is its labels joined by dots, byte for byte: no case folding and
//! no escaping, a label holding a dot or a zero byte kept as it travelled.
//! What each buffer holds, and on which packet it is read, is held to
//! Suricata by `tests/fixtures/suricata/dns-verdicts.txt`.

use std::sync::Arc;

use super::tx::{Fields, Ready};

/// The most compression pointers one name may follow.
const JUMPS: usize = 64;

/// The longest name decoded; a longer one stops the message.
const NAME_LIMIT: usize = 1024;

/// The longest message a TCP direction waits for, the length prefix's
/// largest value.
const TCP_LIMIT: usize = 2 + u16::MAX as usize;

/// One resource record.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Record {
    name: Vec<u8>,
    kind: u16,
    /// The name the data carries, for the types whose target Suricata reads
    /// into `dns.response.rrname`: NS, CNAME, PTR, MX and the SOA's primary
    /// server.
    target: Option<Vec<u8>>,
}

/// A parsed message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    opcode: u8,
    rcode: u8,
    /// Each question's name and type.
    questions: Vec<(Vec<u8>, u16)>,
    /// The answers, authorities and additionals.
    sections: [Vec<Record>; 3],
}

/// The section buffers, answers then authorities then additionals.
const SECTIONS: [&str; 3] = [
    "dns.answers.rrname",
    "dns.authorities.rrname",
    "dns.additionals.rrname",
];

impl Message {
    /// The buffers of the message sent by `side`: the request's when the
    /// client sent it, the response's when the server did.
    #[must_use]
    pub fn fields(&self, side: usize) -> Fields {
        let mut fields = Fields::default();
        for (name, kind) in &self.questions {
            if side == 0 {
                fields.put("dns.query", name.clone());
                fields.put_int("dns.rrtype", u64::from(*kind));
            }
            fields.put("dns.queries.rrname", name.clone());
        }
        for (buffer, records) in SECTIONS.iter().zip(&self.sections) {
            for record in records {
                fields.put(buffer, record.name.clone());
            }
        }
        if side == 1 {
            for (name, _) in &self.questions {
                fields.put("dns.response.rrname", name.clone());
            }
            for record in self.sections.iter().flatten() {
                fields.put("dns.response.rrname", record.name.clone());
                if let Some(target) = &record.target {
                    fields.put("dns.response.rrname", target.clone());
                }
            }
            for record in &self.sections[0] {
                fields.put_int("dns.rrtype", u64::from(record.kind));
            }
        }
        fields.put_int("dns.opcode", u64::from(self.opcode));
        fields.put_int("dns.rcode", u64::from(self.rcode));
        fields
    }
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    let pair = bytes.get(at..at.checked_add(2)?)?;
    Some(u16::from_be_bytes([pair[0], pair[1]]))
}

/// The name starting at `at`, and where the bytes after it start, pointers
/// followed through the whole message.
fn name_at(message: &[u8], at: usize) -> Option<(Vec<u8>, usize)> {
    let mut name = Vec::new();
    let mut pos = at;
    let mut end = None;
    let mut jumps = 0;
    loop {
        let len = *message.get(pos)?;
        match len & 0xc0 {
            0x00 if len == 0 => {
                return Some((name, end.unwrap_or(pos + 1)));
            }
            0x00 => {
                let label = message.get(pos + 1..pos + 1 + usize::from(len))?;
                if !name.is_empty() {
                    name.push(b'.');
                }
                name.extend_from_slice(label);
                if name.len() > NAME_LIMIT {
                    return None;
                }
                pos += 1 + usize::from(len);
            }
            0xc0 => {
                let target = usize::from(u16_at(message, pos)? & 0x3fff);
                end.get_or_insert(pos + 2);
                jumps += 1;
                if jumps > JUMPS {
                    return None;
                }
                pos = target;
            }
            _ => return None,
        }
    }
}

/// Parse a whole message, `None` when it is cut short or malformed: what
/// Suricata does not take for DNS.
#[must_use]
pub fn parse(message: &[u8]) -> Option<Message> {
    let flags = u16_at(message, 2)?;
    let counts = [
        u16_at(message, 4)?,
        u16_at(message, 6)?,
        u16_at(message, 8)?,
        u16_at(message, 10)?,
    ];
    let mut pos = 12;
    let mut questions = Vec::new();
    for _ in 0..counts[0] {
        let (name, next) = name_at(message, pos)?;
        let kind = u16_at(message, next)?;
        u16_at(message, next + 2)?;
        questions.push((name, kind));
        pos = next + 4;
    }
    let mut sections: [Vec<Record>; 3] = Default::default();
    for (section, &count) in sections.iter_mut().zip(&counts[1..]) {
        for _ in 0..count {
            let (name, next) = name_at(message, pos)?;
            let kind = u16_at(message, next)?;
            let length = usize::from(u16_at(message, next + 8)?);
            let data = next + 10;
            message.get(data..data + length)?;
            let target = match kind {
                2 | 5 | 6 | 12 => name_at(message, data).map(|(n, _)| n),
                15 => name_at(message, data + 2).map(|(n, _)| n),
                _ => None,
            };
            section.push(Record { name, kind, target });
            pos = data + length;
        }
    }
    let opcode = u8::try_from((flags >> 11) & 0xf).unwrap_or_default();
    let rcode = u8::try_from(flags & 0xf).unwrap_or_default();
    Some(Message {
        opcode,
        rcode,
        questions,
        sections,
    })
}

/// A connection's DNS: the messages each direction sent, a TCP direction's
/// bytes held until a whole length-prefixed message is in.
#[derive(Debug, Clone, Default)]
pub struct Dns {
    held: [Vec<u8>; 2],
    next: [u64; 2],
}

impl Dns {
    /// One message, a UDP datagram or a TCP message with its length prefix
    /// as `payload`, sent by `side`.
    fn ready(&mut self, side: usize, message: &[u8], payload: &[u8]) -> Option<Ready> {
        let parsed = parse(message)?;
        let id = self.next[side];
        self.next[side] += 1;
        Some(Ready {
            id,
            side,
            fields: Arc::new(parsed.fields(side)),
            payload: Arc::from(payload),
            whole: true,
            latest: false,
            last: false,
        })
    }

    /// A datagram `side` sent.
    pub fn datagram(&mut self, side: usize, bytes: &[u8]) -> Vec<Ready> {
        self.ready(side, bytes, bytes).into_iter().collect()
    }

    /// Bytes of `side`'s TCP stream, in order: each whole message they
    /// complete.
    pub fn stream(&mut self, side: usize, bytes: &[u8]) -> Vec<Ready> {
        let mut held = std::mem::take(&mut self.held[side]);
        held.extend_from_slice(bytes);
        let mut out = Vec::new();
        let mut start = 0;
        while let Some(len) = u16_at(&held, start).map(usize::from) {
            let Some(message) = held.get(start + 2..start + 2 + len) else {
                break;
            };
            let payload = &held[start..start + 2 + len];
            out.extend(self.ready(side, message, payload));
            start += 2 + len;
        }
        held.drain(..start);
        held.truncate(TCP_LIMIT);
        self.held[side] = held;
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(labels: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for label in labels {
            out.push(u8::try_from(label.len()).expect("short label"));
            out.extend_from_slice(label);
        }
        out.push(0);
        out
    }

    fn query(id: u16, names: &[Vec<u8>]) -> Vec<u8> {
        let mut out = vec![0, 0, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
        out[..2].copy_from_slice(&id.to_be_bytes());
        out[4..6].copy_from_slice(&u16::try_from(names.len()).expect("few").to_be_bytes());
        for n in names {
            out.extend_from_slice(n);
            out.extend_from_slice(&[0, 1, 0, 1]);
        }
        out
    }

    fn all(fields: &Fields, buffer: &str) -> Vec<Vec<u8>> {
        (0..)
            .map_while(|i| fields.get(buffer, i).map(<[u8]>::to_vec))
            .collect()
    }

    #[test]
    fn names_are_read_byte_for_byte() {
        let q = query(
            1,
            &[
                name(&[b"Ex.ample", b"COM"]),
                name(&[b"a\x00b", b"test"]),
                vec![0],
            ],
        );
        let fields = parse(&q).expect("parses").fields(0);
        assert_eq!(
            all(&fields, "dns.query"),
            vec![b"Ex.ample.COM".to_vec(), b"a\x00b.test".to_vec()]
        );
        assert_eq!(fields.get("dns.response.rrname", 0), None);
    }

    #[test]
    fn pointers_are_followed_and_loops_refused() {
        let mut q = query(1, &[name(&[b"example", b"com"])]);
        q[5] = 2;
        q.extend_from_slice(&[4, b'c', b'o', b'm', b'p', 0xc0, 12, 0, 1, 0, 1]);
        let fields = parse(&q).expect("parses").fields(0);
        assert_eq!(all(&fields, "dns.query")[1], b"comp.example.com".to_vec());
        let mut looped = query(1, &[]);
        looped[5] = 1;
        looped.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1]);
        assert_eq!(parse(&looped), None);
    }

    #[test]
    fn a_message_cut_short_is_no_dns() {
        let q = query(1, &[name(&[b"example", b"com"])]);
        assert!(parse(&q[..q.len() - 1]).is_none());
        assert!(parse(&q[..11]).is_none());
    }

    #[test]
    fn a_response_names_its_targets() {
        let mut r = query(9, &[name(&[b"full", b"test"])]);
        r[2] = 0x81;
        r[3] = 0x83;
        r[7] = 2;
        let mut record = |owner: &[u8], kind: u16, data: &[u8]| {
            r.extend_from_slice(owner);
            r.extend_from_slice(&kind.to_be_bytes());
            r.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
            r.extend_from_slice(&u16::try_from(data.len()).expect("short").to_be_bytes());
            r.extend_from_slice(data);
        };
        record(&[0xc0, 12], 5, &name(&[b"target", b"test"]));
        record(
            &[0xc0, 12],
            33,
            &[&[0, 1, 0, 2, 0, 80][..], &name(&[b"srv"])].concat(),
        );
        let fields = parse(&r).expect("parses").fields(1);
        assert_eq!(
            all(&fields, "dns.response.rrname"),
            vec![
                b"full.test".to_vec(),
                b"full.test".to_vec(),
                b"target.test".to_vec(),
                b"full.test".to_vec()
            ]
        );
        let ints = |f: &str| {
            all(&fields, f)
                .iter()
                .filter_map(|b| super::super::tx::int_of(b))
                .collect::<Vec<_>>()
        };
        assert_eq!(ints("dns.rrtype"), vec![5, 33]);
        assert_eq!(ints("dns.rcode"), vec![3]);
        assert_eq!(ints("dns.opcode"), vec![0]);
        assert!(all(&fields, "dns.query").is_empty());
    }

    #[test]
    fn tcp_messages_are_cut_on_their_length_prefix() {
        let one = query(1, &[name(&[b"one", b"test"])]);
        let two = query(2, &[name(&[b"two", b"test"])]);
        let mut framed = Vec::new();
        for m in [&one, &two] {
            framed.extend_from_slice(&u16::try_from(m.len()).expect("short").to_be_bytes());
            framed.extend_from_slice(m);
        }
        let mut dns = Dns::default();
        assert!(dns.stream(0, &framed[..5]).is_empty());
        let ready = dns.stream(0, &framed[5..]);
        assert_eq!(ready.iter().map(|r| r.id).collect::<Vec<_>>(), vec![0, 1]);
        assert_eq!(ready[1].fields.get("dns.query", 0), Some(&b"two.test"[..]));
        assert_eq!(&ready[0].payload[2..], &one[..]);
    }
}
