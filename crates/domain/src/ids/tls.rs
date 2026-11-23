//! The TLS handshake read as Suricata reads it, into the buffers a rule
//! names: the server name, the certificates, the hello randoms, the JA3,
//! JA3S and JA4 fingerprints, the version and the handshake state.
//!
//! The connection is one transaction whose two sides grow as the handshake
//! goes: every time a direction's bytes are read, both sides are offered
//! again as they now stand, and a side waiting for its next packet is
//! replaced by the newer one. Records are read until the direction changes
//! cipher; what follows is encrypted and only counted.

use std::sync::Arc;

use md5::{Digest, Md5};
use sha1::Sha1;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};

use super::tx::{Fields, Ready};
use crate::l7::entity::TlsClientHello;
use crate::l7::ja4::compute_ja4;

/// The most handshake bytes a direction holds while a message is
/// incomplete: a certificate chain fits several times over.
const HANDSHAKE_LIMIT: usize = 256 * 1024;

/// The most record bytes a side keeps for a rule that reads the payload
/// beside the handshake's buffers.
const PAYLOAD_LIMIT: usize = 64 * 1024;

/// The handshake state flags `ssl_state` names.
pub const STATE_CLIENT_HELLO: u64 = 1;
pub const STATE_SERVER_HELLO: u64 = 2;
pub const STATE_CLIENT_KEYX: u64 = 4;
pub const STATE_SERVER_KEYX: u64 = 8;

/// What one direction of the handshake carried.
#[derive(Debug, Clone, Default)]
#[allow(clippy::struct_excessive_bools)]
struct Side {
    /// Bytes not yet making a whole record header.
    records: Vec<u8>,
    /// What remains of the record being read, and whether it is a handshake
    /// record.
    remaining: usize,
    handshake_record: bool,
    /// Handshake bytes not yet making a whole message.
    handshake: Vec<u8>,
    /// The direction changed cipher: what follows is not read.
    encrypted: bool,
    /// The record bytes as they travelled, up to [`PAYLOAD_LIMIT`].
    payload: Vec<u8>,
    /// The protocol version: the first record's, then the hello's, then the
    /// one the supported versions name.
    version: u16,
    hello: bool,
    sni: Option<Vec<u8>>,
    random: Option<[u8; 32]>,
    alpn: Vec<Vec<u8>>,
    ja3: Option<String>,
    ja4: Option<String>,
    certs: Vec<Vec<u8>>,
    /// The chain's length is known: the certificates were read, or the
    /// server ended its hello or changed cipher without sending any.
    chain_known: bool,
}

/// The TLS parser of one connection, client first.
#[derive(Debug, Clone, Default)]
pub struct Tls {
    sides: [Side; 2],
    /// The last handshake message that moved the state.
    state: u64,
    /// The server's handshake reached a second read: the state no longer
    /// moves, which is when Suricata stops moving it.
    frozen: bool,
    server_reads: u8,
    /// Each side's part of the handshake is over: it changed cipher, or
    /// the server chose TLS 1.3, after which neither side's handshake is
    /// read in the clear.
    finished: [bool; 2],
}

impl Tls {
    /// Read the bytes `side` sent, in order, and offer both sides as they
    /// now stand.
    pub fn feed(&mut self, side: usize, bytes: &[u8]) -> Vec<Ready> {
        if self.sides[0].encrypted && self.sides[1].encrypted {
            return Vec::new();
        }
        let mut read = false;
        self.sides[side].records.extend_from_slice(bytes);
        loop {
            let dir = &mut self.sides[side];
            if dir.encrypted {
                dir.records.clear();
                break;
            }
            if dir.remaining > 0 {
                let take = dir.remaining.min(dir.records.len());
                if take == 0 {
                    break;
                }
                let body: Vec<u8> = dir.records.drain(..take).collect();
                dir.remaining -= take;
                keep(&mut dir.payload, &body);
                if dir.handshake_record {
                    dir.handshake.extend_from_slice(&body);
                    if dir.handshake.len() > HANDSHAKE_LIMIT {
                        dir.handshake.clear();
                    }
                    read |= self.messages(side);
                }
                continue;
            }
            if dir.records.len() < 5 {
                break;
            }
            let kind = dir.records[0];
            let version = u16::from_be_bytes([dir.records[1], dir.records[2]]);
            if !(20..=23).contains(&kind) || dir.records[1] != 3 && version != 0x0200 {
                dir.encrypted = true;
                break;
            }
            let header: Vec<u8> = dir.records.drain(..5).collect();
            keep(&mut dir.payload, &header);
            if dir.version == 0 {
                dir.version = version;
            }
            dir.remaining = usize::from(u16::from_be_bytes([header[3], header[4]]));
            dir.handshake_record = kind == 22;
            read = true;
            if kind == 20 {
                dir.encrypted = true;
                self.finished[side] = true;
                if side == 1 {
                    dir.chain_known = true;
                } else if !self.frozen {
                    // The client's change of cipher ends the state the
                    // handshake stood in, as Suricata reads it.
                    self.state = 0;
                }
            }
        }
        if read && side == 1 {
            self.server_reads = self.server_reads.saturating_add(1);
        }
        vec![self.ready(0), self.ready(1)]
    }

    /// Read the whole handshake messages `side` holds; whether any was read.
    fn messages(&mut self, side: usize) -> bool {
        let mut read = false;
        loop {
            let hs = &self.sides[side].handshake;
            if hs.len() < 4 {
                return read;
            }
            let len = (usize::from(hs[1]) << 16) | (usize::from(hs[2]) << 8) | usize::from(hs[3]);
            if hs.len() < 4 + len {
                return read;
            }
            let message: Vec<u8> = self.sides[side].handshake.drain(..4 + len).collect();
            read = true;
            if side == 1 && self.server_reads > 0 {
                self.frozen = true;
            }
            self.message(side, message[0], &message[4..]);
            if self.sides[side].encrypted {
                self.sides[side].handshake.clear();
                return read;
            }
        }
    }

    fn message(&mut self, side: usize, kind: u8, body: &[u8]) {
        let state = match kind {
            1 if side == 0 => {
                if let Some(hello) = client_hello(body) {
                    self.client_hello(&hello);
                }
                Some(STATE_CLIENT_HELLO)
            }
            2 if side == 1 => {
                self.server_hello(body);
                Some(STATE_SERVER_HELLO)
            }
            11 => {
                self.sides[side].certs = certificates(body);
                if side == 1 {
                    self.sides[1].chain_known = true;
                }
                None
            }
            12 if side == 1 => Some(STATE_SERVER_KEYX),
            14 if side == 1 => {
                self.sides[1].chain_known = true;
                None
            }
            16 if side == 0 => Some(STATE_CLIENT_KEYX),
            _ => None,
        };
        if let Some(state) = state
            && !self.frozen
        {
            self.state = state;
        }
    }

    fn client_hello(&mut self, hello: &Hello) {
        let dir = &mut self.sides[0];
        dir.hello = true;
        dir.version = hello.version;
        if let Some(&v) = hello.supported_versions.first() {
            dir.version = v;
        }
        dir.random = Some(hello.random);
        dir.sni.clone_from(&hello.sni);
        dir.alpn.clone_from(&hello.alpn);
        let groups = dashed(&hello.groups);
        dir.ja3 = Some(format!(
            "{},{},{},{groups},{}",
            hello.version,
            dashed(&hello.ciphers),
            dashed(&hello.extensions),
            hello
                .point_formats
                .iter()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join("-"),
        ));
        let alpn = hello
            .alpn
            .iter()
            .map(|p| String::from_utf8_lossy(p).into_owned())
            .collect();
        let ja4 = compute_ja4(&TlsClientHello {
            sni: hello
                .sni
                .as_ref()
                .map(|s| String::from_utf8_lossy(s).into_owned()),
            record_version: 0,
            handshake_version: hello.version,
            cipher_suites: hello.ciphers.clone(),
            extension_types: hello.extensions.clone(),
            supported_groups: hello.groups.clone(),
            signature_algorithms: hello.signature_algorithms.clone(),
            alpn_protocols: alpn,
            supported_versions: hello.supported_versions.clone(),
            session_id: None,
        });
        dir.ja4 = Some(ja4.ja4);
    }

    fn server_hello(&mut self, body: &[u8]) {
        let Some(hello) = server_hello(body) else {
            return;
        };
        let dir = &mut self.sides[1];
        dir.hello = true;
        dir.version = hello.selected.unwrap_or(hello.version);
        dir.random = Some(hello.random);
        dir.alpn = hello.alpn.into_iter().collect();
        dir.ja3 = Some(format!(
            "{},{},{}",
            hello.version,
            hello.cipher,
            dashed(&hello.extensions)
        ));
        if hello.selected == Some(0x0304) {
            dir.encrypted = true;
            dir.chain_known = true;
            self.finished = [true; 2];
        }
    }

    /// One side as it now stands.
    fn ready(&self, side: usize) -> Ready {
        let dir = &self.sides[side];
        let mut fields = Fields::default();
        fields.put_int("ssl_state", self.state);
        if dir.version != 0 {
            fields.put_int("tls.version", u64::from(dir.version));
        }
        if let Some(sni) = &dir.sni {
            fields.put("tls.sni", sni.clone());
        }
        for proto in &dir.alpn {
            fields.put("tls.alpn", proto.clone());
        }
        if let Some(random) = dir.random
            && (side == 0 || self.sides[0].hello)
        {
            fields.put("tls.random", random.to_vec());
            fields.put("tls.random_time", random[..4].to_vec());
            fields.put("tls.random_bytes", random[4..].to_vec());
        }
        if let Some(ja3) = &dir.ja3 {
            let (hash, string) = if side == 0 {
                ("ja3.hash", "ja3.string")
            } else {
                ("ja3s.hash", "ja3s.string")
            };
            fields.put(hash, hex(&Md5::digest(ja3.as_bytes()), "").into_bytes());
            fields.put(string, ja3.clone().into_bytes());
        }
        if let Some(ja4) = &dir.ja4 {
            fields.put("ja4.hash", ja4.clone().into_bytes());
        }
        if side == 1 && dir.chain_known {
            fields.put_int("tls.cert_chain_len", dir.certs.len() as u64);
        }
        for cert in &dir.certs {
            fields.put("tls.certs", cert.clone());
        }
        if let Some(leaf) = dir.certs.first() {
            leaf_fields(&mut fields, leaf);
        }
        Ready {
            id: 0,
            side,
            fields: Arc::new(fields),
            payload: Arc::from(dir.payload.as_slice()),
            latest: true,
            last: self.finished[side],
        }
    }
}

fn keep(payload: &mut Vec<u8>, bytes: &[u8]) {
    let room = PAYLOAD_LIMIT.saturating_sub(payload.len());
    payload.extend_from_slice(&bytes[..bytes.len().min(room)]);
}

/// The buffers read off the first certificate of a side.
fn leaf_fields(fields: &mut Fields, der: &[u8]) {
    fields.put(
        "tls.cert_fingerprint",
        hex(&Sha1::digest(der), ":").into_bytes(),
    );
    let Ok((_, cert)) = X509Certificate::from_der(der) else {
        return;
    };
    fields.put("tls.cert_subject", cert.subject().to_string().into_bytes());
    fields.put("tls.cert_issuer", cert.issuer().to_string().into_bytes());
    fields.put(
        "tls.cert_serial",
        hex(cert.raw_serial(), ":").to_uppercase().into_bytes(),
    );
    let validity = cert.validity();
    fields.put_int(
        "tls_cert_notbefore",
        u64::try_from(validity.not_before.timestamp()).unwrap_or(0),
    );
    fields.put_int(
        "tls_cert_notafter",
        u64::try_from(validity.not_after.timestamp()).unwrap_or(0),
    );
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in &san.value.general_names {
            match name {
                GeneralName::DNSName(dns) => {
                    fields.put("tls.subjectaltname", dns.as_bytes().to_vec());
                }
                GeneralName::IPAddress(ip) => {
                    fields.put("tls.subjectaltname", format!("{ip:?}").into_bytes());
                }
                _ => {}
            }
        }
    }
}

fn hex(bytes: &[u8], sep: &str) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(sep)
}

fn dashed(values: &[u16]) -> String {
    values
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join("-")
}

/// A value TLS reserves so that a peer learns to ignore what it does not
/// know; fingerprints leave it out.
fn grease(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a && value >> 8 == value & 0xff
}

/// A cursor over a handshake message.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Some(head)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }

    fn u24(&mut self) -> Option<usize> {
        self.take(3)
            .map(|b| (usize::from(b[0]) << 16) | (usize::from(b[1]) << 8) | usize::from(b[2]))
    }

    fn vec8(&mut self) -> Option<&'a [u8]> {
        let n = self.u8()?;
        self.take(usize::from(n))
    }

    fn vec16(&mut self) -> Option<&'a [u8]> {
        let n = self.u16()?;
        self.take(usize::from(n))
    }

    fn u16s(data: &[u8]) -> Vec<u16> {
        data.as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_be_bytes(*c))
            .collect()
    }
}

/// What a client hello offers, GREASE left out.
#[derive(Debug, Default)]
struct Hello {
    version: u16,
    random: [u8; 32],
    ciphers: Vec<u16>,
    extensions: Vec<u16>,
    groups: Vec<u16>,
    point_formats: Vec<u8>,
    signature_algorithms: Vec<u16>,
    supported_versions: Vec<u16>,
    sni: Option<Vec<u8>>,
    alpn: Vec<Vec<u8>>,
}

fn random(r: &mut Reader<'_>) -> Option<[u8; 32]> {
    r.take(32)?.try_into().ok()
}

fn alpn_list(data: &[u8]) -> Vec<Vec<u8>> {
    let mut r = Reader(data);
    let mut out = Vec::new();
    if let Some(list) = r.vec16() {
        let mut l = Reader(list);
        while let Some(p) = l.vec8() {
            out.push(p.to_vec());
        }
    }
    out
}

fn client_hello(body: &[u8]) -> Option<Hello> {
    let mut r = Reader(body);
    let mut hello = Hello {
        version: r.u16()?,
        random: random(&mut r)?,
        ..Hello::default()
    };
    r.vec8()?;
    hello.ciphers = Reader::u16s(r.vec16()?)
        .into_iter()
        .filter(|c| !grease(*c))
        .collect();
    r.vec8()?;
    let Some(extensions) = r.vec16() else {
        return Some(hello);
    };
    let mut e = Reader(extensions);
    while let (Some(kind), Some(data)) = (e.u16(), e.vec16()) {
        if grease(kind) {
            continue;
        }
        hello.extensions.push(kind);
        let mut d = Reader(data);
        match kind {
            0 => {
                let mut list = Reader(d.vec16().unwrap_or_default());
                while let (Some(name_type), Some(name)) = (list.u8(), list.vec16()) {
                    if name_type == 0 {
                        hello.sni = Some(name.to_vec());
                        break;
                    }
                }
            }
            10 => {
                hello.groups = Reader::u16s(d.vec16().unwrap_or_default())
                    .into_iter()
                    .filter(|g| !grease(*g))
                    .collect();
            }
            11 => hello.point_formats = d.vec8().unwrap_or_default().to_vec(),
            13 => hello.signature_algorithms = Reader::u16s(d.vec16().unwrap_or_default()),
            16 => hello.alpn = alpn_list(data),
            43 => {
                hello.supported_versions = Reader::u16s(d.vec8().unwrap_or_default())
                    .into_iter()
                    .filter(|v| !grease(*v))
                    .collect();
            }
            _ => {}
        }
    }
    Some(hello)
}

/// What a server hello settles on.
struct ServerHello {
    version: u16,
    random: [u8; 32],
    cipher: u16,
    extensions: Vec<u16>,
    selected: Option<u16>,
    alpn: Option<Vec<u8>>,
}

fn server_hello(body: &[u8]) -> Option<ServerHello> {
    let mut r = Reader(body);
    let version = r.u16()?;
    let random = random(&mut r)?;
    r.vec8()?;
    let cipher = r.u16()?;
    r.u8()?;
    let mut hello = ServerHello {
        version,
        random,
        cipher,
        extensions: Vec::new(),
        selected: None,
        alpn: None,
    };
    let Some(extensions) = r.vec16() else {
        return Some(hello);
    };
    let mut e = Reader(extensions);
    while let (Some(kind), Some(data)) = (e.u16(), e.vec16()) {
        if grease(kind) {
            continue;
        }
        hello.extensions.push(kind);
        match kind {
            16 => hello.alpn = alpn_list(data).into_iter().next(),
            43 => hello.selected = Reader(data).u16(),
            _ => {}
        }
    }
    Some(hello)
}

/// The certificates of a Certificate message, in order; the TLS 1.3 form,
/// with a request context and per-certificate extensions, is read too.
fn certificates(body: &[u8]) -> Vec<Vec<u8>> {
    let mut r = Reader(body);
    let mut out = Vec::new();
    let Some(total) = r.u24() else {
        return out;
    };
    let Some(list) = r.take(total) else {
        return out;
    };
    let mut l = Reader(list);
    while let Some(len) = l.u24() {
        let Some(der) = l.take(len) else {
            break;
        };
        out.push(der.to_vec());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(kind: u8, version: u16, body: &[u8]) -> Vec<u8> {
        let mut out = vec![kind];
        out.extend_from_slice(&version.to_be_bytes());
        out.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    fn message(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![kind];
        out.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes()[1..]);
        out.extend_from_slice(body);
        out
    }

    fn extension(kind: u16, body: &[u8]) -> Vec<u8> {
        let mut out = kind.to_be_bytes().to_vec();
        out.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    fn hello() -> Vec<u8> {
        let name = b"Leaf.Example.TEST";
        let mut host = vec![0];
        host.extend_from_slice(&u16::try_from(name.len()).unwrap().to_be_bytes());
        host.extend_from_slice(name);
        let mut sni = u16::try_from(host.len()).unwrap().to_be_bytes().to_vec();
        sni.extend_from_slice(&host);
        let ext = [
            extension(0x0a0a, b""),
            extension(0, &sni),
            extension(10, &[0, 6, 0x1a, 0x1a, 0, 29, 0, 23]),
            extension(11, &[1, 0]),
            extension(13, &[0, 4, 4, 3, 8, 4]),
            extension(16, b"\x00\x03\x02h2"),
        ]
        .concat();
        let mut body = vec![3, 3];
        body.extend((0x40..0x60).collect::<Vec<u8>>());
        body.extend_from_slice(&[0, 0, 6, 0x2a, 0x2a, 0xc0, 0x2f, 0, 0x2f, 1, 0]);
        body.extend_from_slice(&u16::try_from(ext.len()).unwrap().to_be_bytes());
        body.extend_from_slice(&ext);
        message(1, &body)
    }

    fn server() -> Vec<u8> {
        let ext = extension(0xff01, &[0]);
        let mut body = vec![3, 3];
        body.extend((0xa0..0xc0).collect::<Vec<u8>>());
        body.extend_from_slice(&[0, 0xc0, 0x2f, 0]);
        body.extend_from_slice(&u16::try_from(ext.len()).unwrap().to_be_bytes());
        body.extend_from_slice(&ext);
        record(22, 0x0303, &[message(2, &body), message(14, b"")].concat())
    }

    fn get<'a>(ready: &'a Ready, name: &str) -> Option<&'a [u8]> {
        ready.fields.get(name, 0)
    }

    fn int(ready: &Ready, name: &str) -> Option<u64> {
        get(ready, name).and_then(super::super::tx::int_of)
    }

    #[test]
    fn a_client_hello_gives_its_name_fingerprints_and_random() {
        let mut tls = Tls::default();
        let out = tls.feed(0, &record(22, 0x0301, &hello()));
        assert_eq!(out.len(), 2);
        let client = &out[0];
        assert_eq!(get(client, "tls.sni"), Some(&b"Leaf.Example.TEST"[..]));
        assert_eq!(
            get(client, "ja3.string"),
            Some(&b"771,49199-47,0-10-11-13-16,29-23,0"[..])
        );
        assert_eq!(
            get(client, "ja3.hash"),
            Some(&b"f8ec247b167c2a862ce2004b13b0321f"[..])
        );
        assert_eq!(
            get(client, "ja4.hash"),
            Some(&b"t12d0205h2_37f356531c84_876bcc86782c"[..])
        );
        assert_eq!(
            get(client, "tls.random_time"),
            Some(&[0x40, 0x41, 0x42, 0x43][..])
        );
        assert_eq!(get(client, "tls.alpn"), Some(&b"h2"[..]));
        assert_eq!(int(client, "tls.version"), Some(0x0303));
        assert_eq!(int(client, "ssl_state"), Some(STATE_CLIENT_HELLO));
        assert_eq!(int(&out[1], "ssl_state"), Some(STATE_CLIENT_HELLO));
        assert!(out.iter().all(|r| r.latest && r.id == 0));
    }

    #[test]
    fn a_hello_split_over_records_and_segments_is_read_whole() {
        let h = hello();
        let wire = [record(22, 0x0301, &h[..30]), record(22, 0x0301, &h[30..])].concat();
        let mut tls = Tls::default();
        let first = tls.feed(0, &wire[..12]);
        assert_eq!(int(&first[0], "tls.version"), Some(0x0301));
        assert!(get(&first[0], "tls.sni").is_none());
        let second = tls.feed(0, &wire[12..]);
        assert_eq!(get(&second[0], "tls.sni"), Some(&b"Leaf.Example.TEST"[..]));
        assert_eq!(second[0].payload.as_ref(), wire.as_slice());
    }

    #[test]
    fn the_server_hello_gives_ja3s_and_a_chain_of_none() {
        let mut tls = Tls::default();
        tls.feed(0, &record(22, 0x0301, &hello()));
        let out = tls.feed(1, &server());
        let server = &out[1];
        assert_eq!(get(server, "ja3s.string"), Some(&b"771,49199,65281"[..]));
        assert_eq!(int(server, "tls.cert_chain_len"), Some(0));
        assert_eq!(
            get(server, "tls.random_time"),
            Some(&[0xa0, 0xa1, 0xa2, 0xa3][..])
        );
        assert_eq!(int(server, "ssl_state"), Some(STATE_SERVER_HELLO));
        assert!(int(&out[0], "tls.cert_chain_len").is_none());
    }

    #[test]
    fn the_server_random_waits_for_the_client_hello() {
        let mut tls = Tls::default();
        let out = tls.feed(1, &server());
        assert!(get(&out[1], "ja3s.hash").is_some());
        assert!(get(&out[1], "tls.random").is_none());
    }

    #[test]
    fn a_second_read_of_the_server_freezes_the_state() {
        let mut tls = Tls::default();
        tls.feed(0, &record(22, 0x0301, &hello()));
        let sh = server();
        tls.feed(1, &sh[..20]);
        let out = tls.feed(1, &sh[20..]);
        assert_eq!(int(&out[1], "ssl_state"), Some(STATE_CLIENT_HELLO));
    }

    #[test]
    fn a_change_of_cipher_stops_the_reading() {
        let mut tls = Tls::default();
        let wire = [record(20, 0x0303, &[1]), record(22, 0x0303, &hello())].concat();
        let out = tls.feed(0, &wire);
        assert!(get(&out[0], "tls.sni").is_none());
    }

    #[test]
    fn grease_is_every_reserved_value() {
        assert!(grease(0x0a0a) && grease(0xfafa) && grease(0x2a2a));
        assert!(!grease(0x0a1a) && !grease(0x002f));
    }
}
