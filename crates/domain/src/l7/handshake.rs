//! What a TLS handshake negotiated, read off the server's first flight.
//!
//! The `ServerHello` is in clear in every version: it names the protocol
//! version, the cipher suite and, in TLS 1.3, the key exchange group in its
//! `key_share`. In TLS 1.2 the group is in the `ServerKeyExchange` of an
//! ECDHE suite and the certificate travels in clear, so its validity window
//! can be read too. In TLS 1.3 the certificate is encrypted and the record
//! says so rather than leaving an empty field that reads as a healthy one.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use super::parser::parse_tls_server_hello;

/// TLS 1.3 on the wire, as `supported_versions` carries it.
pub const TLS_1_3: u16 = 0x0304;
/// TLS 1.2 on the wire.
pub const TLS_1_2: u16 = 0x0303;

/// The fixed random of a `HelloRetryRequest` (RFC 8446 section 4.1.3): a
/// `ServerHello` carrying it asks the client for another group and settles
/// nothing.
const HELLO_RETRY_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

const HS_SERVER_HELLO: u8 = 0x02;
const HS_CERTIFICATE: u8 = 0x0b;
const HS_SERVER_KEY_EXCHANGE: u8 = 0x0c;
const HS_SERVER_HELLO_DONE: u8 = 0x0e;
const RECORD_HANDSHAKE: u8 = 0x16;
/// `ECCurveType.named_curve` (RFC 8422 section 5.4).
const NAMED_CURVE: u8 = 0x03;

/// What can be said about the server's certificate from the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum CertificateValidity {
    /// TLS 1.3 encrypts the certificate: nothing about it can be read.
    NotObservable,
    /// TLS 1.2, but the certificate was not in the bytes the agent read: a
    /// resumed session sends none, and a long chain can start beyond them.
    NotCaptured,
    /// The leaf certificate's validity window, in seconds since the epoch.
    Window { not_before: i64, not_after: i64 },
}

/// How the key exchange resists a quantum adversary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyExchangeClass {
    /// A classical group combined with ML-KEM: safe if either half holds.
    PostQuantumHybrid,
    /// ML-KEM alone.
    PostQuantum,
    /// Elliptic curve or finite field Diffie-Hellman alone.
    Classical,
    /// The client encrypts the secret to the certificate's RSA key: no
    /// forward secrecy and no group at all.
    RsaKeyTransport,
    /// A group or a suite this agent does not name.
    Unknown,
}

/// The posture a handshake gives its flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CryptoPosture {
    /// TLS 1.2 or 1.3 over a post-quantum or hybrid group.
    PostQuantum,
    /// TLS 1.2 or 1.3 over a classical exchange.
    Classical,
    /// Below TLS 1.2, whatever the exchange.
    LegacyTls,
}

/// What one handshake negotiated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsHandshake {
    /// The negotiated version, from `supported_versions` when present.
    pub version: u16,
    /// The selected cipher suite.
    pub cipher: u16,
    /// The selected key exchange group, absent when the exchange has none or
    /// it was not in the bytes read.
    pub group: Option<u16>,
    pub certificate: CertificateValidity,
}

impl TlsHandshake {
    /// How the key exchange holds against a quantum adversary.
    pub fn key_exchange(&self) -> KeyExchangeClass {
        if let Some(group) = self.group {
            return group_class(group);
        }
        if self.version < TLS_1_3 && cipher_key_exchange(self.cipher) == Some(SuiteExchange::Rsa) {
            return KeyExchangeClass::RsaKeyTransport;
        }
        KeyExchangeClass::Unknown
    }

    /// The posture this handshake gives its flow.
    pub fn posture(&self) -> CryptoPosture {
        if self.version < TLS_1_2 {
            return CryptoPosture::LegacyTls;
        }
        match self.key_exchange() {
            KeyExchangeClass::PostQuantumHybrid | KeyExchangeClass::PostQuantum => {
                CryptoPosture::PostQuantum
            }
            _ => CryptoPosture::Classical,
        }
    }
}

/// Read what a handshake negotiated from the start of a server's flight.
///
/// Returns `None` when the payload does not start with a `ServerHello`, and
/// for a `HelloRetryRequest`, which settles nothing.
pub fn read_server_flight(payload: &[u8]) -> Option<TlsHandshake> {
    let hello = parse_tls_server_hello(payload).ok()?;
    let stream = handshake_stream(payload);
    let mut messages = HandshakeMessages::new(&stream);
    let (kind, body) = messages.next()?;
    if kind != HS_SERVER_HELLO || body.get(2..34).is_some_and(|r| r == HELLO_RETRY_RANDOM) {
        return None;
    }

    if hello.selected_version >= TLS_1_3 {
        return Some(TlsHandshake {
            version: hello.selected_version,
            cipher: hello.selected_cipher,
            group: hello.selected_group,
            certificate: CertificateValidity::NotObservable,
        });
    }

    let mut certificate = CertificateValidity::NotCaptured;
    let mut group = None;
    for (kind, body) in messages {
        match kind {
            HS_CERTIFICATE => {
                if let Some((not_before, not_after)) = leaf_validity(body) {
                    certificate = CertificateValidity::Window {
                        not_before,
                        not_after,
                    };
                }
            }
            HS_SERVER_KEY_EXCHANGE
                if cipher_key_exchange(hello.selected_cipher) == Some(SuiteExchange::Ecdhe) =>
            {
                if body.len() >= 3 && body[0] == NAMED_CURVE {
                    group = Some(u16::from_be_bytes([body[1], body[2]]));
                }
            }
            HS_SERVER_HELLO_DONE => break,
            _ => {}
        }
    }

    Some(TlsHandshake {
        version: hello.selected_version,
        cipher: hello.selected_cipher,
        group,
        certificate,
    })
}

/// The handshake bytes of every leading handshake record, concatenated, so a
/// message split across records reads as one.
fn handshake_stream(payload: &[u8]) -> Vec<u8> {
    let mut stream = Vec::with_capacity(payload.len());
    let mut pos = 0;
    while pos + 5 <= payload.len() && payload[pos] == RECORD_HANDSHAKE {
        let len = usize::from(u16::from_be_bytes([payload[pos + 3], payload[pos + 4]]));
        let start = pos + 5;
        let end = (start + len).min(payload.len());
        stream.extend_from_slice(&payload[start..end]);
        pos = start + len;
    }
    stream
}

/// The handshake messages in a stream, each as its type and its body. A
/// message cut short by the end of the captured bytes is yielded with the
/// part that was read, so a parser can take what it needs from its head.
struct HandshakeMessages<'a> {
    stream: &'a [u8],
    pos: usize,
}

impl<'a> HandshakeMessages<'a> {
    fn new(stream: &'a [u8]) -> Self {
        Self { stream, pos: 0 }
    }
}

impl<'a> Iterator for HandshakeMessages<'a> {
    type Item = (u8, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let head = self.stream.get(self.pos..self.pos + 4)?;
        let len = u24(&head[1..4]);
        let start = self.pos + 4;
        let end = (start + len).min(self.stream.len());
        self.pos = start + len;
        Some((head[0], &self.stream[start..end]))
    }
}

fn u24(bytes: &[u8]) -> usize {
    (usize::from(bytes[0]) << 16) | (usize::from(bytes[1]) << 8) | usize::from(bytes[2])
}

/// The validity window of the first certificate in a TLS 1.2 `Certificate`
/// message, which is the server's own.
fn leaf_validity(body: &[u8]) -> Option<(i64, i64)> {
    // certificate_list<0..2^24-1>, then the first ASN.1Cert<1..2^24-1>.
    let cert_len = u24(body.get(3..6)?);
    let cert = body.get(6..)?;
    let cert = &cert[..cert_len.min(cert.len())];

    // Certificate ::= SEQUENCE { tbsCertificate SEQUENCE { ... } ... }
    let (tag, outer, _) = der_element(cert, 0)?;
    if tag != 0x30 {
        return None;
    }
    let (tag, tbs, _) = der_element(cert, outer)?;
    if tag != 0x30 {
        return None;
    }
    let mut pos = tbs;
    // version [0] EXPLICIT, absent for a v1 certificate.
    if cert.get(pos) == Some(&0xA0) {
        pos = der_skip(cert, pos)?;
    }
    pos = der_skip(cert, pos)?; // serialNumber
    pos = der_skip(cert, pos)?; // signature
    pos = der_skip(cert, pos)?; // issuer
    let (tag, validity, _) = der_element(cert, pos)?;
    if tag != 0x30 {
        return None;
    }
    let (tag, start, len) = der_element(cert, validity)?;
    let not_before = der_time(tag, cert.get(start..start + len)?)?;
    let (tag, start, len) = der_element(cert, start + len)?;
    let not_after = der_time(tag, cert.get(start..start + len)?)?;
    Some((not_before, not_after))
}

/// The tag, the content offset and the content length of the DER element at
/// `pos`.
fn der_element(buf: &[u8], pos: usize) -> Option<(u8, usize, usize)> {
    let tag = *buf.get(pos)?;
    let first = *buf.get(pos + 1)?;
    if first & 0x80 == 0 {
        return Some((tag, pos + 2, usize::from(first)));
    }
    let count = usize::from(first & 0x7f);
    if count == 0 || count > 4 {
        return None;
    }
    let bytes = buf.get(pos + 2..pos + 2 + count)?;
    let len = bytes
        .iter()
        .fold(0usize, |acc, &b| (acc << 8) | usize::from(b));
    Some((tag, pos + 2 + count, len))
}

/// The offset just past the DER element at `pos`, when all of it was read.
fn der_skip(buf: &[u8], pos: usize) -> Option<usize> {
    let (_, start, len) = der_element(buf, pos)?;
    let end = start.checked_add(len)?;
    (end <= buf.len()).then_some(end)
}

/// A `UTCTime` (tag `0x17`) or `GeneralizedTime` (tag `0x18`) in UTC, as
/// seconds since the epoch.
fn der_time(tag: u8, text: &[u8]) -> Option<i64> {
    let digits = |s: &[u8]| -> Option<i64> {
        s.iter().try_fold(0i64, |acc, &c| {
            c.is_ascii_digit().then(|| acc * 10 + i64::from(c - b'0'))
        })
    };
    let (year, rest) = match tag {
        0x17 if text.len() >= 13 => {
            let yy = digits(&text[0..2])?;
            // RFC 5280 section 4.1.2.5.1: 50..99 is the twentieth century.
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &text[2..])
        }
        0x18 if text.len() >= 15 => (digits(&text[0..4])?, &text[4..]),
        _ => return None,
    };
    if rest.get(10) != Some(&b'Z') {
        return None;
    }
    let month = digits(&rest[0..2])?;
    let day = digits(&rest[2..4])?;
    let hour = digits(&rest[4..6])?;
    let minute = digits(&rest[6..8])?;
    let second = digits(&rest[8..10])?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 {
        return None;
    }
    if second > 60 {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second)
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's
/// algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// How a TLS 1.2 suite exchanges its key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SuiteExchange {
    Ecdhe,
    Dhe,
    Rsa,
    /// A TLS 1.3 suite, which names no exchange: the group does.
    Tls13,
}

/// The name and the exchange of the suites seen in practice.
const SUITES: &[(u16, &str, SuiteExchange)] = &[
    (0x1301, "TLS_AES_128_GCM_SHA256", SuiteExchange::Tls13),
    (0x1302, "TLS_AES_256_GCM_SHA384", SuiteExchange::Tls13),
    (0x1303, "TLS_CHACHA20_POLY1305_SHA256", SuiteExchange::Tls13),
    (0x1304, "TLS_AES_128_CCM_SHA256", SuiteExchange::Tls13),
    (0x1305, "TLS_AES_128_CCM_8_SHA256", SuiteExchange::Tls13),
    (
        0xC02B,
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        SuiteExchange::Ecdhe,
    ),
    (
        0xC02C,
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        SuiteExchange::Ecdhe,
    ),
    (
        0xC02F,
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        SuiteExchange::Ecdhe,
    ),
    (
        0xC030,
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        SuiteExchange::Ecdhe,
    ),
    (
        0xCCA8,
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        SuiteExchange::Ecdhe,
    ),
    (
        0xCCA9,
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        SuiteExchange::Ecdhe,
    ),
    (
        0xC009,
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        SuiteExchange::Ecdhe,
    ),
    (
        0xC00A,
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        SuiteExchange::Ecdhe,
    ),
    (
        0xC013,
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        SuiteExchange::Ecdhe,
    ),
    (
        0xC014,
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        SuiteExchange::Ecdhe,
    ),
    (
        0xC023,
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
        SuiteExchange::Ecdhe,
    ),
    (
        0xC024,
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        SuiteExchange::Ecdhe,
    ),
    (
        0xC027,
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        SuiteExchange::Ecdhe,
    ),
    (
        0xC028,
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        SuiteExchange::Ecdhe,
    ),
    (
        0xC012,
        "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
        SuiteExchange::Ecdhe,
    ),
    (
        0xC011,
        "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
        SuiteExchange::Ecdhe,
    ),
    (
        0x009E,
        "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        SuiteExchange::Dhe,
    ),
    (
        0x009F,
        "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        SuiteExchange::Dhe,
    ),
    (
        0xCCAA,
        "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        SuiteExchange::Dhe,
    ),
    (
        0x0033,
        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        SuiteExchange::Dhe,
    ),
    (
        0x0039,
        "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
        SuiteExchange::Dhe,
    ),
    (
        0x0067,
        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
        SuiteExchange::Dhe,
    ),
    (
        0x006B,
        "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
        SuiteExchange::Dhe,
    ),
    (
        0x009C,
        "TLS_RSA_WITH_AES_128_GCM_SHA256",
        SuiteExchange::Rsa,
    ),
    (
        0x009D,
        "TLS_RSA_WITH_AES_256_GCM_SHA384",
        SuiteExchange::Rsa,
    ),
    (0x002F, "TLS_RSA_WITH_AES_128_CBC_SHA", SuiteExchange::Rsa),
    (0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA", SuiteExchange::Rsa),
    (
        0x003C,
        "TLS_RSA_WITH_AES_128_CBC_SHA256",
        SuiteExchange::Rsa,
    ),
    (
        0x003D,
        "TLS_RSA_WITH_AES_256_CBC_SHA256",
        SuiteExchange::Rsa,
    ),
    (0x000A, "TLS_RSA_WITH_3DES_EDE_CBC_SHA", SuiteExchange::Rsa),
    (0x0005, "TLS_RSA_WITH_RC4_128_SHA", SuiteExchange::Rsa),
    (0x0004, "TLS_RSA_WITH_RC4_128_MD5", SuiteExchange::Rsa),
];

fn cipher_key_exchange(cipher: u16) -> Option<SuiteExchange> {
    SUITES
        .iter()
        .find(|(id, _, _)| *id == cipher)
        .map(|(_, _, kx)| *kx)
}

/// The IANA name of a cipher suite, where this agent knows it.
pub fn cipher_name(cipher: u16) -> Option<&'static str> {
    SUITES
        .iter()
        .find(|(id, _, _)| *id == cipher)
        .map(|(_, name, _)| *name)
}

/// The name of a protocol version as the wire carries it.
pub fn version_name(version: u16) -> Option<&'static str> {
    match version {
        0x0304 => Some("TLS 1.3"),
        0x0303 => Some("TLS 1.2"),
        0x0302 => Some("TLS 1.1"),
        0x0301 => Some("TLS 1.0"),
        0x0300 => Some("SSL 3.0"),
        _ => None,
    }
}

/// The groups seen in practice, by IANA `NamedGroup` code point.
const GROUPS: &[(u16, &str, KeyExchangeClass)] = &[
    (
        0x11EC,
        "X25519MLKEM768",
        KeyExchangeClass::PostQuantumHybrid,
    ),
    (
        0x11EB,
        "SecP256r1MLKEM768",
        KeyExchangeClass::PostQuantumHybrid,
    ),
    (
        0x11ED,
        "SecP384r1MLKEM1024",
        KeyExchangeClass::PostQuantumHybrid,
    ),
    (
        0x6399,
        "X25519Kyber768Draft00",
        KeyExchangeClass::PostQuantumHybrid,
    ),
    (0x0200, "MLKEM512", KeyExchangeClass::PostQuantum),
    (0x0201, "MLKEM768", KeyExchangeClass::PostQuantum),
    (0x0202, "MLKEM1024", KeyExchangeClass::PostQuantum),
    (0x001D, "x25519", KeyExchangeClass::Classical),
    (0x001E, "x448", KeyExchangeClass::Classical),
    (0x0017, "secp256r1", KeyExchangeClass::Classical),
    (0x0018, "secp384r1", KeyExchangeClass::Classical),
    (0x0019, "secp521r1", KeyExchangeClass::Classical),
    (0x0100, "ffdhe2048", KeyExchangeClass::Classical),
    (0x0101, "ffdhe3072", KeyExchangeClass::Classical),
    (0x0102, "ffdhe4096", KeyExchangeClass::Classical),
    (0x0103, "ffdhe6144", KeyExchangeClass::Classical),
    (0x0104, "ffdhe8192", KeyExchangeClass::Classical),
];

/// The IANA name of a key exchange group, where this agent knows it.
pub fn group_name(group: u16) -> Option<&'static str> {
    GROUPS
        .iter()
        .find(|(id, _, _)| *id == group)
        .map(|(_, name, _)| *name)
}

fn group_class(group: u16) -> KeyExchangeClass {
    GROUPS
        .iter()
        .find(|(id, _, _)| *id == group)
        .map_or(KeyExchangeClass::Unknown, |(_, _, class)| *class)
}

/// One handshake, with the flow it settled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeRecord {
    pub client: IpAddr,
    pub client_port: u16,
    pub server: IpAddr,
    pub server_port: u16,
    /// When the server's flight was read, in nanoseconds since the epoch.
    pub observed_at_ns: u64,
    pub handshake: TlsHandshake,
}

/// The most recent handshakes, oldest dropped first.
pub struct HandshakeLog {
    entries: Mutex<VecDeque<HandshakeRecord>>,
    capacity: usize,
}

impl HandshakeLog {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: Mutex::new(VecDeque::with_capacity(capacity.min(1024))),
            capacity,
        }
    }

    pub fn record(&self, record: HandshakeRecord) {
        if self.capacity == 0 {
            return;
        }
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if entries.len() >= self.capacity {
            entries.pop_front();
        }
        entries.push_back(record);
    }

    /// The handshakes held, newest first.
    pub fn recent(&self) -> Vec<HandshakeRecord> {
        let entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        entries.iter().rev().cloned().collect()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut msg = vec![kind];
        msg.extend_from_slice(&u24_bytes(body.len()));
        msg.extend_from_slice(body);
        msg
    }

    fn u24_bytes(n: usize) -> [u8; 3] {
        [(n >> 16) as u8, (n >> 8) as u8, n as u8]
    }

    fn tls_record(fragment: &[u8]) -> Vec<u8> {
        let mut out = vec![0x16, 0x03, 0x03];
        out.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
        out.extend_from_slice(fragment);
        out
    }

    fn server_hello(version: u16, cipher: u16, extensions: &[u8], random: [u8; 32]) -> Vec<u8> {
        let mut body = version.to_be_bytes().to_vec();
        body.extend_from_slice(&random);
        body.push(0); // session id
        body.extend_from_slice(&cipher.to_be_bytes());
        body.push(0); // compression
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(extensions);
        record(HS_SERVER_HELLO, &body)
    }

    fn tls13_extensions(group: u16) -> Vec<u8> {
        let mut ext = vec![0x00, 0x2B, 0x00, 0x02, 0x03, 0x04];
        ext.extend_from_slice(&[0x00, 0x33, 0x00, 0x06]);
        ext.extend_from_slice(&group.to_be_bytes());
        ext.extend_from_slice(&[0x00, 0x02, 0xAA, 0xBB]);
        ext
    }

    fn der(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if content.len() < 0x80 {
            out.push(content.len() as u8);
        } else {
            out.push(0x82);
            out.extend_from_slice(&(content.len() as u16).to_be_bytes());
        }
        out.extend_from_slice(content);
        out
    }

    fn certificate(not_before: &[u8], not_after: &[u8], issuer_len: usize) -> Vec<u8> {
        let mut tbs = der(0xA0, &der(0x02, &[2]));
        tbs.extend(der(0x02, &[0x01, 0x23]));
        tbs.extend(der(0x30, &der(0x06, &[0x2A, 0x86, 0x48])));
        tbs.extend(der(0x30, &vec![0x41; issuer_len]));
        let mut validity = der(0x17, not_before);
        validity.extend(der(0x18, not_after));
        tbs.extend(der(0x30, &validity));
        tbs.extend(der(0x30, &[0x55; 40])); // subject
        der(0x30, &der(0x30, &tbs))
    }

    fn certificate_message(cert: &[u8]) -> Vec<u8> {
        let mut list = u24_bytes(cert.len()).to_vec();
        list.extend_from_slice(cert);
        let mut body = u24_bytes(list.len()).to_vec();
        body.extend(list);
        record(HS_CERTIFICATE, &body)
    }

    #[test]
    fn tls13_keeps_version_group_and_cipher_and_hides_the_certificate() {
        let flight = tls_record(&server_hello(
            0x0303,
            0x1301,
            &tls13_extensions(0x11EC),
            [7; 32],
        ));
        let hs = read_server_flight(&flight).expect("a handshake");
        assert_eq!(hs.version, TLS_1_3);
        assert_eq!(hs.cipher, 0x1301);
        assert_eq!(hs.group, Some(0x11EC));
        assert_eq!(hs.certificate, CertificateValidity::NotObservable);
        assert_eq!(hs.key_exchange(), KeyExchangeClass::PostQuantumHybrid);
        assert_eq!(hs.posture(), CryptoPosture::PostQuantum);
    }

    #[test]
    fn a_hello_retry_request_settles_nothing() {
        let flight = tls_record(&server_hello(
            0x0303,
            0x1301,
            &tls13_extensions(0x11EC),
            HELLO_RETRY_RANDOM,
        ));
        assert!(read_server_flight(&flight).is_none());
    }

    #[test]
    fn tls12_reads_the_group_and_the_leaf_validity_across_records() {
        let hello = server_hello(0x0303, 0xC02F, &[], [3; 32]);
        let cert = certificate_message(&certificate(b"250101000000Z", b"20270630235959Z", 200));
        let mut ske = vec![NAMED_CURVE, 0x00, 0x1D, 0x20];
        ske.extend_from_slice(&[0x99; 32]);
        let mut second = cert;
        second.extend(record(HS_SERVER_KEY_EXCHANGE, &ske));
        second.extend(record(HS_SERVER_HELLO_DONE, &[]));
        let mut flight = tls_record(&hello);
        flight.extend(tls_record(&second));

        let hs = read_server_flight(&flight).expect("a handshake");
        assert_eq!(hs.version, TLS_1_2);
        assert_eq!(hs.group, Some(0x001D));
        assert_eq!(
            hs.certificate,
            CertificateValidity::Window {
                not_before: 1_735_689_600,
                not_after: 1_814_399_999,
            }
        );
        assert_eq!(hs.key_exchange(), KeyExchangeClass::Classical);
        assert_eq!(hs.posture(), CryptoPosture::Classical);
    }

    #[test]
    fn a_certificate_cut_after_its_validity_still_gives_the_window() {
        let hello = server_hello(0x0303, 0x009C, &[], [3; 32]);
        let cert = certificate_message(&certificate(b"240301120000Z", b"20250301120000Z", 300));
        let mut flight = tls_record(&hello);
        let mut second = tls_record(&cert);
        // Keep the bytes up to just past the validity, as a capture limit would.
        second.truncate(second.len() - 30);
        flight.extend(second);

        let hs = read_server_flight(&flight).expect("a handshake");
        assert!(matches!(hs.certificate, CertificateValidity::Window { .. }));
        assert_eq!(hs.group, None);
        assert_eq!(hs.key_exchange(), KeyExchangeClass::RsaKeyTransport);
    }

    #[test]
    fn tls12_without_the_certificate_says_it_was_not_captured() {
        let flight = tls_record(&server_hello(0x0303, 0xC030, &[], [3; 32]));
        let hs = read_server_flight(&flight).expect("a handshake");
        assert_eq!(hs.certificate, CertificateValidity::NotCaptured);
        assert_eq!(hs.key_exchange(), KeyExchangeClass::Unknown);
    }

    #[test]
    fn below_tls12_is_legacy_whatever_the_exchange() {
        let hello = server_hello(0x0301, 0xC013, &[], [3; 32]);
        let mut ske = vec![NAMED_CURVE, 0x00, 0x17];
        ske.push(0);
        let mut flight = tls_record(&hello);
        flight.extend(tls_record(&record(HS_SERVER_KEY_EXCHANGE, &ske)));
        let hs = read_server_flight(&flight).expect("a handshake");
        assert_eq!(hs.group, Some(0x0017));
        assert_eq!(hs.posture(), CryptoPosture::LegacyTls);
    }

    #[test]
    fn a_dhe_server_key_exchange_is_not_read_as_a_curve() {
        let hello = server_hello(0x0303, 0x009E, &[], [3; 32]);
        let mut ske = vec![0x03, 0x00];
        ske.extend_from_slice(&[0x11; 64]);
        let mut flight = tls_record(&hello);
        flight.extend(tls_record(&record(HS_SERVER_KEY_EXCHANGE, &ske)));
        let hs = read_server_flight(&flight).expect("a handshake");
        assert_eq!(hs.group, None);
    }

    #[test]
    fn a_client_hello_is_not_a_server_flight() {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0; 32]);
        body.extend_from_slice(&[0, 0, 2, 0x13, 0x01, 1, 0, 0, 0]);
        assert!(read_server_flight(&tls_record(&record(0x01, &body))).is_none());
    }

    #[test]
    fn every_prefix_and_every_flipped_byte_of_a_flight_reads_without_panicking() {
        let hello = server_hello(0x0303, 0xC02F, &[], [3; 32]);
        let mut second =
            certificate_message(&certificate(b"250101000000Z", b"20270630235959Z", 150));
        second.extend(record(
            HS_SERVER_KEY_EXCHANGE,
            &[NAMED_CURVE, 0x00, 0x1D, 0x01, 0x02],
        ));
        let mut flight = tls_record(&hello);
        flight.extend(tls_record(&second));
        for end in 0..=flight.len() {
            let _ = read_server_flight(&flight[..end]);
        }
        for i in 0..flight.len() {
            let mut bent = flight.clone();
            bent[i] ^= 0xFF;
            let _ = read_server_flight(&bent);
        }
    }

    #[test]
    fn times_convert_to_epoch_seconds() {
        assert_eq!(der_time(0x17, b"700101000000Z"), Some(0));
        assert_eq!(der_time(0x17, b"491231235959Z"), Some(2_524_607_999));
        assert_eq!(der_time(0x18, b"20000229120000Z"), Some(951_825_600));
        assert_eq!(der_time(0x17, b"700101000000+0100"), None);
        assert_eq!(der_time(0x17, b"701301000000Z"), None);
    }

    #[test]
    fn names_cover_the_values_seen_in_practice() {
        assert_eq!(version_name(TLS_1_3), Some("TLS 1.3"));
        assert_eq!(group_name(0x11EC), Some("X25519MLKEM768"));
        assert_eq!(
            cipher_name(0xC02F),
            Some("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
        );
        assert_eq!(group_name(0x4242), None);
        assert_eq!(group_class(0x0201), KeyExchangeClass::PostQuantum);
    }

    #[test]
    fn the_log_drops_the_oldest_and_lists_newest_first() {
        let log = HandshakeLog::new(2);
        for port in [1u16, 2, 3] {
            log.record(HandshakeRecord {
                client: IpAddr::from([10, 0, 0, 1]),
                client_port: port,
                server: IpAddr::from([10, 0, 0, 2]),
                server_port: 443,
                observed_at_ns: u64::from(port),
                handshake: TlsHandshake {
                    version: TLS_1_3,
                    cipher: 0x1301,
                    group: Some(0x001D),
                    certificate: CertificateValidity::NotObservable,
                },
            });
        }
        let ports: Vec<u16> = log.recent().iter().map(|r| r.client_port).collect();
        assert_eq!(ports, vec![3, 2]);
    }
}
