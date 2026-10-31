//! The cryptographic posture of each edge between two workloads.
//!
//! Every connection the agent reads is counted once, on the edge between its
//! client, its server and the server's port, as one of four things: a TLS
//! handshake over a post-quantum or hybrid group, a TLS handshake over a
//! classical exchange, a handshake below TLS 1.2, or a request sent in clear
//! text, with the protocol named.
//!
//! A connection that upgrades to TLS in band (SMTP `STARTTLS`, an LDAP `StartTLS`
//! extended request, a PostgreSQL `SSLRequest`) is never counted as clear
//! text: the upgrade request and the greeting that precedes it carry nothing,
//! and once the upgrade succeeds no readable request follows. What is counted
//! instead is the handshake that follows. A connection whose upgrade the server
//! refused goes on in clear and is counted as such at its first real request.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use super::handshake::{CertificateValidity, CryptoPosture, KeyExchangeClass, TlsHandshake};
use super::service_graph::GraphEnd;

/// How many distinct edges are kept before the least recently seen one goes.
pub const DEFAULT_MAX_POSTURE_EDGES: usize = 4_096;

/// How many connections are remembered as already counted.
pub const DEFAULT_MAX_COUNTED_FLOWS: usize = 65_536;

/// How long a connection stays remembered after its last counted payload.
pub const COUNTED_FLOW_IDLE_NS: u64 = 120_000_000_000;

/// How many distinct negotiated suites an edge lists before it only counts.
pub const MAX_SUITES_PER_EDGE: usize = 16;

/// A protocol read in clear text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClearTextProtocol {
    Http,
    Ldap,
    Smtp,
    Redis,
    Postgres,
}

impl ClearTextProtocol {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Ldap => "ldap",
            Self::Smtp => "smtp",
            Self::Redis => "redis",
            Self::Postgres => "postgres",
        }
    }
}

/// What a TLS handshake settled on: the version, the key exchange group
/// where one was read, and the cipher suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct NegotiatedSuite {
    pub version: u16,
    pub group: Option<u16>,
    pub cipher: u16,
}

impl NegotiatedSuite {
    /// The suite a handshake settled on.
    #[must_use]
    pub fn of(handshake: &TlsHandshake) -> Self {
        Self {
            version: handshake.version,
            group: handshake.group,
            cipher: handshake.cipher,
        }
    }

    /// The posture this suite gives its connection.
    #[must_use]
    pub fn posture(self) -> CryptoPosture {
        self.handshake().posture()
    }

    /// How this suite's key exchange stands against a quantum adversary.
    #[must_use]
    pub fn key_exchange(self) -> KeyExchangeClass {
        self.handshake().key_exchange()
    }

    fn handshake(self) -> TlsHandshake {
        TlsHandshake {
            version: self.version,
            cipher: self.cipher,
            group: self.group,
            certificate: CertificateValidity::NotObservable,
        }
    }
}

/// What one connection is counted as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowPosture {
    Tls(NegotiatedSuite),
    ClearText(ClearTextProtocol),
}

/// SMTP commands a client sends before it decides to upgrade or not.
const SMTP_PRELUDE: &[&[u8]] = &[b"EHLO", b"HELO", b"STARTTLS", b"NOOP", b"QUIT", b"RSET"];

/// SMTP commands that move mail or credentials.
const SMTP_REQUESTS: &[&[u8]] = &[
    b"MAIL", b"RCPT", b"DATA", b"AUTH", b"VRFY", b"EXPN", b"BDAT",
];

/// The PostgreSQL protocol version of a `StartupMessage`.
const PG_PROTOCOL_V3: u32 = 0x0003_0000;

/// The object identifier of the LDAP `StartTLS` extended operation,
/// `1.3.6.1.4.1.1466.20037`, as the request carries it.
const LDAP_START_TLS_OID: &[u8] = b"1.3.6.1.4.1.1466.20037";

/// The protocol of a request a client sent in clear text, when the payload
/// is one. `label` is what the L7 detector named the payload.
///
/// A greeting, a server's answer, a capability probe and an upgrade request
/// are not requests: none of them tells whether the connection will stay in
/// clear, and none carries data.
#[must_use]
pub fn clear_text_request(label: &str, payload: &[u8]) -> Option<ClearTextProtocol> {
    match label {
        // The detector names an HTTP payload by its request method, so it
        // is the client's.
        "http" => Some(ClearTextProtocol::Http),
        // A RESP array is what a client sends; a server answers with a
        // simple string, an error, an integer or a bulk string.
        "redis" => Some(ClearTextProtocol::Redis),
        "smtp" => smtp_request(payload).then_some(ClearTextProtocol::Smtp),
        "postgres" => postgres_request(payload).then_some(ClearTextProtocol::Postgres),
        "unknown" => ldap_request(payload).then_some(ClearTextProtocol::Ldap),
        _ => None,
    }
}

fn smtp_request(payload: &[u8]) -> bool {
    let verb = payload
        .split(|b| *b == b' ' || *b == b'\r' || *b == b'\n')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    if SMTP_PRELUDE.contains(&verb.as_slice()) {
        return false;
    }
    SMTP_REQUESTS.contains(&verb.as_slice())
}

fn postgres_request(payload: &[u8]) -> bool {
    match payload.first() {
        Some(b'Q' | b'P') => true,
        _ => payload
            .get(4..8)
            .and_then(|v| <[u8; 4]>::try_from(v).ok())
            .is_some_and(|v| u32::from_be_bytes(v) == PG_PROTOCOL_V3),
    }
}

/// An LDAP request a client sends: a `LDAPMessage` sequence whose message
/// identifier is followed by one of the request operations. A `StartTLS`
/// extended request and an unbind carry nothing and are left out.
fn ldap_request(payload: &[u8]) -> bool {
    let Some(body) = ber_body(payload, 0x30) else {
        return false;
    };
    let Some((id_len, id_header)) = ber_length(body.get(1..).unwrap_or_default()) else {
        return false;
    };
    if body.first() != Some(&0x02) || !(1..=4).contains(&id_len) {
        return false;
    }
    let Some(&op) = body.get(1 + id_header + id_len) else {
        return false;
    };
    match op {
        // bindRequest, searchRequest, modifyRequest, addRequest, delRequest,
        // modDNRequest, compareRequest.
        0x60 | 0x63 | 0x66 | 0x68 | 0x4a | 0x6c | 0x6e => true,
        // extendedRequest: everything but StartTLS.
        0x77 => !body
            .windows(LDAP_START_TLS_OID.len())
            .any(|w| w == LDAP_START_TLS_OID),
        _ => false,
    }
}

/// The content of a BER element of the given tag at the start of `bytes`,
/// truncated to what was captured.
fn ber_body(bytes: &[u8], tag: u8) -> Option<&[u8]> {
    if bytes.first() != Some(&tag) {
        return None;
    }
    let (len, header) = ber_length(bytes.get(1..)?)?;
    let body = bytes.get(1 + header..)?;
    // A sequence announcing more than an LDAP request ever holds is not one.
    if len > 16 * 1024 * 1024 || len == 0 {
        return None;
    }
    Some(&body[..len.min(body.len())])
}

/// A BER length and the number of bytes it took.
fn ber_length(bytes: &[u8]) -> Option<(usize, usize)> {
    let first = *bytes.first()?;
    if first < 0x80 {
        return Some((usize::from(first), 1));
    }
    let count = usize::from(first & 0x7f);
    if count == 0 || count > 4 {
        return None;
    }
    let mut len = 0usize;
    for b in bytes.get(1..=count)? {
        len = (len << 8) | usize::from(*b);
    }
    Some((len, 1 + count))
}

/// What identifies an edge.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PostureEdgeKey {
    pub client: GraphEnd,
    pub server: GraphEnd,
    pub server_port: u16,
}

/// What an edge's connections were counted as.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EdgePosture {
    pub post_quantum: u64,
    pub classical: u64,
    pub legacy_tls: u64,
    /// Connections in clear text, by protocol.
    pub clear_text: BTreeMap<ClearTextProtocol, u64>,
    /// TLS connections by the suite they negotiated, up to
    /// [`MAX_SUITES_PER_EDGE`] distinct suites.
    pub suites: BTreeMap<NegotiatedSuite, u64>,
    /// TLS connections whose suite came after the list was full.
    pub unlisted_suites: u64,
    /// Wall-clock nanoseconds of the first and the last counted connection.
    pub first_seen_ns: u64,
    pub last_seen_ns: u64,
}

impl EdgePosture {
    /// Connections counted on the edge.
    #[must_use]
    pub fn connections(&self) -> u64 {
        self.post_quantum
            .saturating_add(self.classical)
            .saturating_add(self.legacy_tls)
            .saturating_add(self.clear_text_connections())
    }

    /// Connections counted in clear text, whatever the protocol.
    #[must_use]
    pub fn clear_text_connections(&self) -> u64 {
        self.clear_text
            .values()
            .fold(0u64, |sum, n| sum.saturating_add(*n))
    }

    fn add(&mut self, posture: FlowPosture) {
        let slot = match posture {
            FlowPosture::Tls(suite) => {
                let listed = if self.suites.len() < MAX_SUITES_PER_EDGE
                    || self.suites.contains_key(&suite)
                {
                    self.suites.entry(suite).or_default()
                } else {
                    &mut self.unlisted_suites
                };
                *listed = listed.saturating_add(1);
                match suite.posture() {
                    CryptoPosture::PostQuantum => &mut self.post_quantum,
                    CryptoPosture::Classical => &mut self.classical,
                    CryptoPosture::LegacyTls => &mut self.legacy_tls,
                }
            }
            FlowPosture::ClearText(protocol) => self.clear_text.entry(protocol).or_default(),
        };
        *slot = slot.saturating_add(1);
    }
}

/// One connection, by its two ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowTuple {
    pub client: IpAddr,
    pub client_port: u16,
    pub server: IpAddr,
    pub server_port: u16,
}

/// The edges, sorted by key.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PostureReading {
    pub edges: Vec<(PostureEdgeKey, EdgePosture)>,
    /// Edges dropped, least recently seen first, to make room for new ones.
    pub evicted_edges: u64,
}

/// Every edge's posture since the agent started, bounded in edges.
#[derive(Debug)]
pub struct PostureTable {
    edges: HashMap<PostureEdgeKey, EdgePosture>,
    counted: HashMap<FlowTuple, u64>,
    max_edges: usize,
    max_flows: usize,
    evicted_edges: u64,
}

impl Default for PostureTable {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_POSTURE_EDGES, DEFAULT_MAX_COUNTED_FLOWS)
    }
}

impl PostureTable {
    #[must_use]
    pub fn new(max_edges: usize, max_flows: usize) -> Self {
        Self {
            edges: HashMap::new(),
            counted: HashMap::new(),
            max_edges: max_edges.max(1),
            max_flows: max_flows.max(1),
            evicted_edges: 0,
        }
    }

    /// Whether `flow` was counted and is still remembered at `now_ns`.
    #[must_use]
    pub fn counted(&self, flow: &FlowTuple, now_ns: u64) -> bool {
        self.counted
            .get(flow)
            .is_some_and(|seen| now_ns.saturating_sub(*seen) < COUNTED_FLOW_IDLE_NS)
    }

    /// Count `flow` on `key` as `posture`, unless the same connection was
    /// counted already. A connection seen again refreshes its memory, so a
    /// long-lived one is counted once. Returns whether it was counted.
    pub fn record(
        &mut self,
        key: PostureEdgeKey,
        flow: FlowTuple,
        posture: FlowPosture,
        now_ns: u64,
    ) -> bool {
        let seen_before = self.counted(&flow, now_ns);
        self.remember(flow, now_ns);
        if seen_before {
            return false;
        }
        if !self.edges.contains_key(&key) && self.edges.len() >= self.max_edges {
            self.evict_oldest_edge();
        }
        let edge = self.edges.entry(key).or_insert_with(|| EdgePosture {
            first_seen_ns: now_ns,
            ..EdgePosture::default()
        });
        edge.add(posture);
        edge.last_seen_ns = edge.last_seen_ns.max(now_ns);
        true
    }

    #[must_use]
    pub fn read(&self) -> PostureReading {
        let mut edges: Vec<_> = self
            .edges
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        edges.sort_by(|a, b| a.0.cmp(&b.0));
        PostureReading {
            edges,
            evicted_edges: self.evicted_edges,
        }
    }

    fn remember(&mut self, flow: FlowTuple, now_ns: u64) {
        if !self.counted.contains_key(&flow) && self.counted.len() >= self.max_flows {
            self.counted
                .retain(|_, seen| now_ns.saturating_sub(*seen) < COUNTED_FLOW_IDLE_NS);
            if self.counted.len() >= self.max_flows
                && let Some(oldest) = self
                    .counted
                    .iter()
                    .min_by_key(|(_, seen)| **seen)
                    .map(|(flow, _)| *flow)
            {
                self.counted.remove(&oldest);
            }
        }
        self.counted.insert(flow, now_ns);
    }

    fn evict_oldest_edge(&mut self) {
        if let Some(oldest) = self
            .edges
            .iter()
            .min_by_key(|(_, edge)| edge.last_seen_ns)
            .map(|(key, _)| key.clone())
        {
            self.edges.remove(&oldest);
            self.evicted_edges = self.evicted_edges.saturating_add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn end(last: u8) -> GraphEnd {
        GraphEnd {
            service: None,
            address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, last)),
        }
    }

    /// A suite that gives `posture`.
    fn tls(posture: CryptoPosture) -> FlowPosture {
        FlowPosture::Tls(match posture {
            CryptoPosture::PostQuantum => NegotiatedSuite {
                version: 0x0304,
                group: Some(0x11ec),
                cipher: 0x1301,
            },
            CryptoPosture::Classical => NegotiatedSuite {
                version: 0x0304,
                group: Some(0x001d),
                cipher: 0x1301,
            },
            CryptoPosture::LegacyTls => NegotiatedSuite {
                version: 0x0301,
                group: None,
                cipher: 0x002f,
            },
        })
    }

    #[test]
    fn a_suite_names_its_key_exchange() {
        let hybrid = NegotiatedSuite {
            version: 0x0304,
            group: Some(0x11ec),
            cipher: 0x1301,
        };
        let rsa = NegotiatedSuite {
            version: 0x0303,
            group: None,
            cipher: 0x002f,
        };
        assert_eq!(hybrid.key_exchange(), KeyExchangeClass::PostQuantumHybrid);
        assert_eq!(rsa.key_exchange(), KeyExchangeClass::RsaKeyTransport);
    }

    #[test]
    fn a_suite_is_listed_until_the_edge_holds_enough_of_them() {
        let mut table = PostureTable::default();
        let cipher = |n: u16| {
            FlowPosture::Tls(NegotiatedSuite {
                version: 0x0303,
                group: Some(0x0017),
                cipher: n,
            })
        };
        for n in 0..=u16::try_from(MAX_SUITES_PER_EDGE).unwrap_or(u16::MAX) {
            table.record(key(443), flow(n, 443), cipher(0xc02f + n), 1);
        }
        table.record(key(443), flow(1_000, 443), cipher(0xc02f), 1);
        let edge = &table.read().edges[0].1;
        assert_eq!(edge.suites.len(), MAX_SUITES_PER_EDGE);
        assert_eq!(edge.unlisted_suites, 1);
        assert_eq!(
            edge.suites[&NegotiatedSuite {
                version: 0x0303,
                group: Some(0x0017),
                cipher: 0xc02f
            }],
            2
        );
        assert_eq!(
            edge.classical,
            u64::try_from(MAX_SUITES_PER_EDGE).unwrap_or(0) + 2
        );
    }

    fn key(server_port: u16) -> PostureEdgeKey {
        PostureEdgeKey {
            client: end(1),
            server: end(2),
            server_port,
        }
    }

    fn flow(client_port: u16, server_port: u16) -> FlowTuple {
        FlowTuple {
            client: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            client_port,
            server: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            server_port,
        }
    }

    /// An LDAP message around `op`, with message id 1.
    fn ldap(op: &[u8]) -> Vec<u8> {
        let mut inner = vec![0x02, 0x01, 0x01];
        inner.extend_from_slice(op);
        let mut out = vec![0x30, u8::try_from(inner.len()).unwrap()];
        out.extend(inner);
        out
    }

    #[test]
    fn smtp_counts_at_the_first_command_that_moves_mail() {
        assert_eq!(clear_text_request("smtp", b"EHLO client.example\r\n"), None);
        assert_eq!(
            clear_text_request("smtp", b"220 mx.example ESMTP\r\n"),
            None
        );
        assert_eq!(clear_text_request("unknown", b"STARTTLS\r\n"), None);
        assert_eq!(
            clear_text_request("smtp", b"MAIL FROM:<a@example>\r\n"),
            Some(ClearTextProtocol::Smtp)
        );
        assert_eq!(
            clear_text_request("smtp", b"auth plain AGEAYg==\r\n"),
            Some(ClearTextProtocol::Smtp)
        );
    }

    #[test]
    fn postgres_counts_a_startup_or_a_query_and_not_an_ssl_request() {
        let ssl_request = [0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f];
        assert_eq!(clear_text_request("unknown", &ssl_request), None);
        assert_eq!(clear_text_request("postgres", &ssl_request), None);
        let startup = [0, 0, 0, 9, 0, 3, 0, 0, 0];
        assert_eq!(
            clear_text_request("postgres", &startup),
            Some(ClearTextProtocol::Postgres)
        );
        assert_eq!(
            clear_text_request("postgres", b"Q\0\0\0\x0dselect 1\0"),
            Some(ClearTextProtocol::Postgres)
        );
    }

    #[test]
    fn ldap_counts_a_bind_or_a_search_and_not_start_tls_or_an_answer() {
        let bind = ldap(&[0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00]);
        assert_eq!(
            clear_text_request("unknown", &bind),
            Some(ClearTextProtocol::Ldap)
        );
        let search = ldap(&[0x63, 0x03, 0x04, 0x01, b'x']);
        assert_eq!(
            clear_text_request("unknown", &search),
            Some(ClearTextProtocol::Ldap)
        );
        let mut start_tls = vec![0x77, 0x18, 0x80, 0x16];
        start_tls.extend_from_slice(LDAP_START_TLS_OID);
        assert_eq!(clear_text_request("unknown", &ldap(&start_tls)), None);
        let bind_response = ldap(&[0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00]);
        assert_eq!(clear_text_request("unknown", &bind_response), None);
        let unbind = ldap(&[0x42, 0x00]);
        assert_eq!(clear_text_request("unknown", &unbind), None);
    }

    #[test]
    fn ldap_reads_a_long_form_length_and_survives_any_truncation() {
        let mut bind = vec![0x30, 0x81, 0x0a, 0x02, 0x01, 0x01, 0x60, 0x05];
        bind.extend_from_slice(&[0x02, 0x01, 0x03, 0x04, 0x00]);
        assert_eq!(
            clear_text_request("unknown", &bind),
            Some(ClearTextProtocol::Ldap)
        );
        for end in 0..bind.len() {
            let _ = clear_text_request("unknown", &bind[..end]);
        }
    }

    #[test]
    fn protocols_that_are_not_named_count_nothing() {
        assert_eq!(clear_text_request("ftp", b"USER bob\r\n"), None);
        assert_eq!(clear_text_request("tls", &[0x16, 0x03, 0x01]), None);
        assert_eq!(clear_text_request("unknown", b"hello"), None);
    }

    #[test]
    fn a_connection_counts_once_however_many_requests_it_carries() {
        let mut table = PostureTable::default();
        let posture = FlowPosture::ClearText(ClearTextProtocol::Http);
        assert!(table.record(key(80), flow(40_000, 80), posture, 1));
        assert!(!table.record(key(80), flow(40_000, 80), posture, 2));
        assert!(table.record(key(80), flow(40_001, 80), posture, 3));
        let reading = table.read();
        assert_eq!(reading.edges.len(), 1);
        let edge = &reading.edges[0].1;
        assert_eq!(edge.clear_text[&ClearTextProtocol::Http], 2);
        assert_eq!(edge.connections(), 2);
        assert_eq!((edge.first_seen_ns, edge.last_seen_ns), (1, 3));
    }

    #[test]
    fn a_connection_idle_past_its_memory_counts_again() {
        let mut table = PostureTable::default();
        let posture = tls(CryptoPosture::Classical);
        assert!(table.record(key(443), flow(40_000, 443), posture, 0));
        assert!(!table.record(
            key(443),
            flow(40_000, 443),
            posture,
            COUNTED_FLOW_IDLE_NS - 1
        ));
        assert!(!table.record(
            key(443),
            flow(40_000, 443),
            posture,
            2 * COUNTED_FLOW_IDLE_NS - 2
        ));
        assert!(table.record(
            key(443),
            flow(40_000, 443),
            posture,
            4 * COUNTED_FLOW_IDLE_NS
        ));
        assert_eq!(table.read().edges[0].1.classical, 2);
    }

    #[test]
    fn each_posture_lands_in_its_own_count_on_its_own_port() {
        let mut table = PostureTable::default();
        table.record(key(443), flow(1, 443), tls(CryptoPosture::PostQuantum), 1);
        table.record(key(443), flow(2, 443), tls(CryptoPosture::LegacyTls), 1);
        table.record(
            key(6379),
            flow(3, 6379),
            FlowPosture::ClearText(ClearTextProtocol::Redis),
            1,
        );
        let reading = table.read();
        assert_eq!(reading.edges.len(), 2);
        let tls = &reading.edges[0].1;
        assert_eq!((tls.post_quantum, tls.legacy_tls, tls.classical), (1, 1, 0));
        assert_eq!(reading.edges[1].0.server_port, 6379);
        assert_eq!(reading.edges[1].1.clear_text_connections(), 1);
    }

    #[test]
    fn a_full_table_drops_the_edge_seen_least_recently() {
        let mut table = PostureTable::new(2, 16);
        let posture = tls(CryptoPosture::Classical);
        table.record(key(1), flow(1, 1), posture, 10);
        table.record(key(2), flow(2, 2), posture, 5);
        table.record(key(3), flow(3, 3), posture, 20);
        let reading = table.read();
        assert_eq!(reading.evicted_edges, 1);
        let ports: Vec<u16> = reading.edges.iter().map(|(k, _)| k.server_port).collect();
        assert_eq!(ports, vec![1, 3]);
    }

    #[test]
    fn a_full_flow_memory_forgets_the_oldest_connection() {
        let mut table = PostureTable::new(16, 2);
        let posture = tls(CryptoPosture::Classical);
        table.record(key(1), flow(1, 1), posture, 1);
        table.record(key(1), flow(2, 1), posture, 2);
        table.record(key(1), flow(3, 1), posture, 3);
        assert!(!table.counted(&flow(1, 1), 4));
        assert!(table.counted(&flow(3, 1), 4));
    }
}
