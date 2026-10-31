use std::sync::Arc;

use axum::Json;
use axum::extract::{ConnectInfo, Query, State};
use axum::http::request::Parts;
use domain::l7::crypto_posture::{EdgePosture, PostureReading};
use domain::l7::handshake::{
    CertificateValidity, CryptoPosture, HandshakeRecord, KeyExchangeClass, cipher_name,
    version_name,
};
use domain::l7::service_graph::GraphEnd;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use tokio_rustls::rustls::NamedGroup;
use utoipa::{IntoParams, ToSchema};

use super::error::{ApiError, ErrorBody};
use super::service_graph_handler::ServiceEndBody;
use super::state::AppState;
use super::tls::TlsConnectInfo;

/// Per-connection TLS status, surfaced so operators can confirm the
/// negotiated key-exchange group (e.g. verify a post-quantum hybrid
/// handshake) on a live connection.
#[derive(Serialize, ToSchema)]
pub struct TlsStatusResponse {
    /// Whether this request arrived over TLS.
    pub tls: bool,
    /// Negotiated TLS 1.3 key-exchange named group for this connection
    /// (e.g. `X25519MLKEM768`, `X25519`, `secp256r1`), or `null` when the
    /// request did not arrive over TLS.
    pub negotiated_group: Option<String>,
    /// `true` when the negotiated group is the post-quantum hybrid
    /// (`X25519MLKEM768`).
    pub post_quantum: bool,
}

/// Canonical lowercase-free name matching OpenSSL's group naming so the
/// value can be compared directly against `openssl s_client` output.
fn group_name(group: NamedGroup) -> String {
    match group {
        NamedGroup::X25519MLKEM768 => "X25519MLKEM768".to_string(),
        NamedGroup::X25519 => "X25519".to_string(),
        NamedGroup::secp256r1 => "secp256r1".to_string(),
        NamedGroup::secp384r1 => "secp384r1".to_string(),
        NamedGroup::secp521r1 => "secp521r1".to_string(),
        other => format!("{other:?}"),
    }
}

/// `GET /api/v1/tls/status` - report the negotiated TLS key-exchange group
/// for the current connection.
#[utoipa::path(
    get, path = "/api/v1/tls/status",
    tag = "TLS",
    responses(
        (status = 200, description = "Negotiated TLS parameters for this connection", body = TlsStatusResponse),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn tls_status(parts: Parts) -> Json<TlsStatusResponse> {
    // The TLS connection info is stored as a request extension by
    // `into_make_service_with_connect_info::<TlsConnectInfo>`; over plain HTTP
    // the extension is `ConnectInfo<SocketAddr>` instead, so it is absent here.
    let info = parts
        .extensions
        .get::<ConnectInfo<TlsConnectInfo>>()
        .copied();
    let group = info.and_then(|c| c.0.kx_group);
    Json(TlsStatusResponse {
        tls: info.is_some(),
        negotiated_group: group.map(group_name),
        post_quantum: group == Some(NamedGroup::X25519MLKEM768),
    })
}

/// How many handshakes a request returns when it does not say.
const DEFAULT_HANDSHAKE_LIMIT: usize = 100;

#[derive(Debug, Deserialize, IntoParams)]
pub struct HandshakeQueryParams {
    /// Most handshakes to return, newest first (default 100, at most the
    /// log's capacity).
    pub limit: Option<usize>,
}

/// What the server's certificate shows from the wire.
#[derive(Debug, Serialize, ToSchema)]
pub struct CertificateBody {
    /// `not_observable` in TLS 1.3, where the certificate is encrypted;
    /// `not_captured` in TLS 1.2 when it was not in the bytes read, which is
    /// also what a resumed session gives; `read` when the window below is the
    /// leaf certificate's.
    pub state: &'static str,
    /// Start of validity, in seconds since the epoch, when read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<i64>,
    /// End of validity, in seconds since the epoch, when read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_after: Option<i64>,
}

/// One TLS handshake seen on the node.
#[derive(Debug, Serialize, ToSchema)]
pub struct TlsHandshakeBody {
    pub client: String,
    pub client_port: u16,
    pub server: String,
    pub server_port: u16,
    /// When the server's flight was read, in nanoseconds since the epoch.
    pub observed_at_ns: u64,
    /// The negotiated version as the wire carries it (`772` is TLS 1.3).
    pub version: u16,
    /// Its name, absent for a value this agent does not name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_name: Option<&'static str>,
    /// The selected cipher suite's code point.
    pub cipher: u16,
    /// Its IANA name, absent for a suite this agent does not name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cipher_name: Option<&'static str>,
    /// The selected key exchange group's code point, absent when the
    /// exchange has none or it was not in the bytes read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<u16>,
    /// Its IANA name, absent for a group this agent does not name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_name: Option<&'static str>,
    /// `post_quantum_hybrid`, `post_quantum`, `classical`,
    /// `rsa_key_transport` or `unknown`.
    pub key_exchange: &'static str,
    /// `post_quantum`, `classical` or `legacy_tls` (below TLS 1.2).
    pub posture: &'static str,
    pub certificate: CertificateBody,
}

/// The handshakes the log holds.
#[derive(Debug, Serialize, ToSchema)]
pub struct TlsHandshakesResponse {
    /// Whether this agent reads TLS handshakes at all.
    pub recording: bool,
    /// How many handshakes the log keeps before dropping the oldest.
    pub capacity: usize,
    /// Newest first.
    pub handshakes: Vec<TlsHandshakeBody>,
}

fn key_exchange_label(class: KeyExchangeClass) -> &'static str {
    match class {
        KeyExchangeClass::PostQuantumHybrid => "post_quantum_hybrid",
        KeyExchangeClass::PostQuantum => "post_quantum",
        KeyExchangeClass::Classical => "classical",
        KeyExchangeClass::RsaKeyTransport => "rsa_key_transport",
        KeyExchangeClass::Unknown => "unknown",
    }
}

fn posture_label(posture: CryptoPosture) -> &'static str {
    match posture {
        CryptoPosture::PostQuantum => "post_quantum",
        CryptoPosture::Classical => "classical",
        CryptoPosture::LegacyTls => "legacy_tls",
    }
}

fn handshake_body(record: &HandshakeRecord) -> TlsHandshakeBody {
    let hs = &record.handshake;
    let certificate = match hs.certificate {
        CertificateValidity::NotObservable => CertificateBody {
            state: "not_observable",
            not_before: None,
            not_after: None,
        },
        CertificateValidity::NotCaptured => CertificateBody {
            state: "not_captured",
            not_before: None,
            not_after: None,
        },
        CertificateValidity::Window {
            not_before,
            not_after,
        } => CertificateBody {
            state: "read",
            not_before: Some(not_before),
            not_after: Some(not_after),
        },
    };
    TlsHandshakeBody {
        client: record.client.to_string(),
        client_port: record.client_port,
        server: record.server.to_string(),
        server_port: record.server_port,
        observed_at_ns: record.observed_at_ns,
        version: hs.version,
        version_name: version_name(hs.version),
        cipher: hs.cipher,
        cipher_name: cipher_name(hs.cipher),
        group: hs.group,
        group_name: hs.group.and_then(domain::l7::handshake::group_name),
        key_exchange: key_exchange_label(hs.key_exchange()),
        posture: posture_label(hs.posture()),
        certificate,
    }
}

/// `GET /api/v1/tls/handshakes` - what the TLS handshakes seen on the node
/// negotiated: version, cipher suite, key exchange group and, in TLS 1.2,
/// the certificate's validity.
#[utoipa::path(
    get, path = "/api/v1/tls/handshakes",
    tag = "TLS",
    params(HandshakeQueryParams),
    responses(
        (status = 200, description = "Recent TLS handshakes, newest first", body = TlsHandshakesResponse),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn tls_handshakes(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HandshakeQueryParams>,
) -> Json<TlsHandshakesResponse> {
    Json(list_handshakes(
        state.handshake_log.as_deref(),
        params.limit,
    ))
}

fn list_handshakes(
    log: Option<&domain::l7::handshake::HandshakeLog>,
    limit: Option<usize>,
) -> TlsHandshakesResponse {
    let Some(log) = log else {
        return TlsHandshakesResponse {
            recording: false,
            capacity: 0,
            handshakes: Vec::new(),
        };
    };
    let limit = limit.unwrap_or(DEFAULT_HANDSHAKE_LIMIT).min(log.capacity());
    let handshakes = log
        .recent()
        .iter()
        .take(limit)
        .map(handshake_body)
        .collect();
    TlsHandshakesResponse {
        recording: true,
        capacity: log.capacity(),
        handshakes,
    }
}

/// Connections counted on an edge, or over the node, by posture.
#[derive(Debug, Default, Serialize, ToSchema)]
pub struct PostureCountsBody {
    /// Every connection counted.
    pub connections: u64,
    /// TLS 1.2 or 1.3 over a post-quantum or hybrid group.
    pub post_quantum: u64,
    /// TLS 1.2 or 1.3 over a classical exchange.
    pub classical: u64,
    /// Below TLS 1.2.
    pub legacy_tls: u64,
    /// Requests read in clear text, whatever the protocol.
    pub clear_text: u64,
    /// The clear-text connections by protocol: `http`, `ldap`, `smtp`,
    /// `redis` or `postgres`. A protocol with none is absent.
    pub clear_text_protocols: BTreeMap<&'static str, u64>,
    /// Each class's share of `connections`, from 0 to 1.
    pub shares: PostureSharesBody,
}

/// Each posture's share of the connections counted.
#[derive(Debug, Default, Serialize, ToSchema)]
pub struct PostureSharesBody {
    pub post_quantum: f64,
    pub classical: f64,
    pub legacy_tls: f64,
    pub clear_text: f64,
}

/// One edge between two workloads, on one server port.
#[derive(Debug, Serialize, ToSchema)]
pub struct PostureEdgeBody {
    pub client: ServiceEndBody,
    pub server: ServiceEndBody,
    pub server_port: u16,
    #[serde(flatten)]
    pub counts: PostureCountsBody,
    /// When the first and the last connection were counted, in nanoseconds
    /// since the epoch.
    pub first_seen_ns: u64,
    pub last_seen_ns: u64,
}

/// The cryptographic posture of each edge since the agent started.
#[derive(Debug, Serialize, ToSchema)]
pub struct TlsPostureResponse {
    /// The node's connections, every edge summed.
    pub totals: PostureCountsBody,
    /// Edges dropped, least recently seen first, to make room for new ones.
    pub evicted_edges: u64,
    /// Most connections first.
    pub edges: Vec<PostureEdgeBody>,
}

impl PostureCountsBody {
    fn add(&mut self, edge: &EdgePosture) {
        self.post_quantum = self.post_quantum.saturating_add(edge.post_quantum);
        self.classical = self.classical.saturating_add(edge.classical);
        self.legacy_tls = self.legacy_tls.saturating_add(edge.legacy_tls);
        for (protocol, n) in &edge.clear_text {
            let slot = self
                .clear_text_protocols
                .entry(protocol.as_str())
                .or_default();
            *slot = slot.saturating_add(*n);
        }
        self.clear_text = self
            .clear_text
            .saturating_add(edge.clear_text_connections());
        self.connections = self.connections.saturating_add(edge.connections());
        self.shares = PostureSharesBody {
            post_quantum: share(self.post_quantum, self.connections),
            classical: share(self.classical, self.connections),
            legacy_tls: share(self.legacy_tls, self.connections),
            clear_text: share(self.clear_text, self.connections),
        };
    }
}

#[allow(clippy::cast_precision_loss)]
fn share(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        0.0
    } else {
        part as f64 / whole as f64
    }
}

fn end_body(end: &GraphEnd) -> ServiceEndBody {
    ServiceEndBody {
        service: end.service.clone(),
        address: end.address.to_string(),
    }
}

fn posture_response(reading: &PostureReading) -> TlsPostureResponse {
    let mut totals = PostureCountsBody::default();
    let mut edges: Vec<PostureEdgeBody> = reading
        .edges
        .iter()
        .map(|(key, edge)| {
            totals.add(edge);
            let mut counts = PostureCountsBody::default();
            counts.add(edge);
            PostureEdgeBody {
                client: end_body(&key.client),
                server: end_body(&key.server),
                server_port: key.server_port,
                counts,
                first_seen_ns: edge.first_seen_ns,
                last_seen_ns: edge.last_seen_ns,
            }
        })
        .collect();
    edges.sort_by_key(|edge| std::cmp::Reverse(edge.counts.connections));
    TlsPostureResponse {
        totals,
        evicted_edges: reading.evicted_edges,
        edges,
    }
}

/// `GET /api/v1/tls/posture` - the cryptographic posture of each edge
/// between two workloads: how many connections ran over a post-quantum
/// group, a classical exchange, a TLS version below 1.2, or in clear text,
/// with the clear-text protocols named.
#[utoipa::path(
    get, path = "/api/v1/tls/posture",
    tag = "TLS",
    responses(
        (status = 200, description = "Each edge's posture since the agent started", body = TlsPostureResponse),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
        (status = 404, description = "The L7 dispatcher is not running on this node", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn tls_posture(
    State(state): State<Arc<AppState>>,
) -> Result<Json<TlsPostureResponse>, ApiError> {
    let meter = state.crypto_posture.load_full().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "the L7 dispatcher is not running on this node".to_string(),
    })?;
    Ok(Json(posture_response(&meter.reading())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::l7::crypto_posture::{ClearTextProtocol, PostureEdgeKey};
    use domain::l7::handshake::TlsHandshake;
    use std::net::IpAddr;

    fn a_record(
        certificate: CertificateValidity,
        version: u16,
        group: Option<u16>,
    ) -> HandshakeRecord {
        HandshakeRecord {
            client: IpAddr::from([10, 0, 0, 1]),
            client_port: 51_000,
            server: IpAddr::from([10, 0, 0, 2]),
            server_port: 443,
            observed_at_ns: 7,
            handshake: TlsHandshake {
                version,
                cipher: 0xC02F,
                group,
                certificate,
            },
        }
    }

    #[test]
    fn a_tls13_hybrid_handshake_reads_post_quantum_with_no_certificate() {
        let body = handshake_body(&a_record(
            CertificateValidity::NotObservable,
            0x0304,
            Some(0x11EC),
        ));
        assert_eq!(body.version_name, Some("TLS 1.3"));
        assert_eq!(body.group_name, Some("X25519MLKEM768"));
        assert_eq!(body.key_exchange, "post_quantum_hybrid");
        assert_eq!(body.posture, "post_quantum");
        assert_eq!(body.certificate.state, "not_observable");
        assert!(body.certificate.not_after.is_none());
        let json = serde_json::to_value(&body).unwrap();
        assert!(json["certificate"].get("not_after").is_none());
    }

    #[test]
    fn a_tls12_handshake_carries_the_certificate_window() {
        let body = handshake_body(&a_record(
            CertificateValidity::Window {
                not_before: 1,
                not_after: 2,
            },
            0x0303,
            Some(0x001D),
        ));
        assert_eq!(
            body.cipher_name,
            Some("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
        );
        assert_eq!(body.posture, "classical");
        assert_eq!(body.certificate.state, "read");
        assert_eq!(body.certificate.not_after, Some(2));
    }

    #[test]
    fn below_tls12_reads_legacy() {
        let body = handshake_body(&a_record(CertificateValidity::NotCaptured, 0x0301, None));
        assert_eq!(body.posture, "legacy_tls");
        assert_eq!(body.certificate.state, "not_captured");
        assert_eq!(body.key_exchange, "unknown");
    }

    #[test]
    fn the_list_answers_not_recording_without_a_log_and_honours_the_limit() {
        let empty = list_handshakes(None, None);
        assert!(!empty.recording);

        let log = Arc::new(domain::l7::handshake::HandshakeLog::new(8));
        for _ in 0..3 {
            log.record(a_record(
                CertificateValidity::NotObservable,
                0x0304,
                Some(0x001D),
            ));
        }
        let listed = list_handshakes(Some(&log), Some(2));
        assert!(listed.recording);
        assert_eq!(listed.capacity, 8);
        assert_eq!(listed.handshakes.len(), 2);
    }

    #[test]
    fn the_posture_sums_every_edge_and_puts_the_busiest_first() {
        let end = |last: u8, service: Option<&str>| GraphEnd {
            service: service.map(str::to_string),
            address: IpAddr::from([10, 0, 0, last]),
        };
        let quiet = EdgePosture {
            post_quantum: 1,
            first_seen_ns: 1,
            last_seen_ns: 2,
            ..EdgePosture::default()
        };
        let busy = EdgePosture {
            classical: 1,
            legacy_tls: 1,
            clear_text: BTreeMap::from([(ClearTextProtocol::Ldap, 2)]),
            ..EdgePosture::default()
        };
        let reading = PostureReading {
            edges: vec![
                (
                    PostureEdgeKey {
                        client: end(1, Some("shop/web")),
                        server: end(2, None),
                        server_port: 443,
                    },
                    quiet,
                ),
                (
                    PostureEdgeKey {
                        client: end(1, Some("shop/web")),
                        server: end(3, None),
                        server_port: 389,
                    },
                    busy,
                ),
            ],
            evicted_edges: 0,
        };
        let response = posture_response(&reading);
        assert_eq!(response.totals.connections, 5);
        assert_eq!(response.totals.clear_text_protocols["ldap"], 2);
        assert!((response.totals.shares.clear_text - 0.4).abs() < 1e-9);
        assert!((response.totals.shares.post_quantum - 0.2).abs() < 1e-9);
        assert_eq!(response.edges[0].server_port, 389);
        assert_eq!(response.edges[0].counts.connections, 4);
        let json = serde_json::to_value(&response.edges[1]).unwrap();
        assert_eq!(json["post_quantum"], 1);
        assert_eq!(json["client"]["service"], "shop/web");
        assert!(json["server"].get("service").is_none());
    }

    #[test]
    fn group_name_maps_known_groups() {
        assert_eq!(group_name(NamedGroup::X25519MLKEM768), "X25519MLKEM768");
        assert_eq!(group_name(NamedGroup::X25519), "X25519");
        assert_eq!(group_name(NamedGroup::secp256r1), "secp256r1");
    }

    #[test]
    fn post_quantum_flag_matches_hybrid_group() {
        // The PQ hybrid group is the only one flagged post-quantum.
        assert_eq!(group_name(NamedGroup::X25519MLKEM768), "X25519MLKEM768");
        assert_eq!(NamedGroup::X25519MLKEM768, NamedGroup::X25519MLKEM768);
        assert_ne!(NamedGroup::X25519, NamedGroup::X25519MLKEM768);
    }
}
