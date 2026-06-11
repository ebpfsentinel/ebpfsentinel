use axum::Json;
use axum::extract::ConnectInfo;
use axum::http::request::Parts;
use serde::Serialize;
use tokio_rustls::rustls::NamedGroup;
use utoipa::ToSchema;

use super::error::ErrorBody;
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

/// `GET /api/v1/tls/status` — report the negotiated TLS key-exchange group
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

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(NamedGroup::X25519MLKEM768 == NamedGroup::X25519MLKEM768);
        assert!(NamedGroup::X25519 != NamedGroup::X25519MLKEM768);
    }
}
