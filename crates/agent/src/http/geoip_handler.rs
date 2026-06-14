use std::net::IpAddr;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Query, State};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use super::error::{ApiError, ErrorBody};
use super::state::AppState;

// ── Response DTOs ─────────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
pub struct GeoIpStatusResponse {
    /// Whether `GeoIP` enrichment is enabled in the agent configuration.
    pub enabled: bool,
    /// Whether an mmdb-backed lookup database is loaded and ready.
    pub ready: bool,
}

#[derive(Serialize, ToSchema)]
pub struct GeoIpLookupResponse {
    pub ip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub as_org: Option<String>,
}

#[derive(Deserialize, IntoParams)]
pub struct GeoIpLookupQuery {
    /// IP address to resolve (IPv4 or IPv6).
    pub ip: String,
}

// ── Handlers ──────────────────────────────────────────────────────

/// `GET /api/v1/geoip/status` — `GeoIP` enrichment status.
#[utoipa::path(
    get, path = "/api/v1/geoip/status",
    tag = "GeoIP",
    responses((status = 200, description = "GeoIP status", body = GeoIpStatusResponse),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn geoip_status(State(state): State<Arc<AppState>>) -> Json<GeoIpStatusResponse> {
    let enabled = state
        .config
        .read()
        .await
        .geoip
        .as_ref()
        .is_some_and(|g| g.enabled);
    let ready = state.geoip_port.as_ref().is_some_and(|p| p.is_ready());
    Json(GeoIpStatusResponse { enabled, ready })
}

/// `GET /api/v1/geoip/lookup?ip=<addr>` — resolve an IP to `GeoIP` info.
#[utoipa::path(
    get, path = "/api/v1/geoip/lookup",
    tag = "GeoIP",
    params(GeoIpLookupQuery),
    responses((status = 200, description = "GeoIP lookup result", body = GeoIpLookupResponse),
        (status = 400, description = "Invalid IP address", body = ErrorBody),
        (status = 404, description = "GeoIP not available", body = ErrorBody),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn geoip_lookup(
    State(state): State<Arc<AppState>>,
    Query(query): Query<GeoIpLookupQuery>,
) -> Result<Json<GeoIpLookupResponse>, ApiError> {
    let port = state.geoip_port.as_ref().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "GeoIP lookup not available".to_string(),
    })?;
    let ip: IpAddr = query.ip.parse().map_err(|_| ApiError::BadRequest {
        code: "INVALID_IP",
        message: format!("invalid IP address: {}", query.ip),
    })?;
    let info = port.lookup(&ip);
    Ok(Json(GeoIpLookupResponse {
        ip: query.ip,
        country_code: info.as_ref().and_then(|i| i.country_code.clone()),
        country_name: info.as_ref().and_then(|i| i.country_name.clone()),
        city: info.as_ref().and_then(|i| i.city.clone()),
        asn: info.as_ref().and_then(|i| i.asn),
        as_org: info.and_then(|i| i.as_org),
    }))
}
