use std::sync::Arc;

use axum::Extension;
use axum::Json;
use axum::extract::{Path, State};
use domain::auth::entity::JwtClaims;
use domain::zone::entity::{Zone, ZonePair, ZonePolicy};
use domain::zone::error::ZoneError;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::error::{ApiError, ErrorBody};
use super::middleware::rbac::require_write_access;
use super::state::AppState;

// ── Response DTOs ─────────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
pub struct ZoneStatusResponse {
    pub enabled: bool,
    pub zone_count: usize,
    pub policy_count: usize,
}

#[derive(Serialize, ToSchema)]
pub struct ZoneResponse {
    pub id: String,
    pub interfaces: Vec<String>,
    pub default_policy: String,
}

#[derive(Serialize, ToSchema)]
pub struct ZonePolicyResponse {
    /// Stable identifier `{from}__{to}` for API addressing.
    pub id: String,
    pub from: String,
    pub to: String,
    pub policy: String,
    /// Alias of `policy`, exposed under the `action` field name.
    pub action: String,
}

impl ZonePolicyResponse {
    fn from_pair(p: &ZonePair) -> Self {
        let policy = format_zone_policy(p.policy).to_string();
        Self {
            id: format!("{}__{}", p.from, p.to),
            from: p.from.clone(),
            to: p.to.clone(),
            action: policy.clone(),
            policy,
        }
    }
}

fn format_zone_policy(policy: ZonePolicy) -> &'static str {
    match policy {
        ZonePolicy::Allow => "allow",
        ZonePolicy::Deny => "deny",
    }
}

/// Map an `allow`/`deny`/anything-else action string to a domain policy.
/// Only `allow` permits traffic; every other verb (deny, alert, …) denies.
fn parse_zone_action(action: &str) -> ZonePolicy {
    if action.eq_ignore_ascii_case("allow") {
        ZonePolicy::Allow
    } else {
        ZonePolicy::Deny
    }
}

fn map_zone_error(err: &ZoneError) -> ApiError {
    match err {
        ZoneError::NotFound { id } => ApiError::NotFound {
            code: "ZONE_NOT_FOUND",
            message: format!("zone not found: {id}"),
        },
        ZoneError::PairNotFound { from, to } => ApiError::NotFound {
            code: "ZONE_POLICY_NOT_FOUND",
            message: format!("zone policy not found: {from} -> {to}"),
        },
        ZoneError::Duplicate { id } => ApiError::Conflict {
            code: "ZONE_CONFLICT",
            message: format!("duplicate zone: {id}"),
        },
        ZoneError::Invalid { reason } => ApiError::BadRequest {
            code: "ZONE_INVALID",
            message: reason.clone(),
        },
    }
}

// ── Request DTOs ──────────────────────────────────────────────────

#[derive(Deserialize, ToSchema)]
pub struct CreateZoneRequest {
    /// Zone name; used as the zone identifier.
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    /// Subnets are accepted for forward-compatibility but not yet enforced.
    #[serde(default)]
    pub subnets: Option<Vec<String>>,
    /// Network interfaces grouped into this zone.
    #[serde(default)]
    pub interfaces: Option<Vec<String>>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

#[derive(Deserialize, ToSchema)]
pub struct CreateZonePolicyRequest {
    #[serde(default)]
    pub name: Option<String>,
    /// Source zone identifier.
    pub source_zone: String,
    /// Destination zone identifier.
    pub dest_zone: String,
    /// `allow` permits traffic; any other verb denies.
    pub action: String,
    #[serde(default)]
    pub priority: Option<u32>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

// ── Handlers ──────────────────────────────────────────────────────

/// `GET /api/v1/zones/status` — zone service status.
#[utoipa::path(
    get, path = "/api/v1/zones/status",
    tag = "Zones",
    responses((status = 200, description = "Zone status", body = ZoneStatusResponse),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn zone_status(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ZoneStatusResponse>, ApiError> {
    let zone = state.zone_service.as_ref().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "Zone service not enabled".to_string(),
    })?;
    let svc = zone.read().await;
    Ok(Json(ZoneStatusResponse {
        enabled: svc.enabled(),
        zone_count: svc.zone_count(),
        policy_count: svc.policy_count(),
    }))
}

/// `GET /api/v1/zones` — list security zones.
#[utoipa::path(
    get, path = "/api/v1/zones",
    tag = "Zones",
    responses((status = 200, description = "Zone list", body = Vec<ZoneResponse>),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn list_zones(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<ZoneResponse>>, ApiError> {
    let zone = state.zone_service.as_ref().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "Zone service not enabled".to_string(),
    })?;
    let svc = zone.read().await;
    let zones: Vec<ZoneResponse> = svc
        .zones()
        .iter()
        .map(|z| ZoneResponse {
            id: z.id.clone(),
            interfaces: z.interfaces.clone(),
            default_policy: format_zone_policy(z.default_policy).to_string(),
        })
        .collect();
    Ok(Json(zones))
}

/// `GET /api/v1/zones/policies` — list inter-zone policies.
#[utoipa::path(
    get, path = "/api/v1/zones/policies",
    tag = "Zones",
    responses((status = 200, description = "Zone policies", body = Vec<ZonePolicyResponse>),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn list_zone_policies(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<ZonePolicyResponse>>, ApiError> {
    let zone = state.zone_service.as_ref().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "Zone service not enabled".to_string(),
    })?;
    let svc = zone.read().await;
    let policies: Vec<ZonePolicyResponse> = svc
        .zone_policies()
        .iter()
        .map(ZonePolicyResponse::from_pair)
        .collect();
    Ok(Json(policies))
}

/// `POST /api/v1/zones` — create a security zone.
#[utoipa::path(
    post, path = "/api/v1/zones",
    tag = "Zones",
    request_body = CreateZoneRequest,
    responses((status = 201, description = "Zone created", body = ZoneResponse),
        (status = 400, description = "Invalid zone", body = ErrorBody),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
        (status = 409, description = "Zone conflict", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn create_zone(
    State(state): State<Arc<AppState>>,
    claims: Option<Extension<JwtClaims>>,
    Json(req): Json<CreateZoneRequest>,
) -> Result<(axum::http::StatusCode, Json<ZoneResponse>), ApiError> {
    if let Some(Extension(ref claims)) = claims {
        require_write_access(claims)?;
    }
    let zone = state.zone_service.as_ref().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "Zone service not enabled".to_string(),
    })?;
    let new_zone = Zone {
        id: req.name,
        interfaces: req.interfaces.unwrap_or_default(),
        default_policy: ZonePolicy::Deny,
    };
    let mut svc = zone.write().await;
    svc.add_zone(new_zone.clone())
        .map_err(|e| map_zone_error(&e))?;
    Ok((
        axum::http::StatusCode::CREATED,
        Json(ZoneResponse {
            id: new_zone.id,
            interfaces: new_zone.interfaces,
            default_policy: format_zone_policy(new_zone.default_policy).to_string(),
        }),
    ))
}

/// `DELETE /api/v1/zones/{id}` — remove a security zone.
#[utoipa::path(
    delete, path = "/api/v1/zones/{id}",
    tag = "Zones",
    params(("id" = String, Path, description = "Zone identifier")),
    responses((status = 204, description = "Zone deleted"),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
        (status = 404, description = "Zone not found", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn delete_zone(
    State(state): State<Arc<AppState>>,
    claims: Option<Extension<JwtClaims>>,
    Path(id): Path<String>,
) -> Result<axum::http::StatusCode, ApiError> {
    if let Some(Extension(ref claims)) = claims {
        require_write_access(claims)?;
    }
    let zone = state.zone_service.as_ref().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "Zone service not enabled".to_string(),
    })?;
    let mut svc = zone.write().await;
    svc.remove_zone(&id).map_err(|e| map_zone_error(&e))?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// `POST /api/v1/zones/policies` — create an inter-zone policy.
#[utoipa::path(
    post, path = "/api/v1/zones/policies",
    tag = "Zones",
    request_body = CreateZonePolicyRequest,
    responses((status = 201, description = "Zone policy created", body = ZonePolicyResponse),
        (status = 400, description = "Invalid policy", body = ErrorBody),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn create_zone_policy(
    State(state): State<Arc<AppState>>,
    claims: Option<Extension<JwtClaims>>,
    Json(req): Json<CreateZonePolicyRequest>,
) -> Result<(axum::http::StatusCode, Json<ZonePolicyResponse>), ApiError> {
    if let Some(Extension(ref claims)) = claims {
        require_write_access(claims)?;
    }
    let zone = state.zone_service.as_ref().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "Zone service not enabled".to_string(),
    })?;
    let pair = ZonePair {
        from: req.source_zone,
        to: req.dest_zone,
        policy: parse_zone_action(&req.action),
    };
    let mut svc = zone.write().await;
    svc.add_policy(pair.clone())
        .map_err(|e| map_zone_error(&e))?;
    Ok((
        axum::http::StatusCode::CREATED,
        Json(ZonePolicyResponse::from_pair(&pair)),
    ))
}

/// `DELETE /api/v1/zones/policies/{id}` — remove an inter-zone policy.
#[utoipa::path(
    delete, path = "/api/v1/zones/policies/{id}",
    tag = "Zones",
    params(("id" = String, Path, description = "Policy identifier `{from}__{to}`")),
    responses((status = 204, description = "Zone policy deleted"),
        (status = 400, description = "Invalid policy id", body = ErrorBody),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
        (status = 404, description = "Zone policy not found", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn delete_zone_policy(
    State(state): State<Arc<AppState>>,
    claims: Option<Extension<JwtClaims>>,
    Path(id): Path<String>,
) -> Result<axum::http::StatusCode, ApiError> {
    if let Some(Extension(ref claims)) = claims {
        require_write_access(claims)?;
    }
    let zone = state.zone_service.as_ref().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "Zone service not enabled".to_string(),
    })?;
    let (from, to) = id.split_once("__").ok_or(ApiError::BadRequest {
        code: "INVALID_POLICY_ID",
        message: "policy id must be of the form '{from}__{to}'".to_string(),
    })?;
    let mut svc = zone.write().await;
    svc.remove_policy(from, to)
        .map_err(|e| map_zone_error(&e))?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}
