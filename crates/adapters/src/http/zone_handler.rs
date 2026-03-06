use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use serde::Serialize;
use utoipa::ToSchema;

use super::error::ApiError;
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
    pub from: String,
    pub to: String,
    pub policy: String,
}

fn format_zone_policy(policy: domain::zone::entity::ZonePolicy) -> &'static str {
    match policy {
        domain::zone::entity::ZonePolicy::Allow => "allow",
        domain::zone::entity::ZonePolicy::Deny => "deny",
    }
}

// ── Handlers ──────────────────────────────────────────────────────

/// `GET /api/v1/zones/status` — zone service status.
#[utoipa::path(
    get, path = "/api/v1/zones/status",
    tag = "Zones",
    responses((status = 200, description = "Zone status", body = ZoneStatusResponse))
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
    responses((status = 200, description = "Zone list", body = Vec<ZoneResponse>))
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
    responses((status = 200, description = "Zone policies", body = Vec<ZonePolicyResponse>))
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
        .map(|p| ZonePolicyResponse {
            from: p.from.clone(),
            to: p.to.clone(),
            policy: format_zone_policy(p.policy).to_string(),
        })
        .collect();
    Ok(Json(policies))
}
