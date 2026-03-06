use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use serde::Serialize;

use super::error::ApiError;
use super::state::AppState;

// ── Response DTOs ─────────────────────────────────────────────────

#[derive(Serialize)]
pub struct ZoneStatusResponse {
    pub enabled: bool,
    pub zone_count: usize,
    pub policy_count: usize,
}

#[derive(Serialize)]
pub struct ZoneResponse {
    pub id: String,
    pub interfaces: Vec<String>,
    pub default_policy: String,
}

#[derive(Serialize)]
pub struct ZonePolicyResponse {
    pub from: String,
    pub to: String,
    pub policy: String,
}

// ── Handlers ──────────────────────────────────────────────────────

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
            default_policy: format!("{:?}", z.default_policy).to_lowercase(),
        })
        .collect();
    Ok(Json(zones))
}

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
            policy: format!("{:?}", p.policy).to_lowercase(),
        })
        .collect();
    Ok(Json(policies))
}
