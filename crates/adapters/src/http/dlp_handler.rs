use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use serde::Serialize;
use utoipa::ToSchema;

use super::error::ApiError;
use super::state::AppState;

// ── Response DTOs ─────────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
pub struct DlpStatusResponse {
    pub enabled: bool,
    pub mode: String,
    pub pattern_count: usize,
}

#[derive(Serialize, ToSchema)]
pub struct DlpPatternResponse {
    pub id: String,
    pub name: String,
    pub regex: String,
    pub severity: String,
    pub data_type: String,
    pub enabled: bool,
}

// ── Handlers ──────────────────────────────────────────────────────

/// `GET /api/v1/dlp/status` — DLP status.
#[utoipa::path(
    get, path = "/api/v1/dlp/status",
    tag = "DLP",
    responses((status = 200, description = "DLP status", body = DlpStatusResponse))
)]
pub async fn dlp_status(
    State(state): State<Arc<AppState>>,
) -> Result<Json<DlpStatusResponse>, ApiError> {
    let dlp = state.dlp_service.as_ref().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "DLP not enabled".to_string(),
    })?;
    let svc = dlp.read().await;
    Ok(Json(DlpStatusResponse {
        enabled: svc.enabled(),
        mode: svc.mode().as_str().to_string(),
        pattern_count: svc.pattern_count(),
    }))
}

/// `GET /api/v1/dlp/patterns` — list DLP patterns.
#[utoipa::path(
    get, path = "/api/v1/dlp/patterns",
    tag = "DLP",
    responses((status = 200, description = "DLP patterns", body = Vec<DlpPatternResponse>))
)]
pub async fn list_dlp_patterns(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<DlpPatternResponse>>, ApiError> {
    let dlp = state.dlp_service.as_ref().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "DLP not enabled".to_string(),
    })?;
    let svc = dlp.read().await;
    let patterns: Vec<DlpPatternResponse> = svc
        .list_patterns()
        .iter()
        .map(|p| DlpPatternResponse {
            id: p.id.0.clone(),
            name: p.name.clone(),
            regex: p.regex.clone(),
            severity: format!("{:?}", p.severity).to_lowercase(),
            data_type: p.data_type.clone(),
            enabled: p.enabled,
        })
        .collect();
    Ok(Json(patterns))
}
