use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use serde::Serialize;
use utoipa::ToSchema;

use super::error::ApiError;
use super::state::AppState;

// ── Response DTOs ─────────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
pub struct AliasStatusResponse {
    pub alias_count: usize,
}

// ── Handlers ──────────────────────────────────────────────────────

/// `GET /api/v1/aliases/status` — alias service status.
#[utoipa::path(
    get, path = "/api/v1/aliases/status",
    tag = "Aliases",
    responses((status = 200, description = "Alias status", body = AliasStatusResponse))
)]
pub async fn alias_status(
    State(state): State<Arc<AppState>>,
) -> Result<Json<AliasStatusResponse>, ApiError> {
    let alias = state.alias_service.as_ref().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "Alias service not enabled".to_string(),
    })?;
    let svc = alias.read().await;
    Ok(Json(AliasStatusResponse {
        alias_count: svc.alias_count(),
    }))
}
