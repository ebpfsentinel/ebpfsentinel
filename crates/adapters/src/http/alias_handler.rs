use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::error::ApiError;
use super::state::AppState;

// ── Response DTOs ─────────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
pub struct AliasStatusResponse {
    pub alias_count: usize,
}

/// Request body for `PUT /api/v1/aliases/{id}/content`.
#[derive(Deserialize, ToSchema)]
pub struct ExternalAliasContent {
    /// IP addresses/CIDRs to load into the alias.
    pub ips: Vec<String>,
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

/// `PUT /api/v1/aliases/{id}/content` — push content for an External alias.
#[utoipa::path(
    put, path = "/api/v1/aliases/{id}/content",
    tag = "Aliases",
    request_body = ExternalAliasContent,
    responses(
        (status = 200, description = "Content loaded"),
        (status = 404, description = "Alias not found"),
        (status = 400, description = "Invalid content or alias is not External"),
    )
)]
pub async fn set_external_alias_content(
    State(state): State<Arc<AppState>>,
    Path(alias_id): Path<String>,
    Json(body): Json<ExternalAliasContent>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let alias_svc = state.alias_service.as_ref().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "Alias service not enabled".to_string(),
    })?;

    // Parse IP strings to domain IpNetwork
    let mut ips = Vec::with_capacity(body.ips.len());
    for s in &body.ips {
        let ip = infrastructure::config::parse_cidr(s).map_err(|_| ApiError::BadRequest {
            code: "INVALID_IP",
            message: format!("invalid IP/CIDR: {s}"),
        })?;
        ips.push(ip);
    }

    let mut svc = alias_svc.write().await;
    svc.set_external_ips(&alias_id, &ips)
        .map_err(|e| ApiError::BadRequest {
            code: "SET_EXTERNAL_FAILED",
            message: e.to_string(),
        })?;

    Ok(Json(serde_json::json!({
        "status": "ok",
        "alias": alias_id,
        "ips_loaded": body.ips.len()
    })))
}
