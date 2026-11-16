use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::error::{ApiError, ErrorBody};
use super::state::AppState;

// ── Response DTOs ─────────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
pub struct AliasStatusResponse {
    pub alias_count: usize,
}

/// Response to `PUT /api/v1/aliases/{id}/content`.
#[derive(Serialize, ToSchema)]
pub struct ExternalAliasContentResponse {
    /// Always `ok`: a refused content answers 400.
    pub status: &'static str,
    /// The alias the content was loaded into.
    pub alias: String,
    /// How many addresses the alias now holds.
    pub ips_loaded: usize,
}

/// Request body for `PUT /api/v1/aliases/{id}/content`.
#[derive(Deserialize, ToSchema)]
pub struct ExternalAliasContent {
    /// IP addresses/CIDRs to load into the alias.
    pub ips: Vec<String>,
}

// ── Handlers ──────────────────────────────────────────────────────

/// `GET /api/v1/aliases/status` - alias service status.
#[utoipa::path(
    get, path = "/api/v1/aliases/status",
    tag = "Aliases",
    responses((status = 200, description = "Alias status", body = AliasStatusResponse),
        (status = 404, description = "Feature not enabled on this agent", body = ErrorBody),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
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

/// `PUT /api/v1/aliases/{id}/content` - push content for an External alias.
#[utoipa::path(
    put, path = "/api/v1/aliases/{id}/content",
    tag = "Aliases",
    params(("id" = String, Path, description = "Identifier of an External alias")),
    request_body = ExternalAliasContent,
    responses(
        (status = 200, description = "Content loaded", body = ExternalAliasContentResponse),
        (status = 404, description = "Alias service not enabled", body = ErrorBody),
        (status = 400, description = "Invalid content or alias is not External", body = ErrorBody),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn set_external_alias_content(
    State(state): State<Arc<AppState>>,
    Path(alias_id): Path<String>,
    Json(body): Json<ExternalAliasContent>,
) -> Result<Json<ExternalAliasContentResponse>, ApiError> {
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

    Ok(Json(ExternalAliasContentResponse {
        status: "ok",
        alias: alias_id,
        ips_loaded: body.ips.len(),
    }))
}
