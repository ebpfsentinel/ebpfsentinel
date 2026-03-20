use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::error::{ApiError, ErrorBody};
use super::state::AppState;

// ── Response DTOs ─────────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
pub struct NatStatusResponse {
    pub enabled: bool,
    pub rule_count: usize,
}

#[derive(Serialize, ToSchema)]
pub struct NatRuleResponse {
    pub id: String,
    pub nat_type: String,
    pub direction: String,
    pub priority: u32,
    pub enabled: bool,
}

// ── Handlers ──────────────────────────────────────────────────────

/// `GET /api/v1/nat/status` — NAT status.
#[utoipa::path(
    get, path = "/api/v1/nat/status",
    tag = "NAT",
    responses((status = 200, description = "NAT status", body = NatStatusResponse),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn nat_status(
    State(state): State<Arc<AppState>>,
) -> Result<Json<NatStatusResponse>, ApiError> {
    let nat = state.nat_service.as_ref().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "NAT not enabled".to_string(),
    })?;
    let svc = nat.read().await;
    Ok(Json(NatStatusResponse {
        enabled: svc.enabled(),
        rule_count: svc.rule_count(),
    }))
}

/// `GET /api/v1/nat/rules` — list NAT rules.
#[utoipa::path(
    get, path = "/api/v1/nat/rules",
    tag = "NAT",
    responses((status = 200, description = "NAT rules", body = Vec<NatRuleResponse>),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn list_nat_rules(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<NatRuleResponse>>, ApiError> {
    let nat = state.nat_service.as_ref().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "NAT not enabled".to_string(),
    })?;
    let svc = nat.read().await;
    let mut rules: Vec<NatRuleResponse> = svc
        .dnat_rules()
        .iter()
        .map(|r| NatRuleResponse {
            id: r.id.0.clone(),
            nat_type: format!("{:?}", r.nat_type).to_lowercase(),
            direction: "dnat".to_string(),
            priority: r.priority,
            enabled: r.enabled,
        })
        .collect();
    rules.extend(svc.snat_rules().iter().map(|r| NatRuleResponse {
        id: r.id.0.clone(),
        nat_type: format!("{:?}", r.nat_type).to_lowercase(),
        direction: "snat".to_string(),
        priority: r.priority,
        enabled: r.enabled,
    }));
    Ok(Json(rules))
}

// ── NPTv6 DTOs ───────────────────────────────────────────────────

/// Response DTO for an `NPTv6` prefix translation rule.
#[derive(Serialize, ToSchema)]
pub struct NptV6RuleResponse {
    pub id: String,
    pub enabled: bool,
    pub internal_prefix: String,
    pub external_prefix: String,
    pub prefix_len: u8,
}

/// Request DTO for creating an `NPTv6` prefix translation rule.
#[derive(Deserialize, ToSchema)]
pub struct CreateNptV6RuleRequest {
    pub id: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub internal_prefix: String,
    pub external_prefix: String,
    pub prefix_len: u8,
}

fn default_true() -> bool {
    true
}

// ── NPTv6 Handlers ──────────────────────────────────────────────

/// `GET /api/v1/nat/nptv6` -- list `NPTv6` rules.
#[utoipa::path(
    get, path = "/api/v1/nat/nptv6",
    tag = "NAT",
    responses((status = 200, description = "NPTv6 rules", body = Vec<NptV6RuleResponse>),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn list_nptv6_rules(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<NptV6RuleResponse>>, ApiError> {
    let nat = state.nat_service.as_ref().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "NAT not enabled".to_string(),
    })?;
    let svc = nat.read().await;
    let rules: Vec<NptV6RuleResponse> = svc
        .nptv6_rules()
        .iter()
        .map(|r| NptV6RuleResponse {
            id: r.id.clone(),
            enabled: r.enabled,
            internal_prefix: r.internal_prefix.to_string(),
            external_prefix: r.external_prefix.to_string(),
            prefix_len: r.prefix_len,
        })
        .collect();
    Ok(Json(rules))
}

/// `POST /api/v1/nat/nptv6` -- create an `NPTv6` rule.
#[utoipa::path(
    post, path = "/api/v1/nat/nptv6",
    tag = "NAT",
    request_body = CreateNptV6RuleRequest,
    responses(
        (status = 201, description = "NPTv6 rule created", body = NptV6RuleResponse),
        (status = 400, description = "Invalid rule"),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn create_nptv6_rule(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateNptV6RuleRequest>,
) -> Result<Json<NptV6RuleResponse>, ApiError> {
    let nat = state.nat_service.as_ref().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "NAT not enabled".to_string(),
    })?;

    let internal_prefix: std::net::Ipv6Addr =
        req.internal_prefix
            .parse()
            .map_err(|e| ApiError::BadRequest {
                code: "INVALID_PREFIX",
                message: format!("invalid internal_prefix: {e}"),
            })?;
    let external_prefix: std::net::Ipv6Addr =
        req.external_prefix
            .parse()
            .map_err(|e| ApiError::BadRequest {
                code: "INVALID_PREFIX",
                message: format!("invalid external_prefix: {e}"),
            })?;

    let rule = domain::nat::entity::NptV6Rule {
        id: req.id.clone(),
        enabled: req.enabled,
        internal_prefix,
        external_prefix,
        prefix_len: req.prefix_len,
        group_mask: 0,
    };

    let mut svc = nat.write().await;
    svc.add_nptv6_rule(rule).map_err(|e| ApiError::BadRequest {
        code: "INVALID_RULE",
        message: e.to_string(),
    })?;

    Ok(Json(NptV6RuleResponse {
        id: req.id,
        enabled: req.enabled,
        internal_prefix: internal_prefix.to_string(),
        external_prefix: external_prefix.to_string(),
        prefix_len: req.prefix_len,
    }))
}

/// `DELETE /api/v1/nat/nptv6/{id}` -- delete an `NPTv6` rule.
#[utoipa::path(
    delete, path = "/api/v1/nat/nptv6/{id}",
    tag = "NAT",
    params(("id" = String, Path, description = "NPTv6 rule ID")),
    responses(
        (status = 204, description = "NPTv6 rule deleted"),
        (status = 404, description = "Rule not found"),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn delete_nptv6_rule(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<()>, ApiError> {
    let nat = state.nat_service.as_ref().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "NAT not enabled".to_string(),
    })?;
    let mut svc = nat.write().await;
    svc.remove_nptv6_rule(&id).map_err(|e| ApiError::NotFound {
        code: "RULE_NOT_FOUND",
        message: e.to_string(),
    })?;
    Ok(Json(()))
}
