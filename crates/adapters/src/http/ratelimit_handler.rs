use std::sync::Arc;

use axum::Extension;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use domain::auth::entity::JwtClaims;
use domain::common::entity::RuleId;
use domain::ratelimit::entity::{
    RateLimitAction, RateLimitAlgorithm, RateLimitPolicy, RateLimitScope,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::error::{ApiError, ErrorBody};
use super::middleware::rbac::require_write_access;
use super::state::AppState;
use super::validation::{
    MAX_ID_LENGTH, MAX_PATTERN_LENGTH, MAX_SHORT_STRING_LENGTH, validate_string_length,
};

// ── Request / Response DTOs ─────────────────────────────────────────

#[derive(Deserialize, ToSchema)]
pub struct CreateRateLimitRuleRequest {
    pub id: String,
    pub rate: u64,
    pub burst: u64,
    #[serde(default)]
    pub src_ip: Option<String>,
    #[serde(default = "default_action")]
    pub action: String,
    #[serde(default = "default_scope")]
    pub scope: String,
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_action() -> String {
    "drop".to_string()
}
fn default_scope() -> String {
    "source_ip".to_string()
}
fn default_algorithm() -> String {
    "token_bucket".to_string()
}
fn default_enabled() -> bool {
    true
}

#[derive(Serialize, ToSchema)]
pub struct RateLimitRuleResponse {
    pub id: String,
    pub scope: String,
    pub rate: u64,
    pub burst: u64,
    pub action: String,
    pub algorithm: String,
    pub src_ip: Option<String>,
    pub enabled: bool,
}

impl RateLimitRuleResponse {
    fn from_policy(p: &RateLimitPolicy) -> Self {
        Self {
            id: p.id.0.clone(),
            scope: format_scope(p.scope),
            rate: p.rate,
            burst: p.burst,
            action: format_action(p.action),
            algorithm: format_algorithm(p.algorithm),
            src_ip: p.src_ip.map(format_cidr),
            enabled: p.enabled,
        }
    }
}

// ── Handlers ────────────────────────────────────────────────────────

/// `GET /api/v1/ratelimit/rules` — list all rate limit rules.
#[utoipa::path(
    get, path = "/api/v1/ratelimit/rules",
    tag = "Rate Limiting",
    responses((status = 200, description = "List of rate limit rules", body = Vec<RateLimitRuleResponse>))
)]
pub async fn list_ratelimit_rules(
    State(state): State<Arc<AppState>>,
) -> Json<Vec<RateLimitRuleResponse>> {
    let svc = state.ratelimit_service.read().await;
    let rules: Vec<RateLimitRuleResponse> = svc
        .policies()
        .iter()
        .map(RateLimitRuleResponse::from_policy)
        .collect();
    Json(rules)
}

/// `POST /api/v1/ratelimit/rules` — create a new rate limit rule.
#[utoipa::path(
    post, path = "/api/v1/ratelimit/rules",
    tag = "Rate Limiting",
    request_body = CreateRateLimitRuleRequest,
    responses(
        (status = 201, description = "Rule created", body = RateLimitRuleResponse),
        (status = 400, description = "Validation error", body = ErrorBody),
        (status = 409, description = "Duplicate rule", body = ErrorBody),
    )
)]
pub async fn create_ratelimit_rule(
    State(state): State<Arc<AppState>>,
    claims: Option<Extension<JwtClaims>>,
    Json(req): Json<CreateRateLimitRuleRequest>,
) -> Result<impl IntoResponse, ApiError> {
    if let Some(Extension(ref claims)) = claims {
        require_write_access(claims)?;
    }
    let policy = parse_request(req)?;
    let rule_id = policy.id.0.clone();
    let after_json = serde_json::to_string(&policy).ok();

    let mut svc = state.ratelimit_service.write().await;
    svc.add_policy(policy.clone())?;
    drop(svc);

    tracing::info!(rule_id = %rule_id, "ratelimit rule created via API");

    state.audit_service.read().await.record_rule_change(
        domain::audit::entity::AuditComponent::Ratelimit,
        domain::audit::entity::AuditAction::RuleAdded,
        domain::audit::rule_change::ChangeActor::Api,
        &rule_id,
        None,
        after_json,
    );

    Ok((
        StatusCode::CREATED,
        Json(RateLimitRuleResponse::from_policy(&policy)),
    ))
}

/// `DELETE /api/v1/ratelimit/rules/{id}` — delete a rate limit rule.
#[utoipa::path(
    delete, path = "/api/v1/ratelimit/rules/{id}",
    tag = "Rate Limiting",
    params(("id" = String, Path, description = "Rule identifier")),
    responses(
        (status = 204, description = "Rule deleted"),
        (status = 404, description = "Rule not found", body = ErrorBody),
    )
)]
pub async fn delete_ratelimit_rule(
    State(state): State<Arc<AppState>>,
    claims: Option<Extension<JwtClaims>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    if let Some(Extension(ref claims)) = claims {
        require_write_access(claims)?;
    }
    // Capture before snapshot for audit trail
    let before_json = {
        let svc = state.ratelimit_service.read().await;
        svc.policies()
            .iter()
            .find(|p| p.id.0 == id)
            .and_then(|p| serde_json::to_string(p).ok())
    };

    let mut svc = state.ratelimit_service.write().await;
    svc.remove_policy(&RuleId(id.clone()))?;
    drop(svc);

    tracing::info!(rule_id = %id, "ratelimit rule deleted via API");

    state.audit_service.read().await.record_rule_change(
        domain::audit::entity::AuditComponent::Ratelimit,
        domain::audit::entity::AuditAction::RuleRemoved,
        domain::audit::rule_change::ChangeActor::Api,
        &id,
        before_json,
        None,
    );

    Ok(StatusCode::NO_CONTENT)
}

// ── Request parsing ─────────────────────────────────────────────────

fn parse_request(req: CreateRateLimitRuleRequest) -> Result<RateLimitPolicy, ApiError> {
    validate_string_length("id", &req.id, MAX_ID_LENGTH)?;
    validate_string_length("action", &req.action, MAX_SHORT_STRING_LENGTH)?;
    validate_string_length("scope", &req.scope, MAX_SHORT_STRING_LENGTH)?;
    validate_string_length("algorithm", &req.algorithm, MAX_SHORT_STRING_LENGTH)?;
    if let Some(ref s) = req.src_ip {
        validate_string_length("src_ip", s, MAX_PATTERN_LENGTH)?;
    }

    let action = match req.action.to_lowercase().as_str() {
        "drop" | "deny" | "block" => RateLimitAction::Drop,
        "pass" | "allow" => RateLimitAction::Pass,
        _ => {
            return Err(ApiError::BadRequest {
                code: "VALIDATION_ERROR",
                message: format!("invalid action '{}': expected drop or pass", req.action),
            });
        }
    };

    let scope = match req.scope.to_lowercase().as_str() {
        "source_ip" | "src_ip" | "per_ip" | "per-ip" => RateLimitScope::SourceIp,
        "global" => RateLimitScope::Global,
        _ => {
            return Err(ApiError::BadRequest {
                code: "VALIDATION_ERROR",
                message: format!(
                    "invalid scope '{}': expected source_ip or global",
                    req.scope
                ),
            });
        }
    };

    let algorithm = match req.algorithm.to_lowercase().as_str() {
        "token_bucket" | "tokenbucket" => RateLimitAlgorithm::TokenBucket,
        "fixed_window" | "fixedwindow" => RateLimitAlgorithm::FixedWindow,
        "sliding_window" | "slidingwindow" => RateLimitAlgorithm::SlidingWindow,
        "leaky_bucket" | "leakybucket" => RateLimitAlgorithm::LeakyBucket,
        _ => {
            return Err(ApiError::BadRequest {
                code: "VALIDATION_ERROR",
                message: format!(
                    "invalid algorithm '{}': expected token_bucket, fixed_window, sliding_window, or leaky_bucket",
                    req.algorithm
                ),
            });
        }
    };

    let src_ip = if let Some(ref cidr_str) = req.src_ip {
        Some(
            infrastructure::config::parse_cidr(cidr_str).map_err(|e| ApiError::BadRequest {
                code: "VALIDATION_ERROR",
                message: format!("invalid CIDR: {e}"),
            })?,
        )
    } else {
        None
    };

    Ok(RateLimitPolicy {
        id: RuleId(req.id),
        scope,
        rate: req.rate,
        burst: req.burst,
        action,
        src_ip,
        enabled: req.enabled,
        algorithm,
    })
}

// ── Formatting helpers ──────────────────────────────────────────────

fn format_scope(s: RateLimitScope) -> String {
    match s {
        RateLimitScope::SourceIp => "source_ip".to_string(),
        RateLimitScope::Global => "global".to_string(),
    }
}

fn format_action(a: RateLimitAction) -> String {
    match a {
        RateLimitAction::Drop => "drop".to_string(),
        RateLimitAction::Pass => "pass".to_string(),
    }
}

fn format_algorithm(a: RateLimitAlgorithm) -> String {
    match a {
        RateLimitAlgorithm::TokenBucket => "token_bucket".to_string(),
        RateLimitAlgorithm::FixedWindow => "fixed_window".to_string(),
        RateLimitAlgorithm::SlidingWindow => "sliding_window".to_string(),
        RateLimitAlgorithm::LeakyBucket => "leaky_bucket".to_string(),
    }
}

fn format_cidr(cidr: domain::firewall::entity::IpNetwork) -> String {
    match cidr {
        domain::firewall::entity::IpNetwork::V4 { addr, prefix_len } => {
            let a = (addr >> 24) & 0xFF;
            let b = (addr >> 16) & 0xFF;
            let c = (addr >> 8) & 0xFF;
            let d = addr & 0xFF;
            format!("{a}.{b}.{c}.{d}/{prefix_len}")
        }
        domain::firewall::entity::IpNetwork::V6 { addr, prefix_len } => {
            let ip = std::net::Ipv6Addr::from(addr);
            format!("{ip}/{prefix_len}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_scope_variants() {
        assert_eq!(format_scope(RateLimitScope::SourceIp), "source_ip");
        assert_eq!(format_scope(RateLimitScope::Global), "global");
    }

    #[test]
    fn format_action_variants() {
        assert_eq!(format_action(RateLimitAction::Drop), "drop");
        assert_eq!(format_action(RateLimitAction::Pass), "pass");
    }

    #[test]
    fn format_algorithm_variants() {
        assert_eq!(
            format_algorithm(RateLimitAlgorithm::TokenBucket),
            "token_bucket"
        );
        assert_eq!(
            format_algorithm(RateLimitAlgorithm::FixedWindow),
            "fixed_window"
        );
        assert_eq!(
            format_algorithm(RateLimitAlgorithm::SlidingWindow),
            "sliding_window"
        );
        assert_eq!(
            format_algorithm(RateLimitAlgorithm::LeakyBucket),
            "leaky_bucket"
        );
    }

    #[test]
    fn format_cidr_output() {
        use domain::firewall::entity::IpNetwork;
        assert_eq!(
            format_cidr(IpNetwork::V4 {
                addr: 0x0A000000,
                prefix_len: 8
            }),
            "10.0.0.0/8"
        );
        assert_eq!(
            format_cidr(IpNetwork::V4 {
                addr: 0xC0A80100,
                prefix_len: 24
            }),
            "192.168.1.0/24"
        );
        assert_eq!(
            format_cidr(IpNetwork::V4 {
                addr: 0xC0A80001,
                prefix_len: 32
            }),
            "192.168.0.1/32"
        );
    }

    #[test]
    fn parse_create_request_valid() {
        let req = CreateRateLimitRuleRequest {
            id: "rl-001".to_string(),
            rate: 1000,
            burst: 2000,
            src_ip: Some("10.0.0.0/8".to_string()),
            action: "drop".to_string(),
            scope: "source_ip".to_string(),
            algorithm: "token_bucket".to_string(),
            enabled: true,
        };
        let policy = parse_request(req).unwrap();
        assert_eq!(policy.id.0, "rl-001");
        assert_eq!(policy.rate, 1000);
        assert_eq!(policy.burst, 2000);
        assert!(policy.src_ip.is_some());
        assert_eq!(policy.action, RateLimitAction::Drop);
        assert_eq!(policy.scope, RateLimitScope::SourceIp);
        assert_eq!(policy.algorithm, RateLimitAlgorithm::TokenBucket);
    }

    #[test]
    fn parse_create_request_with_algorithm() {
        let req = CreateRateLimitRuleRequest {
            id: "rl-001".to_string(),
            rate: 1000,
            burst: 2000,
            src_ip: None,
            action: "drop".to_string(),
            scope: "source_ip".to_string(),
            algorithm: "leaky_bucket".to_string(),
            enabled: true,
        };
        let policy = parse_request(req).unwrap();
        assert_eq!(policy.algorithm, RateLimitAlgorithm::LeakyBucket);
    }

    #[test]
    fn parse_create_request_invalid_action() {
        let req = CreateRateLimitRuleRequest {
            id: "rl-001".to_string(),
            rate: 1000,
            burst: 2000,
            src_ip: None,
            action: "nuke".to_string(),
            scope: "source_ip".to_string(),
            algorithm: "token_bucket".to_string(),
            enabled: true,
        };
        assert!(parse_request(req).is_err());
    }

    #[test]
    fn parse_create_request_invalid_algorithm() {
        let req = CreateRateLimitRuleRequest {
            id: "rl-001".to_string(),
            rate: 1000,
            burst: 2000,
            src_ip: None,
            action: "drop".to_string(),
            scope: "source_ip".to_string(),
            algorithm: "random".to_string(),
            enabled: true,
        };
        assert!(parse_request(req).is_err());
    }

    #[test]
    fn parse_create_request_invalid_cidr() {
        let req = CreateRateLimitRuleRequest {
            id: "rl-001".to_string(),
            rate: 1000,
            burst: 2000,
            src_ip: Some("not-a-cidr".to_string()),
            action: "drop".to_string(),
            scope: "source_ip".to_string(),
            algorithm: "token_bucket".to_string(),
            enabled: true,
        };
        assert!(parse_request(req).is_err());
    }

    #[test]
    fn response_from_policy() {
        let policy = RateLimitPolicy {
            id: RuleId("rl-001".to_string()),
            scope: RateLimitScope::SourceIp,
            rate: 1000,
            burst: 2000,
            action: RateLimitAction::Drop,
            src_ip: None,
            enabled: true,
            algorithm: RateLimitAlgorithm::TokenBucket,
        };
        let resp = RateLimitRuleResponse::from_policy(&policy);
        assert_eq!(resp.id, "rl-001");
        assert_eq!(resp.scope, "source_ip");
        assert_eq!(resp.rate, 1000);
        assert_eq!(resp.burst, 2000);
        assert_eq!(resp.action, "drop");
        assert_eq!(resp.algorithm, "token_bucket");
        assert!(resp.src_ip.is_none());
        assert!(resp.enabled);
    }

    #[test]
    fn response_from_policy_leaky_bucket() {
        let policy = RateLimitPolicy {
            id: RuleId("rl-002".to_string()),
            scope: RateLimitScope::Global,
            rate: 500,
            burst: 1000,
            action: RateLimitAction::Pass,
            src_ip: None,
            enabled: true,
            algorithm: RateLimitAlgorithm::LeakyBucket,
        };
        let resp = RateLimitRuleResponse::from_policy(&policy);
        assert_eq!(resp.algorithm, "leaky_bucket");
        assert_eq!(resp.action, "pass");
        assert_eq!(resp.scope, "global");
    }

    #[test]
    fn response_serialization() {
        let resp = RateLimitRuleResponse {
            id: "rl-001".to_string(),
            scope: "source_ip".to_string(),
            rate: 1000,
            burst: 2000,
            action: "drop".to_string(),
            algorithm: "token_bucket".to_string(),
            src_ip: Some("10.0.0.0/8".to_string()),
            enabled: true,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["id"], "rl-001");
        assert_eq!(json["rate"], 1000);
        assert_eq!(json["src_ip"], "10.0.0.0/8");
        assert_eq!(json["algorithm"], "token_bucket");
    }
}
