use std::sync::Arc;

use axum::Extension;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use domain::auth::entity::JwtClaims;
use domain::common::entity::RuleId;
use domain::ratelimit::entity::{RateLimitAction, RateLimitAlgorithm, RateLimitPolicy};
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
    /// Source host to limit, as a bare address or a `/32`.
    pub src_ip: String,
    #[serde(default = "default_action")]
    pub action: String,
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_action() -> String {
    "drop".to_string()
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
    pub rate: u64,
    pub burst: u64,
    pub action: String,
    pub algorithm: String,
    pub src_ip: String,
    pub enabled: bool,
}

impl RateLimitRuleResponse {
    fn from_policy(p: &RateLimitPolicy) -> Self {
        Self {
            id: p.id.0.clone(),
            rate: p.rate,
            burst: p.burst,
            action: format_action(p.action),
            algorithm: format_algorithm(p.algorithm),
            src_ip: format_cidr(p.src_ip),
            enabled: p.enabled,
        }
    }
}

// ── Handlers ────────────────────────────────────────────────────────

/// `GET /api/v1/ratelimit/rules` — list all rate limit rules.
#[utoipa::path(
    get, path = "/api/v1/ratelimit/rules",
    tag = "Rate Limiting",
    responses((status = 200, description = "List of rate limit rules", body = Vec<RateLimitRuleResponse>),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
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
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
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

    state.audit_service.record_rule_change(
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
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
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

    state.audit_service.record_rule_change(
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
    validate_string_length("algorithm", &req.algorithm, MAX_SHORT_STRING_LENGTH)?;
    validate_string_length("src_ip", &req.src_ip, MAX_PATTERN_LENGTH)?;

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

    let src_ip =
        infrastructure::config::parse_cidr(&req.src_ip).map_err(|e| ApiError::BadRequest {
            code: "VALIDATION_ERROR",
            message: format!("invalid CIDR: {e}"),
        })?;

    let policy = RateLimitPolicy {
        id: RuleId(req.id),
        rate: req.rate,
        burst: req.burst,
        action,
        src_ip,
        enabled: req.enabled,
        algorithm,
        group_mask: 0,
    };

    // Surface the source-address rules (single host, IPv4, not the default
    // entry) as a 400 rather than a 500 from the engine.
    policy.validate().map_err(|e| ApiError::BadRequest {
        code: "VALIDATION_ERROR",
        message: e.to_string(),
    })?;

    Ok(policy)
}

// ── Formatting helpers ──────────────────────────────────────────────

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
                addr: 0x0A00_0000,
                prefix_len: 8
            }),
            "10.0.0.0/8"
        );
        assert_eq!(
            format_cidr(IpNetwork::V4 {
                addr: 0xC0A8_0100,
                prefix_len: 24
            }),
            "192.168.1.0/24"
        );
        assert_eq!(
            format_cidr(IpNetwork::V4 {
                addr: 0xC0A8_0001,
                prefix_len: 32
            }),
            "192.168.0.1/32"
        );
    }

    fn request(src_ip: &str, action: &str, algorithm: &str) -> CreateRateLimitRuleRequest {
        CreateRateLimitRuleRequest {
            id: "rl-001".to_string(),
            rate: 1000,
            burst: 2000,
            src_ip: src_ip.to_string(),
            action: action.to_string(),
            algorithm: algorithm.to_string(),
            enabled: true,
        }
    }

    #[test]
    fn parse_create_request_valid() {
        let policy = parse_request(request("10.0.0.7", "drop", "token_bucket")).unwrap();
        assert_eq!(policy.id.0, "rl-001");
        assert_eq!(policy.rate, 1000);
        assert_eq!(policy.burst, 2000);
        assert_eq!(policy.action, RateLimitAction::Drop);
        assert_eq!(policy.algorithm, RateLimitAlgorithm::TokenBucket);
    }

    #[test]
    fn parse_create_request_with_algorithm() {
        let policy = parse_request(request("10.0.0.7", "drop", "leaky_bucket")).unwrap();
        assert_eq!(policy.algorithm, RateLimitAlgorithm::LeakyBucket);
    }

    #[test]
    fn parse_create_request_invalid_action() {
        assert!(parse_request(request("10.0.0.7", "nuke", "token_bucket")).is_err());
    }

    #[test]
    fn parse_create_request_invalid_algorithm() {
        assert!(parse_request(request("10.0.0.7", "drop", "random")).is_err());
    }

    #[test]
    fn parse_create_request_invalid_cidr() {
        assert!(parse_request(request("not-a-cidr", "drop", "token_bucket")).is_err());
    }

    /// A prefix would be narrowed to its network address by the exact-match
    /// config map, so the request is refused instead of silently misapplied.
    #[test]
    fn parse_create_request_rejects_a_prefix() {
        assert!(parse_request(request("10.0.0.0/8", "drop", "token_bucket")).is_err());
    }

    #[test]
    fn response_from_policy() {
        let policy = RateLimitPolicy {
            id: RuleId("rl-001".to_string()),
            rate: 1000,
            burst: 2000,
            action: RateLimitAction::Drop,
            src_ip: domain::firewall::entity::IpNetwork::V4 {
                addr: 0xC0A8_0001,
                prefix_len: 32,
            },
            enabled: true,
            algorithm: RateLimitAlgorithm::TokenBucket,
            group_mask: 0,
        };
        let resp = RateLimitRuleResponse::from_policy(&policy);
        assert_eq!(resp.id, "rl-001");
        assert_eq!(resp.rate, 1000);
        assert_eq!(resp.burst, 2000);
        assert_eq!(resp.action, "drop");
        assert_eq!(resp.algorithm, "token_bucket");
        assert_eq!(resp.src_ip, "192.168.0.1/32");
        assert!(resp.enabled);
    }

    #[test]
    fn response_from_policy_leaky_bucket() {
        let policy = RateLimitPolicy {
            id: RuleId("rl-002".to_string()),
            rate: 500,
            burst: 1000,
            action: RateLimitAction::Pass,
            src_ip: domain::firewall::entity::IpNetwork::V4 {
                addr: 0x0A00_0007,
                prefix_len: 32,
            },
            enabled: true,
            algorithm: RateLimitAlgorithm::LeakyBucket,
            group_mask: 0,
        };
        let resp = RateLimitRuleResponse::from_policy(&policy);
        assert_eq!(resp.algorithm, "leaky_bucket");
        assert_eq!(resp.action, "pass");
        assert_eq!(resp.src_ip, "10.0.0.7/32");
    }

    #[test]
    fn response_serialization() {
        let resp = RateLimitRuleResponse {
            id: "rl-001".to_string(),
            rate: 1000,
            burst: 2000,
            action: "drop".to_string(),
            algorithm: "token_bucket".to_string(),
            src_ip: "10.0.0.7/32".to_string(),
            enabled: true,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["id"], "rl-001");
        assert_eq!(json["rate"], 1000);
        assert_eq!(json["src_ip"], "10.0.0.7/32");
        assert_eq!(json["algorithm"], "token_bucket");
    }
}
