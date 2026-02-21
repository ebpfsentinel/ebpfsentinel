use std::sync::Arc;

use axum::Extension;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use domain::auth::entity::JwtClaims;
use infrastructure::config::parse_domain_mode;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::error::{ApiError, ErrorBody};
use super::middleware::rbac::require_write_access;
use super::state::AppState;

// ── Request / Response DTOs ─────────────────────────────────────────

#[derive(Serialize, ToSchema)]
pub struct IpsRuleResponse {
    pub id: String,
    pub description: String,
    pub severity: String,
    pub mode: String,
    pub protocol: String,
    pub dst_port: Option<u16>,
    pub pattern: String,
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_pattern: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_match_mode: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct BlacklistEntryResponse {
    pub ip: String,
    pub reason: String,
    pub auto_generated: bool,
    pub ttl_remaining_secs: u64,
}

#[derive(Serialize, ToSchema)]
pub struct DomainBlockResponse {
    pub ip: String,
    pub domain: String,
    pub source: String,
    pub reason: String,
    pub ttl_remaining_secs: u64,
}

#[derive(Deserialize, ToSchema)]
pub struct PatchRuleModeRequest {
    /// `alert` or `block`.
    pub mode: String,
}

// ── Handlers ────────────────────────────────────────────────────────

/// `GET /api/v1/ips/rules` — list all IPS rules.
#[utoipa::path(
    get, path = "/api/v1/ips/rules",
    tag = "IPS",
    responses((status = 200, description = "List of IPS rules", body = Vec<IpsRuleResponse>))
)]
pub async fn list_ips_rules(State(state): State<Arc<AppState>>) -> Json<Vec<IpsRuleResponse>> {
    let svc = state.ips_service.read().await;
    let rules: Vec<IpsRuleResponse> = svc
        .list_rules()
        .iter()
        .map(|r| IpsRuleResponse {
            id: r.id.0.clone(),
            description: r.description.clone(),
            severity: format_severity(r.severity),
            mode: r.mode.as_str().to_string(),
            protocol: format_protocol(r.protocol),
            dst_port: r.dst_port,
            pattern: r.pattern.clone(),
            enabled: r.enabled,
            domain_pattern: r.domain_pattern.clone(),
            domain_match_mode: r.domain_match_mode.as_ref().map(format_domain_match_mode),
        })
        .collect();
    Json(rules)
}

/// `PATCH /api/v1/ips/rules/{id}` — toggle a rule's mode.
#[utoipa::path(
    patch, path = "/api/v1/ips/rules/{id}",
    tag = "IPS",
    params(("id" = String, Path, description = "Rule identifier")),
    request_body = PatchRuleModeRequest,
    responses(
        (status = 200, description = "Rule updated", body = IpsRuleResponse),
        (status = 400, description = "Invalid mode", body = ErrorBody),
        (status = 404, description = "Rule not found", body = ErrorBody),
    )
)]
pub async fn patch_ips_rule_mode(
    State(state): State<Arc<AppState>>,
    claims: Option<Extension<JwtClaims>>,
    Path(id): Path<String>,
    Json(req): Json<PatchRuleModeRequest>,
) -> Result<impl IntoResponse, ApiError> {
    if let Some(Extension(ref claims)) = claims {
        require_write_access(claims)?;
    }
    let new_mode = parse_domain_mode(&req.mode).map_err(|e| ApiError::BadRequest {
        code: "VALIDATION_ERROR",
        message: format!("invalid mode: {e}"),
    })?;

    // Capture before snapshot for audit trail
    let before_json = {
        let svc = state.ips_service.read().await;
        svc.list_rules()
            .iter()
            .find(|r| r.id.0 == id)
            .and_then(|r| serde_json::to_string(r).ok())
    };

    let mut svc = state.ips_service.write().await;
    let old_mode = svc.update_rule_mode(&id, new_mode)?;

    if old_mode != new_mode {
        tracing::info!(
            component = "ips",
            rule_id = %id,
            old_mode = old_mode.as_str(),
            new_mode = new_mode.as_str(),
            "rule mode toggled via API"
        );
    }

    // Return the updated rule
    let rule = svc
        .list_rules()
        .iter()
        .find(|r| r.id.0 == id)
        .map(|r| IpsRuleResponse {
            id: r.id.0.clone(),
            description: r.description.clone(),
            severity: format_severity(r.severity),
            mode: r.mode.as_str().to_string(),
            protocol: format_protocol(r.protocol),
            dst_port: r.dst_port,
            pattern: r.pattern.clone(),
            enabled: r.enabled,
            domain_pattern: r.domain_pattern.clone(),
            domain_match_mode: r.domain_match_mode.as_ref().map(format_domain_match_mode),
        });

    // Capture after snapshot and record rule change
    let after_json = svc
        .list_rules()
        .iter()
        .find(|r| r.id.0 == id)
        .and_then(|r| serde_json::to_string(r).ok());
    drop(svc);

    if old_mode != new_mode {
        state.audit_service.read().await.record_rule_change(
            domain::audit::entity::AuditComponent::Ips,
            domain::audit::entity::AuditAction::RuleUpdated,
            domain::audit::rule_change::ChangeActor::Api,
            &id,
            before_json,
            after_json,
        );
    }

    match rule {
        Some(resp) => Ok((StatusCode::OK, Json(resp))),
        None => Err(ApiError::NotFound {
            code: "IPS_RULE_NOT_FOUND",
            message: format!("Rule {id} not found"),
        }),
    }
}

/// `GET /api/v1/ips/blacklist` — list current IPS blacklist entries.
#[utoipa::path(
    get, path = "/api/v1/ips/blacklist",
    tag = "IPS",
    responses((status = 200, description = "Current blacklist entries", body = Vec<BlacklistEntryResponse>))
)]
pub async fn list_ips_blacklist(
    State(state): State<Arc<AppState>>,
) -> Json<Vec<BlacklistEntryResponse>> {
    let svc = state.ips_service.read().await;
    let entries: Vec<BlacklistEntryResponse> = svc
        .list_blacklist()
        .iter()
        .map(|e| {
            let elapsed = e.added_at.elapsed();
            let remaining = e.ttl.saturating_sub(elapsed);
            BlacklistEntryResponse {
                ip: e.ip.to_string(),
                reason: e.reason.clone(),
                auto_generated: e.auto_generated,
                ttl_remaining_secs: remaining.as_secs(),
            }
        })
        .collect();
    Json(entries)
}

/// `GET /api/v1/ips/domain-blocks` — list IPS blacklist entries originating from domain mechanisms.
#[utoipa::path(
    get, path = "/api/v1/ips/domain-blocks",
    tag = "IPS",
    responses((status = 200, description = "Domain-based IPS blocks", body = Vec<DomainBlockResponse>))
)]
pub async fn list_ips_domain_blocks(
    State(state): State<Arc<AppState>>,
) -> Json<Vec<DomainBlockResponse>> {
    let svc = state.ips_service.read().await;
    let entries: Vec<DomainBlockResponse> = svc
        .list_blacklist()
        .iter()
        .filter_map(|e| {
            let (source, domain) = if let Some(d) = e.reason.strip_prefix("dns-blocklist: ") {
                ("dns-blocklist".to_string(), d.to_string())
            } else if let Some(d) = e.reason.strip_prefix("reputation: ") {
                ("reputation".to_string(), d.to_string())
            } else {
                return None;
            };

            let elapsed = e.added_at.elapsed();
            let remaining = e.ttl.saturating_sub(elapsed);
            Some(DomainBlockResponse {
                ip: e.ip.to_string(),
                domain,
                source,
                reason: e.reason.clone(),
                ttl_remaining_secs: remaining.as_secs(),
            })
        })
        .collect();
    Json(entries)
}

// ── Formatting helpers ──────────────────────────────────────────────

fn format_severity(s: domain::common::entity::Severity) -> String {
    match s {
        domain::common::entity::Severity::Low => "low".to_string(),
        domain::common::entity::Severity::Medium => "medium".to_string(),
        domain::common::entity::Severity::High => "high".to_string(),
        domain::common::entity::Severity::Critical => "critical".to_string(),
    }
}

fn format_domain_match_mode(m: &domain::ids::entity::DomainMatchMode) -> String {
    match m {
        domain::ids::entity::DomainMatchMode::Exact => "exact".to_string(),
        domain::ids::entity::DomainMatchMode::Wildcard => "wildcard".to_string(),
        domain::ids::entity::DomainMatchMode::Regex => "regex".to_string(),
    }
}

fn format_protocol(p: domain::common::entity::Protocol) -> String {
    match p {
        domain::common::entity::Protocol::Tcp => "tcp".to_string(),
        domain::common::entity::Protocol::Udp => "udp".to_string(),
        domain::common::entity::Protocol::Icmp => "icmp".to_string(),
        domain::common::entity::Protocol::Any => "any".to_string(),
        domain::common::entity::Protocol::Other(n) => format!("other({n})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::common::entity::{Protocol, Severity};

    #[test]
    fn format_severity_variants() {
        assert_eq!(format_severity(Severity::Low), "low");
        assert_eq!(format_severity(Severity::Medium), "medium");
        assert_eq!(format_severity(Severity::High), "high");
        assert_eq!(format_severity(Severity::Critical), "critical");
    }

    #[test]
    fn format_protocol_variants() {
        assert_eq!(format_protocol(Protocol::Tcp), "tcp");
        assert_eq!(format_protocol(Protocol::Udp), "udp");
        assert_eq!(format_protocol(Protocol::Icmp), "icmp");
        assert_eq!(format_protocol(Protocol::Any), "any");
    }

    #[test]
    fn parse_patch_request() {
        let json = r#"{"mode":"block"}"#;
        let req: PatchRuleModeRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.mode, "block");
    }

    #[test]
    fn ips_rule_response_serialization() {
        let resp = IpsRuleResponse {
            id: "ips-001".to_string(),
            description: "Test".to_string(),
            severity: "high".to_string(),
            mode: "block".to_string(),
            protocol: "tcp".to_string(),
            dst_port: Some(22),
            pattern: String::new(),
            enabled: true,
            domain_pattern: None,
            domain_match_mode: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["id"], "ips-001");
        assert_eq!(json["mode"], "block");
        assert_eq!(json["dst_port"], 22);
        // domain fields should be absent when None
        assert!(json.get("domain_pattern").is_none());
    }

    #[test]
    fn ips_rule_response_with_domain_fields() {
        let resp = IpsRuleResponse {
            id: "ips-002".to_string(),
            description: "Domain rule".to_string(),
            severity: "critical".to_string(),
            mode: "alert".to_string(),
            protocol: "tcp".to_string(),
            dst_port: Some(443),
            pattern: String::new(),
            enabled: true,
            domain_pattern: Some("*.evil.com".to_string()),
            domain_match_mode: Some("wildcard".to_string()),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["domain_pattern"], "*.evil.com");
        assert_eq!(json["domain_match_mode"], "wildcard");
    }

    #[test]
    fn domain_block_response_serialization() {
        let resp = DomainBlockResponse {
            ip: "10.0.0.1".to_string(),
            domain: "evil.com".to_string(),
            source: "dns-blocklist".to_string(),
            reason: "dns-blocklist: evil.com".to_string(),
            ttl_remaining_secs: 120,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["ip"], "10.0.0.1");
        assert_eq!(json["domain"], "evil.com");
        assert_eq!(json["source"], "dns-blocklist");
    }

    #[test]
    fn blacklist_entry_response_serialization() {
        let resp = BlacklistEntryResponse {
            ip: "10.0.0.1".to_string(),
            reason: "auto-blacklisted".to_string(),
            auto_generated: true,
            ttl_remaining_secs: 3500,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["ip"], "10.0.0.1");
        assert_eq!(json["ttl_remaining_secs"], 3500);
        assert_eq!(json["auto_generated"], true);
    }

    #[test]
    fn parse_invalid_mode_is_caught() {
        let result = parse_domain_mode("banana");
        assert!(result.is_err());
    }
}
