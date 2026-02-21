use std::sync::Arc;

use axum::Extension;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use domain::auth::entity::JwtClaims;
use domain::common::entity::RuleId;
use domain::firewall::entity::{FirewallAction, IpCidr, IpNetwork, PortRange};
use domain::l7::domain_matcher::DomainMatcher;
use domain::l7::entity::{L7Matcher, L7Rule};
use infrastructure::config::parse_cidr;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::error::{ApiError, ErrorBody};
use super::middleware::rbac::require_write_access;
use super::state::AppState;
use super::validation::{
    MAX_ID_LENGTH, MAX_PATTERN_LENGTH, MAX_SHORT_STRING_LENGTH, validate_string_length,
};

// ── Request / Response DTOs ─────────────────────────────────────────

fn default_enabled() -> bool {
    true
}

#[derive(Deserialize, ToSchema)]
pub struct CreateL7RuleRequest {
    pub id: String,
    pub priority: u32,
    pub action: String,
    pub protocol: String,

    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub sni: Option<String>,
    #[serde(default)]
    pub service: Option<String>,
    #[serde(default)]
    pub grpc_method: Option<String>,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub smb_command: Option<u16>,
    #[serde(default)]
    pub is_smb2: Option<bool>,

    #[serde(default)]
    pub src_ip: Option<String>,
    #[serde(default)]
    pub dst_ip: Option<String>,
    #[serde(default)]
    pub dst_port: Option<u16>,

    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

#[derive(Serialize, ToSchema)]
pub struct L7RuleResponse {
    pub id: String,
    pub priority: u32,
    pub action: String,
    pub matcher: serde_json::Value,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub dst_port: Option<String>,
    pub enabled: bool,
}

// ── Conversion helpers ──────────────────────────────────────────────

fn parse_action(s: &str) -> Result<FirewallAction, ApiError> {
    match s.to_lowercase().as_str() {
        "allow" | "pass" => Ok(FirewallAction::Allow),
        "deny" | "drop" | "block" => Ok(FirewallAction::Deny),
        "log" => Ok(FirewallAction::Log),
        _ => Err(ApiError::BadRequest {
            code: "VALIDATION_ERROR",
            message: format!("invalid action '{s}': expected allow|deny|log"),
        }),
    }
}

fn build_domain_matcher(
    field: &str,
    pattern: Option<&str>,
) -> Result<Option<DomainMatcher>, ApiError> {
    pattern
        .map(DomainMatcher::new)
        .transpose()
        .map_err(|e| ApiError::BadRequest {
            code: "VALIDATION_ERROR",
            message: format!("invalid {field} pattern: {e}"),
        })
}

fn build_matcher(req: &CreateL7RuleRequest) -> Result<L7Matcher, ApiError> {
    match req.protocol.to_lowercase().as_str() {
        "http" => Ok(L7Matcher::Http {
            method: req.method.clone(),
            path_pattern: req.path.clone(),
            host_pattern: build_domain_matcher("host", req.host.as_deref())?,
            content_type: req.content_type.clone(),
        }),
        "tls" => Ok(L7Matcher::Tls {
            sni_pattern: build_domain_matcher("sni", req.sni.as_deref())?,
        }),
        "grpc" => Ok(L7Matcher::Grpc {
            service_pattern: req.service.clone(),
            method_pattern: req.grpc_method.clone(),
        }),
        "smtp" => Ok(L7Matcher::Smtp {
            command: req.command.clone(),
        }),
        "ftp" => Ok(L7Matcher::Ftp {
            command: req.command.clone(),
        }),
        "smb" => Ok(L7Matcher::Smb {
            command: req.smb_command,
            is_smb2: req.is_smb2,
        }),
        other => Err(ApiError::BadRequest {
            code: "VALIDATION_ERROR",
            message: format!("invalid protocol '{other}': expected http|tls|grpc|smtp|ftp|smb"),
        }),
    }
}

impl CreateL7RuleRequest {
    fn into_domain_rule(self) -> Result<L7Rule, ApiError> {
        validate_string_length("id", &self.id, MAX_ID_LENGTH)?;
        validate_string_length("action", &self.action, MAX_SHORT_STRING_LENGTH)?;
        validate_string_length("protocol", &self.protocol, MAX_SHORT_STRING_LENGTH)?;
        if let Some(ref s) = self.host {
            validate_string_length("host", s, MAX_PATTERN_LENGTH)?;
        }
        if let Some(ref s) = self.sni {
            validate_string_length("sni", s, MAX_PATTERN_LENGTH)?;
        }
        if let Some(ref s) = self.path {
            validate_string_length("path", s, MAX_PATTERN_LENGTH)?;
        }
        if let Some(ref s) = self.src_ip {
            validate_string_length("src_ip", s, MAX_PATTERN_LENGTH)?;
        }
        if let Some(ref s) = self.dst_ip {
            validate_string_length("dst_ip", s, MAX_PATTERN_LENGTH)?;
        }

        let action = parse_action(&self.action)?;
        let matcher = build_matcher(&self)?;

        let src_ip = self
            .src_ip
            .as_deref()
            .map(parse_cidr)
            .transpose()
            .map_err(|e| ApiError::BadRequest {
                code: "VALIDATION_ERROR",
                message: format!("invalid src_ip: {e}"),
            })?;

        let dst_ip = self
            .dst_ip
            .as_deref()
            .map(parse_cidr)
            .transpose()
            .map_err(|e| ApiError::BadRequest {
                code: "VALIDATION_ERROR",
                message: format!("invalid dst_ip: {e}"),
            })?;

        let dst_port = self.dst_port.map(|p| PortRange { start: p, end: p });

        Ok(L7Rule {
            id: RuleId(self.id),
            priority: self.priority,
            action,
            matcher,
            src_ip,
            dst_ip,
            dst_port,
            enabled: self.enabled,
        })
    }
}

fn format_ip(cidr: IpCidr) -> String {
    match cidr {
        IpNetwork::V4 { addr, prefix_len } => {
            let a = (addr >> 24) & 0xFF;
            let b = (addr >> 16) & 0xFF;
            let c = (addr >> 8) & 0xFF;
            let d = addr & 0xFF;
            if prefix_len == 32 {
                format!("{a}.{b}.{c}.{d}")
            } else {
                format!("{a}.{b}.{c}.{d}/{prefix_len}")
            }
        }
        IpNetwork::V6 { addr, prefix_len } => {
            let ip = std::net::Ipv6Addr::from(addr);
            if prefix_len == 128 {
                format!("{ip}")
            } else {
                format!("{ip}/{prefix_len}")
            }
        }
    }
}

fn format_port(range: PortRange) -> String {
    if range.start == range.end {
        range.start.to_string()
    } else {
        format!("{}-{}", range.start, range.end)
    }
}

fn format_action(action: FirewallAction) -> &'static str {
    match action {
        FirewallAction::Allow => "allow",
        FirewallAction::Deny => "deny",
        FirewallAction::Log => "log",
    }
}

impl From<&L7Rule> for L7RuleResponse {
    fn from(rule: &L7Rule) -> Self {
        Self {
            id: rule.id.0.clone(),
            priority: rule.priority,
            action: format_action(rule.action).to_string(),
            matcher: serde_json::to_value(&rule.matcher).unwrap_or_default(),
            src_ip: rule.src_ip.map(format_ip),
            dst_ip: rule.dst_ip.map(format_ip),
            dst_port: rule.dst_port.map(format_port),
            enabled: rule.enabled,
        }
    }
}

// ── Handlers ────────────────────────────────────────────────────────

/// `GET /api/v1/firewall/l7-rules` — list all L7 rules.
#[utoipa::path(
    get, path = "/api/v1/firewall/l7-rules",
    tag = "L7 Firewall",
    responses((status = 200, description = "List of L7 rules", body = Vec<L7RuleResponse>))
)]
pub async fn list_l7_rules(State(state): State<Arc<AppState>>) -> Json<Vec<L7RuleResponse>> {
    let svc = state.l7_service.read().await;
    let rules: Vec<L7RuleResponse> = svc.rules().iter().map(L7RuleResponse::from).collect();
    Json(rules)
}

/// `POST /api/v1/firewall/l7-rules` — create a new L7 rule.
#[utoipa::path(
    post, path = "/api/v1/firewall/l7-rules",
    tag = "L7 Firewall",
    request_body = CreateL7RuleRequest,
    responses(
        (status = 201, description = "L7 rule created", body = L7RuleResponse),
        (status = 400, description = "Validation error", body = ErrorBody),
        (status = 409, description = "Duplicate rule", body = ErrorBody),
    )
)]
pub async fn create_l7_rule(
    State(state): State<Arc<AppState>>,
    claims: Option<Extension<JwtClaims>>,
    Json(req): Json<CreateL7RuleRequest>,
) -> Result<impl IntoResponse, ApiError> {
    if let Some(Extension(ref claims)) = claims {
        require_write_access(claims)?;
    }
    let rule = req.into_domain_rule()?;
    let response = L7RuleResponse::from(&rule);
    let rule_id = rule.id.0.clone();
    let after_json = serde_json::to_string(&rule).ok();
    state.l7_service.write().await.add_rule(rule)?;

    state.audit_service.read().await.record_rule_change(
        domain::audit::entity::AuditComponent::L7,
        domain::audit::entity::AuditAction::RuleAdded,
        domain::audit::rule_change::ChangeActor::Api,
        &rule_id,
        None,
        after_json,
    );

    Ok((StatusCode::CREATED, Json(response)))
}

/// `DELETE /api/v1/firewall/l7-rules/:id` — delete an L7 rule by ID.
#[utoipa::path(
    delete, path = "/api/v1/firewall/l7-rules/{id}",
    tag = "L7 Firewall",
    params(("id" = String, Path, description = "Rule identifier")),
    responses(
        (status = 204, description = "Rule deleted"),
        (status = 404, description = "Rule not found", body = ErrorBody),
    )
)]
pub async fn delete_l7_rule(
    State(state): State<Arc<AppState>>,
    claims: Option<Extension<JwtClaims>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    if let Some(Extension(ref claims)) = claims {
        require_write_access(claims)?;
    }
    // Capture before snapshot for audit trail
    let before_json = {
        let svc = state.l7_service.read().await;
        svc.rules()
            .iter()
            .find(|r| r.id.0 == id)
            .and_then(|r| serde_json::to_string(r).ok())
    };

    state
        .l7_service
        .write()
        .await
        .remove_rule(&RuleId(id.clone()))?;

    state.audit_service.read().await.record_rule_change(
        domain::audit::entity::AuditComponent::L7,
        domain::audit::entity::AuditAction::RuleRemoved,
        domain::audit::rule_change::ChangeActor::Api,
        &id,
        before_json,
        None,
    );

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_action_valid() {
        assert!(matches!(parse_action("allow"), Ok(FirewallAction::Allow)));
        assert!(matches!(parse_action("deny"), Ok(FirewallAction::Deny)));
        assert!(matches!(parse_action("log"), Ok(FirewallAction::Log)));
        assert!(matches!(parse_action("BLOCK"), Ok(FirewallAction::Deny)));
    }

    #[test]
    fn parse_action_invalid() {
        assert!(parse_action("nope").is_err());
    }

    #[test]
    fn build_http_matcher() {
        let req = CreateL7RuleRequest {
            id: "l7-001".to_string(),
            priority: 10,
            action: "deny".to_string(),
            protocol: "http".to_string(),
            method: Some("DELETE".to_string()),
            path: Some("/admin".to_string()),
            host: None,
            content_type: None,
            sni: None,
            service: None,
            grpc_method: None,
            command: None,
            smb_command: None,
            is_smb2: None,
            src_ip: None,
            dst_ip: None,
            dst_port: None,
            enabled: true,
        };
        let matcher = build_matcher(&req).unwrap();
        assert!(matches!(
            matcher,
            L7Matcher::Http {
                method: Some(_),
                path_pattern: Some(_),
                ..
            }
        ));
    }

    #[test]
    fn build_tls_matcher() {
        let req = CreateL7RuleRequest {
            id: "l7-tls".to_string(),
            priority: 10,
            action: "deny".to_string(),
            protocol: "tls".to_string(),
            method: None,
            path: None,
            host: None,
            content_type: None,
            sni: Some("evil.com".to_string()),
            service: None,
            grpc_method: None,
            command: None,
            smb_command: None,
            is_smb2: None,
            src_ip: None,
            dst_ip: None,
            dst_port: None,
            enabled: true,
        };
        let matcher = build_matcher(&req).unwrap();
        assert!(matches!(
            matcher,
            L7Matcher::Tls {
                sni_pattern: Some(_)
            }
        ));
    }

    #[test]
    fn build_invalid_protocol() {
        let req = CreateL7RuleRequest {
            id: "bad".to_string(),
            priority: 10,
            action: "deny".to_string(),
            protocol: "invalid".to_string(),
            method: None,
            path: None,
            host: None,
            content_type: None,
            sni: None,
            service: None,
            grpc_method: None,
            command: None,
            smb_command: None,
            is_smb2: None,
            src_ip: None,
            dst_ip: None,
            dst_port: None,
            enabled: true,
        };
        assert!(build_matcher(&req).is_err());
    }

    #[test]
    fn create_request_to_domain_valid() {
        let req = CreateL7RuleRequest {
            id: "l7-001".to_string(),
            priority: 10,
            action: "deny".to_string(),
            protocol: "http".to_string(),
            method: Some("POST".to_string()),
            path: Some("/api".to_string()),
            host: None,
            content_type: None,
            sni: None,
            service: None,
            grpc_method: None,
            command: None,
            smb_command: None,
            is_smb2: None,
            src_ip: Some("10.0.0.0/8".to_string()),
            dst_ip: None,
            dst_port: Some(8080),
            enabled: true,
        };
        let rule = req.into_domain_rule().unwrap();
        assert_eq!(rule.id.0, "l7-001");
        assert_eq!(rule.action, FirewallAction::Deny);
        assert!(rule.src_ip.is_some());
        match rule.src_ip.unwrap() {
            IpNetwork::V4 { prefix_len, .. } => assert_eq!(prefix_len, 8),
            IpNetwork::V6 { .. } => panic!("expected V4"),
        }
        assert_eq!(rule.dst_port.unwrap().start, 8080);
    }

    #[test]
    fn create_request_invalid_action() {
        let req = CreateL7RuleRequest {
            id: "l7-001".to_string(),
            priority: 10,
            action: "nuke".to_string(),
            protocol: "http".to_string(),
            method: None,
            path: None,
            host: None,
            content_type: None,
            sni: None,
            service: None,
            grpc_method: None,
            command: None,
            smb_command: None,
            is_smb2: None,
            src_ip: None,
            dst_ip: None,
            dst_port: None,
            enabled: true,
        };
        assert!(req.into_domain_rule().is_err());
    }

    #[test]
    fn l7_rule_response_from_domain() {
        let rule = L7Rule {
            id: RuleId("l7-001".to_string()),
            priority: 10,
            action: FirewallAction::Deny,
            matcher: L7Matcher::Http {
                method: Some("DELETE".to_string()),
                path_pattern: Some("/admin".to_string()),
                host_pattern: None,
                content_type: None,
            },
            src_ip: Some(IpNetwork::V4 {
                addr: 0x0A000000,
                prefix_len: 8,
            }),
            dst_ip: None,
            dst_port: Some(PortRange {
                start: 8080,
                end: 8080,
            }),
            enabled: true,
        };
        let resp = L7RuleResponse::from(&rule);
        assert_eq!(resp.id, "l7-001");
        assert_eq!(resp.action, "deny");
        assert_eq!(resp.src_ip.as_deref(), Some("10.0.0.0/8"));
        assert_eq!(resp.dst_port.as_deref(), Some("8080"));
        assert!(resp.matcher.is_object());
    }
}
