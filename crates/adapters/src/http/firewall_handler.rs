use std::sync::Arc;

use axum::Extension;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use domain::auth::entity::JwtClaims;
use domain::common::entity::{Protocol, RuleId};
use domain::firewall::entity::{FirewallAction, FirewallRule, IpCidr, IpNetwork, PortRange, Scope};
use infrastructure::config::parse_cidr;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::error::{ApiError, ErrorBody};
use super::middleware::rbac::require_namespace_write;
use super::state::AppState;
use super::validation::{
    MAX_ID_LENGTH, MAX_PATTERN_LENGTH, MAX_SHORT_STRING_LENGTH, validate_string_length,
};

// ── Request / Response DTOs ─────────────────────────────────────────

fn default_protocol() -> String {
    "any".to_string()
}

fn default_scope() -> String {
    "global".to_string()
}

fn default_enabled() -> bool {
    true
}

#[derive(Deserialize, ToSchema)]
pub struct CreateRuleRequest {
    pub id: String,
    pub priority: u32,
    /// `allow`, `deny`, or `log`.
    pub action: String,
    /// `tcp`, `udp`, `icmp`, or `any`. Defaults to `any`.
    #[serde(default = "default_protocol")]
    pub protocol: String,
    /// Source IP in CIDR notation (e.g. `192.168.1.0/24`).
    pub src_ip: Option<String>,
    /// Destination IP in CIDR notation.
    pub dst_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    /// `global`, `interface:<name>`, or `namespace:<name>`. Defaults to `global`.
    #[serde(default = "default_scope")]
    pub scope: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Optional 802.1Q VLAN ID filter.
    #[serde(default)]
    pub vlan_id: Option<u16>,
}

#[derive(Serialize, ToSchema)]
pub struct RuleResponse {
    pub id: String,
    pub enabled: bool,
    pub priority: u32,
    pub action: String,
    pub protocol: String,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_port: Option<String>,
    pub dst_port: Option<String>,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vlan_id: Option<u16>,
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

fn parse_protocol(s: &str) -> Result<Protocol, ApiError> {
    match s.to_lowercase().as_str() {
        "tcp" => Ok(Protocol::Tcp),
        "udp" => Ok(Protocol::Udp),
        "icmp" => Ok(Protocol::Icmp),
        "any" | "*" => Ok(Protocol::Any),
        _ => Err(ApiError::BadRequest {
            code: "VALIDATION_ERROR",
            message: format!("invalid protocol '{s}': expected tcp|udp|icmp|any"),
        }),
    }
}

fn parse_scope(s: &str) -> Scope {
    if s.eq_ignore_ascii_case("global") {
        Scope::Global
    } else if let Some(iface) = s.strip_prefix("interface:") {
        Scope::Interface(iface.to_string())
    } else if let Some(ns) = s.strip_prefix("namespace:") {
        Scope::Namespace(ns.to_string())
    } else {
        // Default: treat as interface name
        Scope::Interface(s.to_string())
    }
}

impl CreateRuleRequest {
    fn into_domain_rule(self) -> Result<FirewallRule, ApiError> {
        validate_string_length("id", &self.id, MAX_ID_LENGTH)?;
        validate_string_length("action", &self.action, MAX_SHORT_STRING_LENGTH)?;
        validate_string_length("protocol", &self.protocol, MAX_SHORT_STRING_LENGTH)?;
        validate_string_length("scope", &self.scope, MAX_SHORT_STRING_LENGTH)?;
        if let Some(ref s) = self.src_ip {
            validate_string_length("src_ip", s, MAX_PATTERN_LENGTH)?;
        }
        if let Some(ref s) = self.dst_ip {
            validate_string_length("dst_ip", s, MAX_PATTERN_LENGTH)?;
        }

        let action = parse_action(&self.action)?;
        let protocol = parse_protocol(&self.protocol)?;

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

        let src_port = self.src_port.map(|p| PortRange { start: p, end: p });
        let dst_port = self.dst_port.map(|p| PortRange { start: p, end: p });
        let scope = parse_scope(&self.scope);

        Ok(FirewallRule {
            id: RuleId(self.id),
            priority: self.priority,
            action,
            protocol,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            scope,
            enabled: self.enabled,
            vlan_id: self.vlan_id,
            src_alias: None,
            dst_alias: None,
            src_port_alias: None,
            dst_port_alias: None,
            ct_states: None,
            tcp_flags: None,
            icmp_type: None,
            icmp_code: None,
            negate_src: false,
            negate_dst: false,
            dscp_match: None,
            dscp_mark: None,
            max_states: None,
            src_mac: None,
            dst_mac: None,
            schedule: None,
            system: false,
            route_action: None,
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

fn format_protocol(proto: Protocol) -> &'static str {
    match proto {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
        Protocol::Icmp => "icmp",
        Protocol::Any => "any",
        Protocol::Other(_) => "other",
    }
}

fn format_scope(scope: &Scope) -> String {
    match scope {
        Scope::Global => "global".to_string(),
        Scope::Interface(iface) => format!("interface:{iface}"),
        Scope::Namespace(ns) => format!("namespace:{ns}"),
    }
}

impl From<&FirewallRule> for RuleResponse {
    fn from(rule: &FirewallRule) -> Self {
        Self {
            id: rule.id.0.clone(),
            enabled: rule.enabled,
            priority: rule.priority,
            action: format_action(rule.action).to_string(),
            protocol: format_protocol(rule.protocol).to_string(),
            src_ip: rule.src_ip.map(format_ip),
            dst_ip: rule.dst_ip.map(format_ip),
            src_port: rule.src_port.map(format_port),
            dst_port: rule.dst_port.map(format_port),
            scope: format_scope(&rule.scope),
            vlan_id: rule.vlan_id,
        }
    }
}

// ── Handlers ────────────────────────────────────────────────────────

/// `GET /api/v1/firewall/rules` — list all active rules.
#[utoipa::path(
    get, path = "/api/v1/firewall/rules",
    tag = "Firewall",
    responses(
        (status = 200, description = "List of firewall rules", body = Vec<RuleResponse>),
    )
)]
pub async fn list_rules(State(state): State<Arc<AppState>>) -> Json<Vec<RuleResponse>> {
    let svc = state.firewall_service.read().await;
    let rules: Vec<RuleResponse> = svc.list_rules().iter().map(RuleResponse::from).collect();
    Json(rules)
}

/// `POST /api/v1/firewall/rules` — create a new rule.
#[utoipa::path(
    post, path = "/api/v1/firewall/rules",
    tag = "Firewall",
    request_body = CreateRuleRequest,
    responses(
        (status = 201, description = "Rule created", body = RuleResponse),
        (status = 400, description = "Validation error", body = ErrorBody),
        (status = 409, description = "Duplicate rule", body = ErrorBody),
    )
)]
pub async fn create_rule(
    State(state): State<Arc<AppState>>,
    claims: Option<Extension<JwtClaims>>,
    Json(req): Json<CreateRuleRequest>,
) -> Result<impl IntoResponse, ApiError> {
    if let Some(Extension(ref claims)) = claims {
        let scope = parse_scope(&req.scope);
        require_namespace_write(claims, &scope)?;
    }
    let rule = req.into_domain_rule()?;
    let response = RuleResponse::from(&rule);
    let rule_id = rule.id.0.clone();
    let after_json = serde_json::to_string(&rule).ok();
    state.firewall_service.write().await.add_rule(rule)?;

    state.audit_service.read().await.record_rule_change(
        domain::audit::entity::AuditComponent::Firewall,
        domain::audit::entity::AuditAction::RuleAdded,
        domain::audit::rule_change::ChangeActor::Api,
        &rule_id,
        None,
        after_json,
    );

    Ok((StatusCode::CREATED, Json(response)))
}

/// `DELETE /api/v1/firewall/rules/:id` — delete a rule by ID.
#[utoipa::path(
    delete, path = "/api/v1/firewall/rules/{id}",
    tag = "Firewall",
    params(("id" = String, Path, description = "Rule identifier")),
    responses(
        (status = 204, description = "Rule deleted"),
        (status = 404, description = "Rule not found", body = ErrorBody),
    )
)]
pub async fn delete_rule(
    State(state): State<Arc<AppState>>,
    claims: Option<Extension<JwtClaims>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    // RBAC: check namespace access based on the rule's scope
    if let Some(Extension(ref claims)) = claims {
        let svc = state.firewall_service.read().await;
        if let Some(rule) = svc.list_rules().iter().find(|r| r.id.0 == id) {
            require_namespace_write(claims, &rule.scope)?;
        }
    }

    // Capture before snapshot for audit trail
    let before_json = {
        let svc = state.firewall_service.read().await;
        svc.list_rules()
            .iter()
            .find(|r| r.id.0 == id)
            .and_then(|r| serde_json::to_string(r).ok())
    };

    state
        .firewall_service
        .write()
        .await
        .remove_rule(&RuleId(id.clone()))?;

    state.audit_service.read().await.record_rule_change(
        domain::audit::entity::AuditComponent::Firewall,
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
        assert!(matches!(parse_action("PASS"), Ok(FirewallAction::Allow)));
        assert!(matches!(parse_action("DROP"), Ok(FirewallAction::Deny)));
    }

    #[test]
    fn parse_action_invalid() {
        assert!(parse_action("invalid").is_err());
    }

    #[test]
    fn parse_protocol_valid() {
        assert!(matches!(parse_protocol("tcp"), Ok(Protocol::Tcp)));
        assert!(matches!(parse_protocol("udp"), Ok(Protocol::Udp)));
        assert!(matches!(parse_protocol("any"), Ok(Protocol::Any)));
    }

    #[test]
    fn parse_protocol_invalid() {
        assert!(parse_protocol("invalid").is_err());
    }

    #[test]
    fn parse_scope_variants() {
        assert!(matches!(parse_scope("global"), Scope::Global));
        assert!(matches!(parse_scope("interface:eth0"), Scope::Interface(_)));
        assert!(matches!(parse_scope("namespace:prod"), Scope::Namespace(_)));
        // Bare name → Interface
        assert!(matches!(parse_scope("wlan0"), Scope::Interface(_)));
    }

    #[test]
    fn format_ip_host() {
        let cidr = IpNetwork::V4 {
            addr: 0xC0A80001,
            prefix_len: 32,
        };
        assert_eq!(format_ip(cidr), "192.168.0.1");
    }

    #[test]
    fn format_ip_subnet() {
        let cidr = IpNetwork::V4 {
            addr: 0xC0A80100,
            prefix_len: 24,
        };
        assert_eq!(format_ip(cidr), "192.168.1.0/24");
    }

    #[test]
    fn format_port_single() {
        let range = PortRange { start: 80, end: 80 };
        assert_eq!(format_port(range), "80");
    }

    #[test]
    fn format_port_range() {
        let range = PortRange {
            start: 80,
            end: 443,
        };
        assert_eq!(format_port(range), "80-443");
    }

    #[test]
    fn create_request_to_domain_valid() {
        let req = CreateRuleRequest {
            id: "fw-001".to_string(),
            priority: 100,
            action: "deny".to_string(),
            protocol: "tcp".to_string(),
            src_ip: Some("192.168.1.0/24".to_string()),
            dst_ip: None,
            src_port: None,
            dst_port: Some(22),
            scope: "global".to_string(),
            enabled: true,
            vlan_id: None,
        };
        let rule = req.into_domain_rule().unwrap();
        assert_eq!(rule.id.0, "fw-001");
        assert_eq!(rule.priority, 100);
        assert_eq!(rule.action, FirewallAction::Deny);
        assert_eq!(rule.protocol, Protocol::Tcp);
        assert!(rule.src_ip.is_some());
        assert_eq!(rule.dst_port.unwrap().start, 22);
    }

    #[test]
    fn create_request_invalid_action() {
        let req = CreateRuleRequest {
            id: "fw-001".to_string(),
            priority: 100,
            action: "nope".to_string(),
            protocol: "tcp".to_string(),
            src_ip: None,
            dst_ip: None,
            src_port: None,
            dst_port: None,
            scope: "global".to_string(),
            enabled: true,
            vlan_id: None,
        };
        assert!(req.into_domain_rule().is_err());
    }

    #[test]
    fn create_request_invalid_cidr() {
        let req = CreateRuleRequest {
            id: "fw-001".to_string(),
            priority: 100,
            action: "deny".to_string(),
            protocol: "tcp".to_string(),
            src_ip: Some("not-a-cidr".to_string()),
            dst_ip: None,
            src_port: None,
            dst_port: None,
            scope: "global".to_string(),
            enabled: true,
            vlan_id: None,
        };
        assert!(req.into_domain_rule().is_err());
    }

    #[test]
    fn rule_response_from_domain() {
        let rule = FirewallRule {
            id: RuleId("fw-001".to_string()),
            priority: 100,
            action: FirewallAction::Deny,
            protocol: Protocol::Tcp,
            src_ip: Some(IpNetwork::V4 {
                addr: 0xC0A80100,
                prefix_len: 24,
            }),
            dst_ip: None,
            src_port: None,
            dst_port: Some(PortRange { start: 22, end: 22 }),
            scope: Scope::Global,
            enabled: true,
            vlan_id: None,
            src_alias: None,
            dst_alias: None,
            src_port_alias: None,
            dst_port_alias: None,
            ct_states: None,
            tcp_flags: None,
            icmp_type: None,
            icmp_code: None,
            negate_src: false,
            negate_dst: false,
            dscp_match: None,
            dscp_mark: None,
            max_states: None,
            src_mac: None,
            dst_mac: None,
            schedule: None,
            system: false,
            route_action: None,
        };
        let resp = RuleResponse::from(&rule);
        assert_eq!(resp.id, "fw-001");
        assert_eq!(resp.action, "deny");
        assert_eq!(resp.protocol, "tcp");
        assert_eq!(resp.src_ip.as_deref(), Some("192.168.1.0/24"));
        assert_eq!(resp.dst_port.as_deref(), Some("22"));
        assert_eq!(resp.scope, "global");
    }
}
