use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use domain::ids::entity::ThresholdConfig;
use infrastructure::config::group_mask_words;
use serde::Serialize;
use utoipa::ToSchema;

use super::error::{ApiError, ErrorBody};
use super::state::AppState;

// ── Response DTOs ───────────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
pub struct IdsStatusResponse {
    pub enabled: bool,
    pub mode: String,
    pub rule_count: usize,
}

#[derive(Serialize, ToSchema)]
pub struct IdsRuleResponse {
    pub id: String,
    pub description: String,
    pub severity: String,
    pub mode: String,
    pub protocol: String,
    pub dst_port: Option<u16>,
    /// Source-port match, set on rules watching the reply leg of a flow. A
    /// rule carrying one fires on nothing else, so a listing that dropped it
    /// read as matching every port.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_port: Option<u16>,
    pub pattern: String,
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold: Option<ThresholdResponse>,
    /// Domain the rule matches on, for rules evaluated against resolved names
    /// rather than against a port.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_pattern: Option<String>,
    /// How `domain_pattern` is read: `exact`, `wildcard` or `regex`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_match_mode: Option<String>,
    /// Per-country threshold overrides, keyed by ISO 3166-1 alpha-2 code. A
    /// rule stricter for one country reads as a single threshold without
    /// them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country_thresholds: Option<BTreeMap<String, ThresholdResponse>>,
    /// The interface groups this rule is scoped to, in the words the
    /// configuration file used, `!` prefix included. Empty is a floating
    /// rule, which sees every interface the classifier is attached to.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<String>,
    /// Present only when another rule holds a kernel map slot this rule also
    /// claims.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel_slot: Option<SlotContentionResponse>,
}

/// A kernel map slot holds one rule, so two rules watching the same port and
/// protocol cannot both be installed. This says which rule took the slot and
/// whether the loser is still evaluated.
#[derive(Serialize, ToSchema)]
pub struct SlotContentionResponse {
    /// Ids of the rules holding a slot this rule also claims.
    pub shadowed_by: Vec<String>,
    /// `false` means the rule is loaded, enabled, and matches nothing.
    pub evaluated_in_userspace: bool,
}

impl From<&application::ids_service_impl::SlotShadow> for SlotContentionResponse {
    fn from(shadow: &application::ids_service_impl::SlotShadow) -> Self {
        Self {
            shadowed_by: shadow.shadowed_by.clone(),
            evaluated_in_userspace: shadow.evaluated_in_userspace,
        }
    }
}

/// Per-rule threshold/rate detection, surfaced for rate-based IDS rules.
#[derive(Serialize, ToSchema)]
pub struct ThresholdResponse {
    pub threshold_type: String,
    pub count: u32,
    pub window_secs: u64,
    pub track_by: String,
}

impl From<&ThresholdConfig> for ThresholdResponse {
    fn from(t: &ThresholdConfig) -> Self {
        Self {
            threshold_type: t.threshold_type.as_str().to_string(),
            count: t.count,
            window_secs: t.window_secs,
            track_by: t.track_by.as_str().to_string(),
        }
    }
}

// ── Handlers ────────────────────────────────────────────────────────

/// `GET /api/v1/ids/status` - IDS service status.
#[utoipa::path(
    get, path = "/api/v1/ids/status",
    tag = "IDS",
    responses(
        (status = 200, description = "IDS status", body = IdsStatusResponse),
        (status = 404, description = "IDS not available", body = ErrorBody),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn ids_status(
    State(state): State<Arc<AppState>>,
) -> Result<Json<IdsStatusResponse>, ApiError> {
    let svc_arc = state.ids_service.as_ref().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "IDS service is not enabled".to_string(),
    })?;
    let svc = svc_arc.load();
    Ok(Json(IdsStatusResponse {
        enabled: svc.enabled(),
        mode: svc.mode().as_str().to_string(),
        rule_count: svc.rule_count(),
    }))
}

/// `GET /api/v1/ids/rules` - list all IDS rules.
#[utoipa::path(
    get, path = "/api/v1/ids/rules",
    tag = "IDS",
    responses(
        (status = 200, description = "List of IDS rules", body = Vec<IdsRuleResponse>),
        (status = 404, description = "IDS not available", body = ErrorBody),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn list_ids_rules(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<IdsRuleResponse>>, ApiError> {
    let svc_arc = state.ids_service.as_ref().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "IDS service is not enabled".to_string(),
    })?;
    // A rule scoped to one interface group inspects that slice and nothing
    // else, so the listing names the groups rather than reading as a rule on
    // every interface.
    let group_bits = state.config.read().await.interface_group_bitmasks();
    let svc = svc_arc.load();
    let shadows = svc.slot_shadows();
    let rules: Vec<IdsRuleResponse> = svc
        .list_rules()
        .iter()
        .map(|r| IdsRuleResponse {
            id: r.id.0.clone(),
            description: r.description.clone(),
            severity: format_severity(r.severity),
            mode: r.mode.as_str().to_string(),
            protocol: format_protocol(r.protocol),
            dst_port: r.dst_port,
            src_port: r.src_port,
            pattern: r.pattern.clone(),
            enabled: r.enabled,
            threshold: r.threshold.as_ref().map(ThresholdResponse::from),
            domain_pattern: r.domain_pattern.clone(),
            domain_match_mode: r.domain_match_mode.as_ref().map(format_domain_match_mode),
            country_thresholds: r.country_thresholds.as_ref().map(|by_country| {
                by_country
                    .iter()
                    .map(|(code, t)| (code.clone(), ThresholdResponse::from(t)))
                    .collect()
            }),
            interfaces: group_mask_words(r.group_mask, &group_bits),
            kernel_slot: shadows.get(&r.id.0).map(SlotContentionResponse::from),
        })
        .collect();
    Ok(Json(rules))
}

// ── Formatting helpers ──────────────────────────────────────────────
//
// The IDS and IPS listings answer the same rule array, so they spell a
// severity, a protocol and a domain match mode from one place: two readings
// of one rule saying `High` and `high` is a screen that cannot group them.

pub fn format_severity(s: domain::common::entity::Severity) -> String {
    match s {
        domain::common::entity::Severity::Low => "low".to_string(),
        domain::common::entity::Severity::Medium => "medium".to_string(),
        domain::common::entity::Severity::High => "high".to_string(),
        domain::common::entity::Severity::Critical => "critical".to_string(),
    }
}

pub fn format_domain_match_mode(m: &domain::ids::entity::DomainMatchMode) -> String {
    match m {
        domain::ids::entity::DomainMatchMode::Exact => "exact".to_string(),
        domain::ids::entity::DomainMatchMode::Wildcard => "wildcard".to_string(),
        domain::ids::entity::DomainMatchMode::Regex => "regex".to_string(),
    }
}

pub fn format_protocol(p: domain::common::entity::Protocol) -> String {
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
    use domain::ids::entity::{DomainMatchMode, ThresholdType, TrackBy};

    fn a_rule_response() -> IdsRuleResponse {
        IdsRuleResponse {
            id: "ids-001".to_string(),
            description: "SSH scan".to_string(),
            severity: format_severity(Severity::High),
            mode: "alert".to_string(),
            protocol: format_protocol(Protocol::Tcp),
            dst_port: Some(22),
            src_port: None,
            pattern: String::new(),
            enabled: true,
            threshold: None,
            domain_pattern: None,
            domain_match_mode: None,
            country_thresholds: None,
            kernel_slot: None,
            interfaces: Vec::new(),
        }
    }

    #[test]
    fn ids_status_response_serialization() {
        let resp = IdsStatusResponse {
            enabled: true,
            mode: "alert".to_string(),
            rule_count: 5,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["enabled"], true);
        assert_eq!(json["mode"], "alert");
        assert_eq!(json["rule_count"], 5);
    }

    #[test]
    fn ids_rule_response_serialization() {
        let resp = IdsRuleResponse {
            threshold: Some(ThresholdResponse::from(&ThresholdConfig {
                threshold_type: ThresholdType::Threshold,
                count: 5,
                window_secs: 30,
                track_by: TrackBy::SrcIp,
            })),
            ..a_rule_response()
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["id"], "ids-001");
        assert_eq!(json["dst_port"], 22);
        assert_eq!(json["threshold"]["count"], 5);
        assert!(json.get("kernel_slot").is_none());
    }

    /// The IPS listing answers the same rules in lowercase, so a reading that
    /// spelled them `High`/`Tcp`/`Alert` gave one rule two identities.
    #[test]
    fn ids_rule_response_speaks_the_vocabulary_the_ips_listing_does() {
        let json = serde_json::to_value(a_rule_response()).unwrap();
        assert_eq!(json["severity"], "high");
        assert_eq!(json["protocol"], "tcp");
        assert_eq!(json["mode"], "alert");
    }

    /// A threshold is written `limit` / `src_ip` in the configuration file, so
    /// the reading of a rule says what the file that declared it said.
    #[test]
    fn threshold_response_speaks_the_configured_spelling() {
        let resp = ThresholdResponse::from(&ThresholdConfig {
            threshold_type: ThresholdType::Limit,
            count: 3,
            window_secs: 60,
            track_by: TrackBy::SrcIp,
        });
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["threshold_type"], "limit");
        assert_eq!(json["track_by"], "src_ip");
    }

    /// A rule watching a reply port fires on nothing else, and a rule matching
    /// a resolved name never looks at a port at all: without either field the
    /// listing reads as a rule matching every port.
    #[test]
    fn ids_rule_response_carries_the_narrowing_a_rule_was_written_with() {
        let resp = IdsRuleResponse {
            dst_port: None,
            src_port: Some(53),
            domain_pattern: Some("*.evil.com".to_string()),
            domain_match_mode: Some(format_domain_match_mode(&DomainMatchMode::Wildcard)),
            ..a_rule_response()
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["src_port"], 53);
        assert_eq!(json["domain_pattern"], "*.evil.com");
        assert_eq!(json["domain_match_mode"], "wildcard");
    }

    /// A per-country override is the whole point of the rule it sits on, and a
    /// listing dropping it reported the loosest threshold as the only one.
    #[test]
    fn ids_rule_response_carries_a_per_country_threshold() {
        let mut by_country = BTreeMap::new();
        by_country.insert(
            "KP".to_string(),
            ThresholdResponse::from(&ThresholdConfig {
                threshold_type: ThresholdType::Limit,
                count: 1,
                window_secs: 60,
                track_by: TrackBy::SrcIp,
            }),
        );
        let resp = IdsRuleResponse {
            country_thresholds: Some(by_country),
            ..a_rule_response()
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["country_thresholds"]["KP"]["count"], 1);
        assert_eq!(json["country_thresholds"]["KP"]["threshold_type"], "limit");
    }

    #[test]
    fn ids_rule_response_omits_what_a_rule_was_not_written_with() {
        let json = serde_json::to_value(a_rule_response()).unwrap();
        assert!(json.get("src_port").is_none());
        assert!(json.get("domain_pattern").is_none());
        assert!(json.get("domain_match_mode").is_none());
        assert!(json.get("country_thresholds").is_none());
    }

    #[test]
    fn ids_rule_response_reports_a_lost_kernel_slot() {
        let resp = IdsRuleResponse {
            id: "ids-002".to_string(),
            description: "Shadowed by an IPS rule".to_string(),
            kernel_slot: Some(SlotContentionResponse {
                shadowed_by: vec!["ips-001".to_string()],
                evaluated_in_userspace: true,
            }),
            ..a_rule_response()
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["kernel_slot"]["shadowed_by"][0], "ips-001");
        assert_eq!(json["kernel_slot"]["evaluated_in_userspace"], true);
    }

    /// A floating rule and a rule scoped to a group have to read differently,
    /// so the field is absent rather than empty when there is no scope: an
    /// empty list beside a named one reads as a rule nothing applies to.
    #[test]
    fn interface_scope_is_absent_on_a_floating_rule_and_named_otherwise() {
        let mut resp = a_rule_response();
        assert!(
            serde_json::to_value(&resp)
                .unwrap()
                .get("interfaces")
                .is_none()
        );

        resp.interfaces = vec!["dmz".to_string(), "!wan".to_string()];
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["interfaces"], serde_json::json!(["dmz", "!wan"]));
    }
}
