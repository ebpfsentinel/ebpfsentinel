use std::sync::Arc;

use axum::Extension;
use axum::Json;
use axum::extract::{Path, Query, State};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use domain::alert::query::AlertQuery;
use domain::audit::entity::{AuditAction, AuditComponent};
use domain::auth::entity::JwtClaims;
use domain::common::entity::Severity;
use ports::secondary::metrics_port::AlertMetrics;

use super::error::{ApiError, ErrorBody};
use super::middleware::rbac::require_write_access;
use super::state::AppState;

// ── Query parameters DTO ────────────────────────────────────────────

#[derive(Debug, Deserialize, IntoParams)]
pub struct AlertQueryParams {
    /// Filter by component (e.g. "ids", "dlp", "threatintel").
    pub component: Option<String>,
    /// Filter by minimum severity ("low", "medium", "high", "critical").
    pub min_severity: Option<String>,
    /// Filter by rule ID (exact match).
    pub rule_id: Option<String>,
    /// Filter by false-positive flag.
    pub false_positive: Option<bool>,
    /// Start of time range (nanoseconds since epoch, inclusive).
    pub from: Option<u64>,
    /// End of time range (nanoseconds since epoch, inclusive).
    pub to: Option<u64>,
    /// Maximum entries to return (default 100, max 1000).
    pub limit: Option<usize>,
    /// Number of entries to skip (default 0).
    pub offset: Option<usize>,
}

// ── Response DTOs ───────────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
pub struct AlertListResponse {
    pub alerts: Vec<AlertResponse>,
    pub total: usize,
    pub limit: usize,
    pub offset: usize,
}

#[derive(Serialize, ToSchema)]
pub struct AlertResponse {
    pub id: String,
    pub timestamp_ns: u64,
    pub component: String,
    pub severity: String,
    pub rule_id: String,
    pub action: String,
    /// Source address as four big-endian u32 words.
    /// IPv4: `[v4, 0, 0, 0]`. IPv6: full 128-bit address.
    pub src_addr: Vec<u32>,
    /// Destination address (same encoding as `src_addr`).
    pub dst_addr: Vec<u32>,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    /// `true` if the addresses are IPv6.
    pub is_ipv6: bool,
    pub message: String,
    pub false_positive: bool,
    /// Reverse-DNS domain for source IP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_domain: Option<String>,
    /// Reverse-DNS domain for destination IP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_domain: Option<String>,
    /// Reputation score for source domain (0.0=clean, 1.0=malicious).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_domain_score: Option<f64>,
    /// Reputation score for destination domain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_domain_score: Option<f64>,
    /// Threat intel: IOC confidence score (0-100).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<u8>,
    /// Threat intel: threat category.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat_type: Option<String>,
    /// DLP: data category (pci, pii, credentials, custom).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_type: Option<String>,
    /// DLP: process ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// DLP: thread group ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tgid: Option<u32>,
    /// DLP: direction (0=write, 1=read).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<u8>,
    /// IDS: matched domain name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_domain: Option<String>,
    /// `DDoS`: attack type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attack_type: Option<String>,
    /// `DDoS`: peak packets per second.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peak_pps: Option<u64>,
    /// `DDoS`: current smoothed packets per second.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_pps: Option<u64>,
    /// `DDoS`: mitigation status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mitigation_status: Option<String>,
    /// `DDoS`: total packets in attack.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_packets: Option<u64>,
}

#[derive(Serialize, ToSchema)]
pub struct FalsePositiveResponse {
    pub alert_id: String,
    pub marked: bool,
}

// ── Constants ───────────────────────────────────────────────────────

const DEFAULT_LIMIT: usize = 100;
const MAX_LIMIT: usize = 1000;

// ── Helpers ─────────────────────────────────────────────────────────

fn parse_severity(s: &str) -> Option<Severity> {
    match s.to_lowercase().as_str() {
        "low" => Some(Severity::Low),
        "medium" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" => Some(Severity::Critical),
        _ => None,
    }
}

fn severity_label(s: Severity) -> &'static str {
    match s {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

// ── Handlers ────────────────────────────────────────────────────────

/// `GET /api/v1/alerts` — query stored alerts with optional filters.
#[utoipa::path(
    get, path = "/api/v1/alerts",
    tag = "Alerts",
    params(AlertQueryParams),
    responses(
        (status = 200, description = "Paginated alerts", body = AlertListResponse),
        (status = 503, description = "Alert store not configured", body = ErrorBody),
    )
)]
pub async fn list_alerts(
    State(state): State<Arc<AppState>>,
    Query(params): Query<AlertQueryParams>,
) -> Result<Json<AlertListResponse>, ApiError> {
    let store = state
        .alert_store
        .as_ref()
        .ok_or(ApiError::ServiceUnavailable {
            message: "alert store not configured".to_string(),
        })?;

    let limit = params.limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT);
    let offset = params.offset.unwrap_or(0);

    let min_severity = params.min_severity.as_deref().and_then(parse_severity);

    let query = AlertQuery {
        from_ns: params.from,
        to_ns: params.to,
        component: params.component,
        min_severity,
        rule_id: params.rule_id,
        false_positive: params.false_positive,
        limit,
        offset,
    };

    let total = store.alert_count().map_err(|e| ApiError::Internal {
        message: format!("alert count failed: {e}"),
    })?;

    let alerts = store.query_alerts(&query).map_err(|e| ApiError::Internal {
        message: format!("alert query failed: {e}"),
    })?;

    let response_alerts: Vec<AlertResponse> = alerts
        .into_iter()
        .map(|a| AlertResponse {
            id: a.id,
            timestamp_ns: a.timestamp_ns,
            component: a.component,
            severity: severity_label(a.severity).to_string(),
            rule_id: a.rule_id.0,
            action: a.action.as_str().to_string(),
            src_addr: a.src_addr.to_vec(),
            dst_addr: a.dst_addr.to_vec(),
            src_port: a.src_port,
            dst_port: a.dst_port,
            protocol: a.protocol,
            is_ipv6: a.is_ipv6,
            message: a.message,
            false_positive: a.false_positive,
            src_domain: a.src_domain,
            dst_domain: a.dst_domain,
            src_domain_score: a.src_domain_score,
            dst_domain_score: a.dst_domain_score,
            confidence: a.confidence,
            threat_type: a.threat_type,
            data_type: a.data_type,
            pid: a.pid,
            tgid: a.tgid,
            direction: a.direction,
            matched_domain: a.matched_domain,
            attack_type: a.attack_type,
            peak_pps: a.peak_pps,
            current_pps: a.current_pps,
            mitigation_status: a.mitigation_status,
            total_packets: a.total_packets,
        })
        .collect();

    Ok(Json(AlertListResponse {
        alerts: response_alerts,
        total,
        limit,
        offset,
    }))
}

/// `POST /api/v1/alerts/{id}/false-positive` — mark an alert as false positive.
#[utoipa::path(
    post, path = "/api/v1/alerts/{id}/false-positive",
    tag = "Alerts",
    params(("id" = String, Path, description = "Alert identifier")),
    responses(
        (status = 200, description = "Alert marked as false positive", body = FalsePositiveResponse),
        (status = 404, description = "Alert not found", body = ErrorBody),
    )
)]
pub async fn mark_false_positive(
    State(state): State<Arc<AppState>>,
    claims: Option<Extension<JwtClaims>>,
    Path(id): Path<String>,
) -> Result<Json<FalsePositiveResponse>, ApiError> {
    if let Some(Extension(ref claims)) = claims {
        require_write_access(claims)?;
    }
    let store = state
        .alert_store
        .as_ref()
        .ok_or(ApiError::ServiceUnavailable {
            message: "alert store not configured".to_string(),
        })?;

    // Fetch the alert first to get component and rule_id for the metric.
    let alert = store.get_alert(&id).map_err(|e| ApiError::Internal {
        message: format!("alert lookup failed: {e}"),
    })?;

    let alert = alert.ok_or(ApiError::NotFound {
        code: "ALERT_NOT_FOUND",
        message: format!("alert {id} not found"),
    })?;

    if alert.false_positive {
        // Already marked — return idempotent success.
        return Ok(Json(FalsePositiveResponse {
            alert_id: id,
            marked: true,
        }));
    }

    let marked = store
        .mark_false_positive(&id)
        .map_err(|e| ApiError::Internal {
            message: format!("mark false positive failed: {e}"),
        })?;

    if marked {
        // Increment FP metric.
        state
            .metrics
            .record_false_positive(&alert.component, &alert.rule_id.0);

        // Record audit entry for the FP marking.
        let audit_svc = state.audit_service.read().await;
        audit_svc.record_security_decision(
            AuditComponent::parse_name(&alert.component),
            AuditAction::FalsePositive,
            alert.timestamp_ns,
            alert.src_addr,
            alert.dst_addr,
            alert.is_ipv6,
            alert.src_port,
            alert.dst_port,
            alert.protocol,
            &alert.rule_id.0,
            &format!("alert {id} marked as false positive"),
        );
    }

    Ok(Json(FalsePositiveResponse {
        alert_id: id,
        marked,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alert_response_serialization() {
        let resp = AlertResponse {
            id: "test-001".to_string(),
            timestamp_ns: 1_000_000_000,
            component: "ids".to_string(),
            severity: "high".to_string(),
            rule_id: "ids-001".to_string(),
            action: "alert".to_string(),
            src_addr: vec![0xC0A8_0001, 0, 0, 0],
            dst_addr: vec![0x0A00_0001, 0, 0, 0],
            src_port: 12345,
            dst_port: 80,
            protocol: 6,
            is_ipv6: false,
            message: "test alert".to_string(),
            false_positive: false,
            src_domain: None,
            dst_domain: Some("evil.com".to_string()),
            src_domain_score: None,
            dst_domain_score: Some(0.85),
            confidence: None,
            threat_type: None,
            data_type: None,
            pid: None,
            tgid: None,
            direction: None,
            matched_domain: None,
            attack_type: None,
            peak_pps: None,
            current_pps: None,
            mitigation_status: None,
            total_packets: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["id"], "test-001");
        assert_eq!(json["component"], "ids");
        assert_eq!(json["severity"], "high");
        assert!(!json["is_ipv6"].as_bool().unwrap());
        assert_eq!(json["src_addr"][0], 0xC0A8_0001u32);
        assert!(!json["false_positive"].as_bool().unwrap());
        // Domain fields: None → absent (skip_serializing_if), Some → present
        assert!(json.get("src_domain").is_none());
        assert_eq!(json["dst_domain"], "evil.com");
        assert!((json["dst_domain_score"].as_f64().unwrap() - 0.85).abs() < 0.01);
        // Domain-specific fields absent when None
        assert!(json.get("confidence").is_none());
        assert!(json.get("attack_type").is_none());
    }

    #[test]
    fn false_positive_response_serialization() {
        let resp = FalsePositiveResponse {
            alert_id: "test-001".to_string(),
            marked: true,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["alert_id"], "test-001");
        assert!(json["marked"].as_bool().unwrap());
    }

    #[test]
    fn alert_list_response_serialization() {
        let resp = AlertListResponse {
            alerts: vec![],
            total: 42,
            limit: 100,
            offset: 0,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["total"], 42);
        assert_eq!(json["limit"], 100);
        assert!(json["alerts"].as_array().unwrap().is_empty());
    }

    #[test]
    fn query_params_deserialize_defaults() {
        let params: AlertQueryParams = serde_json::from_str("{}").unwrap();
        assert!(params.component.is_none());
        assert!(params.min_severity.is_none());
        assert!(params.rule_id.is_none());
        assert!(params.false_positive.is_none());
        assert!(params.limit.is_none());
        assert!(params.offset.is_none());
    }

    #[test]
    fn query_params_deserialize_with_values() {
        let json = r#"{
            "component": "ids",
            "min_severity": "high",
            "rule_id": "ids-001",
            "false_positive": true,
            "limit": 50,
            "offset": 10
        }"#;
        let params: AlertQueryParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.component.as_deref(), Some("ids"));
        assert_eq!(params.min_severity.as_deref(), Some("high"));
        assert_eq!(params.rule_id.as_deref(), Some("ids-001"));
        assert_eq!(params.false_positive, Some(true));
        assert_eq!(params.limit, Some(50));
        assert_eq!(params.offset, Some(10));
    }

    #[test]
    fn parse_severity_values() {
        assert_eq!(parse_severity("low"), Some(Severity::Low));
        assert_eq!(parse_severity("medium"), Some(Severity::Medium));
        assert_eq!(parse_severity("HIGH"), Some(Severity::High));
        assert_eq!(parse_severity("critical"), Some(Severity::Critical));
        assert_eq!(parse_severity("unknown"), None);
        assert_eq!(parse_severity(""), None);
    }
}
