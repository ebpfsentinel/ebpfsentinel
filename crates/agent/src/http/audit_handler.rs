use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use domain::audit::entity::{AuditAction, AuditComponent};
use domain::audit::query::AuditQuery;

use super::error::{ApiError, ErrorBody};
use super::state::AppState;

// ── Query parameters DTO ────────────────────────────────────────────

#[derive(Debug, Deserialize, IntoParams)]
pub struct AuditQueryParams {
    /// Start of time range (nanoseconds since epoch, inclusive).
    pub from: Option<u64>,
    /// End of time range (nanoseconds since epoch, inclusive).
    pub to: Option<u64>,
    /// Filter by component name (e.g. "firewall", "ids").
    #[param(value_type = Option<String>)]
    pub component: Option<AuditComponent>,
    /// Filter by action (e.g. "drop", "alert").
    #[param(value_type = Option<String>)]
    pub action: Option<AuditAction>,
    /// Filter by rule ID (exact match).
    pub rule_id: Option<String>,
    /// Maximum entries to return (default 100, max 1000).
    pub limit: Option<usize>,
    /// Number of entries to skip (default 0).
    pub offset: Option<usize>,
}

// ── Response DTOs ───────────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
pub struct AuditLogResponse {
    pub entries: Vec<AuditEntryResponse>,
    pub total: usize,
    pub limit: usize,
    pub offset: usize,
}

#[derive(Serialize, ToSchema)]
pub struct AuditEntryResponse {
    pub timestamp_ns: u64,
    pub component: String,
    pub action: String,
    // The entry stores the whole address; serving only the first word
    // rendered an IPv6 decision as a dotted quad built from its first 32
    // bits, which reads exactly like an IPv4 address that was never seen.
    // The shape is the one the alert API already uses.
    /// Source address as four big-endian u32 words.
    /// IPv4: `[v4, 0, 0, 0]`. IPv6: full 128-bit address.
    pub src_addr: Vec<u32>,
    /// Destination address (same encoding as `src_addr`).
    pub dst_addr: Vec<u32>,
    /// `true` if the addresses are IPv6.
    pub is_ipv6: bool,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub rule_id: String,
    pub detail: String,
}

// ── Handler ─────────────────────────────────────────────────────────

const DEFAULT_LIMIT: usize = 100;
const MAX_LIMIT: usize = 1000;

/// `GET /api/v1/audit/logs` - query stored audit log entries.
#[utoipa::path(
    get, path = "/api/v1/audit/logs",
    tag = "Audit",
    params(AuditQueryParams),
    responses(
        (status = 200, description = "Paginated audit log entries", body = AuditLogResponse),
        (status = 503, description = "Audit store not configured", body = ErrorBody),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn list_audit_logs(
    State(state): State<Arc<AppState>>,
    Query(params): Query<AuditQueryParams>,
) -> Result<Json<AuditLogResponse>, ApiError> {
    let limit = params.limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT);
    let offset = params.offset.unwrap_or(0);

    let query = AuditQuery {
        from_ns: params.from,
        to_ns: params.to,
        component: params.component,
        action: params.action,
        rule_id: params.rule_id,
        limit,
        offset,
    };

    let svc = &state.audit_service;

    if !svc.has_store() {
        return Err(ApiError::ServiceUnavailable {
            message: "audit store not configured".to_string(),
        });
    }

    let entries = svc.query_logs(&query).map_err(|e| ApiError::Internal {
        message: format!("audit query failed: {e}"),
    })?;

    let total = svc.stored_entry_count().map_err(|e| ApiError::Internal {
        message: format!("audit count failed: {e}"),
    })?;

    let response_entries: Vec<AuditEntryResponse> = entries
        .into_iter()
        .map(|e| AuditEntryResponse {
            timestamp_ns: e.timestamp_ns,
            component: e.component.as_str().to_string(),
            action: e.action.as_str().to_string(),
            src_addr: e.src_addr.to_vec(),
            dst_addr: e.dst_addr.to_vec(),
            is_ipv6: e.is_ipv6,
            src_port: e.src_port,
            dst_port: e.dst_port,
            protocol: e.protocol,
            rule_id: e.rule_id,
            detail: e.detail,
        })
        .collect();

    Ok(Json(AuditLogResponse {
        entries: response_entries,
        total,
        limit,
        offset,
    }))
}

// ── Rule history DTOs ───────────────────────────────────────────────

#[derive(Debug, Deserialize, IntoParams)]
pub struct RuleHistoryQueryParams {
    /// Maximum entries to return (default 50, max 500).
    pub limit: Option<usize>,
}

#[derive(Serialize, ToSchema)]
pub struct RuleHistoryResponse {
    pub rule_id: String,
    pub entries: Vec<RuleChangeResponse>,
}

#[derive(Serialize, ToSchema)]
pub struct RuleChangeResponse {
    pub version: u64,
    pub timestamp_ns: u64,
    pub component: String,
    pub action: String,
    pub actor: String,
    pub before: Option<String>,
    pub after: Option<String>,
}

const HISTORY_DEFAULT_LIMIT: usize = 50;
const HISTORY_MAX_LIMIT: usize = 500;

/// `GET /api/v1/audit/rules/{id}/history` - query rule version history.
#[utoipa::path(
    get, path = "/api/v1/audit/rules/{id}/history",
    tag = "Audit",
    params(
        ("id" = String, Path, description = "Rule identifier"),
        RuleHistoryQueryParams,
    ),
    responses(
        (status = 200, description = "Rule version history", body = RuleHistoryResponse),
        (status = 503, description = "Rule change store not configured", body = ErrorBody),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn rule_history(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(params): Query<RuleHistoryQueryParams>,
) -> Result<Json<RuleHistoryResponse>, ApiError> {
    let limit = params
        .limit
        .unwrap_or(HISTORY_DEFAULT_LIMIT)
        .min(HISTORY_MAX_LIMIT);

    let svc = &state.audit_service;

    if !svc.has_rule_change_store() {
        return Err(ApiError::ServiceUnavailable {
            message: "rule change store not configured".to_string(),
        });
    }

    let entries = svc
        .query_rule_history(&id, limit)
        .map_err(|e| ApiError::Internal {
            message: format!("rule history query failed: {e}"),
        })?;

    let response_entries: Vec<RuleChangeResponse> = entries
        .into_iter()
        .map(|e| RuleChangeResponse {
            version: e.version,
            timestamp_ns: e.timestamp_ns,
            component: e.component.as_str().to_string(),
            action: e.action.as_str().to_string(),
            actor: e.actor.as_str().to_string(),
            before: e.before,
            after: e.after,
        })
        .collect();

    Ok(Json(RuleHistoryResponse {
        rule_id: id,
        entries: response_entries,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_entry_response_serialization() {
        let resp = AuditEntryResponse {
            timestamp_ns: 1_000_000_000,
            component: "firewall".to_string(),
            action: "drop".to_string(),
            src_addr: vec![0xC0A8_0001, 0, 0, 0],
            dst_addr: vec![0x0A00_0001, 0, 0, 0],
            is_ipv6: false,
            src_port: 12345,
            dst_port: 80,
            protocol: 6,
            rule_id: "fw-001".to_string(),
            detail: "Denied by rule".to_string(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["component"], "firewall");
        assert_eq!(json["action"], "drop");
        assert_eq!(json["rule_id"], "fw-001");
        assert_eq!(json["timestamp_ns"], 1_000_000_000_u64);
    }

    /// A decision taken on an IPv6 flow, which the response used to carry
    /// as the first 32 bits of the address and nothing saying so.
    #[test]
    fn audit_entry_response_keeps_the_whole_ipv6_address() {
        let entry = domain::audit::entity::AuditEntry::security_decision(
            AuditComponent::Firewall,
            AuditAction::Drop,
            1_000_000_000,
            [0x2001_0DB8, 0, 0, 0x0000_0001],
            [0xFD00_0000, 0, 0, 0x0000_0002],
            true,
            443,
            8080,
            6,
            "fw-006",
            "Denied by rule",
        );
        let resp = AuditEntryResponse {
            timestamp_ns: entry.timestamp_ns,
            component: entry.component.as_str().to_string(),
            action: entry.action.as_str().to_string(),
            src_addr: entry.src_addr.to_vec(),
            dst_addr: entry.dst_addr.to_vec(),
            is_ipv6: entry.is_ipv6,
            src_port: entry.src_port,
            dst_port: entry.dst_port,
            protocol: entry.protocol,
            rule_id: entry.rule_id.clone(),
            detail: entry.detail.clone(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["is_ipv6"], true);
        assert_eq!(
            json["src_addr"],
            serde_json::json!([0x2001_0DB8_u32, 0, 0, 1])
        );
        assert_eq!(
            json["dst_addr"],
            serde_json::json!([0xFD00_0000_u32, 0, 0, 2])
        );
    }

    #[test]
    fn audit_log_response_serialization() {
        let resp = AuditLogResponse {
            entries: vec![],
            total: 42,
            limit: 100,
            offset: 0,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["total"], 42);
        assert_eq!(json["limit"], 100);
        assert_eq!(json["offset"], 0);
        assert!(json["entries"].as_array().unwrap().is_empty());
    }

    #[test]
    fn query_params_deserialize_defaults() {
        let params: AuditQueryParams = serde_json::from_str("{}").unwrap();
        assert!(params.from.is_none());
        assert!(params.to.is_none());
        assert!(params.component.is_none());
        assert!(params.action.is_none());
        assert!(params.rule_id.is_none());
        assert!(params.limit.is_none());
        assert!(params.offset.is_none());
    }

    #[test]
    fn query_params_deserialize_with_values() {
        let json = r#"{
            "from": 1000,
            "to": 2000,
            "component": "firewall",
            "action": "drop",
            "rule_id": "fw-001",
            "limit": 50,
            "offset": 10
        }"#;
        let params: AuditQueryParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.from, Some(1000));
        assert_eq!(params.to, Some(2000));
        assert_eq!(params.component, Some(AuditComponent::Firewall));
        assert_eq!(params.action, Some(AuditAction::Drop));
        assert_eq!(params.rule_id.as_deref(), Some("fw-001"));
        assert_eq!(params.limit, Some(50));
        assert_eq!(params.offset, Some(10));
    }

    #[test]
    fn rule_change_response_serialization() {
        let resp = RuleChangeResponse {
            version: 3,
            timestamp_ns: 1_000_000_000,
            component: "firewall".to_string(),
            action: "rule_added".to_string(),
            actor: "api".to_string(),
            before: None,
            after: Some(r#"{"id":"fw-001"}"#.to_string()),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["version"], 3);
        assert_eq!(json["component"], "firewall");
        assert_eq!(json["action"], "rule_added");
        assert_eq!(json["actor"], "api");
        assert!(json["before"].is_null());
        assert_eq!(json["after"], r#"{"id":"fw-001"}"#);
    }

    #[test]
    fn rule_history_response_serialization() {
        let resp = RuleHistoryResponse {
            rule_id: "fw-001".to_string(),
            entries: vec![],
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["rule_id"], "fw-001");
        assert!(json["entries"].as_array().unwrap().is_empty());
    }

    #[test]
    fn rule_history_query_params_defaults() {
        let params: RuleHistoryQueryParams = serde_json::from_str("{}").unwrap();
        assert!(params.limit.is_none());
    }
}
