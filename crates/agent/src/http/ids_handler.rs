use std::sync::Arc;

use axum::Json;
use axum::extract::State;
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
    pub pattern: String,
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold: Option<ThresholdResponse>,
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

// ── Handlers ────────────────────────────────────────────────────────

/// `GET /api/v1/ids/status` — IDS service status.
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
        mode: format!("{:?}", svc.mode()),
        rule_count: svc.rule_count(),
    }))
}

/// `GET /api/v1/ids/rules` — list all IDS rules.
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
    let svc = svc_arc.load();
    let shadows = svc.slot_shadows();
    let rules: Vec<IdsRuleResponse> = svc
        .list_rules()
        .iter()
        .map(|r| IdsRuleResponse {
            id: r.id.0.clone(),
            description: r.description.clone(),
            severity: format!("{:?}", r.severity),
            mode: format!("{:?}", r.mode),
            protocol: format!("{:?}", r.protocol),
            dst_port: r.dst_port,
            pattern: r.pattern.clone(),
            enabled: r.enabled,
            threshold: r.threshold.as_ref().map(|t| ThresholdResponse {
                threshold_type: format!("{:?}", t.threshold_type),
                count: t.count,
                window_secs: t.window_secs,
                track_by: format!("{:?}", t.track_by),
            }),
            kernel_slot: shadows.get(&r.id.0).map(SlotContentionResponse::from),
        })
        .collect();
    Ok(Json(rules))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_status_response_serialization() {
        let resp = IdsStatusResponse {
            enabled: true,
            mode: "Alert".to_string(),
            rule_count: 5,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["enabled"], true);
        assert_eq!(json["mode"], "Alert");
        assert_eq!(json["rule_count"], 5);
    }

    #[test]
    fn ids_rule_response_serialization() {
        let resp = IdsRuleResponse {
            id: "ids-001".to_string(),
            description: "SSH scan".to_string(),
            severity: "High".to_string(),
            mode: "Alert".to_string(),
            protocol: "Tcp".to_string(),
            dst_port: Some(22),
            pattern: String::new(),
            enabled: true,
            threshold: Some(ThresholdResponse {
                threshold_type: "Threshold".to_string(),
                count: 5,
                window_secs: 30,
                track_by: "SrcIp".to_string(),
            }),
            kernel_slot: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["id"], "ids-001");
        assert_eq!(json["dst_port"], 22);
        assert_eq!(json["threshold"]["count"], 5);
        assert!(json.get("kernel_slot").is_none());
    }

    #[test]
    fn ids_rule_response_reports_a_lost_kernel_slot() {
        let resp = IdsRuleResponse {
            id: "ids-002".to_string(),
            description: "Shadowed by an IPS rule".to_string(),
            severity: "High".to_string(),
            mode: "Alert".to_string(),
            protocol: "Tcp".to_string(),
            dst_port: Some(22),
            pattern: String::new(),
            enabled: true,
            threshold: None,
            kernel_slot: Some(SlotContentionResponse {
                shadowed_by: vec!["ips-001".to_string()],
                evaluated_in_userspace: true,
            }),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["kernel_slot"]["shadowed_by"][0], "ips-001");
        assert_eq!(json["kernel_slot"]["evaluated_in_userspace"], true);
    }
}
