use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use serde::Serialize;
use utoipa::ToSchema;

use super::error::ApiError;
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
}

// ── Handlers ────────────────────────────────────────────────────────

/// `GET /api/v1/ids/status` — IDS service status.
#[utoipa::path(
    get, path = "/api/v1/ids/status",
    tag = "IDS",
    responses(
        (status = 200, description = "IDS status", body = IdsStatusResponse),
        (status = 404, description = "IDS not available"),
    )
)]
pub async fn ids_status(
    State(state): State<Arc<AppState>>,
) -> Result<Json<IdsStatusResponse>, ApiError> {
    let svc_arc = state.ids_service.as_ref().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "IDS service is not enabled".to_string(),
    })?;
    let svc = svc_arc.read().await;
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
        (status = 404, description = "IDS not available"),
    )
)]
pub async fn list_ids_rules(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<IdsRuleResponse>>, ApiError> {
    let svc_arc = state.ids_service.as_ref().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "IDS service is not enabled".to_string(),
    })?;
    let svc = svc_arc.read().await;
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
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["id"], "ids-001");
        assert_eq!(json["dst_port"], 22);
    }
}
