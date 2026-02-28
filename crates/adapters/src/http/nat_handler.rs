use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use serde::Serialize;

use super::error::ApiError;
use super::state::AppState;

// ── Response DTOs ─────────────────────────────────────────────────

#[derive(Serialize)]
pub struct NatStatusResponse {
    pub enabled: bool,
    pub rule_count: usize,
}

#[derive(Serialize)]
pub struct NatRuleResponse {
    pub id: String,
    pub nat_type: String,
    pub direction: String,
    pub priority: u32,
    pub enabled: bool,
}

// ── Handlers ──────────────────────────────────────────────────────

pub async fn nat_status(
    State(state): State<Arc<AppState>>,
) -> Result<Json<NatStatusResponse>, ApiError> {
    let nat = state.nat_service.as_ref().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "NAT not enabled".to_string(),
    })?;
    let svc = nat.read().await;
    Ok(Json(NatStatusResponse {
        enabled: svc.enabled(),
        rule_count: svc.rule_count(),
    }))
}

pub async fn list_nat_rules(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<NatRuleResponse>>, ApiError> {
    let nat = state.nat_service.as_ref().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "NAT not enabled".to_string(),
    })?;
    let svc = nat.read().await;
    let mut rules: Vec<NatRuleResponse> = svc
        .dnat_rules()
        .iter()
        .map(|r| NatRuleResponse {
            id: r.id.0.clone(),
            nat_type: format!("{:?}", r.nat_type).to_lowercase(),
            direction: "dnat".to_string(),
            priority: r.priority,
            enabled: r.enabled,
        })
        .collect();
    rules.extend(svc.snat_rules().iter().map(|r| NatRuleResponse {
        id: r.id.0.clone(),
        nat_type: format!("{:?}", r.nat_type).to_lowercase(),
        direction: "snat".to_string(),
        priority: r.priority,
        enabled: r.enabled,
    }));
    Ok(Json(rules))
}
