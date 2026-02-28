use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use serde::Serialize;

use super::error::ApiError;
use super::state::AppState;

// ── Response DTOs ─────────────────────────────────────────────────

#[derive(Serialize)]
pub struct RoutingStatusResponse {
    pub enabled: bool,
    pub gateway_count: usize,
}

#[derive(Serialize)]
pub struct GatewayResponse {
    pub id: u8,
    pub name: String,
    pub interface: String,
    pub gateway_ip: String,
    pub priority: u32,
    pub enabled: bool,
    pub status: String,
}

// ── Handlers ──────────────────────────────────────────────────────

pub async fn routing_status(
    State(state): State<Arc<AppState>>,
) -> Result<Json<RoutingStatusResponse>, ApiError> {
    let routing = state.routing_service.as_ref().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "Routing not enabled".to_string(),
    })?;
    let svc = routing.read().await;
    Ok(Json(RoutingStatusResponse {
        enabled: svc.enabled(),
        gateway_count: svc.gateway_count(),
    }))
}

pub async fn list_gateways(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<GatewayResponse>>, ApiError> {
    let routing = state.routing_service.as_ref().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "Routing not enabled".to_string(),
    })?;
    let svc = routing.read().await;
    let gateways: Vec<GatewayResponse> = svc
        .list_gateways()
        .iter()
        .map(|gs| GatewayResponse {
            id: gs.gateway.id,
            name: gs.gateway.name.clone(),
            interface: gs.gateway.interface.clone(),
            gateway_ip: gs.gateway.gateway_ip.clone(),
            priority: gs.gateway.priority,
            enabled: gs.gateway.enabled,
            status: format!("{:?}", gs.status).to_lowercase(),
        })
        .collect();
    Ok(Json(gateways))
}
