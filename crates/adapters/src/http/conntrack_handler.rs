use std::sync::Arc;

use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

use super::error::ApiError;
use super::state::AppState;

// ── Response DTOs ─────────────────────────────────────────────────

#[derive(Serialize)]
pub struct ConnTrackStatusResponse {
    pub enabled: bool,
    pub connection_count: u64,
}

#[derive(Serialize)]
pub struct ConnectionResponse {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub state: String,
    pub packets_fwd: u32,
    pub packets_rev: u32,
    pub bytes_fwd: u32,
    pub bytes_rev: u32,
}

// ── Query params ─────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ListQuery {
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize {
    100
}

// ── Handlers ──────────────────────────────────────────────────────

pub async fn conntrack_status(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ConnTrackStatusResponse>, ApiError> {
    let ct = state.conntrack_service.as_ref().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "Conntrack not enabled".to_string(),
    })?;
    let svc = ct.read().await;
    let count = svc.connection_count().unwrap_or(0);
    Ok(Json(ConnTrackStatusResponse {
        enabled: svc.enabled(),
        connection_count: count,
    }))
}

pub async fn list_connections(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Vec<ConnectionResponse>>, ApiError> {
    let ct = state.conntrack_service.as_ref().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "Conntrack not enabled".to_string(),
    })?;
    let svc = ct.read().await;
    let conns = svc
        .get_connections(query.limit)
        .map_err(|e| ApiError::Internal {
            message: format!("conntrack query failed: {e}"),
        })?;
    let result = conns
        .into_iter()
        .map(|c| ConnectionResponse {
            src_ip: c.src_ip,
            dst_ip: c.dst_ip,
            src_port: c.src_port,
            dst_port: c.dst_port,
            protocol: c.protocol,
            state: c.state.to_string(),
            packets_fwd: c.packets_fwd,
            packets_rev: c.packets_rev,
            bytes_fwd: c.bytes_fwd,
            bytes_rev: c.bytes_rev,
        })
        .collect();
    Ok(Json(result))
}

pub async fn flush_connections(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, ApiError> {
    let ct = state.conntrack_service.as_ref().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "Conntrack not enabled".to_string(),
    })?;
    let mut svc = ct.write().await;
    let count = svc.flush_all().map_err(|e| ApiError::Internal {
        message: format!("conntrack flush failed: {e}"),
    })?;
    tracing::info!(count, "conntrack table flushed via API");
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({ "flushed": count })),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_limit_is_100() {
        assert_eq!(default_limit(), 100);
    }
}
