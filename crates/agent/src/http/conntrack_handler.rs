use std::convert::Infallible;
use std::sync::Arc;

use axum::Extension;
use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::response::sse::{Event, KeepAlive, Sse};
use domain::auth::entity::JwtClaims;
use serde::{Deserialize, Serialize};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;
use utoipa::ToSchema;

use super::error::{ApiError, ErrorBody};
use super::middleware::rbac::require_write_access;
use super::state::AppState;

// ── Response DTOs ─────────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
pub struct ConnTrackStatusResponse {
    pub enabled: bool,
    pub connection_count: u64,
    /// Conntrack table capacity — the maximum number of flows the
    /// agent tracks before eviction (the BPF connection-table size).
    pub max_connections: u64,
}

#[derive(Serialize, ToSchema)]
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

/// `GET /api/v1/conntrack/status` — connection tracking status.
#[utoipa::path(
    get, path = "/api/v1/conntrack/status",
    tag = "ConnTrack",
    responses((status = 200, description = "Conntrack status", body = ConnTrackStatusResponse),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
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
        max_connections: u64::from(ebpf_common::conntrack::CT_MAX_ENTRIES_V4),
    }))
}

/// `GET /api/v1/conntrack/connections` — list tracked connections.
#[utoipa::path(
    get, path = "/api/v1/conntrack/connections",
    tag = "ConnTrack",
    responses((status = 200, description = "Connection list", body = Vec<ConnectionResponse>),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
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

/// `POST /api/v1/conntrack/flush` — flush all tracked connections.
#[utoipa::path(
    post, path = "/api/v1/conntrack/flush",
    tag = "ConnTrack",
    responses((status = 200, description = "Connections flushed"),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn flush_connections(
    State(state): State<Arc<AppState>>,
    claims: Option<Extension<JwtClaims>>,
) -> Result<impl IntoResponse, ApiError> {
    if let Some(Extension(ref claims)) = claims {
        require_write_access(claims)?;
    }
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

/// `GET /api/v1/conntrack/events` — Server-Sent Events stream of
/// conntrack lifecycle events (new / update / destroy).
///
/// The poller diffs `/proc/net/nf_conntrack` snapshots every 2 s and
/// pushes changes into a broadcast channel. Each SSE client receives
/// a copy. Lagged clients silently skip missed events.
pub async fn conntrack_events(
    State(state): State<Arc<AppState>>,
) -> Result<Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>>, ApiError> {
    let tx = state
        .conntrack_event_tx
        .as_ref()
        .ok_or(ApiError::NotFound {
            code: "SERVICE_NOT_AVAILABLE",
            message: "Conntrack event stream not enabled".to_string(),
        })?;
    let rx = tx.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|item| match item {
        Ok(evt) => {
            let json = serde_json::to_string(&evt).unwrap_or_default();
            Some(Ok(Event::default()
                .event(evt.event_type.as_str())
                .data(json)))
        }
        Err(_) => None, // lagged — skip
    });
    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_limit_is_100() {
        assert_eq!(default_limit(), 100);
    }
}
