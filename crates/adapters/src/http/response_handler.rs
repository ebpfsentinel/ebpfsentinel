use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::extract::{Path, State};
use domain::response::entity::{ResponseAction, ResponseActionType};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::error::ApiError;
use super::state::AppState;

// ── Request/Response DTOs ────────────────────────────────────────────

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateResponseRequest {
    /// Action type: `block_ip` or `throttle_ip`.
    pub action: String,
    /// Target IP or CIDR (e.g. "1.2.3.4" or "10.0.0.0/24").
    pub target: String,
    /// TTL duration string (e.g. "1h", "30m", "86400s").
    pub ttl: String,
    /// Rate limit in packets per second (required for `throttle_ip`).
    #[serde(default)]
    pub rate_pps: Option<u64>,
}

#[derive(Serialize, ToSchema)]
pub struct ResponseActionResponse {
    pub id: String,
    pub action_type: String,
    pub target: String,
    pub ttl_secs: u64,
    pub remaining_secs: u64,
    pub rule_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_pps: Option<u64>,
    pub revoked: bool,
}

#[derive(Serialize, ToSchema)]
pub struct ResponseListResponse {
    pub actions: Vec<ResponseActionResponse>,
    pub active_count: usize,
}

// ── Handlers ─────────────────────────────────────────────────────────

/// `POST /api/v1/responses/manual` — create a time-bounded response action.
#[utoipa::path(
    post, path = "/api/v1/responses/manual",
    tag = "Responses",
    request_body = CreateResponseRequest,
    responses(
        (status = 201, description = "Response action created", body = ResponseActionResponse),
        (status = 400, description = "Invalid request"),
    )
)]
pub async fn create_response_action(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateResponseRequest>,
) -> Result<Json<ResponseActionResponse>, ApiError> {
    let action_type = match req.action.as_str() {
        "block_ip" => ResponseActionType::BlockIp,
        "throttle_ip" => ResponseActionType::ThrottleIp,
        _ => {
            return Err(ApiError::BadRequest {
                code: "INVALID_REQUEST",
                message: format!(
                    "unknown action type: '{}'. Expected block_ip or throttle_ip",
                    req.action
                ),
            });
        }
    };

    let ttl_secs = parse_ttl(&req.ttl).ok_or_else(|| ApiError::BadRequest {
        code: "INVALID_REQUEST",
        message: format!(
            "invalid TTL format: '{}'. Expected e.g. '1h', '30m', '3600s'",
            req.ttl
        ),
    })?;

    let now_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .try_into()
        .unwrap_or(u64::MAX);

    let id = format!("resp-{}", now_ns / 1_000_000); // ms-precision ID
    let rule_id = format!("response-{id}");

    let action = ResponseAction {
        id: id.clone(),
        action_type,
        target: req.target.clone(),
        ttl_secs,
        created_at_ns: now_ns,
        expires_at_ns: now_ns + ttl_secs * 1_000_000_000,
        rule_id: rule_id.clone(),
        rate_pps: req.rate_pps,
        revoked: false,
    };

    // Register in response engine
    let response_engine = state
        .response_engine
        .as_ref()
        .ok_or(ApiError::ServiceUnavailable {
            message: "response engine not configured".to_string(),
        })?;

    {
        let mut engine = response_engine.write().await;
        engine
            .add(action.clone())
            .map_err(|e| ApiError::BadRequest {
                code: "INVALID_REQUEST",
                message: e,
            })?;
    }

    let resp = to_response(&action, now_ns);
    Ok(Json(resp))
}

/// `GET /api/v1/responses` — list active response actions.
#[utoipa::path(
    get, path = "/api/v1/responses",
    tag = "Responses",
    responses(
        (status = 200, description = "Active response actions", body = ResponseListResponse),
    )
)]
pub async fn list_response_actions(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ResponseListResponse>, ApiError> {
    let response_engine = state
        .response_engine
        .as_ref()
        .ok_or(ApiError::ServiceUnavailable {
            message: "response engine not configured".to_string(),
        })?;

    let now_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .try_into()
        .unwrap_or(u64::MAX);

    let engine = response_engine.read().await;
    let active = engine.list_active(now_ns);
    let active_count = active.len();
    let actions: Vec<ResponseActionResponse> =
        active.into_iter().map(|a| to_response(a, now_ns)).collect();

    Ok(Json(ResponseListResponse {
        actions,
        active_count,
    }))
}

/// `DELETE /api/v1/responses/{id}` — revoke a response action early.
#[utoipa::path(
    delete, path = "/api/v1/responses/{id}",
    tag = "Responses",
    params(("id" = String, Path, description = "Response action ID")),
    responses(
        (status = 200, description = "Action revoked", body = ResponseActionResponse),
        (status = 404, description = "Action not found"),
    )
)]
pub async fn revoke_response_action(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<ResponseActionResponse>, ApiError> {
    let response_engine = state
        .response_engine
        .as_ref()
        .ok_or(ApiError::ServiceUnavailable {
            message: "response engine not configured".to_string(),
        })?;

    let now_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .try_into()
        .unwrap_or(u64::MAX);

    let mut engine = response_engine.write().await;
    let action = engine.revoke(&id).ok_or(ApiError::NotFound {
        code: "RESPONSE_NOT_FOUND",
        message: format!("response action '{id}' not found or already revoked"),
    })?;

    Ok(Json(to_response(&action, now_ns)))
}

// ── Helpers ──────────────────────────────────────────────────────────

fn to_response(action: &ResponseAction, now_ns: u64) -> ResponseActionResponse {
    ResponseActionResponse {
        id: action.id.clone(),
        action_type: format!("{:?}", action.action_type).to_lowercase(),
        target: action.target.clone(),
        ttl_secs: action.ttl_secs,
        remaining_secs: action.remaining_secs(now_ns),
        rule_id: action.rule_id.clone(),
        rate_pps: action.rate_pps,
        revoked: action.revoked,
    }
}

/// Parse a human-readable TTL string into seconds.
/// Supports: `30s`, `5m`, `1h`, `1d`, or bare number (seconds).
fn parse_ttl(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (num_str, multiplier) = if let Some(n) = s.strip_suffix('s') {
        (n, 1u64)
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 60)
    } else if let Some(n) = s.strip_suffix('h') {
        (n, 3600)
    } else if let Some(n) = s.strip_suffix('d') {
        (n, 86400)
    } else {
        (s, 1)
    };
    let num: u64 = num_str.parse().ok()?;
    Some(num * multiplier)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ttl_seconds() {
        assert_eq!(parse_ttl("30s"), Some(30));
        assert_eq!(parse_ttl("3600"), Some(3600));
    }

    #[test]
    fn parse_ttl_minutes() {
        assert_eq!(parse_ttl("5m"), Some(300));
    }

    #[test]
    fn parse_ttl_hours() {
        assert_eq!(parse_ttl("1h"), Some(3600));
        assert_eq!(parse_ttl("24h"), Some(86400));
    }

    #[test]
    fn parse_ttl_days() {
        assert_eq!(parse_ttl("1d"), Some(86400));
    }

    #[test]
    fn parse_ttl_invalid() {
        assert_eq!(parse_ttl(""), None);
        assert_eq!(parse_ttl("abc"), None);
    }

    #[test]
    fn response_serialization() {
        let resp = ResponseActionResponse {
            id: "resp-001".to_string(),
            action_type: "block_ip".to_string(),
            target: "1.2.3.4".to_string(),
            ttl_secs: 3600,
            remaining_secs: 1800,
            rule_id: "response-resp-001".to_string(),
            rate_pps: None,
            revoked: false,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["id"], "resp-001");
        assert_eq!(json["action_type"], "block_ip");
        assert_eq!(json["remaining_secs"], 1800);
        assert!(json.get("rate_pps").is_none());
    }
}
