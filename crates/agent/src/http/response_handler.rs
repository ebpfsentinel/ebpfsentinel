use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use application::ips_service_impl::IpsAppService;
use application::ratelimit_service_impl::RateLimitAppService;
use arc_swap::ArcSwap;
use axum::Extension;
use axum::Json;
use axum::extract::{Path, State};
use domain::audit::entity::AuditAction;
use domain::auth::entity::JwtClaims;
use domain::common::entity::RuleId;
use domain::firewall::entity::IpCidr;
use domain::ratelimit::entity::{RateLimitAction, RateLimitAlgorithm, RateLimitPolicy};
use domain::response::entity::{ResponseAction, ResponseActionType};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use utoipa::ToSchema;

use super::error::{ApiError, ErrorBody};
use super::middleware::rbac::require_write_access;
use super::state::AppState;

// ── Request/Response DTOs ────────────────────────────────────────────

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateResponseRequest {
    /// Action type: `block_ip` or `throttle_ip`.
    pub action: String,
    /// Target host address (e.g. `1.2.3.4` or `2001:db8::1`). The blacklist
    /// and the rate limiter are both keyed by a single address, so a prefix
    /// is refused rather than silently narrowed.
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
        (status = 400, description = "Invalid request", body = ErrorBody),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn create_response_action(
    State(state): State<Arc<AppState>>,
    claims: Option<Extension<JwtClaims>>,
    Json(req): Json<CreateResponseRequest>,
) -> Result<Json<ResponseActionResponse>, ApiError> {
    if let Some(Extension(ref claims)) = claims {
        require_write_access(claims)?;
    }
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

    let target: IpAddr = req
        .target
        .trim()
        .parse()
        .map_err(|_| ApiError::BadRequest {
            code: "INVALID_REQUEST",
            message: format!(
                "invalid target: '{}'. Expected a single host address, e.g. '1.2.3.4'",
                req.target
            ),
        })?;

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

    let response_engine = state
        .response_engine
        .as_ref()
        .ok_or(ApiError::ServiceUnavailable {
            message: "response engine not configured".to_string(),
        })?;

    // The TTL cap is checked before the data plane is touched, so a refused
    // action leaves nothing installed behind it.
    let max_ttl_secs = response_engine.read().await.max_ttl_secs();
    if ttl_secs > max_ttl_secs {
        return Err(ApiError::BadRequest {
            code: "INVALID_REQUEST",
            message: format!("TTL {ttl_secs}s exceeds maximum {max_ttl_secs}s"),
        });
    }

    enforce(
        &state.ips_service,
        &state.ratelimit_service,
        &action,
        target,
    )
    .await?;

    {
        let mut engine = response_engine.write().await;
        engine
            .add(action.clone())
            .map_err(|e| ApiError::BadRequest {
                code: "INVALID_REQUEST",
                message: e,
            })?;
    }

    state.audit_service.record_response_action(
        AuditAction::RuleAdded,
        &action.target,
        &action.rule_id,
        &format!(
            "created {} response on {} (ttl {}s)",
            to_response(&action, now_ns).action_type,
            action.target,
            action.ttl_secs
        ),
    );

    let resp = to_response(&action, now_ns);
    Ok(Json(resp))
}

/// `GET /api/v1/responses` — list active response actions.
#[utoipa::path(
    get, path = "/api/v1/responses",
    tag = "Responses",
    responses(
        (status = 200, description = "Active response actions", body = ResponseListResponse),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
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
        (status = 404, description = "Action not found", body = ErrorBody),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn revoke_response_action(
    State(state): State<Arc<AppState>>,
    claims: Option<Extension<JwtClaims>>,
    Path(id): Path<String>,
) -> Result<Json<ResponseActionResponse>, ApiError> {
    if let Some(Extension(ref claims)) = claims {
        require_write_access(claims)?;
    }
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

    let action = {
        let mut engine = response_engine.write().await;
        engine.revoke(&id).ok_or(ApiError::NotFound {
            code: "RESPONSE_NOT_FOUND",
            message: format!("response action '{id}' not found or already revoked"),
        })?
    };

    withdraw(&state.ips_service, &state.ratelimit_service, &action).await;

    state.audit_service.record_response_action(
        AuditAction::RuleRemoved,
        &action.target,
        &action.rule_id,
        &format!("revoked response on {} before ttl", action.target),
    );

    Ok(Json(to_response(&action, now_ns)))
}

// ── Helpers ──────────────────────────────────────────────────────────

/// Apply a response to the data plane.
///
/// A block goes to the IPS blacklist, which drops the source and expires the
/// entry on its own clock. A throttle installs a per-source token bucket in
/// the XDP rate limiter, whose map is keyed by a 32-bit address and holds no
/// expiry of its own: the sweeper lifts it when the TTL elapses.
async fn enforce(
    ips_service: &ArcSwap<IpsAppService>,
    ratelimit_service: &RwLock<RateLimitAppService>,
    action: &ResponseAction,
    target: IpAddr,
) -> Result<(), ApiError> {
    match action.action_type {
        ResponseActionType::BlockIp => ips_service
            .load()
            .add_to_blacklist(
                target,
                format!("manual response {}", action.id),
                Duration::from_secs(action.ttl_secs),
            )
            .map_err(|e| ApiError::BadRequest {
                code: "ENFORCEMENT_FAILED",
                message: format!("blacklisting {target} failed: {e}"),
            }),
        ResponseActionType::ThrottleIp => {
            let rate = action.rate_pps.unwrap_or(0);
            if rate == 0 {
                return Err(ApiError::BadRequest {
                    code: "INVALID_REQUEST",
                    message: "throttle_ip needs rate_pps above zero: it is the bucket to install"
                        .to_string(),
                });
            }
            let IpAddr::V4(v4) = target else {
                return Err(ApiError::BadRequest {
                    code: "INVALID_REQUEST",
                    message: format!(
                        "the rate limiter matches IPv4 sources; contain {target} with block_ip"
                    ),
                });
            };
            let policy = RateLimitPolicy {
                id: RuleId(action.rule_id.clone()),
                rate,
                // One second of build-up, the same bucket shape the automatic
                // throttle installs.
                burst: rate,
                action: RateLimitAction::Drop,
                src_ip: IpCidr::V4 {
                    addr: v4.to_bits(),
                    prefix_len: 32,
                },
                enabled: true,
                algorithm: RateLimitAlgorithm::TokenBucket,
                group_mask: 0,
                tenant_id: 0,
            };
            let mut rl = ratelimit_service.write().await;
            rl.add_policy(policy).map_err(|e| ApiError::BadRequest {
                code: "ENFORCEMENT_FAILED",
                message: format!("throttling {target} failed: {e}"),
            })
        }
    }
}

/// Lift a response from the data plane, best-effort.
///
/// Called on an early revoke and when the sweeper finds an elapsed TTL. A
/// blacklist entry may already have expired itself, and a throttle may have
/// been removed by a config reload, so a missing entry is not an error.
pub(crate) async fn withdraw(
    ips_service: &ArcSwap<IpsAppService>,
    ratelimit_service: &RwLock<RateLimitAppService>,
    action: &ResponseAction,
) {
    match action.action_type {
        ResponseActionType::BlockIp => {
            let Ok(target) = action.target.parse::<IpAddr>() else {
                return;
            };
            if let Err(e) = ips_service.load().remove_from_blacklist(target) {
                tracing::debug!(target = %action.target, error = %e, "response: blacklist entry already gone");
            }
        }
        ResponseActionType::ThrottleIp => {
            let mut rl = ratelimit_service.write().await;
            if let Err(e) = rl.remove_policy(&RuleId(action.rule_id.clone())) {
                tracing::debug!(rule_id = %action.rule_id, error = %e, "response: throttle entry already gone");
            }
        }
    }
}

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

    // ── Data-plane enforcement ───────────────────────────────────────

    fn services() -> (ArcSwap<IpsAppService>, RwLock<RateLimitAppService>) {
        let noop: Arc<dyn ports::secondary::metrics_port::MetricsPort> =
            Arc::new(ports::test_utils::NoopMetrics);
        (
            ArcSwap::from_pointee(IpsAppService::new(
                domain::ips::engine::IpsEngine::default(),
                Arc::clone(&noop),
            )),
            RwLock::new(RateLimitAppService::new(
                domain::ratelimit::engine::RateLimitEngine::new(),
                noop,
            )),
        )
    }

    fn action(
        action_type: ResponseActionType,
        target: &str,
        rate_pps: Option<u64>,
    ) -> ResponseAction {
        ResponseAction {
            id: "resp-001".to_string(),
            action_type,
            target: target.to_string(),
            ttl_secs: 60,
            created_at_ns: 0,
            expires_at_ns: 60_000_000_000,
            rule_id: "response-resp-001".to_string(),
            rate_pps,
            revoked: false,
        }
    }

    #[tokio::test]
    async fn a_block_reaches_the_blacklist_and_withdraw_lifts_it() {
        let (ips, rl) = services();
        let action = action(ResponseActionType::BlockIp, "1.2.3.4", None);
        let target: IpAddr = "1.2.3.4".parse().unwrap();

        enforce(&ips, &rl, &action, target).await.unwrap();
        assert!(ips.load().is_blacklisted(target));

        withdraw(&ips, &rl, &action).await;
        assert!(!ips.load().is_blacklisted(target));
    }

    #[tokio::test]
    async fn a_throttle_installs_a_host_bucket_and_withdraw_lifts_it() {
        let (ips, rl) = services();
        let action = action(ResponseActionType::ThrottleIp, "1.2.3.4", Some(500));
        let target: IpAddr = "1.2.3.4".parse().unwrap();

        enforce(&ips, &rl, &action, target).await.unwrap();
        {
            let guard = rl.read().await;
            let policies = guard.policies();
            assert_eq!(policies.len(), 1);
            assert_eq!(policies[0].rate, 500);
            assert_eq!(policies[0].burst, 500);
            assert_eq!(
                policies[0].src_ip,
                IpCidr::V4 {
                    addr: u32::from(std::net::Ipv4Addr::new(1, 2, 3, 4)),
                    prefix_len: 32,
                }
            );
        }

        withdraw(&ips, &rl, &action).await;
        assert_eq!(rl.read().await.policies().len(), 0);
    }

    #[tokio::test]
    async fn a_throttle_without_a_rate_installs_nothing() {
        let (ips, rl) = services();
        let action = action(ResponseActionType::ThrottleIp, "1.2.3.4", None);

        let err = enforce(&ips, &rl, &action, "1.2.3.4".parse().unwrap())
            .await
            .unwrap_err();
        assert!(format!("{err:?}").contains("rate_pps"));
        assert_eq!(rl.read().await.policies().len(), 0);
    }

    #[tokio::test]
    async fn a_throttle_on_an_ipv6_target_installs_nothing() {
        let (ips, rl) = services();
        let action = action(ResponseActionType::ThrottleIp, "2001:db8::1", Some(500));

        let err = enforce(&ips, &rl, &action, "2001:db8::1".parse().unwrap())
            .await
            .unwrap_err();
        assert!(format!("{err:?}").contains("IPv4"));
        assert_eq!(rl.read().await.policies().len(), 0);
    }
}
