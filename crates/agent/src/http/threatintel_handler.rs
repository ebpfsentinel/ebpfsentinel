use std::sync::Arc;
use std::sync::atomic::Ordering;

use axum::Extension;
use axum::Json;
use axum::extract::State;
use domain::auth::entity::JwtClaims;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::error::{ApiError, ErrorBody};
use super::middleware::rbac::require_write_access;
use super::state::AppState;

// ── Response DTOs ───────────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
pub struct ThreatIntelStatusResponse {
    pub enabled: bool,
    pub mode: String,
    pub ioc_count: usize,
    pub feed_count: usize,
}

#[derive(Serialize, ToSchema)]
pub struct IocResponse {
    pub ip: String,
    pub feed_id: String,
    pub confidence: u8,
    pub threat_type: String,
    pub source_feed: String,
}

#[derive(Serialize, ToSchema)]
pub struct UrlIocResponse {
    pub url: String,
    pub feed_id: String,
    pub confidence: u8,
    pub threat_type: String,
}

#[derive(Serialize, ToSchema)]
pub struct FeedResponse {
    pub id: String,
    pub name: String,
    pub url: String,
    pub format: String,
    pub enabled: bool,
    pub refresh_interval_secs: u64,
    pub max_iocs: usize,
    pub min_confidence: u8,
    /// Unix-epoch milliseconds of the last completed feed fetch, or `null`
    /// if no fetch has run yet. Shared across feeds (one fetch cycle).
    pub last_fetched: Option<u64>,
}

/// Optional body for a feed refresh request.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct RefreshFeedRequest {
    /// Feed to refresh. Accepted for forward compatibility; the fetcher
    /// currently refreshes every enabled feed in a single cycle.
    #[serde(default)]
    pub feed_id: Option<String>,
}

/// Response to a feed refresh request.
#[derive(Serialize, ToSchema)]
pub struct RefreshResponse {
    pub status: String,
    pub message: String,
}

// ── Handlers ────────────────────────────────────────────────────────

/// `GET /api/v1/threatintel/status` — threat intel subsystem status.
#[utoipa::path(
    get, path = "/api/v1/threatintel/status",
    tag = "Threat Intelligence",
    responses((status = 200, description = "Threat intel subsystem status", body = ThreatIntelStatusResponse),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn threatintel_status(
    State(state): State<Arc<AppState>>,
) -> Json<ThreatIntelStatusResponse> {
    let svc = state.threatintel_service.load();
    Json(ThreatIntelStatusResponse {
        enabled: svc.enabled(),
        mode: svc.mode().as_str().to_string(),
        ioc_count: svc.ioc_count(),
        feed_count: svc.list_feeds().len(),
    })
}

/// `GET /api/v1/threatintel/iocs` — list loaded IOCs.
#[utoipa::path(
    get, path = "/api/v1/threatintel/iocs",
    tag = "Threat Intelligence",
    responses((status = 200, description = "List of loaded IOCs", body = Vec<IocResponse>),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn list_iocs(State(state): State<Arc<AppState>>) -> Json<Vec<IocResponse>> {
    let svc = state.threatintel_service.load();
    let iocs: Vec<IocResponse> = svc
        .engine()
        .all_iocs()
        .map(|ioc| IocResponse {
            ip: ioc.ip.to_string(),
            feed_id: ioc.feed_id.clone(),
            confidence: ioc.confidence,
            threat_type: ioc.threat_type.to_string(),
            source_feed: ioc.source_feed.clone(),
        })
        .collect();
    Json(iocs)
}

/// `GET /api/v1/threatintel/urls` — list malicious URL indicators ingested
/// from CTI feeds. The threat-intel engine is IP-only, so URL indicators are
/// surfaced from the service's retained snapshot.
#[utoipa::path(
    get, path = "/api/v1/threatintel/urls",
    tag = "Threat Intelligence",
    responses((status = 200, description = "List of malicious URL indicators", body = Vec<UrlIocResponse>),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn list_url_iocs(State(state): State<Arc<AppState>>) -> Json<Vec<UrlIocResponse>> {
    let svc = state.threatintel_service.load();
    let urls: Vec<UrlIocResponse> = svc
        .urls()
        .iter()
        .map(|u| UrlIocResponse {
            url: u.url.clone(),
            feed_id: u.feed_id.clone(),
            confidence: u.confidence,
            threat_type: u.threat_type.to_string(),
        })
        .collect();
    Json(urls)
}

/// `GET /api/v1/threatintel/feeds` — list configured feeds.
#[utoipa::path(
    get, path = "/api/v1/threatintel/feeds",
    tag = "Threat Intelligence",
    responses((status = 200, description = "List of configured feeds", body = Vec<FeedResponse>),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn list_feeds(State(state): State<Arc<AppState>>) -> Json<Vec<FeedResponse>> {
    let svc = state.threatintel_service.load();
    let last_fetched = svc.last_fetched();
    let feeds: Vec<FeedResponse> = svc
        .list_feeds()
        .iter()
        .map(|f| FeedResponse {
            id: f.id.clone(),
            name: f.name.clone(),
            url: f.url.clone(),
            format: format!("{:?}", f.format).to_lowercase(),
            enabled: f.enabled,
            refresh_interval_secs: f.refresh_interval_secs,
            max_iocs: f.max_iocs,
            min_confidence: f.min_confidence,
            last_fetched,
        })
        .collect();
    Json(feeds)
}

/// `POST /api/v1/threatintel/feeds/refresh` — trigger an immediate re-fetch
/// of all enabled threat-intel feeds.
#[utoipa::path(
    post, path = "/api/v1/threatintel/feeds/refresh",
    tag = "Threat Intelligence",
    request_body = RefreshFeedRequest,
    responses((status = 200, description = "Feed refresh triggered", body = RefreshResponse),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
        (status = 409, description = "A feed refresh is already running", body = ErrorBody),
        (status = 503, description = "Threat intel feeds not enabled", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn refresh_feeds(
    State(state): State<Arc<AppState>>,
    claims: Option<Extension<JwtClaims>>,
    body: Option<Json<RefreshFeedRequest>>,
) -> Result<Json<RefreshResponse>, ApiError> {
    if let Some(Extension(ref claims)) = claims {
        require_write_access(claims)?;
    }
    let req = body.map(|Json(b)| b).unwrap_or_default();
    let trigger =
        state
            .feed_refresh_trigger
            .as_ref()
            .ok_or_else(|| ApiError::ServiceUnavailable {
                message: "threat intel feeds are not enabled".to_string(),
            })?;
    // Claim the single fetch slot. The write rate limit bounds how often this
    // route may be called; it does not bound how many outbound feed downloads
    // are in flight, so a caller staying inside the limit could still stack one
    // full fetch of every configured feed per request and point the agent at
    // somebody else's server. One cycle runs at a time and a second caller is
    // told so rather than queued behind the first. The flag is cleared by the
    // feed fetcher when the cycle it started ends, whatever the outcome.
    if state
        .feed_refresh_in_flight
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err(ApiError::Conflict {
            code: "REFRESH_IN_PROGRESS",
            message: "a threat intel feed refresh is already running".to_string(),
        });
    }

    match trigger.try_send(()) {
        // Sent, or a refresh is already queued — both mean a fetch will run.
        Ok(()) | Err(tokio::sync::mpsc::error::TrySendError::Full(())) => {
            tracing::info!(feed_id = ?req.feed_id, "threat intel feed refresh requested");
            Ok(Json(RefreshResponse {
                status: "ok".to_string(),
                message: "feed refresh triggered".to_string(),
            }))
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(())) => {
            // Nothing will run, so nothing will clear the flag: release it here
            // or the route answers `409` for the life of the process.
            state.feed_refresh_in_flight.store(false, Ordering::SeqCst);
            Err(ApiError::ServiceUnavailable {
                message: "feed fetcher is not running".to_string(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_response_serialization() {
        let resp = ThreatIntelStatusResponse {
            enabled: true,
            mode: "alert".to_string(),
            ioc_count: 42,
            feed_count: 3,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["enabled"], true);
        assert_eq!(json["mode"], "alert");
        assert_eq!(json["ioc_count"], 42);
        assert_eq!(json["feed_count"], 3);
    }

    #[test]
    fn ioc_response_serialization() {
        let resp = IocResponse {
            ip: "10.0.0.1".to_string(),
            feed_id: "alienvault-otx".to_string(),
            confidence: 90,
            threat_type: "c2".to_string(),
            source_feed: "AlienVault OTX".to_string(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["ip"], "10.0.0.1");
        assert_eq!(json["feed_id"], "alienvault-otx");
        assert_eq!(json["confidence"], 90);
        assert_eq!(json["threat_type"], "c2");
    }

    #[test]
    fn feed_response_serialization() {
        let resp = FeedResponse {
            id: "test".to_string(),
            name: "Test Feed".to_string(),
            url: "https://example.com".to_string(),
            format: "csv".to_string(),
            enabled: true,
            refresh_interval_secs: 3600,
            max_iocs: 500_000,
            min_confidence: 0,
            last_fetched: Some(1_700_000_000_000),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["id"], "test");
        assert_eq!(json["refresh_interval_secs"], 3600);
        assert_eq!(json["last_fetched"], 1_700_000_000_000_u64);
    }

    #[test]
    fn feed_response_null_last_fetched() {
        let resp = FeedResponse {
            id: "test".to_string(),
            name: "Test Feed".to_string(),
            url: "https://example.com".to_string(),
            format: "stix".to_string(),
            enabled: true,
            refresh_interval_secs: 3600,
            max_iocs: 1000,
            min_confidence: 0,
            last_fetched: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json["last_fetched"].is_null());
    }

    #[test]
    fn refresh_request_defaults_feed_id_none() {
        let req: RefreshFeedRequest = serde_json::from_str("{}").unwrap();
        assert!(req.feed_id.is_none());
        let req: RefreshFeedRequest = serde_json::from_str(r#"{"feed_id":"x"}"#).unwrap();
        assert_eq!(req.feed_id.as_deref(), Some("x"));
    }

    // ── Manual refresh is single-flight ──────────────────────────────

    use std::sync::atomic::AtomicBool;

    use adapters::metrics::AgentMetrics;
    use application::audit_service_impl::AuditAppService;
    use application::firewall_service_impl::FirewallAppService;
    use application::ips_service_impl::IpsAppService;
    use application::l7_service_impl::L7AppService;
    use application::ratelimit_service_impl::RateLimitAppService;
    use application::threatintel_service_impl::ThreatIntelAppService;
    use domain::audit::entity::AuditEntry;
    use domain::audit::error::AuditError;
    use domain::firewall::engine::FirewallEngine;
    use domain::ips::engine::IpsEngine;
    use domain::l7::engine::L7Engine;
    use domain::ratelimit::engine::RateLimitEngine;
    use domain::threatintel::engine::ThreatIntelEngine;
    use ports::secondary::audit_sink::AuditSink;
    use ports::secondary::metrics_port::MetricsPort;
    use ports::test_utils::NoopMetrics;

    struct NoopSink;
    impl AuditSink for NoopSink {
        fn write_entry(&self, _entry: &AuditEntry) -> Result<(), AuditError> {
            Ok(())
        }
    }

    fn bare_state() -> AppState {
        let noop: Arc<dyn MetricsPort> = Arc::new(NoopMetrics);
        let fw_svc = FirewallAppService::new(FirewallEngine::new(), None, Arc::clone(&noop));
        let ips_svc = IpsAppService::new(IpsEngine::default(), Arc::clone(&noop));
        let l7_svc = L7AppService::new(L7Engine::new(), Arc::clone(&noop));
        let rl_svc = RateLimitAppService::new(RateLimitEngine::new(), Arc::clone(&noop));
        let ti_svc = ThreatIntelAppService::new(
            ThreatIntelEngine::new(1_000_000),
            Arc::clone(&noop),
            vec![],
        );
        let audit_svc = AuditAppService::new(Arc::new(NoopSink) as Arc<dyn AuditSink>);
        let (reload_tx, _reload_rx) = tokio::sync::mpsc::channel(1);
        AppState::new(
            Arc::new(AgentMetrics::new()),
            Arc::new(AtomicBool::new(false)),
            Arc::new(tokio::sync::RwLock::new(fw_svc)),
            Arc::new(arc_swap::ArcSwap::from_pointee(ips_svc)),
            Arc::new(arc_swap::ArcSwap::from_pointee(l7_svc)),
            Arc::new(tokio::sync::RwLock::new(rl_svc)),
            Arc::new(arc_swap::ArcSwap::from_pointee(ti_svc)),
            Arc::new(audit_svc),
            Arc::new(tokio::sync::RwLock::new(
                infrastructure::config::AgentConfig::from_yaml("agent:\n  interfaces: [eth0]")
                    .unwrap(),
            )),
            reload_tx,
            Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
        )
    }

    #[tokio::test]
    async fn refresh_refuses_a_second_caller_while_a_cycle_is_running() {
        let (tx, _rx) = tokio::sync::mpsc::channel::<()>(4);
        let flag = Arc::new(AtomicBool::new(false));
        let state = Arc::new(bare_state().with_feed_refresh_trigger(tx, Arc::clone(&flag)));

        let first = refresh_feeds(State(Arc::clone(&state)), None, None).await;
        assert!(first.is_ok(), "the first caller starts the cycle");
        assert!(flag.load(Ordering::SeqCst), "the fetch slot is claimed");

        match refresh_feeds(State(Arc::clone(&state)), None, None).await {
            Err(ApiError::Conflict { code, .. }) => assert_eq!(code, "REFRESH_IN_PROGRESS"),
            _ => panic!("a second caller must not queue a second fetch"),
        }
    }

    #[tokio::test]
    async fn refresh_runs_again_once_the_cycle_has_ended() {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(4);
        let flag = Arc::new(AtomicBool::new(false));
        let state = Arc::new(bare_state().with_feed_refresh_trigger(tx, Arc::clone(&flag)));

        assert!(
            refresh_feeds(State(Arc::clone(&state)), None, None)
                .await
                .is_ok()
        );
        assert_eq!(rx.try_recv(), Ok(()), "one fetch was asked for");
        // What the feed fetcher's own guard does when the cycle ends.
        flag.store(false, Ordering::SeqCst);

        assert!(
            refresh_feeds(State(Arc::clone(&state)), None, None)
                .await
                .is_ok(),
            "the slot is free again once the cycle has ended"
        );
    }

    #[tokio::test]
    async fn refresh_releases_the_slot_when_the_fetcher_is_gone() {
        let (tx, rx) = tokio::sync::mpsc::channel::<()>(4);
        drop(rx);
        let flag = Arc::new(AtomicBool::new(false));
        let state = Arc::new(bare_state().with_feed_refresh_trigger(tx, Arc::clone(&flag)));

        match refresh_feeds(State(Arc::clone(&state)), None, None).await {
            Err(ApiError::ServiceUnavailable { .. }) => {}
            _ => panic!("a dead fetcher must report unavailable"),
        }
        assert!(
            !flag.load(Ordering::SeqCst),
            "nothing will clear a slot claimed for a fetch that never starts"
        );
    }

    #[tokio::test]
    async fn refresh_reports_unavailable_without_a_trigger() {
        let state = Arc::new(bare_state());
        match refresh_feeds(State(Arc::clone(&state)), None, None).await {
            Err(ApiError::ServiceUnavailable { .. }) => {}
            _ => panic!("feeds switched off must report unavailable"),
        }
    }
}
