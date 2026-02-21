use std::sync::Arc;
use std::sync::atomic::Ordering;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Serialize;
use utoipa::ToSchema;

use super::state::AppState;

#[derive(Serialize, ToSchema)]
pub struct HealthResponse {
    /// Always `"ok"`.
    #[schema(value_type = String)]
    pub status: &'static str,
}

#[derive(Serialize, ToSchema)]
pub struct ReadyResponse {
    /// `"ready"` or `"not_ready"`.
    #[schema(value_type = String)]
    pub status: &'static str,
    /// Whether eBPF programs are successfully loaded.
    pub ebpf_loaded: bool,
}

/// Liveness probe — always returns 200 if the process is running.
#[utoipa::path(
    get, path = "/healthz",
    tag = "Health",
    responses(
        (status = 200, description = "Agent is alive", body = HealthResponse),
    )
)]
pub async fn healthz() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

/// Readiness probe — returns 200 when eBPF programs are loaded, 503 otherwise.
#[utoipa::path(
    get, path = "/readyz",
    tag = "Health",
    responses(
        (status = 200, description = "Agent is ready", body = ReadyResponse),
        (status = 503, description = "Agent is not ready", body = ReadyResponse),
    )
)]
pub async fn readyz(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let loaded = state.ebpf_loaded.load(Ordering::Relaxed);
    let status = if loaded { "ready" } else { "not_ready" };
    let code = if loaded {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        code,
        Json(ReadyResponse {
            status,
            ebpf_loaded: loaded,
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

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
    use infrastructure::metrics::AgentMetrics;
    use ports::secondary::audit_sink::AuditSink;
    use ports::secondary::metrics_port::MetricsPort;
    use ports::test_utils::NoopMetrics;

    struct NoopSink;
    impl AuditSink for NoopSink {
        fn write_entry(&self, _entry: &AuditEntry) -> Result<(), AuditError> {
            Ok(())
        }
    }

    fn test_state(ebpf_loaded: bool) -> Arc<AppState> {
        let noop: Arc<dyn MetricsPort> = Arc::new(NoopMetrics);
        let svc = FirewallAppService::new(FirewallEngine::new(), None, Arc::clone(&noop));
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
        Arc::new(AppState::new(
            Arc::new(AgentMetrics::new()),
            Arc::new(AtomicBool::new(ebpf_loaded)),
            Arc::new(tokio::sync::RwLock::new(svc)),
            Arc::new(tokio::sync::RwLock::new(ips_svc)),
            Arc::new(tokio::sync::RwLock::new(l7_svc)),
            Arc::new(tokio::sync::RwLock::new(rl_svc)),
            Arc::new(tokio::sync::RwLock::new(ti_svc)),
            Arc::new(tokio::sync::RwLock::new(audit_svc)),
            Arc::new(tokio::sync::RwLock::new(
                infrastructure::config::AgentConfig::from_yaml("agent:\n  interfaces: [eth0]")
                    .unwrap(),
            )),
            reload_tx,
            Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
        ))
    }

    #[tokio::test]
    async fn healthz_always_returns_ok() {
        let Json(resp) = healthz().await;
        assert_eq!(resp.status, "ok");
    }

    #[tokio::test]
    async fn readyz_returns_ready_when_loaded() {
        let state = test_state(true);
        let resp = readyz(State(state)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn readyz_returns_unavailable_when_not_loaded() {
        let state = test_state(false);
        let resp = readyz(State(state)).await.into_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
