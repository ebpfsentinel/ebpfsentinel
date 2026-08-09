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
    /// Helpers the startup probe found missing, one sentence each. Empty both
    /// when the kernel offers everything and when the probe could not run -
    /// `/api/v1/ebpf/kernel-features` distinguishes the two.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub kernel_helpers_missing: Vec<String>,
}

/// Helpers the startup probe reported missing, empty when it never ran.
///
/// A program refused by the helper gate can be an optional one, in which case
/// the agent stays up and `ebpf_loaded` stays true. Readiness has to look at
/// the gap itself, or a host missing a helper would report ready while
/// silently running without that program.
fn missing_kernel_helpers() -> Vec<String> {
    adapters::ebpf::cached_kernel_helpers().map_or_else(Vec::new, |report| {
        report
            .missing_required
            .iter()
            .map(ToString::to_string)
            .collect()
    })
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
    let (code, body) = readiness(loaded, missing_kernel_helpers());
    (code, Json(body))
}

/// Decide readiness from the two inputs, so the verdict is testable without a
/// kernel and without reaching into the process-wide probe cache.
fn readiness(loaded: bool, missing: Vec<String>) -> (StatusCode, ReadyResponse) {
    let ready = loaded && missing.is_empty();
    let code = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        code,
        ReadyResponse {
            status: if ready { "ready" } else { "not_ready" },
            ebpf_loaded: loaded,
            kernel_helpers_missing: missing,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
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

    #[test]
    fn a_missing_helper_holds_readiness_back_even_when_programs_loaded() {
        // The refused program can be an optional one, so `ebpf_loaded` alone
        // would call this host ready while a feature is silently absent.
        let (code, body) = readiness(
            true,
            vec![
                "tc-qos needs bpf_skb_ecn_set_ce but this kernel does not support it for \
                  sched_cls programs"
                    .to_string(),
            ],
        );
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body.status, "not_ready");
        assert!(body.ebpf_loaded);
        assert_eq!(body.kernel_helpers_missing.len(), 1);
    }

    #[test]
    fn an_unprobed_kernel_does_not_hold_readiness_back() {
        // No probe result is not a negative result. The token-only load path
        // cannot probe at all, and every host on it must still reach ready.
        let (code, body) = readiness(true, Vec::new());
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body.status, "ready");
        assert!(body.kernel_helpers_missing.is_empty());
    }
}
