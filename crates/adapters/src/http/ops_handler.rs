use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde::Serialize;
use utoipa::ToSchema;

use super::state::AppState;

// ── Response types ────────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
pub struct ReloadResponse {
    pub status: String,
    pub message: String,
}

#[derive(Serialize, ToSchema)]
pub struct ProgramStatus {
    pub name: String,
    pub loaded: bool,
}

#[derive(Serialize, ToSchema)]
pub struct EbpfStatusResponse {
    pub programs: Vec<ProgramStatus>,
}

// ── Handlers ──────────────────────────────────────────────────────

/// Trigger a configuration reload via the API.
#[utoipa::path(
    post, path = "/api/v1/config/reload",
    tag = "Operations",
    responses(
        (status = 200, description = "Reload triggered successfully", body = ReloadResponse),
        (status = 500, description = "Failed to trigger reload", body = ReloadResponse),
    )
)]
pub async fn reload_config(
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<ReloadResponse>) {
    match state.reload_trigger.try_send(()) {
        Ok(()) => (
            StatusCode::OK,
            Json(ReloadResponse {
                status: "ok".to_string(),
                message: "configuration reload triggered".to_string(),
            }),
        ),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ReloadResponse {
                status: "error".to_string(),
                message: "reload already in progress or channel unavailable".to_string(),
            }),
        ),
    }
}

/// Return the current (sanitized) agent configuration.
#[utoipa::path(
    get, path = "/api/v1/config",
    tag = "Operations",
    responses(
        (status = 200, description = "Current sanitized configuration"),
    )
)]
pub async fn get_config(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let config = state.config.read().await;
    let sanitized = config.sanitized();
    // Serialize to JSON value to avoid exposing the Rust struct directly
    let value = serde_json::to_value(&sanitized).unwrap_or_default();
    Json(value)
}

/// Return the load status of each eBPF program.
#[utoipa::path(
    get, path = "/api/v1/ebpf/status",
    tag = "Operations",
    responses(
        (status = 200, description = "eBPF program status", body = EbpfStatusResponse),
    )
)]
pub async fn get_ebpf_status(State(state): State<Arc<AppState>>) -> Json<EbpfStatusResponse> {
    let status_map = state.ebpf_program_status.read().await;
    let programs: Vec<ProgramStatus> = status_map
        .iter()
        .map(|(name, loaded)| ProgramStatus {
            name: name.clone(),
            loaded: *loaded,
        })
        .collect();
    Json(EbpfStatusResponse { programs })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
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
    use infrastructure::config::AgentConfig;
    use infrastructure::metrics::AgentMetrics;
    use ports::secondary::audit_sink::AuditSink;
    use ports::secondary::metrics_port::MetricsPort;
    use ports::test_utils::NoopMetrics;
    use tokio::sync::RwLock;

    struct NoopSink;
    impl AuditSink for NoopSink {
        fn write_entry(&self, _entry: &AuditEntry) -> Result<(), AuditError> {
            Ok(())
        }
    }

    fn make_state() -> (Arc<AppState>, tokio::sync::mpsc::Receiver<()>) {
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
        let (reload_tx, reload_rx) = tokio::sync::mpsc::channel(1);
        let state = Arc::new(AppState::new(
            Arc::new(AgentMetrics::new()),
            Arc::new(AtomicBool::new(false)),
            Arc::new(RwLock::new(fw_svc)),
            Arc::new(RwLock::new(ips_svc)),
            Arc::new(RwLock::new(l7_svc)),
            Arc::new(RwLock::new(rl_svc)),
            Arc::new(RwLock::new(ti_svc)),
            Arc::new(RwLock::new(audit_svc)),
            Arc::new(RwLock::new(
                AgentConfig::from_yaml("agent:\n  interfaces: [eth0]").unwrap(),
            )),
            reload_tx,
            Arc::new(RwLock::new(HashMap::new())),
        ));
        (state, reload_rx)
    }

    #[tokio::test]
    async fn reload_config_returns_ok() {
        let (state, _rx) = make_state();
        let (status, Json(resp)) = reload_config(State(state)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(resp.status, "ok");
    }

    #[tokio::test]
    async fn reload_config_returns_error_when_channel_full() {
        let (state, _rx) = make_state();
        // Fill the channel (capacity 1)
        let _ = state.reload_trigger.try_send(());
        let (status, Json(resp)) = reload_config(State(state)).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(resp.status, "error");
    }

    #[tokio::test]
    async fn get_config_returns_sanitized_json() {
        let (state, _rx) = make_state();
        let Json(value) = get_config(State(state)).await;
        assert!(value.is_object());
        // Should have the "agent" key
        assert!(value.get("agent").is_some());
    }

    #[tokio::test]
    async fn get_config_masks_api_keys() {
        let yaml = "agent:\n  interfaces: [eth0]\nauth:\n  enabled: true\n  api_keys:\n    - name: test\n      key: secret-value\n      role: admin";
        let config = AgentConfig::from_yaml(yaml).unwrap();
        let (state, _rx) = make_state();
        *state.config.write().await = config;

        let Json(value) = get_config(State(state)).await;
        let keys = value["auth"]["api_keys"].as_array().unwrap();
        assert_eq!(keys[0]["key"].as_str().unwrap(), "***");
    }

    #[tokio::test]
    async fn get_ebpf_status_empty() {
        let (state, _rx) = make_state();
        let Json(resp) = get_ebpf_status(State(state)).await;
        assert!(resp.programs.is_empty());
    }

    #[tokio::test]
    async fn get_ebpf_status_with_programs() {
        let (state, _rx) = make_state();
        {
            let mut status = state.ebpf_program_status.write().await;
            status.insert("xdp_firewall".to_string(), true);
            status.insert("tc_ids".to_string(), false);
        }

        let Json(resp) = get_ebpf_status(State(state)).await;
        assert_eq!(resp.programs.len(), 2);

        let fw = resp.programs.iter().find(|p| p.name == "xdp_firewall");
        assert!(fw.is_some());
        assert!(fw.unwrap().loaded);

        let ids = resp.programs.iter().find(|p| p.name == "tc_ids");
        assert!(ids.is_some());
        assert!(!ids.unwrap().loaded);
    }
}
