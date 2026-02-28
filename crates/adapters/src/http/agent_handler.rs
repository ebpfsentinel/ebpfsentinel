use std::sync::Arc;
use std::sync::atomic::Ordering;

use axum::Json;
use axum::extract::State;
use serde::Serialize;
use utoipa::ToSchema;

use super::state::AppState;

#[derive(Serialize, ToSchema)]
pub struct AgentStatusResponse {
    pub version: String,
    pub uptime_seconds: u64,
    pub ebpf_loaded: bool,
    pub rule_count: usize,
    pub firewall_enabled: bool,
    pub firewall_mode: String,
}

/// Returns the current agent status including version, uptime, and eBPF state.
#[utoipa::path(
    get, path = "/api/v1/agent/status",
    tag = "Agent",
    responses(
        (status = 200, description = "Current agent status", body = AgentStatusResponse),
    )
)]
pub async fn agent_status(State(state): State<Arc<AppState>>) -> Json<AgentStatusResponse> {
    let svc = state.firewall_service.read().await;
    let rule_count = svc.rule_count();
    let firewall_mode = svc.mode().as_str().to_string();
    let firewall_enabled = svc.enabled();
    drop(svc);
    Json(AgentStatusResponse {
        version: state.version.to_string(),
        uptime_seconds: state.start_time.elapsed().as_secs(),
        ebpf_loaded: state.ebpf_loaded.load(Ordering::Relaxed),
        rule_count,
        firewall_enabled,
        firewall_mode,
    })
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
    use domain::common::entity::{Protocol, RuleId};
    use domain::firewall::engine::FirewallEngine;
    use domain::firewall::entity::{FirewallAction, FirewallRule, Scope};
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

    #[tokio::test]
    async fn status_response_has_expected_fields() {
        let mut engine = FirewallEngine::new();
        engine
            .add_rule(FirewallRule {
                id: RuleId("fw-001".to_string()),
                priority: 10,
                action: FirewallAction::Deny,
                protocol: Protocol::Any,
                src_ip: None,
                dst_ip: None,
                src_port: None,
                dst_port: None,
                scope: Scope::Global,
                enabled: true,
                vlan_id: None,
                src_alias: None,
                dst_alias: None,
                src_port_alias: None,
                dst_port_alias: None,
                ct_states: None,
                tcp_flags: None,
                icmp_type: None,
                icmp_code: None,
                negate_src: false,
                negate_dst: false,
                dscp_match: None,
                dscp_mark: None,
                max_states: None,
                src_mac: None,
                dst_mac: None,
                schedule: None,
                system: false,
                route_action: None,
            })
            .unwrap();

        let noop: Arc<dyn MetricsPort> = Arc::new(NoopMetrics);
        let svc = FirewallAppService::new(engine, None, Arc::clone(&noop));
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
        let state = Arc::new(AppState::new(
            Arc::new(AgentMetrics::new()),
            Arc::new(AtomicBool::new(true)),
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
        ));

        let Json(resp) = agent_status(State(state)).await;
        assert_eq!(resp.version, env!("CARGO_PKG_VERSION"));
        assert!(resp.ebpf_loaded);
        assert_eq!(resp.rule_count, 1);
        assert!(resp.uptime_seconds < 2);
        assert!(resp.firewall_enabled);
        assert_eq!(resp.firewall_mode, "alert");
    }
}
