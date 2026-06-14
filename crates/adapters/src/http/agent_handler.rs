use std::sync::Arc;
use std::sync::atomic::Ordering;

use axum::Json;
use axum::extract::State;
use serde::Serialize;
use utoipa::ToSchema;

use super::error::ErrorBody;
use super::state::AppState;

/// Operator-managed metadata advertised to the dashboard, plus the
/// minimum identity fields needed to identify the agent uniquely.
///
/// Read-only view of the agent's `management` config block; both fields
/// are hot-reloadable via the existing config reload mechanism.
#[derive(Serialize, ToSchema)]
pub struct AgentIdentityResponse {
    /// Build version of the running agent (`CARGO_PKG_VERSION`).
    pub version: String,
    /// `gethostname()` at startup; surfaces the host running the agent.
    pub hostname: String,
    /// Process uptime in whole seconds.
    pub uptime_seconds: u64,
    /// `true` when the agent's configuration is owned by the Kubernetes
    /// operator (CRD-driven). The dashboard locks its config-edit UI on
    /// agents reporting `true` to prevent two-way drift.
    pub operator_managed: bool,
    /// Optional URL the operator exposes (typically a Kubernetes-native
    /// UI). The dashboard deep-links to this URL from the
    /// "operator-managed" badge.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operator_endpoint: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct AgentStatusResponse {
    /// Coarse lifecycle state: `running` once eBPF programs are attached,
    /// `degraded` while operating without them (userspace-only fallback).
    pub status: String,
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
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn agent_status(State(state): State<Arc<AppState>>) -> Json<AgentStatusResponse> {
    let svc = state.firewall_service.read().await;
    let rule_count = svc.rule_count();
    let firewall_mode = svc.mode().as_str().to_string();
    let firewall_enabled = svc.enabled();
    drop(svc);
    let ebpf_loaded = state.ebpf_loaded.load(Ordering::Relaxed);
    Json(AgentStatusResponse {
        status: if ebpf_loaded { "running" } else { "degraded" }.to_string(),
        version: state.version.to_string(),
        uptime_seconds: state.start_time.elapsed().as_secs(),
        ebpf_loaded,
        rule_count,
        firewall_enabled,
        firewall_mode,
    })
}

/// Returns the agent's identity metadata, including the operator-managed
/// flag and the optional operator UI deep-link URL.
///
/// Hot-reloadable: a config reload that toggles `management.operator_managed`
/// or updates `management.operator_endpoint` is reflected on the next
/// request without restart.
#[utoipa::path(
    get, path = "/api/v1/agent/identity",
    tag = "Agent",
    responses(
        (status = 200, description = "Agent identity metadata", body = AgentIdentityResponse),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn agent_identity(State(state): State<Arc<AppState>>) -> Json<AgentIdentityResponse> {
    let cfg = state.config.read().await;
    let operator_managed = cfg.management.operator_managed;
    let operator_endpoint = cfg.management.operator_endpoint.clone();
    drop(cfg);
    Json(AgentIdentityResponse {
        version: state.version.to_string(),
        hostname: hostname(),
        uptime_seconds: state.start_time.elapsed().as_secs(),
        operator_managed,
        operator_endpoint,
    })
}

/// Read the system hostname at request time. Falls back to `"unknown"`
/// if the syscall fails (e.g. in stripped containers without
/// `gethostname` support).
fn hostname() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "unknown".to_string())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    use crate::metrics::AgentMetrics;
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
                src_mac_alias: None,
                dst_mac_alias: None,
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
                group_mask: 0,
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
        ));

        let Json(resp) = agent_status(State(state)).await;
        assert_eq!(resp.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(resp.status, "running");
        assert!(resp.ebpf_loaded);
        assert_eq!(resp.rule_count, 1);
        assert!(resp.uptime_seconds < 2);
        assert!(resp.firewall_enabled);
        assert_eq!(resp.firewall_mode, "alert");
    }
}
