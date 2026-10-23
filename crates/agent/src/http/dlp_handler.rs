use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use serde::Serialize;
use utoipa::ToSchema;

use super::error::{ApiError, ErrorBody};
use super::state::AppState;

// ── Response DTOs ─────────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
pub struct DlpStatusResponse {
    pub enabled: bool,
    pub mode: String,
    pub pattern_count: usize,
}

#[derive(Serialize, ToSchema)]
pub struct DlpPatternResponse {
    pub id: String,
    pub name: String,
    /// What the pattern is for, as the configuration file wrote it. Empty
    /// where none was written.
    pub description: String,
    pub regex: String,
    /// `low`, `medium`, `high` or `critical`.
    pub severity: String,
    /// `pci`, `pii`, `credentials` or `custom`.
    pub data_type: String,
    /// `alert` or `block`, this pattern's own. A pattern may block while the
    /// service default alerts, so a listing carrying only the service mode
    /// reads as a set of patterns that all merely report.
    pub mode: String,
    pub enabled: bool,
}

// ── Handlers ──────────────────────────────────────────────────────

/// One pattern, as the listing route answers it.
fn response_for(p: &domain::dlp::entity::DlpPattern) -> DlpPatternResponse {
    DlpPatternResponse {
        id: p.id.0.clone(),
        name: p.name.clone(),
        description: p.description.clone(),
        regex: p.regex.clone(),
        severity: format!("{:?}", p.severity).to_lowercase(),
        data_type: p.data_type.clone(),
        mode: p.mode.as_str().to_string(),
        enabled: p.enabled,
    }
}

/// `GET /api/v1/dlp/status` - DLP status.
#[utoipa::path(
    get, path = "/api/v1/dlp/status",
    tag = "DLP",
    responses((status = 200, description = "DLP status", body = DlpStatusResponse),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn dlp_status(
    State(state): State<Arc<AppState>>,
) -> Result<Json<DlpStatusResponse>, ApiError> {
    let dlp = state.dlp_service.as_ref().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "DLP not enabled".to_string(),
    })?;
    let svc = dlp.load();
    Ok(Json(DlpStatusResponse {
        enabled: svc.enabled(),
        mode: svc.mode().as_str().to_string(),
        pattern_count: svc.pattern_count(),
    }))
}

/// `GET /api/v1/dlp/patterns` - list DLP patterns.
#[utoipa::path(
    get, path = "/api/v1/dlp/patterns",
    tag = "DLP",
    responses((status = 200, description = "DLP patterns", body = Vec<DlpPatternResponse>),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn list_dlp_patterns(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<DlpPatternResponse>>, ApiError> {
    let dlp = state.dlp_service.as_ref().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "DLP not enabled".to_string(),
    })?;
    let svc = dlp.load();
    let patterns: Vec<DlpPatternResponse> = svc.list_patterns().iter().map(response_for).collect();
    Ok(Json(patterns))
}

/// One workload the scope decided on, as the scope route answers it.
#[derive(Serialize, ToSchema)]
pub struct DlpScopeWorkloadResponse {
    /// Absolute cgroup v2 path, where one was resolved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cgroup: Option<String>,
    /// Cgroup id the kernel allow-list carries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cgroup_id: Option<u64>,
    /// Tenant, where one was attributed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pod: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    /// The rule that decided it, by name.
    pub rule: String,
}

/// A rule that matched nothing, and why.
#[derive(Serialize, ToSchema)]
pub struct DlpScopeUnmatchedResponse {
    pub rule: String,
    /// The matchers it carries, as one line.
    pub selector: String,
    /// `include` or `exclude`.
    pub action: String,
    /// Why it matched nothing, in a sentence an operator can act on.
    pub reason: String,
}

/// What the probes are reading right now.
///
/// The effective scope rather than the configured one: it is built from the
/// workloads the resolvers answered for, so an operator verifies the fence
/// instead of trusting the document.
#[derive(Serialize, ToSchema)]
pub struct DlpScopeResponse {
    /// `all` when every task on the node is read, `workloads` when the
    /// kernel allow-list decides.
    pub mode: String,
    /// How many selectors are in force.
    pub selectors: usize,
    /// How many cgroup ids the kernel allow-list carries.
    pub allowed_cgroups: usize,
    /// Whether the probes are armed at all.
    pub enabled: bool,
    pub in_scope: Vec<DlpScopeWorkloadResponse>,
    pub excluded: Vec<DlpScopeWorkloadResponse>,
    pub unmatched: Vec<DlpScopeUnmatchedResponse>,
    /// Workloads seen and named by no rule, counted rather than listed:
    /// on a busy node that list is the node.
    pub unselected: usize,
    /// When the scope was last resolved, seconds since the epoch.
    pub refreshed_unix: u64,
}

fn workload_response(w: &domain::dlp::scope::DlpScopedWorkload) -> DlpScopeWorkloadResponse {
    DlpScopeWorkloadResponse {
        cgroup: w.cgroup.clone(),
        cgroup_id: w.cgroup_id,
        tenant: w.tenant.clone(),
        namespace: w.namespace.clone(),
        pod: w.pod.clone(),
        container: w.container.clone(),
        unit: w.unit.clone(),
        exe: w.exe.clone(),
        rule: w.rule.clone(),
    }
}

fn scope_response(scope: &domain::dlp::scope::EffectiveDlpScope) -> DlpScopeResponse {
    DlpScopeResponse {
        mode: scope.mode.clone(),
        selectors: scope.selectors,
        allowed_cgroups: scope.allowed_cgroups,
        enabled: scope.enabled,
        in_scope: scope.in_scope.iter().map(workload_response).collect(),
        excluded: scope.excluded.iter().map(workload_response).collect(),
        unmatched: scope
            .unmatched
            .iter()
            .map(|u| DlpScopeUnmatchedResponse {
                rule: u.rule.clone(),
                selector: u.selector.clone(),
                action: u.action.clone(),
                reason: u.reason.clone(),
            })
            .collect(),
        unselected: scope.unselected,
        refreshed_unix: scope.refreshed_unix,
    }
}

/// `GET /api/v1/dlp/scope` - which workloads DLP is reading.
#[utoipa::path(
    get, path = "/api/v1/dlp/scope",
    tag = "DLP",
    responses((status = 200, description = "Effective DLP scope", body = DlpScopeResponse),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
        (status = 404, description = "DLP not enabled", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn dlp_scope(
    State(state): State<Arc<AppState>>,
) -> Result<Json<DlpScopeResponse>, ApiError> {
    let dlp = state.dlp_service.as_ref().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "DLP not enabled".to_string(),
    })?;
    let enabled = dlp.load().enabled();

    // No resolver means the node reads every task it has a probe on, which is
    // what `mode: all` configures. Answering with that rather than a 404 is
    // what makes the route usable as a verification: an operator asks the same
    // question on every node and reads the answer, scoped or not.
    let Some(service) = state.dlp_scope_service.load_full() else {
        let mut scope = domain::dlp::scope::EffectiveDlpScope::disabled(now_unix());
        scope.enabled = enabled;
        return Ok(Json(scope_response(&scope)));
    };

    let scope = service.effective_scope().map_err(|e| ApiError::Internal {
        message: e.to_string(),
    })?;
    Ok(Json(scope_response(&scope)))
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use adapters::metrics::AgentMetrics;
    use application::dlp_scope_service::DlpScopeService;
    use domain::common::entity::{DomainMode, RuleId, Severity};
    use domain::common::error::DomainError;
    use domain::dlp::entity::DlpPattern;
    use domain::dlp::scope::{DlpScopeMode, DlpScopePolicy, DlpScopeSelector};
    use ports::secondary::dlp_scope_map_port::DlpScopeMapPort;

    use super::*;

    /// Stands in for the kernel maps, so a route test asserts what the scope
    /// says rather than what a probe loaded.
    struct NoopSink;

    impl ports::secondary::audit_sink::AuditSink for NoopSink {
        fn write_entry(
            &self,
            _entry: &domain::audit::entity::AuditEntry,
        ) -> Result<(), domain::audit::error::AuditError> {
            Ok(())
        }
    }

    struct NoMaps;

    impl DlpScopeMapPort for NoMaps {
        fn publish_scope(&mut self, _scoped: bool, _cgroup_ids: &[u64]) -> Result<(), DomainError> {
            Ok(())
        }
        fn allowed_cgroups(&self) -> usize {
            0
        }
    }

    fn state() -> AppState {
        let noop = Arc::new(AgentMetrics::new());
        let mut dlp = application::dlp_service_impl::DlpAppService::new(
            domain::dlp::engine::DlpEngine::new(),
            Arc::clone(&noop) as Arc<dyn ports::secondary::metrics_port::MetricsPort>,
        );
        dlp.set_enabled(true);
        let (reload_tx, _reload_rx) = tokio::sync::mpsc::channel(1);
        AppState::new(
            Arc::clone(&noop),
            Arc::new(std::sync::atomic::AtomicBool::new(true)),
            Arc::new(tokio::sync::RwLock::new(
                application::firewall_service_impl::FirewallAppService::new(
                    domain::firewall::engine::FirewallEngine::new(),
                    None,
                    Arc::clone(&noop) as Arc<dyn ports::secondary::metrics_port::MetricsPort>,
                ),
            )),
            Arc::new(arc_swap::ArcSwap::from_pointee(
                application::ips_service_impl::IpsAppService::new(
                    domain::ips::engine::IpsEngine::new(domain::ips::entity::IpsPolicy::default()),
                    Arc::clone(&noop) as Arc<dyn ports::secondary::metrics_port::MetricsPort>,
                ),
            )),
            Arc::new(arc_swap::ArcSwap::from_pointee(
                application::l7_service_impl::L7AppService::new(
                    domain::l7::engine::L7Engine::new(),
                    Arc::clone(&noop) as Arc<dyn ports::secondary::metrics_port::MetricsPort>,
                ),
            )),
            Arc::new(tokio::sync::RwLock::new(
                application::ratelimit_service_impl::RateLimitAppService::new(
                    domain::ratelimit::engine::RateLimitEngine::new(),
                    Arc::clone(&noop) as Arc<dyn ports::secondary::metrics_port::MetricsPort>,
                ),
            )),
            Arc::new(arc_swap::ArcSwap::from_pointee(
                application::threatintel_service_impl::ThreatIntelAppService::new(
                    domain::threatintel::engine::ThreatIntelEngine::new(1_000),
                    Arc::clone(&noop) as Arc<dyn ports::secondary::metrics_port::MetricsPort>,
                    vec![],
                ),
            )),
            Arc::new(application::audit_service_impl::AuditAppService::new(
                Arc::new(NoopSink) as Arc<dyn ports::secondary::audit_sink::AuditSink>,
            )),
            Arc::new(tokio::sync::RwLock::new(
                infrastructure::config::AgentConfig::from_yaml("agent:\n  interfaces: [eth0]")
                    .expect("a minimal configuration"),
            )),
            reload_tx,
            Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
        )
        .with_dlp_service(Arc::new(arc_swap::ArcSwap::from_pointee(dlp)))
    }

    fn pattern(mode: DomainMode) -> DlpPattern {
        DlpPattern {
            id: RuleId("dlp-cred-aws".to_string()),
            name: "AWS access key".to_string(),
            regex: "AKIA[0-9A-Z]{16}".to_string(),
            severity: Severity::Critical,
            mode,
            data_type: "credentials".to_string(),
            description: "Long-lived AWS access key identifier".to_string(),
            enabled: true,
        }
    }

    /// A pattern that stops a transfer while the service default only
    /// records one is the difference between a leak reported and a leak
    /// prevented, and the listing is where somebody checks which they have.
    #[test]
    fn a_pattern_carries_the_mode_it_is_enforced_at() {
        let p = pattern(DomainMode::Block);
        let body = serde_json::to_value(response_for(&p)).expect("serialise");

        assert_eq!(body["mode"], "block");
        assert_eq!(
            serde_json::to_value(response_for(&pattern(DomainMode::Alert))).expect("serialise")["mode"],
            "alert"
        );
    }

    /// A node reading every task answers the same question as a scoped one,
    /// because an operator verifying the fence asks it on every node.
    #[tokio::test]
    async fn a_node_with_no_resolver_says_it_reads_everything() {
        let body = dlp_scope(State(Arc::new(state())))
            .await
            .expect("the route answers");

        assert_eq!(body.mode, "all");
        assert!(body.enabled, "the probes are armed, the scope is open");
        assert_eq!(body.allowed_cgroups, 0);
        assert!(body.in_scope.is_empty());
    }

    /// The route reports the rule that matched nothing, which is the whole
    /// reason it exists: a typo in a pod name is DLP silently off.
    #[tokio::test]
    async fn a_scoped_node_reports_the_rule_that_matched_nothing() {
        let selector = DlpScopeSelector {
            name: Some("payments".to_string()),
            pod: Some("api-typo".to_string()),
            ..DlpScopeSelector::default()
        };
        let policy = DlpScopePolicy::from_selectors(vec![selector]).expect("a valid policy");
        let scope = Arc::new(DlpScopeService::new(
            DlpScopeMode::Workloads,
            policy,
            Vec::new(),
        ));
        scope.install_maps(Box::new(NoMaps)).expect("install");
        scope.reconcile().await.expect("reconcile");

        let state = Arc::new(state());
        state.install_dlp_scope_service(scope);
        let body = dlp_scope(State(state)).await.expect("the route answers");

        assert_eq!(body.mode, "workloads");
        assert_eq!(body.selectors, 1);
        assert!(body.in_scope.is_empty());
        assert_eq!(body.unmatched.len(), 1);
        assert_eq!(body.unmatched[0].rule, "payments");
        assert_eq!(body.unmatched[0].action, "include");
    }

    #[test]
    fn a_pattern_carries_what_it_was_written_for() {
        let body =
            serde_json::to_value(response_for(&pattern(DomainMode::Alert))).expect("serialise");

        assert_eq!(body["description"], "Long-lived AWS access key identifier");
        assert_eq!(body["data_type"], "credentials");
        assert_eq!(body["severity"], "critical");
    }
}
