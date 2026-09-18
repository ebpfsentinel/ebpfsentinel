use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use domain::alert::mitre;
use serde::Serialize;
use utoipa::ToSchema;

use super::error::ErrorBody;
use super::state::AppState;

/// MITRE ATT&CK coverage response.
#[derive(Serialize, ToSchema)]
pub struct MitreCoverageResponse {
    /// ATT&CK framework version.
    pub attack_version: String,
    /// Total number of covered techniques (for active components).
    pub total_techniques: usize,
    /// Covered techniques grouped by component.
    pub techniques: Vec<TechniqueEntry>,
    /// Coverage summary per tactic.
    pub by_tactic: Vec<TacticSummary>,
}

/// A single technique in the coverage matrix.
#[derive(Serialize, ToSchema)]
pub struct TechniqueEntry {
    pub component: String,
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: String,
    pub description: String,
}

/// Per-tactic summary.
#[derive(Serialize, ToSchema)]
pub struct TacticSummary {
    pub tactic: String,
    pub covered_techniques: usize,
    pub components: Vec<String>,
}

/// The components whose mappings this agent can actually raise.
///
/// A service that is configured but switched off raises nothing, so counting
/// it would report coverage the agent does not have; a service that is running
/// and was never asked about would leave the matrix short of what it does
/// cover. Both readings are taken from the service's own `enabled` flag rather
/// than from whether it was built.
async fn active_components(state: &AppState) -> Vec<&'static str> {
    // The DNS mappings are raised by the blocklist and by domain reputation,
    // and both are built only where DNS intelligence is turned on.
    let running = [
        ("firewall", state.firewall_service.read().await.enabled()),
        ("ips", state.ips_service.load().enabled()),
        ("ratelimit", state.ratelimit_service.read().await.enabled()),
        ("l7", state.l7_service.load().enabled()),
        ("threatintel", state.threatintel_service.load().enabled()),
        (
            "ids",
            state
                .ids_service
                .as_ref()
                .is_some_and(|s| s.load().enabled()),
        ),
        (
            "dlp",
            state
                .dlp_service
                .as_ref()
                .is_some_and(|s| s.load().enabled()),
        ),
        (
            "ddos",
            state
                .ddos_service
                .as_ref()
                .is_some_and(|s| s.load().enabled()),
        ),
        (
            "dns",
            state.dns_blocklist_service.is_some() || state.domain_reputation_service.is_some(),
        ),
    ];

    running
        .into_iter()
        .filter_map(|(component, active)| active.then_some(component))
        .collect()
}

/// Every component this handler can report, running or not.
///
/// A word here that the mapping is not keyed on filters the matrix down to
/// nothing without saying so, which is what the test beside it asserts against.
#[cfg(test)]
const REPORTABLE_COMPONENTS: [&str; 9] = [
    "firewall",
    "ips",
    "ratelimit",
    "l7",
    "threatintel",
    "ids",
    "dlp",
    "ddos",
    "dns",
];

/// `GET /api/v1/mitre/coverage` - MITRE ATT&CK coverage matrix.
#[utoipa::path(
    get, path = "/api/v1/mitre/coverage",
    tag = "MITRE ATT&CK",
    responses(
        (status = 200, description = "Coverage matrix of covered ATT&CK techniques", body = MitreCoverageResponse),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn mitre_coverage(State(state): State<Arc<AppState>>) -> Json<MitreCoverageResponse> {
    let active = active_components(&state).await;
    let report = mitre::coverage_report(&active);

    let techniques = report
        .techniques
        .into_iter()
        .map(|t| TechniqueEntry {
            component: t.component,
            technique_id: t.technique_id,
            technique_name: t.technique_name,
            tactic: t.tactic,
            description: t.description,
        })
        .collect();

    let by_tactic = report
        .by_tactic
        .into_iter()
        .map(|t| TacticSummary {
            tactic: t.tactic,
            covered_techniques: t.covered_techniques,
            components: t.components,
        })
        .collect();

    Json(MitreCoverageResponse {
        attack_version: report.attack_version,
        total_techniques: report.total_techniques,
        techniques,
        by_tactic,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;

    use adapters::metrics::AgentMetrics;
    use application::audit_service_impl::AuditAppService;
    use application::ddos_service_impl::DdosAppService;
    use application::firewall_service_impl::FirewallAppService;
    use application::ids_service_impl::IdsAppService;
    use application::ips_service_impl::IpsAppService;
    use application::l7_service_impl::L7AppService;
    use application::ratelimit_service_impl::RateLimitAppService;
    use application::threatintel_service_impl::ThreatIntelAppService;
    use domain::audit::entity::AuditEntry;
    use domain::audit::error::AuditError;
    use domain::ddos::engine::DdosEngine;
    use domain::firewall::engine::FirewallEngine;
    use domain::ids::engine::IdsEngine;
    use domain::ips::engine::IpsEngine;
    use domain::l7::engine::L7Engine;
    use domain::ratelimit::engine::RateLimitEngine;
    use domain::threatintel::engine::ThreatIntelEngine;
    use ports::secondary::audit_sink::AuditSink;
    use ports::secondary::metrics_port::MetricsPort;
    use ports::test_utils::NoopMetrics;

    use super::*;

    struct NoopSink;
    impl AuditSink for NoopSink {
        fn write_entry(&self, _entry: &AuditEntry) -> Result<(), AuditError> {
            Ok(())
        }
    }

    /// Every always-present service switched off, and nothing optional wired.
    fn quiet_state() -> AppState {
        let noop: Arc<dyn MetricsPort> = Arc::new(NoopMetrics);
        let mut fw_svc = FirewallAppService::new(FirewallEngine::new(), None, Arc::clone(&noop));
        fw_svc.set_enabled(false);
        let mut ips_svc = IpsAppService::new(IpsEngine::default(), Arc::clone(&noop));
        ips_svc.set_enabled(false);
        let mut l7_svc = L7AppService::new(L7Engine::new(), Arc::clone(&noop));
        l7_svc.set_enabled(false);
        let mut rl_svc = RateLimitAppService::new(RateLimitEngine::new(), Arc::clone(&noop));
        rl_svc.set_enabled(false);
        let mut ti_svc = ThreatIntelAppService::new(
            ThreatIntelEngine::new(1_000_000),
            Arc::clone(&noop),
            vec![],
        );
        ti_svc.set_enabled(false);
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

    fn ids_service(enabled: bool) -> Arc<arc_swap::ArcSwap<IdsAppService>> {
        let noop: Arc<dyn MetricsPort> = Arc::new(NoopMetrics);
        let mut svc = IdsAppService::new(IdsEngine::new(), None, noop);
        svc.set_enabled(enabled);
        Arc::new(arc_swap::ArcSwap::from_pointee(svc))
    }

    fn ddos_service(enabled: bool) -> Arc<arc_swap::ArcSwap<DdosAppService>> {
        let noop: Arc<dyn MetricsPort> = Arc::new(NoopMetrics);
        let mut svc = DdosAppService::new(DdosEngine::default(), noop);
        svc.set_enabled(enabled);
        Arc::new(arc_swap::ArcSwap::from_pointee(svc))
    }

    #[tokio::test]
    async fn an_agent_running_nothing_covers_nothing() {
        let state = quiet_state();

        assert!(active_components(&state).await.is_empty());
    }

    /// The matrix is what the agent can raise, and a service that is switched
    /// off raises none of its mappings.
    #[tokio::test]
    async fn a_service_that_is_switched_off_is_not_counted() {
        let state = quiet_state().with_ids_service(ids_service(false));

        assert!(!active_components(&state).await.contains(&"ids"));
    }

    #[tokio::test]
    async fn every_service_that_is_running_is_counted() {
        let state = quiet_state()
            .with_ids_service(ids_service(true))
            .with_ddos_service(ddos_service(true));
        state.firewall_service.write().await.set_enabled(true);

        let active = active_components(&state).await;

        assert!(active.contains(&"firewall"));
        assert!(active.contains(&"ids"));
        assert!(active.contains(&"ddos"));
    }

    /// Every word this handler activates has to be a word the mapping knows,
    /// or the filter silently drops it and the matrix reads empty.
    #[test]
    fn the_words_are_the_ones_the_mapping_is_keyed_on() {
        for component in REPORTABLE_COMPONENTS {
            let report = mitre::coverage_report(&[component]);
            assert!(
                report.total_techniques > 0,
                "no mapping is keyed on {component}"
            );
        }
    }

    #[test]
    fn coverage_response_serialization() {
        let resp = MitreCoverageResponse {
            attack_version: "v18".to_string(),
            total_techniques: 2,
            techniques: vec![
                TechniqueEntry {
                    component: "ids".to_string(),
                    technique_id: "T1071".to_string(),
                    technique_name: "Application Layer Protocol".to_string(),
                    tactic: "command-and-control".to_string(),
                    description: "IDS signature match".to_string(),
                },
                TechniqueEntry {
                    component: "dlp".to_string(),
                    technique_id: "T1041".to_string(),
                    technique_name: "Exfiltration Over C2 Channel".to_string(),
                    tactic: "exfiltration".to_string(),
                    description: "DLP match: PCI or generic".to_string(),
                },
            ],
            by_tactic: vec![TacticSummary {
                tactic: "command-and-control".to_string(),
                covered_techniques: 1,
                components: vec!["ids".to_string()],
            }],
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["attack_version"], "v18");
        assert_eq!(json["total_techniques"], 2);
        assert_eq!(json["techniques"].as_array().unwrap().len(), 2);
        assert_eq!(json["techniques"][0]["technique_id"], "T1071");
        assert_eq!(json["by_tactic"][0]["tactic"], "command-and-control");
    }
}
