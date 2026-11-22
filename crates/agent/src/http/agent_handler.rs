use std::sync::Arc;
use std::sync::atomic::Ordering;

use axum::extract::State;
use axum::{Extension, Json};
use domain::audit::entity::AuditAction;
use domain::auth::entity::JwtClaims;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::error::{ApiError, ErrorBody};
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

/// Where a metadata enricher ended up, as the agent decided it at startup.
///
/// The deployment matrix claims container enrichment per mode; this is the
/// same claim answered by the running agent, so the two can be compared on a
/// node instead of taken on trust.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum EnricherState {
    /// The agent has not finished starting, so it has decided nothing yet.
    Starting,
    /// Running: alerts carry the workload's name, image and labels.
    On,
    /// Enabled, but the runtime socket is not there. Alerts keep the
    /// container id the resolver reads and lose everything named.
    OffNoSocket,
    /// Enabled, but no Kubernetes API is reachable from this process.
    OffNotInCluster,
    /// Enabled, reachable, and the client could not be built.
    OffUnavailable,
    /// This build does not carry the enricher at all.
    OffNotBuilt,
    /// Turned off in the configuration.
    OffByConfiguration,
}

/// What this agent can say about the containers it sees.
///
/// Every field is a verdict rather than a setting: the procfs actually being
/// read, whether it is the host's, and what each enricher decided.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct ContainerCoverage {
    /// The procfs every container and DLP lookup is rooted on.
    pub proc_root: String,
    /// `proc_root` is a mounted host procfs rather than this process's own,
    /// which is what covers a neighbouring container without sharing the
    /// node's pid namespace.
    pub host_proc: bool,
    /// The cgroup-id resolver is running, so an alert carries a container id.
    pub resolver: bool,
    pub docker: EnricherState,
    pub podman: EnricherState,
    /// LXC containers: Proxmox CTs, Incus instances and plain LXC.
    pub lxc: EnricherState,
    pub kubernetes: EnricherState,
    /// Each Podman runtime the agent has gone to, root's and each user's,
    /// and what it found there. A rootless container whose owner's runtime
    /// is not reachable stays unnamed, and this is where that is said.
    pub podman_runtimes: Vec<PodmanRuntimeReport>,
}

/// One Podman runtime and whether the agent reached it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct PodmanRuntimeReport {
    /// The user whose runtime this is, absent for root's.
    pub uid: Option<u32>,
    pub socket: String,
    pub reach: PodmanReach,
}

/// What the agent found at a Podman socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PodmanReach {
    /// Answered: this owner's containers are named.
    Reachable,
    /// No socket there: the user's `podman.socket` unit is not enabled, or
    /// the directory is not mounted into the agent.
    NoSocket,
    /// The socket refused the agent, which a user's socket does to anybody
    /// but root and that user.
    Refused,
    /// The socket did not answer in time.
    Unavailable,
    /// Rootless runtimes are turned off in the configuration.
    RootlessOff,
    /// No socket answered and the owner's container store is read instead:
    /// containers are named with their image, their labels and their state
    /// from Podman's database, with their image alone from an older store.
    Store,
}

impl From<adapters::container::PodmanRuntime> for PodmanRuntimeReport {
    fn from(runtime: adapters::container::PodmanRuntime) -> Self {
        use adapters::container::{PodmanOwner, PodmanReach as Found};
        Self {
            uid: match runtime.owner {
                PodmanOwner::Root => None,
                PodmanOwner::User(uid) => Some(uid),
            },
            socket: runtime.socket,
            reach: match runtime.reach {
                Found::Reachable => PodmanReach::Reachable,
                Found::NoSocket => PodmanReach::NoSocket,
                Found::Refused => PodmanReach::Refused,
                Found::Unavailable => PodmanReach::Unavailable,
                Found::RootlessOff => PodmanReach::RootlessOff,
                Found::Store => PodmanReach::Store,
            },
        }
    }
}

impl ContainerCoverage {
    /// What the agent reports before it has built its enrichers.
    #[must_use]
    pub fn starting() -> Self {
        Self {
            proc_root: "/proc".to_string(),
            host_proc: false,
            resolver: false,
            docker: EnricherState::Starting,
            podman: EnricherState::Starting,
            lxc: EnricherState::Starting,
            kubernetes: EnricherState::Starting,
            podman_runtimes: Vec::new(),
        }
    }
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
    /// What the agent sees of the containers on this node.
    pub container_coverage: ContainerCoverage,
    /// Which document is running and what changed the policy since.
    pub config: ConfigProvenanceDto,
}

/// Which configuration document the agent is running, and the policy writes
/// its API accepted outside that document since the process started.
///
/// Whoever wrote the document compares `document_sha256` with the digest of
/// what they wrote: a difference is a node still on an older document. A
/// non-zero `runtime_writes` is a node whose policy was changed by hand; a
/// reload does not clear it, a restart does.
#[derive(Debug, Serialize, ToSchema)]
pub struct ConfigProvenanceDto {
    /// Lowercase hex SHA-256 of the document's bytes as last loaded.
    pub document_sha256: Option<String>,
    /// When that document was loaded, in seconds since the Unix epoch.
    pub loaded_at: Option<u64>,
    /// Policy writes accepted through the API since the process started.
    pub runtime_writes: u64,
    /// The last of those writes.
    pub last_runtime_write: Option<RuntimeWriteDto>,
}

/// One policy write accepted outside the document.
#[derive(Debug, Serialize, ToSchema)]
pub struct RuntimeWriteDto {
    pub method: String,
    pub path: String,
    /// Seconds since the Unix epoch.
    pub at: u64,
}

impl From<infrastructure::config::provenance::ConfigProvenance> for ConfigProvenanceDto {
    fn from(record: infrastructure::config::provenance::ConfigProvenance) -> Self {
        Self {
            document_sha256: record.document_sha256,
            loaded_at: record.loaded_at,
            runtime_writes: record.runtime_writes,
            last_runtime_write: record.last_runtime_write.map(|write| RuntimeWriteDto {
                method: write.method,
                path: write.path,
                at: write.at,
            }),
        }
    }
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
        container_coverage: {
            let mut coverage = state.container_coverage.load().as_ref().clone();
            // Read live: a user's runtime is gone to the first time one of
            // their containers is seen, long after startup decided the rest.
            if let Some(podman) = state.podman_enricher.load().as_ref() {
                coverage.podman_runtimes = podman.runtimes().into_iter().map(Into::into).collect();
            }
            coverage
        },
        config: infrastructure::config::provenance::provenance().into(),
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

/// Why the agent is being stopped, for the record.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct StopRequest {
    /// Free text kept in the run record, the audit trail and the next
    /// start's log line.
    #[serde(default)]
    pub reason: Option<String>,
}

/// What the agent answers to a stop.
#[derive(Debug, Serialize, ToSchema)]
pub struct StopResponse {
    /// `stopping` under a service unit: the answer leaves before the shutdown
    /// starts. `armed` in a container, whose runtime restarts the agent on
    /// any exit: the agent keeps running, and the runtime's own stop inside
    /// the window is recorded as this one.
    pub status: String,
    /// The exit status the agent ends with, which its unit treats as final;
    /// absent when the stop is armed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// How long an armed stop waits for the runtime's stop; absent when the
    /// agent is stopping.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window_seconds: Option<u64>,
}

impl From<crate::lifecycle::StopOutcome> for StopResponse {
    fn from(outcome: crate::lifecycle::StopOutcome) -> Self {
        match outcome {
            crate::lifecycle::StopOutcome::Stopping => Self {
                status: "stopping".to_string(),
                exit_code: Some(domain::lifecycle::STOP_EXIT_CODE),
                window_seconds: None,
            },
            crate::lifecycle::StopOutcome::Armed { window } => Self {
                status: "armed".to_string(),
                exit_code: None,
                window_seconds: Some(window.as_secs()),
            },
        }
    }
}

/// Stop the agent and keep it stopped.
///
/// The documented way to stop a host agent: the request is recorded under
/// the caller's name with its reason, the agent shuts down in order and exits
/// with status `79`, which its service unit does not restart. In a container,
/// whose runtime restarts on any exit status, the stop is armed instead: the
/// agent keeps running and the runtime's own stop, inside the window, is
/// recorded as this one. A stop by any other means is raised as an alert at
/// the next start.
#[utoipa::path(
    post, path = "/api/v1/agent/stop",
    tag = "Operations",
    request_body(content = StopRequest, description = "Why the agent is stopped", content_type = "application/json"),
    responses(
        (status = 202, description = "The agent is stopping, or the stop is armed for the container runtime's", body = StopResponse),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
        (status = 503, description = "This agent cannot be stopped through the API", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn stop_agent(
    State(state): State<Arc<AppState>>,
    claims: Option<Extension<JwtClaims>>,
    body: Option<Json<StopRequest>>,
) -> Result<(axum::http::StatusCode, Json<StopResponse>), ApiError> {
    let Some(stop) = state.local_stop.as_ref() else {
        return Err(ApiError::ServiceUnavailable {
            message: "this agent is not stopped through the API".to_string(),
        });
    };
    let via = claims.map_or_else(|| "local".to_string(), |Extension(c)| c.sub);
    let reason = body
        .and_then(|Json(b)| b.reason)
        .map(|r| domain::lifecycle::clean_stop_text(&r))
        .filter(|r| !r.is_empty());
    state.audit_service.record_config_change(
        AuditAction::AgentStopped,
        &format!(
            "stopped by {via}{}",
            reason
                .as_deref()
                .map_or_else(String::new, |r| format!(": {r}"))
        ),
    );
    let outcome = stop.request(Some(&via), reason.as_deref());
    Ok((axum::http::StatusCode::ACCEPTED, Json(outcome.into())))
}

/// Read the system hostname at request time. Falls back to `"unknown"`
/// if the syscall fails (e.g. in stripped containers without
/// `gethostname` support). Also what the syslog and CEF flow sinks put in
/// their header, so the name a SIEM sees and the name this route reports are
/// read the same way.
pub(crate) fn hostname() -> String {
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

    use adapters::metrics::AgentMetrics;
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

    fn state_with_one_rule() -> Arc<AppState> {
        let mut engine = FirewallEngine::new();
        engine
            .add_rule(FirewallRule {
                mode: domain::firewall::entity::RuleMode::Enforce,
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
                group_mask: 0,
                tenant_id: 0,
                workload: None,
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
        Arc::new(AppState::new(
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
        ))
    }

    #[tokio::test]
    async fn stop_is_unavailable_where_nothing_wired_it() {
        let state = state_with_one_rule();
        let refused = stop_agent(State(state), None, None).await;
        assert!(matches!(refused, Err(ApiError::ServiceUnavailable { .. })));
    }

    #[tokio::test]
    async fn stop_records_the_caller_and_ends_the_run() {
        let dir = tempfile::tempdir().expect("dir");
        let (journal, _) =
            adapters::lifecycle::RunJournal::open(dir.path().join("run.json"), "boot-1");
        let journal = Arc::new(journal);
        let cancel = tokio_util::sync::CancellationToken::new();
        let state = Arc::into_inner(state_with_one_rule())
            .expect("sole owner")
            .with_local_stop(Arc::new(
                crate::lifecycle::LocalStop::new(Arc::clone(&journal), cancel.clone())
                    .under_unit(true),
            ));
        let claims: JwtClaims =
            serde_json::from_value(serde_json::json!({ "sub": "ops", "exp": 0 })).expect("claims");
        let (status, Json(resp)) = stop_agent(
            State(Arc::new(state)),
            Some(Extension(claims)),
            Some(Json(StopRequest {
                reason: Some("kernel upgrade".to_string()),
            })),
        )
        .await
        .expect("accepted");
        assert_eq!(status, axum::http::StatusCode::ACCEPTED);
        assert_eq!(resp.exit_code, Some(79));
        let end = journal.ended().expect("recorded");
        assert_eq!(end.how, domain::lifecycle::EndCause::Command);
        assert_eq!(end.requested_by.as_deref(), Some("ops"));
        assert_eq!(end.reason.as_deref(), Some("kernel upgrade"));
        assert!(crate::lifecycle::stop_commanded());
        tokio::time::timeout(std::time::Duration::from_secs(5), cancel.cancelled())
            .await
            .expect("the run is ended once the answer left");
    }

    #[tokio::test]
    async fn in_a_container_the_stop_is_armed_and_the_runtime_stop_is_recorded_as_it() {
        let dir = tempfile::tempdir().expect("dir");
        let (journal, _) =
            adapters::lifecycle::RunJournal::open(dir.path().join("run.json"), "boot-1");
        let journal = Arc::new(journal);
        let cancel = tokio_util::sync::CancellationToken::new();
        let state = Arc::into_inner(state_with_one_rule())
            .expect("sole owner")
            .with_local_stop(Arc::new(
                crate::lifecycle::LocalStop::new(Arc::clone(&journal), cancel.clone())
                    .under_unit(false),
            ));
        let (status, Json(resp)) = stop_agent(
            State(Arc::new(state)),
            None,
            Some(Json(StopRequest {
                reason: Some("host maintenance".to_string()),
            })),
        )
        .await
        .expect("accepted");
        assert_eq!(status, axum::http::StatusCode::ACCEPTED);
        assert_eq!(resp.status, "armed");
        assert_eq!(resp.exit_code, None);
        assert_eq!(
            resp.window_seconds,
            Some(crate::lifecycle::ARMED_STOP_WINDOW.as_secs())
        );
        assert!(journal.ended().is_none(), "the agent keeps running");
        assert!(!cancel.is_cancelled());
        // `docker stop` arrives: the end is the stop that was asked for.
        crate::lifecycle::record_end(&journal);
        let end = journal.ended().expect("recorded");
        assert_eq!(end.how, domain::lifecycle::EndCause::Command);
        assert_eq!(end.requested_by.as_deref(), Some("local"));
        assert_eq!(end.reason.as_deref(), Some("host maintenance"));
        assert!(
            crate::lifecycle::stop_commanded(),
            "the container ends with the stop's own status"
        );
    }

    #[tokio::test]
    async fn status_response_has_expected_fields() {
        let state = state_with_one_rule();

        let Json(resp) = agent_status(State(state)).await;
        assert_eq!(resp.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(resp.status, "running");
        assert!(resp.ebpf_loaded);
        assert_eq!(resp.rule_count, 1);
        assert!(resp.uptime_seconds < 2);
        assert!(resp.firewall_enabled);
        assert_eq!(resp.firewall_mode, "alert");
    }

    /// Before startup has built the enrichers there is nothing to report, and
    /// saying `starting` is the difference between a verdict and a guess.
    #[tokio::test]
    async fn container_coverage_starts_undecided() {
        let state = state_with_one_rule();

        let Json(resp) = agent_status(State(state)).await;
        assert_eq!(resp.container_coverage.docker, EnricherState::Starting);
        assert_eq!(resp.container_coverage.kubernetes, EnricherState::Starting);
        assert!(!resp.container_coverage.resolver);
        assert!(!resp.container_coverage.host_proc);
    }

    /// The deployment matrix claims a mode covers containers; this is the same
    /// claim answered by the node, so the two can be compared on the node.
    #[tokio::test]
    async fn container_coverage_reports_what_startup_decided() {
        let state = state_with_one_rule();
        state.container_coverage.store(Arc::new(ContainerCoverage {
            proc_root: "/host/proc".to_string(),
            host_proc: true,
            resolver: true,
            docker: EnricherState::OffNoSocket,
            podman: EnricherState::On,
            lxc: EnricherState::On,
            kubernetes: EnricherState::On,
            podman_runtimes: Vec::new(),
        }));
        let dir = tempfile::tempdir().unwrap();
        let podman = Arc::new(adapters::container::PodmanEnricher::new(
            dir.path().join("podman.sock"),
            Some(dir.path().to_path_buf()),
            100,
            Arc::new(adapters::container::DockerCache::with_defaults()),
        ));
        let rootless = domain::container::entity::ContainerInfo::Container {
            container_id: "ab".repeat(32),
            runtime: domain::container::entity::ContainerRuntime::Podman,
            cgroup_path: "/user.slice/user-1000.slice/user@1000.service/x".to_string(),
            pid: 1,
        };
        ports::secondary::metadata_enricher_port::MetadataEnricher::enrich(&*podman, &rootless)
            .await
            .unwrap();
        state.podman_enricher.store(Some(podman));

        let Json(resp) = agent_status(State(state)).await;
        let coverage = &resp.container_coverage;
        assert_eq!(coverage.proc_root, "/host/proc");
        assert!(coverage.host_proc);
        assert!(coverage.resolver);
        assert_eq!(coverage.docker, EnricherState::OffNoSocket);
        assert_eq!(coverage.kubernetes, EnricherState::On);

        let wire = serde_json::to_value(&resp).unwrap();
        assert_eq!(wire["container_coverage"]["docker"], "off_no_socket");
        assert_eq!(wire["container_coverage"]["kubernetes"], "on");
        assert_eq!(wire["container_coverage"]["proc_root"], "/host/proc");
        assert_eq!(wire["container_coverage"]["podman"], "on");
        let runtime = &wire["container_coverage"]["podman_runtimes"][0];
        assert_eq!(runtime["uid"], 1000);
        assert_eq!(runtime["reach"], "no_socket");
    }
}
