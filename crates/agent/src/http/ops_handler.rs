use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::Extension;
use axum::Json;
use axum::extract::State;
use domain::auth::entity::JwtClaims;
use infrastructure::config::AgentConfig;
use serde::Serialize;
use utoipa::ToSchema;

use super::error::{ApiError, ErrorBody};
use super::middleware::rbac::require_write_access;
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

/// One attach the kernel refused, and what is standing in the way.
#[derive(Serialize, ToSchema)]
pub struct AttachBlockEntry {
    pub program: String,
    pub interface: String,
    /// Operator-readable sentence: what the kernel said, translated against
    /// what is actually on the interface right now.
    pub reason: String,
    /// True when the interface already carries somebody else's XDP program,
    /// the nested-XDP case that Docker and Kubernetes produce.
    pub nested_xdp: bool,
}

#[derive(Serialize, ToSchema)]
pub struct EbpfStatusResponse {
    pub programs: Vec<ProgramStatus>,
    /// Attaches that lost, if any. `programs[].loaded` says a program is in
    /// the kernel; this says whether it reached the wire.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub attach_blocked: Vec<AttachBlockEntry>,
}

/// One `(program type, helper)` answer from the startup probe.
#[derive(Serialize, ToSchema)]
pub struct HelperSupportEntry {
    pub program_type: String,
    pub helper: String,
    pub supported: bool,
}

/// A helper an object needs that this kernel does not offer for its type.
#[derive(Serialize, ToSchema)]
pub struct MissingHelperEntry {
    pub object: String,
    pub program_type: String,
    pub helper: String,
    /// The same fact as one sentence, for logs and support tickets.
    pub detail: String,
}

/// One uprobe the DLP module currently holds a link for.
#[derive(Serialize, ToSchema)]
pub struct UprobeEntry {
    /// Library basename.
    pub lib: String,
    /// Path the link was created against, as the loader saw it.
    pub path: String,
    /// Block device of the probed file.
    pub dev: u64,
    /// Inode of the probed file. With `dev`, the identity two runs are compared
    /// on: the same path can name a different file after a package upgrade.
    pub ino: u64,
    /// Loader name of the eBPF program behind the probe.
    pub program: String,
    /// Exported symbol the probe sits on.
    pub symbol: String,
    /// File offset the link was created at. A changed offset for an unchanged
    /// inode is a resolution regression, not a new build.
    pub offset: u64,
    /// The probe fires on return rather than on entry.
    pub retprobe: bool,
    /// `BPF_LINK_CREATE` was issued by the warden (rootless posture) rather than
    /// by the agent itself.
    pub brokered: bool,
    /// The attachment survives a reconcile that finds no process mapping the
    /// inode - the cold-start system-library fallback.
    pub sticky: bool,
}

/// The uprobe set the DLP module currently holds.
///
/// An empty list is a real answer, and always the same one: no TLS payload is
/// being read. It covers a DLP module that is not loaded, a scan that resolved
/// nothing, and a datapath that has been detached.
#[derive(Serialize, ToSchema)]
pub struct UprobeInventoryResponse {
    /// Distinct libraries carrying probes.
    pub libraries: usize,
    /// Every probe, ordered by inode then symbol so two runs diff cleanly.
    pub probes: Vec<UprobeEntry>,
}

/// What the kernel answered when the agent probed it at startup.
///
/// `probed = false` means the probe could not run, **not** that the kernel
/// lacks anything: `helpers` and `missing_required` are then empty because
/// nothing was measured, and `reason` says why. Treating that as a capability
/// report would invert its meaning.
#[derive(Serialize, ToSchema)]
pub struct KernelFeaturesResponse {
    pub probed: bool,
    pub reason: Option<String>,
    /// How the agent loads its objects, which is why a probe needing
    /// `CAP_BPF` can be unavailable on a host where every program loads.
    pub load_mode: String,
    pub program_types: Vec<ProgramTypeSupport>,
    pub helpers: Vec<HelperSupportEntry>,
    pub missing_required: Vec<MissingHelperEntry>,
}

#[derive(Serialize, ToSchema)]
pub struct ProgramTypeSupport {
    pub program_type: String,
    pub supported: bool,
}
/// How long the reload endpoint waits for the reload task to confirm before
/// answering. Past this the answer says `pending` rather than `ok`.
const RELOAD_CONFIRM_TIMEOUT: Duration = Duration::from_secs(8);

// ── Handlers ──────────────────────────────────────────────────────

/// Trigger a configuration reload via the API.
#[utoipa::path(
    post, path = "/api/v1/config/reload",
    tag = "Operations",
    responses(
        (status = 200, description = "Reload triggered successfully", body = ReloadResponse),
        (status = 500, description = "Failed to trigger reload", body = ErrorBody),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn reload_config(
    State(state): State<Arc<AppState>>,
    claims: Option<Extension<JwtClaims>>,
) -> Result<Json<ReloadResponse>, ApiError> {
    if let Some(Extension(ref claims)) = claims {
        require_write_access(claims)?;
    }
    // Validate the on-disk config before triggering the reload so a bad edit
    // is rejected up front instead of crashing the reload task. The load
    // reads files and compiles every rule regex, which measured 16 s cold on
    // a test VM — far too long to run on a runtime worker, where it would
    // stall every other request in flight. Hand it to a blocking thread.
    if let Some(path) = state.config_path.as_deref() {
        let path = path.to_string();
        let validated =
            tokio::task::spawn_blocking(move || AgentConfig::load(Path::new(&path)).map(|_| ()))
                .await
                .map_err(|e| ApiError::Internal {
                    message: format!("config validation task failed: {e}"),
                })?;
        if let Err(e) = validated {
            return Err(ApiError::BadRequest {
                code: "INVALID_CONFIG",
                message: format!("config reload rejected: {e}"),
            });
        }
    }

    // Register for the completion signal *before* triggering so we never
    // miss the notify_waiters() fired by the reload task.
    let notified = state.reload_complete.as_ref().map(|n| {
        let mut fut = Box::pin(n.notified());
        fut.as_mut().enable();
        fut
    });

    state
        .reload_trigger
        .try_send(())
        .map_err(|_| ApiError::Internal {
            message: "reload already in progress or channel unavailable".to_string(),
        })?;

    // Wait for the reload to actually complete (bounded), so callers that
    // read state immediately after see the new config. If the bound expires
    // the reload is still running: say so instead of reporting success, or a
    // caller that reads state next would be told it is looking at the new
    // config when it may still be the old one.
    let confirmed = match notified {
        Some(fut) => tokio::time::timeout(RELOAD_CONFIRM_TIMEOUT, fut)
            .await
            .is_ok(),
        None => false,
    };

    if confirmed {
        Ok(Json(ReloadResponse {
            status: "ok".to_string(),
            message: "configuration reloaded".to_string(),
        }))
    } else {
        Ok(Json(ReloadResponse {
            status: "pending".to_string(),
            message: format!(
                "reload triggered but not confirmed within {}s; it is still in progress",
                RELOAD_CONFIRM_TIMEOUT.as_secs()
            ),
        }))
    }
}

/// Return the current (sanitized) agent configuration.
#[utoipa::path(
    get, path = "/api/v1/config",
    tag = "Operations",
    responses(
        (status = 200, description = "Current sanitized configuration"),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
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
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
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
    let attach_blocked = adapters::ebpf::blocked_attaches()
        .into_iter()
        .map(|b| AttachBlockEntry {
            program: b.program,
            interface: b.interface,
            reason: b.reason,
            nested_xdp: b.nested_xdp,
        })
        .collect();
    Json(EbpfStatusResponse {
        programs,
        attach_blocked,
    })
}

/// Return the DLP uprobe set the agent currently holds links for.
#[utoipa::path(
    get, path = "/api/v1/ebpf/uprobes",
    tag = "Operations",
    responses(
        (status = 200, description = "Attached DLP uprobes with their resolved offsets", body = UprobeInventoryResponse),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn get_uprobes() -> Json<UprobeInventoryResponse> {
    Json(uprobe_inventory_body(adapters::ebpf::attached_uprobes()))
}

/// Build the response from an attach set.
///
/// Takes the set as an argument so the shape of the answer is testable without
/// a kernel, a loaded program, or the process-wide registry.
fn uprobe_inventory_body(probes: Vec<adapters::ebpf::AttachedUprobe>) -> UprobeInventoryResponse {
    let mut inodes: Vec<(u64, u64)> = probes.iter().map(|p| (p.dev, p.ino)).collect();
    inodes.sort_unstable();
    inodes.dedup();
    UprobeInventoryResponse {
        libraries: inodes.len(),
        probes: probes
            .into_iter()
            .map(|p| UprobeEntry {
                lib: p.lib,
                path: p.path,
                dev: p.dev,
                ino: p.ino,
                program: p.program.to_string(),
                symbol: p.symbol.to_string(),
                offset: p.offset,
                retprobe: p.retprobe,
                brokered: p.brokered,
                sticky: p.sticky,
            })
            .collect(),
    }
}

/// Return what the startup helper probe learned about this kernel.
#[utoipa::path(
    get, path = "/api/v1/ebpf/kernel-features",
    tag = "Operations",
    responses(
        (status = 200, description = "Kernel helper support as probed at startup", body = KernelFeaturesResponse),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn get_kernel_features() -> Json<KernelFeaturesResponse> {
    // Read the cache rather than probe, so hitting the endpoint never issues
    // a syscall pass of its own.
    Json(kernel_features_body(adapters::ebpf::cached_kernel_helpers()))
}

/// Build the response from a probe report, or from its absence.
///
/// Takes the report as an argument so the shape of the answer is testable
/// without a kernel and without the process-wide cache.
fn kernel_features_body(report: Option<&adapters::ebpf::HelperReport>) -> KernelFeaturesResponse {
    use adapters::ebpf::ProbeStatus;

    let Some(report) = report else {
        return KernelFeaturesResponse {
            probed: false,
            reason: Some("startup has not run the kernel helper probe".to_string()),
            load_mode: adapters::ebpf::helper_probe::LOAD_MODE.to_string(),
            program_types: Vec::new(),
            helpers: Vec::new(),
            missing_required: Vec::new(),
        };
    };

    let reason = match &report.status {
        ProbeStatus::Probed => None,
        ProbeStatus::NotProbed { reason } => Some(reason.clone()),
    };

    KernelFeaturesResponse {
        probed: report.status.probed(),
        reason,
        load_mode: report.load_mode.to_string(),
        program_types: report
            .program_types
            .iter()
            .map(|(program_type, supported)| ProgramTypeSupport {
                program_type: (*program_type).to_string(),
                supported: *supported,
            })
            .collect(),
        helpers: report
            .helpers
            .iter()
            .map(|h| HelperSupportEntry {
                program_type: h.program_type.to_string(),
                helper: h.helper.to_string(),
                supported: h.supported,
            })
            .collect(),
        missing_required: report
            .missing_required
            .iter()
            .map(|m| MissingHelperEntry {
                object: m.object.to_string(),
                program_type: m.program_type.to_string(),
                helper: m.helper.to_string(),
                detail: m.to_string(),
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
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
    use infrastructure::config::AgentConfig;
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
            Arc::new(arc_swap::ArcSwap::from_pointee(ips_svc)),
            Arc::new(arc_swap::ArcSwap::from_pointee(l7_svc)),
            Arc::new(RwLock::new(rl_svc)),
            Arc::new(arc_swap::ArcSwap::from_pointee(ti_svc)),
            Arc::new(audit_svc),
            Arc::new(RwLock::new(
                AgentConfig::from_yaml("agent:\n  interfaces: [eth0]").unwrap(),
            )),
            reload_tx,
            Arc::new(RwLock::new(HashMap::new())),
        ));
        (state, reload_rx)
    }

    /// Same state, un-wrapped, so a test can set optional fields before use.
    fn make_state_mut() -> (AppState, tokio::sync::mpsc::Receiver<()>) {
        let (state, rx) = make_state();
        let inner = Arc::try_unwrap(state).unwrap_or_else(|_| {
            panic!("make_state must return a uniquely-owned Arc");
        });
        (inner, rx)
    }

    fn claims_with_role(role: &str) -> JwtClaims {
        JwtClaims {
            sub: "test-user".to_string(),
            exp: 9_999_999_999,
            iat: 0,
            iss: None,
            aud: None,
            role: Some(role.to_string()),
            namespaces: None,
            tenant_id: None,
            roles: None,
        }
    }

    #[tokio::test]
    async fn reload_without_a_completion_signal_reports_pending() {
        // No `reload_complete` notifier: the handler triggers the reload but
        // has no way to observe it finishing, so it must not claim success.
        let (state, _rx) = make_state();
        let result = reload_config(State(state), None).await;
        let Json(resp) = result.expect("reload should be accepted");
        assert_eq!(resp.status, "pending");
        assert!(
            resp.message.contains("not confirmed"),
            "message should say why: {}",
            resp.message
        );
    }

    #[tokio::test]
    async fn reload_reports_ok_once_the_reload_task_confirms() {
        let (mut state, _rx) = make_state_mut();
        let notify = Arc::new(tokio::sync::Notify::new());
        state.reload_complete = Some(Arc::clone(&notify));
        let state = Arc::new(state);

        // Confirm shortly after the handler starts waiting.
        let notifier = Arc::clone(&notify);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            notifier.notify_waiters();
        });

        let result = reload_config(State(state), None).await;
        let Json(resp) = result.expect("reload should succeed");
        assert_eq!(resp.status, "ok");
    }

    #[tokio::test]
    async fn reload_config_returns_error_when_channel_full() {
        let (state, _rx) = make_state();
        // Fill the channel (capacity 1)
        let _ = state.reload_trigger.try_send(());
        let result = reload_config(State(state), None).await;
        assert!(matches!(result, Err(ApiError::Internal { .. })));
    }

    #[tokio::test]
    async fn reload_config_rejects_viewer() {
        let (state, _rx) = make_state();
        let claims = Extension(claims_with_role("viewer"));
        let result = reload_config(State(state), Some(claims)).await;
        assert!(
            matches!(
                result,
                Err(ApiError::Forbidden {
                    code: "INSUFFICIENT_ROLE",
                    ..
                })
            ),
            "viewer must not be able to reload config"
        );
    }

    #[tokio::test]
    async fn reload_config_allows_operator() {
        let (state, _rx) = make_state();
        let claims = Extension(claims_with_role("operator"));
        let result = reload_config(State(state), Some(claims)).await;
        assert!(result.is_ok(), "operator must be allowed to reload config");
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

    #[test]
    fn an_empty_uprobe_set_reports_no_libraries_rather_than_omitting_the_field() {
        // "DLP is not inspecting anything" has to be readable as an answer, not
        // inferred from a missing key.
        let resp = uprobe_inventory_body(Vec::new());
        assert_eq!(resp.libraries, 0);
        assert!(resp.probes.is_empty());
    }

    #[test]
    fn the_uprobe_inventory_counts_libraries_by_inode_not_by_probe() {
        // Three probes on one library is one library. Counting probes would make
        // a single-library host look like three.
        let probe =
            |ino: u64, symbol: &'static str, retprobe: bool| adapters::ebpf::AttachedUprobe {
                lib: "libssl.so.3".to_string(),
                path: "/lib/libssl.so.3".to_string(),
                dev: 1,
                ino,
                program: "ssl_write",
                symbol,
                offset: 0x1000 + ino,
                retprobe,
                brokered: true,
                sticky: false,
            };
        let resp = uprobe_inventory_body(vec![
            probe(10, "SSL_read", false),
            probe(10, "SSL_read", true),
            probe(10, "SSL_write", false),
            probe(20, "SSL_write", false),
        ]);

        assert_eq!(resp.libraries, 2);
        assert_eq!(resp.probes.len(), 4);
        // The offset is the whole point of the endpoint: it must survive the
        // conversion, per probe, unrounded.
        assert_eq!(resp.probes[0].offset, 0x100A);
        assert_eq!(resp.probes[3].offset, 0x1014);
        assert!(resp.probes.iter().all(|p| p.brokered));
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

    #[test]
    fn kernel_features_says_not_probed_rather_than_unsupported() {
        // The distinction is the whole point of the field: an empty helper
        // list under `probed: false` means nothing was measured, and a reader
        // that took it for "this kernel has no helpers" would be inverted.
        let resp = kernel_features_body(None);
        assert!(!resp.probed);
        assert!(resp.reason.is_some());
        assert!(resp.helpers.is_empty());
        assert!(resp.missing_required.is_empty());

        let refused = adapters::ebpf::HelperReport::not_probed("operation not permitted");
        let resp = kernel_features_body(Some(&refused));
        assert!(!resp.probed);
        assert_eq!(resp.reason.as_deref(), Some("operation not permitted"));
        assert!(resp.missing_required.is_empty());
    }

    #[test]
    fn kernel_features_reports_each_gap_with_object_type_and_helper() {
        let report = adapters::ebpf::HelperReport {
            status: adapters::ebpf::ProbeStatus::Probed,
            load_mode: "bpf-token",
            program_types: vec![("xdp", true), ("sched_cls", true), ("kprobe", false)],
            helpers: vec![adapters::ebpf::HelperSupport {
                program_type: "sched_cls",
                helper: "bpf_skb_ecn_set_ce",
                supported: false,
            }],
            missing_required: vec![adapters::ebpf::MissingHelper {
                object: "tc-qos",
                program_type: "sched_cls",
                helper: "bpf_skb_ecn_set_ce",
            }],
        };

        let resp = kernel_features_body(Some(&report));
        assert!(resp.probed);
        assert!(resp.reason.is_none());
        assert_eq!(resp.program_types.len(), 3);
        let gap = &resp.missing_required[0];
        assert_eq!(gap.object, "tc-qos");
        assert_eq!(gap.program_type, "sched_cls");
        assert_eq!(gap.helper, "bpf_skb_ecn_set_ce");
        assert!(gap.detail.contains("tc-qos"));
        assert!(gap.detail.contains("bpf_skb_ecn_set_ce"));
    }
}
