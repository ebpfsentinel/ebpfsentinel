use std::sync::Arc;

use application::host_rule_service::{FED_INTENTS, HostRuleService, not_fed_reason};
use application::ransom_service::RansomService;
use application::write_refusal_control::WriteRefusalControl;
use axum::Json;
use axum::extract::State;
use domain::hostrule::{
    Applicability, HostRule, HostShadowReading, HostSources, Intent, Source, resolve,
};
use serde::Serialize;
use utoipa::ToSchema;

use super::error::ErrorBody;
use super::state::AppState;

/// Why a source with nothing behind it in this build is absent.
const NOT_IN_THIS_BUILD: &str = "no source for it is part of this build";

/// One field an intention carries.
#[derive(Debug, Serialize, ToSchema)]
pub struct IntentFieldBody {
    /// The key a rule writes.
    pub name: &'static str,
    /// Its type: `text`, `path`, `integer`, `port`, `address`, `boolean`
    /// or `hash`.
    #[serde(rename = "type")]
    pub ty: &'static str,
    /// What it holds.
    pub doc: &'static str,
}

/// One intention and whether this host serves it.
#[derive(Debug, Serialize, ToSchema)]
pub struct IntentBody {
    /// The name a rule writes, such as `process.connects`.
    pub name: &'static str,
    /// `process`, `file`, `posture` or `surface`.
    pub family: &'static str,
    /// The kernel mechanism serving it, in one line.
    pub hook: &'static str,
    /// The sources it needs, every one of them.
    pub sources: Vec<&'static str>,
    /// Oldest kernel the hook exists on, as `major.minor`.
    pub min_kernel: String,
    /// What serves it, less well, when the hook is absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback: Option<&'static str>,
    /// `applicable` or `not_applicable`.
    pub state: &'static str,
    /// Why this host cannot serve it, one sentence per missing source.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub fields: Vec<IntentFieldBody>,
}

/// Every intention a host rule may name, resolved against this host.
#[derive(Debug, Serialize, ToSchema)]
pub struct HostIntentsResponse {
    /// The running kernel as `major.minor`, absent when it could not be read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel: Option<String>,
    /// How many of the intentions this host serves.
    pub applicable: usize,
    pub intents: Vec<IntentBody>,
}

/// `GET /api/v1/host-rules/intents` - what a host rule can name, and
/// which of it this host serves.
#[utoipa::path(
    get, path = "/api/v1/host-rules/intents",
    tag = "Operations",
    responses((status = 200, description = "Every intention a host rule may name, its fields, the hook serving it and whether this host serves it", body = HostIntentsResponse),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn get_host_intents(State(state): State<Arc<AppState>>) -> Json<HostIntentsResponse> {
    let host = host_sources(&state).await;
    Json(intents_body(&host))
}

/// What this host reported about each source, read from what attached and
/// what is reading rather than from the kernel version.
async fn host_sources(state: &AppState) -> HostSources {
    let programs = state.ebpf_program_status.read().await;
    let running = [
        (
            Source::NetworkProgramInventory,
            state.network_programs.load().is_some(),
        ),
        (
            Source::RawSocketInventory,
            state.raw_sockets.load().is_some(),
        ),
        (Source::HiddenPortScan, state.hidden_ports.load().is_some()),
        (
            Source::HiddenProcessScan,
            state.hidden_processes.load().is_some(),
        ),
    ];
    let running: Vec<Source> = running
        .into_iter()
        .filter_map(|(source, on)| on.then_some(source))
        .collect();
    reported_sources(&programs, &running)
}

/// The sources an agent task reads rather than an attached program, and
/// what is said of each when that task is not running.
const TASK_SOURCES: [(Source, &str); 4] = [
    (
        Source::NetworkProgramInventory,
        "the network program inventory is not reading",
    ),
    (
        Source::RawSocketInventory,
        "the packet socket inventory is not reading",
    ),
    (
        Source::HiddenPortScan,
        "the hidden port sweep is not running",
    ),
    (
        Source::HiddenProcessScan,
        "the hidden process sweep is not running",
    ),
];

/// What this host reports about each source, given which datapath programs
/// loaded and which of the agent's own readings, the inventories and the
/// hidden sweeps, are running.
///
/// The process tracing and socket attribution halves are read from what
/// their attachers published, so a binary that builds its own datapath
/// answers the same way the agent does.
#[must_use]
pub fn reported_sources<S: std::hash::BuildHasher>(
    programs: &std::collections::HashMap<String, bool, S>,
    running: &[Source],
) -> HostSources {
    let kernel = adapters::ebpf::kernel_probe::probe()
        .ok()
        .map(|k| (k.major, k.minor));
    let mut host = HostSources::new(kernel);

    let process = adapters::ebpf::process_attach::status();
    host = attach(
        host,
        Source::ProcessTracing,
        process.attached,
        process.reason,
    );
    let attribution = adapters::ebpf::attribution_attach::status();
    host = attach(
        host,
        Source::SocketAttribution,
        attribution.attached,
        attribution.reason,
    );

    host = program(host, Source::DnsCapture, programs, "tc-dns");
    host = program(host, Source::TlsCapture, programs, "tc-ids");

    for (source, reason) in TASK_SOURCES {
        host = if running.contains(&source) {
            host.present(source)
        } else {
            host.absent(source, reason)
        };
    }

    host = match adapters::warden::file_watch::status() {
        None => host.present(Source::FileWatch),
        Some(reason) => host.absent(Source::FileWatch, reason),
    };

    host.absent(Source::PackageInventory, NOT_IN_THIS_BUILD)
}

fn attach(
    host: HostSources,
    source: Source,
    attached: bool,
    reason: Option<String>,
) -> HostSources {
    if attached {
        host.present(source)
    } else {
        host.absent(
            source,
            reason.unwrap_or_else(|| "its hooks are not attached".to_string()),
        )
    }
}

fn program<S: std::hash::BuildHasher>(
    host: HostSources,
    source: Source,
    programs: &std::collections::HashMap<String, bool, S>,
    name: &str,
) -> HostSources {
    match programs.get(name) {
        Some(true) => host.present(source),
        Some(false) => host.absent(source, format!("{name} did not load")),
        None => host.absent(source, format!("{name} is not configured")),
    }
}

/// Whether a rule naming `intent` can match on this host: a source must
/// report it, and something in this build must hand its events to the
/// rules. The missing source is the reason given first; the second is
/// checked here rather than in the binding, because a
/// hook that attached and a rule engine nobody feeds is still a rule that
/// never fires.
fn served(intent: Intent, host: &HostSources) -> Result<(), String> {
    match resolve(intent, host) {
        Applicability::NotApplicable { reason } => Err(reason),
        Applicability::Applicable if !FED_INTENTS.contains(&intent) => Err(not_fed_reason(intent)),
        Applicability::Applicable => Ok(()),
    }
}

/// Every intention a rule may name, against what `host` reports.
#[must_use]
pub fn intents_body(host: &HostSources) -> HostIntentsResponse {
    let intents: Vec<IntentBody> = Intent::ALL
        .into_iter()
        .map(|intent| {
            let binding = intent.binding();
            let (state, reason) = match served(intent, host) {
                Ok(()) => ("applicable", None),
                Err(reason) => ("not_applicable", Some(reason)),
            };
            IntentBody {
                name: intent.as_str(),
                family: intent.family().as_str(),
                hook: binding.hook,
                sources: binding.sources.iter().map(|s| s.as_str()).collect(),
                min_kernel: format!("{}.{}", binding.min_kernel.0, binding.min_kernel.1),
                fallback: binding.fallback,
                state,
                reason,
                fields: intent
                    .fields()
                    .iter()
                    .map(|f| IntentFieldBody {
                        name: f.name,
                        ty: f.ty.name(),
                        doc: f.doc,
                    })
                    .collect(),
            }
        })
        .collect();
    HostIntentsResponse {
        kernel: host.kernel.map(|(major, minor)| format!("{major}.{minor}")),
        applicable: intents.iter().filter(|i| i.state == "applicable").count(),
        intents,
    }
}

/// One intention a rule names, and whether this host serves it.
#[derive(Debug, Serialize, ToSchema)]
pub struct RuleIntentBody {
    pub name: &'static str,
    /// `applicable` or `not_applicable`.
    pub state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Events a shadow rule would have acted on about one workload.
#[derive(Debug, Serialize, ToSchema)]
pub struct HostShadowWorkloadBody {
    /// The container, else the cgroup, else the systemd unit; absent for a
    /// process in none of them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workload: Option<String>,
    pub events: u64,
}

/// What a rule in shadow would have done since the reading started.
#[derive(Debug, Serialize, ToSchema)]
pub struct HostShadowBody {
    /// Events on which it would have acted.
    pub events: u64,
    /// Those events by workload, the first ones seen, bounded.
    pub workloads: Vec<HostShadowWorkloadBody>,
    /// Events about a workload that came after the sample was full.
    pub unsampled: u64,
}

impl From<HostShadowReading> for HostShadowBody {
    fn from(reading: HostShadowReading) -> Self {
        Self {
            events: reading.events,
            workloads: reading
                .workloads
                .into_iter()
                .map(|hits| HostShadowWorkloadBody {
                    workload: hits.workload,
                    events: hits.events,
                })
                .collect(),
            unsampled: reading.unsampled,
        }
    }
}

/// One loaded host rule.
#[derive(Debug, Serialize, ToSchema)]
pub struct HostRuleBody {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// `low`, `medium`, `high` or `critical`.
    pub severity: String,
    /// `alert`, and `kill_process` where the rule stops the process.
    pub then: Vec<&'static str>,
    /// `applicable` when every intention it names is served here,
    /// `partially_applicable` when some are, `not_applicable` when none is.
    pub state: &'static str,
    pub intents: Vec<RuleIntentBody>,
    /// `shadow`, counting what it would have done and doing none of it, or
    /// `enforce`, acting on what it matches.
    pub mode: &'static str,
    /// What it would have done, for a rule in shadow.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shadow: Option<HostShadowBody>,
    /// The rule as it was written, `workload` and `when` included.
    #[schema(value_type = Object)]
    pub spec: serde_json::Value,
}

/// Every loaded host rule, and what they have matched since the start.
#[derive(Debug, Serialize, ToSchema)]
pub struct HostRulesResponse {
    /// Events that matched a rule, in force or in shadow.
    pub matched: u64,
    /// When the shadow readings started, nanoseconds since the epoch: the
    /// agent's start.
    pub shadow_since_ns: u64,
    /// Of the matches of rules in force, alerts lost to a full alert queue.
    pub dropped: u64,
    /// First steps of sequences waiting for their second now.
    pub pending: usize,
    /// First steps not held because the bounded set of waiting ones was
    /// full.
    pub pending_refused: u64,
    /// Groups a count is running for now.
    pub counting: usize,
    /// Events not counted because the groups or the events held were at
    /// their bound.
    pub counting_refused: u64,
    /// Matches an exception left alone: no alert and no shadow reading.
    pub exempted: u64,
    /// The exceptions in force.
    pub exceptions: Vec<HostRuleExceptionBody>,
    pub rules: Vec<HostRuleBody>,
}

/// A workload some host rules leave alone.
#[derive(Debug, Serialize, ToSchema)]
pub struct HostRuleExceptionBody {
    pub id: String,
    /// The rules it silences; empty for every rule.
    pub rules: Vec<String>,
    /// The workload it names, written as a rule's `workload`.
    #[schema(value_type = Object)]
    pub workload: serde_json::Value,
}

/// One mass encryption verdict reached in shadow, as the alert would have
/// read.
#[derive(Debug, Serialize, ToSchema)]
pub struct ShadowVerdictBody {
    /// When it was reached, boot-time nanoseconds.
    pub at_ns: u64,
    /// The actor's pid.
    pub pid: u32,
    /// The actor's executable, where the process table knew it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    /// The container, else the cgroup, else the systemd unit it was counted
    /// under.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workload: Option<String>,
    /// The alert's message: the signals, their evidence and what this host
    /// cannot read.
    pub message: String,
}

/// The mass encryption verdict and what it reached in shadow.
#[derive(Debug, Serialize, ToSchema)]
pub struct MassEncryptionResponse {
    /// Whether the verdict is evaluated here: the file watch feeds it, so it
    /// is off where the watch is.
    pub enabled: bool,
    /// `shadow`, counting the verdicts and raising nothing, or `enforce`,
    /// raising an alert for each; absent where the verdict is off.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<&'static str>,
    /// The verdicts reached in shadow since the agent started, by workload.
    pub shadow: HostShadowBody,
    /// The last verdicts reached in shadow, newest last.
    pub recent: Vec<ShadowVerdictBody>,
}

/// `GET /api/v1/host-rules/mass-encryption` - the mass encryption verdict's
/// mode and what it reached in shadow.
#[utoipa::path(
    get, path = "/api/v1/host-rules/mass-encryption",
    tag = "Operations",
    responses((status = 200, description = "Whether the mass encryption verdict is evaluated, its mode, and the verdicts it reached in shadow by workload with the last ones as they would have read", body = MassEncryptionResponse),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn get_mass_encryption(
    State(state): State<Arc<AppState>>,
) -> Json<MassEncryptionResponse> {
    let service = state.ransom_service.load_full();
    Json(mass_encryption_body(service.as_deref()))
}

/// The verdict's mode and shadow reading, or an empty reading where it is
/// not evaluated.
#[must_use]
pub fn mass_encryption_body(service: Option<&RansomService>) -> MassEncryptionResponse {
    let Some(service) = service else {
        return MassEncryptionResponse {
            enabled: false,
            mode: None,
            shadow: HostShadowReading::default().into(),
            recent: Vec::new(),
        };
    };
    let shadow = service.shadow();
    MassEncryptionResponse {
        enabled: true,
        mode: Some(service.mode().as_str()),
        shadow: shadow.reading.into(),
        recent: recent_bodies(shadow.recent),
    }
}

/// The last verdicts reached in shadow, as the API writes them.
fn recent_bodies(
    recent: impl IntoIterator<Item = domain::ransom::ShadowVerdict>,
) -> Vec<ShadowVerdictBody> {
    recent
        .into_iter()
        .map(|verdict| ShadowVerdictBody {
            at_ns: verdict.at_ns,
            pid: verdict.pid,
            exe: verdict.exe,
            workload: verdict.workload,
            message: verdict.message,
        })
        .collect()
}

/// The write refusal's mode and the writes it would have refused in shadow.
#[derive(Debug, Serialize, ToSchema)]
pub struct WriteRefusalShadowResponse {
    /// Whether a refusal runs here, on either route.
    pub enabled: bool,
    /// `shadow`, counting the writers that reached the threshold and refusing
    /// nothing, or `enforce`, refusing their next open; absent where no
    /// refusal runs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<&'static str>,
    /// When this reading started, boot-time nanoseconds. A promotion names it,
    /// and is refused if the reading started again since.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub counting_since_ns: Option<u64>,
    /// The writes it would have refused, by the workload of the writer.
    pub shadow: HostShadowBody,
    /// The last of them as the alert would have read, newest last.
    pub recent: Vec<ShadowVerdictBody>,
}

/// `GET /api/v1/host-rules/write-refusal` - the write refusal's mode and what
/// it would have refused in shadow.
#[utoipa::path(
    get, path = "/api/v1/host-rules/write-refusal",
    tag = "Operations",
    responses((status = 200, description = "Whether a write refusal runs, its mode, when its reading started, and the writes it would have refused in shadow by workload with the last ones as they would have read", body = WriteRefusalShadowResponse),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn get_write_refusal_shadow(
    State(state): State<Arc<AppState>>,
) -> Json<WriteRefusalShadowResponse> {
    let control = state.write_refusal.load_full();
    Json(write_refusal_body(control.as_deref()))
}

/// The refusal's mode and shadow reading, or an empty reading where none
/// runs.
#[must_use]
pub fn write_refusal_body(control: Option<&WriteRefusalControl>) -> WriteRefusalShadowResponse {
    let Some(control) = control else {
        return WriteRefusalShadowResponse {
            enabled: false,
            mode: None,
            counting_since_ns: None,
            shadow: HostShadowReading::default().into(),
            recent: Vec::new(),
        };
    };
    let shadow = control.shadow();
    WriteRefusalShadowResponse {
        enabled: true,
        mode: Some(if control.enforcing() {
            "enforce"
        } else {
            "shadow"
        }),
        counting_since_ns: Some(control.since_ns()),
        shadow: shadow.reading.into(),
        recent: recent_bodies(shadow.recent),
    }
}

/// `GET /api/v1/host-rules` - the loaded host rules and whether this host
/// can match each of them.
#[utoipa::path(
    get, path = "/api/v1/host-rules",
    tag = "Operations",
    responses((status = 200, description = "Every loaded host rule, the intentions it names and whether this host serves each, with the match counters", body = HostRulesResponse),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn get_host_rules(State(state): State<Arc<AppState>>) -> Json<HostRulesResponse> {
    let host = host_sources(&state).await;
    let service = state.host_rule_service.load_full();
    Json(rules_body(service.as_deref(), &host))
}

/// Every rule, its mode and its reading, against what `host` reports.
#[must_use]
pub fn rules_body(service: Option<&HostRuleService>, host: &HostSources) -> HostRulesResponse {
    let Some(service) = service else {
        return HostRulesResponse {
            matched: 0,
            shadow_since_ns: 0,
            dropped: 0,
            pending: 0,
            pending_refused: 0,
            counting: 0,
            counting_refused: 0,
            exempted: 0,
            exceptions: Vec::new(),
            rules: Vec::new(),
        };
    };
    let (matched, dropped) = service.counts();
    let memory = service.memory();
    HostRulesResponse {
        matched,
        shadow_since_ns: service.shadow_since_ns(),
        dropped,
        pending: memory.pending,
        pending_refused: memory.pending_refused,
        counting: memory.counting,
        counting_refused: memory.counting_refused,
        exempted: service.exempted(),
        exceptions: service
            .exceptions()
            .iter()
            .map(|exception| HostRuleExceptionBody {
                id: exception.id().to_string(),
                rules: exception.rules().to_vec(),
                workload: serde_json::to_value(exception.selector())
                    .unwrap_or(serde_json::Value::Null),
            })
            .collect(),
        rules: service
            .rules()
            .rules()
            .iter()
            .map(|rule| rule_body(rule, service, host))
            .collect(),
    }
}

fn rule_body(rule: &HostRule, service: &HostRuleService, host: &HostSources) -> HostRuleBody {
    let intents: Vec<RuleIntentBody> = rule
        .intents()
        .into_iter()
        .map(|intent| match served(intent, host) {
            Ok(()) => RuleIntentBody {
                name: intent.as_str(),
                state: "applicable",
                reason: None,
            },
            Err(reason) => RuleIntentBody {
                name: intent.as_str(),
                state: "not_applicable",
                reason: Some(reason),
            },
        })
        .collect();
    let served_count = intents.iter().filter(|i| i.state == "applicable").count();
    let state = if served_count == intents.len() {
        "applicable"
    } else if served_count == 0 {
        "not_applicable"
    } else {
        "partially_applicable"
    };
    HostRuleBody {
        id: rule.spec.id.clone(),
        description: rule.spec.description.clone(),
        severity: rule.spec.severity.to_ascii_lowercase(),
        then: rule.spec.then.iter().map(|a| a.as_str()).collect(),
        state,
        intents,
        mode: service.mode(rule.id()).unwrap_or(rule.spec.mode).as_str(),
        shadow: service.reading(rule.id()).map(HostShadowBody::from),
        spec: serde_json::to_value(&rule.spec).unwrap_or(serde_json::Value::Null),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_mass_encryption_verdict_reads_off_where_the_watch_is_off() {
        let body = mass_encryption_body(None);
        assert!(!body.enabled);
        assert!(body.mode.is_none());
        assert_eq!(body.shadow.events, 0);
        assert!(body.recent.is_empty());
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let service = RansomService::new(tx, Arc::new(|| HostSources::new(Some((6, 12)))));
        let body = mass_encryption_body(Some(&service));
        assert!(body.enabled);
        assert_eq!(body.mode, Some("shadow"));
    }

    #[test]
    fn the_write_refusal_reading_names_its_start_and_turns_to_enforce_on_promotion() {
        let body = write_refusal_body(None);
        assert!(!body.enabled);
        assert!(body.counting_since_ns.is_none());
        let control = WriteRefusalControl::new(false, 42_000);
        control.record(domain::ransom::ShadowVerdict {
            at_ns: 43_000,
            pid: 7,
            exe: None,
            workload: Some("/system.slice/batch.service".to_string()),
            message: "write refusal would refuse".to_string(),
        });
        let body = write_refusal_body(Some(&control));
        assert_eq!(body.mode, Some("shadow"));
        assert_eq!(body.counting_since_ns, Some(42_000));
        assert_eq!(body.shadow.events, 1);
        assert_eq!(body.recent.len(), 1);
        control.promote(42_000).unwrap();
        assert_eq!(write_refusal_body(Some(&control)).mode, Some("enforce"));
    }

    #[test]
    fn every_intent_is_listed_with_its_fields() {
        let body = intents_body(&HostSources::new(Some((6, 12))));
        assert_eq!(body.intents.len(), Intent::ALL.len());
        assert_eq!(body.kernel.as_deref(), Some("6.12"));
        let connects = body
            .intents
            .iter()
            .find(|i| i.name == "process.connects")
            .unwrap();
        assert_eq!(connects.family, "process");
        assert!(
            connects
                .fields
                .iter()
                .any(|f| f.name == "remote_port" && f.ty == "port")
        );
    }

    #[test]
    fn a_host_reporting_nothing_serves_nothing_and_says_why() {
        let body = intents_body(&HostSources::new(None));
        assert_eq!(body.applicable, 0);
        assert!(body.kernel.is_none());
        for intent in &body.intents {
            assert_eq!(intent.state, "not_applicable");
            assert!(intent.reason.as_deref().is_some_and(|r| !r.is_empty()));
        }
    }

    #[test]
    fn the_sources_present_decide_what_is_served() {
        let host = HostSources::new(Some((6, 12)))
            .present(Source::ProcessTracing)
            .absent(Source::FileWatch, "the file watch is not enabled");
        let body = intents_body(&host);
        let starts = body
            .intents
            .iter()
            .find(|i| i.name == "process.starts")
            .unwrap();
        assert_eq!(starts.state, "applicable");
        assert!(starts.reason.is_none());
        let changes = body
            .intents
            .iter()
            .find(|i| i.name == "file.changes")
            .unwrap();
        assert_eq!(changes.state, "not_applicable");
        assert_eq!(
            changes.reason.as_deref(),
            Some("file_watch: the file watch is not enabled")
        );
        assert_eq!(body.applicable, 2);

        let watched = HostSources::new(Some((6, 12)))
            .present(Source::ProcessTracing)
            .present(Source::FileWatch);
        let body = intents_body(&watched);
        for name in [
            "file.changes",
            "file.appears",
            "file.disappears",
            "file.renames",
            "file.permissions_change",
            "file.integrity_breaks",
        ] {
            let intent = body.intents.iter().find(|i| i.name == name).unwrap();
            assert_eq!(intent.state, "applicable", "{name}: {:?}", intent.reason);
        }
        assert_eq!(body.applicable, 8);
    }

    #[test]
    fn an_intent_no_source_feeds_to_the_rules_is_not_applicable_even_when_hooked() {
        let mut host = HostSources::new(Some((6, 12)));
        for source in [Source::ProcessTracing, Source::SocketAttribution] {
            host = host.present(source);
        }
        let body = intents_body(&host);
        let connects = body
            .intents
            .iter()
            .find(|i| i.name == "process.connects")
            .unwrap();
        assert_eq!(connects.state, "not_applicable");
        assert_eq!(
            connects.reason.as_deref(),
            Some("no source in this build delivers `process.connects` events to host rules")
        );
    }

    fn service(json: &str) -> HostRuleService {
        let specs: Vec<domain::hostrule::HostRuleSpec> = serde_json::from_str(json).unwrap();
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        HostRuleService::new(domain::hostrule::HostRuleSet::compile(specs).unwrap(), tx)
    }

    #[test]
    fn each_rule_says_whether_this_host_can_match_it() {
        let service = service(
            r#"[{"id":"starts","severity":"HIGH","when":{"process.starts":{"uid":0}}},
                {"id":"either","when":{"any_of":[{"process.starts":{}},{"process.connects":{}}]}},
                {"id":"connects","then":["alert","kill_process"],"when":{"process.connects":{"remote_port":4444}}}]"#,
        );
        let host = HostSources::new(Some((6, 12))).present(Source::ProcessTracing);
        let body = rules_body(Some(&service), &host);
        let states: Vec<&str> = body.rules.iter().map(|r| r.state).collect();
        assert_eq!(
            states,
            vec!["applicable", "partially_applicable", "not_applicable"]
        );
        assert_eq!(body.rules[0].severity, "high");
        assert_eq!(body.rules[2].then, vec!["alert", "kill_process"]);
        assert_eq!(body.rules[0].spec["when"]["process.starts"]["uid"], 0);
        assert!(body.rules[2].intents[0].reason.is_some());
        assert_eq!((body.matched, body.dropped), (0, 0));
        assert_eq!((body.pending, body.pending_refused), (0, 0));
        assert_eq!((body.counting, body.counting_refused), (0, 0));
        assert_eq!(
            body.rules[0].mode, "shadow",
            "a rule is in shadow unless it says otherwise"
        );
        assert_eq!(body.rules[0].shadow.as_ref().map(|s| s.events), Some(0));
        assert_eq!(body.shadow_since_ns, service.shadow_since_ns());
    }

    #[test]
    fn a_rule_written_in_force_carries_no_reading() {
        let service = service(r#"[{"id":"loud","mode":"enforce","when":{"process.starts":{}}}]"#);
        let host = HostSources::new(Some((6, 12))).present(Source::ProcessTracing);
        let body = rules_body(Some(&service), &host);
        assert_eq!(body.rules[0].mode, "enforce");
        assert!(body.rules[0].shadow.is_none());
    }

    #[test]
    fn no_service_is_no_rule() {
        let body = rules_body(None, &HostSources::new(None));
        assert!(body.rules.is_empty());
    }

    #[test]
    fn a_program_that_did_not_load_is_named() {
        let mut programs = std::collections::HashMap::new();
        programs.insert("tc-dns".to_string(), false);
        let host = program(
            HostSources::new(None),
            Source::DnsCapture,
            &programs,
            "tc-dns",
        );
        assert_eq!(
            host.sources.get(&Source::DnsCapture),
            Some(&Err("tc-dns did not load".to_string()))
        );
        let host = program(host, Source::TlsCapture, &programs, "tc-ids");
        assert_eq!(
            host.sources.get(&Source::TlsCapture),
            Some(&Err("tc-ids is not configured".to_string()))
        );
    }
}
