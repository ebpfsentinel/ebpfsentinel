use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use domain::hostrule::{Applicability, HostSources, Intent, Source, resolve};
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

    {
        let programs = state.ebpf_program_status.read().await;
        host = program(host, Source::DnsCapture, &programs, "tc-dns");
        host = program(host, Source::TlsCapture, &programs, "tc-ids");
    }

    host = if state.network_programs.load().is_some() {
        host.present(Source::NetworkProgramInventory)
    } else {
        host.absent(
            Source::NetworkProgramInventory,
            "the network program inventory is not reading",
        )
    };
    host = if state.raw_sockets.load().is_some() {
        host.present(Source::RawSocketInventory)
    } else {
        host.absent(
            Source::RawSocketInventory,
            "the packet socket inventory is not reading",
        )
    };

    for source in [
        Source::FileWatch,
        Source::HiddenProcessScan,
        Source::HiddenPortScan,
        Source::PackageInventory,
    ] {
        host = host.absent(source, NOT_IN_THIS_BUILD);
    }
    host
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

fn program(
    host: HostSources,
    source: Source,
    programs: &std::collections::HashMap<String, bool>,
    name: &str,
) -> HostSources {
    match programs.get(name) {
        Some(true) => host.present(source),
        Some(false) => host.absent(source, format!("{name} did not load")),
        None => host.absent(source, format!("{name} is not configured")),
    }
}

fn intents_body(host: &HostSources) -> HostIntentsResponse {
    let intents: Vec<IntentBody> = Intent::ALL
        .into_iter()
        .map(|intent| {
            let binding = intent.binding();
            let (state, reason) = match resolve(intent, host) {
                Applicability::Applicable => ("applicable", None),
                Applicability::NotApplicable { reason } => ("not_applicable", Some(reason)),
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

#[cfg(test)]
mod tests {
    use super::*;

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
            .absent(Source::FileWatch, NOT_IN_THIS_BUILD);
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
            Some("file_watch: no source for it is part of this build")
        );
        assert_eq!(body.applicable, 2);
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
