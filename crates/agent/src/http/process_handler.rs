//! What the node's processes are, as the exec and exit tracepoints saw them.
//!
//! The table is attribution and never enforcement: it answers what a pid is,
//! and nothing on these routes stops, signals or changes a process. A pid is
//! in the answer from the exec that created it to the exit that ended it, so
//! a listing is the set of processes alive on the node and not a history of
//! what ran.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use super::error::{ApiError, ErrorBody};
use super::state::AppState;

// ── Response DTOs ─────────────────────────────────────────────────

/// What the agent can say about the two tracepoints behind the table.
#[derive(Serialize, ToSchema)]
pub struct ProcessTracingResponse {
    /// Every tracepoint is attached and the table is being filled.
    pub attached: bool,
    /// The tracepoints that did attach, in attach order.
    pub tracepoints: Vec<String>,
    /// Why the table is empty or stale, in one sentence. `None` when
    /// everything attached.
    pub reason: Option<String>,
    /// Command lines are being kept. Off by default: an argument vector
    /// carries secrets often enough that keeping it is a decision.
    pub command_line: bool,
    /// The kernel reads each process's parent and start time, and forks are
    /// followed. False on a kernel whose BTF does not describe the fields,
    /// where the parent comes from `/proc` once the process is seen.
    pub lineage: bool,
    /// Why the kernel does not read the parent, in one sentence.
    pub lineage_reason: Option<String>,
}

/// The bound and what it cost, so a reader can tell an empty table from a
/// full one shedding its oldest entry.
#[derive(Serialize, ToSchema)]
pub struct ProcessTableStatsResponse {
    pub capacity: usize,
    pub entries: usize,
    pub recorded: u64,
    pub replaced: u64,
    pub evicted: u64,
    pub purged: u64,
    pub missing_exit: u64,
    /// Forks recorded, each a process that had not exec'd yet.
    pub forks: u64,
    /// Exited processes kept because something they started still runs.
    pub ancestors: usize,
    /// The ceiling on those, a quarter of `capacity`.
    pub ancestor_capacity: usize,
    /// Exited ancestors dropped at that ceiling. Nonzero means some chains
    /// end early.
    pub ancestors_evicted: u64,
}

/// One ancestor of a process, live or exited.
#[derive(Serialize, ToSchema)]
pub struct ProcessAncestorResponse {
    pub pid: u32,
    /// When it started, on the agent's boot clock. With the pid, the name a
    /// reused pid cannot take.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_ns: Option<u64>,
    pub comm: String,
    pub identity: ProcessIdentityResponse,
    pub uid: u32,
    /// When it exited, for an ancestor kept after its exit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exited_at_ns: Option<u64>,
}

/// The chain above a process, parent first.
#[derive(Serialize, ToSchema)]
pub struct ProcessAncestryResponse {
    /// At most eight, parent first.
    pub ancestors: Vec<ProcessAncestorResponse>,
    /// The chain stops at an ancestor that was named and that the table no
    /// longer holds, rather than at the root.
    pub incomplete: bool,
    /// The chain goes on past the eighth ancestor and was cut there.
    pub truncated: bool,
}

/// What the table knows a process by. `kind` is `path` or `unknown`, and a
/// path may carry the digest of the file it named beside it.
#[derive(Serialize, ToSchema)]
pub struct ProcessIdentityResponse {
    /// `path` or `unknown`.
    pub kind: String,
    /// The executable path, where the identity carries one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Digest of the file behind the path: `fsverity-sha256:<hex>` where the
    /// kernel measured a file with fs-verity on, `sha256:<hex>` where the
    /// agent read its contents. Absent where the file could not be opened,
    /// which a rootless agent cannot do for another user's process.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exe_hash: Option<String>,
}

/// The container a process runs in, where it runs in one. Absent means the
/// host, which is why the field is omitted rather than filled with a name.
#[derive(Serialize, ToSchema)]
pub struct ProcessContainerResponse {
    pub id: String,
    /// `docker`, `containerd`, `crio`, `podman` or `unknown`.
    pub runtime: String,
    /// The container name an enricher resolved, or the namespaced pod name
    /// under Kubernetes. Absent when no enricher answered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The image, where the enricher that answered carries one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
}

/// One row of the table.
#[derive(Serialize, ToSchema)]
pub struct ProcessEntryResponse {
    pub pid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_pid: Option<u32>,
    pub comm: String,
    pub identity: ProcessIdentityResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
    pub uid: u32,
    pub gid: u32,
    pub cgroup_id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container: Option<ProcessContainerResponse>,
    /// When the exec, or the fork for a process that has not exec'd, was
    /// seen, in nanoseconds since the Unix epoch.
    pub started_at_ns: u64,
    /// When the process started, on the kernel's boot clock: an identity
    /// that tells this process apart from a later one given its pid.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_ns: Option<u64>,
    /// When the parent started, read in the kernel with its pid.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_start_ns: Option<u64>,
    /// The ancestors, on the single-process route only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ancestry: Option<ProcessAncestryResponse>,
}

/// `GET /api/v1/processes`.
#[derive(Serialize, ToSchema)]
pub struct ProcessListResponse {
    pub tracing: ProcessTracingResponse,
    pub stats: ProcessTableStatsResponse,
    /// Newest first, so a reader watching a node sees what just started.
    pub processes: Vec<ProcessEntryResponse>,
}

// ── Mapping ───────────────────────────────────────────────────────

fn tracing_response() -> ProcessTracingResponse {
    let status = adapters::ebpf::process_attach::status();
    ProcessTracingResponse {
        attached: status.attached,
        tracepoints: status.tracepoints,
        reason: status.reason,
        command_line: status.command_line,
        lineage: status.lineage,
        lineage_reason: status.lineage_reason,
    }
}

fn stats_response(stats: &domain::process::entity::ProcessTableStats) -> ProcessTableStatsResponse {
    ProcessTableStatsResponse {
        capacity: stats.capacity,
        entries: stats.entries,
        recorded: stats.recorded,
        replaced: stats.replaced,
        evicted: stats.evicted,
        purged: stats.purged,
        missing_exit: stats.missing_exit,
        forks: stats.forks,
        ancestors: stats.ancestors,
        ancestor_capacity: stats.ancestor_capacity,
        ancestors_evicted: stats.ancestors_evicted,
    }
}

fn identity_response(entry: &domain::process::entity::ProcessEntry) -> ProcessIdentityResponse {
    ProcessIdentityResponse {
        kind: entry.identity.kind().to_string(),
        path: entry.identity.path().map(ToString::to_string),
        exe_hash: entry.exe_hash.map(|hash| hash.to_string()),
    }
}

fn ancestry_response(lineage: &domain::process::engine::Lineage) -> ProcessAncestryResponse {
    ProcessAncestryResponse {
        ancestors: lineage
            .ancestors
            .iter()
            .map(|a| ProcessAncestorResponse {
                pid: a.pid,
                start_ns: a.start_ns,
                comm: a.comm.clone(),
                identity: identity_response(a),
                uid: a.uid,
                exited_at_ns: a.exited_at_ns,
            })
            .collect(),
        incomplete: lineage.incomplete,
        truncated: lineage.truncated,
    }
}

fn entry_response(entry: &domain::process::entity::ProcessEntry) -> ProcessEntryResponse {
    ProcessEntryResponse {
        pid: entry.pid,
        parent_pid: entry.parent_pid,
        comm: entry.comm.clone(),
        identity: identity_response(entry),
        command_line: entry.command_line.clone(),
        uid: entry.uid,
        gid: entry.gid,
        cgroup_id: entry.cgroup_id,
        container: entry.container.as_ref().and_then(container_response),
        started_at_ns: entry.started_at_ns,
        start_ns: entry.start_ns,
        parent_start_ns: entry.parent_start_ns,
        ancestry: None,
    }
}

/// The container block, where the context names a container. A host
/// context produces none: the field means there is a container, so filling
/// it with the host would make every process look containerised.
fn container_response(
    ctx: &domain::container::entity::ContainerContext,
) -> Option<ProcessContainerResponse> {
    use domain::container::entity::ContainerMetadata;

    let id = ctx.info.container_id()?.to_string();
    let (name, image) = match ctx.metadata.as_ref() {
        Some(ContainerMetadata::Docker(d)) => (
            (!d.name.is_empty()).then(|| d.name.clone()),
            (!d.image.is_empty()).then(|| d.image.clone()),
        ),
        Some(ContainerMetadata::Kubernetes(k)) => {
            (Some(format!("{}/{}", k.namespace, k.pod_name)), None)
        }
        _ => (None, None),
    };
    Some(ProcessContainerResponse {
        id,
        runtime: ctx.info.runtime().to_string(),
        name,
        image,
    })
}

/// The table, or the 503 that says why there is none.
fn table(
    state: &AppState,
) -> Result<Arc<application::process_table_service::ProcessTableService>, ApiError> {
    state
        .process_table_service
        .load_full()
        .ok_or_else(|| ApiError::ServiceUnavailable {
            message: "the process table is not running on this agent".to_string(),
        })
}

// ── Handlers ──────────────────────────────────────────────────────

/// What a listing may be narrowed to.
#[derive(Debug, Default, Deserialize, IntoParams)]
pub struct ProcessListQuery {
    /// Only the processes whose executable is this path, compared exactly.
    /// A process whose executable could not be read never matches.
    pub exe: Option<String>,
}

/// The entries a listing answers with, narrowed to one executable path
/// where the request names one.
fn listed(
    entries: &[domain::process::entity::ProcessEntry],
    exe: Option<&str>,
) -> Vec<ProcessEntryResponse> {
    entries
        .iter()
        .filter(|entry| exe.is_none_or(|exe| entry.identity.path() == Some(exe)))
        .map(entry_response)
        .collect()
}

/// `GET /api/v1/processes` - the processes alive on this node.
#[utoipa::path(
    get, path = "/api/v1/processes",
    tag = "Processes",
    params(ProcessListQuery),
    responses(
        (status = 200, description = "The process table", body = ProcessListResponse),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
        (status = 503, description = "The process table is not running", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn list_processes(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ProcessListQuery>,
) -> Result<Json<ProcessListResponse>, ApiError> {
    let svc = table(&state)?;
    let processes = listed(&svc.list(), query.exe.as_deref());
    Ok(Json(ProcessListResponse {
        tracing: tracing_response(),
        stats: stats_response(&svc.stats()),
        processes,
    }))
}

/// `GET /api/v1/processes/{pid}` - one process, by pid.
#[utoipa::path(
    get, path = "/api/v1/processes/{pid}",
    tag = "Processes",
    params(("pid" = u32, Path, description = "Process id")),
    responses(
        (status = 200, description = "The process", body = ProcessEntryResponse),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
        (status = 404, description = "No such process in the table", body = ErrorBody),
        (status = 503, description = "The process table is not running", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn get_process(
    State(state): State<Arc<AppState>>,
    Path(pid): Path<u32>,
) -> Result<Json<ProcessEntryResponse>, ApiError> {
    let svc = table(&state)?;
    // An exited process leaves the live table, so a pid the table does not
    // carry is a pid that is gone and not a lookup that failed. Its entry
    // survives only as somebody's ancestor, which is where it is shown.
    let entry = svc.get(pid).ok_or_else(|| ApiError::NotFound {
        code: "process_not_found",
        message: format!("no process {pid} in the table"),
    })?;
    let mut body = entry_response(&entry);
    body.ancestry = Some(ancestry_response(&svc.lineage(pid)));
    Ok(Json(body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::process::entity::{ProcessEntry, ProcessIdentity};

    #[test]
    fn an_entry_with_a_path_says_so_and_carries_it() {
        let mut entry = ProcessEntry::new(42, "curl", 7);
        entry.identity = ProcessIdentity::Path {
            path: "/usr/bin/curl".to_string(),
            dev: 1,
            inode: 2,
        };
        let json = serde_json::to_value(entry_response(&entry)).unwrap();
        assert_eq!(json["identity"]["kind"], "path");
        assert_eq!(json["identity"]["path"], "/usr/bin/curl");
        assert_eq!(json["pid"], 42);
    }

    #[test]
    fn a_listing_narrowed_to_an_executable_keeps_only_that_path() {
        let with_path = |pid, path: &str| {
            let mut entry = ProcessEntry::new(pid, "x", 0);
            entry.identity = ProcessIdentity::Path {
                path: path.to_string(),
                dev: 1,
                inode: u64::from(pid),
            };
            entry
        };
        let entries = vec![
            with_path(1, "/usr/bin/curl"),
            with_path(2, "/usr/bin/bash"),
            ProcessEntry::new(3, "gone", 0),
            with_path(4, "/usr/bin/curl"),
        ];
        let pids = |rows: Vec<ProcessEntryResponse>| rows.iter().map(|r| r.pid).collect::<Vec<_>>();
        assert_eq!(pids(listed(&entries, Some("/usr/bin/curl"))), vec![1, 4]);
        assert_eq!(
            pids(listed(&entries, Some("/usr/bin/cur"))),
            Vec::<u32>::new()
        );
        assert_eq!(pids(listed(&entries, None)), vec![1, 2, 3, 4]);
    }

    #[test]
    fn a_host_process_carries_no_container_block_and_no_command_line() {
        let entry = ProcessEntry::new(1, "init", 0);
        let json = serde_json::to_value(entry_response(&entry)).unwrap();
        assert_eq!(json["identity"]["kind"], "unknown");
        assert!(json.get("container").is_none());
        assert!(json.get("command_line").is_none());
        assert!(json.get("parent_pid").is_none());
    }

    #[test]
    fn the_stats_body_carries_every_counter_the_table_keeps() {
        let stats = domain::process::entity::ProcessTableStats {
            capacity: 8,
            entries: 2,
            recorded: 5,
            replaced: 1,
            evicted: 2,
            purged: 1,
            missing_exit: 3,
            forks: 4,
            ancestors: 1,
            ancestor_capacity: 2,
            ancestors_evicted: 6,
        };
        let json = serde_json::to_value(stats_response(&stats)).unwrap();
        assert_eq!(json["capacity"], 8);
        assert_eq!(json["entries"], 2);
        assert_eq!(json["recorded"], 5);
        assert_eq!(json["replaced"], 1);
        assert_eq!(json["evicted"], 2);
        assert_eq!(json["purged"], 1);
        assert_eq!(json["missing_exit"], 3);
        assert_eq!(json["forks"], 4);
        assert_eq!(json["ancestors"], 1);
        assert_eq!(json["ancestor_capacity"], 2);
        assert_eq!(json["ancestors_evicted"], 6);
    }

    #[test]
    fn an_ancestry_names_exited_ancestors_and_a_lost_link() {
        let mut shell = ProcessEntry::new(10, "sh", 5);
        shell.start_ns = Some(4);
        shell.exited_at_ns = Some(9);
        let body = ancestry_response(&domain::process::engine::Lineage {
            ancestors: vec![shell],
            truncated: false,
            incomplete: true,
        });
        let json = serde_json::to_value(body).unwrap();
        assert_eq!(json["ancestors"][0]["pid"], 10);
        assert_eq!(json["ancestors"][0]["exited_at_ns"], 9);
        assert_eq!(json["incomplete"], true);
        assert_eq!(json["truncated"], false);
    }

    #[test]
    fn a_listed_entry_carries_no_ancestry() {
        let json = serde_json::to_value(entry_response(&ProcessEntry::new(1, "init", 0))).unwrap();
        assert!(json.get("ancestry").is_none());
    }
}
