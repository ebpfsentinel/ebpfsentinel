//! What the node's processes are, as the exec and exit tracepoints saw them.
//!
//! The table is attribution and never enforcement: it answers what a pid is,
//! and nothing on these routes stops, signals or changes a process. A pid is
//! in the answer from the exec that created it to the exit that ended it, so
//! a listing is the set of processes alive on the node and not a history of
//! what ran.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use serde::Serialize;
use utoipa::ToSchema;

use super::error::{ApiError, ErrorBody};
use super::state::AppState;

// ── Response DTOs ─────────────────────────────────────────────────

/// What the agent can say about the two tracepoints behind the table.
#[derive(Serialize, ToSchema)]
pub struct ProcessTracingResponse {
    /// Both tracepoints are attached and the table is being filled.
    pub attached: bool,
    /// The tracepoints that did attach, in attach order.
    pub tracepoints: Vec<String>,
    /// Why the table is empty or stale, in one sentence. `None` when
    /// everything attached.
    pub reason: Option<String>,
    /// Command lines are being kept. Off by default: an argument vector
    /// carries secrets often enough that keeping it is a decision.
    pub command_line: bool,
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
}

/// What the table knows a process by. `kind` is `path` or `unknown`; the
/// hash of the executable is not computed yet, and when it is it arrives as
/// a third kind rather than as a field nobody can tell apart from absent.
#[derive(Serialize, ToSchema)]
pub struct ProcessIdentityResponse {
    /// `path` or `unknown`.
    pub kind: String,
    /// The executable path, where the identity carries one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
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
    pub started_at_ns: u64,
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
    }
}

fn entry_response(entry: &domain::process::entity::ProcessEntry) -> ProcessEntryResponse {
    ProcessEntryResponse {
        pid: entry.pid,
        parent_pid: entry.parent_pid,
        comm: entry.comm.clone(),
        identity: ProcessIdentityResponse {
            kind: entry.identity.kind().to_string(),
            path: entry.identity.path().map(ToString::to_string),
        },
        command_line: entry.command_line.clone(),
        uid: entry.uid,
        gid: entry.gid,
        cgroup_id: entry.cgroup_id,
        container: entry.container.as_ref().and_then(container_response),
        started_at_ns: entry.started_at_ns,
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

/// `GET /api/v1/processes` - the processes alive on this node.
#[utoipa::path(
    get, path = "/api/v1/processes",
    tag = "Processes",
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
) -> Result<Json<ProcessListResponse>, ApiError> {
    let svc = table(&state)?;
    let processes = svc.list().iter().map(entry_response).collect();
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
    // An exited process is purged rather than kept, so a pid the table does
    // not carry is a pid that is gone and not a lookup that failed.
    svc.get(pid)
        .map(|entry| Json(entry_response(&entry)))
        .ok_or_else(|| ApiError::NotFound {
            code: "process_not_found",
            message: format!("no process {pid} in the table"),
        })
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
        };
        let json = serde_json::to_value(stats_response(&stats)).unwrap();
        assert_eq!(json["capacity"], 8);
        assert_eq!(json["entries"], 2);
        assert_eq!(json["recorded"], 5);
        assert_eq!(json["replaced"], 1);
        assert_eq!(json["evicted"], 2);
        assert_eq!(json["purged"], 1);
        assert_eq!(json["missing_exit"], 3);
    }
}
