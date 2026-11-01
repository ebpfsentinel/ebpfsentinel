use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use domain::hidden::{HiddenProcess, ProcessSweepCounts};
use serde::Serialize;
use utoipa::ToSchema;

use super::error::ErrorBody;
use super::state::AppState;

/// One process that answers a signal and that `/proc` does not list.
#[derive(Debug, Serialize, ToSchema)]
pub struct HiddenProcessBody {
    pub pid: u32,
    /// The command name, where its `/proc` entry could be read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comm: Option<String>,
}

/// How the last sweep reached its result.
#[derive(Debug, Default, Serialize, ToSchema)]
pub struct HiddenProcessCountsBody {
    /// The pid space swept, `pid_max`.
    pub pid_space: u32,
    /// Pids signalled.
    pub probed: u32,
    /// Thread groups the first listing of `/proc` held.
    pub listed: u32,
    /// Pids that answered and were not listed as a thread group.
    pub answered_unlisted: u32,
    /// Of those, threads of a listed group.
    pub explained_by_thread: u32,
    /// Thread groups on their way out.
    pub explained_by_exit: u32,
    /// Pids gone by the second signal, or listed by the second listing.
    pub unconfirmed: u32,
    /// Pids that changed hands between the two observations.
    pub reused: u32,
    /// Processes reported hidden.
    pub hidden: u32,
}

impl From<ProcessSweepCounts> for HiddenProcessCountsBody {
    fn from(c: ProcessSweepCounts) -> Self {
        Self {
            pid_space: c.pid_space,
            probed: c.probed,
            listed: c.listed,
            answered_unlisted: c.answered_unlisted,
            explained_by_thread: c.explained_by_thread,
            explained_by_exit: c.explained_by_exit,
            unconfirmed: c.unconfirmed,
            reused: c.reused,
            hidden: c.hidden,
        }
    }
}

/// The last comparison of the listing of `/proc` with a signal sweep.
#[derive(Debug, Serialize, ToSchema)]
pub struct HiddenProcessesResponse {
    /// Whether the sweep runs.
    pub reading: bool,
    /// Where the readings come from: `warden` or `local`. Absent when the
    /// sweep is off.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<&'static str>,
    /// The pace asked for, in pids a second.
    pub pids_per_second: u32,
    /// When the last sweep was made, in nanoseconds since the epoch, `0`
    /// before the first.
    pub scanned_at_ns: u64,
    /// Why the last sweep failed or was not taken. The result is then the
    /// sweep before.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    pub counts: HiddenProcessCountsBody,
    pub hidden: Vec<HiddenProcessBody>,
}

fn body(process: &HiddenProcess) -> HiddenProcessBody {
    HiddenProcessBody {
        pid: process.pid,
        comm: process.comm.clone(),
    }
}

/// `GET /api/v1/ebpf/hidden-processes` - pids that answer a signal and that
/// `/proc` does not list.
#[utoipa::path(
    get, path = "/api/v1/ebpf/hidden-processes",
    tag = "Operations",
    responses((status = 200, description = "The last comparison of the listing of /proc with a signal sweep, with what explained each unlisted pid", body = HiddenProcessesResponse),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn get_hidden_processes(
    State(state): State<Arc<AppState>>,
) -> Json<HiddenProcessesResponse> {
    let Some(watcher) = state.hidden_processes.load_full() else {
        return Json(HiddenProcessesResponse {
            reading: false,
            source: None,
            pids_per_second: 0,
            scanned_at_ns: 0,
            last_error: None,
            counts: HiddenProcessCountsBody::default(),
            hidden: Vec::new(),
        });
    };
    let report = watcher.report();
    Json(HiddenProcessesResponse {
        reading: true,
        source: Some(watcher.source()),
        pids_per_second: watcher.rate(),
        scanned_at_ns: report.scanned_at_ns,
        last_error: report.error.clone(),
        counts: report.sweep.counts.into(),
        hidden: report.sweep.hidden.iter().map(body).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hidden_process_names_its_pid_and_command() {
        let b = body(&HiddenProcess {
            pid: 4242,
            comm: Some("implant".into()),
        });
        assert_eq!((b.pid, b.comm.as_deref()), (4242, Some("implant")));
    }

    #[test]
    fn the_counts_carry_over_one_for_one() {
        let counts = ProcessSweepCounts {
            pid_space: 32_768,
            explained_by_thread: 40,
            reused: 1,
            hidden: 1,
            ..ProcessSweepCounts::default()
        };
        let b = HiddenProcessCountsBody::from(counts);
        assert_eq!(
            (b.pid_space, b.explained_by_thread, b.reused, b.hidden),
            (32_768, 40, 1, 1)
        );
    }
}
