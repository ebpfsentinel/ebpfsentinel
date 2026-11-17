//! How a run starts, ends and is stopped, and the unit that keeps it running.
//!
//! The stop command is the documented way to stop a host agent: it records who
//! asked and why, then ends the agent with [`STOP_EXIT_CODE`], which the units
//! treat as final where every other exit is restarted. Shared with the
//! enterprise layer, which calls the same pieces from its own boot.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use adapters::lifecycle::{RUN_RECORD_FILE, RunJournal};
use application::alert_event::AlertEvent;
use domain::alert::entity::Alert;
pub use domain::lifecycle::STOP_EXIT_CODE;
use domain::lifecycle::{EndCause, PreviousRun};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

/// How often the unit files are compared with the ones the agent started
/// under.
pub const UNIT_CHECK_INTERVAL: Duration = Duration::from_secs(30);

/// How long a stop waits before ending the agent, for its answer to leave.
const STOP_GRACE: Duration = Duration::from_millis(500);

/// Set once the stop command was accepted, read by `main` for the exit status.
static STOP_COMMANDED: AtomicBool = AtomicBool::new(false);

/// Whether this run is ending on its own stop command.
#[must_use]
pub fn stop_commanded() -> bool {
    STOP_COMMANDED.load(Ordering::SeqCst)
}

fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}

/// Open this run's record beside `audit_storage_path`, the way the instance
/// lock sits, and say how the previous run ended.
#[must_use]
pub fn open_journal(audit_storage_path: &str) -> (Arc<RunJournal>, PreviousRun) {
    let path = Path::new(audit_storage_path).with_file_name(RUN_RECORD_FILE);
    let (journal, previous) = RunJournal::open(path, &adapters::lifecycle::boot_id());
    (Arc::new(journal), previous)
}

/// Log how the previous run ended, and raise it when nobody accounted for
/// it.
pub async fn report_previous(previous: &PreviousRun, alerts: &mpsc::Sender<AlertEvent>) {
    match previous {
        PreviousRun::Unknown | PreviousRun::HostShutdown | PreviousRun::Commanded(_) => {
            info!("{}", previous.message());
        }
        PreviousRun::Failed(_) | PreviousRun::Signalled(_) | PreviousRun::Unrecorded { .. } => {
            warn!("{}", previous.message());
        }
    }
    if let Some(alert) = previous.alert(now_ns()) {
        let _ = alerts.send(AlertEvent::System(Box::new(alert))).await;
    }
}

/// Complete the record of a run that ends without its stop command, which
/// leaves a signal as the only thing that could have ended it in order.
pub fn record_end(journal: &RunJournal) {
    journal.finish(EndCause::Signal, None, None);
}

/// Holds the run's record for the whole run: a run that leaves early on an
/// error records a failure when this drops, and a run that ended in order
/// already recorded how, which the drop then leaves alone.
#[derive(Debug)]
pub struct RunGuard(pub Arc<RunJournal>);

impl Drop for RunGuard {
    fn drop(&mut self) {
        self.0.finish(EndCause::Failure, None, None);
    }
}

/// The stop command's side: records the request, then ends the run.
#[derive(Debug)]
pub struct LocalStop {
    journal: Arc<RunJournal>,
    stop: CancellationToken,
}

impl LocalStop {
    #[must_use]
    pub fn new(journal: Arc<RunJournal>, stop: CancellationToken) -> Self {
        Self { journal, stop }
    }

    /// Record the stop and end the agent once the answer had time to leave.
    pub fn request(&self, requested_by: Option<&str>, reason: Option<&str>) {
        self.journal.finish(EndCause::Command, requested_by, reason);
        STOP_COMMANDED.store(true, Ordering::SeqCst);
        warn!(
            requested_by = requested_by.unwrap_or("unknown"),
            reason = reason.unwrap_or(""),
            "stop requested through the API; the agent ends and stays stopped"
        );
        let stop = self.stop.clone();
        tokio::spawn(async move {
            tokio::time::sleep(STOP_GRACE).await;
            stop.cancel();
        });
    }
}

/// Watch the agent's unit files and raise a mask or an edit. Does nothing
/// outside a systemd service.
pub fn spawn_unit_watch(alerts: mpsc::Sender<AlertEvent>, cancel: CancellationToken) {
    let Some(unit) = adapters::lifecycle::own_unit() else {
        info!("not running as a systemd service; the unit watch is off");
        return;
    };
    let units = adapters::lifecycle::watched_units(&unit);
    let mut baseline = adapters::lifecycle::system_unit_fingerprint(&units);
    info!(
        unit = %unit,
        files = baseline.len(),
        "watching the service unit for a mask or an edit"
    );
    if let Some(mask) = baseline.masks().next() {
        warn!(path = %mask, "the agent's unit is already masked at start: it will not come back after its next stop");
        let _ = alerts.try_send(AlertEvent::System(Box::new(Alert::operational(
            domain::lifecycle::AGENT_LIFECYCLE_COMPONENT,
            domain::lifecycle::RULE_UNIT_MASKED,
            domain::common::entity::Severity::High,
            format!(
                "the agent's service unit is masked at start by {mask}: the next stop keeps it down"
            ),
            now_ns(),
        ))));
    }
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(UNIT_CHECK_INTERVAL);
        tick.tick().await;
        loop {
            tokio::select! {
                () = cancel.cancelled() => return,
                _ = tick.tick() => {}
            }
            let current = adapters::lifecycle::system_unit_fingerprint(&units);
            if let Some(tamper) = current.compare(&baseline) {
                warn!("{}", tamper.message());
                if alerts
                    .send(AlertEvent::System(Box::new(tamper.alert(now_ns()))))
                    .await
                    .is_err()
                {
                    return;
                }
                baseline = current;
            }
        }
    });
}
