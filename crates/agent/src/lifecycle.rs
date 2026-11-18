//! How a run starts, ends and is stopped, and the unit that keeps it running.
//!
//! The stop command is the documented way to stop a host agent: it records who
//! asked and why, then ends the agent with [`STOP_EXIT_CODE`], which the units
//! treat as final where every other exit is restarted. A container runtime
//! restarts on every exit status alike and cannot be told to keep one down, so
//! outside a systemd unit the command arms the stop instead: the runtime's own
//! stop, arriving inside the window, is recorded as the one asked for, and a
//! stop nobody asked for stays a signal the next start raises. Shared with the
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

/// How long an armed stop waits for the container runtime's own stop.
pub const ARMED_STOP_WINDOW: Duration = Duration::from_secs(300);

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
///
/// A signal inside an armed stop's window is that stop: the run ends with
/// [`STOP_EXIT_CODE`] as a unit's would, so whatever reads the container's
/// exit status, a kubelet and the operator reading it after, tells it from a
/// stop nobody authorised.
pub fn record_end(journal: &RunJournal) {
    match journal.armed() {
        Some((requested_by, reason)) => {
            journal.finish(
                EndCause::Command,
                requested_by.as_deref(),
                reason.as_deref(),
            );
            STOP_COMMANDED.store(true, Ordering::SeqCst);
        }
        None => journal.finish(EndCause::Signal, None, None),
    }
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

/// What the stop command did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopOutcome {
    /// The agent is ending with [`STOP_EXIT_CODE`].
    Stopping,
    /// The agent keeps running: the supervisor's own stop, inside `window`,
    /// is recorded as this one.
    Armed { window: Duration },
}

/// The stop command's side: records the request, then ends the run, or arms
/// it where the supervisor would only start the agent again.
#[derive(Debug)]
pub struct LocalStop {
    journal: Arc<RunJournal>,
    stop: CancellationToken,
    under_unit: bool,
}

impl LocalStop {
    /// Ends the agent itself under a systemd unit, which honours the stop
    /// status, and arms the stop anywhere else.
    #[must_use]
    pub fn new(journal: Arc<RunJournal>, stop: CancellationToken) -> Self {
        let under_unit = adapters::lifecycle::own_unit().is_some();
        Self {
            journal,
            stop,
            under_unit,
        }
    }

    /// The same, with the supervisor stated rather than read off the cgroup.
    #[must_use]
    pub fn under_unit(mut self, under_unit: bool) -> Self {
        self.under_unit = under_unit;
        self
    }

    /// Record the stop and end the agent once the answer had time to leave,
    /// or arm it for [`ARMED_STOP_WINDOW`] outside a unit.
    pub fn request(&self, requested_by: Option<&str>, reason: Option<&str>) -> StopOutcome {
        self.request_within(requested_by, reason, ARMED_STOP_WINDOW)
    }

    /// [`Self::request`] with the window an armed stop is held for.
    pub fn request_within(
        &self,
        requested_by: Option<&str>,
        reason: Option<&str>,
        window: Duration,
    ) -> StopOutcome {
        if !self.under_unit {
            self.journal.arm(requested_by, reason, window);
            warn!(
                requested_by = requested_by.unwrap_or("unknown"),
                reason = reason.unwrap_or(""),
                window_secs = window.as_secs(),
                "stop requested through the API; outside a service unit the agent keeps running until its container is stopped, which is recorded as this stop"
            );
            return StopOutcome::Armed { window };
        }
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
        StopOutcome::Stopping
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
    let masked_at_start = baseline.masks().next().map(|mask| {
        warn!(path = %mask, "the agent's unit is already masked at start: it will not come back after its next stop");
        AlertEvent::System(Box::new(Alert::operational(
            domain::lifecycle::AGENT_LIFECYCLE_COMPONENT,
            domain::lifecycle::RULE_UNIT_MASKED,
            domain::common::entity::Severity::High,
            format!(
                "the agent's service unit is masked at start by {mask}: the next stop keeps it down"
            ),
            now_ns(),
        )))
    });
    tokio::spawn(async move {
        // Sent on the watch's own task, which may wait for room: a start busy
        // enough to fill the alert channel is no reason to lose this one.
        if let Some(alert) = masked_at_start {
            let _ = alerts.send(alert).await;
        }
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
