use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use domain::alert::entity::Alert;
use domain::hidden::{HiddenProcess, ProcessSweep, sweep_processes};
use domain::hostrule::{FieldValue, HostRuleError, Intent, IntentEvent};
use ports::secondary::hidden_process_port::HiddenProcessReader;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::alert_event::AlertEvent;
use crate::host_rule_service::HostRuleService;
use crate::learning_service::now_ns;

/// The sweep as of the last reading.
#[derive(Debug, Clone, Default)]
pub struct HiddenProcessReport {
    pub sweep: ProcessSweep,
    /// When the last reading was made, `0` before the first.
    pub scanned_at_ns: u64,
    /// Why the last reading failed; the sweep is then the one before.
    pub error: Option<String>,
}

/// The `process.hidden` event of one finding: its pid and, where it could be
/// read, its command name.
fn process_event(hidden: &HiddenProcess) -> Result<IntentEvent, HostRuleError> {
    let event = IntentEvent::new(Intent::ProcessHidden)
        .with("pid", FieldValue::Integer(i64::from(hidden.pid)))?;
    match &hidden.comm {
        Some(comm) => event.with("comm", FieldValue::Text(comm.clone())),
        None => Ok(event),
    }
}

/// Compares the listing of `/proc` with a null signal across the pid space
/// on an interval.
pub struct HiddenProcessWatcher {
    reader: Arc<dyn HiddenProcessReader>,
    rate: u32,
    alerts: mpsc::Sender<AlertEvent>,
    report: ArcSwap<HiddenProcessReport>,
    host_rules: Option<Arc<HostRuleService>>,
}

impl HiddenProcessWatcher {
    #[must_use]
    pub fn new(
        reader: Arc<dyn HiddenProcessReader>,
        rate: u32,
        alerts: mpsc::Sender<AlertEvent>,
    ) -> Self {
        Self {
            reader,
            rate,
            alerts,
            report: ArcSwap::from_pointee(HiddenProcessReport::default()),
            host_rules: None,
        }
    }

    /// Hand each new finding to the host rules as well, as `process.hidden`.
    #[must_use]
    pub fn with_host_rules(mut self, host_rules: Arc<HostRuleService>) -> Self {
        self.host_rules = Some(host_rules);
        self
    }

    /// The sweep as of the last reading.
    #[must_use]
    pub fn report(&self) -> Arc<HiddenProcessReport> {
        self.report.load_full()
    }

    /// Where readings come from: `warden` or `local`.
    #[must_use]
    pub fn source(&self) -> &'static str {
        self.reader.source()
    }

    /// The pace asked for, in pids a second.
    #[must_use]
    pub fn rate(&self) -> u32 {
        self.rate
    }

    /// Sweep once, replace the report and alert on each hidden process the
    /// previous sweep did not report. Returns the number of alerts raised.
    pub async fn sample(self: &Arc<Self>) -> usize {
        let me = Arc::clone(self);
        let read = tokio::task::spawn_blocking(move || me.reader.read(me.rate)).await;
        let now = now_ns();
        let reading = match read {
            Ok(Ok(reading)) => reading,
            Ok(Err(err)) => {
                warn!(error = %err, "the pid space could not be swept");
                let previous = self.report.load_full();
                self.report.store(Arc::new(HiddenProcessReport {
                    sweep: previous.sweep.clone(),
                    scanned_at_ns: now,
                    error: Some(err.to_string()),
                }));
                return 0;
            }
            Err(err) => {
                warn!(error = %err, "hidden process sweep did not run");
                return 0;
            }
        };
        let sweep = sweep_processes(&reading);
        let previous = self.report.load_full();
        let before: BTreeSet<u32> = previous.sweep.hidden.iter().map(|h| h.pid).collect();
        let fresh: Vec<&HiddenProcess> = sweep
            .hidden
            .iter()
            .filter(|h| !before.contains(&h.pid))
            .collect();
        if let Some(rules) = &self.host_rules {
            for hidden in &fresh {
                match process_event(hidden) {
                    Ok(event) => rules.record_posture(&event, now),
                    Err(err) => warn!(error = %err, "hidden process not handed to the host rules"),
                }
            }
        }
        let events: Vec<AlertEvent> = fresh
            .into_iter()
            .map(|h| AlertEvent::System(Box::new(Alert::from_hidden_process(h, now))))
            .collect();
        self.report.store(Arc::new(HiddenProcessReport {
            sweep,
            scanned_at_ns: now,
            error: None,
        }));
        let raised = events.len();
        for event in events {
            if self.alerts.send(event).await.is_err() {
                debug!("alert pipeline closed, hidden process sweep stops sending");
                break;
            }
        }
        raised
    }

    /// Sweep on `interval` until `cancel` fires.
    pub async fn run(self: Arc<Self>, interval: Duration, cancel: CancellationToken) {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                () = cancel.cancelled() => {
                    debug!("hidden process sweep stopped");
                    break;
                }
                _ = ticker.tick() => {
                    self.sample().await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::common::error::DomainError;
    use domain::hidden::{PidObservation, ProcessReading};
    use std::sync::Mutex;

    type Reading = Result<ProcessReading, DomainError>;

    struct Scripted {
        readings: Mutex<Vec<Reading>>,
    }

    impl HiddenProcessReader for Scripted {
        fn read(&self, _rate: u32) -> Reading {
            let mut readings = self
                .readings
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if readings.is_empty() {
                Ok(ProcessReading::default())
            } else {
                readings.remove(0)
            }
        }

        fn source(&self) -> &'static str {
            "local"
        }
    }

    fn concealing(pid: u32) -> ProcessReading {
        let seen = PidObservation {
            pid,
            tgid: Some(pid),
            start_time: Some(900),
            state: Some('S'),
            comm: Some("implant".into()),
        };
        ProcessReading {
            pid_space: 32_768,
            probed: 32_767,
            listed: 100,
            first: vec![seen.clone()],
            second: vec![seen],
            ..ProcessReading::default()
        }
    }

    fn watcher(readings: Vec<Reading>) -> (Arc<HiddenProcessWatcher>, mpsc::Receiver<AlertEvent>) {
        let (tx, rx) = mpsc::channel(16);
        let reader = Arc::new(Scripted {
            readings: Mutex::new(readings),
        });
        (Arc::new(HiddenProcessWatcher::new(reader, 100_000, tx)), rx)
    }

    #[tokio::test]
    async fn a_hidden_process_alerts_once_while_it_stays_hidden() {
        let (watcher, mut rx) = watcher(vec![
            Ok(concealing(4242)),
            Ok(concealing(4242)),
            Ok(ProcessReading::default()),
            Ok(concealing(4242)),
        ]);
        assert_eq!(watcher.sample().await, 1);
        let Some(AlertEvent::System(alert)) = rx.recv().await else {
            panic!("expected a system alert");
        };
        assert_eq!(alert.component, "hidden_process");
        assert_eq!(alert.tgid, Some(4242));
        assert_eq!(watcher.sample().await, 0, "still hidden, already reported");
        assert_eq!(watcher.sample().await, 0);
        assert_eq!(
            watcher.sample().await,
            1,
            "hidden again after a clean sweep"
        );
        assert_eq!(watcher.rate(), 100_000);
    }

    #[tokio::test]
    async fn a_new_hidden_process_is_handed_to_the_host_rules_once() {
        let (tx, _rx) = mpsc::channel(16);
        let specs: Vec<domain::hostrule::HostRuleSpec> = serde_json::from_str(
            r#"[{"id":"shadowed","mode":"shadow","when":{"process.hidden":{"comm":"implant"}}}]"#,
        )
        .unwrap();
        let rules = Arc::new(HostRuleService::new(
            domain::hostrule::HostRuleSet::compile(specs).unwrap(),
            tx,
        ));
        let (alerts, mut rx) = mpsc::channel(16);
        let reader = Arc::new(Scripted {
            readings: Mutex::new(vec![Ok(concealing(4242)), Ok(concealing(4242))]),
        });
        let watcher = Arc::new(
            HiddenProcessWatcher::new(reader, 100_000, alerts).with_host_rules(Arc::clone(&rules)),
        );
        assert_eq!(watcher.sample().await, 1);
        assert_eq!(watcher.sample().await, 0);
        assert!(
            rx.recv().await.is_some(),
            "the sweep's own alert still goes"
        );
        assert_eq!(
            rules.reading("shadowed").map(|r| r.events),
            Some(1),
            "counted the sweep it first appeared in, not every sweep after"
        );
    }

    #[tokio::test]
    async fn a_busy_host_with_every_answer_listed_reports_nothing() {
        let (watcher, mut rx) = watcher(vec![Ok(ProcessReading {
            pid_space: 4_194_304,
            probed: 4_194_303,
            listed: 900,
            threads: 12_000,
            ..ProcessReading::default()
        })]);
        assert_eq!(watcher.sample().await, 0);
        assert!(rx.try_recv().is_err());
        assert!(watcher.report().scanned_at_ns > 0);
        assert!(watcher.report().error.is_none());
    }

    #[tokio::test]
    async fn a_failed_reading_keeps_the_last_sweep_and_says_why() {
        let (watcher, _rx) = watcher(vec![
            Ok(concealing(4242)),
            Err(DomainError::EngineError("warden down".into())),
        ]);
        watcher.sample().await;
        assert_eq!(watcher.sample().await, 0);
        let report = watcher.report();
        assert_eq!(report.sweep.hidden.len(), 1);
        assert!(
            report
                .error
                .as_deref()
                .is_some_and(|e| e.contains("warden down"))
        );
    }
}
