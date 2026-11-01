use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use domain::alert::entity::Alert;
use domain::hidden::{PortFamily, PortSweep, Transport, sweep_ports};
use ports::secondary::hidden_port_port::HiddenPortReader;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::alert_event::AlertEvent;
use crate::learning_service::now_ns;

/// The sweep as of the last reading.
#[derive(Debug, Clone, Default)]
pub struct HiddenPortReport {
    pub sweep: PortSweep,
    /// When the last reading was made, `0` before the first.
    pub scanned_at_ns: u64,
    /// Why the last reading failed; the sweep is then the one before.
    pub error: Option<String>,
}

/// What identifies one hidden port across sweeps.
type HiddenKey = (u64, Transport, PortFamily, u16);

/// Compares the kernel's socket listings with a bind probe on an interval.
pub struct HiddenPortWatcher {
    reader: Arc<dyn HiddenPortReader>,
    ports: Arc<[u16]>,
    alerts: mpsc::Sender<AlertEvent>,
    report: ArcSwap<HiddenPortReport>,
}

impl HiddenPortWatcher {
    #[must_use]
    pub fn new(
        reader: Arc<dyn HiddenPortReader>,
        ports: Vec<u16>,
        alerts: mpsc::Sender<AlertEvent>,
    ) -> Self {
        Self {
            reader,
            ports: ports.into(),
            alerts,
            report: ArcSwap::from_pointee(HiddenPortReport::default()),
        }
    }

    /// The sweep as of the last reading.
    #[must_use]
    pub fn report(&self) -> Arc<HiddenPortReport> {
        self.report.load_full()
    }

    /// Where readings come from: `warden` or `local`.
    #[must_use]
    pub fn source(&self) -> &'static str {
        self.reader.source()
    }

    /// How many ports each namespace is probed on.
    #[must_use]
    pub fn probed_ports(&self) -> usize {
        self.ports.len()
    }

    /// Sweep once, replace the report and alert on each hidden port the
    /// previous sweep did not report. Returns the number of alerts raised.
    pub async fn sample(self: &Arc<Self>) -> usize {
        let me = Arc::clone(self);
        let read = tokio::task::spawn_blocking(move || me.reader.read(&me.ports)).await;
        let now = now_ns();
        let namespaces = match read {
            Ok(Ok(namespaces)) => namespaces,
            Ok(Err(err)) => {
                warn!(error = %err, "socket listings could not be read");
                let previous = self.report.load_full();
                self.report.store(Arc::new(HiddenPortReport {
                    sweep: previous.sweep.clone(),
                    scanned_at_ns: now,
                    error: Some(err.to_string()),
                }));
                return 0;
            }
            Err(err) => {
                warn!(error = %err, "hidden port reading did not run");
                return 0;
            }
        };
        let sweep = sweep_ports(&namespaces);
        let previous = self.report.load_full();
        let before: BTreeSet<HiddenKey> = previous
            .sweep
            .hidden
            .iter()
            .map(|h| (h.netns, h.transport, h.family, h.port))
            .collect();
        let events: Vec<AlertEvent> = sweep
            .hidden
            .iter()
            .filter(|h| !before.contains(&(h.netns, h.transport, h.family, h.port)))
            .map(|h| AlertEvent::System(Box::new(Alert::from_hidden_port(h, now))))
            .collect();
        self.report.store(Arc::new(HiddenPortReport {
            sweep,
            scanned_at_ns: now,
            error: None,
        }));
        let raised = events.len();
        for event in events {
            if self.alerts.send(event).await.is_err() {
                debug!("alert pipeline closed, hidden port sweep stops sending");
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
                    debug!("hidden port sweep stopped");
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
    use domain::hidden::{NamespacePorts, PortProbe, PortReading};
    use std::sync::Mutex;

    type Reading = Result<Vec<NamespacePorts>, DomainError>;

    struct Scripted {
        readings: Mutex<Vec<Reading>>,
    }

    impl HiddenPortReader for Scripted {
        fn read(&self, _ports: &[u16]) -> Reading {
            let mut readings = self
                .readings
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if readings.is_empty() {
                Ok(Vec::new())
            } else {
                readings.remove(0)
            }
        }

        fn source(&self) -> &'static str {
            "local"
        }
    }

    fn concealing(port: u16) -> Vec<NamespacePorts> {
        let refused = PortProbe {
            transport: Transport::Tcp,
            family: PortFamily::V4,
            port,
        };
        vec![NamespacePorts {
            netns: 1,
            host_netns: true,
            reading: Ok(PortReading {
                probed: 4,
                refused_first: vec![refused],
                refused_second: vec![refused],
                ..PortReading::default()
            }),
        }]
    }

    fn watcher(readings: Vec<Reading>) -> (Arc<HiddenPortWatcher>, mpsc::Receiver<AlertEvent>) {
        let (tx, rx) = mpsc::channel(16);
        let reader = Arc::new(Scripted {
            readings: Mutex::new(readings),
        });
        (
            Arc::new(HiddenPortWatcher::new(reader, vec![22, 31337], tx)),
            rx,
        )
    }

    #[tokio::test]
    async fn a_hidden_port_alerts_once_while_it_stays_hidden() {
        let (watcher, mut rx) = watcher(vec![
            Ok(concealing(31337)),
            Ok(concealing(31337)),
            Ok(Vec::new()),
            Ok(concealing(31337)),
        ]);
        assert_eq!(watcher.sample().await, 1);
        let Some(AlertEvent::System(alert)) = rx.recv().await else {
            panic!("expected a system alert");
        };
        assert_eq!(alert.component, "hidden_port");
        assert_eq!(alert.dst_port, 31337);
        assert_eq!(alert.protocol, 6);
        assert_eq!(watcher.sample().await, 0, "still hidden, already reported");
        assert_eq!(watcher.sample().await, 0);
        assert_eq!(
            watcher.sample().await,
            1,
            "hidden again after a clean sweep"
        );
        assert_eq!(watcher.probed_ports(), 2);
    }

    #[tokio::test]
    async fn a_busy_host_with_every_refusal_explained_reports_nothing() {
        let (watcher, mut rx) = watcher(vec![Ok(Vec::new())]);
        assert_eq!(watcher.sample().await, 0);
        assert!(rx.try_recv().is_err());
        assert!(watcher.report().scanned_at_ns > 0);
        assert!(watcher.report().error.is_none());
    }

    #[tokio::test]
    async fn a_failed_reading_keeps_the_last_sweep_and_says_why() {
        let (watcher, _rx) = watcher(vec![
            Ok(concealing(31337)),
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
