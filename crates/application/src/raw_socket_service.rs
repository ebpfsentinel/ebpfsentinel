//! Keeping the inventory of the node's packet sockets, and raising an alert
//! for each one that appears.
//!
//! The kernel raises no event when a packet socket is opened that names the
//! process, so the inventory is read on an interval. A socket opened and
//! closed between two readings is never seen. The first reading only primes
//! the inventory: the sockets already open when the agent starts are listed
//! and none of them raises an alert, since the agent cannot say they are new.

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use domain::alert::entity::Alert;
use domain::raw_socket::{RawSocket, new_sockets};
use domain::workload::entity::Workload;
use ports::secondary::raw_socket_port::RawSocketReader;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::alert_event::AlertEvent;
use crate::learning_service::now_ns;
use crate::workload_resolver::WorkloadResolver;

/// One socket and the workload holding it, where the holder resolved.
#[derive(Debug, Clone)]
pub struct RawSocketEntry {
    pub socket: RawSocket,
    pub workload: Option<Workload>,
}

/// The inventory as of the last reading.
#[derive(Debug, Clone, Default)]
pub struct RawSocketInventory {
    pub sockets: Vec<RawSocketEntry>,
    /// When the last reading was made, `0` before the first.
    pub scanned_at_ns: u64,
    /// Why the last reading failed; the sockets are then the reading before.
    pub error: Option<String>,
}

/// Reads the packet sockets on an interval.
pub struct RawSocketWatcher {
    reader: Arc<dyn RawSocketReader>,
    workloads: WorkloadResolver,
    alerts: mpsc::Sender<AlertEvent>,
    inventory: ArcSwap<RawSocketInventory>,
    /// Whether a reading has succeeded yet, so the first one primes.
    primed: std::sync::atomic::AtomicBool,
}

impl RawSocketWatcher {
    #[must_use]
    pub fn new(
        reader: Arc<dyn RawSocketReader>,
        workloads: WorkloadResolver,
        alerts: mpsc::Sender<AlertEvent>,
    ) -> Self {
        Self {
            reader,
            workloads,
            alerts,
            inventory: ArcSwap::from_pointee(RawSocketInventory::default()),
            primed: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// The inventory as of the last reading.
    #[must_use]
    pub fn inventory(&self) -> Arc<RawSocketInventory> {
        self.inventory.load_full()
    }

    /// Where readings come from: `warden` or `local`.
    #[must_use]
    pub fn source(&self) -> &'static str {
        self.reader.source()
    }

    /// Read the sockets once, replace the inventory and alert on each socket
    /// the previous reading lacked. Returns the number of alerts raised.
    pub async fn sample(self: &Arc<Self>) -> usize {
        let me = Arc::clone(self);
        let read = tokio::task::spawn_blocking(move || {
            let sockets = me.reader.list()?;
            Ok::<_, domain::common::error::DomainError>(
                sockets
                    .into_iter()
                    .map(|socket| {
                        let workload = socket.pid.and_then(|pid| me.workloads.by_pid(pid));
                        RawSocketEntry { socket, workload }
                    })
                    .collect::<Vec<_>>(),
            )
        })
        .await;
        let now = now_ns();
        let entries = match read {
            Ok(Ok(entries)) => entries,
            Ok(Err(err)) => {
                warn!(error = %err, "packet sockets could not be listed");
                self.keep_with_error(err.to_string(), now);
                return 0;
            }
            Err(err) => {
                warn!(error = %err, "packet socket reading did not run");
                return 0;
            }
        };
        let events = self.replace(entries, now);
        let raised = events.len();
        for event in events {
            if self.alerts.send(event).await.is_err() {
                debug!("alert pipeline closed, packet socket inventory stops sending");
                break;
            }
        }
        raised
    }

    fn keep_with_error(&self, error: String, now: u64) {
        let previous = self.inventory.load_full();
        self.inventory.store(Arc::new(RawSocketInventory {
            sockets: previous.sockets.clone(),
            scanned_at_ns: now,
            error: Some(error),
        }));
    }

    /// Install `entries` as the inventory and build an alert for each new
    /// socket, none on the first reading.
    fn replace(&self, entries: Vec<RawSocketEntry>, now: u64) -> Vec<AlertEvent> {
        let previous = self.inventory.load_full();
        let primed = self.primed.swap(true, std::sync::atomic::Ordering::AcqRel);
        let events = if primed {
            let before: Vec<RawSocket> =
                previous.sockets.iter().map(|e| e.socket.clone()).collect();
            let current: Vec<RawSocket> = entries.iter().map(|e| e.socket.clone()).collect();
            new_sockets(&before, &current)
                .into_iter()
                .map(|socket| {
                    let workload = entries
                        .iter()
                        .find(|e| e.socket.key() == socket.key())
                        .and_then(|e| e.workload.clone());
                    AlertEvent::System(Box::new(Alert::from_raw_socket(socket, workload, now)))
                })
                .collect()
        } else {
            Vec::new()
        };
        self.inventory.store(Arc::new(RawSocketInventory {
            sockets: entries,
            scanned_at_ns: now,
            error: None,
        }));
        events
    }

    /// Read on `interval` until `cancel` fires.
    pub async fn run(self: Arc<Self>, interval: Duration, cancel: CancellationToken) {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                () = cancel.cancelled() => {
                    debug!("packet socket inventory stopped");
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
    use domain::raw_socket::{FilterState, RawSocketKind};
    use std::sync::Mutex;

    struct Scripted {
        readings: Mutex<Vec<Result<Vec<RawSocket>, DomainError>>>,
    }

    impl RawSocketReader for Scripted {
        fn list(&self) -> Result<Vec<RawSocket>, DomainError> {
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

    fn socket(inode: u64, filter: Option<u32>) -> RawSocket {
        RawSocket {
            inode,
            kind: RawSocketKind::Raw,
            protocol: 0x0003,
            ifindex: 0,
            interface: None,
            uid: 0,
            netns: 1,
            host_netns: true,
            pid: Some(4242),
            filter: FilterState::from_count(filter),
        }
    }

    fn watcher(
        readings: Vec<Result<Vec<RawSocket>, DomainError>>,
    ) -> (Arc<RawSocketWatcher>, mpsc::Receiver<AlertEvent>) {
        let (tx, rx) = mpsc::channel(16);
        let reader = Arc::new(Scripted {
            readings: Mutex::new(readings),
        });
        (
            Arc::new(RawSocketWatcher::new(reader, WorkloadResolver::new(), tx)),
            rx,
        )
    }

    #[tokio::test]
    async fn the_first_reading_primes_and_a_later_socket_alerts() {
        let (watcher, mut rx) = watcher(vec![
            Ok(vec![socket(1, Some(0))]),
            Ok(vec![socket(1, Some(0)), socket(2, Some(30))]),
        ]);
        assert_eq!(watcher.sample().await, 0);
        assert_eq!(watcher.inventory().sockets.len(), 1);
        assert_eq!(watcher.sample().await, 1);
        let Some(AlertEvent::System(alert)) = rx.recv().await else {
            panic!("expected a system alert");
        };
        assert_eq!(alert.component, "raw_socket");
        assert_eq!(alert.tgid, Some(4242));
        assert_eq!(watcher.inventory().sockets.len(), 2);
        assert!(watcher.inventory().scanned_at_ns > 0);
    }

    #[tokio::test]
    async fn a_failed_reading_keeps_the_last_inventory_and_says_why() {
        let (watcher, _rx) = watcher(vec![
            Ok(vec![socket(1, Some(0))]),
            Err(DomainError::EngineError("warden down".into())),
            Ok(vec![socket(1, Some(0))]),
        ]);
        watcher.sample().await;
        assert_eq!(watcher.sample().await, 0);
        let inventory = watcher.inventory();
        assert_eq!(inventory.sockets.len(), 1);
        assert!(
            inventory
                .error
                .as_deref()
                .is_some_and(|e| e.contains("warden down"))
        );
        assert_eq!(watcher.sample().await, 0);
        assert!(watcher.inventory().error.is_none());
    }

    #[tokio::test]
    async fn a_failed_first_reading_does_not_prime() {
        let (watcher, _rx) = watcher(vec![
            Err(DomainError::EngineError("warden down".into())),
            Ok(vec![socket(1, Some(0))]),
        ]);
        watcher.sample().await;
        assert_eq!(watcher.sample().await, 0);
        assert_eq!(watcher.inventory().sockets.len(), 1);
    }
}
