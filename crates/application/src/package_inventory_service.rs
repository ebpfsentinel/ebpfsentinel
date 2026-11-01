use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use domain::inventory::InventorySweep;
use ports::secondary::package_inventory_port::PackageInventoryReader;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::learning_service::now_ns;

/// The package inventory as of the last sweep.
#[derive(Debug, Clone, Default)]
pub struct PackageInventoryReport {
    pub sweep: InventorySweep,
    /// When the last sweep was made, `0` before the first.
    pub scanned_at_ns: u64,
    /// Why the last sweep failed; the inventory is then the one before.
    pub error: Option<String>,
}

/// Reads what the package managers say is installed, in every root, on an
/// interval.
pub struct PackageInventoryService {
    reader: Arc<dyn PackageInventoryReader>,
    report: ArcSwap<PackageInventoryReport>,
}

impl PackageInventoryService {
    #[must_use]
    pub fn new(reader: Arc<dyn PackageInventoryReader>) -> Self {
        Self {
            reader,
            report: ArcSwap::from_pointee(PackageInventoryReport::default()),
        }
    }

    /// The inventory as of the last sweep.
    #[must_use]
    pub fn report(&self) -> Arc<PackageInventoryReport> {
        self.report.load_full()
    }

    /// Where readings come from: `warden` or `local`.
    #[must_use]
    pub fn source(&self) -> &'static str {
        self.reader.source()
    }

    /// Sweep once and replace the report.
    pub async fn sample(self: &Arc<Self>) {
        let me = Arc::clone(self);
        let read = tokio::task::spawn_blocking(move || me.reader.read()).await;
        let now = now_ns();
        match read {
            Ok(Ok(sweep)) => self.report.store(Arc::new(PackageInventoryReport {
                sweep,
                scanned_at_ns: now,
                error: None,
            })),
            Ok(Err(err)) => {
                warn!(error = %err, "the package databases could not be read");
                let previous = self.report.load_full();
                self.report.store(Arc::new(PackageInventoryReport {
                    sweep: previous.sweep.clone(),
                    scanned_at_ns: now,
                    error: Some(err.to_string()),
                }));
            }
            Err(err) => warn!(error = %err, "package inventory sweep did not run"),
        }
    }

    /// Sweep on `interval` until `cancel` fires.
    pub async fn run(self: Arc<Self>, interval: Duration, cancel: CancellationToken) {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                () = cancel.cancelled() => {
                    debug!("package inventory sweep stopped");
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
    use domain::inventory::{RootInventory, RootScope};
    use std::sync::Mutex;

    struct Scripted {
        readings: Mutex<Vec<Result<InventorySweep, DomainError>>>,
    }

    impl PackageInventoryReader for Scripted {
        fn read(&self) -> Result<InventorySweep, DomainError> {
            let mut readings = self
                .readings
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if readings.is_empty() {
                Ok(InventorySweep::default())
            } else {
                readings.remove(0)
            }
        }

        fn source(&self) -> &'static str {
            "local"
        }
    }

    fn host() -> InventorySweep {
        InventorySweep {
            roots: vec![RootInventory {
                scope: RootScope::Host,
                pid: 1,
                databases: Vec::new(),
                error: None,
            }],
            ..InventorySweep::default()
        }
    }

    #[tokio::test]
    async fn a_failed_sweep_keeps_the_last_inventory_and_says_why() {
        let service = Arc::new(PackageInventoryService::new(Arc::new(Scripted {
            readings: Mutex::new(vec![
                Ok(host()),
                Err(DomainError::EngineError("warden down".into())),
            ]),
        })));
        assert_eq!(service.report().scanned_at_ns, 0);
        service.sample().await;
        assert_eq!(service.report().sweep, host());
        assert!(service.report().error.is_none());
        service.sample().await;
        let report = service.report();
        assert_eq!(report.sweep, host());
        assert!(
            report
                .error
                .as_deref()
                .is_some_and(|e| e.contains("warden down"))
        );
        assert_eq!(service.source(), "local");
    }
}
