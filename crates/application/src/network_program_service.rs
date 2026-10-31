//! Keeping the inventory of the eBPF programs other than the agent's on the
//! node's network path.
//!
//! The kernel raises no event naming the loader when a program is attached,
//! so the inventory is read on an interval, and a program attached and
//! detached between two readings is never seen. The agent's own programs are
//! set apart by the descriptors it holds: what it holds is what it loaded.

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use domain::network_program::{NetworkProgram, split_own};
use domain::workload::entity::Workload;
use ports::secondary::network_program_port::NetworkProgramReader;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::learning_service::now_ns;
use crate::workload_resolver::WorkloadResolver;

/// One process holding a program, and its workload where it resolved.
#[derive(Debug, Clone)]
pub struct ProgramHolder {
    pub pid: u32,
    pub workload: Option<Workload>,
}

/// One program and the processes holding it.
#[derive(Debug, Clone)]
pub struct NetworkProgramEntry {
    pub program: NetworkProgram,
    pub holders: Vec<ProgramHolder>,
}

/// The inventory as of the last reading.
#[derive(Debug, Clone, Default)]
pub struct NetworkProgramInventory {
    /// The programs the agent does not hold.
    pub programs: Vec<NetworkProgramEntry>,
    /// How many programs on the network path are the agent's own.
    pub own_programs: usize,
    /// When the last reading was made, `0` before the first.
    pub scanned_at_ns: u64,
    /// Why the last reading failed; the programs are then the reading before.
    pub error: Option<String>,
}

/// Reads the programs on the network path on an interval.
pub struct NetworkProgramWatcher {
    reader: Arc<dyn NetworkProgramReader>,
    workloads: WorkloadResolver,
    inventory: ArcSwap<NetworkProgramInventory>,
}

impl NetworkProgramWatcher {
    #[must_use]
    pub fn new(reader: Arc<dyn NetworkProgramReader>, workloads: WorkloadResolver) -> Self {
        Self {
            reader,
            workloads,
            inventory: ArcSwap::from_pointee(NetworkProgramInventory::default()),
        }
    }

    /// The inventory as of the last reading.
    #[must_use]
    pub fn inventory(&self) -> Arc<NetworkProgramInventory> {
        self.inventory.load_full()
    }

    /// Where readings come from: `warden` or `local`.
    #[must_use]
    pub fn source(&self) -> &'static str {
        self.reader.source()
    }

    /// Read the programs once and replace the inventory. Returns whether the
    /// reading succeeded.
    pub async fn sample(self: &Arc<Self>) -> bool {
        let me = Arc::clone(self);
        let read = tokio::task::spawn_blocking(move || {
            let programs = me.reader.list()?;
            let (foreign, own_programs) = split_own(programs, &me.reader.own());
            let entries = foreign
                .into_iter()
                .map(|program| {
                    let holders = program
                        .holders
                        .iter()
                        .map(|&pid| ProgramHolder {
                            pid,
                            workload: me.workloads.by_pid(pid),
                        })
                        .collect();
                    NetworkProgramEntry { program, holders }
                })
                .collect::<Vec<_>>();
            Ok::<_, domain::common::error::DomainError>((entries, own_programs))
        })
        .await;
        let now = now_ns();
        match read {
            Ok(Ok((programs, own_programs))) => {
                self.inventory.store(Arc::new(NetworkProgramInventory {
                    programs,
                    own_programs,
                    scanned_at_ns: now,
                    error: None,
                }));
                true
            }
            Ok(Err(err)) => {
                warn!(error = %err, "eBPF programs on the network path could not be listed");
                let previous = self.inventory.load_full();
                self.inventory.store(Arc::new(NetworkProgramInventory {
                    programs: previous.programs.clone(),
                    own_programs: previous.own_programs,
                    scanned_at_ns: now,
                    error: Some(err.to_string()),
                }));
                false
            }
            Err(err) => {
                warn!(error = %err, "eBPF program reading did not run");
                false
            }
        }
    }

    /// Read on `interval` until `cancel` fires.
    pub async fn run(self: Arc<Self>, interval: Duration, cancel: CancellationToken) {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                () = cancel.cancelled() => {
                    debug!("eBPF program inventory stopped");
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
    use domain::network_program::{NetworkHook, OwnBpfObjects};
    use std::collections::HashSet;
    use std::sync::Mutex;

    struct Scripted {
        readings: Mutex<Vec<Result<Vec<NetworkProgram>, DomainError>>>,
    }

    impl NetworkProgramReader for Scripted {
        fn list(&self) -> Result<Vec<NetworkProgram>, DomainError> {
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

        fn own(&self) -> OwnBpfObjects {
            OwnBpfObjects {
                prog_ids: HashSet::from([1]),
                link_ids: HashSet::new(),
            }
        }

        fn source(&self) -> &'static str {
            "local"
        }
    }

    fn program(prog_id: u32) -> NetworkProgram {
        NetworkProgram {
            prog_id,
            prog_type: "xdp".to_string(),
            name: "probe".to_string(),
            tag: "00".to_string(),
            link_id: None,
            hook: NetworkHook::Xdp,
            ifindex: Some(2),
            interface: Some("eth0".to_string()),
            cgroup_id: None,
            detail: None,
            created_by_uid: Some(0),
            holders: vec![4242],
        }
    }

    fn watcher(
        readings: Vec<Result<Vec<NetworkProgram>, DomainError>>,
    ) -> Arc<NetworkProgramWatcher> {
        let reader = Arc::new(Scripted {
            readings: Mutex::new(readings),
        });
        Arc::new(NetworkProgramWatcher::new(reader, WorkloadResolver::new()))
    }

    #[tokio::test]
    async fn the_agent_own_programs_are_counted_and_not_listed() {
        let watcher = watcher(vec![Ok(vec![program(1), program(2)])]);
        assert!(watcher.sample().await);
        let inventory = watcher.inventory();
        assert_eq!(inventory.own_programs, 1);
        assert_eq!(inventory.programs.len(), 1);
        assert_eq!(inventory.programs[0].program.prog_id, 2);
        assert_eq!(inventory.programs[0].holders[0].pid, 4242);
        assert!(inventory.scanned_at_ns > 0);
    }

    #[tokio::test]
    async fn a_failed_reading_keeps_the_last_inventory_and_says_why() {
        let watcher = watcher(vec![
            Ok(vec![program(2)]),
            Err(DomainError::EngineError("warden down".into())),
            Ok(vec![program(2)]),
        ]);
        watcher.sample().await;
        assert!(!watcher.sample().await);
        let inventory = watcher.inventory();
        assert_eq!(inventory.programs.len(), 1);
        assert!(
            inventory
                .error
                .as_deref()
                .is_some_and(|e| e.contains("warden down"))
        );
        assert!(watcher.sample().await);
        assert!(watcher.inventory().error.is_none());
    }
}
