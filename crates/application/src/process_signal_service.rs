//! Arming a kill, waiting for it, and reporting what actually happened.
//!
//! The service never signals anything itself. It checks the target against
//! the domain's protected list, writes it into the kernel's armed map, waits
//! for the tracepoint to catch the target at its next syscall, and then goes
//! and looks whether the process is still there.
//!
//! The last step is the one that makes this safe to put on a screen. A signal
//! sent is not a process stopped: a target can block or handle it, and a
//! target that makes no further syscall before the window closes is never
//! reached at all. Both come back as `Survived`, so an operator reads what
//! happened rather than what was attempted.

use std::sync::Arc;
use std::time::Duration;

use domain::audit::entity::{AuditAction, AuditEntry};
use domain::common::error::DomainError;
use domain::response::signal::{ProcessKillOutcome, ProcessSignalGuard, ProtectedReason};
use ebpf_common::signal::{SIGNAL_OUTCOME_PROTECTED, SIGNAL_OUTCOME_SENT};
use ports::secondary::audit_store::AuditStore;
use ports::secondary::process_executable_port::ProcessExecutableReader;
use ports::secondary::process_signal_map_port::ProcessSignalMapPort;
use tokio::sync::Mutex;
use tracing::{info, warn};

/// How long a target stays armed, and how often the ring is read while it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessSignalSettings {
    /// The signal sent, as a number. 9 cannot be caught; 15 can.
    pub signal: u32,
    /// How long the kernel keeps looking for the target.
    pub window: Duration,
    /// How often the outcome ring is drained while waiting.
    pub poll_interval: Duration,
}

impl Default for ProcessSignalSettings {
    fn default() -> Self {
        Self {
            signal: 9,
            window: Duration::from_secs(2),
            poll_interval: Duration::from_millis(20),
        }
    }
}

/// Arms the kernel's signal map and reports the outcome.
pub struct ProcessSignalService {
    maps: Arc<Mutex<dyn ProcessSignalMapPort>>,
    executables: Arc<dyn ProcessExecutableReader>,
    audit: Option<Arc<dyn AuditStore>>,
    guard: ProcessSignalGuard,
    settings: ProcessSignalSettings,
}

impl ProcessSignalService {
    /// Build the service and publish the kernel's protected set.
    ///
    /// The set is written here rather than at the first kill, because an
    /// agent that armed a target before the fence was in place would be
    /// relying on nothing but its own code being right.
    ///
    /// # Errors
    ///
    /// Whatever writing the protected map refused.
    pub async fn new(
        maps: Arc<Mutex<dyn ProcessSignalMapPort>>,
        executables: Arc<dyn ProcessExecutableReader>,
        audit: Option<Arc<dyn AuditStore>>,
        guard: ProcessSignalGuard,
        settings: ProcessSignalSettings,
    ) -> Result<Self, DomainError> {
        maps.lock()
            .await
            .set_protected(&guard.kernel_protected_pids())?;
        Ok(Self {
            maps,
            executables,
            audit,
            guard,
            settings,
        })
    }

    /// The settings this service arms with.
    #[must_use]
    pub fn settings(&self) -> ProcessSignalSettings {
        self.settings
    }

    /// Stop the thread group `tgid`, on behalf of `rule_id`.
    ///
    /// Returns what happened rather than whether it worked: a refusal and a
    /// survivor are both ordinary answers, and only a map the kernel would
    /// not take is an error.
    ///
    /// # Errors
    ///
    /// Whatever writing or reading the signal maps refused.
    pub async fn kill(&self, tgid: u32, rule_id: &str) -> Result<ProcessKillOutcome, DomainError> {
        let executable = self.executables.read_executable(tgid);
        let verdict = self
            .guard
            .verdict(tgid, executable.as_ref().map(|e| e.path.as_str()));
        if let Some(reason) = verdict.reason() {
            let outcome = ProcessKillOutcome::Refused {
                reason: reason.clone(),
            };
            warn!(tgid, rule_id, reason = %reason.as_sentence(), "process kill refused");
            self.record(tgid, rule_id, &outcome);
            return Ok(outcome);
        }

        let signal = self.settings.signal;
        let window_ns = u64::try_from(self.settings.window.as_nanos()).unwrap_or(u64::MAX);
        self.maps.lock().await.arm(tgid, signal, window_ns)?;
        let outcome = self.wait_for_outcome(tgid, signal).await;
        // The arming comes off whatever happened, including the cases where
        // the kernel already removed it: leaving one behind would signal the
        // next process to inherit this thread group id.
        self.maps.lock().await.disarm(tgid)?;

        let outcome = outcome?;
        info!(tgid, rule_id, signal, outcome = %outcome.as_sentence(), "process kill taken");
        self.record(tgid, rule_id, &outcome);
        Ok(outcome)
    }

    /// Poll the outcome ring until the kernel acts or the window closes.
    async fn wait_for_outcome(
        &self,
        tgid: u32,
        signal: u32,
    ) -> Result<ProcessKillOutcome, DomainError> {
        let deadline = tokio::time::Instant::now() + self.settings.window;
        let mut signalled = false;
        while tokio::time::Instant::now() < deadline {
            tokio::time::sleep(self.settings.poll_interval).await;
            let events = self.maps.lock().await.drain_events()?;
            for event in events {
                if event.tgid != tgid {
                    // Another decision's record. The ring is shared and the
                    // service may be arming more than one target at a time.
                    continue;
                }
                match event.outcome {
                    SIGNAL_OUTCOME_SENT => signalled = true,
                    SIGNAL_OUTCOME_PROTECTED => {
                        // The kernel's own fence fired, which means the
                        // numbers it holds and the list this service checked
                        // disagreed. The kernel wins and says so.
                        return Ok(ProcessKillOutcome::Refused {
                            reason: ProtectedReason::ConfiguredPid { tgid },
                        });
                    }
                    _ => {}
                }
            }
            if signalled {
                break;
            }
        }
        if signalled && self.executables.read_executable(tgid).is_none() {
            return Ok(ProcessKillOutcome::Killed { tgid, signal });
        }
        Ok(ProcessKillOutcome::Survived {
            tgid,
            signal,
            signal_sent: signalled,
        })
    }

    /// Write the audit record. A store that refuses is logged and not fatal:
    /// the process is already dead or already spared, and failing the call
    /// afterwards would report neither.
    fn record(&self, tgid: u32, rule_id: &str, outcome: &ProcessKillOutcome) {
        let Some(store) = self.audit.as_ref() else {
            return;
        };
        let action = if outcome.is_killed() {
            AuditAction::ProcessSignalled
        } else {
            match outcome {
                ProcessKillOutcome::Refused { .. } => AuditAction::ProcessSignalRefused,
                _ => AuditAction::ProcessSignalled,
            }
        };
        let entry = AuditEntry::response_action(
            action,
            &format!("pid:{tgid}"),
            rule_id,
            &outcome.as_sentence(),
        );
        if let Err(e) = store.store_entry(&entry) {
            warn!(tgid, error = %e, "process kill audit record was refused");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::audit::error::AuditError;
    use domain::audit::query::AuditQuery;
    use domain::dlp::entity::{DlpExecutable, DlpIdentitySource};
    use ebpf_common::signal::{SIGNAL_OUTCOME_HELPER_FAILED, SignalEvent};
    use std::sync::Mutex as StdMutex;

    #[derive(Default)]
    struct FakeMaps {
        protected: Vec<u32>,
        armed: Vec<(u32, u32, u64)>,
        disarmed: Vec<u32>,
        events: Vec<SignalEvent>,
    }

    impl ProcessSignalMapPort for FakeMaps {
        fn set_protected(&mut self, tgids: &[u32]) -> Result<(), DomainError> {
            self.protected = tgids.to_vec();
            Ok(())
        }
        fn arm(&mut self, tgid: u32, signal: u32, window_ns: u64) -> Result<(), DomainError> {
            self.armed.push((tgid, signal, window_ns));
            Ok(())
        }
        fn disarm(&mut self, tgid: u32) -> Result<(), DomainError> {
            self.disarmed.push(tgid);
            Ok(())
        }
        fn drain_events(&mut self) -> Result<Vec<SignalEvent>, DomainError> {
            Ok(std::mem::take(&mut self.events))
        }
    }

    struct FakeExecutables {
        path: Option<String>,
        /// Whether the process is still there once the signal has been sent.
        alive_after: bool,
        reads: StdMutex<usize>,
    }

    impl FakeExecutables {
        fn new(path: Option<&str>, alive_after: bool) -> Self {
            Self {
                path: path.map(str::to_string),
                alive_after,
                reads: StdMutex::new(0),
            }
        }
    }

    impl ProcessExecutableReader for FakeExecutables {
        fn read_executable(&self, _pid: u32) -> Option<DlpExecutable> {
            let mut reads = self
                .reads
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *reads += 1;
            let first = *reads == 1;
            let path = self.path.clone()?;
            if first || self.alive_after {
                Some(DlpExecutable {
                    path,
                    dev: 0,
                    inode: 0,
                    source: DlpIdentitySource::ProcessAtAlertTime,
                })
            } else {
                None
            }
        }
    }

    #[derive(Default)]
    struct FakeAudit {
        entries: StdMutex<Vec<AuditEntry>>,
    }

    impl AuditStore for FakeAudit {
        fn store_entry(&self, entry: &AuditEntry) -> Result<(), AuditError> {
            self.entries
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(entry.clone());
            Ok(())
        }
        fn query_entries(&self, _query: &AuditQuery) -> Result<Vec<AuditEntry>, AuditError> {
            Ok(Vec::new())
        }
        fn cleanup_expired(&self, _before_ns: u64) -> Result<usize, AuditError> {
            Ok(0)
        }
        fn entry_count(&self) -> Result<usize, AuditError> {
            Ok(0)
        }
    }

    fn settings() -> ProcessSignalSettings {
        ProcessSignalSettings {
            signal: 9,
            window: Duration::from_millis(60),
            poll_interval: Duration::from_millis(5),
        }
    }

    async fn service(
        maps: Arc<Mutex<dyn ProcessSignalMapPort>>,
        executables: Arc<dyn ProcessExecutableReader>,
        audit: Arc<FakeAudit>,
    ) -> ProcessSignalService {
        ProcessSignalService::new(
            maps,
            executables,
            Some(audit),
            ProcessSignalGuard::new(4242, &[], &[]),
            settings(),
        )
        .await
        .expect("the fake maps take the protected set")
    }

    #[tokio::test]
    async fn the_protected_set_is_published_before_anything_can_be_armed() {
        let maps = Arc::new(Mutex::new(FakeMaps::default()));
        let service = ProcessSignalService::new(
            maps.clone(),
            Arc::new(FakeExecutables::new(None, false)),
            None,
            ProcessSignalGuard::new(4242, &[], &[7]),
            settings(),
        )
        .await
        .expect("the fake maps take the protected set");
        assert_eq!(service.settings().signal, 9);
        assert_eq!(maps.lock().await.protected, vec![1, 7, 4242]);
    }

    #[tokio::test]
    async fn a_protected_target_is_refused_without_arming_the_kernel() {
        let maps = Arc::new(Mutex::new(FakeMaps::default()));
        let audit = Arc::new(FakeAudit::default());
        let service = service(
            maps.clone(),
            Arc::new(FakeExecutables::new(Some("/usr/bin/kubelet"), true)),
            audit.clone(),
        )
        .await;

        let outcome = service.kill(5000, "rule-1").await.expect("no map error");
        assert!(matches!(
            outcome,
            ProcessKillOutcome::Refused {
                reason: ProtectedReason::HardProtected { .. }
            }
        ));
        assert!(maps.lock().await.armed.is_empty());
        let entries = audit
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action, AuditAction::ProcessSignalRefused);
        assert_eq!(entries[0].rule_id, "rule-1");
        assert!(entries[0].detail.contains("kubelet"));
    }

    #[tokio::test]
    async fn a_signalled_target_that_disappears_is_reported_killed() {
        let maps = Arc::new(Mutex::new(FakeMaps {
            events: vec![SignalEvent {
                at_ns: 1,
                tgid: 5000,
                signal: 9,
                outcome: SIGNAL_OUTCOME_SENT,
                _pad: 0,
            }],
            ..FakeMaps::default()
        }));
        let audit = Arc::new(FakeAudit::default());
        let service = service(
            maps.clone(),
            Arc::new(FakeExecutables::new(Some("/tmp/miner"), false)),
            audit.clone(),
        )
        .await;

        let outcome = service.kill(5000, "rule-2").await.expect("no map error");
        assert_eq!(
            outcome,
            ProcessKillOutcome::Killed {
                tgid: 5000,
                signal: 9
            }
        );
        let held = maps.lock().await;
        assert_eq!(held.armed, vec![(5000, 9, 60_000_000)]);
        assert_eq!(held.disarmed, vec![5000]);
        drop(held);
        let entries = audit
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(entries[0].action, AuditAction::ProcessSignalled);
        assert!(entries[0].detail.contains("gone"));
    }

    #[tokio::test]
    async fn a_signalled_target_that_is_still_there_is_reported_as_a_survivor() {
        let maps = Arc::new(Mutex::new(FakeMaps {
            events: vec![SignalEvent {
                at_ns: 1,
                tgid: 5000,
                signal: 9,
                outcome: SIGNAL_OUTCOME_SENT,
                _pad: 0,
            }],
            ..FakeMaps::default()
        }));
        let audit = Arc::new(FakeAudit::default());
        let service = service(
            maps,
            Arc::new(FakeExecutables::new(Some("/tmp/miner"), true)),
            audit,
        )
        .await;

        let outcome = service.kill(5000, "rule-3").await.expect("no map error");
        assert_eq!(
            outcome,
            ProcessKillOutcome::Survived {
                tgid: 5000,
                signal: 9,
                signal_sent: true
            }
        );
    }

    #[tokio::test]
    async fn a_target_the_kernel_never_reaches_is_a_survivor_nothing_was_sent_to() {
        let maps = Arc::new(Mutex::new(FakeMaps::default()));
        let audit = Arc::new(FakeAudit::default());
        let service = service(
            maps.clone(),
            Arc::new(FakeExecutables::new(Some("/tmp/miner"), true)),
            audit,
        )
        .await;

        let outcome = service.kill(5000, "rule-4").await.expect("no map error");
        assert_eq!(
            outcome,
            ProcessKillOutcome::Survived {
                tgid: 5000,
                signal: 9,
                signal_sent: false
            }
        );
        assert_eq!(maps.lock().await.disarmed, vec![5000]);
    }

    #[tokio::test]
    async fn the_kernels_own_fence_overrides_this_services_verdict() {
        let maps = Arc::new(Mutex::new(FakeMaps {
            events: vec![SignalEvent {
                at_ns: 1,
                tgid: 5000,
                signal: 9,
                outcome: SIGNAL_OUTCOME_PROTECTED,
                _pad: 0,
            }],
            ..FakeMaps::default()
        }));
        let audit = Arc::new(FakeAudit::default());
        let service = service(
            maps,
            Arc::new(FakeExecutables::new(Some("/tmp/miner"), true)),
            audit,
        )
        .await;

        let outcome = service.kill(5000, "rule-5").await.expect("no map error");
        assert!(matches!(outcome, ProcessKillOutcome::Refused { .. }));
    }

    #[tokio::test]
    async fn a_record_about_another_target_is_not_read_as_this_ones_outcome() {
        let maps = Arc::new(Mutex::new(FakeMaps {
            events: vec![
                SignalEvent {
                    at_ns: 1,
                    tgid: 6000,
                    signal: 9,
                    outcome: SIGNAL_OUTCOME_SENT,
                    _pad: 0,
                },
                SignalEvent {
                    at_ns: 2,
                    tgid: 5000,
                    signal: 9,
                    outcome: SIGNAL_OUTCOME_HELPER_FAILED,
                    _pad: 0,
                },
            ],
            ..FakeMaps::default()
        }));
        let audit = Arc::new(FakeAudit::default());
        let service = service(
            maps,
            Arc::new(FakeExecutables::new(Some("/tmp/miner"), false)),
            audit,
        )
        .await;

        let outcome = service.kill(5000, "rule-6").await.expect("no map error");
        assert_eq!(
            outcome,
            ProcessKillOutcome::Survived {
                tgid: 5000,
                signal: 9,
                signal_sent: false
            }
        );
    }

    #[tokio::test]
    async fn a_target_whose_executable_cannot_be_read_is_refused() {
        let maps = Arc::new(Mutex::new(FakeMaps::default()));
        let audit = Arc::new(FakeAudit::default());
        let service = service(
            maps.clone(),
            Arc::new(FakeExecutables::new(None, false)),
            audit,
        )
        .await;

        let outcome = service.kill(5000, "rule-7").await.expect("no map error");
        assert_eq!(
            outcome,
            ProcessKillOutcome::Refused {
                reason: ProtectedReason::NotIdentified
            }
        );
        assert!(maps.lock().await.armed.is_empty());
    }
}
