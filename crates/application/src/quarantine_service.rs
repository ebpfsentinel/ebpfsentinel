//! Cutting a workload off the network without stopping it, and letting it
//! back on.
//!
//! Two halves, and the second is the one that is easy to forget. Writing the
//! cgroup into the kernel map refuses what the workload opens next, and
//! nothing more: a connection it already holds has no `connect()` left for a
//! hook to refuse, so a quarantine that stopped there would leave an exfiltr-
//! ation already in flight running to completion. So the arming is followed by
//! a walk of the conntrack table, resolving each row to the task that opened
//! it and deleting only the rows belonging to this cgroup.
//!
//! That walk is why the teardown counts are part of the outcome. The socket
//! tables cannot name the owner of every row - a socket opened before the
//! agent started, an entry the LRU dropped, a transited flow with no local
//! process at all - and those rows are left alone and counted, because an
//! operator reading "quarantined" needs to know whether the cut had holes in
//! it. Guessing at them would mean tearing down a neighbour's connections.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use domain::audit::entity::{AuditAction, AuditEntry};
use domain::common::error::DomainError;
use domain::container::engine::CgroupIdResolver;
use domain::response::quarantine::{
    ActiveQuarantine, CgroupQuarantineGuard, QuarantineMode, QuarantineOutcome,
};
use ebpf_common::quarantine::{QUARANTINE_MODE_ENFORCE, QUARANTINE_MODE_REPORT};
use ports::secondary::audit_store::AuditStore;
use ports::secondary::conntrack_kill_port::{ConnTrackFlow, ConnTrackKillPort};
use ports::secondary::conntrack_map_port::ConnTrackMapPort;
use ports::secondary::quarantine_map_port::QuarantineMapPort;
use ports::secondary::socket_identity_port::FlowEndpoints;
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::workload_resolver::WorkloadResolver;

/// How long a quarantine lasts by default, and how much of the conntrack table
/// one teardown is allowed to walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuarantineSettings {
    /// How long the kernel keeps refusing, unless the caller says otherwise.
    pub window: Duration,
    /// The longest a window may be, whoever asks.
    ///
    /// A quarantine is a response rather than a policy, so it ends: an
    /// unbounded one is a workload cut off by an automation nobody remembers
    /// arming, which is the shape of outage this capability is most likely to
    /// cause. An operator who wants it permanent writes a workload rule.
    pub max_window: Duration,
    /// How many conntrack rows one teardown reads.
    ///
    /// Bounded because the table can hold hundreds of thousands of rows on a
    /// busy node and the walk resolves each one: a teardown that took seconds
    /// would hold the quarantine's own lock while the workload kept sending.
    pub max_flows_scanned: usize,
}

impl Default for QuarantineSettings {
    fn default() -> Self {
        Self {
            window: Duration::from_mins(15),
            max_window: Duration::from_hours(24),
            max_flows_scanned: 65_536,
        }
    }
}

/// What a teardown managed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Teardown {
    deleted: u64,
    unresolved: u64,
}

/// Arms, lifts and reports cgroup quarantines.
pub struct QuarantineService {
    maps: Arc<Mutex<dyn QuarantineMapPort>>,
    cgroups: Arc<dyn CgroupIdResolver>,
    conntrack: Option<Arc<dyn ConnTrackMapPort>>,
    kill: Option<Arc<dyn ConnTrackKillPort>>,
    workloads: Option<WorkloadResolver>,
    audit: Option<Arc<dyn AuditStore>>,
    guard: CgroupQuarantineGuard,
    settings: QuarantineSettings,
}

impl QuarantineService {
    /// Build the service.
    ///
    /// The teardown ports are separate and optional because the quarantine
    /// itself works without them: a node with no readable conntrack table
    /// still refuses everything the workload opens next, and says in the
    /// outcome that it tore nothing down rather than claiming a clean cut.
    #[must_use]
    pub fn new(
        maps: Arc<Mutex<dyn QuarantineMapPort>>,
        cgroups: Arc<dyn CgroupIdResolver>,
        guard: CgroupQuarantineGuard,
        settings: QuarantineSettings,
    ) -> Self {
        Self {
            maps,
            cgroups,
            conntrack: None,
            kill: None,
            workloads: None,
            audit: None,
            guard,
            settings,
        }
    }

    /// Give the service the three ports an established-flow teardown needs.
    ///
    /// All three together: the table to read, the owner lookup that says which
    /// rows are this cgroup's, and the delete. Two of the three would be a
    /// teardown that either deleted nothing or deleted the wrong rows.
    #[must_use]
    pub fn with_flow_teardown(
        mut self,
        conntrack: Arc<dyn ConnTrackMapPort>,
        kill: Arc<dyn ConnTrackKillPort>,
        workloads: WorkloadResolver,
    ) -> Self {
        self.conntrack = Some(conntrack);
        self.kill = Some(kill);
        self.workloads = Some(workloads);
        self
    }

    /// Give the service an audit store.
    #[must_use]
    pub fn with_audit(mut self, audit: Arc<dyn AuditStore>) -> Self {
        self.audit = Some(audit);
        self
    }

    /// The settings this service arms with.
    #[must_use]
    pub fn settings(&self) -> QuarantineSettings {
        self.settings
    }

    /// Whether this service can tear established flows down.
    #[must_use]
    pub fn tears_flows_down(&self) -> bool {
        self.conntrack.is_some() && self.kill.is_some() && self.workloads.is_some()
    }

    /// How many fences stand between a caller and a protected cgroup.
    #[must_use]
    pub fn protected_count(&self) -> usize {
        self.guard.protected_count()
    }

    /// Cut `cgroup_id` off the network on behalf of `rule_id`.
    ///
    /// `window` is clamped to [`QuarantineSettings::max_window`], and `None`
    /// takes the configured default.
    ///
    /// Returns what happened rather than whether it worked: a protected
    /// cgroup is an ordinary answer, and only a map the kernel would not take
    /// is an error.
    ///
    /// # Errors
    ///
    /// Whatever writing the quarantine map refused.
    pub async fn quarantine(
        &self,
        cgroup_id: u64,
        mode: QuarantineMode,
        window: Option<Duration>,
        rule_id: &str,
    ) -> Result<QuarantineOutcome, DomainError> {
        let path = self.cgroups.path_for_id(cgroup_id);
        let verdict = self.guard.verdict(cgroup_id, path.as_deref());
        if let Some(reason) = verdict.reason() {
            let outcome = QuarantineOutcome::Refused {
                reason: reason.clone(),
            };
            warn!(cgroup_id, rule_id, reason = %reason.as_sentence(), "quarantine refused");
            self.record(cgroup_id, rule_id, &outcome);
            return Ok(outcome);
        }

        let window = window
            .unwrap_or(self.settings.window)
            .min(self.settings.max_window);
        let window_ns = u64::try_from(window.as_nanos()).unwrap_or(u64::MAX);
        let kernel_mode = match mode {
            QuarantineMode::Enforce => QUARANTINE_MODE_ENFORCE,
            QuarantineMode::Report => QUARANTINE_MODE_REPORT,
        };
        // The map goes first. A teardown before the arming would delete the
        // flows a workload still has every right to reopen, and the reopened
        // ones would stay.
        self.maps
            .lock()
            .await
            .arm(cgroup_id, kernel_mode, window_ns)?;

        // Report-only tears nothing down: the mode exists to measure the
        // blast radius of cutting a workload off, and a measurement that
        // killed its connections would be the thing it was measuring.
        let teardown = if mode.enforces() {
            self.tear_down_flows(cgroup_id)
        } else {
            Teardown::default()
        };

        let outcome = QuarantineOutcome::Armed {
            cgroup_id,
            mode,
            flows_torn_down: teardown.deleted,
            flows_unresolved: teardown.unresolved,
        };
        info!(
            cgroup_id,
            rule_id,
            path = path.as_deref().unwrap_or("unknown"),
            window_ms = window.as_millis(),
            outcome = %outcome.as_sentence(),
            "workload quarantined"
        );
        self.record(cgroup_id, rule_id, &outcome);
        Ok(outcome)
    }

    /// Let `cgroup_id` reach the network again.
    ///
    /// # Errors
    ///
    /// Whatever removing the entry refused.
    pub async fn release(
        &self,
        cgroup_id: u64,
        rule_id: &str,
    ) -> Result<QuarantineOutcome, DomainError> {
        let removed = self.maps.lock().await.release(cgroup_id)?;
        let outcome = if removed {
            QuarantineOutcome::Released { cgroup_id }
        } else {
            QuarantineOutcome::NotQuarantined { cgroup_id }
        };
        info!(cgroup_id, rule_id, outcome = %outcome.as_sentence(), "quarantine release");
        self.record(cgroup_id, rule_id, &outcome);
        Ok(outcome)
    }

    /// Every cgroup the kernel is still refusing for, with the time it has
    /// left.
    ///
    /// Entries whose deadline has passed are left out: the kernel has already
    /// stopped acting on them, so listing them would name workloads that
    /// reach the network as cut off.
    ///
    /// # Errors
    ///
    /// Whatever reading the quarantine map refused.
    pub async fn active(&self) -> Result<Vec<ActiveQuarantine>, DomainError> {
        let maps = self.maps.lock().await;
        let now = maps.now_ns();
        let entries = maps.entries()?;
        drop(maps);
        let mut active: Vec<ActiveQuarantine> = entries
            .into_iter()
            .filter(|(_, entry)| entry.expires_at_ns > now)
            .map(|(cgroup_id, entry)| ActiveQuarantine {
                cgroup_id,
                path: self.cgroups.path_for_id(cgroup_id),
                mode: if entry.mode == QUARANTINE_MODE_REPORT {
                    QuarantineMode::Report
                } else {
                    // Anything that is not the report value enforces,
                    // including a value this build does not know: a map entry
                    // written by a newer agent must not read as permissive.
                    QuarantineMode::Enforce
                },
                remaining_ms: (entry.expires_at_ns - now) / 1_000_000,
            })
            .collect();
        active.sort_unstable_by_key(|a| a.cgroup_id);
        Ok(active)
    }

    /// Drop the entries the kernel has already stopped acting on.
    ///
    /// Each one is audited as a release, because a quarantine ending is an
    /// event an operator reading the log needs: the alternative is a record
    /// saying a workload was cut off and nothing saying it stopped being.
    ///
    /// # Errors
    ///
    /// Whatever walking or writing the quarantine map refused.
    pub async fn sweep_expired(&self, rule_id: &str) -> Result<Vec<u64>, DomainError> {
        let swept = self.maps.lock().await.sweep_expired()?;
        for cgroup_id in &swept {
            let outcome = QuarantineOutcome::Released {
                cgroup_id: *cgroup_id,
            };
            info!(cgroup_id, rule_id, "quarantine expired");
            self.record(*cgroup_id, rule_id, &outcome);
        }
        Ok(swept)
    }

    /// Delete the established flows belonging to this cgroup, and count the
    /// rows whose owner nothing could name.
    fn tear_down_flows(&self, cgroup_id: u64) -> Teardown {
        let (Some(conntrack), Some(kill), Some(workloads)) =
            (&self.conntrack, &self.kill, &self.workloads)
        else {
            return Teardown::default();
        };
        let connections = match conntrack.get_connections(self.settings.max_flows_scanned) {
            Ok(connections) => connections,
            Err(e) => {
                // The arming stands: refusing what the workload opens next
                // does not depend on this table being readable.
                warn!(cgroup_id, error = %e, "conntrack table unreadable, no flows torn down");
                return Teardown::default();
            }
        };
        let mut teardown = Teardown::default();
        for connection in connections {
            let (Ok(src), Ok(dst)) = (
                connection.src_ip.parse::<IpAddr>(),
                connection.dst_ip.parse::<IpAddr>(),
            ) else {
                teardown.unresolved += 1;
                continue;
            };
            let flow = FlowEndpoints {
                local_addr: src,
                remote_addr: dst,
                local_port: connection.src_port,
                remote_port: connection.dst_port,
                protocol: connection.protocol,
            };
            let Some(cgroup) = workloads.by_flow(&flow).and_then(|w| w.cgroup) else {
                // A socket opened before the agent started, an evicted entry,
                // or a transited flow with no local process. Left alone and
                // counted: deleting it would cut a flow that may belong to
                // anything on the node.
                teardown.unresolved += 1;
                continue;
            };
            if cgroup != cgroup_id {
                continue;
            }
            match kill.delete_flow(&ConnTrackFlow {
                protocol: connection.protocol,
                src_ip: connection.src_ip.clone(),
                dst_ip: connection.dst_ip.clone(),
                src_port: connection.src_port,
                dst_port: connection.dst_port,
            }) {
                Ok(deleted) => teardown.deleted += deleted,
                Err(e) => {
                    warn!(cgroup_id, error = %e, "a quarantined workload's flow was not torn down");
                    teardown.unresolved += 1;
                }
            }
        }
        teardown
    }

    /// Write the audit record. A store that refuses is logged and not fatal:
    /// the workload is already cut off or already spared, and failing the call
    /// afterwards would report neither.
    fn record(&self, cgroup_id: u64, rule_id: &str, outcome: &QuarantineOutcome) {
        let Some(store) = self.audit.as_ref() else {
            return;
        };
        let action = match outcome {
            QuarantineOutcome::Refused { .. } => AuditAction::WorkloadQuarantineRefused,
            QuarantineOutcome::Armed { .. } => AuditAction::WorkloadQuarantined,
            QuarantineOutcome::Released { .. } | QuarantineOutcome::NotQuarantined { .. } => {
                AuditAction::WorkloadReleased
            }
        };
        let entry = AuditEntry::response_action(
            action,
            &format!("cgroup:{cgroup_id}"),
            rule_id,
            &outcome.as_sentence(),
        );
        if let Err(e) = store.store_entry(&entry) {
            warn!(cgroup_id, error = %e, "quarantine audit record was refused");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::audit::error::AuditError;
    use domain::audit::query::AuditQuery;
    use domain::conntrack::entity::{ConnTrackSettings, Connection, ConnectionState};
    use domain::response::quarantine::ProtectedCgroupReason;
    use domain::workload::entity::WorkloadSource;
    use ebpf_common::quarantine::{QuarantineEntry, QuarantineEvent};
    use ports::secondary::socket_identity_port::{SocketIdentityReader, SocketOwner};
    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;

    /// The boot-clock reading the fake maps answer with, so a window written
    /// in a test has a deadline a test can predict.
    const NOW_NS: u64 = 1_000_000_000;

    #[derive(Default)]
    struct FakeMaps {
        entries: HashMap<u64, QuarantineEntry>,
        armed: Vec<(u64, u32, u64)>,
        released: Vec<u64>,
    }

    impl QuarantineMapPort for FakeMaps {
        fn arm(&mut self, cgroup_id: u64, mode: u32, window_ns: u64) -> Result<(), DomainError> {
            self.armed.push((cgroup_id, mode, window_ns));
            self.entries.insert(
                cgroup_id,
                QuarantineEntry {
                    expires_at_ns: NOW_NS + window_ns,
                    mode,
                    _pad: 0,
                },
            );
            Ok(())
        }
        fn release(&mut self, cgroup_id: u64) -> Result<bool, DomainError> {
            self.released.push(cgroup_id);
            Ok(self.entries.remove(&cgroup_id).is_some())
        }
        fn entry(&self, cgroup_id: u64) -> Result<Option<QuarantineEntry>, DomainError> {
            Ok(self.entries.get(&cgroup_id).copied())
        }
        fn entries(&self) -> Result<Vec<(u64, QuarantineEntry)>, DomainError> {
            Ok(self.entries.iter().map(|(k, v)| (*k, *v)).collect())
        }
        fn sweep_expired(&mut self) -> Result<Vec<u64>, DomainError> {
            let expired: Vec<u64> = self
                .entries
                .iter()
                .filter(|(_, e)| NOW_NS >= e.expires_at_ns)
                .map(|(k, _)| *k)
                .collect();
            for key in &expired {
                self.entries.remove(key);
            }
            Ok(expired)
        }
        fn drain_events(&mut self) -> Result<Vec<QuarantineEvent>, DomainError> {
            Ok(Vec::new())
        }
        fn now_ns(&self) -> u64 {
            NOW_NS
        }
    }

    struct FakeCgroups {
        paths: HashMap<u64, String>,
    }

    impl FakeCgroups {
        fn with(cgroup_id: u64, path: &str) -> Self {
            let mut paths = HashMap::new();
            paths.insert(cgroup_id, path.to_string());
            Self { paths }
        }
    }

    impl CgroupIdResolver for FakeCgroups {
        fn path_for_id(&self, cgroup_id: u64) -> Option<String> {
            self.paths.get(&cgroup_id).cloned()
        }
    }

    struct FakeConntrack {
        connections: Vec<Connection>,
        fail: bool,
    }

    impl ConnTrackMapPort for FakeConntrack {
        fn get_connections(&self, _limit: usize) -> Result<Vec<Connection>, DomainError> {
            if self.fail {
                return Err(DomainError::EngineError("no table".into()));
            }
            Ok(self.connections.clone())
        }
        fn flush_all(&mut self) -> Result<u64, DomainError> {
            Ok(0)
        }
        fn set_config(&mut self, _settings: &ConnTrackSettings) -> Result<(), DomainError> {
            Ok(())
        }
        fn connection_count(&self) -> Result<u64, DomainError> {
            Ok(0)
        }
    }

    #[derive(Default)]
    struct FakeKill {
        deleted: StdMutex<Vec<ConnTrackFlow>>,
    }

    impl ConnTrackKillPort for FakeKill {
        fn delete_matching(&self, _protocol: u8, _dst_port: u16) -> Result<u64, DomainError> {
            panic!("a quarantine must never delete by port alone");
        }
        fn delete_flow(&self, flow: &ConnTrackFlow) -> Result<u64, DomainError> {
            self.deleted
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(flow.clone());
            Ok(1)
        }
    }

    /// Answers with a cgroup per source port, and with nothing for the ports
    /// it was not given.
    struct FakeSockets {
        owners: HashMap<u16, u64>,
    }

    impl SocketIdentityReader for FakeSockets {
        fn by_cookie(&self, _cookie: u64) -> Option<SocketOwner> {
            None
        }
        fn by_flow(&self, flow: &FlowEndpoints) -> Option<SocketOwner> {
            self.owners.get(&flow.local_port).map(|cgroup| SocketOwner {
                pid: 10,
                tgid: 10,
                uid: 0,
                cgroup_id: *cgroup,
                source: WorkloadSource::Flow,
            })
        }
        fn by_originated_flow(&self, _flow: &FlowEndpoints) -> Option<SocketOwner> {
            None
        }
    }

    #[derive(Default)]
    struct FakeAudit {
        entries: StdMutex<Vec<AuditEntry>>,
    }

    impl FakeAudit {
        fn taken(&self) -> Vec<AuditEntry> {
            self.entries
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }
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

    fn connection(src_port: u16, dst_port: u16) -> Connection {
        Connection {
            src_ip: "10.0.0.2".to_string(),
            dst_ip: "93.184.216.34".to_string(),
            src_port,
            dst_port,
            protocol: 6,
            state: ConnectionState::Established,
            packets_fwd: 1,
            packets_rev: 1,
            bytes_fwd: 100,
            bytes_rev: 100,
            workload: None,
        }
    }

    fn settings() -> QuarantineSettings {
        QuarantineSettings {
            window: Duration::from_secs(60),
            max_window: Duration::from_secs(300),
            max_flows_scanned: 1_000,
        }
    }

    fn guard() -> CgroupQuarantineGuard {
        CgroupQuarantineGuard::new(77, 1, &[], &[])
    }

    /// The owner lookup the teardown walks, keyed by source port.
    fn resolver(owners: HashMap<u16, u64>) -> WorkloadResolver {
        WorkloadResolver::new().with_sockets(Box::new(FakeSockets { owners }))
    }

    #[tokio::test]
    async fn a_protected_cgroup_is_refused_without_arming_the_kernel() {
        let maps = Arc::new(Mutex::new(FakeMaps::default()));
        let audit = Arc::new(FakeAudit::default());
        let service = QuarantineService::new(
            maps.clone(),
            Arc::new(FakeCgroups::with(5000, "/system.slice/kubelet.service")),
            guard(),
            settings(),
        )
        .with_audit(audit.clone());

        let outcome = service
            .quarantine(5000, QuarantineMode::Enforce, None, "rule-1")
            .await
            .expect("no map error");
        assert!(matches!(
            outcome,
            QuarantineOutcome::Refused {
                reason: ProtectedCgroupReason::HardProtected { .. }
            }
        ));
        assert!(maps.lock().await.armed.is_empty());
        let taken = audit.taken();
        assert_eq!(taken.len(), 1);
        assert_eq!(taken[0].action, AuditAction::WorkloadQuarantineRefused);
        assert!(taken[0].detail.contains("kubelet"));
    }

    #[tokio::test]
    async fn arming_cuts_the_cgroups_own_flows_and_leaves_its_neighbours_alone() {
        let maps = Arc::new(Mutex::new(FakeMaps::default()));
        let audit = Arc::new(FakeAudit::default());
        let kill = Arc::new(FakeKill::default());
        // 40000 is the quarantined workload, 40001 a neighbour on the same
        // destination port, 40002 a row nothing can name.
        let sockets = resolver([(40_000u16, 5000u64), (40_001, 6000)].into_iter().collect());
        let conntrack = Arc::new(FakeConntrack {
            connections: vec![
                connection(40_000, 443),
                connection(40_001, 443),
                connection(40_002, 443),
            ],
            fail: false,
        });
        let service = QuarantineService::new(
            maps.clone(),
            Arc::new(FakeCgroups::with(5000, "/kubepods.slice/pod-a/container-b")),
            guard(),
            settings(),
        )
        .with_flow_teardown(conntrack, kill.clone(), sockets)
        .with_audit(audit.clone());
        assert!(service.tears_flows_down());

        let outcome = service
            .quarantine(5000, QuarantineMode::Enforce, None, "rule-2")
            .await
            .expect("no map error");
        assert_eq!(
            outcome,
            QuarantineOutcome::Armed {
                cgroup_id: 5000,
                mode: QuarantineMode::Enforce,
                flows_torn_down: 1,
                flows_unresolved: 1,
            }
        );
        assert_eq!(
            maps.lock().await.armed,
            vec![(5000, QUARANTINE_MODE_ENFORCE, 60_000_000_000)]
        );
        let deleted = kill
            .deleted
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(deleted.len(), 1);
        assert_eq!(deleted[0].src_port, 40_000);
        drop(deleted);
        assert_eq!(audit.taken()[0].action, AuditAction::WorkloadQuarantined);
    }

    #[tokio::test]
    async fn report_only_arms_the_map_and_tears_nothing_down() {
        let maps = Arc::new(Mutex::new(FakeMaps::default()));
        let kill = Arc::new(FakeKill::default());
        let service = QuarantineService::new(
            maps.clone(),
            Arc::new(FakeCgroups::with(5000, "/payload.slice")),
            guard(),
            settings(),
        )
        .with_flow_teardown(
            Arc::new(FakeConntrack {
                connections: vec![connection(40_000, 443)],
                fail: false,
            }),
            kill.clone(),
            resolver([(40_000u16, 5000u64)].into_iter().collect()),
        );

        let outcome = service
            .quarantine(5000, QuarantineMode::Report, None, "rule-3")
            .await
            .expect("no map error");
        assert_eq!(
            outcome,
            QuarantineOutcome::Armed {
                cgroup_id: 5000,
                mode: QuarantineMode::Report,
                flows_torn_down: 0,
                flows_unresolved: 0,
            }
        );
        assert_eq!(
            maps.lock().await.armed,
            vec![(5000, QUARANTINE_MODE_REPORT, 60_000_000_000)]
        );
        assert!(
            kill.deleted
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_window_longer_than_the_ceiling_is_clamped_to_it() {
        let maps = Arc::new(Mutex::new(FakeMaps::default()));
        let service = QuarantineService::new(
            maps.clone(),
            Arc::new(FakeCgroups::with(5000, "/payload.slice")),
            guard(),
            settings(),
        );

        service
            .quarantine(
                5000,
                QuarantineMode::Enforce,
                Some(Duration::from_hours(24)),
                "rule-4",
            )
            .await
            .expect("no map error");
        assert_eq!(maps.lock().await.armed[0].2, 300_000_000_000);
    }

    #[tokio::test]
    async fn an_unreadable_conntrack_table_still_arms_and_says_it_tore_nothing_down() {
        let maps = Arc::new(Mutex::new(FakeMaps::default()));
        let service = QuarantineService::new(
            maps.clone(),
            Arc::new(FakeCgroups::with(5000, "/payload.slice")),
            guard(),
            settings(),
        )
        .with_flow_teardown(
            Arc::new(FakeConntrack {
                connections: Vec::new(),
                fail: true,
            }),
            Arc::new(FakeKill::default()),
            resolver(HashMap::new()),
        );

        let outcome = service
            .quarantine(5000, QuarantineMode::Enforce, None, "rule-5")
            .await
            .expect("an unreadable table is not an error");
        assert_eq!(
            outcome,
            QuarantineOutcome::Armed {
                cgroup_id: 5000,
                mode: QuarantineMode::Enforce,
                flows_torn_down: 0,
                flows_unresolved: 0,
            }
        );
        assert!(!maps.lock().await.armed.is_empty());
    }

    #[tokio::test]
    async fn releasing_something_that_was_not_quarantined_says_so() {
        let maps = Arc::new(Mutex::new(FakeMaps::default()));
        let audit = Arc::new(FakeAudit::default());
        let service = QuarantineService::new(
            maps,
            Arc::new(FakeCgroups::with(5000, "/payload.slice")),
            guard(),
            settings(),
        )
        .with_audit(audit.clone());

        let outcome = service.release(5000, "operator").await.expect("no error");
        assert_eq!(
            outcome,
            QuarantineOutcome::NotQuarantined { cgroup_id: 5000 }
        );
        assert_eq!(audit.taken()[0].action, AuditAction::WorkloadReleased);
    }

    #[tokio::test]
    async fn a_quarantine_is_listed_until_it_is_released() {
        let maps = Arc::new(Mutex::new(FakeMaps::default()));
        let service = QuarantineService::new(
            maps,
            Arc::new(FakeCgroups::with(5000, "/payload.slice")),
            guard(),
            settings(),
        );

        service
            .quarantine(5000, QuarantineMode::Enforce, None, "rule-6")
            .await
            .expect("no map error");
        let active = service.active().await.expect("no map error");
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].cgroup_id, 5000);
        assert_eq!(active[0].path.as_deref(), Some("/payload.slice"));
        assert_eq!(active[0].mode, QuarantineMode::Enforce);
        assert_eq!(active[0].remaining_ms, 60_000);

        service.release(5000, "operator").await.expect("no error");
        assert!(service.active().await.expect("no map error").is_empty());
    }

    #[tokio::test]
    async fn an_expired_entry_is_not_listed_and_is_swept_as_a_release() {
        let maps = Arc::new(Mutex::new(FakeMaps {
            entries: [(
                5000u64,
                QuarantineEntry {
                    expires_at_ns: NOW_NS - 1,
                    mode: QUARANTINE_MODE_ENFORCE,
                    _pad: 0,
                },
            )]
            .into_iter()
            .collect(),
            ..FakeMaps::default()
        }));
        let audit = Arc::new(FakeAudit::default());
        let service = QuarantineService::new(
            maps.clone(),
            Arc::new(FakeCgroups::with(5000, "/payload.slice")),
            guard(),
            settings(),
        )
        .with_audit(audit.clone());

        assert!(service.active().await.expect("no map error").is_empty());
        assert_eq!(
            service.sweep_expired("expiry").await.expect("no map error"),
            vec![5000]
        );
        assert_eq!(audit.taken()[0].action, AuditAction::WorkloadReleased);
        assert!(maps.lock().await.entries.is_empty());
    }

    #[tokio::test]
    async fn an_unknown_mode_in_the_map_reads_as_enforcing() {
        // A newer agent could write a mode this build does not know. Reading
        // it as permissive would report a cut-off workload as free to reach
        // the network, which is the wrong way for this to be wrong.
        let maps = Arc::new(Mutex::new(FakeMaps {
            entries: [(
                5000u64,
                QuarantineEntry {
                    expires_at_ns: NOW_NS + 1_000_000_000,
                    mode: 99,
                    _pad: 0,
                },
            )]
            .into_iter()
            .collect(),
            ..FakeMaps::default()
        }));
        let service = QuarantineService::new(
            maps,
            Arc::new(FakeCgroups::with(5000, "/payload.slice")),
            guard(),
            settings(),
        );
        let active = service.active().await.expect("no map error");
        assert_eq!(active[0].mode, QuarantineMode::Enforce);
    }

    #[tokio::test]
    async fn a_service_with_no_teardown_ports_says_so_rather_than_claiming_a_clean_cut() {
        let maps = Arc::new(Mutex::new(FakeMaps::default()));
        let service = QuarantineService::new(
            maps,
            Arc::new(FakeCgroups::with(5000, "/payload.slice")),
            guard(),
            settings(),
        );
        assert!(!service.tears_flows_down());
        assert!(service.protected_count() > 0);

        let outcome = service
            .quarantine(5000, QuarantineMode::Enforce, None, "rule-7")
            .await
            .expect("no map error");
        assert_eq!(
            outcome,
            QuarantineOutcome::Armed {
                cgroup_id: 5000,
                mode: QuarantineMode::Enforce,
                flows_torn_down: 0,
                flows_unresolved: 0,
            }
        );
    }
}
