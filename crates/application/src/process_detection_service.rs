//! Where the three process detections get the processes they test.
//!
//! A detection asks about a process that holds a connection, and there is no
//! kernel event for "a process opened a connection" that names the process:
//! the attribution hooks fill lookup tables keyed on the socket. So the
//! detector reads the kernel's connection table on an interval, the way the
//! learning window does, and resolves each connection this node opened to the
//! process behind it, ancestry included. Shells and interpreters are tested a
//! second way on the same tick, straight from the process table, because a
//! shell handed a socket by `nc -e` holds the connection without having opened
//! it.
//!
//! What a sample cannot see is stated rather than hidden: a connection that
//! opens and closes between two reads is never tested. A process is reported
//! once per detection for its lifetime; a pid reused by another process is a
//! new process and is tested afresh.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use domain::common::entity::Protocol;
use domain::conntrack::entity::Connection;
use domain::process::detection::{ProcessDetectionKind, ProcessDetectionPolicy, ProcessFacts};
use domain::workload::entity::Workload;
use ports::secondary::process_facts_port::ProcessFactsReader;
use ports::secondary::socket_identity_port::FlowEndpoints;
use tokio::sync::{RwLock, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::alert_event::AlertEvent;
use crate::conntrack_service_impl::ConnTrackAppService;
use crate::learning_service::now_ns;
use crate::process_table_service::ProcessTableService;
use crate::workload_resolver::WorkloadResolver;

/// Rows read from the connection table in one sample, for the reason the
/// learning window bounds its own read.
pub const DETECTION_SAMPLE_ROWS: usize = 16_384;

/// A process already reported for one detection: its pid, the kernel start
/// time that tells it apart from a later holder of the pid, and the detection.
type Reported = (u32, Option<u64>, ProcessDetectionKind);

/// One process to test and the connection it was found holding, if any.
struct Candidate {
    workload: Workload,
    destination: Option<(IpAddr, u16, u8)>,
}

/// Reads the connection table and the process table on an interval and
/// raises an alert for each process one of the detections names.
pub struct ProcessDetector {
    policy: ProcessDetectionPolicy,
    kill_process: bool,
    conntrack: Arc<RwLock<ConnTrackAppService>>,
    workloads: WorkloadResolver,
    processes: Arc<ProcessTableService>,
    facts: Arc<dyn ProcessFactsReader>,
    alerts: mpsc::Sender<AlertEvent>,
    reported: Mutex<HashSet<Reported>>,
    rows: usize,
}

impl ProcessDetector {
    #[must_use]
    pub fn new(
        policy: ProcessDetectionPolicy,
        conntrack: Arc<RwLock<ConnTrackAppService>>,
        workloads: WorkloadResolver,
        processes: Arc<ProcessTableService>,
        facts: Arc<dyn ProcessFactsReader>,
        alerts: mpsc::Sender<AlertEvent>,
    ) -> Self {
        Self {
            policy,
            kill_process: false,
            conntrack,
            workloads,
            processes,
            facts,
            alerts,
            reported: Mutex::new(HashSet::new()),
            rows: DETECTION_SAMPLE_ROWS,
        }
    }

    /// Stop the process each alert names, through the same process kill an
    /// IPS rule asks for.
    #[must_use]
    pub fn with_kill_process(mut self, kill_process: bool) -> Self {
        self.kill_process = kill_process;
        self
    }

    /// The processes behind the connections this node opened, one per pid.
    fn flow_candidates(&self, connections: &[Connection]) -> Vec<Candidate> {
        let mut seen = HashSet::new();
        let mut candidates = Vec::new();
        for connection in connections {
            let protocol = Protocol::from_u8(connection.protocol);
            if !matches!(protocol, Protocol::Tcp | Protocol::Udp) {
                continue;
            }
            let (Ok(local_addr), Ok(remote_addr)) = (
                connection.src_ip.parse::<IpAddr>(),
                connection.dst_ip.parse::<IpAddr>(),
            ) else {
                continue;
            };
            let endpoints = FlowEndpoints {
                local_addr,
                remote_addr,
                local_port: connection.src_port,
                remote_port: connection.dst_port,
                protocol: connection.protocol,
            };
            let Some(workload) = self.workloads.by_originated_flow(&endpoints) else {
                continue;
            };
            if seen.insert(workload.pid) {
                candidates.push(Candidate {
                    workload,
                    destination: Some((remote_addr, connection.dst_port, connection.protocol)),
                });
            }
        }
        candidates
    }

    /// The shells and interpreters the table holds that no connection named,
    /// tested only for streams on a socket.
    fn interpreter_candidates(&self, already: &HashSet<u32>) -> Vec<Candidate> {
        self.processes
            .list()
            .into_iter()
            .filter(|entry| !already.contains(&entry.pid))
            .filter(|entry| {
                entry
                    .identity
                    .path()
                    .is_some_and(|path| self.policy.is_interpreter(path))
            })
            .filter_map(|entry| self.workloads.by_pid(entry.pid))
            .map(|workload| Candidate {
                workload,
                destination: None,
            })
            .collect()
    }

    /// Test every candidate once and build the events for the ones that
    /// fire and were not reported before. Blocking: it reads proc files.
    fn detect(&self, connections: &[Connection], at_ns: u64) -> Vec<AlertEvent> {
        let mut candidates = self.flow_candidates(connections);
        let from_flows: HashSet<u32> = candidates.iter().map(|c| c.workload.pid).collect();
        let interpreters = self.interpreter_candidates(&from_flows);
        let from_flows_count = candidates.len();
        candidates.extend(interpreters);

        let mut reported = self
            .reported
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // A process that is gone can never be reported again, and its pid may
        // come back as somebody else.
        reported.retain(|(pid, start, _)| {
            self.processes
                .get(*pid)
                .is_some_and(|entry| entry.start_ns == *start)
        });

        let mut events = Vec::new();
        for (index, candidate) in candidates.into_iter().enumerate() {
            let facts = self.facts.read_facts(candidate.workload.pid);
            let holds_flow = index < from_flows_count;
            // A process found only in the table holds no connection it
            // opened, so only a stream on a socket says it talks to the
            // network at all.
            if !holds_flow && !facts.is_some_and(|f| f.streams_on_socket) {
                continue;
            }
            let Some(detection) = self.policy.evaluate(
                &candidate.workload,
                facts.unwrap_or(ProcessFacts::default()),
            ) else {
                continue;
            };
            let start = self
                .processes
                .get(candidate.workload.pid)
                .and_then(|entry| entry.start_ns);
            if !reported.insert((candidate.workload.pid, start, detection.kind)) {
                continue;
            }
            let alert = domain::alert::entity::Alert::from_process_detection(
                &detection,
                candidate.workload,
                candidate.destination,
                at_ns,
            );
            events.push(AlertEvent::ProcessDetection {
                alert: Box::new(alert),
                kill_process: self.kill_process,
            });
        }
        events
    }

    /// Read the tables once and send what fired, returning how many alerts
    /// were raised.
    pub async fn sample(self: &Arc<Self>) -> usize {
        let conntrack = Arc::clone(&self.conntrack);
        let rows = self.rows;
        let read =
            tokio::task::spawn_blocking(move || conntrack.blocking_read().get_connections(rows))
                .await;
        let connections = match read {
            Ok(Ok(connections)) => connections,
            Ok(Err(err)) => {
                // The interpreters are still worth testing without the table.
                warn!(error = %err, "process detection could not read the connection table");
                Vec::new()
            }
            Err(err) => {
                warn!(error = %err, "process detection sample did not run");
                return 0;
            }
        };
        let me = Arc::clone(self);
        let events =
            match tokio::task::spawn_blocking(move || me.detect(&connections, now_ns())).await {
                Ok(events) => events,
                Err(err) => {
                    warn!(error = %err, "process detection did not run");
                    return 0;
                }
            };
        let raised = events.len();
        for event in events {
            if self.alerts.send(event).await.is_err() {
                debug!("alert pipeline closed, process detection stops sending");
                break;
            }
        }
        raised
    }

    /// Sample until `cancel` fires.
    pub async fn run(self: Arc<Self>, interval: Duration, cancel: CancellationToken) {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                () = cancel.cancelled() => {
                    debug!("process detection stopped");
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
    use std::collections::HashMap;
    use std::net::Ipv4Addr;

    use domain::conntrack::entity::ConnectionState;
    use domain::dlp::entity::{DlpExecutable, DlpIdentitySource};
    use domain::process::entity::{ProcessEventKind, ProcessLifecycleEvent};
    use domain::workload::entity::WorkloadSource;
    use ports::secondary::process_executable_port::ProcessExecutableReader;
    use ports::secondary::socket_identity_port::{SocketIdentityReader, SocketOwner};
    use ports::test_utils::NoopMetrics;

    use super::*;

    const NGINX: u32 = 100;
    const WEB_SHELL: u32 = 200;
    const LOGIN_SHELL: u32 = 300;
    const NC_SHELL: u32 = 400;

    struct Executables;
    impl ProcessExecutableReader for Executables {
        fn read_executable(&self, pid: u32) -> Option<DlpExecutable> {
            let path = match pid {
                NGINX => "/usr/sbin/nginx",
                WEB_SHELL | LOGIN_SHELL | NC_SHELL => "/usr/bin/bash",
                _ => return None,
            };
            Some(DlpExecutable {
                path: path.to_string(),
                dev: 1,
                inode: u64::from(pid),
                source: DlpIdentitySource::ProcessAtAlertTime,
            })
        }
    }

    struct Facts(HashMap<u32, ProcessFacts>);
    impl ProcessFactsReader for Facts {
        fn read_facts(&self, pid: u32) -> Option<ProcessFacts> {
            Some(self.0.get(&pid).copied().unwrap_or_default())
        }
    }

    /// The web shell's connection, and nothing else.
    struct WebShellSocket;
    impl SocketIdentityReader for WebShellSocket {
        fn by_cookie(&self, _cookie: u64) -> Option<SocketOwner> {
            None
        }
        fn by_flow(&self, flow: &FlowEndpoints) -> Option<SocketOwner> {
            self.by_originated_flow(flow)
        }
        fn by_originated_flow(&self, flow: &FlowEndpoints) -> Option<SocketOwner> {
            (flow.remote_port == 4444).then_some(SocketOwner {
                pid: WEB_SHELL,
                tgid: WEB_SHELL,
                uid: 33,
                cgroup_id: 9,
                source: WorkloadSource::Flow,
            })
        }
    }

    fn egress() -> Connection {
        Connection {
            src_ip: "10.0.0.7".to_string(),
            dst_ip: "203.0.113.9".to_string(),
            src_port: 45_112,
            dst_port: 4444,
            protocol: 6,
            state: ConnectionState::Established,
            packets_fwd: 1,
            packets_rev: 1,
            bytes_fwd: 100,
            bytes_rev: 100,
            workload: None,
            reply: None,
        }
    }

    async fn exec(table: &ProcessTableService, pid: u32, parent: Option<u32>) {
        let mut event = ProcessLifecycleEvent::bare(ProcessEventKind::Exec, pid, "x", 1);
        event.start_ns = Some(u64::from(pid));
        event.parent_pid = parent;
        event.parent_start_ns = parent.map(u64::from);
        table.apply(event).await;
    }

    async fn detector(
        facts: HashMap<u32, ProcessFacts>,
    ) -> (ProcessDetector, mpsc::Receiver<AlertEvent>) {
        let table = ProcessTableService::new(64, false).with_executables(Arc::new(Executables));
        exec(&table, NGINX, None).await;
        exec(&table, WEB_SHELL, Some(NGINX)).await;
        exec(&table, LOGIN_SHELL, None).await;
        exec(&table, NC_SHELL, None).await;
        let table = Arc::new(table);
        let workloads = WorkloadResolver::new()
            .with_sockets(Box::new(WebShellSocket))
            .with_processes(Arc::clone(&table));
        let conntrack = Arc::new(RwLock::new(ConnTrackAppService::new(Arc::new(NoopMetrics))));
        let (tx, rx) = mpsc::channel(8);
        let detector = ProcessDetector::new(
            ProcessDetectionPolicy::default(),
            conntrack,
            workloads,
            table,
            Arc::new(Facts(facts)),
            tx,
        );
        (detector, rx)
    }

    fn alerts(events: &[AlertEvent]) -> Vec<(u32, String, bool)> {
        events
            .iter()
            .filter_map(|event| match event {
                AlertEvent::ProcessDetection {
                    alert,
                    kill_process,
                } => Some((
                    alert.workload.as_ref().map_or(0, |w| w.pid),
                    alert.rule_id.0.clone(),
                    *kill_process,
                )),
                _ => None,
            })
            .collect()
    }

    #[tokio::test]
    async fn a_shell_under_a_server_dialling_out_raises_once_with_its_ancestry() {
        let (detector, _rx) = detector(HashMap::new()).await;
        let events = detector.detect(&[egress()], 7);
        assert_eq!(
            alerts(&events),
            vec![(WEB_SHELL, "process-reverse-shell".to_string(), false)]
        );
        let AlertEvent::ProcessDetection { alert, .. } = &events[0] else {
            panic!("a process detection");
        };
        assert_eq!(alert.dst_port, 4444);
        assert_eq!(alert.dst_addr[0], u32::from(Ipv4Addr::new(203, 0, 113, 9)));
        let chain = alert
            .workload
            .as_ref()
            .and_then(|w| w.ancestry.as_ref())
            .expect("the ancestry travels");
        assert_eq!(chain.ancestors[0].pid, NGINX);
        assert!(
            detector.detect(&[egress()], 8).is_empty(),
            "a process is reported once per detection"
        );
    }

    #[tokio::test]
    async fn a_shell_handed_a_socket_is_found_without_a_connection_of_its_own() {
        let facts = HashMap::from([(
            NC_SHELL,
            ProcessFacts {
                streams_on_socket: true,
                fileless: false,
            },
        )]);
        let (detector, _rx) = detector(facts).await;
        let detector = detector.with_kill_process(true);
        assert_eq!(
            alerts(&detector.detect(&[], 7)),
            vec![(NC_SHELL, "process-reverse-shell".to_string(), true)],
            "the login shell, on a terminal, stays quiet"
        );
    }

    #[tokio::test]
    async fn a_sample_sends_what_fired_to_the_pipeline() {
        let facts = HashMap::from([(
            NC_SHELL,
            ProcessFacts {
                streams_on_socket: true,
                fileless: false,
            },
        )]);
        let (detector, mut rx) = detector(facts).await;
        let detector = Arc::new(detector);
        assert_eq!(detector.sample().await, 1);
        assert!(matches!(
            rx.try_recv(),
            Ok(AlertEvent::ProcessDetection { .. })
        ));
    }
}
