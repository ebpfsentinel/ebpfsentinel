//! Where the learning window gets what it folds.
//!
//! There is no kernel event for "a workload opened a connection": the
//! attribution hooks fill lookup tables and the workload firewall's ring
//! buffer carries refusals, which is the opposite of what a first policy is
//! written from. What this node did reach is in the kernel's own connection
//! table, so the sampler reads that table on an interval and folds what it
//! finds into the open window.
//!
//! The connection table is the host's own, and a connection between two
//! containers on one bridge is switched inside the bridge without ever
//! reaching it, unless the bridge hands its frames to netfilter. So each
//! sample also lists the attribution hooks' flow index, which every
//! `connect()` on the node writes whatever namespace the socket lives in,
//! and folds what the table did not already carry.
//!
//! The cost of reading a table rather than a stream is stated rather than
//! hidden: a flow that opens and closes between two samples is never seen,
//! and a flow that lives across ten samples is folded ten times. The first
//! is why a window has to be long enough, the second is why the aggregate
//! counts distinct edges rather than connections, and both travel with the
//! document the window produces.

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwapOption;
use domain::common::entity::Protocol;
use domain::conntrack::entity::Connection;
use domain::learning::entity::{ObservedFlow, ObservedWorkload};
use ports::secondary::socket_identity_port::FlowEndpoints;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::conntrack_service_impl::ConnTrackAppService;
use crate::learning_service::{LearningAppService, now_ns};
use crate::process_table_service::ProcessTableService;
use crate::workload_policy_service::workload_of;
use crate::workload_resolver::WorkloadResolver;

/// How often the open window reads the connection table.
///
/// Ten seconds is the compromise the limitation above forces: often enough
/// that a short-lived connection has a chance of being present for one
/// sample, rare enough that a window of a day is 8 640 reads of a proc file
/// rather than a hundred thousand.
pub const LEARNING_SAMPLE_INTERVAL: Duration = Duration::from_secs(10);

/// Rows read from the connection table in one sample.
///
/// The table on a busy node is large and the window only needs destinations,
/// so the read is bounded: a node past this in one sample learns the first
/// rows of it and says so through the dropped count rather than stalling a
/// worker on a megabyte of proc file.
pub const LEARNING_SAMPLE_ROWS: usize = 16_384;

/// Reads the connection table on an interval and folds it into the window.
pub struct LearningCollector {
    learning: Arc<LearningAppService>,
    conntrack: Arc<RwLock<ConnTrackAppService>>,
    workloads: WorkloadResolver,
    processes: ArcSwapOption<ProcessTableService>,
    rows: usize,
}

impl LearningCollector {
    /// A collector that will read `conntrack` for `learning`.
    #[must_use]
    pub fn new(
        learning: Arc<LearningAppService>,
        conntrack: Arc<RwLock<ConnTrackAppService>>,
        workloads: WorkloadResolver,
    ) -> Self {
        Self {
            learning,
            conntrack,
            workloads,
            processes: ArcSwapOption::empty(),
            rows: LEARNING_SAMPLE_ROWS,
        }
    }

    /// Name the cgroup and the container through the process table.
    ///
    /// Without it a flow still names its executable and its container id,
    /// which is what the socket tables carry; with it a rule can be written
    /// against a unit, a cgroup subtree or a container name.
    pub fn install_processes(&self, processes: Arc<ProcessTableService>) {
        self.processes.store(Some(processes));
    }

    /// Everything one row says about the workload at its originating end.
    fn observed_workload(
        &self,
        pid: u32,
        flow: &domain::workload::entity::Workload,
    ) -> ObservedWorkload {
        let mut observed = ObservedWorkload {
            exe: flow.exe.clone(),
            unit: flow.unit.clone(),
            cgroup: None,
            container_id: flow.container.clone(),
            container_name: None,
        };
        if let Some(entry) = self.processes.load().as_ref().and_then(|p| p.get(pid)) {
            let resolved = workload_of(&entry);
            observed.exe = resolved.exe.or(observed.exe);
            observed.unit = resolved.unit.or(observed.unit);
            observed.cgroup = resolved.cgroup;
            observed.container_id = resolved.container_id.or(observed.container_id);
            observed.container_name = resolved.container_name;
        }
        observed
    }

    /// The flows one reading of the table offers the window.
    ///
    /// A row whose local end is this node's listening side is not an edge at
    /// all and is left out: the destination on it is a client's ephemeral
    /// port, and a policy carrying that would allow a address nobody dialled.
    /// A row nothing can be attributed to is kept, with no workload, because
    /// the window has to be able to say how much of what it saw it could not
    /// name.
    fn flows_of(&self, connections: &[Connection]) -> Vec<ObservedFlow> {
        let mut flows = Vec::new();
        for connection in connections {
            // The workload firewall decides at connect, sendmsg and bind, so
            // a destination it could never carry is not worth learning.
            let protocol = Protocol::from_u8(connection.protocol);
            if !matches!(protocol, Protocol::Tcp | Protocol::Udp) {
                continue;
            }
            let (Ok(local_addr), Ok(remote_addr)) = (
                connection.src_ip.parse(),
                connection.dst_ip.parse::<std::net::IpAddr>(),
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
            let workload = if let Some(workload) = self.workloads.by_originated_flow(&endpoints) {
                self.observed_workload(workload.pid, &workload)
            } else {
                if self.workloads.by_flow(&endpoints).is_some() {
                    // Attributable the other way round: this node accepted
                    // the connection rather than opening it.
                    continue;
                }
                ObservedWorkload::default()
            };
            flows.push(ObservedFlow {
                workload,
                source: local_addr,
                destination: remote_addr,
                port: connection.dst_port,
                protocol,
            });
        }
        flows
    }

    /// The connections the flow index holds as opened on this node that the
    /// rows read did not already carry, each with the workload that opened
    /// it.
    ///
    /// The index keeps a connection for a while after it was opened, so one
    /// opened before the window is left out: the window learns what ran
    /// while it was open, not what ran just before.
    fn originated_beside(&self, connections: &[Connection], now_ns: u64) -> Vec<ObservedFlow> {
        let Some(window) = self.learning.active_session() else {
            return Vec::new();
        };
        let open_for = now_ns.saturating_sub(window.started_at_ns);
        let read: std::collections::HashSet<(String, u16, String, u16, u8)> = connections
            .iter()
            .map(|c| {
                (
                    c.src_ip.clone(),
                    c.src_port,
                    c.dst_ip.clone(),
                    c.dst_port,
                    c.protocol,
                )
            })
            .collect();
        self.workloads
            .originated_flows(open_for)
            .into_iter()
            .filter(|(flow, _)| {
                !read.contains(&(
                    flow.local_addr.to_string(),
                    flow.local_port,
                    flow.remote_addr.to_string(),
                    flow.remote_port,
                    flow.protocol,
                ))
            })
            .filter_map(|(flow, workload)| {
                let protocol = Protocol::from_u8(flow.protocol);
                if !matches!(protocol, Protocol::Tcp | Protocol::Udp) {
                    return None;
                }
                Some(ObservedFlow {
                    workload: self.observed_workload(workload.pid, &workload),
                    source: flow.local_addr,
                    destination: flow.remote_addr,
                    port: flow.remote_port,
                    protocol,
                })
            })
            .collect()
    }

    /// Read the table once and fold it, returning the destinations the
    /// window had not seen before.
    pub async fn sample(&self, now_ns: u64) -> usize {
        if self.learning.tick(now_ns).is_some() {
            return 0;
        }
        if !self.learning.is_observing() {
            return 0;
        }
        let conntrack = Arc::clone(&self.conntrack);
        let rows = self.rows;
        // The read reaches the proc file, a `conntrack` dump or the warden,
        // all of them blocking, so it runs off the async worker.
        let read =
            tokio::task::spawn_blocking(move || conntrack.blocking_read().get_connections(rows))
                .await;
        let (connections, read) = match read {
            Ok(Ok(connections)) => (connections, true),
            Ok(Err(err)) => {
                warn!(error = %err, "learning sample could not read the connection table");
                (Vec::new(), false)
            }
            Err(err) => {
                warn!(error = %err, "learning sample did not run");
                (Vec::new(), false)
            }
        };
        let mut flows = self.flows_of(&connections);
        flows.extend(self.originated_beside(&connections, now_ns));
        if !read && flows.is_empty() {
            // The agent is up even though this sample is empty, and the
            // window must not come back looking like one the agent slept
            // through.
            self.learning.touch(now_ns);
            return 0;
        }
        let new_edges = self.learning.observe(&flows, now_ns);
        debug!(
            rows = connections.len(),
            flows = flows.len(),
            new_edges,
            "learning sample folded"
        );
        new_edges
    }

    /// Sample until `cancel` fires, then leave the open window interrupted
    /// rather than running: nobody is watching it any more.
    pub async fn run(self: Arc<Self>, interval: Duration, cancel: CancellationToken) {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                () = cancel.cancelled() => {
                    self.learning.interrupt_running(now_ns());
                    debug!("learning sampler stopped");
                    break;
                }
                _ = ticker.tick() => {
                    self.sample(now_ns()).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use domain::conntrack::entity::ConnectionState;
    use domain::learning::entity::LearningScope;
    use domain::workload::entity::WorkloadSource;
    use ports::secondary::socket_identity_port::{SocketIdentityReader, SocketOwner};
    use ports::test_utils::NoopMetrics;

    use super::*;

    const SEC: u64 = 1_000_000_000;

    /// Answers for one originating five-tuple and for nothing else, which is
    /// what the kernel table does.
    struct OneSocket {
        endpoints: FlowEndpoints,
        owner: SocketOwner,
    }

    impl SocketIdentityReader for OneSocket {
        fn by_cookie(&self, _cookie: u64) -> Option<SocketOwner> {
            None
        }

        fn by_flow(&self, flow: &FlowEndpoints) -> Option<SocketOwner> {
            let mirrored = FlowEndpoints {
                local_addr: flow.remote_addr,
                remote_addr: flow.local_addr,
                local_port: flow.remote_port,
                remote_port: flow.local_port,
                protocol: flow.protocol,
            };
            (self.endpoints == *flow || self.endpoints == mirrored).then_some(self.owner)
        }

        fn by_originated_flow(&self, flow: &FlowEndpoints) -> Option<SocketOwner> {
            (self.endpoints == *flow).then_some(self.owner)
        }
    }

    fn connection(src: &str, sport: u16, dst: &str, dport: u16, protocol: u8) -> Connection {
        Connection {
            src_ip: src.to_string(),
            dst_ip: dst.to_string(),
            src_port: sport,
            dst_port: dport,
            protocol,
            state: ConnectionState::Established,
            packets_fwd: 1,
            packets_rev: 1,
            bytes_fwd: 100,
            bytes_rev: 100,
            workload: None,
            reply: None,
        }
    }

    fn collector(reader: OneSocket) -> LearningCollector {
        let learning = Arc::new(LearningAppService::new(64, Arc::new(NoopMetrics)));
        learning
            .start(LearningScope::Node, 600, 1_000 * SEC)
            .expect("the window opens");
        let conntrack = Arc::new(RwLock::new(ConnTrackAppService::new(Arc::new(NoopMetrics))));
        let workloads = WorkloadResolver::new().with_sockets(Box::new(reader));
        LearningCollector::new(learning, conntrack, workloads)
    }

    fn egress() -> FlowEndpoints {
        FlowEndpoints {
            local_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)),
            remote_addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
            local_port: 45_112,
            remote_port: 443,
            protocol: 6,
        }
    }

    fn owner() -> SocketOwner {
        SocketOwner {
            pid: 4_242,
            tgid: 4_242,
            uid: 0,
            cgroup_id: 77,
            source: WorkloadSource::Flow,
        }
    }

    #[test]
    fn a_connection_this_node_opened_becomes_an_edge() {
        let collector = collector(OneSocket {
            endpoints: egress(),
            owner: owner(),
        });
        let flows = collector.flows_of(&[connection("10.0.0.7", 45_112, "203.0.113.9", 443, 6)]);
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].port, 443);
        assert_eq!(
            flows[0].destination,
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))
        );
    }

    #[test]
    fn a_connection_this_node_accepted_is_not_an_edge() {
        let collector = collector(OneSocket {
            endpoints: FlowEndpoints {
                local_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)),
                remote_addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
                local_port: 443,
                remote_port: 51_000,
                protocol: 6,
            },
            owner: owner(),
        });
        let flows = collector.flows_of(&[connection("203.0.113.9", 51_000, "10.0.0.7", 443, 6)]);
        assert!(
            flows.is_empty(),
            "a client's ephemeral port is not a destination a policy carries"
        );
    }

    #[test]
    fn a_flow_nothing_can_name_is_kept_and_carries_no_workload() {
        let collector = collector(OneSocket {
            endpoints: egress(),
            owner: owner(),
        });
        let flows = collector.flows_of(&[connection("10.0.0.7", 51_001, "198.51.100.4", 53, 17)]);
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].workload, ObservedWorkload::default());
    }

    #[test]
    fn a_protocol_no_workload_rule_can_carry_is_left_out() {
        let collector = collector(OneSocket {
            endpoints: egress(),
            owner: owner(),
        });
        let flows = collector.flows_of(&[connection("10.0.0.7", 0, "198.51.100.4", 0, 1)]);
        assert!(flows.is_empty(), "an ICMP row names no port to allow");
    }

    #[tokio::test]
    async fn a_sample_with_no_connection_table_still_says_the_agent_was_up() {
        let collector = collector(OneSocket {
            endpoints: egress(),
            owner: owner(),
        });
        assert_eq!(collector.sample(1_100 * SEC).await, 0);
        let progress = collector
            .learning
            .progress(None, 1_100 * SEC)
            .expect("the window is open");
        assert!(progress.continuous);
        assert_eq!(progress.edges, 0);
    }

    /// A flow index holding one connection opened on this node, which the
    /// host's connection table never saw.
    /// A reader whose index holds one connection, opened this long ago.
    struct Indexed(OneSocket, u64);

    impl SocketIdentityReader for Indexed {
        fn by_cookie(&self, cookie: u64) -> Option<SocketOwner> {
            self.0.by_cookie(cookie)
        }

        fn by_flow(&self, flow: &FlowEndpoints) -> Option<SocketOwner> {
            self.0.by_flow(flow)
        }

        fn by_originated_flow(&self, flow: &FlowEndpoints) -> Option<SocketOwner> {
            self.0.by_originated_flow(flow)
        }

        fn originated_flows(&self, within_ns: u64) -> Vec<(FlowEndpoints, SocketOwner)> {
            if self.1 > within_ns {
                return Vec::new();
            }
            vec![(self.0.endpoints, self.0.owner)]
        }
    }

    fn indexed_collector(opened_ago_ns: u64) -> LearningCollector {
        let learning = Arc::new(LearningAppService::new(64, Arc::new(NoopMetrics)));
        learning
            .start(LearningScope::Node, 600, 1_000 * SEC)
            .expect("the window opens");
        let conntrack = Arc::new(RwLock::new(ConnTrackAppService::new(Arc::new(NoopMetrics))));
        let workloads = WorkloadResolver::new().with_sockets(Box::new(Indexed(
            OneSocket {
                endpoints: egress(),
                owner: owner(),
            },
            opened_ago_ns,
        )));
        LearningCollector::new(learning, conntrack, workloads)
    }

    #[tokio::test]
    async fn a_connection_the_host_table_never_saw_is_learned_from_the_flow_index() {
        let collector = indexed_collector(30 * SEC);
        // The test reader names a pid no process table describes, so the
        // flow is folded as seen and unattributed: what matters is that it
        // reached the window at all.
        collector.sample(1_100 * SEC).await;
        let progress = collector
            .learning
            .progress(None, 1_100 * SEC)
            .expect("the window is open");
        assert_eq!(progress.observations, 1);
        let flows = collector.originated_beside(&[], 1_100 * SEC);
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].port, 443);
        assert_eq!(flows[0].source, egress().local_addr);
        assert_eq!(flows[0].destination, egress().remote_addr);
    }

    #[test]
    fn a_connection_both_tables_hold_is_folded_once() {
        let collector = indexed_collector(30 * SEC);
        let rows = [connection("10.0.0.7", 45_112, "203.0.113.9", 443, 6)];
        assert_eq!(collector.flows_of(&rows).len(), 1);
        assert!(collector.originated_beside(&rows, 1_100 * SEC).is_empty());
    }

    #[tokio::test]
    async fn a_connection_opened_before_the_window_is_not_learned() {
        // The window opened 100 s ago; the connection was opened 150 s ago.
        let collector = indexed_collector(150 * SEC);
        collector.sample(1_100 * SEC).await;
        let progress = collector
            .learning
            .progress(None, 1_100 * SEC)
            .expect("the window is open");
        assert_eq!(progress.observations, 0);
    }

    #[tokio::test]
    async fn a_sample_past_the_deadline_closes_the_window() {
        let collector = collector(OneSocket {
            endpoints: egress(),
            owner: owner(),
        });
        assert_eq!(collector.sample(2_000 * SEC).await, 0);
        assert!(!collector.learning.is_observing());
    }
}
