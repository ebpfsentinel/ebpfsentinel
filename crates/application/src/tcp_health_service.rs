//! TCP health per edge, read on a cadence and published per service pair.
//!
//! Each poll reads the kernel-side counter whole, takes what moved since the
//! last poll, names both ends of every edge that moved and adds it to the
//! Prometheus counters under those names. The kernel keys an edge by its
//! addresses, so naming is where the cardinality is bounded: the local end
//! is the service holding the socket, the peer is a service only when it
//! runs on this node too, and every name passes the same cap the request
//! meter uses.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};

use domain::exposure::entity::ListenerProtocol;
use domain::l7::red::{ServiceNames, UNATTRIBUTED_SERVICE, service_name};
use domain::tcp_health::{EdgeRole, NO_LISTENER, RawTcpEdge, TcpEdgeDeltas, TcpEdgeId};
use ports::secondary::metrics_port::PacketMetrics;
use ports::secondary::tcp_health_port::TcpHealthPort;
use tracing::warn;

use crate::workload_resolver::WorkloadResolver;

/// The peer of an edge whose other end does not run on this node. The
/// agent on that node counts the same connection under its own name.
pub const OFF_NODE_PEER: &str = "off_node";

struct State {
    deltas: TcpEdgeDeltas,
    names: ServiceNames,
}

pub struct TcpHealthService {
    source: Box<dyn TcpHealthPort>,
    metrics: Arc<dyn PacketMetrics>,
    workloads: WorkloadResolver,
    state: Mutex<State>,
}

/// The services this node's listening sockets belong to, by address and
/// port, read once per poll.
struct Listeners(Vec<(IpAddr, u16, String)>);

impl Listeners {
    fn read(workloads: &WorkloadResolver) -> Self {
        Self(
            workloads
                .bound_sockets()
                .unwrap_or_default()
                .into_iter()
                .filter(|(socket, _)| socket.protocol == ListenerProtocol::Tcp && socket.listening)
                .map(|(socket, workload)| (socket.address, socket.port, service_name(&workload)))
                .collect(),
        )
    }

    /// The service accepting on `address` and `port`, a socket bound to that
    /// address first and one bound to every address after it.
    fn on(&self, address: IpAddr, port: u16) -> Option<&str> {
        let exact = self.0.iter().find(|(a, p, _)| *p == port && *a == address);
        let wildcard = || {
            self.0
                .iter()
                .find(|(a, p, _)| *p == port && a.is_unspecified())
        };
        exact.or_else(wildcard).map(|(_, _, name)| name.as_str())
    }
}

impl TcpHealthService {
    #[must_use]
    pub fn new(
        source: Box<dyn TcpHealthPort>,
        metrics: Arc<dyn PacketMetrics>,
        workloads: WorkloadResolver,
    ) -> Self {
        Self {
            source,
            metrics,
            workloads,
            state: Mutex::new(State {
                deltas: TcpEdgeDeltas::default(),
                names: ServiceNames::default(),
            }),
        }
    }

    /// Read the counter once and publish what moved.
    pub fn poll(&self) {
        let (edges, uncounted) = match self.source.read() {
            Ok(read) => read,
            Err(e) => {
                warn!(error = %e, "TCP health counter read failed");
                return;
            }
        };
        let listeners = Listeners::read(&self.workloads);
        let mut by_cgroup: HashMap<u64, Option<String>> = HashMap::new();
        let mut local_name = |id: &TcpEdgeId| -> String {
            if id.is_no_listener() {
                return NO_LISTENER.to_string();
            }
            if id.role == EdgeRole::Server
                && let Some(name) = listeners.on(id.local, id.port)
            {
                return name.to_string();
            }
            by_cgroup
                .entry(id.cgroup)
                .or_insert_with(|| {
                    self.workloads
                        .by_cgroup(id.cgroup)
                        .map(|workload| service_name(&workload))
                })
                .clone()
                .unwrap_or_else(|| UNATTRIBUTED_SERVICE.to_string())
        };
        // Where both ends run here, the kernel holds the connection twice,
        // once from each socket: the peer of one key is the local end of its
        // mirror.
        let mut named: HashMap<TcpEdgeId, String> = HashMap::with_capacity(edges.len());
        let mut mirrors: HashMap<TcpEdgeId, String> = HashMap::with_capacity(edges.len());
        for edge in &edges {
            let name = local_name(&edge.id);
            mirrors.insert(without_cgroup(&edge.id), name.clone());
            named.insert(edge.id, name);
        }

        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let increments = state.deltas.advance(&edges, uncounted);
        for RawTcpEdge { id, counts } in &increments.edges {
            let local = named
                .get(id)
                .cloned()
                .unwrap_or_else(|| UNATTRIBUTED_SERVICE.to_string());
            let peer = mirror_of(id)
                .and_then(|mirror| mirrors.get(&mirror).cloned())
                .or_else(|| {
                    (id.role == EdgeRole::Client)
                        .then(|| listeners.on(id.remote, id.port).map(str::to_string))
                        .flatten()
                })
                .unwrap_or_else(|| OFF_NODE_PEER.to_string());
            let local = state.names.admit(local);
            let peer = state.names.admit(peer);
            self.metrics
                .record_tcp_edge(&local, &peer, id.role.as_str(), counts);
        }
        if increments.uncounted > 0 {
            self.metrics
                .record_tcp_health_uncounted(increments.uncounted);
        }
    }
}

/// An edge's identity with its cgroup left out, which is how its mirror
/// finds it.
fn without_cgroup(id: &TcpEdgeId) -> TcpEdgeId {
    TcpEdgeId { cgroup: 0, ..*id }
}

/// The key the other end of the same connection is held under, when it runs
/// on this node. The cgroup is the other socket's own and is not known from
/// this side, so the mirror is found by its addresses, port and role.
fn mirror_of(id: &TcpEdgeId) -> Option<TcpEdgeId> {
    if id.is_no_listener() {
        return None;
    }
    Some(TcpEdgeId {
        local: id.remote,
        remote: id.local,
        port: id.port,
        role: match id.role {
            EdgeRole::Client => EdgeRole::Server,
            EdgeRole::Server => EdgeRole::Client,
        },
        cgroup: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::common::error::DomainError;
    use domain::tcp_health::TcpCounts;
    use std::net::Ipv4Addr;

    type Recorded = Vec<(String, String, String, TcpCounts)>;

    #[derive(Default)]
    struct Recorder {
        edges: Mutex<Recorded>,
        uncounted: Mutex<u64>,
    }

    impl PacketMetrics for Recorder {
        fn record_tcp_edge(&self, service: &str, peer: &str, role: &str, counts: &TcpCounts) {
            self.edges.lock().unwrap().push((
                service.to_string(),
                peer.to_string(),
                role.to_string(),
                *counts,
            ));
        }
        fn record_tcp_health_uncounted(&self, count: u64) {
            *self.uncounted.lock().unwrap() += count;
        }
    }

    struct Fixed(Mutex<Vec<(Vec<RawTcpEdge>, u64)>>);

    impl TcpHealthPort for Fixed {
        fn read(&self) -> Result<(Vec<RawTcpEdge>, u64), DomainError> {
            let mut readings = self.0.lock().unwrap();
            if readings.is_empty() {
                return Err(DomainError::EngineError("gone".into()));
            }
            Ok(readings.remove(0))
        }
    }

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    fn edge(local: u8, remote: u8, port: u16, role: EdgeRole, counts: TcpCounts) -> RawTcpEdge {
        RawTcpEdge {
            id: TcpEdgeId {
                local: ip(local),
                remote: ip(remote),
                port,
                role,
                cgroup: 0,
            },
            counts,
        }
    }

    fn service(readings: Vec<(Vec<RawTcpEdge>, u64)>) -> (TcpHealthService, Arc<Recorder>) {
        let recorder = Arc::new(Recorder::default());
        let service = TcpHealthService::new(
            Box::new(Fixed(Mutex::new(readings))),
            Arc::clone(&recorder) as Arc<dyn PacketMetrics>,
            WorkloadResolver::new(),
        );
        (service, recorder)
    }

    #[test]
    fn what_moved_is_published_once_under_unattributed_and_off_node_names() {
        let opened = TcpCounts {
            opened: 2,
            ..TcpCounts::default()
        };
        let (service, recorder) = service(vec![
            (vec![edge(1, 2, 443, EdgeRole::Client, opened)], 3),
            (vec![edge(1, 2, 443, EdgeRole::Client, opened)], 3),
        ]);
        service.poll();
        service.poll();
        // A failed read publishes nothing and keeps the deltas.
        service.poll();
        let edges = recorder.edges.lock().unwrap();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].0, UNATTRIBUTED_SERVICE);
        assert_eq!(edges[0].1, OFF_NODE_PEER);
        assert_eq!(edges[0].2, "client");
        assert_eq!(edges[0].3.opened, 2);
        assert_eq!(*recorder.uncounted.lock().unwrap(), 3);
    }

    #[test]
    fn a_reset_with_no_socket_is_counted_under_no_listener() {
        let reset = TcpCounts {
            resets_sent: 40,
            ..TcpCounts::default()
        };
        let (service, recorder) = service(vec![(vec![edge(1, 9, 0, EdgeRole::Server, reset)], 0)]);
        service.poll();
        let edges = recorder.edges.lock().unwrap();
        assert_eq!(edges[0].0, NO_LISTENER);
        assert_eq!(edges[0].1, OFF_NODE_PEER);
        assert_eq!(edges[0].3.resets_sent, 40);
    }

    #[test]
    fn the_mirror_of_an_edge_is_the_other_socket_of_the_same_connection() {
        let id = edge(1, 2, 5432, EdgeRole::Client, TcpCounts::default()).id;
        let mirror = mirror_of(&id).expect("a connection has two ends");
        assert_eq!(mirror.local, ip(2));
        assert_eq!(mirror.remote, ip(1));
        assert_eq!(mirror.role, EdgeRole::Server);
        let mut held = edge(2, 1, 5432, EdgeRole::Server, TcpCounts::default()).id;
        held.cgroup = 99;
        assert_eq!(without_cgroup(&held), mirror);
        assert!(mirror_of(&edge(1, 2, 0, EdgeRole::Server, TcpCounts::default()).id).is_none());
    }
}
