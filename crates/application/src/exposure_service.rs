//! What this node listens on, and who for.
//!
//! The socket hooks record every bind with the task that made it; this turns
//! that table into the listeners an operator reads: only the sockets that
//! accept traffic, one row per address, port and process however many
//! sockets a `SO_REUSEPORT` server spread itself over, and the widest scope
//! first, because a socket bound on every address is the one nobody may have
//! meant to expose.

use std::collections::BTreeMap;
use std::net::IpAddr;

use domain::exposure::entity::{BoundSocket, ListenerProtocol, ListenerScope};
use domain::workload::entity::Workload;

use crate::workload_resolver::WorkloadResolver;

/// One address and port a process accepts traffic on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listener {
    pub address: IpAddr,
    pub port: u16,
    pub protocol: ListenerProtocol,
    pub scope: ListenerScope,
    /// How many sockets the process holds on this address and port: more
    /// than one is a server that spread its accept over `SO_REUSEPORT`.
    pub sockets: u32,
    /// The earliest of their binds, in nanoseconds of boot time.
    pub bound_at_ns: u64,
    pub workload: Workload,
}

/// Lists the node's listeners from the socket tables the resolver holds.
#[derive(Clone)]
pub struct ExposureService {
    workloads: WorkloadResolver,
}

impl ExposureService {
    /// Share `workloads`, so a reload installing or clearing the socket
    /// tables is seen here at the same instant as everywhere else.
    #[must_use]
    pub fn new(workloads: WorkloadResolver) -> Self {
        Self { workloads }
    }

    /// The listeners, widest scope first, or `None` when the socket hooks are
    /// not attached on this node.
    #[must_use]
    pub fn listeners(&self) -> Option<Vec<Listener>> {
        Some(listeners_of(self.workloads.bound_sockets()?))
    }
}

type RowKey = (ListenerScope, ListenerProtocol, u16, IpAddr, u32);

fn listeners_of(bound: Vec<(BoundSocket, Workload)>) -> Vec<Listener> {
    let mut rows: BTreeMap<RowKey, Listener> = BTreeMap::new();
    for (socket, workload) in bound {
        if !socket.accepts() {
            continue;
        }
        let key = (
            socket.scope(),
            socket.protocol,
            socket.port,
            socket.address,
            socket.pid,
        );
        rows.entry(key)
            .and_modify(|row| {
                row.sockets = row.sockets.saturating_add(1);
                row.bound_at_ns = row.bound_at_ns.min(socket.bound_at_ns);
            })
            .or_insert_with(|| Listener {
                address: socket.address,
                port: socket.port,
                protocol: socket.protocol,
                scope: socket.scope(),
                sockets: 1,
                bound_at_ns: socket.bound_at_ns,
                workload,
            });
    }
    rows.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::workload::entity::WorkloadSource;
    use ports::secondary::socket_identity_port::{
        FlowEndpoints, SocketIdentityReader, SocketOwner,
    };
    use std::net::Ipv4Addr;

    fn bound(
        address: [u8; 4],
        port: u16,
        protocol: ListenerProtocol,
        listening: bool,
        pid: u32,
        at: u64,
    ) -> BoundSocket {
        BoundSocket {
            address: IpAddr::V4(Ipv4Addr::from(address)),
            port,
            protocol,
            listening,
            pid,
            uid: 0,
            cgroup_id: 9,
            bound_at_ns: at,
        }
    }

    struct Table(Vec<BoundSocket>);

    impl SocketIdentityReader for Table {
        fn by_cookie(&self, _cookie: u64) -> Option<SocketOwner> {
            None
        }
        fn by_flow(&self, _flow: &FlowEndpoints) -> Option<SocketOwner> {
            None
        }
        fn by_originated_flow(&self, _flow: &FlowEndpoints) -> Option<SocketOwner> {
            None
        }
        fn bound_sockets(&self) -> Vec<BoundSocket> {
            self.0.clone()
        }
    }

    #[test]
    fn a_node_without_the_hooks_does_not_know_its_listeners() {
        let service = ExposureService::new(WorkloadResolver::new());
        assert!(service.listeners().is_none());
    }

    #[test]
    fn the_widest_scope_comes_first_and_a_client_that_bound_is_not_a_listener() {
        let resolver = WorkloadResolver::new().with_sockets(Box::new(Table(vec![
            bound([127, 0, 0, 1], 5432, ListenerProtocol::Tcp, true, 10, 1),
            bound([10, 0, 0, 7], 443, ListenerProtocol::Tcp, true, 11, 1),
            bound([0, 0, 0, 0], 6379, ListenerProtocol::Tcp, true, 12, 1),
            bound([0, 0, 0, 0], 53, ListenerProtocol::Udp, false, 13, 1),
            bound([10, 0, 0, 7], 40_000, ListenerProtocol::Tcp, false, 14, 1),
        ])));
        let listeners = ExposureService::new(resolver).listeners().unwrap();
        let ports: Vec<u16> = listeners.iter().map(|l| l.port).collect();
        assert_eq!(ports, [6379, 53, 443, 5432]);
        assert_eq!(listeners[0].scope, ListenerScope::AllAddresses);
        assert_eq!(listeners[0].workload.pid, 12);
        assert_eq!(listeners[0].workload.cgroup, Some(9));
        assert_eq!(listeners[0].workload.source, WorkloadSource::Socket);
        assert_eq!(listeners[3].scope, ListenerScope::Loopback);
    }

    #[test]
    fn a_reuseport_server_is_one_row_counting_its_sockets_from_its_first_bind() {
        let resolver = WorkloadResolver::new().with_sockets(Box::new(Table(vec![
            bound([0, 0, 0, 0], 80, ListenerProtocol::Tcp, true, 20, 30),
            bound([0, 0, 0, 0], 80, ListenerProtocol::Tcp, true, 20, 10),
            bound([0, 0, 0, 0], 80, ListenerProtocol::Tcp, true, 21, 50),
        ])));
        let listeners = ExposureService::new(resolver).listeners().unwrap();
        assert_eq!(listeners.len(), 2);
        assert_eq!(listeners[0].sockets, 2);
        assert_eq!(listeners[0].bound_at_ns, 10);
        assert_eq!(listeners[1].sockets, 1);
    }
}
