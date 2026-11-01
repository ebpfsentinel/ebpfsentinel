//! What this node listens on, and who for.
//!
//! The socket hooks record every bind with the task that made it; this turns
//! that table into the listeners an operator reads: only the sockets that
//! accept traffic, one row per address, port and process however many
//! sockets a `SO_REUSEPORT` server spread itself over, and the widest scope
//! first, because a socket bound on every address is the one nobody may have
//! meant to expose.
//!
//! Each row is then read against the two other halves of an exposure: who
//! the packet firewall lets through to it, and whether anybody connected.
//! Listening, allowed and observed in one row is what turns an inventory into
//! a finding: a socket open to everything that nobody has used is one to close.

use std::collections::BTreeMap;
use std::net::IpAddr;

use domain::exposure::entity::{
    AcceptedConnections, BoundSocket, ExposureClass, ListenerProtocol, ListenerScope,
};
use domain::exposure::reach::{FirewallPosture, ListenerEndpoint, Reach, reach_of};
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
    /// Who the packet firewall lets through to it.
    pub reach: Reach,
    /// TCP connections accepted on it since the hooks attached, `None` for a
    /// transport whose use is not counted.
    pub accepted: Option<u64>,
    /// The last of them, in nanoseconds of boot time.
    pub last_accepted_at_ns: Option<u64>,
    pub class: ExposureClass,
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

    /// The listeners, widest scope first, each read against `posture` and
    /// the connections counted, or `None` when the socket hooks are not
    /// attached on this node.
    #[must_use]
    pub fn listeners(&self, posture: &FirewallPosture) -> Option<Vec<Listener>> {
        let bound = self.workloads.bound_sockets()?;
        let accepted = self.workloads.accepted_connections().unwrap_or_default();
        Some(listeners_of(bound, &accepted, posture))
    }
}

type RowKey = (ListenerScope, ListenerProtocol, u16, IpAddr, u32);

fn listeners_of(
    bound: Vec<(BoundSocket, Workload)>,
    accepted: &[AcceptedConnections],
    posture: &FirewallPosture,
) -> Vec<Listener> {
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
            .or_insert_with(|| row(&socket, workload, accepted, posture));
    }
    rows.into_values().collect()
}

fn row(
    socket: &BoundSocket,
    workload: Workload,
    accepted: &[AcceptedConnections],
    posture: &FirewallPosture,
) -> Listener {
    let reach = reach_of(
        ListenerEndpoint {
            address: socket.address,
            port: socket.port,
            protocol: socket.protocol,
        },
        posture,
    );
    let (count, last) = match socket.protocol {
        ListenerProtocol::Udp => (None, None),
        ListenerProtocol::Tcp => {
            let (count, last) = accepted
                .iter()
                .filter(|seen| seen.reached(socket.address, socket.port))
                .fold((0u64, 0u64), |(count, last), seen| {
                    (
                        count.saturating_add(seen.accepted),
                        last.max(seen.last_at_ns),
                    )
                });
            (Some(count), (count > 0).then_some(last))
        }
    };
    Listener {
        address: socket.address,
        port: socket.port,
        protocol: socket.protocol,
        scope: socket.scope(),
        sockets: 1,
        bound_at_ns: socket.bound_at_ns,
        workload,
        class: ExposureClass::of(socket.scope(), reach.open, count),
        reach,
        accepted: count,
        last_accepted_at_ns: last,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::common::entity::DomainMode;
    use domain::exposure::reach::ReachDecision;
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

    struct Seen(Vec<BoundSocket>, Vec<AcceptedConnections>);

    impl SocketIdentityReader for Seen {
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
        fn accepted_connections(&self) -> Vec<AcceptedConnections> {
            self.1.clone()
        }
    }

    fn open_posture() -> FirewallPosture {
        FirewallPosture {
            rules: Vec::new(),
            enabled: true,
            mode: DomainMode::Block,
            default_drop: false,
        }
    }

    fn seen(address: [u8; 4], port: u16, accepted: u64, last: u64) -> AcceptedConnections {
        AcceptedConnections {
            address: IpAddr::V4(Ipv4Addr::from(address)),
            port,
            accepted,
            last_at_ns: last,
        }
    }

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
        assert!(service.listeners(&open_posture()).is_none());
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
        let listeners = ExposureService::new(resolver)
            .listeners(&open_posture())
            .unwrap();
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
        let listeners = ExposureService::new(resolver)
            .listeners(&open_posture())
            .unwrap();
        assert_eq!(listeners.len(), 2);
        assert_eq!(listeners[0].sockets, 2);
        assert_eq!(listeners[0].bound_at_ns, 10);
        assert_eq!(listeners[1].sockets, 1);
    }

    #[test]
    fn a_listener_is_classed_by_scope_policy_and_the_connections_it_took() {
        let resolver = WorkloadResolver::new().with_sockets(Box::new(Seen(
            vec![
                bound([0, 0, 0, 0], 443, ListenerProtocol::Tcp, true, 30, 1),
                bound([0, 0, 0, 0], 6379, ListenerProtocol::Tcp, true, 31, 1),
                bound([10, 0, 0, 7], 22, ListenerProtocol::Tcp, true, 32, 1),
                bound([0, 0, 0, 0], 53, ListenerProtocol::Udp, false, 33, 1),
                bound([127, 0, 0, 1], 5432, ListenerProtocol::Tcp, true, 34, 1),
            ],
            vec![
                seen([10, 0, 0, 7], 443, 5, 70),
                seen([10, 0, 0, 8], 443, 2, 90),
                seen([10, 0, 0, 8], 22, 9, 95),
            ],
        )));
        let mut posture = open_posture();
        let mut deny = domain::firewall::entity::FirewallRule {
            id: domain::common::entity::RuleId("no-ssh".into()),
            ..sample_rule()
        };
        deny.dst_port = Some(domain::firewall::entity::PortRange { start: 22, end: 22 });
        posture.rules.push(deny);
        let listeners = ExposureService::new(resolver).listeners(&posture).unwrap();
        let by_port = |port: u16| listeners.iter().find(|l| l.port == port).unwrap();

        let https = by_port(443);
        assert_eq!(https.class, ExposureClass::ExposedUsed);
        assert_eq!(https.accepted, Some(7));
        assert_eq!(https.last_accepted_at_ns, Some(90));

        let redis = by_port(6379);
        assert_eq!(redis.class, ExposureClass::ExposedUnused);
        assert_eq!(redis.accepted, Some(0));
        assert_eq!(redis.last_accepted_at_ns, None);

        // Bound on one address: the connections to another one are not its.
        let ssh = by_port(22);
        assert_eq!(ssh.class, ExposureClass::ClosedByPolicy);
        assert_eq!(ssh.accepted, Some(0));
        assert!(matches!(ssh.reach.decided_by, ReachDecision::Rule { .. }));

        assert_eq!(by_port(53).class, ExposureClass::ExposedUnmeasured);
        assert_eq!(by_port(53).accepted, None);
        assert_eq!(by_port(5432).class, ExposureClass::LoopbackOnly);
    }

    fn sample_rule() -> domain::firewall::entity::FirewallRule {
        use domain::common::entity::{Protocol, RuleId};
        use domain::firewall::entity::{FirewallAction, FirewallRule, Scope};
        FirewallRule {
            mode: domain::firewall::entity::RuleMode::Enforce,
            id: RuleId("sample".to_string()),
            priority: 1,
            action: FirewallAction::Deny,
            protocol: Protocol::Any,
            src_ip: None,
            dst_ip: None,
            src_port: None,
            dst_port: None,
            scope: Scope::Global,
            enabled: true,
            vlan_id: None,
            src_alias: None,
            dst_alias: None,
            src_port_alias: None,
            dst_port_alias: None,
            src_mac_alias: None,
            dst_mac_alias: None,
            ct_states: None,
            tcp_flags: None,
            icmp_type: None,
            icmp_code: None,
            negate_src: false,
            negate_dst: false,
            dscp_match: None,
            dscp_mark: None,
            max_states: None,
            src_mac: None,
            dst_mac: None,
            schedule: None,
            system: false,
            group_mask: 0,
            tenant_id: 0,
            workload: None,
        }
    }
}
