//! The cryptographic posture of each edge, fed by the L7 dispatch path.
//!
//! The dispatcher hands every L7 payload here once its protocol is known, and
//! every TLS server flight once its handshake is read. A request read in clear
//! and a handshake each count their connection once on the edge between the
//! two workloads, named from the agent's socket tables the way the service map
//! names them.

use std::sync::{Mutex, PoisonError};

use domain::l7::crypto_posture::{
    FlowPosture, FlowTuple, PostureEdgeKey, PostureReading, PostureTable, clear_text_request,
};
use domain::l7::handshake::TlsHandshake;
use domain::l7::red::service_name;
use domain::l7::service_graph::GraphEnd;
use ebpf_common::event::PacketEvent;
use ports::secondary::socket_identity_port::FlowEndpoints;

use crate::workload_resolver::WorkloadResolver;

/// Counts each connection's posture on its edge.
pub struct CryptoPostureMeter {
    table: Mutex<PostureTable>,
    workloads: WorkloadResolver,
}

impl CryptoPostureMeter {
    #[must_use]
    pub fn new(workloads: WorkloadResolver) -> Self {
        Self {
            table: Mutex::new(PostureTable::default()),
            workloads,
        }
    }

    /// Offer one L7 payload running from client to server. `label` is the
    /// protocol the detector named it. Counts the connection as clear text
    /// when the payload is a request read in clear.
    pub fn observe_payload(&self, header: &PacketEvent, label: &str, payload: &[u8], now_ns: u64) {
        let Some(protocol) = clear_text_request(label, payload) else {
            return;
        };
        let ipv6 = header.is_ipv6();
        let flow = FlowTuple {
            client: crate::addr_to_ip(header.src_addr, ipv6),
            client_port: header.src_port,
            server: crate::addr_to_ip(header.dst_addr, ipv6),
            server_port: header.dst_port,
        };
        self.record(
            flow,
            header.protocol,
            FlowPosture::ClearText(protocol),
            now_ns,
        );
    }

    /// Count the connection a server's flight belongs to as what its
    /// handshake negotiated. The flight runs from server to client, so the
    /// client is the packet's destination.
    pub fn observe_handshake(&self, header: &PacketEvent, handshake: &TlsHandshake, now_ns: u64) {
        let ipv6 = header.is_ipv6();
        let flow = FlowTuple {
            client: crate::addr_to_ip(header.dst_addr, ipv6),
            client_port: header.dst_port,
            server: crate::addr_to_ip(header.src_addr, ipv6),
            server_port: header.src_port,
        };
        self.record(
            flow,
            header.protocol,
            FlowPosture::Tls(handshake.posture()),
            now_ns,
        );
    }

    /// Every edge's posture since the agent started.
    #[must_use]
    pub fn reading(&self) -> PostureReading {
        self.table
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .read()
    }

    fn record(&self, flow: FlowTuple, protocol: u8, posture: FlowPosture, now_ns: u64) {
        // The socket tables are asked only for a connection not counted yet,
        // and before the lock is taken.
        if self
            .table
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .counted(&flow, now_ns)
        {
            return;
        }
        let key = PostureEdgeKey {
            client: GraphEnd {
                service: self.name(&flow, protocol, true),
                address: flow.client,
            },
            server: GraphEnd {
                service: self.name(&flow, protocol, false),
                address: flow.server,
            },
            server_port: flow.server_port,
        };
        self.table
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .record(key, flow, posture, now_ns);
    }

    /// The service at one end, asked about from that end, since the socket
    /// tables are keyed by a socket's own end.
    fn name(&self, flow: &FlowTuple, protocol: u8, client: bool) -> Option<String> {
        let endpoints = if client {
            FlowEndpoints {
                local_addr: flow.client,
                remote_addr: flow.server,
                local_port: flow.client_port,
                remote_port: flow.server_port,
                protocol,
            }
        } else {
            FlowEndpoints {
                local_addr: flow.server,
                remote_addr: flow.client,
                local_port: flow.server_port,
                remote_port: flow.client_port,
                protocol,
            }
        };
        self.workloads
            .by_originated_flow(&endpoints)
            .map(|workload| service_name(&workload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::l7::crypto_posture::ClearTextProtocol;
    use domain::l7::handshake::{CertificateValidity, CryptoPosture};

    fn event(src: [u8; 4], src_port: u16, dst: [u8; 4], dst_port: u16) -> PacketEvent {
        PacketEvent {
            timestamp_ns: 0,
            src_addr: [u32::from_be_bytes(src), 0, 0, 0],
            dst_addr: [u32::from_be_bytes(dst), 0, 0, 0],
            src_port,
            dst_port,
            protocol: 6,
            event_type: ebpf_common::event::EVENT_TYPE_L7,
            action: 0,
            flags: 0,
            rule_id: 0,
            vlan_id: 0,
            cpu_id: 0,
            socket_cookie: 0,
            cgroup_id: 0,
            cgroup1_id: 0,
            rss_hash: 0,
            rss_hash_type: 0,
            rx_hw_timestamp_ns: 0,
        }
    }

    #[test]
    fn a_handshake_and_a_clear_request_land_on_their_own_edges() {
        let meter = CryptoPostureMeter::new(WorkloadResolver::new());
        let hybrid = TlsHandshake {
            version: domain::l7::handshake::TLS_1_3,
            cipher: 0x1301,
            group: Some(0x11ec),
            certificate: CertificateValidity::NotObservable,
        };
        // The server flight runs from 10.0.0.2:443 to the client.
        meter.observe_handshake(
            &event([10, 0, 0, 2], 443, [10, 0, 0, 1], 50_000),
            &hybrid,
            1,
        );
        meter.observe_payload(
            &event([10, 0, 0, 1], 50_001, [10, 0, 0, 3], 80),
            "http",
            b"GET / HTTP/1.1\r\n\r\n",
            2,
        );
        meter.observe_payload(
            &event([10, 0, 0, 1], 50_001, [10, 0, 0, 3], 80),
            "http",
            b"GET /again HTTP/1.1\r\n\r\n",
            3,
        );
        let reading = meter.reading();
        assert_eq!(reading.edges.len(), 2);
        let (tls_key, tls) = &reading.edges[0];
        assert_eq!(tls_key.server_port, 443);
        assert_eq!(tls_key.client.address.to_string(), "10.0.0.1");
        assert_eq!(tls.post_quantum, 1);
        let (_, clear) = &reading.edges[1];
        assert_eq!(clear.clear_text[&ClearTextProtocol::Http], 1);
        assert_eq!(hybrid.posture(), CryptoPosture::PostQuantum);
    }

    #[test]
    fn a_greeting_counts_nothing() {
        let meter = CryptoPostureMeter::new(WorkloadResolver::new());
        meter.observe_payload(
            &event([10, 0, 0, 2], 25, [10, 0, 0, 1], 50_000),
            "smtp",
            b"220 mx.example ESMTP\r\n",
            1,
        );
        assert!(meter.reading().edges.is_empty());
    }
}
