//! Rate, errors and duration per service, fed by the L7 dispatch path.
//!
//! The dispatcher hands every L7 payload here once its protocol is known.
//! A payload that opens a request is remembered against its flow along with
//! the services at each end, a payload on the reverse flow is offered as the
//! answer, and every finished or abandoned request becomes one count on
//! `l7_requests` and, when it was answered, one observation on
//! `l7_request_duration_seconds`.
//!
//! The dispatch workers pick their worker from the source address alone, so
//! a request and its answer land on different workers; the table is shared
//! behind one lock rather than kept per worker. The workload lookups happen
//! before the lock is taken.
//!
//! Every sample is also folded into a [`ServiceGraph`], one count on the
//! edge between the two ends in the minute the request was opened, which is
//! what the service map reads.

use std::sync::{Arc, Mutex, PoisonError};

use domain::l7::reassembler::FlowId;
use domain::l7::red::{
    RedConfig, RedProtocol, RedSample, RedTracker, ServiceNames, UNATTRIBUTED_SERVICE, service_name,
};
use domain::l7::service_graph::{EdgeKey, GraphEnd, GraphReading, Observer, ServiceGraph};
use ebpf_common::event::PacketEvent;
use ports::secondary::metrics_port::MetricsPort;
use ports::secondary::socket_identity_port::FlowEndpoints;

use crate::workload_resolver::WorkloadResolver;

/// The side of the connection a service was on.
pub const ROLE_CLIENT: &str = "client";
pub const ROLE_SERVER: &str = "server";

/// The services a request is counted against, with the side each was on.
type Ends = Vec<(String, &'static str)>;

/// What a pending request carries until it is answered or abandoned.
struct Tag {
    ends: Ends,
    edge: EdgeKey,
    opened_ns: u64,
}

/// The names the socket tables gave each end, before they are admitted.
struct Named {
    client: Option<String>,
    server: Option<String>,
}

struct State {
    tracker: RedTracker<Tag>,
    names: ServiceNames,
}

/// Turns L7 payloads into per-service request counts and durations.
pub struct L7RedMeter {
    state: Mutex<State>,
    graph: Mutex<ServiceGraph>,
    workloads: WorkloadResolver,
    metrics: Arc<dyn MetricsPort>,
}

impl L7RedMeter {
    #[must_use]
    pub fn new(
        config: RedConfig,
        names: ServiceNames,
        workloads: WorkloadResolver,
        metrics: Arc<dyn MetricsPort>,
    ) -> Self {
        Self {
            state: Mutex::new(State {
                tracker: RedTracker::new(config),
                names,
            }),
            graph: Mutex::new(ServiceGraph::default()),
            workloads,
            metrics,
        }
    }

    /// Offer one reassembled L7 payload. `label` is the protocol the
    /// detector named it.
    pub fn observe(&self, header: &PacketEvent, label: &str, payload: &[u8]) {
        let flow = FlowId::new(
            header.src_addr,
            header.dst_addr,
            header.src_port,
            header.dst_port,
            header.is_ipv6(),
        );
        let at_ns = header.timestamp_ns;

        let answered = {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            if state.tracker.awaits_answer_on(&flow) {
                Some(state.tracker.answer(&flow, at_ns, payload))
            } else {
                None
            }
        };
        match answered {
            Some(Some(sample)) => return self.record(&sample),
            // A payload on a flow whose reverse is waiting is never itself
            // a request, even when it is not the answer yet.
            Some(None) => return,
            None => {}
        }

        let Some(protocol) = RedProtocol::of_request(label, payload) else {
            return;
        };
        let named = self.ends_of(header);
        let ipv6 = header.is_ipv6();
        let client_addr = crate::addr_to_ip(header.src_addr, ipv6);
        let server_addr = crate::addr_to_ip(header.dst_addr, ipv6);
        let gone = {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            let client = named.client.map(|name| state.names.admit(name));
            let server = named.server.map(|name| state.names.admit(name));
            let observer = match (&client, &server) {
                (_, Some(_)) => Observer::Server,
                (Some(_), None) => Observer::Client,
                (None, None) => Observer::Transit,
            };
            let mut ends = Vec::with_capacity(2);
            if let Some(name) = &client {
                ends.push((name.clone(), ROLE_CLIENT));
            }
            if let Some(name) = &server {
                ends.push((name.clone(), ROLE_SERVER));
            }
            if ends.is_empty() {
                ends.push((
                    state.names.admit(UNATTRIBUTED_SERVICE.to_string()),
                    ROLE_SERVER,
                ));
            }
            let tag = Tag {
                ends,
                edge: EdgeKey {
                    client: GraphEnd {
                        service: client,
                        address: client_addr,
                    },
                    server: GraphEnd {
                        service: server,
                        address: server_addr,
                    },
                    server_port: header.dst_port,
                    protocol,
                    observer,
                },
                opened_ns: at_ns,
            };
            state.tracker.request(flow, at_ns, protocol, tag)
        };
        for sample in &gone {
            self.record(sample);
        }
    }

    /// The workloads at each end of a request, as the client that opened
    /// it and the server that accepted it. The socket tables are keyed by a
    /// socket's own end, so each side is asked about from its own end.
    fn ends_of(&self, header: &PacketEvent) -> Named {
        let ipv6 = header.is_ipv6();
        let client = crate::addr_to_ip(header.src_addr, ipv6);
        let server = crate::addr_to_ip(header.dst_addr, ipv6);
        let from_client = FlowEndpoints {
            local_addr: client,
            remote_addr: server,
            local_port: header.src_port,
            remote_port: header.dst_port,
            protocol: header.protocol,
        };
        let client_name = self
            .workloads
            .by_originated_flow(&from_client)
            .map(|workload| service_name(&workload));
        let from_server = FlowEndpoints {
            local_addr: server,
            remote_addr: client,
            local_port: header.dst_port,
            remote_port: header.src_port,
            protocol: header.protocol,
        };
        let server_name = self
            .workloads
            .by_originated_flow(&from_server)
            .map(|workload| service_name(&workload));
        Named {
            client: client_name,
            server: server_name,
        }
    }

    /// The service graph over the last `minutes` minutes up to `now_ns`,
    /// read on the same clock the kernel stamps events with.
    #[must_use]
    pub fn graph(&self, now_ns: u64, minutes: u64) -> GraphReading {
        self.graph
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .read(now_ns, minutes)
    }

    fn record(&self, sample: &RedSample<Tag>) {
        let seconds = sample
            .duration_ns
            .map(|ns| std::time::Duration::from_nanos(ns).as_secs_f64());
        for (service, role) in &sample.tag.ends {
            self.metrics.record_l7_request(
                service,
                role,
                sample.protocol.as_str(),
                sample.outcome.as_str(),
                seconds,
            );
        }
        self.graph
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .record(
                sample.tag.opened_ns,
                sample.tag.edge.clone(),
                sample.outcome,
                sample.duration_ns,
            );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::workload::entity::WorkloadSource;
    use ports::secondary::socket_identity_port::{SocketIdentityReader, SocketOwner};
    use ports::test_utils::NoopMetrics;

    type Recorded = Vec<(String, String, String, String, Option<f64>)>;

    #[derive(Default)]
    struct Recorder(Mutex<Recorded>);

    impl ports::secondary::metrics_port::PacketMetrics for Recorder {
        fn record_l7_request(
            &self,
            service: &str,
            role: &str,
            protocol: &str,
            outcome: &str,
            duration_seconds: Option<f64>,
        ) {
            self.0.lock().unwrap_or_else(PoisonError::into_inner).push((
                service.into(),
                role.into(),
                protocol.into(),
                outcome.into(),
                duration_seconds,
            ));
        }
    }
    impl ports::secondary::metrics_port::FirewallMetrics for Recorder {}
    impl ports::secondary::metrics_port::AlertMetrics for Recorder {}
    impl ports::secondary::metrics_port::IpsMetrics for Recorder {}
    impl ports::secondary::metrics_port::DnsMetrics for Recorder {}
    impl ports::secondary::metrics_port::DomainMetrics for Recorder {}
    impl ports::secondary::metrics_port::SystemMetrics for Recorder {}
    impl ports::secondary::metrics_port::ConfigMetrics for Recorder {}
    impl ports::secondary::metrics_port::EventMetrics for Recorder {}
    impl ports::secondary::metrics_port::DlpMetrics for Recorder {}
    impl ports::secondary::metrics_port::DdosMetrics for Recorder {}
    impl ports::secondary::metrics_port::ConntrackMetrics for Recorder {}
    impl ports::secondary::metrics_port::RoutingMetrics for Recorder {}
    impl ports::secondary::metrics_port::AuditMetrics for Recorder {}
    impl ports::secondary::metrics_port::LbMetrics for Recorder {}
    impl ports::secondary::metrics_port::FingerprintMetrics for Recorder {}
    impl ports::secondary::metrics_port::ContainerMetrics for Recorder {}
    impl ports::secondary::metrics_port::CtMetrics for Recorder {}
    impl ports::secondary::metrics_port::ThreatIntelMetrics for Recorder {}
    impl ports::secondary::metrics_port::ZoneMetrics for Recorder {}

    /// Answers for a socket opened from `port` only.
    struct OwnsPort(u16);

    impl SocketIdentityReader for OwnsPort {
        fn by_cookie(&self, _cookie: u64) -> Option<SocketOwner> {
            None
        }
        fn by_flow(&self, _flow: &FlowEndpoints) -> Option<SocketOwner> {
            None
        }
        fn by_originated_flow(&self, flow: &FlowEndpoints) -> Option<SocketOwner> {
            (flow.local_port == self.0).then_some(SocketOwner {
                pid: 7,
                tgid: 7,
                uid: 0,
                cgroup_id: 0,
                source: WorkloadSource::Flow,
            })
        }
    }

    fn event(src_port: u16, dst_port: u16, at_ns: u64) -> PacketEvent {
        let (src_addr, dst_addr) = if src_port < dst_port {
            ([0x0a00_0002, 0, 0, 0], [0x0a00_0001, 0, 0, 0])
        } else {
            ([0x0a00_0001, 0, 0, 0], [0x0a00_0002, 0, 0, 0])
        };
        PacketEvent {
            timestamp_ns: at_ns,
            src_addr,
            dst_addr,
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

    fn meter(workloads: WorkloadResolver) -> (L7RedMeter, Arc<Recorder>) {
        let recorder = Arc::new(Recorder::default());
        let meter = L7RedMeter::new(
            RedConfig::default(),
            ServiceNames::default(),
            workloads,
            recorder.clone(),
        );
        (meter, recorder)
    }

    #[test]
    fn a_request_and_its_answer_count_once_against_the_server_with_its_duration() {
        let (meter, recorder) = meter(WorkloadResolver::new().with_sockets(Box::new(OwnsPort(80))));
        meter.observe(&event(40_000, 80, 1_000_000), "http", b"GET / HTTP/1.1\r\n");
        meter.observe(
            &event(80, 40_000, 3_000_000),
            "unknown",
            b"HTTP/1.1 502 Bad",
        );
        let recorded = recorder.0.lock().unwrap_or_else(PoisonError::into_inner);
        assert_eq!(recorded.len(), 1);
        let (service, role, protocol, outcome, seconds) = &recorded[0];
        assert_eq!(
            (
                service.as_str(),
                role.as_str(),
                protocol.as_str(),
                outcome.as_str()
            ),
            (UNATTRIBUTED_SERVICE, ROLE_SERVER, "http", "error")
        );
        assert!(seconds.is_some_and(|s| (s - 0.002).abs() < 1e-9));
        drop(recorded);

        let graph = meter.graph(3_000_000, 1);
        assert_eq!(graph.edges.len(), 1);
        let (edge, counts) = &graph.edges[0];
        assert_eq!(edge.observer, Observer::Server);
        assert_eq!(edge.server_port, 80);
        assert_eq!(edge.server.address.to_string(), "10.0.0.2");
        assert_eq!((counts.requests, counts.errors, counts.answered), (1, 1, 1));
        assert_eq!(counts.duration_ns_sum, 2_000_000);
    }

    #[test]
    fn both_ends_on_this_node_count_once_each() {
        struct Both;
        impl SocketIdentityReader for Both {
            fn by_cookie(&self, _cookie: u64) -> Option<SocketOwner> {
                None
            }
            fn by_flow(&self, _flow: &FlowEndpoints) -> Option<SocketOwner> {
                None
            }
            fn by_originated_flow(&self, _flow: &FlowEndpoints) -> Option<SocketOwner> {
                Some(SocketOwner {
                    pid: 9,
                    tgid: 9,
                    uid: 0,
                    cgroup_id: 0,
                    source: WorkloadSource::Flow,
                })
            }
        }
        let (meter, recorder) = meter(WorkloadResolver::new().with_sockets(Box::new(Both)));
        meter.observe(&event(40_000, 6379, 10), "redis", b"*1\r\n$4\r\nPING\r\n");
        meter.observe(&event(6379, 40_000, 20), "redis", b"+PONG\r\n");
        let recorded = recorder.0.lock().unwrap_or_else(PoisonError::into_inner);
        let roles: Vec<&str> = recorded.iter().map(|r| r.1.as_str()).collect();
        assert_eq!(roles, vec![ROLE_CLIENT, ROLE_SERVER]);
        assert!(recorded.iter().all(|r| r.3 == "ok"));
        drop(recorded);
        let graph = meter.graph(20, 60);
        assert_eq!(graph.edges.len(), 1, "one edge, seen from the server");
        assert_eq!(graph.edges[0].0.observer, Observer::Server);
        assert!(graph.edges[0].0.client.service.is_some());
    }

    #[test]
    fn protocols_without_a_readable_failure_are_not_measured() {
        let (meter, recorder) = meter(WorkloadResolver::new());
        meter.observe(&event(40_000, 443, 10), "tls", b"\x16\x03\x01\x00");
        meter.observe(&event(443, 40_000, 20), "tls", b"\x16\x03\x03\x00");
        assert!(
            recorder
                .0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .is_empty()
        );
    }

    #[test]
    fn a_meter_on_a_noop_port_accepts_traffic() {
        let meter = L7RedMeter::new(
            RedConfig::default(),
            ServiceNames::default(),
            WorkloadResolver::new(),
            Arc::new(NoopMetrics),
        );
        meter.observe(&event(1, 80, 1), "http", b"GET / HTTP/1.1\r\n");
        meter.observe(&event(80, 1, 2), "http", b"HTTP/1.1 200 OK\r\n");
    }
}
