use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use criterion::{Criterion, criterion_group, criterion_main};

use application::l7_red_meter::L7RedMeter;
use application::workload_resolver::WorkloadResolver;
use domain::l7::red::{RedConfig, RedOutcome, RedProtocol, ServiceNames};
use domain::l7::service_graph::{
    DEFAULT_MAX_EDGES_PER_MINUTE, EdgeKey, GRAPH_MINUTES, GraphEnd, Observer, ServiceGraph,
};
use ebpf_common::event::{EVENT_TYPE_L7, PacketEvent};
use ports::test_utils::NoopMetrics;

fn event(src: u32, dst: u32, src_port: u16, dst_port: u16, at_ns: u64) -> PacketEvent {
    PacketEvent {
        timestamp_ns: at_ns,
        src_addr: [src, 0, 0, 0],
        dst_addr: [dst, 0, 0, 0],
        src_port,
        dst_port,
        protocol: 6,
        event_type: EVENT_TYPE_L7,
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

/// One HTTP request and its answer, on a table already holding as many
/// pending requests as the default bound allows.
fn bench_request_and_answer(c: &mut Criterion) {
    let meter = L7RedMeter::new(
        RedConfig::default(),
        ServiceNames::default(),
        WorkloadResolver::new(),
        Arc::new(NoopMetrics),
    );
    let mut at = 1_u64;
    for port in 0..u16::MAX {
        meter.observe(
            &event(0x0a00_0001, 0x0a00_0002, port, 80, at),
            "http",
            b"GET / HTTP/1.1\r\n",
        );
        at += 1;
    }
    let mut port = 0_u16;
    c.bench_function("l7_red_meter/request_and_answer_full_table", |b| {
        b.iter(|| {
            port = port.wrapping_add(1);
            at += 2;
            meter.observe(
                black_box(&event(0x0a00_0003, 0x0a00_0002, port, 80, at)),
                "http",
                black_box(b"GET /health HTTP/1.1\r\n"),
            );
            meter.observe(
                black_box(&event(0x0a00_0002, 0x0a00_0003, 80, port, at + 1)),
                "http",
                black_box(b"HTTP/1.1 200 OK\r\n"),
            );
        });
    });
}

/// One reading of the whole window with every minute holding as many edges
/// as the default bound allows, which is the most a service map request can
/// cost the agent.
fn bench_graph_read(c: &mut Criterion) {
    let mut graph = ServiceGraph::default();
    let minute = 60_000_000_000_u64;
    for m in 0..GRAPH_MINUTES {
        for client in 0..u32::try_from(DEFAULT_MAX_EDGES_PER_MINUTE).unwrap_or(u32::MAX) {
            let key = EdgeKey {
                client: GraphEnd {
                    service: Some(format!("ns/client-{}", client % 64)),
                    address: IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + client)),
                },
                server: GraphEnd {
                    service: Some("shop/api".to_string()),
                    address: IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1)),
                },
                server_port: 8080,
                protocol: RedProtocol::Http,
                observer: Observer::Server,
            };
            graph.record(m * minute, key, RedOutcome::Ok, Some(1_000_000));
        }
    }
    let now = (GRAPH_MINUTES - 1) * minute;
    c.bench_function("service_graph/read_full_window", |b| {
        b.iter(|| black_box(graph.read(black_box(now), GRAPH_MINUTES)));
    });
}

criterion_group!(benches, bench_request_and_answer, bench_graph_read);
criterion_main!(benches);
