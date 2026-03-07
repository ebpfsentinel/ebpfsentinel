#![allow(clippy::cast_possible_truncation)]

use std::hint::black_box;
use std::sync::Arc;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use application::firewall_service_impl::FirewallAppService;
use domain::common::entity::{Protocol, RuleId};
use domain::firewall::engine::FirewallEngine;
use domain::firewall::entity::{FirewallAction, FirewallRule, IpNetwork, PacketInfo, PortRange, Scope};
use ports::test_utils::NoopMetrics;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_rule(id: usize, priority: u32, action: FirewallAction) -> FirewallRule {
    FirewallRule {
        id: RuleId(format!("fw-{id:05}")),
        priority,
        action,
        protocol: Protocol::Tcp,
        src_ip: Some(IpNetwork::V4 {
            addr: 0x0A00_0000 | (id as u32 & 0x00FF_FFFF),
            prefix_len: 24,
        }),
        dst_ip: None,
        src_port: None,
        dst_port: Some(PortRange { start: 80, end: 80 }),
        scope: Scope::Global,
        enabled: true,
        vlan_id: None,
        src_alias: None,
        dst_alias: None,
        src_port_alias: None,
        dst_port_alias: None,
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
        route_action: None,
    }
}

fn make_packet(matching: bool) -> PacketInfo {
    PacketInfo {
        src_addr: if matching {
            [0x0A00_0001, 0, 0, 0]
        } else {
            [0xC0A8_0001, 0, 0, 0]
        },
        dst_addr: [0x0A00_0001, 0, 0, 0],
        src_port: 12345,
        dst_port: 80,
        protocol: Protocol::Tcp,
        interface: "eth0".to_string(),
        is_ipv6: false,
        vlan_id: None,
    }
}

fn engine_with_rules(n: usize) -> FirewallEngine {
    let mut engine = FirewallEngine::new();
    for i in 0..n {
        engine
            .add_rule(make_rule(i, (i + 1) as u32, FirewallAction::Allow))
            .unwrap();
    }
    engine
}

fn app_service_with_rules(n: usize) -> FirewallAppService {
    let metrics: Arc<dyn ports::secondary::metrics_port::MetricsPort> = Arc::new(NoopMetrics);
    let mut svc = FirewallAppService::new(FirewallEngine::new(), None, metrics);
    for i in 0..n {
        svc.add_rule(make_rule(i, (i + 1) as u32, FirewallAction::Allow))
            .unwrap();
    }
    svc
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

fn bench_firewall_add_rule_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("firewall_add_rule_overhead");

    for &n in &[100, 1_000] {
        // Engine-only: raw domain add_rule
        group.bench_with_input(BenchmarkId::new("engine_only", n), &n, |b, &n| {
            b.iter_batched(
                || engine_with_rules(n),
                |mut engine| {
                    let _ = engine.add_rule(make_rule(n, (n + 1) as u32, FirewallAction::Deny));
                },
                criterion::BatchSize::SmallInput,
            );
        });

        // App service: engine + metrics + (no map sync since map_port is None)
        group.bench_with_input(BenchmarkId::new("app_service", n), &n, |b, &n| {
            b.iter_batched(
                || app_service_with_rules(n),
                |mut svc| {
                    let _ = svc.add_rule(make_rule(n, (n + 1) as u32, FirewallAction::Deny));
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

fn bench_firewall_evaluate_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("firewall_evaluate_overhead");

    for &n in &[100, 1_000] {
        let engine = engine_with_rules(n);
        let packet = make_packet(true);

        // Engine-only: raw domain evaluate
        group.bench_with_input(BenchmarkId::new("engine_only", n), &n, |b, _| {
            b.iter(|| engine.evaluate(black_box(&packet)));
        });

        // NOTE: FirewallAppService does not expose a public `evaluate` method;
        // packet evaluation at runtime is performed inside the eBPF kernel
        // program. The domain engine's `evaluate` is used only in tests and
        // config validation. We therefore benchmark the engine directly for
        // both arms — this group exists to show that the engine evaluation
        // cost itself scales predictably with rule count.
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_firewall_add_rule_overhead,
    bench_firewall_evaluate_overhead,
);
criterion_main!(benches);
