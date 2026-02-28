#![allow(clippy::cast_possible_truncation)]

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};

use domain::common::entity::{Protocol, RuleId};
use domain::firewall::engine::FirewallEngine;
use domain::firewall::entity::{
    FirewallAction, FirewallRule, IpNetwork, PacketInfo, PortRange, Scope,
};

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

fn bench_evaluate(c: &mut Criterion) {
    let mut group = c.benchmark_group("firewall_evaluate");

    for &n in &[10, 100, 1_000, 10_000] {
        let engine = engine_with_rules(n);
        let packet_match = make_packet(true);
        let packet_miss = make_packet(false);

        group.bench_with_input(BenchmarkId::new("match", n), &n, |b, _| {
            b.iter(|| engine.evaluate(black_box(&packet_match)));
        });

        group.bench_with_input(BenchmarkId::new("miss", n), &n, |b, _| {
            b.iter(|| engine.evaluate(black_box(&packet_miss)));
        });
    }

    group.finish();
}

fn bench_add_rule(c: &mut Criterion) {
    let mut group = c.benchmark_group("firewall_add_rule");

    for &n in &[10, 100, 1_000] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter_batched(
                || {
                    let mut engine = FirewallEngine::new();
                    for i in 0..n {
                        engine
                            .add_rule(make_rule(i, (i + 1) as u32, FirewallAction::Allow))
                            .unwrap();
                    }
                    engine
                },
                |mut engine| {
                    let _ = engine.add_rule(make_rule(n, (n + 1) as u32, FirewallAction::Deny));
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

fn bench_reload(c: &mut Criterion) {
    let mut group = c.benchmark_group("firewall_reload");

    for &n in &[100, 1_000, 10_000] {
        let rules: Vec<FirewallRule> = (0..n)
            .map(|i| make_rule(i, (i + 1) as u32, FirewallAction::Allow))
            .collect();

        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter_batched(
                || (FirewallEngine::new(), rules.clone()),
                |(mut engine, rules)| {
                    let _ = engine.reload(rules);
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

criterion_group!(benches, bench_evaluate, bench_add_rule, bench_reload);
criterion_main!(benches);
