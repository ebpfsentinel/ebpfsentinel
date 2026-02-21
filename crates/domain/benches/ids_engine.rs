#![allow(clippy::cast_possible_truncation)]

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};

use domain::common::entity::{DomainMode, Protocol, RuleId, Severity};
use domain::ids::engine::IdsEngine;
use domain::ids::entity::IdsRule;
use ebpf_common::event::{EVENT_TYPE_IDS, PacketEvent};

fn make_rule(id: usize) -> IdsRule {
    IdsRule {
        id: RuleId(format!("ids-{id:05}")),
        description: format!("Test rule {id}"),
        severity: Severity::Medium,
        mode: DomainMode::Alert,
        protocol: Protocol::Tcp,
        dst_port: Some(22),
        pattern: String::new(),
        enabled: true,
        threshold: None,
        domain_pattern: None,
        domain_match_mode: None,
    }
}

fn make_rule_with_pattern(id: usize, pattern: &str) -> IdsRule {
    IdsRule {
        pattern: pattern.to_string(),
        ..make_rule(id)
    }
}

fn make_event(rule_id: u32) -> PacketEvent {
    PacketEvent {
        timestamp_ns: 1_000_000_000,
        src_addr: [0xC0A8_0001, 0, 0, 0],
        dst_addr: [0x0A00_0001, 0, 0, 0],
        src_port: 12345,
        dst_port: 22,
        protocol: 6,
        event_type: EVENT_TYPE_IDS,
        action: 0,
        flags: 0,
        rule_id,
        vlan_id: 0,
        cpu_id: 0,
        socket_cookie: 0,
    }
}

fn engine_with_rules(n: usize) -> IdsEngine {
    let mut engine = IdsEngine::new();
    for i in 0..n {
        engine.add_rule(make_rule(i)).unwrap();
    }
    engine
}

fn bench_evaluate_event(c: &mut Criterion) {
    let mut group = c.benchmark_group("ids_evaluate_event");

    for &n in &[10, 100, 1_000, 10_000] {
        let engine = engine_with_rules(n);

        group.bench_with_input(BenchmarkId::new("hit_first", n), &n, |b, _| {
            let event = make_event(0);
            b.iter(|| engine.evaluate_event(black_box(&event)));
        });

        group.bench_with_input(BenchmarkId::new("hit_last", n), &n, |b, &n| {
            let event = make_event((n - 1) as u32);
            b.iter(|| engine.evaluate_event(black_box(&event)));
        });

        group.bench_with_input(BenchmarkId::new("miss", n), &n, |b, _| {
            let event = make_event(u32::MAX);
            b.iter(|| engine.evaluate_event(black_box(&event)));
        });
    }

    group.finish();
}

fn bench_add_rule(c: &mut Criterion) {
    let mut group = c.benchmark_group("ids_add_rule");

    for &n in &[10, 100, 1_000] {
        group.bench_with_input(BenchmarkId::new("plain", n), &n, |b, &n| {
            b.iter_batched(
                || engine_with_rules(n),
                |mut engine| {
                    let _ = engine.add_rule(make_rule(n));
                },
                criterion::BatchSize::SmallInput,
            );
        });

        group.bench_with_input(BenchmarkId::new("with_regex", n), &n, |b, &n| {
            b.iter_batched(
                || engine_with_rules(n),
                |mut engine| {
                    let _ = engine.add_rule(make_rule_with_pattern(n, r"GET\s+/admin"));
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

fn bench_reload(c: &mut Criterion) {
    let mut group = c.benchmark_group("ids_reload");

    for &n in &[100, 1_000, 10_000] {
        let rules: Vec<IdsRule> = (0..n).map(make_rule).collect();

        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter_batched(
                || (IdsEngine::new(), rules.clone()),
                |(mut engine, rules)| {
                    let _ = engine.reload(rules);
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

criterion_group!(benches, bench_evaluate_event, bench_add_rule, bench_reload);
criterion_main!(benches);
