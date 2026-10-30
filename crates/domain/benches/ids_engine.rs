#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::unwrap_used)]

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::fmt::Write as _;
use std::hint::black_box;

use domain::common::entity::{DomainMode, Protocol, RuleId, Severity};
use domain::ids::engine::IdsEngine;
use domain::ids::entity::IdsRule;
use domain::ids::suricata::{SuricataVars, compile_ruleset};
use ebpf_common::event::{EVENT_TYPE_IDS, PacketEvent};

fn make_rule(id: usize) -> IdsRule {
    IdsRule {
        id: RuleId(format!("ids-{id:05}")),
        description: format!("Test rule {id}"),
        severity: Severity::Medium,
        mode: DomainMode::Alert,
        protocol: Protocol::Tcp,
        dst_port: Some(22),
        src_port: None,
        pattern: String::new(),
        enabled: true,
        threshold: None,
        domain_pattern: None,
        domain_match_mode: None,
        country_thresholds: None,
        group_mask: 0,
        tenant_id: 0,
        workload: None,
        kill_process: false,
        imported: None,
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
        cgroup_id: 0,
        cgroup1_id: 0,
        rss_hash: 0,
        rss_hash_type: 0,
        rx_hw_timestamp_ns: 0,
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

/// An imported ruleset of `n` content rules, all on one port so that every
/// rule is a candidate for every segment: the worst case of the payload scan.
fn imported_engine(n: usize) -> IdsEngine {
    let mut text = String::new();
    for i in 0..n {
        writeln!(
            text,
            "alert tcp any any -> any 80 (msg:\"rule {i}\"; \
             flow:to_server,established; content:\"needle-{i:05}\"; nocase; \
             content:\"/admin\"; distance:0; sid:{};)",
            i + 1
        )
        .unwrap();
    }
    let compiled = compile_ruleset(&text, &SuricataVars::default());
    assert_eq!(compiled.report.compiled, n);
    let mut engine = IdsEngine::new();
    engine.reload(compiled.rules).unwrap();
    engine
}

fn bench_imported_payload(c: &mut Criterion) {
    let mut group = c.benchmark_group("ids_imported_payload");
    let mut event = make_event(0);
    event.dst_port = 80;
    // A request no rule matches walks every candidate rule.
    let miss = b"GET /index.html HTTP/1.1\r\nHost: example.test\r\nUser-Agent: bench\r\n\r\n";

    for &n in &[100, 1_000, 5_000] {
        let engine = imported_engine(n);
        group.bench_with_input(BenchmarkId::new("miss", n), &n, |b, _| {
            b.iter(|| black_box(engine.evaluate_payload_with_context(&event, miss, None)));
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_evaluate_event,
    bench_add_rule,
    bench_reload,
    bench_imported_payload
);
criterion_main!(benches);
