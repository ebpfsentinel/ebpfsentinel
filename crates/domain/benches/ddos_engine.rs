#![allow(clippy::cast_possible_truncation)]

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;

use domain::common::entity::RuleId;
use domain::ddos::engine::DdosEngine;
use domain::ddos::entity::{DdosAttackType, DdosEvent, DdosMitigationAction, DdosPolicy};

fn make_policy(id: &str, threshold: u64) -> DdosPolicy {
    DdosPolicy {
        id: RuleId(id.to_string()),
        attack_type: DdosAttackType::SynFlood,
        detection_threshold_pps: threshold,
        mitigation_action: DdosMitigationAction::Block,
        auto_block_duration_secs: 300,
        enabled: true,
        country_thresholds: None,
    }
}

fn make_event(src_idx: u32, ts: u64) -> DdosEvent {
    DdosEvent {
        timestamp_ns: ts,
        attack_type: DdosAttackType::SynFlood,
        src_addr: [0x0A00_0000 | (src_idx & 0x00FF_FFFF), 0, 0, 0],
        dst_addr: [0x0A00_0001, 0, 0, 0],
        src_port: 12345,
        dst_port: 80,
        protocol: 6,
        is_ipv6: false,
    }
}

fn bench_process_event(c: &mut Criterion) {
    let mut group = c.benchmark_group("ddos_process_event");

    for &n in &[100, 1_000, 10_000] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter_batched(
                || {
                    let mut engine = DdosEngine::new();
                    engine.add_policy(make_policy("syn-1", 1000)).unwrap();
                    let events: Vec<DdosEvent> = (0..n)
                        .map(|i| make_event(i as u32, (i as u64 + 1) * 1_000_000))
                        .collect();
                    (engine, events)
                },
                |(mut engine, events)| {
                    for event in &events {
                        let _ = engine.process_event(black_box(event));
                    }
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

fn bench_tick(c: &mut Criterion) {
    let mut group = c.benchmark_group("ddos_tick");

    for &n in &[100, 1_000, 10_000] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter_batched(
                || {
                    let mut engine = DdosEngine::new();
                    // Add one policy per attack type to allow multiple active attacks
                    let attack_types = [
                        DdosAttackType::SynFlood,
                        DdosAttackType::UdpAmplification,
                        DdosAttackType::IcmpFlood,
                        DdosAttackType::RstFlood,
                        DdosAttackType::FinFlood,
                        DdosAttackType::AckFlood,
                        DdosAttackType::Volumetric,
                    ];
                    for (i, &at) in attack_types.iter().enumerate() {
                        let policy = DdosPolicy {
                            id: RuleId(format!("ddos-{i}")),
                            attack_type: at,
                            detection_threshold_pps: 1000,
                            mitigation_action: DdosMitigationAction::Block,
                            auto_block_duration_secs: 300,
                            enabled: true,
                            country_thresholds: None,
                        };
                        engine.add_policy(policy).unwrap();
                    }
                    // Inject events across attack types to create active attacks
                    for i in 0..n {
                        let at = attack_types[i % attack_types.len()];
                        let event = DdosEvent {
                            timestamp_ns: (i as u64 + 1) * 1_000_000,
                            attack_type: at,
                            src_addr: [0x0A00_0000 | (i as u32 & 0x00FF_FFFF), 0, 0, 0],
                            dst_addr: [0x0A00_0001, 0, 0, 0],
                            src_port: 12345,
                            dst_port: 80,
                            protocol: 6,
                            is_ipv6: false,
                        };
                        engine.process_event(&event);
                    }
                    engine
                },
                |mut engine| {
                    engine.tick();
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

fn bench_add_policy(c: &mut Criterion) {
    let mut group = c.benchmark_group("ddos_add_policy");

    for &n in &[10, 100, 1_000] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter_batched(
                || {
                    let mut engine = DdosEngine::new();
                    for i in 0..n {
                        let policy = DdosPolicy {
                            id: RuleId(format!("ddos-{i:05}")),
                            attack_type: DdosAttackType::SynFlood,
                            detection_threshold_pps: 1000,
                            mitigation_action: DdosMitigationAction::Block,
                            auto_block_duration_secs: 300,
                            enabled: true,
                            country_thresholds: None,
                        };
                        engine.add_policy(policy).unwrap();
                    }
                    engine
                },
                |mut engine| {
                    let policy = DdosPolicy {
                        id: RuleId(format!("ddos-{n:05}")),
                        attack_type: DdosAttackType::SynFlood,
                        detection_threshold_pps: 1000,
                        mitigation_action: DdosMitigationAction::Block,
                        auto_block_duration_secs: 300,
                        enabled: true,
                        country_thresholds: None,
                    };
                    let _ = engine.add_policy(policy);
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

criterion_group!(benches, bench_process_event, bench_tick, bench_add_policy);
criterion_main!(benches);
