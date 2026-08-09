use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;

use domain::common::entity::RuleId;
use domain::firewall::entity::IpNetwork;
use domain::ratelimit::engine::RateLimitEngine;
use domain::ratelimit::entity::{RateLimitAction, RateLimitAlgorithm, RateLimitPolicy};

fn make_policy(id: usize, rate: u64, burst: u64) -> RateLimitPolicy {
    RateLimitPolicy {
        id: RuleId(format!("rl-{id:05}")),
        rate,
        burst,
        action: RateLimitAction::Drop,
        // One host per policy, the way the config map is keyed.
        src_ip: IpNetwork::V4 {
            addr: 0x0A00_0000 + u32::try_from(id).unwrap_or(0) + 1,
            prefix_len: 32,
        },
        enabled: true,
        algorithm: RateLimitAlgorithm::default(),
        group_mask: 0,
    }
}

fn engine_with_policies(n: usize) -> RateLimitEngine {
    let mut engine = RateLimitEngine::new();
    for i in 0..n {
        engine
            .add_policy(make_policy(i, 1000 + i as u64, 2000 + i as u64))
            .unwrap();
    }
    engine
}

fn bench_add_policy(c: &mut Criterion) {
    let mut group = c.benchmark_group("ratelimit_add_policy");

    for &n in &[10, 100, 1_000] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter_batched(
                || engine_with_policies(n),
                |mut engine| {
                    let _ = engine.add_policy(black_box(make_policy(n, 9999, 9999)));
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

fn bench_reload(c: &mut Criterion) {
    let mut group = c.benchmark_group("ratelimit_reload");

    for &n in &[100, 1_000, 10_000] {
        let policies: Vec<RateLimitPolicy> = (0..n)
            .map(|i| make_policy(i, 1000 + i as u64, 2000 + i as u64))
            .collect();

        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter_batched(
                || (RateLimitEngine::new(), policies.clone()),
                |(mut engine, policies)| {
                    let _ = engine.reload(policies);
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

criterion_group!(benches, bench_add_policy, bench_reload);
criterion_main!(benches);
