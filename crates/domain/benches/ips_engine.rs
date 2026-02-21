#![allow(clippy::cast_possible_truncation)]

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use domain::ips::engine::IpsEngine;
use domain::ips::entity::IpsPolicy;

fn ip(i: u32) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(i.to_be_bytes()))
}

fn test_policy() -> IpsPolicy {
    IpsPolicy {
        max_blacklist_duration: Duration::from_secs(3600),
        auto_blacklist_threshold: 3,
        max_blacklist_size: 2_000_000,
    }
}

fn engine_with_blacklist(n: usize) -> IpsEngine {
    let mut engine = IpsEngine::new(test_policy());
    for i in 0..n as u32 {
        engine
            .add_to_blacklist(
                ip(i + 1),
                "bench".to_string(),
                false,
                Duration::from_secs(3600),
            )
            .unwrap();
    }
    engine
}

fn bench_is_blacklisted(c: &mut Criterion) {
    let mut group = c.benchmark_group("ips_is_blacklisted");

    for &n in &[100, 1_000, 10_000, 100_000] {
        group.bench_with_input(BenchmarkId::new("hit", n), &n, |b, &n| {
            b.iter_batched(
                || engine_with_blacklist(n),
                |mut engine| {
                    engine.is_blacklisted(black_box(ip(1)));
                },
                criterion::BatchSize::SmallInput,
            );
        });

        group.bench_with_input(BenchmarkId::new("miss", n), &n, |b, &n| {
            b.iter_batched(
                || engine_with_blacklist(n),
                |mut engine| {
                    engine.is_blacklisted(black_box(ip(n as u32 + 1000)));
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

fn bench_record_detection(c: &mut Criterion) {
    let mut group = c.benchmark_group("ips_record_detection");

    group.bench_function("under_threshold", |b| {
        b.iter_batched(
            || IpsEngine::new(test_policy()),
            |mut engine| {
                engine.record_detection(black_box(ip(1)));
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.bench_function("at_threshold", |b| {
        b.iter_batched(
            || {
                let mut engine = IpsEngine::new(test_policy());
                engine.record_detection(ip(1));
                engine.record_detection(ip(1));
                engine
            },
            |mut engine| {
                engine.record_detection(black_box(ip(1)));
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn bench_cleanup_expired(c: &mut Criterion) {
    let mut group = c.benchmark_group("ips_cleanup_expired");

    for &n in &[100, 1_000, 10_000] {
        group.bench_with_input(BenchmarkId::new("none_expired", n), &n, |b, &n| {
            b.iter_batched(
                || engine_with_blacklist(n),
                |mut engine| {
                    engine.cleanup_expired();
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_is_blacklisted,
    bench_record_detection,
    bench_cleanup_expired
);
criterion_main!(benches);
