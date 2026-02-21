#![allow(clippy::cast_possible_truncation)]

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use std::net::{IpAddr, Ipv4Addr};

use domain::threatintel::engine::ThreatIntelEngine;
use domain::threatintel::entity::{Ioc, ThreatType};

fn make_ioc(i: u32) -> Ioc {
    Ioc {
        ip: IpAddr::V4(Ipv4Addr::from(i.to_be_bytes())),
        feed_id: "bench-feed".to_string(),
        confidence: 80,
        threat_type: ThreatType::Malware,
        last_seen: 0,
        source_feed: "Benchmark Feed".to_string(),
    }
}

fn engine_with_iocs(n: usize) -> ThreatIntelEngine {
    let mut engine = ThreatIntelEngine::new(n + 1000);
    for i in 1..=n as u32 {
        engine.add_ioc(make_ioc(i)).unwrap();
    }
    engine
}

fn bench_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("threatintel_lookup");

    for &n in &[1_000, 10_000, 100_000, 1_000_000] {
        let engine = engine_with_iocs(n);
        let hit_ip: IpAddr = Ipv4Addr::from(1u32.to_be_bytes()).into();
        let miss_ip: IpAddr = Ipv4Addr::from(((n as u32) + 1000).to_be_bytes()).into();

        group.bench_with_input(BenchmarkId::new("hit", n), &n, |b, _| {
            b.iter(|| engine.lookup(black_box(&hit_ip)));
        });

        group.bench_with_input(BenchmarkId::new("miss", n), &n, |b, _| {
            b.iter(|| engine.lookup(black_box(&miss_ip)));
        });
    }

    group.finish();
}

fn bench_add_ioc(c: &mut Criterion) {
    let mut group = c.benchmark_group("threatintel_add_ioc");
    group.sample_size(50);

    for &n in &[1_000, 10_000, 100_000] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter_batched(
                || engine_with_iocs(n),
                |mut engine| {
                    let _ = engine.add_ioc(make_ioc(n as u32 + 1));
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

fn bench_reload(c: &mut Criterion) {
    let mut group = c.benchmark_group("threatintel_reload");
    group.sample_size(20);

    for &n in &[1_000, 10_000, 100_000] {
        let iocs: Vec<Ioc> = (1..=n as u32).map(make_ioc).collect();

        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter_batched(
                || (ThreatIntelEngine::new(n + 1000), iocs.clone()),
                |(mut engine, iocs)| {
                    let _ = engine.reload(iocs);
                },
                criterion::BatchSize::LargeInput,
            );
        });
    }

    group.finish();
}

fn bench_iocs_by_feed(c: &mut Criterion) {
    let mut group = c.benchmark_group("threatintel_iocs_by_feed");

    for &n in &[1_000, 10_000, 100_000] {
        let engine = engine_with_iocs(n);

        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| {
                let results = engine.iocs_by_feed(black_box("bench-feed"));
                black_box(results.len());
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_lookup,
    bench_add_ioc,
    bench_reload,
    bench_iocs_by_feed
);
criterion_main!(benches);
