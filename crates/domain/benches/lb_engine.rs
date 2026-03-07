#![allow(clippy::cast_possible_truncation)]

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};

use domain::common::entity::RuleId;
use domain::loadbalancer::engine::LbEngine;
use domain::loadbalancer::entity::{LbAlgorithm, LbBackend, LbProtocol, LbService};

fn make_backend(id: usize, weight: u32) -> LbBackend {
    LbBackend {
        id: format!("be-{id}"),
        addr: IpAddr::V4(Ipv4Addr::new(10, 0, (id >> 8) as u8, id as u8)),
        port: 8080 + id as u16,
        weight,
        enabled: true,
    }
}

fn make_service(id: usize, algorithm: LbAlgorithm, n_backends: usize) -> LbService {
    let backends: Vec<LbBackend> = (0..n_backends).map(|i| make_backend(i, 1)).collect();
    LbService {
        id: RuleId(format!("svc-{id}")),
        name: format!("service-{id}"),
        protocol: LbProtocol::Tcp,
        listen_port: 443 + id as u16,
        algorithm,
        backends,
        enabled: true,
        health_check: None,
    }
}

fn client_addr(n: u8) -> [u32; 4] {
    [u32::from_le_bytes([192, 168, 1, n]), 0, 0, 0]
}

fn bench_select_round_robin(c: &mut Criterion) {
    let mut group = c.benchmark_group("lb_select_round_robin");

    for &n_backends in &[2, 5, 10, 20] {
        group.bench_function(BenchmarkId::new("backends", n_backends), |b| {
            let mut engine = LbEngine::new();
            engine
                .add_service(make_service(0, LbAlgorithm::RoundRobin, n_backends))
                .unwrap();
            b.iter(|| {
                let _ = engine.select_backend(black_box("svc-0"), black_box(client_addr(1)));
            });
        });
    }

    group.finish();
}

fn bench_select_ip_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("lb_select_ip_hash");

    for &n_backends in &[2, 5, 10, 20] {
        group.bench_function(BenchmarkId::new("backends", n_backends), |b| {
            let mut engine = LbEngine::new();
            engine
                .add_service(make_service(0, LbAlgorithm::IpHash, n_backends))
                .unwrap();
            let mut i = 0u8;
            b.iter(|| {
                i = i.wrapping_add(1);
                let _ = engine.select_backend(black_box("svc-0"), black_box(client_addr(i)));
            });
        });
    }

    group.finish();
}

fn bench_select_weighted(c: &mut Criterion) {
    let mut group = c.benchmark_group("lb_select_weighted");

    for &n_backends in &[2, 5, 10] {
        group.bench_function(BenchmarkId::new("backends", n_backends), |b| {
            let mut engine = LbEngine::new();
            let mut svc = make_service(0, LbAlgorithm::Weighted, n_backends);
            for (i, be) in svc.backends.iter_mut().enumerate() {
                be.weight = (i as u32 + 1) * 10;
            }
            engine.add_service(svc).unwrap();
            let mut i = 0u8;
            b.iter(|| {
                i = i.wrapping_add(1);
                let _ = engine.select_backend(black_box("svc-0"), black_box(client_addr(i)));
            });
        });
    }

    group.finish();
}

fn bench_select_least_conn(c: &mut Criterion) {
    let mut group = c.benchmark_group("lb_select_least_conn");

    for &n_backends in &[2, 5, 10, 20] {
        group.bench_function(BenchmarkId::new("backends", n_backends), |b| {
            let mut engine = LbEngine::new();
            engine
                .add_service(make_service(0, LbAlgorithm::LeastConn, n_backends))
                .unwrap();
            for i in 0..n_backends {
                for _ in 0..i {
                    let _ = engine.record_connection("svc-0", &format!("be-{i}"));
                }
            }
            b.iter(|| {
                let _ = engine.select_backend(black_box("svc-0"), black_box(client_addr(1)));
            });
        });
    }

    group.finish();
}

fn bench_reload(c: &mut Criterion) {
    let mut group = c.benchmark_group("lb_reload");

    for &n_services in &[5, 10, 32, 64] {
        let services: Vec<LbService> = (0..n_services)
            .map(|i| make_service(i, LbAlgorithm::RoundRobin, 3))
            .collect();

        group.bench_function(BenchmarkId::from_parameter(n_services), |b| {
            b.iter_batched(
                || (LbEngine::new(), services.clone()),
                |(mut engine, services)| {
                    let _ = engine.reload(services);
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_select_round_robin,
    bench_select_ip_hash,
    bench_select_weighted,
    bench_select_least_conn,
    bench_reload
);
criterion_main!(benches);
