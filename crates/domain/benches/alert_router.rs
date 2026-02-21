#![allow(clippy::cast_possible_truncation, clippy::similar_names)]

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use std::time::Duration;

use domain::alert::engine::AlertRouter;
use domain::alert::entity::{Alert, AlertDestination, AlertRoute};
use domain::common::entity::{DomainMode, RuleId, Severity};

fn make_alert(id: usize, severity: Severity) -> Alert {
    Alert {
        id: format!("alert-{id}"),
        timestamp_ns: 1_000_000_000,
        component: "ids".to_string(),
        severity,
        rule_id: RuleId(format!("ids-{id:05}")),
        action: DomainMode::Alert,
        src_addr: [id as u32, 0, 0, 0],
        dst_addr: [0x0A00_0001, 0, 0, 0],
        src_port: 12345,
        dst_port: 22,
        protocol: 6,
        is_ipv6: false,
        message: "benchmark alert".to_string(),
        false_positive: false,
        src_domain: None,
        dst_domain: None,
        src_domain_score: None,
        dst_domain_score: None,
    }
}

fn make_route(name: &str, min_severity: Severity) -> AlertRoute {
    AlertRoute {
        name: name.to_string(),
        destination: AlertDestination::Log,
        min_severity,
        event_types: None,
    }
}

fn make_route_with_types(name: &str, min_severity: Severity, types: Vec<String>) -> AlertRoute {
    AlertRoute {
        name: name.to_string(),
        destination: AlertDestination::Log,
        min_severity,
        event_types: Some(types),
    }
}

fn bench_process_alert(c: &mut Criterion) {
    let mut group = c.benchmark_group("alert_process_alert");

    // Vary number of routes
    for &n_routes in &[1, 5, 10, 20] {
        let routes: Vec<AlertRoute> = (0..n_routes)
            .map(|i| {
                let sev = match i % 4 {
                    0 => Severity::Low,
                    1 => Severity::Medium,
                    2 => Severity::High,
                    _ => Severity::Critical,
                };
                make_route(&format!("route-{i}"), sev)
            })
            .collect();

        group.bench_with_input(
            BenchmarkId::new("unique_alerts", n_routes),
            &n_routes,
            |b, _| {
                b.iter_batched(
                    || {
                        AlertRouter::new(
                            routes.clone(),
                            Duration::from_secs(0), // no dedup (each alert is unique)
                            Duration::from_secs(300),
                            1_000_000,
                        )
                    },
                    |mut router| {
                        let alert = make_alert(rand_id(), Severity::High);
                        router.process_alert(black_box(&alert));
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

fn bench_dedup(c: &mut Criterion) {
    let mut group = c.benchmark_group("alert_dedup");

    let routes = vec![make_route("all", Severity::Low)];

    group.bench_function("first_seen", |b| {
        b.iter_batched(
            || {
                AlertRouter::new(
                    routes.clone(),
                    Duration::from_secs(60),
                    Duration::from_secs(300),
                    100_000,
                )
            },
            |mut router| {
                let alert = make_alert(rand_id(), Severity::High);
                router.process_alert(black_box(&alert));
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.bench_function("duplicate_suppressed", |b| {
        b.iter_batched(
            || {
                let mut router = AlertRouter::new(
                    routes.clone(),
                    Duration::from_secs(60),
                    Duration::from_secs(300),
                    100_000,
                );
                // Pre-fill with the alert we'll try to submit
                let alert = make_alert(42, Severity::High);
                router.process_alert(&alert);
                (router, alert)
            },
            |(mut router, alert)| {
                router.process_alert(black_box(&alert));
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn bench_event_type_filter(c: &mut Criterion) {
    let mut group = c.benchmark_group("alert_event_type_filter");

    let routes = vec![
        make_route_with_types("ids-only", Severity::Low, vec!["ids".to_string()]),
        make_route_with_types(
            "multi",
            Severity::Low,
            vec![
                "ids".to_string(),
                "dlp".to_string(),
                "threatintel".to_string(),
            ],
        ),
        make_route("all", Severity::High),
    ];

    group.bench_function("3_routes_mixed_filters", |b| {
        b.iter_batched(
            || {
                AlertRouter::new(
                    routes.clone(),
                    Duration::from_secs(0),
                    Duration::from_secs(300),
                    1_000_000,
                )
            },
            |mut router| {
                let alert = make_alert(rand_id(), Severity::High);
                router.process_alert(black_box(&alert));
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

/// Simple counter for unique alert IDs (avoids dedup).
fn rand_id() -> usize {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

criterion_group!(
    benches,
    bench_process_alert,
    bench_dedup,
    bench_event_type_filter
);
criterion_main!(benches);
