use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use tempfile::TempDir;

use adapters::storage::redb_alert_store::RedbAlertStore;
use adapters::storage::redb_audit_store::RedbAuditStore;
use domain::alert::entity::Alert;
use domain::alert::query::AlertQuery;
use domain::audit::entity::{AuditAction, AuditComponent, AuditEntry};
use domain::common::entity::{DomainMode, RuleId, Severity};
use ports::secondary::alert_store::AlertStore;
use ports::secondary::audit_store::AuditStore;

fn make_alert(id: &str, ts: u64) -> Alert {
    Alert {
        id: id.to_string(),
        timestamp_ns: ts,
        component: "ids".to_string(),
        severity: Severity::High,
        rule_id: RuleId("ids-001".to_string()),
        action: DomainMode::Alert,
        src_addr: [0xC0A8_0001, 0, 0, 0],
        dst_addr: [0x0A00_0001, 0, 0, 0],
        src_port: 12345,
        dst_port: 80,
        protocol: 6,
        is_ipv6: false,
        message: "benchmark alert".to_string(),
        false_positive: false,
        src_domain: None,
        dst_domain: None,
        src_domain_score: None,
        dst_domain_score: None,
        src_geo: None,
        dst_geo: None,
        confidence: None,
        threat_type: None,
        data_type: None,
        pid: None,
        tgid: None,
        direction: None,
        matched_domain: None,
        attack_type: None,
        peak_pps: None,
        current_pps: None,
        mitigation_status: None,
        total_packets: None,
    }
}

fn make_audit_entry(ts: u64) -> AuditEntry {
    AuditEntry::security_decision(
        AuditComponent::Firewall,
        AuditAction::Drop,
        ts,
        [1, 0, 0, 0],
        [2, 0, 0, 0],
        false,
        80,
        443,
        6,
        "fw-001",
        "bench",
    )
}

fn bench_alert_store(c: &mut Criterion) {
    let mut group = c.benchmark_group("alert_store_store");

    for &existing in &[0, 100, 1_000] {
        group.bench_with_input(
            BenchmarkId::from_parameter(existing),
            &existing,
            |b, &existing| {
                b.iter_batched(
                    || {
                        let dir = TempDir::new().unwrap();
                        let path = dir.path().join("alerts.redb");
                        let store = RedbAlertStore::open(&path).unwrap();
                        for i in 0..existing {
                            store
                                .store_alert(&make_alert(&format!("pre-{i}"), i as u64))
                                .unwrap();
                        }
                        (store, dir, existing)
                    },
                    |(store, _dir, existing)| {
                        let _ = store.store_alert(black_box(&make_alert(
                            "new",
                            existing as u64 + 1,
                        )));
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

fn bench_alert_query(c: &mut Criterion) {
    let mut group = c.benchmark_group("alert_store_query");

    for &n in &[100, 1_000] {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("alerts.redb");
        let store = RedbAlertStore::open(&path).unwrap();
        for i in 0..n {
            store
                .store_alert(&make_alert(&format!("a-{i}"), i as u64))
                .unwrap();
        }
        let query = AlertQuery {
            limit: 50,
            ..Default::default()
        };

        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| store.query_alerts(black_box(&query)));
        });
    }

    group.finish();
}

fn bench_audit_store(c: &mut Criterion) {
    let mut group = c.benchmark_group("audit_store");

    for &existing in &[0, 100, 1_000] {
        group.bench_with_input(
            BenchmarkId::from_parameter(existing),
            &existing,
            |b, &existing| {
                b.iter_batched(
                    || {
                        let dir = TempDir::new().unwrap();
                        let path = dir.path().join("audit.redb");
                        let store = RedbAuditStore::open(&path, 50_000).unwrap();
                        for i in 0..existing {
                            store.store_entry(&make_audit_entry(i as u64)).unwrap();
                        }
                        (store, dir, existing)
                    },
                    |(store, _dir, existing)| {
                        let _ =
                            store.store_entry(black_box(&make_audit_entry(existing as u64 + 1)));
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_alert_store, bench_alert_query, bench_audit_store);
criterion_main!(benches);
