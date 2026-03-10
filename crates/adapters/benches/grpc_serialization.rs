use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;

use domain::alert::entity::Alert;
use domain::common::entity::{DomainMode, RuleId, Severity};

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
        message: "benchmark alert for serialization".to_string(),
        false_positive: false,
        src_domain: Some("src.example.com".to_string()),
        dst_domain: Some("dst.example.com".to_string()),
        src_domain_score: Some(0.85),
        dst_domain_score: Some(0.1),
        src_geo: None,
        dst_geo: None,
        confidence: Some(95),
        threat_type: Some("malware".to_string()),
        data_type: None,
        pid: Some(1234),
        tgid: Some(1234),
        direction: Some(1),
        matched_domain: Some("evil.example.com".to_string()),
        attack_type: None,
        peak_pps: None,
        current_pps: None,
        mitigation_status: None,
        total_packets: None,
    }
}

fn bench_alert_json_serialize(c: &mut Criterion) {
    let mut group = c.benchmark_group("alert_json_serialize");

    for &count in &[1, 10, 100] {
        let alerts: Vec<Alert> = (0..count)
            .map(|i: i32| make_alert(&format!("alert-{i}"), u64::from(i.cast_unsigned()) * 1000))
            .collect();

        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, _| {
            b.iter(|| {
                for alert in &alerts {
                    let _ = serde_json::to_string(black_box(alert));
                }
            });
        });
    }

    group.finish();
}

fn bench_alert_json_deserialize(c: &mut Criterion) {
    let mut group = c.benchmark_group("alert_json_deserialize");

    for &count in &[1, 10, 100] {
        let jsons: Vec<String> = (0..count)
            .map(|i: i32| {
                serde_json::to_string(&make_alert(
                    &format!("alert-{i}"),
                    u64::from(i.cast_unsigned()) * 1000,
                ))
                .unwrap()
            })
            .collect();

        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, _| {
            b.iter(|| {
                for json in &jsons {
                    let _ = serde_json::from_str::<Alert>(black_box(json));
                }
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_alert_json_serialize,
    bench_alert_json_deserialize
);
criterion_main!(benches);
