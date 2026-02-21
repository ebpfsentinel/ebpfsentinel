#![allow(clippy::cast_possible_truncation)]

use std::fmt::Write;
use std::net::IpAddr;

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};

use domain::common::error::DomainError;
use domain::threatintel::entity::{FeedConfig, FeedFormat, FieldMapping, Ioc, ThreatType};
use domain::threatintel::parser::{parse_feed, parse_threat_type};

/// JSON parser for benchmarks (uses serde_json dev-dependency).
fn bench_json_parser(text: &str, config: &FeedConfig) -> Result<Vec<Ioc>, DomainError> {
    let mapping = config.field_mapping.clone().unwrap_or_default();
    let parsed: serde_json::Value = serde_json::from_str(text)
        .map_err(|e| DomainError::EngineError(format!("JSON parse error: {e}")))?;
    let items = match &parsed {
        serde_json::Value::Array(arr) => arr.as_slice(),
        _ => {
            return Err(DomainError::EngineError(
                "JSON feed must be a top-level array".to_string(),
            ));
        }
    };
    let mut iocs = Vec::new();
    for item in items {
        let ip_str = item
            .get(&mapping.ip_field)
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let ip: IpAddr = match ip_str.parse() {
            Ok(ip) => ip,
            Err(_) => continue,
        };
        let confidence = mapping
            .confidence_field
            .as_ref()
            .and_then(|cf| item.get(cf.as_str()))
            .and_then(serde_json::Value::as_u64)
            .map_or(100, |v| v.min(100) as u8);
        let threat_type = mapping
            .category_field
            .as_ref()
            .and_then(|cf| item.get(cf.as_str()))
            .and_then(serde_json::Value::as_str)
            .map_or(ThreatType::Other, parse_threat_type);
        iocs.push(Ioc {
            ip,
            feed_id: config.id.clone(),
            confidence,
            threat_type,
            last_seen: 0,
            source_feed: config.name.clone(),
        });
    }
    Ok(iocs)
}

/// No-op JSON parser for non-JSON benchmarks.
fn no_json(_: &str, _: &FeedConfig) -> Result<Vec<Ioc>, DomainError> {
    Err(DomainError::EngineError("unexpected".into()))
}

fn plaintext_config() -> FeedConfig {
    FeedConfig {
        id: "bench".to_string(),
        name: "Bench Feed".to_string(),
        url: "https://example.com".to_string(),
        format: FeedFormat::Plaintext,
        enabled: true,
        refresh_interval_secs: 3600,
        max_iocs: 1_000_000,
        default_action: None,
        min_confidence: 0,
        field_mapping: None,
        auth_header: None,
    }
}

fn csv_config() -> FeedConfig {
    FeedConfig {
        format: FeedFormat::Csv,
        field_mapping: Some(FieldMapping {
            ip_field: "ip".to_string(),
            confidence_field: Some("score".to_string()),
            category_field: Some("category".to_string()),
            separator: ',',
            comment_prefix: Some("#".to_string()),
            skip_header: true,
        }),
        ..plaintext_config()
    }
}

fn json_config() -> FeedConfig {
    FeedConfig {
        format: FeedFormat::Json,
        field_mapping: Some(FieldMapping {
            ip_field: "ip_address".to_string(),
            confidence_field: Some("confidence".to_string()),
            category_field: Some("type".to_string()),
            ..FieldMapping::default()
        }),
        ..plaintext_config()
    }
}

fn generate_plaintext(n: usize) -> Vec<u8> {
    let mut data = String::with_capacity(n * 16);
    data.push_str("# Benchmark plaintext feed\n");
    for i in 0..n {
        let a = (i >> 16) & 0xFF;
        let b = (i >> 8) & 0xFF;
        let c = i & 0xFF;
        let _ = writeln!(data, "10.{a}.{b}.{c}");
    }
    data.into_bytes()
}

fn generate_csv(n: usize) -> Vec<u8> {
    let mut data = String::with_capacity(n * 32);
    data.push_str("ip,score,category\n");
    let categories = ["malware", "c2", "scanner", "spam"];
    for i in 0..n {
        let a = (i >> 16) & 0xFF;
        let b = (i >> 8) & 0xFF;
        let c = i & 0xFF;
        let confidence = 50 + (i % 51);
        let cat = categories[i % categories.len()];
        let _ = writeln!(data, "10.{a}.{b}.{c},{confidence},{cat}");
    }
    data.into_bytes()
}

fn generate_json(n: usize) -> Vec<u8> {
    let mut data = String::with_capacity(n * 80);
    data.push('[');
    let categories = ["malware", "c2", "scanner", "spam"];
    for i in 0..n {
        if i > 0 {
            data.push(',');
        }
        let a = (i >> 16) & 0xFF;
        let b = (i >> 8) & 0xFF;
        let c = i & 0xFF;
        let confidence = 50 + (i % 51);
        let cat = categories[i % categories.len()];
        let _ = write!(
            data,
            r#"{{"ip_address":"10.{a}.{b}.{c}","confidence":{confidence},"type":"{cat}"}}"#
        );
    }
    data.push(']');
    data.into_bytes()
}

fn bench_parse_plaintext(c: &mut Criterion) {
    let mut group = c.benchmark_group("feed_parse_plaintext");

    for &n in &[100, 1_000, 10_000] {
        let data = generate_plaintext(n);
        let config = plaintext_config();

        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| parse_feed(black_box(&data), black_box(&config), no_json));
        });
    }

    group.finish();
}

fn bench_parse_csv(c: &mut Criterion) {
    let mut group = c.benchmark_group("feed_parse_csv");

    for &n in &[100, 1_000, 10_000] {
        let data = generate_csv(n);
        let config = csv_config();

        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| parse_feed(black_box(&data), black_box(&config), no_json));
        });
    }

    group.finish();
}

fn bench_parse_json(c: &mut Criterion) {
    let mut group = c.benchmark_group("feed_parse_json");

    for &n in &[100, 1_000, 10_000] {
        let data = generate_json(n);
        let config = json_config();

        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| parse_feed(black_box(&data), black_box(&config), bench_json_parser));
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_parse_plaintext,
    bench_parse_csv,
    bench_parse_json
);
criterion_main!(benches);
