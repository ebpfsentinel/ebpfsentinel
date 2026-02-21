use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};

use domain::common::entity::{DomainMode, RuleId, Severity};
use domain::dlp::engine::DlpEngine;
use domain::dlp::entity::DlpPattern;

fn make_pattern(id: usize, regex: &str) -> DlpPattern {
    DlpPattern {
        id: RuleId(format!("dlp-{id:03}")),
        name: format!("Pattern {id}"),
        regex: regex.to_string(),
        severity: Severity::High,
        mode: DomainMode::Alert,
        data_type: "pci".to_string(),
        description: String::new(),
        enabled: true,
    }
}

/// Realistic DLP patterns for credit cards, SSNs, emails, etc.
const REALISTIC_PATTERNS: &[&str] = &[
    r"\b4[0-9]{12}(?:[0-9]{3})?\b",                                 // Visa
    r"\b5[1-5][0-9]{14}\b",                                         // Mastercard
    r"\b3[47][0-9]{13}\b",                                          // Amex
    r"\b\d{3}-\d{2}-\d{4}\b",                                       // SSN
    r"\b[A-Z]{2}\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{0,2}\b", // IBAN
    r"\bAKIA[0-9A-Z]{16}\b",                                        // AWS key
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",          // Email
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b",                                 // IPv4
    r"\b[0-9a-fA-F]{40}\b",                                         // SHA1 hash
    r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----",                    // Private key header
];

fn engine_with_patterns(n: usize) -> DlpEngine {
    let mut engine = DlpEngine::new();
    for i in 0..n {
        let pattern = REALISTIC_PATTERNS[i % REALISTIC_PATTERNS.len()];
        engine.add_pattern(make_pattern(i, pattern)).unwrap();
    }
    engine
}

fn generate_data(size: usize, has_sensitive: bool) -> Vec<u8> {
    let mut data = Vec::with_capacity(size);
    let filler = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. ";

    while data.len() < size {
        if has_sensitive && data.len() == size / 2 {
            data.extend_from_slice(b"Card: 4111111111111111 SSN: 123-45-6789 ");
        }
        let remaining = size - data.len();
        let chunk = remaining.min(filler.len());
        data.extend_from_slice(&filler[..chunk]);
    }
    data.truncate(size);
    data
}

fn bench_scan_data(c: &mut Criterion) {
    let mut group = c.benchmark_group("dlp_scan_data");

    // Vary pattern count
    for &n_patterns in &[1, 5, 10] {
        let engine = engine_with_patterns(n_patterns);
        let data_1k = generate_data(1024, false);

        group.bench_with_input(
            BenchmarkId::new("no_match_1KB", n_patterns),
            &n_patterns,
            |b, _| {
                b.iter(|| engine.scan_data(black_box(&data_1k)));
            },
        );
    }

    // Vary data size with 5 patterns
    let engine = engine_with_patterns(5);
    for &size in &[1024, 10_240, 102_400] {
        let label = match size {
            1024 => "1KB",
            10_240 => "10KB",
            102_400 => "100KB",
            _ => unreachable!(),
        };

        let data_clean = generate_data(size, false);
        group.bench_with_input(
            BenchmarkId::new(format!("clean_{label}"), 5),
            &size,
            |b, _| {
                b.iter(|| engine.scan_data(black_box(&data_clean)));
            },
        );

        let data_sensitive = generate_data(size, true);
        group.bench_with_input(
            BenchmarkId::new(format!("sensitive_{label}"), 5),
            &size,
            |b, _| {
                b.iter(|| engine.scan_data(black_box(&data_sensitive)));
            },
        );
    }

    group.finish();
}

fn bench_reload(c: &mut Criterion) {
    let mut group = c.benchmark_group("dlp_reload");

    for &n in &[5, 10, 20] {
        let patterns: Vec<DlpPattern> = (0..n)
            .map(|i| {
                let p = REALISTIC_PATTERNS[i % REALISTIC_PATTERNS.len()];
                make_pattern(i, p)
            })
            .collect();

        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter_batched(
                || (DlpEngine::new(), patterns.clone()),
                |(mut engine, patterns)| {
                    let _ = engine.reload(patterns);
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

criterion_group!(benches, bench_scan_data, bench_reload);
criterion_main!(benches);
