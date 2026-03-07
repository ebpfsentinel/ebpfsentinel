#![allow(clippy::cast_possible_truncation)]

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;

use domain::dns::blocklist::DomainBlocklistEngine;
use domain::dns::engine::DnsCacheEngine;
use domain::dns::entity::{
    BlocklistAction, DnsCacheConfig, DomainBlocklistConfig, DomainPattern, DomainReputation,
    InjectTarget, ReputationConfig, ReputationFactor,
};
use domain::dns::reputation::DomainReputationEngine;
use std::net::{IpAddr, Ipv4Addr};

// ── DNS Cache benchmarks ────────────────────────────────────────────

fn bench_dns_cache_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("dns_cache_lookup");

    for &n in &[1_000, 10_000, 100_000] {
        let mut engine = DnsCacheEngine::new(DnsCacheConfig {
            max_entries: n + 1,
            min_ttl_secs: 60,
            purge_interval_secs: 30,
        });

        for i in 0..n {
            let domain = format!("domain-{i}.example.com");
            let ips = vec![IpAddr::V4(Ipv4Addr::new(
                10,
                ((i >> 16) & 0xFF) as u8,
                ((i >> 8) & 0xFF) as u8,
                (i & 0xFF) as u8,
            ))];
            engine.insert(domain, ips, 300, 0);
        }

        let target = format!("domain-{}.example.com", n / 2);

        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| {
                let _ = engine.lookup_domain(black_box(&target), 1_000_000_000);
            });
        });
    }

    group.finish();
}

fn bench_dns_cache_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("dns_cache_insert");

    for &n in &[1_000, 10_000] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter_batched(
                || {
                    let mut engine = DnsCacheEngine::new(DnsCacheConfig {
                        max_entries: n + 1,
                        min_ttl_secs: 60,
                        purge_interval_secs: 30,
                    });
                    for i in 0..n {
                        let domain = format!("domain-{i}.example.com");
                        let ips = vec![IpAddr::V4(Ipv4Addr::new(
                            10,
                            ((i >> 16) & 0xFF) as u8,
                            ((i >> 8) & 0xFF) as u8,
                            (i & 0xFF) as u8,
                        ))];
                        engine.insert(domain, ips, 300, 0);
                    }
                    engine
                },
                |mut engine| {
                    engine.insert(
                        black_box("new-domain.example.com".to_string()),
                        vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))],
                        300,
                        1_000_000_000,
                    );
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

// ── Domain Blocklist benchmarks ─────────────────────────────────────

fn bench_blocklist_evaluate(c: &mut Criterion) {
    let mut group = c.benchmark_group("blocklist_evaluate");

    for &n in &[100, 1_000, 10_000] {
        let patterns: Vec<DomainPattern> = (0..n)
            .map(|i| DomainPattern::parse(&format!("blocked-{i}.example.com")).unwrap())
            .collect();

        let config = DomainBlocklistConfig {
            patterns,
            action: BlocklistAction::Block,
            inject_target: InjectTarget::ThreatIntel,
            grace_period_secs: 300,
        };
        let mut engine = DomainBlocklistEngine::new(config);

        let hit_domain = format!("blocked-{}.example.com", n / 2);
        let miss_domain = "clean-domain.example.com".to_string();

        group.bench_with_input(BenchmarkId::new("hit", n), &n, |b, _| {
            b.iter(|| engine.evaluate(black_box(&hit_domain)));
        });

        group.bench_with_input(BenchmarkId::new("miss", n), &n, |b, _| {
            b.iter(|| engine.evaluate(black_box(&miss_domain)));
        });
    }

    group.finish();
}

fn bench_blocklist_wildcard(c: &mut Criterion) {
    let mut group = c.benchmark_group("blocklist_wildcard");

    for &n in &[100, 1_000, 10_000] {
        let patterns: Vec<DomainPattern> = (0..n)
            .map(|i| DomainPattern::parse(&format!("*.malware-{i}.com")).unwrap())
            .collect();

        let config = DomainBlocklistConfig {
            patterns,
            action: BlocklistAction::Block,
            inject_target: InjectTarget::ThreatIntel,
            grace_period_secs: 300,
        };
        let mut engine = DomainBlocklistEngine::new(config);

        let match_domain = format!("tracker.malware-{}.com", n / 2);

        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| engine.evaluate(black_box(&match_domain)));
        });
    }

    group.finish();
}

// ── Domain Reputation benchmarks ────────────────────────────────────

fn bench_reputation_compute_score(c: &mut Criterion) {
    let mut group = c.benchmark_group("reputation_compute_score");

    let all_factors = vec![
        ReputationFactor::BlocklistHit {
            list_name: "test-list".to_string(),
        },
        ReputationFactor::CtiMatch {
            feed_name: "abuse-ch".to_string(),
            threat_type: "c2".to_string(),
        },
        ReputationFactor::HighEntropy { entropy: 4.2 },
        ReputationFactor::ShortTtl { avg_ttl: 30 },
        ReputationFactor::L7RuleMatch {
            rule_id: "rule-1".to_string(),
        },
        ReputationFactor::FrequentQueries { rate_per_min: 100.0 },
        ReputationFactor::HighRiskCountry {
            country_code: "XX".to_string(),
        },
        ReputationFactor::CtiMatch {
            feed_name: "otx".to_string(),
            threat_type: "malware".to_string(),
        },
        ReputationFactor::L7RuleMatch {
            rule_id: "rule-2".to_string(),
        },
        ReputationFactor::FrequentQueries { rate_per_min: 200.0 },
    ];

    for &n in &[1, 5, 10] {
        let rep = DomainReputation {
            domain: "suspect.example.com".to_string(),
            factors: all_factors[..n].to_vec(),
            first_seen: 0,
            last_seen: 0,
            total_connections: 42,
        };

        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| black_box(&rep).compute_score());
        });
    }

    group.finish();
}

fn bench_reputation_update(c: &mut Criterion) {
    let mut group = c.benchmark_group("reputation_update");

    for &n in &[1_000, 10_000] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter_batched(
                || {
                    let config = ReputationConfig {
                        enabled: true,
                        max_tracked_domains: n + 1,
                        ..ReputationConfig::default()
                    };
                    let mut engine = DomainReputationEngine::new(config);
                    for i in 0..n {
                        engine.update(
                            &format!("domain-{i}.example.com"),
                            ReputationFactor::HighEntropy { entropy: 3.8 },
                            0,
                        );
                    }
                    engine
                },
                |mut engine| {
                    engine.update(
                        black_box("new-domain.example.com"),
                        ReputationFactor::BlocklistHit {
                            list_name: "test".to_string(),
                        },
                        1_000_000_000,
                    );
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_dns_cache_lookup,
    bench_dns_cache_insert,
    bench_blocklist_evaluate,
    bench_blocklist_wildcard,
    bench_reputation_compute_score,
    bench_reputation_update
);
criterion_main!(benches);
