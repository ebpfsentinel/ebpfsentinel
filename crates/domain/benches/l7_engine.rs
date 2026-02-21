#![allow(clippy::cast_possible_truncation)]

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};

use domain::common::entity::RuleId;
use domain::firewall::entity::{FirewallAction, PortRange};
use domain::l7::domain_matcher::DomainMatcher;
use domain::l7::engine::L7Engine;
use domain::l7::entity::{
    HttpRequest, L7Matcher, L7Rule, ParsedProtocol, SmtpCommand, TlsClientHello,
};
use ebpf_common::event::PacketEvent;

fn make_l7_rule(id: usize, priority: u32, matcher: L7Matcher) -> L7Rule {
    L7Rule {
        id: RuleId(format!("l7-{id:05}")),
        priority,
        action: FirewallAction::Deny,
        matcher,
        src_ip: None,
        dst_ip: None,
        dst_port: None,
        enabled: true,
    }
}

fn http_matcher(method: &str) -> L7Matcher {
    L7Matcher::Http {
        method: Some(method.to_string()),
        path_pattern: None,
        host_pattern: None,
        content_type: None,
    }
}

fn make_header() -> PacketEvent {
    PacketEvent {
        timestamp_ns: 0,
        src_addr: [0xC0A8_0001, 0, 0, 0],
        dst_addr: [0x0A00_0001, 0, 0, 0],
        src_port: 12345,
        dst_port: 80,
        protocol: 6,
        event_type: 6,
        action: 0,
        flags: 0,
        rule_id: 0,
        vlan_id: 0,
        cpu_id: 0,
        socket_cookie: 0,
    }
}

fn make_http_parsed() -> ParsedProtocol {
    ParsedProtocol::Http(HttpRequest {
        method: "GET".to_string(),
        path: "/api/v1/users/search?q=admin".to_string(),
        version: "HTTP/1.1".to_string(),
        host: Some("api.example.com".to_string()),
        content_type: Some("application/json".to_string()),
        headers: vec![
            ("Accept".to_string(), "application/json".to_string()),
            ("Authorization".to_string(), "Bearer token123".to_string()),
        ],
    })
}

fn engine_with_http_rules(n: usize) -> L7Engine {
    let mut engine = L7Engine::new();
    let methods = ["POST", "PUT", "DELETE", "PATCH"];
    for i in 0..n {
        let method = methods[i % methods.len()];
        engine
            .add_rule(make_l7_rule(i, (i + 1) as u32, http_matcher(method)))
            .unwrap();
    }
    engine
}

fn bench_evaluate(c: &mut Criterion) {
    let mut group = c.benchmark_group("l7_evaluate");

    for &n in &[10, 100, 1_000] {
        let engine = engine_with_http_rules(n);
        let header = make_header();
        let http_parsed = make_http_parsed();

        group.bench_with_input(BenchmarkId::new("http_miss", n), &n, |b, _| {
            b.iter(|| engine.evaluate(black_box(&header), black_box(&http_parsed)));
        });
    }

    // TLS evaluation
    {
        let mut engine = L7Engine::new();
        for i in 0..100 {
            engine
                .add_rule(make_l7_rule(
                    i,
                    (i + 1) as u32,
                    L7Matcher::Tls {
                        sni_pattern: Some(DomainMatcher::new(&format!("evil-{i}.com")).unwrap()),
                    },
                ))
                .unwrap();
        }
        let header = make_header();
        let tls_parsed = ParsedProtocol::Tls(TlsClientHello {
            sni: Some("safe.example.com".to_string()),
        });

        group.bench_function("tls_100_rules_miss", |b| {
            b.iter(|| engine.evaluate(black_box(&header), black_box(&tls_parsed)));
        });
    }

    // SMTP evaluation
    {
        let mut engine = L7Engine::new();
        for i in 0..50 {
            engine
                .add_rule(make_l7_rule(
                    i,
                    (i + 1) as u32,
                    L7Matcher::Smtp {
                        command: Some("VRFY".to_string()),
                    },
                ))
                .unwrap();
        }
        let header = make_header();
        let smtp_parsed = ParsedProtocol::Smtp(SmtpCommand {
            command: "EHLO".to_string(),
            params: "example.com".to_string(),
        });

        group.bench_function("smtp_50_rules_miss", |b| {
            b.iter(|| engine.evaluate(black_box(&header), black_box(&smtp_parsed)));
        });
    }

    group.finish();
}

fn bench_evaluate_with_l3l4(c: &mut Criterion) {
    let mut group = c.benchmark_group("l7_evaluate_l3l4");

    let mut engine = L7Engine::new();
    for i in 0..100 {
        let mut rule = make_l7_rule(i, (i + 1) as u32, http_matcher("POST"));
        rule.dst_port = Some(PortRange {
            start: (8080 + i) as u16,
            end: (8080 + i) as u16,
        });
        engine.add_rule(rule).unwrap();
    }

    let header = make_header(); // dst_port=80, won't match 8080+
    let parsed = make_http_parsed();

    group.bench_function("100_rules_port_mismatch", |b| {
        b.iter(|| engine.evaluate(black_box(&header), black_box(&parsed)));
    });

    group.finish();
}

criterion_group!(benches, bench_evaluate, bench_evaluate_with_l3l4);
criterion_main!(benches);
