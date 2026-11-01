//! The per-event cost of a glob against a regular expression saying the
//! same thing, which is why glob stays the documented default.

#![allow(clippy::unwrap_used)]

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

use domain::hostrule::{FieldValue, HostRule, HostRuleSpec, Intent, IntentEvent};

fn rule(matcher: &str, pattern: &str) -> HostRule {
    let json =
        format!(r#"{{"id":"r","when":{{"process.starts":{{"exe_{matcher}":["{pattern}"]}}}}}}"#);
    let spec: HostRuleSpec = serde_json::from_str(&json).unwrap();
    HostRule::compile(spec).unwrap()
}

fn event(exe: &str) -> IntentEvent {
    IntentEvent::new(Intent::ProcessStarts)
        .with("exe", FieldValue::Text(exe.to_string()))
        .unwrap()
}

fn bench_matchers(c: &mut Criterion) {
    let glob = rule("matches", "/tmp/*/payload*");
    let regex = rule("regex", "^/tmp/[^/]+/payload");
    let hit = event("/tmp/build-1234/payload.bin");
    let miss = event("/usr/lib/x86_64-linux-gnu/libexec/some-long-helper-binary");
    assert!(glob.matches(&hit, None) && regex.matches(&hit, None));
    assert!(!glob.matches(&miss, None) && !regex.matches(&miss, None));

    let mut group = c.benchmark_group("host_rule_matcher");
    group.bench_function("glob_hit", |b| {
        b.iter(|| glob.matches(black_box(&hit), None));
    });
    group.bench_function("glob_miss", |b| {
        b.iter(|| glob.matches(black_box(&miss), None));
    });
    group.bench_function("regex_hit", |b| {
        b.iter(|| regex.matches(black_box(&hit), None));
    });
    group.bench_function("regex_miss", |b| {
        b.iter(|| regex.matches(black_box(&miss), None));
    });
    group.finish();
}

criterion_group!(benches, bench_matchers);
criterion_main!(benches);
