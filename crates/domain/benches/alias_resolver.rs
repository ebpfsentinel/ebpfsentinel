#![allow(clippy::cast_possible_truncation)]

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;

use domain::alias::entity::{Alias, AliasId, AliasKind};
use domain::alias::resolver::AliasResolver;
use domain::firewall::entity::IpNetwork;

fn ip_set_alias(id: &str, n_ips: usize) -> Alias {
    let values: Vec<IpNetwork> = (0..n_ips)
        .map(|i| IpNetwork::V4 {
            addr: 0x0A00_0000 | (i as u32),
            prefix_len: 32,
        })
        .collect();
    Alias {
        id: AliasId(id.to_string()),
        kind: AliasKind::IpSet {
            values,
            exclude: Vec::new(),
        },
        description: None,
    }
}

fn nested_alias(id: &str, refs: Vec<&str>) -> Alias {
    Alias {
        id: AliasId(id.to_string()),
        kind: AliasKind::Nested {
            aliases: refs.into_iter().map(String::from).collect(),
            exclude: Vec::new(),
        },
        description: None,
    }
}

fn flat_resolver(n: usize) -> AliasResolver {
    let aliases: Vec<Alias> = (0..n)
        .map(|i| ip_set_alias(&format!("set-{i}"), 10))
        .collect();
    let mut resolver = AliasResolver::new();
    resolver.load(aliases).unwrap();
    resolver
}

fn chain_resolver(depth: usize) -> AliasResolver {
    let mut aliases = vec![ip_set_alias("leaf", 5)];
    for i in 0..depth {
        let parent_name = if i == 0 {
            "leaf".to_string()
        } else {
            format!("mid-{}", i - 1)
        };
        aliases.push(nested_alias(&format!("mid-{i}"), vec![&parent_name]));
    }
    aliases.push(nested_alias("top", vec![&format!("mid-{}", depth - 1)]));
    let mut resolver = AliasResolver::new();
    resolver.load(aliases).unwrap();
    resolver
}

fn fanout_resolver(n: usize) -> AliasResolver {
    let mut aliases: Vec<Alias> = (0..n)
        .map(|i| ip_set_alias(&format!("child-{i}"), 5))
        .collect();
    let ref_names: Vec<String> = (0..n).map(|i| format!("child-{i}")).collect();
    let ref_strs: Vec<&str> = ref_names.iter().map(String::as_str).collect();
    aliases.push(nested_alias("top", ref_strs));
    let mut resolver = AliasResolver::new();
    resolver.load(aliases).unwrap();
    resolver
}

fn bench_resolve_flat(c: &mut Criterion) {
    let mut group = c.benchmark_group("alias_resolve_flat");

    for &n in &[10, 50, 100] {
        let resolver = flat_resolver(n);
        group.bench_function(BenchmarkId::from_parameter(n), |b| {
            b.iter(|| resolver.resolve_ips(black_box("set-0")));
        });
    }

    group.finish();
}

fn bench_resolve_chain(c: &mut Criterion) {
    let mut group = c.benchmark_group("alias_resolve_chain");

    for &depth in &[5, 10, 20, 50] {
        let resolver = chain_resolver(depth);
        group.bench_function(BenchmarkId::from_parameter(depth), |b| {
            b.iter(|| resolver.resolve_ips(black_box("top")));
        });
    }

    group.finish();
}

fn bench_resolve_fanout(c: &mut Criterion) {
    let mut group = c.benchmark_group("alias_resolve_fanout");

    for &n in &[10, 50, 100] {
        let resolver = fanout_resolver(n);
        group.bench_function(BenchmarkId::from_parameter(n), |b| {
            b.iter(|| resolver.resolve_ips(black_box("top")));
        });
    }

    group.finish();
}

fn bench_load(c: &mut Criterion) {
    let mut group = c.benchmark_group("alias_load");

    for &n in &[10, 50, 100, 200] {
        let aliases: Vec<Alias> = (0..n)
            .map(|i| ip_set_alias(&format!("set-{i}"), 10))
            .collect();

        group.bench_function(BenchmarkId::from_parameter(n), |b| {
            b.iter_batched(
                || (AliasResolver::new(), aliases.clone()),
                |(mut resolver, aliases)| {
                    let _ = resolver.load(aliases);
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_resolve_flat,
    bench_resolve_chain,
    bench_resolve_fanout,
    bench_load
);
criterion_main!(benches);
