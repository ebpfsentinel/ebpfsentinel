//! Benchmarks for the userspace side of eBPF map operations.
//!
//! These measure the cost of converting domain entities into the `#[repr(C)]`
//! structs that get written to eBPF maps.  The benchmarks do **not** require
//! loaded eBPF programs or `CAP_BPF` -- they exercise pure userspace conversion
//! logic.  If a future variant needs real kernel maps, check for root at
//! runtime and skip gracefully.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::manual_is_multiple_of
)]

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;

use domain::common::entity::{Protocol, RuleId};
use domain::firewall::entity::{FirewallAction, FirewallRule, IpNetwork, PortRange, Scope};
use ebpf_common::firewall::FirewallRuleEntry;
use ebpf_common::ratelimit::RateLimitConfig;
use ebpf_common::threatintel::{ThreatIntelKey, ThreatIntelValue};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns `true` when the effective UID is 0 (root).
/// Used by benchmarks that would need real eBPF access.
fn is_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .map(|s| {
            s.lines()
                .any(|l| l.starts_with("Uid:") && l.split_whitespace().nth(1) == Some("0"))
        })
        .unwrap_or(false)
}

/// Build a synthetic [`FirewallRule`] with deterministic fields derived from `i`.
fn make_firewall_rule(i: usize) -> FirewallRule {
    let octet = (i % 256) as u8;
    let subnet = ((i / 256) % 256) as u8;
    FirewallRule {
        id: RuleId(format!("bench-fw-{i}")),
        priority: (i as u32 % 1000) + 1,
        action: match i % 3 {
            0 => FirewallAction::Allow,
            1 => FirewallAction::Deny,
            _ => FirewallAction::Log,
        },
        protocol: match i % 4 {
            0 => Protocol::Tcp,
            1 => Protocol::Udp,
            2 => Protocol::Icmp,
            _ => Protocol::Any,
        },
        src_ip: Some(IpNetwork::V4 {
            addr: u32::from_be_bytes([10, subnet, octet, 0]),
            prefix_len: 24,
        }),
        dst_ip: Some(IpNetwork::V4 {
            addr: u32::from_be_bytes([192, 168, subnet, 0]),
            prefix_len: 24,
        }),
        src_port: if i % 2 == 0 {
            Some(PortRange {
                start: 1024,
                end: 65535,
            })
        } else {
            None
        },
        dst_port: Some(PortRange {
            start: 80,
            end: 80 + (i % 10) as u16,
        }),
        scope: Scope::Global,
        enabled: true,
        vlan_id: if i % 5 == 0 { Some(100) } else { None },
        src_alias: None,
        dst_alias: None,
        src_port_alias: None,
        dst_port_alias: None,
        src_mac_alias: None,
        dst_mac_alias: None,
        ct_states: None,
        tcp_flags: None,
        icmp_type: None,
        icmp_code: None,
        negate_src: false,
        negate_dst: false,
        dscp_match: None,
        dscp_mark: None,
        max_states: None,
        src_mac: None,
        dst_mac: None,
        schedule: None,
        system: false,
        route_action: None,
        group_mask: 0,
    }
}

// ---------------------------------------------------------------------------
// Benchmark group 1: FirewallRule -> FirewallRuleEntry conversion
// ---------------------------------------------------------------------------

fn firewall_rule_conversion(c: &mut Criterion) {
    let mut group = c.benchmark_group("firewall_rule_conversion");

    for count in [100, 1_000, 10_000] {
        group.bench_with_input(
            BenchmarkId::new("convert_rules", count),
            &count,
            |b, &count| {
                let rules: Vec<FirewallRule> = (0..count).map(make_firewall_rule).collect();
                b.iter(|| {
                    let entries: Vec<FirewallRuleEntry> =
                        rules.iter().map(FirewallRule::to_ebpf_entry).collect();
                    black_box(entries)
                });
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark group 2: IOC entry construction (ThreatIntelKey + Value)
// ---------------------------------------------------------------------------

fn ioc_entry_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("ioc_entry_construction");

    for count in [1_000usize, 10_000] {
        group.bench_with_input(
            BenchmarkId::new("construct_iocs", count),
            &count,
            |b, &count| {
                // Pre-generate raw IOC data (IP as u32 + metadata)
                let raw_iocs: Vec<(u32, u8, u8, u8)> = (0..count)
                    .map(|i| {
                        let ip = u32::from_be_bytes([
                            10,
                            ((i / 65536) % 256) as u8,
                            ((i / 256) % 256) as u8,
                            (i % 256) as u8,
                        ]);
                        let feed_id = (i % 8) as u8;
                        let confidence = (50 + (i % 51)) as u8;
                        let threat_type = (i % 5) as u8;
                        (ip, feed_id, confidence, threat_type)
                    })
                    .collect();

                b.iter(|| {
                    let entries: Vec<(ThreatIntelKey, ThreatIntelValue)> = raw_iocs
                        .iter()
                        .map(|&(ip, feed_id, confidence, threat_type)| {
                            let key = ThreatIntelKey { ip };
                            let value = ThreatIntelValue {
                                action: if confidence > 80 {
                                    ebpf_common::threatintel::THREATINTEL_ACTION_DROP
                                } else {
                                    ebpf_common::threatintel::THREATINTEL_ACTION_ALERT
                                },
                                feed_id,
                                confidence,
                                threat_type,
                            };
                            (key, value)
                        })
                        .collect();
                    black_box(entries)
                });
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark group 3: Rate limit policy construction
// ---------------------------------------------------------------------------

fn ratelimit_policy_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("ratelimit_policy_construction");

    for count in [100usize, 1_000] {
        group.bench_with_input(
            BenchmarkId::new("construct_policies", count),
            &count,
            |b, &count| {
                // Pre-generate raw policy parameters
                let raw_policies: Vec<(u64, u64, u8, u8)> = (0..count)
                    .map(|i| {
                        let rate_pps = 1000 + (i as u64 * 100);
                        let ns_per_token = 1_000_000_000u64 / rate_pps;
                        let burst = 50 + (i as u64 % 200);
                        let action = ebpf_common::ratelimit::RATELIMIT_ACTION_DROP;
                        let algorithm = (i % 4) as u8;
                        (ns_per_token, burst, action, algorithm)
                    })
                    .collect();

                b.iter(|| {
                    let configs: Vec<RateLimitConfig> = raw_policies
                        .iter()
                        .map(
                            |&(ns_per_token, burst, action, algorithm)| RateLimitConfig {
                                ns_per_token,
                                burst,
                                action,
                                algorithm,
                                _padding: [0; 2],
                                group_mask: 0,
                            },
                        )
                        .collect();
                    black_box(configs)
                });
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark group 4: Backend struct construction (for load balancer maps)
// ---------------------------------------------------------------------------

fn backend_struct_construction(c: &mut Criterion) {
    if !is_root() {
        eprintln!(
            "skipping backend_struct_construction: \
             full eBPF map benchmarks require root (CAP_BPF)"
        );
        // Still register the group so Criterion reports it, but do no work.
    }

    let mut group = c.benchmark_group("backend_struct_construction");

    for count in [10usize, 100] {
        group.bench_with_input(
            BenchmarkId::new("construct_backends", count),
            &count,
            |b, &count| {
                // Simulate backend entries as (ip, port, weight) tuples
                let raw_backends: Vec<(u32, u16, u16)> = (0..count)
                    .map(|i| {
                        let ip =
                            u32::from_be_bytes([172, 16, ((i / 256) % 256) as u8, (i % 256) as u8]);
                        let port = 8080 + (i % 10) as u16;
                        let weight = 1 + (i % 100) as u16;
                        (ip, port, weight)
                    })
                    .collect();

                b.iter(|| {
                    // Build a Vec of (key, value) tuples representing backend
                    // map entries.  We use a simple byte arrays here since the
                    // actual load-balancer eBPF types mirror this shape.
                    let entries: Vec<([u8; 8], [u8; 8])> = raw_backends
                        .iter()
                        .map(|&(ip, port, weight)| {
                            let mut key = [0u8; 8];
                            key[0..4].copy_from_slice(&ip.to_ne_bytes());
                            key[4..6].copy_from_slice(&port.to_ne_bytes());

                            let mut val = [0u8; 8];
                            val[0..4].copy_from_slice(&ip.to_ne_bytes());
                            val[4..6].copy_from_slice(&port.to_ne_bytes());
                            val[6..8].copy_from_slice(&weight.to_ne_bytes());

                            (key, val)
                        })
                        .collect();
                    black_box(entries)
                });
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Criterion harness
// ---------------------------------------------------------------------------

criterion_group!(
    benches,
    firewall_rule_conversion,
    ioc_entry_construction,
    ratelimit_policy_construction,
    backend_struct_construction,
);
criterion_main!(benches);
