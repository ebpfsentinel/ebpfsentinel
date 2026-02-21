#![no_main]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use libfuzzer_sys::fuzz_target;

use domain::common::entity::{DomainMode, Protocol, RuleId, Severity};
use domain::ids::engine::IdsEngine;
use domain::ids::entity::{IdsRule, ThresholdConfig, ThresholdType, TrackBy};
use domain::ips::engine::IpsEngine;
use domain::ips::entity::{IpsPolicy, WhitelistEntry};
use ebpf_common::event::{PacketEvent, EVENT_TYPE_IDS};

// Interpret fuzz bytes as structured IDS/IPS inputs.
//
// Layout (minimum 20 bytes):
//   [0]      — sub-target selector
//   [1..5]   — src_ip (u32 BE)
//   [5..9]   — dst_ip (u32 BE)
//   [9..11]  — src_port (u16 BE)
//   [11..13] — dst_port (u16 BE)
//   [13]     — protocol
//   [14]     — rule_id (index)
//   [15..19] — threshold params (type, count, track_by, window_secs)
//   [19..]   — text payload (regex pattern, whitelist string, etc.)
fuzz_target!(|data: &[u8]| {
    if data.len() < 20 {
        return;
    }

    let selector = data[0] % 4;
    let src_ip = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
    let dst_ip = u32::from_be_bytes([data[5], data[6], data[7], data[8]]);
    let src_port = u16::from_be_bytes([data[9], data[10]]);
    let dst_port = u16::from_be_bytes([data[11], data[12]]);
    let protocol = data[13];
    let rule_id_idx = data[14] as u32;
    let thresh_type = data[15];
    let thresh_count = u32::from(data[16]).max(1);
    let track_by_byte = data[17];
    let window_secs = u64::from(data[18]);
    let text = &data[19..];

    match selector {
        // ── IDS: rule loading with fuzzed regex patterns ────────────
        0 => {
            if let Ok(pattern) = std::str::from_utf8(text) {
                let mut engine = IdsEngine::new();
                let rule = IdsRule {
                    id: RuleId("fuzz-001".to_string()),
                    description: String::new(),
                    severity: Severity::Medium,
                    mode: DomainMode::Alert,
                    protocol: Protocol::Tcp,
                    dst_port: if dst_port == 0 { None } else { Some(dst_port) },
                    pattern: pattern.to_string(),
                    enabled: true,
                    threshold: None,
                    domain_pattern: None,
                    domain_match_mode: None,
                };
                // Exercise regex compilation with DoS limits.
                let _ = engine.add_rule(rule);
            }
        }

        // ── IDS: evaluate_event + threshold detection ───────────────
        1 => {
            let mut engine = IdsEngine::new();
            // Load a few rules so evaluate_event has something to match.
            for i in 0..3u8 {
                let _ = engine.add_rule(IdsRule {
                    id: RuleId(format!("fuzz-{i:03}")),
                    description: String::new(),
                    severity: Severity::Medium,
                    mode: DomainMode::Alert,
                    protocol: Protocol::Tcp,
                    dst_port: Some(22),
                    pattern: String::new(),
                    enabled: i % 2 == 0,
                    threshold: None,
                    domain_pattern: None,
                    domain_match_mode: None,
                });
            }

            let event = PacketEvent {
                timestamp_ns: 0,
                src_addr: [src_ip, 0, 0, 0],
                dst_addr: [dst_ip, 0, 0, 0],
                src_port,
                dst_port,
                protocol,
                event_type: EVENT_TYPE_IDS,
                action: 0,
                flags: 0,
                rule_id: rule_id_idx,
                vlan_id: 0,
                cpu_id: 0,
                socket_cookie: 0,
            };

            // Exercise event evaluation (index lookup + sampling).
            if let Some((_, rule)) = engine.evaluate_event(&event) {
                // Exercise threshold detection.
                let threshold = ThresholdConfig {
                    threshold_type: match thresh_type % 3 {
                        0 => ThresholdType::Limit,
                        1 => ThresholdType::Threshold,
                        _ => ThresholdType::Both,
                    },
                    count: thresh_count,
                    window_secs,
                    track_by: match track_by_byte % 3 {
                        0 => TrackBy::SrcIp,
                        1 => TrackBy::DstIp,
                        _ => TrackBy::Both,
                    },
                };
                let rule_id = rule.id.clone();
                engine.check_threshold(&rule_id, &threshold, src_ip, dst_ip);
            }
        }

        // ── IPS: whitelist parsing from fuzzed strings ──────────────
        2 => {
            if let Ok(s) = std::str::from_utf8(text) {
                let _ = s.parse::<WhitelistEntry>();
            }

            // Also exercise WhitelistEntry::matches with fuzzed IPs.
            let ipv4 = IpAddr::V4(Ipv4Addr::from(src_ip));
            let ipv6_bytes: [u8; 16] = [
                data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
                data[9], data[10], data[11], data[12], data[13], data[14], data[15], data[16],
            ];
            let ipv6 = IpAddr::V6(Ipv6Addr::from(ipv6_bytes));

            if let Ok(entry) = WhitelistEntry::new(ipv4, Some(data[17] % 33)) {
                let _ = entry.matches(ipv4);
                let _ = entry.matches(ipv6);
            }
            if let Ok(entry) = WhitelistEntry::new(ipv6, Some(data[18] % 129)) {
                let _ = entry.matches(ipv4);
                let _ = entry.matches(ipv6);
            }
        }

        // ── IPS: detection recording + blacklist lifecycle ──────────
        _ => {
            let policy = IpsPolicy {
                max_blacklist_duration: std::time::Duration::from_secs(window_secs.max(1)),
                auto_blacklist_threshold: thresh_count,
                max_blacklist_size: 100,
            };
            let mut engine = IpsEngine::new(policy);

            let ip = IpAddr::V4(Ipv4Addr::from(src_ip));
            let _ = engine.record_detection(ip);
            let _ = engine.is_blacklisted(ip);

            // Exercise explicit add/remove.
            let ip2 = IpAddr::V4(Ipv4Addr::from(dst_ip));
            let _ = engine.add_to_blacklist(
                ip2,
                "fuzz".to_string(),
                false,
                std::time::Duration::from_secs(60),
            );
            let _ = engine.is_blacklisted(ip2);
            let _ = engine.remove_from_blacklist(&ip2);

            // Exercise cleanup.
            let _ = engine.cleanup_expired();
        }
    }
});
