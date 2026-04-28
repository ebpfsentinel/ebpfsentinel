#![no_main]
//! Fuzz the SSE alerts-stream filter.
//!
//! Drives `AlertFilter::compile` with arbitrary attacker-controlled query
//! parameters and `AlertFilter::matches` against a synthetic alert. Must
//! never panic — `compile` returns `Result`, `matches` returns `bool`.
//! Any panic is a crash worth reproducing.

use libfuzzer_sys::fuzz_target;

use domain::alert::entity::Alert;
use domain::alert::filter::AlertFilter;
use domain::alert::mitre::MitreAttackInfo;
use domain::common::entity::{DomainMode, RuleId, Severity};

/// Slice up to `n` UTF-8 bytes off `data`, returning the borrowed prefix
/// and the remaining tail. Returns `None` if `data` doesn't yield a valid
/// UTF-8 chunk at this length.
fn split_utf8<'a>(data: &'a [u8], n: usize) -> Option<(&'a str, &'a [u8])> {
    if data.len() < n {
        return None;
    }
    let (head, tail) = data.split_at(n);
    std::str::from_utf8(head).ok().map(|s| (s, tail))
}

fn sample_alert(seed: u8) -> Alert {
    let component = match seed % 4 {
        0 => "ids",
        1 => "dlp",
        2 => "ddos",
        _ => "threatintel",
    };
    let severity = match (seed >> 2) & 0b11 {
        0 => Severity::Low,
        1 => Severity::Medium,
        2 => Severity::High,
        _ => Severity::Critical,
    };
    let mitre_attack = if seed & 0x80 == 0 {
        Some(MitreAttackInfo {
            technique_id: "T1071".to_string(),
            technique_name: "Application Layer Protocol".to_string(),
            tactic: match (seed >> 4) & 0b11 {
                0 => "command-and-control",
                1 => "exfiltration",
                2 => "impact",
                _ => "Discovery",
            }
            .to_string(),
        })
    } else {
        None
    };
    Alert {
        id: format!("fuzz-{seed}"),
        timestamp_ns: u64::from(seed),
        component: component.to_string(),
        severity,
        rule_id: RuleId(String::new()),
        action: DomainMode::Alert,
        src_addr: [0; 4],
        dst_addr: [0; 4],
        src_port: 0,
        dst_port: 0,
        protocol: 0,
        is_ipv6: false,
        message: String::new(),
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
        mitre_attack,
        ja4_fingerprint: None,
        ml_anomaly_score: None,
        ml_top_feature: None,
        ml_engine: None,
        ai_provider: None,
        ai_sni: None,
        ai_bytes_sent: None,
        ai_exfil_type: None,
        tls_threat_category: None,
        tls_pqc_status: None,
        container: None,
        container_metadata: None,
    }
}

fuzz_target!(|data: &[u8]| {
    // Reject pathologically large inputs to keep the fuzz iteration fast.
    if data.len() > 4096 {
        return;
    }
    if data.is_empty() {
        return;
    }

    // Layout: [seed:1][sev_len:1][sev:bytes][comp_len:1][comp:bytes][tact_len:1][tact:bytes]
    let seed = data[0];
    let mut cursor = &data[1..];

    let severity_min = match cursor.split_first() {
        Some((&n, rest)) => {
            cursor = rest;
            split_utf8(cursor, usize::from(n)).map(|(s, tail)| {
                cursor = tail;
                s.to_owned()
            })
        }
        None => None,
    };

    let component = match cursor.split_first() {
        Some((&n, rest)) => {
            cursor = rest;
            split_utf8(cursor, usize::from(n)).map(|(s, tail)| {
                cursor = tail;
                s.to_owned()
            })
        }
        None => None,
    };

    let mitre_tactic = match cursor.split_first() {
        Some((&n, rest)) => split_utf8(rest, usize::from(n)).map(|(s, _)| s.to_owned()),
        None => None,
    };

    let alert = sample_alert(seed);

    if let Ok(filter) = AlertFilter::compile(severity_min.as_deref(), component, mitre_tactic) {
        let _ = filter.matches(&alert);
    }
});
