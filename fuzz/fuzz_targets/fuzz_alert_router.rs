#![no_main]

use std::time::Duration;

use libfuzzer_sys::fuzz_target;

use domain::alert::engine::AlertRouter;
use domain::alert::entity::{Alert, AlertDestination, AlertRoute};
use domain::common::entity::{DomainMode, RuleId, Severity};

// Fuzz the AlertRouter: dedup, throttle, route matching, and reload.
//
// Layout:
//   [0]    = number of routes (1–6)
//   [1]    = dedup_window_secs (0–255)
//   [2]    = throttle_max (1–255)
//   [3]    = selector (0=process, 1=reload+process)
//   rest   = consumed in 16-byte chunks as alerts
fuzz_target!(|data: &[u8]| {
    if data.len() < 20 {
        return;
    }

    let num_routes = ((data[0] as usize) % 6) + 1;
    let dedup_secs = data[1] as u64;
    let throttle_max = (data[2] as usize).max(1);
    let selector = data[3] % 2;
    let mut cursor = 4;

    // Build routes from fuzz data
    let mut routes = Vec::new();
    for i in 0..num_routes {
        if cursor >= data.len() {
            break;
        }
        let byte = data[cursor];
        cursor += 1;

        let min_severity = Severity::from_u8(byte % 4);
        let destination = match (byte >> 2) % 3 {
            0 => AlertDestination::Log,
            1 => AlertDestination::Email {
                to: "test@example.com".to_string(),
            },
            _ => AlertDestination::Webhook {
                url: "https://hooks.example.com/alert".to_string(),
            },
        };
        let event_types = if byte & 0x20 != 0 {
            let types: Vec<String> = ["ids", "firewall", "dlp", "threatintel"]
                .iter()
                .enumerate()
                .filter(|(j, _)| byte & (1 << (j + 4)) != 0)
                .map(|(_, t)| t.to_string())
                .collect();
            if types.is_empty() {
                None
            } else {
                Some(types)
            }
        } else {
            None
        };

        routes.push(AlertRoute {
            name: format!("route-{i}"),
            destination,
            min_severity,
            event_types,
        });
    }

    let mut router = AlertRouter::new(
        routes.clone(),
        Duration::from_secs(dedup_secs),
        Duration::from_secs(300),
        throttle_max,
    );

    // Parse and process alerts
    let components = ["ids", "firewall", "dlp", "threatintel", "ips", "ratelimit"];
    while cursor + 16 <= data.len() {
        let chunk = &data[cursor..cursor + 16];
        cursor += 16;

        let severity = Severity::from_u8(chunk[0] % 4);
        let component = components[(chunk[1] as usize) % components.len()];
        let rule_id = format!("fuzz-{}-{}", component, chunk[2]);

        let alert = Alert {
            id: format!("alert-{}", u32::from_le_bytes([chunk[3], chunk[4], chunk[5], chunk[6]])),
            timestamp_ns: u64::from_le_bytes([
                chunk[7], chunk[8], chunk[9], chunk[10], chunk[11], chunk[12], chunk[13], chunk[14],
            ]),
            component: component.to_string(),
            severity,
            rule_id: RuleId(rule_id),
            action: if chunk[15] & 1 != 0 {
                DomainMode::Block
            } else {
                DomainMode::Alert
            },
            src_addr: [
                u32::from_le_bytes([chunk[3], chunk[4], chunk[5], chunk[6]]),
                0,
                0,
                0,
            ],
            dst_addr: [
                u32::from_le_bytes([chunk[7], chunk[8], chunk[9], chunk[10]]),
                0,
                0,
                0,
            ],
            src_port: u16::from_le_bytes([chunk[11], chunk[12]]),
            dst_port: u16::from_le_bytes([chunk[13], chunk[14]]),
            protocol: chunk[15],
            is_ipv6: false,
            message: String::new(),
            false_positive: false,
            src_domain: None,
            dst_domain: None,
            src_domain_score: None,
            dst_domain_score: None,
        };

        let _ = router.process_alert(&alert);
    }

    // Sub-target 1: reload routes mid-stream
    if selector == 1 {
        let new_routes: Vec<AlertRoute> = routes
            .into_iter()
            .map(|mut r| {
                r.min_severity = Severity::Low;
                r
            })
            .collect();
        router.reload_routes(new_routes);

        // Process one more alert after reload
        let alert = Alert {
            id: "reload-test".to_string(),
            timestamp_ns: 999_999_999,
            component: "ids".to_string(),
            severity: Severity::Critical,
            rule_id: RuleId("reload-rule".to_string()),
            action: DomainMode::Alert,
            src_addr: [0xFFFF_FFFF, 0, 0, 0],
            dst_addr: [0x0100_0001, 0, 0, 0],
            src_port: 65535,
            dst_port: 443,
            protocol: 6,
            is_ipv6: false,
            message: String::new(),
            false_positive: false,
            src_domain: None,
            dst_domain: None,
            src_domain_score: None,
            dst_domain_score: None,
        };
        let _ = router.process_alert(&alert);
    }
});
