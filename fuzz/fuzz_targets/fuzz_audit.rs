#![no_main]

use libfuzzer_sys::fuzz_target;

use domain::audit::entity::{AuditAction, AuditComponent, AuditEntry};
use domain::audit::query::AuditQuery;
use domain::audit::rule_change::{ChangeActor, RuleChangeEntry};

// Fuzz the audit subsystem: parse component names, create entries, query matching,
// rule change records.
//
// Layout:
//   [0]    = selector (0=parse+entry, 1=query matching, 2=rule changes)
//   rest   = consumed in chunks per operation
fuzz_target!(|data: &[u8]| {
    if data.len() < 20 {
        return;
    }

    let selector = data[0] % 3;
    let mut cursor = 1;

    match selector {
        // Sub-target 0: parse component names + create security decisions
        0 => {
            // Parse component names from fuzz bytes
            while cursor + 16 <= data.len() {
                let chunk = &data[cursor..cursor + 16];
                cursor += 16;

                // Parse component from string-like byte
                let name_len = (chunk[0] as usize % 10) + 1;
                let name_end = (1 + name_len).min(chunk.len());
                let name = String::from_utf8_lossy(&chunk[1..name_end]);
                let component = AuditComponent::parse_name(&name);
                let _ = component.as_str();

                let action = match chunk[11] % 10 {
                    0 => AuditAction::Pass,
                    1 => AuditAction::Drop,
                    2 => AuditAction::Alert,
                    3 => AuditAction::RateExceeded,
                    4 => AuditAction::ConfigChanged,
                    5 => AuditAction::RuleAdded,
                    6 => AuditAction::RuleRemoved,
                    7 => AuditAction::RuleUpdated,
                    8 => AuditAction::PolicyViolation,
                    _ => AuditAction::FalsePositive,
                };
                let _ = action.as_str();

                let ts = u64::from_le_bytes([
                    chunk[3], chunk[4], chunk[5], chunk[6],
                    chunk[7], chunk[8], chunk[9], chunk[10],
                ]);

                let src = [u32::from(chunk[12]), 0, 0, 0];
                let dst = [u32::from(chunk[13]), 0, 0, 0];

                let entry = AuditEntry::security_decision(
                    component,
                    action,
                    ts,
                    src,
                    dst,
                    chunk[14] & 1 != 0,
                    u16::from(chunk[14]),
                    u16::from(chunk[15]),
                    chunk[12] % 3 + 6,
                    "fuzz-rule",
                    &name,
                );
                let _ = entry.src_ip();
                let _ = entry.dst_ip();
            }
        }
        // Sub-target 1: create entries and query matching
        1 => {
            let mut entries = Vec::new();
            while cursor + 12 <= data.len() && entries.len() < 32 {
                let chunk = &data[cursor..cursor + 12];
                cursor += 12;

                let component = match chunk[0] % 9 {
                    0 => AuditComponent::Firewall,
                    1 => AuditComponent::Ids,
                    2 => AuditComponent::Ips,
                    3 => AuditComponent::L7,
                    4 => AuditComponent::Ratelimit,
                    5 => AuditComponent::Threatintel,
                    6 => AuditComponent::Dlp,
                    7 => AuditComponent::Ddos,
                    _ => AuditComponent::Config,
                };

                let action = match chunk[1] % 4 {
                    0 => AuditAction::Pass,
                    1 => AuditAction::Drop,
                    2 => AuditAction::Alert,
                    _ => AuditAction::RateExceeded,
                };

                let ts = u64::from_le_bytes([
                    chunk[2], chunk[3], chunk[4], chunk[5],
                    chunk[6], chunk[7], chunk[8], chunk[9],
                ]);

                let entry = AuditEntry::security_decision(
                    component,
                    action,
                    ts,
                    [u32::from(chunk[10]), 0, 0, 0],
                    [u32::from(chunk[11]), 0, 0, 0],
                    false,
                    80,
                    443,
                    6,
                    &format!("rule-{}", chunk[10]),
                    "fuzz detail",
                );
                entries.push(entry);
            }

            // Build query from remaining bytes
            if cursor + 4 <= data.len() {
                let qb = &data[cursor..cursor + 4];
                let query = AuditQuery {
                    from_ns: if qb[0] & 1 != 0 { Some(u64::from(qb[1]) * 1_000_000) } else { None },
                    to_ns: if qb[0] & 2 != 0 { Some(u64::from(qb[2]) * 1_000_000_000) } else { None },
                    component: if qb[0] & 4 != 0 { Some(AuditComponent::Firewall) } else { None },
                    action: if qb[0] & 8 != 0 { Some(AuditAction::Drop) } else { None },
                    rule_id: if qb[0] & 16 != 0 { Some(format!("rule-{}", qb[3])) } else { None },
                    limit: (qb[3] as usize % 100) + 1,
                    offset: 0,
                };
                for entry in &entries {
                    let _ = query.matches(entry);
                }
            }
        }
        // Sub-target 2: rule change records
        _ => {
            while cursor + 8 <= data.len() {
                let chunk = &data[cursor..cursor + 8];
                cursor += 8;

                let component = match chunk[0] % 9 {
                    0 => AuditComponent::Firewall,
                    1 => AuditComponent::Ids,
                    2 => AuditComponent::Ips,
                    3 => AuditComponent::L7,
                    4 => AuditComponent::Ratelimit,
                    5 => AuditComponent::Threatintel,
                    6 => AuditComponent::Dlp,
                    7 => AuditComponent::Ddos,
                    _ => AuditComponent::Config,
                };

                let action = match chunk[1] % 3 {
                    0 => AuditAction::RuleAdded,
                    1 => AuditAction::RuleRemoved,
                    _ => AuditAction::RuleUpdated,
                };

                let actor = match chunk[2] % 3 {
                    0 => ChangeActor::Api,
                    1 => ChangeActor::ConfigReload,
                    _ => ChangeActor::Cli,
                };

                let version = u64::from(u16::from_le_bytes([chunk[3], chunk[4]]));

                let before = if chunk[5] & 1 != 0 {
                    Some(r#"{"old": true}"#.to_string())
                } else {
                    None
                };
                let after = if chunk[5] & 2 != 0 {
                    Some(r#"{"new": true}"#.to_string())
                } else {
                    None
                };

                let entry = RuleChangeEntry::new(
                    format!("rule-{}", chunk[6]),
                    version,
                    component,
                    action,
                    actor,
                    before,
                    after,
                );
                let _ = entry.actor.as_str();
            }

            // Also exercise config_change factory
            let _ = AuditEntry::config_change(AuditAction::ConfigChanged, "fuzz reload");
        }
    }
});
