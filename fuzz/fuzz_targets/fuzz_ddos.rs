#![no_main]

use libfuzzer_sys::fuzz_target;

use domain::common::entity::RuleId;
use domain::ddos::engine::DdosEngine;
use domain::ddos::entity::{
    DdosAttackType, DdosEvent, DdosMitigationAction, DdosPolicy,
};

// Fuzz the DdosEngine with random policies and events: add/remove policies,
// process events, tick state machine, exercise lifecycle transitions.
//
// Layout:
//   [0] = selector (0=policy CRUD, 1=event processing, 2=mixed lifecycle)
//   rest = consumed in chunks per operation
fuzz_target!(|data: &[u8]| {
    if data.len() < 18 {
        return;
    }

    let selector = data[0] % 3;
    let mut cursor = 1;

    // Parse policies from fuzz data (12 bytes per policy)
    let mut policies = Vec::new();
    while cursor + 12 <= data.len() && policies.len() < 16 {
        let chunk = &data[cursor..cursor + 12];
        cursor += 12;

        let attack_type = match chunk[0] % 7 {
            0 => DdosAttackType::SynFlood,
            1 => DdosAttackType::UdpAmplification,
            2 => DdosAttackType::IcmpFlood,
            3 => DdosAttackType::RstFlood,
            4 => DdosAttackType::FinFlood,
            5 => DdosAttackType::AckFlood,
            _ => DdosAttackType::Volumetric,
        };

        let threshold = u64::from_le_bytes([
            chunk[1], chunk[2], chunk[3], chunk[4],
            chunk[5], chunk[6], chunk[7], chunk[8],
        ]);

        let action = match chunk[9] % 3 {
            0 => DdosMitigationAction::Alert,
            1 => DdosMitigationAction::Throttle,
            _ => DdosMitigationAction::Block,
        };

        let auto_block_secs = u64::from(u16::from_le_bytes([chunk[10], chunk[11]]));

        let id = format!("ddos-fuzz-{}", policies.len());
        let policy = DdosPolicy {
            id: RuleId(id),
            attack_type,
            detection_threshold_pps: threshold,
            mitigation_action: action,
            auto_block_duration_secs: auto_block_secs,
            enabled: chunk[9] & 0x80 == 0,
        };
        policies.push(policy);
    }

    let mut engine = DdosEngine::new();

    match selector {
        // Sub-target 0: policy CRUD
        0 => {
            for policy in &policies {
                let _ = engine.add_policy(policy.clone());
            }
            let _ = engine.policy_count();
            let _ = engine.policies();
            for policy in &policies {
                let _ = engine.remove_policy(&policy.id);
            }
            // Reload
            let _ = engine.reload(policies);
        }
        // Sub-target 1: event processing with state transitions
        1 => {
            // Add all valid policies first
            for policy in &policies {
                let _ = engine.add_policy(policy.clone());
            }

            // Process events from remaining data
            let mut ts: u64 = 1_000_000_000;
            let mut event_cursor = cursor;
            while event_cursor + 4 <= data.len() {
                let eb = &data[event_cursor..event_cursor + 4];
                event_cursor += 4;

                let attack_type = match eb[0] % 7 {
                    0 => DdosAttackType::SynFlood,
                    1 => DdosAttackType::UdpAmplification,
                    2 => DdosAttackType::IcmpFlood,
                    3 => DdosAttackType::RstFlood,
                    4 => DdosAttackType::FinFlood,
                    5 => DdosAttackType::AckFlood,
                    _ => DdosAttackType::Volumetric,
                };

                // Advance timestamp by fuzzed delta (avoid overflow)
                let delta = u64::from(u16::from_le_bytes([eb[2], eb[3]])) * 1_000_000;
                ts = ts.saturating_add(delta);

                let event = DdosEvent {
                    timestamp_ns: ts,
                    attack_type,
                    src_addr: [u32::from(eb[1]), 0, 0, 0],
                    dst_addr: [0x0A000001, 0, 0, 0],
                    src_port: 12345,
                    dst_port: 80,
                    protocol: 6,
                    is_ipv6: eb[1] & 1 != 0,
                };
                let _ = engine.process_event(&event);
            }

            let _ = engine.active_attack_count();
            let _ = engine.active_attacks();
            let _ = engine.total_mitigated();
            let _ = engine.attack_history(10);
        }
        // Sub-target 2: mixed lifecycle (policies + events + ticks)
        _ => {
            let mid = policies.len() / 2;
            for policy in &policies[..mid] {
                let _ = engine.add_policy(policy.clone());
            }
            let _ = engine.reload(policies[mid..].to_vec());

            // Process events and tick periodically
            let mut ts: u64 = 1_000_000_000;
            let mut event_cursor = cursor;
            let mut tick_counter = 0u32;
            while event_cursor + 2 <= data.len() {
                let eb = &data[event_cursor..event_cursor + 2];
                event_cursor += 2;

                let attack_type = match eb[0] % 7 {
                    0 => DdosAttackType::SynFlood,
                    1 => DdosAttackType::UdpAmplification,
                    2 => DdosAttackType::IcmpFlood,
                    3 => DdosAttackType::RstFlood,
                    4 => DdosAttackType::FinFlood,
                    5 => DdosAttackType::AckFlood,
                    _ => DdosAttackType::Volumetric,
                };

                ts = ts.saturating_add(u64::from(eb[1]) * 10_000_000);

                let event = DdosEvent {
                    timestamp_ns: ts,
                    attack_type,
                    src_addr: [0xC0A80001, 0, 0, 0],
                    dst_addr: [0x0A000001, 0, 0, 0],
                    src_port: 12345,
                    dst_port: 80,
                    protocol: 6,
                    is_ipv6: false,
                };
                let _ = engine.process_event(&event);

                tick_counter += 1;
                if tick_counter % 4 == 0 {
                    engine.tick();
                }
            }

            let _ = engine.active_attack_count();
            let _ = engine.total_mitigated();
            let _ = engine.attack_history(50);
        }
    }
});
