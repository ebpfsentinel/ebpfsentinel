#![no_main]

use libfuzzer_sys::fuzz_target;

use domain::common::entity::RuleId;
use domain::firewall::entity::IpNetwork;
use domain::ratelimit::engine::RateLimitEngine;
use domain::ratelimit::entity::{
    RateLimitAction, RateLimitAlgorithm, RateLimitPolicy, RateLimitScope,
};

// Fuzz the RateLimitEngine with random policies: add, remove, reload.
//
// Layout:
//   [0] = selector (0=add+remove, 1=reload, 2=mixed operations)
//   rest = consumed in 20-byte chunks per policy
fuzz_target!(|data: &[u8]| {
    if data.len() < 22 {
        return;
    }

    let selector = data[0] % 3;
    let mut cursor = 1;
    let mut policies = Vec::new();

    // Parse policies from fuzz data
    while cursor + 20 <= data.len() && policies.len() < 16 {
        let chunk = &data[cursor..cursor + 20];
        cursor += 20;

        let rate = u64::from_le_bytes([
            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
        ]);
        let burst = u64::from_le_bytes([
            chunk[8], chunk[9], chunk[10], chunk[11], chunk[12], chunk[13], chunk[14], chunk[15],
        ]);

        let scope = if chunk[16] & 1 != 0 {
            RateLimitScope::Global
        } else {
            RateLimitScope::SourceIp
        };

        let action = if chunk[16] & 2 != 0 {
            RateLimitAction::Pass
        } else {
            RateLimitAction::Drop
        };

        let algorithm = match chunk[17] % 4 {
            0 => RateLimitAlgorithm::TokenBucket,
            1 => RateLimitAlgorithm::FixedWindow,
            2 => RateLimitAlgorithm::SlidingWindow,
            _ => RateLimitAlgorithm::LeakyBucket,
        };

        let src_ip = if chunk[18] & 1 != 0 {
            Some(IpNetwork::V4 {
                addr: u32::from_le_bytes([chunk[18], chunk[19], chunk[17], chunk[16]]),
                prefix_len: chunk[19] % 33,
            })
        } else {
            None
        };

        let id = format!("rl-{}", policies.len());
        let policy = RateLimitPolicy {
            id: RuleId(id),
            scope,
            rate,
            burst,
            action,
            src_ip,
            enabled: chunk[18] & 2 != 0,
            algorithm,
        };
        policies.push(policy);
    }

    let mut engine = RateLimitEngine::new();

    match selector {
        // Sub-target 0: add then remove
        0 => {
            for policy in &policies {
                let _ = engine.add_policy(policy.clone());
            }
            let _ = engine.policy_count();
            for policy in &policies {
                let _ = engine.remove_policy(&policy.id);
            }
        }
        // Sub-target 1: reload
        1 => {
            let _ = engine.reload(policies.clone());
            let _ = engine.policy_count();
            // Reload again with empty
            let _ = engine.reload(vec![]);
        }
        // Sub-target 2: mixed add/reload
        _ => {
            let mid = policies.len() / 2;
            for policy in &policies[..mid] {
                let _ = engine.add_policy(policy.clone());
            }
            let _ = engine.reload(policies[mid..].to_vec());
            let _ = engine.policy_count();
            // Exercise eBPF conversion on valid policies
            for policy in engine.policies() {
                let _ = policy.to_ebpf_key();
                let _ = policy.to_ebpf_config();
            }
        }
    }
});
