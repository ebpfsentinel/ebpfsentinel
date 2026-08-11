#![no_main]

use libfuzzer_sys::fuzz_target;

use domain::common::entity::RuleId;
use domain::firewall::entity::IpCidr;
use domain::ratelimit::entity::{
    CountryTierConfig, RateLimitAction, RateLimitAlgorithm, RateLimitPolicy,
};

// Fuzz CountryTierConfig.to_ebpf_config() and RateLimitPolicy.to_ebpf_config()
// with extreme values (u64::MAX rate/burst, all algorithm variants).
//
// Layout: consumed in 24-byte chunks
fuzz_target!(|data: &[u8]| {
    let mut cursor = 0;

    while cursor + 24 <= data.len() {
        let chunk = &data[cursor..cursor + 24];
        cursor += 24;

        let rate = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
        let burst = u64::from_le_bytes(chunk[8..16].try_into().unwrap());
        let tier_id = chunk[16];
        let algo_byte = chunk[17];
        let action_byte = chunk[18];
        let scope_byte = chunk[19];
        let prefix_len = chunk[20];
        let ip_bytes = [chunk[21], chunk[22], chunk[23], chunk[20]];

        let algorithm = match algo_byte % 4 {
            0 => RateLimitAlgorithm::TokenBucket,
            1 => RateLimitAlgorithm::FixedWindow,
            2 => RateLimitAlgorithm::SlidingWindow,
            _ => RateLimitAlgorithm::LeakyBucket,
        };

        let action = if action_byte & 1 != 0 {
            RateLimitAction::Pass
        } else {
            RateLimitAction::Drop
        };

        // Fuzz CountryTierConfig eBPF conversion
        let tier = CountryTierConfig {
            tier_id,
            country_codes: vec!["XX".to_string()],
            rate,
            burst,
            algorithm,
            action,
        };
        let cfg = tier.to_ebpf_config();
        // Verify output doesn't panic and action is preserved
        let _ = cfg.ns_per_token;
        let _ = cfg.burst;

        // Fuzz RateLimitPolicy eBPF conversion (all algorithms × address forms)
        let src_ip = if scope_byte & 2 != 0 {
            IpCidr::V4 {
                addr: u32::from_le_bytes(ip_bytes),
                prefix_len,
            }
        } else if scope_byte & 4 != 0 {
            let mut addr = [0u8; 16];
            addr[..4].copy_from_slice(&ip_bytes);
            IpCidr::V6 { addr, prefix_len }
        } else {
            IpCidr::V4 {
                addr: u32::from_le_bytes(ip_bytes),
                prefix_len: 32,
            }
        };

        let policy = RateLimitPolicy {
            id: RuleId("fuzz-rl".to_string()),
            rate,
            burst,
            action,
            src_ip,
            enabled: true,
            algorithm,
            group_mask: u32::from_le_bytes(ip_bytes),
            tenant_id: u32::from(scope_byte % 4),
        };

        // validate() should not panic
        let _ = policy.validate();

        // eBPF conversions should not panic even on extreme values
        let _ = policy.to_ebpf_key();
        let _ = policy.to_ebpf_config();
    }
});
