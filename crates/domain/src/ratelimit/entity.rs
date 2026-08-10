use serde::{Deserialize, Serialize};

use crate::common::entity::RuleId;
use crate::firewall::entity::IpCidr;
use ebpf_common::ratelimit::{
    ALGO_FIXED_WINDOW, ALGO_LEAKY_BUCKET, ALGO_SLIDING_WINDOW, ALGO_TOKEN_BUCKET,
    RATELIMIT_ACTION_DROP, RATELIMIT_ACTION_PASS, RateLimitConfig as EbpfConfig,
    RateLimitKey as EbpfKey,
};

use super::error::RateLimitError;

/// Action when rate limit is exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RateLimitAction {
    /// Drop the packet (`XDP_DROP`).
    Drop,
    /// Pass the packet but mark as throttled (for alerting).
    Pass,
}

/// Rate limiting algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitAlgorithm {
    /// Token bucket: smooth rate limiting with burst allowance.
    #[default]
    TokenBucket,
    /// Fixed window: hard counter reset every 1-second window.
    FixedWindow,
    /// Sliding window: 8 sub-slots for smoother window-based limiting.
    SlidingWindow,
    /// Leaky bucket: constant drain rate with capacity limit.
    LeakyBucket,
}

/// A rate limit policy: one source host, one bucket.
///
/// The eBPF config map is keyed by the source address, so a policy names
/// exactly one host. Everything the policies do not name falls back to the
/// section defaults, which give every unnamed source its own bucket. Whole
/// countries are covered by [`CountryTierConfig`], which resolves to CIDRs
/// and matches with an LPM trie.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitPolicy {
    pub id: RuleId,
    /// Tokens per second (refill rate).
    pub rate: u64,
    /// Maximum tokens (bucket size). Must be >= 1.
    pub burst: u64,
    /// Action when rate is exceeded.
    pub action: RateLimitAction,
    /// Source host this policy limits. Must be an IPv4 `/32`: the config map
    /// is an exact-match hash on a 32-bit address, so nothing else can match.
    pub src_ip: IpCidr,
    pub enabled: bool,
    /// Rate limiting algorithm to use.
    pub algorithm: RateLimitAlgorithm,
    /// Interface group bitmask for multi-interface rule scoping.
    /// 0 = floating (applies to all interfaces). Bit 31 = invert.
    #[serde(default)]
    pub group_mask: u32,
    /// Tenant this policy belongs to. 0 = global: the policy applies to every
    /// tenant, which is the only behaviour a standalone agent can produce.
    /// A non-zero value keys the policy under that tenant, and the data plane
    /// falls back to the global entry for traffic it resolves elsewhere.
    #[serde(default)]
    pub tenant_id: u32,
}

impl RateLimitPolicy {
    /// Validate all fields of this policy.
    pub fn validate(&self) -> Result<(), RateLimitError> {
        self.id
            .validate()
            .map_err(|reason| RateLimitError::InvalidPolicy(reason.to_string()))?;

        if self.rate == 0 {
            return Err(RateLimitError::InvalidRate);
        }
        if self.burst == 0 {
            return Err(RateLimitError::InvalidBurst);
        }

        match self.src_ip {
            IpCidr::V4 { addr, prefix_len } => {
                if prefix_len != 32 {
                    return Err(RateLimitError::InvalidPolicy(format!(
                        "source must be a single host, got a /{prefix_len} prefix",
                    )));
                }
                if addr == 0 {
                    return Err(RateLimitError::InvalidPolicy(
                        "source 0.0.0.0 is the entry the section defaults own".to_string(),
                    ));
                }
            }
            IpCidr::V6 { .. } => {
                return Err(RateLimitError::InvalidPolicy(
                    "the per-source config map holds IPv4 addresses only".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Convert to an eBPF map key: the source host this policy limits.
    pub fn to_ebpf_key(&self) -> EbpfKey {
        let src_ip = match self.src_ip {
            IpCidr::V4 { addr, .. } => addr,
            IpCidr::V6 { .. } => 0,
        };
        EbpfKey {
            tenant_id: self.tenant_id,
            src_ip,
        }
    }

    /// Convert to an eBPF map config value.
    /// Field interpretation depends on the selected algorithm.
    pub fn to_ebpf_config(&self) -> EbpfConfig {
        let action = match self.action {
            RateLimitAction::Drop => RATELIMIT_ACTION_DROP,
            RateLimitAction::Pass => RATELIMIT_ACTION_PASS,
        };

        match self.algorithm {
            RateLimitAlgorithm::TokenBucket => {
                let ns_per_token = 1_000_000_000u64.checked_div(self.rate).unwrap_or(0);
                EbpfConfig {
                    ns_per_token,
                    burst: self.burst,
                    action,
                    algorithm: ALGO_TOKEN_BUCKET,
                    _padding: [0; 2],
                    group_mask: self.group_mask,
                    tenant_id: self.tenant_id,
                    _pad2: [0; 4],
                }
            }
            RateLimitAlgorithm::FixedWindow => EbpfConfig {
                ns_per_token: self.rate,
                burst: 0,
                action,
                algorithm: ALGO_FIXED_WINDOW,
                _padding: [0; 2],
                group_mask: self.group_mask,
                tenant_id: self.tenant_id,
                _pad2: [0; 4],
            },
            RateLimitAlgorithm::SlidingWindow => EbpfConfig {
                ns_per_token: self.rate,
                burst: 0,
                action,
                algorithm: ALGO_SLIDING_WINDOW,
                _padding: [0; 2],
                group_mask: self.group_mask,
                tenant_id: self.tenant_id,
                _pad2: [0; 4],
            },
            RateLimitAlgorithm::LeakyBucket => EbpfConfig {
                ns_per_token: self.rate,
                burst: self.burst,
                action,
                algorithm: ALGO_LEAKY_BUCKET,
                _padding: [0; 2],
                group_mask: self.group_mask,
                tenant_id: self.tenant_id,
                _pad2: [0; 4],
            },
        }
    }
}

/// Country-tier rate limit configuration.
///
/// Maps a set of country codes to a tier ID with specific rate limit parameters.
/// Used to load per-country rate limits into eBPF LPM Trie maps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CountryTierConfig {
    /// Tier ID (1-15). 0 is reserved for the default tier.
    pub tier_id: u8,
    /// ISO 3166-1 alpha-2 country codes assigned to this tier.
    pub country_codes: Vec<String>,
    /// Packets per second (rate).
    pub rate: u64,
    /// Maximum burst (bucket size).
    pub burst: u64,
    /// Rate limiting algorithm.
    pub algorithm: RateLimitAlgorithm,
    /// Action when rate exceeded.
    pub action: RateLimitAction,
}

impl CountryTierConfig {
    /// Convert to an eBPF `RateLimitConfig` for the tier config array map.
    pub fn to_ebpf_config(&self) -> EbpfConfig {
        let action = match self.action {
            RateLimitAction::Drop => RATELIMIT_ACTION_DROP,
            RateLimitAction::Pass => RATELIMIT_ACTION_PASS,
        };

        match self.algorithm {
            RateLimitAlgorithm::TokenBucket => {
                let ns_per_token = 1_000_000_000u64.checked_div(self.rate).unwrap_or(0);
                EbpfConfig {
                    ns_per_token,
                    burst: self.burst,
                    action,
                    algorithm: ALGO_TOKEN_BUCKET,
                    _padding: [0; 2],
                    group_mask: 0,
                    tenant_id: 0,
                    _pad2: [0; 4],
                }
            }
            RateLimitAlgorithm::FixedWindow => EbpfConfig {
                ns_per_token: self.rate,
                burst: 0,
                action,
                algorithm: ALGO_FIXED_WINDOW,
                _padding: [0; 2],
                group_mask: 0,
                tenant_id: 0,
                _pad2: [0; 4],
            },
            RateLimitAlgorithm::SlidingWindow => EbpfConfig {
                ns_per_token: self.rate,
                burst: 0,
                action,
                algorithm: ALGO_SLIDING_WINDOW,
                _padding: [0; 2],
                group_mask: 0,
                tenant_id: 0,
                _pad2: [0; 4],
            },
            RateLimitAlgorithm::LeakyBucket => EbpfConfig {
                ns_per_token: self.rate,
                burst: self.burst,
                action,
                algorithm: ALGO_LEAKY_BUCKET,
                _padding: [0; 2],
                group_mask: 0,
                tenant_id: 0,
                _pad2: [0; 4],
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::entity::IpNetwork;

    fn make_policy(id: &str, rate: u64, burst: u64) -> RateLimitPolicy {
        RateLimitPolicy {
            id: RuleId(id.to_string()),
            rate,
            burst,
            action: RateLimitAction::Drop,
            src_ip: IpNetwork::V4 {
                addr: 0xC0A8_0164,
                prefix_len: 32,
            },
            enabled: true,
            algorithm: RateLimitAlgorithm::default(),
            group_mask: 0,
            tenant_id: 0,
        }
    }

    #[test]
    fn validate_ok() {
        assert!(make_policy("rl-001", 1000, 2000).validate().is_ok());
    }

    #[test]
    fn validate_empty_id() {
        assert!(make_policy("", 1000, 2000).validate().is_err());
    }

    #[test]
    fn validate_zero_rate() {
        assert!(make_policy("rl-001", 0, 2000).validate().is_err());
    }

    #[test]
    fn validate_zero_burst() {
        assert!(make_policy("rl-001", 1000, 0).validate().is_err());
    }

    /// A prefix would be silently narrowed to its network address by the
    /// exact-match config map, so it is refused instead.
    #[test]
    fn validate_rejects_a_prefix() {
        let mut policy = make_policy("rl-001", 1000, 2000);
        policy.src_ip = IpNetwork::V4 {
            addr: 0x0A00_0000,
            prefix_len: 8,
        };
        assert!(policy.validate().is_err());
    }

    /// The config map key is a 32-bit address; an IPv6 source cannot be one.
    #[test]
    fn validate_rejects_ipv6() {
        let mut policy = make_policy("rl-001", 1000, 2000);
        policy.src_ip = IpNetwork::V6 {
            addr: [0; 16],
            prefix_len: 128,
        };
        assert!(policy.validate().is_err());
    }

    /// Key 0 is where the section defaults live; a policy claiming it would
    /// replace them for every unnamed source.
    #[test]
    fn validate_rejects_the_default_entry() {
        let mut policy = make_policy("rl-001", 1000, 2000);
        policy.src_ip = IpNetwork::V4 {
            addr: 0,
            prefix_len: 32,
        };
        assert!(policy.validate().is_err());
    }

    #[test]
    fn to_ebpf_key_is_the_source_host() {
        let mut policy = make_policy("rl-001", 1000, 2000);
        policy.src_ip = IpNetwork::V4 {
            addr: 0xC0A8_0101,
            prefix_len: 32,
        };
        let key = policy.to_ebpf_key();
        assert_eq!(key.src_ip, 0xC0A8_0101);
        assert_eq!(key.tenant_id, 0);
    }

    #[test]
    fn ebpf_key_and_config_carry_the_policy_tenant() {
        let mut policy = make_policy("rl-001", 1000, 2000);
        policy.tenant_id = 9;
        assert_eq!(policy.to_ebpf_key().tenant_id, 9);
        assert_eq!(policy.to_ebpf_config().tenant_id, 9);
    }

    #[test]
    fn to_ebpf_config_token_bucket() {
        let policy = make_policy("rl-001", 1000, 2000);
        let cfg = policy.to_ebpf_config();
        assert_eq!(cfg.ns_per_token, 1_000_000); // 1e9 / 1000
        assert_eq!(cfg.burst, 2000);
        assert_eq!(cfg.action, RATELIMIT_ACTION_DROP);
        assert_eq!(cfg.algorithm, ALGO_TOKEN_BUCKET);
    }

    #[test]
    fn to_ebpf_config_pass_action() {
        let mut policy = make_policy("rl-001", 1000, 2000);
        policy.action = RateLimitAction::Pass;
        let cfg = policy.to_ebpf_config();
        assert_eq!(cfg.action, RATELIMIT_ACTION_PASS);
    }

    #[test]
    fn to_ebpf_config_ns_per_token_precision() {
        let policy = make_policy("rl-001", 100, 200);
        let cfg = policy.to_ebpf_config();
        assert_eq!(cfg.ns_per_token, 10_000_000); // 1e9 / 100
    }

    #[test]
    fn to_ebpf_config_single_token_per_second() {
        let policy = make_policy("rl-001", 1, 1);
        let cfg = policy.to_ebpf_config();
        assert_eq!(cfg.ns_per_token, 1_000_000_000);
        assert_eq!(cfg.burst, 1);
    }

    #[test]
    fn to_ebpf_config_fixed_window() {
        let mut policy = make_policy("rl-001", 500, 1);
        policy.algorithm = RateLimitAlgorithm::FixedWindow;
        let cfg = policy.to_ebpf_config();
        assert_eq!(cfg.ns_per_token, 500); // rate stored directly
        assert_eq!(cfg.burst, 0);
        assert_eq!(cfg.algorithm, ALGO_FIXED_WINDOW);
    }

    #[test]
    fn to_ebpf_config_sliding_window() {
        let mut policy = make_policy("rl-001", 1000, 1);
        policy.algorithm = RateLimitAlgorithm::SlidingWindow;
        let cfg = policy.to_ebpf_config();
        assert_eq!(cfg.ns_per_token, 1000); // max packets per window
        assert_eq!(cfg.burst, 0);
        assert_eq!(cfg.algorithm, ALGO_SLIDING_WINDOW);
    }

    #[test]
    fn to_ebpf_config_leaky_bucket() {
        let mut policy = make_policy("rl-001", 100, 500);
        policy.algorithm = RateLimitAlgorithm::LeakyBucket;
        let cfg = policy.to_ebpf_config();
        assert_eq!(cfg.ns_per_token, 100); // drain rate
        assert_eq!(cfg.burst, 500); // capacity
        assert_eq!(cfg.algorithm, ALGO_LEAKY_BUCKET);
    }

    #[test]
    fn default_algorithm_is_token_bucket() {
        assert_eq!(
            RateLimitAlgorithm::default(),
            RateLimitAlgorithm::TokenBucket
        );
    }

    #[test]
    fn country_tier_config_to_ebpf_config_token_bucket() {
        let tier = CountryTierConfig {
            tier_id: 1,
            country_codes: vec!["RU".to_string()],
            rate: 500,
            burst: 1000,
            algorithm: RateLimitAlgorithm::TokenBucket,
            action: RateLimitAction::Drop,
        };
        let cfg = tier.to_ebpf_config();
        assert_eq!(cfg.ns_per_token, 2_000_000); // 1e9 / 500
        assert_eq!(cfg.burst, 1000);
        assert_eq!(cfg.action, RATELIMIT_ACTION_DROP);
        assert_eq!(cfg.algorithm, ALGO_TOKEN_BUCKET);
    }

    #[test]
    fn country_tier_config_to_ebpf_config_fixed_window() {
        let tier = CountryTierConfig {
            tier_id: 2,
            country_codes: vec!["CN".to_string()],
            rate: 200,
            burst: 1,
            algorithm: RateLimitAlgorithm::FixedWindow,
            action: RateLimitAction::Pass,
        };
        let cfg = tier.to_ebpf_config();
        assert_eq!(cfg.ns_per_token, 200);
        assert_eq!(cfg.burst, 0);
        assert_eq!(cfg.action, RATELIMIT_ACTION_PASS);
        assert_eq!(cfg.algorithm, ALGO_FIXED_WINDOW);
    }
}
