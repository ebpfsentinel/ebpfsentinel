use serde::{Deserialize, Serialize};

use crate::common::entity::RuleId;
use crate::firewall::entity::IpCidr;
use ebpf_common::ratelimit::{
    ALGO_FIXED_WINDOW, ALGO_LEAKY_BUCKET, ALGO_SLIDING_WINDOW, ALGO_TOKEN_BUCKET,
    RATELIMIT_ACTION_DROP, RATELIMIT_ACTION_PASS, RateLimitConfig as EbpfConfig,
    RateLimitKey as EbpfKey,
};

use super::error::RateLimitError;

/// Scope of rate limiting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RateLimitScope {
    /// Per-source-IP rate limiting (each source IP has its own bucket).
    SourceIp,
    /// Global rate limiting (single bucket for all traffic).
    Global,
}

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

/// A rate limit policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitPolicy {
    pub id: RuleId,
    pub scope: RateLimitScope,
    /// Tokens per second (refill rate).
    pub rate: u64,
    /// Maximum tokens (bucket size). Must be >= 1.
    pub burst: u64,
    /// Action when rate is exceeded.
    pub action: RateLimitAction,
    /// Optional source IP CIDR filter. `None` = all source IPs.
    pub src_ip: Option<IpCidr>,
    pub enabled: bool,
    /// Rate limiting algorithm to use.
    pub algorithm: RateLimitAlgorithm,
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

        if let Some(ref cidr) = self.src_ip {
            match cidr {
                IpCidr::V4 { prefix_len, .. } => {
                    if *prefix_len > 32 {
                        return Err(RateLimitError::InvalidPolicy(format!(
                            "invalid CIDR prefix length: {prefix_len}",
                        )));
                    }
                }
                IpCidr::V6 { prefix_len, .. } => {
                    if *prefix_len > 128 {
                        return Err(RateLimitError::InvalidPolicy(format!(
                            "invalid CIDR prefix length: {prefix_len}",
                        )));
                    }
                }
            }
        }

        Ok(())
    }

    /// Convert to an eBPF map key. For `SourceIp` scope with a specific IP,
    /// uses that IP. For `Global`, uses key 0.
    pub fn to_ebpf_key(&self) -> EbpfKey {
        match self.scope {
            RateLimitScope::SourceIp => {
                let src_ip = self.src_ip.map_or(0, |c| match c {
                    IpCidr::V4 { addr, .. } => addr,
                    IpCidr::V6 { .. } => 0,
                });
                EbpfKey { src_ip }
            }
            RateLimitScope::Global => EbpfKey { src_ip: 0 },
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
                let ns_per_token = if self.rate > 0 {
                    1_000_000_000 / self.rate
                } else {
                    0
                };
                EbpfConfig {
                    ns_per_token,
                    burst: self.burst,
                    action,
                    algorithm: ALGO_TOKEN_BUCKET,
                    _padding: [0; 6],
                }
            }
            RateLimitAlgorithm::FixedWindow => EbpfConfig {
                ns_per_token: self.rate,
                burst: 0,
                action,
                algorithm: ALGO_FIXED_WINDOW,
                _padding: [0; 6],
            },
            RateLimitAlgorithm::SlidingWindow => EbpfConfig {
                ns_per_token: self.rate,
                burst: 0,
                action,
                algorithm: ALGO_SLIDING_WINDOW,
                _padding: [0; 6],
            },
            RateLimitAlgorithm::LeakyBucket => EbpfConfig {
                ns_per_token: self.rate,
                burst: self.burst,
                action,
                algorithm: ALGO_LEAKY_BUCKET,
                _padding: [0; 6],
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
            scope: RateLimitScope::SourceIp,
            rate,
            burst,
            action: RateLimitAction::Drop,
            src_ip: None,
            enabled: true,
            algorithm: RateLimitAlgorithm::default(),
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

    #[test]
    fn validate_invalid_cidr() {
        let mut policy = make_policy("rl-001", 1000, 2000);
        policy.src_ip = Some(IpNetwork::V4 {
            addr: 0,
            prefix_len: 33,
        });
        assert!(policy.validate().is_err());
    }

    #[test]
    fn validate_valid_cidr() {
        let mut policy = make_policy("rl-001", 1000, 2000);
        policy.src_ip = Some(IpNetwork::V4 {
            addr: 0x0A00_0000,
            prefix_len: 8,
        });
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn to_ebpf_key_source_ip_no_cidr() {
        let policy = make_policy("rl-001", 1000, 2000);
        let key = policy.to_ebpf_key();
        assert_eq!(key.src_ip, 0);
    }

    #[test]
    fn to_ebpf_key_source_ip_with_cidr() {
        let mut policy = make_policy("rl-001", 1000, 2000);
        policy.src_ip = Some(IpNetwork::V4 {
            addr: 0xC0A8_0100,
            prefix_len: 24,
        });
        let key = policy.to_ebpf_key();
        assert_eq!(key.src_ip, 0xC0A8_0100);
    }

    #[test]
    fn to_ebpf_key_global() {
        let mut policy = make_policy("rl-001", 1000, 2000);
        policy.scope = RateLimitScope::Global;
        let key = policy.to_ebpf_key();
        assert_eq!(key.src_ip, 0);
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
}
