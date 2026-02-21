//! Rate limiting domain configuration structs and conversion logic.

use domain::common::entity::RuleId;
use domain::ratelimit::entity::{
    RateLimitAction, RateLimitAlgorithm, RateLimitPolicy, RateLimitScope,
};
use serde::{Deserialize, Serialize};

use super::common::{ConfigError, default_true, parse_cidr};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitSectionConfig {
    #[serde(default)]
    pub enabled: bool,

    /// Default rate (tokens/sec) for IPs without a specific rule.
    #[serde(default = "default_ratelimit_rate")]
    pub default_rate: u64,

    /// Default burst (max tokens) for IPs without a specific rule.
    #[serde(default = "default_ratelimit_burst")]
    pub default_burst: u64,

    /// Default algorithm for rules that don't specify one.
    #[serde(default = "default_ratelimit_algorithm")]
    pub default_algorithm: String,

    #[serde(default)]
    pub rules: Vec<RateLimitRuleConfig>,
}

fn default_ratelimit_rate() -> u64 {
    1000
}
fn default_ratelimit_burst() -> u64 {
    2000
}
fn default_ratelimit_algorithm() -> String {
    "token_bucket".to_string()
}

impl Default for RateLimitSectionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            default_rate: default_ratelimit_rate(),
            default_burst: default_ratelimit_burst(),
            default_algorithm: default_ratelimit_algorithm(),
            rules: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitRuleConfig {
    pub id: String,

    /// Tokens per second.
    pub rate: u64,

    /// Maximum burst (bucket size).
    pub burst: u64,

    /// Optional source IP CIDR filter.
    #[serde(default)]
    pub src_ip: Option<String>,

    /// Action on limit exceeded: "drop" or "pass".
    #[serde(default = "default_ratelimit_action")]
    pub action: String,

    /// Scope: `source_ip` (default) or `global`.
    #[serde(default = "default_ratelimit_scope")]
    pub scope: String,

    /// Algorithm: `token_bucket`, `fixed_window`, `sliding_window`, `leaky_bucket`.
    #[serde(default = "default_ratelimit_algorithm")]
    pub algorithm: String,

    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_ratelimit_action() -> String {
    "drop".to_string()
}

fn default_ratelimit_scope() -> String {
    "source_ip".to_string()
}

impl RateLimitRuleConfig {
    pub(super) fn validate(&self, idx: usize) -> Result<(), ConfigError> {
        let prefix = format!("ratelimit.rules[{idx}]");

        if self.id.is_empty() {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.id"),
                message: "rule ID must not be empty".to_string(),
            });
        }

        if self.rate == 0 {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.rate"),
                message: "rate must be > 0".to_string(),
            });
        }

        if self.burst == 0 {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.burst"),
                message: "burst must be > 0".to_string(),
            });
        }

        parse_ratelimit_action(&self.action).map_err(|()| ConfigError::InvalidValue {
            field: format!("{prefix}.action"),
            value: self.action.clone(),
            expected: "drop, pass".to_string(),
        })?;

        parse_ratelimit_scope(&self.scope).map_err(|()| ConfigError::InvalidValue {
            field: format!("{prefix}.scope"),
            value: self.scope.clone(),
            expected: "source_ip, global".to_string(),
        })?;

        parse_ratelimit_algorithm(&self.algorithm).map_err(|()| ConfigError::InvalidValue {
            field: format!("{prefix}.algorithm"),
            value: self.algorithm.clone(),
            expected: "token_bucket, fixed_window, sliding_window, leaky_bucket".to_string(),
        })?;

        if let Some(ref cidr) = self.src_ip {
            parse_cidr(cidr).map_err(|e| ConfigError::InvalidCidr {
                value: cidr.clone(),
                reason: e.to_string(),
            })?;
        }

        Ok(())
    }

    pub fn to_domain_policy(&self) -> Result<RateLimitPolicy, ConfigError> {
        let action =
            parse_ratelimit_action(&self.action).map_err(|()| ConfigError::InvalidValue {
                field: "action".to_string(),
                value: self.action.clone(),
                expected: "drop, pass".to_string(),
            })?;

        let scope = parse_ratelimit_scope(&self.scope).map_err(|()| ConfigError::InvalidValue {
            field: "scope".to_string(),
            value: self.scope.clone(),
            expected: "source_ip, global".to_string(),
        })?;

        let algorithm =
            parse_ratelimit_algorithm(&self.algorithm).map_err(|()| ConfigError::InvalidValue {
                field: "algorithm".to_string(),
                value: self.algorithm.clone(),
                expected: "token_bucket, fixed_window, sliding_window, leaky_bucket".to_string(),
            })?;

        let src_ip = self
            .src_ip
            .as_deref()
            .map(parse_cidr)
            .transpose()
            .map_err(|e| ConfigError::InvalidCidr {
                value: self.src_ip.clone().unwrap_or_default(),
                reason: e.to_string(),
            })?;

        Ok(RateLimitPolicy {
            id: RuleId(self.id.clone()),
            scope,
            rate: self.rate,
            burst: self.burst,
            action,
            src_ip,
            enabled: self.enabled,
            algorithm,
        })
    }
}

fn parse_ratelimit_action(s: &str) -> Result<RateLimitAction, ()> {
    match s.to_lowercase().as_str() {
        "drop" | "deny" | "block" => Ok(RateLimitAction::Drop),
        "pass" | "allow" => Ok(RateLimitAction::Pass),
        _ => Err(()),
    }
}

fn parse_ratelimit_scope(s: &str) -> Result<RateLimitScope, ()> {
    match s.to_lowercase().as_str() {
        "source_ip" | "src_ip" | "per_ip" | "per-ip" => Ok(RateLimitScope::SourceIp),
        "global" => Ok(RateLimitScope::Global),
        _ => Err(()),
    }
}

fn parse_ratelimit_algorithm(s: &str) -> Result<RateLimitAlgorithm, ()> {
    match s.to_lowercase().as_str() {
        "token_bucket" | "tokenbucket" => Ok(RateLimitAlgorithm::TokenBucket),
        "fixed_window" | "fixedwindow" => Ok(RateLimitAlgorithm::FixedWindow),
        "sliding_window" | "slidingwindow" => Ok(RateLimitAlgorithm::SlidingWindow),
        "leaky_bucket" | "leakybucket" => Ok(RateLimitAlgorithm::LeakyBucket),
        _ => Err(()),
    }
}
