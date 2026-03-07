//! Rate limiting domain configuration structs and conversion logic.

use domain::common::entity::RuleId;
use domain::ratelimit::entity::{
    CountryTierConfig, RateLimitAction, RateLimitAlgorithm, RateLimitPolicy, RateLimitScope,
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

    /// Per-country rate limit tier configurations.
    /// Each tier maps country codes to a rate limit config loaded into eBPF LPM Trie maps.
    #[serde(default)]
    pub country_tiers: Vec<CountryTierConfigYaml>,
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
            country_tiers: Vec::new(),
        }
    }
}

/// YAML configuration for a country-tier rate limit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CountryTierConfigYaml {
    /// Tier ID (1-15).
    pub tier_id: u8,
    /// Country codes assigned to this tier.
    pub country_codes: Vec<String>,
    /// Packets per second.
    pub rate: u64,
    /// Maximum burst (bucket size).
    pub burst: u64,
    /// Algorithm: `token_bucket`, `fixed_window`, `sliding_window`, `leaky_bucket`.
    #[serde(default = "default_ratelimit_algorithm")]
    pub algorithm: String,
    /// Action on limit exceeded: `drop` or `pass`.
    #[serde(default = "default_ratelimit_action")]
    pub action: String,
}

impl CountryTierConfigYaml {
    pub(super) fn validate(&self, idx: usize) -> Result<(), ConfigError> {
        let prefix = format!("ratelimit.country_tiers[{idx}]");

        if self.tier_id == 0 || self.tier_id > 15 {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.tier_id"),
                message: "tier_id must be 1-15".to_string(),
            });
        }

        if self.country_codes.is_empty() {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.country_codes"),
                message: "country_codes must not be empty".to_string(),
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

        parse_ratelimit_algorithm(&self.algorithm).map_err(|()| ConfigError::InvalidValue {
            field: format!("{prefix}.algorithm"),
            value: self.algorithm.clone(),
            expected: "token_bucket, fixed_window, sliding_window, leaky_bucket".to_string(),
        })?;

        Ok(())
    }

    pub fn to_domain_tier(&self) -> Result<CountryTierConfig, ConfigError> {
        let action =
            parse_ratelimit_action(&self.action).map_err(|()| ConfigError::InvalidValue {
                field: "action".to_string(),
                value: self.action.clone(),
                expected: "drop, pass".to_string(),
            })?;

        let algorithm =
            parse_ratelimit_algorithm(&self.algorithm).map_err(|()| ConfigError::InvalidValue {
                field: "algorithm".to_string(),
                value: self.algorithm.clone(),
                expected: "token_bucket, fixed_window, sliding_window, leaky_bucket".to_string(),
            })?;

        Ok(CountryTierConfig {
            tier_id: self.tier_id,
            country_codes: self.country_codes.clone(),
            rate: self.rate,
            burst: self.burst,
            algorithm,
            action,
        })
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

    /// Optional country code filter (userspace annotation only).
    #[serde(default)]
    pub country_codes: Option<Vec<String>>,
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
            country_codes: self.country_codes.clone(),
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

#[cfg(test)]
mod tests {
    use super::*;

    // ── Default config ───────────────────────────────────────────────

    #[test]
    fn default_config() {
        let cfg = RateLimitSectionConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.default_rate, 1000);
        assert_eq!(cfg.default_burst, 2000);
        assert_eq!(cfg.default_algorithm, "token_bucket");
        assert!(cfg.rules.is_empty());
        assert!(cfg.country_tiers.is_empty());
    }

    // ── Helpers ──────────────────────────────────────────────────────

    fn valid_rule() -> RateLimitRuleConfig {
        serde_yaml_ng::from_str(
            r#"
id: rl1
rate: 500
burst: 1000
action: drop
scope: source_ip
algorithm: token_bucket
"#,
        )
        .unwrap()
    }

    // ── RateLimitRuleConfig::validate() ──────────────────────────────

    #[test]
    fn validate_empty_id_error() {
        let mut rule = valid_rule();
        rule.id = String::new();
        let err = rule.validate(0).unwrap_err();
        assert!(err.to_string().contains("rule ID must not be empty"));
    }

    #[test]
    fn validate_rate_zero_error() {
        let mut rule = valid_rule();
        rule.rate = 0;
        let err = rule.validate(0).unwrap_err();
        assert!(err.to_string().contains("rate must be > 0"));
    }

    #[test]
    fn validate_burst_zero_error() {
        let mut rule = valid_rule();
        rule.burst = 0;
        let err = rule.validate(0).unwrap_err();
        assert!(err.to_string().contains("burst must be > 0"));
    }

    #[test]
    fn validate_invalid_action_error() {
        let mut rule = valid_rule();
        rule.action = "explode".to_string();
        let err = rule.validate(0).unwrap_err();
        assert!(err.to_string().contains("explode"));
    }

    #[test]
    fn validate_invalid_scope_error() {
        let mut rule = valid_rule();
        rule.scope = "per_subnet".to_string();
        let err = rule.validate(0).unwrap_err();
        assert!(err.to_string().contains("per_subnet"));
    }

    #[test]
    fn validate_invalid_algorithm_error() {
        let mut rule = valid_rule();
        rule.algorithm = "magic".to_string();
        let err = rule.validate(0).unwrap_err();
        assert!(err.to_string().contains("magic"));
    }

    #[test]
    fn validate_invalid_cidr_error() {
        let mut rule = valid_rule();
        rule.src_ip = Some("not-a-cidr".to_string());
        let err = rule.validate(0).unwrap_err();
        assert!(err.to_string().contains("not-a-cidr"));
    }

    #[test]
    fn validate_valid_rule_passes() {
        let rule = valid_rule();
        rule.validate(0).unwrap();
    }

    // ── RateLimitRuleConfig::to_domain_policy() ──────────────────────

    #[test]
    fn to_domain_policy_correct_conversion() {
        let rule: RateLimitRuleConfig = serde_yaml_ng::from_str(
            r#"
id: rl-test
rate: 200
burst: 400
action: pass
scope: global
algorithm: sliding_window
src_ip: "10.0.0.0/8"
"#,
        )
        .unwrap();

        let policy = rule.to_domain_policy().unwrap();
        assert_eq!(policy.id.0, "rl-test");
        assert_eq!(policy.rate, 200);
        assert_eq!(policy.burst, 400);
        assert!(matches!(policy.action, RateLimitAction::Pass));
        assert!(matches!(policy.scope, RateLimitScope::Global));
        assert!(matches!(
            policy.algorithm,
            RateLimitAlgorithm::SlidingWindow
        ));
        assert!(policy.src_ip.is_some());
        assert!(policy.enabled);
    }

    // ── CountryTierConfigYaml::validate() ────────────────────────────

    fn valid_tier() -> CountryTierConfigYaml {
        serde_yaml_ng::from_str(
            r#"
tier_id: 1
country_codes: ["US", "CA"]
rate: 5000
burst: 10000
algorithm: token_bucket
action: drop
"#,
        )
        .unwrap()
    }

    #[test]
    fn tier_validate_tier_id_zero_error() {
        let mut tier = valid_tier();
        tier.tier_id = 0;
        let err = tier.validate(0).unwrap_err();
        assert!(err.to_string().contains("tier_id must be 1-15"));
    }

    #[test]
    fn tier_validate_tier_id_16_error() {
        let mut tier = valid_tier();
        tier.tier_id = 16;
        let err = tier.validate(0).unwrap_err();
        assert!(err.to_string().contains("tier_id must be 1-15"));
    }

    #[test]
    fn tier_validate_empty_country_codes_error() {
        let mut tier = valid_tier();
        tier.country_codes = Vec::new();
        let err = tier.validate(0).unwrap_err();
        assert!(err.to_string().contains("country_codes must not be empty"));
    }

    // ── CountryTierConfigYaml::to_domain_tier() ──────────────────────

    #[test]
    fn tier_to_domain_correct_conversion() {
        let tier = valid_tier();
        let domain = tier.to_domain_tier().unwrap();
        assert_eq!(domain.tier_id, 1);
        assert_eq!(domain.country_codes, vec!["US", "CA"]);
        assert_eq!(domain.rate, 5000);
        assert_eq!(domain.burst, 10000);
        assert!(matches!(domain.algorithm, RateLimitAlgorithm::TokenBucket));
        assert!(matches!(domain.action, RateLimitAction::Drop));
    }
}
