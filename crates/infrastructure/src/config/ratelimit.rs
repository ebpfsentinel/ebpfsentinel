//! Rate limiting domain configuration structs and conversion logic.

use std::collections::HashMap;

use domain::common::entity::RuleId;
use domain::firewall::entity::IpNetwork;
use domain::ratelimit::entity::{
    CountryTierConfig, RateLimitAction, RateLimitAlgorithm, RateLimitPolicy,
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

impl RateLimitSectionConfig {
    /// Validate every rule, and reject two rules naming the same source.
    ///
    /// The config map holds one entry per source address, so a second rule on
    /// the same host would overwrite the first with nothing to show for it.
    pub(super) fn validate_rules(&self) -> Result<(), ConfigError> {
        let mut seen: HashMap<u32, &str> = HashMap::new();

        for (idx, rule) in self.rules.iter().enumerate() {
            rule.validate(idx)?;

            let IpNetwork::V4 { addr, .. } = parse_cidr(&rule.src_ip)? else {
                continue; // Rejected by the rule's own validation above.
            };
            if let Some(first) = seen.insert(addr, &rule.id) {
                return Err(ConfigError::Validation {
                    field: format!("ratelimit.rules[{idx}].src_ip"),
                    message: format!(
                        "source {} is already limited by rule '{first}': one source carries \
                         one bucket, so the second rule would replace the first",
                        rule.src_ip
                    ),
                });
            }
        }

        Ok(())
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

/// A per-source override of the section defaults.
///
/// One rule limits one source host: the eBPF config map is an exact-match
/// hash on the packet's 32-bit source address. Sources no rule names get the
/// section defaults, each with its own bucket. To limit a whole country, use
/// `country_tiers`, which resolves country codes to CIDRs and matches them
/// with an LPM trie.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitRuleConfig {
    pub id: String,

    /// Tokens per second.
    pub rate: u64,

    /// Maximum burst (bucket size).
    pub burst: u64,

    /// Source host, as a bare address or a `/32`. Shorter prefixes and IPv6
    /// are refused: the config map matches one exact address.
    pub src_ip: String,

    /// Action on limit exceeded: "drop" or "pass".
    #[serde(default = "default_ratelimit_action")]
    pub action: String,

    /// Algorithm: `token_bucket`, `fixed_window`, `sliding_window`, `leaky_bucket`.
    #[serde(default = "default_ratelimit_algorithm")]
    pub algorithm: String,

    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Interface groups this rule applies to. Empty = all (floating).
    /// Prefix with "!" for inversion (e.g., `"!lan"` = all except lan).
    #[serde(default)]
    pub interfaces: Vec<String>,
}

fn default_ratelimit_action() -> String {
    "drop".to_string()
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

        parse_ratelimit_algorithm(&self.algorithm).map_err(|()| ConfigError::InvalidValue {
            field: format!("{prefix}.algorithm"),
            value: self.algorithm.clone(),
            expected: "token_bucket, fixed_window, sliding_window, leaky_bucket".to_string(),
        })?;

        validate_source_host(format!("{prefix}.src_ip"), &self.src_ip)?;

        Ok(())
    }

    /// Convert to a domain `RateLimitPolicy`. `group_bits` maps every
    /// configured interface-group name to its bit, so `interfaces` can be
    /// resolved into the mask the limiter compares against the arrival
    /// interface.
    pub fn to_domain_policy(
        &self,
        group_bits: &HashMap<String, u32>,
    ) -> Result<RateLimitPolicy, ConfigError> {
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

        let src_ip = parse_cidr(&self.src_ip).map_err(|e| ConfigError::InvalidCidr {
            value: self.src_ip.clone(),
            reason: e.to_string(),
        })?;

        Ok(RateLimitPolicy {
            id: RuleId(self.id.clone()),
            rate: self.rate,
            burst: self.burst,
            action,
            src_ip,
            enabled: self.enabled,
            algorithm,
            group_mask: super::parse_group_mask(&self.interfaces, group_bits).map_err(
                |message| ConfigError::Validation {
                    field: "ratelimit.rules.interfaces".to_string(),
                    message,
                },
            )?,
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

/// Validate a rule's source address.
///
/// The config map is an exact-match hash on a 32-bit source address, so a
/// prefix shorter than `/32` would be narrowed to its network address and an
/// IPv6 source has no key at all. `0.0.0.0` is the entry the section defaults
/// own; a rule claiming it would silently replace them for every source no
/// other rule names. All three are refused here with the reason rather than
/// accepted and then quietly misapplied.
fn validate_source_host(field: String, value: &str) -> Result<(), ConfigError> {
    match parse_cidr(value).map_err(|e| ConfigError::InvalidCidr {
        value: value.to_string(),
        reason: e.to_string(),
    })? {
        IpNetwork::V4 {
            addr: 0,
            prefix_len: 32,
        } => Err(ConfigError::Validation {
            field,
            message: "0.0.0.0 is the entry ratelimit.default_rate and default_burst own; \
                      change those instead of naming it in a rule"
                .to_string(),
        }),
        IpNetwork::V4 { prefix_len: 32, .. } => Ok(()),
        IpNetwork::V4 { prefix_len, .. } => Err(ConfigError::Validation {
            field,
            message: format!(
                "prefix /{prefix_len} cannot be enforced: a rule limits one exact source \
                 address, so only a single host (or /32) is accepted. Use country_tiers to \
                 cover a range"
            ),
        }),
        IpNetwork::V6 { .. } => Err(ConfigError::Validation {
            field,
            message: "IPv6 sources cannot be enforced: the per-source config map is keyed by a \
                      32-bit IPv4 address. Use country_tiers, which carries an IPv6 trie"
                .to_string(),
        }),
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
            r"
id: rl1
rate: 500
burst: 1000
src_ip: 10.0.0.7
action: drop
algorithm: token_bucket
",
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
    fn validate_invalid_algorithm_error() {
        let mut rule = valid_rule();
        rule.algorithm = "magic".to_string();
        let err = rule.validate(0).unwrap_err();
        assert!(err.to_string().contains("magic"));
    }

    #[test]
    fn validate_invalid_cidr_error() {
        let mut rule = valid_rule();
        rule.src_ip = "not-a-cidr".to_string();
        let err = rule.validate(0).unwrap_err();
        assert!(err.to_string().contains("not-a-cidr"));
    }

    /// A prefix has nothing to match in an exact-match config map.
    #[test]
    fn validate_prefix_source_error() {
        let mut rule = valid_rule();
        rule.src_ip = "10.0.0.0/8".to_string();
        let err = rule.validate(0).unwrap_err();
        assert!(err.to_string().contains("single host"));
    }

    /// Key 0 belongs to the section defaults.
    #[test]
    fn validate_default_entry_source_error() {
        let mut rule = valid_rule();
        rule.src_ip = "0.0.0.0".to_string();
        let err = rule.validate(0).unwrap_err();
        assert!(err.to_string().contains("default_rate"));
    }

    /// The config map holds one entry per source address.
    #[test]
    fn validate_rules_rejects_a_duplicate_source() {
        let mut first = valid_rule();
        first.id = "first".to_string();
        let mut second = valid_rule();
        second.id = "second".to_string();
        second.src_ip = format!("{}/32", first.src_ip);

        let section = RateLimitSectionConfig {
            rules: vec![first, second],
            ..RateLimitSectionConfig::default()
        };
        let err = section.validate_rules().unwrap_err();
        assert!(err.to_string().contains("already limited by rule 'first'"));
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
algorithm: sliding_window
src_ip: "10.0.0.7"
"#,
        )
        .unwrap();

        let policy = rule.to_domain_policy(&HashMap::new()).unwrap();
        assert_eq!(policy.id.0, "rl-test");
        assert_eq!(policy.rate, 200);
        assert_eq!(policy.burst, 400);
        assert!(matches!(policy.action, RateLimitAction::Pass));
        assert!(matches!(
            policy.algorithm,
            RateLimitAlgorithm::SlidingWindow
        ));
        assert!(matches!(
            policy.src_ip,
            IpNetwork::V4 {
                addr: 0x0A00_0007,
                prefix_len: 32
            }
        ));
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
