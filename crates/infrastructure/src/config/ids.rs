//! IDS domain configuration structs and conversion logic.

use domain::common::entity::RuleId;
use domain::ids::entity::{IdsRule, SamplingMode, ThresholdConfig, ThresholdType, TrackBy};
use serde::{Deserialize, Serialize};

use super::common::{
    ConfigError, default_mode, default_true, parse_domain_mode, parse_protocol, parse_severity,
    validate_regex,
};

// ── Sampling config ───────────────────────────────────────────────

/// Event sampling configuration for IDS/IPS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingConfig {
    /// Sampling mode: "none", "random", "hash".
    #[serde(default = "default_sampling_mode")]
    pub mode: String,

    /// Sampling rate (0.0–1.0). Required for "random" and "hash" modes.
    pub rate: Option<f64>,
}

fn default_sampling_mode() -> String {
    "none".to_string()
}

impl SamplingConfig {
    pub(super) fn validate(&self, prefix: &str) -> Result<(), ConfigError> {
        match self.mode.as_str() {
            "none" => Ok(()),
            "random" | "hash" => {
                let rate = self.rate.ok_or_else(|| ConfigError::Validation {
                    field: format!("{prefix}.sampling.rate"),
                    message: "rate is required for random/hash sampling".to_string(),
                })?;
                if !(0.0..=1.0).contains(&rate) {
                    return Err(ConfigError::Validation {
                        field: format!("{prefix}.sampling.rate"),
                        message: "rate must be between 0.0 and 1.0".to_string(),
                    });
                }
                Ok(())
            }
            _ => Err(ConfigError::InvalidValue {
                field: format!("{prefix}.sampling.mode"),
                value: self.mode.clone(),
                expected: "none, random, hash".to_string(),
            }),
        }
    }

    /// Convert to the domain `SamplingMode` enum.
    pub fn to_domain_sampling(&self) -> Result<SamplingMode, ConfigError> {
        match self.mode.as_str() {
            "none" => Ok(SamplingMode::None),
            "random" => Ok(SamplingMode::Random {
                rate: self.rate.unwrap_or(0.0),
            }),
            "hash" => Ok(SamplingMode::Hash {
                rate: self.rate.unwrap_or(0.0),
            }),
            _ => Err(ConfigError::InvalidValue {
                field: "sampling.mode".to_string(),
                value: self.mode.clone(),
                expected: "none, random, hash".to_string(),
            }),
        }
    }
}

// ── Threshold config ──────────────────────────────────────────────

/// Per-rule threshold/rate detection configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdRuleConfig {
    /// Threshold type: "limit", "threshold", "both".
    #[serde(rename = "type")]
    pub threshold_type: String,

    /// Number of occurrences for the threshold logic.
    pub count: u32,

    /// Time window in seconds for counting occurrences.
    pub window_secs: u64,

    /// IP to track: `src_ip`, `dst_ip`, `both` (default: `src_ip`).
    #[serde(default = "default_track_by")]
    pub track_by: String,
}

fn default_track_by() -> String {
    "src_ip".to_string()
}

impl ThresholdRuleConfig {
    pub(super) fn validate(&self, prefix: &str) -> Result<(), ConfigError> {
        match self.threshold_type.as_str() {
            "limit" | "threshold" | "both" => {}
            _ => {
                return Err(ConfigError::InvalidValue {
                    field: format!("{prefix}.threshold.type"),
                    value: self.threshold_type.clone(),
                    expected: "limit, threshold, both".to_string(),
                });
            }
        }

        if self.count == 0 {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.threshold.count"),
                message: "count must be > 0".to_string(),
            });
        }

        if self.window_secs == 0 {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.threshold.window_secs"),
                message: "window_secs must be > 0".to_string(),
            });
        }

        match self.track_by.as_str() {
            "src_ip" | "dst_ip" | "both" => {}
            _ => {
                return Err(ConfigError::InvalidValue {
                    field: format!("{prefix}.threshold.track_by"),
                    value: self.track_by.clone(),
                    expected: "src_ip, dst_ip, both".to_string(),
                });
            }
        }

        Ok(())
    }

    /// Convert to the domain `ThresholdConfig`.
    pub fn to_domain_threshold(&self) -> Result<ThresholdConfig, ConfigError> {
        let threshold_type = match self.threshold_type.as_str() {
            "limit" => ThresholdType::Limit,
            "threshold" => ThresholdType::Threshold,
            "both" => ThresholdType::Both,
            _ => {
                return Err(ConfigError::InvalidValue {
                    field: "threshold.type".to_string(),
                    value: self.threshold_type.clone(),
                    expected: "limit, threshold, both".to_string(),
                });
            }
        };

        let track_by = match self.track_by.as_str() {
            "src_ip" => TrackBy::SrcIp,
            "dst_ip" => TrackBy::DstIp,
            "both" => TrackBy::Both,
            _ => {
                return Err(ConfigError::InvalidValue {
                    field: "threshold.track_by".to_string(),
                    value: self.track_by.clone(),
                    expected: "src_ip, dst_ip, both".to_string(),
                });
            }
        };

        Ok(ThresholdConfig {
            threshold_type,
            count: self.count,
            window_secs: self.window_secs,
            track_by,
        })
    }
}

// ── IDS config ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdsConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,

    #[serde(default = "default_mode")]
    pub mode: String,

    #[serde(default)]
    pub sampling: Option<SamplingConfig>,

    #[serde(default)]
    pub rules: Vec<IdsRuleConfig>,
}

impl Default for IdsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: "alert".to_string(),
            sampling: None,
            rules: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdsRuleConfig {
    pub id: String,

    #[serde(default)]
    pub description: Option<String>,

    pub severity: String,

    /// Per-rule mode override. If absent, inherits from the global IDS mode.
    #[serde(default)]
    pub mode: Option<String>,

    #[serde(default = "default_protocol_any")]
    pub protocol: String,

    pub dst_port: Option<u16>,

    /// Payload regex pattern for deeper inspection.
    #[serde(default)]
    pub pattern: Option<String>,

    #[serde(default = "default_true")]
    pub enabled: bool,

    #[serde(default)]
    pub threshold: Option<ThresholdRuleConfig>,

    /// Optional domain pattern for userspace domain-aware matching.
    #[serde(default)]
    pub domain_pattern: Option<String>,

    /// How to interpret `domain_pattern`: "exact", "wildcard", or "regex".
    #[serde(default)]
    pub domain_match_mode: Option<String>,
}

fn default_protocol_any() -> String {
    "any".to_string()
}

impl IdsRuleConfig {
    pub(super) fn validate(&self, idx: usize) -> Result<(), ConfigError> {
        let prefix = format!("ids.rules[{idx}]");

        if self.id.is_empty() {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.id"),
                message: "rule ID must not be empty".to_string(),
            });
        }

        parse_severity(&self.severity).map_err(|()| ConfigError::InvalidValue {
            field: format!("{prefix}.severity"),
            value: self.severity.clone(),
            expected: "low, medium, high, critical".to_string(),
        })?;

        parse_protocol(&self.protocol).map_err(|()| ConfigError::InvalidValue {
            field: format!("{prefix}.protocol"),
            value: self.protocol.clone(),
            expected: "tcp, udp, icmp, any".to_string(),
        })?;

        if let Some(ref mode) = self.mode {
            parse_domain_mode(mode)?;
        }

        // Validate regex pattern if present (with ReDoS prevention limits)
        if let Some(ref pattern) = self.pattern
            && !pattern.is_empty()
        {
            validate_regex(pattern, &format!("{prefix}.pattern"))?;
        }

        // Validate threshold if present
        if let Some(ref threshold) = self.threshold {
            threshold.validate(&prefix)?;
        }

        // Validate domain-aware fields
        match (&self.domain_pattern, &self.domain_match_mode) {
            (Some(_), None) => {
                return Err(ConfigError::Validation {
                    field: format!("{prefix}.domain_match_mode"),
                    message: "domain_match_mode is required when domain_pattern is set".to_string(),
                });
            }
            (None, Some(_)) => {
                return Err(ConfigError::Validation {
                    field: format!("{prefix}.domain_pattern"),
                    message: "domain_pattern is required when domain_match_mode is set".to_string(),
                });
            }
            (Some(pattern), Some(mode)) => {
                match mode.as_str() {
                    "exact" => {}
                    "wildcard" => {
                        // Validate it's a valid wildcard domain pattern
                        domain::dns::entity::DomainPattern::parse(pattern).map_err(|e| {
                            ConfigError::Validation {
                                field: format!("{prefix}.domain_pattern"),
                                message: format!("invalid wildcard domain pattern: {e}"),
                            }
                        })?;
                    }
                    "regex" => {
                        validate_regex(pattern, &format!("{prefix}.domain_pattern"))?;
                    }
                    other => {
                        return Err(ConfigError::InvalidValue {
                            field: format!("{prefix}.domain_match_mode"),
                            value: other.to_string(),
                            expected: "exact, wildcard, regex".to_string(),
                        });
                    }
                }
            }
            (None, None) => {}
        }

        Ok(())
    }

    pub fn to_domain_rule(&self, global_mode: &str) -> Result<IdsRule, ConfigError> {
        let severity = parse_severity(&self.severity).map_err(|()| ConfigError::InvalidValue {
            field: "severity".to_string(),
            value: self.severity.clone(),
            expected: "low, medium, high, critical".to_string(),
        })?;

        let protocol = parse_protocol(&self.protocol).map_err(|()| ConfigError::InvalidValue {
            field: "protocol".to_string(),
            value: self.protocol.clone(),
            expected: "tcp, udp, icmp, any".to_string(),
        })?;

        let mode_str = self.mode.as_deref().unwrap_or(global_mode);
        let mode = parse_domain_mode(mode_str)?;

        let threshold = self
            .threshold
            .as_ref()
            .map(ThresholdRuleConfig::to_domain_threshold)
            .transpose()?;

        let domain_match_mode = self
            .domain_match_mode
            .as_deref()
            .map(|s| match s {
                "exact" => Ok(domain::ids::entity::DomainMatchMode::Exact),
                "wildcard" => Ok(domain::ids::entity::DomainMatchMode::Wildcard),
                "regex" => Ok(domain::ids::entity::DomainMatchMode::Regex),
                other => Err(ConfigError::InvalidValue {
                    field: "domain_match_mode".to_string(),
                    value: other.to_string(),
                    expected: "exact, wildcard, regex".to_string(),
                }),
            })
            .transpose()?;

        Ok(IdsRule {
            id: RuleId(self.id.clone()),
            description: self.description.clone().unwrap_or_default(),
            severity,
            mode,
            protocol,
            dst_port: self.dst_port,
            pattern: self.pattern.clone().unwrap_or_default(),
            enabled: self.enabled,
            threshold,
            domain_pattern: self.domain_pattern.clone(),
            domain_match_mode,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_rule() -> IdsRuleConfig {
        IdsRuleConfig {
            id: "ids-001".to_string(),
            description: Some("Test rule".to_string()),
            severity: "medium".to_string(),
            mode: None,
            protocol: "tcp".to_string(),
            dst_port: Some(22),
            pattern: None,
            enabled: true,
            threshold: None,
            domain_pattern: None,
            domain_match_mode: None,
        }
    }

    #[test]
    fn validate_domain_pattern_without_mode_fails() {
        let mut rule = base_rule();
        rule.domain_pattern = Some("evil.com".to_string());
        // domain_match_mode is None
        assert!(rule.validate(0).is_err());
    }

    #[test]
    fn validate_domain_mode_without_pattern_fails() {
        let mut rule = base_rule();
        rule.domain_match_mode = Some("exact".to_string());
        // domain_pattern is None
        assert!(rule.validate(0).is_err());
    }

    #[test]
    fn validate_domain_exact_ok() {
        let mut rule = base_rule();
        rule.domain_pattern = Some("evil.com".to_string());
        rule.domain_match_mode = Some("exact".to_string());
        assert!(rule.validate(0).is_ok());
    }

    #[test]
    fn validate_domain_wildcard_ok() {
        let mut rule = base_rule();
        rule.domain_pattern = Some("*.evil.com".to_string());
        rule.domain_match_mode = Some("wildcard".to_string());
        assert!(rule.validate(0).is_ok());
    }

    #[test]
    fn validate_domain_regex_ok() {
        let mut rule = base_rule();
        rule.domain_pattern = Some("beacon\\.evil\\.(com|net)".to_string());
        rule.domain_match_mode = Some("regex".to_string());
        assert!(rule.validate(0).is_ok());
    }

    #[test]
    fn validate_domain_invalid_mode_fails() {
        let mut rule = base_rule();
        rule.domain_pattern = Some("evil.com".to_string());
        rule.domain_match_mode = Some("fuzzy".to_string());
        assert!(rule.validate(0).is_err());
    }

    #[test]
    fn validate_domain_invalid_wildcard_pattern_fails() {
        let mut rule = base_rule();
        rule.domain_pattern = Some("not-a-wildcard".to_string());
        rule.domain_match_mode = Some("wildcard".to_string());
        // DomainPattern::parse should fail for non-wildcard with wildcard mode
        // Actually "not-a-wildcard" will parse as Exact, which is valid for wildcard mode too
        // Let me use an obviously invalid pattern
        rule.domain_pattern = Some("".to_string());
        assert!(rule.validate(0).is_err());
    }

    #[test]
    fn to_domain_rule_with_domain_fields() {
        let mut rule = base_rule();
        rule.domain_pattern = Some("*.evil.com".to_string());
        rule.domain_match_mode = Some("wildcard".to_string());
        let domain_rule = rule.to_domain_rule("alert").unwrap();
        assert_eq!(domain_rule.domain_pattern, Some("*.evil.com".to_string()));
        assert_eq!(
            domain_rule.domain_match_mode,
            Some(domain::ids::entity::DomainMatchMode::Wildcard)
        );
    }

    #[test]
    fn to_domain_rule_without_domain_fields() {
        let rule = base_rule();
        let domain_rule = rule.to_domain_rule("alert").unwrap();
        assert!(domain_rule.domain_pattern.is_none());
        assert!(domain_rule.domain_match_mode.is_none());
    }
}
