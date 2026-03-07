//! IPS domain configuration structs and conversion logic.

use std::collections::HashMap;

use domain::common::entity::RuleId;
use domain::ids::entity::IdsRule;
use domain::ips::entity::IpsPolicy;
use serde::{Deserialize, Serialize};

use super::common::{
    ConfigError, default_mode, default_true, parse_domain_mode, parse_protocol, parse_severity,
};
use super::ids::{SamplingConfig, ThresholdRuleConfig};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpsConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,

    #[serde(default = "default_mode")]
    pub mode: String,

    #[serde(default = "default_max_blacklist_duration")]
    pub max_blacklist_duration_secs: u64,

    #[serde(default = "default_auto_blacklist_threshold")]
    pub auto_blacklist_threshold: u32,

    #[serde(default = "default_max_blacklist_size")]
    pub max_blacklist_size: usize,

    #[serde(default)]
    pub whitelist: Vec<String>,

    /// Alias names to include in the whitelist (resolved to IPs from top-level aliases).
    #[serde(default)]
    pub whitelist_aliases: Vec<String>,

    #[serde(default)]
    pub sampling: Option<SamplingConfig>,

    #[serde(default)]
    pub rules: Vec<IpsRuleConfig>,

    /// Per-country auto-blacklist thresholds (ISO 3166-1 alpha-2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country_thresholds: Option<HashMap<String, u32>>,
}

fn default_max_blacklist_duration() -> u64 {
    3600
}
fn default_auto_blacklist_threshold() -> u32 {
    3
}
fn default_max_blacklist_size() -> usize {
    10_000
}

impl Default for IpsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: "alert".to_string(),
            max_blacklist_duration_secs: default_max_blacklist_duration(),
            auto_blacklist_threshold: default_auto_blacklist_threshold(),
            max_blacklist_size: default_max_blacklist_size(),
            whitelist: Vec::new(),
            whitelist_aliases: Vec::new(),
            sampling: None,
            rules: Vec::new(),
            country_thresholds: None,
        }
    }
}

impl IpsConfig {
    pub fn to_domain_policy(&self) -> IpsPolicy {
        IpsPolicy {
            max_blacklist_duration: std::time::Duration::from_secs(
                self.max_blacklist_duration_secs,
            ),
            auto_blacklist_threshold: self.auto_blacklist_threshold,
            max_blacklist_size: self.max_blacklist_size,
            country_thresholds: self.country_thresholds.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpsRuleConfig {
    pub id: String,

    #[serde(default)]
    pub description: Option<String>,

    pub severity: String,

    /// Per-rule mode override. If absent, inherits from the global IPS mode.
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
}

fn default_protocol_any() -> String {
    "any".to_string()
}

impl IpsRuleConfig {
    pub(super) fn validate_ips(&self, idx: usize) -> Result<(), ConfigError> {
        let prefix = format!("ips.rules[{idx}]");

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

        if let Some(ref threshold) = self.threshold {
            threshold.validate(&prefix)?;
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
            domain_pattern: None,
            domain_match_mode: None,
            country_thresholds: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::common::entity::{DomainMode, Severity};

    fn valid_rule_config() -> IpsRuleConfig {
        IpsRuleConfig {
            id: "ips-1".to_string(),
            description: Some("Test rule".to_string()),
            severity: "high".to_string(),
            mode: None,
            protocol: "tcp".to_string(),
            dst_port: Some(80),
            pattern: None,
            enabled: true,
            threshold: None,
        }
    }

    // ── Default config ─────────────────────────────────────────────

    #[test]
    fn default_config() {
        let cfg = IpsConfig::default();
        assert!(cfg.enabled);
        assert_eq!(cfg.mode, "alert");
        assert_eq!(cfg.max_blacklist_duration_secs, 3600);
        assert_eq!(cfg.auto_blacklist_threshold, 3);
        assert_eq!(cfg.max_blacklist_size, 10_000);
    }

    // ── IpsConfig::to_domain_policy ────────────────────────────────

    #[test]
    fn to_domain_policy_correct() {
        let cfg = IpsConfig::default();
        let policy = cfg.to_domain_policy();
        assert_eq!(
            policy.max_blacklist_duration,
            std::time::Duration::from_secs(3600)
        );
        assert_eq!(policy.auto_blacklist_threshold, 3);
        assert_eq!(policy.max_blacklist_size, 10_000);
        assert!(policy.country_thresholds.is_none());
    }

    // ── IpsRuleConfig::validate_ips ────────────────────────────────

    #[test]
    fn validate_empty_id_error() {
        let mut r = valid_rule_config();
        r.id = String::new();
        let err = r.validate_ips(0).unwrap_err();
        assert!(err.to_string().contains("id"), "error: {err}");
    }

    #[test]
    fn validate_invalid_severity_error() {
        let mut r = valid_rule_config();
        r.severity = "banana".to_string();
        let err = r.validate_ips(0).unwrap_err();
        assert!(err.to_string().contains("severity"), "error: {err}");
    }

    #[test]
    fn validate_invalid_protocol_error() {
        let mut r = valid_rule_config();
        r.protocol = "ftp".to_string();
        let err = r.validate_ips(0).unwrap_err();
        assert!(err.to_string().contains("protocol"), "error: {err}");
    }

    #[test]
    fn validate_invalid_mode_error() {
        let mut r = valid_rule_config();
        r.mode = Some("nope".to_string());
        let err = r.validate_ips(0).unwrap_err();
        assert!(err.to_string().contains("mode"), "error: {err}");
    }

    #[test]
    fn validate_valid_rule_passes() {
        let r = valid_rule_config();
        assert!(r.validate_ips(0).is_ok());
    }

    // ── IpsRuleConfig::to_domain_rule ──────────────────────────────

    #[test]
    fn to_domain_rule_global_mode_inheritance() {
        let r = valid_rule_config();
        let domain = r.to_domain_rule("alert").unwrap();
        assert_eq!(domain.id.0, "ips-1");
        assert_eq!(domain.severity, Severity::High);
        assert_eq!(domain.mode, DomainMode::Alert);
        assert_eq!(domain.protocol, domain::common::entity::Protocol::Tcp);
        assert_eq!(domain.dst_port, Some(80));
        assert!(domain.enabled);
    }

    #[test]
    fn to_domain_rule_per_rule_mode_override() {
        let mut r = valid_rule_config();
        r.mode = Some("block".to_string());
        let domain = r.to_domain_rule("alert").unwrap();
        assert_eq!(domain.mode, DomainMode::Block);
    }
}
