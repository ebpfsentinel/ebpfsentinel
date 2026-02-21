//! IPS domain configuration structs and conversion logic.

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

    #[serde(default)]
    pub sampling: Option<SamplingConfig>,

    #[serde(default)]
    pub rules: Vec<IpsRuleConfig>,
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
            sampling: None,
            rules: Vec::new(),
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
        })
    }
}
