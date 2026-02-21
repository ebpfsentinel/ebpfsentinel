//! DLP (Data Loss Prevention) domain configuration structs and conversion logic.

use domain::common::entity::RuleId;
use domain::dlp::entity::DlpPattern;
use serde::{Deserialize, Serialize};

use super::common::{
    ConfigError, default_mode, default_true, parse_domain_mode, parse_severity, validate_regex,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,

    #[serde(default = "default_mode")]
    pub mode: String,

    #[serde(default)]
    pub patterns: Vec<DlpPatternConfig>,
}

impl Default for DlpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: "alert".to_string(),
            patterns: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpPatternConfig {
    pub id: String,
    pub name: String,
    pub regex: String,
    pub severity: String,
    pub data_type: String,

    /// Per-pattern mode override. If absent, inherits from the global DLP mode.
    #[serde(default)]
    pub mode: Option<String>,

    #[serde(default)]
    pub description: Option<String>,

    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl DlpPatternConfig {
    pub fn validate(&self, idx: usize) -> Result<(), ConfigError> {
        let prefix = format!("dlp.patterns[{idx}]");

        if self.id.is_empty() {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.id"),
                message: "pattern ID must not be empty".to_string(),
            });
        }

        if self.regex.is_empty() {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.regex"),
                message: "regex must not be empty".to_string(),
            });
        }

        if self.name.is_empty() {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.name"),
                message: "pattern name must not be empty".to_string(),
            });
        }

        if self.data_type.is_empty() {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.data_type"),
                message: "data_type must not be empty".to_string(),
            });
        }

        parse_severity(&self.severity).map_err(|()| ConfigError::InvalidValue {
            field: format!("{prefix}.severity"),
            value: self.severity.clone(),
            expected: "low, medium, high, critical".to_string(),
        })?;

        if let Some(ref mode) = self.mode {
            parse_domain_mode(mode)?;
        }

        // Validate that the regex compiles (with ReDoS prevention limits)
        validate_regex(&self.regex, &format!("{prefix}.regex"))?;

        Ok(())
    }

    pub fn to_domain_pattern(&self, global_mode: &str) -> Result<DlpPattern, ConfigError> {
        let severity = parse_severity(&self.severity).map_err(|()| ConfigError::InvalidValue {
            field: "severity".to_string(),
            value: self.severity.clone(),
            expected: "low, medium, high, critical".to_string(),
        })?;

        let mode_str = self.mode.as_deref().unwrap_or(global_mode);
        let mode = parse_domain_mode(mode_str)?;

        Ok(DlpPattern {
            id: RuleId(self.id.clone()),
            name: self.name.clone(),
            regex: self.regex.clone(),
            severity,
            mode,
            data_type: self.data_type.clone(),
            description: self.description.clone().unwrap_or_default(),
            enabled: self.enabled,
        })
    }
}
