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

#[cfg(test)]
mod tests {
    use super::*;
    use domain::common::entity::{DomainMode, Severity};

    fn valid_pattern_config() -> DlpPatternConfig {
        DlpPatternConfig {
            id: "pat-1".to_string(),
            name: "Credit Card".to_string(),
            regex: r"\d{4}-\d{4}-\d{4}-\d{4}".to_string(),
            severity: "high".to_string(),
            data_type: "pci".to_string(),
            mode: None,
            description: Some("CC pattern".to_string()),
            enabled: true,
        }
    }

    #[test]
    fn default_config() {
        let cfg = DlpConfig::default();
        assert!(cfg.enabled);
        assert_eq!(cfg.mode, "alert");
        assert!(cfg.patterns.is_empty());
    }

    #[test]
    fn valid_pattern_deserialization() {
        let yaml = r#"
id: pat-1
name: Credit Card
regex: '\d{4}-\d{4}-\d{4}-\d{4}'
severity: high
data_type: pci
"#;
        let pattern: DlpPatternConfig = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(pattern.id, "pat-1");
        assert_eq!(pattern.name, "Credit Card");
        assert_eq!(pattern.data_type, "pci");
        assert!(pattern.enabled); // default
        assert!(pattern.mode.is_none()); // default
    }

    #[test]
    fn validate_empty_id_error() {
        let mut p = valid_pattern_config();
        p.id = String::new();
        let err = p.validate(0).unwrap_err();
        assert!(err.to_string().contains("id"), "error: {err}");
    }

    #[test]
    fn validate_empty_regex_error() {
        let mut p = valid_pattern_config();
        p.regex = String::new();
        let err = p.validate(0).unwrap_err();
        assert!(err.to_string().contains("regex"), "error: {err}");
    }

    #[test]
    fn validate_empty_name_error() {
        let mut p = valid_pattern_config();
        p.name = String::new();
        let err = p.validate(0).unwrap_err();
        assert!(err.to_string().contains("name"), "error: {err}");
    }

    #[test]
    fn validate_empty_data_type_error() {
        let mut p = valid_pattern_config();
        p.data_type = String::new();
        let err = p.validate(0).unwrap_err();
        assert!(err.to_string().contains("data_type"), "error: {err}");
    }

    #[test]
    fn validate_invalid_severity_error() {
        let mut p = valid_pattern_config();
        p.severity = "banana".to_string();
        let err = p.validate(0).unwrap_err();
        assert!(err.to_string().contains("severity"), "error: {err}");
    }

    #[test]
    fn validate_invalid_mode_error() {
        let mut p = valid_pattern_config();
        p.mode = Some("invalid_mode".to_string());
        let err = p.validate(0).unwrap_err();
        assert!(err.to_string().contains("mode"), "error: {err}");
    }

    #[test]
    fn validate_valid_pattern_passes() {
        let p = valid_pattern_config();
        assert!(p.validate(0).is_ok());
    }

    #[test]
    fn to_domain_pattern_global_mode_inheritance() {
        let p = valid_pattern_config();
        let domain = p.to_domain_pattern("alert").unwrap();
        assert_eq!(domain.id.0, "pat-1");
        assert_eq!(domain.name, "Credit Card");
        assert_eq!(domain.severity, Severity::High);
        assert_eq!(domain.mode, DomainMode::Alert);
        assert_eq!(domain.data_type, "pci");
        assert_eq!(domain.description, "CC pattern");
        assert!(domain.enabled);
    }

    #[test]
    fn to_domain_pattern_per_pattern_mode_override() {
        let mut p = valid_pattern_config();
        p.mode = Some("block".to_string());
        let domain = p.to_domain_pattern("alert").unwrap();
        assert_eq!(domain.mode, DomainMode::Block);
    }
}
