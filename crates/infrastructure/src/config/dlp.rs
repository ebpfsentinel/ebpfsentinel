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

    #[serde(default)]
    pub scope: DlpScopeConfig,
}

impl Default for DlpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: "alert".to_string(),
            patterns: Vec::new(),
            scope: DlpScopeConfig::default(),
        }
    }
}

/// Which cgroups the DLP probes may read plaintext from.
///
/// A uprobe belongs to an inode, so one `libssl` layer shared by every
/// container on the node arms one probe that fires for all of them. On a host
/// that is the point; on a shared node it means the agent reads a neighbour's
/// plaintext, so the scope is a deliberate choice rather than a default.
///
/// * `all` - every task on the node, which is what a host agent does.
/// * `workloads` - only tasks under one of `cgroups`, enforced in the probe.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DlpScopeConfig {
    #[serde(default = "default_scope_mode")]
    pub mode: String,

    /// cgroup v2 paths, relative to `container.resolver.cgroup_root`, whose
    /// tasks are in scope. A path covers everything below it, so naming a pod
    /// slice covers its containers without listing ids that change on restart.
    #[serde(default)]
    pub cgroups: Vec<String>,
}

impl Default for DlpScopeConfig {
    fn default() -> Self {
        Self {
            mode: default_scope_mode(),
            cgroups: Vec::new(),
        }
    }
}

fn default_scope_mode() -> String {
    DLP_SCOPE_ALL.to_string()
}

/// Scope mode reading every task on the node.
pub const DLP_SCOPE_ALL: &str = "all";
/// Scope mode reading only the configured cgroups.
pub const DLP_SCOPE_WORKLOADS: &str = "workloads";

impl DlpScopeConfig {
    /// Whether the probes filter on cgroup.
    #[must_use]
    pub fn is_workload_scoped(&self) -> bool {
        self.mode == DLP_SCOPE_WORKLOADS
    }

    /// Validate the scope block.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown mode, for `workloads` with no cgroup
    /// listed - which would arm the probes and discard every event, reading as
    /// DLP being on while nothing is inspected - or for a path that is empty or
    /// escapes the cgroup root.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.mode != DLP_SCOPE_ALL && self.mode != DLP_SCOPE_WORKLOADS {
            return Err(ConfigError::InvalidValue {
                field: "dlp.scope.mode".to_string(),
                value: self.mode.clone(),
                expected: format!("{DLP_SCOPE_ALL}, {DLP_SCOPE_WORKLOADS}"),
            });
        }

        if self.mode == DLP_SCOPE_ALL {
            if !self.cgroups.is_empty() {
                return Err(ConfigError::Validation {
                    field: "dlp.scope.cgroups".to_string(),
                    message: format!(
                        "cgroups are listed but mode is '{DLP_SCOPE_ALL}', which ignores them; \
                         set mode to '{DLP_SCOPE_WORKLOADS}'"
                    ),
                });
            }
            return Ok(());
        }

        if self.cgroups.is_empty() {
            return Err(ConfigError::Validation {
                field: "dlp.scope.cgroups".to_string(),
                message: format!(
                    "mode '{DLP_SCOPE_WORKLOADS}' needs at least one cgroup path; an empty \
                     list arms the probes and drops every event"
                ),
            });
        }

        for (idx, path) in self.cgroups.iter().enumerate() {
            let field = format!("dlp.scope.cgroups[{idx}]");
            if path.trim().is_empty() {
                return Err(ConfigError::Validation {
                    field,
                    message: "cgroup path must not be empty".to_string(),
                });
            }
            if path.split('/').any(|seg| seg == "..") {
                return Err(ConfigError::Validation {
                    field,
                    message: "cgroup path must not escape the cgroup root with '..'".to_string(),
                });
            }
        }

        Ok(())
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
        assert_eq!(cfg.scope.mode, DLP_SCOPE_ALL);
        assert!(!cfg.scope.is_workload_scoped());
    }

    #[test]
    fn scope_all_with_no_cgroup_is_valid() {
        assert!(DlpScopeConfig::default().validate().is_ok());
    }

    #[test]
    fn scope_rejects_an_unknown_mode() {
        let scope = DlpScopeConfig {
            mode: "pods".to_string(),
            cgroups: Vec::new(),
        };
        assert!(scope.validate().is_err());
    }

    #[test]
    fn scope_workloads_without_a_cgroup_is_refused() {
        let scope = DlpScopeConfig {
            mode: DLP_SCOPE_WORKLOADS.to_string(),
            cgroups: Vec::new(),
        };
        assert!(scope.validate().is_err());
    }

    #[test]
    fn scope_all_with_cgroups_listed_is_refused() {
        let scope = DlpScopeConfig {
            mode: DLP_SCOPE_ALL.to_string(),
            cgroups: vec!["/kubepods.slice".to_string()],
        };
        assert!(scope.validate().is_err());
    }

    #[test]
    fn scope_rejects_a_path_escaping_the_cgroup_root() {
        let scope = DlpScopeConfig {
            mode: DLP_SCOPE_WORKLOADS.to_string(),
            cgroups: vec!["../../etc".to_string()],
        };
        assert!(scope.validate().is_err());
    }

    #[test]
    fn scope_workloads_with_a_pod_slice_is_valid() {
        let scope = DlpScopeConfig {
            mode: DLP_SCOPE_WORKLOADS.to_string(),
            cgroups: vec![
                "kubepods.slice/kubepods-besteffort.slice".to_string(),
                "/system.slice/docker-abc.scope".to_string(),
            ],
        };
        assert!(scope.validate().is_ok());
        assert!(scope.is_workload_scoped());
    }

    #[test]
    fn valid_pattern_deserialization() {
        let yaml = r"
id: pat-1
name: Credit Card
regex: '\d{4}-\d{4}-\d{4}-\d{4}'
severity: high
data_type: pci
";
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
