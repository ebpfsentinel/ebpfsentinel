//! DLP (Data Loss Prevention) domain configuration structs and conversion logic.

use domain::common::entity::RuleId;
use domain::dlp::entity::DlpPattern;
use domain::dlp::scope::{DlpScopePolicy, DlpScopeSelector};
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
/// * `workloads` - only tasks under one of `cgroups`, or matched by one of
///   `selectors`, enforced in the probe.
///
/// `mode` is also the answer for a workload no selector names, and it is
/// written down rather than inferred: a selector list is refused under `all`,
/// so a document that aims the fence has had to say that everything else is
/// outside it. An empty selector list leaves that same `mode` in charge, with
/// the configured `cgroups` as the whole of the scope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DlpScopeConfig {
    #[serde(default = "default_scope_mode")]
    pub mode: String,

    /// cgroup v2 paths, relative to `container.resolver.cgroup_root`, whose
    /// tasks are in scope. A path covers everything below it, so naming a pod
    /// slice covers its containers without listing ids that change on restart.
    #[serde(default)]
    pub cgroups: Vec<String>,

    /// Workload selectors, in the vocabulary the rest of the agent names a
    /// workload by: a tenant, a namespace, a pod, a container, a cgroup, a
    /// systemd unit or an executable, any combination of them narrowing
    /// together. Each is resolved against the workloads actually running and
    /// compiled into the same cgroup allow-list the probes read, so a pod
    /// that restarts under a new id stays in scope without the document
    /// changing.
    ///
    /// A selector carrying `action: exclude` takes a workload out whatever
    /// else matched it, which is how one tenant inside a selected namespace
    /// is kept unread.
    #[serde(default)]
    pub selectors: Vec<DlpScopeSelector>,

    /// How often the selectors are resolved against the workloads running,
    /// in seconds. A pod that starts between two passes is read from the
    /// pass that sees it and not before, so this is the width of the window
    /// in which a newly selected workload is not yet inspected.
    #[serde(default = "default_scope_refresh_seconds")]
    pub refresh_seconds: u64,
}

impl Default for DlpScopeConfig {
    fn default() -> Self {
        Self {
            mode: default_scope_mode(),
            cgroups: Vec::new(),
            selectors: Vec::new(),
            refresh_seconds: default_scope_refresh_seconds(),
        }
    }
}

fn default_scope_mode() -> String {
    DLP_SCOPE_ALL.to_string()
}

fn default_scope_refresh_seconds() -> u64 {
    15
}

/// The slowest refresh the scope accepts, an hour.
const DLP_SCOPE_REFRESH_MAX_SECONDS: u64 = 3_600;

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

    /// The selectors as the policy the resolver evaluates.
    ///
    /// # Errors
    ///
    /// Returns an error naming the offending selector, with the same
    /// refusals [`Self::validate`] documents.
    pub fn to_policy(&self) -> Result<DlpScopePolicy, ConfigError> {
        DlpScopePolicy::from_selectors(self.selectors.clone()).map_err(|err| {
            ConfigError::Validation {
                field: "dlp.scope.selectors".to_string(),
                message: err.to_string(),
            }
        })
    }

    /// Validate the scope block.
    ///
    /// # Errors
    ///
    /// Returns an error for a refresh interval of zero or longer than an
    /// hour, for an unknown mode, for `workloads` with neither a
    /// cgroup nor a selector - which would arm the probes and discard every
    /// event, reading as DLP being on while nothing is inspected - for a
    /// cgroup path that is empty or escapes the cgroup root, for a selector
    /// listed under mode `all`, which ignores it, and for a selector that
    /// names nothing or names it badly.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.refresh_seconds == 0 || self.refresh_seconds > DLP_SCOPE_REFRESH_MAX_SECONDS {
            return Err(ConfigError::InvalidValue {
                field: "dlp.scope.refresh_seconds".to_string(),
                value: self.refresh_seconds.to_string(),
                expected: format!("1..={DLP_SCOPE_REFRESH_MAX_SECONDS}"),
            });
        }

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
            if !self.selectors.is_empty() {
                return Err(ConfigError::Validation {
                    field: "dlp.scope.selectors".to_string(),
                    message: format!(
                        "selectors are listed but mode is '{DLP_SCOPE_ALL}', which reads every \
                         task on the node and ignores them; set mode to \
                         '{DLP_SCOPE_WORKLOADS}' to say that everything else is out of scope"
                    ),
                });
            }
            return Ok(());
        }

        if self.cgroups.is_empty() && self.selectors.is_empty() {
            return Err(ConfigError::Validation {
                field: "dlp.scope.cgroups".to_string(),
                message: format!(
                    "mode '{DLP_SCOPE_WORKLOADS}' needs at least one cgroup path or one \
                     selector; an empty scope arms the probes and drops every event"
                ),
            });
        }

        self.to_policy()?;

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
            selectors: Vec::new(),
            ..DlpScopeConfig::default()
        };
        assert!(scope.validate().is_err());
    }

    #[test]
    fn scope_workloads_without_a_cgroup_is_refused() {
        let scope = DlpScopeConfig {
            mode: DLP_SCOPE_WORKLOADS.to_string(),
            cgroups: Vec::new(),
            selectors: Vec::new(),
            ..DlpScopeConfig::default()
        };
        assert!(scope.validate().is_err());
    }

    #[test]
    fn scope_all_with_cgroups_listed_is_refused() {
        let scope = DlpScopeConfig {
            mode: DLP_SCOPE_ALL.to_string(),
            cgroups: vec!["/kubepods.slice".to_string()],
            selectors: Vec::new(),
            ..DlpScopeConfig::default()
        };
        assert!(scope.validate().is_err());
    }

    #[test]
    fn scope_rejects_a_path_escaping_the_cgroup_root() {
        let scope = DlpScopeConfig {
            mode: DLP_SCOPE_WORKLOADS.to_string(),
            cgroups: vec!["../../etc".to_string()],
            selectors: Vec::new(),
            ..DlpScopeConfig::default()
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
            selectors: Vec::new(),
            ..DlpScopeConfig::default()
        };
        assert!(scope.validate().is_ok());
        assert!(scope.is_workload_scoped());
    }

    #[test]
    fn scope_workloads_with_a_selector_and_no_cgroup_is_valid() {
        let scope = DlpScopeConfig {
            mode: DLP_SCOPE_WORKLOADS.to_string(),
            cgroups: Vec::new(),
            selectors: vec![DlpScopeSelector {
                name: Some("payments".to_string()),
                namespace: Some("payments".to_string()),
                ..DlpScopeSelector::default()
            }],
            ..DlpScopeConfig::default()
        };
        assert!(scope.validate().is_ok());
        assert_eq!(scope.to_policy().expect("a valid policy").len(), 1);
    }

    #[test]
    fn scope_all_with_selectors_listed_is_refused() {
        let scope = DlpScopeConfig {
            mode: DLP_SCOPE_ALL.to_string(),
            cgroups: Vec::new(),
            selectors: vec![DlpScopeSelector {
                namespace: Some("payments".to_string()),
                ..DlpScopeSelector::default()
            }],
            ..DlpScopeConfig::default()
        };
        let err = scope
            .validate()
            .expect_err("mode all reads the node and ignores a selector");
        assert!(err.to_string().contains("selectors"));
    }

    #[test]
    fn scope_refuses_a_selector_naming_nothing() {
        let scope = DlpScopeConfig {
            mode: DLP_SCOPE_WORKLOADS.to_string(),
            cgroups: Vec::new(),
            selectors: vec![DlpScopeSelector::default()],
            ..DlpScopeConfig::default()
        };
        assert!(scope.validate().is_err());
    }

    #[test]
    fn a_selector_reads_from_yaml_in_the_workload_vocabulary() {
        let yaml = r"
mode: workloads
selectors:
  - name: payments
    namespace: payments
  - action: exclude
    pod: vault-0
";
        let scope: DlpScopeConfig = serde_norway::from_str(yaml).expect("a readable scope");
        assert!(scope.validate().is_ok());
        let policy = scope.to_policy().expect("a valid policy");
        assert_eq!(policy.len(), 2);
        assert_eq!(policy.selectors()[1].action.as_str(), "exclude");
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
        let pattern: DlpPatternConfig = serde_norway::from_str(yaml).unwrap();
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
