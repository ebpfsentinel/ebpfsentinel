//! Management metadata block for the agent.
//!
//! Surfaces two pieces of information to the dashboard:
//!
//! - `operator_managed` — when `true`, the agent's configuration is
//!   reconciled by the Kubernetes operator (CRD-driven). The dashboard
//!   uses this flag to lock its config-edit UI on this agent and prevent
//!   two-way drift between the dashboard and the operator's source of
//!   truth.
//! - `operator_endpoint` — optional URL the operator exposes (typically
//!   a Kubernetes-native UI). The dashboard deep-links to it from the
//!   "this agent is operator-managed" badge.
//!
//! Both fields are read-only and benign: no behaviour changes inside the
//! agent based on these values.

use serde::{Deserialize, Serialize};

use super::ConfigError;

/// Management metadata exposed via `GET /api/v1/agent/identity`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ManagementConfig {
    /// `true` when the agent is reconciled by the Kubernetes operator.
    pub operator_managed: bool,

    /// Optional URL the operator exposes (Kubernetes-native UI or the
    /// operator's own web admin). Validated as a parseable URL with an
    /// `http` or `https` scheme.
    pub operator_endpoint: Option<String>,
}

impl ManagementConfig {
    /// Validate the management block. Rejects malformed URLs and
    /// non-HTTP(S) schemes so the dashboard can safely deep-link.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if let Some(url) = self.operator_endpoint.as_deref() {
            validate_http_url("management.operator_endpoint", url)?;
        }
        Ok(())
    }
}

/// Reject anything that is not a parseable absolute URL with an
/// `http` or `https` scheme, a non-empty host, and no inline whitespace.
fn validate_http_url(field: &str, value: &str) -> Result<(), ConfigError> {
    if value.chars().any(char::is_whitespace) {
        return Err(ConfigError::Validation {
            field: field.to_string(),
            message: format!("URL must not contain whitespace, got {value:?}"),
        });
    }
    let scheme_split = value
        .split_once("://")
        .ok_or_else(|| ConfigError::Validation {
            field: field.to_string(),
            message: format!("URL must be absolute (`http://` or `https://`), got {value:?}"),
        })?;
    let (scheme, rest) = scheme_split;
    if !matches!(scheme, "http" | "https") {
        return Err(ConfigError::Validation {
            field: field.to_string(),
            message: format!("URL scheme must be `http` or `https`, got `{scheme}` in {value:?}"),
        });
    }
    let host_end = rest.find(['/', '?', '#']).map_or(rest.len(), |idx| idx);
    let host = &rest[..host_end];
    if host.is_empty() {
        return Err(ConfigError::Validation {
            field: field.to_string(),
            message: format!("URL must have a non-empty host, got {value:?}"),
        });
    }
    if host.chars().any(|c| !is_host_char(c)) {
        return Err(ConfigError::Validation {
            field: field.to_string(),
            message: format!("URL host contains invalid characters, got {value:?}"),
        });
    }
    Ok(())
}

#[inline]
fn is_host_char(c: char) -> bool {
    matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '-' | ':' | '[' | ']' | '_')
}

#[cfg(test)]
mod tests {
    use super::ManagementConfig;
    use crate::config::ConfigError;

    #[test]
    fn default_is_unmanaged_with_no_endpoint() {
        let cfg = ManagementConfig::default();
        assert!(!cfg.operator_managed);
        assert!(cfg.operator_endpoint.is_none());
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn deserialise_default_when_block_absent() {
        let parsed: Option<ManagementConfig> = serde_yaml_ng::from_str("").unwrap();
        assert!(parsed.is_none() || parsed == Some(ManagementConfig::default()));
    }

    #[test]
    fn deserialise_explicit_block() {
        let yaml = "operator_managed: true\noperator_endpoint: https://operator.example.com\n";
        let cfg: ManagementConfig = serde_yaml_ng::from_str(yaml).unwrap();
        assert!(cfg.operator_managed);
        assert_eq!(
            cfg.operator_endpoint.as_deref(),
            Some("https://operator.example.com")
        );
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn rejects_unknown_fields() {
        let yaml = "operator_managed: true\nrogue_field: 1\n";
        let err = serde_yaml_ng::from_str::<ManagementConfig>(yaml).unwrap_err();
        assert!(err.to_string().contains("rogue_field"));
    }

    #[test]
    fn rejects_non_http_scheme() {
        let cfg = ManagementConfig {
            operator_managed: true,
            operator_endpoint: Some("ftp://operator.example.com".to_string()),
        };
        let err = cfg.validate().unwrap_err();
        match err {
            ConfigError::Validation {
                ref field,
                ref message,
            } => {
                assert_eq!(field, "management.operator_endpoint");
                assert!(message.contains("http"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn rejects_relative_url() {
        let cfg = ManagementConfig {
            operator_managed: true,
            operator_endpoint: Some("/operator".to_string()),
        };
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::Validation { ref field, .. }) if field == "management.operator_endpoint"
        ));
    }

    #[test]
    fn rejects_url_with_whitespace() {
        let cfg = ManagementConfig {
            operator_managed: true,
            operator_endpoint: Some("https://operator example.com".to_string()),
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_empty_host() {
        let cfg = ManagementConfig {
            operator_managed: true,
            operator_endpoint: Some("https:///path".to_string()),
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn accepts_url_with_port_and_path() {
        let cfg = ManagementConfig {
            operator_managed: true,
            operator_endpoint: Some("https://operator.example.com:9443/ui".to_string()),
        };
        assert!(cfg.validate().is_ok());
    }
}
