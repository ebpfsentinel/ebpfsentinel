//! Anonymous usage telemetry.
//!
//! On by default, and there are exactly two ways to switch it off: this block,
//! and `EBPFSENTINEL_TELEMETRY_DISABLE`, which exists because a container image
//! is often the only thing an operator can change.
//!
//! What it reports is fixed in `domain::telemetry`: a random installation
//! identifier, the agent version, and which eBPF programs are loaded. There is
//! no key here to widen that with, because widening it is a decision taken in
//! the domain rather than in somebody's configuration file.

use serde::{Deserialize, Serialize};

use super::ConfigError;

/// The environment variable that switches telemetry off.
///
/// Any value at all counts, including `0`: somebody who sets this variable has
/// said what they want, and reading their answer as a boolean is how "I set it
/// to 0 and it stayed on" happens.
pub const DISABLE_ENV: &str = "EBPFSENTINEL_TELEMETRY_DISABLE";

/// Where the installation identifier lives when nothing says otherwise.
const DEFAULT_STATE_PATH: &str = "/var/lib/ebpfsentinel/telemetry/installation";

/// Anonymous usage telemetry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TelemetryConfig {
    /// Whether this agent says it exists. On unless it is turned off.
    pub enabled: bool,

    /// Where the installation identifier is kept between restarts.
    pub state_path: String,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            state_path: DEFAULT_STATE_PATH.to_string(),
        }
    }
}

impl TelemetryConfig {
    /// Whether telemetry runs, taking the environment into account.
    ///
    /// The variable wins over the file, because the person setting it is
    /// usually the one who cannot edit the file.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.enabled && std::env::var_os(DISABLE_ENV).is_none()
    }

    /// Checks the block hard enough that a wrong one fails at boot.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Validation`] when the state path is empty or
    /// relative. A relative path would put the identifier wherever the agent
    /// happened to be started from, so a service restarted from a different
    /// directory would mint a new one and be counted twice.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let path = self.state_path.trim();

        if path.is_empty() {
            return Err(ConfigError::Validation {
                field: "telemetry.state_path".to_string(),
                message: "must not be empty".to_string(),
            });
        }

        if !path.starts_with('/') {
            return Err(ConfigError::Validation {
                field: "telemetry.state_path".to_string(),
                message: "must be an absolute path".to_string(),
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telemetry_is_on_unless_somebody_turns_it_off() {
        let config = TelemetryConfig::default();
        assert!(config.enabled);
        assert_eq!(config.state_path, DEFAULT_STATE_PATH);
    }

    #[test]
    fn the_config_file_can_turn_it_off() {
        let config = TelemetryConfig {
            enabled: false,
            ..TelemetryConfig::default()
        };
        assert!(!config.is_active());
    }

    #[test]
    fn a_relative_state_path_is_refused_at_boot() {
        // A relative path follows the working directory, so a service restarted
        // from elsewhere would mint a second identifier and be counted twice.
        let config = TelemetryConfig {
            state_path: "telemetry/installation".to_string(),
            ..TelemetryConfig::default()
        };
        assert!(config.validate().is_err());

        let empty = TelemetryConfig {
            state_path: String::new(),
            ..TelemetryConfig::default()
        };
        assert!(empty.validate().is_err());

        assert!(TelemetryConfig::default().validate().is_ok());
    }

    #[test]
    fn a_key_nobody_declared_is_refused_rather_than_ignored() {
        // `deny_unknown_fields` is what stops somebody thinking they widened
        // what is collected by writing a key into their config file.
        let refused: Result<TelemetryConfig, _> =
            serde_yaml_ng::from_str("enabled: true\nendpoint: https://elsewhere.test\n");
        assert!(refused.is_err());
    }
}
