use serde::{Deserialize, Serialize};

use super::ConfigError;

const DEFAULT_INTERVAL_SECS: u64 = 900;
const MIN_INTERVAL_SECS: u64 = 60;
const MAX_INTERVAL_SECS: u64 = 86_400;

/// What the package managers say is installed, read in every root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PackageInventoryConfig {
    /// Whether the databases are read at all.
    pub enabled: bool,

    /// How often every root is read, in seconds. A database that has not
    /// changed since the last sweep is only looked at, not read again.
    pub interval_secs: u64,
}

impl Default for PackageInventoryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: DEFAULT_INTERVAL_SECS,
        }
    }
}

impl PackageInventoryConfig {
    /// Checks the block hard enough that a wrong one fails at boot.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Validation`] when the interval is out of range.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !(MIN_INTERVAL_SECS..=MAX_INTERVAL_SECS).contains(&self.interval_secs) {
            return Err(ConfigError::Validation {
                field: "package_inventory.interval_secs".to_string(),
                message: format!(
                    "must be between {MIN_INTERVAL_SECS} and {MAX_INTERVAL_SECS} seconds"
                ),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn on_by_default_every_fifteen_minutes() {
        let config = PackageInventoryConfig::default();
        assert!(config.enabled);
        assert_eq!(config.interval_secs, 900);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn an_interval_out_of_range_fails_at_boot() {
        for interval_secs in [0, 59, 86_401] {
            let config = PackageInventoryConfig {
                interval_secs,
                ..PackageInventoryConfig::default()
            };
            assert!(config.validate().is_err(), "{interval_secs}");
        }
    }

    #[test]
    fn an_unknown_key_is_refused() {
        assert!(serde_norway::from_str::<PackageInventoryConfig>("enable: false").is_err());
    }
}
