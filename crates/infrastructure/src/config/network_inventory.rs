//! Listing who else reads the node's traffic: every packet socket open on
//! the node, with the process holding it and the filter attached to it.
//!
//! On by default. A reading walks `/proc` and asks the kernel for each
//! namespace's packet sockets, which costs one directory walk per interval
//! and nothing on the packet path.

use serde::{Deserialize, Serialize};

use super::ConfigError;

const DEFAULT_INTERVAL_SECS: u64 = 30;
const MAX_INTERVAL_SECS: u64 = 3_600;

/// The inventory of the node's packet sockets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct NetworkInventoryConfig {
    /// Whether the inventory is read at all.
    pub enabled: bool,

    /// How often the sockets are read, in seconds. A socket opened and
    /// closed between two readings is never seen.
    pub interval_secs: u64,
}

impl Default for NetworkInventoryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: DEFAULT_INTERVAL_SECS,
        }
    }
}

impl NetworkInventoryConfig {
    /// Checks the block hard enough that a wrong one fails at boot.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Validation`] when the interval is zero or
    /// longer than an hour.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.interval_secs == 0 || self.interval_secs > MAX_INTERVAL_SECS {
            return Err(ConfigError::Validation {
                field: "network_inventory.interval_secs".to_string(),
                message: format!("must be between 1 and {MAX_INTERVAL_SECS} seconds"),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn on_by_default_and_read_every_thirty_seconds() {
        let config = NetworkInventoryConfig::default();
        assert!(config.enabled);
        assert_eq!(config.interval_secs, 30);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn an_interval_out_of_range_is_refused() {
        for secs in [0, MAX_INTERVAL_SECS + 1] {
            let config = NetworkInventoryConfig {
                interval_secs: secs,
                ..NetworkInventoryConfig::default()
            };
            assert!(config.validate().is_err());
        }
    }
}
