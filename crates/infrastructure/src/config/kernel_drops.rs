//! Counting the packets the kernel drops, by the reason it gives.
//!
//! On by default. The counter hooks the kernel's own drop point, so it costs
//! every dropped packet a map update and costs a delivered packet nothing.

use serde::{Deserialize, Serialize};

use super::ConfigError;

const DEFAULT_POLL_INTERVAL_SECS: u64 = 10;
const MAX_POLL_INTERVAL_SECS: u64 = 3_600;

/// The kernel drop counter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct KernelDropsConfig {
    /// Whether the counter is loaded.
    pub enabled: bool,

    /// How often the counts are read into the metrics and the API, in
    /// seconds.
    pub poll_interval_secs: u64,
}

impl Default for KernelDropsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            poll_interval_secs: DEFAULT_POLL_INTERVAL_SECS,
        }
    }
}

impl KernelDropsConfig {
    /// Checks the block hard enough that a wrong one fails at boot.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Validation`] when the interval is zero or
    /// longer than an hour.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.poll_interval_secs == 0 || self.poll_interval_secs > MAX_POLL_INTERVAL_SECS {
            return Err(ConfigError::Validation {
                field: "kernel_drops.poll_interval_secs".to_string(),
                message: format!("must be between 1 and {MAX_POLL_INTERVAL_SECS} seconds"),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn on_by_default_and_read_every_ten_seconds() {
        let config = KernelDropsConfig::default();
        assert!(config.enabled);
        assert_eq!(config.poll_interval_secs, 10);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn an_interval_out_of_range_is_refused() {
        for secs in [0, MAX_POLL_INTERVAL_SECS + 1] {
            let config = KernelDropsConfig {
                poll_interval_secs: secs,
                ..KernelDropsConfig::default()
            };
            assert!(config.validate().is_err());
        }
    }
}
