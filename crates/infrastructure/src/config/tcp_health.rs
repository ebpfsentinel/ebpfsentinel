//! TCP health per edge: retransmissions, resets and connections opened,
//! failed and closed, counted by the TCP stack's own tracepoints.
//!
//! On by default. Each hook fires on an event the stack already handles
//! slowly - a retransmission, a reset, a state change - so it costs a
//! connection a handful of map updates over its life and costs a segment
//! delivered in order nothing.

use serde::{Deserialize, Serialize};

use super::ConfigError;

const DEFAULT_POLL_INTERVAL_SECS: u64 = 10;
const MAX_POLL_INTERVAL_SECS: u64 = 3_600;

/// The TCP health counter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TcpHealthConfig {
    /// Whether the counter is loaded.
    pub enabled: bool,

    /// How often the counts are read into the metrics, in
    /// seconds.
    pub poll_interval_secs: u64,
}

impl Default for TcpHealthConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            poll_interval_secs: DEFAULT_POLL_INTERVAL_SECS,
        }
    }
}

impl TcpHealthConfig {
    /// Checks the block hard enough that a wrong one fails at boot.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Validation`] when the interval is zero or
    /// longer than an hour.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.poll_interval_secs == 0 || self.poll_interval_secs > MAX_POLL_INTERVAL_SECS {
            return Err(ConfigError::Validation {
                field: "tcp_health.poll_interval_secs".to_string(),
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
        let config = TcpHealthConfig::default();
        assert!(config.enabled);
        assert_eq!(config.poll_interval_secs, 10);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn an_interval_out_of_range_is_refused() {
        for secs in [0, MAX_POLL_INTERVAL_SECS + 1] {
            let config = TcpHealthConfig {
                poll_interval_secs: secs,
                ..TcpHealthConfig::default()
            };
            assert!(config.validate().is_err());
        }
    }
}
