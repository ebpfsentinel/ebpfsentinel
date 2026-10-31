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
const DEFAULT_SCAN_WINDOW_SECS: u64 = 60;
const MAX_SCAN_WINDOW_SECS: u64 = 3_600;
const DEFAULT_SCAN_RESETS: u64 = 100;

/// The TCP health counter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TcpHealthConfig {
    /// Whether the counter is loaded.
    pub enabled: bool,

    /// How often the counts are read into the metrics, in
    /// seconds.
    pub poll_interval_secs: u64,

    /// The alert raised for a source drawing resets faster than its line.
    pub reset_scan: ResetScanConfig,
}

/// A source drawing too many resets over a window raises a scan alert.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ResetScanConfig {
    /// Whether the alert is raised.
    pub enabled: bool,

    /// How long the resets of one source are summed over, in seconds.
    pub window_secs: u64,

    /// How many resets over the window a source may draw before the alert
    /// is raised. The Enterprise edition replaces this line with each
    /// source's own baseline once it has one, and uses it until then.
    pub resets: u64,
}

impl Default for ResetScanConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            window_secs: DEFAULT_SCAN_WINDOW_SECS,
            resets: DEFAULT_SCAN_RESETS,
        }
    }
}

impl Default for TcpHealthConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            poll_interval_secs: DEFAULT_POLL_INTERVAL_SECS,
            reset_scan: ResetScanConfig::default(),
        }
    }
}

impl TcpHealthConfig {
    /// Checks the block hard enough that a wrong one fails at boot.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Validation`] when the interval or the scan
    /// window is zero or longer than an hour, or the scan line is zero.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.poll_interval_secs == 0 || self.poll_interval_secs > MAX_POLL_INTERVAL_SECS {
            return Err(ConfigError::Validation {
                field: "tcp_health.poll_interval_secs".to_string(),
                message: format!("must be between 1 and {MAX_POLL_INTERVAL_SECS} seconds"),
            });
        }
        let scan = &self.reset_scan;
        if scan.window_secs == 0 || scan.window_secs > MAX_SCAN_WINDOW_SECS {
            return Err(ConfigError::Validation {
                field: "tcp_health.reset_scan.window_secs".to_string(),
                message: format!("must be between 1 and {MAX_SCAN_WINDOW_SECS} seconds"),
            });
        }
        if scan.resets == 0 {
            return Err(ConfigError::Validation {
                field: "tcp_health.reset_scan.resets".to_string(),
                message: "must be at least 1".to_string(),
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
        assert!(config.reset_scan.enabled);
        assert_eq!(config.reset_scan.window_secs, 60);
        assert_eq!(config.reset_scan.resets, 100);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn a_scan_line_out_of_range_is_refused() {
        for scan in [
            ResetScanConfig {
                window_secs: 0,
                ..ResetScanConfig::default()
            },
            ResetScanConfig {
                window_secs: MAX_SCAN_WINDOW_SECS + 1,
                ..ResetScanConfig::default()
            },
            ResetScanConfig {
                resets: 0,
                ..ResetScanConfig::default()
            },
        ] {
            let config = TcpHealthConfig {
                reset_scan: scan,
                ..TcpHealthConfig::default()
            };
            assert!(config.validate().is_err());
        }
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
