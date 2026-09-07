//! Manual packet-capture bounds.
//!
//! `POST /api/v1/capture` takes a duration from the caller, and the capture
//! engine refuses anything above its ceiling. That ceiling lives here so it
//! is a documented key with a default rather than a literal at wire-up time.
//!
//! This is not the auto-capture block: `auto_capture` decides whether a PCAP
//! starts on its own when an alert fires and carries its own, tighter, OSS
//! duration cap. The ceiling here applies to every capture the agent runs,
//! whoever asked for it.

use serde::{Deserialize, Serialize};

use super::ConfigError;

/// Default ceiling on a single capture, in seconds.
pub const DEFAULT_MAX_CAPTURE_DURATION_SECS: u64 = 300;

/// Highest ceiling a configuration may set, in seconds. A capture holds a
/// socket and writes to disk for its whole duration, so the bound is an hour
/// rather than open-ended.
pub const MAX_CAPTURE_DURATION_CEILING_SECS: u64 = 3600;

/// Manual packet-capture configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct CaptureConfig {
    /// Longest capture the agent accepts, in seconds. A request above this
    /// is refused rather than clamped.
    pub max_duration_secs: u64,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            max_duration_secs: DEFAULT_MAX_CAPTURE_DURATION_SECS,
        }
    }
}

impl CaptureConfig {
    /// Validate the capture block.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.max_duration_secs == 0 {
            return Err(ConfigError::Validation {
                field: "capture.max_duration_secs".to_string(),
                message: "must be at least 1 second".to_string(),
            });
        }
        if self.max_duration_secs > MAX_CAPTURE_DURATION_CEILING_SECS {
            return Err(ConfigError::Validation {
                field: "capture.max_duration_secs".to_string(),
                message: format!(
                    "{} exceeds the maximum of {MAX_CAPTURE_DURATION_CEILING_SECS} seconds",
                    self.max_duration_secs
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
    fn the_default_ceiling_is_five_minutes() {
        assert_eq!(CaptureConfig::default().max_duration_secs, 300);
        assert!(CaptureConfig::default().validate().is_ok());
    }

    #[test]
    fn a_ceiling_of_zero_is_refused() {
        let cfg = CaptureConfig {
            max_duration_secs: 0,
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn a_ceiling_past_the_hard_bound_is_refused() {
        let cfg = CaptureConfig {
            max_duration_secs: MAX_CAPTURE_DURATION_CEILING_SECS + 1,
        };
        assert!(cfg.validate().is_err());
        let cfg = CaptureConfig {
            max_duration_secs: MAX_CAPTURE_DURATION_CEILING_SECS,
        };
        assert!(cfg.validate().is_ok());
    }
}
