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

/// Default number of days a capture file is kept.
pub const DEFAULT_CAPTURE_RETENTION_DAYS: u32 = 7;

/// Highest retention a configuration may set, in days. A year of captures is
/// an archive, which is a thing to copy off the node rather than to keep in
/// the agent's state directory.
pub const MAX_CAPTURE_RETENTION_DAYS: u32 = 365;

/// Default ceiling on everything the capture directory holds, in megabytes.
/// One capture at the default duration and snap length is well under this, so
/// the ceiling is what stops a node that captures often rather than what
/// bounds a single capture.
pub const DEFAULT_CAPTURE_MAX_TOTAL_MB: u64 = 1024;

/// Highest total-size ceiling a configuration may set, in megabytes.
pub const MAX_CAPTURE_TOTAL_MB: u64 = 1_048_576;

/// Manual packet-capture configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct CaptureConfig {
    /// Longest capture the agent accepts, in seconds. A request above this
    /// is refused rather than clamped.
    pub max_duration_secs: u64,
    /// How many days a capture file is kept. `0` keeps every file for ever,
    /// which is what the agent did before there was a sweep.
    pub retention_days: u32,
    /// How much room every capture file together may take, in megabytes. `0`
    /// is no ceiling. A sweep deletes the oldest files first until the total
    /// fits, and never the capture that is still writing.
    pub max_total_size_mb: u64,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            max_duration_secs: DEFAULT_MAX_CAPTURE_DURATION_SECS,
            retention_days: DEFAULT_CAPTURE_RETENTION_DAYS,
            max_total_size_mb: DEFAULT_CAPTURE_MAX_TOTAL_MB,
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
        if self.retention_days > MAX_CAPTURE_RETENTION_DAYS {
            return Err(ConfigError::Validation {
                field: "capture.retention_days".to_string(),
                message: format!(
                    "{} exceeds the maximum of {MAX_CAPTURE_RETENTION_DAYS} days",
                    self.retention_days
                ),
            });
        }
        if self.max_total_size_mb > MAX_CAPTURE_TOTAL_MB {
            return Err(ConfigError::Validation {
                field: "capture.max_total_size_mb".to_string(),
                message: format!(
                    "{} exceeds the maximum of {MAX_CAPTURE_TOTAL_MB} MB",
                    self.max_total_size_mb
                ),
            });
        }
        Ok(())
    }

    /// The retention policy these keys describe.
    #[must_use]
    pub fn retention(&self) -> domain::capture::retention::RetentionPolicy {
        domain::capture::retention::RetentionPolicy::new(
            self.retention_days,
            self.max_total_size_mb,
        )
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
            ..CaptureConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn a_ceiling_past_the_hard_bound_is_refused() {
        let cfg = CaptureConfig {
            max_duration_secs: MAX_CAPTURE_DURATION_CEILING_SECS + 1,
            ..CaptureConfig::default()
        };
        assert!(cfg.validate().is_err());
        let cfg = CaptureConfig {
            max_duration_secs: MAX_CAPTURE_DURATION_CEILING_SECS,
            ..CaptureConfig::default()
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn the_defaults_keep_a_week_and_a_gigabyte() {
        let cfg = CaptureConfig::default();
        assert_eq!(cfg.retention_days, 7);
        assert_eq!(cfg.max_total_size_mb, 1024);
        let policy = cfg.retention();
        assert_eq!(policy.max_age_secs(), Some(7 * 86_400));
        assert_eq!(policy.max_total_bytes(), Some(1024 * 1024 * 1024));
    }

    #[test]
    fn both_limits_may_be_turned_off() {
        let cfg = CaptureConfig {
            retention_days: 0,
            max_total_size_mb: 0,
            ..CaptureConfig::default()
        };
        assert!(cfg.validate().is_ok());
        assert_eq!(cfg.retention().max_age_secs(), None);
        assert_eq!(cfg.retention().max_total_bytes(), None);
    }

    #[test]
    fn a_retention_past_a_year_is_refused() {
        let cfg = CaptureConfig {
            retention_days: MAX_CAPTURE_RETENTION_DAYS + 1,
            ..CaptureConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn a_ceiling_past_the_hard_total_is_refused() {
        let cfg = CaptureConfig {
            max_total_size_mb: MAX_CAPTURE_TOTAL_MB + 1,
            ..CaptureConfig::default()
        };
        assert!(cfg.validate().is_err());
    }
}
