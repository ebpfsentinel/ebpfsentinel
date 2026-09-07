//! Manual response-action bounds.
//!
//! `POST /api/v1/response` takes a TTL from the caller, and the response
//! engine refuses anything above its ceiling. That ceiling lives here so it
//! is a documented key with a default rather than a literal at wire-up time.
//!
//! This is not the auto-response block: `auto_response` decides whether an
//! action fires on its own when an alert matches a policy and carries its own
//! per-policy TTL. The ceiling here applies to every response action the
//! agent installs, whoever asked for it.

use serde::{Deserialize, Serialize};

use super::ConfigError;

/// Default ceiling on a response action's TTL, in seconds.
pub const DEFAULT_MAX_RESPONSE_TTL_SECS: u64 = 86_400;

/// Highest ceiling a configuration may set, in seconds. A response action is
/// a temporary measure that a firewall rule should replace, so the bound is
/// thirty days rather than open-ended.
pub const MAX_RESPONSE_TTL_CEILING_SECS: u64 = 2_592_000;

/// Manual response-action configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ResponseConfig {
    /// Longest TTL the agent accepts on a response action, in seconds. A
    /// request above this is refused rather than clamped.
    pub max_ttl_secs: u64,
}

impl Default for ResponseConfig {
    fn default() -> Self {
        Self {
            max_ttl_secs: DEFAULT_MAX_RESPONSE_TTL_SECS,
        }
    }
}

impl ResponseConfig {
    /// Validate the response block.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.max_ttl_secs == 0 {
            return Err(ConfigError::Validation {
                field: "response.max_ttl_secs".to_string(),
                message: "must be at least 1 second".to_string(),
            });
        }
        if self.max_ttl_secs > MAX_RESPONSE_TTL_CEILING_SECS {
            return Err(ConfigError::Validation {
                field: "response.max_ttl_secs".to_string(),
                message: format!(
                    "{} exceeds the maximum of {MAX_RESPONSE_TTL_CEILING_SECS} seconds",
                    self.max_ttl_secs
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
    fn the_default_ceiling_is_twenty_four_hours() {
        assert_eq!(ResponseConfig::default().max_ttl_secs, 86_400);
        assert!(ResponseConfig::default().validate().is_ok());
    }

    #[test]
    fn a_ceiling_of_zero_is_refused() {
        let cfg = ResponseConfig { max_ttl_secs: 0 };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn a_ceiling_past_the_hard_bound_is_refused() {
        let cfg = ResponseConfig {
            max_ttl_secs: MAX_RESPONSE_TTL_CEILING_SECS + 1,
        };
        assert!(cfg.validate().is_err());
        let cfg = ResponseConfig {
            max_ttl_secs: MAX_RESPONSE_TTL_CEILING_SECS,
        };
        assert!(cfg.validate().is_ok());
    }
}
