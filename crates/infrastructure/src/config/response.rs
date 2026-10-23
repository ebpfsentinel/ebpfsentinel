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

/// Highest signal number a configuration may name. Real-time signals go up to
/// 64 on Linux, and anything above that is a typo rather than a choice.
pub const MAX_SIGNAL_NUMBER: u32 = 64;

/// Longest a target may stay armed, in milliseconds. The arming is held for a
/// single decision, so a window measured in minutes would be a standing
/// licence to kill rather than one action.
pub const MAX_KILL_WINDOW_MS: u64 = 30_000;

/// Stopping the process behind a flow.
///
/// Off by default, and off is the only safe default: a rule that terminates a
/// production process is a rule whose blast radius an operator has to have
/// read first. Turning it on arms nothing by itself either - the capability
/// becomes reachable, and an action still has to ask for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct KillProcessConfig {
    /// Whether the signal program is loaded at all.
    pub enabled: bool,
    /// The signal sent. 9 cannot be caught or ignored; 15 can, which is why it
    /// is not the default for an action an operator armed deliberately.
    pub signal: u32,
    /// How long the kernel keeps looking for the target, in milliseconds. A
    /// process that makes no syscall in that time is reported as a survivor.
    pub window_ms: u64,
    /// Executable names that are never signalled, whatever a rule says. Added
    /// to the list the agent holds in code: this key can widen the protection
    /// and has no way to narrow it.
    pub protected_commands: Vec<String>,
    /// Thread group ids that are never signalled. The kernel holds these by
    /// number, so they are refused inside the probe and not only above it.
    pub protected_pids: Vec<u32>,
}

impl Default for KillProcessConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            signal: 9,
            window_ms: 2_000,
            protected_commands: Vec::new(),
            protected_pids: Vec::new(),
        }
    }
}

impl KillProcessConfig {
    /// Validate the kill-process block.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.signal == 0 || self.signal > MAX_SIGNAL_NUMBER {
            return Err(ConfigError::Validation {
                field: "response.kill_process.signal".to_string(),
                message: format!("must be between 1 and {MAX_SIGNAL_NUMBER}"),
            });
        }
        if self.window_ms == 0 || self.window_ms > MAX_KILL_WINDOW_MS {
            return Err(ConfigError::Validation {
                field: "response.kill_process.window_ms".to_string(),
                message: format!("must be between 1 and {MAX_KILL_WINDOW_MS}"),
            });
        }
        if self.protected_commands.iter().any(|c| c.trim().is_empty()) {
            return Err(ConfigError::Validation {
                field: "response.kill_process.protected_commands".to_string(),
                message: "an empty name protects nothing and hides a typo".to_string(),
            });
        }
        if self.protected_pids.contains(&0) {
            return Err(ConfigError::Validation {
                field: "response.kill_process.protected_pids".to_string(),
                message: "0 is not a thread group id".to_string(),
            });
        }
        Ok(())
    }
}

/// Manual response-action configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ResponseConfig {
    /// Longest TTL the agent accepts on a response action, in seconds. A
    /// request above this is refused rather than clamped.
    pub max_ttl_secs: u64,
    /// Stopping the process behind a flow.
    pub kill_process: KillProcessConfig,
}

impl Default for ResponseConfig {
    fn default() -> Self {
        Self {
            max_ttl_secs: DEFAULT_MAX_RESPONSE_TTL_SECS,
            kill_process: KillProcessConfig::default(),
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
        self.kill_process.validate()
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
        let cfg = ResponseConfig {
            max_ttl_secs: 0,
            ..ResponseConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn a_ceiling_past_the_hard_bound_is_refused() {
        let cfg = ResponseConfig {
            max_ttl_secs: MAX_RESPONSE_TTL_CEILING_SECS + 1,
            ..ResponseConfig::default()
        };
        assert!(cfg.validate().is_err());
        let cfg = ResponseConfig {
            max_ttl_secs: MAX_RESPONSE_TTL_CEILING_SECS,
            ..ResponseConfig::default()
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn stopping_a_process_is_off_until_it_is_turned_on() {
        let cfg = KillProcessConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.signal, 9);
        assert!(cfg.protected_commands.is_empty());
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn a_signal_number_no_kernel_has_is_refused() {
        for signal in [0, MAX_SIGNAL_NUMBER + 1, 1_000] {
            let cfg = KillProcessConfig {
                signal,
                ..KillProcessConfig::default()
            };
            match cfg.validate() {
                Ok(()) => panic!("signal {signal} must be refused"),
                Err(e) => assert!(e.to_string().contains("kill_process.signal")),
            }
        }
    }

    #[test]
    fn an_arming_window_is_bounded_at_both_ends() {
        let cfg = KillProcessConfig {
            window_ms: 0,
            ..KillProcessConfig::default()
        };
        assert!(cfg.validate().is_err());
        let cfg = KillProcessConfig {
            window_ms: MAX_KILL_WINDOW_MS + 1,
            ..KillProcessConfig::default()
        };
        assert!(cfg.validate().is_err());
        let cfg = KillProcessConfig {
            window_ms: MAX_KILL_WINDOW_MS,
            ..KillProcessConfig::default()
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn a_protected_entry_that_names_nothing_is_refused() {
        let cfg = KillProcessConfig {
            protected_commands: vec!["  ".to_string()],
            ..KillProcessConfig::default()
        };
        assert!(cfg.validate().is_err());
        let cfg = KillProcessConfig {
            protected_pids: vec![0],
            ..KillProcessConfig::default()
        };
        assert!(cfg.validate().is_err());
    }
}
