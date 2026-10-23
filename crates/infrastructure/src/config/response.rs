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

/// Default length of a quarantine, in seconds.
pub const DEFAULT_QUARANTINE_WINDOW_SECS: u64 = 900;

/// Longest a quarantine may be configured to last, in seconds. A quarantine is
/// a response and not a policy, so it ends: a workload cut off for a week by an
/// automation nobody remembers arming is the outage this capability is most
/// likely to cause, and a permanent cut is a workload rule instead.
pub const MAX_QUARANTINE_WINDOW_SECS: u64 = 604_800;

/// Most conntrack rows one teardown may read. The walk resolves the owner of
/// each row, so an unbounded one would hold the quarantine up on a busy node
/// while the workload it is cutting off keeps sending.
pub const MAX_QUARANTINE_FLOWS_SCANNED: usize = 1_048_576;

/// Cutting a workload off the network without stopping it.
///
/// Off by default like every other response that reaches into a running
/// system, though the blast radius is narrower than stopping a process: the
/// workload stays up, keeps its memory and keeps serving anything that does
/// not need the network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct QuarantineConfig {
    /// Whether the capability is reachable at all.
    pub enabled: bool,
    /// How long a quarantine lasts when the caller names no window, in
    /// seconds.
    pub window_secs: u64,
    /// Longest window this node accepts. A request above it is clamped rather
    /// than refused, because a quarantine that is shorter than asked still
    /// cuts the workload off and a refused one does not.
    pub max_window_secs: u64,
    /// Whether to tear the workload's established flows down when arming.
    ///
    /// On by default: the hooks refuse what a workload opens next and have no
    /// say over a connection it already holds, so leaving this off means an
    /// exfiltration already in flight runs to completion.
    pub tear_down_flows: bool,
    /// How many conntrack rows one teardown reads.
    pub max_flows_scanned: usize,
    /// cgroup paths that are never quarantined, whatever a rule says. Added to
    /// the list the agent holds in code: this key can widen the protection and
    /// has no way to narrow it. Matched by whole path component, so naming a
    /// slice protects the tree under it.
    pub protected_paths: Vec<String>,
    /// cgroup ids that are never quarantined. For a cgroup whose path this
    /// node cannot read, which is the one case a path cannot fence.
    pub protected_ids: Vec<u64>,
    /// How often the lapsed entries are swept out of the map, in seconds.
    ///
    /// The kernel stops refusing at the deadline it was given whether or not
    /// this runs, so the sweep is what keeps the map from filling and what
    /// makes the listed quarantines the live ones.
    pub sweep_interval_secs: u64,
}

impl Default for QuarantineConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            window_secs: DEFAULT_QUARANTINE_WINDOW_SECS,
            max_window_secs: 86_400,
            tear_down_flows: true,
            max_flows_scanned: 65_536,
            protected_paths: Vec::new(),
            protected_ids: Vec::new(),
            sweep_interval_secs: 30,
        }
    }
}

impl QuarantineConfig {
    /// Validate the quarantine block.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.window_secs == 0 || self.window_secs > MAX_QUARANTINE_WINDOW_SECS {
            return Err(ConfigError::Validation {
                field: "response.quarantine.window_secs".to_string(),
                message: format!("must be between 1 and {MAX_QUARANTINE_WINDOW_SECS}"),
            });
        }
        if self.max_window_secs == 0 || self.max_window_secs > MAX_QUARANTINE_WINDOW_SECS {
            return Err(ConfigError::Validation {
                field: "response.quarantine.max_window_secs".to_string(),
                message: format!("must be between 1 and {MAX_QUARANTINE_WINDOW_SECS}"),
            });
        }
        if self.window_secs > self.max_window_secs {
            return Err(ConfigError::Validation {
                field: "response.quarantine.window_secs".to_string(),
                message: "the default window may not exceed the ceiling it is clamped to"
                    .to_string(),
            });
        }
        if self.max_flows_scanned == 0 || self.max_flows_scanned > MAX_QUARANTINE_FLOWS_SCANNED {
            return Err(ConfigError::Validation {
                field: "response.quarantine.max_flows_scanned".to_string(),
                message: format!("must be between 1 and {MAX_QUARANTINE_FLOWS_SCANNED}"),
            });
        }
        if self.sweep_interval_secs == 0 || self.sweep_interval_secs > 3_600 {
            return Err(ConfigError::Validation {
                field: "response.quarantine.sweep_interval_secs".to_string(),
                message: "must be between 1 and 3600".to_string(),
            });
        }
        if self.protected_paths.iter().any(|p| p.trim().is_empty()) {
            return Err(ConfigError::Validation {
                field: "response.quarantine.protected_paths".to_string(),
                message: "an empty path protects nothing and hides a typo".to_string(),
            });
        }
        if let Some(path) = self
            .protected_paths
            .iter()
            .find(|p| !p.trim_start().starts_with('/'))
        {
            return Err(ConfigError::Validation {
                field: "response.quarantine.protected_paths".to_string(),
                message: format!("'{path}' is not a cgroup path: it must start with '/'"),
            });
        }
        if self.protected_ids.contains(&0) {
            return Err(ConfigError::Validation {
                field: "response.quarantine.protected_ids".to_string(),
                message: "0 is not a cgroup id".to_string(),
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
    /// Cutting a workload off the network without stopping it.
    pub quarantine: QuarantineConfig,
}

impl Default for ResponseConfig {
    fn default() -> Self {
        Self {
            max_ttl_secs: DEFAULT_MAX_RESPONSE_TTL_SECS,
            kill_process: KillProcessConfig::default(),
            quarantine: QuarantineConfig::default(),
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
        self.kill_process.validate()?;
        self.quarantine.validate()
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

    #[test]
    fn quarantining_is_off_until_it_is_turned_on_and_tears_flows_down_when_it_is() {
        let cfg = QuarantineConfig::default();
        assert!(!cfg.enabled);
        assert!(cfg.tear_down_flows);
        assert_eq!(cfg.window_secs, DEFAULT_QUARANTINE_WINDOW_SECS);
        assert!(cfg.validate().is_ok());
        assert!(ResponseConfig::default().validate().is_ok());
    }

    #[test]
    fn a_quarantine_window_is_bounded_at_both_ends() {
        for window_secs in [0, MAX_QUARANTINE_WINDOW_SECS + 1] {
            let cfg = QuarantineConfig {
                window_secs,
                max_window_secs: MAX_QUARANTINE_WINDOW_SECS,
                ..QuarantineConfig::default()
            };
            match cfg.validate() {
                Ok(()) => panic!("a window of {window_secs} must be refused"),
                Err(e) => assert!(e.to_string().contains("quarantine.window_secs")),
            }
        }
    }

    #[test]
    fn a_default_window_above_its_own_ceiling_is_refused() {
        // Otherwise every quarantine would be silently clamped to something
        // shorter than the key an operator set, which reads as the key being
        // ignored.
        let cfg = QuarantineConfig {
            window_secs: 3_600,
            max_window_secs: 60,
            ..QuarantineConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn a_protected_cgroup_entry_that_names_nothing_is_refused() {
        let cfg = QuarantineConfig {
            protected_paths: vec!["  ".to_string()],
            ..QuarantineConfig::default()
        };
        assert!(cfg.validate().is_err());
        let cfg = QuarantineConfig {
            protected_paths: vec!["system.slice/sshd.service".to_string()],
            ..QuarantineConfig::default()
        };
        match cfg.validate() {
            Ok(()) => panic!("a relative path matches nothing and must be refused"),
            Err(e) => assert!(e.to_string().contains("must start with")),
        }
        let cfg = QuarantineConfig {
            protected_ids: vec![0],
            ..QuarantineConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn a_teardown_or_a_sweep_without_a_bound_is_refused() {
        let cfg = QuarantineConfig {
            max_flows_scanned: 0,
            ..QuarantineConfig::default()
        };
        assert!(cfg.validate().is_err());
        let cfg = QuarantineConfig {
            max_flows_scanned: MAX_QUARANTINE_FLOWS_SCANNED + 1,
            ..QuarantineConfig::default()
        };
        assert!(cfg.validate().is_err());
        let cfg = QuarantineConfig {
            sweep_interval_secs: 0,
            ..QuarantineConfig::default()
        };
        assert!(cfg.validate().is_err());
    }
}
