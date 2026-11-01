use serde::{Deserialize, Serialize};

use super::ConfigError;

const DEFAULT_PORT_INTERVAL_SECS: u64 = 300;
const MIN_INTERVAL_SECS: u64 = 60;
const MAX_INTERVAL_SECS: u64 = 86_400;
/// The well-known ports, probed unless turned off.
const WELL_KNOWN: std::ops::RangeInclusive<u16> = 1..=1024;
const MAX_EXTRA_PORTS: usize = 4_096;
const DEFAULT_PROCESS_INTERVAL_SECS: u64 = 900;
const DEFAULT_PIDS_PER_SECOND: u32 = 100_000;
/// The pace bounds the warden itself clamps to.
const PIDS_PER_SECOND: std::ops::RangeInclusive<u32> = 10_000..=10_000_000;

/// Comparisons of two readings of the same kernel state, where an entry the
/// kernel holds and its own listing leaves out is reported.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct HiddenChecksConfig {
    /// Sockets the listings omit while the port refuses a bind.
    pub ports: HiddenPortsConfig,
    /// Pids that answer a signal while `/proc` does not list them.
    pub processes: HiddenProcessesConfig,
}

/// The hidden process sweep.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct HiddenProcessesConfig {
    /// Whether the sweep runs at all.
    pub enabled: bool,

    /// How often the pid space is swept, in seconds.
    pub interval_secs: u64,

    /// How many pids are signalled a second, so the sweep is never itself
    /// a load: at the default a full 22-bit pid space takes 42 seconds.
    pub pids_per_second: u32,
}

impl Default for HiddenProcessesConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: DEFAULT_PROCESS_INTERVAL_SECS,
            pids_per_second: DEFAULT_PIDS_PER_SECOND,
        }
    }
}

/// The hidden port sweep.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct HiddenPortsConfig {
    /// Whether the sweep runs at all.
    pub enabled: bool,

    /// How often every namespace is swept, in seconds. Each sweep binds
    /// every probed port for an instant, which is why the floor is a
    /// minute.
    pub interval_secs: u64,

    /// Whether ports 1 to 1024 are probed.
    pub well_known: bool,

    /// Ports probed in addition, such as a backdoor's usual high port.
    pub extra_ports: Vec<u16>,
}

impl Default for HiddenPortsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: DEFAULT_PORT_INTERVAL_SECS,
            well_known: true,
            extra_ports: Vec::new(),
        }
    }
}

impl HiddenPortsConfig {
    /// The ports each namespace is probed on, sorted and without repeats.
    #[must_use]
    pub fn probed_ports(&self) -> Vec<u16> {
        let mut ports: Vec<u16> = if self.well_known {
            WELL_KNOWN.collect()
        } else {
            Vec::new()
        };
        ports.extend(self.extra_ports.iter().copied());
        ports.sort_unstable();
        ports.dedup();
        ports
    }
}

impl HiddenChecksConfig {
    /// Checks the block hard enough that a wrong one fails at boot.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Validation`] when the interval is out of range,
    /// a port is zero, too many extra ports are listed, the port sweep is on
    /// with no port to probe, or the process sweep's pace is out of range.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let ports = &self.ports;
        if !(MIN_INTERVAL_SECS..=MAX_INTERVAL_SECS).contains(&ports.interval_secs) {
            return Err(ConfigError::Validation {
                field: "hidden_checks.ports.interval_secs".to_string(),
                message: format!(
                    "must be between {MIN_INTERVAL_SECS} and {MAX_INTERVAL_SECS} seconds"
                ),
            });
        }
        if ports.extra_ports.contains(&0) {
            return Err(ConfigError::Validation {
                field: "hidden_checks.ports.extra_ports".to_string(),
                message: "port 0 cannot be probed".to_string(),
            });
        }
        if ports.extra_ports.len() > MAX_EXTRA_PORTS {
            return Err(ConfigError::Validation {
                field: "hidden_checks.ports.extra_ports".to_string(),
                message: format!("at most {MAX_EXTRA_PORTS} ports"),
            });
        }
        if ports.enabled && ports.probed_ports().is_empty() {
            return Err(ConfigError::Validation {
                field: "hidden_checks.ports".to_string(),
                message: "the sweep is on with no port to probe: keep well_known or list \
                          extra_ports"
                    .to_string(),
            });
        }
        let processes = &self.processes;
        if !(MIN_INTERVAL_SECS..=MAX_INTERVAL_SECS).contains(&processes.interval_secs) {
            return Err(ConfigError::Validation {
                field: "hidden_checks.processes.interval_secs".to_string(),
                message: format!(
                    "must be between {MIN_INTERVAL_SECS} and {MAX_INTERVAL_SECS} seconds"
                ),
            });
        }
        if !PIDS_PER_SECOND.contains(&processes.pids_per_second) {
            return Err(ConfigError::Validation {
                field: "hidden_checks.processes.pids_per_second".to_string(),
                message: format!(
                    "must be between {} and {}",
                    PIDS_PER_SECOND.start(),
                    PIDS_PER_SECOND.end()
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
    fn on_by_default_probing_the_well_known_ports_every_five_minutes() {
        let config = HiddenChecksConfig::default();
        assert!(config.ports.enabled);
        assert_eq!(config.ports.interval_secs, 300);
        assert_eq!(config.ports.probed_ports().len(), 1024);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn extra_ports_join_the_well_known_ones_without_repeats() {
        let config = HiddenPortsConfig {
            extra_ports: vec![31337, 22, 31337],
            ..HiddenPortsConfig::default()
        };
        let ports = config.probed_ports();
        assert_eq!(ports.len(), 1025);
        assert_eq!(ports.last(), Some(&31337));
    }

    #[test]
    fn a_wrong_block_fails_at_boot() {
        let bad = [
            HiddenPortsConfig {
                interval_secs: 59,
                ..HiddenPortsConfig::default()
            },
            HiddenPortsConfig {
                interval_secs: MAX_INTERVAL_SECS + 1,
                ..HiddenPortsConfig::default()
            },
            HiddenPortsConfig {
                extra_ports: vec![0],
                ..HiddenPortsConfig::default()
            },
            HiddenPortsConfig {
                well_known: false,
                ..HiddenPortsConfig::default()
            },
            HiddenPortsConfig {
                extra_ports: vec![1; MAX_EXTRA_PORTS + 1],
                ..HiddenPortsConfig::default()
            },
        ];
        for ports in bad {
            let config = HiddenChecksConfig {
                ports,
                ..HiddenChecksConfig::default()
            };
            assert!(config.validate().is_err());
        }
    }

    #[test]
    fn the_process_sweep_is_on_every_quarter_hour_at_a_bounded_pace() {
        let config = HiddenChecksConfig::default();
        assert!(config.processes.enabled);
        assert_eq!(config.processes.interval_secs, 900);
        assert_eq!(config.processes.pids_per_second, 100_000);
        let bad = [
            HiddenProcessesConfig {
                interval_secs: 30,
                ..HiddenProcessesConfig::default()
            },
            HiddenProcessesConfig {
                pids_per_second: 9_999,
                ..HiddenProcessesConfig::default()
            },
            HiddenProcessesConfig {
                pids_per_second: 10_000_001,
                ..HiddenProcessesConfig::default()
            },
        ];
        for processes in bad {
            let config = HiddenChecksConfig {
                processes,
                ..HiddenChecksConfig::default()
            };
            assert!(config.validate().is_err());
        }
    }

    #[test]
    fn an_unknown_key_is_refused() {
        let parsed: Result<HiddenChecksConfig, _> =
            serde_norway::from_str("ports:\n  enabled: true\n  interval: 30\n");
        assert!(parsed.is_err());
    }
}
