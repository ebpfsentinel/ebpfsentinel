use serde::{Deserialize, Serialize};

use super::common::{ConfigError, default_true};

/// How many live processes the table holds by default.
///
/// A busy node runs a few hundred processes and forks far more; eight
/// thousand entries covers an ordinary node with room for a build or a test
/// run, at roughly a few hundred bytes an entry.
fn default_capacity() -> usize {
    8_192
}

/// The smallest table worth filling. Below this, eviction on an ordinary node
/// is constant and a lookup that returns nothing means "evicted" far more
/// often than "not a process we saw", which is the ambiguity the whole table
/// exists to remove.
const MIN_CAPACITY: usize = 256;

/// The largest table the agent will keep. Past this the memory is a decision
/// an operator should write down rather than reach by typing a large number.
const MAX_CAPACITY: usize = 262_144;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessTableConfig {
    /// Attach the exec and exit tracepoints and keep the table. On by
    /// default: an alert naming a pid and no program is half an answer.
    ///
    /// A kernel that refuses the attach is not a failure to start: the agent
    /// runs on with an empty table and says so once, with the reason, which
    /// the kernel-features endpoint then reports.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// How many live processes the table holds before the oldest exec is
    /// dropped. The bound exists for a lost exit notification rather than for
    /// the ordinary case, where an exit removes its own entry.
    #[serde(default = "default_capacity")]
    pub capacity: usize,

    /// Keep the command line each process was started with.
    ///
    /// Off by default, and deliberately: argv routinely carries a password,
    /// a token or a connection string, so a table that collected it by
    /// default would be a credential store nobody asked for. Turning it on is
    /// an operator's decision about their own node.
    #[serde(default)]
    pub capture_command_line: bool,
}

impl Default for ProcessTableConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            capacity: default_capacity(),
            capture_command_line: false,
        }
    }
}

impl ProcessTableConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.capacity < MIN_CAPACITY || self.capacity > MAX_CAPACITY {
            return Err(ConfigError::Validation {
                field: "process_table.capacity".to_string(),
                message: format!(
                    "must be between {MIN_CAPACITY} and {MAX_CAPACITY}, got {}",
                    self.capacity
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
    fn the_default_is_on_and_valid() {
        let cfg = ProcessTableConfig::default();
        assert!(cfg.enabled);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn the_command_line_is_off_until_somebody_turns_it_on() {
        assert!(!ProcessTableConfig::default().capture_command_line);
    }

    #[test]
    fn a_table_too_small_to_be_honest_is_refused() {
        let cfg = ProcessTableConfig {
            capacity: 8,
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn a_table_large_enough_to_be_a_memory_decision_is_refused() {
        let cfg = ProcessTableConfig {
            capacity: MAX_CAPACITY + 1,
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn the_section_round_trips_through_yaml() {
        let yaml = "enabled: true\ncapacity: 1024\ncapture_command_line: true\n";
        let cfg: ProcessTableConfig = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(cfg.capacity, 1024);
        assert!(cfg.capture_command_line);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn an_empty_section_is_the_default_section() {
        let cfg: ProcessTableConfig = serde_yaml_ng::from_str("{}").unwrap();
        assert_eq!(cfg.capacity, default_capacity());
        assert!(cfg.enabled);
    }
}
