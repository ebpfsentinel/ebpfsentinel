use domain::process::detection::{
    DEFAULT_INTERPRETERS, DEFAULT_SERVERS, ProcessDetectionPolicy, validate_entry,
};
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

    /// The three detections read off the table where a process touches the
    /// network.
    #[serde(default)]
    pub detections: ProcessDetectionConfig,
}

impl Default for ProcessTableConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            capacity: default_capacity(),
            capture_command_line: false,
            detections: ProcessDetectionConfig::default(),
        }
    }
}

/// How often the detections read the connection and process tables.
fn default_detection_interval_secs() -> u64 {
    10
}

const MIN_DETECTION_INTERVAL_SECS: u64 = 1;
const MAX_DETECTION_INTERVAL_SECS: u64 = 3_600;

fn default_interpreters() -> Vec<String> {
    DEFAULT_INTERPRETERS
        .iter()
        .map(ToString::to_string)
        .collect()
}

fn default_servers() -> Vec<String> {
    DEFAULT_SERVERS.iter().map(ToString::to_string).collect()
}

/// A reverse shell, a binary with no file and an unexpected descendant of a
/// server, each tested on every process holding a connection this node
/// opened.
///
/// On by default, raising alerts and stopping nothing: the three are rare on
/// an ordinary node and each is worth an operator's look, while killing a
/// process on a list somebody else wrote is the operator's decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessDetectionConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Seconds between two reads of the tables. A connection that opens and
    /// closes between two reads is not tested.
    #[serde(default = "default_detection_interval_secs")]
    pub interval_secs: u64,

    /// Which of the three detections run.
    #[serde(default)]
    pub kinds: ProcessDetectionKinds,

    /// The shells and interpreters a reverse shell is made of. A name, a full
    /// path when it carries a `/`, either ending in `*` for a prefix.
    #[serde(default = "default_interpreters")]
    pub interpreters: Vec<String>,

    /// The servers whose descendants should answer rather than dial out.
    #[serde(default = "default_servers")]
    pub servers: Vec<String>,

    /// Programs a server is expected to start and that may connect out, such
    /// as the client a PHP application calls.
    #[serde(default)]
    pub expected: Vec<String>,

    /// Stop each process an alert names, through the process kill the
    /// `response.kill_process` section configures.
    #[serde(default)]
    pub kill_process: bool,
}

impl Default for ProcessDetectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: default_detection_interval_secs(),
            kinds: ProcessDetectionKinds::default(),
            interpreters: default_interpreters(),
            servers: default_servers(),
            expected: Vec::new(),
            kill_process: false,
        }
    }
}

/// One switch per detection, each on by default.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ProcessDetectionKinds {
    /// A shell or interpreter talking to the network, through its own
    /// standard streams or from under a server.
    #[serde(default = "default_true")]
    pub reverse_shell: bool,

    /// A process holding a connection whose binary is gone from disk or was
    /// never on it.
    #[serde(default = "default_true")]
    pub fileless: bool,

    /// A process a server started that connects out and is not expected.
    #[serde(default = "default_true")]
    pub server_descendant: bool,
}

impl Default for ProcessDetectionKinds {
    fn default() -> Self {
        Self {
            reverse_shell: true,
            fileless: true,
            server_descendant: true,
        }
    }
}

impl ProcessDetectionConfig {
    /// The domain policy these settings describe.
    #[must_use]
    pub fn to_policy(&self) -> ProcessDetectionPolicy {
        ProcessDetectionPolicy {
            reverse_shell: self.kinds.reverse_shell,
            fileless: self.kinds.fileless,
            server_descendant: self.kinds.server_descendant,
            interpreters: self.interpreters.clone(),
            servers: self.servers.clone(),
            expected: self.expected.clone(),
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if !(MIN_DETECTION_INTERVAL_SECS..=MAX_DETECTION_INTERVAL_SECS)
            .contains(&self.interval_secs)
        {
            return Err(ConfigError::Validation {
                field: "process_table.detections.interval_secs".to_string(),
                message: format!(
                    "must be between {MIN_DETECTION_INTERVAL_SECS} and \
                     {MAX_DETECTION_INTERVAL_SECS}, got {}",
                    self.interval_secs
                ),
            });
        }
        for (field, entries) in [
            ("interpreters", &self.interpreters),
            ("servers", &self.servers),
            ("expected", &self.expected),
        ] {
            for entry in entries {
                validate_entry(entry).map_err(|message| ConfigError::Validation {
                    field: format!("process_table.detections.{field}"),
                    message,
                })?;
            }
        }
        Ok(())
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
        self.detections.validate()
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
        let cfg: ProcessTableConfig = serde_norway::from_str(yaml).unwrap();
        assert_eq!(cfg.capacity, 1024);
        assert!(cfg.capture_command_line);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn the_detections_are_on_alerting_and_stopping_nothing() {
        let cfg = ProcessTableConfig::default().detections;
        assert!(cfg.enabled);
        assert!(cfg.kinds.reverse_shell && cfg.kinds.fileless && cfg.kinds.server_descendant);
        assert!(!cfg.kill_process);
        assert_eq!(cfg.to_policy(), ProcessDetectionPolicy::default());
    }

    #[test]
    fn a_detection_list_entry_with_a_star_inside_is_refused() {
        let mut cfg = ProcessTableConfig::default();
        cfg.detections.expected = vec!["cu*rl".to_string()];
        assert!(cfg.validate().is_err());
        cfg.detections.expected = vec!["curl".to_string()];
        cfg.detections.interval_secs = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn the_detections_read_from_yaml() {
        let yaml = "detections:\n  expected: [curl]\n  kill_process: true\n  kinds:\n    fileless: false\n";
        let cfg: ProcessTableConfig = serde_norway::from_str(yaml).unwrap();
        assert_eq!(cfg.detections.expected, vec!["curl".to_string()]);
        assert!(cfg.detections.kill_process);
        assert!(!cfg.detections.kinds.fileless);
        assert!(cfg.detections.kinds.reverse_shell);
        assert_eq!(cfg.detections.servers, default_servers());
    }

    #[test]
    fn an_empty_section_is_the_default_section() {
        let cfg: ProcessTableConfig = serde_norway::from_str("{}").unwrap();
        assert_eq!(cfg.capacity, default_capacity());
        assert!(cfg.enabled);
    }
}
