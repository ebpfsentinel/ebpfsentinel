use serde::{Deserialize, Serialize};

use domain::learning::entity::{LEARNING_DEFAULT_MAX_EDGES, LEARNING_MAX_EDGES_CEILING};

use super::common::{ConfigError, default_true};

/// How often the open window reads the connection table, in seconds.
///
/// Mirrors the collector's own default. Below the minimum the reads cost
/// more than the window is worth on a busy node; above the maximum a
/// connection has to live minutes to be seen at all.
fn default_sample_interval_secs() -> u64 {
    10
}

const MIN_SAMPLE_INTERVAL_SECS: u64 = 1;
const MAX_SAMPLE_INTERVAL_SECS: u64 = 300;

/// The smallest aggregate worth keeping: a window that refuses the fourth
/// destination describes nothing.
const MIN_MAX_EDGES: usize = 64;

fn default_max_edges() -> usize {
    LEARNING_DEFAULT_MAX_EDGES
}

fn default_storage_path() -> String {
    "data/learning.redb".to_string()
}

/// Learning mode: what this node reached, for the window an operator asked
/// for, written down as a policy they can read before it is one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearningConfig {
    /// Allow a window to be opened on this node.
    ///
    /// On by default and costing nothing while no window is open: the
    /// sampler reads the connection table only for a window somebody asked
    /// for. Turning it off takes the routes away rather than leaving them
    /// answering that nothing was observed.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// How many distinct destinations one window holds.
    ///
    /// The aggregate refuses past this rather than evicting, and says how
    /// many it refused: a policy written from a window that quietly dropped
    /// its oldest destinations would be missing exactly the edges nobody
    /// remembers.
    #[serde(default = "default_max_edges")]
    pub max_edges: usize,

    /// Seconds between two readings of the connection table.
    #[serde(default = "default_sample_interval_secs")]
    pub sample_interval_secs: u64,

    /// Where an open window is written down so it survives a restart. An
    /// empty string keeps the window in memory only, which costs a redeploy
    /// the whole window rather than a hole in it.
    #[serde(default = "default_storage_path")]
    pub storage_path: String,
}

impl Default for LearningConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_edges: default_max_edges(),
            sample_interval_secs: default_sample_interval_secs(),
            storage_path: default_storage_path(),
        }
    }
}

impl LearningConfig {
    /// # Errors
    ///
    /// Returns [`ConfigError::Validation`] when the ceiling or the interval
    /// is outside the range the sampler can honour.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.max_edges < MIN_MAX_EDGES || self.max_edges > LEARNING_MAX_EDGES_CEILING {
            return Err(ConfigError::Validation {
                field: "learning.max_edges".to_string(),
                message: format!(
                    "must be between {MIN_MAX_EDGES} and {LEARNING_MAX_EDGES_CEILING}, got {}",
                    self.max_edges
                ),
            });
        }
        if self.sample_interval_secs < MIN_SAMPLE_INTERVAL_SECS
            || self.sample_interval_secs > MAX_SAMPLE_INTERVAL_SECS
        {
            return Err(ConfigError::Validation {
                field: "learning.sample_interval_secs".to_string(),
                message: format!(
                    "must be between {MIN_SAMPLE_INTERVAL_SECS} and {MAX_SAMPLE_INTERVAL_SECS}, got {}",
                    self.sample_interval_secs
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
    fn a_node_that_says_nothing_can_still_open_a_window() {
        let cfg = LearningConfig::default();
        assert!(cfg.enabled);
        assert_eq!(cfg.max_edges, LEARNING_DEFAULT_MAX_EDGES);
        assert_eq!(cfg.sample_interval_secs, 10);
        assert_eq!(cfg.storage_path, "data/learning.redb");
        cfg.validate().expect("the default validates");
    }

    #[test]
    fn omitted_fields_keep_their_defaults() {
        let cfg: LearningConfig = serde_norway::from_str("enabled: false\n").unwrap();
        assert!(!cfg.enabled);
        assert_eq!(cfg.max_edges, LEARNING_DEFAULT_MAX_EDGES);
        assert_eq!(cfg.storage_path, "data/learning.redb");
    }

    #[test]
    fn a_window_in_memory_only_is_written_as_an_empty_path() {
        let cfg: LearningConfig = serde_norway::from_str("storage_path: \"\"\n").unwrap();
        assert!(cfg.storage_path.is_empty());
        cfg.validate().expect("no store is a choice, not an error");
    }

    #[test]
    fn a_ceiling_nobody_could_hold_is_refused() {
        let cfg = LearningConfig {
            max_edges: LEARNING_MAX_EDGES_CEILING + 1,
            ..LearningConfig::default()
        };
        let err = cfg.validate().expect_err("the ceiling is refused");
        assert!(err.to_string().contains("learning.max_edges"));
    }

    #[test]
    fn a_sampler_asked_to_run_every_hour_is_refused() {
        let cfg = LearningConfig {
            sample_interval_secs: 3_600,
            ..LearningConfig::default()
        };
        let err = cfg.validate().expect_err("the interval is refused");
        assert!(err.to_string().contains("learning.sample_interval_secs"));
    }
}
