use serde::{Deserialize, Serialize};

use super::ConfigError;

const DEFAULT_LEARNING_SECS: u64 = 7 * 86_400;
const DEFAULT_WINDOW_SECS: u64 = 300;
const DEFAULT_MIN_NEW_PEERS: usize = 5;
const DEFAULT_MIN_BYTES_PER_PEER: u64 = 1_048_576;
const MAX_LEARNING_SECS: u64 = 90 * 86_400;
const MAX_WINDOW_SECS: u64 = 86_400;
const MAX_MIN_NEW_PEERS: usize = 256;

/// Writes pushed over SMB to file servers this host never wrote to before.
///
/// Read off the flow records the conntrack table yields, so it needs that
/// table and runs whether or not flow export is configured.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ShareWritesConfig {
    /// Whether the writes are followed at all.
    pub enabled: bool,

    /// How long every server written to is taken as ordinary, in seconds,
    /// from the first write the agent sees. Held in memory: a restart
    /// learns again.
    pub learning_secs: u64,

    /// How long one process's writes to new servers are added up, in
    /// seconds.
    pub window_secs: u64,

    /// New servers in one window that raise the alert.
    pub min_new_peers: usize,

    /// Bytes a new server must receive in the window to count.
    pub min_bytes_per_peer: u64,
}

impl Default for ShareWritesConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            learning_secs: DEFAULT_LEARNING_SECS,
            window_secs: DEFAULT_WINDOW_SECS,
            min_new_peers: DEFAULT_MIN_NEW_PEERS,
            min_bytes_per_peer: DEFAULT_MIN_BYTES_PER_PEER,
        }
    }
}

impl ShareWritesConfig {
    /// Checks the block hard enough that a wrong one fails at boot.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Validation`] naming the first value out of
    /// range.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let refuse = |field: &str, message: String| {
            Err(ConfigError::Validation {
                field: format!("share_writes.{field}"),
                message,
            })
        };
        if self.learning_secs == 0 || self.learning_secs > MAX_LEARNING_SECS {
            return refuse(
                "learning_secs",
                format!("must be between 1 and {MAX_LEARNING_SECS} seconds"),
            );
        }
        if self.window_secs == 0 || self.window_secs > MAX_WINDOW_SECS {
            return refuse(
                "window_secs",
                format!("must be between 1 and {MAX_WINDOW_SECS} seconds"),
            );
        }
        if self.min_new_peers < 2 || self.min_new_peers > MAX_MIN_NEW_PEERS {
            return refuse(
                "min_new_peers",
                format!(
                    "must be between 2 and {MAX_MIN_NEW_PEERS}: one new server is a host doing its job"
                ),
            );
        }
        if self.min_bytes_per_peer == 0 {
            return refuse("min_bytes_per_peer", "must be at least 1".to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn off_by_default_with_a_week_of_learning() {
        let config = ShareWritesConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.learning_secs, 604_800);
        assert_eq!(config.min_new_peers, 5);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn a_value_out_of_range_is_refused_by_name() {
        let cases = [
            ShareWritesConfig {
                learning_secs: 0,
                ..ShareWritesConfig::default()
            },
            ShareWritesConfig {
                window_secs: MAX_WINDOW_SECS + 1,
                ..ShareWritesConfig::default()
            },
            ShareWritesConfig {
                min_new_peers: 1,
                ..ShareWritesConfig::default()
            },
            ShareWritesConfig {
                min_bytes_per_peer: 0,
                ..ShareWritesConfig::default()
            },
        ];
        for (config, field) in cases.iter().zip([
            "learning_secs",
            "window_secs",
            "min_new_peers",
            "min_bytes_per_peer",
        ]) {
            match config.validate() {
                Err(ConfigError::Validation { field: named, .. }) => {
                    assert_eq!(named, format!("share_writes.{field}"));
                }
                other => panic!("expected a refusal of {field}, got {other:?}"),
            }
        }
    }
}
