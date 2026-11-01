//! Watching whole filesystems for changes, and the process behind each.
//!
//! Off by default. Each path names the filesystem it lives on, and the whole
//! filesystem is watched: an overlay cannot be watched itself, so a
//! container's writes are seen on the filesystem beneath it, where its upper
//! directory lives.

use serde::{Deserialize, Serialize};

use super::ConfigError;

/// Paths one watch may name; the warden refuses more.
pub const MAX_FILE_WATCH_FILESYSTEMS: usize = 64;

/// The file watch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct FileWatchConfig {
    /// Whether the watch is opened.
    pub enabled: bool,

    /// One path per filesystem to watch, absolute, as the watch's holder
    /// reaches it: the warden's mount namespace for a rootless agent.
    pub filesystems: Vec<String>,
}

impl Default for FileWatchConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            filesystems: vec!["/".to_owned()],
        }
    }
}

impl FileWatchConfig {
    /// Checks the block hard enough that a wrong one fails at boot.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Validation`] when the watch is on and names no
    /// filesystem, more than [`MAX_FILE_WATCH_FILESYSTEMS`], or a path that
    /// is not absolute.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let invalid = |message: String| ConfigError::Validation {
            field: "file_watch.filesystems".to_string(),
            message,
        };
        if self.enabled && self.filesystems.is_empty() {
            return Err(invalid(
                "must name at least one filesystem when enabled".into(),
            ));
        }
        if self.filesystems.len() > MAX_FILE_WATCH_FILESYSTEMS {
            return Err(invalid(format!(
                "at most {MAX_FILE_WATCH_FILESYSTEMS} filesystems"
            )));
        }
        if let Some(path) = self.filesystems.iter().find(|p| !p.starts_with('/')) {
            return Err(invalid(format!("{path:?} is not an absolute path")));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn off_by_default_and_naming_the_root_filesystem() {
        let config = FileWatchConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.filesystems, vec!["/".to_owned()]);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn an_enabled_watch_with_nothing_to_watch_is_refused() {
        let config = FileWatchConfig {
            enabled: true,
            filesystems: Vec::new(),
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn a_relative_path_or_too_many_are_refused() {
        let relative = FileWatchConfig {
            enabled: true,
            filesystems: vec!["var/lib".into()],
        };
        assert!(relative.validate().is_err());
        let many = FileWatchConfig {
            enabled: true,
            filesystems: (0..=MAX_FILE_WATCH_FILESYSTEMS)
                .map(|i| format!("/m{i}"))
                .collect(),
        };
        assert!(many.validate().is_err());
    }

    #[test]
    fn an_unknown_key_is_refused() {
        let parsed: Result<FileWatchConfig, _> =
            serde_norway::from_str("enabled: true\npaths: [/]\n");
        assert!(parsed.is_err());
    }
}
