//! Watching whole filesystems for changes, and the process behind each.
//!
//! Off by default. Each path names the filesystem it lives on, and the whole
//! filesystem is watched: an overlay cannot be watched itself, so a
//! container's writes are seen on the filesystem beneath it, where its upper
//! directory lives.

use domain::file_watch::{DECLARED_ORIGIN, WATCHED_PATHS_MAX, WatchedPaths, check_watched_path};
use domain::firewall::entity::RuleMode;
use domain::ransom::{
    CANARIES_MAX, CANARY_DIRECTORIES, CANARY_EXEMPT, CANARY_NAMES, CountBy,
    WRITE_REFUSAL_THRESHOLD, WRITE_REFUSAL_WINDOW_SECS, WriteRefusalSetRef, canary_name_refusal,
    canary_paths, validate_write_refusal,
};
use serde::{Deserialize, Serialize};

use super::ConfigError;

/// Paths one watch may name; the warden refuses more.
pub const MAX_FILE_WATCH_FILESYSTEMS: usize = 64;

/// The largest file hashed by default.
pub const DEFAULT_MAX_HASH_BYTES: u64 = 16 * 1024 * 1024;

/// The most baselines kept by default.
pub const DEFAULT_MAX_BASELINES: u64 = 500_000;

/// Ceiling on the hash size: one reading is bounded by the warden's budget
/// per request, and a file larger than that would never be hashed anyway.
pub const MAX_HASH_BYTES_CEILING: u64 = 64 * 1024 * 1024;

/// The file watch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct FileWatchConfig {
    /// Whether the watch is opened.
    pub enabled: bool,

    /// One path per filesystem to watch, absolute, as the watch's holder
    /// reaches it: the warden's mount namespace for a rootless agent.
    pub filesystems: Vec<String>,

    /// A regular file larger than this many bytes is not hashed; its size
    /// and modification time are compared instead.
    pub max_hash_bytes: u64,

    /// Baselines kept at most. A path first seen once the store holds this
    /// many gets none, and is counted.
    pub max_baselines: u64,

    /// Paths watched for any difference, each a file or a directory and
    /// everything beneath it: a change under one is an alert, whichever
    /// process made it.
    pub paths: Vec<String>,

    /// Canary files planted into data directories, any open of which is a
    /// decisive mass encryption signal.
    pub canaries: CanaryConfig,

    /// What a mass encryption verdict does once it is reached.
    pub mass_encryption: MassEncryptionConfig,

    /// Write-opens refused in the kernel past a count, under the directories
    /// named. Independent of `enabled`: it needs the BPF LSM, not the watch.
    pub write_refusal: WriteRefusalConfig,
}

/// The kernel refusing a write-open past a count.
///
/// Needs the BPF LSM active at boot (`lsm=bpf`); without it the agent says
/// so and refuses nothing. It fails open: an agent that stops refuses
/// nothing, and the files written before the threshold are lost in every
/// case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct WriteRefusalConfig {
    /// Whether the program is loaded. Off by default.
    pub enabled: bool,

    /// `shadow`, the default, counts what would have been refused and
    /// reports it; `enforce` refuses.
    pub mode: RuleMode,

    /// The data paths watched, each absolute and everything beneath it,
    /// refused at the threshold: mass writes there are legitimate.
    pub paths: Vec<String>,

    /// The system paths watched, each absolute and everything beneath it,
    /// refused at the first write by an executable not in
    /// `system_writers`: a write there is anomalous once.
    pub system_paths: Vec<String>,

    /// The executables expected to write under the system paths, each an
    /// absolute path: the package manager, the estate's configuration tool.
    pub system_writers: Vec<String>,

    /// The write-open by one writer inside the window that is refused
    /// first under a data path; every one after it in the window is refused
    /// too.
    pub threshold: u32,

    /// The window the count runs over, in seconds.
    pub window_secs: u64,

    /// `process` counts each thread group alone; `cgroup` counts a
    /// container or a unit as one writer, forks included.
    pub count_by: CountBy,
}

impl Default for WriteRefusalConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: RuleMode::Shadow,
            paths: Vec::new(),
            system_paths: Vec::new(),
            system_writers: Vec::new(),
            threshold: WRITE_REFUSAL_THRESHOLD,
            window_secs: WRITE_REFUSAL_WINDOW_SECS,
            count_by: CountBy::Process,
        }
    }
}

impl WriteRefusalConfig {
    /// Checks the block when it is turned on.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Validation`] naming the first entry or number
    /// that cannot be applied.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }
        validate_write_refusal(self.set(), self.threshold, self.window_secs).map_err(|e| {
            ConfigError::Validation {
                field: "file_watch.write_refusal".to_string(),
                message: e.to_string(),
            }
        })
    }

    /// The watched paths of both regimes and the expected writers.
    #[must_use]
    pub fn set(&self) -> WriteRefusalSetRef<'_> {
        WriteRefusalSetRef {
            data: &self.paths,
            system: &self.system_paths,
            writers: &self.system_writers,
        }
    }
}

/// The composed mass encryption verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct MassEncryptionConfig {
    /// `shadow`, the default, counts each verdict by workload and keeps the
    /// last ones without raising anything, so the thresholds can be watched
    /// against this host's own work first; `enforce` raises an alert.
    pub mode: RuleMode,

    /// Whether a verdict in force also kills the run: the actor and every
    /// process it started, then a second alert saying how many files it
    /// wrote before it died. Off by default, needs `enforce` and
    /// `response.kill_process.enabled`.
    pub stop: bool,
}

impl Default for MassEncryptionConfig {
    fn default() -> Self {
        Self {
            mode: RuleMode::Shadow,
            stop: false,
        }
    }
}

/// Canary files: names no legitimate process has a reason to open, planted
/// into the directories a run walks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct CanaryConfig {
    /// Whether canaries are planted. Off by default: planting writes files
    /// into the operator's own directories.
    pub enabled: bool,

    /// Where canaries are planted, each an absolute directory as the
    /// watch's holder reaches it. One absent on the host is reported and
    /// skipped.
    pub directories: Vec<String>,

    /// The names planted into each directory.
    pub names: Vec<String>,

    /// Executables, by full path, whose opens of a canary are not a signal:
    /// whatever walks these directories by design, a backup or a scanner.
    pub exempt: Vec<String>,
}

impl Default for CanaryConfig {
    fn default() -> Self {
        let owned = |list: &[&str]| list.iter().map(|s| (*s).to_owned()).collect();
        Self {
            enabled: false,
            directories: owned(CANARY_DIRECTORIES),
            names: owned(CANARY_NAMES),
            exempt: owned(CANARY_EXEMPT),
        }
    }
}

impl CanaryConfig {
    /// Every canary path, each name in each directory.
    #[must_use]
    pub fn paths(&self) -> Vec<String> {
        canary_paths(&self.directories, &self.names)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        let invalid = |field: &str, message: String| ConfigError::Validation {
            field: format!("file_watch.canaries.{field}"),
            message,
        };
        if let Some(dir) = self.directories.iter().find(|d| !d.starts_with('/')) {
            return Err(invalid(
                "directories",
                format!("{dir:?} is not an absolute path"),
            ));
        }
        for name in &self.names {
            if let Some(why) = canary_name_refusal(name) {
                return Err(invalid("names", format!("{name:?} {why}")));
            }
        }
        if let Some(exe) = self.exempt.iter().find(|e| !e.starts_with('/')) {
            return Err(invalid(
                "exempt",
                format!("{exe:?} is not an absolute path"),
            ));
        }
        if self.enabled && self.names.is_empty() {
            return Err(invalid(
                "names",
                "must name at least one canary when enabled".into(),
            ));
        }
        if self.directories.len().saturating_mul(self.names.len()) > CANARIES_MAX {
            return Err(invalid(
                "directories",
                format!("at most {CANARIES_MAX} canaries, every name in every directory"),
            ));
        }
        Ok(())
    }
}

impl Default for FileWatchConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            filesystems: vec!["/".to_owned()],
            max_hash_bytes: DEFAULT_MAX_HASH_BYTES,
            max_baselines: DEFAULT_MAX_BASELINES,
            paths: Vec::new(),
            canaries: CanaryConfig::default(),
            mass_encryption: MassEncryptionConfig::default(),
            write_refusal: WriteRefusalConfig::default(),
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
    /// is not absolute, a hash size above [`MAX_HASH_BYTES_CEILING`], or no
    /// room for a single baseline, and when a watched path is not one the
    /// watch can name or there are more than [`WATCHED_PATHS_MAX`].
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.max_hash_bytes > MAX_HASH_BYTES_CEILING {
            return Err(ConfigError::Validation {
                field: "file_watch.max_hash_bytes".to_string(),
                message: format!("at most {MAX_HASH_BYTES_CEILING}"),
            });
        }
        if self.max_baselines == 0 {
            return Err(ConfigError::Validation {
                field: "file_watch.max_baselines".to_string(),
                message: "must keep at least one baseline".into(),
            });
        }
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
        let invalid_path = |message: String| ConfigError::Validation {
            field: "file_watch.paths".to_string(),
            message,
        };
        if self.paths.len() > WATCHED_PATHS_MAX {
            return Err(invalid_path(format!("at most {WATCHED_PATHS_MAX} paths")));
        }
        for path in &self.paths {
            check_watched_path(path).map_err(invalid_path)?;
        }
        self.canaries.validate()?;
        self.write_refusal.validate()
    }

    /// The declared paths, each watched through the configuration.
    #[must_use]
    pub fn watched_paths(&self) -> WatchedPaths {
        let mut watched = WatchedPaths::new();
        for path in &self.paths {
            // Validation refused every path `add` would, so nothing is lost.
            if watched.add(path, DECLARED_ORIGIN).is_err() {
                break;
            }
        }
        watched
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
        assert_eq!(config.mass_encryption.mode, RuleMode::Shadow);
        assert!(!config.write_refusal.enabled);
        assert_eq!(config.write_refusal.mode, RuleMode::Shadow);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn a_write_refusal_turned_on_names_its_directories_or_fails_at_boot() {
        let mut config = FileWatchConfig::default();
        config.write_refusal.enabled = true;
        let err = config.validate().expect_err("no directory");
        assert!(
            err.to_string().contains("file_watch.write_refusal"),
            "{err}"
        );
        config.write_refusal.paths = vec!["/srv/data".into()];
        assert!(config.validate().is_ok());
        config.write_refusal.paths = vec!["/".into()];
        assert!(config.validate().is_err());
        let parsed: FileWatchConfig = serde_norway::from_str(
            "write_refusal:\n  enabled: true\n  mode: enforce\n  paths: [/srv]\n  threshold: 5\n  window_secs: 10\n  count_by: cgroup\n",
        )
        .expect("parses");
        assert_eq!(parsed.write_refusal.mode, RuleMode::Enforce);
        assert_eq!(parsed.write_refusal.count_by, CountBy::Cgroup);
        assert_eq!(parsed.write_refusal.threshold, 5);
        assert!(parsed.validate().is_ok());
    }

    #[test]
    fn a_write_refusal_may_watch_system_paths_alone_with_their_expected_writers() {
        let parsed: FileWatchConfig = serde_norway::from_str(
            "write_refusal:\n  enabled: true\n  system_paths: [/etc, /usr/bin]\n  system_writers: [/usr/bin/dpkg]\n",
        )
        .expect("parses");
        assert!(parsed.validate().is_ok());
        assert_eq!(parsed.write_refusal.set().system.len(), 2);
        let mut overlap = parsed.clone();
        overlap.write_refusal.paths = vec!["/etc/".into()];
        assert!(overlap.validate().is_err());
        let mut relative = parsed;
        relative.write_refusal.system_writers = vec!["dpkg".into()];
        let err = relative.validate().expect_err("relative writer");
        assert!(err.to_string().contains("expected writer"), "{err}");
    }

    #[test]
    fn an_enabled_watch_with_nothing_to_watch_is_refused() {
        let config = FileWatchConfig {
            enabled: true,
            filesystems: Vec::new(),
            ..FileWatchConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn a_relative_path_or_too_many_are_refused() {
        let relative = FileWatchConfig {
            enabled: true,
            filesystems: vec!["var/lib".into()],
            ..FileWatchConfig::default()
        };
        assert!(relative.validate().is_err());
        let many = FileWatchConfig {
            enabled: true,
            filesystems: (0..=MAX_FILE_WATCH_FILESYSTEMS)
                .map(|i| format!("/m{i}"))
                .collect(),
            ..FileWatchConfig::default()
        };
        assert!(many.validate().is_err());
    }

    #[test]
    fn a_declared_path_is_watched_through_the_configuration() {
        let config = FileWatchConfig {
            enabled: true,
            paths: vec!["/etc/ssh".into(), "/etc/ssh".into(), "/etc/shadow".into()],
            ..FileWatchConfig::default()
        };
        assert!(config.validate().is_ok());
        let watched = config.watched_paths();
        assert_eq!(watched.len(), 2);
        assert_eq!(
            watched.covering("/etc/ssh/sshd_config"),
            Some(("/etc/ssh", DECLARED_ORIGIN))
        );
    }

    #[test]
    fn a_path_the_watch_cannot_name_is_refused() {
        for path in ["etc/ssh", "/", "/etc/../root", "/etc/ssh/"] {
            let config = FileWatchConfig {
                paths: vec![path.into()],
                ..FileWatchConfig::default()
            };
            assert!(config.validate().is_err(), "{path}");
        }
        let many = FileWatchConfig {
            paths: (0..=WATCHED_PATHS_MAX).map(|i| format!("/p{i}")).collect(),
            ..FileWatchConfig::default()
        };
        assert!(many.validate().is_err());
    }

    #[test]
    fn canaries_are_off_by_default_and_their_defaults_are_valid() {
        let config = FileWatchConfig::default();
        assert!(!config.canaries.enabled);
        assert_eq!(
            config.canaries.paths().len(),
            CANARY_DIRECTORIES.len() * CANARY_NAMES.len()
        );
        assert!(
            config
                .canaries
                .paths()
                .contains(&"/srv/0000-archive.docx".to_owned())
        );
        let on = FileWatchConfig {
            canaries: CanaryConfig {
                enabled: true,
                ..CanaryConfig::default()
            },
            ..FileWatchConfig::default()
        };
        assert!(on.validate().is_ok());
    }

    #[test]
    fn a_canary_the_watch_cannot_plant_is_refused() {
        let with = |canaries: CanaryConfig| FileWatchConfig {
            canaries,
            ..FileWatchConfig::default()
        };
        let base = CanaryConfig {
            enabled: true,
            ..CanaryConfig::default()
        };
        for bad in [
            CanaryConfig {
                directories: vec!["srv".into()],
                ..base.clone()
            },
            CanaryConfig {
                names: vec!["a/b".into()],
                ..base.clone()
            },
            CanaryConfig {
                names: Vec::new(),
                ..base.clone()
            },
            CanaryConfig {
                exempt: vec!["restic".into()],
                ..base.clone()
            },
            CanaryConfig {
                directories: (0..=CANARIES_MAX).map(|i| format!("/d{i}")).collect(),
                ..base.clone()
            },
        ] {
            assert!(with(bad.clone()).validate().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn hashing_past_the_ceiling_or_keeping_nothing_is_refused() {
        let big = FileWatchConfig {
            max_hash_bytes: MAX_HASH_BYTES_CEILING + 1,
            ..FileWatchConfig::default()
        };
        assert!(big.validate().is_err());
        let none = FileWatchConfig {
            max_baselines: 0,
            ..FileWatchConfig::default()
        };
        assert!(none.validate().is_err());
        let parsed: FileWatchConfig =
            serde_norway::from_str("max_hash_bytes: 1024\n").unwrap_or_default();
        assert_eq!(parsed.max_hash_bytes, 1024);
        assert_eq!(parsed.max_baselines, DEFAULT_MAX_BASELINES);
    }

    #[test]
    fn an_unknown_key_is_refused() {
        let parsed: Result<FileWatchConfig, _> =
            serde_norway::from_str("enabled: true\nmounts: [/]\n");
        assert!(parsed.is_err());
    }
}
