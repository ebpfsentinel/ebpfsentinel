//! Paths whose change is an alert: the files and directories an operator
//! declares, or a profile names, because a difference there is somebody's
//! business rather than a line in a log.
//!
//! The watch covers whole filesystems and compares every changed path with
//! its baseline whatever is declared; declaring a path only decides what a
//! difference there amounts to. A declared file is read as soon as the watch
//! opens, so its first change is compared rather than learned; a file first
//! seen under a declared directory is learned, unless it arrived while the
//! watch was open, which is an alert of its own.

use std::collections::{BTreeMap, BTreeSet};

use super::baseline::FileDrift;
use super::entity::FileChangeKind;
use crate::alert::mitre::MitreAttackInfo;
use crate::common::entity::RuleId;

/// The component of the alerts raised for a change under a watched path.
pub const FILE_INTEGRITY_COMPONENT: &str = "file_integrity";

/// Most paths watched at once, declared and profiled together.
pub const WATCHED_PATHS_MAX: usize = 1024;

/// Longest watched path, in bytes.
pub const WATCHED_PATH_MAX_BYTES: usize = 4096;

/// What the operator's own list is called where a path came from.
pub const DECLARED_ORIGIN: &str = "configuration";

/// Checks that `path` is written the way a watched path is: absolute, not
/// the root, with no empty, `.` or `..` component and no trailing slash.
///
/// # Errors
///
/// What is wrong with it, in words.
pub fn check_watched_path(path: &str) -> Result<(), String> {
    if !path.starts_with('/') {
        return Err(format!("`{path}` is not absolute"));
    }
    if path == "/" {
        return Err(
            "`/` would make every change on the filesystem an alert; name the files and \
             directories that matter"
                .to_owned(),
        );
    }
    if path.len() > WATCHED_PATH_MAX_BYTES {
        return Err(format!(
            "a path longer than {WATCHED_PATH_MAX_BYTES} bytes is not one the kernel names"
        ));
    }
    if path[1..]
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(format!(
            "`{path}` carries an empty, `.` or `..` component, or ends with `/`"
        ));
    }
    Ok(())
}

/// The watched paths, each with where it came from: [`DECLARED_ORIGIN`] for
/// the configuration, a profile's name otherwise.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WatchedPaths {
    paths: BTreeMap<String, String>,
}

impl WatchedPaths {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Watch `path`, noting where it came from. A path named twice keeps its
    /// first origin.
    ///
    /// # Errors
    ///
    /// The path is not written the way a watched path is, or the set already
    /// holds [`WATCHED_PATHS_MAX`] paths.
    pub fn add(&mut self, path: &str, origin: &str) -> Result<(), String> {
        check_watched_path(path)?;
        if self.paths.contains_key(path) {
            return Ok(());
        }
        if self.paths.len() >= WATCHED_PATHS_MAX {
            return Err(format!("at most {WATCHED_PATHS_MAX} paths are watched"));
        }
        self.paths.insert(path.to_owned(), origin.to_owned());
        Ok(())
    }

    /// The watched path covering `path`, itself or its nearest watched
    /// ancestor, and where that came from.
    #[must_use]
    pub fn covering(&self, path: &str) -> Option<(&str, &str)> {
        let mut at = path;
        loop {
            if let Some((declared, origin)) = self.paths.get_key_value(at) {
                return Some((declared.as_str(), origin.as_str()));
            }
            match at.rsplit_once('/') {
                Some((parent, _)) if !parent.is_empty() => at = parent,
                _ => return None,
            }
        }
    }

    /// Whether `path` is itself watched, rather than under a watched
    /// directory.
    #[must_use]
    pub fn names(&self, path: &str) -> bool {
        self.paths.contains_key(path)
    }

    /// Every watched path, in order.
    pub fn paths(&self) -> impl Iterator<Item = &str> {
        self.paths.keys().map(String::as_str)
    }

    /// Where each watched path sits: what the watch is opened on so the
    /// filesystem holding it is watched, each once.
    #[must_use]
    pub fn directories(&self) -> Vec<String> {
        let dirs: BTreeSet<String> = self
            .paths
            .keys()
            .filter_map(|path| match path.rsplit_once('/') {
                Some(("", _)) => Some("/".to_owned()),
                Some((dir, _)) => Some(dir.to_owned()),
                None => None,
            })
            .collect();
        dirs.into_iter().collect()
    }

    /// How many paths came from each origin.
    #[must_use]
    pub fn origins(&self) -> BTreeMap<&str, usize> {
        let mut counts = BTreeMap::new();
        for origin in self.paths.values() {
            *counts.entry(origin.as_str()).or_default() += 1;
        }
        counts
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.paths.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }
}

/// A difference under a watched path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchedPathChange {
    /// The path that changed.
    pub path: String,
    /// The watched path covering it.
    pub watched: String,
    /// Where the watched path came from.
    pub origin: String,
    /// What differs from the baseline; empty when the path appeared.
    pub drift: Vec<FileDrift>,
    /// The path arrived while the watch was open and had no baseline.
    pub appeared: bool,
    /// The writer, `0` when the kernel could not name it in the agent's
    /// view.
    pub writer: u32,
}

impl WatchedPathChange {
    /// The rule the change raises.
    #[must_use]
    pub fn rule_id(&self) -> RuleId {
        RuleId(
            if self.appeared {
                "watched-path-appeared"
            } else {
                "watched-path-changed"
            }
            .to_owned(),
        )
    }

    /// The alert's sentence.
    #[must_use]
    pub fn message(&self) -> String {
        let by = if self.writer == 0 {
            "a process the agent cannot name".to_owned()
        } else {
            format!("process {}", self.writer)
        };
        let under = if self.path == self.watched {
            format!("watched through {}", self.origin)
        } else {
            format!("under {}, watched through {}", self.watched, self.origin)
        };
        if self.appeared {
            format!("{} appeared {under}, put there by {by}", self.path)
        } else {
            let what: Vec<&str> = self.drift.iter().map(|d| d.as_str()).collect();
            format!(
                "{} {under} was changed by {by}: {}",
                self.path,
                what.join(", ")
            )
        }
    }

    /// A watched file is one whose content somebody relies on, so changing
    /// it is manipulating stored data.
    #[must_use]
    pub fn mitre() -> MitreAttackInfo {
        MitreAttackInfo {
            technique_id: "T1565.001".to_string(),
            technique_name: "Data Manipulation: Stored Data Manipulation".to_string(),
            tactic: "impact".to_string(),
        }
    }
}

/// One settled change, as the watched paths judge it.
#[derive(Debug, Clone, Copy)]
pub struct SettledPath<'a> {
    pub path: &'a str,
    /// Every kind of change seen since the path was last read.
    pub kinds: &'a BTreeSet<FileChangeKind>,
    /// Whether the path was known before this reading.
    pub had_baseline: bool,
    /// What differs from the baseline.
    pub drift: &'a [FileDrift],
    /// Whether the path exists now.
    pub present: bool,
    /// The writer, `0` when unnamed.
    pub writer: u32,
}

/// What a settled change amounts to, given the watched paths.
///
/// Nothing when no watched path covers it, when the agent itself wrote it,
/// or when nothing differs and nothing arrived.
#[must_use]
pub fn watched_path_change(
    watched: &WatchedPaths,
    settled: &SettledPath<'_>,
    own_pid: u32,
) -> Option<WatchedPathChange> {
    let writer = settled.writer;
    if writer != 0 && writer == own_pid {
        return None;
    }
    let (covering, origin) = watched.covering(settled.path)?;
    let kinds = settled.kinds;
    let appeared = !settled.had_baseline
        && settled.present
        && (kinds.contains(&FileChangeKind::Created) || kinds.contains(&FileChangeKind::MovedIn));
    if settled.drift.is_empty() && !appeared {
        return None;
    }
    Some(WatchedPathChange {
        path: settled.path.to_owned(),
        watched: covering.to_owned(),
        origin: origin.to_owned(),
        drift: settled.drift.to_vec(),
        appeared,
        writer,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn watched() -> WatchedPaths {
        let mut set = WatchedPaths::new();
        set.add("/etc/ssh", DECLARED_ORIGIN).unwrap();
        set.add("/etc/shadow", "debian").unwrap();
        set
    }

    fn kinds(list: &[FileChangeKind]) -> BTreeSet<FileChangeKind> {
        list.iter().copied().collect()
    }

    fn judge(
        set: &WatchedPaths,
        path: &str,
        kinds: &BTreeSet<FileChangeKind>,
        (had_baseline, present): (bool, bool),
        drift: &[FileDrift],
        (writer, own_pid): (u32, u32),
    ) -> Option<WatchedPathChange> {
        let settled = SettledPath {
            path,
            kinds,
            had_baseline,
            drift,
            present,
            writer,
        };
        watched_path_change(set, &settled, own_pid)
    }

    #[test]
    fn a_path_is_covered_by_itself_or_its_nearest_watched_ancestor() {
        let set = watched();
        assert_eq!(set.covering("/etc/shadow"), Some(("/etc/shadow", "debian")));
        assert_eq!(
            set.covering("/etc/ssh/sshd_config.d/x.conf"),
            Some(("/etc/ssh", DECLARED_ORIGIN))
        );
        assert_eq!(set.covering("/etc/sshd"), None);
        assert_eq!(set.covering("/etc/shadow-"), None);
        assert_eq!(set.covering("/etc"), None);
        assert!(set.names("/etc/ssh"));
        assert!(!set.names("/etc/ssh/sshd_config"));
    }

    #[test]
    fn a_watched_path_is_absolute_and_never_the_root() {
        for bad in ["etc", "/", "/etc/", "/etc//ssh", "/etc/../shadow", "/./etc"] {
            assert!(check_watched_path(bad).is_err(), "{bad}");
        }
        assert!(check_watched_path("/etc/ssh").is_ok());
        let mut set = WatchedPaths::new();
        assert!(set.add("relative", DECLARED_ORIGIN).is_err());
        assert!(set.is_empty());
    }

    #[test]
    fn the_first_origin_of_a_path_is_kept_and_the_set_is_bounded() {
        let mut set = watched();
        set.add("/etc/shadow", "rhel").unwrap();
        assert_eq!(set.covering("/etc/shadow"), Some(("/etc/shadow", "debian")));
        assert_eq!(set.origins().get("debian"), Some(&1));
        let mut full = WatchedPaths::new();
        for i in 0..WATCHED_PATHS_MAX {
            full.add(&format!("/w/{i}"), DECLARED_ORIGIN).unwrap();
        }
        assert!(full.add("/w/last", DECLARED_ORIGIN).is_err());
        assert_eq!(full.directories(), vec!["/w".to_owned()]);
    }

    #[test]
    fn a_difference_under_a_watched_path_is_a_change() {
        let written = kinds(&[FileChangeKind::Written]);
        let change = judge(
            &watched(),
            "/etc/ssh/sshd_config",
            &written,
            (true, true),
            &[FileDrift::Content],
            (812, 77),
        )
        .unwrap();
        assert_eq!(change.rule_id().0, "watched-path-changed");
        assert_eq!(
            change.message(),
            "/etc/ssh/sshd_config under /etc/ssh, watched through configuration was changed by process 812: content"
        );
        let shadow = judge(
            &watched(),
            "/etc/shadow",
            &written,
            (true, true),
            &[FileDrift::Mode],
            (812, 77),
        )
        .unwrap();
        assert_eq!(
            shadow.message(),
            "/etc/shadow watched through debian was changed by process 812: mode"
        );
    }

    #[test]
    fn a_file_arriving_under_a_watched_directory_is_an_appearance() {
        let created = kinds(&[FileChangeKind::Created, FileChangeKind::Written]);
        let change = judge(
            &watched(),
            "/etc/ssh/authorized_keys2",
            &created,
            (false, true),
            &[],
            (0, 77),
        )
        .unwrap();
        assert!(change.appeared);
        assert_eq!(change.rule_id().0, "watched-path-appeared");
        assert!(
            change
                .message()
                .ends_with("put there by a process the agent cannot name")
        );
    }

    #[test]
    fn nothing_is_raised_outside_the_watch_by_the_agent_or_for_nothing() {
        let set = watched();
        let written = kinds(&[FileChangeKind::Written]);
        let drift = [FileDrift::Content];
        let known = (true, true);
        assert!(judge(&set, "/var/log/x", &written, known, &drift, (9, 1)).is_none());
        assert!(judge(&set, "/etc/shadow", &written, known, &drift, (77, 77)).is_none());
        assert!(judge(&set, "/etc/shadow", &written, known, &[], (9, 1)).is_none());
        // Seen for the first time without arriving: learned, not raised.
        assert!(judge(&set, "/etc/ssh/known", &written, (false, true), &[], (9, 1)).is_none());
        // Arrived and already gone again: nothing is left to report on.
        let created = kinds(&[FileChangeKind::Created]);
        assert!(judge(&set, "/etc/ssh/tmp", &created, (false, false), &[], (9, 1)).is_none());
    }
}
