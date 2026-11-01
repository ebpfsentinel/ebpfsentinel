//! A write refused in the kernel, past a count of write-opens.
//!
//! The detection of this module's siblings reaches a verdict after the
//! files are written; this is the part that stops the next one from being
//! opened. A writer is counted against the watched directories, inside a
//! window, and the write-open that reaches the threshold is refused by the
//! kernel before a byte moves, so a run loses `threshold - 1` files there
//! and no more. It needs the BPF LSM active at boot, and it fails open: an
//! agent that is gone refuses nothing.

use ebpf_common::write_refusal::{
    WRITE_REFUSAL_HOOK_OPEN, WRITE_REFUSAL_HOOK_TRUNCATE, WRITE_REFUSAL_MAX_DIRECTORIES,
    WRITE_REFUSAL_MAX_WRITERS,
};

use crate::common::entity::RuleId;

/// The rule a write refusal alert carries.
pub const WRITE_REFUSAL_RULE_ID: &str = "write-refusal";

/// How many directories the watched set may name; the kernel's map size.
pub const MAX_WRITE_REFUSAL_DIRECTORIES: usize = WRITE_REFUSAL_MAX_DIRECTORIES as usize;

/// How many writers the kernel counts at once; past it a newcomer is let
/// through and counted as such.
pub const WRITE_REFUSAL_WRITERS: usize = WRITE_REFUSAL_MAX_WRITERS as usize;

/// The threshold that ships: the write-opens inside one window that a single
/// writer may make under the watched directories before the next is refused.
/// The same number the detection uses for distinct files rewritten, so the
/// kernel refuses where the userspace reading would have reached its verdict.
pub const WRITE_REFUSAL_THRESHOLD: u32 = 100;

/// The window that ships, in seconds; the detection's own.
pub const WRITE_REFUSAL_WINDOW_SECS: u64 = 60;

/// The longest window a configuration may set. A day-long window turns a
/// counter into a quota, which is a different feature.
pub const MAX_WRITE_REFUSAL_WINDOW_SECS: u64 = 3_600;

/// What a writer is counted as.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CountBy {
    /// One count per thread group.
    #[default]
    Process,
    /// One count per cgroup, so the workers a run forks share the count of
    /// the process that forked them, which a per-process count lets each of
    /// them restart.
    Cgroup,
}

impl CountBy {
    /// The name the configuration and the API use.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Process => "process",
            Self::Cgroup => "cgroup",
        }
    }
}

/// Which call was decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteRefusalHook {
    /// A file opened for writing, created or truncated by `open`.
    Open,
    /// A file truncated by path.
    Truncate,
}

impl WriteRefusalHook {
    /// The hook a kernel record names, `None` for a number this build does
    /// not know.
    #[must_use]
    pub fn from_kernel(value: u8) -> Option<Self> {
        match value {
            WRITE_REFUSAL_HOOK_OPEN => Some(Self::Open),
            WRITE_REFUSAL_HOOK_TRUNCATE => Some(Self::Truncate),
            _ => None,
        }
    }

    /// What the writer was doing, for a sentence.
    #[must_use]
    pub fn describe(self) -> &'static str {
        match self {
            Self::Open => "opening for writing",
            Self::Truncate => "truncating",
        }
    }
}

/// A writer that reached the threshold, as the kernel reported it once per
/// writer and window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteRefusalRecord {
    /// `bpf_ktime_get_boot_ns` at the decision.
    pub at_ns: u64,
    /// Thread group that wrote.
    pub tgid: u32,
    /// The writer's cgroup.
    pub cgroup_id: u64,
    /// The file's device and inode, in the encoding `stat(2)` uses.
    pub file: (u64, u64),
    /// The file's own name, as the kernel read it, possibly cut.
    pub name: String,
    /// The watched directory it lies under, as configured, or `None` when
    /// the set changed between the decision and the reading.
    pub directory: Option<String>,
    /// The count that reached the threshold.
    pub count: u32,
    /// Which call was decided.
    pub hook: WriteRefusalHook,
    /// The kernel refused the write rather than counted it.
    pub refused: bool,
}

impl WriteRefusalRecord {
    /// The rule the alert carries.
    #[must_use]
    pub fn rule() -> RuleId {
        RuleId(WRITE_REFUSAL_RULE_ID.to_string())
    }

    /// One sentence saying what happened.
    #[must_use]
    pub fn message(&self) -> String {
        let verb = if self.refused {
            "refused"
        } else {
            "would refuse"
        };
        let under = self
            .directory
            .as_deref()
            .map_or_else(|| "a watched directory".to_string(), |d| format!("`{d}`"));
        format!(
            "write refusal {verb} pid {} {} `{}` under {under}: write {} inside the window, and every one after it until the window ends",
            self.tgid,
            self.hook.describe(),
            self.name,
            self.count,
        )
    }
}

/// Why a watched set cannot be applied.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WriteRefusalError {
    /// Turned on with nothing to watch.
    #[error("names no directory to watch")]
    Empty,
    /// A path is relative, which the agent would resolve against its own
    /// working directory rather than the one the operator meant.
    #[error("`{0}` is not an absolute path")]
    NotAbsolute(String),
    /// The root, which would count every write on the node.
    #[error("`/` would count every write on the node; name the data directories")]
    Root,
    /// A path is listed twice.
    #[error("`{0}` is listed twice")]
    Duplicate(String),
    /// The set does not fit the kernel's map.
    #[error("{0} directories are listed, and at most {MAX_WRITE_REFUSAL_DIRECTORIES} fit")]
    TooMany(usize),
    /// A threshold of zero.
    #[error("the threshold must be at least 1")]
    ZeroThreshold,
    /// A window of zero or past the ceiling.
    #[error("the window must be between 1 and {MAX_WRITE_REFUSAL_WINDOW_SECS} seconds")]
    Window,
}

/// Check a watched set and its numbers before anything is stat-ed or
/// written.
///
/// # Errors
///
/// Returns the first entry, or number, that cannot be applied.
pub fn validate_write_refusal(
    paths: &[String],
    threshold: u32,
    window_secs: u64,
) -> Result<(), WriteRefusalError> {
    if paths.is_empty() {
        return Err(WriteRefusalError::Empty);
    }
    if paths.len() > MAX_WRITE_REFUSAL_DIRECTORIES {
        return Err(WriteRefusalError::TooMany(paths.len()));
    }
    let mut seen = std::collections::HashSet::new();
    for path in paths {
        if !path.starts_with('/') {
            return Err(WriteRefusalError::NotAbsolute(path.clone()));
        }
        if path.trim_end_matches('/').is_empty() {
            return Err(WriteRefusalError::Root);
        }
        if !seen.insert(path.trim_end_matches('/')) {
            return Err(WriteRefusalError::Duplicate(path.clone()));
        }
    }
    if threshold == 0 {
        return Err(WriteRefusalError::ZeroThreshold);
    }
    if window_secs == 0 || window_secs > MAX_WRITE_REFUSAL_WINDOW_SECS {
        return Err(WriteRefusalError::Window);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(p: &[&str]) -> Vec<String> {
        p.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn a_set_of_data_directories_with_the_shipped_numbers_is_accepted() {
        assert_eq!(
            validate_write_refusal(
                &paths(&["/srv/data", "/home"]),
                WRITE_REFUSAL_THRESHOLD,
                WRITE_REFUSAL_WINDOW_SECS
            ),
            Ok(())
        );
    }

    #[test]
    fn each_shape_that_cannot_be_applied_is_named() {
        let ok = paths(&["/srv"]);
        assert_eq!(
            validate_write_refusal(&[], 1, 1),
            Err(WriteRefusalError::Empty)
        );
        assert_eq!(
            validate_write_refusal(&paths(&["srv"]), 1, 1),
            Err(WriteRefusalError::NotAbsolute("srv".into()))
        );
        assert_eq!(
            validate_write_refusal(&paths(&["//"]), 1, 1),
            Err(WriteRefusalError::Root)
        );
        assert_eq!(
            validate_write_refusal(&paths(&["/srv", "/srv/"]), 1, 1),
            Err(WriteRefusalError::Duplicate("/srv/".into()))
        );
        let many: Vec<String> = (0..=MAX_WRITE_REFUSAL_DIRECTORIES)
            .map(|i| format!("/d{i}"))
            .collect();
        assert_eq!(
            validate_write_refusal(&many, 1, 1),
            Err(WriteRefusalError::TooMany(
                MAX_WRITE_REFUSAL_DIRECTORIES + 1
            ))
        );
        assert_eq!(
            validate_write_refusal(&ok, 0, 1),
            Err(WriteRefusalError::ZeroThreshold)
        );
        assert_eq!(
            validate_write_refusal(&ok, 1, 0),
            Err(WriteRefusalError::Window)
        );
        assert_eq!(
            validate_write_refusal(&ok, 1, MAX_WRITE_REFUSAL_WINDOW_SECS + 1),
            Err(WriteRefusalError::Window)
        );
    }

    #[test]
    fn the_hooks_read_back_from_the_kernel_numbers() {
        assert_eq!(
            WriteRefusalHook::from_kernel(WRITE_REFUSAL_HOOK_OPEN),
            Some(WriteRefusalHook::Open)
        );
        assert_eq!(
            WriteRefusalHook::from_kernel(WRITE_REFUSAL_HOOK_TRUNCATE),
            Some(WriteRefusalHook::Truncate)
        );
        assert_eq!(WriteRefusalHook::from_kernel(7), None);
    }

    #[test]
    fn the_message_says_refused_or_would_refuse_and_names_the_directory() {
        let mut record = WriteRefusalRecord {
            at_ns: 1,
            tgid: 4242,
            cgroup_id: 9,
            file: (2049, 77),
            name: "invoice.pdf".into(),
            directory: Some("/srv/data".into()),
            count: 100,
            hook: WriteRefusalHook::Open,
            refused: true,
        };
        let m = record.message();
        assert!(m.starts_with("write refusal refused pid 4242 opening for writing `invoice.pdf`"));
        assert!(m.contains("under `/srv/data`"), "{m}");
        record.refused = false;
        record.directory = None;
        let m = record.message();
        assert!(m.contains("would refuse"), "{m}");
        assert!(m.contains("under a watched directory"), "{m}");
    }

    #[test]
    fn the_counting_unit_is_named_as_the_configuration_writes_it() {
        assert_eq!(CountBy::default(), CountBy::Process);
        assert_eq!(CountBy::Cgroup.as_str(), "cgroup");
    }
}
