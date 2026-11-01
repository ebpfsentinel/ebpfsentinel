//! A change on a watched filesystem.

/// What happened to an entry. One report may carry several, because the
/// kernel merges changes to one entry that are still queued together.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FileChangeKind {
    /// The entry appeared in the directory.
    Created,
    /// A file opened for writing was closed.
    Written,
    /// Its mode, owner, times or extended attributes changed.
    AttributesChanged,
    /// It was moved out of the directory.
    MovedOut,
    /// It was moved into the directory.
    MovedIn,
    /// It was removed from the directory.
    Deleted,
}

impl FileChangeKind {
    /// Every kind, in the order a report lists them.
    pub const ALL: [Self; 6] = [
        Self::Created,
        Self::Written,
        Self::AttributesChanged,
        Self::MovedOut,
        Self::MovedIn,
        Self::Deleted,
    ];

    /// The name a metric or a log line carries.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Written => "written",
            Self::AttributesChanged => "attributes_changed",
            Self::MovedOut => "moved_out",
            Self::MovedIn => "moved_in",
            Self::Deleted => "deleted",
        }
    }
}

/// One change, as the agent's mount namespace (or the warden's) reaches it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileChange {
    /// What happened, in [`FileChangeKind::ALL`] order and never empty.
    pub kinds: Vec<FileChangeKind>,
    /// Whether the entry is a directory.
    pub is_dir: bool,
    /// The process that made the change, `0` when it could not be named.
    pub pid: u32,
    /// The directory holding the entry. On an overlay this is the upper
    /// directory on the filesystem beneath, not the path the writer saw.
    pub directory: Option<String>,
    /// The entry inside that directory.
    pub name: String,
    /// Device of the entry, when it still existed once read.
    pub dev: Option<u64>,
    /// Inode of the entry, when it still existed once read.
    pub ino: Option<u64>,
    /// Why the directory could not be named, when it could not.
    pub unresolved: Option<String>,
    /// For a rename reported with both names, the full path the entry left.
    pub renamed_from: Option<String>,
}

/// A canary opened or read: the only file the watch reports an open of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileOpened {
    /// The process that opened it, `0` when it could not be named.
    pub pid: u32,
    /// The canary's path, absent when its directory could not be named.
    pub path: Option<String>,
}

/// A canary the watch was asked to plant, and whether one stands there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlantedCanary {
    /// The path asked for.
    pub path: String,
    /// Why no canary is watched there, `None` when one is.
    pub error: Option<String>,
}

/// What one reading handed over.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileChangeBatch {
    /// The changes, in the order the kernel queued them.
    pub changes: Vec<FileChange>,
    /// Canaries opened or read, in the order the kernel queued them.
    pub opened: Vec<FileOpened>,
    /// Changes were lost before these because the kernel's queue was full.
    pub overflowed: bool,
}

/// A filesystem the watch was asked to cover, and whether it does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchedFilesystem {
    /// The path the configuration named.
    pub path: String,
    /// Why the filesystem holding it is not watched, `None` when it is.
    pub error: Option<String>,
    /// Its renames are reported once with both names; where they are not, a
    /// rename reads as a disappearance plus an appearance.
    pub renames: bool,
}

impl WatchedFilesystem {
    /// Whether the mark took.
    #[must_use]
    pub const fn is_watched(&self) -> bool {
        self.error.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_kind_has_a_distinct_name() {
        let mut names: Vec<_> = FileChangeKind::ALL.iter().map(|k| k.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), FileChangeKind::ALL.len());
    }

    #[test]
    fn a_filesystem_with_a_reason_is_not_watched() {
        let refused = WatchedFilesystem {
            path: "/".into(),
            error: Some("no such path".into()),
            renames: false,
        };
        assert!(!refused.is_watched());
        let watched = WatchedFilesystem {
            path: "/".into(),
            error: None,
            renames: true,
        };
        assert!(watched.is_watched());
    }
}
