//! What a file was, and what changed since.
//!
//! A baseline is read on first sight and again after every change the watch
//! reports. What could not be read is said, with the reason, and never
//! recorded as an empty value: a file whose content could not be hashed has
//! no hash, not the hash of nothing.

use serde::{Deserialize, Serialize};

/// The kind of entry a path names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileType {
    Regular,
    Directory,
    Symlink,
    /// A device, a socket or a pipe: never opened, never hashed.
    Other,
}

/// One extended attribute, by name and the digest of its value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XattrDigest {
    pub name: String,
    /// SHA-256 of the value, in lower-case hex.
    pub sha256: String,
}

/// What a path named when it was last read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileBaseline {
    pub file_type: FileType,
    pub size: u64,
    /// Modification time, in nanoseconds since the epoch.
    pub mtime_ns: i64,
    /// Permission bits, set-id and sticky bits, without the type.
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub dev: u64,
    pub ino: u64,
    /// Where a symbolic link points.
    pub link_target: Option<String>,
    /// SHA-256 of a regular file's content, in lower-case hex.
    pub sha256: Option<String>,
    /// Why a regular file has no hash: too large to hash, or unreadable.
    pub hash_unread: Option<String>,
    /// Shannon entropy of the first 64 KiB of a regular file's content, in
    /// thousandths of a bit per byte, read with the hash. Absent where the
    /// content was not read, and in a baseline kept before it was measured.
    #[serde(default)]
    pub entropy_millibits: Option<u16>,
    /// Extended attributes, sorted by name.
    pub xattrs: Vec<XattrDigest>,
    /// Why the extended attributes could not be listed.
    pub xattrs_unread: Option<String>,
}

/// What reading a path found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileReading {
    Present(FileBaseline),
    /// Nothing is at the path any more.
    Gone,
    /// Something is there and could not be read, for this reason.
    Unreadable(String),
}

/// One path and what reading it found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileFacts {
    pub path: String,
    pub reading: FileReading,
}

/// What differs between a baseline and a new reading of its path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FileDrift {
    /// The content, or the target of a link, is different.
    Content,
    /// The content can no longer be hashed, so whether it changed is unknown.
    ContentUnverified,
    Mode,
    Owner,
    ExtendedAttributes,
    /// The path names another kind of entry, such as a link where a file was.
    TypeChanged,
    Disappeared,
    /// The path can no longer be read at all.
    Unreadable,
}

impl FileDrift {
    /// Every drift, in the order a comparison reports them.
    pub const ALL: [Self; 8] = [
        Self::Content,
        Self::ContentUnverified,
        Self::Mode,
        Self::Owner,
        Self::ExtendedAttributes,
        Self::TypeChanged,
        Self::Disappeared,
        Self::Unreadable,
    ];

    /// The name a metric or a log line carries.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Content => "content",
            Self::ContentUnverified => "content_unverified",
            Self::Mode => "mode",
            Self::Owner => "owner",
            Self::ExtendedAttributes => "extended_attributes",
            Self::TypeChanged => "type_changed",
            Self::Disappeared => "disappeared",
            Self::Unreadable => "unreadable",
        }
    }
}

impl FileBaseline {
    /// What differs in `reading` from this baseline, in [`FileDrift::ALL`]
    /// order; empty when nothing the baseline holds changed.
    #[must_use]
    pub fn drift(&self, reading: &FileReading) -> Vec<FileDrift> {
        let new = match reading {
            FileReading::Gone => return vec![FileDrift::Disappeared],
            FileReading::Unreadable(_) => return vec![FileDrift::Unreadable],
            FileReading::Present(new) => new,
        };
        if new.file_type != self.file_type {
            return vec![FileDrift::TypeChanged];
        }
        let mut drift = Vec::new();
        match (&self.sha256, &new.sha256) {
            (Some(old), Some(now)) if old != now => drift.push(FileDrift::Content),
            (Some(_), None) => drift.push(FileDrift::ContentUnverified),
            // Neither hashed, or only the new one: size and time are what is
            // left to compare.
            (None, _)
                if self.file_type == FileType::Regular
                    && (self.size != new.size || self.mtime_ns != new.mtime_ns) =>
            {
                drift.push(FileDrift::Content);
            }
            _ => {}
        }
        if self.link_target != new.link_target {
            drift.push(FileDrift::Content);
        }
        if self.mode != new.mode {
            drift.push(FileDrift::Mode);
        }
        if self.uid != new.uid || self.gid != new.gid {
            drift.push(FileDrift::Owner);
        }
        if self.xattrs_unread.is_none() && new.xattrs_unread.is_none() && self.xattrs != new.xattrs
        {
            drift.push(FileDrift::ExtendedAttributes);
        }
        drift.dedup();
        drift
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file() -> FileBaseline {
        FileBaseline {
            file_type: FileType::Regular,
            size: 12,
            mtime_ns: 1_700_000_000_000_000_000,
            mode: 0o644,
            uid: 0,
            gid: 0,
            dev: 2049,
            ino: 42,
            link_target: None,
            sha256: Some("a".repeat(64)),
            hash_unread: None,
            entropy_millibits: None,
            xattrs: vec![XattrDigest {
                name: "security.selinux".into(),
                sha256: "b".repeat(64),
            }],
            xattrs_unread: None,
        }
    }

    fn present(f: FileBaseline) -> FileReading {
        FileReading::Present(f)
    }

    #[test]
    fn the_same_reading_is_no_drift_even_on_another_inode() {
        let mut moved_over = file();
        moved_over.ino = 43;
        assert!(file().drift(&present(moved_over)).is_empty());
    }

    #[test]
    fn a_changed_hash_is_content() {
        let mut new = file();
        new.sha256 = Some("c".repeat(64));
        assert_eq!(file().drift(&present(new)), vec![FileDrift::Content]);
    }

    #[test]
    fn a_changed_mode_is_mode() {
        let mut new = file();
        new.mode = 0o4755;
        assert_eq!(file().drift(&present(new)), vec![FileDrift::Mode]);
    }

    #[test]
    fn a_changed_owner_or_group_is_owner() {
        let mut new = file();
        new.gid = 1000;
        assert_eq!(file().drift(&present(new)), vec![FileDrift::Owner]);
    }

    #[test]
    fn a_changed_xattr_is_extended_attributes() {
        let mut new = file();
        new.xattrs[0].sha256 = "d".repeat(64);
        assert_eq!(
            file().drift(&present(new)),
            vec![FileDrift::ExtendedAttributes]
        );
    }

    #[test]
    fn xattrs_unreadable_on_either_side_are_not_compared() {
        let mut new = file();
        new.xattrs = Vec::new();
        new.xattrs_unread = Some("permission denied".into());
        assert!(file().drift(&present(new)).is_empty());
    }

    #[test]
    fn a_file_that_disappeared_or_cannot_be_read_says_so() {
        assert_eq!(
            file().drift(&FileReading::Gone),
            vec![FileDrift::Disappeared]
        );
        assert_eq!(
            file().drift(&FileReading::Unreadable("permission denied".into())),
            vec![FileDrift::Unreadable]
        );
    }

    #[test]
    fn a_file_replaced_by_a_symlink_is_a_type_change() {
        let mut link = file();
        link.file_type = FileType::Symlink;
        link.sha256 = None;
        link.link_target = Some("/tmp/evil".into());
        assert_eq!(file().drift(&present(link)), vec![FileDrift::TypeChanged]);
    }

    #[test]
    fn a_hash_that_can_no_longer_be_read_is_unverified_never_a_zero() {
        let mut new = file();
        new.sha256 = None;
        new.hash_unread = Some("permission denied".into());
        assert_eq!(
            file().drift(&present(new)),
            vec![FileDrift::ContentUnverified]
        );
    }

    #[test]
    fn an_unhashed_file_falls_back_to_size_and_time() {
        let mut old = file();
        old.sha256 = None;
        old.hash_unread = Some("larger than 16777216 bytes".into());
        let same = old.clone();
        assert!(old.drift(&present(same)).is_empty());
        let mut grown = old.clone();
        grown.size = 13;
        assert_eq!(old.drift(&present(grown)), vec![FileDrift::Content]);
    }

    #[test]
    fn a_retargeted_link_is_content() {
        let mut old = file();
        old.file_type = FileType::Symlink;
        old.sha256 = None;
        old.link_target = Some("/usr/bin/true".into());
        let mut new = old.clone();
        new.link_target = Some("/tmp/x".into());
        assert_eq!(old.drift(&present(new)), vec![FileDrift::Content]);
    }

    #[test]
    fn every_drift_has_a_distinct_name() {
        let mut names: Vec<_> = FileDrift::ALL.iter().map(|d| d.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), FileDrift::ALL.len());
    }
}
