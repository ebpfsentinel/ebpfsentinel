//! What a watched file is expected to be on every node of a fleet.
//!
//! A baseline holds what one node read, inode and modification time
//! included, and no two nodes share those. A fingerprint keeps only what a
//! fleet can agree on: the kind of entry, the content hash or the link
//! target, the permission bits, the owner and the extended attribute
//! digests. A set of fingerprints held as the expected state is what a node
//! joining the fleet is compared against on first sight, instead of learning
//! whatever was on its disk when the agent started.
//!
//! A fingerprint carries digests and never content, so the set an estate
//! holds names its files and nothing of what is in them.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::baseline::{FileBaseline, FileDrift, FileReading, FileType, XattrDigest};
use super::watched::check_watched_path;

/// Most fingerprints held as the expected state, and most one node lists.
pub const EXPECTED_BASELINES_MAX: usize = 100_000;

/// The part of a baseline every node of a fleet can share.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileFingerprint {
    pub file_type: FileType,
    /// SHA-256 of a regular file's content, in lower-case hex; absent when
    /// the node that read it could not hash it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Where a symbolic link points.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_target: Option<String>,
    /// Permission bits, set-id and sticky bits, without the type.
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    /// Extended attributes sorted by name; absent when they could not be
    /// listed, which is not the same as none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xattrs: Option<Vec<XattrDigest>>,
}

impl FileFingerprint {
    /// What a fleet can share of `baseline`.
    #[must_use]
    pub fn of(baseline: &FileBaseline) -> Self {
        Self {
            file_type: baseline.file_type,
            sha256: baseline.sha256.clone(),
            link_target: baseline.link_target.clone(),
            mode: baseline.mode,
            uid: baseline.uid,
            gid: baseline.gid,
            xattrs: baseline
                .xattrs_unread
                .is_none()
                .then(|| baseline.xattrs.clone()),
        }
    }

    /// What differs in `reading` from this expected state, in
    /// [`FileDrift::ALL`] order. Only what both sides hold is compared: an
    /// expected file with no hash says nothing of the content, and nothing
    /// is said of attributes either side could not list.
    #[must_use]
    pub fn drift(&self, reading: &FileReading) -> Vec<FileDrift> {
        let now = match reading {
            FileReading::Gone => return vec![FileDrift::Disappeared],
            FileReading::Unreadable(_) => return vec![FileDrift::Unreadable],
            FileReading::Present(now) => now,
        };
        if now.file_type != self.file_type {
            return vec![FileDrift::TypeChanged];
        }
        let mut drift = Vec::new();
        match (&self.sha256, &now.sha256) {
            (Some(expected), Some(read)) if expected != read => drift.push(FileDrift::Content),
            (Some(_), None) => drift.push(FileDrift::ContentUnverified),
            _ => {}
        }
        if self.link_target != now.link_target {
            drift.push(FileDrift::Content);
        }
        if self.mode != now.mode {
            drift.push(FileDrift::Mode);
        }
        if self.uid != now.uid || self.gid != now.gid {
            drift.push(FileDrift::Owner);
        }
        if let Some(expected) = &self.xattrs
            && now.xattrs_unread.is_none()
            && *expected != now.xattrs
        {
            drift.push(FileDrift::ExtendedAttributes);
        }
        drift.dedup();
        drift
    }

    fn check(&self) -> Result<(), String> {
        let hex = |value: &str| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        if let Some(sha) = &self.sha256
            && !hex(sha)
        {
            return Err("a content hash is 64 lower-case hex digits".to_owned());
        }
        if self.mode > 0o7777 {
            return Err(format!(
                "mode {:o} carries more than permission bits",
                self.mode
            ));
        }
        if let Some(xattrs) = &self.xattrs
            && let Some(bad) = xattrs.iter().find(|x| x.name.is_empty() || !hex(&x.sha256))
        {
            return Err(format!(
                "extended attribute `{}` needs a name and a 64 hex digit digest",
                bad.name
            ));
        }
        Ok(())
    }
}

/// One path and the fingerprint expected there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedBaseline {
    pub path: String,
    #[serde(flatten)]
    pub fingerprint: FileFingerprint,
}

/// The expected state a fleet holds, by path.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExpectedBaselines {
    by_path: BTreeMap<String, FileFingerprint>,
}

impl ExpectedBaselines {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The expected state `entries` describe.
    ///
    /// # Errors
    ///
    /// A path that is not written the way a watched path is, a path named
    /// twice, a fingerprint whose hash or mode is malformed, or more than
    /// [`EXPECTED_BASELINES_MAX`] entries: the set is refused whole, because
    /// half a fleet's expected state compares a node against nothing for the
    /// half left out.
    pub fn from_entries(entries: Vec<ExpectedBaseline>) -> Result<Self, String> {
        if entries.len() > EXPECTED_BASELINES_MAX {
            return Err(format!(
                "at most {EXPECTED_BASELINES_MAX} expected baselines are held"
            ));
        }
        let mut by_path = BTreeMap::new();
        for entry in entries {
            check_watched_path(&entry.path)?;
            entry
                .fingerprint
                .check()
                .map_err(|e| format!("{}: {e}", entry.path))?;
            if by_path
                .insert(entry.path.clone(), entry.fingerprint)
                .is_some()
            {
                return Err(format!("`{}` is named twice", entry.path));
            }
        }
        Ok(Self { by_path })
    }

    /// The fingerprint expected at `path`.
    #[must_use]
    pub fn get(&self, path: &str) -> Option<&FileFingerprint> {
        self.by_path.get(path)
    }

    /// Every path the set names, in order.
    pub fn paths(&self) -> impl Iterator<Item = &str> {
        self.by_path.keys().map(String::as_str)
    }

    /// Every entry, in path order, in the shape it was written in.
    #[must_use]
    pub fn entries(&self) -> Vec<ExpectedBaseline> {
        self.by_path
            .iter()
            .map(|(path, fingerprint)| ExpectedBaseline {
                path: path.clone(),
                fingerprint: fingerprint.clone(),
            })
            .collect()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.by_path.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_path.is_empty()
    }
}

/// The written form of a fleet's expected state: what one node lists of its
/// own baselines, and what every node is handed back.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedBaselinesDocument {
    pub baselines: Vec<ExpectedBaseline>,
    /// Whether the node that listed them left some out.
    #[serde(default)]
    pub truncated: bool,
}

impl ExpectedBaselinesDocument {
    /// The expected state this document describes.
    ///
    /// # Errors
    ///
    /// A listing a node cut short, and every refusal of
    /// [`ExpectedBaselines::from_entries`]: what was left out of a listing
    /// is not known to be expected, and holding the rest would read as a
    /// fleet agreeing on less than it does.
    pub fn into_expected(self) -> Result<ExpectedBaselines, String> {
        if self.truncated {
            return Err("the listing was cut short, so it is not a whole expected state".into());
        }
        ExpectedBaselines::from_entries(self.baselines)
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
            head: None,
            xattrs: vec![XattrDigest {
                name: "security.selinux".into(),
                sha256: "b".repeat(64),
            }],
            xattrs_unread: None,
        }
    }

    #[test]
    fn another_node_reading_the_same_file_matches_whatever_its_inode_and_time() {
        let expected = FileFingerprint::of(&file());
        let mut elsewhere = file();
        elsewhere.ino = 7;
        elsewhere.dev = 3;
        elsewhere.mtime_ns = 1;
        assert!(expected.drift(&FileReading::Present(elsewhere)).is_empty());
    }

    #[test]
    fn content_mode_owner_and_attributes_are_each_named() {
        let expected = FileFingerprint::of(&file());
        let mut other = file();
        other.sha256 = Some("c".repeat(64));
        other.mode = 0o600;
        other.gid = 4;
        other.xattrs.clear();
        assert_eq!(
            expected.drift(&FileReading::Present(other)),
            vec![
                FileDrift::Content,
                FileDrift::Mode,
                FileDrift::Owner,
                FileDrift::ExtendedAttributes
            ]
        );
        assert_eq!(
            expected.drift(&FileReading::Gone),
            vec![FileDrift::Disappeared]
        );
    }

    #[test]
    fn what_either_side_could_not_read_is_not_compared_as_a_difference() {
        let mut unhashed = file();
        unhashed.sha256 = None;
        unhashed.xattrs_unread = Some("not supported".into());
        let expected = FileFingerprint::of(&unhashed);
        assert_eq!(expected.xattrs, None);
        let mut other = file();
        other.sha256 = Some("c".repeat(64));
        other.xattrs.clear();
        assert!(expected.drift(&FileReading::Present(other)).is_empty());

        let hashed = FileFingerprint::of(&file());
        assert_eq!(
            hashed.drift(&FileReading::Present(unhashed)),
            vec![FileDrift::ContentUnverified]
        );
    }

    #[test]
    fn a_link_pointing_elsewhere_is_content_and_a_file_in_its_place_is_a_type_change() {
        let mut link = file();
        link.file_type = FileType::Symlink;
        link.sha256 = None;
        link.link_target = Some("/usr/lib/a".into());
        let expected = FileFingerprint::of(&link);
        let mut moved = link.clone();
        moved.link_target = Some("/tmp/a".into());
        assert_eq!(
            expected.drift(&FileReading::Present(moved)),
            vec![FileDrift::Content]
        );
        assert_eq!(
            expected.drift(&FileReading::Present(file())),
            vec![FileDrift::TypeChanged]
        );
    }

    #[test]
    fn the_expected_state_is_refused_whole_on_one_bad_entry() {
        let good = ExpectedBaseline {
            path: "/etc/ssh/sshd_config".into(),
            fingerprint: FileFingerprint::of(&file()),
        };
        let held = ExpectedBaselines::from_entries(vec![good.clone()]).unwrap();
        assert_eq!(held.len(), 1);
        assert!(held.get("/etc/ssh/sshd_config").is_some());
        assert!(held.get("/etc/ssh").is_none());

        assert!(ExpectedBaselines::from_entries(vec![good.clone(), good.clone()]).is_err());
        let mut relative = good.clone();
        relative.path = "etc/ssh".into();
        assert!(ExpectedBaselines::from_entries(vec![relative]).is_err());
        let mut upper = good.clone();
        upper.fingerprint.sha256 = Some("A".repeat(64));
        assert!(ExpectedBaselines::from_entries(vec![upper]).is_err());
        let mut typed = good;
        typed.fingerprint.mode = 0o100_644;
        assert!(ExpectedBaselines::from_entries(vec![typed]).is_err());
    }

    #[test]
    fn an_entry_reads_flat_the_way_a_node_lists_it() {
        let json = format!(
            r#"{{"path":"/etc/hosts","file_type":"regular","sha256":"{}","mode":420,"uid":0,"gid":0}}"#,
            "d".repeat(64)
        );
        let entry: ExpectedBaseline = serde_json::from_str(&json).unwrap();
        assert_eq!(entry.fingerprint.mode, 0o644);
        assert_eq!(entry.fingerprint.xattrs, None);
        let back = serde_json::to_string(&entry).unwrap();
        assert!(!back.contains("link_target"));
    }

    #[test]
    fn a_listing_cut_short_is_not_an_expected_state() {
        let entry = ExpectedBaseline {
            path: "/etc/hosts".into(),
            fingerprint: FileFingerprint::of(&file()),
        };
        let whole = ExpectedBaselinesDocument {
            baselines: vec![entry.clone()],
            truncated: false,
        };
        let json = serde_json::to_string(&whole).unwrap();
        let read: ExpectedBaselinesDocument = serde_json::from_str(&json).unwrap();
        assert_eq!(read.into_expected().unwrap().entries(), vec![entry.clone()]);
        let cut = ExpectedBaselinesDocument {
            baselines: vec![entry],
            truncated: true,
        };
        assert!(cut.into_expected().is_err());
        assert!(
            serde_json::from_str::<ExpectedBaselinesDocument>(r#"{"baselines":[],"extra":1}"#)
                .is_err()
        );
    }
}
