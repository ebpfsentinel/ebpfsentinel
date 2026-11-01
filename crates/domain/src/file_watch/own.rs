//! The agent's own files: its binary, its configuration, the eBPF objects it
//! loads and the store holding the file baselines.
//!
//! An agent somebody else can rewrite is an agent that reports what that
//! somebody chooses, so a change to one of these files made by any process
//! but the agent is an alert, whether or not a rule asks for it. The agent's
//! own writes are not: it keeps its baseline store open and writes it all
//! day, and nothing else of its own is written by it at all.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use super::baseline::FileDrift;
use super::entity::FileChangeKind;
use crate::alert::mitre::MitreAttackInfo;
use crate::common::entity::RuleId;

/// The component of the alerts raised for a change to the agent's files.
pub const AGENT_FILES_COMPONENT: &str = "agent_files";

/// What one of the agent's files is to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnFileRole {
    /// The executable the agent runs from.
    Binary,
    /// The configuration file it was started with.
    Configuration,
    /// An eBPF object it loads into the kernel.
    Program,
    /// The store holding every file baseline, its own included.
    BaselineStore,
}

impl OwnFileRole {
    /// Every role, in the order the documentation lists them.
    pub const ALL: [Self; 4] = [
        Self::Binary,
        Self::Configuration,
        Self::Program,
        Self::BaselineStore,
    ];

    /// What the alert calls the file.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::Binary => "binary",
            Self::Configuration => "configuration",
            Self::Program => "eBPF object",
            Self::BaselineStore => "file baseline store",
        }
    }

    /// The rule a change to a file of this role raises.
    #[must_use]
    pub fn rule_id(self) -> RuleId {
        RuleId(
            match self {
                Self::Binary => "agent-binary-changed",
                Self::Configuration => "agent-configuration-changed",
                Self::Program => "agent-program-changed",
                Self::BaselineStore => "agent-baseline-store-changed",
            }
            .to_string(),
        )
    }
}

/// The agent's files, by path.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OwnFiles {
    files: BTreeMap<String, OwnFileRole>,
}

impl OwnFiles {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Count `path` among the agent's files. An empty path is ignored, and a
    /// path named twice keeps its first role.
    pub fn add(&mut self, path: impl Into<String>, role: OwnFileRole) {
        let path = path.into();
        if !path.is_empty() {
            self.files.entry(path).or_insert(role);
        }
    }

    /// What `path` is to the agent, if it is one of its files.
    #[must_use]
    pub fn role(&self, path: &str) -> Option<OwnFileRole> {
        self.files.get(path).copied()
    }

    /// Every path, in order.
    pub fn paths(&self) -> impl Iterator<Item = &str> {
        self.files.keys().map(String::as_str)
    }

    /// The directories holding the files, each once: what the watch is
    /// opened on so the filesystem holding every file is watched.
    #[must_use]
    pub fn directories(&self) -> Vec<String> {
        let dirs: BTreeSet<String> = self
            .files
            .keys()
            .filter_map(|path| match path.rsplit_once('/') {
                Some(("", _)) => Some("/".to_owned()),
                Some((dir, _)) => Some(dir.to_owned()),
                None => None,
            })
            .collect();
        dirs.into_iter().collect()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.files.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
}

/// A change to one of the agent's files that another process made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnFileChange {
    pub path: String,
    pub role: OwnFileRole,
    /// What differs from the baseline.
    pub drift: Vec<FileDrift>,
    /// The writer, `0` when the kernel could not name it in the agent's
    /// view.
    pub writer: u32,
}

impl OwnFileChange {
    /// The alert's sentence.
    #[must_use]
    pub fn message(&self) -> String {
        let what: Vec<&str> = self.drift.iter().map(|d| d.as_str()).collect();
        let by = if self.writer == 0 {
            "a process the agent cannot name".to_owned()
        } else {
            format!("process {}", self.writer)
        };
        format!(
            "the agent's {} {} was changed by {by}: {}",
            self.role.describe(),
            self.path,
            what.join(", ")
        )
    }

    /// Altering the agent's own files is turning a defence off, or making it
    /// lie, without stopping it.
    #[must_use]
    pub fn mitre() -> MitreAttackInfo {
        MitreAttackInfo {
            technique_id: "T1562.001".to_string(),
            technique_name: "Impair Defenses: Disable or Modify Tools".to_string(),
            tactic: "defense-evasion".to_string(),
        }
    }
}

/// What a settled change to an agent's file amounts to.
///
/// Nothing when the agent itself wrote it, or when nothing differs from the
/// baseline. The baseline store's content is the agent's to change, so a
/// content difference there counts only when another process wrote the
/// file; every other difference counts on every file.
#[must_use]
pub fn own_file_change(
    path: &str,
    role: OwnFileRole,
    kinds: &BTreeSet<FileChangeKind>,
    drift: &[FileDrift],
    writer: u32,
    own_pid: u32,
) -> Option<OwnFileChange> {
    if writer != 0 && writer == own_pid {
        return None;
    }
    let mut drift: Vec<FileDrift> = if role == OwnFileRole::BaselineStore {
        drift
            .iter()
            .copied()
            .filter(|d| !matches!(d, FileDrift::Content | FileDrift::ContentUnverified))
            .collect()
    } else {
        drift.to_vec()
    };
    if role == OwnFileRole::BaselineStore && kinds.contains(&FileChangeKind::Written) {
        drift.insert(0, FileDrift::Content);
    }
    (!drift.is_empty()).then(|| OwnFileChange {
        path: path.to_owned(),
        role,
        drift,
        writer,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(list: &[FileChangeKind]) -> BTreeSet<FileChangeKind> {
        list.iter().copied().collect()
    }

    #[test]
    fn the_agents_own_writes_raise_nothing() {
        let out = own_file_change(
            "/etc/ebpfsentinel/config.yaml",
            OwnFileRole::Configuration,
            &kinds(&[FileChangeKind::Written]),
            &[FileDrift::Content],
            77,
            77,
        );
        assert!(out.is_none());
    }

    #[test]
    fn another_writer_raises_the_drift_it_left() {
        let out = own_file_change(
            "/usr/local/bin/ebpfsentinel-agent",
            OwnFileRole::Binary,
            &kinds(&[FileChangeKind::Written]),
            &[FileDrift::Content, FileDrift::Mode],
            900,
            77,
        )
        .unwrap();
        assert_eq!(out.drift, vec![FileDrift::Content, FileDrift::Mode]);
        assert_eq!(out.role.rule_id().0, "agent-binary-changed");
        assert_eq!(
            out.message(),
            "the agent's binary /usr/local/bin/ebpfsentinel-agent was changed by process 900: content, mode"
        );
    }

    #[test]
    fn an_unnamed_writer_is_never_the_agent() {
        let out = own_file_change(
            "/usr/local/lib/ebpfsentinel/tc-ids",
            OwnFileRole::Program,
            &kinds(&[FileChangeKind::Deleted]),
            &[FileDrift::Disappeared],
            0,
            0,
        )
        .unwrap();
        assert!(out.message().contains("a process the agent cannot name"));
    }

    #[test]
    fn the_store_counts_content_only_when_another_process_wrote_it() {
        let store = "/var/lib/ebpfsentinel/file_baselines.redb";
        // Touched by somebody else: the content moved because the agent
        // writes it, not because of the touch.
        let touched = own_file_change(
            store,
            OwnFileRole::BaselineStore,
            &kinds(&[FileChangeKind::AttributesChanged]),
            &[FileDrift::Content],
            900,
            77,
        );
        assert!(touched.is_none());
        let written = own_file_change(
            store,
            OwnFileRole::BaselineStore,
            &kinds(&[FileChangeKind::Written]),
            &[FileDrift::ContentUnverified, FileDrift::Owner],
            900,
            77,
        )
        .unwrap();
        assert_eq!(written.drift, vec![FileDrift::Content, FileDrift::Owner]);
    }

    #[test]
    fn directories_are_listed_once() {
        let mut own = OwnFiles::new();
        own.add("/usr/local/lib/ebpfsentinel/tc-ids", OwnFileRole::Program);
        own.add("/usr/local/lib/ebpfsentinel/tc-dns", OwnFileRole::Program);
        own.add("/agent", OwnFileRole::Binary);
        own.add("", OwnFileRole::Binary);
        own.add("/agent", OwnFileRole::Configuration);
        assert_eq!(own.len(), 3);
        assert_eq!(own.role("/agent"), Some(OwnFileRole::Binary));
        assert_eq!(
            own.directories(),
            vec!["/".to_string(), "/usr/local/lib/ebpfsentinel".to_string()]
        );
    }
}
