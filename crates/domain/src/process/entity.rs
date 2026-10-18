use serde::{Deserialize, Serialize};

use crate::container::entity::ContainerContext;

/// Which of the two kernel notifications a lifecycle event carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProcessEventKind {
    /// A task replaced its image: the pid now stands for a new binary.
    Exec,
    /// A thread group leader is gone: the pid stands for nothing.
    Exit,
}

/// A kernel process notification, as the ring buffer delivers it.
///
/// Nothing here is resolved: the reader hands over what the tracepoint could
/// read about the calling task, and the service decides what to go and look
/// up in `/proc` on the strength of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessLifecycleEvent {
    pub kind: ProcessEventKind,
    /// Thread id. Equal to `tgid` for the records that reach the table.
    pub pid: u32,
    /// Process id, the key the table uses.
    pub tgid: u32,
    pub uid: u32,
    pub gid: u32,
    pub cgroup_id: u64,
    /// The kernel's `comm`, already trimmed of its NUL padding.
    pub comm: String,
    /// `bpf_ktime_get_boot_ns` at the tracepoint.
    pub at_ns: u64,
}

/// What a table entry claims about the binary behind a pid, and how good the
/// claim is.
///
/// A path is what `/proc/<pid>/exe` answered at exec time. It is not proof:
/// a binary can be named anything, a path can be replaced under a running
/// process, and a container can present its own filesystem. The variant is
/// therefore part of the answer rather than a detail of it, so a reader is
/// never left to assume a path was verified. A second variant naming a
/// content hash is what will make the claim provable, and until the hashing
/// exists this enum has no field to put one in: an entry says `path` or it
/// says `unknown`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum ProcessIdentity {
    /// The executable `/proc/<pid>/exe` pointed at, with the device and inode
    /// of the same read so the name and the file cannot drift apart.
    Path { path: String, dev: u64, inode: u64 },
    /// Nothing readable: the process was gone before the lookup, or the agent
    /// may not look at it.
    Unknown,
}

impl ProcessIdentity {
    /// The word an API response and an alert use for this identity.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Path { .. } => "path",
            Self::Unknown => "unknown",
        }
    }

    /// The executable path where there is one.
    #[must_use]
    pub fn path(&self) -> Option<&str> {
        match self {
            Self::Path { path, .. } => Some(path),
            Self::Unknown => None,
        }
    }
}

/// What `/proc` could add to an exec that the kernel notification does not
/// carry: who forked it, and what it was asked to run.
///
/// Both halves are optional for the same reason the identity is: the lookup
/// happens after the exec, so the process may already be gone, and an agent
/// that may not read another task's `/proc` entry gets nothing rather than a
/// guess.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProcessDetails {
    /// The parent at the time of the read.
    pub parent_pid: Option<u32>,
    /// argv joined with single spaces. `None` where the capture is off or
    /// the process has no argv, never an empty string.
    pub command_line: Option<String>,
}

/// One live process, as the table knows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessEntry {
    /// Process id. The key, and the only field that is never absent.
    pub pid: u32,
    /// The parent at the moment of the exec, where `/proc` still had one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_pid: Option<u32>,
    /// The kernel's `comm`: sixteen bytes, truncated by the kernel, a hint.
    pub comm: String,
    /// What the entry claims about the binary, and how good the claim is.
    pub identity: ProcessIdentity,
    /// The argv of the exec, joined with spaces, where the configuration
    /// allows it to be captured. Absent otherwise, and absent rather than
    /// empty for a kernel thread, which has no argv at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
    pub uid: u32,
    pub gid: u32,
    /// cgroup v2 id as the kernel reported it at exec.
    pub cgroup_id: u64,
    /// The container the process runs in, with whatever the runtime enricher
    /// could add. Absent on a host process and on a node with no resolver.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<ContainerContext>,
    /// `bpf_ktime_get_boot_ns` at the exec. A boot clock, so it survives a
    /// wall-clock change, and it is what orders the table for eviction.
    pub started_at_ns: u64,
}

impl ProcessEntry {
    /// A minimal entry for `pid`, with nothing resolved.
    #[must_use]
    pub fn new(pid: u32, comm: impl Into<String>, started_at_ns: u64) -> Self {
        Self {
            pid,
            parent_pid: None,
            comm: comm.into(),
            identity: ProcessIdentity::Unknown,
            command_line: None,
            uid: 0,
            gid: 0,
            cgroup_id: 0,
            container: None,
            started_at_ns,
        }
    }
}

/// What the table has done since the agent started.
///
/// `evicted` and `missing_exit` are the two numbers that say whether the
/// table is telling the truth: eviction means the bound was reached and the
/// oldest process stopped being nameable, and an exit for a pid the table
/// never held means an exec notification was lost on the way in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ProcessTableStats {
    /// The configured ceiling on live entries.
    pub capacity: usize,
    /// Entries held right now.
    pub entries: usize,
    /// Execs recorded, including those that replaced an existing pid.
    pub recorded: u64,
    /// Execs that replaced an entry for the same pid, which is the normal
    /// shell-then-binary sequence rather than an anomaly.
    pub replaced: u64,
    /// Entries dropped because the table was full.
    pub evicted: u64,
    /// Entries removed because the kernel said the process exited.
    pub purged: u64,
    /// Exit notifications for a pid the table did not hold.
    pub missing_exit: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_identity_says_which_kind_it_is() {
        let path = ProcessIdentity::Path {
            path: "/usr/bin/curl".to_string(),
            dev: 64,
            inode: 1234,
        };
        assert_eq!(path.kind(), "path");
        assert_eq!(path.path(), Some("/usr/bin/curl"));
        assert_eq!(ProcessIdentity::Unknown.kind(), "unknown");
        assert_eq!(ProcessIdentity::Unknown.path(), None);
    }

    #[test]
    fn a_fresh_entry_claims_nothing_it_has_not_read() {
        let entry = ProcessEntry::new(42, "curl", 1_000);
        assert_eq!(entry.identity, ProcessIdentity::Unknown);
        assert!(entry.command_line.is_none());
        assert!(entry.parent_pid.is_none());
        assert!(entry.container.is_none());
    }

    #[test]
    fn an_entry_serialises_without_the_fields_it_has_nothing_for() {
        let entry = ProcessEntry::new(42, "curl", 1_000);
        let json = serde_json::to_string(&entry).unwrap();
        assert!(!json.contains("command_line"));
        assert!(!json.contains("parent_pid"));
        assert!(json.contains("\"kind\":\"unknown\""));
    }
}
