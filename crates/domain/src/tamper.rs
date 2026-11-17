//! What the kernel refused somebody who tried to stop, trace or unpin the
//! agent.
//!
//! The refusal is decided at the BPF LSM hooks; this is the record userspace
//! reads off the ring, and the alert it becomes. Every refusal is an alert:
//! somebody with the rights to send a signal to a root process, or to remove
//! a pinned link, has already done most of what an intruder needs, and the
//! one thing that stopped them is the agent they were after.

use serde::Serialize;

use crate::alert::mitre::MitreAttackInfo;
use crate::common::entity::RuleId;

/// The component every tamper refusal is filed under.
pub const TAMPER_COMPONENT: &str = "tamper_protection";

/// What the refused caller tried.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TamperKind {
    /// Send the agent or the warden a signal that ends or stops it.
    Signal,
    /// Trace the agent, or write its memory.
    Trace,
    /// Remove a pinned link or a configuration file.
    Unlink,
    /// Move a pinned link or a configuration file away, or over it.
    Rename,
    /// Kill or freeze the agent's cgroup.
    Cgroup,
}

impl TamperKind {
    /// The kind the kernel encodes as `kind`.
    #[must_use]
    pub fn from_kernel(kind: u8) -> Option<Self> {
        match kind {
            1 => Some(Self::Signal),
            2 => Some(Self::Trace),
            3 => Some(Self::Unlink),
            4 => Some(Self::Rename),
            5 => Some(Self::Cgroup),
            _ => None,
        }
    }

    /// The stable rule id an alert of this kind carries.
    #[must_use]
    pub fn rule_id(self) -> RuleId {
        RuleId(
            match self {
                Self::Signal => "tamper-signal-refused",
                Self::Trace => "tamper-trace-refused",
                Self::Unlink => "tamper-unlink-refused",
                Self::Rename => "tamper-rename-refused",
                Self::Cgroup => "tamper-cgroup-refused",
            }
            .to_string(),
        )
    }
}

/// One refusal, as userspace reads it off the kernel's ring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TamperRefusal {
    /// `CLOCK_BOOTTIME` nanoseconds at the refusal.
    pub at_ns: u64,
    pub kind: TamperKind,
    /// Thread group of the caller, as the host numbers it.
    pub caller_tgid: u32,
    /// The caller's command name.
    pub caller_comm: String,
    /// The protected thread group, for a signal or a trace.
    pub target_tgid: Option<u32>,
    /// The signal number, for a signal; the ptrace mode, for a trace.
    pub detail: u32,
    /// The file refused, by `stat(2)` device and inode, for an unlink, a
    /// rename or a cgroup file.
    pub file: Option<(u64, u64)>,
    /// The name of the entry refused, as the kernel read it.
    pub name: String,
    /// The protected path the file belongs to, when userspace knows it.
    pub path: Option<String>,
}

impl TamperRefusal {
    /// The technique the attempt is filed under.
    #[must_use]
    pub fn mitre() -> MitreAttackInfo {
        MitreAttackInfo {
            technique_id: "T1562.001".to_string(),
            technique_name: "Impair Defenses: Disable or Modify Tools".to_string(),
            tactic: "defense-evasion".to_string(),
        }
    }

    /// One sentence saying what was refused and to whom.
    #[must_use]
    pub fn message(&self) -> String {
        let caller = format!("{} (pid {})", self.caller_comm, self.caller_tgid);
        let target = self
            .target_tgid
            .map_or_else(String::new, |t| format!(" pid {t}"));
        let where_ = self
            .path
            .as_deref()
            .map_or_else(String::new, |p| format!(" under {p}"));
        match self.kind {
            TamperKind::Signal => format!(
                "the kernel refused {caller} signal {} ({}) to the agent{target}",
                self.detail,
                signal_name(self.detail)
            ),
            TamperKind::Trace => {
                format!("the kernel refused {caller} a trace or memory access to the agent{target}")
            }
            TamperKind::Unlink => format!(
                "the kernel refused {caller} the removal of `{}`{where_}",
                self.name
            ),
            TamperKind::Rename => format!(
                "the kernel refused {caller} a rename of `{}`{where_}",
                self.name
            ),
            TamperKind::Cgroup => format!(
                "the kernel refused {caller} a write to `{}` in the agent's cgroup{where_}",
                self.name
            ),
        }
    }
}

/// The name of a signal the guard may refuse, for the message.
#[must_use]
pub fn signal_name(signal: u32) -> &'static str {
    match signal {
        1 => "SIGHUP",
        2 => "SIGINT",
        3 => "SIGQUIT",
        6 => "SIGABRT",
        9 => "SIGKILL",
        15 => "SIGTERM",
        19 => "SIGSTOP",
        20 => "SIGTSTP",
        _ => "signal",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refusal(kind: TamperKind) -> TamperRefusal {
        TamperRefusal {
            at_ns: 1,
            kind,
            caller_tgid: 4242,
            caller_comm: "kill".to_string(),
            target_tgid: Some(7),
            detail: 9,
            file: None,
            name: "xdp_firewall".to_string(),
            path: Some("/sys/fs/bpf/ebpfsentinel-links".to_string()),
        }
    }

    #[test]
    fn every_kernel_kind_has_a_kind_and_nothing_else_does() {
        for (raw, kind) in [
            (1, TamperKind::Signal),
            (2, TamperKind::Trace),
            (3, TamperKind::Unlink),
            (4, TamperKind::Rename),
            (5, TamperKind::Cgroup),
        ] {
            assert_eq!(TamperKind::from_kernel(raw), Some(kind));
        }
        assert_eq!(TamperKind::from_kernel(0), None);
        assert_eq!(TamperKind::from_kernel(6), None);
    }

    #[test]
    fn the_message_names_the_caller_and_what_it_tried() {
        let signal = refusal(TamperKind::Signal).message();
        assert!(signal.contains("kill (pid 4242)"), "{signal}");
        assert!(signal.contains("SIGKILL"), "{signal}");
        let unlink = refusal(TamperKind::Unlink).message();
        assert!(unlink.contains("`xdp_firewall`"), "{unlink}");
        assert!(
            unlink.contains("/sys/fs/bpf/ebpfsentinel-links"),
            "{unlink}"
        );
    }

    #[test]
    fn each_kind_has_its_own_rule() {
        let ids: std::collections::HashSet<_> = [
            TamperKind::Signal,
            TamperKind::Trace,
            TamperKind::Unlink,
            TamperKind::Rename,
            TamperKind::Cgroup,
        ]
        .into_iter()
        .map(|k| k.rule_id().0)
        .collect();
        assert_eq!(ids.len(), 5);
    }
}
