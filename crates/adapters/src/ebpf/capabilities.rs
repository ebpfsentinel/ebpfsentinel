//! Every capability that switches on host by host, in one table.
//!
//! The floor guarantees the base programs load. Above it, each entry here is
//! something a host may or may not offer: a kfunc a vendor backported or a
//! configuration left out, the BPF LSM that only a boot parameter turns on, or
//! a hook a deployment's privilege lets the agent attach. Each entry says what
//! it unlocks, how the agent asks for it, the kernel that introduced it and
//! what runs where it is absent, so an operator reading why a host has less
//! than another reads it from one place.
//!
//! The table asks nothing itself. Each entry points at a probe or an attach
//! status that already exists and that the agent already publishes; the
//! report built from it reads those answers rather than asking again.
//!
//! A capability is enabled by a probe, never by a version. `since` is used to
//! word a hint and for nothing else, because a vendor kernel that keeps its
//! number for its whole life carries work backported into it, and a kernel
//! whose number says a kfunc is there may have been built without it.

use super::kernel_probe::{MIN_KERNEL_MAJOR, MIN_KERNEL_MINOR, parse_version};

/// A kernel release, as far as a hint needs one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct KernelVersion {
    pub major: u32,
    pub minor: u32,
}

impl KernelVersion {
    /// The floor the agent refuses below.
    pub const FLOOR: Self = Self {
        major: MIN_KERNEL_MAJOR,
        minor: MIN_KERNEL_MINOR,
    };

    /// The version a release string such as `6.12.48+deb13-amd64` names, or
    /// `None` when it names none.
    #[must_use]
    pub fn parse(release: &str) -> Option<Self> {
        parse_version(release)
            .ok()
            .map(|(major, minor)| Self { major, minor })
    }
}

impl std::fmt::Display for KernelVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// How the running kernel is asked whether it offers a capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeKind {
    /// The kfuncs are read from the kernel's own BTF and nothing is loaded,
    /// so the answer is "declared", never "confirmed".
    DeclaredInBtf,
    /// A small program calling the kfuncs is loaded through the agent's token
    /// and closed.
    Loaded,
    /// A sleepable LSM program is loaded through the token and the BPF LSM is
    /// read off the active security modules.
    SleepableLsm,
    /// The active security modules, fixed at boot by `lsm=`.
    ActiveSecurityModules,
    /// The attach status the adapter behind the capability publishes once it
    /// has tried.
    AttachStatus,
}

impl ProbeKind {
    /// The word an API reader matches on.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DeclaredInBtf => "declared_in_btf",
            Self::Loaded => "loaded",
            Self::SleepableLsm => "sleepable_lsm",
            Self::ActiveSecurityModules => "active_security_modules",
            Self::AttachStatus => "attach_status",
        }
    }
}

/// One capability above the floor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capability {
    /// Stable identifier: a metric label and an API field, so renaming one is
    /// a breaking change.
    pub id: &'static str,
    /// What it gives where it is active, in one sentence.
    pub unlocks: &'static str,
    /// How the kernel is asked.
    pub probe: ProbeKind,
    /// The kernel that introduced what it rests on, or the floor when that is
    /// older. Used to word a hint, never to enable anything.
    pub since: KernelVersion,
    /// Whether it rests on the BPF LSM being active at boot.
    pub needs_lsm: bool,
    /// What runs where it is absent, in one sentence.
    pub fallback: &'static str,
}

/// Every capability above the floor, in the order they are reported.
pub const CATALOGUE: &[Capability] = &[
    Capability {
        id: "bpf_lsm",
        unlocks: "programs attached at security module hooks, which is where the kernel \
                  decides a call before it happens",
        probe: ProbeKind::ActiveSecurityModules,
        since: KernelVersion::FLOOR,
        needs_lsm: true,
        fallback: "each capability resting on it runs its own fallback, listed beside it",
    },
    Capability {
        id: "file_kfuncs",
        unlocks: "a task's executable, a rendered path and a file's extended attribute read \
                  in the kernel",
        probe: ProbeKind::SleepableLsm,
        since: KernelVersion::FLOOR,
        needs_lsm: true,
        fallback: "executables are identified by the device and inode read in userspace, and \
                   paths and attributes are read off the filesystem",
    },
    Capability {
        id: "kprobe_session",
        unlocks: "one program on a function's entry and return for the kernel TLS record path, \
                  instead of a kprobe, a kretprobe and a map correlating them",
        probe: ProbeKind::Loaded,
        since: KernelVersion::FLOOR,
        needs_lsm: false,
        fallback: "nothing changes: no shipped program rests on it yet",
    },
    Capability {
        id: "copy_from_user_str",
        unlocks: "the real argument vector of a process, read at exec",
        probe: ProbeKind::SleepableLsm,
        since: KernelVersion::FLOOR,
        needs_lsm: true,
        fallback: "nothing changes: no shipped program rests on it yet",
    },
    Capability {
        id: "tcp_reqsk_assign",
        unlocks: "a validated SYN cookie handed to the stack as a request socket, so the \
                  stack does not revalidate a cookie it did not issue",
        probe: ProbeKind::DeclaredInBtf,
        since: KernelVersion::FLOOR,
        needs_lsm: false,
        fallback: "nothing changes: no shipped program rests on it yet",
    },
    Capability {
        id: "attribution",
        unlocks: "the workload that opened a socket, named on every flow",
        probe: ProbeKind::AttachStatus,
        since: KernelVersion::FLOOR,
        needs_lsm: false,
        fallback: "flows carry no workload name and everything else is unchanged",
    },
    Capability {
        id: "process_tracing",
        unlocks: "the process behind a flow or an alert, with its command line and lineage",
        probe: ProbeKind::AttachStatus,
        since: KernelVersion::FLOOR,
        needs_lsm: false,
        fallback: "flows and alerts carry no process and everything else is unchanged",
    },
    Capability {
        id: "workload_firewall",
        unlocks: "rules on what a named workload may connect to, send to or bind, decided in \
                  the syscall",
        probe: ProbeKind::AttachStatus,
        since: KernelVersion::FLOOR,
        needs_lsm: false,
        fallback: "no workload rule is enforced, and a configuration that needs one refuses \
                   to start rather than running unenforced",
    },
    Capability {
        id: "quarantine",
        unlocks: "a workload cut off from the network in the kernel for a bounded time",
        probe: ProbeKind::AttachStatus,
        since: KernelVersion::FLOOR,
        needs_lsm: false,
        fallback: "a quarantine is refused with the reason and the alert still fires",
    },
    Capability {
        id: "process_signal",
        unlocks: "a process stopped by a signal sent from the kernel",
        probe: ProbeKind::AttachStatus,
        since: KernelVersion::FLOOR,
        needs_lsm: false,
        fallback: "a signal is refused with the reason and the alert still fires",
    },
    Capability {
        id: "immediate_signal",
        unlocks: "a signal that reaches its target at once, even a process making no syscall",
        probe: ProbeKind::Loaded,
        since: KernelVersion {
            major: 6,
            minor: 13,
        },
        needs_lsm: false,
        fallback: "the signal waits for the target's next syscall, and a target making none \
                   within the window is reported as a survivor",
    },
    Capability {
        id: "network_executables",
        unlocks: "the list of executables allowed to reach the network, decided before the \
                  socket exists",
        probe: ProbeKind::AttachStatus,
        since: KernelVersion::FLOOR,
        needs_lsm: true,
        fallback: "an observing list is skipped with the reason and an enforcing list refuses \
                   to start the agent",
    },
    Capability {
        id: "write_refusal",
        unlocks: "a write-open refused past a count, before a byte is written",
        probe: ProbeKind::AttachStatus,
        since: KernelVersion::FLOOR,
        needs_lsm: true,
        fallback: "a fanotify permission group refuses on at most 4,096 marked inodes, and \
                   where that cannot run the mass encryption detection and its stop remain",
    },
    Capability {
        id: "self_protection",
        unlocks: "the agent's own maps and links refused to every other task",
        probe: ProbeKind::AttachStatus,
        since: KernelVersion::FLOOR,
        needs_lsm: true,
        fallback: "the agent's objects are guarded only by the privilege it takes to reach \
                   them, and the node reports itself unprotected",
    },
];

/// The entry with this identifier.
#[must_use]
pub fn find(id: &str) -> Option<&'static Capability> {
    CATALOGUE.iter().find(|c| c.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ebpf::kfunc_feature_probe;

    /// The identifiers as they are published. A rename is a breaking change
    /// for every dashboard, alert and script reading the metric or the API,
    /// so it has to be made here on purpose.
    const PUBLISHED_IDS: &[&str] = &[
        "bpf_lsm",
        "file_kfuncs",
        "kprobe_session",
        "copy_from_user_str",
        "tcp_reqsk_assign",
        "attribution",
        "process_tracing",
        "workload_firewall",
        "quarantine",
        "process_signal",
        "immediate_signal",
        "network_executables",
        "write_refusal",
        "self_protection",
    ];

    #[test]
    fn every_entry_says_what_it_unlocks_what_replaces_it_and_how_it_is_asked() {
        for c in CATALOGUE {
            assert!(!c.unlocks.trim().is_empty(), "{} unlocks nothing", c.id);
            assert!(!c.fallback.trim().is_empty(), "{} has no fallback", c.id);
            assert!(
                c.since >= KernelVersion::FLOOR,
                "{} names {} below the floor",
                c.id,
                c.since
            );
            assert!(!c.probe.as_str().is_empty());
            assert!(
                !c.unlocks.ends_with('.') && !c.fallback.ends_with('.'),
                "{} is a sentence fragment read inside a line",
                c.id
            );
        }
    }

    #[test]
    fn identifiers_are_unique_and_stable() {
        let ids: Vec<&str> = CATALOGUE.iter().map(|c| c.id).collect();
        assert_eq!(ids, PUBLISHED_IDS);
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), ids.len(), "an identifier is repeated");
        for id in ids {
            assert!(
                id.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                "{id} is not a label a metric can carry as is"
            );
        }
    }

    #[test]
    fn the_unused_kfunc_facts_keep_their_consumer_and_gain_no_fourth() {
        let probed = kfunc_feature_probe::entry_consumers();
        let unused: Vec<&Capability> = CATALOGUE
            .iter()
            .filter(|c| c.fallback.starts_with("nothing changes"))
            .collect();
        assert_eq!(unused.len(), probed.len());
        for (name, consumer) in probed {
            let entry = find(name).expect("every probed kfunc fact is in the catalogue");
            assert_eq!(entry.unlocks, consumer, "{name} lost its consumer sentence");
        }
    }

    #[test]
    fn an_lsm_probe_is_only_ever_an_lsm_capability() {
        for c in CATALOGUE {
            if matches!(
                c.probe,
                ProbeKind::SleepableLsm | ProbeKind::ActiveSecurityModules
            ) {
                assert!(c.needs_lsm, "{} is asked through the LSM", c.id);
            }
        }
    }

    #[test]
    fn the_floor_is_the_one_the_agent_refuses_below() {
        assert_eq!(KernelVersion::FLOOR.to_string(), "6.12");
    }
}
