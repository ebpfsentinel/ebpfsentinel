//! Which processes a response may never signal, and what came of the ones it
//! did.
//!
//! Killing the process behind a flow is the first response this agent takes
//! that can stop something the operator did not deploy as an attacker. The
//! blast radius of getting it wrong is not an alert: it is a node that lost its
//! container runtime, or an agent that killed itself halfway through deciding
//! to.
//!
//! So the list of what may never be signalled is code, not configuration.
//! `HARD_PROTECTED_COMMANDS` is compiled in, a configured list is added to it,
//! and nothing subtracts from it: `protected_names` in a file can widen the
//! fence and has no spelling that narrows it.
//!
//! The match is on the basename of the executable the target is running, which
//! is a name and not an identity - a process can be renamed, and the binary
//! hash is what will eventually prove it. That is the right failure direction
//! here: a renamed `kubelet` is refused, and an attacker who renames their
//! payload to `kubelet` buys immunity from this one response while every
//! network action still applies to it.

use serde::{Deserialize, Serialize};

/// Executables a response may never signal, whatever the configuration says.
///
/// Three groups and no fourth: the init process, this agent and its warden,
/// and the things that run containers. Killing any of them turns a contained
/// incident into an outage, and an operator who wants one of them stopped has
/// a service manager for that.
pub const HARD_PROTECTED_COMMANDS: &[&str] = &[
    "systemd",
    "init",
    "ebpfsentinel-agent",
    "ebpfsentinel-warden",
    "containerd",
    "dockerd",
    "docker",
    "crio",
    "conmon",
    "runc",
    "crun",
    "podman",
    "kubelet",
];

/// Prefix covering every container shim, whose basename carries the runtime
/// and its version (`containerd-shim-runc-v2` and whatever replaces it).
pub const HARD_PROTECTED_PREFIX: &str = "containerd-shim";

/// Why a target was refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProtectedReason {
    /// Thread group 0 is no process and 1 is the init of whichever pid
    /// namespace the agent reads.
    InitProcess,
    /// The agent's own thread group.
    TheAgentItself,
    /// The executable could not be read, so nothing about the target can be
    /// checked. A target that cannot be identified is not signalled.
    NotIdentified,
    /// The basename is on the compiled-in list.
    HardProtected { command: String },
    /// The basename is on the configured list.
    ConfiguredCommand { command: String },
    /// The thread group id is on the configured list.
    ConfiguredPid { tgid: u32 },
}

impl ProtectedReason {
    /// One sentence for the audit record and the API answer.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        match self {
            Self::InitProcess => "the init process is never signalled".to_string(),
            Self::TheAgentItself => "the agent does not signal itself".to_string(),
            Self::NotIdentified => {
                "the target's executable could not be read, so it was not signalled".to_string()
            }
            Self::HardProtected { command } => {
                format!("`{command}` is protected and configuration cannot override it")
            }
            Self::ConfiguredCommand { command } => {
                format!("`{command}` is on the configured protected list")
            }
            Self::ConfiguredPid { tgid } => {
                format!("process {tgid} is on the configured protected list")
            }
        }
    }
}

/// Whether a target may be signalled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignalVerdict {
    /// Nothing protects this target.
    Allowed,
    /// It is protected, for this reason.
    Protected(ProtectedReason),
}

impl SignalVerdict {
    /// Whether the signal may be armed.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed)
    }

    /// The reason, where there is one.
    #[must_use]
    pub fn reason(&self) -> Option<&ProtectedReason> {
        match self {
            Self::Allowed => None,
            Self::Protected(reason) => Some(reason),
        }
    }
}

/// What came of one decision to kill.
///
/// `Survived` is a result and not an error. A target that makes no further
/// syscall before the arming expires is never signalled, and a target that
/// catches the signal is still running: both are reported, because an audit
/// line saying a process was killed when it is still serving traffic is the
/// one outcome an operator cannot recover from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ProcessKillOutcome {
    /// The target was protected, so nothing was armed.
    Refused { reason: ProtectedReason },
    /// The signal was sent and the target is gone.
    Killed { tgid: u32, signal: u32 },
    /// The target is still there. `signal_sent` separates the two ways that
    /// happens: the kernel never caught the target, or it did and the target
    /// handled the signal.
    Survived {
        tgid: u32,
        signal: u32,
        signal_sent: bool,
    },
}

impl ProcessKillOutcome {
    /// Whether the target is gone.
    #[must_use]
    pub fn is_killed(&self) -> bool {
        matches!(self, Self::Killed { .. })
    }

    /// One sentence for the audit record.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        match self {
            Self::Refused { reason } => reason.as_sentence(),
            Self::Killed { tgid, signal } => {
                format!("process {tgid} was signalled {signal} and is gone")
            }
            Self::Survived {
                tgid,
                signal,
                signal_sent: true,
            } => format!("process {tgid} was signalled {signal} and is still running"),
            Self::Survived {
                tgid,
                signal_sent: false,
                ..
            } => format!("process {tgid} was never reached before the arming expired"),
        }
    }
}

/// Decides which targets are off limits.
///
/// Built once from the configuration and the agent's own thread group id, so
/// the decision is the same wherever it is asked.
#[derive(Debug, Clone)]
pub struct ProcessSignalGuard {
    self_tgid: u32,
    commands: Vec<String>,
    pids: Vec<u32>,
}

impl ProcessSignalGuard {
    /// Build the guard. Configured names are compared without case, because a
    /// protected list that misses `Kubelet` is a protected list that failed.
    #[must_use]
    pub fn new(self_tgid: u32, protected_commands: &[String], protected_pids: &[u32]) -> Self {
        let mut commands: Vec<String> = protected_commands
            .iter()
            .map(|c| c.trim().to_ascii_lowercase())
            .filter(|c| !c.is_empty())
            .collect();
        commands.sort_unstable();
        commands.dedup();
        let mut pids = protected_pids.to_vec();
        pids.sort_unstable();
        pids.dedup();
        Self {
            self_tgid,
            commands,
            pids,
        }
    }

    /// Whether `tgid`, running `executable_path`, may be signalled.
    ///
    /// `executable_path` is what the agent could read at this instant;
    /// `None` is either a process that has already gone or one whose
    /// `/proc` entry is unreadable, and both are refusals.
    #[must_use]
    pub fn verdict(&self, tgid: u32, executable_path: Option<&str>) -> SignalVerdict {
        if tgid <= 1 {
            return SignalVerdict::Protected(ProtectedReason::InitProcess);
        }
        if tgid == self.self_tgid {
            return SignalVerdict::Protected(ProtectedReason::TheAgentItself);
        }
        if self.pids.binary_search(&tgid).is_ok() {
            return SignalVerdict::Protected(ProtectedReason::ConfiguredPid { tgid });
        }
        let Some(path) = executable_path else {
            return SignalVerdict::Protected(ProtectedReason::NotIdentified);
        };
        let command = basename(path).to_ascii_lowercase();
        if command.is_empty() {
            return SignalVerdict::Protected(ProtectedReason::NotIdentified);
        }
        if let Some(hard) = hard_protected(&command) {
            return SignalVerdict::Protected(ProtectedReason::HardProtected {
                command: hard.to_string(),
            });
        }
        if self.commands.binary_search(&command).is_ok() {
            return SignalVerdict::Protected(ProtectedReason::ConfiguredCommand { command });
        }
        SignalVerdict::Allowed
    }

    /// The thread group ids the kernel's own protected map is filled with.
    ///
    /// The numbers, and only the numbers: a protected name needs a path read
    /// that a tracepoint cannot do, so the kernel fence covers pid 1, the
    /// agent and whatever the configuration named by number, and the name
    /// list is enforced here before anything is armed.
    #[must_use]
    pub fn kernel_protected_pids(&self) -> Vec<u32> {
        let mut pids = vec![1, self.self_tgid];
        pids.extend(self.pids.iter().copied());
        pids.retain(|p| *p != 0);
        pids.sort_unstable();
        pids.dedup();
        pids
    }

    /// The configured names this guard holds, lowercased and deduplicated.
    #[must_use]
    pub fn configured_commands(&self) -> &[String] {
        &self.commands
    }
}

/// The compiled-in entry `command` matches, where it matches one.
#[must_use]
pub fn hard_protected(command: &str) -> Option<&'static str> {
    if command.starts_with(HARD_PROTECTED_PREFIX) {
        return Some(HARD_PROTECTED_PREFIX);
    }
    HARD_PROTECTED_COMMANDS
        .iter()
        .find(|c| **c == command)
        .copied()
}

/// Last path component, which is the command as a protected list names it.
#[must_use]
fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard() -> ProcessSignalGuard {
        ProcessSignalGuard::new(4242, &["Nginx".to_string(), " ".to_string()], &[999])
    }

    #[test]
    fn the_init_process_is_refused_whatever_it_runs() {
        assert_eq!(
            guard().verdict(1, Some("/usr/bin/evil")),
            SignalVerdict::Protected(ProtectedReason::InitProcess)
        );
        assert_eq!(
            guard().verdict(0, Some("/usr/bin/evil")),
            SignalVerdict::Protected(ProtectedReason::InitProcess)
        );
    }

    #[test]
    fn the_agent_does_not_signal_itself() {
        assert_eq!(
            guard().verdict(4242, Some("/usr/bin/ebpfsentinel-agent")),
            SignalVerdict::Protected(ProtectedReason::TheAgentItself)
        );
    }

    #[test]
    fn the_hard_list_holds_the_container_runtimes_and_the_kubelet() {
        for path in [
            "/usr/bin/containerd",
            "/usr/bin/containerd-shim-runc-v2",
            "/usr/bin/dockerd",
            "/usr/bin/kubelet",
            "/usr/sbin/runc",
            "/usr/bin/ebpfsentinel-warden",
        ] {
            let verdict = guard().verdict(5000, Some(path));
            assert!(
                matches!(
                    verdict,
                    SignalVerdict::Protected(ProtectedReason::HardProtected { .. })
                ),
                "{path} was not protected: {verdict:?}"
            );
        }
    }

    #[test]
    fn a_configured_name_widens_the_fence_and_is_matched_without_case() {
        assert_eq!(
            guard().verdict(5000, Some("/usr/sbin/NGINX")),
            SignalVerdict::Protected(ProtectedReason::ConfiguredCommand {
                command: "nginx".to_string()
            })
        );
    }

    #[test]
    fn a_configured_name_cannot_narrow_the_hard_list() {
        // There is no spelling of the configuration that removes an entry:
        // the guard only ever adds to what is compiled in.
        let permissive = ProcessSignalGuard::new(4242, &[], &[]);
        assert!(
            !permissive
                .verdict(5000, Some("/usr/bin/kubelet"))
                .is_allowed()
        );
    }

    #[test]
    fn a_configured_pid_is_refused_before_its_path_is_read() {
        assert_eq!(
            guard().verdict(999, None),
            SignalVerdict::Protected(ProtectedReason::ConfiguredPid { tgid: 999 })
        );
    }

    #[test]
    fn a_target_with_no_readable_executable_is_refused() {
        assert_eq!(
            guard().verdict(5000, None),
            SignalVerdict::Protected(ProtectedReason::NotIdentified)
        );
        assert_eq!(
            guard().verdict(5000, Some("/")),
            SignalVerdict::Protected(ProtectedReason::NotIdentified)
        );
    }

    #[test]
    fn an_ordinary_process_is_allowed() {
        let verdict = guard().verdict(5000, Some("/tmp/.hidden/miner"));
        assert!(verdict.is_allowed());
        assert!(verdict.reason().is_none());
    }

    #[test]
    fn the_kernel_fence_carries_pid_one_the_agent_and_the_configured_numbers() {
        assert_eq!(guard().kernel_protected_pids(), vec![1, 999, 4242]);
    }

    #[test]
    fn the_kernel_fence_never_carries_thread_group_zero() {
        let guard = ProcessSignalGuard::new(0, &[], &[0]);
        assert_eq!(guard.kernel_protected_pids(), vec![1]);
    }

    #[test]
    fn every_outcome_says_what_happened_in_one_sentence() {
        let refused = ProcessKillOutcome::Refused {
            reason: ProtectedReason::InitProcess,
        };
        assert!(!refused.is_killed());
        assert!(refused.as_sentence().contains("init"));

        let killed = ProcessKillOutcome::Killed { tgid: 7, signal: 9 };
        assert!(killed.is_killed());
        assert!(killed.as_sentence().contains("gone"));

        let handled = ProcessKillOutcome::Survived {
            tgid: 7,
            signal: 15,
            signal_sent: true,
        };
        assert!(!handled.is_killed());
        assert!(handled.as_sentence().contains("still running"));

        let never = ProcessKillOutcome::Survived {
            tgid: 7,
            signal: 15,
            signal_sent: false,
        };
        assert!(never.as_sentence().contains("never reached"));
    }

    #[test]
    fn the_hard_list_names_nothing_twice() {
        let mut names = HARD_PROTECTED_COMMANDS.to_vec();
        names.sort_unstable();
        let total = names.len();
        names.dedup();
        assert_eq!(names.len(), total);
    }
}
