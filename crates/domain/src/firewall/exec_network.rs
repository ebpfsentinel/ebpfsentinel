//! Which executables may reach the network.
//!
//! An allow-list of binaries, decided by the kernel when a task creates an
//! internet socket or connects one. A task whose executable is outside the
//! list is refused in enforce mode and reported in observe mode, which is the
//! default and what a list written for the first time should run as until the
//! reports stop naming something the node needs.
//!
//! The identity the kernel compares is the executable's inode and the device
//! it lives on, read from the task itself, so a list entry names a file rather
//! than a path: a binary copied elsewhere is a different file, and a binary
//! reached through a symlink is the same one.

use super::workload::WorkloadMode;
use crate::common::entity::RuleId;

/// The rule an exec-network alert carries, so a refusal here is found under
/// one name beside the workload firewall's own rules.
pub const EXEC_NETWORK_RULE: &str = "network-executables";

/// What an exec-network alert says its executable identity is: read by the
/// kernel off the task making the call, at the call, rather than resolved
/// afterwards from a process that may have gone.
pub const EXEC_NETWORK_EXECUTABLE_SOURCE: &str = "kernel_task";

/// How many executables a list may name. The kernel holds the set in a hash
/// map of this size and a list that does not fit is refused whole rather than
/// cut, because a cut list is a binary silently refused.
pub const MAX_NETWORK_EXECUTABLES: usize = 1_024;

/// The allow-list as configured.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NetworkExecutables {
    /// Observe or enforce.
    pub mode: WorkloadMode,
    /// Absolute paths of the executables allowed to reach the network.
    pub executables: Vec<String>,
}

/// Why a list cannot be applied.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NetworkExecutablesError {
    /// The list names nothing, which in enforce mode would cut every task on
    /// the node off but the agent.
    #[error("the list of executables allowed to reach the network is empty")]
    Empty,
    /// A path is relative, which the agent would resolve against its own
    /// working directory rather than the one the operator meant.
    #[error("`{0}` is not an absolute path")]
    NotAbsolute(String),
    /// A path is listed twice.
    #[error("`{0}` is listed twice")]
    Duplicate(String),
    /// The list does not fit the kernel's set.
    #[error("{0} executables are listed, and at most {MAX_NETWORK_EXECUTABLES} fit")]
    TooMany(usize),
}

impl NetworkExecutables {
    /// Check the list before anything is stat-ed or written.
    ///
    /// # Errors
    ///
    /// Returns the first entry, or the shape of the list, that cannot be
    /// applied.
    pub fn validate(&self) -> Result<(), NetworkExecutablesError> {
        if self.executables.is_empty() {
            return Err(NetworkExecutablesError::Empty);
        }
        if self.executables.len() > MAX_NETWORK_EXECUTABLES {
            return Err(NetworkExecutablesError::TooMany(self.executables.len()));
        }
        let mut seen = std::collections::HashSet::new();
        for path in &self.executables {
            if !path.starts_with('/') {
                return Err(NetworkExecutablesError::NotAbsolute(path.clone()));
            }
            if !seen.insert(path.as_str()) {
                return Err(NetworkExecutablesError::Duplicate(path.clone()));
            }
        }
        Ok(())
    }
}

/// Which call was decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecNetworkHook {
    /// The task was creating an internet socket.
    Create,
    /// The task was connecting one.
    Connect,
}

impl ExecNetworkHook {
    /// The hook a kernel record names, `None` for a number this build does
    /// not know.
    #[must_use]
    pub fn from_kernel(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Create),
            1 => Some(Self::Connect),
            _ => None,
        }
    }

    /// What the task was doing, for a sentence.
    #[must_use]
    pub fn describe(self) -> &'static str {
        match self {
            Self::Create => "creating an internet socket",
            Self::Connect => "connecting a socket",
        }
    }
}

/// A call by an executable outside the list, as the kernel reported it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecNetworkRecord {
    /// `bpf_ktime_get_boot_ns` at the decision.
    pub at_ns: u64,
    /// Thread group that made the call.
    pub tgid: u32,
    /// The executable's device and inode, in the encoding `stat(2)` uses.
    /// `None` when the kernel could not read them, which the list treats as
    /// outside it.
    pub executable: Option<(u64, u64)>,
    /// Which call was decided.
    pub hook: ExecNetworkHook,
    /// The socket was IPv6.
    pub ipv6: bool,
    /// The kernel refused the call rather than observed it.
    pub refused: bool,
}

impl ExecNetworkRecord {
    /// The rule the alert carries.
    #[must_use]
    pub fn rule() -> RuleId {
        RuleId(EXEC_NETWORK_RULE.to_string())
    }

    /// One sentence saying what happened.
    #[must_use]
    pub fn message(&self) -> String {
        let verb = if self.refused {
            "refused"
        } else {
            "would refuse"
        };
        let identity = match self.executable {
            Some((dev, ino)) => format!("executable dev {dev} inode {ino}"),
            None => "an executable the kernel could not read".to_string(),
        };
        format!(
            "network executables {verb} pid {} {} ({identity}, not in the list)",
            self.tgid,
            self.hook.describe()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(paths: &[&str]) -> NetworkExecutables {
        NetworkExecutables {
            mode: WorkloadMode::Observe,
            executables: paths.iter().map(|p| (*p).to_string()).collect(),
        }
    }

    #[test]
    fn observe_is_the_default() {
        assert_eq!(NetworkExecutables::default().mode, WorkloadMode::Observe);
    }

    #[test]
    fn a_list_of_absolute_distinct_paths_is_valid() {
        assert_eq!(
            list(&["/usr/sbin/sshd", "/usr/bin/curl"]).validate(),
            Ok(())
        );
    }

    #[test]
    fn an_empty_list_is_refused() {
        assert_eq!(list(&[]).validate(), Err(NetworkExecutablesError::Empty));
    }

    #[test]
    fn a_relative_path_is_refused_by_name() {
        assert_eq!(
            list(&["/usr/bin/curl", "bin/wget"]).validate(),
            Err(NetworkExecutablesError::NotAbsolute("bin/wget".to_string()))
        );
    }

    #[test]
    fn a_path_listed_twice_is_refused() {
        assert_eq!(
            list(&["/usr/bin/curl", "/usr/bin/curl"]).validate(),
            Err(NetworkExecutablesError::Duplicate(
                "/usr/bin/curl".to_string()
            ))
        );
    }

    #[test]
    fn a_list_larger_than_the_kernel_set_is_refused_whole() {
        let paths: Vec<String> = (0..=MAX_NETWORK_EXECUTABLES)
            .map(|i| format!("/opt/bin/{i}"))
            .collect();
        let too_many = NetworkExecutables {
            mode: WorkloadMode::Enforce,
            executables: paths,
        };
        assert_eq!(
            too_many.validate(),
            Err(NetworkExecutablesError::TooMany(
                MAX_NETWORK_EXECUTABLES + 1
            ))
        );
    }

    #[test]
    fn the_kernel_hooks_are_read_back_and_an_unknown_one_is_not_guessed() {
        assert_eq!(
            ExecNetworkHook::from_kernel(0),
            Some(ExecNetworkHook::Create)
        );
        assert_eq!(
            ExecNetworkHook::from_kernel(1),
            Some(ExecNetworkHook::Connect)
        );
        assert_eq!(ExecNetworkHook::from_kernel(7), None);
    }

    #[test]
    fn the_message_says_whether_the_call_was_refused_and_what_ran() {
        let mut record = ExecNetworkRecord {
            at_ns: 1,
            tgid: 4242,
            executable: Some((2049, 131)),
            hook: ExecNetworkHook::Connect,
            ipv6: false,
            refused: true,
        };
        assert_eq!(
            record.message(),
            "network executables refused pid 4242 connecting a socket (executable dev 2049 \
             inode 131, not in the list)"
        );
        record.refused = false;
        record.executable = None;
        assert!(
            record
                .message()
                .starts_with("network executables would refuse pid 4242")
        );
        assert!(record.message().contains("could not read"));
    }
}
