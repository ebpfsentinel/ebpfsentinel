//! Attaching the syscall-entry tracepoint that carries the signal, and saying
//! so when it cannot be attached.
//!
//! One program on one tracepoint, and the attach is all-or-nothing in a
//! stronger sense than the process table's: an operator who armed a kill and
//! got no refusal would believe a process was stopped. So the status is
//! published with the reason the kernel gave, and the service that arms reads
//! it before it promises anything.

use std::os::fd::{OwnedFd, RawFd};
use std::sync::{Mutex, OnceLock};

use tracing::{info, warn};

use super::kfunc_attach;
use super::loader::EbpfLoader;

/// The program of the signal object and the tracepoint it hooks.
///
/// `sys_enter` is the one event every live process reaches: the helper
/// signals the task the program runs in, so the hook has to be somewhere that
/// task itself goes through rather than somewhere its packets do.
pub const SIGNAL_PROGRAM: &str = "signal_on_syscall_entry";
/// The raw tracepoint the signal program attaches to.
pub const SIGNAL_TRACEPOINT: &str = "sys_enter";

/// What the agent can say about the signal capability, for the start-up log
/// and for the kernel-features endpoint.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SignalStatus {
    /// The tracepoint is attached and a kill can be armed.
    pub attached: bool,
    /// Why it is off, in one sentence. `None` when it is on.
    pub reason: Option<String>,
    /// The signal number a kill would send. Zero until the caller that knows
    /// the configuration says which, so a reader seeing a zero beside an
    /// attached tracepoint is reading a start-up that has not finished.
    pub signal: u32,
    /// How long a target stays armed, in milliseconds.
    pub window_ms: u64,
    /// How many thread group ids the kernel refuses to signal whatever a rule
    /// asks. Never zero on a running node: the agent itself is one of them.
    pub protected: usize,
}

/// The one status the whole process reports.
static STATUS: OnceLock<Mutex<SignalStatus>> = OnceLock::new();

fn status_cell() -> &'static Mutex<SignalStatus> {
    STATUS.get_or_init(|| Mutex::new(SignalStatus::default()))
}

/// Publish what the agent can say about the signal capability.
pub fn publish_status(status: SignalStatus) {
    let mut held = status_cell()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *held = status;
}

/// What the agent can currently say about the signal capability.
#[must_use]
pub fn status() -> SignalStatus {
    status_cell()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// Holds the tracepoint link alive. Dropping it detaches the program, which is
/// what turning the capability off does.
#[derive(Default)]
pub struct SignalAttacher {
    link: Option<OwnedFd>,
}

impl SignalAttacher {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach the signal tracepoint of `loader`, publishing what happened.
    ///
    /// Returns the status rather than an error: the agent runs without the
    /// capability, and the caller that arms kills is the one that must see
    /// the refusal.
    pub fn attach(&mut self, loader: &EbpfLoader) -> SignalStatus {
        let status = match Self::attach_one(loader) {
            Ok(link) => {
                self.link = Some(link);
                info!(
                    tracepoint = SIGNAL_TRACEPOINT,
                    "process signalling attached"
                );
                SignalStatus {
                    attached: true,
                    ..SignalStatus::default()
                }
            }
            Err(reason) => {
                warn!(
                    tracepoint = SIGNAL_TRACEPOINT,
                    reason, "process signalling off: the tracepoint attach was refused"
                );
                SignalStatus {
                    attached: false,
                    reason: Some(reason),
                    ..SignalStatus::default()
                }
            }
        };
        publish_status(status.clone());
        status
    }

    fn attach_one(loader: &EbpfLoader) -> Result<OwnedFd, String> {
        let prog_fd: RawFd = loader
            .program_fd(SIGNAL_PROGRAM)
            .ok_or_else(|| format!("program `{SIGNAL_PROGRAM}` is not in the loaded object"))?;
        kfunc_attach::attach_raw_tracepoint(SIGNAL_PROGRAM, prog_fd, SIGNAL_TRACEPOINT)
            .map_err(|e| e.to_string())
    }

    /// Whether this attacher holds the link.
    #[must_use]
    pub fn attached(&self) -> bool {
        self.link.is_some()
    }

    /// Detach the tracepoint, leaving the agent running without the
    /// capability.
    pub fn detach(&mut self) {
        if self.link.take().is_none() {
            return;
        }
        info!("process signalling detached");
        publish_status(SignalStatus::default());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hook_is_the_syscall_entry_tracepoint() {
        assert_eq!(SIGNAL_TRACEPOINT, "sys_enter");
        assert_eq!(SIGNAL_PROGRAM, "signal_on_syscall_entry");
    }

    #[test]
    fn the_default_status_says_nothing_is_attached_and_blames_nobody() {
        let s = SignalStatus::default();
        assert!(!s.attached);
        assert!(s.reason.is_none());
    }

    /// The published status is one global, so the tests that write it take
    /// turns rather than reading each other's value.
    static PUBLISHED: Mutex<()> = Mutex::new(());

    #[test]
    fn a_published_status_is_what_the_next_reader_gets() {
        let _turn = PUBLISHED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let s = SignalStatus {
            attached: true,
            reason: None,
            signal: 9,
            window_ms: 2_000,
            protected: 3,
        };
        publish_status(s.clone());
        assert_eq!(status(), s);
        publish_status(SignalStatus::default());
    }

    #[test]
    fn an_attacher_with_no_link_detaches_without_touching_the_status() {
        let _turn = PUBLISHED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let published = SignalStatus {
            attached: true,
            reason: None,
            signal: 9,
            window_ms: 2_000,
            protected: 3,
        };
        publish_status(published.clone());
        let mut attacher = SignalAttacher::new();
        assert!(!attacher.attached());
        attacher.detach();
        assert_eq!(status(), published);
        publish_status(SignalStatus::default());
    }
}
