//! Attaching the two process tracepoints, and saying so when they cannot be.
//!
//! `sched_process_exec` and `sched_process_exit` are the only two events the
//! table needs: one creates an entry, the other removes it. Both programs
//! read the calling task through helpers and return zero, so nothing here can
//! refuse a fork, slow an exec down measurably, or change a verdict. A kernel
//! that refuses the attach costs the agent its process names and nothing
//! else, which is why this module degrades rather than failing the start: the
//! reason is published, so an operator reading a flow with no process can
//! find out why instead of guessing.

use std::os::fd::{OwnedFd, RawFd};
use std::sync::{Mutex, OnceLock};

use tracing::{info, warn};

use super::kfunc_attach;
use super::loader::EbpfLoader;

/// The programs of the process object, with the tracepoint each one hooks.
///
/// The object is built as `raw_tp` rather than `tp_btf`: the token-only
/// loader issues `BPF_PROG_LOAD` without an `attach_btf_id`, which `tp_btf`
/// requires, and both programs read the current task through helpers alone,
/// so BTF would buy them nothing they use.
pub const PROCESS_HOOKS: &[(&str, &str)] = &[
    ("process_exec", "sched_process_exec"),
    ("process_exit", "sched_process_exit"),
];

/// What the agent can say about process tracing, for the start-up log and for
/// the kernel-features endpoint.
///
/// `attached` false with a `reason` is the degraded case: the agent runs, the
/// process table stays empty, and the sentence says which tracepoint the
/// kernel refused and with what errno.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcessTracingStatus {
    /// Both tracepoints are attached and the table is being filled.
    pub attached: bool,
    /// The tracepoints that did attach, in attach order.
    pub tracepoints: Vec<String>,
    /// Why process tracing is off, in one sentence. `None` when it is on.
    pub reason: Option<String>,
    /// Whether argv is being captured into the table.
    pub command_line: bool,
}

/// The one status the whole process reports, written by the attacher and read
/// by the kernel-features handler.
static STATUS: OnceLock<Mutex<ProcessTracingStatus>> = OnceLock::new();

fn status_cell() -> &'static Mutex<ProcessTracingStatus> {
    STATUS.get_or_init(|| Mutex::new(ProcessTracingStatus::default()))
}

/// Publish what the agent can say about process tracing.
pub fn publish_status(status: ProcessTracingStatus) {
    let mut held = status_cell()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *held = status;
}

/// What the agent can currently say about process tracing.
#[must_use]
pub fn status() -> ProcessTracingStatus {
    status_cell()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// Holds the tracepoint links alive. Dropping it detaches both programs,
/// which is what a reload that turns the table off does.
#[derive(Default)]
pub struct ProcessTracingAttacher {
    links: Vec<OwnedFd>,
}

impl ProcessTracingAttacher {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach both tracepoints of `loader`, publishing what happened.
    ///
    /// Returns the status rather than an error: no caller treats a refused
    /// tracepoint as fatal, and a `Result` would invite one to.
    /// `command_line` only travels into the status, so the endpoint can say
    /// whether argv is being kept without the reader going to the config.
    pub fn attach_all(&mut self, loader: &EbpfLoader, command_line: bool) -> ProcessTracingStatus {
        let mut attached = Vec::with_capacity(PROCESS_HOOKS.len());
        for (program, tracepoint) in PROCESS_HOOKS {
            match Self::attach_one(loader, program, tracepoint) {
                Ok(link) => {
                    self.links.push(link);
                    attached.push((*tracepoint).to_string());
                }
                Err(reason) => {
                    // Anything already attached comes off. Exec without exit
                    // is worse than neither: the table would fill with dead
                    // pids and name the wrong binary on a reused one.
                    self.links.clear();
                    warn!(
                        program,
                        tracepoint,
                        reason,
                        "process tracing off: the tracepoint attach was refused"
                    );
                    let status = ProcessTracingStatus {
                        attached: false,
                        tracepoints: Vec::new(),
                        reason: Some(reason),
                        command_line,
                    };
                    publish_status(status.clone());
                    return status;
                }
            }
        }
        info!(
            tracepoints = attached.len(),
            command_line, "process tracing attached"
        );
        let status = ProcessTracingStatus {
            attached: true,
            tracepoints: attached,
            reason: None,
            command_line,
        };
        publish_status(status.clone());
        status
    }

    /// Attach one program to its tracepoint. There is nothing per-attacher
    /// about it: the attach is issued here rather than brokered, because the
    /// BPF token the agent loaded the object with already covers it.
    fn attach_one(loader: &EbpfLoader, program: &str, tracepoint: &str) -> Result<OwnedFd, String> {
        let prog_fd: RawFd = loader
            .program_fd(program)
            .ok_or_else(|| format!("program `{program}` is not in the loaded object"))?;
        kfunc_attach::attach_raw_tracepoint(program, prog_fd, tracepoint).map_err(|e| e.to_string())
    }

    /// How many tracepoints this attacher currently holds a link for.
    #[must_use]
    pub fn attached(&self) -> usize {
        self.links.len()
    }

    /// Detach both tracepoints, leaving the agent running with no table.
    pub fn detach_all(&mut self) {
        if self.links.is_empty() {
            return;
        }
        self.links.clear();
        info!("process tracing detached");
        publish_status(ProcessTracingStatus::default());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_hooks_are_named_once_and_carry_their_own_tracepoint() {
        let mut programs: Vec<&str> = PROCESS_HOOKS.iter().map(|(p, _)| *p).collect();
        programs.sort_unstable();
        programs.dedup();
        assert_eq!(programs.len(), PROCESS_HOOKS.len());

        let mut tracepoints: Vec<&str> = PROCESS_HOOKS.iter().map(|(_, t)| *t).collect();
        tracepoints.sort_unstable();
        tracepoints.dedup();
        assert_eq!(tracepoints.len(), PROCESS_HOOKS.len());
    }

    #[test]
    fn the_exec_hook_comes_before_the_exit_hook() {
        assert_eq!(PROCESS_HOOKS[0].1, "sched_process_exec");
        assert_eq!(PROCESS_HOOKS[1].1, "sched_process_exit");
    }

    #[test]
    fn the_default_status_says_nothing_is_attached_and_blames_nobody() {
        let s = ProcessTracingStatus::default();
        assert!(!s.attached);
        assert!(s.reason.is_none());
        assert!(s.tracepoints.is_empty());
        assert!(!s.command_line);
    }

    /// The published status is one global, so the two tests that write it
    /// take turns rather than reading each other's value.
    static PUBLISHED: Mutex<()> = Mutex::new(());

    #[test]
    fn a_published_status_is_what_the_next_reader_gets() {
        let _turn = PUBLISHED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let s = ProcessTracingStatus {
            attached: true,
            tracepoints: vec!["sched_process_exec".to_string()],
            reason: None,
            command_line: true,
        };
        publish_status(s.clone());
        assert_eq!(status(), s);
        publish_status(ProcessTracingStatus::default());
    }

    #[test]
    fn an_attacher_with_no_links_detaches_without_touching_the_status() {
        let _turn = PUBLISHED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let published = ProcessTracingStatus {
            attached: true,
            tracepoints: vec!["sched_process_exec".to_string()],
            reason: None,
            command_line: false,
        };
        publish_status(published.clone());
        let mut attacher = ProcessTracingAttacher::new();
        assert_eq!(attacher.attached(), 0);
        attacher.detach_all();
        assert_eq!(status(), published);
        publish_status(ProcessTracingStatus::default());
    }
}
