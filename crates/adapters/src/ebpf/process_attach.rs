//! Attaching the three process tracepoints, and saying so when they cannot be.
//!
//! `sched_process_exec`, `sched_process_fork` and `sched_process_exit` are
//! the events the table needs: the first two create an entry, the last
//! removes it. Every program reads tasks through helpers and returns zero, so
//! nothing here can refuse a fork, slow an exec down measurably, or change a
//! verdict. A kernel
//! that refuses the attach costs the agent its process names and nothing
//! else, which is why this module degrades rather than failing the start: the
//! reason is published, so an operator reading a flow with no process can
//! find out why instead of guessing.
//!
//! The arguments of a started process are read by a fourth program, a
//! sleepable LSM program on `bprm_committed_creds`, which copies them out of
//! the new image with `bpf_copy_from_user_task_str` before the exec record is
//! written. It is attached only when command lines are kept, the BPF LSM is
//! active and the kernel loaded it; otherwise the table reads
//! `/proc/<pid>/cmdline` after the exec, as it always did, and the status says
//! why. Its hook is fixed when it loads, so it stays with the agent rather
//! than being handed to the warden.

use std::os::fd::OwnedFd;
use std::sync::{Mutex, OnceLock};

use aya::maps::{Array, MapData};
use ebpf_common::process::{ProcessArgvLayout, ProcessLayout};
use tracing::{info, warn};

use super::kfunc;
use super::loader::EbpfLoader;
use super::map_store::MapStore;

/// The programs of the process object, with the tracepoint each one hooks.
///
/// The object is built as `raw_tp` rather than `tp_btf`: the token-only
/// loader issues `BPF_PROG_LOAD` without an `attach_btf_id`, which `tp_btf`
/// requires, and the programs read tasks through `bpf_probe_read_kernel` at
/// offsets userspace wrote, so BTF in the program would buy them nothing.
///
/// Exit is attached last and fork before it: a table fed exec and fork but
/// not yet exit holds a few dead entries for a moment, one fed exit first
/// would count every early exit as a lost exec.
pub const PROCESS_HOOKS: &[(&str, &str)] = &[
    ("process_exec", "sched_process_exec"),
    ("process_fork", "sched_process_fork"),
    ("process_exit", "sched_process_exit"),
];

/// The sleepable program reading a started process's arguments.
pub const PROCESS_ARGV_PROGRAM: &str = "process_exec_argv";

/// The programs of the process object a kernel may refuse while the rest of
/// the object still loads, as every load of it names them.
pub const PROCESS_OPTIONAL_PROGRAMS: &[&str] = &[PROCESS_ARGV_PROGRAM];

/// Where the running kernel keeps the two `linux_binprm` fields the argument
/// read needs: the user address of the first argument and their count.
///
/// # Errors
///
/// Returns the member the kernel's BTF does not describe, in one sentence.
pub fn resolve_argv_layout() -> Result<ProcessArgvLayout, String> {
    const MEMBERS: [&str; 2] = ["p", "argc"];
    let found = kfunc::vmlinux_struct_member_offsets("linux_binprm", &MEMBERS)
        .map_err(|e| format!("the kernel BTF does not describe `linux_binprm`: {e}"))?;
    let at = |i: usize| -> Result<u32, String> {
        found
            .get(i)
            .copied()
            .flatten()
            .ok_or_else(|| format!("the kernel BTF has no `linux_binprm.{}`", MEMBERS[i]))
    };
    Ok(ProcessArgvLayout {
        binprm_p: at(0)?,
        binprm_argc: at(1)?,
        valid: 1,
        _pad: 0,
    })
}

/// Write `layout` into the object's `PROCESS_ARGV_LAYOUT`.
///
/// # Errors
///
/// Returns an error when the map is missing or the write is refused.
pub fn write_argv_layout(
    ebpf: &mut dyn MapStore,
    layout: &ProcessArgvLayout,
) -> anyhow::Result<()> {
    let mut map: Array<MapData, ProcessArgvLayout> = Array::try_from(
        ebpf.take_map("PROCESS_ARGV_LAYOUT")
            .ok_or_else(|| anyhow::anyhow!("map 'PROCESS_ARGV_LAYOUT' not found"))?,
    )?;
    map.set(0, layout, 0)
        .map_err(|e| anyhow::anyhow!("PROCESS_ARGV_LAYOUT write failed: {e}"))
}

/// What the host said about each thing the kernel read of arguments needs,
/// in the order they are asked.
#[derive(Debug, Clone, Default)]
pub struct ArgvWitnesses<'a> {
    /// Why the BPF LSM cannot host a program here, `None` when it can.
    pub lsm: Option<&'a str>,
    /// The kfunc probe's verdict on the copy, and its reason.
    pub probe: Option<(Option<bool>, Option<&'a str>)>,
    /// Why the kernel refused the program when the object loaded.
    pub refused: Option<&'a str>,
}

/// Why the kernel does not read arguments at exec, `None` when nothing stands
/// in the way. A probe that could not answer is no reason: the load already
/// asked the kernel, and its refusal is the witness that counts.
#[must_use]
pub fn argv_refusal(w: &ArgvWitnesses<'_>) -> Option<String> {
    if let Some(reason) = w.lsm {
        return Some(format!("the BPF LSM is not active: {reason}"));
    }
    if let Some((Some(false), reason)) = w.probe {
        return Some(format!(
            "the kernel does not offer bpf_copy_from_user_task_str: {}",
            reason.unwrap_or("the probe was refused")
        ));
    }
    w.refused
        .map(|reason| format!("the kernel refused `{PROCESS_ARGV_PROGRAM}`: {reason}"))
}

/// Ask the host, then write the layout the program reads: `None` when the
/// argument read can be attached, the reason it cannot otherwise.
pub fn prepare_argv(loader: &mut EbpfLoader) -> Option<String> {
    let lsm = super::lsm_probe::status();
    let probe = super::kfunc_feature_probe::cached()
        .and_then(|all| all.iter().find(|f| f.name == "copy_from_user_str"))
        .map(|f| (f.usable, f.reason.as_deref()));
    let witnesses = ArgvWitnesses {
        lsm: if lsm.active {
            None
        } else {
            Some(
                lsm.reason
                    .as_deref()
                    .unwrap_or("bpf is not among the active modules"),
            )
        },
        probe,
        refused: loader.refused_program(PROCESS_ARGV_PROGRAM),
    };
    if let Some(reason) = argv_refusal(&witnesses) {
        return Some(reason);
    }
    match resolve_argv_layout() {
        Ok(layout) => write_argv_layout(loader.ebpf_mut(), &layout)
            .err()
            .map(|e| e.to_string()),
        Err(reason) => Some(reason),
    }
}

/// Where the running kernel keeps the four fields the parent walk reads.
///
/// All four or an error: a walk handed a partial layout would read some other
/// field as a pid and name the wrong parent, which is worse than naming none.
///
/// # Errors
///
/// Returns the member the kernel's BTF does not describe, in one sentence.
pub fn resolve_layout() -> Result<ProcessLayout, String> {
    const MEMBERS: [&str; 4] = ["real_parent", "group_leader", "tgid", "start_boottime"];
    let found = kfunc::vmlinux_struct_member_offsets("task_struct", &MEMBERS)
        .map_err(|e| format!("the kernel BTF does not describe `task_struct`: {e}"))?;
    let at = |i: usize| -> Result<u32, String> {
        found
            .get(i)
            .copied()
            .flatten()
            .ok_or_else(|| format!("the kernel BTF has no `task_struct.{}`", MEMBERS[i]))
    };
    let mut layout = ProcessLayout {
        task_real_parent: at(0)?,
        task_group_leader: at(1)?,
        task_tgid: at(2)?,
        task_start_boottime: at(3)?,
        valid: 1,
        ..ProcessLayout::default()
    };
    match resolve_namespace_offsets() {
        Ok(ns) => {
            layout.task_thread_pid = ns[0];
            layout.pid_level = ns[1];
            layout.pid_numbers = ns[2];
            layout.upid_ns = ns[3];
            layout.pid_namespace_inum = ns[4];
            layout.ns_valid = 1;
        }
        Err(reason) => warn!(
            reason,
            "a fork's child and a record's parent keep the kernel's numbers: \
             right on a host, wrong wherever the procfs is a pid namespace of its own"
        ),
    }
    Ok(layout)
}

/// The offsets numbering another task in a pid namespace: `task_struct.thread_pid`,
/// `pid.level`, `pid.numbers`, `upid.ns`, and `ns_common.inum` counted from the
/// start of `pid_namespace`.
///
/// The program steps through `pid.numbers` sixteen bytes at a time and reads
/// the number at the start of each entry, so a kernel whose `struct upid` is
/// laid out otherwise gets no offsets rather than a walk reading the wrong
/// field.
pub(crate) fn resolve_namespace_offsets() -> Result<[u32; 5], String> {
    let one = |owner: &str, member: &str| -> Result<u32, String> {
        kfunc::vmlinux_struct_member_offsets(owner, &[member])
            .map_err(|e| format!("the kernel BTF does not describe `{owner}`: {e}"))?
            .first()
            .copied()
            .flatten()
            .ok_or_else(|| format!("the kernel BTF has no `{owner}.{member}`"))
    };
    let thread_pid = one("task_struct", "thread_pid")?;
    let level = one("pid", "level")?;
    let numbers = one("pid", "numbers")?;
    let nr = one("upid", "nr")?;
    let ns = one("upid", "ns")?;
    if nr != 0 || ns != 8 {
        return Err(format!(
            "`struct upid` is laid out as nr at {nr} and ns at {ns}, not the int and pointer the walk steps over"
        ));
    }
    let ns_common = one("pid_namespace", "ns")?;
    let inum = one("ns_common", "inum")?;
    Ok([thread_pid, level, numbers, ns, ns_common + inum])
}

/// The offsets a program walks the calling task's `struct pid` through:
/// `task_struct.group_leader`, then the five [`resolve_namespace_offsets`]
/// returns.
///
/// # Errors
///
/// Returns the member the kernel's BTF does not describe, in one sentence.
pub(crate) fn resolve_walk_offsets() -> Result<[u32; 6], String> {
    let group_leader = kfunc::vmlinux_struct_member_offsets("task_struct", &["group_leader"])
        .map_err(|e| format!("the kernel BTF does not describe `task_struct`: {e}"))?
        .first()
        .copied()
        .flatten()
        .ok_or("the kernel BTF has no `task_struct.group_leader`")?;
    let [thread_pid, level, numbers, upid_ns, inum] = resolve_namespace_offsets()?;
    Ok([group_leader, thread_pid, level, numbers, upid_ns, inum])
}

/// Write `layout` into the object's `PROCESS_LAYOUT` before anything attaches.
///
/// # Errors
///
/// Returns an error when the map is missing or the write is refused.
pub fn write_layout(ebpf: &mut dyn MapStore, layout: &ProcessLayout) -> anyhow::Result<()> {
    let mut map: Array<MapData, ProcessLayout> = Array::try_from(
        ebpf.take_map("PROCESS_LAYOUT")
            .ok_or_else(|| anyhow::anyhow!("map 'PROCESS_LAYOUT' not found"))?,
    )?;
    map.set(0, layout, 0)
        .map_err(|e| anyhow::anyhow!("PROCESS_LAYOUT write failed: {e}"))
}

/// What the agent can say about process tracing, for the start-up log and for
/// the kernel-features endpoint.
///
/// `attached` false with a `reason` is the degraded case: the agent runs, the
/// process table stays empty, and the sentence says which tracepoint the
/// kernel refused and with what errno.
// Each flag is a separate fact the endpoint reports as it stands, not a
// state of one machine.
#[allow(clippy::struct_excessive_bools)]
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
    /// Whether the kernel reads the arguments at exec. False means they are
    /// read from `/proc/<pid>/cmdline` afterwards, which a process that has
    /// already exited leaves empty.
    pub command_line_kernel: bool,
    /// Why the kernel does not read the arguments, in one sentence. `None`
    /// when it does, or when command lines are not kept at all.
    pub command_line_reason: Option<String>,
    /// Whether the kernel reads each process's parent and start time. False
    /// when the layout could not be read from BTF, in which case the parent
    /// comes from `/proc` after the fact and forks are not followed.
    pub lineage: bool,
    /// Why the kernel does not read the parent, in one sentence.
    pub lineage_reason: Option<String>,
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

/// Holds the tracepoint links alive. Dropping it detaches every program,
/// which is what a reload that turns the table off does.
#[derive(Default)]
pub struct ProcessTracingAttacher {
    links: Vec<OwnedFd>,
    /// The argument read at exec, held apart: losing it costs the kernel's
    /// command line and nothing else.
    argv_link: Option<OwnedFd>,
}

impl ProcessTracingAttacher {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach every tracepoint of `loader`, publishing what happened.
    ///
    /// Returns the status rather than an error: no caller treats a refused
    /// tracepoint as fatal, and a `Result` would invite one to.
    /// `command_line` says whether argv is kept; when it is and
    /// `argv_refusal` is `None` ([`prepare_argv`]), the argument read is
    /// attached after the tracepoints. `lineage_reason` is why the layout was
    /// not written, `None` when it was.
    pub fn attach_all(
        &mut self,
        loader: &EbpfLoader,
        command_line: bool,
        argv_refusal: Option<String>,
        lineage_reason: Option<String>,
    ) -> ProcessTracingStatus {
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
                    self.argv_link = None;
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
                        command_line_kernel: false,
                        command_line_reason: None,
                        lineage: false,
                        lineage_reason: lineage_reason.clone(),
                    };
                    publish_status(status.clone());
                    return status;
                }
            }
        }
        let command_line_reason = if command_line {
            self.attach_argv(loader, argv_refusal).err()
        } else {
            self.argv_link = None;
            None
        };
        let command_line_kernel = self.argv_link.is_some();
        if let Some(reason) = &command_line_reason {
            warn!(
                reason,
                "arguments read from /proc after the exec, not by the kernel at exec"
            );
        }
        let lineage = lineage_reason.is_none();
        info!(
            tracepoints = attached.len(),
            command_line, command_line_kernel, lineage, "process tracing attached"
        );
        let status = ProcessTracingStatus {
            attached: true,
            tracepoints: attached,
            reason: None,
            command_line,
            command_line_kernel,
            command_line_reason,
            lineage,
            lineage_reason,
        };
        publish_status(status.clone());
        status
    }

    /// Attach the argument read at exec, unless `refusal` says why not.
    fn attach_argv(&mut self, loader: &EbpfLoader, refusal: Option<String>) -> Result<(), String> {
        self.argv_link = None;
        if let Some(reason) = refusal {
            return Err(reason);
        }
        let prog_fd = loader.program_fd(PROCESS_ARGV_PROGRAM).ok_or_else(|| {
            format!("program `{PROCESS_ARGV_PROGRAM}` is not in the loaded object")
        })?;
        let link = super::kfunc_attach::attach_lsm(PROCESS_ARGV_PROGRAM, prog_fd)
            .map_err(|e| e.to_string())?;
        self.argv_link = Some(link);
        Ok(())
    }

    /// Attach one program to its tracepoint. There is nothing per-attacher
    /// about it: the attach is issued here rather than brokered, because the
    /// BPF token the agent loaded the object with already covers it.
    fn attach_one(loader: &EbpfLoader, program: &str, tracepoint: &str) -> Result<OwnedFd, String> {
        super::preload::attach_raw_tracepoint(loader, program, tracepoint)
    }

    /// How many tracepoints this attacher currently holds a link for.
    #[must_use]
    pub fn attached(&self) -> usize {
        self.links.len()
    }

    /// Detach every tracepoint, leaving the agent running with no table.
    pub fn detach_all(&mut self) {
        if self.links.is_empty() && self.argv_link.is_none() {
            return;
        }
        self.links.clear();
        self.argv_link = None;
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
    fn the_argument_read_is_attached_where_every_witness_allows_it() {
        assert_eq!(argv_refusal(&ArgvWitnesses::default()), None);
        let unknown = ArgvWitnesses {
            probe: Some((None, Some("it needs CAP_BPF"))),
            ..ArgvWitnesses::default()
        };
        assert_eq!(
            argv_refusal(&unknown),
            None,
            "a probe with no answer is no reason"
        );
        let confirmed = ArgvWitnesses {
            probe: Some((Some(true), None)),
            ..ArgvWitnesses::default()
        };
        assert_eq!(argv_refusal(&confirmed), None);
    }

    #[test]
    fn the_first_witness_against_the_argument_read_is_the_reason_given() {
        let all = ArgvWitnesses {
            lsm: Some("bpf is not in lsm="),
            probe: Some((Some(false), Some("not declared"))),
            refused: Some("invalid argument"),
        };
        assert_eq!(
            argv_refusal(&all).as_deref(),
            Some("the BPF LSM is not active: bpf is not in lsm=")
        );
        let probe = ArgvWitnesses {
            lsm: None,
            ..all.clone()
        };
        assert_eq!(
            argv_refusal(&probe).as_deref(),
            Some("the kernel does not offer bpf_copy_from_user_task_str: not declared")
        );
        let refused = ArgvWitnesses {
            lsm: None,
            probe: None,
            ..all
        };
        assert_eq!(
            argv_refusal(&refused).as_deref(),
            Some("the kernel refused `process_exec_argv`: invalid argument")
        );
    }

    #[test]
    fn the_argument_read_is_the_one_program_the_object_may_lose() {
        assert_eq!(PROCESS_OPTIONAL_PROGRAMS, &[PROCESS_ARGV_PROGRAM]);
        assert!(
            PROCESS_HOOKS
                .iter()
                .all(|(p, _)| *p != PROCESS_ARGV_PROGRAM)
        );
    }

    #[test]
    fn the_running_kernel_describes_the_argument_read() {
        if !std::path::Path::new("/sys/kernel/btf/vmlinux").exists() {
            return;
        }
        let layout = resolve_argv_layout().expect("linux_binprm carries p and argc");
        assert_eq!(layout.valid, 1);
        assert_ne!(layout.binprm_p, layout.binprm_argc);
    }

    #[test]
    fn the_exit_hook_is_attached_last() {
        assert_eq!(PROCESS_HOOKS[0].1, "sched_process_exec");
        assert_eq!(PROCESS_HOOKS[1].1, "sched_process_fork");
        assert_eq!(PROCESS_HOOKS[2].1, "sched_process_exit");
    }

    #[test]
    fn the_running_kernel_describes_the_parent_walk() {
        // Only where the build host exposes BTF, which every supported
        // kernel does; elsewhere there is no layout to read.
        if !std::path::Path::new("/sys/kernel/btf/vmlinux").exists() {
            return;
        }
        let layout = resolve_layout().expect("task_struct carries the four members");
        assert_eq!(layout.valid, 1);
        let mut offsets = [
            layout.task_real_parent,
            layout.task_group_leader,
            layout.task_tgid,
            layout.task_start_boottime,
        ];
        offsets.sort_unstable();
        offsets.windows(2).for_each(|w| assert!(w[0] < w[1]));
    }

    #[test]
    fn the_default_status_says_nothing_is_attached_and_blames_nobody() {
        let s = ProcessTracingStatus::default();
        assert!(!s.attached);
        assert!(s.reason.is_none());
        assert!(s.tracepoints.is_empty());
        assert!(!s.command_line);
        assert!(!s.lineage);
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
            command_line_kernel: true,
            command_line_reason: None,
            lineage: true,
            lineage_reason: None,
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
            command_line_kernel: false,
            command_line_reason: None,
            lineage: true,
            lineage_reason: None,
        };
        publish_status(published.clone());
        let mut attacher = ProcessTracingAttacher::new();
        assert_eq!(attacher.attached(), 0);
        attacher.detach_all();
        assert_eq!(status(), published);
        publish_status(ProcessTracingStatus::default());
    }
}
