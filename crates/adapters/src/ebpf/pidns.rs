//! Which pid namespace the kernel programs number tasks in.
//!
//! The agent names a task by reading `<procfs>/<pid>`, and a procfs answers
//! in the pid namespace it was mounted from. On a machine that is the initial
//! namespace and the kernel's own pid is the right one; on a node that is
//! itself a container - a kind node - the procfs belongs to the node's
//! namespace, where every task has another number. The view written here
//! tells the programs which namespace to answer in, so an exec, a refusal or
//! a signal arming names the task `/proc` shows.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use aya::maps::{Array, MapData};
use ebpf_common::exec_network::kernel_dev;
use ebpf_common::pidns::PidNsView;
use tracing::{info, warn};

use ebpf_common::process::{PROCESS_PID_NS_LEVELS, PROCESS_UPID_SIZE};

use super::kfunc_feature_probe::insn::{add_imm, encode, exit, mov_imm, mov_reg};
use super::kfunc_loader::{
    PROBE_F_SLEEPABLE, PROBE_PROG_TYPE_SYSCALL, ProbeProgram, load_raw_program,
};
use super::map_store::MapStore;

/// The map every object sending a pid declares, shared by name on the pin path.
pub const PIDNS_VIEW_MAP: &str = "PIDNS_VIEW";

/// Inode of the initial pid namespace (`PROC_PID_INIT_INO`), fixed by the
/// kernel. A view naming it is no view: the kernel's own number already is
/// the one `/proc` shows.
pub const INITIAL_PID_NS_INO: u64 = 0xEFFF_FFFC;

/// The view decided at start-up, once, for every object loaded after it.
static VIEW: OnceLock<PidNsView> = OnceLock::new();

/// The namespace of the procfs at `proc_root`, as the programs compare it.
///
/// The namespace is read off the procfs's pid 1 rather than off `self`: the
/// link `self/ns/pid` names the agent's own namespace, which is not the
/// procfs's wherever a host procfs is mounted into an agent container with a
/// namespace of its own. Pid 1 of a procfs lives in that procfs's namespace,
/// so its link names the right one. An unreadable link or the initial
/// namespace leaves no view, and the programs keep the kernel's numbers.
#[must_use]
pub fn view_of(proc_root: &Path) -> (PidNsView, PathBuf, Option<String>) {
    use std::os::unix::fs::MetadataExt;
    let link = proc_root.join("1/ns/pid");
    match std::fs::metadata(&link) {
        Ok(ns) => (view_from(ns.dev(), ns.ino()), link, None),
        Err(e) => (PidNsView::default(), link, Some(e.to_string())),
    }
}

/// The view for the namespace `stat(2)` describes as `dev` and `ino`.
#[must_use]
pub fn view_from(dev: u64, ino: u64) -> PidNsView {
    if ino == INITIAL_PID_NS_INO {
        return PidNsView::default();
    }
    PidNsView {
        // `stat(2)` encodes a device one way and the kernel compares it in
        // its own encoding.
        dev: u64::from(kernel_dev(libc::major(dev), libc::minor(dev))),
        ino,
        valid: 1,
        ..PidNsView::default()
    }
}

/// `view` with the depth of its namespace and the offsets the programs walk
/// a task's `struct pid` through, read from the running kernel. Without them
/// a task of a namespace below the view's is sent as pid 0, which the
/// start-up log says.
fn with_walk(mut view: PidNsView, proc_root: &Path) -> PidNsView {
    if view.valid == 0 {
        return view;
    }
    let walk = super::process_attach::resolve_walk_offsets().and_then(|offsets| {
        let (expected, up) = procfs_distance(proc_root)?;
        let ancestor = ancestor_namespace(up)?;
        if ancestor.nr != expected || u64::from(ancestor.inum) != view.ino {
            return Err(format!(
                "the kernel names namespace {} {up} levels above the agent, the procfs is {}",
                ancestor.inum, view.ino
            ));
        }
        Ok((offsets, ancestor.level))
    });
    match walk {
        Ok(([group_leader, thread_pid, level, numbers, upid_ns, inum], depth)) => {
            view.level = depth;
            view.task_group_leader = group_leader;
            view.task_thread_pid = thread_pid;
            view.pid_level = level;
            view.pid_numbers = numbers;
            view.upid_ns = upid_ns;
            view.pid_namespace_inum = inum;
            view.walk_valid = 1;
        }
        Err(reason) => warn!(
            reason,
            "the tasks of pid namespaces below the procfs's, a pod's on a container node, \
             have no number the kernel programs can read and are sent as pid 0"
        ),
    }
    view
}

/// Decide the view from `proc_root`, once, and say which one it is.
///
/// The procfs's pid 1 answers first. Its link is refused to an agent that may
/// not trace that task, which is the agent of a pod sharing no pid namespace
/// with its node, and the kernel answers then: the agent's own task names
/// every namespace above it, and `NSpid` in the procfs says how far up the
/// procfs's sits.
pub fn decide(proc_root: &Path) -> PidNsView {
    *VIEW.get_or_init(|| with_walk(decide_namespace(proc_root), proc_root))
}

fn decide_namespace(proc_root: &Path) -> PidNsView {
    let (view, link, error) = view_of(proc_root);
    let Some(error) = error else {
        if view.valid != 0 {
            info!(
                link = %link.display(),
                ino = view.ino,
                "the procfs belongs to a pid namespace of its own: the kernel programs number \
                 tasks in it"
            );
        }
        return view;
    };
    match view_through_kernel(proc_root) {
        Ok(view) => {
            if view.valid != 0 {
                info!(
                    link = %link.display(),
                    error,
                    ino = view.ino,
                    "the procfs belongs to a pid namespace above the agent's own, read \
                     from the agent's task: the kernel programs number tasks in it"
                );
            }
            view
        }
        Err(reason) => {
            warn!(
                link = %link.display(),
                error,
                reason,
                "the procfs's pid namespace could not be read: pids stay the kernel's own, \
                 which is wrong wherever the procfs is not the initial namespace"
            );
            PidNsView::default()
        }
    }
}

/// The agent's number in the procfs at `proc_root` and how many namespace
/// levels the procfs sits above the agent's own, from `NSpid` in its status.
///
/// The kernel prints `NSpid` from the procfs's namespace down to the task's
/// own, one number per level, so the count less one is the distance and the
/// first number is the one a task of that namespace is known by.
fn procfs_distance(proc_root: &Path) -> Result<(u32, u32), String> {
    let path = proc_root.join("self/status");
    let status = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    parse_nspid(&status).ok_or_else(|| format!("{} carries no readable NSpid", path.display()))
}

fn parse_nspid(status: &str) -> Option<(u32, u32)> {
    let line = status.lines().find_map(|l| l.strip_prefix("NSpid:"))?;
    let numbers: Vec<u32> = line
        .split_whitespace()
        .map(str::parse)
        .collect::<Result<_, _>>()
        .ok()?;
    let first = *numbers.first()?;
    let up = u32::try_from(numbers.len() - 1).ok()?;
    Some((first, up))
}

/// The procfs's namespace read from the agent's own task, `up` levels above
/// the agent's namespace, with the device every namespace link reports.
fn view_through_kernel(proc_root: &Path) -> Result<PidNsView, String> {
    use std::os::unix::fs::MetadataExt;
    let (expected, up) = procfs_distance(proc_root)?;
    // The agent's own link is always readable, and every namespace lives on
    // the one nsfs device it reports.
    let own = proc_root.join("self/ns/pid");
    let own = std::fs::metadata(&own).map_err(|e| format!("{}: {e}", own.display()))?;
    if up == 0 {
        return Ok(view_from(own.dev(), own.ino()));
    }
    let ancestor = ancestor_namespace(up)?;
    if ancestor.nr != expected {
        return Err(format!(
            "the kernel numbers the agent {} {up} levels up, the procfs says {expected}",
            ancestor.nr
        ));
    }
    Ok(view_from(own.dev(), u64::from(ancestor.inum)))
}

/// `BPF_FUNC_get_current_task`.
const HELPER_GET_CURRENT_TASK: i32 = 35;
/// `BPF_FUNC_probe_read_kernel`.
const HELPER_PROBE_READ_KERNEL: i32 = 113;

/// The program's argument and answer: `up`, then the number, the namespace
/// inode and the namespace's depth it writes back.
const CTX_LEN: usize = 16;

/// A namespace above the agent's, as the kernel describes it.
struct Ancestor {
    /// The agent's number there.
    nr: u32,
    /// Its inode.
    inum: u32,
    /// Its depth, the initial namespace being 0.
    level: u32,
}

/// Run a program as the agent's own task that reads, `up` levels above the
/// task's namespace, the task's number there, that namespace's inode and its
/// depth.
fn ancestor_namespace(up: u32) -> Result<Ancestor, String> {
    use std::os::fd::AsFd;
    let offsets = super::process_attach::resolve_namespace_offsets()?;
    let insns = assemble_ancestor(offsets).ok_or("the namespace program could not be assembled")?;
    let probe = ProbeProgram {
        prog_type: PROBE_PROG_TYPE_SYSCALL,
        expected_attach_type: 0,
        prog_flags: PROBE_F_SLEEPABLE,
        attach_btf_id: 0,
        insns,
    };
    let prog = load_raw_program(&probe, b"pidns_ancestor").map_err(|(errno, log)| {
        let last = log
            .lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .unwrap_or("");
        format!(
            "the kernel refused the namespace program (errno {errno}): {}",
            last.trim()
        )
    })?;
    let mut ctx = [0u8; CTX_LEN];
    ctx[..4].copy_from_slice(&up.to_ne_bytes());
    let ret = super::prog_test_run::run_syscall_in_place(prog.as_fd(), &mut ctx)
        .map_err(|e| e.to_string())?;
    if ret != 0 {
        return Err(format!(
            "the agent's task has no namespace {up} levels above its own, or a read failed"
        ));
    }
    let word = |at: usize| u32::from_ne_bytes([ctx[at], ctx[at + 1], ctx[at + 2], ctx[at + 3]]);
    Ok(Ancestor {
        nr: word(4),
        inum: word(8),
        level: word(12),
    })
}

/// The program: `current->thread_pid`, its `level`, the `upid` at
/// `level - up` and, through its `ns`, the namespace's inode. Returns 0 with
/// the number at offset 4, the inode at offset 8 and `level - up` at offset
/// 12 of its context, 1 when
/// any read fails or the level does not exist.
fn assemble_ancestor(offsets: [u32; 5]) -> Option<Vec<u64>> {
    let [thread_pid, level, numbers, upid_ns, inum] =
        offsets.map(|o| i32::try_from(o).unwrap_or(i32::MAX));
    let mut insns: Vec<u64> = Vec::with_capacity(64);
    let mut fails: Vec<usize> = Vec::new();
    let read = |insns: &mut Vec<u64>,
                fails: &mut Vec<usize>,
                stack: i32,
                size: i32,
                base: u8,
                off: i32| {
        insns.push(mov_reg(1, 10));
        insns.push(add_imm(1, stack));
        insns.push(mov_imm(2, size));
        insns.push(mov_reg(3, base));
        insns.push(add_imm(3, off));
        insns.push(encode(0x85, 0, 0, 0, HELPER_PROBE_READ_KERNEL));
        fails.push(insns.len());
        insns.push(encode(0x55, 0, 0, 0, 0)); // r0 != 0
    };
    insns.push(mov_reg(6, 1));
    insns.push(encode(0x85, 0, 0, 0, HELPER_GET_CURRENT_TASK));
    insns.push(mov_reg(7, 0));
    read(&mut insns, &mut fails, -8, 8, 7, thread_pid);
    insns.push(encode(0x79, 7, 10, -8, 0)); // r7 = struct pid *
    fails.push(insns.len());
    insns.push(encode(0x15, 7, 0, 0, 0)); // null
    read(&mut insns, &mut fails, -16, 4, 7, level);
    insns.push(encode(0x61, 8, 10, -16, 0)); // r8 = level
    insns.push(encode(0x61, 9, 6, 0, 0)); // r9 = up
    fails.push(insns.len());
    insns.push(encode(0x2d, 9, 8, 0, 0)); // up > level
    insns.push(encode(0x1f, 8, 9, 0, 0)); // r8 = level - up
    insns.push(encode(0x63, 6, 8, 12, 0)); // ctx.level
    fails.push(insns.len());
    insns.push(encode(
        0x25,
        8,
        0,
        0,
        i32::try_from(PROCESS_PID_NS_LEVELS - 1).ok()?,
    ));
    insns.push(encode(
        0x27,
        8,
        0,
        0,
        i32::try_from(PROCESS_UPID_SIZE).ok()?,
    ));
    insns.push(add_imm(8, numbers));
    insns.push(encode(0x0f, 7, 8, 0, 0)); // r7 = &numbers[level - up]
    read(&mut insns, &mut fails, -16, 4, 7, 0);
    insns.push(encode(0x61, 1, 10, -16, 0));
    insns.push(encode(0x63, 6, 1, 4, 0)); // ctx.nr
    read(&mut insns, &mut fails, -8, 8, 7, upid_ns);
    insns.push(encode(0x79, 7, 10, -8, 0)); // r7 = struct pid_namespace *
    fails.push(insns.len());
    insns.push(encode(0x15, 7, 0, 0, 0));
    read(&mut insns, &mut fails, -16, 4, 7, inum);
    insns.push(encode(0x61, 1, 10, -16, 0));
    insns.push(encode(0x63, 6, 1, 8, 0)); // ctx.inum
    insns.push(mov_imm(0, 0));
    insns.push(exit());
    let fail = insns.len();
    insns.push(mov_imm(0, 1));
    insns.push(exit());
    for at in fails {
        let off = i16::try_from(fail.checked_sub(at + 1)?).ok()?;
        insns[at] = (insns[at] & !(0xffff << 16)) | (u64::from(off.cast_unsigned()) << 16);
    }
    Some(insns)
}

/// Write `view` into the object's `PIDNS_VIEW`.
///
/// # Errors
///
/// Returns an error when the object declares no such map or the write is
/// refused; the programs then number tasks as the kernel does.
pub fn publish(ebpf: &mut dyn MapStore, view: &PidNsView) -> anyhow::Result<()> {
    let mut map: Array<MapData, PidNsView> = Array::try_from(
        ebpf.take_map(PIDNS_VIEW_MAP)
            .ok_or_else(|| anyhow::anyhow!("map '{PIDNS_VIEW_MAP}' not found"))?,
    )?;
    map.set(0, view, 0)
        .map_err(|e| anyhow::anyhow!("{PIDNS_VIEW_MAP} write failed: {e}"))
}

/// Decide the view from `proc_root` once and write it into the object, with
/// a refusal logged rather than returned: a program that keeps the kernel's
/// numbers still runs, it names the wrong task only where the procfs is not
/// the initial namespace.
pub fn publish_or_warn(ebpf: &mut dyn MapStore, proc_root: &Path, object: &str) {
    let view = decide(proc_root);
    if let Err(error) = publish(ebpf, &view) {
        warn!(object, error = %error, "pid namespace view not written: pids are the kernel's own");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_initial_namespace_is_no_view() {
        assert_eq!(view_from(4, INITIAL_PID_NS_INO).valid, 0);
    }

    #[test]
    fn another_namespace_is_compared_in_the_kernel_encoding() {
        let view = view_from(libc::makedev(0, 4), 4_026_532_312);
        assert_eq!(view.valid, 1);
        assert_eq!(view.ino, 4_026_532_312);
        assert_eq!(view.dev, 4);
    }

    #[test]
    fn nspid_gives_the_number_in_the_procfs_and_the_distance() {
        let status = "Name:\tagent\nNSpid:\t4123\t1\nPPid:\t0\n";
        assert_eq!(parse_nspid(status), Some((4123, 1)));
        assert_eq!(parse_nspid("NSpid:\t77\n"), Some((77, 0)));
        assert_eq!(parse_nspid("Name:\tx\n"), None);
    }

    #[test]
    fn every_failed_read_lands_on_the_failure_exit() {
        let insns = assemble_ancestor([2000, 4, 64, 8, 136]).expect("assembles");
        let fail = insns.len() - 2;
        for (at, insn) in insns.iter().enumerate() {
            let code = (insn & 0xff) as u8;
            if matches!(code, 0x55 | 0x15 | 0x2d | 0x25) {
                let off = usize::from(((insn >> 16) & 0xffff) as u16);
                assert_eq!(at + 1 + off, fail, "jump at {at}");
            }
        }
        assert_eq!(insns[fail], mov_imm(0, 1));
    }

    #[test]
    fn a_procfs_without_pid_one_leaves_the_kernel_numbers() {
        let dir = tempfile::tempdir().unwrap();
        let (view, _, error) = view_of(dir.path());
        assert_eq!(view.valid, 0);
        assert!(error.is_some());
    }
}
