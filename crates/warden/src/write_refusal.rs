//! The two privileged halves of the write refusal where the BPF LSM is not
//! active: opening its fanotify permission group, and reading what a thread
//! blocked on one of its events asked for.
//!
//! A permission class needs `CAP_SYS_ADMIN` in the initial user namespace,
//! and another process's pending system call sits behind a ptrace access
//! check; the rootless agent holds neither. An agent that does hold them runs
//! the same two functions in-process.
//!
//! Everything read here is under the procfs given and the cgroup tree, never
//! a watched path: a reader that opened a watched file would wait on the
//! answer it is computing.

use std::fs::File;
use std::io;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::Path;

use ebpfsentinel_warden_proto::{OPENER_READINGS_MAX, OpenIntent, OpenerReading};

/// The flags the group is opened with: permission events, and the opener's
/// thread rather than its thread group, so its pending system call is the
/// one read.
pub const GROUP_FLAGS: libc::c_uint =
    libc::FAN_CLASS_CONTENT | libc::FAN_CLOEXEC | libc::FAN_REPORT_TID;

/// Where the cgroup tree is read.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// Open the write refusal's permission group.
///
/// # Errors
///
/// Returns why the group cannot be opened here, in one sentence.
pub fn permission_group() -> Result<OwnedFd, String> {
    permission_group_with(GROUP_FLAGS)
}

/// Open a permission group with `flags`.
///
/// Refuses a notification class and the reporting flags before the kernel
/// is asked: the permission classes cannot carry them, and a group opened
/// without a permission class would let every open through unasked.
fn permission_group_with(flags: libc::c_uint) -> Result<OwnedFd, String> {
    let reporting = libc::FAN_REPORT_FID | libc::FAN_REPORT_DIR_FID | libc::FAN_REPORT_NAME;
    if flags & reporting != 0 {
        return Err("a permission group cannot report file handles".to_string());
    }
    if flags & (libc::FAN_CLASS_CONTENT | libc::FAN_CLASS_PRE_CONTENT) == 0 {
        return Err("a group without a permission class refuses nothing".to_string());
    }
    // SAFETY: plain flags, no pointer.
    let fd = unsafe {
        libc::fanotify_init(
            flags,
            (libc::O_RDONLY | libc::O_LARGEFILE | libc::O_CLOEXEC).cast_unsigned(),
        )
    };
    if fd < 0 {
        let err = io::Error::last_os_error();
        return Err(match err.raw_os_error() {
            Some(libc::EPERM) => {
                "a fanotify permission group needs CAP_SYS_ADMIN in the initial user namespace"
                    .to_string()
            }
            Some(libc::EINVAL) => "this kernel refuses a fanotify permission group".to_string(),
            _ => format!("the fanotify permission group was refused: {err}"),
        });
    }
    // SAFETY: `fanotify_init` returned a fresh descriptor nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Read each thread, at most [`OPENER_READINGS_MAX`]; the rest read as gone.
#[must_use]
pub fn read_openers(proc_root: &Path, tids: &[u32]) -> Vec<OpenerReading> {
    tids.iter()
        .enumerate()
        .map(|(i, tid)| {
            if i < OPENER_READINGS_MAX {
                read_opener(proc_root, *tid)
            } else {
                OpenerReading::GONE
            }
        })
        .collect()
}

/// What one thread blocked on a permission event asked for, and who it is.
#[must_use]
pub fn read_opener(proc_root: &Path, tid: u32) -> OpenerReading {
    let task = proc_root.join(tid.to_string());
    let Some(tgid) = std::fs::read_to_string(task.join("status"))
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find_map(|l| l.strip_prefix("Tgid:"))
                .and_then(|v| v.trim().parse::<u32>().ok())
        })
    else {
        return OpenerReading::GONE;
    };
    let intent = std::fs::read_to_string(task.join("syscall"))
        .map_or(OpenIntent::Unknown, |line| intent_of(&line, &task));
    let exe = std::fs::metadata(task.join("exe"))
        .ok()
        .map(|m| (m.dev(), m.ino()));
    let cgroup_id = std::fs::read_to_string(task.join("cgroup"))
        .ok()
        .and_then(|c| {
            c.lines()
                .find_map(|l| l.strip_prefix("0::"))
                .map(str::to_string)
        })
        .and_then(|rel| std::fs::metadata(format!("{CGROUP_ROOT}{rel}")).ok())
        .map_or(0, |m| m.ino());
    OpenerReading {
        intent,
        tgid,
        cgroup_id,
        exe,
    }
}

/// Whether open flags ask for writing: a write access mode or a truncation.
fn writes(flags: u64) -> bool {
    let accmode = flags & u64::from(libc::O_ACCMODE.cast_unsigned());
    accmode != u64::from(libc::O_RDONLY.cast_unsigned())
        || flags & u64::from(libc::O_TRUNC.cast_unsigned()) != 0
}

fn hex(field: &str) -> Option<u64> {
    u64::from_str_radix(field.trim_start_matches("0x"), 16).ok()
}

/// Read the intent off `/proc/<tid>/syscall`, the number then six
/// arguments; `openat2` points at its flags, read from the opener's memory.
fn intent_of(line: &str, task: &Path) -> OpenIntent {
    let fields: Vec<&str> = line.split_whitespace().collect();
    let Some(nr) = fields.first().and_then(|n| n.parse::<i64>().ok()) else {
        return OpenIntent::Unknown;
    };
    let arg = |i: usize| fields.get(i + 1).and_then(|f| hex(f));
    let flags = match nr {
        n if n == libc::SYS_openat => arg(2),
        n if n == libc::SYS_openat2 => arg(2).and_then(|how| open_how_flags(task, how)),
        #[cfg(target_arch = "x86_64")]
        n if n == libc::SYS_open => arg(1),
        #[cfg(target_arch = "x86_64")]
        n if n == libc::SYS_creat => return OpenIntent::Write,
        _ => None,
    };
    match flags {
        Some(f) if writes(f) => OpenIntent::Write,
        Some(_) => OpenIntent::Read,
        None => OpenIntent::Unknown,
    }
}

/// The first field of the opener's `struct open_how`, its flags.
fn open_how_flags(task: &Path, address: u64) -> Option<u64> {
    let mem = File::open(task.join("mem")).ok()?;
    let mut flags = [0u8; 8];
    mem.read_exact_at(&mut flags, address).ok()?;
    Some(u64::from_ne_bytes(flags))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_permission_group_never_carries_the_reporting_flags_nor_lacks_a_permission_class() {
        assert_eq!(GROUP_FLAGS & libc::FAN_REPORT_FID, 0);
        assert_ne!(GROUP_FLAGS & libc::FAN_CLASS_CONTENT, 0);
        assert!(
            permission_group_with(GROUP_FLAGS | libc::FAN_REPORT_FID)
                .unwrap_err()
                .contains("file handles")
        );
        assert!(
            permission_group_with(libc::FAN_CLASS_NOTIF | libc::FAN_CLOEXEC)
                .unwrap_err()
                .contains("refuses nothing")
        );
    }

    #[test]
    fn the_intent_is_read_off_the_pending_open() {
        let task = Path::new("/proc/1");
        let rdonly = format!(
            "{} 0xffffff9c 0x7ffd 0x0 0x0 0x0 0x0 0x7ffd 0x7f",
            libc::SYS_openat
        );
        let wronly_creat_trunc = format!(
            "{} 0xffffff9c 0x7ffd 0x241 0x1b6 0x0 0x0 0x7ffd 0x7f",
            libc::SYS_openat
        );
        let rdonly_trunc = format!("{} 0xffffff9c 0x7ffd 0x200 0x0 0x0 0x0", libc::SYS_openat);
        assert_eq!(intent_of(&rdonly, task), OpenIntent::Read);
        assert_eq!(intent_of(&wronly_creat_trunc, task), OpenIntent::Write);
        assert_eq!(intent_of(&rdonly_trunc, task), OpenIntent::Write);
        assert_eq!(intent_of("running", task), OpenIntent::Unknown);
        assert_eq!(intent_of("0 0x0 0x0 0x0", task), OpenIntent::Unknown);
    }

    #[test]
    fn a_thread_reads_its_own_group_and_a_missing_one_reads_as_gone() {
        let me = read_opener(Path::new("/proc"), std::process::id());
        assert_eq!(me.tgid, std::process::id());
        assert!(me.exe.is_some());
        let none = read_opener(Path::new("/proc"), u32::MAX);
        assert_eq!(none, OpenerReading::GONE);
        let many = read_openers(Path::new("/proc"), &vec![u32::MAX; OPENER_READINGS_MAX + 2]);
        assert_eq!(many.len(), OPENER_READINGS_MAX + 2);
    }
}
