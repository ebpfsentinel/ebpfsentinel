//! The warden confines itself before it serves.
//!
//! Once the privileged setup is done (the pcap pool and module BTF opened, the
//! listening socket bound), the warden has nothing left to gain from the
//! capabilities a container runtime or systemd gave it that it does not use
//! for an answer, so it takes three steps it cannot undo, in this order:
//!
//! 1. `PR_SET_NO_NEW_PRIVS`: no `execve` it could still make would raise a
//!    privilege. Kubernetes refuses `allowPrivilegeEscalation: false` beside
//!    `CAP_SYS_ADMIN`, so this is the line that holds in a pod.
//! 2. Landlock, where the kernel has it: no execution anywhere, and no file
//!    created, written, truncated, renamed or removed outside the directories
//!    it names (the bpffs it pins links on). Reads are left open, because the
//!    file watch, the DLP scan and the runtime stores read host paths the
//!    agent's configuration names at runtime. A kernel without Landlock is a
//!    weaker posture, logged, never a refusal to serve.
//! 3. A seccomp filter: the system calls the broker makes are allowed, the
//!    ones that would change what the host runs or mounts kill the process,
//!    and any other answers `EPERM`. A thread may not create a namespace and
//!    `setns` enters a network namespace and nothing else.
//!
//! An unknown call answers `EPERM` rather than killing so that a call this
//! list missed fails one request with an error the agent logs, instead of
//! taking every agent's datapath helper down. The calls that matter are named
//! and kill.

use std::ffi::CString;
use std::io;
use std::mem;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crate::policy::WardenPolicy;

/// What the warden ended up confined by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Posture {
    /// The Landlock ABI the kernel answered with, `None` where it has none or
    /// it is disabled.
    pub landlock_abi: Option<u32>,
}

impl std::fmt::Display for Posture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.landlock_abi {
            Some(abi) => write!(f, "no new privileges, Landlock ABI {abi}, seccomp filter"),
            None => write!(
                f,
                "no new privileges, seccomp filter, no Landlock (this kernel does not offer it: \
                 writes and execution are fenced by seccomp and the mounts alone)"
            ),
        }
    }
}

/// What the warden may still change beneath one directory once confined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Writes {
    /// Create, write, replace and remove anything: the directory the socket
    /// is bound in, the directory link pins are kept in.
    Anything,
    /// Create a regular file and write it, nothing else: a directory a
    /// canary is planted in.
    NewFiles,
}

/// Confine the calling process, every thread of it included, leaving writes
/// possible only beneath the directories `writable` names, each as far as its
/// [`Writes`] says.
///
/// # Errors
///
/// `PR_SET_NO_NEW_PRIVS` or the seccomp filter was refused, or Landlock was
/// offered and then refused a ruleset. A directory in `writable` that cannot
/// be opened is logged and left unwritable, not an error.
pub fn confine(writable: &[(&Path, Writes)]) -> Result<Posture, String> {
    no_new_privs()?;
    let landlock_abi = landlock(writable)?;
    seccomp()?;
    Ok(Posture { landlock_abi })
}

/// Confine a warden about to serve `policy`: link pins may be written in
/// their directory, created first so the rule has a directory to hold, and a
/// canary may be created in the directory of each canary path the policy
/// names. Nothing else on the host stays writable, the socket included: it is
/// bound before.
///
/// # Errors
///
/// As [`confine`].
pub fn confine_for_serving(policy: &WardenPolicy) -> Result<Posture, String> {
    let pins = crate::link_pins::pin_dir();
    if let Err(e) = std::fs::create_dir_all(&pins) {
        eprintln!("[warden] link pin directory {}: {e}", pins.display());
    }
    let canary_dirs: Vec<&Path> = policy
        .canaries
        .iter()
        .filter_map(|c| Path::new(c).parent())
        .collect();
    let mut writable = vec![(pins.as_path(), Writes::Anything)];
    writable.extend(canary_dirs.into_iter().map(|d| (d, Writes::NewFiles)));
    confine(&writable)
}

fn no_new_privs() -> Result<(), String> {
    // SAFETY: `prctl` with integer arguments only.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(format!(
            "PR_SET_NO_NEW_PRIVS: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

// Landlock's interface, from `include/uapi/linux/landlock.h`.
const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;
const FS_EXECUTE: u64 = 1 << 0;
const FS_WRITE_FILE: u64 = 1 << 1;
const FS_REMOVE_DIR: u64 = 1 << 4;
const FS_REMOVE_FILE: u64 = 1 << 5;
const FS_MAKE_CHAR: u64 = 1 << 6;
const FS_MAKE_DIR: u64 = 1 << 7;
const FS_MAKE_REG: u64 = 1 << 8;
const FS_MAKE_SOCK: u64 = 1 << 9;
const FS_MAKE_FIFO: u64 = 1 << 10;
const FS_MAKE_BLOCK: u64 = 1 << 11;
const FS_MAKE_SYM: u64 = 1 << 12;
const FS_REFER: u64 = 1 << 13;
const FS_TRUNCATE: u64 = 1 << 14;
const SCOPE_ABSTRACT_UNIX_SOCKET: u64 = 1 << 0;

/// What changes a file system, per ABI: the first ABI knows neither moving a
/// file between directories nor truncating one.
fn fs_writes(abi: u32) -> u64 {
    let mut writes = FS_WRITE_FILE
        | FS_REMOVE_DIR
        | FS_REMOVE_FILE
        | FS_MAKE_CHAR
        | FS_MAKE_DIR
        | FS_MAKE_REG
        | FS_MAKE_SOCK
        | FS_MAKE_FIFO
        | FS_MAKE_BLOCK
        | FS_MAKE_SYM;
    if abi >= 2 {
        writes |= FS_REFER;
    }
    if abi >= 3 {
        writes |= FS_TRUNCATE;
    }
    writes
}

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

fn landlock(writable: &[(&Path, Writes)]) -> Result<Option<u32>, String> {
    // SAFETY: a version query passes no attribute and size zero.
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<RulesetAttr>(),
            0_usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if abi < 1 {
        return Ok(None);
    }
    let abi = u32::try_from(abi).unwrap_or(1);
    let writes = fs_writes(abi);
    let attr = RulesetAttr {
        handled_access_fs: writes | FS_EXECUTE,
        handled_access_net: 0,
        scoped: if abi >= 6 {
            SCOPE_ABSTRACT_UNIX_SOCKET
        } else {
            0
        },
    };
    // The kernel reads as much of the attribute as the ABI it speaks knows:
    // the network field came with the fourth, the scopes with the sixth.
    let size = match abi {
        1..=3 => mem::size_of::<u64>(),
        4 | 5 => 2 * mem::size_of::<u64>(),
        _ => mem::size_of::<RulesetAttr>(),
    };
    // SAFETY: `attr` is live for the call and `size` is no larger than it.
    let ruleset = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &raw const attr,
            size,
            0_u32,
        )
    };
    if ruleset < 0 {
        return Err(format!("Landlock ruleset: {}", io::Error::last_os_error()));
    }
    let ruleset = i32::try_from(ruleset).map_err(|_| "Landlock ruleset fd".to_owned())?;
    let result = landlock_rules(ruleset, writable, writes);
    // SAFETY: `ruleset` was opened above and is closed once, here.
    unsafe { libc::close(ruleset) };
    result.map(|()| Some(abi))
}

fn landlock_rules(ruleset: i32, writable: &[(&Path, Writes)], writes: u64) -> Result<(), String> {
    for (dir, scope) in writable {
        let Ok(path) = CString::new(dir.as_os_str().as_bytes()) else {
            continue;
        };
        // SAFETY: `path` is NUL-terminated and outlives the call.
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_PATH | libc::O_CLOEXEC | libc::O_DIRECTORY,
            )
        };
        if fd < 0 {
            eprintln!(
                "[warden] {} is not writable after confinement: {}",
                dir.display(),
                io::Error::last_os_error()
            );
            continue;
        }
        let rule = PathBeneathAttr {
            allowed_access: match scope {
                Writes::Anything => writes,
                Writes::NewFiles => FS_MAKE_REG | FS_WRITE_FILE,
            },
            parent_fd: fd,
        };
        // SAFETY: `rule` is live for the call and `fd` open.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_landlock_add_rule,
                ruleset,
                LANDLOCK_RULE_PATH_BENEATH,
                &raw const rule,
                0_u32,
            )
        };
        let error = io::Error::last_os_error();
        // SAFETY: `fd` was opened above and is closed once, here.
        unsafe { libc::close(fd) };
        if rc != 0 {
            return Err(format!("Landlock rule for {}: {error}", dir.display()));
        }
    }
    // SAFETY: `ruleset` is an open Landlock ruleset; no pointer is passed.
    let rc = unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset, 0_u32) };
    if rc != 0 {
        return Err(format!(
            "Landlock restrict_self: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xC000_003E;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xC000_00B7;

/// The calls that change what the host runs, mounts or loads, or reach into
/// another process. One of them is the act of a warden taken over, so it ends
/// the process rather than failing.
pub const KILLED: &[libc::c_long] = &[
    libc::SYS_execve,
    libc::SYS_execveat,
    libc::SYS_ptrace,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
    libc::SYS_init_module,
    libc::SYS_finit_module,
    libc::SYS_delete_module,
    libc::SYS_kexec_load,
    libc::SYS_kexec_file_load,
    libc::SYS_mount,
    libc::SYS_umount2,
    libc::SYS_pivot_root,
    libc::SYS_chroot,
    libc::SYS_fsopen,
    libc::SYS_fsmount,
    libc::SYS_fspick,
    libc::SYS_move_mount,
    libc::SYS_open_tree,
    libc::SYS_mount_setattr,
    libc::SYS_unshare,
    libc::SYS_keyctl,
    libc::SYS_add_key,
    libc::SYS_request_key,
    libc::SYS_userfaultfd,
    libc::SYS_swapon,
    libc::SYS_swapoff,
    libc::SYS_reboot,
    libc::SYS_acct,
    libc::SYS_settimeofday,
    libc::SYS_clock_settime,
    libc::SYS_sethostname,
    libc::SYS_setdomainname,
    libc::SYS_personality,
    libc::SYS_io_uring_setup,
    libc::SYS_io_uring_enter,
    libc::SYS_io_uring_register,
    libc::SYS_mknodat,
    libc::SYS_setuid,
    libc::SYS_setgid,
    libc::SYS_setreuid,
    libc::SYS_setregid,
    libc::SYS_setresuid,
    libc::SYS_setresgid,
    libc::SYS_setfsuid,
    libc::SYS_setfsgid,
    libc::SYS_setgroups,
    libc::SYS_capset,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_iopl,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_ioperm,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_mknod,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_uselib,
];

/// The calls the broker makes once it serves: the C library and the Rust
/// runtime under every thread, the sockets it answers on and speaks netlink
/// over, the files it reads, and the kernel interfaces it brokers (`bpf`,
/// `perf_event_open` for a uprobe, fanotify for the file watch and the write
/// refusal, `fsconfig` on the bpffs the agent hands over, the pidfds that name
/// an agent). `clone` and `setns` are allowed under argument checks of their
/// own and are not listed.
pub const ALLOWED: &[libc::c_long] = &[
    // Memory, signals, threads, time.
    libc::SYS_brk,
    libc::SYS_mmap,
    libc::SYS_munmap,
    libc::SYS_mremap,
    libc::SYS_mprotect,
    libc::SYS_madvise,
    libc::SYS_rt_sigaction,
    libc::SYS_rt_sigprocmask,
    libc::SYS_rt_sigreturn,
    libc::SYS_sigaltstack,
    libc::SYS_futex,
    libc::SYS_set_robust_list,
    libc::SYS_get_robust_list,
    libc::SYS_set_tid_address,
    libc::SYS_rseq,
    libc::SYS_membarrier,
    libc::SYS_sched_yield,
    libc::SYS_sched_getaffinity,
    libc::SYS_nanosleep,
    libc::SYS_clock_nanosleep,
    libc::SYS_clock_gettime,
    libc::SYS_clock_getres,
    libc::SYS_gettimeofday,
    libc::SYS_exit,
    libc::SYS_exit_group,
    libc::SYS_wait4,
    libc::SYS_waitid,
    libc::SYS_restart_syscall,
    libc::SYS_tgkill,
    libc::SYS_tkill,
    libc::SYS_kill,
    libc::SYS_getpid,
    libc::SYS_gettid,
    libc::SYS_getppid,
    libc::SYS_getuid,
    libc::SYS_geteuid,
    libc::SYS_getgid,
    libc::SYS_getegid,
    libc::SYS_getresuid,
    libc::SYS_getresgid,
    libc::SYS_getgroups,
    libc::SYS_capget,
    libc::SYS_prctl,
    libc::SYS_prlimit64,
    libc::SYS_getrlimit,
    libc::SYS_getrusage,
    libc::SYS_uname,
    libc::SYS_sysinfo,
    libc::SYS_getrandom,
    libc::SYS_umask,
    libc::SYS_getcwd,
    libc::SYS_seccomp,
    // Descriptors and files.
    libc::SYS_read,
    libc::SYS_write,
    libc::SYS_readv,
    libc::SYS_writev,
    libc::SYS_pread64,
    libc::SYS_pwrite64,
    libc::SYS_preadv,
    libc::SYS_lseek,
    libc::SYS_close,
    libc::SYS_close_range,
    libc::SYS_dup,
    libc::SYS_dup3,
    libc::SYS_fcntl,
    libc::SYS_ioctl,
    libc::SYS_flock,
    libc::SYS_fsync,
    libc::SYS_fdatasync,
    libc::SYS_fadvise64,
    libc::SYS_openat,
    libc::SYS_openat2,
    libc::SYS_open_by_handle_at,
    libc::SYS_name_to_handle_at,
    libc::SYS_fstat,
    libc::SYS_newfstatat,
    libc::SYS_statx,
    libc::SYS_statfs,
    libc::SYS_fstatfs,
    libc::SYS_faccessat,
    libc::SYS_faccessat2,
    libc::SYS_readlinkat,
    libc::SYS_flistxattr,
    libc::SYS_fgetxattr,
    libc::SYS_getdents64,
    libc::SYS_unlinkat,
    libc::SYS_mkdirat,
    libc::SYS_fchmod,
    libc::SYS_fchmodat,
    libc::SYS_pipe2,
    libc::SYS_eventfd2,
    libc::SYS_ppoll,
    libc::SYS_pselect6,
    libc::SYS_epoll_create1,
    libc::SYS_epoll_ctl,
    libc::SYS_epoll_pwait,
    // Sockets: the agent's, the runtimes', netlink, packet capture.
    libc::SYS_socket,
    libc::SYS_socketpair,
    libc::SYS_bind,
    libc::SYS_listen,
    libc::SYS_accept,
    libc::SYS_accept4,
    libc::SYS_connect,
    libc::SYS_getsockname,
    libc::SYS_getpeername,
    libc::SYS_sendto,
    libc::SYS_recvfrom,
    libc::SYS_sendmsg,
    libc::SYS_recvmsg,
    libc::SYS_sendmmsg,
    libc::SYS_recvmmsg,
    libc::SYS_shutdown,
    libc::SYS_setsockopt,
    libc::SYS_getsockopt,
    // What the warden brokers.
    libc::SYS_bpf,
    libc::SYS_perf_event_open,
    libc::SYS_fanotify_init,
    libc::SYS_fanotify_mark,
    libc::SYS_fsconfig,
    libc::SYS_pidfd_open,
    libc::SYS_landlock_create_ruleset,
    libc::SYS_landlock_add_rule,
    libc::SYS_landlock_restrict_self,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_arch_prctl,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_open,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_stat,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_lstat,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_access,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_readlink,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_poll,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_select,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_pipe,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_dup2,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_unlink,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_mkdir,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_getdents,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_epoll_wait,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_time,
];

/// The namespace flags no thread of the warden may be created with.
const CLONE_NAMESPACES: u32 = (libc::CLONE_NEWNS
    | libc::CLONE_NEWUSER
    | libc::CLONE_NEWPID
    | libc::CLONE_NEWNET
    | libc::CLONE_NEWIPC
    | libc::CLONE_NEWUTS
    | libc::CLONE_NEWCGROUP) as u32;

const RET_KILL_PROCESS: u32 = libc::SECCOMP_RET_KILL_PROCESS;
const RET_ALLOW: u32 = libc::SECCOMP_RET_ALLOW;
const RET_EPERM: u32 = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
const RET_ENOSYS: u32 = libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32;

const LD_W_ABS: u16 = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
const JEQ: u16 = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
const JGE: u16 = (libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K) as u16;
const JSET: u16 = (libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K) as u16;
const RET: u16 = (libc::BPF_RET | libc::BPF_K) as u16;

/// Offsets into `struct seccomp_data`: the call, the architecture, and the low
/// word of the first two arguments.
const NR: u32 = 0;
const ARCH: u32 = 4;
const ARG0: u32 = 16;
const ARG1: u32 = 24;

fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

fn nr(call: libc::c_long) -> u32 {
    u32::try_from(call).unwrap_or(u32::MAX)
}

/// The filter program, one test per call so that no jump is longer than one
/// instruction past the return it guards.
#[must_use]
pub fn filter() -> Vec<libc::sock_filter> {
    let mut prog = vec![
        stmt(LD_W_ABS, ARCH),
        jump(JEQ, AUDIT_ARCH, 1, 0),
        stmt(RET, RET_KILL_PROCESS),
        stmt(LD_W_ABS, NR),
    ];
    // The x32 calls of an x86_64 kernel are the same calls under other numbers.
    #[cfg(target_arch = "x86_64")]
    prog.extend([jump(JGE, 0x4000_0000, 0, 1), stmt(RET, RET_KILL_PROCESS)]);
    for call in KILLED {
        prog.extend([jump(JEQ, nr(*call), 0, 1), stmt(RET, RET_KILL_PROCESS)]);
    }
    // `clone3` passes its flags behind a pointer the filter cannot read, so it
    // is answered as missing and the C library falls back to `clone`, whose
    // flags are the first argument.
    prog.extend([
        jump(JEQ, nr(libc::SYS_clone3), 0, 1),
        stmt(RET, RET_ENOSYS),
        jump(JEQ, nr(libc::SYS_clone), 0, 4),
        stmt(LD_W_ABS, ARG0),
        jump(JSET, CLONE_NAMESPACES, 0, 1),
        stmt(RET, RET_KILL_PROCESS),
        stmt(RET, RET_ALLOW),
        // `setns` into a network namespace only: a pod's or a process's,
        // for the capture and the attach that happen there.
        jump(JEQ, nr(libc::SYS_setns), 0, 4),
        stmt(LD_W_ABS, ARG1),
        jump(JEQ, libc::CLONE_NEWNET as u32, 0, 1),
        stmt(RET, RET_ALLOW),
        stmt(RET, RET_KILL_PROCESS),
    ]);
    for call in ALLOWED {
        prog.extend([jump(JEQ, nr(*call), 0, 1), stmt(RET, RET_ALLOW)]);
    }
    prog.push(stmt(RET, RET_EPERM));
    prog
}

fn seccomp() -> Result<(), String> {
    let mut prog = filter();
    let fprog = libc::sock_fprog {
        len: u16::try_from(prog.len()).map_err(|_| "seccomp filter too long".to_owned())?,
        filter: prog.as_mut_ptr(),
    };
    // SAFETY: `fprog` points at `prog`, live for the call; the kernel copies
    // the program before returning.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_TSYNC,
            &raw const fprog,
        )
    };
    if rc != 0 {
        return Err(format!("seccomp filter: {}", io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_call_is_both_killed_and_allowed() {
        for call in KILLED {
            assert!(!ALLOWED.contains(call), "{call}");
        }
        for guarded in [libc::SYS_clone, libc::SYS_clone3, libc::SYS_setns] {
            assert!(!ALLOWED.contains(&guarded) && !KILLED.contains(&guarded));
        }
    }

    #[test]
    fn the_filter_fits_the_kernels_limit() {
        // BPF_MAXINSNS for a classic filter.
        assert!(filter().len() <= 4096);
    }
}
