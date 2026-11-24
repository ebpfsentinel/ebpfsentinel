//! The warden confines itself before it serves.
//!
//! Once the privileged setup is done (the pcap pool and module BTF opened, the
//! listening socket bound), the warden has nothing left to gain from the
//! capabilities a container runtime or systemd gave it that it does not use
//! for an answer, so it takes two steps it cannot undo, in this order:
//!
//! 1. `PR_SET_NO_NEW_PRIVS`: no `execve` it could still make would raise a
//!    privilege. Kubernetes refuses `allowPrivilegeEscalation: false` beside
//!    `CAP_SYS_ADMIN`, so this is the line that holds in a pod.
//! 2. A seccomp filter: the system calls the broker makes are allowed, the
//!    ones that would change what the host runs or mounts kill the process,
//!    and any other answers `EPERM`. A thread may not create a namespace and
//!    `setns` enters a network namespace and nothing else.
//!
//! No Landlock domain: a task inside one may not reach the `/proc` entry of a
//! task outside it (the kernel applies its ptrace rule to the `exe` link, the
//! mappings and the descriptors), and every answer the warden gives about a
//! host process is read there. Writes are fenced by the read-only root the
//! compose file, the chart and the unit give it instead.
//!
//! An unknown call answers `EPERM` rather than killing so that a call this
//! list missed fails one request with an error the agent logs, instead of
//! taking every agent's datapath helper down. The calls that matter are named
//! and kill.

use std::io;

/// Confine the calling process, every thread of it included: no new
/// privileges, then the seccomp filter.
///
/// # Errors
///
/// `PR_SET_NO_NEW_PRIVS` or the seccomp filter was refused.
pub fn confine() -> Result<(), String> {
    no_new_privs()?;
    seccomp()
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
