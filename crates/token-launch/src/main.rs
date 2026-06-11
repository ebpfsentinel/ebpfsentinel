//! `ebpfsentinel-token-launch` — privileged launcher for rootless, token-only
//! eBPF loading.
//!
//! BPF token delegation is a *user-namespace* feature: `BPF_TOKEN_CREATE` only
//! succeeds against a bpffs whose superblock is owned by a user namespace the
//! caller is in. In the initial user namespace it returns `EOPNOTSUPP`, so a
//! token-only agent cannot run directly under systemd/Docker in the host user
//! namespace — it must run inside a child user namespace that owns the delegated
//! bpffs. This launcher sets that up, then execs the agent.
//!
//! 1. While still global root it enumerates every loaded module's BTF object,
//!    inherits an fd for each (cleared of `O_CLOEXEC`), and advertises them to
//!    the agent via `EBPF_MODULE_BTF_FDS=name=fd,...` — this is what lets module
//!    kfuncs (`nf_conntrack`, `fou`) resolve without `CAP_SYS_ADMIN` in the
//!    agent.
//! 2. It sets up the delegated bpffs via the kernel fd-passing dance: a CHILD
//!    unshares a user namespace and `fsopen("bpf")` (the superblock is owned by
//!    the child userns); it passes the fs fd to the (global-root) PARENT via
//!    `SCM_RIGHTS`; the parent applies `delegate_*=any` + `FSCONFIG_CMD_CREATE`
//!    (the steps that need global `CAP_SYS_ADMIN`); the child `fsmount`s +
//!    `move_mount`s it at the bpffs path.
//! 3. The child execs the agent inside the namespace with no global
//!    capabilities. The agent finds the delegated bpffs, creates a BPF token,
//!    and loads/attaches every program through it.
//!
//! Usage: `ebpfsentinel-token-launch [--bpffs <path>] <agent-binary> [args...]`
//!
//! The agent runs in a child user namespace and therefore has no capabilities
//! over host-owned resources (the host network namespace). The eBPF datapath
//! works through the token; host-netns helpers (pcap `AF_PACKET` capture,
//! `conntrack -D` retroactive teardown, gratuitous ARP on VIP takeover) degrade
//! gracefully — their eBPF equivalents keep working.

#![allow(unsafe_code)] // Raw mount/bpf/userns syscalls require libc + unsafe.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

use std::ffi::CString;
use std::mem;
use std::os::fd::RawFd;
use std::process::ExitCode;
use std::ptr;

// `bpf(2)` command numbers (uapi/linux/bpf.h `enum bpf_cmd`).
const BPF_OBJ_GET_INFO_BY_FD: libc::c_int = 15;
const BPF_BTF_GET_FD_BY_ID: libc::c_int = 19;
const BPF_BTF_GET_NEXT_ID: libc::c_int = 23;

// fsconfig(2) commands + move_mount(2) flag (uapi/linux/mount.h).
const FSCONFIG_SET_STRING: libc::c_uint = 1;
const FSCONFIG_CMD_CREATE: libc::c_uint = 6;
const MOVE_MOUNT_F_EMPTY_PATH: libc::c_uint = 0x4;

const DEFAULT_BPFFS: &str = "/sys/fs/bpf/ebpfsentinel";

/// `start_id` / `next_id` branch of `bpf_attr` (`*_GET_NEXT_ID`,
/// `*_GET_FD_BY_ID`). The first `u32` is the id; layout is identical for the
/// next-id and get-fd-by-id commands.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct BpfAttrId {
    id: u32,
    next_id: u32,
    open_flags: u32,
}

/// `info` branch of `bpf_attr` (`BPF_OBJ_GET_INFO_BY_FD`).
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct BpfAttrInfo {
    bpf_fd: u32,
    info_len: u32,
    info: u64,
}

/// Subset of `struct bpf_btf_info` — only the fields we read (`name`).
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct BpfBtfInfo {
    btf: u64,
    btf_size: u32,
    id: u32,
    name: u64,
    name_len: u32,
    kernel_btf: u32,
}

unsafe fn bpf(cmd: libc::c_int, attr: *mut libc::c_void, size: usize) -> libc::c_long {
    // SAFETY: caller passes a valid `bpf_attr` region of `size` bytes.
    unsafe { libc::syscall(libc::SYS_bpf, cmd, attr, size as libc::c_uint) }
}

/// Build `"name=fd,name=fd,..."` for every loaded module BTF. Opened here
/// (global root, before the userns fork) so the child inherits the fds across
/// `execv`.
fn collect_module_btf_fds() -> String {
    let mut out = String::new();
    let mut id: u32 = 0;
    loop {
        let mut next = BpfAttrId {
            id,
            ..Default::default()
        };
        let rc = unsafe {
            bpf(
                BPF_BTF_GET_NEXT_ID,
                ptr::from_mut(&mut next).cast(),
                mem::size_of::<BpfAttrId>(),
            )
        };
        if rc < 0 {
            break;
        }
        id = next.next_id;

        let mut fda = BpfAttrId {
            id,
            ..Default::default()
        };
        let fd = unsafe {
            bpf(
                BPF_BTF_GET_FD_BY_ID,
                ptr::from_mut(&mut fda).cast(),
                mem::size_of::<BpfAttrId>(),
            )
        };
        if fd < 0 {
            continue;
        }
        let fd = fd as RawFd;
        // BTF_GET_FD_BY_ID returns an O_CLOEXEC fd; clear it so the fd survives
        // the child's execv and reaches the agent at the same number.
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFD);
            libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
        }

        let mut name = [0u8; 64];
        let mut info = BpfBtfInfo {
            name: name.as_mut_ptr() as u64,
            name_len: name.len() as u32,
            ..Default::default()
        };
        let mut ia = BpfAttrInfo {
            bpf_fd: fd as u32,
            info_len: mem::size_of::<BpfBtfInfo>() as u32,
            info: ptr::from_mut(&mut info) as u64,
        };
        let rc = unsafe {
            bpf(
                BPF_OBJ_GET_INFO_BY_FD,
                ptr::from_mut(&mut ia).cast(),
                mem::size_of::<BpfAttrInfo>(),
            )
        };
        if rc < 0 {
            unsafe { libc::close(fd) };
            continue;
        }
        let nul = name.iter().position(|&b| b == 0).unwrap_or(name.len());
        let nm = String::from_utf8_lossy(&name[..nul]);
        // vmlinux base BTF has an empty name; modules carry theirs.
        if nm.is_empty() || nm == "vmlinux" {
            unsafe { libc::close(fd) };
            continue;
        }
        if !out.is_empty() {
            out.push(',');
        }
        out.push_str(&format!("{nm}={fd}"));
        // Keep fd open (inherited by the child); do NOT close.
    }
    out
}

/// Write `value` to the file at `path` (used for `setgroups` / `uid_map` /
/// `gid_map`). Returns `false` on error.
fn write_file(path: &str, value: &str) -> bool {
    std::fs::write(path, value).is_ok()
}

/// Send a single fd over a `SCM_RIGHTS` control message.
fn send_fd(sock: RawFd, fd: RawFd) -> bool {
    let mut iov_base = *b"x";
    let mut iov = libc::iovec {
        iov_base: iov_base.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut buf = [0u8; unsafe { libc::CMSG_SPACE(mem::size_of::<RawFd>() as u32) } as usize];
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = ptr::from_mut(&mut iov);
    msg.msg_iovlen = 1;
    msg.msg_control = buf.as_mut_ptr().cast();
    msg.msg_controllen = buf.len();
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(mem::size_of::<RawFd>() as u32) as _;
        ptr::copy_nonoverlapping(
            ptr::from_ref(&fd).cast(),
            libc::CMSG_DATA(cmsg),
            mem::size_of::<RawFd>(),
        );
        libc::sendmsg(sock, &msg, 0) >= 0
    }
}

/// Receive a single fd from a `SCM_RIGHTS` control message; `-1` on error.
fn recv_fd(sock: RawFd) -> RawFd {
    let mut m = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: m.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut buf = [0u8; unsafe { libc::CMSG_SPACE(mem::size_of::<RawFd>() as u32) } as usize];
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = ptr::from_mut(&mut iov);
    msg.msg_iovlen = 1;
    msg.msg_control = buf.as_mut_ptr().cast();
    msg.msg_controllen = buf.len();
    unsafe {
        if libc::recvmsg(sock, &mut msg, 0) < 0 {
            return -1;
        }
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return -1;
        }
        let mut fd: RawFd = -1;
        ptr::copy_nonoverlapping(
            libc::CMSG_DATA(cmsg),
            ptr::from_mut(&mut fd).cast(),
            mem::size_of::<RawFd>(),
        );
        fd
    }
}

/// Create every leading directory of `path` (like `mkdir -p`), ignoring errors.
fn mkdirs(path: &str) {
    let _ = std::fs::create_dir_all(path);
}

fn fsconfig_string(fs: RawFd, key: &str, value: &str) {
    let k = CString::new(key).unwrap();
    let v = CString::new(value).unwrap();
    unsafe {
        libc::syscall(
            libc::SYS_fsconfig,
            fs,
            FSCONFIG_SET_STRING,
            k.as_ptr(),
            v.as_ptr(),
            0,
        );
    }
}

fn child(bpffs: &str, agent_argv: &[CString], modfds: &str, sv1: RawFd) -> ! {
    unsafe {
        libc::setenv(
            c"EBPF_MODULE_BTF_FDS".as_ptr(),
            CString::new(modfds).unwrap().as_ptr(),
            1,
        )
    };
    let (uid, gid) = (unsafe { libc::getuid() }, unsafe { libc::getgid() });
    if unsafe { libc::unshare(libc::CLONE_NEWUSER) } != 0 {
        perror("unshare USER");
        std::process::exit(1);
    }
    write_file("/proc/self/setgroups", "deny");
    if !write_file("/proc/self/uid_map", &format!("0 {uid} 1"))
        || !write_file("/proc/self/gid_map", &format!("0 {gid} 1"))
    {
        eprintln!("[token-launch] failed to write uid/gid map");
        std::process::exit(1);
    }
    if unsafe { libc::setgid(0) } != 0 || unsafe { libc::setuid(0) } != 0 {
        perror("setid");
        std::process::exit(1);
    }
    if unsafe { libc::unshare(libc::CLONE_NEWNS) } != 0 {
        perror("unshare NS");
        std::process::exit(1);
    }
    let root = c"/";
    let none = c"none";
    unsafe {
        libc::mount(
            none.as_ptr(),
            root.as_ptr(),
            ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            ptr::null(),
        );
    }
    let bpf = c"bpf";
    let fs = unsafe { libc::syscall(libc::SYS_fsopen, bpf.as_ptr(), 0) } as RawFd;
    if fs < 0 {
        perror("fsopen(child)");
        std::process::exit(1);
    }
    if !send_fd(sv1, fs) {
        perror("send_fd");
        std::process::exit(1);
    }
    let mut ack = [0u8; 1];
    if unsafe { libc::read(sv1, ack.as_mut_ptr().cast(), 1) } != 1 || ack[0] != 1 {
        eprintln!("[token-launch] parent CMD_CREATE failed");
        std::process::exit(1);
    }
    let mnt = unsafe { libc::syscall(libc::SYS_fsmount, fs, 0, 0) } as RawFd;
    if mnt < 0 {
        perror("fsmount(child)");
        std::process::exit(1);
    }
    mkdirs(bpffs);
    let target = CString::new(bpffs).unwrap();
    let empty = c"";
    let rc = unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            mnt,
            empty.as_ptr(),
            libc::AT_FDCWD,
            target.as_ptr(),
            MOVE_MOUNT_F_EMPTY_PATH,
        )
    };
    if rc != 0 {
        perror("move_mount");
        std::process::exit(1);
    }
    let mut argv: Vec<*const libc::c_char> = agent_argv.iter().map(|a| a.as_ptr()).collect();
    argv.push(ptr::null());
    unsafe { libc::execv(agent_argv[0].as_ptr(), argv.as_ptr()) };
    perror("execv");
    std::process::exit(127);
}

fn perror(ctx: &str) {
    let e = std::io::Error::last_os_error();
    eprintln!("[token-launch] {ctx}: {e}");
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let mut bpffs = DEFAULT_BPFFS.to_string();
    let mut i = 1;
    while i < args.len() && args[i].starts_with("--") {
        if args[i] == "--bpffs" && i + 1 < args.len() {
            bpffs = args[i + 1].clone();
            i += 2;
        } else if args[i] == "--" {
            i += 1;
            break;
        } else {
            eprintln!("unknown option: {}", args[i]);
            return ExitCode::from(2);
        }
    }
    if i >= args.len() {
        eprintln!(
            "usage: ebpfsentinel-token-launch [--bpffs <path>] <agent-binary> [agent-args...]"
        );
        return ExitCode::from(2);
    }
    let agent_argv: Vec<CString> = args[i..]
        .iter()
        .map(|a| CString::new(a.as_str()).unwrap())
        .collect();

    // Open module BTF fds while still global root, before the userns fork.
    let modfds = collect_module_btf_fds();

    let mut sv = [0 as RawFd; 2];
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) } != 0 {
        perror("socketpair");
        return ExitCode::FAILURE;
    }
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe { libc::close(sv[0]) };
        child(&bpffs, &agent_argv, &modfds, sv[1]);
    }
    // PARENT: global root, configures delegation on the child's fs fd.
    unsafe { libc::close(sv[1]) };
    let fs = recv_fd(sv[0]);
    if fs < 0 {
        perror("recv_fd");
        return ExitCode::FAILURE;
    }
    fsconfig_string(fs, "delegate_cmds", "any");
    fsconfig_string(fs, "delegate_maps", "any");
    fsconfig_string(fs, "delegate_progs", "any");
    fsconfig_string(fs, "delegate_attachs", "any");
    let mut ack: u8 = 1;
    if unsafe {
        libc::syscall(
            libc::SYS_fsconfig,
            fs,
            FSCONFIG_CMD_CREATE,
            ptr::null::<libc::c_char>(),
            ptr::null::<libc::c_char>(),
            0,
        )
    } != 0
    {
        perror("CMD_CREATE(parent)");
        ack = 0;
    }
    unsafe { libc::write(sv[0], ptr::from_ref(&ack).cast(), 1) };
    let mut st: libc::c_int = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
    if libc::WIFEXITED(st) {
        ExitCode::from(libc::WEXITSTATUS(st) as u8)
    } else {
        ExitCode::FAILURE
    }
}
