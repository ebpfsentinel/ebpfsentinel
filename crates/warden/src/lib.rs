//! `ebpfsentinel-warden` — shared privileged primitives for the `warden`
//! control-plane broker and the rootless agent's self-bootstrap trampoline (see
//! [`userns_bootstrap`]).
//!
//! BPF token delegation is a *user-namespace* feature: `BPF_TOKEN_CREATE` only
//! succeeds against a bpffs whose superblock is owned by a user namespace the
//! caller is in. In the initial user namespace it returns `EOPNOTSUPP`, so a
//! token-only agent cannot load eBPF directly under systemd/Docker in the host
//! user namespace — it must run inside a child user namespace that owns the
//! delegated bpffs. The agent enters that namespace itself and asks the warden to
//! apply the `delegate_*` mount options (which need `CAP_SYS_ADMIN` in
//! `init_user_ns`) over the control socket.
//!
//! This library holds the syscall primitives both halves share:
//!
//! * [`collect_module_btf_fds`] / [`open_pcap_pool`] / [`prioritize_and_cap_btf`]
//!   — the warden opens these while privileged (BTF enumeration needs
//!   `CAP_SYS_ADMIN`, the `AF_PACKET` pool needs `CAP_NET_RAW`) and hands them to
//!   the agent on `Delegate`, so module kfuncs (`nf_conntrack`, `fou`) resolve and
//!   packet capture works without those capabilities in the agent.
//! * [`enter_userns`] / [`fsopen_bpf`] / [`mount_bpffs`] / [`delegate_over_fd`] +
//!   the `SCM_RIGHTS` helpers ([`send_fd`] / [`recv_fd`] / [`send_msg_fds`] /
//!   [`recv_msg_fds`]) — the bpffs delegation handshake: the agent `fsopen`s a
//!   bpffs in its own userns and sends the fs fd to the warden, which applies
//!   `delegate_*=any` + `FSCONFIG_CMD_CREATE`, then the agent `fsmount`s +
//!   `move_mount`s it and creates the token.
//!
//! The agent stays in the host network namespace, so the host-netns ops it cannot
//! perform from its user namespace (conntrack teardown, route programming,
//! gratuitous ARP, packet capture) are brokered by the warden over the same
//! socket — see [`server`] and [`host_ops`].

#![allow(unsafe_code)] // Raw mount/bpf/userns syscalls require libc + unsafe.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

use std::ffi::CString;
use std::mem;
use std::os::fd::RawFd;
use std::ptr;

pub mod host_ops;
pub mod net_ops;
pub mod server;
pub mod userns_bootstrap;

// `bpf(2)` command numbers (uapi/linux/bpf.h `enum bpf_cmd`).
const BPF_OBJ_GET_INFO_BY_FD: libc::c_int = 15;
const BPF_BTF_GET_FD_BY_ID: libc::c_int = 19;
const BPF_BTF_GET_NEXT_ID: libc::c_int = 23;

// fsconfig(2) commands + move_mount(2) flag (uapi/linux/mount.h).
const FSCONFIG_SET_STRING: libc::c_uint = 1;
const FSCONFIG_CMD_CREATE: libc::c_uint = 6;
const MOVE_MOUNT_F_EMPTY_PATH: libc::c_uint = 0x4;

const DEFAULT_BPFFS: &str = "/sys/fs/bpf/ebpfsentinel";

/// Unprivileged uid/gid the agent drops to before creating its user namespace
/// under a container runtime. `enter_userns` writes a single-entry self-map
/// (`0 <uid> 1`); the kernel refuses to map namespace-uid 0 to the *real* root
/// (uid 0) unless the writer is privileged over the parent user namespace
/// (`verify_root_map`, anti-escalation). Under a stock container runtime the pod
/// runs in the init user namespace (e.g. containerd on Talos/Kubernetes), so a
/// global-root process cannot self-map. Dropping to a non-root id first makes the
/// map target non-root, which is permitted. The agent needs no init-ns
/// capabilities: the warden performs the bpffs delegation and opens the
/// pcap/module-BTF fds, handing them over the control socket. The agent then runs
/// as this host id (namespace-root), so deployments make its config
/// group-readable via fsGroup.
const UNPRIV_UID: libc::uid_t = 65534;
const UNPRIV_GID: libc::gid_t = 65534;

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

/// Collect `(module_name, fd)` for every loaded module BTF. Opened by the warden
/// while it holds `CAP_SYS_ADMIN`, then passed to the agent over `SCM_RIGHTS` (the
/// `serve_loop` delegation handshake) so module kfuncs resolve in the agent's
/// token-only load.
pub fn collect_module_btf_fds() -> Vec<(String, RawFd)> {
    let mut out: Vec<(String, RawFd)> = Vec::new();
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
        // BTF_GET_FD_BY_ID returns an O_CLOEXEC fd; clear it so the fd can be
        // passed to the agent over SCM_RIGHTS on delegation.
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
        out.push((nm.into_owned(), fd));
        // Keep fd open (passed to the agent over delegation); do NOT close.
    }
    out
}

/// Default number of `AF_PACKET` capture sockets to pre-open.
const DEFAULT_PCAP_POOL: usize = 2;

/// Open a small pool of `AF_PACKET`/`SOCK_RAW` sockets for rootless packet
/// capture and return their fds.
///
/// Opened by the warden because the agent, once inside its child user namespace,
/// fails the `CAP_NET_RAW` check on `socket(AF_PACKET)`. Protocol `0` keeps the
/// sockets silent until the agent binds one to an interface with `ETH_P_ALL`. The
/// fds are cleared of `O_CLOEXEC` so they can be passed to the agent over
/// delegation. Pool size is `EBPFSENTINEL_PCAP_POOL` (default `DEFAULT_PCAP_POOL`,
/// capped 32).
pub fn open_pcap_pool() -> Vec<RawFd> {
    let n = std::env::var("EBPFSENTINEL_PCAP_POOL")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 0 && n <= 32)
        .unwrap_or(DEFAULT_PCAP_POOL);
    let mut out: Vec<RawFd> = Vec::new();
    for _ in 0..n {
        let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, 0) };
        if fd < 0 {
            // No CAP_NET_RAW (or AF_PACKET unavailable): leave capture
            // unprovisioned — the agent degrades gracefully.
            perror("socket(AF_PACKET) for pcap pool");
            break;
        }
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFD);
            libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
        }
        out.push(fd);
        // Keep fd open (passed to the agent over delegation); do NOT close.
    }
    out
}

/// Write `value` to the file at `path` (used for `setgroups` / `uid_map` /
/// `gid_map`). Returns `false` on error.
fn write_file(path: &str, value: &str) -> bool {
    match std::fs::write(path, value) {
        Ok(()) => true,
        Err(e) => {
            eprintln!("[warden] write {path}: {e}");
            false
        }
    }
}

/// Send a single fd over a `SCM_RIGHTS` control message.
pub fn send_fd(sock: RawFd, fd: RawFd) -> bool {
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
    msg.msg_controllen = buf.len() as _;
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
pub fn recv_fd(sock: RawFd) -> RawFd {
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
    msg.msg_controllen = buf.len() as _;
    unsafe {
        if libc::recvmsg(sock, &mut msg, 0) < 0 {
            return -1;
        }
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return -1;
        }
        // Defensively confirm this is an SCM_RIGHTS message carrying at least one
        // fd before reading fd-sized bytes out of the control buffer.
        if (*cmsg).cmsg_level != libc::SOL_SOCKET
            || (*cmsg).cmsg_type != libc::SCM_RIGHTS
            || ((*cmsg).cmsg_len as usize) < libc::CMSG_LEN(mem::size_of::<RawFd>() as u32) as usize
        {
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

/// Receive up to `max_fds` fds from a single `SCM_RIGHTS` control message (plus
/// one sentinel payload byte). Returns the received fds, each cleared of
/// `O_CLOEXEC` so they survive the agent trampoline's `execv` into normal
/// startup. The agent uses this to collect the module-BTF + pcap fds the warden
/// sends after a `Delegate`.
pub fn recv_msg_fds(sock: RawFd, max_fds: usize) -> Vec<RawFd> {
    let mut payload = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let cap_bytes = max_fds * mem::size_of::<RawFd>();
    let mut cbuf = vec![0u8; unsafe { libc::CMSG_SPACE(cap_bytes as u32) } as usize];
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = ptr::from_mut(&mut iov);
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr().cast();
    msg.msg_controllen = cbuf.len() as _;
    let mut out: Vec<RawFd> = Vec::new();
    unsafe {
        if libc::recvmsg(sock, &mut msg, 0) < 0 {
            perror("recvmsg fds");
            return out;
        }
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let data_len = (*cmsg).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                let n = data_len / mem::size_of::<RawFd>();
                let mut fds = vec![-1 as RawFd; n];
                ptr::copy_nonoverlapping(libc::CMSG_DATA(cmsg), fds.as_mut_ptr().cast(), data_len);
                for fd in fds {
                    let flags = libc::fcntl(fd, libc::F_GETFD);
                    libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
                    out.push(fd);
                }
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }
    out
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

/// Apply `delegate_*=any` + `FSCONFIG_CMD_CREATE` to a bpffs `fs_fd` whose
/// superblock is owned by a (descendant) user namespace. Requires `CAP_SYS_ADMIN`
/// in `init_user_ns` — done by the all-in-one parent or the bare-metal `warden
/// serve`. Returns `true` on success.
pub fn delegate_over_fd(fs: RawFd) -> bool {
    fsconfig_string(fs, "delegate_cmds", "any");
    fsconfig_string(fs, "delegate_maps", "any");
    fsconfig_string(fs, "delegate_progs", "any");
    fsconfig_string(fs, "delegate_attachs", "any");
    let rc = unsafe {
        libc::syscall(
            libc::SYS_fsconfig,
            fs,
            FSCONFIG_CMD_CREATE,
            ptr::null::<libc::c_char>(),
            ptr::null::<libc::c_char>(),
            0,
        )
    };
    if rc != 0 {
        perror("FSCONFIG_CMD_CREATE");
        return false;
    }
    true
}

/// Probe, in a throwaway fork, whether this process may map namespace-uid 0 to
/// the *real* root (uid 0) in a fresh user namespace. True for a global-root
/// process on a real host; false for a container running in the init user
/// namespace, where the kernel's `verify_root_map` forbids mapping to real root
/// unless privileged over the parent userns (e.g. containerd on Talos/Kubernetes).
/// The probe runs in a child process so its namespace work never affects the
/// caller.
fn root_userns_self_map_ok() -> bool {
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        if unsafe { libc::unshare(libc::CLONE_NEWUSER) } != 0 {
            unsafe { libc::_exit(1) };
        }
        let _ = std::fs::write("/proc/self/setgroups", "deny");
        let ok = std::fs::write("/proc/self/uid_map", "0 0 1").is_ok();
        unsafe { libc::_exit(i32::from(!ok)) };
    }
    if pid < 0 {
        return false;
    }
    let mut st: libc::c_int = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
    libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0
}

/// The uid the agent's bootstrap will present to the warden over `SO_PEERCRED`,
/// so the combined-unit supervisor can pass the matching `warden serve --uid`.
/// Mirrors [`drop_to_unpriv_if_needed`]: a global-root process that may self-map
/// stays root (presents uid 0); one that may not drops to [`UNPRIV_UID`]; an
/// already-unprivileged process presents its own uid.
#[must_use]
pub fn expected_agent_peer_uid() -> u32 {
    let uid = unsafe { libc::getuid() };
    if uid == 0 {
        if root_userns_self_map_ok() {
            0
        } else {
            UNPRIV_UID
        }
    } else {
        uid
    }
}

/// Drop to an unprivileged uid before creating a user namespace, but only when
/// running as global root under a runtime that forbids the root self-map.
///
/// Under a stock container runtime the pod runs in the init user namespace,
/// where a global-root process cannot self-map namespace-0 to real root
/// (`verify_root_map`). Detect that and drop to a non-root id first so the
/// self-map targets a non-root uid (see [`UNPRIV_UID`]). On a real host running
/// as global root the root self-map is permitted, so keep uid 0 (the process
/// then runs as host root, preserving the systemd/bare-metal behaviour). No-op
/// if already running unprivileged. Exits the process on failure.
pub fn drop_to_unpriv_if_needed() {
    if unsafe { libc::getuid() } == 0 && !root_userns_self_map_ok() {
        unsafe { libc::setgroups(0, ptr::null()) };
        if unsafe { libc::setgid(UNPRIV_GID) } != 0 || unsafe { libc::setuid(UNPRIV_UID) } != 0 {
            perror("drop to unprivileged uid before userns");
            std::process::exit(1);
        }
        // Dropping the real uid clears the dumpable flag, which reparents
        // /proc/self/{setgroups,uid_map,gid_map} to root and makes them
        // unwritable by the now-unprivileged process (EACCES). Restore dumpable
        // so enter_userns() can write its id maps.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) } != 0 {
            perror("PR_SET_DUMPABLE");
            std::process::exit(1);
        }
    }
}

/// Enter a fresh user namespace (single-uid self-map) and a private mount
/// namespace. Used by the agent self-bootstrap trampoline; exits the process on
/// failure. Must run single-threaded (before any runtime).
pub fn enter_userns() {
    let (uid, gid) = (unsafe { libc::getuid() }, unsafe { libc::getgid() });
    if unsafe { libc::unshare(libc::CLONE_NEWUSER) } != 0 {
        perror("unshare USER");
        std::process::exit(1);
    }
    write_file("/proc/self/setgroups", "deny");
    if !write_file("/proc/self/uid_map", &format!("0 {uid} 1"))
        || !write_file("/proc/self/gid_map", &format!("0 {gid} 1"))
    {
        eprintln!("[warden] failed to write uid/gid map");
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
    unsafe {
        libc::mount(
            c"none".as_ptr(),
            c"/".as_ptr(),
            ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            ptr::null(),
        );
    }
}

/// `fsopen("bpf")` in the current user namespace; exits on failure.
pub fn fsopen_bpf() -> RawFd {
    let fs = unsafe { libc::syscall(libc::SYS_fsopen, c"bpf".as_ptr(), 0) } as RawFd;
    if fs < 0 {
        perror("fsopen");
        std::process::exit(1);
    }
    fs
}

/// `fsmount` the (delegated) bpffs `fs_fd` and `move_mount` it at `bpffs`.
/// Exits the process on failure. Used by the agent self-bootstrap trampoline.
pub fn mount_bpffs(fs: RawFd, bpffs: &str) {
    let mnt = unsafe { libc::syscall(libc::SYS_fsmount, fs, 0, 0) } as RawFd;
    if mnt < 0 {
        perror("fsmount");
        std::process::exit(1);
    }
    mkdirs(bpffs);
    let target = CString::new(bpffs).unwrap();
    let rc = unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            mnt,
            c"".as_ptr(),
            libc::AT_FDCWD,
            target.as_ptr(),
            MOVE_MOUNT_F_EMPTY_PATH,
        )
    };
    if rc != 0 {
        perror("move_mount");
        std::process::exit(1);
    }
}

pub fn perror(ctx: &str) {
    let e = std::io::Error::last_os_error();
    eprintln!("[warden] {ctx}: {e}");
}

// ── fd passing over SCM_RIGHTS ──────────────────────────────────────────────
//
// The `serve_loop` delegation handshake (`Command::Delegate`) passes the
// module-BTF and pcap fds from the privileged warden to the rootless agent over
// the control socket, using the `SCM_RIGHTS` primitives below.

/// `SCM_RIGHTS` cannot carry more than `SCM_MAX_FD` (253) fds per message.
const SCM_MAX_FDS: usize = 253;
/// Modules whose BTF the eBPF programs need (conntrack/fou kfuncs) — kept at the
/// front of the fd set so a cap never drops them.
const NEEDED_MODULE_BTF: &[&str] = &["nf_conntrack", "fou"];

/// Send `payload` bytes plus `fds` over one `SCM_RIGHTS` control message.
pub fn send_msg_fds(sock: RawFd, payload: &[u8], fds: &[RawFd]) -> bool {
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    };
    let fd_bytes = std::mem::size_of_val(fds);
    let mut cbuf = vec![0u8; unsafe { libc::CMSG_SPACE(fd_bytes as u32) } as usize];
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = ptr::from_mut(&mut iov);
    msg.msg_iovlen = 1;
    if !fds.is_empty() {
        msg.msg_control = cbuf.as_mut_ptr().cast();
        msg.msg_controllen = cbuf.len() as _;
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(fd_bytes as u32) as _;
            ptr::copy_nonoverlapping(fds.as_ptr().cast(), libc::CMSG_DATA(cmsg), fd_bytes);
        }
    }
    unsafe { libc::sendmsg(sock, &msg, 0) >= 0 }
}

/// Keep needed-module BTF fds at the front and cap the set so a single
/// `SCM_RIGHTS` message (plus the pcap fds) stays under `SCM_MAX_FDS`.
pub fn prioritize_and_cap_btf(
    mut btf: Vec<(String, RawFd)>,
    pcap_count: usize,
) -> Vec<(String, RawFd)> {
    btf.sort_by_key(|(n, _)| !NEEDED_MODULE_BTF.contains(&n.as_str()));
    let cap = SCM_MAX_FDS.saturating_sub(pcap_count).saturating_sub(1);
    if btf.len() > cap {
        eprintln!(
            "[warden] {} module BTF fds exceed the SCM_RIGHTS cap; passing {} (needed modules kept)",
            btf.len(),
            cap
        );
        for (_, fd) in btf.drain(cap..) {
            unsafe { libc::close(fd) };
        }
    }
    btf
}

/// Enable kernel SYN cookies in always-on mode (`net.ipv4.tcp_syncookies=2`)
/// from the privileged warden.
///
/// The XDP syncookie offload issues kernel cookies via
/// `bpf_tcp_raw_gen_syncookie`; the kernel only completes a legitimate
/// client's handshake from the passed cookie-ACK when it always validates
/// syncookies. Mode 1 engages only on SYN-backlog overflow, which never
/// happens because XDP absorbs the flood SYNs — so mode 2 is required. The
/// agent cannot set this itself once it is inside the child user namespace,
/// which lacks host-netns `CAP_NET_ADMIN`.
pub fn enable_tcp_syncookies() {
    match std::fs::write("/proc/sys/net/ipv4/tcp_syncookies", "2\n") {
        Ok(()) => eprintln!("[launch] net.ipv4.tcp_syncookies=2 (SYN-cookie handshake completion)"),
        Err(e) => eprintln!("[launch] WARN could not set net.ipv4.tcp_syncookies=2: {e}"),
    }
}
