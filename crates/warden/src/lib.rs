//! `ebpfsentinel-warden` — shared privileged primitives for rootless, token-only
//! eBPF loading, backing both the `warden-token` launcher binary
//! (all-in-one / broker-serve / broker-connect modes, via [`run`]) and the
//! `warden` control-plane binary.
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
//!    agent. It likewise opens a small pool of `AF_PACKET` sockets and advertises
//!    them via `EBPFSENTINEL_PCAP_FDS=fd,...` so the agent can run packet capture
//!    rootless — `CAP_NET_RAW` is checked only at `socket()`, which happens here.
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
//! Usage: `warden-token [--bpffs <path>] <agent-binary> [args...]`
//!
//! The agent runs in a child user namespace and therefore has no capabilities
//! over host-owned resources (the host network namespace). The eBPF datapath
//! works through the token, and pcap capture works through the pre-opened
//! `AF_PACKET` sockets above. The remaining host-netns helpers (`conntrack -D`
//! retroactive teardown, gratuitous ARP on VIP takeover) degrade gracefully —
//! their cap check is re-evaluated per operation, so a pre-opened fd cannot
//! delegate them; their eBPF equivalents keep working.

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

pub mod map_engine;
pub mod net_ops;
pub mod server;

// `bpf(2)` command numbers (uapi/linux/bpf.h `enum bpf_cmd`).
const BPF_OBJ_GET_INFO_BY_FD: libc::c_int = 15;
const BPF_BTF_GET_FD_BY_ID: libc::c_int = 19;
const BPF_BTF_GET_NEXT_ID: libc::c_int = 23;

// fsconfig(2) commands + move_mount(2) flag (uapi/linux/mount.h).
const FSCONFIG_SET_STRING: libc::c_uint = 1;
const FSCONFIG_CMD_CREATE: libc::c_uint = 6;
const MOVE_MOUNT_F_EMPTY_PATH: libc::c_uint = 0x4;

const DEFAULT_BPFFS: &str = "/sys/fs/bpf/ebpfsentinel";

/// Unprivileged uid/gid the all-in-one child drops to before creating its user
/// namespace. `enter_userns` writes a single-entry self-map (`0 <uid> 1`); the
/// kernel refuses to map namespace-uid 0 to the *real* root (uid 0) unless the
/// writer is privileged over the parent user namespace (`verify_root_map`,
/// anti-escalation). Under a stock container runtime the pod runs in the init
/// user namespace (e.g. containerd on Talos/Kubernetes), so a global-root child
/// cannot self-map. Dropping to a non-root id first makes the map target
/// non-root, which is permitted. The child needs no init-ns capabilities: the
/// parent performs the bpffs delegation and the pcap/module-BTF fds are already
/// open and inherited across the fork. The agent then runs as this host id
/// (namespace-root), so deployments make its config group-readable via fsGroup.
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

/// Collect `(module_name, fd)` for every loaded module BTF. Opened here (global
/// root, before the userns fork / while the broker holds `CAP_SYS_ADMIN`) so the
/// fds can be inherited across `execv` (all-in-one) or passed over `SCM_RIGHTS`
/// (broker). Format with [`fmt_btf_env`] for the `EBPF_MODULE_BTF_FDS` env var.
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
        out.push((nm.into_owned(), fd));
        // Keep fd open (inherited by the child / passed by the broker); do NOT close.
    }
    out
}

/// Format `(name, fd)` pairs as the `EBPF_MODULE_BTF_FDS` env value the agent
/// parses: `"name=fd,name=fd,..."`.
fn fmt_btf_env(btf: &[(String, RawFd)]) -> String {
    btf.iter()
        .map(|(n, fd)| format!("{n}={fd}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// Format pcap socket fds as the `EBPFSENTINEL_PCAP_FDS` env value: `"fd,fd"`.
fn fmt_pcap_env(pcap: &[RawFd]) -> String {
    pcap.iter()
        .map(RawFd::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// Default number of `AF_PACKET` capture sockets to pre-open.
const DEFAULT_PCAP_POOL: usize = 2;

/// Open a small pool of `AF_PACKET`/`SOCK_RAW` sockets for rootless packet
/// capture and return their fds as `"fd,fd,..."`.
///
/// Created here (global root, before the userns fork) because the agent, once
/// inside its child user namespace, fails the `CAP_NET_RAW` check on
/// `socket(AF_PACKET)`. Protocol `0` keeps the sockets silent until the agent
/// binds one to an interface with `ETH_P_ALL`. The fds are cleared of
/// `O_CLOEXEC` so they survive the child's `execv` / can be passed by the broker.
/// Pool size is `EBPFSENTINEL_PCAP_POOL` (default `DEFAULT_PCAP_POOL`, capped 32).
/// Format with [`fmt_pcap_env`] for the `EBPFSENTINEL_PCAP_FDS` env var.
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
        // Keep fd open (inherited by the child / passed by the broker); do NOT close.
    }
    out
}

/// Write `value` to the file at `path` (used for `setgroups` / `uid_map` /
/// `gid_map`). Returns `false` on error.
fn write_file(path: &str, value: &str) -> bool {
    match std::fs::write(path, value) {
        Ok(()) => true,
        Err(e) => {
            eprintln!("[warden-token] write {path}: {e}");
            false
        }
    }
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
/// in `init_user_ns` — done by the all-in-one parent or the broker. Returns
/// `true` on success. Shared by the all-in-one fork path and the broker.
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

fn child(bpffs: &str, agent_argv: &[CString], modfds: &str, pcapfds: &str, sv1: RawFd) -> ! {
    unsafe {
        libc::setenv(
            c"EBPF_MODULE_BTF_FDS".as_ptr(),
            CString::new(modfds).unwrap().as_ptr(),
            1,
        )
    };
    if !pcapfds.is_empty() {
        unsafe {
            libc::setenv(
                c"EBPFSENTINEL_PCAP_FDS".as_ptr(),
                CString::new(pcapfds).unwrap().as_ptr(),
                1,
            )
        };
    }
    // Under a stock container runtime the pod runs in the init user namespace,
    // where a global-root child cannot self-map namespace-0 to real root
    // (verify_root_map). Detect that and drop to a non-root id first so the
    // self-map targets a non-root uid (see UNPRIV_UID). On a real host running
    // as global root the root self-map is permitted, so keep uid 0 (the agent
    // then runs as host root, preserving the systemd/bare-metal behaviour). No-op
    // if the container already runs unprivileged.
    if unsafe { libc::getuid() } == 0 && !root_userns_self_map_ok() {
        unsafe { libc::setgroups(0, ptr::null()) };
        if unsafe { libc::setgid(UNPRIV_GID) } != 0 || unsafe { libc::setuid(UNPRIV_UID) } != 0 {
            perror("drop to unprivileged uid before userns");
            std::process::exit(1);
        }
        // Dropping the real uid clears the dumpable flag, which reparents
        // /proc/self/{setgroups,uid_map,gid_map} to root and makes them
        // unwritable by the now-unprivileged child (EACCES). Restore dumpable so
        // enter_userns() can write its id maps.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) } != 0 {
            perror("PR_SET_DUMPABLE");
            std::process::exit(1);
        }
    }
    enter_userns();
    let fs = fsopen_bpf();
    if !send_fd(sv1, fs) {
        perror("send_fd");
        std::process::exit(1);
    }
    let mut ack = [0u8; 1];
    if unsafe { libc::read(sv1, ack.as_mut_ptr().cast(), 1) } != 1 || ack[0] != 1 {
        eprintln!("[warden-token] parent CMD_CREATE failed");
        std::process::exit(1);
    }
    mount_and_exec(fs, bpffs, agent_argv);
}

/// Enter a fresh user namespace (single-uid self-map) and a private mount
/// namespace. Shared by the all-in-one fork child and the broker-connect shim;
/// exits the process on failure. Must run single-threaded (before any runtime).
fn enter_userns() {
    let (uid, gid) = (unsafe { libc::getuid() }, unsafe { libc::getgid() });
    if unsafe { libc::unshare(libc::CLONE_NEWUSER) } != 0 {
        perror("unshare USER");
        std::process::exit(1);
    }
    write_file("/proc/self/setgroups", "deny");
    if !write_file("/proc/self/uid_map", &format!("0 {uid} 1"))
        || !write_file("/proc/self/gid_map", &format!("0 {gid} 1"))
    {
        eprintln!("[warden-token] failed to write uid/gid map");
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
fn fsopen_bpf() -> RawFd {
    let fs = unsafe { libc::syscall(libc::SYS_fsopen, c"bpf".as_ptr(), 0) } as RawFd;
    if fs < 0 {
        perror("fsopen");
        std::process::exit(1);
    }
    fs
}

/// `fsmount` the (delegated) bpffs `fs_fd` and `move_mount` it at `bpffs`, then
/// `execv` the agent inside this namespace. Never returns. Shared by both modes.
fn mount_and_exec(fs: RawFd, bpffs: &str, agent_argv: &[CString]) -> ! {
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
    let mut argv: Vec<*const libc::c_char> = agent_argv.iter().map(|a| a.as_ptr()).collect();
    argv.push(ptr::null());
    unsafe { libc::execv(agent_argv[0].as_ptr(), argv.as_ptr()) };
    perror("execv");
    std::process::exit(127);
}

pub fn perror(ctx: &str) {
    let e = std::io::Error::last_os_error();
    eprintln!("[warden-token] {ctx}: {e}");
}

// ── Broker mode: protocol + fd passing ─────────────────────────────────────
//
// In split deployments the privileged delegation lives in a separate `broker`
// process/container; the unprivileged agent container connects over an AF_UNIX
// socket. The agent sends its own bpffs `fs_fd`; the broker delegates it and
// replies with the module-BTF and pcap fds the agent would otherwise need
// `CAP_SYS_ADMIN` / `CAP_NET_RAW` to open. This relocates the privilege into the
// small broker — the agent runs cap-less.

/// Reply header magic (`ebpfsentinel token broker v1`).
const PROTO_MAGIC: [u8; 4] = *b"ETB1";

/// First byte a client writes on a broker connection, selecting the request.
/// `CMD_DELEGATE` runs the bpffs-delegation + fd-handout handshake; `CMD_CONNTRACK`
/// asks the (host-userns, privileged) broker to read the conntrack table on the
/// non-root agent's behalf — the agent cannot read the `0440 root` proc file from
/// its child user namespace.
const CMD_DELEGATE: u8 = b'D';
const CMD_CONNTRACK: u8 = b'C';
/// Kernel conntrack table the broker reads for `CMD_CONNTRACK`.
const NF_CONNTRACK_PROC: &str = "/proc/net/nf_conntrack";

/// Write the whole buffer to `fd`, looping over short writes. Returns `false` on
/// error.
fn write_all_fd(fd: RawFd, mut buf: &[u8]) -> bool {
    while !buf.is_empty() {
        let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if n <= 0 {
            return false;
        }
        buf = &buf[n as usize..];
    }
    true
}

/// Serve a `CMD_CONNTRACK` request: read `/proc/net/nf_conntrack` (the broker is
/// real root in the host network namespace) and reply with a little-endian `u32`
/// length followed by the raw table bytes. The agent parses them exactly as if it
/// had read the file itself.
fn broker_serve_conntrack(conn: RawFd) {
    let data = std::fs::read(NF_CONNTRACK_PROC).unwrap_or_default();
    let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
    write_all_fd(conn, &len.to_le_bytes());
    write_all_fd(conn, &data[..len as usize]);
}
/// `SCM_RIGHTS` cannot carry more than `SCM_MAX_FD` (253) fds per message.
const SCM_MAX_FDS: usize = 253;
/// Modules whose BTF the eBPF programs need (conntrack/fou kfuncs) — kept at the
/// front of the fd set so a cap never drops them.
const NEEDED_MODULE_BTF: &[&str] = &["nf_conntrack", "fou"];

/// Encode the broker→agent reply header: status + module-BTF names + pcap count.
/// The fds themselves travel in the `SCM_RIGHTS` cmsg, ordered btf-then-pcap.
fn encode_reply(ok: bool, btf_names: &[&str], pcap_count: usize) -> Vec<u8> {
    let mut p = Vec::with_capacity(9 + btf_names.iter().map(|n| 1 + n.len()).sum::<usize>());
    p.extend_from_slice(&PROTO_MAGIC);
    p.push(u8::from(ok));
    p.extend_from_slice(
        &u16::try_from(btf_names.len())
            .unwrap_or(u16::MAX)
            .to_le_bytes(),
    );
    p.extend_from_slice(&u16::try_from(pcap_count).unwrap_or(u16::MAX).to_le_bytes());
    for n in btf_names {
        let bytes = n.as_bytes();
        let len = bytes.len().min(255);
        p.push(u8::try_from(len).unwrap_or(255));
        p.extend_from_slice(&bytes[..len]);
    }
    p
}

/// Decode the reply header. Returns `(ok, btf_names, pcap_count)`.
fn decode_reply(buf: &[u8]) -> Option<(bool, Vec<String>, usize)> {
    if buf.len() < 9 || buf[0..4] != PROTO_MAGIC {
        return None;
    }
    let ok = buf[4] != 0;
    let btf_count = u16::from_le_bytes([buf[5], buf[6]]) as usize;
    let pcap_count = u16::from_le_bytes([buf[7], buf[8]]) as usize;
    let mut off = 9;
    let mut names = Vec::with_capacity(btf_count);
    for _ in 0..btf_count {
        let len = *buf.get(off)? as usize;
        off += 1;
        let end = off.checked_add(len)?;
        names.push(String::from_utf8_lossy(buf.get(off..end)?).into_owned());
        off = end;
    }
    Some((ok, names, pcap_count))
}

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

/// Receive up to `buf.len()` payload bytes plus up to `max_fds` fds.
/// Returns `(payload_len, fds)`; `(0, [])` on error.
pub fn recv_msg_fds(sock: RawFd, buf: &mut [u8], max_fds: usize) -> (usize, Vec<RawFd>) {
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    let mut cbuf =
        vec![0u8; unsafe { libc::CMSG_SPACE((max_fds * mem::size_of::<RawFd>()) as u32) } as usize];
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = ptr::from_mut(&mut iov);
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr().cast();
    msg.msg_controllen = cbuf.len() as _;
    let n = unsafe { libc::recvmsg(sock, &mut msg, 0) };
    if n < 0 {
        return (0, Vec::new());
    }
    // A truncated control buffer means the kernel silently dropped fds; treat it
    // as an error rather than acting on a partial, attacker-influenced fd set.
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        return (0, Vec::new());
    }
    let mut fds = Vec::new();
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let hdr = libc::CMSG_LEN(0) as usize;
                let data_len = (*cmsg).cmsg_len as usize - hdr;
                let count = data_len / mem::size_of::<RawFd>();
                let mut tmp = vec![0 as RawFd; count];
                ptr::copy_nonoverlapping(libc::CMSG_DATA(cmsg), tmp.as_mut_ptr().cast(), data_len);
                fds.extend_from_slice(&tmp);
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }
    (n as usize, fds)
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
            "[broker] {} module BTF fds exceed the SCM_RIGHTS cap; passing {} (needed modules kept)",
            btf.len(),
            cap
        );
        for (_, fd) in btf.drain(cap..) {
            unsafe { libc::close(fd) };
        }
    }
    btf
}

fn bind_listen_unix(sockpath: &str) -> RawFd {
    let _ = std::fs::remove_file(sockpath);
    let s = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if s < 0 {
        perror("socket(AF_UNIX)");
        return -1;
    }
    let mut sa: libc::sockaddr_un = unsafe { mem::zeroed() };
    sa.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (dst, b) in sa.sun_path.iter_mut().zip(sockpath.bytes()) {
        *dst = b as libc::c_char;
    }
    let len = mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
    if unsafe { libc::bind(s, ptr::from_ref(&sa).cast(), len) } != 0 {
        perror("bind");
        return -1;
    }
    if let Ok(cpath) = CString::new(sockpath) {
        unsafe { libc::chmod(cpath.as_ptr(), 0o666) };
    }
    if unsafe { libc::listen(s, 8) } != 0 {
        perror("listen");
        return -1;
    }
    s
}

/// Serve one agent connection: receive its bpffs `fs_fd`, delegate it, and reply
/// with the module-BTF + pcap fds (broker keeps its originals open for the next
/// agent / restart).
fn broker_handle_conn(conn: RawFd, btf: &[(String, RawFd)], pcap: &[RawFd]) {
    let fs = recv_fd(conn);
    if fs < 0 {
        let payload = encode_reply(false, &[], 0);
        send_msg_fds(conn, &payload, &[]);
        return;
    }
    let ok = delegate_over_fd(fs);
    let names: Vec<&str> = btf.iter().map(|(n, _)| n.as_str()).collect();
    let payload = encode_reply(ok, &names, pcap.len());
    if ok {
        let mut fds: Vec<RawFd> = btf.iter().map(|(_, fd)| *fd).collect();
        fds.extend_from_slice(pcap);
        send_msg_fds(conn, &payload, &fds);
    } else {
        send_msg_fds(conn, &payload, &[]);
    }
    unsafe { libc::close(fs) };
}

/// Enable kernel SYN cookies in always-on mode (`net.ipv4.tcp_syncookies=2`)
/// from the privileged launcher, before any user-namespace unshare.
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

/// `--broker-serve <sock>`: the privileged sidecar. Opens module BTF + the pcap
/// pool once, then serves agent connections forever.
fn run_broker_serve(sockpath: &str) -> ExitCode {
    enable_tcp_syncookies();
    let btf = prioritize_and_cap_btf(collect_module_btf_fds(), 0);
    let pcap = open_pcap_pool();
    let s = bind_listen_unix(sockpath);
    if s < 0 {
        return ExitCode::FAILURE;
    }
    eprintln!(
        "[broker] serving on {sockpath} ({} module BTF fds, {} pcap fds, uid={})",
        btf.len(),
        pcap.len(),
        unsafe { libc::getuid() }
    );
    loop {
        let c = unsafe { libc::accept(s, ptr::null_mut(), ptr::null_mut()) };
        if c < 0 {
            perror("accept");
            continue;
        }
        // First byte selects the request: delegation handshake or a conntrack
        // table read on behalf of the non-root agent.
        let mut cmd = [0u8; 1];
        if unsafe { libc::read(c, cmd.as_mut_ptr().cast(), 1) } == 1 {
            match cmd[0] {
                CMD_DELEGATE => broker_handle_conn(c, &btf, &pcap),
                CMD_CONNTRACK => broker_serve_conntrack(c),
                other => eprintln!("[broker] unknown command byte {other:#x}"),
            }
        }
        unsafe { libc::close(c) };
    }
}

/// `--broker-connect <sock>`: the UNPRIVILEGED agent-container entrypoint.
/// Creates its own user namespace, `fsopen`s a bpffs, has the broker delegate it
/// over `sock`, receives the module-BTF + pcap fds, sets the env the agent reads,
/// then execs the agent. Holds no `CAP_SYS_ADMIN` / `CAP_NET_RAW`. Never returns.
fn run_broker_connect(sock: &str, bpffs: &str, agent_argv: &[CString]) -> ! {
    enter_userns();
    let fs = fsopen_bpf();

    let conn = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    let mut sa: libc::sockaddr_un = unsafe { mem::zeroed() };
    sa.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (dst, b) in sa.sun_path.iter_mut().zip(sock.bytes()) {
        *dst = b as libc::c_char;
    }
    let len = mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
    if unsafe { libc::connect(conn, ptr::from_ref(&sa).cast(), len) } != 0 {
        perror("connect broker");
        std::process::exit(1);
    }
    // Select the delegation handshake on this connection.
    if !write_all_fd(conn, &[CMD_DELEGATE]) {
        perror("write broker command");
        std::process::exit(1);
    }
    if !send_fd(conn, fs) {
        perror("send_fd broker");
        std::process::exit(1);
    }

    let mut buf = [0u8; 8192];
    let (n, fds) = recv_msg_fds(conn, &mut buf, SCM_MAX_FDS);
    let Some((ok, btf_names, pcap_count)) = decode_reply(&buf[..n]) else {
        eprintln!("[warden-token] malformed broker reply");
        std::process::exit(1);
    };
    if !ok {
        eprintln!("[warden-token] broker failed to delegate the bpffs");
        std::process::exit(1);
    }
    let nbtf = btf_names.len();
    if fds.len() < nbtf + pcap_count {
        eprintln!(
            "[warden-token] broker sent {} fds, expected {}",
            fds.len(),
            nbtf + pcap_count
        );
        std::process::exit(1);
    }
    // Clear O_CLOEXEC so the received fds survive execv into the agent.
    for &fd in &fds {
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFD);
            libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
        }
    }
    let modfds = btf_names
        .iter()
        .zip(&fds[..nbtf])
        .map(|(name, fd)| format!("{name}={fd}"))
        .collect::<Vec<_>>()
        .join(",");
    let pcapfds = fds[nbtf..nbtf + pcap_count]
        .iter()
        .map(RawFd::to_string)
        .collect::<Vec<_>>()
        .join(",");
    unsafe {
        libc::setenv(
            c"EBPF_MODULE_BTF_FDS".as_ptr(),
            CString::new(modfds).unwrap().as_ptr(),
            1,
        );
        if !pcapfds.is_empty() {
            libc::setenv(
                c"EBPFSENTINEL_PCAP_FDS".as_ptr(),
                CString::new(pcapfds).unwrap().as_ptr(),
                1,
            );
        }
        // Tell the agent where to reach the broker for conntrack reads: it cannot
        // read the 0440-root proc file from its child user namespace, so it proxies
        // each snapshot through the privileged broker (CMD_CONNTRACK).
        libc::setenv(
            c"EBPFSENTINEL_BROKER_SOCK".as_ptr(),
            CString::new(sock).unwrap().as_ptr(),
            1,
        );
    }
    mount_and_exec(fs, bpffs, agent_argv);
}

/// Return the value following `flag` in `args`, if present.
fn flag_value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

/// Entry point for the `warden-token` binary: dispatches the
/// all-in-one, broker-serve and broker-connect launcher modes. Exposed from the
/// library so the privileged primitives are shared with the `warden` binary.
pub fn run() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    // Broker mode: privileged sidecar that delegates bpffs + hands out fds.
    if let Some(sock) = flag_value(&args, "--broker-serve") {
        return run_broker_serve(sock);
    }

    let mut bpffs = DEFAULT_BPFFS.to_string();
    let mut broker_sock: Option<String> = None;
    let mut i = 1;
    while i < args.len() && args[i].starts_with("--") {
        if args[i] == "--bpffs" && i + 1 < args.len() {
            bpffs = args[i + 1].clone();
            i += 2;
        } else if args[i] == "--broker-connect" && i + 1 < args.len() {
            broker_sock = Some(args[i + 1].clone());
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
            "usage: warden-token [--bpffs <path>] [--broker-connect <sock>] \
             <agent-binary> [agent-args...]\n   or: warden-token --broker-serve <sock>"
        );
        return ExitCode::from(2);
    }
    let agent_argv: Vec<CString> = args[i..]
        .iter()
        .map(|a| CString::new(a.as_str()).unwrap())
        .collect();

    // Broker-connect mode: unprivileged shim — own userns, hand the bpffs to the
    // broker for delegation, receive the BTF/pcap fds, then exec the agent.
    if let Some(sock) = broker_sock {
        run_broker_connect(&sock, &bpffs, &agent_argv);
    }

    // Still global root here (before the userns fork): enable always-on SYN
    // cookies so legitimate handshakes complete under the XDP syncookie offload.
    enable_tcp_syncookies();

    // Open module BTF fds and the pcap capture sockets while still global root,
    // before the userns fork, so the child inherits them across execv.
    let modfds = fmt_btf_env(&collect_module_btf_fds());
    let pcapfds = fmt_pcap_env(&open_pcap_pool());

    let mut sv = [0 as RawFd; 2];
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) } != 0 {
        perror("socketpair");
        return ExitCode::FAILURE;
    }
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe { libc::close(sv[0]) };
        child(&bpffs, &agent_argv, &modfds, &pcapfds, sv[1]);
    }
    // PARENT: global root, configures delegation on the child's fs fd.
    unsafe { libc::close(sv[1]) };
    let fs = recv_fd(sv[0]);
    if fs < 0 {
        perror("recv_fd");
        return ExitCode::FAILURE;
    }
    let ack: u8 = u8::from(delegate_over_fd(fs));
    unsafe { libc::write(sv[0], ptr::from_ref(&ack).cast(), 1) };
    let mut st: libc::c_int = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
    if libc::WIFEXITED(st) {
        ExitCode::from(libc::WEXITSTATUS(st) as u8)
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_reply, encode_reply, fmt_btf_env, fmt_pcap_env};
    use std::os::fd::RawFd;

    #[test]
    fn reply_roundtrips() {
        let names = ["nf_conntrack", "fou", "x_tables"];
        let p = encode_reply(true, &names, 2);
        let (ok, got, pcap) = decode_reply(&p).expect("decode");
        assert!(ok);
        assert_eq!(
            got,
            names.iter().map(|s| (*s).to_string()).collect::<Vec<_>>()
        );
        assert_eq!(pcap, 2);
    }

    #[test]
    fn reply_failure_carries_no_names() {
        let p = encode_reply(false, &[], 0);
        let (ok, got, pcap) = decode_reply(&p).expect("decode");
        assert!(!ok);
        assert!(got.is_empty());
        assert_eq!(pcap, 0);
    }

    #[test]
    fn decode_rejects_malformed() {
        assert!(decode_reply(b"nope").is_none());
        assert!(decode_reply(&[]).is_none());
        // truncated trailing name must not panic and must reject
        let mut p = encode_reply(true, &["abcdef"], 0);
        p.truncate(p.len() - 3);
        assert!(decode_reply(&p).is_none());
    }

    #[test]
    fn env_formatting() {
        let btf = vec![("a".to_string(), 3 as RawFd), ("b".to_string(), 5)];
        assert_eq!(fmt_btf_env(&btf), "a=3,b=5");
        assert_eq!(fmt_btf_env(&[]), "");
        assert_eq!(fmt_pcap_env(&[7, 8]), "7,8");
        assert_eq!(fmt_pcap_env(&[]), "");
    }
}
