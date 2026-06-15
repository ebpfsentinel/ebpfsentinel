//! Agent self-bootstrap trampoline (rootless, token-only eBPF loading).
//!
//! In the split deployment the rootless **agent** loads its own eBPF — it is not
//! a passive consumer. But `BPF_TOKEN_CREATE` only succeeds inside a user
//! namespace that owns the delegated bpffs, and applying the `delegate_*` mount
//! options needs `CAP_SYS_ADMIN` in the *init* user namespace, which the agent
//! does not have. So the agent and the privileged [`warden`] split the work over
//! the control socket:
//!
//! 1. The agent enters a fresh user + mount namespace (dropping to an
//!    unprivileged id first under a container runtime — see
//!    [`drop_to_unpriv_if_needed`]).
//! 2. It `fsopen("bpf")` (the superblock is owned by *its* userns) and sends the
//!    fs fd to the warden with a [`Command::Delegate`]. The warden applies
//!    `delegate_*` + `FSCONFIG_CMD_CREATE` (its init-ns `CAP_SYS_ADMIN`) and
//!    returns the module-BTF + pcap fds it opened while privileged.
//! 3. The agent `fsmount`/`move_mount`s the now-delegated bpffs, advertises the
//!    received fds via `EBPF_MODULE_BTF_FDS` / `EBPFSENTINEL_PCAP_FDS`, and
//!    `execv`s itself so the async runtime starts fresh inside the namespace.
//!
//! On the second pass `EBPFSENTINEL_USERNS_READY` is set, so the trampoline is a
//! no-op and normal startup creates the BPF token against the mounted bpffs and
//! loads every program. The agent stays in the host network namespace, so
//! conntrack teardown, route programming, gratuitous ARP and packet capture
//! continue to be brokered by the warden over the same socket.
//!
//! [`warden`]: crate

use std::ffi::CString;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::ptr;

use ebpfsentinel_warden_proto::{Command, PROTOCOL_VERSION, Response, read_frame, write_frame};

use crate::{
    DEFAULT_BPFFS, drop_to_unpriv_if_needed, enter_userns, fsopen_bpf, mount_bpffs, perror,
    recv_msg_fds, send_fd,
};

/// Set to `1` by the trampoline before it re-execs, so the second process image
/// skips the namespace setup and proceeds straight to normal startup.
const READY_ENV: &str = "EBPFSENTINEL_USERNS_READY";
/// Bpffs mount path the trampoline mounts the delegated superblock at; the
/// agent's `bpf_token.bpffs_path` must match. Defaults to [`DEFAULT_BPFFS`].
const BPFFS_ENV: &str = "EBPFSENTINEL_BPFFS";
/// Warden control-socket path; its presence selects the rootless self-bootstrap.
const WARDEN_SOCK_ENV: &str = "EBPFSENTINEL_WARDEN_SOCK";

/// Run the self-bootstrap trampoline when the deployment points the agent at a
/// warden (`EBPFSENTINEL_WARDEN_SOCK`) and it has not bootstrapped yet. Must be
/// called single-threaded, before any async runtime is built. On success it
/// re-execs the process (never returns); on the second pass, or when no warden
/// socket is configured, it returns and normal startup continues. A bootstrap
/// failure is fatal — a token-only agent cannot load eBPF without it.
pub fn maybe_bootstrap_from_env() {
    if std::env::var_os(READY_ENV).is_some() {
        return;
    }
    let Some(sock) = std::env::var_os(WARDEN_SOCK_ENV) else {
        return;
    };
    let sock = sock.to_string_lossy().into_owned();
    if sock.is_empty() {
        return;
    }
    let bpffs = std::env::var(BPFFS_ENV).unwrap_or_else(|_| DEFAULT_BPFFS.to_string());
    if let Err(e) = bootstrap(&bpffs, &sock) {
        eprintln!("[agent] warden self-bootstrap failed: {e}");
        std::process::exit(1);
    }
}

/// Perform the userns + delegation handshake, mount the bpffs, then re-exec.
fn bootstrap(bpffs: &str, sock: &str) -> io::Result<()> {
    drop_to_unpriv_if_needed();
    enter_userns();

    let mut stream = UnixStream::connect(sock)?;
    write_frame(
        &mut stream,
        &Command::Hello {
            version: PROTOCOL_VERSION,
        },
    )?;
    match read_frame::<_, Response>(&mut stream)? {
        Response::HelloOk { version } if version == PROTOCOL_VERSION => {}
        Response::HelloOk { version } => {
            return Err(io::Error::other(format!(
                "warden protocol v{version} != agent v{PROTOCOL_VERSION}"
            )));
        }
        other => {
            return Err(io::Error::other(format!(
                "unexpected handshake reply: {other:?}"
            )));
        }
    }

    // fsopen the bpffs in this userns, then have the warden delegate it.
    let fs = fsopen_bpf();
    write_frame(&mut stream, &Command::Delegate)?;
    if !send_fd(stream.as_raw_fd(), fs) {
        return Err(io::Error::other("failed to send bpffs fd for delegation"));
    }
    let (btf_names, pcap_count) = match read_frame::<_, Response>(&mut stream)? {
        Response::Delegated {
            btf_names,
            pcap_count,
        } => (btf_names, pcap_count),
        Response::Error { message } => {
            return Err(io::Error::other(format!("warden delegation: {message}")));
        }
        other => {
            return Err(io::Error::other(format!(
                "unexpected delegate reply: {other:?}"
            )));
        }
    };
    let want = btf_names.len() + pcap_count as usize;
    let fds = recv_msg_fds(stream.as_raw_fd(), want);
    if fds.len() < want {
        return Err(io::Error::other(format!(
            "expected {want} fds from warden, received {}",
            fds.len()
        )));
    }

    // The warden has applied FSCONFIG_CMD_CREATE on the shared fs context; mount
    // the resulting superblock here.
    mount_bpffs(fs, bpffs);

    // Hand the module-BTF + pcap fds to the second pass via the same env vars the
    // all-in-one launcher uses, so the eBPF loader and capture path are unchanged.
    let btf_env = btf_names
        .iter()
        .zip(fds.iter())
        .map(|(name, fd)| format!("{name}={fd}"))
        .collect::<Vec<_>>()
        .join(",");
    let pcap_env = fds[btf_names.len()..]
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    setenv("EBPF_MODULE_BTF_FDS", &btf_env);
    if !pcap_env.is_empty() {
        setenv("EBPFSENTINEL_PCAP_FDS", &pcap_env);
    }
    setenv(READY_ENV, "1");

    reexec_self()
}

/// `setenv(3)` so the value reaches the re-exec'd image through the C `environ`.
fn setenv(key: &str, value: &str) {
    let k = CString::new(key).unwrap();
    let v = CString::new(value).unwrap();
    // SAFETY: single-threaded (pre-runtime); key/value are valid NUL-terminated.
    unsafe { libc::setenv(k.as_ptr(), v.as_ptr(), 1) };
}

/// Re-exec this binary with the original argv inside the new namespaces. Never
/// returns: on success control transfers to a fresh process image, on failure
/// the process exits.
fn reexec_self() -> ! {
    let exe =
        std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("/proc/self/exe"));
    let exe_c = CString::new(exe.as_os_str().as_bytes()).unwrap();
    let argv: Vec<CString> = std::env::args_os()
        .map(|a| CString::new(a.as_bytes()).unwrap())
        .collect();
    let mut ptrs: Vec<*const libc::c_char> = argv.iter().map(|a| a.as_ptr()).collect();
    ptrs.push(ptr::null());
    // SAFETY: valid NUL-terminated path + argv array terminated by null.
    unsafe { libc::execv(exe_c.as_ptr(), ptrs.as_ptr()) };
    perror("execv self after warden bootstrap");
    std::process::exit(127);
}
