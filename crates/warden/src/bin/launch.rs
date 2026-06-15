//! `ebpfsentinel-launch` — combined-unit supervisor.
//!
//! Starts the privileged `warden` broker, waits for its control socket, then
//! `execv`s the agent against it — one process tree, one systemd unit / one
//! container. The warden stays as a privileged child (it holds
//! `CAP_SYS_ADMIN`/`CAP_NET_ADMIN`/`CAP_NET_RAW` for bpffs delegation, conntrack,
//! routes, ARP and the pcap pool); the agent drops every capability, self-unshares
//! its user namespace, has the warden delegate a bpffs, and loads its own eBPF
//! through a BPF token — never root.
//!
//! Usage: `ebpfsentinel-launch [--socket <path>] <agent-binary> [agent-args...]`
//! The socket defaults to `EBPFSENTINEL_WARDEN_SOCK` or `/run/ebpfsentinel/warden.sock`.

#![allow(unsafe_code)] // setenv + execv require libc.

use std::ffi::CString;
use std::path::Path;
use std::process::{Command, ExitCode};
use std::time::{Duration, Instant};

/// Default warden control-socket path when none is configured.
const DEFAULT_SOCK: &str = "/run/ebpfsentinel/warden.sock";
/// How long to wait for the warden to bind its socket before giving up.
const WARDEN_READY_TIMEOUT: Duration = Duration::from_secs(10);

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    let mut sock =
        std::env::var("EBPFSENTINEL_WARDEN_SOCK").unwrap_or_else(|_| DEFAULT_SOCK.to_string());
    let mut i = 1;
    while i < args.len() && args[i].starts_with("--") {
        if args[i] == "--socket" && i + 1 < args.len() {
            sock = args[i + 1].clone();
            i += 2;
        } else if args[i] == "--" {
            i += 1;
            break;
        } else {
            eprintln!("[launch] unknown option: {}", args[i]);
            return ExitCode::from(2);
        }
    }
    if i >= args.len() {
        eprintln!("usage: ebpfsentinel-launch [--socket <path>] <agent-binary> [agent-args...]");
        return ExitCode::from(2);
    }
    let agent_argv: Vec<CString> = args[i..]
        .iter()
        .map(|a| CString::new(a.as_str()).expect("agent arg holds no NUL"))
        .collect();

    // Ensure the socket directory exists (e.g. /run/ebpfsentinel under a fresh tmpfs).
    if let Some(dir) = Path::new(&sock).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    // The warden must admit the uid the agent's bootstrap will present once it has
    // dropped privileges and entered its user namespace.
    let uid = ebpfsentinel_warden::expected_agent_peer_uid();

    // Spawn the warden broker; it stays privileged in this process tree.
    let warden_bin = warden_binary();
    let mut warden = match Command::new(&warden_bin)
        .args(["serve", &sock, "--uid", &uid.to_string()])
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[launch] spawn {}: {e}", warden_bin.display());
            return ExitCode::FAILURE;
        }
    };

    // The agent's bootstrap connects to the socket once with no retry, so wait for
    // the warden to bind it before handing control over.
    let deadline = Instant::now() + WARDEN_READY_TIMEOUT;
    while !Path::new(&sock).exists() {
        if let Ok(Some(status)) = warden.try_wait() {
            eprintln!("[launch] warden exited before binding the socket: {status}");
            return ExitCode::FAILURE;
        }
        if Instant::now() > deadline {
            eprintln!("[launch] warden socket {sock} not ready after {WARDEN_READY_TIMEOUT:?}");
            let _ = warden.kill();
            return ExitCode::FAILURE;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // Point the agent at the warden and exec it, replacing this process. The agent
    // (now the unit's main process) drops privileges and self-bootstraps; the
    // warden child is reaped with the process tree on shutdown.
    let key = CString::new("EBPFSENTINEL_WARDEN_SOCK").unwrap();
    let val = CString::new(sock.as_str()).expect("socket path holds no NUL");
    // SAFETY: single-threaded; key/value are valid NUL-terminated strings.
    unsafe { libc::setenv(key.as_ptr(), val.as_ptr(), 1) };

    let mut ptrs: Vec<*const libc::c_char> = agent_argv.iter().map(|a| a.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    // SAFETY: valid NUL-terminated path + null-terminated argv array.
    unsafe { libc::execv(agent_argv[0].as_ptr(), ptrs.as_ptr()) };
    eprintln!(
        "[launch] execv {} failed: {}",
        args[i],
        std::io::Error::last_os_error()
    );
    let _ = warden.kill();
    ExitCode::from(127)
}

/// Resolve the `warden` binary: next to this launcher, else on `PATH`.
fn warden_binary() -> std::path::PathBuf {
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let sibling = dir.join("warden");
        if sibling.exists() {
            return sibling;
        }
    }
    std::path::PathBuf::from("warden")
}
