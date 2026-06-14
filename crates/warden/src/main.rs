//! `warden` — the privileged kernel-operation control plane for a fully rootless
//! eBPFsentinel agent.
//!
//! The agent runs non-root with every capability dropped and the runtime-default
//! seccomp profile, so it can issue neither `bpf()` nor netlink/`mount` syscalls.
//! It connects to this process over an `AF_UNIX` socket and asks for a narrow set
//! of typed operations defined by `ebpfsentinel-warden-proto`. The warden holds
//! the extended privileges (`CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `CAP_NET_RAW`) and
//! does nothing on its own initiative — it only answers validated requests.
//!
//! This build serves the protocol handshake and the conntrack-table read; the
//! map, attach, netlink and fd-passing operations are declared by the protocol
//! and answered with `Unimplemented` until their dedicated work lands. The
//! privileged launcher primitives live in the shared `ebpfsentinel-token-launch`
//! library.

#![allow(unsafe_code)] // SO_PEERCRED via getsockopt requires libc + unsafe.
#![allow(clippy::cast_possible_truncation)]

use std::fs;
use std::io::{self, BufReader};
use std::mem;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::ExitCode;
use std::ptr;

use ebpfsentinel_warden::enable_tcp_syncookies;
use ebpfsentinel_warden_proto::{Command, PROTOCOL_VERSION, Response, read_frame, write_frame};

/// Default peer uid the warden accepts — the rootless agent's id. Override with
/// `--uid <n>`.
const DEFAULT_UID: u32 = 65534;
/// Kernel conntrack table the warden reads on the agent's behalf (a `0440 root`
/// file the rootless agent cannot open).
const NF_CONNTRACK_PROC: &str = "/proc/net/nf_conntrack";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("serve") => {
            let Some(sock) = args.get(2) else {
                eprintln!("usage: warden serve <socket> [--uid <n>]");
                return ExitCode::from(2);
            };
            let uid = parse_uid(&args).unwrap_or(DEFAULT_UID);
            serve(sock, uid)
        }
        _ => {
            eprintln!("usage: warden serve <socket> [--uid <n>]");
            ExitCode::from(2)
        }
    }
}

/// Parse `--uid <n>` if present.
fn parse_uid(args: &[String]) -> Option<u32> {
    let i = args.iter().position(|a| a == "--uid")?;
    args.get(i + 1)?.parse().ok()
}

/// Bind the listening socket (mode `0600`) and serve agent connections forever.
fn serve(sockpath: &str, allowed_uid: u32) -> ExitCode {
    // Privileged setup the agent cannot perform once rootless (the XDP syncookie
    // offload needs always-on kernel syncookies).
    enable_tcp_syncookies();

    let _ = fs::remove_file(sockpath);
    let listener = match UnixListener::bind(sockpath) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[warden] bind {sockpath}: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = fs::set_permissions(sockpath, fs::Permissions::from_mode(0o600)) {
        eprintln!("[warden] chmod {sockpath}: {e}");
    }
    eprintln!(
        "[warden] serving on {sockpath} (allowed peer uid {allowed_uid}, protocol v{PROTOCOL_VERSION})"
    );

    for stream in listener.incoming() {
        match stream {
            Ok(conn) => {
                if peer_allowed(&conn, allowed_uid) {
                    handle_conn(conn);
                }
            }
            Err(e) => eprintln!("[warden] accept: {e}"),
        }
    }
    ExitCode::SUCCESS
}

/// Confirm the connected peer's uid matches the one the warden serves, read via
/// `SO_PEERCRED` (the stable-Rust path; `UnixStream::peer_cred` is still nightly).
fn peer_allowed(conn: &UnixStream, allowed_uid: u32) -> bool {
    let mut cred: libc::ucred = unsafe { mem::zeroed() };
    let mut len = mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            conn.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            ptr::from_mut(&mut cred).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        eprintln!("[warden] getsockopt(SO_PEERCRED) failed");
        return false;
    }
    if cred.uid == allowed_uid {
        true
    } else {
        eprintln!(
            "[warden] rejecting peer uid {} (expected {allowed_uid})",
            cred.uid
        );
        false
    }
}

/// Handle one agent connection: require a matching-version `Hello`, then answer
/// commands until the peer closes the connection.
fn handle_conn(conn: UnixStream) {
    let mut reader = BufReader::new(match conn.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    });
    let mut writer = conn;

    let Ok(first) = read_frame::<_, Command>(&mut reader) else {
        return;
    };
    match first {
        Command::Hello { version } if version == PROTOCOL_VERSION => {
            if write_frame(
                &mut writer,
                &Response::HelloOk {
                    version: PROTOCOL_VERSION,
                },
            )
            .is_err()
            {
                return;
            }
        }
        Command::Hello { version } => {
            let message =
                format!("protocol version mismatch: warden {PROTOCOL_VERSION}, agent {version}");
            let _ = write_frame(&mut writer, &Response::Error { message });
            return;
        }
        _ => {
            let _ = write_frame(
                &mut writer,
                &Response::Error {
                    message: "expected Hello as the first message".into(),
                },
            );
            return;
        }
    }

    while let Ok(cmd) = read_frame::<_, Command>(&mut reader) {
        let resp = dispatch(&cmd);
        if write_frame(&mut writer, &resp).is_err() {
            break;
        }
    }
}

/// Map a request to a response. Only the conntrack read is wired in this build;
/// every other declared command is answered `Unimplemented`.
fn dispatch(cmd: &Command) -> Response {
    match cmd {
        Command::ConntrackDump => match fs::read(NF_CONNTRACK_PROC) {
            Ok(table) => Response::Conntrack { table },
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                Response::Conntrack { table: Vec::new() }
            }
            Err(e) => Response::Error {
                message: format!("read {NF_CONNTRACK_PROC}: {e}"),
            },
        },
        Command::Hello { .. } => Response::Error {
            message: "Hello already completed".into(),
        },
        _ => Response::Unimplemented,
    }
}
