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
//! This build serves the protocol handshake, the conntrack-table read, and the
//! map element operations (`MapLookup`/`MapUpdate`/`MapDelete`) against the maps
//! pinned under its bpffs directory; the attach, netlink and fd-passing
//! operations are declared by the protocol and answered with `Unimplemented`
//! until their dedicated work lands. The privileged launcher primitives and the
//! map engine live in the shared `ebpfsentinel-warden` library.

#![allow(unsafe_code)] // SO_PEERCRED via getsockopt requires libc + unsafe.
#![allow(clippy::cast_possible_truncation)]

use std::fs;
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::ExitCode;
use std::ptr;

use ebpfsentinel_warden::map_engine::{MapRegistry, MapSource};
use ebpfsentinel_warden::{
    collect_module_btf_fds, delegate_over_fd, enable_tcp_syncookies, net_ops, open_pcap_pool,
    prioritize_and_cap_btf, recv_fd, send_msg_fds,
};
use ebpfsentinel_warden_proto::{Command, PROTOCOL_VERSION, Response, read_frame, write_frame};

/// Default peer uid the warden accepts — the rootless agent's id. Override with
/// `--uid <n>`.
const DEFAULT_UID: u32 = 65534;
/// Default bpffs directory holding the pinned maps the warden serves. Override
/// with `--maps-dir <path>`.
const DEFAULT_MAPS_DIR: &str = "/sys/fs/bpf/ebpfsentinel";
/// Kernel conntrack table the warden reads on the agent's behalf (a `0440 root`
/// file the rootless agent cannot open).
const NF_CONNTRACK_PROC: &str = "/proc/net/nf_conntrack";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("serve") => {
            let Some(sock) = args.get(2) else {
                eprintln!("usage: warden serve <socket> [--uid <n>] [--maps-dir <path>]");
                return ExitCode::from(2);
            };
            let uid = parse_uid(&args).unwrap_or(DEFAULT_UID);
            let maps_dir = parse_opt(&args, "--maps-dir").unwrap_or(DEFAULT_MAPS_DIR.to_owned());
            serve(sock, uid, &maps_dir)
        }
        _ => {
            eprintln!("usage: warden serve <socket> [--uid <n>] [--maps-dir <path>]");
            ExitCode::from(2)
        }
    }
}

/// Parse `--uid <n>` if present.
fn parse_uid(args: &[String]) -> Option<u32> {
    parse_opt(args, "--uid")?.parse().ok()
}

/// Parse the value following `flag` if present.
fn parse_opt(args: &[String], flag: &str) -> Option<String> {
    let i = args.iter().position(|a| a == flag)?;
    args.get(i + 1).cloned()
}

/// Bind the listening socket (mode `0600`) and serve agent connections forever.
fn serve(sockpath: &str, allowed_uid: u32, maps_dir: &str) -> ExitCode {
    // Privileged setup the agent cannot perform once rootless (the XDP syncookie
    // offload needs always-on kernel syncookies).
    enable_tcp_syncookies();

    // Open the pinned maps once; their set is the allowlist for map RPC. Because
    // the maps are pinned in bpffs, this re-adopts exactly the objects a previous
    // warden served — a warden restart reloads no eBPF and never disturbs the
    // agent's already-held ring-buffer fds.
    let registry = MapRegistry::open_pin_dir(std::path::Path::new(maps_dir));
    eprintln!(
        "[warden] re-adopted {} pinned map(s) from {maps_dir} {:?}",
        registry.len(),
        registry.names()
    );

    // Open the module-BTF and pcap fds once (privileged: BTF enumeration needs
    // CAP_SYS_ADMIN, the AF_PACKET pool needs CAP_NET_RAW). They are handed to the
    // agent on `Delegate`, making `warden serve` a superset of the legacy
    // `warden-token --broker-serve` lineage. Without the capabilities both sets
    // come back empty and delegation simply carries no fds.
    let pcap = open_pcap_pool();
    let btf = prioritize_and_cap_btf(collect_module_btf_fds(), pcap.len());
    eprintln!(
        "[warden] delegation ready: {} module BTF fd(s), {} pcap fd(s)",
        btf.len(),
        pcap.len()
    );

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
                    handle_conn(conn, &registry, &btf, &pcap);
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
///
/// Reads frame-by-frame on the raw stream (no `BufReader`): a buffered reader
/// would read past a frame boundary and swallow the sentinel byte that carries an
/// inbound `SCM_RIGHTS` fd (e.g. the `Delegate` bpffs fd), dropping the fd.
fn handle_conn<M: MapSource>(
    conn: UnixStream,
    registry: &M,
    btf: &[(String, RawFd)],
    pcap: &[RawFd],
) {
    let mut reader = match conn.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    };
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
        // `GetRingbufFd` / `PcapOpen` answer out-of-band: an `FdReady` frame
        // followed by a fd in an `SCM_RIGHTS` cmsg, so they bypass `dispatch`.
        let ok = match &cmd {
            Command::GetRingbufFd { program } => serve_passed_fd(
                &mut writer,
                registry
                    .ringbuf_fd(program)
                    .ok_or_else(|| format!("'{program}' is not a pinned ring-buffer map")),
            ),
            Command::PcapOpen { iface, filter } => {
                eprintln!("[warden] pcap open on {iface} (filter applied agent-side: {filter:?})");
                match net_ops::open_pcap_fd(iface) {
                    Ok(owned) => {
                        let ok = serve_passed_fd(&mut writer, Ok(owned.as_raw_fd()));
                        drop(owned); // fd dup'd into the agent by SCM_RIGHTS; ours can close
                        ok
                    }
                    Err(message) => serve_passed_fd(&mut writer, Err(message)),
                }
            }
            Command::Delegate => serve_delegate(&mut writer, btf, pcap),
            other => write_frame(&mut writer, &dispatch(other, registry)).is_ok(),
        };
        if !ok {
            break;
        }
    }
}

/// Answer an fd-passing command: on `Ok(fd)` write `FdReady` then send the fd in
/// an `SCM_RIGHTS` cmsg; on `Err` reply with a typed `Error` and send no fd.
/// Returns `false` only on a write/socket error (close the connection); a
/// refused-but-answered request returns `true`.
fn serve_passed_fd(writer: &mut UnixStream, fd: Result<RawFd, String>) -> bool {
    match fd {
        Ok(fd) => {
            if write_frame(writer, &Response::FdReady).is_err() {
                return false;
            }
            // One sentinel payload byte carries the fd; the agent reads `FdReady`,
            // then recvmsg's exactly this byte to collect the descriptor.
            send_msg_fds(writer.as_raw_fd(), &[0u8], &[fd])
        }
        Err(message) => write_frame(writer, &Response::Error { message }).is_ok(),
    }
}

/// Serve a `Delegate`: receive the agent's bpffs `fs_fd` (sent in an `SCM_RIGHTS`
/// cmsg right after the command frame), apply the `delegate_*` options +
/// `FSCONFIG_CMD_CREATE` (the steps that need global `CAP_SYS_ADMIN`), then reply
/// `Delegated` and hand back the module-BTF + pcap fds. This is the `warden serve`
/// equivalent of the legacy `warden-token --broker-serve` delegation handshake.
/// The warden keeps its own BTF/pcap fds open for the next agent / restart.
fn serve_delegate(writer: &mut UnixStream, btf: &[(String, RawFd)], pcap: &[RawFd]) -> bool {
    let fs = recv_fd(writer.as_raw_fd());
    if fs < 0 {
        return write_frame(
            writer,
            &Response::Error {
                message: "no bpffs fd received for delegation".into(),
            },
        )
        .is_ok();
    }
    let ok = delegate_over_fd(fs);
    unsafe { libc::close(fs) };
    if !ok {
        return write_frame(
            writer,
            &Response::Error {
                message: "bpffs delegation (FSCONFIG_CMD_CREATE) failed".into(),
            },
        )
        .is_ok();
    }
    let btf_names: Vec<String> = btf.iter().map(|(name, _)| name.clone()).collect();
    let resp = Response::Delegated {
        btf_names,
        pcap_count: u32::try_from(pcap.len()).unwrap_or(0),
    };
    if write_frame(writer, &resp).is_err() {
        return false;
    }
    // BTF fds first (in `btf_names` order), then the pcap fds — the order the
    // agent reconstructs from `Delegated`.
    let mut fds: Vec<RawFd> = btf.iter().map(|(_, fd)| *fd).collect();
    fds.extend_from_slice(pcap);
    send_msg_fds(writer.as_raw_fd(), &[0u8], &fds)
}

/// Map a request to a response. The conntrack read and map element ops are wired
/// in this build; every other declared command is answered `Unimplemented`.
fn dispatch<M: MapSource>(cmd: &Command, registry: &M) -> Response {
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
        Command::MapLookup { map, key } => match registry.lookup(map, key) {
            Ok(Some(value)) => Response::MapValue { found: true, value },
            Ok(None) => Response::MapValue {
                found: false,
                value: Vec::new(),
            },
            Err(e) => Response::Error {
                message: e.to_string(),
            },
        },
        Command::MapUpdate {
            map,
            key,
            value,
            flags,
        } => match registry.update(map, key, value, *flags) {
            Ok(()) => Response::Ok,
            Err(e) => Response::Error {
                message: e.to_string(),
            },
        },
        Command::MapDelete { map, key } => match registry.delete(map, key) {
            Ok(()) => Response::Ok,
            Err(e) => Response::Error {
                message: e.to_string(),
            },
        },
        // Host-network ops needing CAP_NET_ADMIN/CAP_NET_RAW the token can't grant.
        Command::ConntrackDelete { tuple } => result_to_response(net_ops::conntrack_delete(tuple)),
        Command::ConntrackFlush => result_to_response(net_ops::conntrack_flush()),
        Command::RouteAdd { route } => result_to_response(net_ops::route(true, route)),
        Command::RouteDel { route } => result_to_response(net_ops::route(false, route)),
        Command::ArpAnnounce { iface, ip } => result_to_response(net_ops::arp_announce(iface, ip)),
        Command::Hello { .. } => Response::Error {
            message: "Hello already completed".into(),
        },
        _ => Response::Unimplemented,
    }
}

/// Collapse a `net_ops` result into a `Response`.
fn result_to_response(result: Result<(), String>) -> Response {
    match result {
        Ok(()) => Response::Ok,
        Err(message) => Response::Error { message },
    }
}
