//! The warden control-plane server loop.
//!
//! The `warden` binary is a pure privilege broker: it loads no eBPF and holds no
//! maps (the rootless agent loads its own programs against the bpffs the warden
//! delegates). This loop answers only the privileged operations the agent cannot
//! perform from its user namespace — bpffs delegation + module-BTF/pcap fd hand-off
//! (`Delegate`), an on-demand pcap capture socket (`PcapOpen`), the conntrack-table
//! read, conntrack teardown, route programming, and gratuitous ARP.

use std::mem;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ebpfsentinel_warden_proto::{Command, PROTOCOL_VERSION, Response, read_frame, write_frame};

use crate::host_ops::HostOps;
use crate::{delegate_over_fd, dlp_scan, net_ops, recv_fd, send_msg_fds, uprobe_ops};

/// A handler for [`Command::Extension`] requests — the hook a downstream warden
/// build (e.g. the enterprise warden) installs to add privileged operations the
/// OSS warden does not know about, without forking this server loop or leaking its
/// concepts into the shared protocol.
///
/// `handle` returns `None` for a `kind` this handler does not recognise (the
/// server answers [`Response::Unimplemented`]), `Some(Ok(payload))` for a served
/// request (→ [`Response::Extension`]), or `Some(Err(message))` for a recognised
/// but failed request (→ [`Response::Error`]). The OSS `warden` binary installs no
/// handler, so every extension command answers `Unimplemented`.
pub trait ExtHandler: Send + Sync {
    /// Serve a namespaced extension request, owning the `payload` semantics.
    fn handle(&self, kind: &str, payload: &[u8]) -> Option<Result<Vec<u8>, String>>;
}

/// Serve agent connections on `listener` forever, handing out the `btf` / `pcap`
/// fds on delegation and brokering the host-network ops via `host`. Only a peer
/// whose uid equals `allowed_uid` (checked via `SO_PEERCRED`) is served.
///
/// Each accepted connection is handled on its own thread. The agent keeps a few
/// long-lived `ReconnectingClient` connections open and idle between calls; a
/// single-threaded accept loop would block on one such idle connection's blocking
/// read and never serve any other (a `DlpScan` after a held conntrack/ARP client
/// would deadlock). Thread-per-connection keeps every channel independent — the
/// op rate is low and the connection count small.
pub fn serve_loop(
    listener: &UnixListener,
    btf: Arc<Vec<(String, RawFd)>>,
    pcap: Arc<Vec<RawFd>>,
    host: Arc<dyn HostOps>,
    ext: Option<Arc<dyn ExtHandler>>,
    allowed_uid: u32,
) {
    // The pcap pool is handed out across all connections, so the next-index is
    // shared (a reconnecting agent is re-served from where it left off).
    let pcap_next = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        match stream {
            Ok(conn) => {
                if peer_allowed(&conn, allowed_uid) {
                    let btf = Arc::clone(&btf);
                    let pcap = Arc::clone(&pcap);
                    let host = Arc::clone(&host);
                    let ext = ext.clone();
                    let pcap_next = Arc::clone(&pcap_next);
                    std::thread::spawn(move || {
                        handle_conn(conn, &btf, &pcap, &*host, ext.as_deref(), &pcap_next);
                    });
                }
            }
            Err(e) => eprintln!("[warden] accept: {e}"),
        }
    }
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
fn handle_conn(
    conn: UnixStream,
    btf: &[(String, RawFd)],
    pcap: &[RawFd],
    host: &dyn HostOps,
    ext: Option<&dyn ExtHandler>,
    pcap_next: &AtomicUsize,
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
        // `PcapOpen` answers out-of-band: an `FdReady` frame followed by a fd in an
        // `SCM_RIGHTS` cmsg, so it bypasses `dispatch`.
        let ok = match &cmd {
            Command::PcapOpen { iface, filter } => {
                eprintln!("[warden] pcap open on {iface} (filter applied agent-side: {filter:?})");
                // Claim the next pool slot atomically (the index is shared across
                // all connection threads). The warden keeps its own copy open so a
                // reconnecting agent is re-served in order; the fd is dup'd into
                // the agent by `SCM_RIGHTS`, so closing the agent's copy does not
                // disturb the warden's.
                let idx = pcap_next.fetch_add(1, Ordering::Relaxed);
                if idx < pcap.len() {
                    // Serve a launcher-provided socket: the warden may sit in a
                    // user namespace where `socket(AF_PACKET)` is denied, so the
                    // pre-opened pool is the only way to capture rootlessly.
                    let fd = pcap[idx];
                    serve_passed_fd(&mut writer, Ok(fd))
                } else {
                    // Pool exhausted (or none provided, e.g. a bare-metal warden
                    // running as host root): open one on demand.
                    match net_ops::open_pcap_fd(iface) {
                        Ok(owned) => {
                            let ok = serve_passed_fd(&mut writer, Ok(owned.as_raw_fd()));
                            drop(owned); // fd dup'd into the agent by SCM_RIGHTS; ours can close
                            ok
                        }
                        Err(message) => serve_passed_fd(&mut writer, Err(message)),
                    }
                }
            }
            Command::Delegate => serve_delegate(&mut writer, btf, pcap),
            // `AttachUprobe` answers out-of-band: it first receives the agent's
            // program fd over `SCM_RIGHTS`, creates the link, then replies
            // `FdReady` + the link fd (or a typed `Error`).
            Command::AttachUprobe {
                path,
                offset,
                is_ret,
            } => serve_attach_uprobe(&mut writer, path, *offset, *is_ret),
            // `Extension` is answered by the installed handler (if any); the OSS
            // warden installs none, so it falls through to `Unimplemented`.
            Command::Extension { kind, payload } => {
                let resp = match ext {
                    Some(handler) => match handler.handle(kind, payload) {
                        Some(Ok(payload)) => Response::Extension { payload },
                        Some(Err(message)) => Response::Error { message },
                        None => Response::Unimplemented,
                    },
                    None => Response::Unimplemented,
                };
                write_frame(&mut writer, &resp).is_ok()
            }
            other => write_frame(&mut writer, &dispatch(other, host)).is_ok(),
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
/// `Delegated` and hand back the module-BTF + pcap fds. The warden keeps its own
/// BTF/pcap fds open for the next agent / restart.
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

/// Serve an `AttachUprobe`: receive the agent's program fd (sent in an
/// `SCM_RIGHTS` cmsg right after the command frame), create the `uprobe_multi`
/// link, then reply `FdReady` + the link fd. The warden closes its own copy of
/// both the program fd and the link fd — the link fd is dup'd into the agent by
/// `SCM_RIGHTS` and the link keeps the program alive — so neither leaks.
fn serve_attach_uprobe(writer: &mut UnixStream, path: &str, offset: u64, is_ret: bool) -> bool {
    let prog_fd = recv_fd(writer.as_raw_fd());
    if prog_fd < 0 {
        return write_frame(
            writer,
            &Response::Error {
                message: "no program fd received for uprobe attach".into(),
            },
        )
        .is_ok();
    }
    let result = uprobe_ops::attach_uprobe_link(prog_fd, path, offset, is_ret);
    unsafe { libc::close(prog_fd) };
    match result {
        Ok(link) => {
            let ok = serve_passed_fd(writer, Ok(link));
            unsafe { libc::close(link) };
            ok
        }
        Err(message) => serve_passed_fd(writer, Err(message)),
    }
}

/// Map a request to a response. The conntrack read and the host-network ops go to
/// `host`. The fd-passing commands (`Delegate`, `PcapOpen`) are answered out of
/// band by the caller and never reach here.
fn dispatch(cmd: &Command, host: &dyn HostOps) -> Response {
    match cmd {
        Command::ConntrackDump => match host.conntrack_dump() {
            Ok(table) => Response::Conntrack { table },
            Err(message) => Response::Error { message },
        },
        // Host-network ops needing authority over the init netns, performed
        // directly by the host-root warden.
        Command::ConntrackDelete { tuple } => result_to_response(host.conntrack_delete(tuple)),
        Command::ConntrackFlush => result_to_response(host.conntrack_flush()),
        Command::RouteAdd { route } => result_to_response(host.route_add(route)),
        Command::RouteDel { route } => result_to_response(host.route_del(route)),
        Command::ArpAnnounce { iface, ip } => result_to_response(host.arp_announce(iface, ip)),
        Command::DlpScan => Response::DlpTargets {
            targets: dlp_scan::scan_dlp_targets(),
        },
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

#[cfg(test)]
mod tests {
    use super::{ExtHandler, HostOps, handle_conn};
    use ebpfsentinel_warden_proto::{
        Command, ConntrackTuple, PROTOCOL_VERSION, Response, RouteSpec, read_frame, write_frame,
    };
    use std::os::unix::net::UnixStream;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    use std::thread::JoinHandle;

    /// No host-network op is exercised by the extension tests — only the `Hello`
    /// handshake and `Extension` commands are sent — so every method is a stub.
    struct NullHost;
    impl HostOps for NullHost {
        fn conntrack_dump(&self) -> Result<Vec<u8>, String> {
            Err("unused".into())
        }
        fn conntrack_delete(&self, _tuple: &ConntrackTuple) -> Result<(), String> {
            Err("unused".into())
        }
        fn conntrack_flush(&self) -> Result<(), String> {
            Err("unused".into())
        }
        fn route_add(&self, _route: &RouteSpec) -> Result<(), String> {
            Err("unused".into())
        }
        fn route_del(&self, _route: &RouteSpec) -> Result<(), String> {
            Err("unused".into())
        }
        fn arp_announce(&self, _iface: &str, _ip: &str) -> Result<(), String> {
            Err("unused".into())
        }
    }

    /// Echoes the payload for kind `echo`, fails kind `boom`, and does not
    /// recognise any other kind (so the server answers `Unimplemented`).
    struct FakeExt;
    impl ExtHandler for FakeExt {
        fn handle(&self, kind: &str, payload: &[u8]) -> Option<Result<Vec<u8>, String>> {
            match kind {
                "echo" => Some(Ok(payload.to_vec())),
                "boom" => Some(Err("boom failed".into())),
                _ => None,
            }
        }
    }

    /// Drive `handle_conn` on the server end of a socket pair on its own thread.
    fn run_server(server: UnixStream, ext: Option<Arc<dyn ExtHandler>>) -> JoinHandle<()> {
        std::thread::spawn(move || {
            let pcap_next = AtomicUsize::new(0);
            let host = NullHost;
            handle_conn(server, &[], &[], &host, ext.as_deref(), &pcap_next);
        })
    }

    /// Complete the version handshake on the client end.
    fn hello(client: &mut UnixStream) {
        write_frame(
            client,
            &Command::Hello {
                version: PROTOCOL_VERSION,
            },
        )
        .unwrap();
        let resp: Response = read_frame(client).unwrap();
        assert_eq!(
            resp,
            Response::HelloOk {
                version: PROTOCOL_VERSION
            }
        );
    }

    /// Send one `Extension` and read its response, closing the client to end the
    /// server thread.
    fn one_extension(ext: Option<Arc<dyn ExtHandler>>, kind: &str, payload: Vec<u8>) -> Response {
        let (mut client, server) = UnixStream::pair().unwrap();
        let handle = run_server(server, ext);
        hello(&mut client);
        write_frame(
            &mut client,
            &Command::Extension {
                kind: kind.into(),
                payload,
            },
        )
        .unwrap();
        let resp: Response = read_frame(&mut client).unwrap();
        drop(client);
        handle.join().unwrap();
        resp
    }

    #[test]
    fn extension_handled_ok_returns_payload() {
        let resp = one_extension(Some(Arc::new(FakeExt)), "echo", vec![1, 2, 3]);
        assert_eq!(
            resp,
            Response::Extension {
                payload: vec![1, 2, 3]
            }
        );
    }

    #[test]
    fn extension_handled_err_returns_error() {
        let resp = one_extension(Some(Arc::new(FakeExt)), "boom", vec![]);
        assert_eq!(
            resp,
            Response::Error {
                message: "boom failed".into()
            }
        );
    }

    #[test]
    fn extension_unknown_kind_is_unimplemented() {
        let resp = one_extension(Some(Arc::new(FakeExt)), "mystery", vec![]);
        assert_eq!(resp, Response::Unimplemented);
    }

    #[test]
    fn extension_without_handler_is_unimplemented() {
        let resp = one_extension(None, "echo", vec![1]);
        assert_eq!(resp, Response::Unimplemented);
    }
}
