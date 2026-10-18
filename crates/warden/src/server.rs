//! The warden control-plane server loop.
//!
//! The `warden` binary is a pure privilege broker: it loads no eBPF and holds no
//! maps (the rootless agent loads its own programs against the bpffs the warden
//! delegates). This loop answers only the privileged operations the agent cannot
//! perform from its user namespace - bpffs delegation + module-BTF/pcap fd hand-off
//! (`Delegate`), an on-demand pcap capture socket (`PcapOpen`), the conntrack-table
//! read, conntrack teardown, route programming, and gratuitous ARP.

use std::mem;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::Arc;
use std::time::Duration;

use ebpfsentinel_warden_proto::{Command, PROTOCOL_VERSION, Response, read_frame, write_frame};

use crate::host_ops::HostOps;
use crate::pcap_slots::{PcapSlot, PcapSlots};
use crate::{delegate_over_fd, dlp_scan, net_ops, recv_fd, send_msg_fds, uprobe_ops};

/// How long a connection may hold a thread without saying `Hello`.
///
/// The client sends it immediately on connect, so anything slower than this is
/// not an agent: a peer that connects and then says nothing would otherwise
/// park a warden thread in a blocking read for as long as the warden lives.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long an idle connection that holds nothing is kept.
///
/// Idling is normal and not an error - the agent's clients sit open between
/// calls on purpose, and the client reconnects transparently when a call finds
/// the connection gone - so this is not a liveness check on the agent. It is
/// there for the connection whose peer stopped talking without closing: the
/// socket stays open, the thread stays in its read, and nothing in the protocol
/// ever ends it. Well above every interval the agent polls on, so a working
/// deployment reconnects rarely if at all.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(600);

/// What waiting for the next frame ended with.
enum Waited {
    /// The peer sent something, or closed: either way the read is next.
    Readable,
    /// Nothing arrived inside the timeout.
    TimedOut,
    /// The wait itself failed, which is not something to spin on.
    Failed,
}

/// Wait until `fd` has a frame to read, or `timeout` passes.
///
/// `poll` rather than `SO_RCVTIMEO`: a receive timeout can fire between the
/// length prefix and the body, and `read_exact` reports that as a failure with
/// the bytes already consumed, leaving the stream out of step. Waiting before
/// the read starts means a timeout only ever happens on a frame boundary.
fn wait_for_frame(fd: RawFd, timeout: Duration) -> Waited {
    let millis = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
    loop {
        let mut pollfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // Safety: one pollfd owned by this frame, a count matching it, and a
        // timeout in milliseconds. `poll` writes only `revents`.
        let rc = unsafe { libc::poll(ptr::from_mut(&mut pollfd), 1, millis) };
        if rc > 0 {
            return Waited::Readable;
        }
        if rc == 0 {
            return Waited::TimedOut;
        }
        let e = std::io::Error::last_os_error();
        if e.kind() == std::io::ErrorKind::Interrupted {
            // A signal, not the peer. The remaining wait is restarted rather
            // than inherited, which at this timescale changes nothing.
            continue;
        }
        eprintln!("[warden] poll on connection failed: {e}");
        return Waited::Failed;
    }
}

/// A handler for [`Command::Extension`] requests - the hook a downstream warden
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
/// would deadlock). Thread-per-connection keeps every channel independent - the
/// op rate is low and the connection count small.
///
/// `proc_root` is the procfs the DLP scan walks: `/proc` on a host, the
/// read-only bind mount in a container that was not given the host pid
/// namespace.
pub fn serve_loop(
    listener: &UnixListener,
    btf: Arc<Vec<(String, RawFd)>>,
    pcap: Arc<Vec<RawFd>>,
    host: Arc<dyn HostOps>,
    ext: Option<Arc<dyn ExtHandler>>,
    allowed_uid: u32,
    proc_root: Arc<PathBuf>,
) {
    // The pcap pool is shared across all connections as claimable slots: a slot
    // belongs to the connection that took it until that connection's thread
    // ends, so an agent that restarts gives back every socket it held.
    let slots = PcapSlots::new((*pcap).clone(), net_ops::af_packet_available());
    if !slots.is_empty() {
        eprintln!(
            "[warden] pcap pool: {} socket(s), on-demand open {}",
            slots.len(),
            if slots.can_open_more() {
                "available"
            } else {
                "unavailable in this namespace"
            }
        );
    }
    for stream in listener.incoming() {
        match stream {
            Ok(conn) => {
                if peer_allowed(&conn, allowed_uid) {
                    let btf = Arc::clone(&btf);
                    let host = Arc::clone(&host);
                    let ext = ext.clone();
                    let slots = Arc::clone(&slots);
                    let proc_root = Arc::clone(&proc_root);
                    std::thread::spawn(move || {
                        handle_conn(
                            conn,
                            &Served {
                                btf: &btf,
                                pcap: &slots,
                                host: &*host,
                                ext: ext.as_deref(),
                                proc_root: &proc_root,
                            },
                        );
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
fn handle_conn(conn: UnixStream, served: &Served<'_>) {
    handle_conn_with_timeouts(conn, served, HANDSHAKE_TIMEOUT, IDLE_TIMEOUT);
}

/// What one connection is served out of: the resources the whole warden holds,
/// borrowed for the life of that connection.
///
/// They travel together because every one of them is decided once at startup
/// and read by the same command loop; passing them as a group keeps the two
/// entry points below honest about that.
#[derive(Clone, Copy)]
struct Served<'a> {
    /// The BTF fds handed out on delegation, by name.
    btf: &'a [(String, RawFd)],
    /// The capture-socket pool a connection claims slots from.
    pcap: &'a Arc<PcapSlots>,
    /// The host-network operations the warden brokers.
    host: &'a dyn HostOps,
    /// The downstream extension handler, when this build installs one.
    ext: Option<&'a dyn ExtHandler>,
    /// The procfs the DLP scan walks: `/proc` on a host, the read-only bind
    /// mount in a container that was not given the host pid namespace.
    proc_root: &'a Path,
}

/// [`handle_conn`] with both waits given rather than taken from the constants,
/// so a test can assert the closes without waiting out a production timeout.
fn handle_conn_with_timeouts(
    conn: UnixStream,
    served: &Served<'_>,
    handshake_timeout: Duration,
    idle_timeout: Duration,
) {
    let Served {
        btf,
        pcap,
        host,
        ext,
        proc_root,
    } = *served;
    // Every slot this connection claimed, held until the connection ends: the
    // agent's own pool keeps this connection open for its whole life, so the
    // sockets are in use for exactly as long as it is there to read them.
    let mut claimed: Vec<PcapSlot> = Vec::new();
    let mut reader = match conn.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    };
    let fd = conn.as_raw_fd();
    let mut writer = conn;

    if !matches!(wait_for_frame(fd, handshake_timeout), Waited::Readable) {
        eprintln!(
            "[warden] closing a connection that said nothing within {}s",
            handshake_timeout.as_secs()
        );
        return;
    }
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

    loop {
        match wait_for_frame(fd, idle_timeout) {
            Waited::Readable => {}
            Waited::TimedOut if claimed.is_empty() => {
                // Nothing of the warden's is held over this connection, so
                // closing it costs the agent one reconnect on its next call and
                // ends a thread that had nothing left to answer.
                eprintln!(
                    "[warden] closing a connection idle for {}s",
                    idle_timeout.as_secs()
                );
                return;
            }
            Waited::TimedOut => {
                // This connection is what the agent's capture sockets are held
                // against: dropping it on idleness would free slots the agent
                // is still reading from and hand the same socket to the next
                // caller. An idle pcap connection is the normal case, so it
                // waits as long as it takes.
                continue;
            }
            Waited::Failed => return,
        }
        let Ok(cmd) = read_frame::<_, Command>(&mut reader) else {
            break;
        };
        // `PcapOpen` answers out-of-band: an `FdReady` frame followed by a fd in an
        // `SCM_RIGHTS` cmsg, so it bypasses `dispatch`.
        let ok = match &cmd {
            Command::PcapOpen { iface, filter } => {
                eprintln!("[warden] pcap open on {iface} (filter applied agent-side: {filter:?})");
                if let Some(slot) = pcap.claim() {
                    // Serve a pre-opened socket: the warden may sit in a user
                    // namespace where `socket(AF_PACKET)` is denied, so the pool
                    // is the only way to capture rootlessly. The fd is dup'd into
                    // the agent by `SCM_RIGHTS`, so closing the agent's copy does
                    // not disturb the warden's.
                    eprintln!(
                        "[warden] pcap slot {} served ({} of {} held)",
                        slot.index(),
                        pcap.held(),
                        pcap.len()
                    );
                    let ok = serve_passed_fd(&mut writer, Ok(slot.fd()));
                    claimed.push(slot);
                    ok
                } else if pcap.can_open_more() {
                    // No pool (a bare-metal warden running as host root) or one
                    // that is spent, and this namespace can still open a socket:
                    // open one on demand.
                    match net_ops::open_pcap_fd(iface) {
                        Ok(owned) => {
                            let ok = serve_passed_fd(&mut writer, Ok(owned.as_raw_fd()));
                            drop(owned); // fd dup'd into the agent by SCM_RIGHTS; ours can close
                            ok
                        }
                        Err(message) => serve_passed_fd(&mut writer, Err(message)),
                    }
                } else {
                    // Nothing left and nothing openable: name the pool rather
                    // than returning the `EPERM` of an open that never works
                    // here, which reads as a broken warden instead of a full one.
                    let message = format!(
                        "no packet-capture socket available: {} of {} in use and this warden cannot open another",
                        pcap.held(),
                        pcap.len()
                    );
                    serve_passed_fd(&mut writer, Err(message))
                }
            }
            Command::Delegate => serve_delegate(&mut writer, btf, pcap.fds()),
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
            other => write_frame(&mut writer, &dispatch(other, host, proc_root)).is_ok(),
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
    // BTF fds first (in `btf_names` order), then the pcap fds - the order the
    // agent reconstructs from `Delegated`.
    let mut fds: Vec<RawFd> = btf.iter().map(|(_, fd)| *fd).collect();
    fds.extend_from_slice(pcap);
    send_msg_fds(writer.as_raw_fd(), &[0u8], &fds)
}

/// Serve an `AttachUprobe`: receive the agent's program fd (sent in an
/// `SCM_RIGHTS` cmsg right after the command frame), create the `uprobe_multi`
/// link, then reply `FdReady` + the link fd. The warden closes its own copy of
/// both the program fd and the link fd - the link fd is dup'd into the agent by
/// `SCM_RIGHTS` and the link keeps the program alive - so neither leaks.
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
fn dispatch(cmd: &Command, host: &dyn HostOps, proc_root: &Path) -> Response {
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
            targets: dlp_scan::scan_dlp_targets(proc_root),
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
    use super::{
        ExtHandler, HANDSHAKE_TIMEOUT, HostOps, IDLE_TIMEOUT, PcapSlots, Served, Waited,
        handle_conn, handle_conn_with_timeouts, wait_for_frame,
    };
    use ebpfsentinel_warden_proto::{
        Command, ConntrackTuple, PROTOCOL_VERSION, Response, RouteSpec, read_frame, write_frame,
    };
    use std::os::fd::{AsRawFd, RawFd};
    use std::os::unix::net::UnixStream;
    use std::path::Path;
    use std::sync::Arc;
    use std::thread::JoinHandle;
    use std::time::Duration;

    /// No host-network op is exercised by the extension tests - only the `Hello`
    /// handshake and `Extension` commands are sent - so every method is a stub.
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
            let host = NullHost;
            let slots = PcapSlots::new(Vec::new(), false);
            handle_conn(
                server,
                &Served {
                    btf: &[],
                    pcap: &slots,
                    host: &host,
                    ext: ext.as_deref(),
                    proc_root: Path::new("/proc"),
                },
            );
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

    /// Drive `handle_conn` against a shared slot pool on its own thread.
    fn run_server_with_slots(server: UnixStream, slots: Arc<PcapSlots>) -> JoinHandle<()> {
        std::thread::spawn(move || {
            let host = NullHost;
            handle_conn(
                server,
                &Served {
                    btf: &[],
                    pcap: &slots,
                    host: &host,
                    ext: None,
                    proc_root: Path::new("/proc"),
                },
            );
        })
    }

    /// One connection asking for one capture socket. The connection and its
    /// server thread are returned so the caller decides when the agent goes.
    struct Claim {
        client: UnixStream,
        server: JoinHandle<()>,
        response: Response,
        fd: Option<RawFd>,
    }

    /// Ask for a capture socket over a fresh connection.
    fn claim_over_connection(slots: &Arc<PcapSlots>) -> Claim {
        let (mut client, server) = UnixStream::pair().unwrap();
        let handle = run_server_with_slots(server, Arc::clone(slots));
        hello(&mut client);
        write_frame(
            &mut client,
            &Command::PcapOpen {
                iface: "lo".into(),
                filter: String::new(),
            },
        )
        .unwrap();
        let response: Response = read_frame(&mut client).unwrap();
        let fd = if response == Response::FdReady {
            let fd = crate::recv_fd(client.as_raw_fd());
            assert!(fd >= 0, "an FdReady is followed by a descriptor");
            Some(fd)
        } else {
            None
        };
        Claim {
            client,
            server: handle,
            response,
            fd,
        }
    }

    /// Close a received descriptor and let the agent's connection go, which is
    /// what the warden watches for to take its slot back.
    fn release(claim: Claim) {
        if let Some(fd) = claim.fd {
            // SAFETY: the fd was received over `SCM_RIGHTS` and is owned here.
            unsafe { libc::close(fd) };
        }
        drop(claim.client);
        claim.server.join().unwrap();
    }

    #[test]
    fn every_pool_slot_comes_back_when_its_connection_goes() {
        // Two real descriptors stand in for the pre-opened capture sockets: the
        // warden only ever passes them over `SCM_RIGHTS`, so any fd will do.
        let a = std::fs::File::open("/dev/null").unwrap();
        let b = std::fs::File::open("/dev/null").unwrap();
        let slots = PcapSlots::new(vec![a.as_raw_fd(), b.as_raw_fd()], false);

        let first = claim_over_connection(&slots);
        let second = claim_over_connection(&slots);
        assert_eq!(first.response, Response::FdReady);
        assert_eq!(second.response, Response::FdReady);
        assert_eq!(
            slots.held(),
            2,
            "both sockets are in use while both agents hold them"
        );

        // A third agent finds the pool spent and is told so, rather than meeting
        // the `EPERM` of an open this warden cannot perform.
        let third = claim_over_connection(&slots);
        match &third.response {
            Response::Error { message } => assert!(
                message.contains("2 of 2 in use"),
                "the error names the pool: {message}"
            ),
            other => panic!("expected an exhausted-pool error, got {other:?}"),
        }
        release(third);

        release(first);
        release(second);
        assert_eq!(
            slots.held(),
            0,
            "the connections going returns every socket they held"
        );

        // Which is what an agent restart is: the whole pool is claimable again.
        let again_first = claim_over_connection(&slots);
        let again_second = claim_over_connection(&slots);
        assert_eq!(again_first.response, Response::FdReady);
        assert_eq!(again_second.response, Response::FdReady);
        release(again_first);
        release(again_second);
    }

    /// Drive the connection handler with waits short enough to assert on.
    fn run_server_with_timeouts(
        server: UnixStream,
        handshake: Duration,
        idle: Duration,
    ) -> JoinHandle<()> {
        std::thread::spawn(move || {
            let host = NullHost;
            let slots = PcapSlots::new(Vec::new(), false);
            handle_conn_with_timeouts(
                server,
                &Served {
                    btf: &[],
                    pcap: &slots,
                    host: &host,
                    ext: None,
                    proc_root: Path::new("/proc"),
                },
                handshake,
                idle,
            );
        })
    }

    /// Read until the peer closes, so a test can tell "closed" from "still
    /// holding the thread" without blocking for ever on either.
    fn closed_by_peer(stream: &UnixStream) -> bool {
        use std::io::Read;
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("a read timeout");
        let mut byte = [0u8; 1];
        let mut stream = stream;
        matches!(stream.read(&mut byte), Ok(0))
    }

    #[test]
    fn a_peer_that_says_nothing_is_dropped() {
        let (client, server) = UnixStream::pair().expect("a socket pair");
        let handle =
            run_server_with_timeouts(server, Duration::from_millis(50), Duration::from_millis(50));
        assert!(
            closed_by_peer(&client),
            "a connection that never sent Hello must not keep a warden thread"
        );
        handle.join().expect("the handler returns");
    }

    #[test]
    fn an_idle_connection_holding_nothing_is_closed() {
        let (client, server) = UnixStream::pair().expect("a socket pair");
        let handle =
            run_server_with_timeouts(server, Duration::from_secs(5), Duration::from_millis(50));

        let mut writer = client.try_clone().expect("a writer");
        write_frame(
            &mut writer,
            &Command::Hello {
                version: PROTOCOL_VERSION,
            },
        )
        .expect("the handshake is sent");
        let mut reader = client.try_clone().expect("a reader");
        match read_frame::<_, Response>(&mut reader).expect("the handshake is answered") {
            Response::HelloOk { version } => assert_eq!(version, PROTOCOL_VERSION),
            other => panic!("unexpected handshake answer: {other:?}"),
        }

        assert!(
            closed_by_peer(&client),
            "an idle connection with no slot claimed must not hold a thread for ever"
        );
        handle.join().expect("the handler returns");
    }

    #[test]
    fn a_connection_with_a_frame_waiting_is_read_rather_than_timed_out() {
        use std::io::Write;
        let (mut client, server) = UnixStream::pair().expect("a socket pair");
        client.write_all(&[0u8]).expect("a byte on the wire");
        assert!(matches!(
            wait_for_frame(server.as_raw_fd(), Duration::from_millis(50)),
            Waited::Readable
        ));
    }

    #[test]
    fn a_silent_connection_times_out_rather_than_returning_readable() {
        let (_client, server) = UnixStream::pair().expect("a socket pair");
        assert!(matches!(
            wait_for_frame(server.as_raw_fd(), Duration::from_millis(50)),
            Waited::TimedOut
        ));
    }

    #[test]
    fn a_closed_peer_is_readable_so_the_read_reports_the_end() {
        let (client, server) = UnixStream::pair().expect("a socket pair");
        drop(client);
        assert!(
            matches!(
                wait_for_frame(server.as_raw_fd(), Duration::from_millis(50)),
                Waited::Readable
            ),
            "a hangup must reach the read, which ends the connection, not the timeout branch"
        );
    }

    #[test]
    fn an_idle_connection_holding_a_slot_is_kept() {
        // The agent's capture pool keeps its connection open and silent for the
        // whole run, and the warden holds the socket against that connection.
        // Closing it on idleness would free a socket the agent is still reading.
        let held = std::fs::File::open("/dev/null").expect("a fd to hand out");
        let (client, server) = UnixStream::pair().expect("a socket pair");
        let slots = PcapSlots::new(vec![held.as_raw_fd()], false);
        let handle = std::thread::spawn(move || {
            let host = NullHost;
            handle_conn_with_timeouts(
                server,
                &Served {
                    btf: &[],
                    pcap: &slots,
                    host: &host,
                    ext: None,
                    proc_root: Path::new("/proc"),
                },
                Duration::from_secs(5),
                Duration::from_millis(50),
            );
        });

        let mut writer = client.try_clone().expect("a writer");
        write_frame(
            &mut writer,
            &Command::Hello {
                version: PROTOCOL_VERSION,
            },
        )
        .expect("the handshake is sent");
        write_frame(
            &mut writer,
            &Command::PcapOpen {
                iface: "lo".into(),
                filter: String::new(),
            },
        )
        .expect("the open is sent");

        // Several idle timeouts' worth of silence, and the connection is still
        // there because a slot is claimed against it.
        client
            .set_read_timeout(Some(Duration::from_millis(400)))
            .expect("a read timeout");
        let mut sink = [0u8; 64];
        let mut reading = &client;
        loop {
            use std::io::Read;
            match reading.read(&mut sink) {
                // The handshake and the FdReady answer; keep draining.
                Ok(n) if n > 0 => continue,
                Ok(_) => panic!("the connection holding a capture socket was closed"),
                Err(e) => {
                    assert_eq!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock,
                        "the connection ended for another reason: {e}"
                    );
                    break;
                }
            }
        }

        // Every handle on the client end, the writer clone included: the
        // connection is gone for the warden only once the last fd closes,
        // which is how an agent returns the sockets it held.
        drop(writer);
        drop(client);
        handle
            .join()
            .expect("the handler returns once the peer goes");
        drop(held);
    }

    #[test]
    fn the_handshake_wait_is_the_shorter_of_the_two() {
        assert!(
            HANDSHAKE_TIMEOUT < IDLE_TIMEOUT,
            "a connection gets longer to sit idle than to introduce itself"
        );
    }
}
