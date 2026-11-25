//! The warden control-plane server loop.
//!
//! The `warden` binary is a privilege broker: it holds no maps and loads only
//! its guard on program loads, before this loop starts (the rootless agent
//! loads its own programs against the bpffs the warden delegates). This loop answers only the privileged operations the agent cannot
//! perform from its user namespace - bpffs delegation + module-BTF/pcap fd hand-off
//! (`Delegate`), an on-demand pcap capture socket (`PcapOpen`), the conntrack-table
//! read, conntrack teardown, route programming, and gratuitous ARP.

use std::cell::Cell;
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use ebpfsentinel_warden_proto::{
    Command, FIM_NO_WATCH, MAX_SHARE_SERVERS, PROTOCOL_VERSION, Response, TaskIdentity,
    read_command, write_frame,
};

use crate::fim_watch::FimWatch;
use crate::handed::{self, Handed, Ledger};
use crate::host_ops::HostOps;
use crate::pcap_slots::{PcapSlot, PcapSlots};
use crate::policy::WardenPolicy;
use crate::write_refusal;
use crate::{
    bpf_inventory, cgroup_ops, delegate_over_fd, dlp_scan, exe_read, facts_read, go_executables,
    held_programs, hidden_ports, hidden_processes, link_pins, namespace_ids, net_ops,
    netns_tcx_ops, packet_sockets, podman_connect, podman_store, process_maps, recv_fd,
    resolver_socket, root_runtime, rooted_read, send_msg_fds, served_peer,
};

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

/// Connections served at once when the deployment names no other number.
///
/// The agent keeps one connection per subsystem that talks to the warden,
/// some of them for its whole life (the capture pool, the file watch), and
/// about forty subsystems can; a short-lived command line call adds one.
pub const DEFAULT_MAX_CONNECTIONS: usize = 64;

/// The most connections a deployment may let one warden serve at once.
pub const MAX_CONNECTIONS_CEILING: usize = 256;

/// The connections being served, counted against a ceiling: past it the
/// warden does not accept, so the next connection waits in the listen
/// backlog until one closes rather than costing a thread.
struct Seats {
    taken: Mutex<usize>,
    freed: Condvar,
    max: usize,
}

/// One connection's place, given back when its thread ends.
struct Seat(Arc<Seats>);

impl Seats {
    fn new(max: usize) -> Arc<Self> {
        Arc::new(Self {
            taken: Mutex::new(0),
            freed: Condvar::new(),
            max,
        })
    }

    /// Wait for a free place and take it.
    fn take(self: &Arc<Self>) -> Seat {
        // A count that is only ever raised or lowered by one stays a count
        // after a panic between the two.
        let mut taken = self.taken.lock().unwrap_or_else(PoisonError::into_inner);
        if *taken >= self.max {
            eprintln!(
                "[warden] {} connections in use: the next waits until one closes",
                self.max
            );
        }
        while *taken >= self.max {
            taken = self
                .freed
                .wait(taken)
                .unwrap_or_else(PoisonError::into_inner);
        }
        *taken += 1;
        Seat(Arc::clone(self))
    }
}

impl Drop for Seat {
    fn drop(&mut self) {
        let mut taken = self.0.taken.lock().unwrap_or_else(PoisonError::into_inner);
        *taken = taken.saturating_sub(1);
        self.0.freed.notify_one();
    }
}

thread_local! {
    /// Whether the last answer written on this thread's connection was an
    /// error. Each connection has its own thread, so this is the
    /// connection's.
    static ANSWER_FAILED: Cell<bool> = const { Cell::new(false) };
}

/// Write `resp` on the connection and remember whether it reported a failure,
/// for the command's audit line.
fn reply(writer: &mut UnixStream, resp: &Response) -> io::Result<()> {
    if matches!(
        resp,
        Response::Error { .. } | Response::Unimplemented | Response::Refused { .. }
    ) {
        ANSWER_FAILED.with(|failed| failed.set(true));
    }
    write_frame(writer, resp)
}

/// How one command ended, as its audit line says it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Served,
    Refused,
    Failed,
}

impl Outcome {
    fn name(self) -> &'static str {
        match self {
            Self::Served => "served",
            Self::Refused => "refused",
            Self::Failed => "failed",
        }
    }
}

/// One line per command: what was asked, by which process, how it ended and
/// how long it took. Never a parameter: a path, an address or a payload stays
/// out of the log, so the line says what the agent did and not what it read.
fn audit(cmd: &Command, who: &str, outcome: Outcome, started: Instant) {
    eprintln!(
        "[warden] audit command={} family={} outcome={} {who} duration_ms={}",
        cmd.name(),
        cmd.family().map_or("none", |f| f.name()),
        outcome.name(),
        started.elapsed().as_millis()
    );
}

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
// The loop never returns, so the shared state is owned here for the life of
// the process; taking references would only move the same `Arc`s into the
// caller's frame.
///
/// `policy` decides which commands are served at all; it is read before any
/// handler runs and never changes for the life of the loop.
///
/// `max_connections` connections are served at once, at most
/// [`MAX_CONNECTIONS_CEILING`]; the next waits in the listen backlog.
#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
pub fn serve_loop(
    listener: &UnixListener,
    btf: Arc<Vec<(String, RawFd)>>,
    pcap: Arc<Vec<RawFd>>,
    host: Arc<dyn HostOps>,
    ext: Option<Arc<dyn ExtHandler>>,
    allowed_uid: u32,
    proc_root: Arc<PathBuf>,
    policy: Arc<WardenPolicy>,
    max_connections: usize,
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
    let ledger = Arc::new(Ledger::new());
    let seats = Seats::new(max_connections.clamp(1, MAX_CONNECTIONS_CEILING));
    loop {
        let seat = seats.take();
        match listener.accept() {
            Ok((conn, _)) => {
                if peer_allowed(&conn, allowed_uid) {
                    let btf = Arc::clone(&btf);
                    let host = Arc::clone(&host);
                    let ext = ext.clone();
                    let slots = Arc::clone(&slots);
                    let proc_root = Arc::clone(&proc_root);
                    let policy = Arc::clone(&policy);
                    let ledger = Arc::clone(&ledger);
                    std::thread::spawn(move || {
                        let _seat = seat;
                        handle_conn(
                            conn,
                            &Served {
                                btf: &btf,
                                pcap: &slots,
                                host: &*host,
                                ext: ext.as_deref(),
                                proc_root: &proc_root,
                                policy: &policy,
                                handed: &ledger,
                            },
                        );
                    });
                }
            }
            Err(e) => eprintln!("[warden] accept: {e}"),
        }
    }
}

/// The uid of the process at the other end of `conn`, read via `SO_PEERCRED`
/// (the stable-Rust path; `UnixStream::peer_cred` is still nightly).
pub(crate) fn peer_uid(conn: &UnixStream) -> Option<u32> {
    peer_cred(conn).map(|cred| cred.uid)
}

/// The credentials of the process at the other end of `conn`.
fn peer_cred(conn: &UnixStream) -> Option<libc::ucred> {
    // SAFETY: `ucred` is plain old data, for which all-zero is valid.
    let mut cred: libc::ucred = unsafe { mem::zeroed() };
    let mut len = mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `cred` and `len` are live and `len` holds the size of `cred`, so the kernel
    // writes inside it.
    let rc = unsafe {
        libc::getsockopt(
            conn.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            ptr::from_mut(&mut cred).cast(),
            &raw mut len,
        )
    };
    (rc == 0).then_some(cred)
}

/// Confirm the connected peer's uid matches the one the warden serves.
fn peer_allowed(conn: &UnixStream, allowed_uid: u32) -> bool {
    let Some(uid) = peer_uid(conn) else {
        eprintln!("[warden] getsockopt(SO_PEERCRED) failed");
        return false;
    };
    if uid == allowed_uid {
        true
    } else {
        eprintln!("[warden] rejecting peer uid {uid} (expected {allowed_uid})");
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
    /// What this warden serves, read once at start.
    policy: &'a WardenPolicy,
    /// What each agent process was handed, for the things handed once.
    handed: &'a Ledger,
}

/// [`handle_conn`] with both waits given rather than taken from the constants,
/// so a test can assert the closes without waiting out a production timeout.
// One connection's whole life, handshake to close, kept in one body so the
// slots it claims and the timeouts that end it read in the same place.
#[allow(clippy::too_many_lines)]
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
        policy,
        handed,
    } = *served;
    // The process at the other end, for what is handed once per process. A
    // peer the kernel names no pidfd for is served everything else and
    // refused those.
    let peer = handed::Peer::of(&conn).map_err(|e| format!("the agent's pidfd: {e}"));
    // Who every audit line of this connection names: the pid as this warden
    // sees it and the process identity the ledger counts by.
    let who = format!(
        "pid={} process={}",
        peer_cred(&conn).map_or_else(|| "unknown".into(), |c| c.pid.to_string()),
        peer.as_ref()
            .map_or_else(|_| "unknown".into(), |p| p.id().to_string())
    );
    // Every slot this connection claimed, held until the connection ends: the
    // agent's own pool keeps this connection open for its whole life, so the
    // sockets are in use for exactly as long as it is there to read them.
    let mut claimed: Vec<PcapSlot> = Vec::new();
    // The file watch this connection opened, closed with it: the agent's
    // watcher keeps one connection for the watch and reads it in a loop.
    let mut fim: Option<FimWatch> = None;
    let Ok(mut reader) = conn.try_clone() else {
        return;
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
    let Ok(first) = read_command(&mut reader) else {
        return;
    };
    match first {
        Command::Hello { version } if version == PROTOCOL_VERSION => {
            if reply(
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
            let _ = reply(&mut writer, &Response::Error { message });
            return;
        }
        _ => {
            let _ = reply(
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
            Waited::TimedOut if claimed.is_empty() && fim.is_none() => {
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
        let cmd = match read_command(&mut reader) {
            Ok(cmd) => cmd,
            Err(e) => {
                if e.kind() != io::ErrorKind::UnexpectedEof {
                    eprintln!("[warden] closing a connection whose frame was refused: {e}");
                }
                break;
            }
        };
        let started = Instant::now();
        ANSWER_FAILED.with(|failed| failed.set(false));
        // The policy is checked before any handler runs: a refused command
        // touches nothing on the host. A descriptor the agent sent with it is
        // still taken off the socket and closed, so it is not read as the
        // next command's.
        if let Err(refusal) = policy.check(&cmd) {
            if cmd.sends_fd() {
                let stray = recv_fd(writer.as_raw_fd());
                if stray >= 0 {
                    // SAFETY: the fd arrived over `SCM_RIGHTS` for this one
                    // refused request and nothing else holds this number.
                    unsafe { libc::close(stray) };
                }
            }
            eprintln!("[warden] refused ({}): {}", refusal.family, refusal.reason);
            audit(&cmd, &who, Outcome::Refused, started);
            let resp = Response::Refused {
                family: refusal.family,
                reason: refusal.reason,
            };
            if reply(&mut writer, &resp).is_err() {
                break;
            }
            continue;
        }
        // What is handed once per agent process is refused a second time
        // before any handler runs, like a refused family.
        if let Some(what) = handed_once(&cmd) {
            let taken = peer
                .as_ref()
                .map_err(Clone::clone)
                .and_then(|peer| handed.take(peer, what));
            if let Err(message) = taken {
                eprintln!("[warden] refused: {message}");
                audit(&cmd, &who, Outcome::Refused, started);
                if !refuse_handed(&mut writer, &cmd, message) {
                    break;
                }
                continue;
            }
        }
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
            Command::Delegate => {
                crate::load_guard::before_delegation();
                serve_delegate(&mut writer, btf, pcap.fds())
            }
            Command::ArmLoadGuard => {
                let status = crate::load_guard::arm(peer.as_ref().ok());
                reply(
                    &mut writer,
                    &Response::LoadGuardState {
                        load_guard: status.into_proto(),
                    },
                )
                .is_ok()
            }
            Command::WriteRefusalGroup => match write_refusal::permission_group() {
                Ok(group) => {
                    eprintln!("[warden] write refusal group handed over");
                    // The warden's copy closes here, once sent: the agent's
                    // is the group's only descriptor, so its stop or its
                    // death allows every open still waiting.
                    serve_passed_fd(&mut writer, Ok(group.as_raw_fd()))
                }
                Err(message) => {
                    eprintln!("[warden] write refusal group refused: {message}");
                    serve_passed_fd(&mut writer, Err(message))
                }
            },
            // `OpenExecutable` answers out-of-band: the descriptor of the file
            // the process runs, opened read-only, after an `FdReady`.
            Command::OpenExecutable { pid } => {
                match exe_read::open_executable(proc_root, *pid) {
                    Ok(file) => {
                        // Dup'd into the agent by `SCM_RIGHTS`; ours closes here.
                        serve_passed_fd(&mut writer, Ok(file.as_raw_fd()))
                    }
                    Err(message) => serve_passed_fd(&mut writer, Err(message)),
                }
            }
            // `ConnectPodman` answers out-of-band: the agent's end of a relay
            // to one user's rootless Podman API, after an `FdReady`. The
            // relay is the root runtime's, so a user's runtime is asked the
            // same reads and answers through the same projection: one call of
            // that API starts a container as that user.
            Command::ConnectPodman { uid } => {
                match podman_connect::connect(Path::new(podman_connect::RUN_USER_ROOT), *uid)
                    .and_then(|stream| {
                        root_runtime::relay_to(stream, format!("the Podman API of uid {uid}"))
                    }) {
                    Ok(stream) => {
                        // Dup'd into the agent by `SCM_RIGHTS`; ours closes here.
                        serve_passed_fd(&mut writer, Ok(stream.as_raw_fd()))
                    }
                    Err(message) => {
                        eprintln!("[warden] podman connect for uid {uid} refused: {message}");
                        serve_passed_fd(&mut writer, Err(message))
                    }
                }
            }
            // `ConnectRootRuntime` answers out-of-band: the agent's end of a
            // relay that forwards only the reads it makes, after an `FdReady`.
            Command::ConnectRootRuntime { runtime } => {
                match root_runtime::open(Path::new(runtime.socket()), 0) {
                    Ok(stream) => {
                        // Dup'd into the agent by `SCM_RIGHTS`; ours closes here.
                        serve_passed_fd(&mut writer, Ok(stream.as_raw_fd()))
                    }
                    Err(message) => {
                        eprintln!("[warden] {runtime:?} connect refused: {message}");
                        serve_passed_fd(&mut writer, Err(message))
                    }
                }
            }
            // `ResolverSocket` answers out-of-band: the bound socket, after
            // an `FdReady`.
            Command::ResolverSocket { listen, stream } => {
                match resolver_socket::bind(*listen, *stream) {
                    Ok(socket) => serve_passed_fd(&mut writer, Ok(socket.as_raw_fd())),
                    Err(message) => {
                        eprintln!("[warden] resolver socket on {listen} refused: {message}");
                        serve_passed_fd(&mut writer, Err(message))
                    }
                }
            }
            // `PinLink` takes the link fd that follows the frame and answers
            // `Ok` once it is pinned on the host bpffs.
            Command::PinLink { name } => {
                let link_fd = recv_fd(writer.as_raw_fd());
                let resp = if link_fd < 0 {
                    Response::Error {
                        message: "no link fd received for the pin".into(),
                    }
                } else {
                    let pinned = link_pins::pin(&link_pins::pin_dir(), name, link_fd);
                    // SAFETY: the fd arrived over `SCM_RIGHTS` for this one
                    // request and is owned here; the pin holds the link now.
                    unsafe { libc::close(link_fd) };
                    match pinned {
                        Ok(()) => Response::Ok,
                        Err(message) => {
                            eprintln!("[warden] link pin {name:?} refused: {message}");
                            Response::Error { message }
                        }
                    }
                };
                reply(&mut writer, &resp).is_ok()
            }
            // `OpenPinnedLink` answers out-of-band: the link, after an
            // `FdReady`.
            Command::OpenPinnedLink { name } => {
                match link_pins::open(&link_pins::pin_dir(), name) {
                    Ok(link) => serve_passed_fd(&mut writer, Ok(link.as_raw_fd())),
                    Err(message) => serve_passed_fd(&mut writer, Err(message)),
                }
            }
            Command::FimOpen { paths } => {
                let (watch, marks) = FimWatch::open(paths);
                for mark in &marks {
                    match &mark.error {
                        None => eprintln!("[warden] file watch marked {}", mark.path),
                        Some(reason) => {
                            eprintln!("[warden] file watch not marked on {}: {reason}", mark.path);
                        }
                    }
                }
                fim = watch;
                reply(&mut writer, &Response::FimOpened { marks }).is_ok()
            }
            Command::FimRead { max_wait_ms } => {
                let resp = match fim.as_mut() {
                    Some(watch) => {
                        match watch.read(Duration::from_millis(u64::from(*max_wait_ms))) {
                            Ok((events, overflowed)) => Response::FimEvents { events, overflowed },
                            Err(message) => Response::Error { message },
                        }
                    }
                    None => Response::Error {
                        message: FIM_NO_WATCH.into(),
                    },
                };
                reply(&mut writer, &resp).is_ok()
            }
            Command::FimCanaries { paths } => {
                let resp = match fim.as_mut() {
                    Some(watch) => {
                        let canaries = watch.plant(paths);
                        let refused = canaries.iter().filter(|c| c.error.is_some()).count();
                        eprintln!(
                            "[warden] file watch planted {} of {} canaries",
                            canaries.len() - refused,
                            canaries.len()
                        );
                        Response::FimCanaries { canaries }
                    }
                    None => Response::Error {
                        message: FIM_NO_WATCH.into(),
                    },
                };
                reply(&mut writer, &resp).is_ok()
            }
            Command::FimFacts {
                paths,
                max_hash_bytes,
            } => {
                let resp = match fim.as_ref() {
                    Some(watch) => Response::FimFactsRead {
                        facts: crate::file_facts::read_facts(paths, *max_hash_bytes, &|fsid| {
                            watch.covers(fsid)
                        }),
                    },
                    None => Response::Error {
                        message: FIM_NO_WATCH.into(),
                    },
                };
                reply(&mut writer, &resp).is_ok()
            }
            // `HoldProgram` takes the program fd that follows the frame and
            // answers `Ok` once it is held.
            Command::HoldProgram { name } => {
                let prog_fd = recv_fd(writer.as_raw_fd());
                let resp = if prog_fd < 0 {
                    Response::Error {
                        message: "no program fd received for the hold".into(),
                    }
                } else {
                    let held = held_programs::hold(&held_programs::held_dir(), name, prog_fd);
                    // SAFETY: the fd arrived over `SCM_RIGHTS` for this one
                    // request and is owned here; the pin holds the program now.
                    unsafe { libc::close(prog_fd) };
                    match held {
                        Ok(()) => Response::Ok,
                        Err(message) => {
                            eprintln!("[warden] hold of {name:?} refused: {message}");
                            Response::Error { message }
                        }
                    }
                };
                reply(&mut writer, &resp).is_ok()
            }
            // The attaches of a held program answer out-of-band: `FdReady`
            // and the link, or a typed `Error`.
            Command::AttachHeld { program } => {
                let link = held_programs::attach(&held_programs::held_dir(), program);
                serve_owned_link(&mut writer, program, link)
            }
            Command::AttachUprobe {
                program,
                path,
                offset,
            } => {
                let link = held_programs::attach_uprobe(
                    &held_programs::held_dir(),
                    program,
                    path,
                    *offset,
                );
                serve_owned_link(&mut writer, program, link)
            }
            // `AttachCgroup` answers the same way, with a cgroup directory in
            // place of an ELF offset.
            Command::AttachCgroup {
                cgroup_path,
                attach_type,
            } => serve_attach_cgroup(&mut writer, cgroup_path, *attach_type),
            // `AttachTcxInNetns` answers the same way, with a pod's process and
            // one of its interfaces in place of a cgroup directory.
            Command::AttachTcxInNetns { pid, iface, egress } => {
                serve_attach_tcx_in_netns(&mut writer, proc_root, *pid, iface, *egress)
            }
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
                reply(&mut writer, &resp).is_ok()
            }
            other => reply(&mut writer, &dispatch(other, host, proc_root)).is_ok(),
        };
        let outcome = if ANSWER_FAILED.with(Cell::get) {
            Outcome::Failed
        } else {
            Outcome::Served
        };
        audit(&cmd, &who, outcome, started);
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
            if reply(writer, &Response::FdReady).is_err() {
                return false;
            }
            // One sentinel payload byte carries the fd; the agent reads `FdReady`,
            // then recvmsg's exactly this byte to collect the descriptor.
            send_msg_fds(writer.as_raw_fd(), &[0u8], &[fd])
        }
        Err(message) => reply(writer, &Response::Error { message }).is_ok(),
    }
}

/// The handed-once record a command takes, if it takes one.
fn handed_once(cmd: &Command) -> Option<Handed> {
    match cmd {
        Command::Delegate => Some(Handed::Delegation),
        Command::WriteRefusalGroup => Some(Handed::WriteRefusalGroup),
        Command::ResolverSocket { listen, stream } => Some(Handed::ResolverSocket {
            listen: *listen,
            stream: *stream,
        }),
        Command::PcapOpen { .. } => Some(Handed::CaptureSocket),
        _ => None,
    }
}

/// Answer a handed-once command refused a second time the way its own handler
/// answers a failure: `Delegate` with an `Error` once the bpffs descriptor it
/// carries is taken off the socket and closed, the others with the `Error`
/// their out-of-band answer gives.
fn refuse_handed(writer: &mut UnixStream, cmd: &Command, message: String) -> bool {
    if cmd.sends_fd() {
        let stray = recv_fd(writer.as_raw_fd());
        if stray >= 0 {
            // SAFETY: the fd arrived over `SCM_RIGHTS` for this one refused
            // request and nothing else holds this number.
            unsafe { libc::close(stray) };
        }
    }
    match cmd {
        Command::Delegate => reply(writer, &Response::Error { message }).is_ok(),
        _ => serve_passed_fd(writer, Err(message)),
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
        return reply(
            writer,
            &Response::Error {
                message: "no bpffs fd received for delegation".into(),
            },
        )
        .is_ok();
    }
    let ok = delegate_over_fd(fs);
    // SAFETY: the fd arrived over `SCM_RIGHTS` for this one request and is owned here; nothing
    // uses it after this close.
    unsafe { libc::close(fs) };
    if !ok {
        return reply(
            writer,
            &Response::Error {
                message: "bpffs delegation refused by the kernel; the warden log names the option"
                    .into(),
            },
        )
        .is_ok();
    }
    let btf_names: Vec<String> = btf.iter().map(|(name, _)| name.clone()).collect();
    let resp = Response::Delegated {
        btf_names,
        pcap_count: u32::try_from(pcap.len()).unwrap_or(0),
        loader_keyring: crate::loader_keyring::installed(),
        load_guard: crate::load_guard::installed().into_proto(),
    };
    if reply(writer, &resp).is_err() {
        return false;
    }
    // BTF fds first (in `btf_names` order), then the pcap fds - the order the
    // agent reconstructs from `Delegated`.
    let mut fds: Vec<RawFd> = btf.iter().map(|(_, fd)| *fd).collect();
    fds.extend_from_slice(pcap);
    send_msg_fds(writer.as_raw_fd(), &[0u8], &fds)
}

/// Answer an attach of a held program with the link, closed here once the
/// agent holds its own copy.
fn serve_owned_link(
    writer: &mut UnixStream,
    program: &str,
    link: Result<std::os::fd::OwnedFd, String>,
) -> bool {
    match link {
        Ok(link) => serve_passed_fd(writer, Ok(link.as_raw_fd())),
        Err(message) => {
            eprintln!("[warden] attach of {program:?} refused: {message}");
            serve_passed_fd(writer, Err(message))
        }
    }
}

/// Serve an `AttachCgroup`: receive the agent's program fd, create the cgroup
/// link, then reply `FdReady` + the link fd. The warden closes its own copy of
/// both fds - the link fd is dup'd into the agent by `SCM_RIGHTS` and the link
/// keeps the program alive - so neither leaks.
fn serve_attach_cgroup(writer: &mut UnixStream, cgroup_path: &str, attach_type: u32) -> bool {
    let prog_fd = recv_fd(writer.as_raw_fd());
    if prog_fd < 0 {
        return reply(
            writer,
            &Response::Error {
                message: "no program fd received for cgroup attach".into(),
            },
        )
        .is_ok();
    }
    let result = cgroup_ops::attach_cgroup_link(prog_fd, cgroup_path, attach_type);
    // SAFETY: the fd arrived over `SCM_RIGHTS` for this one request and is owned here; nothing
    // uses it after this close.
    unsafe { libc::close(prog_fd) };
    match result {
        Ok(link) => {
            let ok = serve_passed_fd(writer, Ok(link));
            // SAFETY: `link` was created for this request and the agent now holds its own copy,
            // sent over `SCM_RIGHTS`; this handler uses it no further.
            unsafe { libc::close(link) };
            ok
        }
        Err(message) => serve_passed_fd(writer, Err(message)),
    }
}

/// Serve an `AttachTcxInNetns`: receive the agent's program fd, create the
/// TCX link inside the pod's namespace, then reply `FdReady` + the link fd.
/// The warden closes its own copy of both fds, as for a cgroup attach.
fn serve_attach_tcx_in_netns(
    writer: &mut UnixStream,
    proc_root: &Path,
    pid: u32,
    iface: &str,
    egress: bool,
) -> bool {
    let prog_fd = recv_fd(writer.as_raw_fd());
    if prog_fd < 0 {
        return reply(
            writer,
            &Response::Error {
                message: "no program fd received for a pod namespace attach".into(),
            },
        )
        .is_ok();
    }
    let result = netns_tcx_ops::attach_tcx_in_netns(prog_fd, proc_root, pid, iface, egress);
    // SAFETY: the fd arrived over `SCM_RIGHTS` for this one request and is owned here; nothing
    // uses it after this close.
    unsafe { libc::close(prog_fd) };
    match result {
        Ok(link) => {
            eprintln!(
                "[warden] tcx {} attached on {iface} inside the namespace of pid {pid}",
                if egress { "egress" } else { "ingress" }
            );
            let ok = serve_passed_fd(writer, Ok(link));
            // SAFETY: `link` was created for this request and the agent now holds its own copy,
            // sent over `SCM_RIGHTS`; this handler uses it no further.
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
        Command::ConntrackRestore { restore } => {
            result_to_response(host.conntrack_restore(restore))
        }
        Command::ConntrackFlush => result_to_response(host.conntrack_flush()),
        Command::RouteAdd { route } => result_to_response(host.route_add(route)),
        Command::ArpAnnounce { iface, ip } => result_to_response(host.arp_announce(iface, ip)),
        Command::TcxChain { iface, egress } => match host.tcx_chain(iface, *egress) {
            Ok(prog_ids) => Response::TcxChain { prog_ids },
            Err(message) => Response::Error { message },
        },
        Command::PinnedLinks => match link_pins::list(&link_pins::pin_dir()) {
            Ok(names) => Response::PinnedLinks { names },
            Err(message) => Response::Error { message },
        },
        Command::UnpinLinks { names } => match link_pins::unpin(&link_pins::pin_dir(), names) {
            Ok(removed) => {
                eprintln!("[warden] {removed} link pin(s) removed");
                Response::Ok
            }
            Err(message) => Response::Error { message },
        },
        Command::DlpScan => Response::DlpTargets {
            targets: dlp_scan::scan_dlp_targets(proc_root),
        },
        Command::ReadExecutable { pid } => Response::Executable {
            executable: exe_read::read_executable(proc_root, *pid),
        },
        Command::ReadProcessFacts { pid } => Response::ProcessFacts {
            facts: facts_read::read_facts(proc_root, *pid),
        },
        Command::ReadServedPeer { pid } => Response::ServedPeer {
            peer: served_peer::read(proc_root, *pid),
        },
        Command::ReadShareWriters { servers } => Response::ShareWriters {
            pids: served_peer::share_writers(
                proc_root,
                &servers[..servers.len().min(MAX_SHARE_SERVERS)],
            ),
        },
        Command::PacketSockets => Response::PacketSockets {
            sockets: packet_sockets::scan(proc_root),
        },
        Command::HiddenPorts { ports } => Response::HiddenPorts {
            namespaces: hidden_ports::scan(proc_root, ports),
        },
        Command::NamespaceIds => Response::NamespaceIds {
            namespaces: namespace_ids::scan(proc_root),
        },
        Command::HiddenProcesses { rate } => Response::HiddenProcesses {
            reading: hidden_processes::scan(proc_root, *rate),
        },
        Command::FileRoots => Response::FileRoots {
            roots: rooted_read::file_roots(proc_root),
        },
        Command::ReadRootedFile {
            pid,
            file,
            offset,
            len,
        } => Response::RootedRead {
            read: rooted_read::read_rooted_file(proc_root, *pid, file, *offset, *len),
        },
        Command::ReadPodmanRecord { uid, store, id } => Response::PodmanRecord {
            read: podman_store::read(Path::new(podman_store::PASSWD), *uid, store, id),
        },
        Command::GoExecutables => Response::GoExecutables {
            scan: go_executables::scan(proc_root),
        },
        Command::OpenerReadings { tids } => Response::OpenerReadings {
            readings: write_refusal::read_openers(proc_root, tids),
        },
        Command::ProcessMappings { known } => Response::ProcessMappings {
            scan: process_maps::scan(proc_root, known),
        },
        Command::NetworkPrograms => match bpf_inventory::scan(proc_root) {
            Ok(programs) => Response::NetworkPrograms { programs },
            Err(message) => Response::Error { message },
        },
        Command::Identity => match TaskIdentity::of_self() {
            Ok(identity) => Response::Identity { identity },
            Err(e) => Response::Error {
                message: format!("the warden's pid namespace is unreadable: {e}"),
            },
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
        WardenPolicy, handle_conn, handle_conn_with_timeouts, wait_for_frame,
    };
    use ebpfsentinel_warden_proto::{
        Command, ConntrackRestore, ConntrackTuple, Family, PROTOCOL_VERSION, Response, RouteSpec,
        read_frame, write_frame,
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
        fn conntrack_restore(&self, _restore: &ConntrackRestore) -> Result<(), String> {
            Err("unused".into())
        }
        fn route_add(&self, _route: &RouteSpec) -> Result<(), String> {
            Err("unused".into())
        }
        fn arp_announce(&self, _iface: &str, _ip: &str) -> Result<(), String> {
            Err("unused".into())
        }
        fn tcx_chain(&self, iface: &str, egress: bool) -> Result<Vec<u32>, String> {
            match (iface, egress) {
                ("eth0", false) => Ok(vec![41, 7]),
                _ => Err(format!("no chain on {iface}")),
            }
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

    /// The policy `run_server` serves: the extension kinds the tests send,
    /// every other family off.
    fn test_policy() -> WardenPolicy {
        WardenPolicy {
            package_inventory: true,
            extensions: vec!["echo".into(), "boom".into(), "mystery".into()],
            ..WardenPolicy::default()
        }
    }

    /// Drive `handle_conn` on the server end of a socket pair on its own thread.
    fn run_server(server: UnixStream, ext: Option<Arc<dyn ExtHandler>>) -> JoinHandle<()> {
        run_server_at(server, ext, Path::new("/proc").to_path_buf())
    }

    /// `run_server` reading processes under `proc_root`.
    fn run_server_at(
        server: UnixStream,
        ext: Option<Arc<dyn ExtHandler>>,
        proc_root: std::path::PathBuf,
    ) -> JoinHandle<()> {
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
                    proc_root: &proc_root,
                    policy: &test_policy(),
                    handed: &crate::handed::Ledger::new(),
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

    /// Every command the other tests leave out, sent over the wire to a warden
    /// reading an empty process tree: each is answered with its own response
    /// or an error naming what it could not do, and the connection stays
    /// open for the next. Nothing here touches the host: the readers find no
    /// process, the link pin names are refused before a path is built, and the
    /// cgroup attach arrives without its program.
    #[test]
    fn the_commands_no_other_test_sends_are_answered_over_the_wire() {
        let procs = tempfile::tempdir().unwrap();
        let (mut client, server) = UnixStream::pair().unwrap();
        let handle = run_server_at(server, None, procs.path().to_path_buf());
        hello(&mut client);
        let ask = |client: &mut UnixStream, cmd: &Command| -> Response {
            write_frame(client, cmd).unwrap();
            read_frame(client).unwrap()
        };
        let tuple = ConntrackTuple {
            proto: 6,
            src_ip: "192.0.2.1".into(),
            dst_ip: "192.0.2.2".into(),
            src_port: 1,
            dst_port: 2,
        };
        // The fake host answers every conntrack call `unused`: the command
        // reached it.
        assert_eq!(
            ask(&mut client, &Command::ConntrackDelete { tuple }),
            Response::Error {
                message: "unused".into()
            }
        );
        for cmd in [
            Command::ReadRootedFile {
                pid: 1,
                file: ebpfsentinel_warden_proto::RootedFile::DpkgStatus,
                offset: 0,
                len: 16,
            },
            Command::OpenerReadings { tids: vec![1] },
            Command::ReadProcessFacts { pid: 1 },
            Command::ReadServedPeer { pid: 1 },
            Command::ReadShareWriters {
                servers: vec![std::net::IpAddr::from([192, 0, 2, 20])],
            },
        ] {
            let resp = ask(&mut client, &cmd);
            assert!(
                !matches!(
                    resp,
                    Response::Error { .. } | Response::Refused { .. } | Response::Unimplemented
                ),
                "{}: {resp:?}",
                cmd.name()
            );
        }
        for cmd in [
            Command::OpenExecutable { pid: 1 },
            Command::OpenPinnedLink {
                name: "../x".into(),
            },
            Command::UnpinLinks {
                names: vec!["../x".into()],
            },
        ] {
            let resp = ask(&mut client, &cmd);
            assert!(
                matches!(resp, Response::Error { .. }),
                "{}: {resp:?}",
                cmd.name()
            );
        }
        write_frame(
            &mut client,
            &Command::AttachCgroup {
                cgroup_path: "/sys/fs/cgroup".into(),
                attach_type: 0,
            },
        )
        .unwrap();
        // The byte that would carry the program descriptor, without it.
        std::io::Write::write_all(&mut client, b"x").unwrap();
        let resp: Response = read_frame(&mut client).unwrap();
        assert!(
            matches!(&resp, Response::Error { message } if message.contains("no program fd")),
            "{resp:?}"
        );
        drop(client);
        handle.join().unwrap();
    }

    #[test]
    fn a_full_house_waits_for_a_connection_to_close() {
        let seats = super::Seats::new(1);
        let first = seats.take();
        let waiting = {
            let seats = Arc::clone(&seats);
            std::thread::spawn(move || drop(seats.take()))
        };
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            !waiting.is_finished(),
            "the second waits while the first is served"
        );
        drop(first);
        waiting.join().unwrap();
    }

    #[test]
    fn an_oversized_control_frame_closes_the_connection_unread() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let handle = run_server(server, None);
        hello(&mut client);
        // A length past the control bound and a `PinLink` tag; no body
        // follows, and none is waited for.
        let mut encoded = Vec::new();
        write_frame(&mut encoded, &Command::PinLink { name: "x".into() }).unwrap();
        let tag = encoded[4];
        let mut frame = (ebpfsentinel_warden_proto::CONTROL_FRAME_LEN + 1)
            .to_le_bytes()
            .to_vec();
        frame.extend_from_slice(&[tag, 0, 0, 0, 0]);
        std::io::Write::write_all(&mut client, &frame).unwrap();
        handle.join().unwrap();
        assert!(read_frame::<_, Response>(&mut client).is_err());
    }

    #[test]
    fn an_answer_that_reports_an_error_is_audited_as_failed() {
        super::ANSWER_FAILED.with(|f| f.set(false));
        let (mut a, _b) = UnixStream::pair().unwrap();
        super::reply(&mut a, &Response::Ok).unwrap();
        assert!(!super::ANSWER_FAILED.with(std::cell::Cell::get));
        super::reply(
            &mut a,
            &Response::Error {
                message: "no".into(),
            },
        )
        .unwrap();
        assert!(super::ANSWER_FAILED.with(std::cell::Cell::get));
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

    /// Send one `TcxChain` and read its response.
    fn one_tcx_chain(iface: &str, egress: bool) -> Response {
        let (mut client, server) = UnixStream::pair().unwrap();
        let handle = run_server(server, None);
        hello(&mut client);
        write_frame(
            &mut client,
            &Command::TcxChain {
                iface: iface.into(),
                egress,
            },
        )
        .unwrap();
        let resp: Response = read_frame(&mut client).unwrap();
        drop(client);
        handle.join().unwrap();
        resp
    }

    #[test]
    fn tcx_chain_answers_the_ids_in_run_order() {
        assert_eq!(
            one_tcx_chain("eth0", false),
            Response::TcxChain {
                prog_ids: vec![41, 7]
            }
        );
    }

    #[test]
    fn tcx_chain_failure_is_an_error_naming_it() {
        assert_eq!(
            one_tcx_chain("eth0", true),
            Response::Error {
                message: "no chain on eth0".into()
            }
        );
    }

    #[test]
    fn a_namespace_attach_outside_a_pod_is_refused_over_the_wire() {
        // The init process: its namespace is the host's, and a broker that
        // entered it on request would be a host attach service.
        let (mut client, server) = UnixStream::pair().unwrap();
        let handle = run_server(server, None);
        hello(&mut client);
        write_frame(
            &mut client,
            &Command::AttachTcxInNetns {
                pid: 1,
                iface: "eth0".into(),
                egress: false,
            },
        )
        .unwrap();
        let program = std::fs::File::open("/dev/null").unwrap();
        assert!(crate::send_fd(client.as_raw_fd(), program.as_raw_fd()));
        let resp: Response = read_frame(&mut client).unwrap();
        drop(client);
        handle.join().unwrap();
        match resp {
            Response::Error { message } => {
                assert!(message.contains("not a pod's process"), "{message}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn an_extension_kind_the_policy_does_not_name_is_refused() {
        let resp = one_extension(Some(Arc::new(FakeExt)), "other", vec![]);
        match resp {
            Response::Refused { family, .. } => assert_eq!(family, Family::Extension),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_refused_command_carrying_a_descriptor_leaves_the_connection_in_step() {
        // A hold of a name the warden does not hold is refused: the warden
        // takes the descriptor off the socket, and the next command is read
        // as itself.
        let (mut client, server) = UnixStream::pair().unwrap();
        let handle = run_server(server, None);
        hello(&mut client);
        write_frame(
            &mut client,
            &Command::HoldProgram {
                name: "xdp_firewall".into(),
            },
        )
        .unwrap();
        let program = std::fs::File::open("/dev/null").unwrap();
        assert!(crate::send_fd(client.as_raw_fd(), program.as_raw_fd()));
        let resp: Response = read_frame(&mut client).unwrap();
        match resp {
            Response::Error { message } => {
                assert!(
                    message.contains("not a program the warden holds"),
                    "{message}"
                );
            }
            other => panic!("expected an error, got {other:?}"),
        }
        write_frame(
            &mut client,
            &Command::TcxChain {
                iface: "eth0".into(),
                egress: false,
            },
        )
        .unwrap();
        let resp: Response = read_frame(&mut client).unwrap();
        drop(client);
        handle.join().unwrap();
        assert_eq!(
            resp,
            Response::TcxChain {
                prog_ids: vec![41, 7]
            }
        );
    }

    #[test]
    fn a_route_to_an_unconfigured_gateway_never_reaches_the_host() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let handle = run_server(server, None);
        hello(&mut client);
        write_frame(
            &mut client,
            &Command::RouteAdd {
                route: RouteSpec {
                    dst_cidr: "0.0.0.0/0".into(),
                    gateway: "203.0.113.1".into(),
                    iface: "eth0".into(),
                    table: 254,
                },
            },
        )
        .unwrap();
        let resp: Response = read_frame(&mut client).unwrap();
        drop(client);
        handle.join().unwrap();
        match resp {
            Response::Refused { family, .. } => assert_eq!(family, Family::Routing),
            other => panic!("expected a refusal, got {other:?}"),
        }
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
                    policy: &WardenPolicy::default(),
                    handed: &crate::handed::Ledger::new(),
                },
            );
        })
    }

    #[test]
    fn one_agent_process_is_handed_at_most_its_capture_ceiling_across_connections() {
        let slots = PcapSlots::new(Vec::new(), false);
        let ledger = Arc::new(crate::handed::Ledger::new());
        let ask = |ledger: &Arc<crate::handed::Ledger>| {
            let (mut client, server) = UnixStream::pair().unwrap();
            let slots = Arc::clone(&slots);
            let ledger = Arc::clone(ledger);
            let handle = std::thread::spawn(move || {
                let host = NullHost;
                handle_conn(
                    server,
                    &Served {
                        btf: &[],
                        pcap: &slots,
                        host: &host,
                        ext: None,
                        proc_root: Path::new("/proc"),
                        policy: &WardenPolicy::default(),
                        handed: &ledger,
                    },
                );
            });
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
            drop(client);
            handle.join().unwrap();
            response
        };
        for _ in 0..crate::handed::MAX_PCAP_PER_PROCESS {
            let Response::Error { message } = ask(&ledger) else {
                panic!("an empty pool answers an error");
            };
            assert!(message.contains("no packet-capture socket"), "{message}");
        }
        let Response::Error { message } = ask(&ledger) else {
            panic!("past the ceiling answers an error");
        };
        assert!(message.contains("32 capture sockets"), "{message}");
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
                    policy: &WardenPolicy::default(),
                    handed: &crate::handed::Ledger::new(),
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
                    policy: &WardenPolicy::default(),
                    handed: &crate::handed::Ledger::new(),
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
                Ok(n) if n > 0 => {}
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
