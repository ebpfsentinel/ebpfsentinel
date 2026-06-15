//! The warden control-plane server loop, generic over the [`MapSource`] backing
//! the map RPC.
//!
//! Two callers share this exact protocol logic. The `warden` binary backs it with
//! a [`MapRegistry`](crate::map_engine::MapRegistry) opened from a bpffs pin
//! directory. The agent's `warden-serve` mode backs it with a `MapSource` built
//! from the map fds it holds directly after loading every program in-process — no
//! pins, which sidesteps the fact that token-loaded maps are not pinnable from a
//! delegated bpffs. Either way the wire behaviour is identical.

use std::mem;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::ptr;

use ebpfsentinel_warden_proto::{Command, PROTOCOL_VERSION, Response, read_frame, write_frame};

use crate::host_ops::HostOps;
use crate::map_engine::MapSource;
use crate::{delegate_over_fd, net_ops, recv_fd, send_msg_fds};

/// Serve agent connections on `listener` forever, answering map RPC from
/// `registry` and handing out the `btf` / `pcap` fds on delegation. Only a peer
/// whose uid equals `allowed_uid` (checked via `SO_PEERCRED`) is served.
pub fn serve_loop<M: MapSource>(
    listener: &UnixListener,
    registry: &M,
    btf: &[(String, RawFd)],
    pcap: &[RawFd],
    host: &dyn HostOps,
    allowed_uid: u32,
) {
    for stream in listener.incoming() {
        match stream {
            Ok(conn) => {
                if peer_allowed(&conn, allowed_uid) {
                    handle_conn(conn, registry, btf, pcap, host);
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
fn handle_conn<M: MapSource>(
    conn: UnixStream,
    registry: &M,
    btf: &[(String, RawFd)],
    pcap: &[RawFd],
    host: &dyn HostOps,
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

    // Index into the pre-opened pcap pool. Each `PcapOpen` hands out the next
    // un-served pool fd; the warden keeps its own copy open so a reconnecting
    // agent is re-served from the start (the fd is dup'd into the agent by
    // `SCM_RIGHTS`, so both reference the same socket and closing the agent's copy
    // does not disturb the warden's).
    let mut pcap_next = 0usize;

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
                if pcap_next < pcap.len() {
                    // Serve a launcher-provided socket: the warden may sit in a
                    // user namespace where `socket(AF_PACKET)` is denied, so the
                    // pre-opened pool is the only way to capture rootlessly.
                    let fd = pcap[pcap_next];
                    pcap_next += 1;
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
            other => write_frame(&mut writer, &dispatch(other, registry, host)).is_ok(),
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

/// Map a request to a response. Map element ops go to `registry`; the conntrack
/// read and the host-network ops go to `host` (run locally or forwarded to the
/// resident broker, transparently to the agent). `Attach`/`Detach` (loader-side)
/// are answered `Unimplemented`.
fn dispatch<M: MapSource>(cmd: &Command, registry: &M, host: &dyn HostOps) -> Response {
    match cmd {
        Command::ConntrackDump => match host.conntrack_dump() {
            Ok(table) => Response::Conntrack { table },
            Err(message) => Response::Error { message },
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
        // Host-network ops needing authority over the init netns. `host` runs them
        // directly (broker / bare-metal) or forwards them there (userns warden-serve).
        Command::ConntrackDelete { tuple } => result_to_response(host.conntrack_delete(tuple)),
        Command::ConntrackFlush => result_to_response(host.conntrack_flush()),
        Command::RouteAdd { route } => result_to_response(host.route_add(route)),
        Command::RouteDel { route } => result_to_response(host.route_del(route)),
        Command::ArpAnnounce { iface, ip } => result_to_response(host.arp_announce(iface, ip)),
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
