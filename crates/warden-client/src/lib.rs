//! Pure-userspace client for the eBPFsentinel **warden**.
//!
//! The rootless agent links this crate (and only this crate, plus
//! `ebpfsentinel-warden-proto`) to reach the privileged warden: it owns no `bpf()`
//! / netlink fd and carries no `unsafe` or `libc`, so an agent that routes its
//! kernel operations through [`WardenClient`] can run under `RuntimeDefault`
//! seccomp with every capability dropped.
//!
//! A client connects over the warden's `AF_UNIX` socket, completes the versioned
//! [`Hello`](ebpfsentinel_warden_proto::Command::Hello) handshake once, then issues
//! one [`Command`] per call and reads back its [`Response`]. The control path
//! (conntrack reads/teardown, route programming, gratuitous ARP) is rare, so a
//! simple synchronous request/response loop over the raw stream is sufficient —
//! the hot event path never crosses this client.
//!
//! The optional `fd-pass` feature adds [`WardenClient::pcap_open`], which receives
//! an `AF_PACKET` capture-socket fd over `SCM_RIGHTS`. That receive is the only
//! `libc`/`unsafe` in this crate; with the feature off the crate is
//! `#![forbid(unsafe_code)]`.

#![cfg_attr(not(feature = "fd-pass"), forbid(unsafe_code))]

use std::io;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use ebpfsentinel_warden_proto::{Command, PROTOCOL_VERSION, Response, read_frame, write_frame};
// Re-exported under their real names so callers of the typed control methods can
// build request values without taking a direct dependency on the protocol crate.
pub use ebpfsentinel_warden_proto::{ConntrackTuple, DlpTarget, RouteSpec};

/// A connected, handshaked client to a warden socket.
pub struct WardenClient {
    stream: UnixStream,
}

impl WardenClient {
    /// Connect to the warden listening at `path` and complete the `Hello`
    /// handshake. Fails if the socket is absent, the peer is not a warden, or the
    /// warden runs an incompatible [`PROTOCOL_VERSION`].
    pub fn connect<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let stream = UnixStream::connect(path)?;
        let mut client = Self { stream };
        client.handshake()?;
        Ok(client)
    }

    /// Send `Hello` and require a matching-version `HelloOk`.
    fn handshake(&mut self) -> io::Result<()> {
        write_frame(
            &mut self.stream,
            &Command::Hello {
                version: PROTOCOL_VERSION,
            },
        )?;
        match read_frame::<_, Response>(&mut self.stream)? {
            Response::HelloOk { version } if version == PROTOCOL_VERSION => Ok(()),
            Response::HelloOk { version } => Err(io::Error::other(format!(
                "warden protocol version {version} != client {PROTOCOL_VERSION}"
            ))),
            Response::Error { message } => Err(io::Error::other(message)),
            other => Err(io::Error::other(format!(
                "unexpected handshake response: {other:?}"
            ))),
        }
    }

    /// Issue one command and read its response.
    fn call(&mut self, cmd: &Command) -> io::Result<Response> {
        write_frame(&mut self.stream, cmd)?;
        read_frame(&mut self.stream)
    }

    /// Ask the warden to scan `/proc` for SSL libraries and return the DLP
    /// targets (deduped by inode, with offsets resolved). The rootless agent
    /// cannot read other processes' `/proc`, so this discovery is brokered.
    pub fn dlp_scan(&mut self) -> io::Result<Vec<DlpTarget>> {
        match self.call(&Command::DlpScan)? {
            Response::DlpTargets { targets } => Ok(targets),
            other => Err(unexpected("DlpScan", &other)),
        }
    }

    /// Issue an opaque, namespaced extension command and return the reply payload.
    /// The OSS warden installs no handler, so it answers `Unimplemented` (surfaced
    /// here as an error); a downstream warden (e.g. the enterprise warden) with a
    /// handler for `kind` returns the bytes it produced. Lets a downstream client
    /// add privileged operations without changing the shared protocol.
    pub fn extension(&mut self, kind: &str, payload: Vec<u8>) -> io::Result<Vec<u8>> {
        match self.call(&Command::Extension {
            kind: kind.to_string(),
            payload,
        })? {
            Response::Extension { payload } => Ok(payload),
            other => Err(unexpected("Extension", &other)),
        }
    }

    /// Read the kernel conntrack table the rootless agent cannot open itself.
    pub fn conntrack_dump(&mut self) -> io::Result<Vec<u8>> {
        match self.call(&Command::ConntrackDump)? {
            Response::Conntrack { table } => Ok(table),
            other => Err(unexpected("ConntrackDump", &other)),
        }
    }

    /// Issue a command that the warden answers with a bare `Ok` on success.
    fn expect_ok(&mut self, cmd: &Command, op: &str) -> io::Result<()> {
        match self.call(cmd)? {
            Response::Ok => Ok(()),
            other => Err(unexpected(op, &other)),
        }
    }

    /// Tear down a single conntrack flow (a `CAP_NET_ADMIN` op).
    pub fn conntrack_delete(&mut self, tuple: ConntrackTuple) -> io::Result<()> {
        self.expect_ok(&Command::ConntrackDelete { tuple }, "ConntrackDelete")
    }

    /// Flush the whole conntrack table.
    pub fn conntrack_flush(&mut self) -> io::Result<()> {
        self.expect_ok(&Command::ConntrackFlush, "ConntrackFlush")
    }

    /// Add (idempotent `replace`) a route — multi-WAN gateway programming.
    pub fn route_add(&mut self, route: RouteSpec) -> io::Result<()> {
        self.expect_ok(&Command::RouteAdd { route }, "RouteAdd")
    }

    /// Delete a route.
    pub fn route_del(&mut self, route: RouteSpec) -> io::Result<()> {
        self.expect_ok(&Command::RouteDel { route }, "RouteDel")
    }

    /// Broadcast a gratuitous ARP for `ip` on `iface` (VIP takeover).
    pub fn arp_announce(&mut self, iface: &str, ip: &str) -> io::Result<()> {
        self.expect_ok(
            &Command::ArpAnnounce {
                iface: iface.to_owned(),
                ip: ip.to_owned(),
            },
            "ArpAnnounce",
        )
    }

    /// Ask the warden to open an `AF_PACKET` capture socket bound to `iface` and
    /// receive its fd over `SCM_RIGHTS`. `filter` is recorded by the warden; the
    /// agent installs the cBPF filter on the returned fd itself. Issues no
    /// privileged syscall in the agent.
    #[cfg(feature = "fd-pass")]
    pub fn pcap_open(&mut self, iface: &str, filter: &str) -> io::Result<std::os::fd::OwnedFd> {
        write_frame(
            &mut self.stream,
            &Command::PcapOpen {
                iface: iface.to_owned(),
                filter: filter.to_owned(),
            },
        )?;
        match read_frame::<_, Response>(&mut self.stream)? {
            Response::FdReady => fd_pass::recv_one_fd(&self.stream),
            other => Err(unexpected("PcapOpen", &other)),
        }
    }

    /// Ask the warden to attach a `uprobe_multi` link at `offset` within the ELF
    /// at `path`, binding the agent's `prog_fd` (handed to the warden over
    /// `SCM_RIGHTS`). `is_ret` selects a uretprobe. Returns the link fd; the agent
    /// owns it and dropping it detaches. The warden holds the tracing capability
    /// and resolves `path` in its own namespaces, so a rootless agent can probe a
    /// neighbouring container's `libssl` under `cap-drop: ALL`.
    #[cfg(feature = "fd-pass")]
    pub fn attach_uprobe(
        &mut self,
        path: &str,
        offset: u64,
        is_ret: bool,
        prog_fd: std::os::fd::RawFd,
    ) -> io::Result<std::os::fd::OwnedFd> {
        use std::os::fd::AsRawFd;
        write_frame(
            &mut self.stream,
            &Command::AttachUprobe {
                path: path.to_owned(),
                offset,
                is_ret,
            },
        )?;
        // The program fd rides in an `SCM_RIGHTS` cmsg right after the frame, the
        // mirror of the warden's `Delegate` fs-fd hand-off.
        fd_pass::send_one_fd(self.stream.as_raw_fd(), prog_fd)?;
        match read_frame::<_, Response>(&mut self.stream)? {
            Response::FdReady => fd_pass::recv_one_fd(&self.stream),
            other => Err(unexpected("AttachUprobe", &other)),
        }
    }
}

/// Was an error caused by the warden's connection going away (so a reconnect is
/// worth attempting), as opposed to a genuine application error?
fn is_connection_lost(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::NotConnected
            | io::ErrorKind::UnexpectedEof
    )
}

/// A [`WardenClient`] that survives the warden restarting underneath it.
///
/// The warden is expected to be supervised (native sidecar / systemd) and may
/// bounce independently of the agent. The hot event path is unaffected — the
/// agent holds the ring-buffer fds directly and the pinned kernel objects outlive
/// the warden — but every control call crosses the socket, so a bounce breaks the
/// connection. This wrapper reconnects lazily and, on a connection-loss error,
/// drops the dead client, re-handshakes, and retries the call exactly once. A
/// warden that is still down surfaces a clear `io::Error` rather than hanging.
pub struct ReconnectingClient {
    path: PathBuf,
    client: Option<WardenClient>,
}

impl ReconnectingClient {
    /// Bind to a warden socket path. Does not connect until the first call (the
    /// warden may legitimately start after the agent).
    #[must_use]
    pub fn new<P: Into<PathBuf>>(path: P) -> Self {
        Self {
            path: path.into(),
            client: None,
        }
    }

    /// (Re)establish the connection.
    fn reconnect(&mut self) -> io::Result<()> {
        self.client = Some(WardenClient::connect(&self.path)?);
        Ok(())
    }

    /// Run `op` against a live client, reconnecting + retrying once on a
    /// connection-loss error. `op` may be called twice, so it must be replayable.
    fn with_retry<T, F>(&mut self, mut op: F) -> io::Result<T>
    where
        F: FnMut(&mut WardenClient) -> io::Result<T>,
    {
        if self.client.is_none() {
            self.reconnect()?;
        }
        let first = op(self
            .client
            .as_mut()
            .expect("client present after reconnect"));
        match first {
            Err(e) if is_connection_lost(&e) => {
                self.client = None;
                self.reconnect()?;
                op(self
                    .client
                    .as_mut()
                    .expect("client present after reconnect"))
            }
            other => other,
        }
    }

    /// Read the kernel conntrack table.
    pub fn conntrack_dump(&mut self) -> io::Result<Vec<u8>> {
        self.with_retry(WardenClient::conntrack_dump)
    }

    /// Scan `/proc` for DLP targets through the warden, reconnecting if it bounced.
    pub fn dlp_scan(&mut self) -> io::Result<Vec<DlpTarget>> {
        self.with_retry(WardenClient::dlp_scan)
    }

    /// Issue an opaque extension command through the warden, reconnecting if it
    /// bounced. The closure re-clones `payload` because `with_retry` may replay it.
    pub fn extension(&mut self, kind: &str, payload: &[u8]) -> io::Result<Vec<u8>> {
        self.with_retry(|c| c.extension(kind, payload.to_vec()))
    }

    /// Tear down a single conntrack flow.
    pub fn conntrack_delete(&mut self, tuple: &ConntrackTuple) -> io::Result<()> {
        self.with_retry(|c| c.conntrack_delete(tuple.clone()))
    }

    /// Flush the whole conntrack table.
    pub fn conntrack_flush(&mut self) -> io::Result<()> {
        self.with_retry(WardenClient::conntrack_flush)
    }

    /// Add (idempotent `replace`) a route.
    pub fn route_add(&mut self, route: &RouteSpec) -> io::Result<()> {
        self.with_retry(|c| c.route_add(route.clone()))
    }

    /// Delete a route.
    pub fn route_del(&mut self, route: &RouteSpec) -> io::Result<()> {
        self.with_retry(|c| c.route_del(route.clone()))
    }

    /// Broadcast a gratuitous ARP for `ip` on `iface`.
    pub fn arp_announce(&mut self, iface: &str, ip: &str) -> io::Result<()> {
        self.with_retry(|c| c.arp_announce(iface, ip))
    }

    /// Open a capture socket on `iface`, reconnecting if the warden bounced.
    #[cfg(feature = "fd-pass")]
    pub fn pcap_open(&mut self, iface: &str, filter: &str) -> io::Result<std::os::fd::OwnedFd> {
        self.with_retry(|c| c.pcap_open(iface, filter))
    }

    /// Attach a uprobe through the warden, reconnecting if it bounced. `prog_fd`
    /// is the same descriptor on a retry, so the call is replayable.
    #[cfg(feature = "fd-pass")]
    pub fn attach_uprobe(
        &mut self,
        path: &str,
        offset: u64,
        is_ret: bool,
        prog_fd: std::os::fd::RawFd,
    ) -> io::Result<std::os::fd::OwnedFd> {
        self.with_retry(|c| c.attach_uprobe(path, offset, is_ret, prog_fd))
    }
}

/// `SCM_RIGHTS` fd receive — the sole `unsafe`/`libc` in this crate, compiled only
/// under the `fd-pass` feature.
#[cfg(feature = "fd-pass")]
mod fd_pass {
    use std::io;
    use std::mem;
    use std::os::fd::{FromRawFd, OwnedFd, RawFd};
    use std::os::unix::net::UnixStream;
    use std::ptr;

    /// Send exactly one fd alongside a single sentinel byte — the wire shape the
    /// warden expects for an inbound fd (mirrors its `Delegate` fs-fd receive).
    pub fn send_one_fd(sock: RawFd, fd: RawFd) -> io::Result<()> {
        let mut byte = [0u8; 1];
        let mut iov = libc::iovec {
            iov_base: byte.as_mut_ptr().cast(),
            iov_len: byte.len(),
        };
        // SAFETY: a zeroed `msghdr` is a valid header; the control buffer is sized
        // for exactly one fd via `CMSG_SPACE`.
        let mut cbuf = [0u8; unsafe { libc::CMSG_SPACE(mem::size_of::<RawFd>() as u32) } as usize];
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_iov = ptr::from_mut(&mut iov);
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr().cast();
        msg.msg_controllen = cbuf.len() as _;
        // SAFETY: `cmsg` points into the valid `cbuf` local; we fill exactly one
        // `SCM_RIGHTS` header carrying `fd`.
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(ptr::from_ref(&msg));
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(mem::size_of::<RawFd>() as u32) as _;
            ptr::copy_nonoverlapping(
                ptr::from_ref(&fd).cast(),
                libc::CMSG_DATA(cmsg),
                mem::size_of::<RawFd>(),
            );
        }
        // SAFETY: `msg` points at the valid `iov`/`cbuf` locals above.
        let n = unsafe { libc::sendmsg(sock, ptr::from_ref(&msg), 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Receive exactly one fd, sent by the warden alongside a single sentinel byte.
    pub fn recv_one_fd(stream: &UnixStream) -> io::Result<OwnedFd> {
        use std::os::fd::AsRawFd;

        let mut byte = [0u8; 1];
        let mut iov = libc::iovec {
            iov_base: byte.as_mut_ptr().cast(),
            iov_len: byte.len(),
        };
        // SAFETY: a zeroed `msghdr` is a valid empty message header; the control
        // buffer is sized for exactly one fd via `CMSG_SPACE`.
        let mut cbuf = [0u8; unsafe { libc::CMSG_SPACE(mem::size_of::<RawFd>() as u32) } as usize];
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_iov = ptr::from_mut(&mut iov);
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr().cast();
        msg.msg_controllen = cbuf.len() as _;

        // SAFETY: `msg` points at the valid `iov`/`cbuf` locals above.
        let n = unsafe { libc::recvmsg(stream.as_raw_fd(), ptr::from_mut(&mut msg), 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if msg.msg_flags & libc::MSG_CTRUNC != 0 {
            // The kernel dropped the fd because the control buffer was too small;
            // never act on a partial/forged fd set.
            return Err(io::Error::other("ring-buffer fd was truncated in transit"));
        }
        // SAFETY: walk the well-formed control buffer the kernel just filled.
        let fd = unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(ptr::from_ref(&msg));
            if cmsg.is_null()
                || (*cmsg).cmsg_level != libc::SOL_SOCKET
                || (*cmsg).cmsg_type != libc::SCM_RIGHTS
            {
                return Err(io::Error::other("no SCM_RIGHTS fd in warden reply"));
            }
            let mut raw: RawFd = -1;
            ptr::copy_nonoverlapping(
                libc::CMSG_DATA(cmsg),
                ptr::from_mut(&mut raw).cast(),
                mem::size_of::<RawFd>(),
            );
            raw
        };
        if fd < 0 {
            return Err(io::Error::other("warden returned an invalid fd"));
        }
        // SAFETY: `fd` is a fresh descriptor the kernel just installed; we own it.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

/// Turn an off-protocol or `Error` response into an `io::Error`.
fn unexpected(op: &str, resp: &Response) -> io::Error {
    match resp {
        Response::Error { message } => io::Error::other(format!("{op}: {message}")),
        Response::Unimplemented => {
            io::Error::other(format!("{op}: not implemented by this warden build"))
        }
        other => io::Error::other(format!("{op}: unexpected response {other:?}")),
    }
}

#[cfg(all(test, feature = "fd-pass"))]
mod fd_pass_tests {
    use crate::fd_pass::recv_one_fd;
    use std::io::{Read, Write};
    use std::mem;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::net::UnixStream;
    use std::ptr;

    /// Send one fd alongside a single sentinel byte — the warden's wire shape.
    unsafe fn send_one_fd(sock: RawFd, fd: RawFd) -> bool {
        let mut byte = [0u8; 1];
        let mut iov = libc::iovec {
            iov_base: byte.as_mut_ptr().cast(),
            iov_len: byte.len(),
        };
        let mut cbuf = [0u8; unsafe { libc::CMSG_SPACE(mem::size_of::<RawFd>() as u32) } as usize];
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_iov = ptr::from_mut(&mut iov);
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr().cast();
        msg.msg_controllen = cbuf.len() as _;
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(ptr::from_ref(&msg));
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(mem::size_of::<RawFd>() as u32) as _;
            ptr::copy_nonoverlapping(
                ptr::from_ref(&fd).cast(),
                libc::CMSG_DATA(cmsg),
                mem::size_of::<RawFd>(),
            );
            libc::sendmsg(sock, ptr::from_ref(&msg), 0) >= 0
        }
    }

    #[test]
    fn received_fd_refers_to_the_same_kernel_object() {
        let (sender, receiver) = UnixStream::pair().unwrap();

        // Pass the read end of a pipe across the socket.
        let mut fds = [0 as RawFd; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (read_fd, write_fd) = (fds[0], fds[1]);

        assert!(unsafe { send_one_fd(sender.as_raw_fd(), read_fd) });
        let received: OwnedFd = recv_one_fd(&receiver).expect("recv fd");

        // Drop our copy of the original read end; the received fd must still read
        // bytes written to the write end — proving it is the same pipe.
        unsafe { libc::close(read_fd) };
        let mut writer = unsafe { std::fs::File::from_raw_fd(write_fd) };
        writer.write_all(b"hi").unwrap();
        drop(writer);

        let mut reader = std::fs::File::from(received);
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"hi");
    }
}
