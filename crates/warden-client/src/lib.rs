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
//! (map writes, conntrack reads) is rare, so a simple synchronous
//! request/response loop over the raw stream is sufficient — the hot event path
//! never crosses this client (it rides ring-buffer fds passed once by the warden).

#![forbid(unsafe_code)]

use std::io;
use std::os::unix::net::UnixStream;
use std::path::Path;

use ebpfsentinel_warden_proto::{Command, PROTOCOL_VERSION, Response, read_frame, write_frame};

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

    /// Look up one element of an eBPF map. Returns `None` when the key is absent.
    pub fn map_lookup(&mut self, map: &str, key: Vec<u8>) -> io::Result<Option<Vec<u8>>> {
        match self.call(&Command::MapLookup {
            map: map.to_owned(),
            key,
        })? {
            Response::MapValue { found: true, value } => Ok(Some(value)),
            Response::MapValue { found: false, .. } => Ok(None),
            other => Err(unexpected("MapLookup", &other)),
        }
    }

    /// Insert or update one element of an eBPF map.
    pub fn map_update(
        &mut self,
        map: &str,
        key: Vec<u8>,
        value: Vec<u8>,
        flags: u64,
    ) -> io::Result<()> {
        match self.call(&Command::MapUpdate {
            map: map.to_owned(),
            key,
            value,
            flags,
        })? {
            Response::Ok => Ok(()),
            other => Err(unexpected("MapUpdate", &other)),
        }
    }

    /// Delete one element of an eBPF map.
    pub fn map_delete(&mut self, map: &str, key: Vec<u8>) -> io::Result<()> {
        match self.call(&Command::MapDelete {
            map: map.to_owned(),
            key,
        })? {
            Response::Ok => Ok(()),
            other => Err(unexpected("MapDelete", &other)),
        }
    }

    /// Read the kernel conntrack table the rootless agent cannot open itself.
    pub fn conntrack_dump(&mut self) -> io::Result<Vec<u8>> {
        match self.call(&Command::ConntrackDump)? {
            Response::Conntrack { table } => Ok(table),
            other => Err(unexpected("ConntrackDump", &other)),
        }
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
