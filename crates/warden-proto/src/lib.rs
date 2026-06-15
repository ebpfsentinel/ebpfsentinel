//! Wire protocol for the eBPFsentinel **warden** — the small privileged component
//! that performs kernel operations on behalf of a fully rootless agent.
//!
//! The agent runs non-root with every capability dropped and the runtime-default
//! seccomp profile, so it can issue neither `bpf()` nor netlink/`mount` syscalls.
//! Instead it asks the warden, over an `AF_UNIX` socket, for a narrow set of typed
//! operations. This crate defines that contract: the [`Command`]/[`Response`]
//! messages and a length-prefixed [`write_frame`]/[`read_frame`] codec over any
//! [`Read`]/[`Write`].
//!
//! The codec is pure serialization — no `unsafe`, no `libc`. The few commands that
//! must hand a file descriptor across the boundary (bpffs delegation, module-BTF
//! and pcap fds) ride that fd in an `SCM_RIGHTS` control message *alongside* the
//! frame defined here; the privileged warden binary owns that fd-passing, keeping
//! all `unsafe` out of this shared crate and out of the agent.

#![forbid(unsafe_code)]

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

/// Protocol version negotiated by the [`Command::Hello`] handshake. Bump on any
/// wire-breaking change so a mismatched agent/warden image pair refuses to talk
/// rather than misinterpreting each other's frames.
pub const PROTOCOL_VERSION: u16 = 1;

/// Largest frame payload accepted from a peer. A conntrack dump is the largest
/// legitimate message and stays far below this; the bound just stops a hostile or
/// corrupt length prefix from forcing a huge allocation.
pub const MAX_FRAME_LEN: u32 = 16 * 1024 * 1024;

/// A conntrack entry identity, used to delete a single flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConntrackTuple {
    /// IP protocol number (6 = TCP, 17 = UDP, …).
    pub proto: u8,
    /// Source address, rendered as a string (v4 or v6).
    pub src_ip: String,
    /// Destination address, rendered as a string (v4 or v6).
    pub dst_ip: String,
    /// Source port (0 for protocols without ports).
    pub src_port: u16,
    /// Destination port (0 for protocols without ports).
    pub dst_port: u16,
}

/// A routing-table entry, used by multi-WAN failover.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteSpec {
    /// Destination CIDR (`0.0.0.0/0` for a default route).
    pub dst_cidr: String,
    /// Next-hop gateway address.
    pub gateway: String,
    /// Outgoing interface name.
    pub iface: String,
    /// Routing table id.
    pub table: u32,
}

/// A request from the agent to the warden. Every variant is one kernel operation
/// the rootless agent cannot perform itself; the warden validates each against an
/// allowlist before acting, so a compromised agent cannot turn the warden into an
/// arbitrary-syscall executor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Command {
    /// Version handshake. Must be the first message on a connection.
    Hello {
        /// The agent's protocol version.
        version: u16,
    },
    /// Delegate a bpffs whose `fs_fd` rides in the accompanying `SCM_RIGHTS` cmsg.
    /// The warden applies the `delegate_*` options and creates the superblock,
    /// then returns the module-BTF and pcap fds via [`Response::Delegated`].
    Delegate,
    /// Read the kernel conntrack table on the agent's behalf (the proc file is
    /// `0440 root`, unreadable by the rootless agent).
    ConntrackDump,
    /// Delete a single conntrack flow (a `CAP_NET_ADMIN` netlink operation).
    ConntrackDelete {
        /// The flow to delete.
        tuple: ConntrackTuple,
    },
    /// Flush the whole conntrack table.
    ConntrackFlush,
    /// Add a route (multi-WAN gateway selection / failover).
    RouteAdd {
        /// The route to add.
        route: RouteSpec,
    },
    /// Delete a route.
    RouteDel {
        /// The route to delete.
        route: RouteSpec,
    },
    /// Emit a gratuitous ARP for `ip` on `iface` (VIP takeover).
    ArpAnnounce {
        /// Interface to announce on.
        iface: String,
        /// IP to announce.
        ip: String,
    },
    /// Open an `AF_PACKET` capture socket on `iface` with the cBPF `filter`; the
    /// resulting fd rides in an `SCM_RIGHTS` cmsg.
    PcapOpen {
        /// Capture interface.
        iface: String,
        /// cBPF/tcpdump filter expression.
        filter: String,
    },
}

/// A reply from the warden to the agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    /// Handshake accepted; the warden reports its own protocol version.
    HelloOk {
        /// The warden's protocol version.
        version: u16,
    },
    /// Delegation succeeded. The `btf_names` module-BTF fds followed by
    /// `pcap_count` pcap fds ride in the accompanying `SCM_RIGHTS` cmsg, in that
    /// order.
    Delegated {
        /// Module-BTF names, in fd order.
        btf_names: Vec<String>,
        /// Number of pcap fds following the BTF fds.
        pcap_count: u32,
    },
    /// Raw conntrack table bytes; the agent parses them exactly as if it had read
    /// the proc file itself.
    Conntrack {
        /// The conntrack table contents.
        table: Vec<u8>,
    },
    /// A file descriptor rides in the accompanying `SCM_RIGHTS` cmsg (the pcap
    /// capture socket from [`Command::PcapOpen`]).
    FdReady,
    /// The command succeeded and carries no payload.
    Ok,
    /// The command is part of the protocol but not served by this warden build.
    Unimplemented,
    /// The command failed; `message` explains why.
    Error {
        /// Human-readable failure reason.
        message: String,
    },
}

/// Write one framed message: a `u32` little-endian length prefix followed by the
/// `postcard` encoding of `msg`. The leading byte of the postcard body is the
/// enum-variant tag — the command discriminant — so a reader can dispatch on it
/// without decoding the whole payload.
pub fn write_frame<W: Write, T: Serialize>(w: &mut W, msg: &T) -> io::Result<()> {
    let body = postcard::to_allocvec(msg).map_err(io::Error::other)?;
    let len =
        u32::try_from(body.len()).map_err(|_| io::Error::other("frame too large to encode"))?;
    w.write_all(&len.to_le_bytes())?;
    w.write_all(&body)?;
    w.flush()
}

/// Read one framed message written by [`write_frame`]. Rejects a length prefix
/// over [`MAX_FRAME_LEN`] before allocating, so a corrupt or hostile peer cannot
/// force a large allocation.
pub fn read_frame<R: Read, T: DeserializeOwned>(r: &mut R) -> io::Result<T> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_FRAME_LEN {
        return Err(io::Error::other("frame length exceeds MAX_FRAME_LEN"));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body)?;
    postcard::from_bytes(&body).map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::{
        Command, ConntrackTuple, MAX_FRAME_LEN, Response, RouteSpec, read_frame, write_frame,
    };
    use std::io::Cursor;

    fn all_commands() -> Vec<Command> {
        let tuple = ConntrackTuple {
            proto: 6,
            src_ip: "10.0.0.1".into(),
            dst_ip: "10.0.0.2".into(),
            src_port: 1234,
            dst_port: 80,
        };
        let route = RouteSpec {
            dst_cidr: "0.0.0.0/0".into(),
            gateway: "10.0.0.254".into(),
            iface: "enp0s2".into(),
            table: 100,
        };
        vec![
            Command::Hello { version: 1 },
            Command::Delegate,
            Command::ConntrackDump,
            Command::ConntrackDelete {
                tuple: tuple.clone(),
            },
            Command::ConntrackFlush,
            Command::RouteAdd {
                route: route.clone(),
            },
            Command::RouteDel { route },
            Command::ArpAnnounce {
                iface: "enp0s2".into(),
                ip: "10.0.0.9".into(),
            },
            Command::PcapOpen {
                iface: "enp0s2".into(),
                filter: "tcp port 443".into(),
            },
        ]
    }

    fn all_responses() -> Vec<Response> {
        vec![
            Response::HelloOk { version: 1 },
            Response::Delegated {
                btf_names: vec!["nf_conntrack".into(), "fou".into()],
                pcap_count: 2,
            },
            Response::Conntrack {
                table: vec![0xde, 0xad, 0xbe, 0xef],
            },
            Response::FdReady,
            Response::Ok,
            Response::Unimplemented,
            Response::Error {
                message: "nope".into(),
            },
        ]
    }

    #[test]
    fn every_command_roundtrips() {
        for cmd in all_commands() {
            let mut buf = Vec::new();
            write_frame(&mut buf, &cmd).expect("encode");
            let got: Command = read_frame(&mut Cursor::new(&buf)).expect("decode");
            assert_eq!(cmd, got);
        }
    }

    #[test]
    fn every_response_roundtrips() {
        for resp in all_responses() {
            let mut buf = Vec::new();
            write_frame(&mut buf, &resp).expect("encode");
            let got: Response = read_frame(&mut Cursor::new(&buf)).expect("decode");
            assert_eq!(resp, got);
        }
    }

    #[test]
    fn multiple_frames_stream_in_order() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &Command::Hello { version: 1 }).unwrap();
        write_frame(&mut buf, &Command::ConntrackDump).unwrap();
        let mut cur = Cursor::new(&buf);
        let a: Command = read_frame(&mut cur).unwrap();
        let b: Command = read_frame(&mut cur).unwrap();
        assert_eq!(a, Command::Hello { version: 1 });
        assert_eq!(b, Command::ConntrackDump);
    }

    #[test]
    fn oversized_length_prefix_is_rejected() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(MAX_FRAME_LEN + 1).to_le_bytes());
        let err = read_frame::<_, Command>(&mut Cursor::new(&buf)).unwrap_err();
        assert!(err.to_string().contains("MAX_FRAME_LEN"));
    }

    #[test]
    fn truncated_body_errors_not_panics() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &Command::ConntrackDump).unwrap();
        buf.truncate(buf.len() - 1);
        assert!(read_frame::<_, Command>(&mut Cursor::new(&buf)).is_err());
    }
}
