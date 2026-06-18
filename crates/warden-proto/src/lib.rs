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

/// A discovered SSL library to attach the DLP uprobe set to. Produced by the
/// warden's `/proc` scan (which needs `CAP_SYS_PTRACE` the rootless agent lacks)
/// so the agent never reads a neighbouring container's `/proc` itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DlpTarget {
    /// Path the warden resolves for the attach — the library seen through the
    /// owning process's root (`/proc/<pid>/root/<lib>`), in the warden's
    /// namespace. The agent passes it back verbatim in [`Command::AttachUprobe`].
    pub path: String,
    /// Block device of the resolved file — first half of the dedup key.
    pub dev: u64,
    /// Inode of the resolved file — second half of the dedup key.
    pub ino: u64,
    /// File offset of `SSL_write` (`0` if not exported by this library).
    pub ssl_write_offset: u64,
    /// File offset of `SSL_read` (`0` if not exported by this library).
    pub ssl_read_offset: u64,
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
    /// Attach a uprobe (`is_ret` = uretprobe) at `offset` within the ELF at
    /// `path`, binding the eBPF program whose fd rides in the accompanying
    /// `SCM_RIGHTS` cmsg (sent right after this frame). The warden creates the
    /// `uprobe_multi` `BPF_LINK_CREATE` — it holds the tracing capability the
    /// rootless agent dropped, and resolves `path` in its own (init) mount + pid
    /// namespace — then returns the link fd via [`Response::FdReady`]. This lets
    /// the agent probe a neighbouring container's `libssl` under `cap-drop: ALL`.
    /// The program fd is the agent's own verified eBPF object, and the kernel
    /// rejects a program whose type does not match a uprobe link, so the warden
    /// cannot be coerced into attaching an arbitrary program.
    AttachUprobe {
        /// Absolute path to the target ELF (e.g.
        /// `/proc/<pid>/root/usr/lib/libssl.so.3`).
        path: String,
        /// File offset of the symbol to probe.
        offset: u64,
        /// `true` for a uretprobe (fires on function return).
        is_ret: bool,
    },
    /// Scan `/proc` for SSL libraries mapped by any process and return one
    /// [`DlpTarget`] per unique `(dev, ino)`, with `SSL_write` / `SSL_read`
    /// offsets pre-resolved. Reading another process's `/proc/<pid>/maps` and ELF
    /// needs `CAP_SYS_PTRACE`, which the rootless agent dropped — so it delegates
    /// the whole discovery to the warden and only keeps the attach lifecycle.
    DlpScan,
    /// An opaque, namespaced extension operation. The OSS warden does not
    /// interpret it: a downstream build (e.g. the enterprise warden) installs an
    /// extension handler keyed on `kind` that owns the `payload` semantics, and an
    /// OSS warden with no handler answers [`Response::Unimplemented`]. This keeps
    /// build-specific privileged operations out of the shared protocol — `kind`
    /// namespaces the op, `payload` is its serialized request, and the reply rides
    /// in [`Response::Extension`]. Carries no enterprise-specific fields, so the
    /// AGPL protocol stays agnostic to whatever a handler does with it.
    Extension {
        /// Namespacing key identifying the extension operation.
        kind: String,
        /// Opaque serialized request, defined by the handler for `kind`.
        payload: Vec<u8>,
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
    /// The SSL libraries the warden's `/proc` scan found, answering
    /// [`Command::DlpScan`]. The agent reconciles these against its attached set.
    DlpTargets {
        /// One entry per unique `(dev, ino)` SSL library.
        targets: Vec<DlpTarget>,
    },
    /// The opaque reply to a handled [`Command::Extension`]; `payload` is defined
    /// by the handler that served the request's `kind`. An OSS warden never emits
    /// this (it has no handler); a downstream warden returns it on success.
    Extension {
        /// Opaque serialized reply, defined by the extension handler.
        payload: Vec<u8>,
    },
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
        Command, ConntrackTuple, DlpTarget, MAX_FRAME_LEN, Response, RouteSpec, read_frame,
        write_frame,
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
            Command::AttachUprobe {
                path: "/proc/4242/root/usr/lib/libssl.so.3".into(),
                offset: 0x1234,
                is_ret: true,
            },
            Command::DlpScan,
            Command::Extension {
                kind: "enterprise.proc_tls.v1".into(),
                payload: vec![0x01, 0x02, 0x03],
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
            Response::DlpTargets {
                targets: vec![DlpTarget {
                    path: "/proc/4242/root/usr/lib/libssl.so.3".into(),
                    dev: 48,
                    ino: 917_962,
                    ssl_write_offset: 0x1111,
                    ssl_read_offset: 0x2222,
                }],
            },
            Response::Extension {
                payload: vec![0xaa, 0xbb],
            },
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
