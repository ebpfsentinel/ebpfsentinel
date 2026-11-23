//! Wire protocol for the eBPFsentinel **warden** - the small privileged component
//! that performs kernel operations on behalf of a fully rootless agent.
//!
//! The agent runs non-root with every capability dropped and the runtime-default
//! seccomp profile, so it can issue neither `bpf()` nor netlink/`mount` syscalls.
//! Instead it asks the warden, over an `AF_UNIX` socket, for a narrow set of typed
//! operations. This crate defines that contract: the [`Command`]/[`Response`]
//! messages and a length-prefixed [`write_frame`]/[`read_frame`] codec over any
//! [`Read`]/[`Write`].
//!
//! The codec is pure serialization - no `unsafe`, no `libc`. The few commands that
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
pub const PROTOCOL_VERSION: u16 = 4;

/// Largest frame payload accepted from a peer. A conntrack dump is the largest
/// legitimate message and stays far below this; the bound just stops a hostile or
/// corrupt length prefix from forcing a huge allocation.
pub const MAX_FRAME_LEN: u32 = 16 * 1024 * 1024;

/// Largest command a warden reads when the command carries no list: an
/// interface, an address, a path or a pid fits many times over, so a longer
/// frame is refused before its body is read.
pub const CONTROL_FRAME_LEN: u32 = 64 * 1024;

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

/// An established TCP flow to write into the kernel conntrack table, as a node
/// taking over a failed peer's traffic restores it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConntrackRestore {
    /// The original direction. Only TCP is restored: it is the one protocol
    /// whose mid-stream pickup the agent turns off.
    pub flow: ConntrackTuple,
    /// The reply direction where it differs from the inverse of `flow`, which
    /// is a flow netfilter saw translated. Its `proto` is ignored.
    pub reply: Option<ConntrackTuple>,
}

/// Seconds a restored entry lives before its next packet refreshes it to the
/// kernel's established timeout. Short on purpose: an entry for a flow that
/// closed while the peer failed goes on its own.
pub const CONNTRACK_RESTORE_TIMEOUT_SECS: u32 = 120;

impl ConntrackRestore {
    /// Whether this names one TCP flow fully: both addresses parse, no port is
    /// zero, and the reply direction, where given, is named the same way. The
    /// agent and the warden both refuse anything else before writing over
    /// netlink, so a compromised caller cannot widen an insert through a field.
    #[must_use]
    pub fn is_restorable(&self) -> bool {
        fn named(t: &ConntrackTuple) -> bool {
            t.src_ip.parse::<std::net::IpAddr>().is_ok()
                && t.dst_ip.parse::<std::net::IpAddr>().is_ok()
                && t.src_port != 0
                && t.dst_port != 0
        }
        self.flow.proto == 6 && named(&self.flow) && self.reply.as_ref().is_none_or(named)
    }
}

/// A discovered SSL library to attach the DLP uprobe set to. Produced by the
/// warden's `/proc` scan (which needs `CAP_SYS_PTRACE` the rootless agent lacks)
/// so the agent never reads a neighbouring container's `/proc` itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DlpTarget {
    /// Path the warden resolves for the attach - the library seen through the
    /// owning process's root (`/proc/<pid>/root/<lib>`), in the warden's
    /// namespace. The agent passes it back verbatim in [`Command::AttachUprobe`].
    pub path: String,
    /// Block device of the resolved file - first half of the dedup key.
    pub dev: u64,
    /// Inode of the resolved file - second half of the dedup key.
    pub ino: u64,
    /// File offset of `SSL_write` (`0` if not exported by this library).
    pub ssl_write_offset: u64,
    /// File offset of `SSL_read` (`0` if not exported by this library).
    pub ssl_read_offset: u64,
}

/// The executable a process runs, as `/proc/<pid>/exe` names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutableIdentity {
    /// The link's target, with the kernel's ` (deleted)` suffix removed.
    pub path: String,
    /// Block device of the file the link points at.
    pub dev: u64,
    /// Inode of the file the link points at.
    pub ino: u64,
}

/// What the process detection weighs about one process, read from its
/// `/proc/<pid>` directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessFactsReading {
    /// Standard input or output is an internet socket of the process's own
    /// network namespace.
    pub streams_on_socket: bool,
    /// The image was removed from disk or is an anonymous memory file.
    pub fileless: bool,
}

/// One `AF_PACKET` socket open on the node, as the kernel lists it.
///
/// A packet socket sees frames before the network stack does, which is what a
/// capture tool needs and what a backdoor listening for a magic packet needs
/// too. The kernel lists them per network namespace; the holder is found by
/// matching the socket's inode against every process's descriptors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketSocket {
    /// The socket's inode, unique within its namespace.
    pub inode: u64,
    /// `SOCK_RAW` (3) delivers frames with their link-layer header,
    /// `SOCK_DGRAM` (2) without.
    pub socket_type: u16,
    /// The ethertype the socket receives, in host order; `0x0003` is every
    /// protocol, `0` is none until the socket is bound.
    pub protocol: u16,
    /// The interface it is bound to, `0` for every interface.
    pub ifindex: u32,
    /// The interface's name, where the scanner shares the namespace it lives
    /// in.
    pub interface: Option<String>,
    /// The uid that opened it.
    pub uid: u32,
    /// The inode of its network namespace.
    pub netns: u64,
    /// Whether that namespace is the host's.
    pub host_netns: bool,
    /// The process holding it, `None` when no descriptor names it.
    pub pid: Option<u32>,
    /// Classic BPF instructions in the filter attached to it: `Some(0)` for
    /// no filter, `None` when the kernel could not be asked.
    pub filter_instructions: Option<u32>,
}

/// One eBPF program on the node's network path, and where it is attached.
///
/// Read from the kernel's own lists: every BPF link, the XDP program and the
/// classic `tc` filters of each host interface, and every program of a
/// network type that none of those place. The warden reads identities and
/// never hands out a descriptor on a program.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkProgram {
    /// The program's id.
    pub prog_id: u32,
    /// The program type, as a slug (`xdp`, `sched_cls`, `cgroup_sock_addr`...).
    pub prog_type: String,
    /// The name the loader gave it, at most 15 bytes.
    pub name: String,
    /// The kernel's tag over its instructions, in hex.
    pub tag: String,
    /// The link holding it there, `None` for a legacy attachment or a
    /// program found on no hook.
    pub link_id: Option<u32>,
    /// The hook, as a slug: `xdp`, `tc_ingress`, `tc_egress`, `tcx_ingress`,
    /// `tcx_egress`, `netkit_primary`, `netkit_peer`, `cgroup`, `netfilter`,
    /// `netns`, or `unplaced` for a program of a network type found on no
    /// hook the warden reads.
    pub hook: String,
    /// The interface index the hook is on, for the interface hooks.
    pub ifindex: Option<u32>,
    /// The interface's name, when it is a host interface carrying this
    /// program. `None` with an `ifindex` is an interface in another network
    /// namespace.
    pub interface: Option<String>,
    /// Where the program runs among those on the same hook of the same host
    /// interface, the first being `0`, for the hooks that run several in
    /// turn: `tc_*`, `tcx_*` and `netkit_*`.
    #[serde(default)]
    pub position: Option<u32>,
    /// The cgroup the program is attached to, for the cgroup hooks.
    pub cgroup_id: Option<u64>,
    /// What else places it: the cgroup attach type, the netfilter family,
    /// hook and priority, the network namespace hook.
    pub detail: Option<String>,
    /// The uid that loaded it.
    pub created_by_uid: Option<u32>,
    /// The processes holding a descriptor on the program or its link.
    pub holders: Vec<u32>,
}

/// The program and link ids one process holds descriptors on.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeldBpfObjects {
    /// Programs held directly, and the programs behind each link held.
    pub prog_ids: Vec<u32>,
    /// Links held.
    pub link_ids: Vec<u32>,
}

/// Where a program the warden holds may be attached, decided by its name and
/// never by the agent's request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeldTarget {
    /// The one raw tracepoint the program was written for.
    RawTracepoint(&'static str),
    /// The one kernel function the program was written for, at entry or at
    /// return.
    Kprobe {
        /// The function, as ftrace names it.
        symbol: &'static str,
        /// `true` for a kretprobe.
        is_ret: bool,
    },
    /// A user-space function in a library the warden's own admission accepts,
    /// at an offset the request names; entry or return is the program's.
    Uprobe {
        /// `true` for a uretprobe.
        is_ret: bool,
    },
}

/// `BPF_PROG_TYPE_KPROBE`, the type uprobes share.
pub const BPF_PROG_TYPE_KPROBE: u32 = 2;
/// `BPF_PROG_TYPE_RAW_TRACEPOINT`.
pub const BPF_PROG_TYPE_RAW_TRACEPOINT: u32 = 17;

impl HeldTarget {
    /// The program type a program held for this target must have.
    #[must_use]
    pub fn prog_type(self) -> u32 {
        match self {
            Self::RawTracepoint(_) => BPF_PROG_TYPE_RAW_TRACEPOINT,
            Self::Kprobe { .. } | Self::Uprobe { .. } => BPF_PROG_TYPE_KPROBE,
        }
    }
}

/// A program the agent loads at start-up and hands to the warden, because
/// whoever holds its descriptor chooses where it reads: on the floor kernel
/// creating a raw tracepoint, `kprobe_multi` or `uprobe_multi` link checks no
/// capability, so the agent keeps none of these once it has handed them over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeldProgram {
    /// The program's name in its object, which is the name the hold, the pin
    /// and every attach request use.
    pub name: &'static str,
    /// Where it may be attached.
    pub target: HeldTarget,
    /// The family a policy switches its attach with, `None` where the
    /// program has one fixed target and every agent is served.
    pub family: Option<Family>,
}

const fn raw_tp(name: &'static str, tracepoint: &'static str) -> HeldProgram {
    HeldProgram {
        name,
        target: HeldTarget::RawTracepoint(tracepoint),
        family: None,
    }
}

const fn kprobe(name: &'static str, symbol: &'static str, is_ret: bool) -> HeldProgram {
    HeldProgram {
        name,
        target: HeldTarget::Kprobe { symbol, is_ret },
        family: Some(Family::Uprobe),
    }
}

const fn uprobe(name: &'static str, is_ret: bool) -> HeldProgram {
    HeldProgram {
        name,
        target: HeldTarget::Uprobe { is_ret },
        family: Some(Family::Uprobe),
    }
}

/// Every program the warden holds, the one list the warden's checks and the
/// agent's hand-over read.
pub const HELD_PROGRAMS: &[HeldProgram] = &[
    raw_tp("process_exec", "sched_process_exec"),
    raw_tp("process_fork", "sched_process_fork"),
    raw_tp("process_exit", "sched_process_exit"),
    raw_tp("signal_on_syscall_entry", "sys_enter"),
    raw_tp("drop_reason_kfree_skb", "kfree_skb"),
    raw_tp("tcp_health_retransmit", "tcp_retransmit_skb"),
    raw_tp("tcp_health_send_reset", "tcp_send_reset"),
    raw_tp("tcp_health_receive_reset", "tcp_receive_reset"),
    raw_tp("tcp_health_set_state", "inet_sock_set_state"),
    kprobe("ktls_sendmsg", "tls_sw_sendmsg", false),
    kprobe("ktls_recvmsg_entry", "tls_sw_recvmsg", false),
    kprobe("ktls_recvmsg_ret", "tls_sw_recvmsg", true),
    uprobe("ssl_write", false),
    uprobe("ssl_read_entry", false),
    uprobe("ssl_read_ret", true),
    uprobe("go_tls_write", false),
    uprobe("go_tls_read_entry", false),
    // Go returns are probed at each `RET` instruction, as entries.
    uprobe("go_tls_read_ret", false),
    uprobe("crypto_call", false),
];

/// The held program of that name.
#[must_use]
pub fn held_program(name: &str) -> Option<&'static HeldProgram> {
    HELD_PROGRAMS.iter().find(|p| p.name == name)
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

/// What the warden answers a [`Command::FimRead`] on a connection that opened
/// no watch, which is what a reconnect leaves the agent with.
pub const FIM_NO_WATCH: &str = "no file watch is open on this connection";

/// A filesystem the warden was asked to watch, and whether the mark took.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FimMark {
    /// The path the agent named, in the warden's mount namespace.
    pub path: String,
    /// Why the filesystem holding it is not watched, `None` when it is.
    pub error: Option<String>,
    /// Its renames are reported once with both names; `false` where the
    /// kernel refused that event, and a rename there reads as a disappearance
    /// plus an appearance.
    pub renames: bool,
}

/// A canary the warden was asked to plant, and whether it is watched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FimCanary {
    /// The path the agent named, in the warden's mount namespace.
    pub path: String,
    /// Why no canary is watched at that path, `None` when one is.
    pub error: Option<String>,
}

/// One change on a watched filesystem, its file handle already resolved.
///
/// The kernel reports the directory as a file handle, which only a holder of
/// `CAP_DAC_READ_SEARCH` can open, so the warden opens it and the agent is
/// handed a path and never a handle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FimEvent {
    /// The fanotify event bits, `FAN_CREATE`, `FAN_CLOSE_WRITE` and the rest.
    pub mask: u64,
    /// The writing thread group as the warden's pid namespace numbers it, `0`
    /// when the kernel could not name it there.
    pub pid: u32,
    /// The directory the change happened in, as the warden's mount namespace
    /// reaches it. On an overlay this is the upper directory on the backing
    /// filesystem, not the path the writer saw.
    pub directory: Option<String>,
    /// The entry inside that directory.
    pub name: String,
    /// Device of the entry, when it still exists.
    pub dev: Option<u64>,
    /// Inode of the entry, when it still exists.
    pub ino: Option<u64>,
    /// Why the directory could not be named, when it could not.
    pub unresolved: Option<String>,
    /// For a rename, the full path the entry left, when its directory could
    /// be named.
    pub renamed_from: Option<String>,
}

/// What [`Command::FimFacts`] is refused with on a connection whose watch does
/// not cover the path's filesystem.
pub const FIM_NOT_WATCHED: &str = "the path is not on a watched filesystem";

/// The kind of entry a path names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FimFileType {
    /// A regular file, hashed when not larger than asked.
    Regular,
    /// A directory.
    Directory,
    /// A symbolic link, read and never followed.
    Symlink,
    /// A device, a socket or a pipe: never opened.
    Other,
}

/// One extended attribute: its name and the digest of its value. The value
/// itself never leaves the warden.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FimXattr {
    /// The attribute's name, `security.selinux` and the like.
    pub name: String,
    /// SHA-256 of the value.
    pub sha256: [u8; 32],
}

/// How many leading bytes of a regular file the entropy is sampled over: the
/// first block the hash reads, or the whole file when it is shorter.
pub const FIM_ENTROPY_SAMPLE: usize = 64 * 1024;

/// What a path named when the warden read it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FimFile {
    /// The kind of entry.
    pub file_type: FimFileType,
    /// Size in bytes.
    pub size: u64,
    /// Modification time, nanoseconds since the epoch.
    pub mtime_ns: i64,
    /// Permission, set-id and sticky bits, without the type.
    pub mode: u32,
    /// Owner.
    pub uid: u32,
    /// Group.
    pub gid: u32,
    /// Device.
    pub dev: u64,
    /// Inode.
    pub ino: u64,
    /// Where a symbolic link points.
    pub link_target: Option<String>,
    /// SHA-256 of a regular file's content.
    pub sha256: Option<[u8; 32]>,
    /// Why a regular file carries no hash.
    pub hash_unread: Option<String>,
    /// Shannon entropy of the first [`FIM_ENTROPY_SAMPLE`] bytes of a regular
    /// file's content, in thousandths of a bit per byte, read from the bytes
    /// the hash reads. Absent where the content was not read or is empty.
    pub entropy_millibits: Option<u16>,
    /// The first four bytes of a regular file's content, read with the hash.
    /// Absent where the content was not read or is shorter than four bytes.
    pub head: Option<[u8; 4]>,
    /// Extended attributes, sorted by name.
    pub xattrs: Vec<FimXattr>,
    /// Why the extended attributes were not read.
    pub xattrs_unread: Option<String>,
}

/// What reading one path found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FimReading {
    /// The entry, read.
    Present(FimFile),
    /// Nothing is at the path.
    Gone,
    /// The path could not be read, for this reason.
    Unreadable(String),
}

/// One path and what reading it found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FimFacts {
    /// The path as asked for.
    pub path: String,
    /// What was found there.
    pub reading: FimReading,
}

/// One socket a listing showed inside a namespace, reduced to what explains a
/// refused bind. Duplicates are folded, so an estate of connections on one
/// port is one entry per state rather than one per connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ListedPort {
    /// `true` for UDP, `false` for TCP.
    pub udp: bool,
    /// The local port, in host order.
    pub port: u16,
    /// The kernel's state number for the socket.
    pub state: u8,
    /// `true` when `sock_diag` listed it, `false` for `/proc/net`.
    pub sock_diag: bool,
}

/// One bind the hidden port probe made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BindProbe {
    /// `true` for UDP, `false` for TCP.
    pub udp: bool,
    /// `true` for the IPv6 wildcard, `false` for the IPv4 one.
    pub ipv6: bool,
    /// The port, in host order.
    pub port: u16,
}

/// What `/proc/<pid>` said about a pid that answered a signal and was not
/// listed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PidObservation {
    pub pid: u32,
    /// The thread group, from `status`.
    pub tgid: Option<u32>,
    /// The start time in clock ticks since boot, from `stat`.
    pub start_time: Option<u64>,
    /// The one-letter state, from `stat`.
    pub state: Option<char>,
    /// The command name, from `stat`.
    pub comm: Option<String>,
}

/// The two readings of the hidden process check.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HiddenProcessReading {
    /// Why the sweep was not taken; everything else is then empty.
    pub error: Option<String>,
    /// `pid_max`, the size of the pid space swept.
    pub pid_space: u32,
    /// Pids signalled.
    pub probed: u32,
    /// Thread groups the first listing held.
    pub listed: u32,
    /// Pids that answered and a listed group's `task` directory held.
    pub threads: u32,
    /// Pids that answered and were listed nowhere, as first observed.
    pub first: Vec<PidObservation>,
    /// Of those, the pids the second listing held.
    pub relisted: Vec<u32>,
    /// Of those, the pids that answered the second signal, observed again.
    pub second: Vec<PidObservation>,
}

/// The kernel's ceiling on `pid_max`, the largest pid space a sweep covers.
pub const HIDDEN_PROCESSES_PID_SPACE_MAX: u32 = 4_194_304;
/// The slowest pace a sweep may be asked for, in pids per second.
pub const HIDDEN_PROCESSES_RATE_MIN: u32 = 10_000;
/// The fastest pace a sweep may be asked for, in pids per second.
pub const HIDDEN_PROCESSES_RATE_MAX: u32 = 10_000_000;

/// How long a caller waits for a sweep asked at `rate`: the largest pid
/// space at that pace, with a minute for the listings and the observations
/// around it. A sweep is paced on purpose, so the timeout every other call
/// gets would abandon it on any host whose `pid_max` is the 64-bit default.
#[must_use]
pub fn hidden_processes_call_timeout(rate: u32) -> std::time::Duration {
    let rate = rate.clamp(HIDDEN_PROCESSES_RATE_MIN, HIDDEN_PROCESSES_RATE_MAX);
    let paced = HIDDEN_PROCESSES_PID_SPACE_MAX.div_ceil(rate);
    std::time::Duration::from_secs(u64::from(paced) + 60)
}

/// One network namespace, the id it carries and a process inside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamespaceIdReading {
    /// The namespace's inode.
    pub netns: u64,
    /// The id it carries as seen from the warden's namespace, `None` when the
    /// kernel has given it none yet.
    pub nsid: Option<i32>,
    /// The lowest pid sitting in it.
    pub pid: u32,
}

/// What the hidden port probe read inside one network namespace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamespacePortReading {
    /// The namespace's inode.
    pub netns: u64,
    /// Whether it is the host's.
    pub host_netns: bool,
    /// Why the namespace could not be entered; everything else is then empty.
    pub error: Option<String>,
    /// Both listings, taken before the first probe.
    pub first_listing: Vec<ListedPort>,
    /// Both listings, taken again before the second probe.
    pub second_listing: Vec<ListedPort>,
    /// Binds the first pass attempted.
    pub probed: u32,
    /// Binds refused for another reason than the port being in use.
    pub unprobed: u32,
    /// Binds the first pass saw refused as in use.
    pub refused_first: Vec<BindProbe>,
    /// The first pass's refusals refused again by the second.
    pub refused_second: Vec<BindProbe>,
}

/// The longest piece of a file one [`Command::ReadRootedFile`] hands back,
/// well inside a frame.
pub const ROOTED_CHUNK_MAX: u32 = 8 * 1024 * 1024;

/// The longest dpkg list name the warden opens.
const DPKG_LIST_NAME_MAX: usize = 128;

/// A package database file, named by what it is rather than by a path, so
/// the warden opens only the files on this list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RootedFile {
    /// `var/lib/dpkg/status`.
    DpkgStatus,
    /// `var/lib/dpkg/info/<name>.list`, the files one package owns.
    DpkgList {
        /// The package name, with `:arch` for a `Multi-Arch: same` package.
        name: String,
    },
    /// The rpm database in its SQLite form.
    RpmSqlite,
    /// The rpm database in its Berkeley DB form.
    RpmBerkeley,
    /// The rpm database in its ndb form.
    RpmNdb,
    /// The Alpine installed database.
    ApkInstalled,
}

impl RootedFile {
    /// The paths, relative to the root, this file is looked for at, in
    /// order; `None` for a dpkg list whose name is not a package name.
    #[must_use]
    pub fn candidates(&self) -> Option<Vec<String>> {
        let fixed: &[&str] = match self {
            Self::DpkgStatus => &["var/lib/dpkg/status"],
            Self::DpkgList { name } => {
                return valid_dpkg_list_name(name)
                    .then(|| vec![format!("var/lib/dpkg/info/{name}.list")]);
            }
            Self::RpmSqlite => &[
                "usr/lib/sysimage/rpm/rpmdb.sqlite",
                "var/lib/rpm/rpmdb.sqlite",
            ],
            Self::RpmBerkeley => &["usr/lib/sysimage/rpm/Packages", "var/lib/rpm/Packages"],
            Self::RpmNdb => &[
                "usr/lib/sysimage/rpm/Packages.db",
                "var/lib/rpm/Packages.db",
            ],
            Self::ApkInstalled => &["lib/apk/db/installed", "usr/lib/apk/db/installed"],
        };
        Some(fixed.iter().map(|p| (*p).to_string()).collect())
    }
}

/// Whether `name` is a dpkg package name, optionally with `:arch`: lower
/// case letters, digits and `+.-`, starting with a letter or a digit, so it
/// can name nothing but a file in the info directory.
#[must_use]
pub fn valid_dpkg_list_name(name: &str) -> bool {
    let (package, arch) = match name.split_once(':') {
        Some((p, a)) => (p, Some(a)),
        None => (name, None),
    };
    let lead = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit();
    name.len() <= DPKG_LIST_NAME_MAX
        && package.starts_with(lead)
        && package
            .chars()
            .all(|c| lead(c) || matches!(c, '+' | '.' | '-'))
        && arch.is_none_or(|a| !a.is_empty() && a.chars().all(|c| lead(c) || c == '-'))
}

/// What reading a [`RootedFile`] gave.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RootedRead {
    /// None of its candidate paths exists in that root.
    Absent,
    /// It exists, or the root does, and could not be read, and why.
    Unreadable { reason: String },
    /// A piece of it.
    Chunk {
        /// The candidate path it was found at, relative to the root.
        path: String,
        /// `st_dev` and `st_ino` of the file, so pieces of one reading can
        /// be told from pieces of a file replaced in between.
        dev: u64,
        ino: u64,
        /// The whole file's size.
        size: u64,
        /// Its modification time, in nanoseconds since the epoch, so a
        /// reader can tell an unchanged file without reading it again.
        mtime_ns: i64,
        /// The bytes from the offset asked for.
        data: Vec<u8>,
    },
}

/// One filesystem root processes run in, named by its lowest pid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileRoot {
    /// The lowest pid whose root this is.
    pub pid: u32,
    /// `st_dev` and `st_ino` of the root directory.
    pub dev: u64,
    pub ino: u64,
    /// Whether it is the root of pid 1.
    pub host: bool,
    /// `/proc/<pid>/cgroup`, for the agent to name the container by.
    pub cgroup: String,
}

/// The most bytes of one `.go.buildinfo` section handed back.
pub const GO_BUILDINFO_MAX: usize = 1024 * 1024;

/// The most section bytes one [`Response::GoExecutables`] carries in all,
/// well inside a frame.
pub const GO_SCAN_BYTES_MAX: usize = 12 * 1024 * 1024;

/// The most pids named per executable.
pub const GO_PIDS_MAX: usize = 16;

/// One running executable carrying a Go build information section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoExecutable {
    /// `st_dev` and `st_ino` of the executable, the identity it is
    /// deduplicated by.
    pub dev: u64,
    pub ino: u64,
    /// What `/proc/<pid>/exe` names, inside the root of the process.
    pub path: String,
    /// The pids running it, lowest first, at most [`GO_PIDS_MAX`].
    pub pids: Vec<u32>,
    /// Whether the lowest of them runs in pid 1's root.
    pub host: bool,
    /// `/proc/<pid>/cgroup` of the lowest, for the agent to name the
    /// container by.
    pub cgroup: String,
    /// The section's bytes, at most [`GO_BUILDINFO_MAX`]; `None` when it
    /// could not be read, with `error` saying why.
    pub buildinfo: Option<Vec<u8>>,
    pub error: Option<String>,
}

/// Every running Go executable found in one pass over `/proc`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoExecutableScan {
    /// Distinct executables opened, Go or not.
    pub examined: u32,
    /// Those carrying a `.go.buildinfo` section.
    pub executables: Vec<GoExecutable>,
    /// Go executables found past [`GO_SCAN_BYTES_MAX`], left out.
    pub not_read: u32,
}

/// The most processes one [`Response::ProcessMappings`] lists.
pub const MAPPED_PIDS_MAX: usize = 65_536;

/// The most bytes of one process's `/proc/<pid>/maps` read.
pub const MAPS_BYTES_MAX: usize = 4 * 1024 * 1024;

/// The most distinct executable files one process is listed as mapping.
pub const MAPPED_FILES_PER_PID_MAX: usize = 4096;

/// The most path bytes one [`Response::ProcessMappings`] carries in its
/// file table, well inside a frame; changed processes past it are left for
/// the next call.
pub const MAPPINGS_BYTES_MAX: usize = 8 * 1024 * 1024;

/// What tells one process apart from the one before it under the same pid,
/// and its mappings from the ones it had: a process whose stamp has not moved
/// is not read again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessStamp {
    pub pid: u32,
    /// `starttime` of `/proc/<pid>/stat`, in clock ticks since boot.
    pub start_time: u64,
    /// `vsize` of `/proc/<pid>/stat`, which moves when a mapping is added
    /// or removed.
    pub vsize: u64,
}

/// One file mapped executable by at least one process.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MappedFile {
    /// The device and inode `/proc/<pid>/maps` names.
    pub dev: u64,
    pub ino: u64,
    /// The path as the process sees it, inside its own root.
    pub path: String,
    /// The file was unlinked after it was mapped.
    pub deleted: bool,
}

/// The executable mappings of one process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessMappings {
    pub stamp: ProcessStamp,
    /// `st_dev` and `st_ino` of `/proc/<pid>/root`, the root it runs in.
    pub root_dev: u64,
    pub root_ino: u64,
    /// Indices into [`MappingScan::files`].
    pub files: Vec<u32>,
    /// Its maps were longer than [`MAPS_BYTES_MAX`] or it mapped more than
    /// [`MAPPED_FILES_PER_PID_MAX`] files, and the rest is left out.
    pub truncated: bool,
    /// Why it could not be read; its files are then empty.
    pub error: Option<String>,
}

/// One pass over the processes, reading only the ones whose stamp moved.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MappingScan {
    /// Every process listed, with its stamp, at most [`MAPPED_PIDS_MAX`].
    pub processes: Vec<ProcessStamp>,
    /// Processes past [`MAPPED_PIDS_MAX`], not listed.
    pub not_listed: u32,
    /// The processes read in this call: those the caller did not know.
    pub read: Vec<ProcessMappings>,
    /// The files [`ProcessMappings::files`] point into.
    pub files: Vec<MappedFile>,
    /// Processes to read that [`MAPPINGS_BYTES_MAX`] left for another call.
    pub pending: u32,
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
    /// Replace the main table's default route (multi-WAN gateway failover).
    /// Any other destination or table is refused by the warden.
    RouteAdd {
        /// The route to install.
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
    /// Attach the held uprobe program `program` at `offset` within the ELF at
    /// `path`, entry or return as [`HELD_PROGRAMS`] lists it. The warden
    /// creates the `uprobe_multi` link from the program it holds - the agent
    /// sends none - resolving `path` in its own mount and pid namespace, and
    /// returns the link fd via [`Response::FdReady`], so dropping it detaches.
    /// The path passes the warden's uprobe admission.
    AttachUprobe {
        /// A held program whose target is [`HeldTarget::Uprobe`].
        program: String,
        /// Absolute path to the target ELF (e.g.
        /// `/proc/<pid>/root/usr/lib/libssl.so.3`).
        path: String,
        /// File offset of the symbol to probe.
        offset: u64,
    },
    /// Attach the cgroup-type eBPF program whose fd rides in the accompanying
    /// `SCM_RIGHTS` cmsg (sent right after this frame) to the cgroup directory
    /// at `cgroup_path`, for `attach_type` (`enum bpf_attach_type`). The warden
    /// creates the link - it holds the capability the rootless agent dropped
    /// and resolves the path in its own mount namespace - and returns the link
    /// fd via [`Response::FdReady`], so the attachment dies with the agent that
    /// owns the fd rather than outliving it on the cgroup.
    ///
    /// The warden refuses a path outside the cgroup hierarchy and an attach
    /// type outside the socket hooks it is meant to serve: this must not become
    /// a general-purpose root-held cgroup attach service.
    AttachCgroup {
        /// Absolute path to the cgroup v2 directory, under `/sys/fs/cgroup`.
        cgroup_path: String,
        /// The `enum bpf_attach_type` number to attach for.
        attach_type: u32,
    },
    /// Scan `/proc` for SSL libraries mapped by any process and return one
    /// [`DlpTarget`] per unique `(dev, ino)`, with `SSL_write` / `SSL_read`
    /// offsets pre-resolved. Reading another process's `/proc/<pid>/maps` and ELF
    /// needs `CAP_SYS_PTRACE`, which the rootless agent dropped - so it delegates
    /// the whole discovery to the warden and only keeps the attach lifecycle.
    DlpScan,
    /// An opaque, namespaced extension operation. The OSS warden does not
    /// interpret it: a downstream build (e.g. the enterprise warden) installs an
    /// extension handler keyed on `kind` that owns the `payload` semantics, and an
    /// OSS warden with no handler answers [`Response::Unimplemented`]. This keeps
    /// build-specific privileged operations out of the shared protocol - `kind`
    /// namespaces the op, `payload` is its serialized request, and the reply rides
    /// in [`Response::Extension`]. Carries no enterprise-specific fields, so the
    /// AGPL protocol stays agnostic to whatever a handler does with it.
    Extension {
        /// Namespacing key identifying the extension operation.
        kind: String,
        /// Opaque serialized request, defined by the handler for `kind`.
        payload: Vec<u8>,
    },
    /// Read the programs attached to `iface`'s TCX ingress (or, with
    /// `egress`, egress) hook, in the order the kernel runs them, answered by
    /// [`Response::TcxChain`]. `BPF_PROG_QUERY` wants `CAP_NET_ADMIN` in the
    /// initial user namespace, which the agent's own namespace does not
    /// confer, so the agent cannot read back where its classifiers landed
    /// without asking. Read-only: it names program ids and nothing else.
    TcxChain {
        /// Interface whose chain is read.
        iface: String,
        /// `true` for the egress hook, `false` for ingress.
        egress: bool,
    },
    /// Attach the TC program whose fd rides in the accompanying `SCM_RIGHTS`
    /// cmsg (sent right after this frame) on `iface`'s TCX ingress (or, with
    /// `egress`, egress) hook inside the network namespace of process `pid`.
    /// A pod's own interface and its loopback live only in that namespace,
    /// and entering it wants `CAP_SYS_ADMIN` over the namespace's owner,
    /// which the agent's user namespace does not hold. The warden refuses a
    /// process outside a pod's cgroup and a namespace that is the host's or
    /// its own, then answers [`Response::FdReady`] followed by the link fd.
    AttachTcxInNetns {
        /// A process in the pod whose namespace is entered.
        pid: u32,
        /// Interface inside that namespace.
        iface: String,
        /// `true` for the egress hook, `false` for ingress.
        egress: bool,
    },
    /// Name the executable process `pid` runs, answered by
    /// [`Response::Executable`]. Reading another process's `/proc/<pid>/exe`
    /// is a ptrace access check, and a task in the agent's user namespace
    /// holds no `CAP_SYS_PTRACE` over a process outside it, so the rootless
    /// agent cannot name a single binary on the host without asking.
    /// Read-only: a path, a device and an inode, nothing from the process's
    /// memory or environment.
    ReadExecutable {
        /// The process whose executable is named.
        pid: u32,
    },
    /// List every `AF_PACKET` socket on the node, in every network namespace,
    /// with the process holding it and whether a classic BPF filter is
    /// attached. Read-only, and it takes no argument: the warden decides
    /// which namespaces it reads from what `/proc` shows it.
    PacketSockets,
    /// List every eBPF program on the node's network path: the BPF links,
    /// the XDP program and classic `tc` filters of each host interface, and
    /// the programs of a network type found on none of those, each with the
    /// processes holding it. Enumerating programs and links by id needs
    /// `CAP_SYS_ADMIN`, which no BPF token grants. Read-only.
    NetworkPrograms,
    /// Name the warden's own thread group and the pid namespace it is
    /// numbered in, so the agent can let it read the agent's links once the
    /// kernel refuses them to everybody else. Read-only.
    Identity,
    /// Watch the filesystems holding each of `paths` for changes, answered by
    /// [`Response::FimOpened`]. The watch belongs to this connection and ends
    /// with it, and a second `FimOpen` replaces the first. A filesystem mark
    /// needs `CAP_SYS_ADMIN` and resolving what it reports needs
    /// `CAP_DAC_READ_SEARCH`, neither of which the agent holds. Read-only: the
    /// group is a notification group, it can delay or refuse nothing.
    FimOpen {
        /// Paths in the warden's mount namespace; each marks the whole
        /// filesystem it lives on.
        paths: Vec<String>,
    },
    /// Hand over the changes the watch opened on this connection has seen,
    /// waiting at most `max_wait_ms` for the first one, answered by
    /// [`Response::FimEvents`].
    FimRead {
        /// How long to wait when nothing is queued, capped by the warden.
        max_wait_ms: u32,
    },
    /// Read what each path names, its content hashed when it is a regular
    /// file no larger than `max_hash_bytes`, answered by
    /// [`Response::FimFactsRead`]. Only a path on a filesystem this
    /// connection's watch covers is read; another is answered as unreadable.
    FimFacts {
        /// Absolute paths, as the warden's mount namespace reaches them.
        paths: Vec<String>,
        /// A regular file larger than this is not hashed.
        max_hash_bytes: u64,
    },
    /// Plant a canary at each path and watch it for any open or read,
    /// answered by [`Response::FimCanaries`]. A canary is a small file of
    /// fixed content created where none exists; a file already at the path
    /// is kept only when it holds that content. Each path must sit on a
    /// filesystem this connection's watch covers, and an open of one reads
    /// through [`Command::FimRead`] like any other change. The warden's own
    /// reads of a canary are never reported.
    FimCanaries {
        /// Absolute paths, as the warden's mount namespace reaches them.
        paths: Vec<String>,
    },
    /// In every network namespace `/proc` shows, read the TCP and UDP
    /// listings from `/proc/net` and `sock_diag`, then bind each of `ports`
    /// on both wildcards and both transports with no reuse option and
    /// release it at once; take the listings again and probe the refused
    /// ports a second time. Answered by [`Response::HiddenPorts`]. The bind
    /// is the only thing done in a namespace and nothing is left open.
    HiddenPorts {
        /// The ports to probe, at most 65535 of them.
        ports: Vec<u16>,
    },
    /// List `/proc`, then `kill(pid, 0)` every pid up to `pid_max` at about
    /// `rate` pids a second, which delivers nothing; observe the pids that
    /// answered and were not listed, list again and signal them again.
    /// Answered by [`Response::HiddenProcesses`].
    HiddenProcesses {
        /// The pace, in pids per second, clamped by the warden.
        rate: u32,
    },
    /// List the distinct filesystem roots processes run in, one entry per
    /// root, answered by [`Response::FileRoots`]. Read-only.
    FileRoots,
    /// Read up to `len` bytes from `offset` of `file` inside the root of
    /// `pid`, answered by [`Response::RootedRead`]. The path is resolved
    /// inside that root, so a link cannot lead out of it, and only a regular
    /// file is read. Read-only.
    ReadRootedFile {
        pid: u32,
        file: RootedFile,
        offset: u64,
        /// Capped by [`ROOTED_CHUNK_MAX`].
        len: u32,
    },
    /// Open the executable of every process once per distinct inode and
    /// hand back the `.go.buildinfo` section of those that carry one,
    /// answered by [`Response::GoExecutables`]. Read-only: an executable's
    /// ELF headers and one section, nothing from any process's memory.
    GoExecutables,
    /// List every process with its stamp and read the executable mappings
    /// of those whose stamp is not in `known`, answered by
    /// [`Response::ProcessMappings`]. Read-only: `/proc/<pid>/stat`,
    /// `/proc/<pid>/maps` and the root's identity, nothing from any
    /// process's memory.
    ProcessMappings { known: Vec<ProcessStamp> },
    /// Open a fanotify permission group for the write refusal and hand its
    /// descriptor over in an `SCM_RIGHTS` cmsg after [`Response::FdReady`].
    /// A permission class needs `CAP_SYS_ADMIN` in the initial user
    /// namespace, which the rootless agent does not hold. The warden keeps no
    /// copy: the agent's descriptor is the group's only one, so the agent's
    /// death or its stop closes the group and the kernel allows every open
    /// still waiting.
    WriteRefusalGroup,
    /// Read what each thread blocked on a permission event says about its
    /// open, answered by [`Response::OpenerReadings`] in the order asked.
    /// Reading another process's pending system call is a ptrace access
    /// check the rootless agent fails. Read-only: `/proc` and the cgroup tree.
    OpenerReadings {
        /// The threads, as the agent's pid namespace numbers them.
        tids: Vec<u32>,
    },
    /// Read the two facts the process detection weighs about process `pid`,
    /// answered by [`Response::ProcessFacts`]. The `exe` link and the
    /// standard stream links are ptrace access checks the rootless agent
    /// fails against every process outside its user namespace. Read-only:
    /// three link targets and the process's own internet socket tables, and
    /// what crosses back is two booleans, never a path or a file name.
    ReadProcessFacts {
        /// The process whose facts are read.
        pid: u32,
    },
    /// Open the file process `pid` runs, read-only, through its `exe` link,
    /// and hand the descriptor over in an `SCM_RIGHTS` cmsg after
    /// [`Response::FdReady`], so the agent can digest the file the process
    /// mapped. Opening that link is the same ptrace access check as reading
    /// it. The descriptor reaches the file on disk and nothing of the
    /// process's memory or environment; a process that is gone, or whose
    /// image is not a regular file, answers a typed `Error`.
    OpenExecutable {
        /// The process whose executable is opened.
        pid: u32,
    },
    /// Read the one client process `pid` serves on a file-service port,
    /// answered by [`Response::ServedPeer`]. A file server forks one process
    /// per client, and naming that client means reading the process's socket
    /// links, the ptrace access check the rootless agent fails against a
    /// service running as root. Read-only: the `fd` links and the process's
    /// own TCP tables, and what crosses back is one address.
    ReadServedPeer {
        /// The file service process whose client is read.
        pid: u32,
    },
    /// List the processes holding an established connection to a
    /// file-service port of one of `servers`, answered by
    /// [`Response::ShareWriters`]. Naming them means reading every process's
    /// socket links, the ptrace access check the rootless agent fails against
    /// any process of another user. Read-only: the `fd` links and the TCP
    /// tables of each network namespace, and what crosses back is pids. At
    /// most [`MAX_SHARE_SERVERS`] servers are read; the rest are ignored.
    ReadShareWriters {
        /// The file servers whose clients are listed.
        servers: Vec<std::net::IpAddr>,
    },
    /// Connect to the rootless Podman API of user `uid` and hand the
    /// connected stream over, answered out-of-band by [`Response::FdReady`]
    /// and the descriptor. A user's socket is mode `0600` inside a `0700`
    /// directory, which the agent's own user namespace cannot enter. The
    /// path is the warden's, `/run/user/<uid>/podman/podman.sock`, never the
    /// agent's, and a socket not owned by `uid` is refused, so what crosses
    /// is a connection to that one user's runtime and nothing else. Root's
    /// runtime is not served here: the agent reaches it itself.
    ConnectPodman {
        /// The user whose runtime is connected to; never 0.
        uid: u32,
    },
    /// Write one established TCP flow into the conntrack table (a
    /// `CAP_NET_ADMIN` netlink operation).
    ConntrackRestore {
        /// The flow to restore.
        restore: ConntrackRestore,
    },
    /// Name, for every network namespace `/proc` shows, the id it carries as
    /// seen from the warden's own namespace and one process sitting in it,
    /// answered by [`Response::NamespaceIds`]. Read-only: a rootless agent
    /// cannot open another user's namespace to ask, so the warden asks for it.
    NamespaceIds,
    /// Bind the socket the DNS allow-list resolver serves on and hand it over
    /// in an `SCM_RIGHTS` cmsg after [`Response::FdReady`]: a UDP socket, or a
    /// listening TCP socket when `stream`. Port 53 sits below the unprivileged
    /// range and the rootless agent holds no `CAP_NET_BIND_SERVICE` on the
    /// host. Only port 53 on an address that is neither loopback nor
    /// unspecified is bound, so the warden lends no other privileged port.
    ResolverSocket {
        /// The address the containers are pointed at.
        listen: std::net::SocketAddr,
        /// A TCP listener rather than a UDP socket.
        stream: bool,
    },
    /// Pin the BPF link whose fd rides in the accompanying `SCM_RIGHTS` cmsg
    /// (sent right after this frame) under `name` in the warden's link
    /// directory on the host bpffs, replacing a pin of that name. The agent's
    /// own bpffs lives in its mount namespace and goes with it; a pin on the
    /// host's keeps the hook attached after the agent exits, which is the
    /// point. `name` is checked against [`valid_link_pin_name`].
    PinLink {
        /// The pin's file name.
        name: String,
    },
    /// Name every link pinned in the warden's link directory, answered by
    /// [`Response::PinnedLinks`].
    PinnedLinks,
    /// Open the pinned link `name` and hand its fd over in an `SCM_RIGHTS`
    /// cmsg after [`Response::FdReady`], so a restarted agent swaps its own
    /// program onto the hook rather than attaching a second one.
    OpenPinnedLink {
        /// The pin's file name.
        name: String,
    },
    /// Remove the pins `names` from the warden's link directory, or every
    /// pin there when `names` is empty. A link no process holds detaches
    /// with its last pin.
    UnpinLinks {
        /// The pins to remove; empty for all of them.
        names: Vec<String>,
    },
    /// Open a connection to the API of a container runtime root runs on the
    /// host and hand the agent's end over in an `SCM_RIGHTS` cmsg after
    /// [`Response::FdReady`]. That API is root on the host, so what crosses
    /// is never the runtime's socket: it is one end of a pair whose other end
    /// the warden reads. The warden takes one request from it, refuses it
    /// unless it is a `GET` of a path in [`root_runtime_path_allowed`], sends
    /// a request of its own for that path on the socket it names itself, and
    /// copies the answer back. The agent writes nothing else the runtime sees.
    ConnectRootRuntime {
        /// Which runtime is asked.
        runtime: RootRuntime,
    },
    /// Read one Podman container's record from its owner's container store,
    /// answered by [`Response::PodmanRecord`]. Podman is daemonless and its
    /// socket is off unless enabled, while its store is always written, and
    /// is root's to read. Read-only: the store's `db.sql` opened read-only,
    /// else its `containers.json`, and what crosses back is the container's
    /// name, image, labels, creation time and state, nothing else. A store
    /// whose directory is not owned by the container's owner is not read.
    ReadPodmanRecord {
        /// The owner, `None` for root.
        uid: Option<u32>,
        /// Root's store directory, absolute; for a user, the store relative
        /// to the home the password file gives them.
        store: String,
        /// The container's 64-hex-digit id.
        id: String,
    },
    /// Hand the warden the program named `name`, whose fd rides in the
    /// `SCM_RIGHTS` cmsg sent right after this frame. Accepted only for a
    /// name in [`HELD_PROGRAMS`] and a program of the type listed for it; the
    /// warden pins it in a directory of its own, replacing a program held
    /// under that name before, and answers [`Response::Ok`]. The agent closes
    /// its copies once the answer is in.
    HoldProgram {
        /// The program's name in its object.
        name: String,
    },
    /// Attach the held program `program` to the raw tracepoint or kernel
    /// function [`HELD_PROGRAMS`] lists for it, and return the link fd via
    /// [`Response::FdReady`]. A uprobe program is attached with
    /// [`Command::AttachUprobe`].
    AttachHeld {
        /// A held program whose target is a raw tracepoint or a kprobe.
        program: String,
    },
}

/// What [`Command::ReadPodmanRecord`] found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PodmanStoreRead {
    /// No store there, or not owned by the container's owner.
    NoStore,
    /// The store is there and does not list the container.
    Missing,
    /// The container's record.
    Found(PodmanRecord),
}

/// One container as Podman's store records it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PodmanRecord {
    /// The container's name.
    pub name: String,
    /// The image it was created from, by name, else by id.
    pub image: String,
    /// Its labels, sorted by key; empty when only `containers.json` was
    /// there, which does not carry them.
    pub labels: Vec<(String, String)>,
    /// Whether the labels were read, from the database.
    pub labels_read: bool,
    /// When it was created, RFC 3339.
    pub created: String,
    /// Its state: `created`, `running`, `exited` and so on; empty when not
    /// recorded.
    pub status: String,
}

/// A Podman container id: 64 lowercase hex digits.
#[must_use]
pub fn valid_podman_id(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// A container runtime root runs, reached through
/// [`Command::ConnectRootRuntime`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RootRuntime {
    /// The Docker Engine, at `/var/run/docker.sock`.
    Docker,
    /// Podman's rootful service, at `/run/podman/podman.sock`.
    Podman,
}

impl RootRuntime {
    /// The socket the warden connects to, as the host names it.
    #[must_use]
    pub fn socket(self) -> &'static str {
        match self {
            Self::Docker => "/var/run/docker.sock",
            Self::Podman => "/run/podman/podman.sock",
        }
    }
}

/// The Docker API version every path the agent asks for carries; Podman
/// serves the same compatible paths.
pub const ROOT_RUNTIME_API_PREFIX: &str = "/v1.43";

/// Whether `target`, the request target of a `GET` the agent wrote to a root
/// runtime, is one the warden forwards. Six reads, and nothing else: the
/// liveness ping, the container list, one container's inspect, the network
/// list, one network's inspect, and the event stream. An id or a name is
/// letters, digits, `_`, `.` and `-`, so no segment can climb out of its
/// path, and only the three list reads take a query.
#[must_use]
pub fn root_runtime_path_allowed(target: &str) -> bool {
    fn id(segment: &str) -> bool {
        !segment.is_empty()
            && segment.len() <= 128
            && segment
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
            && segment != "."
            && segment != ".."
    }
    fn query(q: &str) -> bool {
        q.len() <= 2048
            && q.bytes()
                .all(|b| b.is_ascii_graphic() && !matches!(b, b'#' | b'/' | b'\\'))
    }
    if target == "/_ping" {
        return true;
    }
    let Some(rest) = target.strip_prefix(ROOT_RUNTIME_API_PREFIX) else {
        return false;
    };
    let (path, q) = match rest.split_once('?') {
        Some((path, q)) => (path, Some(q)),
        None => (rest, None),
    };
    if q.is_some_and(|q| !query(q)) {
        return false;
    }
    let segments: Vec<&str> = path.split('/').collect();
    match segments.as_slice() {
        ["", "containers", "json"] | ["", "networks" | "events"] => true,
        ["", "containers", container, "json"] => q.is_none() && id(container),
        ["", "networks", network] => q.is_none() && id(network),
        _ => false,
    }
}

/// Longest link pin name the warden accepts.
pub const LINK_PIN_NAME_MAX: usize = 200;

/// Whether `name` may name a link pin: non-empty, at most
/// [`LINK_PIN_NAME_MAX`] bytes, ASCII letters, digits, `-` and `_` only. A
/// bpffs refuses a dot in a name, and a slash would leave the directory.
#[must_use]
pub fn valid_link_pin_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= LINK_PIN_NAME_MAX
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The most servers one [`Command::ReadShareWriters`] reads.
pub const MAX_SHARE_SERVERS: usize = 64;

/// The most threads one [`Command::OpenerReadings`] reads.
pub const OPENER_READINGS_MAX: usize = 1_024;

/// What an opener's pending system call says about its open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OpenIntent {
    /// A write access mode, a truncation or a `creat`.
    Write,
    /// A read-only open.
    Read,
    /// The call could not be read or is not an open.
    Unknown,
}

/// What the warden read about one thread blocked on a permission event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenerReading {
    /// What the pending open asks for.
    pub intent: OpenIntent,
    /// The thread's group, `0` when the thread is gone.
    pub tgid: u32,
    /// The inode of its cgroup directory, `0` when unread.
    pub cgroup_id: u64,
    /// The device and inode of its executable, when readable.
    pub exe: Option<(u64, u64)>,
}

impl OpenerReading {
    /// A thread that could not be read at all.
    pub const GONE: Self = Self {
        intent: OpenIntent::Unknown,
        tgid: 0,
        cgroup_id: 0,
        exe: None,
    };
}

/// A thread group as one pid namespace numbers it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskIdentity {
    /// The thread group, as `getpid(2)` answers inside the namespace.
    pub tgid: u32,
    /// `st_dev` of `/proc/self/ns/pid`, in the encoding `stat(2)` returns.
    pub pid_ns_dev: u64,
    /// `st_ino` of `/proc/self/ns/pid`.
    pub pid_ns_ino: u64,
}

impl TaskIdentity {
    /// The calling process, as its own pid namespace numbers it.
    ///
    /// # Errors
    ///
    /// Returns the error of the `stat` of `/proc/self/ns/pid`, which fails
    /// where no procfs is mounted.
    pub fn of_self() -> io::Result<Self> {
        use std::os::unix::fs::MetadataExt;
        let ns = std::fs::metadata("/proc/self/ns/pid")?;
        Ok(Self {
            tgid: std::process::id(),
            pid_ns_dev: ns.dev(),
            pid_ns_ino: ns.ino(),
        })
    }
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
    /// The programs on one TCX hook, first to run first, answering
    /// [`Command::TcxChain`].
    TcxChain {
        /// Program ids in run order.
        prog_ids: Vec<u32>,
    },
    /// The executable behind one process, answering
    /// [`Command::ReadExecutable`]; `None` when the process is gone or its
    /// link is unreadable.
    Executable {
        /// What `/proc/<pid>/exe` named, when it named anything.
        executable: Option<ExecutableIdentity>,
    },
    /// Every packet socket on the node, answering [`Command::PacketSockets`].
    PacketSockets {
        /// One entry per socket, in no particular order.
        sockets: Vec<PacketSocket>,
    },
    /// Every eBPF program on the network path, answering
    /// [`Command::NetworkPrograms`].
    NetworkPrograms {
        /// One entry per program and hook, in no particular order.
        programs: Vec<NetworkProgram>,
    },
    /// The warden's own thread group, answering [`Command::Identity`].
    Identity {
        /// The warden, as its pid namespace numbers it.
        identity: TaskIdentity,
    },
    /// The outcome of every mark, answering [`Command::FimOpen`], in the
    /// order the paths were given.
    FimOpened {
        /// One entry per path asked for.
        marks: Vec<FimMark>,
    },
    /// The changes read since the last [`Command::FimRead`].
    FimEvents {
        /// In the order the kernel queued them.
        events: Vec<FimEvent>,
        /// The kernel's queue overflowed and changes were lost before these.
        overflowed: bool,
    },
    /// The outcome of every canary, answering [`Command::FimCanaries`], in
    /// the order the paths were given.
    FimCanaries {
        /// One entry per path asked for.
        canaries: Vec<FimCanary>,
    },
    /// What the paths of a [`Command::FimFacts`] name, in the order asked.
    /// Fewer entries than paths means the warden's reading budget ran out
    /// and the rest are to be asked for again.
    FimFactsRead {
        /// One entry per path read.
        facts: Vec<FimFacts>,
    },
    /// What each namespace answered, answering [`Command::HiddenPorts`].
    HiddenPorts {
        /// One entry per network namespace found.
        namespaces: Vec<NamespacePortReading>,
    },
    /// The two readings, answering [`Command::HiddenProcesses`].
    HiddenProcesses { reading: HiddenProcessReading },
    /// One entry per network namespace found, answering
    /// [`Command::NamespaceIds`].
    NamespaceIds { namespaces: Vec<NamespaceIdReading> },
    /// The roots found, answering [`Command::FileRoots`].
    FileRoots { roots: Vec<FileRoot> },
    /// What was read, answering [`Command::ReadRootedFile`].
    RootedRead { read: RootedRead },
    /// The Go executables found, answering [`Command::GoExecutables`].
    GoExecutables { scan: GoExecutableScan },
    /// The processes and the mappings read, answering
    /// [`Command::ProcessMappings`].
    ProcessMappings { scan: MappingScan },
    /// One reading per thread asked, answering [`Command::OpenerReadings`].
    OpenerReadings { readings: Vec<OpenerReading> },
    /// The facts of one process, answering [`Command::ReadProcessFacts`];
    /// `None` when the process is gone or its `exe` link is unreadable.
    ProcessFacts { facts: Option<ProcessFactsReading> },
    /// The client of one file service process, answering
    /// [`Command::ReadServedPeer`]; `None` when the process is gone, holds no
    /// file-service connection, or serves several addresses.
    ServedPeer { peer: Option<std::net::IpAddr> },
    /// The processes connected to a file-service port of one of the servers
    /// asked, lowest pid first, answering [`Command::ReadShareWriters`].
    ShareWriters { pids: Vec<u32> },
    /// The links pinned in the warden's link directory, by pin name,
    /// answering [`Command::PinnedLinks`].
    PinnedLinks { names: Vec<String> },
    /// One container's record, answering [`Command::ReadPodmanRecord`].
    PodmanRecord { read: PodmanStoreRead },
    /// The warden's policy does not serve this command: its family is off
    /// on this node, or a parameter lies outside what the configuration
    /// names. The handler was never reached.
    Refused {
        /// The family the command belongs to.
        family: Family,
        /// What the policy found wrong, naming the parameter when one was.
        reason: String,
    },
}

/// The groups of commands a warden policy switches on one by one, each
/// with the feature that needs it. Commands outside every family here are
/// served to any agent: the handshake, the delegation, the agent's own link
/// pins, read-only facts about processes, the conntrack table the firewall
/// tears flows out of, and the attaches of the agent's own verified programs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Family {
    /// `RouteAdd`: the Multi-WAN gateways.
    Routing,
    /// `ArpAnnounce`: the load balancer's VIP announcer.
    Neighbour,
    /// `ConntrackRestore`: flows taken over from a failed HA peer.
    ConntrackRestore,
    /// `ConnectRootRuntime`, `ConnectPodman`, `ReadPodmanRecord`: the
    /// container runtimes read for attribution.
    Runtime,
    /// `FimOpen`, `FimRead`, `FimFacts`, `FimCanaries`: the file watch.
    FileWatch,
    /// `WriteRefusalGroup`: the fanotify write refusal.
    WriteRefusal,
    /// `AttachUprobe`, `DlpScan`, and `AttachHeld` for a kernel TLS probe:
    /// the TLS plaintext and crypto-call probes.
    Uprobe,
    /// `ResolverSocket`: the DNS allow-list resolver.
    Resolver,
    /// `HiddenPorts`: the hidden port sweep.
    HiddenPorts,
    /// `HiddenProcesses`: the hidden process sweep.
    HiddenProcesses,
    /// `FileRoots`, `ReadRootedFile`, `GoExecutables`, `ProcessMappings`:
    /// the package inventory.
    PackageInventory,
    /// `PacketSockets`, `NetworkPrograms`: the network inventory.
    NetworkInventory,
    /// `Extension`: operations a downstream warden build adds.
    Extension,
}

impl Family {
    /// The family's name as the policy file and the logs write it.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Routing => "routing",
            Self::Neighbour => "neighbour",
            Self::ConntrackRestore => "conntrack-restore",
            Self::Runtime => "runtime",
            Self::FileWatch => "file-watch",
            Self::WriteRefusal => "write-refusal",
            Self::Uprobe => "uprobe",
            Self::Resolver => "resolver",
            Self::HiddenPorts => "hidden-ports",
            Self::HiddenProcesses => "hidden-processes",
            Self::PackageInventory => "package-inventory",
            Self::NetworkInventory => "network-inventory",
            Self::Extension => "extension",
        }
    }
}

impl std::fmt::Display for Family {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

impl Command {
    /// The family a policy switches this command with, `None` for a command
    /// every agent is served.
    #[must_use]
    pub fn family(&self) -> Option<Family> {
        match self {
            Self::RouteAdd { .. } => Some(Family::Routing),
            Self::ArpAnnounce { .. } => Some(Family::Neighbour),
            Self::ConntrackRestore { .. } => Some(Family::ConntrackRestore),
            Self::ConnectRootRuntime { .. }
            | Self::ConnectPodman { .. }
            | Self::ReadPodmanRecord { .. } => Some(Family::Runtime),
            Self::FimOpen { .. }
            | Self::FimRead { .. }
            | Self::FimFacts { .. }
            | Self::FimCanaries { .. } => Some(Family::FileWatch),
            Self::WriteRefusalGroup => Some(Family::WriteRefusal),
            Self::AttachUprobe { .. } | Self::DlpScan => Some(Family::Uprobe),
            Self::AttachHeld { program } => held_program(program).and_then(|p| p.family),
            Self::ResolverSocket { .. } => Some(Family::Resolver),
            Self::HiddenPorts { .. } => Some(Family::HiddenPorts),
            Self::HiddenProcesses { .. } => Some(Family::HiddenProcesses),
            Self::FileRoots
            | Self::ReadRootedFile { .. }
            | Self::GoExecutables
            | Self::ProcessMappings { .. } => Some(Family::PackageInventory),
            Self::PacketSockets | Self::NetworkPrograms => Some(Family::NetworkInventory),
            Self::Extension { .. } => Some(Family::Extension),
            Self::Hello { .. }
            | Self::Delegate
            | Self::ConntrackDump
            | Self::ConntrackDelete { .. }
            | Self::ConntrackFlush
            | Self::PcapOpen { .. }
            | Self::AttachCgroup { .. }
            | Self::TcxChain { .. }
            | Self::AttachTcxInNetns { .. }
            | Self::ReadExecutable { .. }
            | Self::Identity
            | Self::OpenerReadings { .. }
            | Self::ReadProcessFacts { .. }
            | Self::OpenExecutable { .. }
            | Self::ReadServedPeer { .. }
            | Self::ReadShareWriters { .. }
            | Self::NamespaceIds
            | Self::PinLink { .. }
            | Self::PinnedLinks
            | Self::OpenPinnedLink { .. }
            | Self::UnpinLinks { .. }
            | Self::HoldProgram { .. } => None,
        }
    }

    /// The command's name, as an audit line and an error write it.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Hello { .. } => "Hello",
            Self::Delegate => "Delegate",
            Self::ConntrackDump => "ConntrackDump",
            Self::ConntrackDelete { .. } => "ConntrackDelete",
            Self::ConntrackFlush => "ConntrackFlush",
            Self::ConntrackRestore { .. } => "ConntrackRestore",
            Self::RouteAdd { .. } => "RouteAdd",
            Self::ArpAnnounce { .. } => "ArpAnnounce",
            Self::PcapOpen { .. } => "PcapOpen",
            Self::AttachUprobe { .. } => "AttachUprobe",
            Self::AttachCgroup { .. } => "AttachCgroup",
            Self::DlpScan => "DlpScan",
            Self::Extension { .. } => "Extension",
            Self::TcxChain { .. } => "TcxChain",
            Self::AttachTcxInNetns { .. } => "AttachTcxInNetns",
            Self::ReadExecutable { .. } => "ReadExecutable",
            Self::PacketSockets => "PacketSockets",
            Self::NetworkPrograms => "NetworkPrograms",
            Self::Identity => "Identity",
            Self::FimOpen { .. } => "FimOpen",
            Self::FimRead { .. } => "FimRead",
            Self::FimFacts { .. } => "FimFacts",
            Self::FimCanaries { .. } => "FimCanaries",
            Self::HiddenPorts { .. } => "HiddenPorts",
            Self::HiddenProcesses { .. } => "HiddenProcesses",
            Self::NamespaceIds => "NamespaceIds",
            Self::FileRoots => "FileRoots",
            Self::ReadRootedFile { .. } => "ReadRootedFile",
            Self::GoExecutables => "GoExecutables",
            Self::ProcessMappings { .. } => "ProcessMappings",
            Self::WriteRefusalGroup => "WriteRefusalGroup",
            Self::OpenerReadings { .. } => "OpenerReadings",
            Self::ReadProcessFacts { .. } => "ReadProcessFacts",
            Self::OpenExecutable { .. } => "OpenExecutable",
            Self::ReadServedPeer { .. } => "ReadServedPeer",
            Self::ReadShareWriters { .. } => "ReadShareWriters",
            Self::ConnectPodman { .. } => "ConnectPodman",
            Self::ResolverSocket { .. } => "ResolverSocket",
            Self::PinLink { .. } => "PinLink",
            Self::PinnedLinks => "PinnedLinks",
            Self::OpenPinnedLink { .. } => "OpenPinnedLink",
            Self::UnpinLinks { .. } => "UnpinLinks",
            Self::ConnectRootRuntime { .. } => "ConnectRootRuntime",
            Self::ReadPodmanRecord { .. } => "ReadPodmanRecord",
            Self::HoldProgram { .. } => "HoldProgram",
            Self::AttachHeld { .. } => "AttachHeld",
        }
    }

    /// The longest frame a warden reads for this command. A command that
    /// carries a list (paths, thread ids, process stamps, ports, link names,
    /// servers, an extension's payload) keeps [`MAX_FRAME_LEN`], since the list
    /// grows with the host; every other command is bounded by
    /// [`CONTROL_FRAME_LEN`].
    #[must_use]
    pub fn frame_limit(&self) -> u32 {
        match self {
            Self::FimOpen { .. }
            | Self::FimFacts { .. }
            | Self::FimCanaries { .. }
            | Self::HiddenPorts { .. }
            | Self::ProcessMappings { .. }
            | Self::OpenerReadings { .. }
            | Self::ReadShareWriters { .. }
            | Self::UnpinLinks { .. }
            | Self::Extension { .. } => MAX_FRAME_LEN,
            Self::Hello { .. }
            | Self::Delegate
            | Self::ConntrackDump
            | Self::ConntrackDelete { .. }
            | Self::ConntrackFlush
            | Self::ConntrackRestore { .. }
            | Self::RouteAdd { .. }
            | Self::ArpAnnounce { .. }
            | Self::PcapOpen { .. }
            | Self::AttachUprobe { .. }
            | Self::AttachCgroup { .. }
            | Self::DlpScan
            | Self::TcxChain { .. }
            | Self::AttachTcxInNetns { .. }
            | Self::ReadExecutable { .. }
            | Self::PacketSockets
            | Self::NetworkPrograms
            | Self::Identity
            | Self::FimRead { .. }
            | Self::HiddenProcesses { .. }
            | Self::FileRoots
            | Self::ReadRootedFile { .. }
            | Self::GoExecutables
            | Self::WriteRefusalGroup
            | Self::ReadProcessFacts { .. }
            | Self::OpenExecutable { .. }
            | Self::ReadServedPeer { .. }
            | Self::ConnectPodman { .. }
            | Self::NamespaceIds
            | Self::ResolverSocket { .. }
            | Self::PinLink { .. }
            | Self::PinnedLinks
            | Self::OpenPinnedLink { .. }
            | Self::ConnectRootRuntime { .. }
            | Self::ReadPodmanRecord { .. }
            | Self::HoldProgram { .. }
            | Self::AttachHeld { .. } => CONTROL_FRAME_LEN,
        }
    }

    /// One command of every variant. The warden reads each one's wire tag off
    /// it to bound a frame before reading the body, and the tests start from
    /// it. The parameters are placeholders, never a path on a host.
    // One literal per variant, in declaration order: splitting it would only
    // make a missing one harder to see.
    #[allow(clippy::too_many_lines)]
    #[must_use]
    pub fn samples() -> Vec<Self> {
        let tuple = ConntrackTuple {
            proto: 6,
            src_ip: "10.0.0.1".into(),
            dst_ip: "10.0.0.2".into(),
            src_port: 40000,
            dst_port: 443,
        };
        vec![
            Self::Hello {
                version: PROTOCOL_VERSION,
            },
            Self::Delegate,
            Self::ConntrackDump,
            Self::ConntrackDelete {
                tuple: tuple.clone(),
            },
            Self::ConntrackFlush,
            Self::RouteAdd {
                route: RouteSpec {
                    dst_cidr: "0.0.0.0/0".into(),
                    gateway: "192.0.2.1".into(),
                    iface: "eth0".into(),
                    table: 254,
                },
            },
            Self::ArpAnnounce {
                iface: "eth0".into(),
                ip: "192.0.2.10".into(),
            },
            Self::PcapOpen {
                iface: "eth0".into(),
                filter: "tcp port 443".into(),
            },
            Self::AttachUprobe {
                program: "ssl_write".into(),
                path: "libssl.so.3".into(),
                offset: 4096,
            },
            Self::AttachCgroup {
                cgroup_path: "cgroup".into(),
                attach_type: 0,
            },
            Self::DlpScan,
            Self::Extension {
                kind: "kind".into(),
                payload: vec![1, 2, 3],
            },
            Self::TcxChain {
                iface: "eth0".into(),
                egress: true,
            },
            Self::AttachTcxInNetns {
                pid: 1,
                iface: "eth0".into(),
                egress: false,
            },
            Self::ReadExecutable { pid: 1 },
            Self::PacketSockets,
            Self::NetworkPrograms,
            Self::Identity,
            Self::FimOpen {
                paths: vec!["etc".into()],
            },
            Self::FimRead { max_wait_ms: 100 },
            Self::FimFacts {
                paths: vec!["passwd".into()],
                max_hash_bytes: 1024,
            },
            Self::FimCanaries {
                paths: vec!["archive.docx".into()],
            },
            Self::HiddenPorts { ports: vec![22] },
            Self::HiddenProcesses { rate: 100 },
            Self::FileRoots,
            Self::ReadRootedFile {
                pid: 1,
                file: RootedFile::DpkgStatus,
                offset: 0,
                len: 4096,
            },
            Self::GoExecutables,
            Self::ProcessMappings {
                known: vec![ProcessStamp {
                    pid: 1,
                    start_time: 2,
                    vsize: 3,
                }],
            },
            Self::WriteRefusalGroup,
            Self::OpenerReadings { tids: vec![1] },
            Self::ReadProcessFacts { pid: 1 },
            Self::OpenExecutable { pid: 1 },
            Self::ReadServedPeer { pid: 1 },
            Self::ReadShareWriters {
                servers: vec![std::net::IpAddr::from([192, 0, 2, 20])],
            },
            Self::ConnectPodman { uid: 1000 },
            Self::ConntrackRestore {
                restore: ConntrackRestore {
                    flow: tuple,
                    reply: None,
                },
            },
            Self::NamespaceIds,
            Self::ResolverSocket {
                listen: std::net::SocketAddr::from(([127, 0, 0, 1], 53)),
                stream: false,
            },
            Self::PinLink {
                name: "xdp-firewall".into(),
            },
            Self::PinnedLinks,
            Self::OpenPinnedLink {
                name: "xdp-firewall".into(),
            },
            Self::UnpinLinks {
                names: vec!["xdp-firewall".into()],
            },
            Self::ConnectRootRuntime {
                runtime: RootRuntime::Docker,
            },
            Self::ReadPodmanRecord {
                uid: None,
                store: "storage".into(),
                id: "0123456789abcdef".into(),
            },
            Self::HoldProgram {
                name: "process_exec".into(),
            },
            Self::AttachHeld {
                program: "process_exec".into(),
            },
        ]
    }

    /// Whether the agent sends a descriptor right after this frame, which a
    /// warden that refuses the command still has to take off the socket.
    #[must_use]
    pub fn sends_fd(&self) -> bool {
        matches!(
            self,
            Self::Delegate
                | Self::HoldProgram { .. }
                | Self::AttachCgroup { .. }
                | Self::AttachTcxInNetns { .. }
                | Self::PinLink { .. }
        )
    }
}

/// Write one framed message: a `u32` little-endian length prefix followed by the
/// `postcard` encoding of `msg`. The leading byte of the postcard body is the
/// enum-variant tag - the command discriminant - so a reader can dispatch on it
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

/// The wire tag at the start of `body`: postcard writes an enum's variant
/// index as a varint, so a command's tag is its first bytes.
fn variant_tag(body: &[u8]) -> Option<u32> {
    let mut tag: u32 = 0;
    for (i, byte) in body.iter().take(5).enumerate() {
        tag |= u32::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            return Some(tag);
        }
    }
    None
}

/// [`Command::frame_limit`] by wire tag, read once off [`Command::samples`].
fn limit_for_tag(tag: u32) -> Option<u32> {
    static LIMITS: std::sync::OnceLock<Vec<(u32, u32)>> = std::sync::OnceLock::new();
    LIMITS
        .get_or_init(|| {
            Command::samples()
                .iter()
                .filter_map(|cmd| {
                    let body = postcard::to_allocvec(cmd).ok()?;
                    Some((variant_tag(&body)?, cmd.frame_limit()))
                })
                .collect()
        })
        .iter()
        .find(|(t, _)| *t == tag)
        .map(|(_, limit)| *limit)
}

/// Read one [`Command`], refusing a frame longer than its command's
/// [`Command::frame_limit`] before its body is read: the length and the first
/// bytes, which carry the command's tag, are all a refused frame costs.
///
/// # Errors
///
/// The stream ended or failed, the tag names no command, the frame is longer
/// than that command's bound, or the body does not decode.
pub fn read_command<R: Read>(r: &mut R) -> io::Result<Command> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_FRAME_LEN {
        return Err(io::Error::other("frame length exceeds MAX_FRAME_LEN"));
    }
    let len = len as usize;
    let mut head = [0u8; 5];
    let head_len = len.min(head.len());
    r.read_exact(&mut head[..head_len])?;
    let tag = variant_tag(&head[..head_len])
        .ok_or_else(|| io::Error::other("frame carries no command tag"))?;
    let limit = limit_for_tag(tag)
        .ok_or_else(|| io::Error::other(format!("frame tag {tag} names no command")))?;
    if len > limit as usize {
        return Err(io::Error::other(format!(
            "a {len}-byte frame exceeds its command's bound of {limit} bytes"
        )));
    }
    let mut body = vec![0u8; len];
    body[..head_len].copy_from_slice(&head[..head_len]);
    r.read_exact(&mut body[head_len..])?;
    postcard::from_bytes(&body).map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::{
        BindProbe, Command, ConntrackRestore, ConntrackTuple, DlpTarget, ExecutableIdentity,
        FileRoot, GoExecutable, GoExecutableScan, HiddenProcessReading, LINK_PIN_NAME_MAX,
        ListedPort, MAX_FRAME_LEN, MappedFile, MappingScan, NamespaceIdReading,
        NamespacePortReading, NetworkProgram, OpenIntent, OpenerReading, PacketSocket,
        PidObservation, PodmanRecord, PodmanStoreRead, ProcessFactsReading, ProcessMappings,
        ProcessStamp, ROOTED_CHUNK_MAX, Response, RootRuntime, RootedFile, RootedRead, RouteSpec,
        TaskIdentity, read_frame, root_runtime_path_allowed, valid_dpkg_list_name,
        valid_link_pin_name, write_frame,
    };
    use std::io::Cursor;

    #[test]
    fn every_held_program_has_one_name_and_the_type_of_its_target() {
        use super::{
            BPF_PROG_TYPE_KPROBE, BPF_PROG_TYPE_RAW_TRACEPOINT, Family, HELD_PROGRAMS, HeldTarget,
            held_program,
        };
        let mut names: Vec<&str> = HELD_PROGRAMS.iter().map(|p| p.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(
            names.len(),
            HELD_PROGRAMS.len(),
            "a held name is listed twice"
        );
        for p in HELD_PROGRAMS {
            assert_eq!(held_program(p.name), Some(p));
            match p.target {
                HeldTarget::RawTracepoint(tp) => {
                    assert!(!tp.is_empty());
                    assert_eq!(p.target.prog_type(), BPF_PROG_TYPE_RAW_TRACEPOINT);
                    assert_eq!(p.family, None);
                }
                HeldTarget::Kprobe { symbol, .. } => {
                    assert!(!symbol.is_empty());
                    assert_eq!(p.target.prog_type(), BPF_PROG_TYPE_KPROBE);
                    assert_eq!(p.family, Some(Family::Uprobe));
                }
                HeldTarget::Uprobe { .. } => {
                    assert_eq!(p.target.prog_type(), BPF_PROG_TYPE_KPROBE);
                    assert_eq!(p.family, Some(Family::Uprobe));
                }
            }
        }
        assert_eq!(held_program("xdp_firewall"), None);
    }

    #[test]
    fn a_held_attach_takes_the_family_of_its_program() {
        use super::Family;
        let attach = |program: &str| Command::AttachHeld {
            program: program.into(),
        };
        assert_eq!(attach("process_exec").family(), None);
        assert_eq!(attach("ktls_sendmsg").family(), Some(Family::Uprobe));
        assert_eq!(attach("not_held").family(), None);
        assert_eq!(
            Command::HoldProgram {
                name: "ktls_sendmsg".into()
            }
            .family(),
            None
        );
    }

    #[test]
    fn a_sweep_call_outlasts_the_sweep_it_asks_for() {
        use super::{
            HIDDEN_PROCESSES_PID_SPACE_MAX, HIDDEN_PROCESSES_RATE_MIN,
            hidden_processes_call_timeout,
        };
        // The default pace over the 64-bit default pid_max takes 42 seconds.
        let default = hidden_processes_call_timeout(100_000);
        assert!(default.as_secs() > u64::from(HIDDEN_PROCESSES_PID_SPACE_MAX / 100_000));
        // A pace below the floor is swept at the floor, so it waits as long.
        assert_eq!(
            hidden_processes_call_timeout(1),
            hidden_processes_call_timeout(HIDDEN_PROCESSES_RATE_MIN)
        );
        assert!(
            hidden_processes_call_timeout(HIDDEN_PROCESSES_RATE_MIN).as_secs()
                >= u64::from(HIDDEN_PROCESSES_PID_SPACE_MAX / HIDDEN_PROCESSES_RATE_MIN)
        );
    }

    fn tcp(src: &str, dst: &str, sp: u16, dp: u16) -> ConntrackTuple {
        ConntrackTuple {
            proto: 6,
            src_ip: src.into(),
            dst_ip: dst.into(),
            src_port: sp,
            dst_port: dp,
        }
    }

    #[test]
    fn a_named_tcp_flow_with_its_reply_tuple_is_restorable() {
        let restore = ConntrackRestore {
            flow: tcp("10.0.0.5", "198.51.100.7", 51_000, 443),
            reply: Some(tcp("198.51.100.7", "203.0.113.10", 443, 40_123)),
        };
        assert!(restore.is_restorable());
    }

    #[test]
    fn only_a_fully_named_tcp_flow_is_restored() {
        let udp = ConntrackRestore {
            flow: ConntrackTuple {
                proto: 17,
                ..tcp("10.0.0.5", "10.0.0.6", 5353, 53)
            },
            reply: None,
        };
        assert!(!udp.is_restorable());
        let option = ConntrackRestore {
            flow: tcp("--flush", "10.0.0.6", 1, 2),
            reply: None,
        };
        assert!(!option.is_restorable());
        let no_port = ConntrackRestore {
            flow: tcp("10.0.0.5", "10.0.0.6", 0, 443),
            reply: None,
        };
        assert!(!no_port.is_restorable());
        let bad_reply = ConntrackRestore {
            flow: tcp("10.0.0.5", "10.0.0.6", 1, 2),
            reply: Some(tcp("x", "10.0.0.5", 2, 1)),
        };
        assert!(!bad_reply.is_restorable());
    }

    // One literal per variant, so the list grows with the protocol.
    #[expect(clippy::too_many_lines)]
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
            Command::ConntrackRestore {
                restore: ConntrackRestore {
                    flow: tuple.clone(),
                    reply: Some(tuple.clone()),
                },
            },
            Command::RouteAdd { route },
            Command::ArpAnnounce {
                iface: "enp0s2".into(),
                ip: "10.0.0.9".into(),
            },
            Command::PcapOpen {
                iface: "enp0s2".into(),
                filter: "tcp port 443".into(),
            },
            Command::AttachUprobe {
                program: "ssl_read_ret".into(),
                path: "/proc/4242/root/usr/lib/libssl.so.3".into(),
                offset: 0x1234,
            },
            Command::AttachCgroup {
                cgroup_path: "/sys/fs/cgroup".into(),
                attach_type: 10,
            },
            Command::DlpScan,
            Command::Extension {
                kind: "enterprise.proc_tls.v1".into(),
                payload: vec![0x01, 0x02, 0x03],
            },
            Command::TcxChain {
                iface: "enp0s2".into(),
                egress: true,
            },
            Command::AttachTcxInNetns {
                pid: 4242,
                iface: "eth0".into(),
                egress: false,
            },
            Command::ReadExecutable { pid: 4242 },
            Command::PacketSockets,
            Command::NetworkPrograms,
            Command::Identity,
            Command::HiddenPorts {
                ports: vec![22, 31_337],
            },
            Command::HiddenProcesses { rate: 1_000_000 },
            Command::NamespaceIds,
            Command::FileRoots,
            Command::ReadRootedFile {
                pid: 4242,
                file: RootedFile::DpkgList {
                    name: "libc6:amd64".into(),
                },
                offset: 0,
                len: ROOTED_CHUNK_MAX,
            },
            Command::GoExecutables,
            Command::ProcessMappings {
                known: vec![ProcessStamp {
                    pid: 1,
                    start_time: 2,
                    vsize: 170_000_000,
                }],
            },
            Command::WriteRefusalGroup,
            Command::OpenerReadings {
                tids: vec![4242, 4243],
            },
            Command::ReadProcessFacts { pid: 4242 },
            Command::OpenExecutable { pid: 4242 },
            Command::ReadServedPeer { pid: 4242 },
            Command::ReadShareWriters {
                servers: vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2))],
            },
            Command::ConnectPodman { uid: 1000 },
            Command::ResolverSocket {
                listen: "172.17.0.1:53".parse().unwrap(),
                stream: true,
            },
            Command::PinLink {
                name: "xdp_eth0".into(),
            },
            Command::PinnedLinks,
            Command::OpenPinnedLink {
                name: "xdp_eth0".into(),
            },
            Command::UnpinLinks { names: Vec::new() },
            Command::ConnectRootRuntime {
                runtime: RootRuntime::Docker,
            },
            Command::ReadPodmanRecord {
                uid: Some(1000),
                store: ".local/share/containers/storage".into(),
                id: "a".repeat(64),
            },
            Command::HoldProgram {
                name: "ktls_sendmsg".into(),
            },
            Command::AttachHeld {
                program: "ktls_sendmsg".into(),
            },
        ]
    }

    fn all_responses() -> Vec<Response> {
        [
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
            Response::TcxChain {
                prog_ids: vec![41, 7, 112],
            },
            Response::Executable {
                executable: Some(ExecutableIdentity {
                    path: "/usr/bin/sleep".into(),
                    dev: 2049,
                    ino: 131_072,
                }),
            },
            Response::Executable { executable: None },
            Response::PacketSockets {
                sockets: vec![PacketSocket {
                    inode: 31_337,
                    socket_type: 3,
                    protocol: 0x0003,
                    ifindex: 0,
                    interface: None,
                    uid: 0,
                    netns: 4_026_531_840,
                    host_netns: true,
                    pid: Some(812),
                    filter_instructions: Some(30),
                }],
            },
            Response::NetworkPrograms {
                programs: vec![NetworkProgram {
                    prog_id: 812,
                    prog_type: "sched_cls".into(),
                    name: "cil_from_netdev".into(),
                    tag: "0a1b2c3d4e5f6071".into(),
                    link_id: Some(14),
                    hook: "tcx_ingress".into(),
                    ifindex: Some(2),
                    interface: Some("eth0".into()),
                    position: Some(1),
                    cgroup_id: None,
                    detail: None,
                    created_by_uid: Some(0),
                    holders: vec![1312],
                }],
            },
            Response::Identity {
                identity: TaskIdentity {
                    tgid: 4242,
                    pid_ns_dev: 4,
                    pid_ns_ino: 4_026_531_836,
                },
            },
        ]
        .into_iter()
        .chain(hidden_responses())
        .chain(inventory_responses())
        .chain(std::iter::once(Response::PinnedLinks {
            names: vec!["xdp_eth0".into(), "tcx-egress_eth0".into()],
        }))
        .chain(podman_responses())
        .collect()
    }

    fn podman_responses() -> Vec<Response> {
        vec![
            Response::PodmanRecord {
                read: PodmanStoreRead::Found(PodmanRecord {
                    name: "web".into(),
                    image: "docker.io/library/nginx:1.27".into(),
                    labels: vec![("tier".into(), "front".into())],
                    labels_read: true,
                    created: "2026-11-22T00:30:40Z".into(),
                    status: "running".into(),
                }),
            },
            Response::PodmanRecord {
                read: PodmanStoreRead::NoStore,
            },
            Response::PodmanRecord {
                read: PodmanStoreRead::Missing,
            },
        ]
    }

    /// The answers of the two hidden checks.
    fn hidden_responses() -> Vec<Response> {
        vec![
            Response::NamespaceIds {
                namespaces: vec![
                    NamespaceIdReading {
                        netns: 4_026_532_301,
                        nsid: Some(3),
                        pid: 4242,
                    },
                    NamespaceIdReading {
                        netns: 4_026_531_840,
                        nsid: None,
                        pid: 1,
                    },
                ],
            },
            Response::HiddenPorts {
                namespaces: vec![
                    NamespacePortReading {
                        netns: 4_026_531_840,
                        host_netns: true,
                        error: None,
                        first_listing: vec![ListedPort {
                            udp: false,
                            port: 22,
                            state: 10,
                            sock_diag: true,
                        }],
                        second_listing: Vec::new(),
                        probed: 4096,
                        unprobed: 2,
                        refused_first: vec![BindProbe {
                            udp: false,
                            ipv6: true,
                            port: 22,
                        }],
                        refused_second: Vec::new(),
                    },
                    NamespacePortReading {
                        netns: 4_026_532_999,
                        host_netns: false,
                        error: Some("setns: operation not permitted".into()),
                        first_listing: Vec::new(),
                        second_listing: Vec::new(),
                        probed: 0,
                        unprobed: 0,
                        refused_first: Vec::new(),
                        refused_second: Vec::new(),
                    },
                ],
            },
            Response::HiddenProcesses {
                reading: HiddenProcessReading {
                    error: None,
                    pid_space: 4_194_304,
                    probed: 4_194_303,
                    listed: 412,
                    threads: 1_870,
                    first: vec![PidObservation {
                        pid: 31_337,
                        tgid: Some(31_337),
                        start_time: Some(8_812),
                        state: Some('S'),
                        comm: Some("kworker/u:9".into()),
                    }],
                    relisted: Vec::new(),
                    second: vec![PidObservation {
                        pid: 31_337,
                        ..PidObservation::default()
                    }],
                },
            },
            Response::HiddenProcesses {
                reading: HiddenProcessReading {
                    error: Some("/proc lists another pid namespace".into()),
                    ..HiddenProcessReading::default()
                },
            },
        ]
    }

    /// The answers of the inventory reads.
    fn inventory_responses() -> Vec<Response> {
        vec![
            Response::FileRoots {
                roots: vec![FileRoot {
                    pid: 1,
                    dev: 2049,
                    ino: 2,
                    host: true,
                    cgroup: "0::/init.scope\n".into(),
                }],
            },
            Response::RootedRead {
                read: RootedRead::Chunk {
                    path: "var/lib/dpkg/status".into(),
                    dev: 48,
                    ino: 917_962,
                    size: 70_000,
                    mtime_ns: 1_793_000_000_000_000_000,
                    data: b"Package: libc6\n".to_vec(),
                },
            },
            Response::RootedRead {
                read: RootedRead::Unreadable {
                    reason: "not a regular file".into(),
                },
            },
            Response::RootedRead {
                read: RootedRead::Absent,
            },
            Response::GoExecutables {
                scan: GoExecutableScan {
                    examined: 40,
                    executables: vec![GoExecutable {
                        dev: 48,
                        ino: 917_963,
                        path: "/usr/local/bin/coredns".into(),
                        pids: vec![812, 815],
                        host: false,
                        cgroup: "0::/kubepods.slice\n".into(),
                        buildinfo: Some(b"\xff Go buildinf:".to_vec()),
                        error: None,
                    }],
                    not_read: 0,
                },
            },
            Response::ProcessMappings {
                scan: MappingScan {
                    processes: vec![ProcessStamp {
                        pid: 812,
                        start_time: 4_410,
                        vsize: 1_250_000_000,
                    }],
                    not_listed: 0,
                    read: vec![ProcessMappings {
                        stamp: ProcessStamp {
                            pid: 812,
                            start_time: 4_410,
                            vsize: 1_250_000_000,
                        },
                        root_dev: 48,
                        root_ino: 2,
                        files: vec![0],
                        truncated: false,
                        error: None,
                    }],
                    files: vec![MappedFile {
                        dev: 64_769,
                        ino: 917_970,
                        path: "/usr/lib/x86_64-linux-gnu/libssl.so.3".into(),
                        deleted: true,
                    }],
                    pending: 0,
                },
            },
            Response::OpenerReadings {
                readings: vec![
                    OpenerReading {
                        intent: OpenIntent::Write,
                        tgid: 812,
                        cgroup_id: 4_410,
                        exe: Some((64_769, 917_970)),
                    },
                    OpenerReading::GONE,
                ],
            },
            Response::ProcessFacts {
                facts: Some(ProcessFactsReading {
                    streams_on_socket: true,
                    fileless: false,
                }),
            },
            Response::ProcessFacts { facts: None },
            Response::ServedPeer {
                peer: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 7))),
            },
            Response::ServedPeer { peer: None },
            Response::ShareWriters {
                pids: vec![4242, 4243],
            },
        ]
    }

    #[test]
    fn a_link_pin_name_stays_inside_the_directory_and_has_no_dot() {
        assert!(valid_link_pin_name("xdp_eth0"));
        assert!(valid_link_pin_name("cgroup-10__sys_2Ffs"));
        assert!(!valid_link_pin_name(""));
        assert!(!valid_link_pin_name("../escape"));
        assert!(!valid_link_pin_name("xdp_eth0.100"));
        assert!(!valid_link_pin_name("a/b"));
        assert!(!valid_link_pin_name(&"a".repeat(LINK_PIN_NAME_MAX + 1)));
    }

    #[test]
    fn a_process_names_its_own_thread_group_and_pid_namespace() {
        let me = TaskIdentity::of_self().expect("procfs is mounted");
        assert_eq!(me.tgid, std::process::id());
        assert_ne!(me.pid_ns_ino, 0);
    }

    #[test]
    fn a_podman_id_is_64_lowercase_hex_digits() {
        assert!(super::valid_podman_id(&"0f".repeat(32)));
        for bad in [
            "",
            "abc",
            &"A".repeat(64),
            &"0".repeat(65),
            &"../".repeat(21),
        ] {
            assert!(!super::valid_podman_id(bad), "{bad}");
        }
    }

    #[test]
    fn a_dpkg_list_name_names_nothing_but_a_list() {
        for good in ["libc6", "libc6:amd64", "g++-14", "libstdc++6:i386", "0ad"] {
            assert!(valid_dpkg_list_name(good), "{good}");
        }
        for bad in [
            "",
            "../shadow",
            "a/b",
            "Libc",
            ".hidden",
            "a:",
            "a:b/c",
            "a b",
            "-x",
        ] {
            assert!(!valid_dpkg_list_name(bad), "{bad}");
            assert!(
                RootedFile::DpkgList { name: bad.into() }
                    .candidates()
                    .is_none(),
                "{bad}"
            );
        }
        assert!(!valid_dpkg_list_name(&"a".repeat(129)));
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

    /// A variant appended at the end keeps every earlier tag where it was, so
    /// a warden from before it still decodes everything it already served. A
    /// variant removed moves the tags after it, which is what bumping
    /// [`PROTOCOL_VERSION`] is for: the two sides then part at `Hello`, whose
    /// tag never moves, instead of misreading each other.
    #[test]
    fn appended_variants_keep_the_earlier_tags() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &Command::Hello { version: 0 }).unwrap();
        assert_eq!(buf[4], 0);
        buf.clear();
        write_frame(&mut buf, &Command::DlpScan).unwrap();
        assert_eq!(buf[4], 10);
        buf.clear();
        write_frame(
            &mut buf,
            &Response::Error {
                message: String::new(),
            },
        )
        .unwrap();
        assert_eq!(buf[4], 8);
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

    #[test]
    fn the_reads_the_agent_makes_reach_a_root_runtime() {
        for target in [
            "/_ping",
            "/v1.43/containers/json",
            "/v1.43/containers/0123abcdef/json",
            "/v1.43/containers/web-1_a.b/json",
            "/v1.43/networks?filters=%7B%22driver%22%3A%7B%22bridge%22%3Atrue%7D%7D",
            "/v1.43/networks/bridge",
            "/v1.43/events?filters=%7B%22type%22%3A%5B%22container%22%5D%7D",
        ] {
            assert!(root_runtime_path_allowed(target), "{target}");
        }
    }

    #[test]
    fn anything_else_a_root_runtime_serves_is_refused() {
        for target in [
            "",
            "/",
            "/containers/json",
            "/v1.44/containers/json",
            "/v1.43/containers/create",
            "/v1.43/containers/abc/export",
            "/v1.43/containers/abc/archive?path=/etc/shadow",
            "/v1.43/containers/abc/logs",
            "/v1.43/containers/../secrets/json",
            "/v1.43/containers/%2e%2e/json",
            "/v1.43/containers/abc/json?size=1",
            "/v1.43/containers/abc/json/",
            "/v1.43/images/json",
            "/v1.43/secrets",
            "/v1.43/networks/abc/connect",
            "/v1.43/networks/abc?verbose=true",
            "/v1.43/events?until=1#x",
            "/v1.43/events?a=/b",
            "/v1.43/exec/abc/start",
            "/v1.43/swarm",
            "/v1.43/_ping",
        ] {
            assert!(!root_runtime_path_allowed(target), "{target}");
        }
    }

    /// `tests/integration/scripts/warden-route-probe.py` writes a `RouteAdd`
    /// by hand and reads the answer's tag, so it can ask the warden as the
    /// agent would without a Rust client. These are the bytes it writes and
    /// the tag it expects back.
    #[test]
    fn the_integration_probe_speaks_the_wire_format() {
        let route = Command::RouteAdd {
            route: super::RouteSpec {
                dst_cidr: "0.0.0.0/0".into(),
                gateway: "192.0.2.254".into(),
                iface: "lo".into(),
                table: 254,
            },
        };
        let mut expected = vec![5u8, 9];
        expected.extend_from_slice(b"0.0.0.0/0");
        expected.push(11);
        expected.extend_from_slice(b"192.0.2.254");
        expected.push(2);
        expected.extend_from_slice(b"lo");
        expected.extend_from_slice(&[0xfe, 0x01]);
        assert_eq!(postcard::to_allocvec(&route).expect("encode"), expected);
        let hello = Command::Hello {
            version: super::PROTOCOL_VERSION,
        };
        assert_eq!(postcard::to_allocvec(&hello).expect("encode"), [0, 4]);
        let refused = Response::Refused {
            family: super::Family::Routing,
            reason: String::new(),
        };
        assert_eq!(postcard::to_allocvec(&refused).expect("encode")[0], 31);
    }

    #[test]
    fn the_samples_hold_one_command_of_every_variant() {
        use super::{limit_for_tag, variant_tag};
        let samples = Command::samples();
        let mut tags: Vec<u32> = samples
            .iter()
            .map(|c| variant_tag(&postcard::to_allocvec(c).expect("encode")).expect("tag"))
            .collect();
        tags.sort_unstable();
        tags.dedup();
        let expected: Vec<u32> = (0..u32::try_from(samples.len()).expect("count")).collect();
        assert_eq!(tags, expected, "one sample per variant, no variant twice");
        // The tag after the last names no command: a new variant without a
        // sample is a tag the warden would refuse.
        let next = u32::try_from(samples.len()).expect("count");
        assert!(postcard::from_bytes::<Command>(&[u8::try_from(next).expect("tag")]).is_err());
        assert!(limit_for_tag(next).is_none());
    }

    #[test]
    fn every_command_is_read_back_within_its_bound() {
        use super::read_command;
        for cmd in Command::samples() {
            let mut buf = Vec::new();
            write_frame(&mut buf, &cmd).expect("encode");
            assert!(
                buf.len() - 4 <= cmd.frame_limit() as usize,
                "{}",
                cmd.name()
            );
            let back = read_command(&mut Cursor::new(&buf))
                .unwrap_or_else(|e| panic!("{}: {e}", cmd.name()));
            assert_eq!(back, cmd);
        }
    }

    #[test]
    fn a_control_command_past_its_bound_is_refused_before_its_body_is_read() {
        use super::{CONTROL_FRAME_LEN, read_command};
        let cmd = Command::PinLink {
            name: "x".repeat(CONTROL_FRAME_LEN as usize),
        };
        let mut buf = Vec::new();
        write_frame(&mut buf, &cmd).expect("encode");
        // Only the length and the first five bytes are on the stream: a
        // reader that wanted the body would fail on the missing bytes instead.
        buf.truncate(4 + 5);
        let err = read_command(&mut Cursor::new(&buf)).expect_err("refused");
        assert!(
            err.to_string().contains("exceeds its command's bound"),
            "{err}"
        );

        // A list command of the same length is read.
        let list = Command::UnpinLinks {
            names: vec!["x".repeat(CONTROL_FRAME_LEN as usize)],
        };
        let mut buf = Vec::new();
        write_frame(&mut buf, &list).expect("encode");
        assert_eq!(read_command(&mut Cursor::new(&buf)).expect("read"), list);
    }

    #[test]
    fn a_frame_naming_no_command_is_refused() {
        use super::read_command;
        let mut buf = 1_u32.to_le_bytes().to_vec();
        buf.push(0x7f);
        let err = read_command(&mut Cursor::new(&buf)).expect_err("refused");
        assert!(err.to_string().contains("names no command"), "{err}");
        let empty = 0_u32.to_le_bytes();
        assert!(read_command(&mut Cursor::new(&empty)).is_err());
    }
}
