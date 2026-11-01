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
    /// `uprobe_multi` `BPF_LINK_CREATE` - it holds the tracing capability the
    /// rootless agent dropped, and resolves `path` in its own (init) mount + pid
    /// namespace - then returns the link fd via [`Response::FdReady`]. This lets
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
    /// The roots found, answering [`Command::FileRoots`].
    FileRoots { roots: Vec<FileRoot> },
    /// What was read, answering [`Command::ReadRootedFile`].
    RootedRead { read: RootedRead },
    /// The Go executables found, answering [`Command::GoExecutables`].
    GoExecutables { scan: GoExecutableScan },
    /// The processes and the mappings read, answering
    /// [`Command::ProcessMappings`].
    ProcessMappings { scan: MappingScan },
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

#[cfg(test)]
mod tests {
    use super::{
        BindProbe, Command, ConntrackTuple, DlpTarget, ExecutableIdentity, FileRoot, GoExecutable,
        GoExecutableScan, HiddenProcessReading, ListedPort, MAX_FRAME_LEN, MappedFile, MappingScan,
        NamespacePortReading, NetworkProgram, PacketSocket, PidObservation, ProcessMappings,
        ProcessStamp, ROOTED_CHUNK_MAX, Response, RootedFile, RootedRead, RouteSpec, TaskIdentity,
        read_frame, valid_dpkg_list_name, write_frame,
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
        .collect()
    }

    /// The answers of the two hidden checks.
    fn hidden_responses() -> Vec<Response> {
        vec![
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
        ]
    }

    #[test]
    fn a_process_names_its_own_thread_group_and_pid_namespace() {
        let me = TaskIdentity::of_self().expect("procfs is mounted");
        assert_eq!(me.tgid, std::process::id());
        assert_ne!(me.pid_ns_ino, 0);
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
    /// a warden from before it still decodes everything it already served.
    #[test]
    fn appended_variants_keep_the_earlier_tags() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &Command::DlpScan).unwrap();
        assert_eq!(buf[4], 11);
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
}
