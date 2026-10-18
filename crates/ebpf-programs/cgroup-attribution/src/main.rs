//! Socket attribution hooks: the task that opened a socket, recorded against
//! the socket's cookie.
//!
//! Six programs, one answer. `connect4`/`connect6` fire when a task asks for a
//! connection and before any packet exists; `post_bind4`/`post_bind6` fire when
//! a task takes a local address, which is how a server's listening socket is
//! named; `sendmsg4`/`sendmsg6` fire on every datagram sent through an
//! unconnected socket, which is the only moment a UDP sender exists in task
//! context at all. DNS is the traffic this product parses most and almost none
//! of it calls `connect()`, so leaving the datagram path out would make the
//! identity silently partial exactly where it matters.
//!
//! All six write one entry into `SOCKET_IDENTITY`, keyed by the socket cookie
//! the kernel also hands to a packet hook holding the `skb`. Nothing is
//! enforced, nothing is dropped, and no verdict depends on what is recorded:
//! every program returns allow unconditionally, so a failure here costs
//! attribution and never connectivity.

#![no_std]
#![no_main]

use aya_ebpf::{
    btf_maps::{LruHashMap, PerCpuArray},
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_ktime_get_boot_ns, generated,
    },
    macros::{btf_map, cgroup_sock, cgroup_sock_addr, sock_ops},
    programs::{SockAddrContext, SockContext, SockOpsContext},
};
use ebpf_common::attribution::{
    ATTRIBUTION_FAMILY_IPV4, ATTRIBUTION_FAMILY_IPV6, ATTRIBUTION_HOOK_CONNECT,
    ATTRIBUTION_HOOK_POST_BIND, ATTRIBUTION_HOOK_SENDMSG, ATTRIBUTION_IDENTITY_TTL_NS,
    ATTRIBUTION_MAX_SOCKETS, ATTRIBUTION_METRIC_CONNECT, ATTRIBUTION_METRIC_COUNT,
    ATTRIBUTION_METRIC_INSERT_FAILED, ATTRIBUTION_METRIC_NO_COOKIE,
    ATTRIBUTION_METRIC_POST_BIND, ATTRIBUTION_METRIC_SENDMSG, ATTRIBUTION_METRIC_SOCK_OPS,
    SocketIdentity,
};
use ebpf_common::dlp::{
    DLP_FLOW_FAMILY_IPV4, DLP_FLOW_FAMILY_IPV6, DLP_FLOW_PROTOCOL_TCP,
    DLP_FLOW_SOURCE_KERNEL_SOCKET, DLP_TASK_SOCKET_MAX_TASKS, DlpSocket, DlpTaskSocket,
};
use ebpf_helpers::increment_metric;

// ── Maps ────────────────────────────────────────────────────────────

/// Socket cookie -> the task that opened the socket.
///
/// LRU, so a node opening more sockets than the table holds evicts its coldest
/// entries rather than refusing to record the newest. The capacity is a
/// configuration choice applied at map creation by the loader; what is written
/// here is the ceiling a default build carries.
#[btf_map]
static SOCKET_IDENTITY: LruHashMap<u64, SocketIdentity, { ATTRIBUTION_MAX_SOCKETS as usize }> =
    LruHashMap::new();

/// The last socket each task was seen on, the map the DLP uprobes read to name
/// the destination of a write they have no socket for.
///
/// Declared here with the shape `uprobe-dlp` declares, so the two objects are
/// given one kernel map by the loader's pin-by-name sharing rather than one
/// each. This is the join the whole story is about: the uprobe has a plaintext
/// buffer and a thread, the `sockops` hook has the kernel's own socket, and
/// the thread is what they have in common.
#[btf_map]
static DLP_TASK_SOCKET: LruHashMap<u64, DlpTaskSocket, { DLP_TASK_SOCKET_MAX_TASKS as usize }> =
    LruHashMap::new();

/// Per-CPU counters, read by the agent and exported as metrics. Nothing here
/// is an alert: they are how an operator sees that the hooks are attached and
/// firing, and which of the six is doing the work on this node.
#[btf_map]
static ATTRIBUTION_METRICS: PerCpuArray<u64, { ATTRIBUTION_METRIC_COUNT as usize }> =
    PerCpuArray::new();

// ── Programs ────────────────────────────────────────────────────────

/// A task asking for an IPv4 connection, before the SYN exists.
#[cgroup_sock_addr(connect4)]
pub fn attribution_connect4(ctx: SockAddrContext) -> i32 {
    record_sock_addr(&ctx, ATTRIBUTION_HOOK_CONNECT, ATTRIBUTION_METRIC_CONNECT)
}

/// The same for IPv6.
#[cgroup_sock_addr(connect6)]
pub fn attribution_connect6(ctx: SockAddrContext) -> i32 {
    record_sock_addr(&ctx, ATTRIBUTION_HOOK_CONNECT, ATTRIBUTION_METRIC_CONNECT)
}

/// A datagram leaving an unconnected IPv4 socket. A UDP sender never calls
/// `connect()`, so this is where it becomes attributable.
#[cgroup_sock_addr(sendmsg4)]
pub fn attribution_sendmsg4(ctx: SockAddrContext) -> i32 {
    record_sock_addr(&ctx, ATTRIBUTION_HOOK_SENDMSG, ATTRIBUTION_METRIC_SENDMSG)
}

/// The same for IPv6.
#[cgroup_sock_addr(sendmsg6)]
pub fn attribution_sendmsg6(ctx: SockAddrContext) -> i32 {
    record_sock_addr(&ctx, ATTRIBUTION_HOOK_SENDMSG, ATTRIBUTION_METRIC_SENDMSG)
}

/// A task that has just taken a local IPv4 address: a server socket, named at
/// the only moment its opener is still on the stack.
#[cgroup_sock(post_bind4)]
pub fn attribution_post_bind4(ctx: SockContext) -> i32 {
    record_sock(&ctx)
}

/// The same for IPv6.
#[cgroup_sock(post_bind6)]
pub fn attribution_post_bind6(ctx: SockContext) -> i32 {
    record_sock(&ctx)
}

// ── Recording ───────────────────────────────────────────────────────

/// `BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB`: a connection this node opened is up.
const SOCK_OPS_ACTIVE_ESTABLISHED: u32 = 4;
/// `BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB`: a connection this node accepted is up.
const SOCK_OPS_PASSIVE_ESTABLISHED: u32 = 5;

/// A TCP connection has come up: join the socket's own five-tuple to the task
/// the socket hooks recorded against its cookie.
///
/// This is the only hook with a full tuple: `connect` is called before a
/// source port exists and `post_bind` knows no peer. It is also the only one
/// that runs outside the opener's task context, which is why it reads the task
/// out of `SOCKET_IDENTITY` rather than from the current one: the softirq that
/// completes a handshake belongs to nobody.
#[sock_ops]
pub fn attribution_sockops(ctx: SockOpsContext) -> u32 {
    join_socket(&ctx);
    // The return value of a sock_ops program feeds `bpf_sock_ops_cb_flags_set`
    // and the TCP stack's own callbacks. Zero asks for nothing, which is the
    // whole posture: this program observes a connection, it never shapes one.
    0
}

/// Write the established socket against the task that opened it.
///
/// Nothing is written when the cookie is unknown to `SOCKET_IDENTITY`: a
/// socket opened before the hooks attached, or by a task in another cgroup,
/// has no recorded opener, and guessing one would attribute a flow to whatever
/// thread happened to be running.
#[inline(always)]
fn join_socket(ctx: &SockOpsContext) {
    let op = ctx.op();
    if op != SOCK_OPS_ACTIVE_ESTABLISHED && op != SOCK_OPS_PASSIVE_ESTABLISHED {
        return;
    }
    let cookie = unsafe { generated::bpf_get_socket_cookie(ctx.ops.cast()) };
    if cookie == 0 {
        increment_metric!(ATTRIBUTION_METRICS, ATTRIBUTION_METRIC_NO_COOKIE);
        return;
    }
    let Some(identity_ptr) = SOCKET_IDENTITY.get_ptr(&cookie) else {
        return;
    };
    let identity = unsafe { *identity_ptr };
    let now = unsafe { bpf_ktime_get_boot_ns() };
    if now < identity.at_ns || now - identity.at_ns >= ATTRIBUTION_IDENTITY_TTL_NS {
        return;
    }

    let Some(socket) = tuple_of(ctx, identity.family) else {
        return;
    };
    let entry = DlpTaskSocket {
        socket,
        at_ns: now,
    };
    let pid_tgid = (u64::from(identity.tgid) << 32) | u64::from(identity.pid);
    if DLP_TASK_SOCKET.insert(&pid_tgid, &entry, 0).is_err() {
        increment_metric!(ATTRIBUTION_METRICS, ATTRIBUTION_METRIC_INSERT_FAILED);
        return;
    }
    increment_metric!(ATTRIBUTION_METRICS, ATTRIBUTION_METRIC_SOCK_OPS);
}

/// The five-tuple of an established socket, in the encoding the DLP event
/// already carries: addresses as the host-order value of the big-endian word,
/// ports in host order.
///
/// `local_port` is handed over in host order by the kernel and `remote_port`
/// in network order, which is not a symmetry anybody chose; both are converted
/// here so nothing downstream has to know.
#[inline(always)]
fn tuple_of(ctx: &SockOpsContext, family: u8) -> Option<DlpSocket> {
    let mut socket = DlpSocket {
        src_port: ctx.local_port() as u16,
        dst_port: u32::from_be(ctx.remote_port()) as u16,
        protocol: DLP_FLOW_PROTOCOL_TCP,
        source: DLP_FLOW_SOURCE_KERNEL_SOCKET,
        ..DlpSocket::default()
    };
    if family == ATTRIBUTION_FAMILY_IPV4 {
        socket.src_addr[0] = u32::from_be(ctx.local_ip4());
        socket.dst_addr[0] = u32::from_be(ctx.remote_ip4());
        socket.family = DLP_FLOW_FAMILY_IPV4;
        return Some(socket);
    }
    if family == ATTRIBUTION_FAMILY_IPV6 {
        let local = ctx.local_ip6();
        let remote = ctx.remote_ip6();
        let mut word = 0usize;
        while word < 4 {
            socket.src_addr[word] = u32::from_be(local[word]);
            socket.dst_addr[word] = u32::from_be(remote[word]);
            word += 1;
        }
        socket.family = DLP_FLOW_FAMILY_IPV6;
        return Some(socket);
    }
    None
}

/// Allow, whatever happened. These hooks sit on the connect and sendmsg paths
/// of every socket on the node: a program that can return anything else is a
/// program that can take the node off the network, and attribution is not
/// worth that.
const ALLOW: i32 = 1;

/// Record the calling task against the socket's cookie, from a
/// `bpf_sock_addr` context.
#[inline(always)]
fn record_sock_addr(ctx: &SockAddrContext, hook: u8, metric: u32) -> i32 {
    let cookie = unsafe { generated::bpf_get_socket_cookie(ctx.sock_addr.cast()) };
    // Direct context access: the verifier rewrites these into the real
    // members of the kernel's own socket, so nothing is probe-read.
    let family = unsafe { (*ctx.sock_addr).family };
    let protocol = unsafe { (*ctx.sock_addr).protocol };
    insert(cookie, hook, family, protocol, metric);
    ALLOW
}

/// Record the calling task against the socket's cookie, from a `bpf_sock`
/// context.
#[inline(always)]
fn record_sock(ctx: &SockContext) -> i32 {
    let cookie = unsafe { generated::bpf_get_socket_cookie(ctx.sock.cast()) };
    let family = unsafe { (*ctx.sock).family };
    let protocol = unsafe { (*ctx.sock).protocol };
    insert(
        cookie,
        ATTRIBUTION_HOOK_POST_BIND,
        family,
        protocol,
        ATTRIBUTION_METRIC_POST_BIND,
    );
    ALLOW
}

/// Write one identity, or count why there was nothing to write.
///
/// A cookie of zero is the kernel saying this socket has none, which happens
/// before a socket is fully set up. There is no key then, and inventing one
/// would attribute the next flow to whoever ran last.
#[inline(always)]
fn insert(cookie: u64, hook: u8, family: u32, protocol: u32, metric: u32) {
    if cookie == 0 {
        increment_metric!(ATTRIBUTION_METRICS, ATTRIBUTION_METRIC_NO_COOKIE);
        return;
    }
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let identity = SocketIdentity {
        at_ns: unsafe { bpf_ktime_get_boot_ns() },
        cgroup_id: unsafe { bpf_get_current_cgroup_id() },
        pid: pid_tgid as u32,
        tgid: (pid_tgid >> 32) as u32,
        uid: uid_gid as u32,
        gid: (uid_gid >> 32) as u32,
        hook,
        family: family as u8,
        protocol: protocol as u8,
        _pad: [0; 5],
    };
    if SOCKET_IDENTITY.insert(&cookie, &identity, 0).is_err() {
        increment_metric!(ATTRIBUTION_METRICS, ATTRIBUTION_METRIC_INSERT_FAILED);
        return;
    }
    increment_metric!(ATTRIBUTION_METRICS, metric);
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
