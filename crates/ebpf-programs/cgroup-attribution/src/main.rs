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
    macros::{btf_map, cgroup_sock, cgroup_sock_addr},
    programs::{SockAddrContext, SockContext},
};
use ebpf_common::attribution::{
    ATTRIBUTION_HOOK_CONNECT, ATTRIBUTION_HOOK_POST_BIND, ATTRIBUTION_HOOK_SENDMSG,
    ATTRIBUTION_MAX_SOCKETS, ATTRIBUTION_METRIC_CONNECT, ATTRIBUTION_METRIC_COUNT,
    ATTRIBUTION_METRIC_INSERT_FAILED, ATTRIBUTION_METRIC_NO_COOKIE,
    ATTRIBUTION_METRIC_POST_BIND, ATTRIBUTION_METRIC_SENDMSG, SocketIdentity,
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
