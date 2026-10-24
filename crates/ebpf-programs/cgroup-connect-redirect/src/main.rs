//! Steering the TCP connections of selected cgroups to a local listener.
//!
//! Three programs. `connect4`/`connect6` fire while the destination is still
//! an argument of the system call: for a task whose cgroup, or one of its
//! ancestors, is selected and a destination port that is redirected, they
//! record where the connection was going against the socket's cookie and
//! rewrite the destination to the listener. `sockops` fires once the kernel
//! has chosen the source port, which is the address the listener will see the
//! connection come from, and moves the record under that address.
//!
//! A task in a cgroup nobody selected is allowed through untouched, whatever
//! it connects to. A selected task whose destination could not be recorded is
//! refused, because the listener would receive a connection it cannot route.

#![no_std]
#![no_main]

use aya_ebpf::{
    btf_maps::{Array, HashMap, LruHashMap, PerCpuArray},
    helpers::{bpf_get_current_cgroup_id, generated},
    macros::{btf_map, cgroup_sock_addr, sock_ops},
    programs::{SockAddrContext, SockOpsContext},
};
use ebpf_common::redirect::{
    REDIRECT_ANCESTOR_LEVELS, REDIRECT_FAMILY_IPV4, REDIRECT_FAMILY_IPV6, REDIRECT_MAX_CGROUPS,
    REDIRECT_MAX_EXEMPT, REDIRECT_MAX_PENDING, REDIRECT_MAX_PORTS, REDIRECT_METRIC_COUNT,
    REDIRECT_METRIC_PORT_SKIPPED, REDIRECT_METRIC_PUBLISH_FAILED, REDIRECT_METRIC_PUBLISHED,
    REDIRECT_METRIC_REDIRECTED, REDIRECT_METRIC_REFUSED, RedirectOrigin, RedirectPeerKey,
    RedirectTarget,
};
use ebpf_helpers::increment_metric;

// ── Maps ────────────────────────────────────────────────────────────

/// Where redirected connections go. Index 0; a zero port disables the whole
/// program, which is the state it loads in.
#[btf_map]
static REDIRECT_TARGET: Array<RedirectTarget, 1> = Array::new();

/// Cgroup ids whose connections are redirected. Written by userspace from the
/// workloads an operator named, and replaced as a whole on every change.
#[btf_map]
static REDIRECT_CGROUPS: HashMap<u64, u8, { REDIRECT_MAX_CGROUPS as usize }> = HashMap::new();

/// Cgroup ids never redirected, whatever selection covers them: the agent's
/// own, so the listener's onward connection to the real destination is not
/// sent back to the listener.
#[btf_map]
static REDIRECT_EXEMPT: HashMap<u64, u8, { REDIRECT_MAX_EXEMPT as usize }> = HashMap::new();

/// Destination ports, host order, whose connections are redirected.
#[btf_map]
static REDIRECT_PORTS: HashMap<u16, u8, { REDIRECT_MAX_PORTS as usize }> = HashMap::new();

/// Socket cookie -> where the connection was going, between `connect()` and
/// the moment the kernel picks a source port.
#[btf_map]
static REDIRECT_BY_COOKIE: LruHashMap<u64, RedirectOrigin, { REDIRECT_MAX_PENDING as usize }> =
    LruHashMap::new();

/// Source address as the listener sees it -> where the connection was going.
/// Read and deleted by the listener when it accepts.
#[btf_map]
static REDIRECT_BY_PEER: LruHashMap<
    RedirectPeerKey,
    RedirectOrigin,
    { REDIRECT_MAX_PENDING as usize },
> = LruHashMap::new();

/// Per-CPU counters, read by the agent and exported as metrics.
#[btf_map]
static REDIRECT_METRICS: PerCpuArray<u64, { REDIRECT_METRIC_COUNT as usize }> = PerCpuArray::new();

// ── Programs ────────────────────────────────────────────────────────

const AF_INET: u32 = 2;
const AF_INET6: u32 = 10;
const IPPROTO_TCP: u32 = 6;

/// Let the connection through, to wherever it now points.
const ALLOW: i32 = 1;
/// Refuse the connection: `connect()` returns `EPERM` to the task.
const REFUSE: i32 = 0;

/// A task asking for an IPv4 connection.
#[cgroup_sock_addr(connect4)]
pub fn redirect_connect4(ctx: SockAddrContext) -> i32 {
    steer(&ctx, AF_INET)
}

/// A task asking for an IPv6 connection, or an IPv4 one through a dual-stack
/// socket.
#[cgroup_sock_addr(connect6)]
pub fn redirect_connect6(ctx: SockAddrContext) -> i32 {
    steer(&ctx, AF_INET6)
}

/// `BPF_SOCK_OPS_TCP_CONNECT_CB`: the SYN is about to leave and the source
/// port exists.
const SOCK_OPS_TCP_CONNECT: u32 = 3;

/// Publish a redirected connection under the address the listener will see.
#[sock_ops]
pub fn redirect_sockops(ctx: SockOpsContext) -> u32 {
    publish(&ctx);
    // Zero asks the TCP stack for no callback: this hook names a connection,
    // it never shapes one.
    0
}

// ── Steering ────────────────────────────────────────────────────────

#[inline(always)]
fn steer(ctx: &SockAddrContext, hook_family: u32) -> i32 {
    let Some(target) = REDIRECT_TARGET.get(0) else {
        return ALLOW;
    };
    if target.port == 0 {
        return ALLOW;
    }
    if unsafe { (*ctx.sock_addr).protocol } != IPPROTO_TCP {
        return ALLOW;
    }
    let Some(cgroup) = selected_cgroup() else {
        return ALLOW;
    };

    let port = u16::from_be(unsafe { (*ctx.sock_addr).user_port } as u16);
    if REDIRECT_PORTS.get_ptr(&port).is_none() {
        increment_metric!(REDIRECT_METRICS, REDIRECT_METRIC_PORT_SKIPPED);
        return ALLOW;
    }

    let (addr, family, mapped) = destination_of(ctx, hook_family);
    let reachable = if family == REDIRECT_FAMILY_IPV4 {
        target.addr4 != 0
    } else {
        target.addr6 != [0; 4]
    };
    if !reachable {
        // No listener in this family, so there is nowhere to send it; leaving
        // it alone is what an operator who configured one family asked for.
        return ALLOW;
    }
    if is_target(&addr, family, port, target) {
        // Already aimed at the listener: rewriting it again would record the
        // listener as its own destination.
        return ALLOW;
    }

    let cookie = unsafe { generated::bpf_get_socket_cookie(ctx.sock_addr.cast()) };
    if cookie == 0 {
        increment_metric!(REDIRECT_METRICS, REDIRECT_METRIC_REFUSED);
        return REFUSE;
    }
    let origin = RedirectOrigin {
        cgroup_id: cgroup,
        addr,
        port,
        family,
        _pad: [0; 5],
    };
    if REDIRECT_BY_COOKIE.insert(&cookie, &origin, 0).is_err() {
        increment_metric!(REDIRECT_METRICS, REDIRECT_METRIC_REFUSED);
        return REFUSE;
    }

    rewrite(ctx, hook_family, family, mapped, target);
    increment_metric!(REDIRECT_METRICS, REDIRECT_METRIC_REDIRECTED);
    ALLOW
}

/// The selected cgroup the calling task sits in or under, tested from its own
/// upwards.
#[inline(always)]
fn selected_cgroup() -> Option<u64> {
    let own = unsafe { bpf_get_current_cgroup_id() };
    if REDIRECT_EXEMPT.get_ptr(&own).is_some() {
        return None;
    }
    if own != 0 && REDIRECT_CGROUPS.get_ptr(&own).is_some() {
        return Some(own);
    }
    let mut level = 0u32;
    while level < REDIRECT_ANCESTOR_LEVELS {
        let ancestor = unsafe { generated::bpf_get_current_ancestor_cgroup_id(level as i32) };
        if ancestor == 0 {
            break;
        }
        if REDIRECT_CGROUPS.get_ptr(&ancestor).is_some() {
            return Some(own);
        }
        level += 1;
    }
    None
}

/// The destination in host-order words, its family, and whether it reached
/// an IPv6 hook as a mapped IPv4 address.
#[inline(always)]
fn destination_of(ctx: &SockAddrContext, hook_family: u32) -> ([u32; 4], u8, bool) {
    if hook_family == AF_INET {
        let word = u32::from_be(unsafe { (*ctx.sock_addr).user_ip4 });
        return ([word, 0, 0, 0], REDIRECT_FAMILY_IPV4, false);
    }
    let raw = unsafe { (*ctx.sock_addr).user_ip6 };
    let words = [
        u32::from_be(raw[0]),
        u32::from_be(raw[1]),
        u32::from_be(raw[2]),
        u32::from_be(raw[3]),
    ];
    if words[0] == 0 && words[1] == 0 && words[2] == 0x0000_ffff {
        return ([words[3], 0, 0, 0], REDIRECT_FAMILY_IPV4, true);
    }
    (words, REDIRECT_FAMILY_IPV6, false)
}

#[inline(always)]
fn is_target(addr: &[u32; 4], family: u8, port: u16, target: &RedirectTarget) -> bool {
    if port != target.port {
        return false;
    }
    if family == REDIRECT_FAMILY_IPV4 {
        return addr[0] == target.addr4;
    }
    *addr == target.addr6
}

/// Point the connection at the listener.
#[inline(always)]
fn rewrite(
    ctx: &SockAddrContext,
    hook_family: u32,
    family: u8,
    mapped: bool,
    target: &RedirectTarget,
) {
    let sa = ctx.sock_addr;
    unsafe {
        (*sa).user_port = u32::from(target.port.to_be());
    }
    if hook_family == AF_INET {
        unsafe {
            (*sa).user_ip4 = target.addr4.to_be();
        }
        return;
    }
    // Each word is written on its own: the verifier accepts a four-byte store
    // into the context and nothing wider.
    if mapped || family == REDIRECT_FAMILY_IPV4 {
        unsafe {
            (*sa).user_ip6[0] = 0;
            (*sa).user_ip6[1] = 0;
            (*sa).user_ip6[2] = 0x0000_ffffu32.to_be();
            (*sa).user_ip6[3] = target.addr4.to_be();
        }
        return;
    }
    unsafe {
        (*sa).user_ip6[0] = target.addr6[0].to_be();
        (*sa).user_ip6[1] = target.addr6[1].to_be();
        (*sa).user_ip6[2] = target.addr6[2].to_be();
        (*sa).user_ip6[3] = target.addr6[3].to_be();
    }
}

// ── Publishing ──────────────────────────────────────────────────────

/// Move the record of a redirected connection from its cookie to its source
/// address.
#[inline(always)]
fn publish(ctx: &SockOpsContext) {
    if ctx.op() != SOCK_OPS_TCP_CONNECT {
        return;
    }
    let cookie = unsafe { generated::bpf_get_socket_cookie(ctx.ops.cast()) };
    if cookie == 0 {
        return;
    }
    let Some(origin_ptr) = REDIRECT_BY_COOKIE.get_ptr(&cookie) else {
        // Not a connection this program steered.
        return;
    };
    let origin = unsafe { *origin_ptr };
    let _ = REDIRECT_BY_COOKIE.remove(&cookie);

    let Some(key) = source_of(ctx) else {
        increment_metric!(REDIRECT_METRICS, REDIRECT_METRIC_PUBLISH_FAILED);
        return;
    };
    if REDIRECT_BY_PEER.insert(&key, &origin, 0).is_err() {
        increment_metric!(REDIRECT_METRICS, REDIRECT_METRIC_PUBLISH_FAILED);
        return;
    }
    increment_metric!(REDIRECT_METRICS, REDIRECT_METRIC_PUBLISHED);
}

/// The socket's own address, in the shape the listener builds from the peer
/// address `accept()` hands it. A dual-stack socket reaching an IPv4 listener
/// is seen by that listener as IPv4, so a mapped address is unmapped here.
#[inline(always)]
fn source_of(ctx: &SockOpsContext) -> Option<RedirectPeerKey> {
    let port = ctx.local_port() as u16;
    let family = ctx.family();
    if family == AF_INET {
        return Some(RedirectPeerKey {
            addr: [u32::from_be(ctx.local_ip4()), 0, 0, 0],
            port,
            family: REDIRECT_FAMILY_IPV4,
            _pad: 0,
        });
    }
    if family == AF_INET6 {
        let raw = ctx.local_ip6();
        let words = [
            u32::from_be(raw[0]),
            u32::from_be(raw[1]),
            u32::from_be(raw[2]),
            u32::from_be(raw[3]),
        ];
        if words[0] == 0 && words[1] == 0 && words[2] == 0x0000_ffff {
            return Some(RedirectPeerKey {
                addr: [words[3], 0, 0, 0],
                port,
                family: REDIRECT_FAMILY_IPV4,
                _pad: 0,
            });
        }
        return Some(RedirectPeerKey {
            addr: words,
            port,
            family: REDIRECT_FAMILY_IPV6,
            _pad: 0,
        });
    }
    None
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
