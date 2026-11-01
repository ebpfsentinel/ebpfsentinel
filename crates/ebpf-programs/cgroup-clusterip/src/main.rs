//! Resolving a Service's cluster address at `connect()` for the workloads
//! that opted in.
//!
//! Six programs. `connect4`/`connect6` fire while the destination is still
//! an argument of the system call: for a task whose cgroup, or one of its
//! ancestors, is selected and a destination that is a cluster address the
//! table holds, they pick one of the Service's ready backends, record the
//! pair against the socket's cookie and rewrite the destination to the
//! backend. `getpeername4`/`getpeername6` and `recvmsg4`/`recvmsg6` read the
//! record back and answer with the cluster address, so the task sees the
//! address it asked for.
//!
//! Every way of not deciding lets the connection through as the task wrote
//! it, which is kube-proxy's to route: nothing here ever refuses one.

#![no_std]
#![no_main]

use aya_ebpf::{
    btf_maps::{HashMap, LruHashMap, PerCpuArray},
    helpers::{bpf_get_current_cgroup_id, generated},
    macros::{btf_map, cgroup_sock_addr},
    programs::SockAddrContext,
};
use ebpf_common::clusterip::{
    CLUSTERIP_ANCESTOR_LEVELS, CLUSTERIP_FAMILY_IPV4, CLUSTERIP_FAMILY_IPV6,
    CLUSTERIP_MAX_AFFINITY, CLUSTERIP_MAX_BACKENDS, CLUSTERIP_MAX_CGROUPS, CLUSTERIP_MAX_REVERSE,
    CLUSTERIP_MAX_SERVICES, CLUSTERIP_METRIC_AFFINITY_HIT, CLUSTERIP_METRIC_COUNT,
    CLUSTERIP_METRIC_LEFT, CLUSTERIP_METRIC_REVERSED, CLUSTERIP_METRIC_TRANSLATED,
    ClusterIpAffinity, ClusterIpAffinityKey, ClusterIpBackend, ClusterIpKey, ClusterIpReady,
    ClusterIpReverse, ClusterIpService, ClusterIpSlot,
};
use ebpf_helpers::increment_metric;

// ── Maps ────────────────────────────────────────────────────────────

/// Cluster address, port and protocol -> the service port behind it.
#[btf_map]
static CLUSTERIP_SERVICES: HashMap<
    ClusterIpKey,
    ClusterIpService,
    { CLUSTERIP_MAX_SERVICES as usize },
> = HashMap::new();

/// Revision and slot -> one backend of a service port's list.
#[btf_map]
static CLUSTERIP_BACKENDS: HashMap<
    ClusterIpSlot,
    ClusterIpBackend,
    { CLUSTERIP_MAX_BACKENDS as usize },
> = HashMap::new();

/// Service port and backend, present while the backend is ready.
#[btf_map]
static CLUSTERIP_READY: HashMap<ClusterIpReady, u8, { CLUSTERIP_MAX_BACKENDS as usize }> =
    HashMap::new();

/// Cgroup ids whose connections are resolved here. Written by userspace from
/// the workloads an operator named.
#[btf_map]
static CLUSTERIP_CGROUPS: HashMap<u64, u8, { CLUSTERIP_MAX_CGROUPS as usize }> = HashMap::new();

/// Network namespace and service port -> the backend last used.
#[btf_map]
static CLUSTERIP_AFFINITY: LruHashMap<
    ClusterIpAffinityKey,
    ClusterIpAffinity,
    { CLUSTERIP_MAX_AFFINITY as usize },
> = LruHashMap::new();

/// Socket cookie -> the cluster address it asked for and the backend it got.
#[btf_map]
static CLUSTERIP_REVERSE: LruHashMap<u64, ClusterIpReverse, { CLUSTERIP_MAX_REVERSE as usize }> =
    LruHashMap::new();

/// Per-CPU counters, read by the agent and exported as metrics.
#[btf_map]
static CLUSTERIP_METRICS: PerCpuArray<u64, { CLUSTERIP_METRIC_COUNT as usize }> =
    PerCpuArray::new();

// ── Programs ────────────────────────────────────────────────────────

const AF_INET: u32 = 2;
const AF_INET6: u32 = 10;
const IPPROTO_TCP: u32 = 6;
const IPPROTO_UDP: u32 = 17;

/// Every hook answers this: a connection is never refused here.
const ALLOW: i32 = 1;

const NS_PER_SEC: u64 = 1_000_000_000;

/// A task asking for an IPv4 connection.
#[cgroup_sock_addr(connect4)]
pub fn clusterip_connect4(ctx: SockAddrContext) -> i32 {
    resolve(&ctx, AF_INET);
    ALLOW
}

/// A task asking for an IPv6 connection, or an IPv4 one through a dual-stack
/// socket.
#[cgroup_sock_addr(connect6)]
pub fn clusterip_connect6(ctx: SockAddrContext) -> i32 {
    resolve(&ctx, AF_INET6);
    ALLOW
}

/// A task asking whom its IPv4 socket is connected to.
#[cgroup_sock_addr(getpeername4)]
pub fn clusterip_getpeername4(ctx: SockAddrContext) -> i32 {
    reverse(&ctx, AF_INET);
    ALLOW
}

/// A task asking whom its IPv6 socket is connected to.
#[cgroup_sock_addr(getpeername6)]
pub fn clusterip_getpeername6(ctx: SockAddrContext) -> i32 {
    reverse(&ctx, AF_INET6);
    ALLOW
}

/// A datagram read on an IPv4 UDP socket, its source about to be returned.
#[cgroup_sock_addr(recvmsg4)]
pub fn clusterip_recvmsg4(ctx: SockAddrContext) -> i32 {
    reverse(&ctx, AF_INET);
    ALLOW
}

/// A datagram read on an IPv6 UDP socket, its source about to be returned.
#[cgroup_sock_addr(recvmsg6)]
pub fn clusterip_recvmsg6(ctx: SockAddrContext) -> i32 {
    reverse(&ctx, AF_INET6);
    ALLOW
}

// ── Resolving ───────────────────────────────────────────────────────

#[inline(always)]
fn resolve(ctx: &SockAddrContext, hook_family: u32) {
    let protocol = unsafe { (*ctx.sock_addr).protocol };
    if protocol != IPPROTO_TCP && protocol != IPPROTO_UDP {
        return;
    }
    if !selected() {
        return;
    }
    let (addr, family, mapped) = address_of(ctx, hook_family);
    let port = u16::from_be(unsafe { (*ctx.sock_addr).user_port } as u16);
    let key = ClusterIpKey {
        addr,
        port,
        proto: protocol as u8,
        family,
    };
    let Some(service_ptr) = CLUSTERIP_SERVICES.get_ptr(&key) else {
        // Not a cluster address the table holds: nothing to decide.
        return;
    };
    let service = unsafe { *service_ptr };
    if service.count == 0 {
        increment_metric!(CLUSTERIP_METRICS, CLUSTERIP_METRIC_LEFT);
        return;
    }

    let netns = unsafe { generated::bpf_get_netns_cookie(ctx.sock_addr.cast()) };
    let now = unsafe { generated::bpf_ktime_get_ns() };
    let affinity_key = ClusterIpAffinityKey {
        netns,
        stable: service.stable,
        _pad: 0,
    };
    let Some((backend, remembered)) = choose(&service, &affinity_key, now) else {
        increment_metric!(CLUSTERIP_METRICS, CLUSTERIP_METRIC_LEFT);
        return;
    };
    if backend.family != family {
        increment_metric!(CLUSTERIP_METRICS, CLUSTERIP_METRIC_LEFT);
        return;
    }

    let cookie = unsafe { generated::bpf_get_socket_cookie(ctx.sock_addr.cast()) };
    let record = ClusterIpReverse {
        cluster: ClusterIpBackend {
            addr,
            port,
            family,
            _pad: 0,
        },
        backend,
    };
    if cookie == 0 || CLUSTERIP_REVERSE.insert(&cookie, &record, 0).is_err() {
        // Without the record the task would read the backend back from
        // getpeername, so the connection goes the way it was written.
        increment_metric!(CLUSTERIP_METRICS, CLUSTERIP_METRIC_LEFT);
        return;
    }
    if service.affinity_secs != 0 && netns != 0 {
        let entry = ClusterIpAffinity {
            backend,
            _pad: 0,
            last_ns: now,
        };
        let _ = CLUSTERIP_AFFINITY.insert(&affinity_key, &entry, 0);
    }

    write_address(ctx, hook_family, mapped, &backend);
    if remembered {
        increment_metric!(CLUSTERIP_METRICS, CLUSTERIP_METRIC_AFFINITY_HIT);
    }
    increment_metric!(CLUSTERIP_METRICS, CLUSTERIP_METRIC_TRANSLATED);
}

/// The backend for this connection: the one an affinity remembers while it
/// is fresh and still ready, a uniformly drawn one otherwise.
#[inline(always)]
fn choose(
    service: &ClusterIpService,
    affinity_key: &ClusterIpAffinityKey,
    now: u64,
) -> Option<(ClusterIpBackend, bool)> {
    if service.affinity_secs != 0 && affinity_key.netns != 0 {
        if let Some(entry_ptr) = CLUSTERIP_AFFINITY.get_ptr(affinity_key) {
            let entry = unsafe { *entry_ptr };
            let fresh =
                now.wrapping_sub(entry.last_ns) < u64::from(service.affinity_secs) * NS_PER_SEC;
            let ready = ClusterIpReady {
                stable: service.stable,
                backend: entry.backend,
            };
            if fresh && CLUSTERIP_READY.get_ptr(&ready).is_some() {
                return Some((entry.backend, true));
            }
        }
    }
    let draw = unsafe { generated::bpf_get_prandom_u32() };
    let slot = ClusterIpSlot {
        revision: service.revision,
        slot: draw % service.count,
    };
    let backend_ptr = CLUSTERIP_BACKENDS.get_ptr(&slot)?;
    Some((unsafe { *backend_ptr }, false))
}

/// Whether the calling task sits in or under a selected cgroup.
#[inline(always)]
fn selected() -> bool {
    let own = unsafe { bpf_get_current_cgroup_id() };
    if own != 0 && CLUSTERIP_CGROUPS.get_ptr(&own).is_some() {
        return true;
    }
    let mut level = 0u32;
    while level < CLUSTERIP_ANCESTOR_LEVELS {
        let ancestor = unsafe { generated::bpf_get_current_ancestor_cgroup_id(level as i32) };
        if ancestor == 0 {
            return false;
        }
        if CLUSTERIP_CGROUPS.get_ptr(&ancestor).is_some() {
            return true;
        }
        level += 1;
    }
    false
}

// ── Answering with the cluster address ──────────────────────────────

#[inline(always)]
fn reverse(ctx: &SockAddrContext, hook_family: u32) {
    let cookie = unsafe { generated::bpf_get_socket_cookie(ctx.sock_addr.cast()) };
    if cookie == 0 {
        return;
    }
    let Some(record_ptr) = CLUSTERIP_REVERSE.get_ptr(&cookie) else {
        return;
    };
    let record = unsafe { *record_ptr };
    let (addr, family, mapped) = address_of(ctx, hook_family);
    let port = u16::from_be(unsafe { (*ctx.sock_addr).user_port } as u16);
    // Only the backend's own address is rewritten: an unconnected socket
    // that was once translated may read a datagram from anyone.
    if family != record.backend.family || port != record.backend.port || addr != record.backend.addr
    {
        return;
    }
    write_address(ctx, hook_family, mapped, &record.cluster);
    increment_metric!(CLUSTERIP_METRICS, CLUSTERIP_METRIC_REVERSED);
}

// ── Addresses ───────────────────────────────────────────────────────

/// The address in host-order words, its family, and whether it reached an
/// IPv6 hook as a mapped IPv4 address.
#[inline(always)]
fn address_of(ctx: &SockAddrContext, hook_family: u32) -> ([u32; 4], u8, bool) {
    if hook_family == AF_INET {
        let word = u32::from_be(unsafe { (*ctx.sock_addr).user_ip4 });
        return ([word, 0, 0, 0], CLUSTERIP_FAMILY_IPV4, false);
    }
    let raw = unsafe { (*ctx.sock_addr).user_ip6 };
    let words = [
        u32::from_be(raw[0]),
        u32::from_be(raw[1]),
        u32::from_be(raw[2]),
        u32::from_be(raw[3]),
    ];
    if words[0] == 0 && words[1] == 0 && words[2] == 0x0000_ffff {
        return ([words[3], 0, 0, 0], CLUSTERIP_FAMILY_IPV4, true);
    }
    (words, CLUSTERIP_FAMILY_IPV6, false)
}

/// Write `to` into the hook's address, in the shape the hook carries.
#[inline(always)]
fn write_address(ctx: &SockAddrContext, hook_family: u32, mapped: bool, to: &ClusterIpBackend) {
    let sa = ctx.sock_addr;
    unsafe {
        (*sa).user_port = u32::from(to.port.to_be());
    }
    if hook_family == AF_INET {
        unsafe {
            (*sa).user_ip4 = to.addr[0].to_be();
        }
        return;
    }
    // Each word is written on its own: the verifier accepts a four-byte store
    // into the context and nothing wider.
    if mapped || to.family == CLUSTERIP_FAMILY_IPV4 {
        unsafe {
            (*sa).user_ip6[0] = 0;
            (*sa).user_ip6[1] = 0;
            (*sa).user_ip6[2] = 0x0000_ffffu32.to_be();
            (*sa).user_ip6[3] = to.addr[0].to_be();
        }
        return;
    }
    unsafe {
        (*sa).user_ip6[0] = to.addr[0].to_be();
        (*sa).user_ip6[1] = to.addr[1].to_be();
        (*sa).user_ip6[2] = to.addr[2].to_be();
        (*sa).user_ip6[3] = to.addr[3].to_be();
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
