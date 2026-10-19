//! A firewall rule about a workload, decided in the syscall of the task that
//! is opening the socket.
//!
//! The packet path cannot do this. By the time a frame reaches an interface
//! there is no task to ask about, only a five-tuple, so a rule naming a
//! binary, a systemd unit, a cgroup or a container has nowhere to be decided
//! down there. The cgroup socket hooks run one layer up, in `connect()`,
//! `sendmsg()` and `bind()`, with the calling task still on the stack and
//! before a packet exists.
//!
//! Six programs, one decision. `connect4`/`connect6` cover a connected
//! socket, `sendmsg4`/`sendmsg6` the datagram path that never calls
//! `connect()` at all, and `bind4`/`bind6` the moment a workload takes a
//! local address. The bind hooks are the pre-bind ones rather than the
//! post-bind pair the attribution object uses: post-bind runs after the
//! kernel has already assigned the address and cannot refuse it.
//!
//! What the hooks read is a mask, never an identity. Userspace resolves who a
//! cgroup and a task are - a path, a unit name, a container id - and writes
//! one bit per selector of the loaded policy, so the kernel compares integers
//! and never a string. The two maps are ORed: a selector naming an executable
//! is per task, everything else is per cgroup, and a selector mixing the two
//! is only ever written where the whole of it matched.
//!
//! Default is observe. A rule in observe mode counts what it would have
//! refused and lets the syscall through, which is what makes a policy
//! something an operator can measure before turning it on.

#![no_std]
#![no_main]

use aya_ebpf::{
    btf_maps::{Array, HashMap, LruHashMap, PerCpuArray, RingBuf},
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_ktime_get_boot_ns,
    },
    macros::{btf_map, cgroup_sock_addr},
    programs::SockAddrContext,
};
use ebpf_common::workload_policy::{
    WORKLOAD_ACTION_DENY, WORKLOAD_EVENTS_RINGBUF_BYTES, WORKLOAD_FAMILY_ANY, WORKLOAD_FAMILY_IPV4,
    WORKLOAD_FAMILY_IPV6, WORKLOAD_HOOK_BIND, WORKLOAD_HOOK_CONNECT, WORKLOAD_HOOK_SENDMSG,
    WORKLOAD_METRIC_ALLOWED, WORKLOAD_METRIC_BIND, WORKLOAD_METRIC_CONNECT, WORKLOAD_METRIC_COUNT,
    WORKLOAD_METRIC_EVENT_LOST, WORKLOAD_METRIC_NO_RULE, WORKLOAD_METRIC_REFUSED,
    WORKLOAD_METRIC_SENDMSG, WORKLOAD_METRIC_UNRESOLVED, WORKLOAD_METRIC_WOULD_REFUSE,
    WORKLOAD_MODE_ENFORCE, WORKLOAD_POLICY_MAX_CGROUPS, WORKLOAD_POLICY_MAX_RULES,
    WORKLOAD_POLICY_MAX_TASKS, WORKLOAD_PROTOCOL_ANY, WorkloadDenialEvent, WorkloadRuleEntry,
};
use ebpf_helpers::increment_metric;

// ── Maps ────────────────────────────────────────────────────────────

/// The policy, in priority order, with no holes.
///
/// Userspace writes the rules from the highest priority down and leaves every
/// slot past the last one disabled, so the walk stops at the first disabled
/// entry rather than reading sixty-four every time. Slot zero disabled means
/// no policy at all, which is the state every node that never configured one
/// is in.
#[btf_map]
static WORKLOAD_RULES: Array<WorkloadRuleEntry, { WORKLOAD_POLICY_MAX_RULES }> = Array::new();

/// cgroup id -> the selectors this cgroup satisfies, one bit each.
///
/// A plain hash map rather than an LRU: an eviction here is a rule silently
/// ceasing to apply to a container that is still running, which is the one
/// failure a deny policy must not have. Userspace sizes it for the node and
/// an insert it refuses is visible as a refused insert rather than as a quiet
/// hole.
#[btf_map]
static WORKLOAD_CGROUP_SELECTORS: HashMap<u64, u64, { WORKLOAD_POLICY_MAX_CGROUPS as usize }> =
    HashMap::new();

/// Thread group id -> the selectors this task satisfies.
///
/// An executable path belongs to a task and not to its cgroup, so a selector
/// naming one is written here instead. LRU because a pid is reused and a node
/// that forks hard would otherwise fill the table with the dead.
#[btf_map]
static WORKLOAD_TASK_SELECTORS: LruHashMap<u32, u64, { WORKLOAD_POLICY_MAX_TASKS as usize }> =
    LruHashMap::new();

/// What the policy did, per CPU.
#[btf_map]
static WORKLOAD_METRICS: PerCpuArray<u64, { WORKLOAD_METRIC_COUNT as usize }> = PerCpuArray::new();

/// How many operations each rule refused, per CPU, one slot per rule.
///
/// It sits beside the ring buffer rather than being counted off it: a record
/// the buffer had no room for is a denial that happened, and a per-rule
/// figure that drops the overflow is a figure an operator would read as a
/// policy that stopped matching. The counter is the count, the ring is the
/// detail, and the first is exact.
#[btf_map]
static WORKLOAD_RULE_DENIALS: PerCpuArray<u64, { WORKLOAD_POLICY_MAX_RULES }> = PerCpuArray::new();

/// One record per refusal, on its way to an alert.
///
/// Its own ring and not a share of the packet ring: a refusal is rare, it is
/// the one thing a deny policy exists to tell somebody about, and it must not
/// queue behind a flood of packets. A full ring costs the record and never
/// the decision, which is already taken by the time anything is written.
#[btf_map]
static WORKLOAD_EVENTS: RingBuf<WorkloadDenialEvent, { WORKLOAD_EVENTS_RINGBUF_BYTES as usize }> =
    RingBuf::new();

// ── Verdicts, in the kernel's own numbering ─────────────────────────

/// What a `cgroup_sock_addr` program returns to let the syscall proceed.
const ALLOW: i32 = 1;
/// What it returns to refuse it. The caller sees `EPERM`.
const REFUSE: i32 = 0;

/// `AF_INET`, as the socket carries it.
const AF_INET: u32 = 2;
/// `AF_INET6`.
const AF_INET6: u32 = 10;

// ── Programs ────────────────────────────────────────────────────────

/// A workload asking for an IPv4 connection.
#[cgroup_sock_addr(connect4)]
pub fn workload_connect4(ctx: SockAddrContext) -> i32 {
    decide(&ctx, WORKLOAD_HOOK_CONNECT)
}

/// A workload asking for an IPv6 connection.
#[cgroup_sock_addr(connect6)]
pub fn workload_connect6(ctx: SockAddrContext) -> i32 {
    decide(&ctx, WORKLOAD_HOOK_CONNECT)
}

/// A workload sending a datagram with no connection, the path almost all DNS
/// takes.
#[cgroup_sock_addr(sendmsg4)]
pub fn workload_sendmsg4(ctx: SockAddrContext) -> i32 {
    decide(&ctx, WORKLOAD_HOOK_SENDMSG)
}

/// The same, over IPv6.
#[cgroup_sock_addr(sendmsg6)]
pub fn workload_sendmsg6(ctx: SockAddrContext) -> i32 {
    decide(&ctx, WORKLOAD_HOOK_SENDMSG)
}

/// A workload taking an IPv4 local address, before the kernel assigns it.
///
/// The address a rule matches here is the local one the workload is asking
/// for, not a peer's: a rule refusing a listener is a rule about where that
/// listener may sit.
#[cgroup_sock_addr(bind4)]
pub fn workload_bind4(ctx: SockAddrContext) -> i32 {
    decide(&ctx, WORKLOAD_HOOK_BIND)
}

/// The same, over IPv6.
#[cgroup_sock_addr(bind6)]
pub fn workload_bind6(ctx: SockAddrContext) -> i32 {
    decide(&ctx, WORKLOAD_HOOK_BIND)
}

// ── The decision ────────────────────────────────────────────────────

/// Walk the policy for this task and answer the one question the hook asks.
///
/// Nothing is counted on a node with no policy: the hooks stay attached when
/// the last rule is removed, and a counter climbing on an empty policy would
/// be a figure about the attachment rather than about the product.
fn decide(ctx: &SockAddrContext, hook: u8) -> i32 {
    let Some(first) = WORKLOAD_RULES.get(0) else {
        return ALLOW;
    };
    if first.enabled == 0 {
        return ALLOW;
    }
    increment_metric!(WORKLOAD_METRICS, hook_metric(hook));

    let mask = selectors();
    if mask == 0 {
        // A task userspace has not placed in any selector yet. Counting it is
        // the honest version of the race: the process table resolves an exec
        // a moment after the kernel saw it, and a connection inside that
        // window is decided by no rule.
        increment_metric!(WORKLOAD_METRICS, WORKLOAD_METRIC_UNRESOLVED);
        return ALLOW;
    }

    let family = unsafe { (*ctx.sock_addr).family };
    let port = u16::from_be(unsafe { (*ctx.sock_addr).user_port } as u16);
    let protocol = unsafe { (*ctx.sock_addr).protocol } as u8;
    let (addr, family) = address_of(ctx, family);

    for index in 0..WORKLOAD_POLICY_MAX_RULES {
        let Some(rule) = WORKLOAD_RULES.get(index as u32) else {
            break;
        };
        if rule.enabled == 0 {
            break;
        }
        if !applies(rule, mask, &addr, family, port, protocol) {
            continue;
        }
        if rule.action != WORKLOAD_ACTION_DENY {
            increment_metric!(WORKLOAD_METRICS, WORKLOAD_METRIC_ALLOWED);
            return ALLOW;
        }
        let enforced = rule.mode == WORKLOAD_MODE_ENFORCE;
        increment_metric!(
            WORKLOAD_METRICS,
            if enforced {
                WORKLOAD_METRIC_REFUSED
            } else {
                WORKLOAD_METRIC_WOULD_REFUSE
            }
        );
        increment_metric!(WORKLOAD_RULE_DENIALS, index as u32);
        report(index, &addr, family, port, protocol, hook, enforced);
        if enforced {
            return REFUSE;
        }
        return ALLOW;
    }

    increment_metric!(WORKLOAD_METRICS, WORKLOAD_METRIC_NO_RULE);
    ALLOW
}

/// Which counter this hook's own calls are added to.
fn hook_metric(hook: u8) -> u32 {
    match hook {
        WORKLOAD_HOOK_CONNECT => WORKLOAD_METRIC_CONNECT,
        WORKLOAD_HOOK_SENDMSG => WORKLOAD_METRIC_SENDMSG,
        _ => WORKLOAD_METRIC_BIND,
    }
}

/// Write down one refusal, or count the record that did not fit.
///
/// The slot is what travels rather than the rule's name: a hook has no string
/// to send and userspace published the slots in the order it holds the rules,
/// so the translation is exact and costs the kernel nothing.
fn report(
    index: usize,
    addr: &[u32; 4],
    family: u8,
    port: u16,
    protocol: u8,
    hook: u8,
    enforced: bool,
) {
    let Some(mut entry) = WORKLOAD_EVENTS.reserve(0) else {
        increment_metric!(WORKLOAD_METRICS, WORKLOAD_METRIC_EVENT_LOST);
        return;
    };
    entry.write(WorkloadDenialEvent {
        at_ns: unsafe { bpf_ktime_get_boot_ns() },
        cgroup_id: unsafe { bpf_get_current_cgroup_id() },
        dst_addr: *addr,
        tgid: (bpf_get_current_pid_tgid() >> 32) as u32,
        uid: bpf_get_current_uid_gid() as u32,
        dst_port: port,
        rule: index as u16,
        family,
        protocol,
        hook,
        enforced: u8::from(enforced),
    });
    entry.submit(0);
}

/// Every selector the calling task satisfies, from both halves of the lookup.
///
/// The two maps are ORed rather than consulted in turn because a selector is
/// written to exactly one of them: userspace sets a bit only once the whole
/// selector matched, so a rule naming a unit and an executable at the same
/// time sits in the task map alone and is never half-satisfied by a cgroup.
fn selectors() -> u64 {
    let cgroup = unsafe { bpf_get_current_cgroup_id() };
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;

    let by_cgroup = unsafe { WORKLOAD_CGROUP_SELECTORS.get(&cgroup) }.copied();
    let by_task = unsafe { WORKLOAD_TASK_SELECTORS.get(&tgid) }.copied();

    by_cgroup.unwrap_or(0) | by_task.unwrap_or(0)
}

/// The address this hook is about, in the host-order words the rules store,
/// with the family the rule will be compared against.
///
/// A v6 socket reaching a v4 address carries it mapped, `::ffff:a.b.c.d`, and
/// a rule written about that address is a rule about IPv4. Unmapping it here
/// is what stops the same destination being matchable under one family and
/// not the other depending on how the caller opened its socket.
fn address_of(ctx: &SockAddrContext, family: u32) -> ([u32; 4], u8) {
    if family == AF_INET {
        let word = u32::from_be(unsafe { (*ctx.sock_addr).user_ip4 });
        return ([word, 0, 0, 0], WORKLOAD_FAMILY_IPV4);
    }
    if family == AF_INET6 {
        let raw = unsafe { (*ctx.sock_addr).user_ip6 };
        let words = [
            u32::from_be(raw[0]),
            u32::from_be(raw[1]),
            u32::from_be(raw[2]),
            u32::from_be(raw[3]),
        ];
        if words[0] == 0 && words[1] == 0 && words[2] == 0x0000_ffff {
            return ([words[3], 0, 0, 0], WORKLOAD_FAMILY_IPV4);
        }
        return (words, WORKLOAD_FAMILY_IPV6);
    }
    ([0; 4], WORKLOAD_FAMILY_ANY)
}

/// Whether one rule speaks about this operation.
fn applies(
    rule: &WorkloadRuleEntry,
    mask: u64,
    addr: &[u32; 4],
    family: u8,
    port: u16,
    protocol: u8,
) -> bool {
    if mask & (1u64 << (rule.selector & 63)) == 0 {
        return false;
    }
    if rule.family != WORKLOAD_FAMILY_ANY && rule.family != family {
        return false;
    }
    if rule.protocol != WORKLOAD_PROTOCOL_ANY && rule.protocol != protocol {
        return false;
    }
    if (rule.port_start != 0 || rule.port_end != 0)
        && (port < rule.port_start || port > rule.port_end)
    {
        return false;
    }
    inside(&rule.dst_addr, rule.prefix_len, addr)
}

/// Whether an address sits inside a prefix, both as host-order words.
///
/// A prefix length of zero is anywhere, which is also what a rule carrying no
/// address at all is written as.
fn inside(network: &[u32; 4], prefix_len: u8, addr: &[u32; 4]) -> bool {
    let mut remaining = u32::from(prefix_len.min(128));
    let mut word = 0usize;
    while word < 4 {
        if remaining == 0 {
            return true;
        }
        let bits = if remaining >= 32 { 32 } else { remaining };
        let mask = if bits == 32 {
            u32::MAX
        } else {
            u32::MAX << (32 - bits)
        };
        if (network[word] ^ addr[word]) & mask != 0 {
            return false;
        }
        remaining -= bits;
        word += 1;
    }
    true
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
