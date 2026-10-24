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
//!
//! The same six hooks carry a second, unrelated question: whether this cgroup
//! is quarantined. It is asked first and answered before the rule array is
//! even looked at, for two reasons. A quarantine is a response rather than a
//! policy, so it must work on a node whose policy document is empty; and a
//! rule that allows must not be able to let a cut-off workload back out.
//!
//! Two more programs sit on the packet side of the same cgroups, for rules
//! that name a destination by its DNS name. `cgroup_skb` egress and ingress
//! copy the UDP DNS queries and answers of a named workload up to userspace,
//! which pairs them, believes only an answer from a trusted resolver to a
//! query the same cgroup sent, and writes the addresses it learned into
//! `WORKLOAD_FQDN_ALLOWED` for that cgroup and that rule alone. The connect
//! hook then reads that map instead of a prefix. Neither DNS program ever
//! drops a packet: capture is all they do.

#![no_std]
#![no_main]

use aya_ebpf::{
    btf_maps::{Array, HashMap, LruHashMap, PerCpuArray, RingBuf},
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_ktime_get_boot_ns, bpf_skb_cgroup_id, bpf_skb_load_bytes,
    },
    macros::{btf_map, cgroup_skb, cgroup_sock_addr},
    programs::{SkBuffContext, SockAddrContext},
};
use ebpf_common::quarantine::{
    QUARANTINE_EVENTS_RINGBUF_BYTES, QUARANTINE_MAX_CGROUPS, QUARANTINE_METRIC_COUNT,
    QUARANTINE_METRIC_EVENT_LOST, QUARANTINE_METRIC_EXPIRED, QUARANTINE_METRIC_OBSERVED,
    QUARANTINE_METRIC_REFUSED, QUARANTINE_MODE_REPORT, QUARANTINE_OUTCOME_EXPIRED,
    QUARANTINE_OUTCOME_OBSERVED, QUARANTINE_OUTCOME_REFUSED, QuarantineEntry, QuarantineEvent,
};
use ebpf_common::workload_policy::{
    WORKLOAD_ACTION_DENY, WORKLOAD_DNS_MAX_PAYLOAD, WORKLOAD_DNS_QUERY, WORKLOAD_DNS_RESPONSE,
    WORKLOAD_DNS_RINGBUF_BYTES, WORKLOAD_EVENTS_RINGBUF_BYTES, WORKLOAD_FAMILY_ANY,
    WORKLOAD_FAMILY_IPV4, WORKLOAD_FAMILY_IPV6, WORKLOAD_FQDN_MAX_ALLOWED, WORKLOAD_HOOK_BIND,
    WORKLOAD_HOOK_CONNECT, WORKLOAD_HOOK_SENDMSG, WORKLOAD_METRIC_ALLOWED, WORKLOAD_METRIC_BIND,
    WORKLOAD_METRIC_CONNECT, WORKLOAD_METRIC_COUNT, WORKLOAD_METRIC_DNS_LOST,
    WORKLOAD_METRIC_EVENT_LOST, WORKLOAD_METRIC_NO_RULE, WORKLOAD_METRIC_REFUSED,
    WORKLOAD_METRIC_SENDMSG, WORKLOAD_METRIC_UNRESOLVED, WORKLOAD_METRIC_WOULD_REFUSE,
    WORKLOAD_MODE_ENFORCE, WORKLOAD_POLICY_MAX_CGROUPS, WORKLOAD_POLICY_MAX_RULES,
    WORKLOAD_POLICY_MAX_TASKS, WORKLOAD_PROTOCOL_ANY, WorkloadDenialEvent, WorkloadDnsEvent,
    WorkloadFqdnKey, WorkloadRuleEntry,
};
use ebpf_helpers::{increment_metric, opaque_usize};

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

/// cgroup id -> the quarantine cutting it off, with its own expiry.
///
/// A plain hash map for the same reason as the selectors: an eviction here is
/// a workload an operator believes is cut off quietly reaching the network
/// again. Userspace sizes it, and a refused insert is a quarantine that failed
/// to arm rather than one that armed and lapsed.
#[btf_map]
static QUARANTINE_CGROUPS: HashMap<u64, QuarantineEntry, { QUARANTINE_MAX_CGROUPS as usize }> =
    HashMap::new();

/// What the quarantine did, per CPU.
#[btf_map]
static QUARANTINE_METRICS: PerCpuArray<u64, { QUARANTINE_METRIC_COUNT as usize }> =
    PerCpuArray::new();

/// One record per socket operation a quarantine decided, on its way to an
/// alert.
///
/// Separate from the policy's ring because the two are read by different
/// things and a quarantined workload in a reconnect loop would otherwise
/// starve the refusals a deny rule exists to report.
#[btf_map]
static QUARANTINE_EVENTS: RingBuf<QuarantineEvent, { QUARANTINE_EVENTS_RINGBUF_BYTES as usize }> =
    RingBuf::new();

/// (cgroup, address, rule) -> `CLOCK_BOOTTIME` instant the grant lapses.
///
/// Written by userspace from DNS answers the workload itself received, and
/// read by the connect and sendmsg hooks for a rule naming a destination by
/// name. The expiry is compared here, so a grant whose TTL ran out stops
/// opening new connections at that instant whether or not the sweep has run.
#[btf_map]
static WORKLOAD_FQDN_ALLOWED: HashMap<
    WorkloadFqdnKey,
    u64,
    { WORKLOAD_FQDN_MAX_ALLOWED as usize },
> = HashMap::new();

/// Slot zero non-zero while a loaded rule names a destination by name.
///
/// Off, the two DNS programs return at their first instruction, so a node
/// whose policy names no host pays one array read per packet of a named
/// workload and copies nothing.
#[btf_map]
static WORKLOAD_DNS_CAPTURE: Array<u32, 1> = Array::new();

/// DNS queries and answers of named workloads, on their way to the learner.
#[btf_map]
static WORKLOAD_DNS_EVENTS: RingBuf<WorkloadDnsEvent, { WORKLOAD_DNS_RINGBUF_BYTES as usize }> =
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

/// What a `cgroup_skb` program returns to let the packet through.
const SKB_PASS: i32 = 1;

/// `ETH_P_IP` and `ETH_P_IPV6`, host order, as `__sk_buff.protocol` carries
/// them once swapped.
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;
/// UDP, as the IP header numbers it.
const IPPROTO_UDP: u8 = 17;
/// The port DNS is served on.
const DNS_PORT: u16 = 53;
/// A UDP header.
const UDP_HEADER_LEN: usize = 8;
/// A fixed IPv6 header.
const IPV6_HEADER_LEN: usize = 40;

// ── Programs ────────────────────────────────────────────────────────

/// A workload asking for an IPv4 connection.
#[cgroup_sock_addr(connect4)]
pub fn workload_connect4(ctx: SockAddrContext) -> i32 {
    answer(&ctx, WORKLOAD_HOOK_CONNECT)
}

/// A workload asking for an IPv6 connection.
#[cgroup_sock_addr(connect6)]
pub fn workload_connect6(ctx: SockAddrContext) -> i32 {
    answer(&ctx, WORKLOAD_HOOK_CONNECT)
}

/// A workload sending a datagram with no connection, the path almost all DNS
/// takes.
#[cgroup_sock_addr(sendmsg4)]
pub fn workload_sendmsg4(ctx: SockAddrContext) -> i32 {
    answer(&ctx, WORKLOAD_HOOK_SENDMSG)
}

/// The same, over IPv6.
#[cgroup_sock_addr(sendmsg6)]
pub fn workload_sendmsg6(ctx: SockAddrContext) -> i32 {
    answer(&ctx, WORKLOAD_HOOK_SENDMSG)
}

/// A workload taking an IPv4 local address, before the kernel assigns it.
///
/// The address a rule matches here is the local one the workload is asking
/// for, not a peer's: a rule refusing a listener is a rule about where that
/// listener may sit.
#[cgroup_sock_addr(bind4)]
pub fn workload_bind4(ctx: SockAddrContext) -> i32 {
    answer(&ctx, WORKLOAD_HOOK_BIND)
}

/// The same, over IPv6.
#[cgroup_sock_addr(bind6)]
pub fn workload_bind6(ctx: SockAddrContext) -> i32 {
    answer(&ctx, WORKLOAD_HOOK_BIND)
}

/// A packet leaving a socket, which is where a workload's DNS query is seen.
#[cgroup_skb(egress)]
pub fn workload_dns_egress(ctx: SkBuffContext) -> i32 {
    capture(&ctx, WORKLOAD_DNS_QUERY);
    SKB_PASS
}

/// A packet arriving at a socket, which is where the answer is seen, after
/// the kernel found the socket and so with the cgroup of the pod that asked.
#[cgroup_skb(ingress)]
pub fn workload_dns_ingress(ctx: SkBuffContext) -> i32 {
    capture(&ctx, WORKLOAD_DNS_RESPONSE);
    SKB_PASS
}

// ── DNS capture ─────────────────────────────────────────────────────

/// Copy one UDP DNS packet of a named workload into the ring.
///
/// TCP DNS is not read, nor an IPv6 packet carrying extension headers, nor a
/// fragment past the first: none of them teaches anything, which leaves the
/// rule refusing the address rather than allowing it on a reading that was
/// never made.
fn capture(ctx: &SkBuffContext, direction: u8) {
    let Some(flag) = WORKLOAD_DNS_CAPTURE.get(0) else {
        return;
    };
    if *flag == 0 {
        return;
    }
    let cgroup = unsafe { bpf_skb_cgroup_id(ctx.skb.skb) };
    if unsafe { WORKLOAD_CGROUP_SELECTORS.get(&cgroup) }.is_none() {
        return;
    }

    let protocol = u16::from_be(ctx.skb.protocol() as u16);
    let mut src = [0u32; 4];
    let mut dst = [0u32; 4];
    let (l4, family) = if protocol == ETH_P_IP {
        let Ok(first) = ctx.load::<u8>(0) else {
            return;
        };
        if first >> 4 != 4 {
            return;
        }
        let Ok(next) = ctx.load::<u8>(9) else {
            return;
        };
        if next != IPPROTO_UDP {
            return;
        }
        let Ok(fragment) = ctx.load::<u16>(6) else {
            return;
        };
        if u16::from_be(fragment) & 0x1fff != 0 {
            return;
        }
        let (Ok(s4), Ok(d4)) = (ctx.load::<u32>(12), ctx.load::<u32>(16)) else {
            return;
        };
        src[0] = u32::from_be(s4);
        dst[0] = u32::from_be(d4);
        (usize::from(first & 0x0f) * 4, WORKLOAD_FAMILY_IPV4)
    } else if protocol == ETH_P_IPV6 {
        let Ok(next) = ctx.load::<u8>(6) else {
            return;
        };
        if next != IPPROTO_UDP {
            return;
        }
        let (Ok(s6), Ok(d6)) = (ctx.load::<[u32; 4]>(8), ctx.load::<[u32; 4]>(24)) else {
            return;
        };
        let mut word = 0usize;
        while word < 4 {
            src[word] = u32::from_be(s6[word]);
            dst[word] = u32::from_be(d6[word]);
            word += 1;
        }
        (IPV6_HEADER_LEN, WORKLOAD_FAMILY_IPV6)
    } else {
        return;
    };

    let (Ok(sport), Ok(dport)) = (ctx.load::<u16>(l4), ctx.load::<u16>(l4 + 2)) else {
        return;
    };
    let src_port = u16::from_be(sport);
    let dst_port = u16::from_be(dport);
    let dns_port = if direction == WORKLOAD_DNS_QUERY {
        dst_port
    } else {
        src_port
    };
    if dns_port != DNS_PORT {
        return;
    }

    let offset = l4 + UDP_HEADER_LEN;
    let total = ctx.len() as usize;
    if offset >= total {
        return;
    }
    let available = total - offset;
    let payload_len = if available > WORKLOAD_DNS_MAX_PAYLOAD {
        WORKLOAD_DNS_MAX_PAYLOAD
    } else {
        available
    };

    let Some(mut entry) = WORKLOAD_DNS_EVENTS.reserve(0) else {
        increment_metric!(WORKLOAD_METRICS, WORKLOAD_METRIC_DNS_LOST);
        return;
    };
    let record = entry.as_mut_ptr();
    let loaded = unsafe {
        (*record).at_ns = bpf_ktime_get_boot_ns();
        (*record).cgroup_id = cgroup;
        (*record).src_addr = src;
        (*record).dst_addr = dst;
        (*record).src_port = src_port;
        (*record).dst_port = dst_port;
        (*record).payload_len = payload_len as u16;
        (*record).family = family;
        (*record).direction = direction;
        let payload = (*record).payload.as_mut_ptr();
        core::ptr::write_bytes(payload, 0, WORKLOAD_DNS_MAX_PAYLOAD);
        // The reserve spills the length, and the verifier loses its lower
        // bound across the spill; the barrier and the clamp put it back.
        let load_len = opaque_usize(payload_len).clamp(1, WORKLOAD_DNS_MAX_PAYLOAD);
        bpf_skb_load_bytes(
            ctx.skb.skb as *const _,
            offset as u32,
            payload as *mut _,
            load_len as u32,
        ) >= 0
    };
    if loaded {
        entry.submit(0);
    } else {
        entry.discard(0);
    }
}

// ── The decision ────────────────────────────────────────────────────

/// The whole verdict for one socket operation: the quarantine first, the
/// policy after.
///
/// Order is the point. A quarantine that the rule array could overrule would
/// be a response an allow rule turns off, and a quarantine that only worked
/// where a policy was loaded would be a response that does nothing on most
/// nodes. So the cut-off check runs before the array is read at all, and only
/// a cgroup that is not cut off ever reaches a rule.
fn answer(ctx: &SockAddrContext, hook: u8) -> i32 {
    if let Some(verdict) = quarantined(hook) {
        return verdict;
    }
    decide(ctx, hook)
}

/// Whether this task's cgroup is cut off, and what that means for this
/// operation.
///
/// `Some(REFUSE)` is a live enforcing quarantine. `None` is every other case -
/// no entry, an entry that has expired, or one in report-only mode - and the
/// policy decides from there. The expiry is compared here rather than swept by
/// userspace, so an entry outliving the agent that wrote it stops refusing at
/// the instant it was given and not at the instant somebody notices.
fn quarantined(hook: u8) -> Option<i32> {
    let cgroup = unsafe { bpf_get_current_cgroup_id() };
    let entry = *unsafe { QUARANTINE_CGROUPS.get(&cgroup) }?;
    let now = unsafe { bpf_ktime_get_boot_ns() };
    if now >= entry.expires_at_ns {
        increment_metric!(QUARANTINE_METRICS, QUARANTINE_METRIC_EXPIRED);
        record_quarantine(cgroup, hook, QUARANTINE_OUTCOME_EXPIRED);
        return None;
    }
    if entry.mode == QUARANTINE_MODE_REPORT {
        increment_metric!(QUARANTINE_METRICS, QUARANTINE_METRIC_OBSERVED);
        record_quarantine(cgroup, hook, QUARANTINE_OUTCOME_OBSERVED);
        return None;
    }
    increment_metric!(QUARANTINE_METRICS, QUARANTINE_METRIC_REFUSED);
    record_quarantine(cgroup, hook, QUARANTINE_OUTCOME_REFUSED);
    Some(REFUSE)
}

/// Write down one quarantine decision, or count the record that did not fit.
fn record_quarantine(cgroup: u64, hook: u8, outcome: u32) {
    let Some(mut entry) = QUARANTINE_EVENTS.reserve(0) else {
        increment_metric!(QUARANTINE_METRICS, QUARANTINE_METRIC_EVENT_LOST);
        return;
    };
    entry.write(QuarantineEvent {
        at_ns: unsafe { bpf_ktime_get_boot_ns() },
        cgroup_id: cgroup,
        tgid: (bpf_get_current_pid_tgid() >> 32) as u32,
        hook: u32::from(hook),
        outcome,
        _pad: 0,
    });
    entry.submit(0);
}

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
    let cgroup = unsafe { bpf_get_current_cgroup_id() };
    let operation = Operation {
        addr: &addr,
        family,
        port,
        protocol,
        hook,
        cgroup,
    };

    for index in 0..WORKLOAD_POLICY_MAX_RULES {
        let Some(rule) = WORKLOAD_RULES.get(index as u32) else {
            break;
        };
        if rule.enabled == 0 {
            break;
        }
        if !applies(rule, index, mask, &operation) {
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

/// One socket operation, as a rule is compared against it.
struct Operation<'a> {
    addr: &'a [u32; 4],
    family: u8,
    port: u16,
    protocol: u8,
    hook: u8,
    cgroup: u64,
}

/// Whether one rule speaks about this operation.
fn applies(rule: &WorkloadRuleEntry, slot: usize, mask: u64, op: &Operation<'_>) -> bool {
    if mask & (1u64 << (rule.selector & 63)) == 0 {
        return false;
    }
    if rule.family != WORKLOAD_FAMILY_ANY && rule.family != op.family {
        return false;
    }
    if rule.protocol != WORKLOAD_PROTOCOL_ANY && rule.protocol != op.protocol {
        return false;
    }
    if (rule.port_start != 0 || rule.port_end != 0)
        && (op.port < rule.port_start || op.port > rule.port_end)
    {
        return false;
    }
    if rule.fqdn != 0 {
        return learned(slot, op);
    }
    inside(&rule.dst_addr, rule.prefix_len, op.addr)
}

/// Whether this cgroup was answered this address for this rule, and the
/// answer has not lapsed.
///
/// A name is never something a workload binds to, so a rule naming one does
/// not apply at the bind hook at all.
fn learned(slot: usize, op: &Operation<'_>) -> bool {
    if op.hook == WORKLOAD_HOOK_BIND {
        return false;
    }
    let key = WorkloadFqdnKey {
        cgroup_id: op.cgroup,
        addr: *op.addr,
        family: op.family,
        slot: slot as u8,
        _pad: [0; 6],
    };
    let Some(expires) = (unsafe { WORKLOAD_FQDN_ALLOWED.get(&key) }).copied() else {
        return false;
    };
    expires > unsafe { bpf_ktime_get_boot_ns() }
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
