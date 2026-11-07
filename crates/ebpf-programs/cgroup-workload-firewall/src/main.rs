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
//! hook then reads that map instead of a prefix.
//!
//! The same hooks enforce Kubernetes `NetworkPolicy` for the pods of this
//! node, when the agent is asked to. Userspace compiles every policy selecting
//! a local pod into longest-prefix entries of `NETPOL_RULES`, one table per
//! distinct rule set, and writes which table each of the pod's cgroups
//! answers to in `NETPOL_CGROUPS`. Egress is checked at `connect()` and
//! `sendmsg()`, ahead of the workload rules, so a connection must be allowed
//! by both. Ingress is checked by the `cgroup_skb` ingress program, which is
//! the only one that ever drops a packet, and only the first packet of a TCP
//! connection or a UDP datagram that does not answer one the pod sent: every
//! later packet belongs to a connection the policy already let in. ICMP and
//! SCTP inbound are not filtered. The DNS capture never drops anything.

#![no_std]
#![no_main]

use aya_ebpf::{
    btf_maps::{Array, HashMap, LpmTrie, LruHashMap, PerCpuArray, RingBuf, lpm_trie::Key},
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_get_current_task,
        bpf_get_current_uid_gid, bpf_ktime_get_boot_ns, bpf_probe_read_kernel, bpf_skb_cgroup_id,
        bpf_skb_load_bytes,
    },
    macros::{btf_map, cgroup_skb, cgroup_sock_addr},
    programs::{SkBuffContext, SockAddrContext},
};
use ebpf_common::netpol::{
    NETPOL_DIR_EGRESS, NETPOL_DIR_INGRESS, NETPOL_FLAG_EGRESS_ISOLATED, NETPOL_FLAG_ENFORCE,
    NETPOL_FLAG_INGRESS_ISOLATED, NETPOL_KEY_LEN, NETPOL_MAX_CGROUPS, NETPOL_MAX_ENTRIES,
    NETPOL_MAX_RANGES, NETPOL_MAX_REPLIES, NETPOL_METRIC_COUNT, NETPOL_METRIC_EGRESS_CHECKED,
    NETPOL_METRIC_EGRESS_REFUSED, NETPOL_METRIC_EGRESS_WOULD_REFUSE, NETPOL_METRIC_INGRESS_CHECKED,
    NETPOL_METRIC_INGRESS_REFUSED, NETPOL_METRIC_INGRESS_WOULD_REFUSE,
    NETPOL_METRIC_REPLY_ADMITTED, NETPOL_REPLY_WINDOW_NS, NetpolCgroup, NetpolEntry,
    NetpolReplyKey, netpol_key_data, netpol_key_word, netpol_prefix_len,
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
    WORKLOAD_HOOK_CONNECT, WORKLOAD_HOOK_INGRESS, WORKLOAD_HOOK_SENDMSG,
    WORKLOAD_LINEAGE_MAX_DEPTH, WORKLOAD_LINEAGE_MAX_EXECUTABLES, WORKLOAD_METRIC_ALLOWED,
    WORKLOAD_METRIC_BIND, WORKLOAD_METRIC_CONNECT, WORKLOAD_METRIC_COUNT, WORKLOAD_METRIC_DNS_LOST,
    WORKLOAD_METRIC_EVENT_LOST, WORKLOAD_METRIC_LINEAGE_TRUNCATED, WORKLOAD_METRIC_NO_RULE,
    WORKLOAD_METRIC_REFUSED, WORKLOAD_METRIC_SENDMSG, WORKLOAD_METRIC_UNRESOLVED,
    WORKLOAD_METRIC_WOULD_REFUSE, WORKLOAD_MODE_ENFORCE, WORKLOAD_PEER_MAX_ADDRS,
    WORKLOAD_PEER_MAX_TARGETS, WORKLOAD_POLICY_MAX_CGROUPS, WORKLOAD_POLICY_MAX_RULES,
    WORKLOAD_POLICY_MAX_TASKS, WORKLOAD_PROTOCOL_ANY, WORKLOAD_RULE_FQDN, WORKLOAD_RULE_PEER,
    WorkloadDenialEvent, WorkloadDnsEvent, WorkloadExeKey, WorkloadFqdnKey, WorkloadLineageBits,
    WorkloadLineageConfig, WorkloadPeerKey, WorkloadRuleEntry,
};
use ebpf_helpers::raw_skb;
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

/// Executable -> the selectors it satisfies when found above a task, as its
/// direct parent or as any ancestor.
///
/// Keyed by inode and device rather than by path, because the walk reads
/// what the parent is running, and a path is only what it was started as.
#[btf_map]
static WORKLOAD_LINEAGE_EXES: HashMap<
    WorkloadExeKey,
    WorkloadLineageBits,
    { WORKLOAD_LINEAGE_MAX_EXECUTABLES as usize },
> = HashMap::new();

/// Which selectors carry a lineage condition, and the kernel offsets the
/// walk reads. Zeroed, it costs a policy naming no lineage one array read.
#[btf_map]
static WORKLOAD_LINEAGE_CONFIG: Array<WorkloadLineageConfig, 1> = Array::new();

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

/// Every policy rule set of this node, as longest-prefix entries.
///
/// The first word of a key names the table, the family and the direction and
/// is always matched whole, so the longest prefix found is always one of this
/// table's own, and an address no entry holds is closed.
#[btf_map]
static NETPOL_RULES: LpmTrie<[u8; NETPOL_KEY_LEN], NetpolEntry, { NETPOL_MAX_ENTRIES as usize }> =
    LpmTrie::new();

/// cgroup id -> which table it answers to and in which directions.
///
/// A plain hash map, for the reason the selectors have one: an eviction would
/// be a pod quietly leaving its policy while it runs.
#[btf_map]
static NETPOL_CGROUPS: HashMap<u64, NetpolCgroup, { NETPOL_MAX_CGROUPS as usize }> = HashMap::new();

/// (cgroup, peer, peer port, family) -> instant the way back closes.
///
/// A UDP datagram an ingress-isolated pod sends opens its answer, as a
/// stateful implementation of the policy does. LRU because an exchange that
/// is evicted only costs a reply being checked like a new datagram.
#[btf_map]
static NETPOL_REPLIES: LruHashMap<NetpolReplyKey, u64, { NETPOL_MAX_REPLIES as usize }> =
    LruHashMap::new();

/// Remote address -> the slots whose remote workload the list names at it.
///
/// Read at connect and sendmsg, where the address is the destination. An
/// address the list does not carry is in no rule, so a rule naming a remote
/// workload never applies to it.
#[btf_map]
static WORKLOAD_PEER_DESTINATIONS: HashMap<
    WorkloadPeerKey,
    u64,
    { WORKLOAD_PEER_MAX_ADDRS as usize },
> = HashMap::new();

/// Remote address -> the slots decided at the destination whose source half
/// the workload the list names at it satisfies.
#[btf_map]
static WORKLOAD_PEER_SOURCES: HashMap<WorkloadPeerKey, u64, { WORKLOAD_PEER_MAX_ADDRS as usize }> =
    HashMap::new();

/// Local cgroup -> the slots decided at the destination whose remote workload
/// is the one in that cgroup.
#[btf_map]
static WORKLOAD_PEER_TARGETS: HashMap<u64, u64, { WORKLOAD_PEER_MAX_TARGETS as usize }> =
    HashMap::new();

/// What the policy did, per CPU.
#[btf_map]
static NETPOL_METRICS: PerCpuArray<u64, { NETPOL_METRIC_COUNT as usize }> = PerCpuArray::new();

// ── Verdicts, in the kernel's own numbering ─────────────────────────

/// What a `cgroup_sock_addr` program returns to let the syscall proceed.
const ALLOW: i32 = 1;
/// What it returns to refuse it. The caller sees `EPERM`.
const REFUSE: i32 = 0;

/// What a `cgroup_skb` program returns to let the packet through.
const SKB_PASS: i32 = 1;
/// What it returns to drop it.
const SKB_DROP: i32 = 0;

/// `ETH_P_IP` and `ETH_P_IPV6`, host order, as `__sk_buff.protocol` carries
/// them once swapped.
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;
/// UDP, as the IP header numbers it.
const IPPROTO_UDP: u8 = 17;
/// TCP.
const IPPROTO_TCP: u8 = 6;
/// The SYN and ACK bits of a TCP header's flag byte.
const TCP_SYN: u8 = 0x02;
const TCP_ACK: u8 = 0x10;
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
    answer::<false>(&ctx, WORKLOAD_HOOK_CONNECT)
}

/// A workload asking for an IPv6 connection.
#[cgroup_sock_addr(connect6)]
pub fn workload_connect6(ctx: SockAddrContext) -> i32 {
    answer::<true>(&ctx, WORKLOAD_HOOK_CONNECT)
}

/// A workload sending a datagram with no connection, the path almost all DNS
/// takes.
#[cgroup_sock_addr(sendmsg4)]
pub fn workload_sendmsg4(ctx: SockAddrContext) -> i32 {
    answer::<false>(&ctx, WORKLOAD_HOOK_SENDMSG)
}

/// The same, over IPv6.
#[cgroup_sock_addr(sendmsg6)]
pub fn workload_sendmsg6(ctx: SockAddrContext) -> i32 {
    answer::<true>(&ctx, WORKLOAD_HOOK_SENDMSG)
}

/// A workload taking an IPv4 local address, before the kernel assigns it.
///
/// The address a rule matches here is the local one the workload is asking
/// for, not a peer's: a rule refusing a listener is a rule about where that
/// listener may sit.
#[cgroup_sock_addr(bind4)]
pub fn workload_bind4(ctx: SockAddrContext) -> i32 {
    answer::<false>(&ctx, WORKLOAD_HOOK_BIND)
}

/// The same, over IPv6.
#[cgroup_sock_addr(bind6)]
pub fn workload_bind6(ctx: SockAddrContext) -> i32 {
    answer::<true>(&ctx, WORKLOAD_HOOK_BIND)
}

/// A packet leaving a socket, which is where a workload's DNS query is seen
/// and where a UDP exchange of an ingress-isolated pod opens its way back.
#[cgroup_skb(egress)]
pub fn workload_skb_egress(ctx: SkBuffContext) -> i32 {
    capture(&ctx, WORKLOAD_DNS_QUERY);
    remember_reply(&ctx);
    SKB_PASS
}

/// A packet arriving at a socket, which is where a DNS answer is seen and
/// where a pod's ingress policy is decided, after the kernel found the socket
/// and so with the cgroup of the pod it is for.
#[cgroup_skb(ingress)]
pub fn workload_skb_ingress(ctx: SkBuffContext) -> i32 {
    capture(&ctx, WORKLOAD_DNS_RESPONSE);
    let verdict = admit(&ctx);
    if verdict == SKB_DROP {
        return verdict;
    }
    peer_ingress(&ctx)
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
    let cgroup = unsafe { bpf_skb_cgroup_id(raw_skb(ctx)) };
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
            raw_skb(ctx) as *const _,
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
///
/// `V6` is the family of the hook, fixed by the entry point rather than read
/// from the context. The verifier checks every context field a program reads
/// against the hook it is attached to, whether or not the read is reachable,
/// and refuses `user_ip4` in an IPv6 hook as surely as `user_ip6` in an IPv4
/// one. A family read at run time leaves both reads in all six programs, so
/// none of them loads; a family fixed at compile time leaves each program
/// only the one its hook allows.
fn answer<const V6: bool>(ctx: &SockAddrContext, hook: u8) -> i32 {
    if let Some(verdict) = quarantined(hook) {
        return verdict;
    }
    if let Some(verdict) = netpol_egress::<V6>(ctx, hook) {
        return verdict;
    }
    decide::<V6>(ctx, hook)
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
fn decide<const V6: bool>(ctx: &SockAddrContext, hook: u8) -> i32 {
    let Some(first) = WORKLOAD_RULES.get(0) else {
        return ALLOW;
    };
    if first.enabled == 0 {
        return ALLOW;
    }
    increment_metric!(WORKLOAD_METRICS, hook_metric(hook));

    let resolved = selectors();
    let mask = with_lineage(resolved);
    if resolved == 0 && mask == 0 {
        // A task userspace has not placed in any selector yet. Counting it is
        // the honest version of the race: the process table resolves an exec
        // a moment after the kernel saw it, and a connection inside that
        // window is decided by no rule.
        increment_metric!(WORKLOAD_METRICS, WORKLOAD_METRIC_UNRESOLVED);
        return ALLOW;
    }

    let port = u16::from_be(unsafe { (*ctx.sock_addr).user_port } as u16);
    let protocol = unsafe { (*ctx.sock_addr).protocol } as u8;
    let (addr, family) = address_of::<V6>(ctx);
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
        let task = Task {
            tgid: (bpf_get_current_pid_tgid() >> 32) as u32,
            uid: bpf_get_current_uid_gid() as u32,
        };
        report(index, &operation, enforced, &task);
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
fn report(index: usize, op: &Operation<'_>, enforced: bool, task: &Task) {
    let Some(mut entry) = WORKLOAD_EVENTS.reserve(0) else {
        increment_metric!(WORKLOAD_METRICS, WORKLOAD_METRIC_EVENT_LOST);
        return;
    };
    entry.write(WorkloadDenialEvent {
        at_ns: unsafe { bpf_ktime_get_boot_ns() },
        cgroup_id: op.cgroup,
        dst_addr: *op.addr,
        tgid: task.tgid,
        uid: task.uid,
        dst_port: op.port,
        rule: index as u16,
        family: op.family,
        protocol: op.protocol,
        hook: op.hook,
        enforced: u8::from(enforced),
    });
    entry.submit(0);
}

/// The task a refusal is about. At the socket hooks it is the calling task;
/// on a packet arriving there is no calling task, only the cgroup of the
/// socket it is for, and both fields stay zero.
struct Task {
    tgid: u32,
    uid: u32,
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

/// The selectors that still hold once their lineage condition is checked.
///
/// A selector naming a parent or an ancestor is in the cgroup or task table
/// when the rest of it matched, and in `unconditional` when there is no rest.
/// Either way its bit stands only if the walk finds the executable above the
/// calling task. Without the offsets the walk cannot run, and every lineage
/// bit is withheld: a rule about tasks under `nginx` must not apply to every
/// task because the kernel could not be asked where it was started.
#[inline(always)]
fn with_lineage(resolved: u64) -> u64 {
    let Some(config) = WORKLOAD_LINEAGE_CONFIG.get(0) else {
        return resolved;
    };
    if config.lineage == 0 {
        return resolved;
    }
    if config.valid == 0 {
        return resolved & !config.lineage;
    }
    let candidates = resolved | config.unconditional;
    let gated = candidates & config.lineage;
    if gated == 0 {
        return candidates;
    }
    (candidates & !config.lineage) | (gated & ancestry(gated, config))
}

/// The lineage selectors satisfied by the processes above the calling task,
/// stopping as soon as every gated one is.
///
/// `real_parent` is followed rather than `parent`: a traced task's `parent`
/// is its tracer, and a debugger attaching is not the task being started by
/// it. The walk ends at the idle task, whose parent is itself, at a null
/// pointer, or at the depth bound, which is counted when a parent remains.
#[inline(always)]
fn ancestry(gated: u64, config: &WorkloadLineageConfig) -> u64 {
    let mut task = unsafe { bpf_get_current_task() };
    let mut satisfied = 0u64;
    for depth in 0..WORKLOAD_LINEAGE_MAX_DEPTH {
        let (parent, read_parent) = read::<u64>(task, config.task_real_parent);
        if !read_parent || parent == 0 || parent == task {
            return satisfied;
        }
        if let Some(bits) = executable_bits(parent, config) {
            satisfied |= bits.ancestor;
            if depth == 0 {
                satisfied |= bits.parent;
            }
            if satisfied & gated == gated {
                return satisfied;
            }
        }
        task = parent;
    }
    let (parent, read_parent) = read::<u64>(task, config.task_real_parent);
    if read_parent && parent != 0 && parent != task {
        increment_metric!(WORKLOAD_METRICS, WORKLOAD_METRIC_LINEAGE_TRUNCATED);
    }
    satisfied
}

/// What a lineage rule says about the executable `task` runs, if it names it.
/// A kernel thread has no address space and runs nothing a rule can name.
#[inline(always)]
fn executable_bits(task: u64, config: &WorkloadLineageConfig) -> Option<WorkloadLineageBits> {
    let (mm, read_mm) = read::<u64>(task, config.task_mm);
    if !read_mm || mm == 0 {
        return None;
    }
    let (exe_file, read_exe) = read::<u64>(mm, config.mm_exe_file);
    if !read_exe || exe_file == 0 {
        return None;
    }
    let (inode, read_inode) = read::<u64>(exe_file, config.file_inode);
    if !read_inode || inode == 0 {
        return None;
    }
    let (sb, read_sb) = read::<u64>(inode, config.inode_sb);
    let (ino, read_ino) = read::<u64>(inode, config.inode_ino);
    let (dev, read_dev) = read::<u32>(sb, config.sb_dev);
    if !(read_sb && read_ino && read_dev) {
        return None;
    }
    let key = WorkloadExeKey { ino, dev, _pad: 0 };
    unsafe { WORKLOAD_LINEAGE_EXES.get(&key) }.copied()
}

/// Read a `T` at `offset` into the kernel object at `base`, with whether the
/// read succeeded.
///
/// A failed read answers zero rather than nothing: an `Option` carried across
/// the next helper call leaves its payload register undefined on the `None`
/// path, and the verifier refuses a program that stores a register it never
/// saw written.
#[inline(always)]
fn read<T: Default>(base: u64, offset: u32) -> (T, bool) {
    if base == 0 {
        return (T::default(), false);
    }
    let at = (base + u64::from(offset)) as *const T;
    match unsafe { bpf_probe_read_kernel(at) } {
        Ok(value) => (value, true),
        Err(_) => (T::default(), false),
    }
}

/// The address this hook is about, in the host-order words the rules store,
/// with the family the rule will be compared against.
///
/// A v6 socket reaching a v4 address carries it mapped, `::ffff:a.b.c.d`, and
/// a rule written about that address is a rule about IPv4. Unmapping it here
/// is what stops the same destination being matchable under one family and
/// not the other depending on how the caller opened its socket.
///
/// The family is the hook's: an IPv4 hook only ever sees an `AF_INET` socket
/// and an IPv6 hook an `AF_INET6` one, so the context field read is the one
/// the hook allows and no other.
fn address_of<const V6: bool>(ctx: &SockAddrContext) -> ([u32; 4], u8) {
    if !V6 {
        let word = u32::from_be(unsafe { (*ctx.sock_addr).user_ip4 });
        return ([word, 0, 0, 0], WORKLOAD_FAMILY_IPV4);
    }
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
    (words, WORKLOAD_FAMILY_IPV6)
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
    if rule.fqdn == WORKLOAD_RULE_FQDN {
        return learned(slot, op);
    }
    if rule.fqdn == WORKLOAD_RULE_PEER {
        return remote(slot, op);
    }
    inside(&rule.dst_addr, rule.prefix_len, op.addr)
}

/// Whether the list of remote identities names, at this address, the remote
/// workload this rule is about.
///
/// A remote workload is somewhere a workload goes, never somewhere it binds,
/// so the rule does not apply at the bind hook.
fn remote(slot: usize, op: &Operation<'_>) -> bool {
    if op.hook == WORKLOAD_HOOK_BIND {
        return false;
    }
    let key = WorkloadPeerKey {
        addr: *op.addr,
        family: op.family,
        _pad: [0; 3],
    };
    let Some(mask) = (unsafe { WORKLOAD_PEER_DESTINATIONS.get(&key) }).copied() else {
        return false;
    };
    mask & (1u64 << (slot & 63)) != 0
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

// ── NetworkPolicy ───────────────────────────────────────────────────

/// Whether the policy table `slot` opens `port` of `protocol` towards or
/// from `addr` in `direction`.
fn netpol_open(
    slot: u16,
    v6: bool,
    direction: u32,
    addr: [u8; 16],
    protocol: u8,
    port: u16,
) -> bool {
    let key = Key::new(
        netpol_prefix_len(128),
        netpol_key_data(netpol_key_word(slot, v6, direction), addr),
    );
    let Some(entry) = NETPOL_RULES.get(&key) else {
        return false;
    };
    if entry.all != 0 {
        return true;
    }
    let count = usize::from(entry.count);
    let mut index = 0usize;
    while index < NETPOL_MAX_RANGES {
        if index >= count {
            break;
        }
        let range = &entry.ranges[index];
        if range.protocol == protocol && range.lo <= port && port <= range.hi {
            return true;
        }
        index += 1;
    }
    false
}

/// The table and flags of this cgroup, when a policy isolates it in the
/// direction named by `flag`.
fn netpol_target(cgroup: u64, flag: u8) -> Option<NetpolCgroup> {
    let entry = *unsafe { NETPOL_CGROUPS.get(&cgroup) }?;
    if entry.flags & flag == 0 {
        return None;
    }
    Some(entry)
}

/// The policy's answer to a pod's outbound connection or datagram.
///
/// `Some(REFUSE)` only when enforcing; `None` lets the workload rules decide
/// next, so a connection must be allowed by both.
fn netpol_egress<const V6: bool>(ctx: &SockAddrContext, hook: u8) -> Option<i32> {
    if hook == WORKLOAD_HOOK_BIND {
        return None;
    }
    let target = netpol_target(
        unsafe { bpf_get_current_cgroup_id() },
        NETPOL_FLAG_EGRESS_ISOLATED,
    )?;
    let (words, family) = address_of::<V6>(ctx);
    increment_metric!(NETPOL_METRICS, NETPOL_METRIC_EGRESS_CHECKED);
    let v6 = family == WORKLOAD_FAMILY_IPV6;
    let port = u16::from_be(unsafe { (*ctx.sock_addr).user_port } as u16);
    let protocol = unsafe { (*ctx.sock_addr).protocol } as u8;
    if netpol_open(
        target.slot,
        v6,
        NETPOL_DIR_EGRESS,
        address_bytes(&words, v6),
        protocol,
        port,
    ) {
        return None;
    }
    if target.flags & NETPOL_FLAG_ENFORCE != 0 {
        increment_metric!(NETPOL_METRICS, NETPOL_METRIC_EGRESS_REFUSED);
        return Some(REFUSE);
    }
    increment_metric!(NETPOL_METRICS, NETPOL_METRIC_EGRESS_WOULD_REFUSE);
    None
}

/// Host-order words back to the network-order bytes the table is keyed on,
/// an IPv4 address in the first four.
fn address_bytes(words: &[u32; 4], v6: bool) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    let used = if v6 { 4 } else { 1 };
    let mut word = 0usize;
    while word < used {
        let b = words[word].to_be_bytes();
        bytes[word * 4] = b[0];
        bytes[word * 4 + 1] = b[1];
        bytes[word * 4 + 2] = b[2];
        bytes[word * 4 + 3] = b[3];
        word += 1;
    }
    bytes
}

/// The parts of a packet's headers the policy reads.
struct Packet {
    v6: bool,
    protocol: u8,
    src: [u8; 16],
    dst: [u8; 16],
    l4: usize,
}

/// Read the IP header, or `None` for a packet the policy does not look at: a
/// family other than IP, a transport other than TCP or UDP, an IPv6 header
/// followed by an extension header, or an IPv4 fragment past the first.
fn packet(ctx: &SkBuffContext) -> Option<Packet> {
    let protocol = u16::from_be(ctx.skb.protocol() as u16);
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    if protocol == ETH_P_IP {
        let first = ctx.load::<u8>(0).ok()?;
        if first >> 4 != 4 {
            return None;
        }
        let next = ctx.load::<u8>(9).ok()?;
        let fragment = ctx.load::<u16>(6).ok()?;
        if u16::from_be(fragment) & 0x1fff != 0 {
            return None;
        }
        let s4 = ctx.load::<[u8; 4]>(12).ok()?;
        let d4 = ctx.load::<[u8; 4]>(16).ok()?;
        src[..4].copy_from_slice(&s4);
        dst[..4].copy_from_slice(&d4);
        return transport(next).then_some(Packet {
            v6: false,
            protocol: next,
            src,
            dst,
            l4: usize::from(first & 0x0f) * 4,
        });
    }
    if protocol == ETH_P_IPV6 {
        let next = ctx.load::<u8>(6).ok()?;
        src = ctx.load::<[u8; 16]>(8).ok()?;
        dst = ctx.load::<[u8; 16]>(24).ok()?;
        return transport(next).then_some(Packet {
            v6: true,
            protocol: next,
            src,
            dst,
            l4: IPV6_HEADER_LEN,
        });
    }
    None
}

fn transport(protocol: u8) -> bool {
    protocol == IPPROTO_TCP || protocol == IPPROTO_UDP
}

/// Open the way back for a UDP datagram an ingress-isolated pod is sending.
///
/// The entry is only rewritten once half its window has gone, so a pod
/// streaming datagrams costs a lookup per packet and not an update.
fn remember_reply(ctx: &SkBuffContext) {
    let cgroup = unsafe { bpf_skb_cgroup_id(raw_skb(ctx)) };
    if netpol_target(cgroup, NETPOL_FLAG_INGRESS_ISOLATED).is_none() {
        return;
    }
    let Some(packet) = packet(ctx) else {
        return;
    };
    if packet.protocol != IPPROTO_UDP {
        return;
    }
    let Ok(dport) = ctx.load::<u16>(packet.l4 + 2) else {
        return;
    };
    let key = NetpolReplyKey {
        cgroup_id: cgroup,
        addr: packet.dst,
        port: u16::from_be(dport),
        family: u8::from(packet.v6),
        _pad: [0; 5],
    };
    let now = unsafe { bpf_ktime_get_boot_ns() };
    if let Some(expires) = unsafe { NETPOL_REPLIES.get(&key) }
        && *expires > now + NETPOL_REPLY_WINDOW_NS / 2
    {
        return;
    }
    let _ = NETPOL_REPLIES.insert(&key, &(now + NETPOL_REPLY_WINDOW_NS), 0);
}

/// The policy's answer to a packet arriving at an ingress-isolated pod.
fn admit(ctx: &SkBuffContext) -> i32 {
    let cgroup = unsafe { bpf_skb_cgroup_id(raw_skb(ctx)) };
    let Some(target) = netpol_target(cgroup, NETPOL_FLAG_INGRESS_ISOLATED) else {
        return SKB_PASS;
    };
    let Some(packet) = packet(ctx) else {
        return SKB_PASS;
    };
    let (Ok(sport), Ok(dport)) = (ctx.load::<u16>(packet.l4), ctx.load::<u16>(packet.l4 + 2))
    else {
        return SKB_PASS;
    };
    let peer_port = u16::from_be(sport);
    let local_port = u16::from_be(dport);
    if packet.protocol == IPPROTO_TCP {
        let Ok(flags) = ctx.load::<u8>(packet.l4 + 13) else {
            return SKB_PASS;
        };
        if flags & TCP_SYN == 0 || flags & TCP_ACK != 0 {
            return SKB_PASS;
        }
    } else {
        let key = NetpolReplyKey {
            cgroup_id: cgroup,
            addr: packet.src,
            port: peer_port,
            family: u8::from(packet.v6),
            _pad: [0; 5],
        };
        if let Some(expires) = unsafe { NETPOL_REPLIES.get(&key) }
            && *expires > unsafe { bpf_ktime_get_boot_ns() }
        {
            increment_metric!(NETPOL_METRICS, NETPOL_METRIC_REPLY_ADMITTED);
            return SKB_PASS;
        }
    }
    increment_metric!(NETPOL_METRICS, NETPOL_METRIC_INGRESS_CHECKED);
    if netpol_open(
        target.slot,
        packet.v6,
        NETPOL_DIR_INGRESS,
        packet.src,
        packet.protocol,
        local_port,
    ) {
        return SKB_PASS;
    }
    if target.flags & NETPOL_FLAG_ENFORCE != 0 {
        increment_metric!(NETPOL_METRICS, NETPOL_METRIC_INGRESS_REFUSED);
        return SKB_DROP;
    }
    increment_metric!(NETPOL_METRICS, NETPOL_METRIC_INGRESS_WOULD_REFUSE);
    SKB_PASS
}

/// The destination's half of the rules naming a remote workload: a
/// connection opening at a local workload, from an address the list names.
///
/// Only the opening segment of a TCP connection is decided. A datagram opens
/// nothing the destination could keep a decision for, and every later segment
/// belongs to a connection that was already let in. The slots offered here
/// are the ones userspace computed as decidable at this end, so walking them
/// in order gives the same first match the source would have found.
fn peer_ingress(ctx: &SkBuffContext) -> i32 {
    let cgroup = unsafe { bpf_skb_cgroup_id(raw_skb(ctx)) };
    let Some(targets) = (unsafe { WORKLOAD_PEER_TARGETS.get(&cgroup) }).copied() else {
        return SKB_PASS;
    };
    let Some(packet) = packet(ctx) else {
        return SKB_PASS;
    };
    if packet.protocol != IPPROTO_TCP {
        return SKB_PASS;
    }
    let Ok(flags) = ctx.load::<u8>(packet.l4 + 13) else {
        return SKB_PASS;
    };
    if flags & TCP_SYN == 0 || flags & TCP_ACK != 0 {
        return SKB_PASS;
    }
    let Ok(dport) = ctx.load::<u16>(packet.l4 + 2) else {
        return SKB_PASS;
    };
    let local_port = u16::from_be(dport);
    let (addr, family) = peer_words(&packet);
    let key = WorkloadPeerKey {
        addr,
        family,
        _pad: [0; 3],
    };
    let Some(sources) = (unsafe { WORKLOAD_PEER_SOURCES.get(&key) }).copied() else {
        return SKB_PASS;
    };
    let candidates = sources & targets;
    if candidates == 0 {
        return SKB_PASS;
    }

    for index in 0..WORKLOAD_POLICY_MAX_RULES {
        let Some(rule) = WORKLOAD_RULES.get(index as u32) else {
            break;
        };
        if rule.enabled == 0 {
            break;
        }
        if candidates & (1u64 << (index & 63)) == 0 {
            continue;
        }
        if rule.protocol != WORKLOAD_PROTOCOL_ANY && rule.protocol != IPPROTO_TCP {
            continue;
        }
        if (rule.port_start != 0 || rule.port_end != 0)
            && (local_port < rule.port_start || local_port > rule.port_end)
        {
            continue;
        }
        if rule.action != WORKLOAD_ACTION_DENY {
            increment_metric!(WORKLOAD_METRICS, WORKLOAD_METRIC_ALLOWED);
            return SKB_PASS;
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
        let operation = Operation {
            addr: &addr,
            family,
            port: local_port,
            protocol: IPPROTO_TCP,
            hook: WORKLOAD_HOOK_INGRESS,
            cgroup,
        };
        report(index, &operation, enforced, &Task { tgid: 0, uid: 0 });
        if enforced {
            return SKB_DROP;
        }
        return SKB_PASS;
    }
    SKB_PASS
}

/// A packet's source address in the form the socket hooks key on: host-order
/// words, an IPv4 address in the first word, and an IPv4-mapped IPv6 address
/// folded to IPv4.
fn peer_words(packet: &Packet) -> ([u32; 4], u8) {
    let b = &packet.src;
    let word = |i: usize| u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
    if !packet.v6 {
        return ([word(0), 0, 0, 0], WORKLOAD_FAMILY_IPV4);
    }
    let words = [word(0), word(4), word(8), word(12)];
    if words[0] == 0 && words[1] == 0 && words[2] == 0x0000_ffff {
        return ([words[3], 0, 0, 0], WORKLOAD_FAMILY_IPV4);
    }
    (words, WORKLOAD_FAMILY_IPV6)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
