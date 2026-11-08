//! A firewall rule written in workloads rather than in addresses.
//!
//! The packet path knows a five-tuple and nothing else: by the time a frame
//! reaches an interface there is no task to ask about. The socket hooks sit
//! one layer up, in the syscall of the task that is opening the socket, which
//! is the only place a rule naming a binary, a unit, a cgroup or a container
//! can be decided. These are the numbers both sides of that decision agree
//! on: how many rules the kernel array holds and how many distinct workloads
//! the bitmap can name.
//!
//! The policy is keyed on the cgroup and on the task, never on the interface.
//! The interface bitmap caps at thirty-one groups, and a node dense enough to
//! want workload rules has more workloads than that.

/// How many workload rules the kernel array holds.
///
/// Every rule is examined on every `connect()` and `bind()` of a task the
/// policy names, so the array is walked in a bounded loop the verifier can
/// see the end of. Sixty-four is the point where the walk is still a few
/// hundred nanoseconds and the policy is still something a person wrote
/// rather than something a generator emitted; a policy past it is refused
/// with the count in the message rather than silently truncated, because a
/// rule that was dropped on load is a hole nobody can see.
pub const WORKLOAD_POLICY_MAX_RULES: usize = 64;

/// How many distinct workload selectors one policy may name.
///
/// Each selector owns one bit of the mask a cgroup or a task carries, so the
/// mask is a `u64` and the ceiling is its width. Two rules naming the same
/// workload share a selector and therefore a bit, which is why a policy of
/// sixty-four rules over a handful of workloads is ordinary.
pub const WORKLOAD_POLICY_MAX_SELECTORS: usize = 64;

/// The bitmap is wide enough for a full policy, which is what lets the
/// userspace side bound selectors by bounding rules.
///
/// Every rule names one selector, so a policy at the rule ceiling names at
/// most that many workloads. Raising the rule ceiling past the bitmap's width
/// would make a selector silently share a bit with another one, which is a
/// rule firing for a workload it was never written about, so it fails the
/// build here instead.
const _: () = assert!(
    WORKLOAD_POLICY_MAX_RULES <= WORKLOAD_POLICY_MAX_SELECTORS,
    "a policy at the rule ceiling can name more workloads than the mask has bits"
);

/// Capacity of `WORKLOAD_CGROUP_SELECTORS`, the cgroup half of the lookup.
///
/// One entry per cgroup the policy names a workload in, which on a container
/// host is one per running container and on a systemd host one per service.
/// Four thousand covers both with room to spare, and it is a plain hash map
/// rather than an LRU: an eviction here would be a rule silently ceasing to
/// apply to a container that is still running.
pub const WORKLOAD_POLICY_MAX_CGROUPS: u32 = 4_096;

/// Capacity of `WORKLOAD_TASK_SELECTORS`, the per-task half.
///
/// Keyed by thread group id, written for a task whose selector names an
/// executable, because a path belongs to a task and not to its cgroup. LRU,
/// since a pid is reused and a node that forks hard would otherwise fill the
/// table with the dead: the cost of an eviction is a live task whose rules
/// stop applying until userspace writes it again, which is counted rather
/// than hidden.
pub const WORKLOAD_POLICY_MAX_TASKS: u32 = 16_384;

/// `family` on a rule: this rule does not care which family the socket is.
pub const WORKLOAD_FAMILY_ANY: u8 = 0;
/// `family` on a rule: IPv4 only.
pub const WORKLOAD_FAMILY_IPV4: u8 = 4;
/// `family` on a rule: IPv6 only.
pub const WORKLOAD_FAMILY_IPV6: u8 = 6;

/// `protocol` on a rule: any protocol.
pub const WORKLOAD_PROTOCOL_ANY: u8 = 0;

/// `action` on a rule: the workload may do this.
pub const WORKLOAD_ACTION_ALLOW: u8 = 0;
/// `action` on a rule: the workload may not.
pub const WORKLOAD_ACTION_DENY: u8 = 1;

/// `mode` on a rule: a match is counted and the syscall still goes through.
pub const WORKLOAD_MODE_OBSERVE: u8 = 0;
/// `mode` on a rule: a refusal is carried out.
pub const WORKLOAD_MODE_ENFORCE: u8 = 1;

/// Metric index: `connect()` calls the policy looked at.
pub const WORKLOAD_METRIC_CONNECT: u32 = 0;
/// Metric index: `sendmsg()` calls on an unconnected socket.
pub const WORKLOAD_METRIC_SENDMSG: u32 = 1;
/// Metric index: `bind()` calls, where the address matched is the local one
/// the workload is taking rather than a peer's.
pub const WORKLOAD_METRIC_BIND: u32 = 2;
/// Metric index: operations a rule allowed by name.
pub const WORKLOAD_METRIC_ALLOWED: u32 = 3;
/// Metric index: operations the kernel refused.
pub const WORKLOAD_METRIC_REFUSED: u32 = 4;
/// Metric index: operations an observing rule would have refused and let
/// through. This is what an operator watches before turning a policy on.
pub const WORKLOAD_METRIC_WOULD_REFUSE: u32 = 5;
/// Metric index: operations by a task the agent has not placed in any
/// selector while a policy is loaded.
///
/// It is the honest cost of resolving identity in userspace: a task that
/// execs and connects before the process table has seen the exec carries no
/// bit yet, so no rule of a deny policy applies to it. The count is what says
/// how wide that window actually is on this node.
pub const WORKLOAD_METRIC_UNRESOLVED: u32 = 6;
/// Metric index: operations by a named workload that no rule spoke about.
pub const WORKLOAD_METRIC_NO_RULE: u32 = 7;
/// Metric index: denial records the ring buffer had no room for.
///
/// The decision is taken whatever happens to the record, so a lost one costs
/// an alert and never a refusal. It is counted here rather than inferred from
/// a gap, because the per-rule counters are exact and a reader comparing them
/// against the alerts needs the difference to have a name.
pub const WORKLOAD_METRIC_EVENT_LOST: u32 = 8;
/// Metric index: DNS packets of a workload the capture ring had no room for.
///
/// A lost response is an address that was not learned, so the connection
/// that follows is refused as if the name had never resolved. Counting it is
/// what tells that apart from a resolver answering nothing.
pub const WORKLOAD_METRIC_DNS_LOST: u32 = 9;
/// Metric index: lineage walks that reached the depth bound with a parent
/// still above them.
///
/// An ancestor past the bound is not seen, so a rule naming it does not name
/// the task. The count says whether that ever happens on this node rather
/// than leaving it to be inferred from a rule that did not fire.
pub const WORKLOAD_METRIC_LINEAGE_TRUNCATED: u32 = 10;
/// How many counters the metrics array holds.
pub const WORKLOAD_METRIC_COUNT: u32 = 11;

/// `hook` on a denial record: the workload was connecting.
pub const WORKLOAD_HOOK_CONNECT: u8 = 0;
/// `hook` on a denial record: the workload was sending a datagram with no
/// connection.
pub const WORKLOAD_HOOK_SENDMSG: u8 = 1;
/// `hook` on a denial record: the workload was taking a local address.
pub const WORKLOAD_HOOK_BIND: u8 = 2;
/// `hook` on a denial record: a peer was opening a connection to the
/// workload, refused where it arrived. `dst_addr` is then the peer's address
/// and `dst_port` the workload's own port, and there is no calling task.
pub const WORKLOAD_HOOK_INGRESS: u8 = 3;

/// Size of `WORKLOAD_EVENTS`, the ring buffer denial records travel in.
///
/// A record is forty-eight bytes and only a refusal writes one, so sixty-four
/// kilobytes is well over a thousand denials in flight: the buffer is sized
/// for a policy turned on against a workload that then retries in a loop,
/// which is the one shape that produces denials faster than userspace reads
/// them. Past that the records are dropped and counted, never queued in the
/// kernel at the cost of the syscall.
pub const WORKLOAD_EVENTS_RINGBUF_BYTES: u32 = 16 * 4_096;

/// Capacity of `WORKLOAD_FQDN_ALLOWED`, the addresses learned from DNS.
///
/// One entry per pod, address and rule, so a busy namespace resolving a
/// content network's names fills it faster than the rule count suggests.
/// A plain hash map rather than an LRU: an eviction would be a connection
/// refused for a name that resolved a second ago. Userspace sweeps what has
/// lapsed, and a grant that finds the map full is refused and counted.
pub const WORKLOAD_FQDN_MAX_ALLOWED: u32 = 16_384;

/// Size of `WORKLOAD_DNS_EVENTS`, the ring DNS packets of a named workload
/// travel up in.
///
/// Only workloads in a cgroup the policy names are captured, and only while a
/// rule names a destination by name, so this carries a few hundred queries and
/// answers in flight rather than a node's whole resolver traffic.
pub const WORKLOAD_DNS_RINGBUF_BYTES: u32 = 64 * 4_096;

/// Bytes of a DNS message the capture copies, past which the answer is cut.
///
/// Five hundred and twelve is the classic UDP DNS ceiling; a longer answer is
/// truncated, its addresses past the cut are not learned, and a connection to
/// one of them is refused rather than allowed on a partial reading.
pub const WORKLOAD_DNS_MAX_PAYLOAD: usize = 512;

/// `direction` on a DNS record: a query leaving the workload.
pub const WORKLOAD_DNS_QUERY: u8 = 0;
/// `direction` on a DNS record: an answer arriving at the workload.
pub const WORKLOAD_DNS_RESPONSE: u8 = 1;

/// `fqdn` on a rule: the destination is the set of addresses learned for
/// this rule from DNS, per cgroup, rather than `dst_addr`.
pub const WORKLOAD_RULE_FQDN: u8 = 1;

/// `fqdn` on a rule: the destination is a workload on another node, named by
/// the identity the console handed this node, so the address is matched in
/// `WORKLOAD_PEER_DESTINATIONS` rather than against `dst_addr`.
pub const WORKLOAD_RULE_PEER: u8 = 2;

/// `fqdn` on a rule: the destination is `dst_addr`, and the rule speaks only
/// about what the workload sends there. It is not consulted at the bind hook,
/// so a rule about where a workload may send on a port never stops a server
/// on the node from taking that port as its own local address.
pub const WORKLOAD_RULE_SENT: u8 = 3;

/// Capacity of `WORKLOAD_PEER_DESTINATIONS` and `WORKLOAD_PEER_SOURCES`, one
/// entry per peer address a rule names.
///
/// The size of the whole list a node can hold, so a list the node took never
/// needs more room than this; an address that finds the map full is left
/// unnamed and counted, and a rule naming it then matches nothing there.
pub const WORKLOAD_PEER_MAX_ADDRS: u32 = 65_536;

/// Capacity of `WORKLOAD_PEER_TARGETS`, the cgroups of this node a peer rule
/// names as the workload being reached.
pub const WORKLOAD_PEER_MAX_TARGETS: u32 = WORKLOAD_POLICY_MAX_CGROUPS;

/// How many generations the hook walks up from the calling task looking for
/// a parent or an ancestor a rule names.
///
/// The walk runs inside the `connect()` of every task a lineage rule could
/// name, so it is bounded: sixteen generations is deeper than any service
/// tree a rule is written about, and a walk that reaches the bound is
/// counted under `WORKLOAD_METRIC_LINEAGE_TRUNCATED`.
pub const WORKLOAD_LINEAGE_MAX_DEPTH: u32 = 16;

/// Capacity of `WORKLOAD_LINEAGE_EXES`, the executables lineage rules name.
///
/// One selector names one path, so a full policy names at most sixty-four
/// files; the rest is room for the inode an upgraded binary leaves behind,
/// which a running parent still carries until it restarts.
pub const WORKLOAD_LINEAGE_MAX_EXECUTABLES: u32 = 256;

/// One executable, as the lineage walk names it: the inode of
/// `mm->exe_file` and the kernel's encoding of its superblock's device.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct WorkloadExeKey {
    pub ino: u64,
    pub dev: u32,
    pub _pad: u32,
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for WorkloadExeKey {}

/// Which selectors an executable satisfies when it is found above a task.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WorkloadLineageBits {
    /// Selectors whose `parent` is this executable: they hold when it is
    /// the task's direct parent.
    pub parent: u64,
    /// Selectors whose `ancestor` is this executable: they hold when it is
    /// anywhere above the task.
    pub ancestor: u64,
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for WorkloadLineageBits {}

/// The single slot of `WORKLOAD_LINEAGE_CONFIG`: which selectors carry a
/// lineage condition and the offsets the walk reads, from the running
/// kernel's BTF.
///
/// A selector bit in `lineage` holds only when the walk found its parent or
/// ancestor, whatever the cgroup and task tables say: those carry the rest
/// of the selector, resolved in userspace. While `valid` is zero the walk
/// does not run and every lineage bit is withheld, so a rule naming a parent
/// matches nothing rather than matching without its parent.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WorkloadLineageConfig {
    /// Selectors carrying a parent or an ancestor condition.
    pub lineage: u64,
    /// Selectors naming a lineage and nothing else, which every task on the
    /// node satisfies but for the walk.
    pub unconditional: u64,
    /// `task_struct.real_parent`
    pub task_real_parent: u32,
    /// `task_struct.mm`
    pub task_mm: u32,
    /// `mm_struct.exe_file`
    pub mm_exe_file: u32,
    /// `file.f_inode`
    pub file_inode: u32,
    /// `inode.i_ino`
    pub inode_ino: u32,
    /// `inode.i_sb`
    pub inode_sb: u32,
    /// `super_block.s_dev`
    pub sb_dev: u32,
    /// Non-zero once the offsets are complete.
    pub valid: u32,
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for WorkloadLineageConfig {}

/// One workload rule, in the form the kernel walks.
///
/// The source half of a firewall rule is absent on purpose: at `connect()`
/// the kernel has chosen neither a source address nor a source port, so a
/// matcher on either would be matching on nothing. Which rules may name a
/// workload at all is decided where the configuration is read, so what
/// arrives here is already a rule a socket hook can decide.
///
/// Addresses are host-order words, the encoding the rest of the firewall
/// stores them in: `dst_addr[0]` alone for IPv4, all four most-significant
/// word first for IPv6.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WorkloadRuleEntry {
    /// Destination network, host-order words. All zero with `prefix_len` 0
    /// means anywhere.
    pub dst_addr: [u32; 4],
    /// First port of the range, host order. Zero with `port_end` zero means
    /// any port.
    pub port_start: u16,
    /// Last port of the range, inclusive.
    pub port_end: u16,
    /// Which bit of the selector mask this rule's workload owns.
    pub selector: u8,
    /// Prefix length of `dst_addr`, 0 for anywhere.
    pub prefix_len: u8,
    /// `WORKLOAD_FAMILY_*`.
    pub family: u8,
    /// IP protocol as the kernel numbers it, or `WORKLOAD_PROTOCOL_ANY`.
    pub protocol: u8,
    /// `WORKLOAD_ACTION_*`.
    pub action: u8,
    /// `WORKLOAD_MODE_*`.
    pub mode: u8,
    /// Zero for a slot the policy does not use. The kernel stops its walk at
    /// the first disabled slot, so the array is written in priority order
    /// with no holes.
    pub enabled: u8,
    /// `WORKLOAD_RULE_FQDN` when the destination is learned from DNS,
    /// `WORKLOAD_RULE_PEER` when it is a workload on another node,
    /// `WORKLOAD_RULE_SENT` when it is `dst_addr` and the rule is never
    /// consulted at bind, zero when it is `dst_addr` at every hook.
    pub fqdn: u8,
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for WorkloadRuleEntry {}

/// One refusal, as the kernel half writes it down.
///
/// It carries what the hook knew and nothing it would have had to go and look
/// up: the rule's slot, the destination, the calling task and the cgroup.
/// Userspace turns the slot into the rule's own identifier and the task into
/// the workload's name, because both of those are readings it already holds
/// and neither is something a socket hook can do.
///
/// `enforced` is what separates a connection that failed from one that would
/// have: an observing rule writes the same record with it clear, so the alert
/// an operator reads before turning a policy on is the alert they will read
/// after.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WorkloadDenialEvent {
    /// `bpf_ktime_get_boot_ns` at the hook.
    pub at_ns: u64,
    /// The cgroup the calling task sat in.
    pub cgroup_id: u64,
    /// Destination network address, host-order words, IPv4 in word zero.
    pub dst_addr: [u32; 4],
    /// Thread group id of the caller.
    pub tgid: u32,
    /// Effective user id of the caller.
    pub uid: u32,
    /// Destination port, host order.
    pub dst_port: u16,
    /// Which slot of `WORKLOAD_RULES` refused, which is the rule's position
    /// among the enabled rules userspace published.
    pub rule: u16,
    /// `WORKLOAD_FAMILY_IPV4` or `WORKLOAD_FAMILY_IPV6`.
    pub family: u8,
    /// IP protocol as the kernel numbers it.
    pub protocol: u8,
    /// `WORKLOAD_HOOK_*`.
    pub hook: u8,
    /// One when the syscall was refused, zero when the rule only observes.
    pub enforced: u8,
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for WorkloadDenialEvent {}

/// Key of `WORKLOAD_FQDN_ALLOWED`: one address a name resolved to, for one
/// cgroup and one rule.
///
/// The cgroup is in the key because an answer belongs to the pod that asked:
/// the same address learned by another pod is another entry, so an address is
/// never opened for a workload that did not resolve it. The rule's slot is in
/// the key because two rules naming different names can resolve to one
/// address, and each grants only what its own rule says.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WorkloadFqdnKey {
    /// The cgroup of the socket that received the answer.
    pub cgroup_id: u64,
    /// The address, host-order words, IPv4 in word zero.
    pub addr: [u32; 4],
    /// `WORKLOAD_FAMILY_IPV4` or `WORKLOAD_FAMILY_IPV6`.
    pub family: u8,
    /// Which slot of `WORKLOAD_RULES` the address was learned for.
    pub slot: u8,
    pub _pad: [u8; 6],
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for WorkloadFqdnKey {}

/// Key of the peer maps: one address of another node.
///
/// The value is a mask of rule slots, bit `n` for slot `n`, so one lookup
/// answers every rule at once and a rule needs no entry of its own per
/// address.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WorkloadPeerKey {
    /// The address, host-order words, IPv4 in word zero.
    pub addr: [u32; 4],
    /// `WORKLOAD_FAMILY_IPV4` or `WORKLOAD_FAMILY_IPV6`.
    pub family: u8,
    pub _pad: [u8; 3],
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for WorkloadPeerKey {}

/// One DNS packet of a named workload, as the capture hands it up.
///
/// Queries travel as well as answers because an answer is only believed when
/// it answers a query the same cgroup sent to a trusted resolver; the pairing
/// is done in userspace, where the name can be compared.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkloadDnsEvent {
    /// `bpf_ktime_get_boot_ns` at the hook.
    pub at_ns: u64,
    /// The cgroup of the socket the packet belongs to.
    pub cgroup_id: u64,
    /// Source address, host-order words, IPv4 in word zero.
    pub src_addr: [u32; 4],
    /// Destination address, host-order words, IPv4 in word zero.
    pub dst_addr: [u32; 4],
    /// Source port, host order.
    pub src_port: u16,
    /// Destination port, host order.
    pub dst_port: u16,
    /// Bytes of `payload` that carry the message.
    pub payload_len: u16,
    /// `WORKLOAD_FAMILY_IPV4` or `WORKLOAD_FAMILY_IPV6`.
    pub family: u8,
    /// `WORKLOAD_DNS_QUERY` or `WORKLOAD_DNS_RESPONSE`.
    pub direction: u8,
    /// The DNS message, from its header.
    pub payload: [u8; WORKLOAD_DNS_MAX_PAYLOAD],
}

impl Default for WorkloadDnsEvent {
    fn default() -> Self {
        Self {
            at_ns: 0,
            cgroup_id: 0,
            src_addr: [0; 4],
            dst_addr: [0; 4],
            src_port: 0,
            dst_port: 0,
            payload_len: 0,
            family: 0,
            direction: 0,
            payload: [0; WORKLOAD_DNS_MAX_PAYLOAD],
        }
    }
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for WorkloadDnsEvent {}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn the_rule_entry_is_the_size_both_sides_compiled_against() {
        // A kernel map's value size is fixed at creation, so a field added
        // without thinking makes the loader refuse the map rather than
        // misread it. Pinning the number here is what makes that a test
        // failure instead.
        assert_eq!(mem::size_of::<WorkloadRuleEntry>(), 28);
        assert_eq!(mem::align_of::<WorkloadRuleEntry>(), 4);
    }

    #[test]
    fn an_unused_slot_is_disabled_and_decides_nothing() {
        let empty = WorkloadRuleEntry::default();
        assert_eq!(empty.enabled, 0);
        assert_eq!(empty.action, WORKLOAD_ACTION_ALLOW);
        assert_eq!(empty.mode, WORKLOAD_MODE_OBSERVE);
    }

    #[test]
    fn the_denial_record_is_the_size_both_sides_compiled_against() {
        assert_eq!(mem::size_of::<WorkloadDenialEvent>(), 48);
        assert_eq!(mem::align_of::<WorkloadDenialEvent>(), 8);
    }

    #[test]
    fn the_fqdn_key_and_record_are_the_size_both_sides_compiled_against() {
        assert_eq!(mem::size_of::<WorkloadFqdnKey>(), 32);
        assert_eq!(
            mem::size_of::<WorkloadDnsEvent>(),
            56 + WORKLOAD_DNS_MAX_PAYLOAD
        );
    }

    #[test]
    fn the_lineage_types_are_the_size_both_sides_compiled_against() {
        assert_eq!(mem::size_of::<WorkloadExeKey>(), 16);
        assert_eq!(mem::size_of::<WorkloadLineageBits>(), 16);
        assert_eq!(mem::size_of::<WorkloadLineageConfig>(), 48);
    }

    #[test]
    fn the_peer_key_is_the_size_both_sides_compiled_against() {
        assert_eq!(mem::size_of::<WorkloadPeerKey>(), 20);
        assert_eq!(mem::align_of::<WorkloadPeerKey>(), 4);
    }

    // Every rule slot has a bit in a remote workload mask.
    const _: () = assert!(WORKLOAD_POLICY_MAX_RULES <= 64);

    #[test]
    fn a_full_policy_fits_the_lineage_table_with_room_for_upgrades() {
        assert!(WORKLOAD_LINEAGE_MAX_EXECUTABLES as usize >= 2 * WORKLOAD_POLICY_MAX_SELECTORS);
    }

    #[test]
    fn every_rule_slot_fits_the_byte_the_fqdn_key_carries_it_in() {
        assert!(WORKLOAD_POLICY_MAX_RULES <= usize::from(u8::MAX) + 1);
    }

    #[test]
    fn a_rule_slot_fits_the_field_that_carries_it_back() {
        // The record names the slot in sixteen bits; a rule ceiling past that
        // would be a denial attributed to the wrong rule.
        assert!(WORKLOAD_POLICY_MAX_RULES <= usize::from(u16::MAX));
    }

    #[test]
    fn every_hook_is_distinct_and_named() {
        let hooks = [
            WORKLOAD_HOOK_CONNECT,
            WORKLOAD_HOOK_SENDMSG,
            WORKLOAD_HOOK_BIND,
            WORKLOAD_HOOK_INGRESS,
        ];
        for (position, hook) in hooks.iter().enumerate() {
            assert_eq!(usize::from(*hook), position);
        }
    }

    #[test]
    fn every_metric_index_is_inside_the_array_and_distinct() {
        let indices = [
            WORKLOAD_METRIC_CONNECT,
            WORKLOAD_METRIC_SENDMSG,
            WORKLOAD_METRIC_BIND,
            WORKLOAD_METRIC_ALLOWED,
            WORKLOAD_METRIC_REFUSED,
            WORKLOAD_METRIC_WOULD_REFUSE,
            WORKLOAD_METRIC_UNRESOLVED,
            WORKLOAD_METRIC_NO_RULE,
            WORKLOAD_METRIC_EVENT_LOST,
            WORKLOAD_METRIC_DNS_LOST,
            WORKLOAD_METRIC_LINEAGE_TRUNCATED,
        ];
        assert_eq!(indices.len(), WORKLOAD_METRIC_COUNT as usize);
        for (position, index) in indices.iter().enumerate() {
            assert_eq!(*index as usize, position);
        }
    }
}
