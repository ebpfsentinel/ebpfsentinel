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
/// How many counters the metrics array holds.
pub const WORKLOAD_METRIC_COUNT: u32 = 8;

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
    pub _pad: u8,
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for WorkloadRuleEntry {}

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
        ];
        assert_eq!(indices.len(), WORKLOAD_METRIC_COUNT as usize);
        for (position, index) in indices.iter().enumerate() {
            assert_eq!(*index as usize, position);
        }
    }
}
