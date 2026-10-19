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
