//! Why the kernel dropped a packet, counted where it says so.
//!
//! Every path in the network stack that frees a packet it did not deliver
//! calls `kfree_skb_reason` with a value of `enum skb_drop_reason`, and the
//! `kfree_skb` tracepoint fires with that value. The program behind this
//! module counts each of them under its reason and the interface the packet
//! was on, so "packets are disappearing" becomes a counter with a name.
//!
//! The enumeration is not a stable number: the kernel adds reasons in the
//! middle of it from one release to the next. The program therefore counts
//! the raw value and userspace names it from the running kernel's BTF, and
//! the first value that is a drop at all - everything below it means the
//! packet was not dropped or was consumed normally - is handed in through the
//! configuration rather than compiled in.
//!
//! The same goes for the two structure reads that find the interface: the
//! offsets of `sk_buff.dev`, `sk_buff.skb_iif` and `net_device.ifindex` come
//! from the running kernel's BTF, and a program handed no configuration
//! counts nothing rather than reading at a guessed offset.
//!
//! While somebody investigates one workload's drops, its cgroup is written
//! into a watch set and each drop whose socket sits in a watched cgroup is
//! also counted under that cgroup and its reason. The socket is the one the
//! receive path had found, or else the one the packet was sent from; a packet
//! dropped before any socket was looked up belongs to no workload. With the
//! watch set empty, a drop costs one extra array read.

/// The high half of a drop reason names a subsystem with reasons of its own
/// (`SKB_DROP_REASON_SUBSYS_MASK`). Those are counted under the subsystem
/// alone, so a subsystem cannot widen the label set with codes the core
/// enumeration does not name.
pub const DROP_REASON_SUBSYS_MASK: u32 = 0xffff_0000;

/// How many distinct reason and interface pairs the counter map holds.
///
/// About 130 reasons exist in the kernels the agent supports, and a drop on
/// one node concentrates on a handful of interfaces; 4096 pairs is room for
/// every reason on thirty interfaces. A pair that finds the map full is
/// counted in `DROP_METRIC_KEYS_FULL`, never folded into another one.
pub const DROP_REASON_MAX_KEYS: u32 = 4_096;

/// How many workloads can be watched at once. A workload is watched only
/// while somebody investigates its drops, and a node runs a handful of
/// investigations at a time.
pub const DROP_WATCH_MAX: u32 = 64;

/// How many distinct workload and reason pairs are counted while watched.
pub const DROP_WORKLOAD_MAX_KEYS: u32 = 4_096;

/// Metric index: drops counted under their reason and interface.
pub const DROP_METRIC_COUNTED: u32 = 0;
/// Metric index: drops whose pair found the counter map full.
pub const DROP_METRIC_KEYS_FULL: u32 = 1;
/// Metric index: drops seen before userspace wrote the configuration.
pub const DROP_METRIC_UNCONFIGURED: u32 = 2;
/// Total number of metric slots (one past the last index).
pub const DROP_METRIC_COUNT: u32 = 3;

/// Length of `net_device.name`, `IFNAMSIZ`.
pub const DROP_IFNAME_LEN: usize = 16;

/// One counter's identity: the reason the kernel gave and the interface the
/// packet was on.
///
/// The name is read off the device in the kernel, so a drop inside a pod's
/// namespace is labelled with the name it has there rather than whatever the
/// same index means in the agent's. A packet freed after the stack let go of
/// its device carries the index it arrived on and an empty name.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct DropReasonKey {
    pub reason: u32,
    /// `0` when the packet had no device and no input interface.
    pub ifindex: u32,
    /// NUL-padded device name, empty when there was no device to read it off.
    pub name: [u8; DROP_IFNAME_LEN],
}

/// One workload counter's identity: the cgroup v2 id of the socket the
/// packet belonged to, and the reason the kernel gave.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct DropWorkloadKey {
    pub cgroup: u64,
    pub reason: u32,
    pub _pad: u32,
}

/// What the program needs from the running kernel before it counts.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DropReasonConfig {
    /// The lowest `skb_drop_reason` value that is a drop. Zero means the
    /// configuration has not been written and nothing is counted.
    pub first_drop: u32,
    /// Byte offset of `sk_buff.dev`.
    pub skb_dev: u32,
    /// Byte offset of `sk_buff.skb_iif`.
    pub skb_iif: u32,
    /// Byte offset of `net_device.ifindex`.
    pub dev_ifindex: u32,
    /// Byte offset of `net_device.name`.
    pub dev_name: u32,
    /// Byte offset of `sk_buff.sk`.
    pub skb_sk: u32,
    /// Byte offset of the state byte of a socket: `sock.__sk_common` plus
    /// `sock_common.skc_state`.
    pub sk_state: u32,
    /// Byte offset of `sock.sk_cgrp_data`.
    pub sk_cgrp_data: u32,
    /// Byte offset of `sock_cgroup_data.cgroup`.
    pub cgrp_data_cgroup: u32,
    /// Byte offset of `cgroup.kn`.
    pub cgroup_kn: u32,
    /// Byte offset of `kernfs_node.id`.
    pub kn_id: u32,
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for DropReasonKey {}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for DropReasonConfig {}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for DropWorkloadKey {}

/// The pair a drop is counted under: a subsystem reason keeps only its
/// subsystem, and a core reason is kept whole.
#[must_use]
pub const fn counted_reason(reason: u32) -> u32 {
    if reason & DROP_REASON_SUBSYS_MASK != 0 {
        reason & DROP_REASON_SUBSYS_MASK
    } else {
        reason
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn the_key_and_the_configuration_carry_no_implicit_padding() {
        assert_eq!(mem::size_of::<DropReasonKey>(), 24);
        assert_eq!(mem::size_of::<DropReasonConfig>(), 44);
        assert_eq!(mem::size_of::<DropWorkloadKey>(), 16);
    }

    #[test]
    fn a_subsystem_reason_is_counted_under_its_subsystem() {
        assert_eq!(counted_reason(5), 5);
        assert_eq!(counted_reason(0x0001_0007), 0x0001_0000);
        assert_eq!(counted_reason(0x0002_0000), 0x0002_0000);
    }
}
