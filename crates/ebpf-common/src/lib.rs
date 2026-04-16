#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod config_cmd;
pub mod config_flags;
pub mod conntrack;
pub mod ddos;
pub mod dlp;
pub mod dns;
pub mod event;
pub mod firewall;
pub mod ids;
pub mod interface_group;
pub mod loadbalancer;
pub mod nat;
pub mod qos;
pub mod ratelimit;
pub mod scrub;
pub mod tenant;
pub mod threatintel;
pub mod zone;

/// Shared arena event header visible from both BPF and userspace.
/// Used for zero-copy event passing via `BPF_MAP_TYPE_ARENA` mmap.
pub mod arena {
    /// Header written by BPF programs into the arena, read by
    /// userspace via mmap. All fields are atomic-width for
    /// lock-free concurrent access.
    #[repr(C)]
    #[derive(Debug, Clone, Copy, Default)]
    pub struct ArenaEventHeader {
        /// Monotonically increasing sequence number written by BPF.
        /// Userspace polls this to detect new events.
        pub sequence: u64,
        /// Timestamp in nanoseconds (`bpf_ktime_get_boot_ns`).
        pub timestamp_ns: u64,
        /// Event payload size in bytes (after this header).
        pub payload_len: u32,
        /// Event type discriminant (same as `PacketEvent.event_type`).
        pub event_type: u8,
        pub _pad: [u8; 3],
    }

    /// Size of the arena event header.
    pub const ARENA_EVENT_HEADER_SIZE: usize = core::mem::size_of::<ArenaEventHeader>();

    #[cfg(feature = "userspace")]
    unsafe impl aya::Pod for ArenaEventHeader {}

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn arena_event_header_size() {
            assert_eq!(core::mem::size_of::<ArenaEventHeader>(), 24);
        }

        #[test]
        fn arena_event_header_alignment() {
            assert_eq!(core::mem::align_of::<ArenaEventHeader>(), 8);
        }
    }
}
