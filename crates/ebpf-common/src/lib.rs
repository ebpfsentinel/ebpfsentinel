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

    // -----------------------------------------------------------------
    // DLP arena ring layout.
    //
    // DLP_ARENA is a fixed-VA arena map (4 pages = 16 KiB) shared
    // between the uprobe-dlp BPF program and the userspace reader.
    // Both sides mmap/alloc at `DLP_ARENA_FIXED_VA` so a pointer
    // written by BPF is a valid pointer in userspace and vice versa.
    //
    // Layout:
    //   [0..8]    write_seq (u64) — monotonic counter, BPF stores last
    //                                published slot sequence here.
    //   [8..64]   reserved / cache-line padding.
    //   [64..]    ring of DLP_SLOT_COUNT slots, each DLP_SLOT_SIZE
    //             bytes. Each slot holds an `ArenaEventHeader`
    //             followed by a `DlpEventSmall` (288 B truncated
    //             excerpt). Slot index = (sequence - 1) % SLOT_COUNT.
    //
    // The slot's own `ArenaEventHeader.sequence` is written *after*
    // the DlpEventSmall body; userspace double-checks
    // `slot_header.sequence == expected_sequence` before reading the
    // body to detect torn reads when the BPF writer wraps.
    // -----------------------------------------------------------------

    /// Number of pages reserved for DLP arena map (kernel side).
    pub const DLP_ARENA_PAGES: u32 = 4;

    /// Total arena size in bytes.
    pub const DLP_ARENA_SIZE: usize = DLP_ARENA_PAGES as usize * 4096;

    /// Fixed virtual address used by both BPF (`bpf_arena_alloc_pages`
    /// with explicit hint) and userspace (`mmap(MAP_FIXED_NOREPLACE)`)
    /// so the arena pointer space is shared. 16 TiB is well above the
    /// default ASLR heap range and safely below the 47-bit canonical
    /// userspace ceiling on x86_64 / ARM64.
    pub const DLP_ARENA_FIXED_VA: usize = 0x1000_0000_0000;

    /// Bytes reserved at the start of the arena for the ring header.
    /// Cache-line aligned so the `write_seq` u64 sits in its own line.
    pub const DLP_RING_HEADER_SIZE: usize = 64;

    /// Bytes per ring slot (24 B `ArenaEventHeader` + 288 B
    /// `DlpEventSmall` = 312 B, padded to 320 for 64 B alignment).
    pub const DLP_SLOT_SIZE: usize = 320;

    /// Number of slots in the ring.
    pub const DLP_SLOT_COUNT: usize = (DLP_ARENA_SIZE - DLP_RING_HEADER_SIZE) / DLP_SLOT_SIZE;

    /// Byte offset of the `write_seq` counter within the arena.
    pub const DLP_WRITE_SEQ_OFFSET: usize = 0;

    /// Byte offset of slot `i` from arena base.
    #[inline]
    #[must_use]
    pub const fn dlp_slot_offset(slot_idx: usize) -> usize {
        DLP_RING_HEADER_SIZE + slot_idx * DLP_SLOT_SIZE
    }

    // -----------------------------------------------------------------
    // IDS arena ring layout.
    //
    // IDS_ARENA holds full-size L7 events (PacketEvent + 2048 B payload
    // = 2144 B). The ring is sized for bursts: 32 pages = 128 KiB →
    // ~58 slots. Each slot carries one `ArenaEventHeader` + one
    // `L7EventBuf`. The fixed VA sits 1 TiB above the DLP arena to keep
    // the two mappings from colliding.
    // -----------------------------------------------------------------

    /// Number of pages reserved for the IDS arena map.
    pub const IDS_ARENA_PAGES: u32 = 32;

    /// Total IDS arena size in bytes.
    pub const IDS_ARENA_SIZE: usize = IDS_ARENA_PAGES as usize * 4096;

    /// Fixed virtual address for the IDS arena — 17 TiB.
    pub const IDS_ARENA_FIXED_VA: usize = 0x1100_0000_0000;

    /// Bytes reserved at the start of the IDS arena for the ring header.
    pub const IDS_RING_HEADER_SIZE: usize = 64;

    /// Bytes per IDS ring slot (24 B `ArenaEventHeader` + 2144 B
    /// `L7EventBuf` = 2168 B, padded to 2176 B for 64 B alignment).
    pub const IDS_SLOT_SIZE: usize = 2176;

    /// Payload bytes stored per IDS slot (`L7EventBuf` = `PacketEvent`
    /// 96 B + `MAX_L7_PAYLOAD` 2048 B).
    pub const IDS_SLOT_PAYLOAD: usize = 2144;

    /// Number of slots in the IDS ring.
    pub const IDS_SLOT_COUNT: usize = (IDS_ARENA_SIZE - IDS_RING_HEADER_SIZE) / IDS_SLOT_SIZE;

    /// Byte offset of the `write_seq` counter within the IDS arena.
    pub const IDS_WRITE_SEQ_OFFSET: usize = 0;

    /// Byte offset of IDS slot `i` from arena base.
    #[inline]
    #[must_use]
    pub const fn ids_slot_offset(slot_idx: usize) -> usize {
        IDS_RING_HEADER_SIZE + slot_idx * IDS_SLOT_SIZE
    }

    // -----------------------------------------------------------------
    // DNS arena ring layout.
    //
    // DNS_ARENA holds full DNS events (DnsEvent 64 B + 512 B payload
    // = 576 B; packed into `DnsEventBuf` 576 B). 16 pages = 64 KiB
    // yields ~102 slots, enough for DNS bursts without lapping between
    // 50 ms poll ticks. Fixed VA sits 2 TiB above the DLP arena.
    // -----------------------------------------------------------------

    /// Number of pages reserved for the DNS arena map.
    pub const DNS_ARENA_PAGES: u32 = 16;

    /// Total DNS arena size in bytes.
    pub const DNS_ARENA_SIZE: usize = DNS_ARENA_PAGES as usize * 4096;

    /// Fixed virtual address for the DNS arena — 18 TiB.
    pub const DNS_ARENA_FIXED_VA: usize = 0x1200_0000_0000;

    /// Bytes reserved at the start of the DNS arena for the ring header.
    pub const DNS_RING_HEADER_SIZE: usize = 64;

    /// Bytes per DNS ring slot (24 B `ArenaEventHeader` + 576 B
    /// `DnsEventBuf` = 600 B, padded to 640 B for 64 B alignment).
    pub const DNS_SLOT_SIZE: usize = 640;

    /// Payload bytes stored per DNS slot (`DnsEventBuf` = 64 B header
    /// + 512 B payload).
    pub const DNS_SLOT_PAYLOAD: usize = 576;

    /// Number of slots in the DNS ring.
    pub const DNS_SLOT_COUNT: usize = (DNS_ARENA_SIZE - DNS_RING_HEADER_SIZE) / DNS_SLOT_SIZE;

    /// Byte offset of the `write_seq` counter within the DNS arena.
    pub const DNS_WRITE_SEQ_OFFSET: usize = 0;

    /// Byte offset of DNS slot `i` from arena base.
    #[inline]
    #[must_use]
    pub const fn dns_slot_offset(slot_idx: usize) -> usize {
        DNS_RING_HEADER_SIZE + slot_idx * DNS_SLOT_SIZE
    }

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

        #[test]
        fn dlp_ring_layout_fits_in_arena() {
            let last_slot_end = dlp_slot_offset(DLP_SLOT_COUNT - 1) + DLP_SLOT_SIZE;
            assert!(last_slot_end <= DLP_ARENA_SIZE);
            assert_eq!(DLP_SLOT_COUNT, 51);
        }

        #[test]
        fn dlp_slot_holds_header_plus_small_event() {
            // 24 (ArenaEventHeader) + 288 (DlpEventSmall) = 312 ≤ 320.
            const { assert!(ARENA_EVENT_HEADER_SIZE + 288 <= DLP_SLOT_SIZE) };
        }

        #[test]
        fn dlp_write_seq_is_at_start() {
            assert_eq!(DLP_WRITE_SEQ_OFFSET, 0);
            assert!(core::mem::size_of::<u64>() <= DLP_RING_HEADER_SIZE);
        }

        // IDS arena ring is sized to fit a whole number of slots with
        // enough capacity for realistic burst depths.
        const _: () = {
            let last_slot_end = ids_slot_offset(IDS_SLOT_COUNT - 1) + IDS_SLOT_SIZE;
            assert!(last_slot_end <= IDS_ARENA_SIZE);
            assert!(IDS_SLOT_COUNT >= 50);
            assert!(ARENA_EVENT_HEADER_SIZE + IDS_SLOT_PAYLOAD <= IDS_SLOT_SIZE);
        };

        // DNS arena ring sized likewise, with a smaller payload but
        // higher expected burst count.
        const _: () = {
            let last_slot_end = dns_slot_offset(DNS_SLOT_COUNT - 1) + DNS_SLOT_SIZE;
            assert!(last_slot_end <= DNS_ARENA_SIZE);
            assert!(DNS_SLOT_COUNT >= 90);
            assert!(ARENA_EVENT_HEADER_SIZE + DNS_SLOT_PAYLOAD <= DNS_SLOT_SIZE);
        };

        // Each arena uses a distinct fixed VA so mmap regions never
        // collide in userspace.
        const _: () = {
            assert!(DLP_ARENA_FIXED_VA != IDS_ARENA_FIXED_VA);
            assert!(DLP_ARENA_FIXED_VA != DNS_ARENA_FIXED_VA);
            assert!(IDS_ARENA_FIXED_VA != DNS_ARENA_FIXED_VA);
        };
    }
}
