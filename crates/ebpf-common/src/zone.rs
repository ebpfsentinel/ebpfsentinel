//! Security zone shared types for kernel (eBPF) and userspace.
//!
//! Zones group network interfaces and enforce inter-zone policies.
//! The XDP firewall uses `ZONE_MAP` to look up the ingress zone
//! for a packet's interface, then filters rules by zone.

/// Maximum number of zone map entries (ifindex → zone_id).
pub const MAX_ZONE_ENTRIES: u32 = 256;

/// Zone ID 0 is reserved for "no zone" / unzoned interfaces.
pub const ZONE_NONE: u8 = 0;

/// Maximum number of zone policy entries.
pub const MAX_ZONE_POLICIES: u32 = 64;

/// Zone policy entry — maps (from_zone, to_zone) to an action.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZonePolicyEntry {
    /// Source zone ID.
    pub from_zone: u8,
    /// Destination zone ID.
    pub to_zone: u8,
    /// Policy: 0 = allow, 1 = deny.
    pub policy: u8,
    pub _pad: u8,
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for ZonePolicyEntry {}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn zone_policy_entry_size() {
        assert_eq!(mem::size_of::<ZonePolicyEntry>(), 4);
    }

    #[test]
    fn zone_policy_entry_alignment() {
        assert_eq!(mem::align_of::<ZonePolicyEntry>(), 1);
    }

    #[test]
    fn zone_policy_entry_field_offsets() {
        assert_eq!(mem::offset_of!(ZonePolicyEntry, from_zone), 0);
        assert_eq!(mem::offset_of!(ZonePolicyEntry, to_zone), 1);
        assert_eq!(mem::offset_of!(ZonePolicyEntry, policy), 2);
    }
}
