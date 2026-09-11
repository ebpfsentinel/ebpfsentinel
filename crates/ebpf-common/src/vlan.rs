//! VLAN tag walking, shared by every program that parses an Ethernet frame.
//!
//! The walk lives here rather than beside its callers because `ebpf-helpers`
//! is `no_std`, links `aya-ebpf` and is excluded from the workspace, so nothing
//! there is reachable from `cargo test`. It needs only the packet window as two
//! addresses, never a context, so moving it puts the tag stack, its bounds
//! checks and the outer-tag rule under test while the nine programs that walk a
//! frame keep calling one implementation.

/// 802.1Q VLAN `EtherType`.
pub const ETH_P_8021Q: u16 = 0x8100;
/// 802.1ad (QinQ) `EtherType`.
pub const ETH_P_8021AD: u16 = 0x88A8;

/// Size of an 802.1Q VLAN tag in bytes.
pub const VLAN_HDR_LEN: usize = 4;

/// Mask selecting the VLAN ID out of the Tag Control Information field. The
/// top four bits are priority and the drop-eligible indicator, which are not
/// part of the identifier a policy is written against.
pub const VLAN_ID_MASK: u16 = 0x0FFF;

/// Deepest tag stack the walk consumes: the service tag and the customer tag.
///
/// A third tag is left in the frame, so the `EtherType` handed back is the
/// VLAN one and the caller falls through to whatever it does with a frame it
/// cannot read an L3 header out of.
pub const VLAN_MAX_TAGS: usize = 2;

/// Whether `ether_type` introduces a VLAN tag.
#[must_use]
pub const fn is_vlan_ether_type(ether_type: u16) -> bool {
    ether_type == ETH_P_8021Q || ether_type == ETH_P_8021AD
}

/// 802.1Q VLAN tag as it sits on the wire.
///
/// `packed` rather than plain `#[repr(C)]`: the tag sits at whatever offset the
/// Ethernet header and any outer tags left off at, inside a buffer the parser
/// does not own and cannot align, so a two-byte field read at an odd address is
/// reachable and is undefined behaviour under `#[repr(C)]`. Packed makes every
/// field access an unaligned load, which is what the wire actually needs.
#[repr(C, packed)]
pub struct VlanHdr {
    /// Tag Control Information: priority, drop-eligible indicator, VLAN ID.
    pub tci: u16,
    /// The `EtherType` of whatever this tag encapsulates.
    pub ether_type: u16,
}

/// What a VLAN walk found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VlanWalk {
    /// The **outer** tag. On a QinQ frame that is the service provider's
    /// S-VLAN, which is what a policy is written against; the inner customer
    /// C-VLAN is walked so the offsets land correctly and is deliberately not
    /// reported, because a `PacketEvent` carries one VLAN ID and nothing in
    /// the datapath strips the inner tag off the frame.
    pub vlan_id: u16,
    /// Whether any tag was present. An untagged frame and a priority-tagged
    /// frame carrying VLAN 0 cannot otherwise be told apart.
    pub tagged: bool,
    /// The `EtherType` of the encapsulated header.
    pub ether_type: u16,
    /// The offset the encapsulated L3 header starts at.
    pub l3_offset: usize,
}

/// Walk up to [`VLAN_MAX_TAGS`] stacked VLAN tags, returning the outer tag and
/// the `EtherType` and offset of the header underneath them.
///
/// `start` and `end` are the packet window as the datapath holds it, and
/// `ether_type` and `l3_offset` are what the Ethernet header parse left off at.
/// An untagged frame comes back unchanged with `tagged` false.
///
/// Returns `None` when a tag runs past the end of the packet, so a caller
/// treats a truncated frame as one it has nothing to say about.
///
/// # Safety
///
/// `start..end` must be a readable window for the current program invocation,
/// with `start <= end`.
#[inline(always)]
#[must_use]
pub unsafe fn walk_vlan_tags(
    start: usize,
    end: usize,
    mut ether_type: u16,
    mut l3_offset: usize,
) -> Option<VlanWalk> {
    let mut vlan_id: u16 = 0;
    let mut tagged = false;

    let mut i = 0usize;
    while i < VLAN_MAX_TAGS {
        if !is_vlan_ether_type(ether_type) {
            break;
        }
        let pos = start + l3_offset;
        if pos + VLAN_HDR_LEN > end {
            return None;
        }
        let vhdr = pos as *const VlanHdr;
        // Only the outer tag is reported: the inner one advances the offset
        // and nothing else.
        if !tagged {
            vlan_id = u16::from_be(unsafe { (*vhdr).tci }) & VLAN_ID_MASK;
            tagged = true;
        }
        ether_type = u16::from_be(unsafe { (*vhdr).ether_type });
        l3_offset += VLAN_HDR_LEN;
        i += 1;
    }

    Some(VlanWalk {
        vlan_id,
        tagged,
        ether_type,
        l3_offset,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ETH_P_IP: u16 = 0x0800;
    const ETH_P_IPV6: u16 = 0x86DD;

    /// Where an Ethernet header leaves off.
    const L3: usize = 14;

    /// One tag on the wire: TCI then the `EtherType` it encapsulates.
    fn tag(pcp_dei_vid: u16, ether_type: u16) -> Vec<u8> {
        let mut v = Vec::with_capacity(VLAN_HDR_LEN);
        v.extend_from_slice(&pcp_dei_vid.to_be_bytes());
        v.extend_from_slice(&ether_type.to_be_bytes());
        v
    }

    /// A frame whose Ethernet header is followed by `tags`.
    fn frame(tags: &[u8]) -> Vec<u8> {
        let mut v = vec![0u8; L3];
        v.extend_from_slice(tags);
        v.extend_from_slice(&[0u8; 40]);
        v
    }

    fn walk(packet: &[u8], ether_type: u16) -> Option<VlanWalk> {
        let start = packet.as_ptr() as usize;
        let end = start + packet.len();
        unsafe { walk_vlan_tags(start, end, ether_type, L3) }
    }

    #[test]
    fn vlan_ether_types_are_the_two_that_carry_a_tag() {
        assert!(is_vlan_ether_type(ETH_P_8021Q));
        assert!(is_vlan_ether_type(ETH_P_8021AD));
        for other in [ETH_P_IP, ETH_P_IPV6, 0x0806, 0x0000] {
            assert!(!is_vlan_ether_type(other), "{other:#06x}");
        }
    }

    #[test]
    fn an_untagged_frame_comes_back_untouched() {
        let packet = frame(&[]);
        let walked = walk(&packet, ETH_P_IP).expect("an untagged frame parses");
        assert_eq!(
            walked,
            VlanWalk {
                vlan_id: 0,
                tagged: false,
                ether_type: ETH_P_IP,
                l3_offset: L3,
            }
        );
    }

    #[test]
    fn one_tag_advances_by_one_tag() {
        let packet = frame(&tag(100, ETH_P_IP));
        let walked = walk(&packet, ETH_P_8021Q).expect("a tagged frame parses");
        assert_eq!(walked.vlan_id, 100);
        assert!(walked.tagged);
        assert_eq!(walked.ether_type, ETH_P_IP);
        assert_eq!(walked.l3_offset, L3 + VLAN_HDR_LEN);
    }

    #[test]
    fn a_qinq_frame_reports_the_outer_tag_and_lands_under_both() {
        // Service tag 4000 over customer tag 100. A policy is written against
        // the service tag, and the L3 header is under both of them.
        let mut tags = tag(4000, ETH_P_8021Q);
        tags.extend_from_slice(&tag(100, ETH_P_IPV6));
        let packet = frame(&tags);

        let walked = walk(&packet, ETH_P_8021AD).expect("a QinQ frame parses");
        assert_eq!(walked.vlan_id, 4000, "the inner tag was reported");
        assert!(walked.tagged);
        assert_eq!(walked.ether_type, ETH_P_IPV6);
        assert_eq!(walked.l3_offset, L3 + 2 * VLAN_HDR_LEN);
    }

    #[test]
    fn the_priority_and_drop_eligible_bits_are_not_part_of_the_id() {
        // Priority 7, drop-eligible set, VLAN 100: the top four bits belong to
        // neither the identifier nor any policy written against one.
        let tci = (7 << 13) | (1 << 12) | 100;
        let packet = frame(&tag(tci, ETH_P_IP));
        assert_eq!(walk(&packet, ETH_P_8021Q).unwrap().vlan_id, 100);
    }

    #[test]
    fn a_priority_tagged_frame_is_tagged_rather_than_untagged() {
        // VLAN 0 carries priority and no identifier, so the id alone cannot
        // tell it from a frame that never had a tag.
        let packet = frame(&tag(7 << 13, ETH_P_IP));
        let walked = walk(&packet, ETH_P_8021Q).unwrap();
        assert_eq!(walked.vlan_id, 0);
        assert!(walked.tagged);
        assert_eq!(walked.l3_offset, L3 + VLAN_HDR_LEN);
    }

    #[test]
    fn a_third_tag_is_left_in_the_frame() {
        let mut tags = tag(4000, ETH_P_8021Q);
        tags.extend_from_slice(&tag(100, ETH_P_8021Q));
        tags.extend_from_slice(&tag(7, ETH_P_IP));
        let packet = frame(&tags);

        let walked = walk(&packet, ETH_P_8021AD).unwrap();
        assert_eq!(walked.vlan_id, 4000);
        assert_eq!(walked.l3_offset, L3 + VLAN_MAX_TAGS * VLAN_HDR_LEN);
        // The caller is handed a VLAN EtherType, which is not an L3 header it
        // can read, rather than an offset into the middle of a tag.
        assert!(is_vlan_ether_type(walked.ether_type));
    }

    #[test]
    fn a_tag_running_past_the_packet_is_refused() {
        // Three bytes where a tag needs four.
        let mut packet = vec![0u8; L3];
        packet.extend_from_slice(&[0x00, 0x64, 0x08]);
        assert_eq!(walk(&packet, ETH_P_8021Q), None);
    }

    #[test]
    fn a_truncated_inner_tag_is_refused_rather_than_half_walked() {
        let mut packet = vec![0u8; L3];
        packet.extend_from_slice(&tag(4000, ETH_P_8021Q));
        packet.extend_from_slice(&[0x00, 0x64]);
        assert_eq!(walk(&packet, ETH_P_8021AD), None);
    }
}
