//! IPv6 extension header walking, shared by the XDP and TC helpers.
//!
//! The walk lives here rather than beside its two callers because
//! `ebpf-helpers` is `no_std`, links `aya-ebpf` and is excluded from the
//! workspace, so nothing there is reachable from `cargo test`. It took only
//! the packet window as two addresses and an offset, never a context, so
//! moving it costs the callers one line each and puts the loop, its bounds
//! checks and its two caps under test.
//!
//! The XDP and TC copies were identical to the byte before the move, which is
//! the other half of the reason: a rule that has to be stated twice is a rule
//! that gets fixed once.

/// Hop-by-Hop Options header.
pub const IPV6_EXT_HOP_BY_HOP: u8 = 0;
/// Routing header.
pub const IPV6_EXT_ROUTING: u8 = 43;
/// Fragment header.
pub const IPV6_EXT_FRAGMENT: u8 = 44;
/// Authentication header.
pub const IPV6_EXT_AUTH: u8 = 51;
/// Destination Options header.
pub const IPV6_EXT_DESTINATION: u8 = 60;
/// Mobility header.
pub const IPV6_EXT_MOBILITY: u8 = 135;

/// Maximum number of extension headers a single packet may carry before the
/// walk gives up. Bounded for eBPF verifier compliance.
pub const IPV6_EXT_MAX_HEADERS: u32 = 6;

/// Maximum offset the walk may reach before the packet is treated as hostile.
pub const IPV6_EXT_MAX_OFFSET: usize = 512;

/// Whether `proto` names an extension header the walk consumes.
///
/// ESP (50) is deliberately absent: it is terminal, since everything after it
/// is encrypted, so the walk returns it as the upper-layer protocol.
#[must_use]
pub const fn is_ipv6_ext_header(proto: u8) -> bool {
    matches!(
        proto,
        IPV6_EXT_HOP_BY_HOP
            | IPV6_EXT_ROUTING
            | IPV6_EXT_FRAGMENT
            | IPV6_EXT_AUTH
            | IPV6_EXT_DESTINATION
            | IPV6_EXT_MOBILITY
    )
}

/// Byte length of the extension header of type `hdr_type` whose second byte is
/// `hdr_ext_len`.
///
/// `hdr_type` is the header being measured, never the `Next Header` value read
/// out of it: those two are one header apart, and reading the length rule off
/// the following header is how a Fragment header carrying a non-zero second
/// byte moves the parser off the true L4 offset while the host stack stays on
/// it.
///
/// The three rules are the ones RFC 8200 and RFC 4302 state: a Fragment header
/// is a fixed eight bytes and its second byte is reserved, an Authentication
/// header counts in four-byte units from a base of two, and every other
/// extension header counts in eight-byte units from a base of one. The full
/// eight bits of `hdr_ext_len` are used: masking them advances fewer bytes than
/// the host stack for a long header, which is the same divergence by another
/// route.
///
/// The result is bounded by `(255 + 2) * 4 = 1028` for an Authentication header
/// and by `(255 + 1) * 8 = 2048` for the rest, so the multiply stays provable
/// for the verifier.
#[must_use]
pub const fn ipv6_ext_header_len(hdr_type: u8, hdr_ext_len: u8) -> usize {
    match hdr_type {
        IPV6_EXT_FRAGMENT => 8,
        IPV6_EXT_AUTH => (hdr_ext_len as usize + 2) * 4,
        _ => (hdr_ext_len as usize + 1) * 8,
    }
}

/// Walk the IPv6 extension header chain, returning the upper-layer protocol
/// and the offset just past the last extension header.
///
/// `start` and `end` are the packet window as the datapath holds it, and
/// `start_offset` is where the chain begins inside it. Advancement is by a
/// single pointer rather than by `start + variable_offset`, because the
/// verifier rejects the latter as an unbounded minimum value.
///
/// Returns `None` when the chain runs past the end of the packet, so a caller
/// treats an unparsed packet as one it has nothing to say about.
///
/// The header being measured is the one the iteration entered on, never the
/// `Next Header` value read out of it: those two are one header apart, and
/// measuring the following one is how a Fragment header carrying a non-zero
/// reserved byte moves the walk off the offset the host stack lands on.
///
/// ESP (50) is terminal and is returned rather than consumed, since everything
/// after it is encrypted.
///
/// # Safety
///
/// `start..end` must be a readable window for the current program invocation,
/// with `start <= end`.
#[inline(always)]
#[must_use]
pub unsafe fn walk_ipv6_ext_headers(
    start: usize,
    end: usize,
    start_offset: usize,
    mut next_hdr: u8,
) -> Option<(u8, usize)> {
    let mut pos = start + start_offset;

    let mut i = 0u32;
    while i < IPV6_EXT_MAX_HEADERS {
        if !is_ipv6_ext_header(next_hdr) {
            break;
        }
        // Two bytes are needed: the Next Header value and the length byte.
        if pos + 2 > end {
            return None;
        }
        let hdr_ptr = pos as *const u8;
        let this_hdr = next_hdr;
        next_hdr = unsafe { *hdr_ptr };
        let hdr_ext_len = unsafe { *hdr_ptr.add(1) };
        pos += ipv6_ext_header_len(this_hdr, hdr_ext_len);
        if pos > end {
            return None;
        }
        i += 1;
    }

    let final_offset = pos - start;
    if final_offset > IPV6_EXT_MAX_OFFSET {
        return None;
    }
    Some((next_hdr, final_offset))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ext_headers_recognised() {
        for proto in [0u8, 43, 44, 51, 60, 135] {
            assert!(is_ipv6_ext_header(proto), "proto {proto} should be an ext");
        }
    }

    #[test]
    fn terminal_protocols_are_not_ext_headers() {
        // ESP is terminal, TCP/UDP/ICMPv6 are upper-layer, 59 is "no next".
        for proto in [6u8, 17, 50, 58, 59, 132] {
            assert!(
                !is_ipv6_ext_header(proto),
                "proto {proto} should not be an ext"
            );
        }
    }

    #[test]
    fn fragment_header_is_eight_bytes_whatever_the_reserved_byte_says() {
        // The second byte of a Fragment header is Reserved, not Hdr-Ext-Len.
        // A sender is free to fill it with anything, and the length is still 8.
        assert_eq!(ipv6_ext_header_len(IPV6_EXT_FRAGMENT, 0x00), 8);
        assert_eq!(ipv6_ext_header_len(IPV6_EXT_FRAGMENT, 0xFF), 8);
        assert_eq!(ipv6_ext_header_len(IPV6_EXT_FRAGMENT, 0x07), 8);
    }

    #[test]
    fn auth_header_counts_in_four_byte_units() {
        // RFC 4302: Payload Len is the header length in 32-bit words, minus 2.
        assert_eq!(ipv6_ext_header_len(IPV6_EXT_AUTH, 4), 24);
        assert_eq!(ipv6_ext_header_len(IPV6_EXT_AUTH, 0), 8);
        assert_eq!(ipv6_ext_header_len(IPV6_EXT_AUTH, 255), 1028);
    }

    #[test]
    fn other_ext_headers_count_in_eight_byte_units() {
        for hdr in [
            IPV6_EXT_HOP_BY_HOP,
            IPV6_EXT_ROUTING,
            IPV6_EXT_DESTINATION,
            IPV6_EXT_MOBILITY,
        ] {
            assert_eq!(ipv6_ext_header_len(hdr, 0), 8);
            assert_eq!(ipv6_ext_header_len(hdr, 1), 16);
            assert_eq!(ipv6_ext_header_len(hdr, 255), 2048);
        }
    }

    #[test]
    fn length_follows_the_header_being_measured_not_the_one_after_it() {
        // A Fragment header whose Next Header is TCP: measured as a Fragment
        // it is 8 bytes. Measured as a TCP header - which is what reading the
        // rule off the following protocol does - the reserved byte would be
        // taken as Hdr-Ext-Len and the walk would run past the L4 header.
        let reserved = 0xFFu8;
        assert_eq!(ipv6_ext_header_len(IPV6_EXT_FRAGMENT, reserved), 8);
        assert_ne!(ipv6_ext_header_len(6, reserved), 8);

        // An Authentication header whose Next Header is TCP: 4-byte units.
        assert_eq!(ipv6_ext_header_len(IPV6_EXT_AUTH, 4), 24);
        assert_ne!(ipv6_ext_header_len(6, 4), 24);

        // A Hop-by-Hop header whose Next Header is Fragment: 8-byte units.
        // Reading the rule off the Fragment value would fix the advance at 8
        // whatever the Hop-by-Hop header actually measures.
        assert_eq!(ipv6_ext_header_len(IPV6_EXT_HOP_BY_HOP, 2), 24);
        assert_ne!(ipv6_ext_header_len(IPV6_EXT_FRAGMENT, 2), 24);
    }

    #[test]
    fn advance_is_bounded_for_every_input() {
        for hdr in 0u16..=255 {
            for len in 0u16..=255 {
                let advance =
                    ipv6_ext_header_len(u8::try_from(hdr).unwrap(), u8::try_from(len).unwrap());
                assert!(advance >= 8, "hdr {hdr} len {len} advanced {advance}");
                assert!(advance <= 2048, "hdr {hdr} len {len} advanced {advance}");
            }
        }
    }

    #[test]
    fn a_full_chain_lands_on_the_upper_layer_offset() {
        // Hop-by-Hop (16) -> Fragment (8) -> AH (24) -> TCP.
        let chain = [
            (IPV6_EXT_HOP_BY_HOP, 1u8),
            (IPV6_EXT_FRAGMENT, 0xFF),
            (IPV6_EXT_AUTH, 4),
        ];
        let mut offset = 0usize;
        for (hdr, len) in chain {
            assert!(is_ipv6_ext_header(hdr));
            offset += ipv6_ext_header_len(hdr, len);
        }
        assert_eq!(offset, 16 + 8 + 24);
        assert!(offset <= IPV6_EXT_MAX_OFFSET);
    }

    // ── The walk over a packet window ──────────────────────────────

    /// Run the walk over `packet` as though the datapath had handed it the
    /// whole frame, with the chain starting at `start_offset`.
    fn walk(packet: &[u8], start_offset: usize, first_hdr: u8) -> Option<(u8, usize)> {
        let start = packet.as_ptr() as usize;
        let end = start + packet.len();
        unsafe { walk_ipv6_ext_headers(start, end, start_offset, first_hdr) }
    }

    /// One extension header: its Next Header byte, its length byte, and the
    /// padding that takes it to `total` bytes.
    fn ext(next_hdr: u8, len_byte: u8, total: usize) -> Vec<u8> {
        let mut v = vec![0u8; total];
        v[0] = next_hdr;
        v[1] = len_byte;
        v
    }

    const TCP: u8 = 6;
    const ESP: u8 = 50;

    #[test]
    fn a_chain_of_no_extension_headers_advances_nothing() {
        let packet = vec![0u8; 64];
        assert_eq!(walk(&packet, 0, TCP), Some((TCP, 0)));
    }

    #[test]
    fn a_fragment_header_in_front_of_tcp_is_eight_bytes_whatever_the_reserved_byte_says() {
        // The evasion this walk exists to refuse: the reserved byte is the
        // sender's to choose, and reading it as a length takes the walk
        // 2048 bytes past a header that is eight bytes long.
        for reserved in [0x00u8, 0x07, 0x80, 0xFF] {
            let mut packet = ext(TCP, reserved, 8);
            packet.extend_from_slice(&[0u8; 20]);
            assert_eq!(
                walk(&packet, 0, IPV6_EXT_FRAGMENT),
                Some((TCP, 8)),
                "reserved byte {reserved:#04x} moved the walk off the L4 offset"
            );
        }
    }

    #[test]
    fn an_auth_header_in_front_of_tcp_counts_in_four_byte_units() {
        // RFC 4302: (len + 2) * 4, so len 4 is 24 bytes. Measuring it in
        // eight-byte units would land on 40.
        let mut packet = ext(TCP, 4, 24);
        packet.extend_from_slice(&[0u8; 20]);
        assert_eq!(walk(&packet, 0, IPV6_EXT_AUTH), Some((TCP, 24)));
    }

    #[test]
    fn a_hop_by_hop_header_in_front_of_a_fragment_header_keeps_its_own_length() {
        // The Hop-by-Hop header is 24 bytes and the Fragment header after it
        // is eight, so TCP starts at 32. Selecting the fixed-size rule from
        // the following header would have advanced 8 for the first one.
        let mut packet = ext(IPV6_EXT_FRAGMENT, 2, 24);
        packet.extend_from_slice(&ext(TCP, 0xFF, 8));
        packet.extend_from_slice(&[0u8; 20]);
        assert_eq!(walk(&packet, 0, IPV6_EXT_HOP_BY_HOP), Some((TCP, 32)));
    }

    #[test]
    fn the_walk_starts_where_it_is_told_to() {
        let mut packet = vec![0xAAu8; 40];
        packet.extend_from_slice(&ext(TCP, 0, 8));
        packet.extend_from_slice(&[0u8; 20]);
        // The offset comes back relative to the start of the window, so it
        // carries the 40 bytes of IPv6 header the caller skipped.
        assert_eq!(walk(&packet, 40, IPV6_EXT_ROUTING), Some((TCP, 48)));
    }

    #[test]
    fn esp_is_returned_rather_than_walked() {
        let mut packet = ext(ESP, 0, 8);
        packet.extend_from_slice(&[0u8; 20]);
        assert_eq!(walk(&packet, 0, IPV6_EXT_DESTINATION), Some((ESP, 8)));
    }

    #[test]
    fn a_chain_running_past_the_packet_is_refused() {
        // A Destination Options header claiming 2048 bytes inside a 64-byte
        // packet: the walk says nothing rather than reading past the end.
        let packet = ext(TCP, 0xFF, 64);
        assert_eq!(walk(&packet, 0, IPV6_EXT_DESTINATION), None);
    }

    #[test]
    fn a_header_with_no_room_for_its_length_byte_is_refused() {
        // One byte left in the window, and the walk needs two.
        let packet = vec![TCP; 1];
        assert_eq!(walk(&packet, 0, IPV6_EXT_ROUTING), None);
    }

    #[test]
    fn the_walk_gives_up_after_the_bounded_number_of_headers() {
        // Seven Destination Options headers: the walk consumes six, stops on
        // the iteration cap and reports the seventh as the upper layer.
        let mut packet = Vec::new();
        for _ in 0..6 {
            packet.extend_from_slice(&ext(IPV6_EXT_DESTINATION, 0, 8));
        }
        packet.extend_from_slice(&ext(TCP, 0, 8));
        packet.extend_from_slice(&[0u8; 20]);

        let advanced = usize::try_from(IPV6_EXT_MAX_HEADERS).unwrap() * 8;
        assert_eq!(
            walk(&packet, 0, IPV6_EXT_DESTINATION),
            Some((IPV6_EXT_DESTINATION, advanced))
        );
    }

    #[test]
    fn a_chain_past_the_offset_cap_is_refused() {
        // Two Authentication headers of 1028 bytes each clear every bounds
        // check inside a packet that large and still land past the cap.
        let mut packet = ext(IPV6_EXT_AUTH, 255, 1028);
        packet.extend_from_slice(&ext(TCP, 255, 1028));
        packet.extend_from_slice(&[0u8; 20]);
        assert!(packet.len() > IPV6_EXT_MAX_OFFSET);
        assert_eq!(walk(&packet, 0, IPV6_EXT_AUTH), None);
    }
}
