//! IPv6 extension header walking rules, shared by the XDP and TC helpers.
//!
//! The kernel-side walk lives in `ebpf-helpers`, which is `no_std`, links
//! `aya-ebpf` and is excluded from the workspace, so nothing there is reachable
//! from `cargo test`. The part that decides how far the walk advances is pure
//! arithmetic, so it lives here where it is covered.

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
}
