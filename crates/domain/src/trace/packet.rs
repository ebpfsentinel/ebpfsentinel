//! The bytes a trace sends: one Ethernet frame built from a five-tuple.
//!
//! Every checksum is right, so a stage that verifies one answers as it would
//! for a live packet instead of refusing a malformed frame. A TCP packet is
//! the SYN opening a connection, a UDP datagram and an echo request carry no
//! payload: the question a trace answers is whether this flow passes, and a
//! flow starts with its first packet.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::entity::TraceProtocol;

/// The destination MAC of the crafted frame, locally administered.
pub const DST_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x02];
/// The source MAC of the crafted frame, locally administered.
pub const SRC_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x01];

const ETH_LEN: usize = 14;
const IPV4_LEN: usize = 20;
const IPV6_LEN: usize = 40;
const TCP_LEN: usize = 20;
const UDP_LEN: usize = 8;
const ICMP_LEN: usize = 8;
const TTL: u8 = 64;

/// The frame for one packet of the five-tuple. Addresses of two families
/// are a caller's error; the frame then takes the destination's family and
/// the source's address mapped into it.
#[must_use]
pub fn craft(
    src: IpAddr,
    dst: IpAddr,
    src_port: u16,
    dst_port: u16,
    protocol: TraceProtocol,
) -> Vec<u8> {
    match dst {
        IpAddr::V4(dst) => {
            let src = match src {
                IpAddr::V4(v4) => v4,
                IpAddr::V6(v6) => v6.to_ipv4_mapped().unwrap_or(Ipv4Addr::UNSPECIFIED),
            };
            craft_v4(src, dst, src_port, dst_port, protocol)
        }
        IpAddr::V6(dst) => {
            let src = match src {
                IpAddr::V4(v4) => v4.to_ipv6_mapped(),
                IpAddr::V6(v6) => v6,
            };
            craft_v6(src, dst, src_port, dst_port, protocol)
        }
    }
}

fn craft_v4(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    protocol: TraceProtocol,
) -> Vec<u8> {
    let transport = transport(protocol, false, src_port, dst_port);
    let total = IPV4_LEN + transport.len();
    let mut frame = ethernet(0x0800);
    let ip_start = frame.len();
    frame.extend_from_slice(&[0x45, 0]);
    frame.extend_from_slice(&u16::try_from(total).unwrap_or(u16::MAX).to_be_bytes());
    // Identification 0, don't fragment.
    frame.extend_from_slice(&[0, 0, 0x40, 0]);
    frame.extend_from_slice(&[TTL, protocol.number(false), 0, 0]);
    frame.extend_from_slice(&src.octets());
    frame.extend_from_slice(&dst.octets());
    let ip_sum = checksum(&frame[ip_start..], 0);
    frame[ip_start + 10..ip_start + 12].copy_from_slice(&ip_sum.to_be_bytes());

    let mut pseudo = Vec::with_capacity(12);
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&[0, protocol.number(false)]);
    pseudo.extend_from_slice(
        &u16::try_from(transport.len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    // ICMP over IPv4 sums its own bytes only.
    let seed = if protocol == TraceProtocol::Icmp {
        0
    } else {
        partial_sum(&pseudo)
    };
    append_transport(&mut frame, &transport, protocol, seed);
    frame
}

fn craft_v6(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    src_port: u16,
    dst_port: u16,
    protocol: TraceProtocol,
) -> Vec<u8> {
    let transport = transport(protocol, true, src_port, dst_port);
    let payload = u16::try_from(transport.len()).unwrap_or(u16::MAX);
    let mut frame = ethernet(0x86DD);
    frame.extend_from_slice(&[0x60, 0, 0, 0]);
    frame.extend_from_slice(&payload.to_be_bytes());
    frame.extend_from_slice(&[protocol.number(true), TTL]);
    frame.extend_from_slice(&src.octets());
    frame.extend_from_slice(&dst.octets());

    let mut pseudo = Vec::with_capacity(40);
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&u32::from(payload).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, protocol.number(true)]);
    append_transport(&mut frame, &transport, protocol, partial_sum(&pseudo));
    frame
}

fn ethernet(ethertype: u16) -> Vec<u8> {
    let mut frame = Vec::with_capacity(ETH_LEN + IPV6_LEN + TCP_LEN);
    frame.extend_from_slice(&DST_MAC);
    frame.extend_from_slice(&SRC_MAC);
    frame.extend_from_slice(&ethertype.to_be_bytes());
    frame
}

/// The transport header with its checksum field zero.
fn transport(protocol: TraceProtocol, v6: bool, src_port: u16, dst_port: u16) -> Vec<u8> {
    match protocol {
        TraceProtocol::Tcp => {
            let mut tcp = Vec::with_capacity(TCP_LEN);
            tcp.extend_from_slice(&src_port.to_be_bytes());
            tcp.extend_from_slice(&dst_port.to_be_bytes());
            // Sequence 1, acknowledgement 0.
            tcp.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0]);
            // Data offset 5 words, SYN, window 64240.
            tcp.extend_from_slice(&[0x50, 0x02, 0xFA, 0xF0]);
            // Checksum, urgent pointer.
            tcp.extend_from_slice(&[0, 0, 0, 0]);
            tcp
        }
        TraceProtocol::Udp => {
            let mut udp = Vec::with_capacity(UDP_LEN);
            udp.extend_from_slice(&src_port.to_be_bytes());
            udp.extend_from_slice(&dst_port.to_be_bytes());
            udp.extend_from_slice(&u16::try_from(UDP_LEN).unwrap_or(u16::MAX).to_be_bytes());
            udp.extend_from_slice(&[0, 0]);
            udp
        }
        TraceProtocol::Icmp => {
            // Echo request, identifier 1, sequence 1.
            let echo = if v6 { 128 } else { 8 };
            let mut icmp = Vec::with_capacity(ICMP_LEN);
            icmp.extend_from_slice(&[echo, 0, 0, 0, 0, 1, 0, 1]);
            icmp
        }
    }
}

fn append_transport(frame: &mut Vec<u8>, transport: &[u8], protocol: TraceProtocol, seed: u32) {
    let start = frame.len();
    frame.extend_from_slice(transport);
    let at = match protocol {
        TraceProtocol::Tcp => 16,
        TraceProtocol::Udp => 6,
        TraceProtocol::Icmp => 2,
    };
    let mut sum = checksum(&frame[start..], seed);
    // A UDP checksum of zero means none; the one's complement of zero is sent.
    if protocol == TraceProtocol::Udp && sum == 0 {
        sum = 0xFFFF;
    }
    frame[start + at..start + at + 2].copy_from_slice(&sum.to_be_bytes());
}

fn partial_sum(bytes: &[u8]) -> u32 {
    bytes.chunks(2).fold(0u32, |acc, pair| {
        let word = u16::from_be_bytes([pair[0], pair.get(1).copied().unwrap_or(0)]);
        acc + u32::from(word)
    })
}

/// The Internet checksum of `bytes`, starting from a pseudo-header's sum.
fn checksum(bytes: &[u8], seed: u32) -> u16 {
    let mut sum = seed + partial_sum(bytes);
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !u16::try_from(sum).unwrap_or(u16::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(a))
    }

    /// A checksum over a span that includes its own checksum field is zero.
    fn verifies(bytes: &[u8], seed: u32) -> bool {
        checksum(bytes, seed) == 0
    }

    #[test]
    fn an_ipv4_tcp_syn_carries_the_tuple_and_valid_checksums() {
        let frame = craft(
            v4([10, 0, 0, 1]),
            v4([10, 0, 0, 2]),
            40000,
            443,
            TraceProtocol::Tcp,
        );
        assert_eq!(frame.len(), ETH_LEN + IPV4_LEN + TCP_LEN);
        assert_eq!(&frame[12..14], &[0x08, 0x00]);
        assert_eq!(frame[ETH_LEN + 9], 6);
        assert_eq!(&frame[ETH_LEN + 12..ETH_LEN + 16], &[10, 0, 0, 1]);
        assert_eq!(&frame[ETH_LEN + 16..ETH_LEN + 20], &[10, 0, 0, 2]);
        let l4 = ETH_LEN + IPV4_LEN;
        assert_eq!(u16::from_be_bytes([frame[l4], frame[l4 + 1]]), 40000);
        assert_eq!(u16::from_be_bytes([frame[l4 + 2], frame[l4 + 3]]), 443);
        assert_eq!(frame[l4 + 13], 0x02, "SYN only");
        assert!(verifies(&frame[ETH_LEN..l4], 0));
        let pseudo = [10, 0, 0, 1, 10, 0, 0, 2, 0, 6, 0, 20];
        assert!(verifies(&frame[l4..], partial_sum(&pseudo)));
    }

    #[test]
    fn an_ipv4_echo_request_sums_its_own_bytes() {
        let frame = craft(
            v4([1, 1, 1, 1]),
            v4([2, 2, 2, 2]),
            0,
            0,
            TraceProtocol::Icmp,
        );
        let l4 = ETH_LEN + IPV4_LEN;
        assert_eq!(frame.len(), l4 + ICMP_LEN);
        assert_eq!(frame[ETH_LEN + 9], 1);
        assert_eq!(frame[l4], 8);
        assert!(verifies(&frame[l4..], 0));
    }

    #[test]
    fn an_ipv6_udp_datagram_sums_over_the_pseudo_header() {
        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let frame = craft(
            IpAddr::V6(src),
            IpAddr::V6(dst),
            5353,
            53,
            TraceProtocol::Udp,
        );
        let l4 = ETH_LEN + IPV6_LEN;
        assert_eq!(frame.len(), l4 + UDP_LEN);
        assert_eq!(&frame[12..14], &[0x86, 0xDD]);
        assert_eq!(frame[ETH_LEN + 6], 17);
        assert_eq!(
            u16::from_be_bytes([frame[ETH_LEN + 4], frame[ETH_LEN + 5]]),
            8
        );
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&src.octets());
        pseudo.extend_from_slice(&dst.octets());
        pseudo.extend_from_slice(&[0, 0, 0, 8, 0, 0, 0, 17]);
        assert!(verifies(&frame[l4..], partial_sum(&pseudo)));
        assert_ne!(&frame[l4 + 6..l4 + 8], &[0, 0]);
    }

    #[test]
    fn an_icmpv6_echo_request_takes_its_own_type_and_number() {
        let frame = craft(
            "fe80::1".parse().unwrap(),
            "fe80::2".parse().unwrap(),
            0,
            0,
            TraceProtocol::Icmp,
        );
        assert_eq!(frame[ETH_LEN + 6], 58);
        assert_eq!(frame[ETH_LEN + IPV6_LEN], 128);
    }

    #[test]
    fn every_frame_is_long_enough_for_a_test_run() {
        for protocol in [TraceProtocol::Tcp, TraceProtocol::Udp, TraceProtocol::Icmp] {
            assert!(craft(v4([1, 2, 3, 4]), v4([5, 6, 7, 8]), 1, 2, protocol).len() >= ETH_LEN);
        }
    }
}
