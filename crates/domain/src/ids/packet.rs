//! An IP packet read the way Suricata's decoder reads it, for the rules that
//! name header fields: the IPv4 header with its options, the IPv6 header and
//! its extension headers, then TCP, UDP or ICMP, and the payload after them.
//!
//! What each field means where the packet lacks it is held to a real Suricata
//! by `tests/fixtures/suricata/header-verdicts.txt`.

/// IPv4 option bits, by the names `ipopts` takes.
pub mod opt {
    pub const RR: u16 = 1 << 0;
    pub const EOL: u16 = 1 << 1;
    pub const NOP: u16 = 1 << 2;
    pub const TS: u16 = 1 << 3;
    pub const SEC: u16 = 1 << 4;
    pub const ESEC: u16 = 1 << 5;
    pub const LSRR: u16 = 1 << 6;
    pub const SSRR: u16 = 1 << 7;
    pub const SATID: u16 = 1 << 8;
}

/// The IPv4 fragment bits, as `fragbits` names them.
pub mod frag {
    pub const MORE: u8 = 0x01;
    pub const DONT: u8 = 0x02;
    pub const RESERVED: u8 = 0x04;
}

/// A decoded IP packet, borrowing the bytes it was read from.
#[derive(Debug, Clone, Copy)]
pub struct IpPacket<'a> {
    pub v6: bool,
    /// The IP header: with its options for IPv4, the fixed 40 bytes for IPv6.
    pub ip_hdr: &'a [u8],
    pub src: &'a [u8],
    pub dst: &'a [u8],
    /// The IPv4 time to live, or the IPv6 hop limit.
    pub ttl: u8,
    pub v4: Option<V4Fields>,
    /// The transport protocol: the IPv4 protocol, or the IPv6 next header
    /// after the extension headers.
    pub proto: u8,
    pub l4: L4<'a>,
}

/// The fields only an IPv4 header carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V4Fields {
    pub tos: u8,
    pub id: u16,
    /// `frag::MORE`, `frag::DONT` and `frag::RESERVED`.
    pub frag_bits: u8,
    /// The raw 13-bit field, in units of 8 bytes.
    pub frag_offset: u16,
    /// `opt::*`, one bit per option kind the header carries.
    pub options: u16,
}

/// The transport header and what follows it.
#[derive(Debug, Clone, Copy)]
pub enum L4<'a> {
    Tcp(Tcp<'a>),
    Udp {
        hdr: &'a [u8],
        sport: u16,
        dport: u16,
        payload: &'a [u8],
    },
    Icmp(Icmp<'a>),
    /// A protocol not decoded here, a fragment, or a
    /// header cut short: no port, no transport field, no payload.
    None,
}

#[derive(Debug, Clone, Copy)]
pub struct Tcp<'a> {
    pub hdr: &'a [u8],
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub mss: Option<u16>,
    pub wscale: Option<u8>,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, Copy)]
pub struct Icmp<'a> {
    /// The first 8 bytes, from the type byte.
    pub hdr: &'a [u8],
    pub v6: bool,
    pub kind: u8,
    pub code: u8,
    /// Identifier and sequence number, for the messages that carry them.
    pub echo: Option<(u16, u16)>,
    /// The MTU of an `ICMPv6` Packet Too Big.
    pub mtu: Option<u32>,
    pub payload: &'a [u8],
}

const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_ICMP: u8 = 1;
const PROTO_ICMPV6: u8 = 58;

impl<'a> IpPacket<'a> {
    /// Read an IP packet from its first byte, `None` when the bytes are not
    /// a whole IPv4 or IPv6 header.
    #[must_use]
    pub fn decode(bytes: &'a [u8]) -> Option<Self> {
        match bytes.first()? >> 4 {
            4 => Self::v4(bytes),
            6 => Self::v6(bytes),
            _ => None,
        }
    }

    fn v4(bytes: &'a [u8]) -> Option<Self> {
        let ihl = usize::from(bytes[0] & 0x0f) * 4;
        if ihl < 20 || bytes.len() < ihl {
            return None;
        }
        let total = usize::from(be16(bytes, 2)?).clamp(ihl, bytes.len());
        let word = be16(bytes, 6)?;
        let mut frag_bits = 0;
        if word & 0x8000 != 0 {
            frag_bits |= frag::RESERVED;
        }
        if word & 0x4000 != 0 {
            frag_bits |= frag::DONT;
        }
        if word & 0x2000 != 0 {
            frag_bits |= frag::MORE;
        }
        let frag_offset = word & 0x1fff;
        let proto = bytes[9];
        // A fragment, the first one too, is not decoded past IP: its
        // transport is read on the reassembled packet.
        let l4 = if frag_offset == 0 && frag_bits & frag::MORE == 0 {
            L4::decode(proto, &bytes[ihl..total], false)
        } else {
            L4::None
        };
        Some(Self {
            v6: false,
            ip_hdr: &bytes[..ihl],
            src: &bytes[12..16],
            dst: &bytes[16..20],
            ttl: bytes[8],
            v4: Some(V4Fields {
                tos: bytes[1],
                id: be16(bytes, 4)?,
                frag_bits,
                frag_offset,
                options: v4_options(&bytes[20..ihl]),
            }),
            proto,
            l4,
        })
    }

    fn v6(bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() < 40 {
            return None;
        }
        let end = (40 + usize::from(be16(bytes, 4)?)).min(bytes.len());
        let mut next = bytes[6];
        let mut at = 40;
        // Hop-by-hop, routing, authentication and destination options, each
        // naming the header after it. A fragment header ends the walk: the
        // packet's protocol is then the fragment header itself, and its
        // transport is read on the reassembled packet.
        for _ in 0..8 {
            match next {
                0 | 43 | 60 => {
                    let len = (usize::from(*bytes.get(at + 1)?) + 1) * 8;
                    next = *bytes.get(at)?;
                    at += len;
                }
                51 => {
                    let len = (usize::from(*bytes.get(at + 1)?) + 2) * 4;
                    next = *bytes.get(at)?;
                    at += len;
                }
                _ => break,
            }
        }
        let l4 = match bytes.get(at..end) {
            Some(rest) if next != 44 => L4::decode(next, rest, true),
            _ => L4::None,
        };
        Some(Self {
            v6: true,
            ip_hdr: &bytes[..40],
            src: &bytes[8..24],
            dst: &bytes[24..40],
            ttl: bytes[7],
            v4: None,
            proto: next,
            l4,
        })
    }

    /// The source and destination ports, for TCP and UDP.
    #[must_use]
    pub const fn ports(&self) -> Option<(u16, u16)> {
        match self.l4 {
            L4::Tcp(t) => Some((t.sport, t.dport)),
            L4::Udp { sport, dport, .. } => Some((sport, dport)),
            L4::Icmp(_) | L4::None => None,
        }
    }

    /// What follows the transport header, `None` where nothing was decoded.
    #[must_use]
    pub const fn payload(&self) -> Option<&'a [u8]> {
        match self.l4 {
            L4::Tcp(t) => Some(t.payload),
            L4::Udp { payload, .. } => Some(payload),
            L4::Icmp(i) => Some(i.payload),
            L4::None => None,
        }
    }

    /// The bytes of a header a rule names as its buffer.
    #[must_use]
    pub fn header_buffer(&self, name: &str) -> Option<&'a [u8]> {
        match (name, self.l4) {
            ("ipv4.hdr", _) if !self.v6 => Some(self.ip_hdr),
            ("ipv6.hdr", _) if self.v6 => Some(self.ip_hdr),
            ("tcp.hdr", L4::Tcp(t)) => Some(t.hdr),
            ("udp.hdr", L4::Udp { hdr, .. }) => Some(hdr),
            ("icmpv4.hdr", L4::Icmp(i)) if !i.v6 => Some(i.hdr),
            ("icmpv6.hdr", L4::Icmp(i)) if i.v6 => Some(i.hdr),
            _ => None,
        }
    }

    /// The addresses in the `[u32; 4]` encoding the agent's events carry.
    #[must_use]
    pub fn event_addresses(&self) -> ([u32; 4], [u32; 4]) {
        (words(self.src), words(self.dst))
    }
}

impl<'a> L4<'a> {
    fn decode(proto: u8, bytes: &'a [u8], v6: bool) -> Self {
        match proto {
            PROTO_TCP => tcp(bytes).map_or(Self::None, Self::Tcp),
            PROTO_UDP if bytes.len() >= 8 => Self::Udp {
                hdr: &bytes[..8],
                sport: u16::from_be_bytes([bytes[0], bytes[1]]),
                dport: u16::from_be_bytes([bytes[2], bytes[3]]),
                payload: &bytes[8..],
            },
            PROTO_ICMP | PROTO_ICMPV6 if bytes.len() >= 8 => {
                let v6 = v6 && proto == PROTO_ICMPV6;
                let kind = bytes[0];
                let echo = if v6 {
                    matches!(kind, 128 | 129)
                } else {
                    matches!(kind, 0 | 8 | 13..=18)
                };
                Self::Icmp(Icmp {
                    hdr: &bytes[..8],
                    v6,
                    kind,
                    code: bytes[1],
                    echo: echo.then(|| {
                        (
                            u16::from_be_bytes([bytes[4], bytes[5]]),
                            u16::from_be_bytes([bytes[6], bytes[7]]),
                        )
                    }),
                    mtu: (v6 && kind == 2)
                        .then(|| u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]])),
                    payload: &bytes[8..],
                })
            }
            _ => Self::None,
        }
    }
}

fn tcp(bytes: &[u8]) -> Option<Tcp<'_>> {
    let len = usize::from(*bytes.get(12)? >> 4) * 4;
    if len < 20 || bytes.len() < len {
        return None;
    }
    let mut mss = None;
    let mut wscale = None;
    let options = &bytes[20..len];
    let mut at = 0;
    while let Some(&kind) = options.get(at) {
        match kind {
            0 => break,
            1 => at += 1,
            _ => {
                let size = usize::from(*options.get(at + 1)?);
                let body = options.get(at + 2..at + size.max(2))?;
                match (kind, body.len()) {
                    (2, 2) => mss = Some(u16::from_be_bytes([body[0], body[1]])),
                    (3, 1) => wscale = Some(body[0]),
                    _ => {}
                }
                if size < 2 {
                    break;
                }
                at += size;
            }
        }
    }
    Some(Tcp {
        hdr: &bytes[..len],
        sport: u16::from_be_bytes([bytes[0], bytes[1]]),
        dport: u16::from_be_bytes([bytes[2], bytes[3]]),
        seq: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        ack: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        flags: bytes[13],
        window: u16::from_be_bytes([bytes[14], bytes[15]]),
        mss,
        wscale,
        payload: &bytes[len..],
    })
}

/// The option kinds an IPv4 header carries. An end-of-list option ends the
/// walk and counts, so padding after the last option reads as `eol`.
fn v4_options(bytes: &[u8]) -> u16 {
    let mut seen = 0;
    let mut at = 0;
    while let Some(&kind) = bytes.get(at) {
        match kind {
            0 => {
                seen |= opt::EOL;
                break;
            }
            1 => {
                seen |= opt::NOP;
                at += 1;
            }
            _ => {
                let Some(&size) = bytes.get(at + 1) else {
                    break;
                };
                let size = usize::from(size);
                if size < 2 || at + size > bytes.len() {
                    break;
                }
                let body = &bytes[at..at + size];
                // A route whose pointer does not sit on an address slot, a
                // timestamp too short to carry one, a stream identifier of
                // another length: the walk goes on, the option is not seen.
                let route = || {
                    let pointer = usize::from(body.get(2).copied().unwrap_or(0));
                    size >= 3 && pointer >= 4 && pointer <= size + 1 && (pointer - 4) % 4 == 0
                };
                seen |= match kind {
                    7 if route() => opt::RR,
                    131 if route() => opt::LSRR,
                    137 if route() => opt::SSRR,
                    68 if size >= 5 => opt::TS,
                    130 => opt::SEC,
                    133 => opt::ESEC,
                    136 if size == 4 => opt::SATID,
                    _ => 0,
                };
                at += size;
            }
        }
    }
    seen
}

fn be16(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*bytes.get(at)?, *bytes.get(at + 1)?]))
}

fn words(addr: &[u8]) -> [u32; 4] {
    let mut out = [0; 4];
    for (slot, chunk) in out.iter_mut().zip(addr.as_chunks::<4>().0) {
        *slot = u32::from_be_bytes(*chunk);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn a_syn_reads_its_options_and_fields() {
        let bytes = hex(
            "4500003000014000400626c50a0000010a0000029c4000500000303900000000700204009f4c0000020405b401030307",
        );
        let p = IpPacket::decode(&bytes).unwrap();
        let v4 = p.v4.unwrap();
        assert_eq!(v4.frag_bits, frag::DONT);
        let L4::Tcp(t) = p.l4 else { panic!() };
        assert_eq!(
            (t.sport, t.dport, t.seq, t.flags),
            (0x9c40, 80, 12345, 0x02)
        );
        assert_eq!((t.mss, t.wscale), (Some(1460), Some(7)));
        assert!(t.payload.is_empty());
        assert_eq!(p.event_addresses().0, [0x0a00_0001, 0, 0, 0]);
    }

    #[test]
    fn a_fragment_past_the_first_has_no_transport() {
        let bytes = hex("450000241b5c006440114b070a0000010a0000027a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a");
        let p = IpPacket::decode(&bytes).unwrap();
        assert_eq!(p.v4.unwrap().frag_offset, 100);
        assert_eq!(p.proto, 17);
        assert!(matches!(p.l4, L4::None));
        assert!(p.ports().is_none());
    }

    #[test]
    fn padding_after_an_option_reads_as_end_of_list() {
        assert_eq!(v4_options(&[7, 7, 4, 0, 0, 0, 0, 0]), opt::RR | opt::EOL);
        assert_eq!(v4_options(&[7, 7, 5, 0, 0, 0, 0, 0]), opt::EOL);
        assert_eq!(v4_options(&[131, 3, 4, 0]), opt::LSRR | opt::EOL);
        assert_eq!(v4_options(&[1, 7, 7, 4, 0, 0, 0, 0]), opt::NOP | opt::RR);
    }

    #[test]
    fn truncated_bytes_decode_to_nothing() {
        assert!(IpPacket::decode(&[]).is_none());
        assert!(IpPacket::decode(&[0x45, 0, 0]).is_none());
        assert!(IpPacket::decode(&[0x60; 20]).is_none());
    }
}
