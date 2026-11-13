//! The datapath's reverse translation tables, read and written from userspace.
//!
//! `tc-nat-ingress` and `tc-nat-egress` record, for every flow they translate,
//! the reply's tuple and what one of its addresses is restored to. A node that
//! takes over a failed peer's traffic needs the peer's records: the forward leg
//! re-translates identically from the rules, the reply leg finds nothing to
//! undo without them. This manager dumps the tables on the node that holds them
//! and writes a dump into the tables of the node that takes over.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use aya::maps::{HashMap as AyaHashMap, MapData};
use domain::common::error::DomainError;
use domain::nat::entity::{NatReverseEntry, NatReverseKind};
use ebpf_common::nat::{NatReverseKeyV4, NatReverseKeyV6, NatReverseValueV4, NatReverseValueV6};

use crate::ebpf::map_store::MapStore;

/// The four reverse tables of one loaded NAT generation.
pub struct NatReverseMapManager {
    dnat_v4: AyaHashMap<MapData, NatReverseKeyV4, NatReverseValueV4>,
    dnat_v6: AyaHashMap<MapData, NatReverseKeyV6, NatReverseValueV6>,
    snat_v4: AyaHashMap<MapData, NatReverseKeyV4, NatReverseValueV4>,
    snat_v6: AyaHashMap<MapData, NatReverseKeyV6, NatReverseValueV6>,
}

impl NatReverseMapManager {
    /// Take the tables out of the loaded `tc-nat-egress` object, which
    /// declares all four and shares them with `tc-nat-ingress` by pin.
    ///
    /// # Errors
    ///
    /// Returns an error when a table is missing or has another shape.
    pub fn new(ebpf: &mut dyn MapStore) -> anyhow::Result<Self> {
        let mut take = |name: &str| {
            ebpf.take_map(name)
                .ok_or_else(|| anyhow::anyhow!("map '{name}' not found"))
        };
        Ok(Self {
            dnat_v4: AyaHashMap::try_from(take("NAT_DNAT_REVERSE")?)?,
            dnat_v6: AyaHashMap::try_from(take("NAT_DNAT_REVERSE_V6")?)?,
            snat_v4: AyaHashMap::try_from(take("NAT_SNAT_REVERSE")?)?,
            snat_v6: AyaHashMap::try_from(take("NAT_SNAT_REVERSE_V6")?)?,
        })
    }

    /// Up to `limit` records across the four tables, DNAT first.
    ///
    /// A record the datapath evicts while it is being read is skipped rather
    /// than failing the whole dump: it belonged to a flow that is gone.
    #[must_use]
    pub fn dump(&self, limit: usize) -> Vec<NatReverseEntry> {
        let mut out = Vec::new();
        for (kind, table) in [
            (NatReverseKind::Dnat, &self.dnat_v4),
            (NatReverseKind::Snat, &self.snat_v4),
        ] {
            out.extend(
                table
                    .iter()
                    .filter_map(Result::ok)
                    .map(|(k, v)| entry_v4(kind, &k, v))
                    .take(limit.saturating_sub(out.len())),
            );
        }
        for (kind, table) in [
            (NatReverseKind::Dnat, &self.dnat_v6),
            (NatReverseKind::Snat, &self.snat_v6),
        ] {
            out.extend(
                table
                    .iter()
                    .filter_map(Result::ok)
                    .map(|(k, v)| entry_v6(kind, &k, &v))
                    .take(limit.saturating_sub(out.len())),
            );
        }
        out
    }

    /// Write every record into its table and return how many were written.
    /// A record mixing address families is skipped: no table can hold it.
    ///
    /// # Errors
    ///
    /// Returns the first map write the kernel refuses.
    pub fn restore(&mut self, entries: &[NatReverseEntry]) -> Result<usize, DomainError> {
        let mut written = 0;
        for entry in entries {
            match encode(entry) {
                Some(Encoded::V4(k, v)) => {
                    let table = match entry.kind {
                        NatReverseKind::Dnat => &mut self.dnat_v4,
                        NatReverseKind::Snat => &mut self.snat_v4,
                    };
                    table.insert(&k, &v, 0).map_err(|e| map_err(&e))?;
                }
                Some(Encoded::V6(k, v)) => {
                    let table = match entry.kind {
                        NatReverseKind::Dnat => &mut self.dnat_v6,
                        NatReverseKind::Snat => &mut self.snat_v6,
                    };
                    table.insert(&k, &v, 0).map_err(|e| map_err(&e))?;
                }
                None => continue,
            }
            written += 1;
        }
        Ok(written)
    }
}

fn map_err(e: &aya::maps::MapError) -> DomainError {
    DomainError::EngineError(format!("NAT reverse table write failed: {e}"))
}

/// One record as the tables hold it.
#[derive(Debug, PartialEq, Eq)]
enum Encoded {
    V4(NatReverseKeyV4, NatReverseValueV4),
    V6(NatReverseKeyV6, NatReverseValueV6),
}

/// The datapath stores addresses and ports in host order, read off the wire
/// with `from_be_bytes`, so the conversion is the plain integer one.
fn encode(entry: &NatReverseEntry) -> Option<Encoded> {
    match (entry.reply_src, entry.reply_dst, entry.original_addr) {
        (IpAddr::V4(src), IpAddr::V4(dst), IpAddr::V4(orig)) => Some(Encoded::V4(
            NatReverseKeyV4 {
                src_ip: u32::from(src),
                dst_ip: u32::from(dst),
                src_port: entry.reply_src_port,
                dst_port: entry.reply_dst_port,
                protocol: entry.protocol,
                _pad: [0; 3],
            },
            NatReverseValueV4 {
                addr: u32::from(orig),
                port: entry.original_port,
                _pad: 0,
            },
        )),
        (IpAddr::V6(src), IpAddr::V6(dst), IpAddr::V6(orig)) => Some(Encoded::V6(
            NatReverseKeyV6 {
                src_addr: words(src),
                dst_addr: words(dst),
                src_port: entry.reply_src_port,
                dst_port: entry.reply_dst_port,
                protocol: entry.protocol,
                _pad: [0; 3],
            },
            NatReverseValueV6 {
                addr: words(orig),
                port: entry.original_port,
                _pad: 0,
            },
        )),
        _ => None,
    }
}

fn entry_v4(kind: NatReverseKind, k: &NatReverseKeyV4, v: NatReverseValueV4) -> NatReverseEntry {
    NatReverseEntry {
        kind,
        protocol: k.protocol,
        reply_src: IpAddr::V4(Ipv4Addr::from(k.src_ip)),
        reply_dst: IpAddr::V4(Ipv4Addr::from(k.dst_ip)),
        reply_src_port: k.src_port,
        reply_dst_port: k.dst_port,
        original_addr: IpAddr::V4(Ipv4Addr::from(v.addr)),
        original_port: v.port,
    }
}

fn entry_v6(kind: NatReverseKind, k: &NatReverseKeyV6, v: &NatReverseValueV6) -> NatReverseEntry {
    NatReverseEntry {
        kind,
        protocol: k.protocol,
        reply_src: IpAddr::V6(from_words(k.src_addr)),
        reply_dst: IpAddr::V6(from_words(k.dst_addr)),
        reply_src_port: k.src_port,
        reply_dst_port: k.dst_port,
        original_addr: IpAddr::V6(from_words(v.addr)),
        original_port: v.port,
    }
}

/// An IPv6 address as four host-order words, most significant first, which is
/// how the datapath reads one off the header.
fn words(addr: Ipv6Addr) -> [u32; 4] {
    let o = addr.octets();
    [0, 4, 8, 12].map(|i| u32::from_be_bytes([o[i], o[i + 1], o[i + 2], o[i + 3]]))
}

fn from_words(w: [u32; 4]) -> Ipv6Addr {
    let mut o = [0u8; 16];
    for (i, word) in w.iter().enumerate() {
        o[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    Ipv6Addr::from(o)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snat_v4() -> NatReverseEntry {
        NatReverseEntry {
            kind: NatReverseKind::Snat,
            protocol: 6,
            reply_src: "198.51.100.7".parse().unwrap(),
            reply_dst: "203.0.113.10".parse().unwrap(),
            reply_src_port: 443,
            reply_dst_port: 40_123,
            original_addr: "10.0.0.5".parse().unwrap(),
            original_port: 51_000,
        }
    }

    #[test]
    fn a_v4_record_is_written_as_the_datapath_reads_one() {
        let Some(Encoded::V4(k, v)) = encode(&snat_v4()) else {
            panic!("a v4 record encodes as v4");
        };
        assert_eq!(k.src_ip, 0xC633_6407);
        assert_eq!(k.dst_ip, 0xCB00_710A);
        assert_eq!((k.src_port, k.dst_port, k.protocol), (443, 40_123, 6));
        assert_eq!((v.addr, v.port), (0x0A00_0005, 51_000));
        assert_eq!(entry_v4(NatReverseKind::Snat, &k, v), snat_v4());
    }

    #[test]
    fn a_v6_record_survives_the_round_trip() {
        let entry = NatReverseEntry {
            kind: NatReverseKind::Dnat,
            protocol: 17,
            reply_src: "fd00::10".parse().unwrap(),
            reply_dst: "2001:db8::5".parse().unwrap(),
            reply_src_port: 8080,
            reply_dst_port: 50_000,
            original_addr: "2001:db8:ffff::1".parse().unwrap(),
            original_port: 80,
        };
        let Some(Encoded::V6(k, v)) = encode(&entry) else {
            panic!("a v6 record encodes as v6");
        };
        assert_eq!(k.src_addr, [0xfd00_0000, 0, 0, 0x10]);
        assert_eq!(entry_v6(NatReverseKind::Dnat, &k, &v), entry);
    }

    #[test]
    fn a_record_mixing_families_encodes_to_nothing() {
        let mixed = NatReverseEntry {
            original_addr: "fd00::5".parse().unwrap(),
            ..snat_v4()
        };
        assert!(encode(&mixed).is_none());
    }
}
