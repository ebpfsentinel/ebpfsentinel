#![no_main]

use libfuzzer_sys::fuzz_target;

use domain::alias::entity::{Alias, AliasId, AliasKind};
use domain::alias::resolver::AliasResolver;
use domain::firewall::entity::{IpNetwork, PortRange};

// Fuzz the AliasResolver with random aliases: validate, load, resolve IPs/ports,
// exercise circular reference detection.
//
// Layout:
//   [0] = selector (0=validate+load, 1=resolve IPs, 2=resolve ports+nested)
//   rest = consumed in 10-byte chunks (alias definitions)
fuzz_target!(|data: &[u8]| {
    if data.len() < 12 {
        return;
    }

    let selector = data[0] % 3;
    let mut cursor = 1;

    let mut aliases = Vec::new();
    while cursor + 10 <= data.len() && aliases.len() < 16 {
        let chunk = &data[cursor..cursor + 10];
        cursor += 10;

        let id = AliasId(format!("alias-{}", aliases.len()));
        let kind = match chunk[0] % 5 {
            // IpSet
            0 => {
                let addr = u32::from_le_bytes([chunk[1], chunk[2], chunk[3], chunk[4]]);
                let prefix = chunk[5] % 33;
                AliasKind::IpSet {
                    values: vec![IpNetwork::V4 { addr, prefix_len: prefix }],
                }
            }
            // PortSet
            1 => {
                let start = u16::from_le_bytes([chunk[1], chunk[2]]);
                let end = u16::from_le_bytes([chunk[3], chunk[4]]);
                AliasKind::PortSet {
                    values: vec![PortRange { start, end }],
                }
            }
            // Nested (reference another alias by index)
            2 => {
                let ref_idx = (chunk[1] as usize) % 16;
                AliasKind::Nested {
                    aliases: vec![format!("alias-{ref_idx}")],
                }
            }
            // GeoIp
            3 => {
                let c1 = (chunk[1] % 26 + b'A') as char;
                let c2 = (chunk[2] % 26 + b'A') as char;
                AliasKind::GeoIp {
                    country_codes: vec![format!("{c1}{c2}")],
                }
            }
            // InterfaceGroup
            _ => AliasKind::InterfaceGroup {
                interfaces: vec![format!("eth{}", chunk[1] % 4)],
            },
        };

        let alias = Alias {
            id,
            kind,
            description: if chunk[9] & 1 != 0 {
                Some("fuzz".to_string())
            } else {
                None
            },
        };
        aliases.push(alias);
    }

    match selector {
        // Sub-target 0: validate + load all aliases
        0 => {
            for alias in &aliases {
                let _ = alias.validate();
            }
            let mut resolver = AliasResolver::new();
            let _ = resolver.load(aliases);
        }
        // Sub-target 1: load then resolve IPs (exercises circular detection)
        1 => {
            let mut resolver = AliasResolver::new();
            let _ = resolver.load(aliases.clone());
            for alias in &aliases {
                let _ = resolver.resolve_ips(&alias.id.0);
            }
        }
        // Sub-target 2: load then resolve ports + add individually
        _ => {
            let mid = aliases.len() / 2;
            let mut resolver = AliasResolver::new();
            let _ = resolver.load(aliases[..mid].to_vec());
            for alias in &aliases[mid..] {
                let _ = resolver.add(alias.clone());
            }
            for alias in &aliases {
                let _ = resolver.resolve_ports(&alias.id.0);
                let _ = resolver.get(&alias.id.0);
            }
        }
    }
});
