#![no_main]

use std::net::IpAddr;

use libfuzzer_sys::fuzz_target;

use domain::common::entity::RuleId;
use domain::firewall::entity::PortRange;
use domain::nat::entity::{NatRule, NatType};

// Fuzz the NAT subsystem: NatRule validation across all NatType variants.
//
// Layout:
//   [0]    = selector (0=SNAT/DNAT, 1=Masquerade/OneToOne, 2=Redirect/PortForward)
//   rest   = consumed in 20-byte chunks (rule definitions)
fuzz_target!(|data: &[u8]| {
    if data.len() < 22 {
        return;
    }

    let selector = data[0] % 3;
    let mut cursor = 1;

    let mut rules = Vec::new();
    while cursor + 20 <= data.len() && rules.len() < 16 {
        let chunk = &data[cursor..cursor + 20];
        cursor += 20;

        let priority = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let addr_bytes = [chunk[4], chunk[5], chunk[6], chunk[7]];
        let addr = IpAddr::V4(std::net::Ipv4Addr::new(
            addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3],
        ));
        let addr2_bytes = [chunk[8], chunk[9], chunk[10], chunk[11]];
        let addr2 = IpAddr::V4(std::net::Ipv4Addr::new(
            addr2_bytes[0], addr2_bytes[1], addr2_bytes[2], addr2_bytes[3],
        ));

        let port_start = u16::from_le_bytes([chunk[12], chunk[13]]);
        let port_end = u16::from_le_bytes([chunk[14], chunk[15]]);
        let int_port_start = u16::from_le_bytes([chunk[16], chunk[17]]);
        let int_port_end = u16::from_le_bytes([chunk[18], chunk[19]]);

        let nat_type = match (selector, chunk[0] % 2) {
            (0, 0) => NatType::Snat {
                addr,
                port_range: if chunk[19] & 1 != 0 {
                    Some(PortRange { start: port_start, end: port_end })
                } else {
                    None
                },
            },
            (0, _) => NatType::Dnat {
                addr,
                port: if chunk[19] & 1 != 0 { Some(port_start) } else { None },
            },
            (1, 0) => NatType::Masquerade {
                interface: format!("eth{}", chunk[4] % 4),
                port_range: if chunk[19] & 1 != 0 {
                    Some(PortRange { start: port_start, end: port_end })
                } else {
                    None
                },
            },
            (1, _) => NatType::OneToOne {
                external: addr,
                internal: addr2,
            },
            (_, 0) => NatType::Redirect {
                port: port_start,
            },
            (_, _) => NatType::PortForward {
                ext_port: PortRange { start: port_start, end: port_end },
                int_addr: addr,
                int_port: PortRange { start: int_port_start, end: int_port_end },
            },
        };

        let rule = NatRule {
            id: RuleId(format!("nat-fuzz-{}", rules.len())),
            priority,
            nat_type,
            match_src: if chunk[19] & 2 != 0 {
                Some(format!("{}/24", addr))
            } else {
                None
            },
            match_dst: if chunk[19] & 4 != 0 {
                Some(format!("{}/16", addr2))
            } else {
                None
            },
            match_dst_port: if chunk[19] & 8 != 0 {
                Some(PortRange { start: port_start, end: port_end })
            } else {
                None
            },
            match_protocol: if chunk[19] & 16 != 0 {
                Some("tcp".to_string())
            } else {
                None
            },
            enabled: chunk[19] & 32 == 0,
        };

        rules.push(rule);
    }

    // Validate all rules
    for rule in &rules {
        let _ = rule.validate();
    }
});
