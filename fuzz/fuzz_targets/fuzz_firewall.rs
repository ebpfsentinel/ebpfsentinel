#![no_main]

use libfuzzer_sys::fuzz_target;

use domain::common::entity::{Protocol, RuleId};
use domain::firewall::engine::FirewallEngine;
use domain::firewall::entity::{FirewallAction, FirewallRule, IpNetwork, PacketInfo, PortRange, Scope};

// Deserialize fuzz data into a firewall scenario: rules + packets.
//
// Layout (variable-length):
//   [0]    = number of rules (1–8)
//   [1]    = selector byte (sub-target: 0=evaluate, 1=add+remove, 2=reload)
//   rest   = consumed in 28-byte chunks (rule) and 20-byte chunks (packet)
fuzz_target!(|data: &[u8]| {
    if data.len() < 30 {
        return;
    }

    let num_rules = ((data[0] as usize) % 8) + 1;
    let selector = data[1] % 3;
    let mut cursor = 2;

    let mut engine = FirewallEngine::new();
    let mut rules = Vec::new();

    // Parse rules from fuzz data
    for i in 0..num_rules {
        if cursor + 28 > data.len() {
            break;
        }
        let chunk = &data[cursor..cursor + 28];
        cursor += 28;

        let priority = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let action = match chunk[4] % 3 {
            0 => FirewallAction::Allow,
            1 => FirewallAction::Deny,
            _ => FirewallAction::Log,
        };
        let protocol = Protocol::from_u8(chunk[5]);

        let src_ip = if chunk[6] & 1 != 0 {
            let addr = u32::from_le_bytes([chunk[7], chunk[8], chunk[9], chunk[10]]);
            Some(IpNetwork::V4 {
                addr,
                prefix_len: chunk[11] % 33,
            })
        } else {
            None
        };

        let dst_ip = if chunk[6] & 2 != 0 {
            let addr = u32::from_le_bytes([chunk[12], chunk[13], chunk[14], chunk[15]]);
            Some(IpNetwork::V4 {
                addr,
                prefix_len: chunk[16] % 33,
            })
        } else {
            None
        };

        let dst_port = if chunk[6] & 4 != 0 {
            let start = u16::from_le_bytes([chunk[17], chunk[18]]);
            let end = u16::from_le_bytes([chunk[19], chunk[20]]);
            Some(PortRange { start, end })
        } else {
            None
        };

        let scope = match chunk[21] % 3 {
            0 => Scope::Global,
            1 => Scope::Interface("eth0".to_string()),
            _ => Scope::Namespace("prod".to_string()),
        };

        let enabled = chunk[22] & 1 != 0;
        let vlan_id = if chunk[23] & 1 != 0 {
            Some(u16::from_le_bytes([chunk[24], chunk[25]]))
        } else {
            None
        };

        let rule = FirewallRule {
            id: RuleId(format!("fuzz-{i}")),
            priority,
            action,
            protocol,
            src_ip,
            dst_ip,
            src_port: None,
            dst_port,
            scope,
            enabled,
            vlan_id,
        };
        rules.push(rule);
    }

    match selector {
        // Sub-target 0: add rules then evaluate packets
        0 => {
            for rule in &rules {
                let _ = engine.add_rule(rule.clone());
            }
            // Parse and evaluate packets
            while cursor + 20 <= data.len() {
                let pkt = &data[cursor..cursor + 20];
                cursor += 20;
                let packet = PacketInfo {
                    src_addr: [
                        u32::from_le_bytes([pkt[0], pkt[1], pkt[2], pkt[3]]),
                        0,
                        0,
                        0,
                    ],
                    dst_addr: [
                        u32::from_le_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]),
                        0,
                        0,
                        0,
                    ],
                    src_port: u16::from_le_bytes([pkt[8], pkt[9]]),
                    dst_port: u16::from_le_bytes([pkt[10], pkt[11]]),
                    protocol: Protocol::from_u8(pkt[12]),
                    interface: match pkt[13] % 3 {
                        0 => "eth0".to_string(),
                        1 => "wlan0".to_string(),
                        _ => "prod-veth1".to_string(),
                    },
                    is_ipv6: pkt[14] & 1 != 0,
                    vlan_id: if pkt[15] & 1 != 0 {
                        Some(u16::from_le_bytes([pkt[16], pkt[17]]))
                    } else {
                        None
                    },
                };
                let _ = engine.evaluate(&packet);
            }
        }
        // Sub-target 1: add then remove rules
        1 => {
            for rule in &rules {
                let _ = engine.add_rule(rule.clone());
            }
            for rule in &rules {
                let _ = engine.remove_rule(&rule.id);
            }
        }
        // Sub-target 2: reload
        _ => {
            let _ = engine.reload(rules);
        }
    }
});
