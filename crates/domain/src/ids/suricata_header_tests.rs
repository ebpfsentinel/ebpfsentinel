//! The header keywords, protocols, ports and directions held to Suricata.
//!
//! `tests/fixtures/suricata/header-verdicts.txt` is what Suricata 8 alerted
//! on, written by `make-header-verdicts.py` beside it: every rule of
//! `header.rules` run over every packet the script builds. Each rule Suricata
//! loads must compile here, each it refuses must be refused, and on every
//! packet the rules alerting here must be the rules that alerted there.

use ebpf_common::event::{FLAG_IPV6, PacketEvent};

use super::compile_rule_admitting;
use crate::ids::engine::IdsEngine;
use crate::ids::entity::IdsRule;
use crate::ids::packet::IpPacket;
use crate::ids::suricata::SuricataVars;

const VERDICTS: &str = include_str!("../../tests/fixtures/suricata/header-verdicts.txt");

/// Packets whose IPv4 options Suricata judges malformed. It then drops the
/// header's other fields too (`ip_proto` reads 0, `ttl` stops matching), and
/// the engine does not copy that: these packets are named and not compared.
const MALFORMED: usize = 5;

struct Packet {
    name: String,
    bytes: Vec<u8>,
    sids: Vec<u32>,
}

fn with_sid(rule: &str, sid: u32) -> String {
    let close = rule.rfind(')').expect("a rule ends with its option list");
    format!("{} sid:{sid};)", &rule[..close])
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

fn event(packet: &IpPacket<'_>) -> PacketEvent {
    let (src_addr, dst_addr) = packet.event_addresses();
    let (src_port, dst_port) = packet.ports().unwrap_or_default();
    PacketEvent {
        timestamp_ns: 0,
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        protocol: packet.proto,
        event_type: 0,
        action: 0,
        flags: if packet.v6 { FLAG_IPV6 } else { 0 },
        rule_id: 0,
        vlan_id: 0,
        cpu_id: 0,
        socket_cookie: 0,
        cgroup_id: 0,
        cgroup1_id: 0,
        rss_hash: 0,
        rss_hash_type: 0,
        rx_hw_timestamp_ns: 0,
        pkt_len: 0,
        _pad: 0,
    }
}

#[test]
fn header_rules_alert_on_the_packets_suricata_alerts_on() {
    let vars = SuricataVars::default();
    let mut rules: Vec<IdsRule> = Vec::new();
    let mut packets = Vec::new();
    let mut name = String::new();
    for line in VERDICTS.lines() {
        if let Some(comment) = line.strip_prefix("# ") {
            name = comment.to_string();
            continue;
        }
        let mut fields = line.splitn(3, ' ');
        let (Some(kind), Some(number), Some(rest)) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        match kind {
            "rule" | "refused" => {
                let sid: u32 = number.parse().expect("sid");
                let compiled = compile_rule_admitting(&with_sid(rest, sid), &vars, true);
                match (kind, compiled) {
                    ("rule", Ok(mut compiled)) => rules.append(&mut compiled),
                    ("rule", Err(refused)) => panic!(
                        "sid {sid} loads in Suricata, refused here: {} {}",
                        refused.keyword, refused.reason
                    ),
                    (_, Ok(_)) => panic!("sid {sid} is refused by Suricata, compiled here"),
                    (_, Err(_)) => {}
                }
            }
            "packet" => {
                let (bytes, sids) = rest.split_once(' ').expect("packet bytes then sids");
                let sids = if sids == "-" {
                    Vec::new()
                } else {
                    sids.split(',').map(|s| s.parse().expect("sid")).collect()
                };
                packets.push(Packet {
                    name: name.clone(),
                    bytes: hex(bytes),
                    sids,
                });
            }
            _ => {}
        }
    }
    assert!(packets.len() > 40, "the fixture holds the packets");

    let mut engine = IdsEngine::new();
    engine
        .reload(rules)
        .expect("the engine loads the compiled rules");
    let mut skipped = 0;
    let mut wrong = Vec::new();
    for packet in &packets {
        if packet.name.contains("malformed") {
            skipped += 1;
            continue;
        }
        let decoded = IpPacket::decode(&packet.bytes).expect("the packet decodes");
        let mut got: Vec<u32> = engine
            .evaluate_packet(&event(&decoded), &packet.bytes, None)
            .into_iter()
            .filter_map(|(_, rule)| rule.imported.as_ref().map(|i| i.sid))
            .collect();
        got.sort_unstable();
        if got != packet.sids {
            let extra: Vec<_> = got.iter().filter(|s| !packet.sids.contains(s)).collect();
            let missing: Vec<_> = packet.sids.iter().filter(|s| !got.contains(s)).collect();
            wrong.push(format!(
                "{}: extra {extra:?}, missing {missing:?}",
                packet.name
            ));
        }
    }
    assert_eq!(
        skipped, MALFORMED,
        "only the named malformed packets are set aside"
    );
    assert!(
        wrong.is_empty(),
        "differs from Suricata:\n{}",
        wrong.join("\n")
    );
}
