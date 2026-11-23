//! What flows, hosts and pairs remember, against a real Suricata: the
//! packets of `fixtures/suricata/flow.cases`, replayed through one engine
//! loaded with every rule, must raise on each packet the alerts
//! `make-flow-verdicts.py` recorded Suricata raising on it.

use std::net::Ipv4Addr;

use domain::ids::engine::IdsEngine;
use domain::ids::suricata::{SuricataVars, compile_ruleset};
use ebpf_common::event::{EVENT_TYPE_IDS, PacketEvent};

const VERDICTS: &str = include_str!("fixtures/suricata/flow-verdicts.txt");

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex payload"))
        .collect()
}

fn addr(text: &str) -> [u32; 4] {
    [
        u32::from(text.parse::<Ipv4Addr>().expect("an IPv4 address")),
        0,
        0,
        0,
    ]
}

fn port(text: &str) -> u16 {
    text.parse().expect("a port")
}

fn event(fields: &[&str]) -> PacketEvent {
    PacketEvent {
        timestamp_ns: fields[0].parse().expect("a time"),
        src_addr: addr(fields[1]),
        dst_addr: addr(fields[3]),
        src_port: port(fields[2]),
        dst_port: port(fields[4]),
        protocol: 6,
        event_type: EVENT_TYPE_IDS,
        action: 0,
        flags: 0,
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

/// The segment Suricata read: PSH ACK, met midstream since the capture
/// holds no handshake, so every rule is read on the packet.
fn segment(event: &PacketEvent, payload: &[u8]) -> Vec<u8> {
    let total = u16::try_from(40 + payload.len()).expect("a payload fits one packet");
    let mut bytes = vec![0x45, 0];
    bytes.extend_from_slice(&total.to_be_bytes());
    bytes.extend_from_slice(&[0, 1, 0, 0, 64, 6, 0, 0]);
    bytes.extend_from_slice(&event.src_addr[0].to_be_bytes());
    bytes.extend_from_slice(&event.dst_addr[0].to_be_bytes());
    bytes.extend_from_slice(&event.src_port.to_be_bytes());
    bytes.extend_from_slice(&event.dst_port.to_be_bytes());
    bytes.extend_from_slice(&[0, 0, 3, 232, 0, 0, 0, 1, 0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0]);
    bytes.extend_from_slice(payload);
    bytes
}

#[test]
fn the_flow_table_remembers_what_suricata_remembers() {
    let mut rules = String::new();
    let mut loaded = 0;
    let mut packets = Vec::new();
    for line in VERDICTS.lines() {
        if line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("rule ") {
            let mut parts = rest.splitn(3, ' ');
            let sid = parts.next().expect("sid");
            let verdict = parts.next().expect("verdict");
            let text = parts.next().expect("rule");
            assert_eq!(verdict, "loaded", "Suricata refuses rule {sid}");
            rules.push_str(text);
            rules.push('\n');
            loaded += 1;
        } else if let Some(rest) = line.strip_prefix("packet ") {
            let fields: Vec<&str> = rest.split(' ').collect();
            assert_eq!(fields.len(), 7, "packet line: {line}");
            packets.push((event(&fields), hex(fields[5]), fields[6].to_string()));
        }
    }
    assert!(loaded > 40, "the verdict file lost its rules");
    let compiled = compile_ruleset(&rules, &SuricataVars::default());
    let refused: Vec<String> = compiled
        .report
        .refused
        .iter()
        .map(|r| format!("{:?} {}: {}", r.sid, r.keyword, r.reason))
        .collect();
    assert!(refused.is_empty(), "refused here:\n{}", refused.join("\n"));
    let mut engine = IdsEngine::new();
    engine.reload(compiled.rules).expect("the rules load");
    let mut wrong = Vec::new();
    for (event, payload, expected) in &packets {
        let mut sids: Vec<u32> = engine
            .evaluate_packet(event, &segment(event, payload), None)
            .iter()
            .filter_map(|(_, rule)| rule.imported.as_ref().map(|i| i.sid))
            .collect();
        sids.sort_unstable();
        sids.dedup();
        let got = if sids.is_empty() {
            "-".to_string()
        } else {
            sids.iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(",")
        };
        if &got != expected {
            wrong.push(format!(
                "packet at {} ns, {:?}: Suricata {expected}, here {got}",
                event.timestamp_ns,
                String::from_utf8_lossy(payload)
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} disagreements:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}
