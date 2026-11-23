//! The header keywords, protocols, ports and directions held to Suricata.
//!
//! `tests/fixtures/suricata/header-verdicts.txt` is what Suricata 8 alerted
//! on, written by `make-header-verdicts.py` beside it: every rule of
//! `header.rules` run over every packet the script builds. Each rule Suricata
//! loads must compile here, each it refuses must be refused, and on every
//! packet the rules alerting here must be the rules that alerted there.
//! `session-verdicts.txt` and `stream-verdicts.txt` hold conversations the
//! same way, the second with what alerted when each connection's streams
//! were flushed at the end of the capture.

use ebpf_common::event::{FLAG_IPV6, PacketEvent};

use super::compile_rule_admitting;
use crate::ids::engine::IdsEngine;
use crate::ids::entity::IdsRule;
use crate::ids::packet::IpPacket;
use crate::ids::suricata::SuricataVars;

const VERDICTS: &str = include_str!("../../tests/fixtures/suricata/header-verdicts.txt");
const SESSIONS: &str = include_str!("../../tests/fixtures/suricata/session-verdicts.txt");
const STREAMS: &str = include_str!("../../tests/fixtures/suricata/stream-verdicts.txt");
const APPLAYER: &str = include_str!("../../tests/fixtures/suricata/applayer-verdicts.txt");
const HTTP: &str = include_str!("../../tests/fixtures/suricata/http-verdicts.txt");
const DNS: &str = include_str!("../../tests/fixtures/suricata/dns-verdicts.txt");
const DATASETS: &str = include_str!("../../tests/fixtures/suricata/dataset-verdicts.txt");
const IPREP: &str = include_str!("../../tests/fixtures/suricata/iprep-verdicts.txt");
const ET: &str = include_str!("../../tests/fixtures/suricata/et-verdicts.txt");
const TLS: &str = include_str!("../../tests/fixtures/suricata/tls-verdicts.txt");
const WINDOWS: &str = include_str!("../../tests/fixtures/suricata/windows-verdicts.txt");
const HTTP_PAYLOAD: &str = include_str!("../../tests/fixtures/suricata/http-payload-verdicts.txt");
const DCERPC: &str = include_str!("../../tests/fixtures/suricata/dcerpc-verdicts.txt");
const SSH: &str = include_str!("../../tests/fixtures/suricata/ssh-verdicts.txt");
const SMTP: &str = include_str!("../../tests/fixtures/suricata/smtp-verdicts.txt");
const ACTION: &str = include_str!("../../tests/fixtures/suricata/action-verdicts.txt");

/// The second the conversation fixtures' captures start at, which their
/// packet times count from: the time Suricata read a certificate's validity
/// against.
const CAPTURE_EPOCH_NS: u64 = 1_700_000_000 * 1_000_000_000;

/// The Ethernet header Suricata counts in a flow's bytes, as `skb->len`
/// does where tc-ids reads it.
const ETHERNET: u32 = 14;

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
    if rule.contains(&format!("sid:{sid};")) {
        return rule.to_string();
    }
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

#[test]
fn session_rules_alert_on_the_packets_suricata_alerts_on() {
    let vars = SuricataVars::default();
    let mut rules: Vec<IdsRule> = Vec::new();
    let mut packets: Vec<(u64, Vec<u8>, Vec<u32>)> = Vec::new();
    for line in SESSIONS.lines() {
        let mut fields = line.splitn(3, ' ');
        let (Some(kind), Some(number), Some(rest)) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        match kind {
            "rule" => {
                let sid: u32 = number.parse().expect("sid");
                let mut compiled = compile_rule_admitting(&with_sid(rest, sid), &vars, true)
                    .unwrap_or_else(|refused| {
                        panic!(
                            "sid {sid} loads in Suricata, refused here: {} {}",
                            refused.keyword, refused.reason
                        )
                    });
                rules.append(&mut compiled);
            }
            "packet" => {
                let (bytes, sids) = rest.split_once(' ').expect("packet bytes then sids");
                let sids = if sids == "-" {
                    Vec::new()
                } else {
                    sids.split(',').map(|s| s.parse().expect("sid")).collect()
                };
                packets.push((number.parse().expect("time"), hex(bytes), sids));
            }
            _ => {}
        }
    }
    assert!(packets.len() > 30, "the fixture holds the conversations");

    let mut engine = IdsEngine::new();
    engine
        .reload(rules)
        .expect("the engine loads the compiled rules");
    let mut wrong = Vec::new();
    for (n, (ns, bytes, sids)) in packets.iter().enumerate() {
        let decoded = IpPacket::decode(bytes).expect("the packet decodes");
        let mut header = event(&decoded);
        header.timestamp_ns = *ns;
        header.pkt_len = u32::try_from(bytes.len()).expect("a short packet") + ETHERNET;
        let mut got: Vec<u32> = engine
            .evaluate_packet(&header, bytes, None)
            .into_iter()
            .filter_map(|(_, rule)| rule.imported.as_ref().map(|i| i.sid))
            .collect();
        got.sort_unstable();
        if &got != sids {
            let extra: Vec<_> = got.iter().filter(|s| !sids.contains(s)).collect();
            let missing: Vec<_> = sids.iter().filter(|s| !got.contains(s)).collect();
            wrong.push(format!("packet {n}: extra {extra:?}, missing {missing:?}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "differs from Suricata:\n{}",
        wrong.join("\n")
    );
}

#[test]
fn stream_rules_alert_on_the_packets_suricata_alerts_on() {
    replay(STREAMS, 100);
}

#[test]
fn application_rules_alert_on_the_packets_suricata_alerts_on() {
    replay(APPLAYER, 40);
}

#[test]
fn http_rules_alert_on_the_packets_suricata_alerts_on() {
    replay(HTTP, 150);
}

#[test]
fn dns_rules_alert_on_the_packets_suricata_alerts_on() {
    replay(DNS, 60);
}

#[test]
fn tls_rules_alert_on_the_packets_suricata_alerts_on() {
    replay(TLS, 90);
}

#[test]
fn rdp_smb_dcerpc_and_telnet_rules_alert_on_the_packets_suricata_alerts_on() {
    replay(WINDOWS, 60);
}

#[test]
fn dcerpc_rules_alert_on_the_packets_suricata_alerts_on() {
    replay(DCERPC, 150);
}

#[test]
fn dataset_and_datarep_rules_alert_on_the_packets_suricata_alerts_on() {
    replay(DATASETS, 15);
}

#[test]
fn iprep_rules_alert_on_the_packets_suricata_alerts_on() {
    replay(IPREP, 15);
}

/// Emerging Threats Open, run whole by Suricata over hostile and benign
/// conversations: the rules that alerted, and those setting the flowbits
/// they read, alert here on the same packets, and nothing else does.
#[test]
fn emerging_threats_rules_alert_on_the_packets_suricata_alerts_on() {
    replay(ET, 300);
}

/// The whole of Emerging Threats Open as the directory `ET_OPEN_RULES` holds
/// it: at least 99 rules in 100 compile, and over the conversations Suricata
/// was run on with that same ruleset, in `ET_OPEN_VERDICTS` (the committed
/// fixture without it), the rules alerting here are the rules that alerted
/// there. The ruleset changes every day, so the job running this writes both
/// from one download.
#[test]
#[ignore = "needs ET_OPEN_RULES, the rules directory of an Emerging Threats Open download"]
fn the_whole_emerging_threats_ruleset_loads_and_alerts_as_in_suricata() {
    let dir = std::env::var("ET_OPEN_RULES").expect("ET_OPEN_RULES names the rules directory");
    let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
        .expect("the rules directory reads")
        .map(|entry| entry.expect("an entry").path())
        .filter(|path| path.extension().is_some_and(|e| e == "rules"))
        .collect();
    files.sort();
    let texts: Vec<(String, String)> = files
        .iter()
        .map(|path| {
            let text = std::fs::read(path).expect("a ruleset reads");
            (
                path.display().to_string(),
                String::from_utf8_lossy(&text).into_owned(),
            )
        })
        .collect();
    let imported = crate::ids::suricata::compile_rulesets(
        texts
            .iter()
            .map(|(name, text)| (name.clone(), text.as_str())),
        &SuricataVars::default(),
    );
    let total: usize = imported.rulesets.iter().map(|r| r.report.total).sum();
    let compiled: usize = imported.rulesets.iter().map(|r| r.report.compiled).sum();
    let mut refused: Vec<String> = imported
        .rulesets
        .iter()
        .flat_map(|r| r.report.refused.iter())
        .map(|r| format!("{:?} {}: {}", r.sid, r.keyword, r.reason))
        .collect();
    refused.sort();
    println!(
        "{compiled} of {total} rules compiled; refused:\n{}",
        refused.join("\n")
    );
    assert!(
        compiled * 100 >= total * 99,
        "{compiled} of {total} rules compiled, below 99 in 100"
    );
    let verdicts = std::env::var("ET_OPEN_VERDICTS").map_or_else(
        |_| ET.to_string(),
        |path| std::fs::read_to_string(path).expect("the verdicts read"),
    );
    replay_against(&verdicts, 300, Some(imported.rules));
}

#[test]
fn smtp_files_alert_on_the_packets_suricata_alerts_on() {
    replay(SMTP, 80);
}

#[test]
fn pass_drop_and_reject_reach_as_far_as_in_suricata() {
    replay(ACTION, 60);
}

#[test]
fn ssh_rules_alert_on_the_packets_suricata_alerts_on() {
    replay(SSH, 80);
}

#[test]
fn http_buffers_beside_the_payload_alert_on_the_packets_suricata_alerts_on() {
    replay(HTTP_PAYLOAD, 100);
}

/// Names a set the way the agent's configuration does, from a fixture's
/// `set NAME TYPE FILE` line.
fn configure(vars: &SuricataVars, name: &str, rest: &str) {
    let (kind, file) = rest.split_once(' ').expect("a type then a file");
    let path = format!(
        "{}/tests/fixtures/suricata/{file}",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).expect("the set's file is beside");
    vars.datasets.configure(
        name,
        crate::ids::dataset::SetKind::from_name(kind).expect("a set type"),
        Ok(&text),
    );
}

/// The variables a fixture compiles its rules with: the reputation lists
/// its 'categories' and 'reputation' lines name, read from beside it.
fn vars_for(fixture: &str) -> SuricataVars {
    let read = |file: &str| {
        let path = format!(
            "{}/tests/fixtures/suricata/{file}",
            env!("CARGO_MANIFEST_DIR")
        );
        std::fs::read_to_string(path).expect("the list is beside")
    };
    let named = |kind: &str| -> Vec<String> {
        fixture
            .lines()
            .filter_map(|l| l.strip_prefix(kind))
            .filter_map(|l| l.split_once(' ').map(|(_, file)| read(file)))
            .collect()
    };
    let mut vars = SuricataVars::default();
    if let Some(categories) = named("categories ").first() {
        let lists = named("reputation ");
        let lists: Vec<(&str, Result<&str, String>)> =
            lists.iter().map(|t| ("list", Ok(t.as_str()))).collect();
        vars.reputation =
            crate::ids::reputation::Reputation::load(("categories", Ok(categories)), &lists).0;
    }
    vars
}

/// Whether a match alerts once the rule's threshold has counted it, as the
/// packet pipeline asks before raising an alert.
fn past_threshold(engine: &IdsEngine, rule: &IdsRule, event: &PacketEvent) -> bool {
    rule.threshold.is_none()
        || engine.check_threshold_with_country(rule, event.src_addr[0], event.dst_addr[0], None)
}

/// Plays a fixture's conversations through the engine, packet by packet,
/// then flushes every flow, and compares what alerted with what Suricata
/// alerted on.
fn replay(fixture: &str, at_least: usize) {
    replay_against(fixture, at_least, None);
}

/// As `replay`, with `corpus` the rules loaded in place of the fixture's own
/// when it is given; the fixture's rules are still held to Suricata's
/// verdict on loading them.
fn replay_against(fixture: &str, at_least: usize, corpus: Option<Vec<IdsRule>>) {
    let vars = vars_for(fixture);
    let mut rules: Vec<IdsRule> = Vec::new();
    let mut packets: Vec<(u64, Vec<u8>, Vec<u32>)> = Vec::new();
    let mut ends: Vec<(u8, Vec<u32>)> = Vec::new();
    let sids = |text: &str| -> Vec<u32> {
        if text == "-" {
            Vec::new()
        } else {
            text.split(',').map(|s| s.parse().expect("sid")).collect()
        }
    };
    let mut wrong = Vec::new();
    for line in fixture.lines() {
        let mut fields = line.splitn(3, ' ');
        let (Some(kind), Some(number), Some(rest)) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        match kind {
            "set" => configure(&vars, number, rest),
            "rule" | "refused" => {
                let sid: u32 = number.parse().expect("sid");
                match (
                    kind,
                    compile_rule_admitting(&with_sid(rest, sid), &vars, true),
                ) {
                    ("rule", Ok(mut compiled)) => rules.append(&mut compiled),
                    ("rule", Err(refused)) => wrong.push(format!(
                        "sid {sid} loads in Suricata, refused here: {} {}",
                        refused.keyword, refused.reason
                    )),
                    (_, Ok(_)) => {
                        wrong.push(format!("sid {sid} is refused by Suricata, compiled here"));
                    }
                    (_, Err(_)) => {}
                }
            }
            "packet" => {
                let (bytes, alerted) = rest.split_once(' ').expect("packet bytes then sids");
                packets.push((number.parse().expect("time"), hex(bytes), sids(alerted)));
            }
            "end" => ends.push((number.parse().expect("connection"), sids(rest))),
            _ => {}
        }
    }
    assert!(
        packets.len() > at_least,
        "the fixture holds the conversations"
    );

    let mut engine = IdsEngine::new();
    engine
        .reload(corpus.unwrap_or(rules))
        .expect("the engine loads the compiled rules");
    for (n, (ns, bytes, want)) in packets.iter().enumerate() {
        let decoded = IpPacket::decode(bytes).expect("the packet decodes");
        let mut header = event(&decoded);
        header.timestamp_ns = CAPTURE_EPOCH_NS + *ns;
        header.pkt_len = u32::try_from(bytes.len()).expect("a short packet") + ETHERNET;
        let mut got: Vec<u32> = engine
            .evaluate_packet(&header, bytes, None)
            .into_iter()
            .filter(|(_, rule)| past_threshold(&engine, rule, &header))
            .filter_map(|(_, rule)| rule.imported.as_ref().map(|i| i.sid))
            .collect();
        got.sort_unstable();
        if &got != want {
            wrong.push(format!(
                "packet {n} at {ns}: got {got:?}, Suricata {want:?}"
            ));
        }
    }
    let mut ended: Vec<(u8, Vec<u32>)> = ends.iter().map(|(n, _)| (*n, Vec::new())).collect();
    for (event, _, rule) in engine.flush_all() {
        if !past_threshold(&engine, rule, &event) {
            continue;
        }
        let connection = event.src_addr[0].to_be_bytes()[3];
        let sid = rule.imported.as_ref().map_or(0, |i| i.sid);
        match ended.iter_mut().find(|(n, _)| *n == connection) {
            Some((_, got)) => got.push(sid),
            None => wrong.push(format!(
                "end {connection}: unknown connection alerted {sid}"
            )),
        }
    }
    for ((n, want), (_, got)) in ends.iter().zip(ended.iter_mut()) {
        got.sort_unstable();
        if got != want {
            wrong.push(format!("end {n}: got {got:?}, Suricata {want:?}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "differs from Suricata:\n{}",
        wrong.join("\n")
    );
}
