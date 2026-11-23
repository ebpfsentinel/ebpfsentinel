//! The inspection engine against a real Suricata: every case of
//! `fixtures/suricata/inspect.cases`, as `make-inspect-verdicts.py` recorded
//! Suricata's verdict on it, must get the same verdict here, and a rule
//! Suricata refuses to load must be refused here.

use domain::ids::engine::IdsEngine;
use domain::ids::sig::inspect::Program;
use domain::ids::sig::parse_signature;
use domain::ids::suricata::{SuricataVars, compile_ruleset};
use ebpf_common::event::{EVENT_TYPE_IDS, PacketEvent};

const VERDICTS: &str = include_str!("fixtures/suricata/inspect-verdicts.txt");

struct Case {
    sid: String,
    header: bool,
    refused: bool,
    options: String,
    buffers: Vec<(String, bool, Vec<u8>)>,
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex buffer"))
        .collect()
}

fn cases() -> Vec<Case> {
    let mut cases: Vec<Case> = Vec::new();
    for line in VERDICTS.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("rule ") {
            let mut parts = rest.splitn(3, ' ');
            let sid = parts.next().expect("sid").to_string();
            let kind = parts.next().expect("kind");
            let options = parts.next().expect("options").to_string();
            cases.push(Case {
                sid,
                header: kind == "hdr",
                refused: kind == "refused",
                options,
                buffers: Vec::new(),
            });
            continue;
        }
        let mut parts = line.split(' ');
        let (sid, number, verdict, bytes) = (
            parts.next().expect("sid"),
            parts.next().expect("number"),
            parts.next().expect("verdict"),
            parts.next().unwrap_or(""),
        );
        let case = cases.last_mut().expect("a payload under a rule");
        assert_eq!(case.sid, sid, "payload line under another rule");
        case.buffers
            .push((number.to_string(), verdict == "match", hex(bytes)));
    }
    cases
}

fn program(case: &Case) -> Result<Program, String> {
    let text = format!(
        "alert tcp any any -> any 80 (msg:\"case {}\"; {} sid:{};)",
        case.sid, case.options, case.sid
    );
    let signature = parse_signature(&text, &SuricataVars::default())
        .map_err(|r| format!("{}: {}", r.keyword, r.reason))?;
    Program::compile(&signature).map_err(|r| format!("{}: {}", r.keyword, r.reason))
}

#[test]
fn the_engine_decides_what_suricata_decides() {
    let cases = cases();
    assert!(cases.len() > 150, "the verdict file lost its cases");
    let mut wrong = Vec::new();
    for case in &cases {
        let compiled = program(case);
        if case.refused {
            if compiled.is_ok() {
                wrong.push(format!("{}: Suricata refuses it, loaded here", case.sid));
            }
            continue;
        }
        let program = match compiled {
            Ok(program) => program,
            Err(why) => {
                wrong.push(format!(
                    "{}: Suricata loads it, refused here: {why}",
                    case.sid
                ));
                continue;
            }
        };
        for (number, expected, bytes) in &case.buffers {
            let got = if case.header {
                program.matches_with(b"x", &|name| {
                    (name == "tcp.hdr").then_some(bytes.as_slice())
                })
            } else {
                program.matches(bytes)
            };
            if got != *expected {
                wrong.push(format!(
                    "{} payload {number}: Suricata {}, here {}",
                    case.sid,
                    if *expected {
                        "matches"
                    } else {
                        "does not match"
                    },
                    if got { "matches" } else { "does not match" },
                ));
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "{} disagreements:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// Every case loaded into one engine, as a ruleset is: the fast-pattern
/// prefilter in front of the programs drops no rule a payload matches.
#[test]
fn the_prefilter_loses_no_match() {
    // A ruleset also refuses a rule that runs on the port alone and one
    // reading `dsize`, which the program would run.
    let rule = |c: &Case| {
        format!(
            "alert tcp any any -> any 80 (msg:\"case {}\"; {} sid:{};)\n",
            c.sid, c.options, c.sid
        )
    };
    let vars = SuricataVars::default();
    let cases: Vec<Case> = cases()
        .into_iter()
        .filter(|c| !c.refused && !c.header)
        .filter(|c| compile_ruleset(&rule(c), &vars).report.compiled == 1)
        .collect();
    assert!(cases.len() > 100, "the ruleset lost its cases");
    let text: String = cases.iter().map(rule).collect();
    let compiled = compile_ruleset(&text, &vars);
    assert_eq!(compiled.report.compiled, cases.len());
    let mut engine = IdsEngine::new();
    engine.reload(compiled.rules).expect("the cases load");
    let event = PacketEvent {
        timestamp_ns: 1,
        src_addr: [0x0A00_0001, 0, 0, 0],
        dst_addr: [0x0A00_0002, 0, 0, 0],
        src_port: 40000,
        dst_port: 80,
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
    };
    let mut wrong = Vec::new();
    for case in &cases {
        for (number, expected, bytes) in &case.buffers {
            if bytes.is_empty() {
                continue;
            }
            // Suricata read each payload as one segment met midstream, so
            // every rule is read on the packet.
            let packet = tcp_segment(bytes);
            let hits = engine.evaluate_packet(&event, &packet, None);
            let hit = hits.iter().any(|(_, rule)| {
                rule.imported
                    .as_ref()
                    .is_some_and(|i| i.sid.to_string() == case.sid)
            });
            if hit != *expected {
                wrong.push(format!(
                    "{} payload {number}: expected {expected}",
                    case.sid
                ));
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "{} disagreements:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// An IPv4 TCP segment from 10.0.0.1:40000 to 10.0.0.2:80, acknowledging and
/// pushing `payload`.
fn tcp_segment(payload: &[u8]) -> Vec<u8> {
    let total = u16::try_from(40 + payload.len()).expect("a payload fits one packet");
    let mut bytes = vec![0x45, 0];
    bytes.extend_from_slice(&total.to_be_bytes());
    bytes.extend_from_slice(&[0, 1, 0x40, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2]);
    bytes.extend_from_slice(&40000u16.to_be_bytes());
    bytes.extend_from_slice(&80u16.to_be_bytes());
    bytes.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 1, 0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0]);
    bytes.extend_from_slice(payload);
    bytes
}
