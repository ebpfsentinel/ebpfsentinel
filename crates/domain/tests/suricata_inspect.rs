//! The inspection engine against a real Suricata: every case of
//! `fixtures/suricata/inspect.cases`, as `make-inspect-verdicts.py` recorded
//! Suricata's verdict on it, must get the same verdict here, and a rule
//! Suricata refuses to load must be refused here.

use domain::ids::sig::inspect::Program;
use domain::ids::sig::parse_signature;
use domain::ids::suricata::SuricataVars;

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
