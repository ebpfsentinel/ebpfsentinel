//! The signature parser loads the rules a real Suricata loads.
//!
//! `fixtures/suricata/probes.rules` holds one aspect of a keyword per rule;
//! `verdicts.txt` beside it is what Suricata 8.0.8 did with each, written by
//! `make-verdicts.sh`. A rule Suricata loads is never refused here. A rule
//! Suricata refuses is refused here too, except the few listed in `LENIENT`,
//! where the refusal rests on state the parser does not model.

use std::collections::BTreeMap;

use domain::ids::sig::parse_signature;
use domain::ids::suricata::SuricataVars;

const PROBES: &str = include_str!("fixtures/suricata/probes.rules");
const VERDICTS: &str = include_str!("fixtures/suricata/verdicts.txt");

/// Refused by Suricata, loaded here, with the reason.
const LENIENT: &[(&str, &str)] = &[
    (
        "1006",
        "'=>' needs a response buffer; which buffers belong to the response is known once the application parsers expose them",
    ),
    (
        "1115",
        "the parser does not compile PCRE: the regex crate would refuse lookarounds and backreferences Suricata loads",
    ),
    (
        "1252",
        "event names are checked against the decoder's own event table, not the parser's",
    ),
];

fn probe_id(line_number: usize, rule: &str) -> String {
    rule.find("sid:")
        .and_then(|at| {
            let rest = &rule[at + 4..];
            let end = rest.find(';')?;
            let sid = &rest[..end];
            sid.bytes()
                .all(|b| b.is_ascii_digit())
                .then(|| sid.to_owned())
        })
        .unwrap_or_else(|| format!("line:{line_number}"))
}

#[test]
fn the_parser_loads_what_suricata_loads() {
    let verdicts: BTreeMap<&str, bool> = VERDICTS
        .lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .map(|line| {
            let (id, verdict) = line
                .split_once(' ')
                .expect("a verdict line is id and verdict");
            (id, verdict == "loaded")
        })
        .collect();
    let vars = SuricataVars::default();
    let mut wrong = Vec::new();
    let mut seen = 0;
    for (index, rule) in PROBES.lines().enumerate() {
        let trimmed = rule.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        seen += 1;
        let id = probe_id(index + 1, rule);
        let loads = *verdicts
            .get(id.as_str())
            .unwrap_or_else(|| panic!("probe {id} has no verdict: rerun make-verdicts.sh"));
        let parsed = parse_signature(rule, &vars);
        let lenient = LENIENT.iter().any(|(sid, _)| *sid == id);
        match (&parsed, loads) {
            (Ok(_), true) | (Err(_), false) => {
                assert!(
                    !lenient,
                    "probe {id} is listed as lenient but agrees with Suricata"
                );
            }
            (Ok(_), false) if lenient => {}
            (Ok(_), false) => wrong.push(format!("{id}: Suricata refuses, parsed: {rule}")),
            (Err(refused), true) => wrong.push(format!(
                "{id}: Suricata loads, refused on {}: {}: {rule}",
                refused.keyword, refused.reason
            )),
        }
    }
    assert_eq!(seen, verdicts.len(), "every verdict has its probe");
    assert!(
        wrong.is_empty(),
        "{} disagreements:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}
