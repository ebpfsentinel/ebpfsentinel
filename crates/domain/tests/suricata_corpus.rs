//! A published Suricata ruleset read whole through the signature parser.
//!
//! The ruleset is not committed: point `EBPFSENTINEL_SURICATA_RULES` at a
//! directory of `.rules` files (the ET Open build for Suricata 8 is the one
//! measured) and run `cargo test -p ebpfsentinel-domain --test suricata_corpus
//! -- --ignored --nocapture`. Every enabled rule that does not parse is printed
//! with the keyword and the reason; the test fails if any does.

use std::collections::BTreeMap;
use std::path::Path;

use domain::ids::sig::parse_signature;
use domain::ids::suricata::SuricataVars;

fn enabled_rules(dir: &Path) -> Vec<(String, String)> {
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .expect("the rules directory is readable")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "rules"))
        .collect();
    files.sort();
    let mut rules = Vec::new();
    for path in files {
        let text = std::fs::read_to_string(&path).expect("a rules file is UTF-8");
        let name = path
            .file_name()
            .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
        let mut pending = String::new();
        for line in text.lines() {
            let line = line.trim();
            if pending.is_empty() && (line.is_empty() || line.starts_with('#')) {
                continue;
            }
            if let Some(head) = line.strip_suffix('\\') {
                pending.push_str(head);
                continue;
            }
            pending.push_str(line);
            rules.push((name.clone(), std::mem::take(&mut pending)));
        }
    }
    rules
}

#[test]
#[ignore = "needs a Suricata ruleset on disk, named by EBPFSENTINEL_SURICATA_RULES"]
fn every_enabled_rule_parses() {
    let dir = std::env::var("EBPFSENTINEL_SURICATA_RULES")
        .expect("EBPFSENTINEL_SURICATA_RULES names a directory of .rules files");
    let rules = enabled_rules(Path::new(&dir));
    let vars = SuricataVars::default();
    let mut by_keyword: BTreeMap<String, usize> = BTreeMap::new();
    let mut failed = 0usize;
    for (file, rule) in &rules {
        if let Err(refused) = parse_signature(rule, &vars) {
            failed += 1;
            *by_keyword.entry(refused.keyword.clone()).or_default() += 1;
            println!(
                "{file} sid {:?}: {} {}",
                refused.sid, refused.keyword, refused.reason
            );
        }
    }
    println!(
        "{} rules, {} parsed, {failed} refused",
        rules.len(),
        rules.len() - failed
    );
    for (keyword, count) in &by_keyword {
        println!("  {keyword}: {count}");
    }
    assert_eq!(failed, 0, "every enabled rule parses");
}
