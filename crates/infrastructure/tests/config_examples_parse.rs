#![allow(clippy::panic)]
// Regression guard: every shipped config under `config/` must parse and
// validate through the real loader, so docs, examples and the host profiles
// the packages install can never drift into a state that fails
// `ebpfsentinel-agent --config`.
use infrastructure::config::AgentConfig;

fn yaml_files_in(dir: &str) -> Vec<std::path::PathBuf> {
    let mut ents: Vec<_> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("{dir}: {e}"))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "yaml"))
        .collect();
    ents.sort();
    ents
}

#[test]
fn parse_all_examples() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../config");
    let mut files: Vec<std::path::PathBuf> = vec![std::path::PathBuf::from(format!(
        "{root}/ebpfsentinel.yaml"
    ))];
    files.extend(yaml_files_in(&format!("{root}/examples")));

    // The three host profiles are shipped in the packages and in the tarball
    // and are meant to be copied over the configuration as they are, so a
    // profile that does not load is worse than an example that does not.
    let profiles = yaml_files_in(&format!("{root}/profiles"));
    assert!(
        profiles.len() >= 3,
        "the host profiles are missing from {root}/profiles"
    );
    files.extend(profiles);

    let mut fails = Vec::new();
    for f in &files {
        let yaml = std::fs::read_to_string(f).unwrap();
        match AgentConfig::from_yaml(&yaml) {
            Ok(_) => println!("OK   {}", f.file_name().unwrap().to_string_lossy()),
            Err(e) => {
                let name = f.file_name().unwrap().to_string_lossy().to_string();
                println!("FAIL {name}: {e}");
                fails.push(name);
            }
        }
    }
    assert!(fails.is_empty(), "examples failed to parse: {fails:?}");
}

/// Every configuration a suite hands the agent names only keys the agent
/// knows.
///
/// The fixtures carry `__NAME__` placeholders the provisioner fills in at run
/// time, some in places a number or a list goes, so a full load here would be
/// holding the loader to a file that never exists. What is checked is the one
/// thing a placeholder cannot change: a key the schema does not have. Every
/// nested section refuses one, so a typo in a fixture is a suite that tests a
/// default rather than the rule it was written for.
#[test]
fn every_integration_fixture_names_only_known_keys() {
    let dir = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/integration/fixtures"
    );
    let files = yaml_files_in(dir);
    assert!(!files.is_empty(), "no fixtures under {dir}");
    let mut fails = Vec::new();
    for f in &files {
        let yaml = std::fs::read_to_string(f).unwrap();
        if let Err(e) = serde_norway::from_str::<AgentConfig>(&yaml) {
            let message = e.to_string();
            if message.contains("unknown field") {
                let name = f.file_name().unwrap().to_string_lossy().to_string();
                fails.push(format!("{name}: {message}"));
            }
        }
    }
    assert!(fails.is_empty(), "fixtures naming unknown keys: {fails:#?}");
}

/// The configurations a suite writes from a heredoc, held to the same rule.
///
/// Those files are never on disk outside a VM run, so nothing else reads them
/// before the agent does. Most of them are sections appended to a prepared
/// configuration rather than whole files, so a body whose first key sits at
/// the top level is read as a document, given an `agent:` stub when it has
/// none. The marker is the word after `<<`, quoted or not.
#[test]
fn every_suite_heredoc_config_names_only_known_keys() {
    let dir = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/integration/suites"
    );
    let mut sources: Vec<_> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("{dir}: {e}"))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "bats" || x == "bash"))
        .collect();
    sources.sort();
    let mut checked = 0;
    let mut fails = Vec::new();
    for source in &sources {
        let text = std::fs::read_to_string(source).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        let mut index = 0;
        while index < lines.len() {
            let Some(marker) = heredoc_marker(lines[index]) else {
                index += 1;
                continue;
            };
            let start = index + 1;
            let mut end = start;
            while end < lines.len() && lines[end].trim() != marker {
                end += 1;
            }
            let body = lines[start..end.min(lines.len())].join("\n");
            if let Some((first_key, document)) = as_agent_document(&body) {
                checked += 1;
                if let Err(e) = serde_norway::from_str::<AgentConfig>(&document) {
                    let message = e.to_string();
                    // A body whose very first key is not a section is some
                    // other YAML the suite writes (a rule template, a
                    // manifest), not a configuration.
                    let not_a_config = message.contains(&format!("unknown field `{first_key}`"))
                        && message.contains("expected one of `agent`");
                    if message.contains("unknown field") && !not_a_config {
                        let name = source.file_name().unwrap().to_string_lossy().to_string();
                        fails.push(format!("{name}:{}: {message}", start + 1));
                    }
                }
            }
            index = end + 1;
        }
    }
    assert!(
        checked > 0,
        "no suite heredoc carries an agent configuration"
    );
    assert!(
        fails.is_empty(),
        "suite configs naming unknown keys: {fails:#?}"
    );
}

/// The marker a line opens a heredoc with, if it opens one.
fn heredoc_marker(line: &str) -> Option<String> {
    let (_, rest) = line.split_once("<<")?;
    let word: String = rest
        .trim_start_matches('-')
        .trim_start()
        .trim_start_matches(['\'', '"'])
        .chars()
        .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '_')
        .collect();
    (!word.is_empty()).then_some(word)
}

/// A heredoc body as an agent document with its first key, if that key sits
/// at the top level.
fn as_agent_document(body: &str) -> Option<(String, String)> {
    let first = body
        .lines()
        .find(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))?;
    let key = first
        .strip_suffix(':')
        .or_else(|| first.split_once(": ").map(|(k, _)| k))?;
    if key.is_empty() || !key.chars().all(|c| c.is_ascii_lowercase() || c == '_') {
        return None;
    }
    if body.lines().any(|l| l.starts_with("agent:")) {
        Some((key.to_string(), body.to_string()))
    } else {
        Some((
            key.to_string(),
            format!("agent:\n  interfaces: [eth0]\n{body}"),
        ))
    }
}
