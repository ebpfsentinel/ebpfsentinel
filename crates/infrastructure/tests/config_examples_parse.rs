#![allow(clippy::panic, clippy::unwrap_used)]
// Regression guard: every shipped config under `config/` must parse and
// validate through the real loader, so docs, examples and the host profiles
// the packages install can never drift into a state that fails
// `ebpfsentinel-agent --config`.
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use infrastructure::config::AgentConfig;
use regex::Regex;
use serde_norway::Value;

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

/// What a suite's helper writes in place of each placeholder, as a value of
/// the type the key holding it takes.
const FIXTURE_PLACEHOLDERS: &[(&str, &str)] = &[
    ("__INTERFACE__", "eth1"),
    ("__IFACE__", "eth1"),
    ("__HOST_IP__", "10.200.0.1"),
    ("__NS_IP__", "10.200.0.2"),
    ("__GATEWAY__", "172.17.0.1"),
    ("__UPSTREAM__", "10.200.0.53:53"),
    ("__WHITELIST_SUBNET__", "10.200.0.0/24"),
    ("__PUBLISHED_PORT__", "8081"),
    ("__CERT_PATH__", "/etc/ebpfsentinel/tls/agent.crt"),
    ("__KEY_PATH__", "/etc/ebpfsentinel/tls/agent.key"),
    ("__JWT_PUBKEY__", "/etc/ebpfsentinel/jwt.pub"),
    ("__EBPF_DIR__", "/usr/local/lib/ebpfsentinel"),
    ("__CGROUP_ROOT__", "/sys/fs/cgroup"),
    ("__DOCKER_ROOT__", "/var/lib/docker"),
    ("__CURL__", "/usr/bin/curl"),
    ("__PYCOPY__", "/tmp/python3-copy"),
    ("__PYTHON__", "/usr/bin/python3"),
    ("__TIMEOUT__", "/usr/bin/timeout"),
    (
        "__PYMARK_HASH__",
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    ),
    ("__GOVERNED__", "governed"),
    ("__EXEC_MODE__", "observe"),
    ("__KILL__", "false"),
    ("__LABELS__", "true"),
    ("__RULES__", "[]"),
];

/// Every configuration a suite hands the agent loads whole: types, enum
/// spellings and the loader's own validation, once the placeholders hold
/// what the suite writes there.
///
/// Naming only known keys is not enough: a value of the wrong type, an enum
/// word the loader does not have or a rule its validation refuses leaves the
/// agent on a document that never boots, and the suite then tests nothing.
/// `config-invalid.yaml` is the one fixture written to be refused. The data
/// directory holds the ruleset the Suricata import suite writes there.
#[test]
fn every_integration_fixture_loads_whole() {
    let dir = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/integration/fixtures"
    );
    let data_dir = std::env::temp_dir().join(format!("fixtures-load-{}", std::process::id()));
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::write(
        data_dir.join("suite.rules"),
        "alert tcp any any -> any 4445 (msg:\"probe\"; content:\"PROBE\"; sid:9000001; rev:1;)\n",
    )
    .unwrap();
    let data_dir_text = data_dir.to_string_lossy().to_string();
    let mut fails = Vec::new();
    let mut loaded = 0;
    for f in yaml_files_in(dir) {
        let name = f.file_name().unwrap().to_string_lossy().to_string();
        let mut yaml = std::fs::read_to_string(&f).unwrap();
        if !yaml.lines().any(|l| l.starts_with("agent:")) {
            continue;
        }
        yaml = yaml.replace("__DATA_DIR__", &data_dir_text);
        for (placeholder, value) in FIXTURE_PLACEHOLDERS {
            yaml = yaml.replace(placeholder, value);
        }
        let result = AgentConfig::from_yaml(&yaml);
        if name == "config-invalid.yaml" {
            assert!(result.is_err(), "config-invalid.yaml loads");
            continue;
        }
        match result {
            Ok(_) => loaded += 1,
            Err(e) => fails.push(format!("{name}: {e}")),
        }
    }
    let _ = std::fs::remove_dir_all(&data_dir);
    assert!(loaded > 50, "only {loaded} fixtures loaded under {dir}");
    assert!(fails.is_empty(), "fixtures the agent refuses: {fails:#?}");
}

/// What serde reads off the configuration document: for each struct deriving
/// `Deserialize` under `src/config/`, each key under the name serde gives it,
/// with the type names its field declares. A `flatten` field, and each newtype
/// variant of an untagged enum, stands for the keys of the struct it names.
#[derive(Default)]
struct ConfigSchema {
    structs: BTreeMap<String, BTreeMap<String, SchemaField>>,
}

struct SchemaField {
    flatten: bool,
    types: Vec<String>,
}

/// Containers a field's type is seen through to the struct it holds.
const TYPE_WRAPPERS: &[&str] = &[
    "Option", "Vec", "Box", "Arc", "HashMap", "BTreeMap", "IndexMap", "HashSet", "BTreeSet",
];

impl ConfigSchema {
    fn read(dir: &Path) -> Self {
        let item = Regex::new(
            r"(?s)#\[derive\(([^)]*)\)\]((?:\s*#\[[^\]]*\]|\s*///[^\n]*)*)\s*pub struct (\w+)\s*\{(.*?)\n\}",
        )
        .unwrap();
        let untagged = Regex::new(
            r"(?s)#\[serde\([^)]*\buntagged\b[^)]*\)\]((?:\s*#\[[^\]]*\]|\s*///[^\n]*)*)\s*pub enum (\w+)\s*\{(.*?)\n\}",
        )
        .unwrap();
        let variant = Regex::new(r"^\w+\s*\(\s*([A-Za-z_]\w*)\s*\)\s*,?$").unwrap();
        let field = Regex::new(r"^pub(?:\([^)]*\))?\s+(?:r#)?(\w+)\s*:\s*(.+?),?$").unwrap();
        let rename_all = Regex::new(r#"rename_all\s*=\s*"([^"]+)""#).unwrap();
        let rename = Regex::new(r#"\brename\s*=\s*"([^"]+)""#).unwrap();
        let skip = Regex::new(r"\bskip\b|skip_deserializing").unwrap();
        let flatten = Regex::new(r"\bflatten\b").unwrap();
        let ident = Regex::new(r"[A-Za-z_]\w*").unwrap();

        let mut sources = Vec::new();
        rust_files_under(dir, &mut sources);
        sources.sort();
        let texts: Vec<String> = sources
            .iter()
            .map(|p| std::fs::read_to_string(p).unwrap())
            .collect();

        let mut schema = Self::default();
        for text in &texts {
            for caps in item.captures_iter(text) {
                if !caps[1].contains("Deserialize")
                    || rename_all
                        .captures(&caps[2])
                        .is_some_and(|r| &r[1] != "snake_case")
                {
                    continue;
                }
                let fields = schema.structs.entry(caps[3].to_string()).or_default();
                let mut pending = String::new();
                for raw in caps[4].split('\n') {
                    let line = raw.trim();
                    if line.starts_with("#[") {
                        pending.push_str(line);
                        continue;
                    }
                    if let Some(f) = field.captures(line) {
                        let serde = std::mem::take(&mut pending);
                        if skip.is_match(&serde) {
                            continue;
                        }
                        let types = ident
                            .find_iter(&f[2])
                            .map(|m| m.as_str())
                            .filter(|t| !TYPE_WRAPPERS.contains(t))
                            .map(ToString::to_string)
                            .collect();
                        let is_flatten = flatten.is_match(&serde);
                        let key = if is_flatten {
                            format!("<flatten {}>", &f[1])
                        } else {
                            rename
                                .captures(&serde)
                                .map_or_else(|| f[1].to_string(), |r| r[1].to_string())
                        };
                        fields.insert(
                            key,
                            SchemaField {
                                flatten: is_flatten,
                                types,
                            },
                        );
                    } else if !line.is_empty() && !line.starts_with("//") {
                        pending.clear();
                    }
                }
            }
        }
        for text in &texts {
            for caps in untagged.captures_iter(text) {
                let fields = schema.structs.entry(caps[2].to_string()).or_default();
                for raw in caps[3].split('\n') {
                    if let Some(v) = variant.captures(raw.trim()) {
                        fields.insert(
                            format!("<variant {}>", &v[1]),
                            SchemaField {
                                flatten: true,
                                types: vec![v[1].to_string()],
                            },
                        );
                    }
                }
            }
        }
        schema
    }

    /// Every `Struct.key` the loader reads.
    fn inventory(&self) -> BTreeSet<String> {
        self.structs
            .iter()
            .flat_map(|(name, fields)| {
                fields
                    .iter()
                    .filter(|(_, f)| !f.flatten)
                    .map(move |(key, _)| format!("{name}.{key}"))
            })
            .collect()
    }

    /// The keys a value of this type may carry, through flattens and variants.
    fn keys(&self, name: &str) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for (key, f) in self.structs.get(name).into_iter().flatten() {
            if !f.flatten {
                out.insert(key.clone());
                continue;
            }
            for t in f.types.iter().filter(|t| t.as_str() != name) {
                out.extend(self.keys(t));
            }
        }
        out
    }

    /// Records each `Struct.key` this value sets, read as the struct `name`.
    fn walk(&self, name: &str, value: &Value, seen: &mut BTreeSet<String>) {
        let (Some(fields), Value::Mapping(map)) = (self.structs.get(name), value) else {
            return;
        };
        for f in fields.values().filter(|f| f.flatten) {
            for t in &f.types {
                self.walk(t, value, seen);
            }
        }
        for (key, child) in map {
            let Some(key) = yaml_key(key) else { continue };
            let Some(f) = fields.get(&key).filter(|f| !f.flatten) else {
                continue;
            };
            seen.insert(format!("{name}.{key}"));
            for t in f.types.iter().filter(|t| self.structs.contains_key(*t)) {
                self.descend(t, child, seen);
            }
        }
    }

    /// A field's value: the struct itself, a list of it, or a map whose values
    /// are it.
    fn descend(&self, name: &str, value: &Value, seen: &mut BTreeSet<String>) {
        match value {
            Value::Sequence(items) => {
                for item in items {
                    self.descend(name, item, seen);
                }
            }
            Value::Mapping(map) => {
                let keys = self.keys(name);
                if map.is_empty() || map.keys().filter_map(yaml_key).any(|k| keys.contains(&k)) {
                    self.walk(name, value, seen);
                } else {
                    for item in map.values() {
                        self.descend(name, item, seen);
                    }
                }
            }
            _ => {}
        }
    }
}

fn yaml_key(key: &Value) -> Option<String> {
    match key {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn rust_files_under(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files_under(&path, out);
        } else if path.extension().is_some_and(|x| x == "rs") {
            out.push(path);
        }
    }
}

/// Keys no shipped configuration can show, each with why.
const KEYS_NO_EXAMPLE_SETS: &[(&str, &str)] = &[(
    "AgentConfig.enterprise",
    "read by the enterprise loader only, documented with the enterprise examples",
)];

/// Every key the loader reads is set by the default configuration, an
/// example or a host profile, so a reader looking for how a key is written
/// finds it in a file the agent is proven to load.
///
/// Each file is walked from `AgentConfig` along the types the fields declare,
/// so a key counts only where the loader would read it. A key no file sets
/// fails here; so does a line of the exemption list the files now cover.
#[test]
fn every_config_key_is_set_by_an_example() {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let schema = ConfigSchema::read(&crate_dir.join("src/config"));
    let inventory = schema.inventory();
    assert!(
        inventory.len() >= 700 && schema.structs.contains_key("AgentConfig"),
        "read {} keys: the scanner no longer reads the loader",
        inventory.len()
    );

    let root = crate_dir.join("../../config");
    let mut files = vec![root.join("ebpfsentinel.yaml")];
    for dir in ["examples", "profiles"] {
        files.extend(yaml_files_in(&root.join(dir).to_string_lossy()));
    }
    let mut seen = BTreeSet::new();
    for f in &files {
        let doc: Value = serde_norway::from_str(&std::fs::read_to_string(f).unwrap())
            .unwrap_or_else(|e| panic!("{}: {e}", f.display()));
        schema.walk("AgentConfig", &doc, &mut seen);
    }

    let exempt: BTreeSet<String> = KEYS_NO_EXAMPLE_SETS
        .iter()
        .map(|(k, _)| (*k).to_string())
        .collect();
    let unset: Vec<_> = inventory
        .iter()
        .filter(|k| !seen.contains(*k) && !exempt.contains(*k))
        .collect();
    let stale: Vec<_> = exempt
        .iter()
        .filter(|k| seen.contains(*k) || !inventory.contains(*k))
        .collect();
    assert!(
        unset.is_empty(),
        "keys no example under config/ sets: {unset:#?}"
    );
    assert!(
        stale.is_empty(),
        "exempt keys an example now sets or the loader no longer has: {stale:#?}"
    );
}
