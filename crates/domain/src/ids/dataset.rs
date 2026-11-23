//! The sets Suricata's `dataset` and `datarep` keywords look a buffer up in.
//!
//! A set is named by the configuration, with its type and the file its
//! values are read from, or created empty by the first rule that names it
//! with a type. Values live for as long as the rules that share them: a set
//! a rule fills is empty again once the rules are reloaded, and nothing is
//! written back to a file.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};

use super::sig::inspect::{base64, sextet};
use super::sig::model::DatasetMatch;

/// What a set holds, as Suricata's `type` names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetKind {
    /// Any bytes, written base64 in a file.
    String,
    /// The 16 bytes of an MD5 digest, written in hex.
    Md5,
    /// The 32 bytes of a SHA-256 digest, written in hex.
    Sha256,
}

impl SetKind {
    /// The kind a configuration or a rule names, `None` for any other
    /// name, the address kinds included.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "string" => Some(Self::String),
            "md5" => Some(Self::Md5),
            "sha256" => Some(Self::Sha256),
            _ => None,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Md5 => "md5",
            Self::Sha256 => "sha256",
        }
    }

    /// The length every value has, for a digest.
    const fn width(self) -> Option<usize> {
        match self {
            Self::String => None,
            Self::Md5 => Some(16),
            Self::Sha256 => Some(32),
        }
    }

    /// One value as a file writes it.
    fn decode(self, text: &str) -> Option<Vec<u8>> {
        match self {
            Self::String => strict_base64(text.as_bytes()),
            Self::Md5 | Self::Sha256 => {
                let width = self.width()?;
                if text.len() != width * 2 {
                    return None;
                }
                (0..width)
                    .map(|i| u8::from_str_radix(text.get(i * 2..i * 2 + 2)?, 16).ok())
                    .collect()
            }
        }
    }
}

/// Base64 as a set file holds it: groups of four, padded.
fn strict_base64(text: &[u8]) -> Option<Vec<u8>> {
    if text.is_empty() || !text.len().is_multiple_of(4) {
        return None;
    }
    let body = text.len()
        - text
            .iter()
            .rev()
            .take(2)
            .take_while(|&&c| c == b'=')
            .count();
    if !text[..body].iter().all(|&c| sextet(c).is_some()) {
        return None;
    }
    Some(base64(text, false))
}

#[derive(Debug)]
struct Set {
    kind: SetKind,
    /// Each value and its reputation, 0 where the file gives none.
    values: HashMap<Vec<u8>, u64>,
}

impl Set {
    fn new(kind: SetKind) -> Self {
        Self {
            kind,
            values: HashMap::new(),
        }
    }

    /// Reads a file's lines, as Suricata does: the first line says whether
    /// every line carries a reputation after a comma; a line that does not
    /// decode is skipped, and one that changes that answer ends the file.
    fn load(&mut self, text: &str) -> Vec<String> {
        let mut warnings = Vec::new();
        let mut reputation = None;
        for (n, line) in text.lines().enumerate() {
            let line = line.trim_end_matches('\r');
            if line.is_empty() {
                continue;
            }
            let (value, score) = match line.split_once(',') {
                Some((v, s)) => (v, Some(s)),
                None => (line, None),
            };
            let with = score.is_some();
            if *reputation.get_or_insert(with) != with {
                warnings.push(format!(
                    "line {}: a value with and one without a reputation; the lines from here are not read",
                    n + 1
                ));
                break;
            }
            let Some(bytes) = self.kind.decode(value) else {
                warnings.push(format!("line {}: not a {} value", n + 1, self.kind.name()));
                continue;
            };
            let rep = match score.map(str::parse::<u64>) {
                None => 0,
                Some(Ok(r)) => r,
                Some(Err(_)) => {
                    warnings.push(format!("line {}: not a reputation", n + 1));
                    continue;
                }
            };
            self.values.insert(bytes, rep);
        }
        warnings
    }
}

/// A set shared by the rules that name it.
#[derive(Clone)]
pub struct SetRef(Arc<Mutex<Set>>);

impl fmt::Debug for SetRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SetRef")
    }
}

impl SetRef {
    fn set(&self) -> std::sync::MutexGuard<'_, Set> {
        // A set is a map of values: an insert cut short leaves it valid.
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Runs one keyword over a buffer's bytes.
    #[must_use]
    pub fn run(&self, command: Command, value: &[u8]) -> bool {
        let mut set = self.set();
        match command {
            Command::IsSet => set.values.contains_key(value),
            Command::IsNotSet => !set.values.contains_key(value),
            Command::Set => {
                if set.kind.width().is_some_and(|w| w != value.len()) {
                    return false;
                }
                if set.values.contains_key(value) {
                    return false;
                }
                set.values.insert(value.to_vec(), 0);
                true
            }
            Command::Unset => set.values.remove(value).is_some(),
            Command::Reputation(op, score) => set.values.get(value).is_some_and(|&rep| match op {
                RepOp::Lt => rep < score,
                RepOp::Gt => rep > score,
                RepOp::Eq => rep == score,
            }),
        }
    }
}

/// How `datarep` compares a value's reputation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepOp {
    Lt,
    Gt,
    Eq,
}

/// What a `dataset` or `datarep` keyword does with the buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    IsSet,
    IsNotSet,
    /// Adds the value, matching only when it was not there.
    Set,
    /// Removes the value, matching only when it was there.
    Unset,
    Reputation(RepOp, u64),
}

#[derive(Debug)]
enum Entry {
    /// Named by the configuration, its file read.
    Configured(SetRef),
    /// Named by the configuration, its file not readable: the reason.
    Unavailable(String),
    /// Created by a rule naming its type.
    Created(SetRef),
}

/// The sets a ruleset's rules share, by name.
#[derive(Clone, Default)]
pub struct Datasets(Arc<Mutex<HashMap<String, Entry>>>);

impl fmt::Debug for Datasets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Datasets")
    }
}

impl PartialEq for Datasets {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for Datasets {}

impl Datasets {
    fn sets(&self) -> std::sync::MutexGuard<'_, HashMap<String, Entry>> {
        // Each entry is written whole: a poisoned map is still a valid one.
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Names a set with its kind and its file's text, or the reason the
    /// file could not be read, which every rule naming the set is then
    /// refused with. Returns what was skipped in the file.
    pub fn configure(&self, name: &str, kind: SetKind, text: Result<&str, String>) -> Vec<String> {
        let (entry, warnings) = match text {
            Ok(text) => {
                let mut set = Set::new(kind);
                let warnings = set.load(text);
                (
                    Entry::Configured(SetRef(Arc::new(Mutex::new(set)))),
                    warnings,
                )
            }
            Err(reason) => (Entry::Unavailable(reason), Vec::new()),
        };
        self.sets().insert(name.to_string(), entry);
        warnings
    }

    /// The set and the command a rule's keyword runs, or why the rule is
    /// refused.
    ///
    /// # Errors
    ///
    /// The reason, as Suricata refuses the rule or because the agent does
    /// not read what it names.
    pub fn resolve(&self, m: &DatasetMatch) -> Result<(SetRef, Command), String> {
        let command = command(m)?;
        let mut kind = None;
        let mut load = None;
        for (key, arg) in &m.options {
            match key.as_str() {
                "type" => {
                    kind = Some(SetKind::from_name(arg).ok_or_else(|| {
                        "names a set of addresses, read through ip.src and ip.dst, which the agent does not inspect".to_string()
                    })?);
                }
                "load" => load = Some(arg.as_str()),
                "memcap" | "hashsize" => {}
                "save" | "state" => {
                    return Err(format!(
                        "'{key}' writes the set to a file, which the agent does not do"
                    ));
                }
                other => return Err(format!("'{other}' is not read by the agent")),
            }
        }
        let mut sets = self.sets();
        let set = match sets.get(&m.name) {
            Some(Entry::Unavailable(reason)) => {
                return Err(format!("set '{}' is not available: {reason}", m.name));
            }
            Some(Entry::Configured(set)) => set.clone(),
            Some(Entry::Created(set)) => {
                if let Some(load) = load {
                    return Err(not_configured(&m.name, load));
                }
                set.clone()
            }
            None => {
                if let Some(load) = load {
                    return Err(not_configured(&m.name, load));
                }
                let Some(kind) = kind else {
                    return Err(format!(
                        "set '{}' is not defined: the configuration names it, or a rule gives its type",
                        m.name
                    ));
                };
                let set = SetRef(Arc::new(Mutex::new(Set::new(kind))));
                sets.insert(m.name.clone(), Entry::Created(set.clone()));
                set
            }
        };
        let actual = set.set().kind;
        if let Some(kind) = kind
            && kind != actual
        {
            return Err(format!("set '{}' is of type {}", m.name, actual.name()));
        }
        Ok((set, command))
    }
}

fn not_configured(name: &str, load: &str) -> String {
    format!(
        "set '{name}' loads '{load}', and the agent reads a set's file only where the configuration names the set"
    )
}

fn command(m: &DatasetMatch) -> Result<Command, String> {
    Ok(match m.command.as_str() {
        "isset" => Command::IsSet,
        "isnotset" => Command::IsNotSet,
        "set" => Command::Set,
        "unset" => Command::Unset,
        rep => {
            let (op, score) = if let Some(s) = rep.strip_prefix("==") {
                (RepOp::Eq, s)
            } else if let Some(s) = rep.strip_prefix('<') {
                (RepOp::Lt, s)
            } else if let Some(s) = rep.strip_prefix('>') {
                (RepOp::Gt, s)
            } else {
                return Err(format!("'{rep}' is not a {} command", m.keyword));
            };
            let score = score
                .parse()
                .map_err(|_| format!("'{score}' is not a reputation"))?;
            Command::Reputation(op, score)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keyword(command: &str, name: &str, options: &[(&str, &str)]) -> DatasetMatch {
        DatasetMatch {
            keyword: "dataset".into(),
            command: command.into(),
            name: name.into(),
            options: options
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
        }
    }

    #[test]
    fn a_file_is_read_as_suricata_reads_it() {
        let sets = Datasets::default();
        let warnings = sets.configure(
            "s",
            SetKind::String,
            Ok("# comment\nZXhhbXBsZS5jb20=\n\nZXZpbC50ZXN0\ndW5wYWRkZWQueA\n"),
        );
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        let (set, cmd) = sets.resolve(&keyword("isset", "s", &[])).expect("resolves");
        assert!(set.run(cmd, b"example.com"));
        assert!(set.run(cmd, b"evil.test"));
        assert!(!set.run(cmd, b"unpadded.x"));
        assert!(!set.run(cmd, b"EXAMPLE.COM"));
    }

    #[test]
    fn a_file_mixing_reputations_stops_where_they_change() {
        let sets = Datasets::default();
        sets.configure(
            "r",
            SetKind::String,
            Ok("ZXhhbXBsZS5jb20=,5\nZXZpbC50ZXN0\nYWZ0ZXIubWl4,9\n"),
        );
        let (set, _) = sets.resolve(&keyword("isset", "r", &[])).expect("resolves");
        assert!(set.run(Command::Reputation(RepOp::Eq, 5), b"example.com"));
        assert!(!set.run(Command::IsSet, b"evil.test"));
        assert!(!set.run(Command::IsSet, b"after.mix"));
    }

    #[test]
    fn a_set_the_configuration_cannot_read_refuses_its_rules() {
        let sets = Datasets::default();
        sets.configure("gone", SetKind::Md5, Err("no such file".into()));
        let reason = sets
            .resolve(&keyword("isset", "gone", &[]))
            .expect_err("refused");
        assert!(reason.contains("no such file"), "{reason}");
    }

    #[test]
    fn a_rule_loading_a_file_the_configuration_does_not_name_is_refused() {
        let sets = Datasets::default();
        let reason = sets
            .resolve(&keyword(
                "isset",
                "s",
                &[("type", "string"), ("load", "s.lst")],
            ))
            .expect_err("refused");
        assert!(reason.contains("configuration names the set"), "{reason}");
    }

    #[test]
    fn a_set_is_defined_by_the_configuration_or_a_type() {
        let sets = Datasets::default();
        assert!(sets.resolve(&keyword("isset", "s", &[])).is_err());
        let (set, cmd) = sets
            .resolve(&keyword("set", "s", &[("type", "string")]))
            .expect("created");
        assert!(set.run(cmd, b"a"));
        assert!(!set.run(cmd, b"a"));
        let (again, isset) = sets.resolve(&keyword("isset", "s", &[])).expect("defined");
        assert!(again.run(isset, b"a"));
        assert!(
            sets.resolve(&keyword("isset", "s", &[("type", "md5")]))
                .is_err()
        );
        assert!(
            sets.resolve(&keyword("isset", "a", &[("type", "ipv4")]))
                .is_err()
        );
        assert!(
            sets.resolve(&keyword("isset", "s", &[("state", "s.lst")]))
                .is_err()
        );
    }

    #[test]
    fn a_digest_set_holds_raw_digests() {
        let sets = Datasets::default();
        sets.configure(
            "m",
            SetKind::Md5,
            Ok("5ababd603b22780302dd8d83498e5172\nzz\n"),
        );
        let (set, cmd) = sets.resolve(&keyword("isset", "m", &[])).expect("resolves");
        let digest: Vec<u8> = (0..16)
            .map(|i| {
                u8::from_str_radix(&"5ababd603b22780302dd8d83498e5172"[i * 2..i * 2 + 2], 16)
                    .expect("hex")
            })
            .collect();
        assert!(set.run(cmd, &digest));
        assert!(!set.run(Command::Set, b"short"));
    }
}
