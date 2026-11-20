//! Every leaf of a command line is run by an integration suite, or listed.
//!
//! A surface gate (meta `docs/COVERAGE.md`). The inventory is the clap tree
//! itself: every subcommand with no subcommand of its own, hidden ones and
//! clap's `help` aside, named by its path (`nat nptv6 list`). The evidence is
//! a suite line that runs the binary: a marker naming it (the binary's name,
//! or the variable a suite holds its path in) followed by the words of the
//! leaf, read through the same tree so a flag's value is never taken for a
//! subcommand. The OSS agent and the enterprise agent run the same gate
//! against their own trees and suites.
//!
//! What no suite line shows carries a line in the tree's manifest, one table
//! per leaf (`["nat nptv6 list"]`) with exactly one of `suites` (the suites
//! that run it through a helper the scan cannot follow, each of which must
//! still name the leaf's last word), `reason` or `gap`; the number of `gap`
//! lines equals the top-level `gap_ceiling`.

use std::collections::{BTreeMap, BTreeSet};

use clap::Command;

/// The leaves of a command line, each as the words that reach it.
#[must_use]
pub fn leaves(command: &Command) -> BTreeSet<String> {
    let mut built = command.clone();
    built.build();
    let mut out = BTreeSet::new();
    walk(&built, &mut Vec::new(), &mut out);
    out
}

fn walk(command: &Command, path: &mut Vec<String>, out: &mut BTreeSet<String>) {
    let children: Vec<&Command> = command
        .get_subcommands()
        .filter(|c| !c.is_hide_set() && c.get_name() != "help")
        .collect();
    if children.is_empty() {
        if !path.is_empty() {
            out.insert(path.join(" "));
        }
        return;
    }
    for child in children {
        path.push(child.get_name().to_string());
        walk(child, path, out);
        path.pop();
    }
}

/// The leaves a shell text runs: every line that names one of `markers`
/// (comment lines aside, continuation lines joined) is read word by word
/// through the tree, up to the first shell operator.
#[must_use]
pub fn invoked(command: &Command, markers: &[&str], text: &str) -> BTreeSet<String> {
    let mut built = command.clone();
    built.build();
    let mut out = BTreeSet::new();
    for line in logical_lines(text) {
        for marker in markers {
            let mut from = 0;
            while let Some(at) = line[from..].find(marker) {
                let start = from + at;
                let end = start + marker.len();
                from = end;
                let before = line[..start].chars().next_back();
                let after = line[end..].chars().next();
                let word = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '-';
                if before.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
                    || after.is_some_and(word)
                {
                    continue;
                }
                if let Some(leaf) = read_through(&built, &line[end..]) {
                    out.insert(leaf);
                }
            }
        }
    }
    out
}

fn logical_lines(text: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for raw in text.lines() {
        if raw.trim_start().starts_with('#') {
            continue;
        }
        if let Some(head) = raw.trim_end().strip_suffix('\\') {
            current.push_str(head);
            current.push(' ');
            continue;
        }
        current.push_str(raw);
        lines.push(std::mem::take(&mut current));
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

/// The leaf the words after a marker reach, if they reach one.
fn read_through(root: &Command, rest: &str) -> Option<String> {
    let rest = rest.trim_start_matches(['}', '"', '\'']);
    let cut = rest
        .find(['|', ';', '&', ')', '>', '<', '`'])
        .unwrap_or(rest.len());
    let words: Vec<String> = rest[..cut]
        .split_whitespace()
        .map(|w| w.trim_matches(['"', '\'']).to_string())
        .collect();
    let mut node = root;
    let mut path = Vec::new();
    let mut words = words.iter().peekable();
    while let Some(word) = words.next() {
        if let Some(flag) = word.strip_prefix('-') {
            if flag.contains('=') {
                continue;
            }
            let takes_value = node.get_arguments().any(|arg| {
                let named = match flag.strip_prefix('-') {
                    Some(long) => arg.get_long() == Some(long),
                    None => flag.chars().count() == 1 && arg.get_short() == flag.chars().next(),
                };
                named && arg.get_action().takes_values()
            });
            if takes_value {
                words.next();
            }
            continue;
        }
        match node.find_subcommand(word) {
            Some(child) if child.get_name() != "help" => {
                path.push(child.get_name().to_string());
                node = child;
            }
            _ => break,
        }
    }
    let children = node
        .get_subcommands()
        .any(|c| !c.is_hide_set() && c.get_name() != "help");
    (!path.is_empty() && !children).then(|| path.join(" "))
}

/// One manifest line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Line {
    Suites(Vec<String>),
    Reason(String),
    Gap(String),
}

/// A manifest: its `gap_ceiling` and one line per leaf.
#[derive(Debug, Default)]
pub struct Manifest {
    pub gap_ceiling: Option<usize>,
    pub lines: BTreeMap<String, Line>,
}

/// Reads a manifest: a top-level `gap_ceiling = N`, then `["<leaf>"]` tables
/// of exactly one `suites = ["N", ...]`, `reason = "..."` or `gap = "..."`.
///
/// # Errors
///
/// Every line that is not one of those, and every table that does not carry
/// exactly one of the three, each named with its line number.
pub fn read_manifest(name: &str, text: &str) -> Result<Manifest, Vec<String>> {
    let mut manifest = Manifest::default();
    let mut errors = Vec::new();
    let mut tables: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    let mut current: Option<String> = None;
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let at = format!("{name}:{}", index + 1);
        if let Some(leaf) = line.strip_prefix("[\"").and_then(|l| l.strip_suffix("\"]")) {
            if tables.insert(leaf.to_string(), Vec::new()).is_some() {
                errors.push(format!("{at}: [\"{leaf}\"] appears twice"));
            }
            current = Some(leaf.to_string());
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            errors.push(format!("{at}: not a manifest line: {raw}"));
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        match &current {
            None if key == "gap_ceiling" => match value.parse() {
                Ok(n) => manifest.gap_ceiling = Some(n),
                Err(_) => errors.push(format!("{at}: gap_ceiling is not an integer")),
            },
            Some(leaf) => tables
                .entry(leaf.clone())
                .or_default()
                .push((key.to_string(), value.to_string())),
            None => errors.push(format!("{at}: not a manifest line: {raw}")),
        }
    }
    for (leaf, pairs) in tables {
        let line = match pairs.as_slice() {
            [(key, value)] if key == "suites" => strings(value).map(Line::Suites),
            [(key, value)] if key == "reason" => string(value).map(Line::Reason),
            [(key, value)] if key == "gap" => string(value).map(Line::Gap),
            _ => None,
        };
        match line {
            Some(Line::Suites(s)) if s.is_empty() => errors.push(format!(
                "{name}: [\"{leaf}\"]: suites names no suite"
            )),
            Some(line) => {
                manifest.lines.insert(leaf, line);
            }
            None => errors.push(format!(
                "{name}: [\"{leaf}\"]: carries exactly one of suites (a list), reason, gap (a sentence)"
            )),
        }
    }
    if errors.is_empty() {
        Ok(manifest)
    } else {
        Err(errors)
    }
}

fn string(value: &str) -> Option<String> {
    let inner = value.strip_prefix('"')?.strip_suffix('"')?;
    (!inner.trim().is_empty() && !inner.contains('"')).then(|| inner.to_string())
}

fn strings(value: &str) -> Option<Vec<String>> {
    let inner = value.strip_prefix('[')?.strip_suffix(']')?;
    inner
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(string)
        .collect()
}

/// What the gate counted, once it passes.
#[derive(Debug)]
pub struct Report {
    pub surfaces: usize,
    pub by_scan: usize,
    pub by_suite: usize,
    pub by_reason: usize,
    pub gaps: Vec<String>,
    pub gap_ceiling: usize,
}

impl Report {
    /// The summary line the meta runner collects.
    #[must_use]
    pub fn summary(&self, gate: &str) -> String {
        format!(
            "{gate}: {} surfaces, {} by scan, {} by suite, {} by reason, {} gaps (ceiling {})",
            self.surfaces,
            self.by_scan,
            self.by_suite,
            self.by_reason,
            self.gaps.len(),
            self.gap_ceiling
        )
    }
}

/// Crosses `surfaces` (the leaves of `command` the gate owns, all of them
/// or those an extension adds) with the suites and the manifest.
///
/// `suites` maps a suite's number to its text; `helpers` are the texts of
/// the libraries the suites source, whose lines count as runs too.
///
/// # Errors
///
/// Every leaf neither run nor listed, every line for a leaf the scan sees or
/// the tree no longer has, every `suites` line whose suite is missing or no
/// longer names the leaf, and a gap count other than `gap_ceiling`.
pub fn audit(
    command: &Command,
    surfaces: &BTreeSet<String>,
    markers: &[&str],
    suites: &BTreeMap<String, String>,
    helpers: &[String],
    manifest: &Manifest,
) -> Result<Report, Vec<String>> {
    let mut seen = BTreeSet::new();
    for text in suites.values().chain(helpers) {
        seen.extend(invoked(command, markers, text));
    }
    let mut errors = Vec::new();
    let mut report = Report {
        surfaces: surfaces.len(),
        by_scan: 0,
        by_suite: 0,
        by_reason: 0,
        gaps: Vec::new(),
        gap_ceiling: manifest.gap_ceiling.unwrap_or_default(),
    };
    for leaf in surfaces {
        match (seen.contains(leaf), manifest.lines.get(leaf)) {
            (true, None) => report.by_scan += 1,
            (true, Some(_)) => errors.push(format!(
                "[\"{leaf}\"]: a suite runs it, drop its manifest line"
            )),
            (false, None) => errors.push(format!(
                "{leaf}: no suite runs it and the manifest does not list it"
            )),
            (false, Some(Line::Suites(numbers))) => {
                let last = leaf.rsplit(' ').next().unwrap_or(leaf);
                let mut ok = true;
                for number in numbers {
                    match suites.get(number) {
                        None => {
                            errors.push(format!("[\"{leaf}\"]: suite {number} does not exist"));
                            ok = false;
                        }
                        Some(text) if !text.contains(last) => {
                            errors.push(format!(
                                "[\"{leaf}\"]: suite {number} no longer names {last}"
                            ));
                            ok = false;
                        }
                        Some(_) => {}
                    }
                }
                if ok {
                    report.by_suite += 1;
                }
            }
            (false, Some(Line::Reason(_))) => report.by_reason += 1,
            (false, Some(Line::Gap(why))) => report.gaps.push(format!("{leaf}: {why}")),
        }
    }
    for leaf in manifest.lines.keys() {
        if !surfaces.contains(leaf) {
            errors.push(format!(
                "[\"{leaf}\"]: listed in the manifest, not a leaf of the command line"
            ));
        }
    }
    match manifest.gap_ceiling {
        None => errors.push("the manifest carries no integer gap_ceiling".into()),
        Some(c) if c != report.gaps.len() => errors.push(format!(
            "{} gaps but gap_ceiling is {c}: set it to the count",
            report.gaps.len()
        )),
        Some(_) => {}
    }
    if errors.is_empty() {
        Ok(report)
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{Arg, ArgAction};

    fn tree() -> Command {
        Command::new("agent")
            .arg(Arg::new("output").long("output").short('o').global(true))
            .arg(
                Arg::new("verbose")
                    .long("verbose")
                    .action(ArgAction::SetTrue)
                    .global(true),
            )
            .subcommand(Command::new("version"))
            .subcommand(
                Command::new("nat").subcommand(
                    Command::new("nptv6")
                        .subcommand(Command::new("list"))
                        .subcommand(Command::new("add").arg(Arg::new("prefix"))),
                ),
            )
            .subcommand(Command::new("secret").hide(true))
    }

    #[test]
    fn leaves_skip_hidden_commands_and_help() {
        let found: Vec<String> = leaves(&tree()).into_iter().collect();
        assert_eq!(found, ["nat nptv6 add", "nat nptv6 list", "version"]);
    }

    #[test]
    fn a_flag_value_is_not_taken_for_a_subcommand() {
        let text = "out=\"$(\"$AGENT_BIN\" --output version nat nptv6 list)\"";
        let found = invoked(&tree(), &["AGENT_BIN"], text);
        assert_eq!(found, BTreeSet::from(["nat nptv6 list".to_string()]));
    }

    #[test]
    fn a_boolean_flag_takes_no_value() {
        let found = invoked(&tree(), &["agent-bin"], "agent-bin --verbose version");
        assert_eq!(found, BTreeSet::from(["version".to_string()]));
    }

    #[test]
    fn continuation_lines_join_and_comments_do_not_count() {
        let text =
            "# agent-bin version\nagent-bin -o json \\\n  nat nptv6 \\\n  add 2001:db8::/48\n";
        let found = invoked(&tree(), &["agent-bin"], text);
        assert_eq!(found, BTreeSet::from(["nat nptv6 add".to_string()]));
    }

    #[test]
    fn a_marker_inside_a_longer_name_is_not_the_binary() {
        let text = "agent-bin-old version; MY_AGENT_BIN version";
        assert!(invoked(&tree(), &["agent-bin", "AGENT_BIN"], text).is_empty());
    }

    #[test]
    fn a_path_stopping_above_a_leaf_runs_nothing() {
        assert!(invoked(&tree(), &["agent-bin"], "agent-bin nat nptv6 | jq").is_empty());
    }

    #[test]
    fn the_manifest_wants_exactly_one_kind_per_leaf() {
        let errors = read_manifest(
            "m.toml",
            "gap_ceiling = 1\n[\"version\"]\nreason = \"a\"\ngap = \"b\"\n",
        )
        .expect_err("two kinds on one leaf");
        assert_eq!(errors.len(), 1);
    }

    #[test]
    fn the_audit_counts_and_holds_the_ceiling() {
        let manifest = read_manifest(
            "m.toml",
            "gap_ceiling = 1\n[\"nat nptv6 add\"]\nsuites = [\"50\"]\n[\"nat nptv6 list\"]\ngap = \"nothing lists\"\n",
        )
        .expect("a manifest");
        let suites = BTreeMap::from([
            ("01".to_string(), "agent-bin version".to_string()),
            ("50".to_string(), "nptv6_add prefix # runs add".to_string()),
        ]);
        let report = audit(
            &tree(),
            &leaves(&tree()),
            &["agent-bin"],
            &suites,
            &[],
            &manifest,
        )
        .expect("passes");
        assert_eq!(
            report.summary("g"),
            "g: 3 surfaces, 1 by scan, 1 by suite, 0 by reason, 1 gaps (ceiling 1)"
        );
    }

    #[test]
    fn the_audit_refuses_an_unlisted_leaf_and_a_stale_line() {
        let manifest = read_manifest(
            "m.toml",
            "gap_ceiling = 0\n[\"version\"]\nreason = \"x\"\n[\"gone\"]\nreason = \"y\"\n",
        )
        .expect("a manifest");
        let suites = BTreeMap::from([("01".to_string(), "agent-bin version".to_string())]);
        let errors = audit(
            &tree(),
            &leaves(&tree()),
            &["agent-bin"],
            &suites,
            &[],
            &manifest,
        )
        .expect_err("fails");
        assert_eq!(errors.len(), 4, "{errors:?}");
    }
}
