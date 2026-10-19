//! Three invariants this tree states about itself, asserted rather than reviewed.
//!
//! The repository's own rules say a dash is a plain hyphen and that a planning
//! identifier belongs in a pull request rather than in a file somebody ships.
//! Both were hand-maintained until an audit found several hundred breaches, so
//! they are read off the tracked files here: a comment that leaks a story
//! number into a runtime log, or a typographic dash pasted out of a document,
//! fails the build that introduced it.
//!
//! The third is the packages: the unit files are written for the tarball,
//! which installs under `/usr/local`, and the package build rewrites them on
//! the way in. A path added to a unit and not to that rewrite table installs
//! cleanly and fails at the first start, which is the one failure a package
//! must not have.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Dashes that are not the plain hyphen, with the name to print when one is found.
const FORBIDDEN_DASHES: &[(char, &str)] = &[
    ('\u{2012}', "figure dash"),
    ('\u{2013}', "en dash"),
    ('\u{2014}', "em dash"),
    ('\u{2015}', "horizontal bar"),
];

/// Files a scan may not read as text, by extension.
const BINARY_EXTENSIONS: &[&str] = &["onnx", "png", "jpg", "jpeg", "gif", "ico", "pdf", "woff2"];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("xtask sits two levels below the workspace root")
        .to_path_buf()
}

/// Every file git tracks, which is exactly the set that reaches a reader.
fn tracked_files(root: &Path) -> Vec<PathBuf> {
    let out = Command::new("git")
        .arg("ls-files")
        .arg("-z")
        .current_dir(root)
        .output()
        .expect("git ls-files runs at the workspace root");
    assert!(
        out.status.success(),
        "git ls-files failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .expect("git prints paths as UTF-8")
        .split('\0')
        .filter(|p| !p.is_empty())
        .map(|p| root.join(p))
        .filter(|p| {
            p.extension()
                .and_then(|e| e.to_str())
                .is_none_or(|e| !BINARY_EXTENSIONS.contains(&e))
        })
        .collect()
}

fn read_text(path: &Path) -> Option<String> {
    std::fs::read(path)
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned()
}

#[test]
fn tracked_files_carry_no_typographic_dash() {
    let root = workspace_root();
    let mut offences: Vec<String> = Vec::new();

    for path in tracked_files(&root) {
        let Some(text) = read_text(&path) else {
            continue;
        };
        for (number, line) in text.lines().enumerate() {
            for (dash, name) in FORBIDDEN_DASHES {
                if line.contains(*dash) {
                    offences.push(format!(
                        "{}:{}: {name}: {}",
                        relative(&root, &path),
                        number + 1,
                        line.trim()
                    ));
                }
            }
        }
    }

    assert!(
        offences.is_empty(),
        "a dash in this tree is the plain hyphen, in code, comments, docs and \
         user-facing copy alike:\n{}",
        offences.join("\n")
    );
}

/// A planning identifier: `E12`, `E12.3`, `E20.S5`, `E9.2-2`, `Epic 12`, `Story 4.5`,
/// `Wave 7`, `W1-S3`.
///
/// The shape is deliberately narrow, because the alternative is a check nobody
/// can add a line of prose past.
fn planning_reference(line: &str) -> Option<String> {
    let chars: Vec<char> = line.chars().collect();

    for word in ["Epic", "Story", "Wave"] {
        if let Some(at) = line.find(word) {
            let rest = &line[at + word.len()..];
            let rest = rest.strip_prefix(' ').unwrap_or(rest);
            if rest.starts_with(|c: char| c.is_ascii_digit()) {
                let tail: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_digit() || *c == '.')
                    .collect();
                return Some(format!("{word} {tail}"));
            }
        }
    }

    if let Some(reference) = wave_step_reference(&chars) {
        return Some(reference);
    }

    let mut index = 0;
    while index < chars.len() {
        if chars[index] != 'E' {
            index += 1;
            continue;
        }
        let preceded_by_word = index > 0
            && (chars[index - 1].is_ascii_alphanumeric()
                || chars[index - 1] == '_'
                || chars[index - 1] == '.');
        if preceded_by_word {
            index += 1;
            continue;
        }

        let mut cursor = index + 1;
        let digits = chars[cursor..]
            .iter()
            .take_while(|c| c.is_ascii_digit())
            .count();
        if !(1..=2).contains(&digits) {
            index += 1;
            continue;
        }
        cursor += digits;

        // an optional `.3` or `.S5` part, then an optional `-2` part
        for (separator, letter_allowed) in [('.', true), ('-', false)] {
            if chars.get(cursor) != Some(&separator) {
                continue;
            }
            let mut ahead = cursor + 1;
            if letter_allowed && chars.get(ahead).is_some_and(char::is_ascii_uppercase) {
                ahead += 1;
            }
            let part = chars[ahead..]
                .iter()
                .take_while(|c| c.is_ascii_digit())
                .count();
            if part > 0 {
                cursor = ahead + part;
            }
        }

        let followed_by_word = chars
            .get(cursor)
            .is_some_and(|c| c.is_ascii_alphanumeric() || *c == '_');
        if !followed_by_word {
            return Some(chars[index..cursor].iter().collect());
        }
        index = cursor;
    }

    None
}

/// A wave and step pair, `W1-S3`, standing alone as a word.
fn wave_step_reference(chars: &[char]) -> Option<String> {
    let digits_from = |at: usize| {
        chars[at..]
            .iter()
            .take_while(|c| c.is_ascii_digit())
            .count()
    };
    let is_word = |c: &char| c.is_ascii_alphanumeric() || *c == '_';

    for index in 0..chars.len() {
        if chars[index] != 'W' || (index > 0 && is_word(&chars[index - 1])) {
            continue;
        }
        let wave = digits_from(index + 1);
        let dash = index + 1 + wave;
        if wave == 0 || chars.get(dash) != Some(&'-') || chars.get(dash + 1) != Some(&'S') {
            continue;
        }
        let step = digits_from(dash + 2);
        let end = dash + 2 + step;
        if step > 0 && !chars.get(end).is_some_and(is_word) {
            return Some(chars[index..end].iter().collect());
        }
    }

    None
}

#[test]
fn tracked_files_carry_no_planning_reference() {
    let root = workspace_root();
    let mut offences: Vec<String> = Vec::new();

    for path in tracked_files(&root) {
        // this file names the shape it refuses, so it cannot hold to it
        if path.file_name().and_then(|n| n.to_str()) == Some("tree_hygiene.rs") {
            continue;
        }
        let Some(text) = read_text(&path) else {
            continue;
        };
        for (number, line) in text.lines().enumerate() {
            if let Some(reference) = planning_reference(line) {
                offences.push(format!(
                    "{}:{}: {reference}: {}",
                    relative(&root, &path),
                    number + 1,
                    line.trim()
                ));
            }
        }
    }

    assert!(
        offences.is_empty(),
        "an epic or story identifier belongs in a pull request, not in a file \
         that ships:\n{}",
        offences.join("\n")
    );
}

#[test]
fn the_reference_shape_is_the_one_this_tree_used() {
    let found: BTreeMap<&str, Option<String>> = [
        "// E12 - Provider Registry",
        "/// Advanced RBAC (E9.1) - per-domain permission model.",
        "info!(\"TLS beaconing bridge enabled (E20.S5)\");",
        "/// Update an existing custom role (E9.2-2).",
        "# Epic 12 covers the AI surface",
        "Story 4.5 adds tenants",
        "// TODO(Wave 7): store link FDs",
        "// TODO(W1-S3): BPF_MAP_FREEZE for read-only config maps.",
    ]
    .into_iter()
    .map(|line| (line, planning_reference(line)))
    .collect();

    assert_eq!(
        found.values().filter(|r| r.is_some()).count(),
        8,
        "every shape this tree actually used must be caught: {found:#?}"
    );

    for clean in [
        "let mask = 0xE12;",
        "const SCALE: f64 = 1E12;",
        "// the ENOSPC path is handled below",
        "assert_eq!(status.entries, 12);",
        "let e12 = decode(&buf)?;",
        "// EDNS0 padding is not parsed",
        "// the W3C trace context header",
        "let tw1 = W1_S3;",
        "// a wave of SYN packets",
    ] {
        assert_eq!(
            planning_reference(clean),
            None,
            "a line that is not a planning reference must pass: {clean}"
        );
    }
}

/// Paths the unit files name, which the package build has to rewrite.
fn usr_local_paths(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find("/usr/local/") {
        let tail = &rest[at..];
        let end = tail
            .find(|c: char| !(c.is_ascii_alphanumeric() || "/-_.".contains(c)))
            .unwrap_or(tail.len());
        found.push(tail[..end].to_string());
        rest = &tail[end..];
    }
    found.sort();
    found.dedup();
    found
}

#[test]
fn the_package_build_rewrites_every_path_the_units_name() {
    let root = workspace_root();
    let script = root.join("dist/packaging/build-packages.sh");
    let table = read_text(&script).expect("the package build script is readable");

    let mut missing: Vec<String> = Vec::new();
    for unit in ["ebpfsentinel.service", "ebpfsentinel-warden.service"] {
        let text = read_text(&root.join("dist").join(unit)).expect("the unit is readable");
        for path in usr_local_paths(&text) {
            // The rewrite is written as a sed expression, so the path appears
            // between the first two separators of its own rule.
            if !table.contains(&format!("s#{path}#")) {
                missing.push(format!("{unit}: {path}"));
            }
        }
    }

    assert!(
        missing.is_empty(),
        "the units name paths the package build does not rewrite, so the packaged units \
         would point into /usr/local, which no package installs into: {missing:#?}"
    );
}

#[test]
fn the_rewrite_table_names_no_path_the_units_dropped() {
    let root = workspace_root();
    let table =
        read_text(&root.join("dist/packaging/build-packages.sh")).expect("the script is readable");

    let units: String = ["ebpfsentinel.service", "ebpfsentinel-warden.service"]
        .iter()
        .filter_map(|unit| read_text(&root.join("dist").join(unit)))
        .collect();

    let mut stale = Vec::new();
    for path in usr_local_paths(&table) {
        if !units.contains(&path) {
            stale.push(path);
        }
    }

    assert!(
        stale.is_empty(),
        "the package build rewrites paths no unit names any more: {stale:#?}"
    );
}
