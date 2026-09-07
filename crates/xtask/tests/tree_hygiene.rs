//! Two invariants this tree states about itself, asserted rather than reviewed.
//!
//! The repository's own rules say a dash is a plain hyphen and that a planning
//! identifier belongs in a pull request rather than in a file somebody ships.
//! Both were hand-maintained until an audit found several hundred breaches, so
//! they are read off the tracked files here: a comment that leaks a story
//! number into a runtime log, or a typographic dash pasted out of a document,
//! fails the build that introduced it.

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

/// A planning identifier: `E12`, `E12.3`, `E20.S5`, `E9.2-2`, `Epic 12`, `Story 4.5`.
///
/// The shape is deliberately narrow, because the alternative is a check nobody
/// can add a line of prose past.
fn planning_reference(line: &str) -> Option<String> {
    let chars: Vec<char> = line.chars().collect();

    for word in ["Epic", "Story"] {
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
    ]
    .into_iter()
    .map(|line| (line, planning_reference(line)))
    .collect();

    assert_eq!(
        found.values().filter(|r| r.is_some()).count(),
        6,
        "every shape this tree actually used must be caught: {found:#?}"
    );

    for clean in [
        "let mask = 0xE12;",
        "const SCALE: f64 = 1E12;",
        "// the ENOSPC path is handled below",
        "assert_eq!(status.entries, 12);",
        "let e12 = decode(&buf)?;",
        "// EDNS0 padding is not parsed",
    ] {
        assert_eq!(
            planning_reference(clean),
            None,
            "a line that is not a planning reference must pass: {clean}"
        );
    }
}
