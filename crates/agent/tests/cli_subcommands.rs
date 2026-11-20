//! Every leaf of the agent's command line is run by an integration suite, or
//! listed in `cli-subcommands.toml` beside this file.
//!
//! A surface gate (meta `docs/COVERAGE.md`): the inventory is the clap tree
//! `ebpfsentinel_agent::cli::command()` builds, the evidence a line of
//! `tests/integration/suites/*.bats` or `tests/integration/lib/*.bash` that
//! runs the binary with the leaf's words. Run with `--nocapture` to read the
//! summary line the meta runner collects.

#![allow(clippy::panic, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ebpfsentinel_cli_parity::invocations;

const GATE: &str = "ebpfsentinel/cli-subcommands";

/// Below this the tree read is not the one the gate was written for.
const LEAF_FLOOR: usize = 150;

/// How a suite names the binary: its file name, the variable the suites
/// hold its path in, or the helper that prints it.
const MARKERS: &[&str] = &["ebpfsentinel-agent", "AGENT_BIN", "$(_agent_binary)"];

fn texts(dir: &Path, extension: &str) -> Vec<(PathBuf, String)> {
    let mut out: Vec<(PathBuf, String)> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|entry| entry.expect("a directory entry").path())
        .filter(|path| path.extension().is_some_and(|e| e == extension))
        .map(|path| {
            let text = std::fs::read_to_string(&path).expect("a readable suite");
            (path, text)
        })
        .collect();
    out.sort();
    out
}

#[test]
fn every_cli_subcommand_runs_in_a_suite() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let command = ebpfsentinel_agent::cli::command();
    let leaves = invocations::leaves(&command);
    assert!(
        leaves.len() >= LEAF_FLOOR,
        "{} leaves read, floor {LEAF_FLOOR}: the gate no longer reads the tree",
        leaves.len()
    );

    let suites: BTreeMap<String, String> = texts(&root.join("tests/integration/suites"), "bats")
        .into_iter()
        .filter_map(|(path, text)| {
            let name = path.file_name()?.to_str()?;
            Some((name.split('-').next()?.to_string(), text))
        })
        .collect();
    let helpers: Vec<String> = texts(&root.join("tests/integration/lib"), "bash")
        .into_iter()
        .map(|(_, text)| text)
        .collect();
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/cli-subcommands.toml");
    let manifest = invocations::read_manifest(
        "cli-subcommands.toml",
        &std::fs::read_to_string(&path).expect("the manifest"),
    )
    .unwrap_or_else(|errors| panic!("{GATE}:\n{}", errors.join("\n")));

    let report = invocations::audit(&command, &leaves, MARKERS, &suites, &helpers, &manifest)
        .unwrap_or_else(|errors| panic!("{GATE}:\n{}", errors.join("\n")));
    for gap in &report.gaps {
        println!("gap: {gap}");
    }
    println!("{}", report.summary(GATE));
}
