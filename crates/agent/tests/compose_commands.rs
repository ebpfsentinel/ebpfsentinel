//! Every command line a compose file in this tree gives the agent or the
//! warden is one its binary accepts.
//!
//! A compose file is a run instruction a reader copies: a flag the binary does
//! not know stops a one-shot, and everything waiting on it never starts. The
//! agent's lines (`command:`, `entrypoint:`, a `CMD` healthcheck) go through
//! the clap parser the binary uses; the warden reads its own arguments, so its
//! lines are held to the subcommands and flags it reads.

#![allow(clippy::panic, clippy::expect_used)]

use std::path::{Path, PathBuf};

use clap::Parser;
use ebpfsentinel_agent::cli::Cli;
use serde_norway::Value;

/// Below these the walk no longer reads the files the test was written for:
/// the root, `dist/` and demo compose files each start a policy one-shot, a
/// warden and an agent.
const AGENT_LINE_FLOOR: usize = 6;
const WARDEN_LINE_FLOOR: usize = 3;

/// Directories that hold no compose file of ours.
const SKIPPED_DIRS: &[&str] = &["target", "node_modules", "ebpf-out", "fuzz"];

/// The warden's subcommands and the flags each reads with a value
/// (`crates/warden/src/main.rs`); anything else would be ignored silently.
const WARDEN_SUBCOMMANDS: &[(&str, &[&str])] = &[
    (
        "serve",
        &["--uid", "--user", "--policy", "--max-connections"],
    ),
    ("prepare-state", &["--uid", "--user"]),
    ("install-seccomp-profile", &[]),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Binary {
    Agent,
    Warden,
}

fn is_compose_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let yaml = Path::new(name)
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("yml") || e.eq_ignore_ascii_case("yaml"));
    yaml && (name.starts_with("compose") || name.starts_with("docker-compose"))
}

fn compose_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("a directory entry").path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if path.is_dir() {
            if !name.starts_with('.') && !SKIPPED_DIRS.contains(&name) {
                compose_files(&path, out);
            }
        } else if is_compose_file(&path) {
            out.push(path);
        }
    }
}

/// The binary an executable path or an image reference names.
fn binary_named(word: &str) -> Option<Binary> {
    let last = word.rsplit('/').next().unwrap_or(word);
    let name = last.split(':').next().unwrap_or(last);
    match name {
        "ebpfsentinel-agent" | "ebpfsentinel" => Some(Binary::Agent),
        "warden" | "ebpfsentinel-warden" => Some(Binary::Warden),
        _ => None,
    }
}

/// The binary a service's image runs when nothing overrides its entrypoint:
/// the image name, or the Dockerfile it is built from.
fn image_binary(service: &Value) -> Option<Binary> {
    if let Some(image) = service.get("image").and_then(Value::as_str) {
        return binary_named(image);
    }
    let dockerfile = service.get("build")?.get("dockerfile")?.as_str()?;
    match dockerfile.rsplit('/').next()? {
        "Dockerfile.agent" => Some(Binary::Agent),
        "Dockerfile.warden" => Some(Binary::Warden),
        _ => None,
    }
}

/// A compose argument list: a sequence, or a string split on whitespace as
/// compose splits it when no shell is named.
fn words(value: &Value) -> Vec<String> {
    match value {
        Value::Sequence(items) => items
            .iter()
            .map(|item| match item {
                Value::String(s) => s.clone(),
                Value::Number(n) => n.to_string(),
                other => panic!("a compose argument that is not a scalar: {other:?}"),
            })
            .collect(),
        Value::String(s) => s.split_whitespace().map(str::to_string).collect(),
        other => panic!("a compose argument list that is neither list nor string: {other:?}"),
    }
}

/// Every (binary, arguments) a service runs: its main process, and its
/// healthcheck when that execs one of our binaries.
fn invocations(service: &Value) -> Vec<(Binary, Vec<String>)> {
    let mut out = Vec::new();
    let command = service.get("command").map(words);
    match service.get("entrypoint").map(words) {
        Some(entrypoint) => {
            if let Some((first, rest)) = entrypoint.split_first()
                && let Some(binary) = binary_named(first)
            {
                let mut args = rest.to_vec();
                args.extend(command.unwrap_or_default());
                out.push((binary, args));
            }
        }
        None => {
            if let (Some(binary), Some(args)) = (image_binary(service), command) {
                out.push((binary, args));
            }
        }
    }
    if let Some(test) = service.get("healthcheck").and_then(|h| h.get("test")) {
        let test = words(test);
        if let [kind, exe, args @ ..] = test.as_slice()
            && kind == "CMD"
            && let Some(binary) = binary_named(exe)
        {
            out.push((binary, args.to_vec()));
        }
    }
    out
}

fn check_agent(args: &[String]) -> Result<(), String> {
    let argv = std::iter::once("ebpfsentinel-agent".to_string()).chain(args.iter().cloned());
    Cli::try_parse_from(argv)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

fn check_warden(args: &[String]) -> Result<(), String> {
    let Some((subcommand, rest)) = args.split_first() else {
        return Ok(());
    };
    let flags = WARDEN_SUBCOMMANDS
        .iter()
        .find(|(name, _)| name == subcommand)
        .map(|(_, flags)| *flags)
        .ok_or_else(|| format!("`{subcommand}` is not a warden subcommand"))?;
    let Some((target, mut rest)) = rest.split_first() else {
        return Err(format!("`{subcommand}` needs a path"));
    };
    if target.starts_with("--") {
        return Err(format!("`{subcommand}` needs a path before `{target}`"));
    }
    while let Some((flag, tail)) = rest.split_first() {
        if !flags.contains(&flag.as_str()) {
            return Err(format!("`{flag}` is not a flag `{subcommand}` reads"));
        }
        let Some((value, tail)) = tail.split_first() else {
            return Err(format!("`{flag}` needs a value"));
        };
        if (flag == "--uid" || flag == "--max-connections") && value.parse::<u32>().is_err() {
            return Err(format!("`{flag} {value}`: not a number"));
        }
        rest = tail;
    }
    Ok(())
}

#[test]
fn every_compose_command_parses_under_its_binary() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = Vec::new();
    compose_files(&root, &mut files);
    files.sort();

    let mut errors = Vec::new();
    let (mut agent_lines, mut warden_lines) = (0usize, 0usize);
    for file in &files {
        let text = std::fs::read_to_string(file).expect("a readable compose file");
        let doc: Value =
            serde_norway::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", file.display()));
        let Some(services) = doc.get("services").and_then(Value::as_mapping) else {
            continue;
        };
        for (name, service) in services {
            let name = name.as_str().unwrap_or("?");
            for (binary, args) in invocations(service) {
                let result = match binary {
                    Binary::Agent => {
                        agent_lines += 1;
                        check_agent(&args)
                    }
                    Binary::Warden => {
                        warden_lines += 1;
                        check_warden(&args)
                    }
                };
                if let Err(e) = result {
                    let shown = file.strip_prefix(&root).unwrap_or(file).display();
                    errors.push(format!("{shown}: service `{name}` {args:?}: {e}"));
                }
            }
        }
    }

    assert!(
        agent_lines >= AGENT_LINE_FLOOR && warden_lines >= WARDEN_LINE_FLOOR,
        "{agent_lines} agent and {warden_lines} warden command lines read in {} compose files, \
         floors {AGENT_LINE_FLOOR} and {WARDEN_LINE_FLOOR}: the walk no longer reads the tree",
        files.len()
    );
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

#[test]
fn a_global_flag_where_a_subcommand_flag_belongs_is_caught() {
    let args: Vec<String> = [
        "--config",
        "/etc/ebpfsentinel/config.yaml",
        "warden-policy",
        "--output",
        "/run/ebpfsentinel-policy/warden-policy.json",
    ]
    .map(str::to_string)
    .to_vec();
    assert!(check_agent(&args).is_err());
}

#[test]
fn an_unknown_warden_flag_is_caught() {
    let args: Vec<String> = [
        "serve",
        "/run/ebpfsentinel/warden.sock",
        "--polcy",
        "/p.json",
    ]
    .map(str::to_string)
    .to_vec();
    assert!(check_warden(&args).is_err());
}
