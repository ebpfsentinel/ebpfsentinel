//! `cargo xtask cli-parity`: the command line against the document of the
//! agent it drives. The check itself is `ebpfsentinel-cli-parity`, shared with
//! the agent's unit tests and with any other tree that drives an agent.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

fn workspace_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(Path::parent)
        .map_or(manifest.clone(), Path::to_path_buf)
}

fn read(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))
}

pub fn run(
    openapi: Option<PathBuf>,
    client: Vec<PathBuf>,
    exclusions: Option<PathBuf>,
) -> Result<()> {
    let root = workspace_root();
    let openapi = openapi.unwrap_or_else(|| root.join("openapi.json"));
    let client = if client.is_empty() {
        vec![root.join("crates/agent/src/cli")]
    } else {
        client
    };
    let exclusions = exclusions.unwrap_or_else(|| root.join("cli-parity-exclusions.toml"));

    let documented = ebpfsentinel_cli_parity::documented(&read(&openapi)?)
        .with_context(|| openapi.display().to_string())?;
    let mut files = Vec::new();
    for path in &client {
        ebpfsentinel_cli_parity::sources(path, &mut files)
            .with_context(|| format!("reading {}", path.display()))?;
    }
    let (requested, anonymous) = ebpfsentinel_cli_parity::requested(&files);
    let excluded = ebpfsentinel_cli_parity::exclusions(&read(&exclusions)?)
        .with_context(|| exclusions.display().to_string())?;
    let report = ebpfsentinel_cli_parity::check(&documented, &requested, anonymous, &excluded);
    print!("{report}");
    if !report.is_clean() {
        bail!(
            "the command line does not cover the document; add a command or an exclusion with its reason"
        );
    }
    Ok(())
}
