mod build_ebpf;
mod ebpf_cost;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ebpfsentinel_agent::http::openapi::ApiDoc;
use utoipa::OpenApi;

#[derive(Parser)]
#[command(name = "xtask", about = "eBPFsentinel build orchestration")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Build all eBPF kernel programs
    EbpfBuild,
    /// Measure each eBPF program's own cost with `BPF_PROG_TEST_RUN`.
    ///
    /// Needs root and the built objects. Reports a program at a time, with
    /// rules loaded and with every emptiness gate set, since `bpf_stats` on a
    /// live interface bills a tail call to whichever program was entered.
    EbpfCost,
    /// Generate code from proto files
    Codegen,
    /// Emit the agent's OpenAPI spec to JSON.
    ///
    /// Default output: `<workspace>/openapi.json`. Consumed by the
    /// dashboard's `dashboard-shared` crate at build time via progenitor.
    EmitOpenapi {
        /// Output path. Defaults to `openapi.json` at the workspace root.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::EbpfBuild => build_ebpf::build_all(),
        Commands::EbpfCost => ebpf_cost::run(),
        Commands::Codegen => {
            println!("codegen: not yet implemented");
            Ok(())
        }
        Commands::EmitOpenapi { output } => emit_openapi(output),
    }
}

fn emit_openapi(output: Option<PathBuf>) -> Result<()> {
    let path = output.unwrap_or_else(|| PathBuf::from("openapi.json"));
    let spec = ApiDoc::openapi();
    let json = spec.to_pretty_json().context("serialise OpenAPI to JSON")?;
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create parent dir for {}", path.display()))?;
    }
    std::fs::write(&path, json).with_context(|| format!("write {}", path.display()))?;
    println!("wrote OpenAPI spec to {}", path.display());
    Ok(())
}
