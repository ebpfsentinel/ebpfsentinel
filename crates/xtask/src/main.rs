mod build_ebpf;
mod cli_parity;
mod ebpf_cost;
mod ebpf_load;
mod sign_ebpf;

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
    /// Build all eBPF kernel programs, then sign their loaders
    EbpfBuild,
    /// Sign the loaders of already built eBPF objects.
    ///
    /// Writes `<object>.loaders` and `loader-signing.der` beside them. The
    /// key comes from `EBPFSENTINEL_LOADER_SIGNING_KEY` and
    /// `EBPFSENTINEL_LOADER_SIGNING_CERT`, else the committed test key, which
    /// `EBPFSENTINEL_RELEASE_BUILD` refuses.
    EbpfSign {
        /// Directory holding the objects. Defaults to the build output.
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Measure each eBPF program's own cost with `BPF_PROG_TEST_RUN`.
    ///
    /// Needs root and the built objects. Reports a program at a time, with
    /// rules loaded and with every emptiness gate set, since `bpf_stats` on a
    /// live interface bills a tail call to whichever program was entered.
    EbpfCost,
    /// Load every built eBPF object and report what the kernel did with each.
    ///
    /// Needs root. Loads with the process's own capabilities, or through a
    /// BPF token when `EBPFSENTINEL_WARDEN_SOCK` names a running warden, the
    /// way the agent loads. Exits non-zero when any object is refused.
    EbpfLoad {
        /// Directory holding the objects. Defaults to the build output.
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Bind the XDP objects reading receive metadata to this interface,
        /// so their metadata kfunc calls reach the verifier.
        #[arg(long, value_name = "IFACE")]
        dev_bound: Option<String>,
    },
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
    /// Emit the catalogue of capabilities above the kernel floor to JSON.
    ///
    /// Default output: `<workspace>/capabilities.json`, read by the
    /// documentation, the website and the sales material, and held to the
    /// catalogue by a test.
    EmitCapabilities {
        /// Output path. Defaults to `capabilities.json` at the workspace root.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Fail on an operation of the API that no command reaches and no
    /// exclusion names.
    ///
    /// Defaults to this tree: `openapi.json`, the sources under
    /// `crates/agent/src/cli`, and `cli-parity-exclusions.toml`, all at the
    /// workspace root. Another tree driving its own agent passes its own.
    CliParity {
        /// The OpenAPI document of the agent the command line drives.
        #[arg(long)]
        openapi: Option<PathBuf>,
        /// A client source file, or a directory read for `.rs` files.
        /// Repeat for several.
        #[arg(long)]
        client: Vec<PathBuf>,
        /// The exclusion file.
        #[arg(long)]
        exclusions: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::EbpfBuild => build_ebpf::build_all(),
        Commands::EbpfSign { dir } => {
            let dir = dir.unwrap_or_else(build_ebpf::output_dir);
            sign_ebpf::sign_dir(&dir, build_ebpf::EBPF_PROGRAMS)
        }
        Commands::EbpfCost => ebpf_cost::run(),
        Commands::EbpfLoad { dir, dev_bound } => ebpf_load::run(dir, dev_bound),
        Commands::Codegen => {
            println!("codegen: not yet implemented");
            Ok(())
        }
        Commands::EmitOpenapi { output } => emit_openapi(output),
        Commands::EmitCapabilities { output } => emit_capabilities(output),
        Commands::CliParity {
            openapi,
            client,
            exclusions,
        } => cli_parity::run(openapi, client, exclusions),
    }
}

fn emit_capabilities(output: Option<PathBuf>) -> Result<()> {
    let path = output.unwrap_or_else(|| PathBuf::from("capabilities.json"));
    let mut json = serde_json::to_string_pretty(&adapters::ebpf::capabilities::published())
        .context("serialise the capability catalogue to JSON")?;
    json.push('\n');
    std::fs::write(&path, json).with_context(|| format!("write {}", path.display()))?;
    println!("wrote the capability catalogue to {}", path.display());
    Ok(())
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
