mod build_ebpf;

use anyhow::Result;
use clap::{Parser, Subcommand};

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
    /// Generate code from proto files
    Codegen,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::EbpfBuild => build_ebpf::build_all(),
        Commands::Codegen => {
            println!("codegen: not yet implemented");
            Ok(())
        }
    }
}
