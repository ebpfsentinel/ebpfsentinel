use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result};

const EBPF_PROGRAMS: &[&str] = &[
    "xdp-firewall",
    "xdp-ratelimit",
    "xdp-loadbalancer",
    "tc-dns",
    "tc-ids",
    "tc-threatintel",
    "tc-conntrack",
    "tc-nat-ingress",
    "tc-nat-egress",
    "tc-scrub",
    "uprobe-dlp",
];

pub fn build_all() -> Result<()> {
    let workspace_root = std::env::var("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::current_dir().expect("failed to get cwd"));

    let ebpf_base = workspace_root
        .parent()
        .unwrap_or(&workspace_root)
        .join("ebpf-programs");

    // Workspace-level output directory expected by integration tests and
    // the agent's dev-fallback path resolution.
    let output_dir = workspace_root
        .parent()
        .and_then(|p| p.parent())
        .unwrap_or(&workspace_root)
        .join("target")
        .join("bpfel-unknown-none")
        .join("release");

    std::fs::create_dir_all(&output_dir)
        .with_context(|| format!("failed to create output dir {}", output_dir.display()))?;

    for program in EBPF_PROGRAMS {
        let program_dir = ebpf_base.join(program);
        println!("Building eBPF program: {program}");

        let status = Command::new("cargo")
            .arg("+nightly")
            .arg("build")
            .arg("--release")
            .arg("-Z")
            .arg("build-std=core")
            .arg("--target")
            .arg("bpfel-unknown-none")
            .env(
                "CARGO_ENCODED_RUSTFLAGS",
                "-C\x1fdebuginfo=2\x1f-C\x1flink-arg=--btf",
            )
            .current_dir(&program_dir)
            .status()
            .with_context(|| format!("failed to run cargo for {program}"))?;

        if !status.success() {
            anyhow::bail!("eBPF build failed for {program}");
        }

        // Copy the built binary to the workspace-level target directory
        // so that integration tests and the agent's dev-fallback can find it.
        let src = program_dir
            .join("target")
            .join("bpfel-unknown-none")
            .join("release")
            .join(program);
        let dst = output_dir.join(program);
        std::fs::copy(&src, &dst)
            .with_context(|| format!("failed to copy {} -> {}", src.display(), dst.display()))?;
        println!("  -> {}", dst.display());
    }

    println!("All eBPF programs built successfully");
    Ok(())
}
