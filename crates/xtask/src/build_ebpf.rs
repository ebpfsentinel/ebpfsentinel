use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result};

const EBPF_PROGRAMS: &[&str] = &[
    "xdp-firewall",
    "xdp-firewall-reject",
    "xdp-ratelimit",
    "xdp-ratelimit-syncookie",
    "xdp-loadbalancer",
    "xdp-vip-announcer",
    "tc-dns",
    "tc-ids",
    "tc-threatintel",
    "tc-conntrack",
    "tc-nat-ingress",
    "tc-nat-egress",
    "tc-qos",
    "tc-scrub",
    "uprobe-dlp",
];

// Kernel kfuncs called by the eBPF programs. These resolve to undefined
// `extern "C"` symbols in the object; bpf-linker would otherwise internalize
// them (`declare internal fastcc`), which strips every argument off the call
// and produces a verifier rejection (`arg#0 expected pointer to ctx, but got
// scalar`). Passing each kfunc to `--export` keeps the symbol external so the
// argument-register ABI is preserved; the userspace loader then resolves each
// symbol against kernel/module BTF at load time. Exporting a symbol a given
// program does not reference is a harmless no-op, so a single union list is
// applied to every program.
const KFUNC_EXPORTS: &[&str] = &[
    "bpf_ct_change_status",
    "bpf_ct_change_timeout",
    "bpf_ct_insert_entry",
    "bpf_ct_release",
    "bpf_ct_set_nat_info",
    "bpf_ct_set_status",
    "bpf_ct_set_timeout",
    "bpf_dynptr_adjust",
    "bpf_dynptr_clone",
    "bpf_dynptr_from_skb",
    "bpf_dynptr_from_xdp",
    "bpf_dynptr_is_null",
    "bpf_dynptr_size",
    "bpf_dynptr_slice",
    "bpf_dynptr_slice_rdwr",
    "bpf_skb_ct_alloc",
    "bpf_skb_ct_lookup",
    "bpf_skb_get_fou_encap",
    "bpf_skb_get_xfrm_info",
    "bpf_skb_set_fou_encap",
    "bpf_skb_set_xfrm_info",
    "bpf_xdp_ct_alloc",
    "bpf_xdp_ct_lookup",
    "bpf_xdp_get_xfrm_state",
    "bpf_xdp_metadata_rx_hash",
    "bpf_xdp_metadata_rx_timestamp",
    "bpf_xdp_metadata_rx_vlan_tag",
    "bpf_xdp_xfrm_state_release",
];

/// Build the `CARGO_ENCODED_RUSTFLAGS` value: base flags plus a
/// `--export <kfunc>` link-arg pair for each kfunc. Components are separated
/// by the ASCII unit separator (`\x1f`) as cargo expects.
fn encoded_rustflags() -> String {
    let mut parts: Vec<String> = vec![
        "-C".into(),
        "debuginfo=2".into(),
        "-C".into(),
        "link-arg=--btf".into(),
    ];
    for kfunc in KFUNC_EXPORTS {
        parts.push("-C".into());
        parts.push("link-arg=--export".into());
        parts.push("-C".into());
        parts.push(format!("link-arg={kfunc}"));
    }
    parts.join("\x1f")
}

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
            .env("CARGO_ENCODED_RUSTFLAGS", encoded_rustflags())
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
