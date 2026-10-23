use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result};

pub(crate) const EBPF_PROGRAMS: &[&str] = &[
    "xdp-firewall",
    "xdp-firewall-reject",
    "xdp-ratelimit",
    "xdp-ratelimit-syncookie",
    "xdp-loadbalancer",
    "xdp-vip-announcer",
    "xdp-pass",
    "tc-dns",
    "tc-ids",
    "tc-threatintel",
    "tc-conntrack",
    "tc-nat-ingress",
    "tc-nat-egress",
    "tc-qos",
    "tc-scrub",
    "uprobe-dlp",
    "cgroup-attribution",
    "cgroup-workload-firewall",
    "tracepoint-process",
    "tracepoint-signal",
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
    "bpf_ct_change_timeout",
    "bpf_ct_release",
    "bpf_dynptr_from_skb",
    "bpf_dynptr_from_xdp",
    "bpf_dynptr_size",
    "bpf_skb_ct_lookup",
    "bpf_skb_get_fou_encap",
    "bpf_skb_get_xfrm_info",
    "bpf_skb_set_fou_encap",
    "bpf_skb_set_xfrm_info",
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

/// The toolchain file the eBPF crates sit under, read at compile time so the
/// date cannot be in two places at once.
const EBPF_TOOLCHAIN_FILE: &str = include_str!("../../ebpf-programs/rust-toolchain.toml");

/// The channel from `crates/ebpf-programs/rust-toolchain.toml`.
///
/// Passed as `cargo +<channel>` rather than left to rustup, because the
/// toolchain file loses to a `RUSTUP_TOOLCHAIN` in the environment and the
/// release build sets one to the workspace MSRV. An explicit `+` argument wins
/// over both, so this is the only form that holds in every caller: a shell, a
/// hosted runner, and a container whose entrypoint exports a toolchain.
fn ebpf_toolchain() -> Result<&'static str> {
    for line in EBPF_TOOLCHAIN_FILE.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key.trim() != "channel" {
            continue;
        }
        let channel = value.trim().trim_matches('"');
        if !channel.is_empty() {
            return Ok(channel);
        }
    }
    anyhow::bail!(
        "no `channel` in crates/ebpf-programs/rust-toolchain.toml: that file is where the \
         nightly date is written, and without it this build would fall back to whatever \
         nightly happens to be installed"
    )
}

pub fn build_all() -> Result<()> {
    let workspace_root = std::env::var("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::current_dir().expect("failed to get cwd"));

    let ebpf_base = workspace_root
        .parent()
        .unwrap_or(&workspace_root)
        .join("ebpf-programs");

    let repo_root = workspace_root
        .parent()
        .and_then(|p| p.parent())
        .unwrap_or(&workspace_root)
        .to_path_buf();

    // Workspace-level output directory expected by integration tests and
    // the agent's dev-fallback path resolution.
    let output_dir = repo_root
        .join("target")
        .join("bpfel-unknown-none")
        .join("release");

    // Every program is its own crate outside the workspace, so each would
    // otherwise get its own target dir and rebuild `core`, `compiler_builtins`
    // and the aya crates from source: ~600 MB per program, ~9 GB for the set,
    // which overruns the disk of a CI runner that also builds an image. One
    // shared dir builds those dependencies once, and the flags are identical
    // across programs so the artifacts are interchangeable.
    let build_dir = repo_root.join("target").join("ebpf");

    std::fs::create_dir_all(&output_dir)
        .with_context(|| format!("failed to create output dir {}", output_dir.display()))?;

    let toolchain = ebpf_toolchain()?;
    println!("eBPF toolchain: {toolchain}");

    for program in EBPF_PROGRAMS {
        let program_dir = ebpf_base.join(program);
        println!("Building eBPF program: {program}");

        let status = Command::new("cargo")
            .arg(format!("+{toolchain}"))
            .arg("build")
            .arg("--release")
            .arg("-Z")
            .arg("build-std=core")
            .arg("--target")
            .arg("bpfel-unknown-none")
            .env("CARGO_ENCODED_RUSTFLAGS", encoded_rustflags())
            .env("CARGO_TARGET_DIR", &build_dir)
            .current_dir(&program_dir)
            .status()
            .with_context(|| format!("failed to run cargo for {program}"))?;

        if !status.success() {
            anyhow::bail!("eBPF build failed for {program}");
        }

        // Copy the built binary to the workspace-level target directory
        // so that integration tests and the agent's dev-fallback can find it.
        let src = build_dir
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ebpf_toolchain_is_a_dated_nightly() {
        let channel = ebpf_toolchain().expect("the toolchain file must name a channel");
        // A bare `nightly` is what this pin replaced: the compiler that
        // produces the objects the verifier accepts then changes on somebody
        // else's schedule, and a program that stops loading has no second
        // compiler to bisect against.
        assert_ne!(
            channel, "nightly",
            "crates/ebpf-programs/rust-toolchain.toml must pin a date, not float on nightly"
        );
        assert!(
            channel.starts_with("nightly-"),
            "the eBPF objects need `-Z build-std=core`, which only nightly has, so the pin \
             must be a dated nightly: got {channel}"
        );
        // `nightly-YYYY-MM-DD`, which is what rustup installs and what the
        // workflows read out of this file.
        let date = channel.trim_start_matches("nightly-");
        assert_eq!(
            date.len(),
            10,
            "expected nightly-YYYY-MM-DD in the toolchain file, got {channel}"
        );
        assert!(
            date.split('-').count() == 3
                && date
                    .split('-')
                    .all(|p| p.chars().all(|c| c.is_ascii_digit())),
            "expected nightly-YYYY-MM-DD in the toolchain file, got {channel}"
        );
    }
}
