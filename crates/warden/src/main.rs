//! `warden` — the privileged kernel-operation control plane for a fully rootless
//! eBPFsentinel agent.
//!
//! The agent runs non-root with every capability dropped and the runtime-default
//! seccomp profile, so it can issue neither `bpf()` nor netlink/`mount` syscalls.
//! It connects to this process over an `AF_UNIX` socket and asks for a narrow set
//! of typed operations defined by `ebpfsentinel-warden-proto`. The warden holds
//! the extended privileges (`CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `CAP_NET_RAW`) and
//! does nothing on its own initiative — it only answers validated requests.
//!
//! This binary serves the protocol against the maps pinned under its bpffs
//! directory. The protocol logic itself lives in
//! [`ebpfsentinel_warden::server`], so the agent's in-process `warden-serve` mode
//! serves the exact same wire behaviour from the map fds it holds after loading.

#![allow(clippy::cast_possible_truncation)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::process::ExitCode;

use ebpfsentinel_warden::host_ops::LocalHostOps;
use ebpfsentinel_warden::map_engine::MapRegistry;
use ebpfsentinel_warden::server::serve_loop;
use ebpfsentinel_warden::{
    collect_module_btf_fds, enable_tcp_syncookies, open_pcap_pool, prioritize_and_cap_btf,
};
use ebpfsentinel_warden_proto::PROTOCOL_VERSION;

/// Default peer uid the warden accepts — the rootless agent's id. Override with
/// `--uid <n>`.
const DEFAULT_UID: u32 = 65534;
/// Default bpffs directory holding the pinned maps the warden serves. Override
/// with `--maps-dir <path>`.
const DEFAULT_MAPS_DIR: &str = "/sys/fs/bpf/ebpfsentinel";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("serve") => {
            let Some(sock) = args.get(2) else {
                eprintln!("usage: warden serve <socket> [--uid <n>] [--maps-dir <path>]");
                return ExitCode::from(2);
            };
            let uid = parse_uid(&args).unwrap_or(DEFAULT_UID);
            let maps_dir = parse_opt(&args, "--maps-dir").unwrap_or(DEFAULT_MAPS_DIR.to_owned());
            serve(sock, uid, &maps_dir)
        }
        _ => {
            eprintln!("usage: warden serve <socket> [--uid <n>] [--maps-dir <path>]");
            ExitCode::from(2)
        }
    }
}

/// Parse `--uid <n>` if present.
fn parse_uid(args: &[String]) -> Option<u32> {
    parse_opt(args, "--uid")?.parse().ok()
}

/// Parse the value following `flag` if present.
fn parse_opt(args: &[String], flag: &str) -> Option<String> {
    let i = args.iter().position(|a| a == flag)?;
    args.get(i + 1).cloned()
}

/// Bind the listening socket (mode `0600`) and serve agent connections forever.
fn serve(sockpath: &str, allowed_uid: u32, maps_dir: &str) -> ExitCode {
    // Privileged setup the agent cannot perform once rootless (the XDP syncookie
    // offload needs always-on kernel syncookies).
    enable_tcp_syncookies();

    // Open the pinned maps once; their set is the allowlist for map RPC. Because
    // the maps are pinned in bpffs, this re-adopts exactly the objects a previous
    // warden served — a warden restart reloads no eBPF and never disturbs the
    // agent's already-held ring-buffer fds.
    let registry = MapRegistry::open_pin_dir(std::path::Path::new(maps_dir));
    eprintln!(
        "[warden] re-adopted {} pinned map(s) from {maps_dir} {:?}",
        registry.len(),
        registry.names()
    );

    // Open the module-BTF and pcap fds once (privileged: BTF enumeration needs
    // CAP_SYS_ADMIN, the AF_PACKET pool needs CAP_NET_RAW). They are handed to the
    // agent on `Delegate`. Without the capabilities both sets come back empty and
    // delegation simply carries no fds.
    let pcap = open_pcap_pool();
    let btf = prioritize_and_cap_btf(collect_module_btf_fds(), pcap.len());
    eprintln!(
        "[warden] delegation ready: {} module BTF fd(s), {} pcap fd(s)",
        btf.len(),
        pcap.len()
    );

    let _ = fs::remove_file(sockpath);
    let listener = match UnixListener::bind(sockpath) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[warden] bind {sockpath}: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = fs::set_permissions(sockpath, fs::Permissions::from_mode(0o600)) {
        eprintln!("[warden] chmod {sockpath}: {e}");
    }
    eprintln!(
        "[warden] serving on {sockpath} (allowed peer uid {allowed_uid}, protocol v{PROTOCOL_VERSION})"
    );

    // The bare-metal warden runs as host root in the init netns, so it performs
    // host-network ops directly.
    serve_loop(
        &listener,
        &registry,
        &btf,
        &pcap,
        &LocalHostOps,
        allowed_uid,
    );
    ExitCode::SUCCESS
}
