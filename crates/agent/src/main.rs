#![forbid(unsafe_code)]

use anyhow::Result;

use ebpfsentinel_agent::cli::{self, NoExtension};

fn main() -> Result<()> {
    let matches = cli::parse_with(&NoExtension);

    // The rootless daemon self-bootstraps its user namespace + delegated bpffs
    // (via the warden) before any async runtime starts - the userns unshare must
    // run single-threaded. A no-op unless a warden socket is configured, or on
    // the post-`execv` second pass. Only the daemon loads eBPF, so gate on it.
    if matches.subcommand_name().is_none() {
        ebpfsentinel_warden::userns_bootstrap::maybe_bootstrap_from_env();
    }

    let ran = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run(&matches));
    // A stop through the API ends with a status of its own, so the unit
    // restarting the agent on anything else leaves this one stopped.
    if ran.is_ok() && ebpfsentinel_agent::lifecycle::stop_commanded() {
        std::process::exit(ebpfsentinel_agent::lifecycle::STOP_EXIT_CODE);
    }
    ran
}

async fn run(matches: &clap::ArgMatches) -> Result<()> {
    // No subcommand = run the agent daemon. Boxed because the startup
    // future owns every loaded eBPF object and map manager, which is far
    // too large to keep inline on this stack frame.
    if let Some(cli) = cli::run(matches, &NoExtension).await? {
        Box::pin(ebpfsentinel_agent::startup::run(
            &cli.config,
            cli.log_level,
            cli.log_format,
        ))
        .await?;
    }
    Ok(())
}
