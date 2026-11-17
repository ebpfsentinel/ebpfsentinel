//! The agent's command line, as a library.
//!
//! `ebpfsentinel-agent` is this module and a `main` around it. Another binary
//! built on the agent's crates reuses the same parser, client, tables and token
//! resolution through an [`Extension`]: it may add top-level domains and add
//! verbs under an existing one, and it sees the parsed line before the OSS
//! commands do. Whatever it does not claim runs exactly as it does in
//! `ebpfsentinel-agent`, so one grammar answers on both.

use std::future::Future;
use std::pin::Pin;

use anyhow::Result;
use clap::{ArgMatches, CommandFactory, FromArgMatches};

pub mod api_client;
mod args;
pub mod commands;
mod run;
pub mod table;
pub mod token;

pub use args::*;

/// What a command claimed by an extension returns: the work, to be awaited.
pub type Handled<'a> = Pin<Box<dyn Future<Output = Result<()>> + 'a>>;

/// The flags every command shares, resolved once before any command runs.
#[derive(Debug, Clone)]
pub struct Globals {
    /// The configuration file the line names, or the default.
    pub config: String,
    /// The credential to present: `--token`, `EBPFSENTINEL_TOKEN`, or the key
    /// the agent drew for itself beside that configuration file.
    pub token: Option<String>,
    /// `-o table|json`.
    pub output: OutputFormat,
}

impl Globals {
    /// A client for the agent `conn` names, carrying the resolved credential.
    #[must_use]
    pub fn client(&self, conn: &ConnectionArgs) -> api_client::ApiClient {
        api_client::ApiClient::new(&conn.host, conn.port, self.token.clone())
    }
}

/// Domains and verbs a binary adds to the OSS command line.
pub trait Extension {
    /// Add subcommands to the parser, or verbs under an existing one through
    /// [`clap::Command::mut_subcommand`]. Called once, on the OSS parser.
    fn augment(&self, command: clap::Command) -> clap::Command;

    /// Claim the parsed line, or leave it to the OSS commands by answering
    /// `None`. Asked first, so a verb added under an OSS domain is reached.
    fn dispatch<'a>(&'a self, matches: &'a ArgMatches, globals: &'a Globals)
    -> Option<Handled<'a>>;
}

/// The OSS command line alone.
pub struct NoExtension;

impl Extension for NoExtension {
    fn augment(&self, command: clap::Command) -> clap::Command {
        command
    }

    fn dispatch<'a>(&'a self, _: &'a ArgMatches, _: &'a Globals) -> Option<Handled<'a>> {
        None
    }
}

/// The OSS parser, before any extension.
#[must_use]
pub fn command() -> clap::Command {
    Cli::command()
}

/// The parser an extension builds on the OSS one.
#[must_use]
pub fn command_with(extension: &dyn Extension) -> clap::Command {
    extension.augment(command())
}

/// Parse the process arguments against the parser `extension` builds,
/// printing clap's own message and exiting on a line it refuses.
#[must_use]
pub fn parse_with(extension: &dyn Extension) -> ArgMatches {
    command_with(extension).get_matches()
}

/// Run a parsed line: the extension's command if it claims it, else the OSS
/// one. Answers the parsed flags when the line names no command, so the
/// caller starts its own daemon with them.
///
/// # Errors
///
/// Whatever the command run returns.
pub async fn run(matches: &ArgMatches, extension: &dyn Extension) -> Result<Option<Cli>> {
    if matches.subcommand_name().is_none() {
        return Ok(Some(oss_view(matches, extension)));
    }
    let config = matches
        .get_one::<String>("config")
        .cloned()
        .unwrap_or_else(|| infrastructure::constants::DEFAULT_CONFIG_PATH.to_string());
    // A command run beside the agent reads the key the agent drew for itself,
    // so the published invocations keep working now that the API is shut.
    let token = matches
        .get_one::<String>("token")
        .cloned()
        .or_else(|| token::from_bootstrap_key_file(&config));
    let globals = Globals {
        output: matches
            .get_one::<OutputFormat>("output")
            .copied()
            .unwrap_or(OutputFormat::Table),
        config,
        token,
    };
    if let Some(handled) = extension.dispatch(matches, &globals) {
        handled.await?;
        return Ok(None);
    }
    let mut cli = oss_view(matches, extension);
    cli.token = globals.token;
    run::run_oss(cli).await
}

/// The OSS flags read back out of a parsed line, exiting the way clap does on
/// a line the OSS types cannot hold.
fn oss_view(matches: &ArgMatches, extension: &dyn Extension) -> Cli {
    Cli::from_arg_matches(matches).unwrap_or_else(|e| e.format(&mut command_with(extension)).exit())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    /// Adds a `license` domain and a `findings` verb under `dlp`, and records
    /// which lines it claimed with the flags it was handed.
    #[derive(Default)]
    struct Recorder {
        claimed: Mutex<Vec<(String, Option<String>, OutputFormat)>>,
    }

    impl Extension for Recorder {
        fn augment(&self, command: clap::Command) -> clap::Command {
            command
                .subcommand(clap::Command::new("license").subcommand(clap::Command::new("status")))
                .mut_subcommand("dlp", |dlp| dlp.subcommand(clap::Command::new("findings")))
        }

        fn dispatch<'a>(
            &'a self,
            matches: &'a ArgMatches,
            globals: &'a Globals,
        ) -> Option<Handled<'a>> {
            let claimed = match matches.subcommand() {
                Some(("license", _)) => "license",
                Some(("dlp", dlp)) if dlp.subcommand_name() == Some("findings") => "dlp findings",
                _ => return None,
            };
            let entry = (claimed.to_string(), globals.token.clone(), globals.output);
            Some(Box::pin(async move {
                self.claimed.lock().unwrap().push(entry);
                Ok(())
            }))
        }
    }

    fn parse(extension: &dyn Extension, line: &[&str]) -> ArgMatches {
        command_with(extension)
            .try_get_matches_from(line)
            .expect("the line parses")
    }

    #[tokio::test]
    async fn an_extension_domain_and_an_added_verb_are_claimed_with_the_shared_flags() {
        let ext = Recorder::default();
        let line = [
            "ebpfsentinel-agent",
            "--token",
            "k",
            "-o",
            "json",
            "license",
            "status",
        ];
        assert!(run(&parse(&ext, &line), &ext).await.unwrap().is_none());
        let line = ["ebpfsentinel-agent", "dlp", "findings", "--token", "k"];
        assert!(run(&parse(&ext, &line), &ext).await.unwrap().is_none());
        assert_eq!(
            *ext.claimed.lock().unwrap(),
            vec![
                (
                    "license".to_string(),
                    Some("k".to_string()),
                    OutputFormat::Json
                ),
                (
                    "dlp findings".to_string(),
                    Some("k".to_string()),
                    OutputFormat::Table
                ),
            ]
        );
    }

    #[test]
    fn the_oss_verbs_of_an_extended_domain_still_parse() {
        let ext = Recorder::default();
        let cli = oss_view(&parse(&ext, &["ebpfsentinel-agent", "dlp", "status"]), &ext);
        assert!(matches!(
            cli.command,
            Some(Command::Dlp(DomainArgs {
                command: DlpCommand::Status,
                ..
            }))
        ));
    }

    #[tokio::test]
    async fn a_line_naming_no_command_is_handed_back_for_the_daemon() {
        let ext = Recorder::default();
        let cli = run(&parse(&ext, &["ebpfsentinel-agent", "-c", "/x.yaml"]), &ext)
            .await
            .unwrap()
            .expect("handed back");
        assert_eq!(cli.config, "/x.yaml");
        assert!(ext.claimed.lock().unwrap().is_empty());
    }

    #[test]
    fn the_oss_parser_passes_clap_s_own_checks() {
        command_with(&NoExtension).debug_assert();
        command_with(&Recorder::default()).debug_assert();
    }
}
