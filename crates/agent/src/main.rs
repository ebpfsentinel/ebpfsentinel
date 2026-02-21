#![forbid(unsafe_code)]

mod api_client;
mod cli;
mod commands;
mod reload;
mod shutdown;
mod startup;

use anyhow::Result;

use api_client::ApiClient;
use cli::{
    AlertsCommand, AuditCommand, Command, DnsCommand, DomainsCommand, FirewallCommand, IpsCommand,
    L7Command, RatelimitCommand, ThreatintelCommand,
};

#[tokio::main]
#[allow(clippy::too_many_lines)]
async fn main() -> Result<()> {
    let cli = cli::parse();
    let output = cli.output;

    match cli.command {
        Some(Command::Version) => {
            println!("ebpfsentinel-agent {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }

        Some(Command::Status { conn }) => {
            let client = ApiClient::new(&conn.host, conn.port, cli.token);
            commands::cmd_status(&client, output).await
        }

        Some(Command::Health { conn }) => {
            let client = ApiClient::new(&conn.host, conn.port, cli.token);
            commands::cmd_health(&client, output).await
        }

        Some(Command::Metrics { conn }) => {
            let client = ApiClient::new(&conn.host, conn.port, cli.token);
            commands::cmd_metrics(&client).await
        }

        Some(Command::Firewall(args)) => {
            let client = ApiClient::new(&args.conn.host, args.conn.port, cli.token);
            match args.command {
                FirewallCommand::List => commands::cmd_firewall_list(&client, output).await,
                FirewallCommand::Add { json } => {
                    commands::cmd_firewall_add(&client, &json, output).await
                }
                FirewallCommand::Delete { id } => commands::cmd_firewall_delete(&client, &id).await,
            }
        }

        Some(Command::L7(args)) => {
            let client = ApiClient::new(&args.conn.host, args.conn.port, cli.token);
            match args.command {
                L7Command::List => commands::cmd_l7_list(&client, output).await,
                L7Command::Add { json } => commands::cmd_l7_add(&client, &json, output).await,
                L7Command::Delete { id } => commands::cmd_l7_delete(&client, &id).await,
            }
        }

        Some(Command::Ips(args)) => {
            let client = ApiClient::new(&args.conn.host, args.conn.port, cli.token);
            match args.command {
                IpsCommand::List => commands::cmd_ips_list(&client, output).await,
                IpsCommand::Blacklist => commands::cmd_ips_blacklist(&client, output).await,
                IpsCommand::DomainBlocks => commands::cmd_ips_domain_blocks(&client, output).await,
                IpsCommand::SetMode { id, mode } => {
                    commands::cmd_ips_set_mode(&client, &id, &mode).await
                }
            }
        }

        Some(Command::Ratelimit(args)) => {
            let client = ApiClient::new(&args.conn.host, args.conn.port, cli.token);
            match args.command {
                RatelimitCommand::List => commands::cmd_ratelimit_list(&client, output).await,
                RatelimitCommand::Add { json } => {
                    commands::cmd_ratelimit_add(&client, &json, output).await
                }
                RatelimitCommand::Delete { id } => {
                    commands::cmd_ratelimit_delete(&client, &id).await
                }
            }
        }

        Some(Command::Threatintel(args)) => {
            let client = ApiClient::new(&args.conn.host, args.conn.port, cli.token);
            match args.command {
                ThreatintelCommand::Status => {
                    commands::cmd_threatintel_status(&client, output).await
                }
                ThreatintelCommand::Iocs => commands::cmd_threatintel_iocs(&client, output).await,
                ThreatintelCommand::Feeds => commands::cmd_threatintel_feeds(&client, output).await,
            }
        }

        Some(Command::Alerts(args)) => {
            let client = ApiClient::new(&args.conn.host, args.conn.port, cli.token);
            match args.command {
                AlertsCommand::List {
                    component,
                    severity,
                    limit,
                    offset,
                } => {
                    commands::cmd_alerts_list(
                        &client,
                        component.as_deref(),
                        severity.as_deref(),
                        limit,
                        offset,
                        output,
                    )
                    .await
                }
                AlertsCommand::MarkFp { id } => {
                    commands::cmd_alerts_mark_fp(&client, &id, output).await
                }
            }
        }

        Some(Command::Audit(args)) => {
            let client = ApiClient::new(&args.conn.host, args.conn.port, cli.token);
            match args.command {
                AuditCommand::Logs {
                    component,
                    action,
                    limit,
                    offset,
                } => {
                    commands::cmd_audit_logs(
                        &client,
                        component.as_deref(),
                        action.as_deref(),
                        limit,
                        offset,
                        output,
                    )
                    .await
                }
                AuditCommand::History { id } => {
                    commands::cmd_audit_history(&client, &id, output).await
                }
            }
        }

        Some(Command::Dns(args)) => {
            let client = ApiClient::new(&args.conn.host, args.conn.port, cli.token);
            match args.command {
                DnsCommand::Cache {
                    domain,
                    ip,
                    page,
                    page_size,
                } => {
                    commands::cmd_dns_cache(
                        &client,
                        domain.as_deref(),
                        ip.as_deref(),
                        page,
                        page_size,
                        output,
                    )
                    .await
                }
                DnsCommand::Stats => commands::cmd_dns_stats(&client, output).await,
                DnsCommand::Blocklist => commands::cmd_dns_blocklist(&client, output).await,
                DnsCommand::Flush => commands::cmd_dns_flush(&client, output).await,
            }
        }

        Some(Command::Domains(args)) => {
            let client = ApiClient::new(&args.conn.host, args.conn.port, cli.token);
            match args.command {
                DomainsCommand::Reputation {
                    domain,
                    min_score,
                    page,
                    page_size,
                } => {
                    commands::cmd_domains_reputation(
                        &client,
                        domain.as_deref(),
                        min_score,
                        page,
                        page_size,
                        output,
                    )
                    .await
                }
                DomainsCommand::Block { domain } => {
                    commands::cmd_domains_block(&client, &domain, output).await
                }
                DomainsCommand::Unblock { domain } => {
                    commands::cmd_domains_unblock(&client, &domain, output).await
                }
            }
        }

        // No subcommand = run the agent daemon
        None => startup::run(&cli).await,
    }
}
