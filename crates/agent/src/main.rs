#![forbid(unsafe_code)]

mod api_client;
mod cli;
mod commands;

use anyhow::Result;

use api_client::ApiClient;
use cli::{
    AlertsCommand, AuditCommand, Command, DdosCommand, DnsCommand, DomainsCommand,
    FingerprintsCommand, FirewallCommand, IpsCommand, L7Command, LbCommand, MitreCommand,
    NatCommand, NptV6Command, QosCommand, RatelimitCommand, ThreatintelCommand,
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
                    tactic,
                    technique,
                    limit,
                    offset,
                } => {
                    commands::cmd_alerts_list(
                        &client,
                        component.as_deref(),
                        severity.as_deref(),
                        tactic.as_deref(),
                        technique.as_deref(),
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

        Some(Command::Ddos(args)) => {
            let client = ApiClient::new(&args.conn.host, args.conn.port, cli.token);
            match args.command {
                DdosCommand::Status => commands::cmd_ddos_status(&client, output).await,
                DdosCommand::Attacks => commands::cmd_ddos_attacks(&client, output).await,
                DdosCommand::History { limit } => {
                    commands::cmd_ddos_history(&client, limit, output).await
                }
                DdosCommand::Policies => commands::cmd_ddos_policies(&client, output).await,
                DdosCommand::Add { json } => commands::cmd_ddos_add(&client, &json, output).await,
                DdosCommand::Delete { id } => commands::cmd_ddos_delete(&client, &id).await,
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

        Some(Command::Lb(args)) => {
            let client = ApiClient::new(&args.conn.host, args.conn.port, cli.token);
            match args.command {
                LbCommand::Status => commands::cmd_lb_status(&client, output).await,
                LbCommand::Services => commands::cmd_lb_services(&client, output).await,
                LbCommand::Service { id } => commands::cmd_lb_service(&client, &id, output).await,
                LbCommand::Add { json } => commands::cmd_lb_add(&client, &json, output).await,
                LbCommand::Delete { id } => commands::cmd_lb_delete(&client, &id).await,
            }
        }

        Some(Command::Qos(args)) => {
            let client = ApiClient::new(&args.conn.host, args.conn.port, cli.token);
            match args.command {
                QosCommand::Status => commands::cmd_qos_status(&client, output).await,
                QosCommand::Pipes => commands::cmd_qos_pipes(&client, output).await,
                QosCommand::Queues => commands::cmd_qos_queues(&client, output).await,
                QosCommand::Classifiers => commands::cmd_qos_classifiers(&client, output).await,
                QosCommand::AddPipe { json } => {
                    commands::cmd_qos_add_pipe(&client, &json, output).await
                }
                QosCommand::DeletePipe { id } => commands::cmd_qos_delete_pipe(&client, &id).await,
                QosCommand::AddQueue { json } => {
                    commands::cmd_qos_add_queue(&client, &json, output).await
                }
                QosCommand::DeleteQueue { id } => {
                    commands::cmd_qos_delete_queue(&client, &id).await
                }
                QosCommand::AddClassifier { json } => {
                    commands::cmd_qos_add_classifier(&client, &json, output).await
                }
                QosCommand::DeleteClassifier { id } => {
                    commands::cmd_qos_delete_classifier(&client, &id).await
                }
            }
        }

        Some(Command::Nat(args)) => {
            let client = ApiClient::new(&args.conn.host, args.conn.port, cli.token);
            match args.command {
                NatCommand::Status => commands::cmd_nat_status(&client, output).await,
                NatCommand::Rules => commands::cmd_nat_rules(&client, output).await,
                NatCommand::Nptv6(sub) => match sub {
                    NptV6Command::List => commands::cmd_nat_nptv6_list(&client, output).await,
                    NptV6Command::Create {
                        id,
                        internal_prefix,
                        external_prefix,
                        prefix_len,
                    } => {
                        commands::cmd_nat_nptv6_create(
                            &client,
                            &id,
                            &internal_prefix,
                            &external_prefix,
                            prefix_len,
                            output,
                        )
                        .await
                    }
                    NptV6Command::Delete { id } => {
                        commands::cmd_nat_nptv6_delete(&client, &id).await
                    }
                },
            }
        }

        Some(Command::Mitre(args)) => {
            let client = ApiClient::new(&args.conn.host, args.conn.port, cli.token);
            match args.command {
                MitreCommand::Coverage => commands::cmd_mitre_coverage(&client, output).await,
            }
        }

        Some(Command::Fingerprints(args)) => {
            let client = ApiClient::new(&args.conn.host, args.conn.port, cli.token);
            match args.command {
                FingerprintsCommand::Summary => {
                    commands::cmd_fingerprints_summary(&client, output).await
                }
            }
        }

        // No subcommand = run the agent daemon
        None => ebpfsentinel_agent::startup::run(&cli.config, cli.log_level, cli.log_format).await,
    }
}
