use clap::{Args, Parser, Subcommand, ValueEnum};
use infrastructure::config::{LogFormat, LogLevel};
use infrastructure::constants::{DEFAULT_CONFIG_PATH, DEFAULT_HTTP_PORT};

#[derive(Parser, Debug)]
#[command(
    name = "ebpfsentinel-agent",
    about = "eBPFsentinel network security agent",
    version = env!("CARGO_PKG_VERSION"),
)]
pub struct Cli {
    /// Path to the YAML configuration file
    #[arg(short, long, default_value = DEFAULT_CONFIG_PATH)]
    pub config: String,

    /// Log level override (takes precedence over config file)
    #[arg(short, long)]
    pub log_level: Option<LogLevel>,

    /// Log format: json (default, production) or text (development)
    #[arg(long)]
    pub log_format: Option<LogFormat>,

    /// Bearer token for authenticated API requests
    #[arg(long, env = "EBPFSENTINEL_TOKEN", global = true)]
    pub token: Option<String>,

    /// Output format
    #[arg(short, long, default_value = "table", global = true)]
    pub output: OutputFormat,

    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Output format for CLI commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// Human-readable table (default)
    Table,
    /// Raw JSON from the API
    Json,
}

/// Connection parameters for reaching a running agent.
#[derive(Args, Debug, Clone)]
pub struct ConnectionArgs {
    /// Agent API host
    #[arg(long, default_value = "127.0.0.1", env = "EBPFSENTINEL_HOST")]
    pub host: String,

    /// Agent API port
    #[arg(long, default_value_t = DEFAULT_HTTP_PORT, env = "EBPFSENTINEL_PORT")]
    pub port: u16,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Display version and build information
    Version,

    /// Query running agent status
    Status {
        #[command(flatten)]
        conn: ConnectionArgs,
    },

    /// Check agent liveness and readiness
    Health {
        #[command(flatten)]
        conn: ConnectionArgs,
    },

    /// Display Prometheus metrics
    Metrics {
        #[command(flatten)]
        conn: ConnectionArgs,
    },

    /// Manage firewall L3/L4 rules
    Firewall(DomainArgs<FirewallCommand>),

    /// Manage L7 firewall rules
    L7(DomainArgs<L7Command>),

    /// Manage Intrusion Prevention System
    Ips(DomainArgs<IpsCommand>),

    /// Manage rate limiting rules
    Ratelimit(DomainArgs<RatelimitCommand>),

    /// Threat intelligence status and data
    Threatintel(DomainArgs<ThreatintelCommand>),

    /// List and manage alerts
    Alerts(DomainArgs<AlertsCommand>),

    /// View audit logs and rule history
    Audit(DomainArgs<AuditCommand>),

    /// DNS intelligence: cache, stats, blocklist
    Dns(DomainArgs<DnsCommand>),

    /// Domain intelligence: reputation, blocklist management
    Domains(DomainArgs<DomainsCommand>),
}

/// Generic domain args: connection + subcommand.
#[derive(Args, Debug)]
pub struct DomainArgs<T: Subcommand> {
    #[command(flatten)]
    pub conn: ConnectionArgs,

    #[command(subcommand)]
    pub command: T,
}

// ── Firewall ────────────────────────────────────────────────────────────

#[derive(Subcommand, Debug)]
pub enum FirewallCommand {
    /// List all firewall rules
    List,
    /// Add a new firewall rule from inline JSON
    Add {
        /// JSON rule body
        #[arg(long)]
        json: String,
    },
    /// Delete a firewall rule by ID
    Delete {
        /// Rule ID to delete
        id: String,
    },
}

// ── L7 ──────────────────────────────────────────────────────────────────

#[derive(Subcommand, Debug)]
pub enum L7Command {
    /// List all L7 firewall rules
    List,
    /// Add a new L7 rule from inline JSON
    Add {
        /// JSON rule body
        #[arg(long)]
        json: String,
    },
    /// Delete an L7 rule by ID
    Delete {
        /// Rule ID to delete
        id: String,
    },
}

// ── IPS ─────────────────────────────────────────────────────────────────

#[derive(Subcommand, Debug)]
pub enum IpsCommand {
    /// List all IPS rules
    List,
    /// List blacklisted IPs
    Blacklist,
    /// List domain-based IPS blocks (from DNS blocklist or reputation)
    DomainBlocks,
    /// Set IPS rule mode (alert or block)
    SetMode {
        /// Rule ID
        id: String,
        /// New mode
        #[arg(long)]
        mode: String,
    },
}

// ── Rate Limiting ───────────────────────────────────────────────────────

#[derive(Subcommand, Debug)]
pub enum RatelimitCommand {
    /// List all rate limiting rules
    List,
    /// Add a new rate limiting rule from inline JSON
    Add {
        /// JSON rule body
        #[arg(long)]
        json: String,
    },
    /// Delete a rate limiting rule by ID
    Delete {
        /// Rule ID to delete
        id: String,
    },
}

// ── Threat Intelligence ─────────────────────────────────────────────────

#[derive(Subcommand, Debug)]
pub enum ThreatintelCommand {
    /// Show threat intelligence status
    Status,
    /// List Indicators of Compromise
    Iocs,
    /// List configured feeds
    Feeds,
}

// ── Alerts ──────────────────────────────────────────────────────────────

#[derive(Subcommand, Debug)]
pub enum AlertsCommand {
    /// List alerts with optional filters
    List {
        /// Filter by component (ids, dlp, threatintel, etc.)
        #[arg(long)]
        component: Option<String>,
        /// Filter by minimum severity (low, medium, high, critical)
        #[arg(long)]
        severity: Option<String>,
        /// Maximum number of results
        #[arg(long, default_value_t = 100)]
        limit: u64,
        /// Offset for pagination
        #[arg(long, default_value_t = 0)]
        offset: u64,
    },
    /// Mark an alert as false positive
    MarkFp {
        /// Alert ID to mark
        id: String,
    },
}

// ── Audit ───────────────────────────────────────────────────────────────

#[derive(Subcommand, Debug)]
pub enum AuditCommand {
    /// List audit log entries
    Logs {
        /// Filter by component
        #[arg(long)]
        component: Option<String>,
        /// Filter by action
        #[arg(long)]
        action: Option<String>,
        /// Maximum number of results
        #[arg(long, default_value_t = 100)]
        limit: u64,
        /// Offset for pagination
        #[arg(long, default_value_t = 0)]
        offset: u64,
    },
    /// Show change history for a specific rule
    History {
        /// Rule ID
        id: String,
    },
}

// ── Domains ─────────────────────────────────────────────────────────────

#[derive(Subcommand, Debug)]
pub enum DomainsCommand {
    /// List domain reputations
    Reputation {
        /// Filter by domain (exact match)
        #[arg(long)]
        domain: Option<String>,
        /// Minimum reputation score (0.0–1.0)
        #[arg(long)]
        min_score: Option<f64>,
        /// Page number (0-indexed)
        #[arg(long, default_value_t = 0)]
        page: usize,
        /// Page size
        #[arg(long, default_value_t = 50)]
        page_size: usize,
    },
    /// Add a domain to the runtime blocklist
    Block {
        /// Domain pattern to block (e.g. "evil.com" or "*.malware.com")
        domain: String,
    },
    /// Remove a domain from the runtime blocklist
    Unblock {
        /// Domain pattern to unblock
        domain: String,
    },
}

// ── DNS ─────────────────────────────────────────────────────────────────

#[derive(Subcommand, Debug)]
pub enum DnsCommand {
    /// List DNS cache entries
    Cache {
        /// Filter by domain substring
        #[arg(long)]
        domain: Option<String>,
        /// Reverse lookup by IP
        #[arg(long)]
        ip: Option<String>,
        /// Page number (0-indexed)
        #[arg(long, default_value_t = 0)]
        page: usize,
        /// Page size
        #[arg(long, default_value_t = 50)]
        page_size: usize,
    },
    /// Show DNS cache and blocklist statistics
    Stats,
    /// List loaded blocklist rules
    Blocklist,
    /// Flush the DNS cache
    Flush,
}

pub fn parse() -> Cli {
    Cli::parse()
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn cli_default_config_path() {
        let cli = Cli::try_parse_from(["ebpfsentinel-agent"]).unwrap();
        assert_eq!(cli.config, DEFAULT_CONFIG_PATH);
        assert!(cli.log_level.is_none());
        assert!(cli.command.is_none());
    }

    #[test]
    fn cli_custom_config_path() {
        let cli =
            Cli::try_parse_from(["ebpfsentinel-agent", "--config", "/tmp/test.yaml"]).unwrap();
        assert_eq!(cli.config, "/tmp/test.yaml");
    }

    #[test]
    fn cli_log_level_override() {
        let cli = Cli::try_parse_from(["ebpfsentinel-agent", "--log-level", "debug"]).unwrap();
        assert_eq!(cli.log_level, Some(LogLevel::Debug));
    }

    #[test]
    fn cli_version_subcommand() {
        let cli = Cli::try_parse_from(["ebpfsentinel-agent", "version"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Version)));
    }

    #[test]
    fn cli_status_subcommand() {
        let cli = Cli::try_parse_from(["ebpfsentinel-agent", "status"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Status { .. })));
    }

    #[test]
    fn cli_status_with_connection_args() {
        let cli = Cli::try_parse_from([
            "ebpfsentinel-agent",
            "status",
            "--host",
            "10.0.0.1",
            "--port",
            "9090",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Status { conn }) => {
                assert_eq!(conn.host, "10.0.0.1");
                assert_eq!(conn.port, 9090);
            }
            _ => panic!("expected Status command"),
        }
    }

    #[test]
    fn cli_token_global_flag() {
        let cli =
            Cli::try_parse_from(["ebpfsentinel-agent", "--token", "my-secret-token", "status"])
                .unwrap();
        assert_eq!(cli.token.as_deref(), Some("my-secret-token"));
    }

    #[test]
    fn cli_output_json() {
        let cli =
            Cli::try_parse_from(["ebpfsentinel-agent", "--output", "json", "status"]).unwrap();
        assert_eq!(cli.output, OutputFormat::Json);
    }

    #[test]
    fn cli_output_table_default() {
        let cli = Cli::try_parse_from(["ebpfsentinel-agent", "status"]).unwrap();
        assert_eq!(cli.output, OutputFormat::Table);
    }

    #[test]
    fn cli_health_subcommand() {
        let cli = Cli::try_parse_from(["ebpfsentinel-agent", "health"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Health { .. })));
    }

    #[test]
    fn cli_metrics_subcommand() {
        let cli = Cli::try_parse_from(["ebpfsentinel-agent", "metrics"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Metrics { .. })));
    }

    #[test]
    fn cli_firewall_list() {
        let cli = Cli::try_parse_from(["ebpfsentinel-agent", "firewall", "list"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Firewall(DomainArgs {
                command: FirewallCommand::List,
                ..
            }))
        ));
    }

    #[test]
    fn cli_firewall_add() {
        let cli = Cli::try_parse_from([
            "ebpfsentinel-agent",
            "firewall",
            "add",
            "--json",
            r#"{"id":"fw-001"}"#,
        ])
        .unwrap();
        match cli.command {
            Some(Command::Firewall(args)) => match args.command {
                FirewallCommand::Add { json } => assert!(json.contains("fw-001")),
                _ => panic!("expected Add"),
            },
            _ => panic!("expected Firewall command"),
        }
    }

    #[test]
    fn cli_firewall_delete() {
        let cli =
            Cli::try_parse_from(["ebpfsentinel-agent", "firewall", "delete", "fw-001"]).unwrap();
        match cli.command {
            Some(Command::Firewall(args)) => match args.command {
                FirewallCommand::Delete { id } => assert_eq!(id, "fw-001"),
                _ => panic!("expected Delete"),
            },
            _ => panic!("expected Firewall command"),
        }
    }

    #[test]
    fn cli_l7_list() {
        let cli = Cli::try_parse_from(["ebpfsentinel-agent", "l7", "list"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::L7(DomainArgs {
                command: L7Command::List,
                ..
            }))
        ));
    }

    #[test]
    fn cli_ips_list() {
        let cli = Cli::try_parse_from(["ebpfsentinel-agent", "ips", "list"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Ips(DomainArgs {
                command: IpsCommand::List,
                ..
            }))
        ));
    }

    #[test]
    fn cli_ips_blacklist() {
        let cli = Cli::try_parse_from(["ebpfsentinel-agent", "ips", "blacklist"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Ips(DomainArgs {
                command: IpsCommand::Blacklist,
                ..
            }))
        ));
    }

    #[test]
    fn cli_ips_domain_blocks() {
        let cli = Cli::try_parse_from(["ebpfsentinel-agent", "ips", "domain-blocks"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Ips(DomainArgs {
                command: IpsCommand::DomainBlocks,
                ..
            }))
        ));
    }

    #[test]
    fn cli_ips_set_mode() {
        let cli = Cli::try_parse_from([
            "ebpfsentinel-agent",
            "ips",
            "set-mode",
            "ips-001",
            "--mode",
            "block",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Ips(args)) => match args.command {
                IpsCommand::SetMode { id, mode } => {
                    assert_eq!(id, "ips-001");
                    assert_eq!(mode, "block");
                }
                _ => panic!("expected SetMode"),
            },
            _ => panic!("expected Ips command"),
        }
    }

    #[test]
    fn cli_ratelimit_list() {
        let cli = Cli::try_parse_from(["ebpfsentinel-agent", "ratelimit", "list"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Ratelimit(DomainArgs {
                command: RatelimitCommand::List,
                ..
            }))
        ));
    }

    #[test]
    fn cli_threatintel_status() {
        let cli = Cli::try_parse_from(["ebpfsentinel-agent", "threatintel", "status"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Threatintel(DomainArgs {
                command: ThreatintelCommand::Status,
                ..
            }))
        ));
    }

    #[test]
    fn cli_threatintel_iocs() {
        let cli = Cli::try_parse_from(["ebpfsentinel-agent", "threatintel", "iocs"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Threatintel(DomainArgs {
                command: ThreatintelCommand::Iocs,
                ..
            }))
        ));
    }

    #[test]
    fn cli_threatintel_feeds() {
        let cli = Cli::try_parse_from(["ebpfsentinel-agent", "threatintel", "feeds"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Threatintel(DomainArgs {
                command: ThreatintelCommand::Feeds,
                ..
            }))
        ));
    }

    #[test]
    fn cli_alerts_list() {
        let cli = Cli::try_parse_from(["ebpfsentinel-agent", "alerts", "list"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Alerts(DomainArgs {
                command: AlertsCommand::List { .. },
                ..
            }))
        ));
    }

    #[test]
    fn cli_alerts_list_with_filters() {
        let cli = Cli::try_parse_from([
            "ebpfsentinel-agent",
            "alerts",
            "list",
            "--component",
            "ids",
            "--severity",
            "high",
            "--limit",
            "50",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Alerts(args)) => match args.command {
                AlertsCommand::List {
                    component,
                    severity,
                    limit,
                    offset,
                } => {
                    assert_eq!(component.as_deref(), Some("ids"));
                    assert_eq!(severity.as_deref(), Some("high"));
                    assert_eq!(limit, 50);
                    assert_eq!(offset, 0);
                }
                _ => panic!("expected List"),
            },
            _ => panic!("expected Alerts command"),
        }
    }

    #[test]
    fn cli_alerts_mark_fp() {
        let cli =
            Cli::try_parse_from(["ebpfsentinel-agent", "alerts", "mark-fp", "alert-001"]).unwrap();
        match cli.command {
            Some(Command::Alerts(args)) => match args.command {
                AlertsCommand::MarkFp { id } => assert_eq!(id, "alert-001"),
                _ => panic!("expected MarkFp"),
            },
            _ => panic!("expected Alerts command"),
        }
    }

    #[test]
    fn cli_audit_logs() {
        let cli = Cli::try_parse_from(["ebpfsentinel-agent", "audit", "logs"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Audit(DomainArgs {
                command: AuditCommand::Logs { .. },
                ..
            }))
        ));
    }

    #[test]
    fn cli_audit_history() {
        let cli =
            Cli::try_parse_from(["ebpfsentinel-agent", "audit", "history", "fw-001"]).unwrap();
        match cli.command {
            Some(Command::Audit(args)) => match args.command {
                AuditCommand::History { id } => assert_eq!(id, "fw-001"),
                _ => panic!("expected History"),
            },
            _ => panic!("expected Audit command"),
        }
    }

    #[test]
    fn cli_firewall_with_connection_args() {
        let cli = Cli::try_parse_from([
            "ebpfsentinel-agent",
            "firewall",
            "--host",
            "192.168.1.1",
            "--port",
            "3000",
            "list",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Firewall(args)) => {
                assert_eq!(args.conn.host, "192.168.1.1");
                assert_eq!(args.conn.port, 3000);
            }
            _ => panic!("expected Firewall command"),
        }
    }

    #[test]
    fn cli_log_format_json() {
        let cli = Cli::try_parse_from(["ebpfsentinel-agent", "--log-format", "json"]).unwrap();
        assert_eq!(cli.log_format, Some(LogFormat::Json));
    }

    #[test]
    fn cli_log_format_text() {
        let cli = Cli::try_parse_from(["ebpfsentinel-agent", "--log-format", "text"]).unwrap();
        assert_eq!(cli.log_format, Some(LogFormat::Text));
    }

    #[test]
    fn cli_log_format_invalid_rejected() {
        let result = Cli::try_parse_from(["ebpfsentinel-agent", "--log-format", "xml"]);
        assert!(result.is_err());
    }

    #[test]
    fn cli_invalid_log_level_rejected() {
        let result = Cli::try_parse_from(["ebpfsentinel-agent", "--log-level", "banana"]);
        assert!(result.is_err());
    }

    #[test]
    fn cli_output_invalid_rejected() {
        let result = Cli::try_parse_from(["ebpfsentinel-agent", "--output", "xml"]);
        assert!(result.is_err());
    }

    #[test]
    fn cli_dns_cache() {
        let cli = Cli::try_parse_from(["ebpfsentinel-agent", "dns", "cache"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Dns(DomainArgs {
                command: DnsCommand::Cache { .. },
                ..
            }))
        ));
    }

    #[test]
    fn cli_dns_cache_with_domain_filter() {
        let cli = Cli::try_parse_from([
            "ebpfsentinel-agent",
            "dns",
            "cache",
            "--domain",
            "example.com",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Dns(args)) => match args.command {
                DnsCommand::Cache { domain, ip, .. } => {
                    assert_eq!(domain.as_deref(), Some("example.com"));
                    assert!(ip.is_none());
                }
                _ => panic!("expected Cache"),
            },
            _ => panic!("expected Dns command"),
        }
    }

    #[test]
    fn cli_dns_cache_with_ip_filter() {
        let cli =
            Cli::try_parse_from(["ebpfsentinel-agent", "dns", "cache", "--ip", "1.2.3.4"]).unwrap();
        match cli.command {
            Some(Command::Dns(args)) => match args.command {
                DnsCommand::Cache { ip, .. } => {
                    assert_eq!(ip.as_deref(), Some("1.2.3.4"));
                }
                _ => panic!("expected Cache"),
            },
            _ => panic!("expected Dns command"),
        }
    }

    #[test]
    fn cli_dns_stats() {
        let cli = Cli::try_parse_from(["ebpfsentinel-agent", "dns", "stats"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Dns(DomainArgs {
                command: DnsCommand::Stats,
                ..
            }))
        ));
    }

    #[test]
    fn cli_dns_blocklist() {
        let cli = Cli::try_parse_from(["ebpfsentinel-agent", "dns", "blocklist"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Dns(DomainArgs {
                command: DnsCommand::Blocklist,
                ..
            }))
        ));
    }

    #[test]
    fn cli_dns_flush() {
        let cli = Cli::try_parse_from(["ebpfsentinel-agent", "dns", "flush"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Dns(DomainArgs {
                command: DnsCommand::Flush,
                ..
            }))
        ));
    }

    #[test]
    fn cli_domains_reputation() {
        let cli = Cli::try_parse_from(["ebpfsentinel-agent", "domains", "reputation"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Domains(DomainArgs {
                command: DomainsCommand::Reputation { .. },
                ..
            }))
        ));
    }

    #[test]
    fn cli_domains_reputation_with_filters() {
        let cli = Cli::try_parse_from([
            "ebpfsentinel-agent",
            "domains",
            "reputation",
            "--domain",
            "evil.com",
            "--min-score",
            "0.7",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Domains(args)) => match args.command {
                DomainsCommand::Reputation {
                    domain, min_score, ..
                } => {
                    assert_eq!(domain.as_deref(), Some("evil.com"));
                    assert!((min_score.unwrap() - 0.7).abs() < 0.01);
                }
                _ => panic!("expected Reputation"),
            },
            _ => panic!("expected Domains command"),
        }
    }

    #[test]
    fn cli_domains_block() {
        let cli =
            Cli::try_parse_from(["ebpfsentinel-agent", "domains", "block", "evil.com"]).unwrap();
        match cli.command {
            Some(Command::Domains(args)) => match args.command {
                DomainsCommand::Block { domain } => assert_eq!(domain, "evil.com"),
                _ => panic!("expected Block"),
            },
            _ => panic!("expected Domains command"),
        }
    }

    #[test]
    fn cli_domains_unblock() {
        let cli =
            Cli::try_parse_from(["ebpfsentinel-agent", "domains", "unblock", "evil.com"]).unwrap();
        match cli.command {
            Some(Command::Domains(args)) => match args.command {
                DomainsCommand::Unblock { domain } => assert_eq!(domain, "evil.com"),
                _ => panic!("expected Unblock"),
            },
            _ => panic!("expected Domains command"),
        }
    }
}
