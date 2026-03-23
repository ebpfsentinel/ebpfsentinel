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

    /// Top talkers — live view of most active connections by traffic volume
    Top {
        #[command(flatten)]
        conn: ConnectionArgs,

        /// Number of entries to display
        #[arg(short = 'n', long, default_value_t = 20)]
        limit: usize,

        /// Sort by: bytes (default), packets, or alerts
        #[arg(short, long, default_value = "bytes")]
        sort: String,
    },

    /// Network flows — aggregated connection map from conntrack
    Flows {
        #[command(flatten)]
        conn: ConnectionArgs,

        /// Maximum connections to fetch for aggregation
        #[arg(short = 'n', long, default_value_t = 1000)]
        limit: usize,
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

    /// `DDoS` protection: status, attacks, policies
    Ddos(DomainArgs<DdosCommand>),

    /// Load balancer: status, services, backends
    Lb(DomainArgs<LbCommand>),

    /// `QoS` / traffic shaping: status, pipes, queues, classifiers
    Qos(DomainArgs<QosCommand>),

    /// NAT: status, rules, `NPTv6` prefix translation
    Nat(DomainArgs<NatCommand>),

    /// MITRE ATT&CK: coverage matrix
    Mitre(DomainArgs<MitreCommand>),

    /// TLS fingerprints: JA4+ cache and analysis
    Fingerprints(DomainArgs<FingerprintsCommand>),

    /// Manual response actions: block/throttle with TTL
    Responses(DomainArgs<ResponsesCommand>),

    /// Manual packet capture (pcap)
    Capture(DomainArgs<CaptureCommand>),
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
        /// Filter by MITRE ATT&CK tactic (e.g. exfiltration, impact)
        #[arg(long)]
        tactic: Option<String>,
        /// Filter by MITRE ATT&CK technique ID (e.g. T1041)
        #[arg(long)]
        technique: Option<String>,
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

// ── MITRE ATT&CK ────────────────────────────────────────────────────────

#[derive(Subcommand, Debug)]
pub enum MitreCommand {
    /// Show MITRE ATT&CK coverage matrix for active features
    Coverage,
}

// ── Fingerprints ────────────────────────────────────────────────────────

#[derive(Subcommand, Debug)]
pub enum FingerprintsCommand {
    /// Show JA4+ fingerprint cache summary
    Summary,
}

// ── Capture ─────────────────────────────────────────────────────────────

#[derive(Subcommand, Debug)]
pub enum CaptureCommand {
    /// Start a time-bounded packet capture
    Start {
        /// BPF filter expression (e.g. "host 1.2.3.4 and port 443")
        #[arg(long)]
        filter: String,
        /// Capture duration (e.g. 60s, 5m)
        #[arg(long, default_value = "60s")]
        duration: String,
        /// Snap length in bytes
        #[arg(long, default_value_t = 1500)]
        snap_length: u32,
        /// Network interface
        #[arg(long)]
        interface: Option<String>,
    },
    /// Stop a running capture
    Stop {
        /// Capture session ID
        id: String,
    },
    /// List all capture sessions
    List,
}

// ── Responses ───────────────────────────────────────────────────────────

#[derive(Subcommand, Debug)]
pub enum ResponsesCommand {
    /// List active response actions
    List,
    /// Create a time-bounded block or throttle
    Create {
        /// Action type: `block_ip` or `throttle_ip`
        #[arg(long)]
        action: String,
        /// Target IP or CIDR
        #[arg(long)]
        target: String,
        /// TTL duration (e.g. 1h, 30m, 3600s)
        #[arg(long)]
        ttl: String,
        /// Rate limit in pps (for `throttle_ip`)
        #[arg(long)]
        rate_pps: Option<u64>,
    },
    /// Revoke a response action early
    Revoke {
        /// Response action ID
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

// ── DDoS ────────────────────────────────────────────────────────────────

#[derive(Subcommand, Debug)]
pub enum DdosCommand {
    /// Show `DDoS` protection status
    Status,
    /// List active `DDoS` attacks
    Attacks,
    /// List historical `DDoS` attacks
    History {
        /// Maximum number of results
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    /// List `DDoS` mitigation policies
    Policies,
    /// Add a new `DDoS` policy from inline JSON
    Add {
        /// JSON policy body
        #[arg(long)]
        json: String,
    },
    /// Delete a `DDoS` policy by ID
    Delete {
        /// Policy ID to delete
        id: String,
    },
}

// ── Load Balancer ──────────────────────────────────────────────────────

#[derive(Subcommand, Debug)]
pub enum LbCommand {
    /// Show load balancer status
    Status,
    /// List all load balancer services
    Services,
    /// Show a specific service and its backends
    Service {
        /// Service ID
        id: String,
    },
    /// Add a new load balancer service from inline JSON
    Add {
        /// JSON service body
        #[arg(long)]
        json: String,
    },
    /// Delete a load balancer service by ID
    Delete {
        /// Service ID to delete
        id: String,
    },
}

// ── QoS ─────────────────────────────────────────────────────────────────

#[derive(Subcommand, Debug)]
pub enum QosCommand {
    /// Show `QoS` / traffic shaping status
    Status,
    /// List all `QoS` pipes
    Pipes,
    /// List all `QoS` queues
    Queues,
    /// List all `QoS` classifiers
    Classifiers,
    /// Add a new `QoS` pipe from inline JSON
    AddPipe {
        /// JSON pipe body
        #[arg(long)]
        json: String,
    },
    /// Delete a `QoS` pipe by ID
    DeletePipe {
        /// Pipe ID to delete
        id: String,
    },
    /// Add a new `QoS` queue from inline JSON
    AddQueue {
        /// JSON queue body
        #[arg(long)]
        json: String,
    },
    /// Delete a `QoS` queue by ID
    DeleteQueue {
        /// Queue ID to delete
        id: String,
    },
    /// Add a new `QoS` classifier from inline JSON
    AddClassifier {
        /// JSON classifier body
        #[arg(long)]
        json: String,
    },
    /// Delete a `QoS` classifier by ID
    DeleteClassifier {
        /// Classifier ID to delete
        id: String,
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

// ── NAT ──────────────────────────────────────────────────────────────────

#[derive(Subcommand, Debug)]
pub enum NatCommand {
    /// Show NAT status
    Status,
    /// List all NAT rules (DNAT + SNAT)
    Rules,
    /// `NPTv6` (RFC 6296) prefix translation management
    #[command(subcommand)]
    Nptv6(NptV6Command),
}

#[derive(Subcommand, Debug)]
pub enum NptV6Command {
    /// List `NPTv6` prefix translation rules
    List,
    /// Create an `NPTv6` prefix translation rule
    Create {
        /// Rule ID
        #[arg(long)]
        id: String,
        /// Internal (site-local) IPv6 prefix, e.g. `fd00:1::`
        #[arg(long)]
        internal_prefix: String,
        /// External (provider) IPv6 prefix, e.g. `2001:db8:1::`
        #[arg(long)]
        external_prefix: String,
        /// Prefix length in bits (1-64)
        #[arg(long)]
        prefix_len: u8,
    },
    /// Delete an `NPTv6` rule by ID
    Delete {
        /// Rule ID to delete
        id: String,
    },
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
                    tactic,
                    technique,
                    limit,
                    offset,
                } => {
                    assert_eq!(component.as_deref(), Some("ids"));
                    assert_eq!(severity.as_deref(), Some("high"));
                    assert!(tactic.is_none());
                    assert!(technique.is_none());
                    assert_eq!(limit, 50);
                    assert_eq!(offset, 0);
                }
                AlertsCommand::MarkFp { .. } => panic!("expected List"),
            },
            _ => panic!("expected Alerts command"),
        }
    }

    #[test]
    fn cli_alerts_list_with_mitre_filters() {
        let cli = Cli::try_parse_from([
            "ebpfsentinel-agent",
            "alerts",
            "list",
            "--tactic",
            "exfiltration",
            "--technique",
            "T1041",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Alerts(args)) => match args.command {
                AlertsCommand::List {
                    tactic, technique, ..
                } => {
                    assert_eq!(tactic.as_deref(), Some("exfiltration"));
                    assert_eq!(technique.as_deref(), Some("T1041"));
                }
                AlertsCommand::MarkFp { .. } => panic!("expected List"),
            },
            _ => panic!("expected Alerts command"),
        }
    }

    #[test]
    fn cli_mitre_coverage() {
        let cli = Cli::try_parse_from(["ebpfsentinel-agent", "mitre", "coverage"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Mitre(DomainArgs {
                command: MitreCommand::Coverage,
                ..
            }))
        ));
    }

    #[test]
    fn cli_alerts_mark_fp() {
        let cli =
            Cli::try_parse_from(["ebpfsentinel-agent", "alerts", "mark-fp", "alert-001"]).unwrap();
        match cli.command {
            Some(Command::Alerts(args)) => match args.command {
                AlertsCommand::MarkFp { id } => assert_eq!(id, "alert-001"),
                AlertsCommand::List { .. } => panic!("expected MarkFp"),
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
                AuditCommand::Logs { .. } => panic!("expected History"),
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

    #[test]
    fn cli_ddos_status() {
        let cli = Cli::try_parse_from(["ebpfsentinel-agent", "ddos", "status"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Ddos(DomainArgs {
                command: DdosCommand::Status,
                ..
            }))
        ));
    }

    #[test]
    fn cli_ddos_attacks() {
        let cli = Cli::try_parse_from(["ebpfsentinel-agent", "ddos", "attacks"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Ddos(DomainArgs {
                command: DdosCommand::Attacks,
                ..
            }))
        ));
    }

    #[test]
    fn cli_ddos_history() {
        let cli = Cli::try_parse_from(["ebpfsentinel-agent", "ddos", "history"]).unwrap();
        match cli.command {
            Some(Command::Ddos(args)) => match args.command {
                DdosCommand::History { limit } => assert_eq!(limit, 100),
                _ => panic!("expected History"),
            },
            _ => panic!("expected Ddos command"),
        }
    }

    #[test]
    fn cli_ddos_history_with_limit() {
        let cli = Cli::try_parse_from(["ebpfsentinel-agent", "ddos", "history", "--limit", "50"])
            .unwrap();
        match cli.command {
            Some(Command::Ddos(args)) => match args.command {
                DdosCommand::History { limit } => assert_eq!(limit, 50),
                _ => panic!("expected History"),
            },
            _ => panic!("expected Ddos command"),
        }
    }

    #[test]
    fn cli_ddos_policies() {
        let cli = Cli::try_parse_from(["ebpfsentinel-agent", "ddos", "policies"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Ddos(DomainArgs {
                command: DdosCommand::Policies,
                ..
            }))
        ));
    }

    #[test]
    fn cli_ddos_add() {
        let cli = Cli::try_parse_from([
            "ebpfsentinel-agent",
            "ddos",
            "add",
            "--json",
            r#"{"id":"ddos-001","attack_type":"syn_flood","detection_threshold_pps":5000}"#,
        ])
        .unwrap();
        match cli.command {
            Some(Command::Ddos(args)) => match args.command {
                DdosCommand::Add { json } => assert!(json.contains("ddos-001")),
                _ => panic!("expected Add"),
            },
            _ => panic!("expected Ddos command"),
        }
    }

    #[test]
    fn cli_ddos_delete() {
        let cli =
            Cli::try_parse_from(["ebpfsentinel-agent", "ddos", "delete", "ddos-001"]).unwrap();
        match cli.command {
            Some(Command::Ddos(args)) => match args.command {
                DdosCommand::Delete { id } => assert_eq!(id, "ddos-001"),
                _ => panic!("expected Delete"),
            },
            _ => panic!("expected Ddos command"),
        }
    }

    #[test]
    fn cli_lb_status() {
        let cli = Cli::try_parse_from(["ebpfsentinel-agent", "lb", "status"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Lb(DomainArgs {
                command: LbCommand::Status,
                ..
            }))
        ));
    }

    #[test]
    fn cli_lb_services() {
        let cli = Cli::try_parse_from(["ebpfsentinel-agent", "lb", "services"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Lb(DomainArgs {
                command: LbCommand::Services,
                ..
            }))
        ));
    }

    #[test]
    fn cli_lb_service() {
        let cli = Cli::try_parse_from(["ebpfsentinel-agent", "lb", "service", "lb-001"]).unwrap();
        match cli.command {
            Some(Command::Lb(args)) => match args.command {
                LbCommand::Service { id } => assert_eq!(id, "lb-001"),
                _ => panic!("expected Service"),
            },
            _ => panic!("expected Lb command"),
        }
    }

    #[test]
    fn cli_lb_add() {
        let cli = Cli::try_parse_from([
            "ebpfsentinel-agent",
            "lb",
            "add",
            "--json",
            r#"{"id":"lb-001","name":"web","protocol":"tcp","listen_port":443,"backends":[{"id":"be-1","addr":"10.0.0.1","port":8080}]}"#,
        ])
        .unwrap();
        match cli.command {
            Some(Command::Lb(args)) => match args.command {
                LbCommand::Add { json } => assert!(json.contains("lb-001")),
                _ => panic!("expected Add"),
            },
            _ => panic!("expected Lb command"),
        }
    }

    #[test]
    fn cli_lb_delete() {
        let cli = Cli::try_parse_from(["ebpfsentinel-agent", "lb", "delete", "lb-001"]).unwrap();
        match cli.command {
            Some(Command::Lb(args)) => match args.command {
                LbCommand::Delete { id } => assert_eq!(id, "lb-001"),
                _ => panic!("expected Delete"),
            },
            _ => panic!("expected Lb command"),
        }
    }

    #[test]
    fn cli_qos_status() {
        let cli = Cli::try_parse_from(["ebpfsentinel-agent", "qos", "status"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Qos(DomainArgs {
                command: QosCommand::Status,
                ..
            }))
        ));
    }

    #[test]
    fn cli_qos_pipes() {
        let cli = Cli::try_parse_from(["ebpfsentinel-agent", "qos", "pipes"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Qos(DomainArgs {
                command: QosCommand::Pipes,
                ..
            }))
        ));
    }

    #[test]
    fn cli_qos_queues() {
        let cli = Cli::try_parse_from(["ebpfsentinel-agent", "qos", "queues"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Qos(DomainArgs {
                command: QosCommand::Queues,
                ..
            }))
        ));
    }

    #[test]
    fn cli_qos_classifiers() {
        let cli = Cli::try_parse_from(["ebpfsentinel-agent", "qos", "classifiers"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Qos(DomainArgs {
                command: QosCommand::Classifiers,
                ..
            }))
        ));
    }

    #[test]
    fn cli_qos_add_pipe() {
        let cli = Cli::try_parse_from([
            "ebpfsentinel-agent",
            "qos",
            "add-pipe",
            "--json",
            r#"{"id":"pipe-1","rate_bps":1000000}"#,
        ])
        .unwrap();
        match cli.command {
            Some(Command::Qos(args)) => match args.command {
                QosCommand::AddPipe { json } => assert!(json.contains("pipe-1")),
                _ => panic!("expected AddPipe"),
            },
            _ => panic!("expected Qos command"),
        }
    }

    #[test]
    fn cli_qos_delete_pipe() {
        let cli =
            Cli::try_parse_from(["ebpfsentinel-agent", "qos", "delete-pipe", "pipe-1"]).unwrap();
        match cli.command {
            Some(Command::Qos(args)) => match args.command {
                QosCommand::DeletePipe { id } => assert_eq!(id, "pipe-1"),
                _ => panic!("expected DeletePipe"),
            },
            _ => panic!("expected Qos command"),
        }
    }

    #[test]
    fn cli_qos_add_queue() {
        let cli = Cli::try_parse_from([
            "ebpfsentinel-agent",
            "qos",
            "add-queue",
            "--json",
            r#"{"id":"q-1","pipe_id":"pipe-1","weight":50}"#,
        ])
        .unwrap();
        match cli.command {
            Some(Command::Qos(args)) => match args.command {
                QosCommand::AddQueue { json } => assert!(json.contains("q-1")),
                _ => panic!("expected AddQueue"),
            },
            _ => panic!("expected Qos command"),
        }
    }

    #[test]
    fn cli_qos_delete_queue() {
        let cli =
            Cli::try_parse_from(["ebpfsentinel-agent", "qos", "delete-queue", "q-1"]).unwrap();
        match cli.command {
            Some(Command::Qos(args)) => match args.command {
                QosCommand::DeleteQueue { id } => assert_eq!(id, "q-1"),
                _ => panic!("expected DeleteQueue"),
            },
            _ => panic!("expected Qos command"),
        }
    }

    #[test]
    fn cli_qos_add_classifier() {
        let cli = Cli::try_parse_from([
            "ebpfsentinel-agent",
            "qos",
            "add-classifier",
            "--json",
            r#"{"id":"cls-1","queue_id":"q-1"}"#,
        ])
        .unwrap();
        match cli.command {
            Some(Command::Qos(args)) => match args.command {
                QosCommand::AddClassifier { json } => assert!(json.contains("cls-1")),
                _ => panic!("expected AddClassifier"),
            },
            _ => panic!("expected Qos command"),
        }
    }

    #[test]
    fn cli_qos_delete_classifier() {
        let cli = Cli::try_parse_from(["ebpfsentinel-agent", "qos", "delete-classifier", "cls-1"])
            .unwrap();
        match cli.command {
            Some(Command::Qos(args)) => match args.command {
                QosCommand::DeleteClassifier { id } => assert_eq!(id, "cls-1"),
                _ => panic!("expected DeleteClassifier"),
            },
            _ => panic!("expected Qos command"),
        }
    }

    // ── NAT ────────────────────────────────────────────────────────

    #[test]
    fn cli_nat_status() {
        let cli = Cli::try_parse_from(["ebpfsentinel-agent", "nat", "status"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Nat(DomainArgs {
                command: NatCommand::Status,
                ..
            }))
        ));
    }

    #[test]
    fn cli_nat_rules() {
        let cli = Cli::try_parse_from(["ebpfsentinel-agent", "nat", "rules"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Nat(DomainArgs {
                command: NatCommand::Rules,
                ..
            }))
        ));
    }

    #[test]
    fn cli_nat_nptv6_list() {
        let cli = Cli::try_parse_from(["ebpfsentinel-agent", "nat", "nptv6", "list"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Nat(DomainArgs {
                command: NatCommand::Nptv6(NptV6Command::List),
                ..
            }))
        ));
    }

    #[test]
    fn cli_nat_nptv6_create() {
        let cli = Cli::try_parse_from([
            "ebpfsentinel-agent",
            "nat",
            "nptv6",
            "create",
            "--id",
            "nptv6-1",
            "--internal-prefix",
            "fd00:1::",
            "--external-prefix",
            "2001:db8:1::",
            "--prefix-len",
            "48",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Nat(args)) => match args.command {
                NatCommand::Nptv6(NptV6Command::Create {
                    id,
                    internal_prefix,
                    external_prefix,
                    prefix_len,
                }) => {
                    assert_eq!(id, "nptv6-1");
                    assert_eq!(internal_prefix, "fd00:1::");
                    assert_eq!(external_prefix, "2001:db8:1::");
                    assert_eq!(prefix_len, 48);
                }
                _ => panic!("expected Nptv6 Create"),
            },
            _ => panic!("expected Nat command"),
        }
    }

    #[test]
    fn cli_nat_nptv6_delete() {
        let cli = Cli::try_parse_from(["ebpfsentinel-agent", "nat", "nptv6", "delete", "nptv6-1"])
            .unwrap();
        match cli.command {
            Some(Command::Nat(args)) => match args.command {
                NatCommand::Nptv6(NptV6Command::Delete { id }) => {
                    assert_eq!(id, "nptv6-1");
                }
                _ => panic!("expected Nptv6 Delete"),
            },
            _ => panic!("expected Nat command"),
        }
    }
}
