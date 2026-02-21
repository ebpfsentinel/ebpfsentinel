//! Shared parsing helpers and error types used across all config modules.

use std::path::Path;

use tracing::warn;

use domain::common::entity::{DomainMode, Protocol, Severity};
use domain::firewall::entity::{FirewallAction, IpNetwork};

// ── Security limits ────────────────────────────────────────────────
//
// Maximum counts per domain to prevent OOM from excessive config.
// These can be overridden via the `limits` section in the future.

/// Maximum firewall rules (must match `ebpf_common::firewall::MAX_FIREWALL_RULES`).
pub(super) const MAX_FIREWALL_RULES: usize = 4096;
/// Maximum IDS rules.
pub(super) const MAX_IDS_RULES: usize = 50_000;
/// Maximum IPS rules.
pub(super) const MAX_IPS_RULES: usize = 50_000;
/// Maximum L7 rules.
pub(super) const MAX_L7_RULES: usize = 10_000;
/// Maximum DLP patterns.
pub(super) const MAX_DLP_PATTERNS: usize = 1_000;
/// Maximum threat intel feeds.
pub(super) const MAX_THREATINTEL_FEEDS: usize = 100;
/// Maximum rate limit policies.
pub(super) const MAX_RATELIMIT_RULES: usize = 10_000;
/// Maximum alerting routes.
pub(super) const MAX_ALERTING_ROUTES: usize = 100;
/// Maximum compiled regex size (10 MiB) — matches domain engine limit.
pub(super) const REGEX_SIZE_LIMIT: usize = 10 * (1 << 20);
/// Maximum regex nesting depth — matches domain engine limit.
pub(super) const REGEX_NEST_LIMIT: u32 = 200;

// ── Config errors ──────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("I/O error reading config: {0}")]
    Io(#[from] std::io::Error),

    #[error("YAML parse error: {0}")]
    Yaml(String),

    #[error("validation error: {field}: {message}")]
    Validation { field: String, message: String },

    #[error("invalid CIDR notation '{value}': {reason}")]
    InvalidCidr { value: String, reason: String },

    #[error("invalid port range '{value}': {reason}")]
    InvalidPortRange { value: String, reason: String },

    #[error("invalid value '{value}' for field '{field}': expected one of {expected}")]
    InvalidValue {
        field: String,
        value: String,
        expected: String,
    },
}

impl From<serde_yaml_ng::Error> for ConfigError {
    fn from(e: serde_yaml_ng::Error) -> Self {
        Self::Yaml(e.to_string())
    }
}

// ── Shared serde defaults ──────────────────────────────────────────

pub(super) fn default_true() -> bool {
    true
}

pub(super) fn default_mode() -> String {
    "alert".to_string()
}

// ── Parsing helpers ────────────────────────────────────────────────

/// Parse a CIDR string into an `IpNetwork`.
///
/// Supports both IPv4 (`"192.168.1.0/24"`, `"10.0.0.1"`) and
/// IPv6 (`"2001:db8::/32"`, `"::1"`).
pub fn parse_cidr(s: &str) -> Result<IpNetwork, ConfigError> {
    // Detect IPv6 vs IPv4 by presence of ':'
    if s.contains(':') {
        parse_cidr_v6(s)
    } else {
        parse_cidr_v4(s)
    }
}

/// Parse an IPv4 CIDR string like `"192.168.1.0/24"` or `"10.0.0.1"`.
fn parse_cidr_v4(s: &str) -> Result<IpNetwork, ConfigError> {
    let (ip_str, prefix_len) = match s.split_once('/') {
        Some((ip, prefix)) => {
            let len = prefix.parse::<u8>().map_err(|_| ConfigError::InvalidCidr {
                value: s.to_string(),
                reason: format!("invalid prefix length: '{prefix}'"),
            })?;
            if len > 32 {
                return Err(ConfigError::InvalidCidr {
                    value: s.to_string(),
                    reason: format!("prefix length {len} must be 0-32"),
                });
            }
            (ip, len)
        }
        None => (s, 32),
    };

    let octets: Vec<&str> = ip_str.split('.').collect();
    if octets.len() != 4 {
        return Err(ConfigError::InvalidCidr {
            value: s.to_string(),
            reason: format!("expected 4 octets, got {}", octets.len()),
        });
    }

    let mut addr: u32 = 0;
    for (i, octet_str) in octets.iter().enumerate() {
        let octet = octet_str
            .parse::<u8>()
            .map_err(|_| ConfigError::InvalidCidr {
                value: s.to_string(),
                reason: format!("invalid octet: '{octet_str}'"),
            })?;
        addr |= u32::from(octet) << (24 - i * 8);
    }

    Ok(IpNetwork::V4 { addr, prefix_len })
}

/// Parse an IPv6 CIDR string like `"2001:db8::/32"` or `"::1"`.
fn parse_cidr_v6(s: &str) -> Result<IpNetwork, ConfigError> {
    let (ip_str, prefix_len) = match s.split_once('/') {
        Some((ip, prefix)) => {
            let len = prefix.parse::<u8>().map_err(|_| ConfigError::InvalidCidr {
                value: s.to_string(),
                reason: format!("invalid prefix length: '{prefix}'"),
            })?;
            if len > 128 {
                return Err(ConfigError::InvalidCidr {
                    value: s.to_string(),
                    reason: format!("prefix length {len} must be 0-128"),
                });
            }
            (ip, len)
        }
        None => (s, 128),
    };

    let ipv6_addr: std::net::Ipv6Addr = ip_str.parse().map_err(|e| ConfigError::InvalidCidr {
        value: s.to_string(),
        reason: format!("invalid IPv6 address: {e}"),
    })?;

    Ok(IpNetwork::V6 {
        addr: ipv6_addr.octets(),
        prefix_len,
    })
}

/// Log a warning if a file is world-readable (Unix only).
///
/// Security best practice: config files containing secrets (API keys,
/// auth headers, TLS keys) should be readable only by the owner
/// and group (mode 0640 or stricter).
#[cfg(unix)]
pub(super) fn warn_if_world_readable(path: &Path, label: &str) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(metadata) = std::fs::metadata(path) {
        let mode = metadata.permissions().mode();
        if mode & 0o004 != 0 {
            warn!(
                path = %path.display(),
                mode = format!("{mode:04o}"),
                "{label} is world-readable — consider chmod 640 or stricter",
            );
        }
    }
}

#[cfg(not(unix))]
pub(super) fn warn_if_world_readable(_path: &Path, _label: &str) {
    // File permission checks not available on non-Unix platforms.
}

/// Enforce a maximum count on a config collection.
pub(super) fn check_limit(field: &str, count: usize, max: usize) -> Result<(), ConfigError> {
    if count > max {
        return Err(ConfigError::Validation {
            field: field.to_string(),
            message: format!("count {count} exceeds maximum {max}"),
        });
    }
    Ok(())
}

/// Validate a regex pattern with size and nesting limits.
pub(super) fn validate_regex(pattern: &str, field: &str) -> Result<(), ConfigError> {
    regex::RegexBuilder::new(pattern)
        .size_limit(REGEX_SIZE_LIMIT)
        .nest_limit(REGEX_NEST_LIMIT)
        .build()
        .map_err(|e| ConfigError::Validation {
            field: field.to_string(),
            message: format!("invalid regex: {e}"),
        })?;
    Ok(())
}

/// Parse a domain mode string to the domain enum.
pub fn parse_domain_mode(s: &str) -> Result<DomainMode, ConfigError> {
    match s.to_lowercase().as_str() {
        "alert" | "monitor" | "observe" => Ok(DomainMode::Alert),
        "block" | "enforce" => Ok(DomainMode::Block),
        _ => Err(ConfigError::InvalidValue {
            field: "mode".to_string(),
            value: s.to_string(),
            expected: "alert, block".to_string(),
        }),
    }
}

pub(super) fn parse_action(s: &str) -> Result<FirewallAction, ()> {
    match s.to_lowercase().as_str() {
        "allow" | "pass" => Ok(FirewallAction::Allow),
        "deny" | "drop" | "block" => Ok(FirewallAction::Deny),
        "log" => Ok(FirewallAction::Log),
        _ => Err(()),
    }
}

pub(super) fn parse_protocol(s: &str) -> Result<Protocol, ()> {
    match s.to_lowercase().as_str() {
        "tcp" => Ok(Protocol::Tcp),
        "udp" => Ok(Protocol::Udp),
        "icmp" => Ok(Protocol::Icmp),
        "any" | "*" => Ok(Protocol::Any),
        _ => Err(()),
    }
}

pub(super) fn parse_severity(s: &str) -> Result<Severity, ()> {
    match s.to_lowercase().as_str() {
        "low" | "info" => Ok(Severity::Low),
        "medium" | "warning" => Ok(Severity::Medium),
        "high" => Ok(Severity::High),
        "critical" | "crit" => Ok(Severity::Critical),
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── CIDR parsing ──────────────────────────────────────────────

    #[test]
    fn parse_cidr_with_prefix() {
        let cidr = parse_cidr("192.168.1.0/24").unwrap();
        assert!(matches!(
            cidr,
            IpNetwork::V4 {
                addr: 0xC0A8_0100,
                prefix_len: 24
            }
        ));
    }

    #[test]
    fn parse_cidr_single_host() {
        let cidr = parse_cidr("10.0.0.1").unwrap();
        assert!(matches!(
            cidr,
            IpNetwork::V4 {
                addr: 0x0A00_0001,
                prefix_len: 32
            }
        ));
    }

    #[test]
    fn parse_cidr_zero() {
        let cidr = parse_cidr("0.0.0.0/0").unwrap();
        assert!(matches!(
            cidr,
            IpNetwork::V4 {
                addr: 0,
                prefix_len: 0
            }
        ));
    }

    #[test]
    fn parse_cidr_invalid_prefix() {
        assert!(parse_cidr("10.0.0.0/33").is_err());
    }

    #[test]
    fn parse_cidr_invalid_octets() {
        assert!(parse_cidr("10.0.0").is_err());
        assert!(parse_cidr("10.0.0.0.0/24").is_err());
        assert!(parse_cidr("256.0.0.0/24").is_err());
    }

    #[test]
    fn parse_cidr_invalid_format() {
        assert!(parse_cidr("not-an-ip").is_err());
    }

    // ── IPv6 CIDR parsing ──────────────────────────────────────────

    #[test]
    fn parse_cidr_v6_loopback() {
        let cidr = parse_cidr("::1").unwrap();
        match cidr {
            IpNetwork::V6 { addr, prefix_len } => {
                assert_eq!(prefix_len, 128);
                // ::1 = all zeros except last byte = 1
                let mut expected = [0u8; 16];
                expected[15] = 1;
                assert_eq!(addr, expected);
            }
            IpNetwork::V4 { .. } => panic!("expected V6"),
        }
    }

    #[test]
    fn parse_cidr_v6_with_prefix() {
        let cidr = parse_cidr("2001:db8::/32").unwrap();
        match cidr {
            IpNetwork::V6 { addr, prefix_len } => {
                assert_eq!(prefix_len, 32);
                assert_eq!(addr[0], 0x20);
                assert_eq!(addr[1], 0x01);
                assert_eq!(addr[2], 0x0d);
                assert_eq!(addr[3], 0xb8);
                // remaining bytes should be zero
                assert_eq!(&addr[4..], &[0u8; 12]);
            }
            IpNetwork::V4 { .. } => panic!("expected V6"),
        }
    }

    #[test]
    fn parse_cidr_v6_link_local() {
        let cidr = parse_cidr("fe80::1/64").unwrap();
        match cidr {
            IpNetwork::V6 { addr, prefix_len } => {
                assert_eq!(prefix_len, 64);
                assert_eq!(addr[0], 0xfe);
                assert_eq!(addr[1], 0x80);
                assert_eq!(addr[15], 1);
            }
            IpNetwork::V4 { .. } => panic!("expected V6"),
        }
    }

    #[test]
    fn parse_cidr_v6_invalid_prefix() {
        assert!(parse_cidr("::1/129").is_err());
    }

    #[test]
    fn parse_cidr_v6_invalid_address() {
        assert!(parse_cidr("not::a::valid::ipv6::too::many::colons::here").is_err());
    }

    // ── Action / Protocol parsing ─────────────────────────────────

    #[test]
    fn parse_action_variants() {
        assert_eq!(parse_action("allow").unwrap(), FirewallAction::Allow);
        assert_eq!(parse_action("pass").unwrap(), FirewallAction::Allow);
        assert_eq!(parse_action("deny").unwrap(), FirewallAction::Deny);
        assert_eq!(parse_action("drop").unwrap(), FirewallAction::Deny);
        assert_eq!(parse_action("block").unwrap(), FirewallAction::Deny);
        assert_eq!(parse_action("log").unwrap(), FirewallAction::Log);
        assert_eq!(parse_action("ALLOW").unwrap(), FirewallAction::Allow);
        assert!(parse_action("invalid").is_err());
    }

    #[test]
    fn parse_protocol_variants() {
        assert_eq!(parse_protocol("tcp").unwrap(), Protocol::Tcp);
        assert_eq!(parse_protocol("udp").unwrap(), Protocol::Udp);
        assert_eq!(parse_protocol("icmp").unwrap(), Protocol::Icmp);
        assert_eq!(parse_protocol("any").unwrap(), Protocol::Any);
        assert_eq!(parse_protocol("*").unwrap(), Protocol::Any);
        assert_eq!(parse_protocol("TCP").unwrap(), Protocol::Tcp);
        assert!(parse_protocol("invalid").is_err());
    }

    // ── DomainMode parsing ───────────────────────────────────────

    #[test]
    fn parse_domain_mode_alert() {
        assert_eq!(parse_domain_mode("alert").unwrap(), DomainMode::Alert);
        assert_eq!(parse_domain_mode("monitor").unwrap(), DomainMode::Alert);
        assert_eq!(parse_domain_mode("observe").unwrap(), DomainMode::Alert);
        assert_eq!(parse_domain_mode("ALERT").unwrap(), DomainMode::Alert);
    }

    #[test]
    fn parse_domain_mode_block() {
        assert_eq!(parse_domain_mode("block").unwrap(), DomainMode::Block);
        assert_eq!(parse_domain_mode("enforce").unwrap(), DomainMode::Block);
        assert_eq!(parse_domain_mode("BLOCK").unwrap(), DomainMode::Block);
    }

    #[test]
    fn parse_domain_mode_invalid() {
        assert!(parse_domain_mode("invalid").is_err());
    }
}
