use serde::{Deserialize, Serialize};

use crate::common::entity::RuleId;
use crate::firewall::entity::{FirewallAction, IpCidr, PortRange};
use ebpf_common::event::PacketEvent;

use super::domain_matcher::DomainMatcher;
use super::error::L7Error;

// ── Detected protocol ──────────────────────────────────────────────

/// Detected application-layer protocol from raw payload inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectedProtocol {
    Http,
    Tls,
    Grpc,
    Smtp,
    Ftp,
    Smb,
    Unknown,
}

// ── Parsed protocol data ───────────────────────────────────────────

/// Parsed HTTP request from the first bytes of a TCP payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub version: String,
    pub host: Option<String>,
    pub content_type: Option<String>,
    pub headers: Vec<(String, String)>,
}

/// Parsed TLS `ClientHello` with optional SNI extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsClientHello {
    pub sni: Option<String>,
}

/// Parsed gRPC request path (extracted from HTTP/2 framing).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrpcRequest {
    pub service: String,
    pub method: String,
}

/// Parsed SMTP command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmtpCommand {
    pub command: String,
    pub params: String,
}

/// Parsed FTP command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FtpCommand {
    pub command: String,
    pub params: String,
}

/// Parsed SMB header metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmbHeader {
    pub command: u16,
    pub is_smb2: bool,
}

/// Result of parsing an L7 payload — one variant per supported protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedProtocol {
    Http(HttpRequest),
    Tls(TlsClientHello),
    Grpc(GrpcRequest),
    Smtp(SmtpCommand),
    Ftp(FtpCommand),
    Smb(SmbHeader),
    Unknown,
}

// ── L7 matcher ─────────────────────────────────────────────────────

/// Protocol-specific matcher for L7 firewall rules.
///
/// Each field is `Option` — `None` means wildcard (match any value).
/// `Some(pattern)` performs case-insensitive substring matching.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "protocol", rename_all = "lowercase")]
pub enum L7Matcher {
    Http {
        method: Option<String>,
        path_pattern: Option<String>,
        host_pattern: Option<DomainMatcher>,
        content_type: Option<String>,
    },
    Tls {
        sni_pattern: Option<DomainMatcher>,
    },
    Grpc {
        service_pattern: Option<String>,
        method_pattern: Option<String>,
    },
    Smtp {
        command: Option<String>,
    },
    Ftp {
        command: Option<String>,
    },
    Smb {
        command: Option<u16>,
        is_smb2: Option<bool>,
    },
}

// ── L7 rule ────────────────────────────────────────────────────────

/// An L7 firewall rule combining optional L3/L4 header checks with
/// protocol-specific L7 content matching.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L7Rule {
    pub id: RuleId,
    pub priority: u32,
    pub action: FirewallAction,
    pub matcher: L7Matcher,
    pub src_ip: Option<IpCidr>,
    pub dst_ip: Option<IpCidr>,
    pub dst_port: Option<PortRange>,
    pub enabled: bool,
}

impl L7Rule {
    /// Validate all fields of this rule.
    pub fn validate(&self) -> Result<(), L7Error> {
        self.id
            .validate()
            .map_err(|reason| L7Error::InvalidRuleId { reason })?;

        if self.priority == 0 {
            return Err(L7Error::InvalidPriority);
        }

        if let Some(ref cidr) = self.src_ip {
            match cidr {
                IpCidr::V4 { prefix_len, .. } => {
                    if *prefix_len > 32 {
                        return Err(L7Error::InvalidCidr {
                            prefix_len: *prefix_len,
                        });
                    }
                }
                IpCidr::V6 { prefix_len, .. } => {
                    if *prefix_len > 128 {
                        return Err(L7Error::InvalidCidr {
                            prefix_len: *prefix_len,
                        });
                    }
                }
            }
        }
        if let Some(ref cidr) = self.dst_ip {
            match cidr {
                IpCidr::V4 { prefix_len, .. } => {
                    if *prefix_len > 32 {
                        return Err(L7Error::InvalidCidr {
                            prefix_len: *prefix_len,
                        });
                    }
                }
                IpCidr::V6 { prefix_len, .. } => {
                    if *prefix_len > 128 {
                        return Err(L7Error::InvalidCidr {
                            prefix_len: *prefix_len,
                        });
                    }
                }
            }
        }
        if let Some(ref range) = self.dst_port
            && range.start > range.end
        {
            return Err(L7Error::InvalidPortRange {
                start: range.start,
                end: range.end,
            });
        }

        Ok(())
    }

    /// Check if the L3/L4 header fields of a `PacketEvent` match this rule.
    ///
    /// Returns `true` if all specified L3/L4 constraints match (or are `None`).
    pub fn matches_l3l4(&self, header: &PacketEvent) -> bool {
        if let Some(ref cidr) = self.src_ip
            && !cidr.contains_v4(header.src_ip())
        {
            return false;
        }
        if let Some(ref cidr) = self.dst_ip
            && !cidr.contains_v4(header.dst_ip())
        {
            return false;
        }
        if let Some(ref range) = self.dst_port
            && !range.contains(header.dst_port)
        {
            return false;
        }
        true
    }

    /// Check if the parsed L7 protocol data matches this rule's matcher.
    ///
    /// Returns `true` if the protocol variant matches and all specified
    /// patterns match (case-insensitive substring).
    pub fn matches_l7(&self, parsed: &ParsedProtocol) -> bool {
        match (&self.matcher, parsed) {
            (
                L7Matcher::Http {
                    method,
                    path_pattern,
                    host_pattern,
                    content_type,
                },
                ParsedProtocol::Http(req),
            ) => {
                matches_opt_ci(method.as_deref(), &req.method)
                    && matches_opt_substr_ci(path_pattern.as_deref(), &req.path)
                    && matches_opt_domain_matcher(host_pattern.as_ref(), req.host.as_deref())
                    && matches_opt_opt_substr_ci(
                        content_type.as_deref(),
                        req.content_type.as_deref(),
                    )
            }
            (L7Matcher::Tls { sni_pattern }, ParsedProtocol::Tls(hello)) => {
                matches_opt_domain_matcher(sni_pattern.as_ref(), hello.sni.as_deref())
            }
            (
                L7Matcher::Grpc {
                    service_pattern,
                    method_pattern,
                },
                ParsedProtocol::Grpc(req),
            ) => {
                matches_opt_substr_ci(service_pattern.as_deref(), &req.service)
                    && matches_opt_substr_ci(method_pattern.as_deref(), &req.method)
            }
            (L7Matcher::Smtp { command }, ParsedProtocol::Smtp(cmd)) => {
                matches_opt_ci(command.as_deref(), &cmd.command)
            }
            (L7Matcher::Ftp { command }, ParsedProtocol::Ftp(cmd)) => {
                matches_opt_ci(command.as_deref(), &cmd.command)
            }
            (
                L7Matcher::Smb {
                    command,
                    is_smb2: smb2_filter,
                },
                ParsedProtocol::Smb(hdr),
            ) => {
                if let Some(expected_cmd) = command
                    && *expected_cmd != hdr.command
                {
                    return false;
                }
                if let Some(expected_smb2) = smb2_filter
                    && *expected_smb2 != hdr.is_smb2
                {
                    return false;
                }
                true
            }
            _ => false,
        }
    }
}

// ── Matching helpers ───────────────────────────────────────────────

/// Case-insensitive exact match. `None` pattern is wildcard.
fn matches_opt_ci(pattern: Option<&str>, value: &str) -> bool {
    match pattern {
        None => true,
        Some(p) => p.eq_ignore_ascii_case(value),
    }
}

/// Case-insensitive substring match against a required value. `None` pattern is wildcard.
fn matches_opt_substr_ci(pattern: Option<&str>, value: &str) -> bool {
    match pattern {
        None => true,
        Some(p) => {
            let lower_p = p.to_ascii_lowercase();
            let lower_v = value.to_ascii_lowercase();
            lower_v.contains(&lower_p)
        }
    }
}

/// Match an optional `DomainMatcher` against an optional value.
/// `None` matcher is wildcard. `Some` matcher against `None` value returns false.
fn matches_opt_domain_matcher(matcher: Option<&DomainMatcher>, value: Option<&str>) -> bool {
    match (matcher, value) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(m), Some(v)) => m.matches(v),
    }
}

/// Case-insensitive substring match against an optional value.
/// `None` pattern is wildcard. `Some` pattern against `None` value returns false.
fn matches_opt_opt_substr_ci(pattern: Option<&str>, value: Option<&str>) -> bool {
    match (pattern, value) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(p), Some(v)) => {
            let lower_p = p.to_ascii_lowercase();
            let lower_v = v.to_ascii_lowercase();
            lower_v.contains(&lower_p)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::entity::RuleId;
    use crate::firewall::entity::{FirewallAction, IpNetwork, PortRange};

    fn make_http_rule(id: &str, priority: u32) -> L7Rule {
        L7Rule {
            id: RuleId(id.to_string()),
            priority,
            action: FirewallAction::Deny,
            matcher: L7Matcher::Http {
                method: None,
                path_pattern: None,
                host_pattern: None,
                content_type: None,
            },
            src_ip: None,
            dst_ip: None,
            dst_port: None,
            enabled: true,
        }
    }

    fn make_packet_header(src_ip: u32, dst_ip: u32, dst_port: u16) -> PacketEvent {
        PacketEvent {
            timestamp_ns: 0,
            src_addr: [src_ip, 0, 0, 0],
            dst_addr: [dst_ip, 0, 0, 0],
            src_port: 12345,
            dst_port,
            protocol: 6,
            event_type: 6,
            action: 0,
            flags: 0,
            rule_id: 0,
            vlan_id: 0,
            cpu_id: 0,
            socket_cookie: 0,
        }
    }

    // ── Validation tests ───────────────────────────────────────────

    #[test]
    fn validate_ok() {
        let rule = make_http_rule("l7-001", 10);
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn validate_empty_id() {
        let rule = make_http_rule("", 10);
        assert!(rule.validate().is_err());
    }

    #[test]
    fn validate_zero_priority() {
        let rule = make_http_rule("l7-001", 0);
        assert!(rule.validate().is_err());
    }

    #[test]
    fn validate_invalid_cidr() {
        let mut rule = make_http_rule("l7-001", 10);
        rule.src_ip = Some(IpNetwork::V4 {
            addr: 0,
            prefix_len: 33,
        });
        assert!(rule.validate().is_err());
    }

    #[test]
    fn validate_invalid_port_range() {
        let mut rule = make_http_rule("l7-001", 10);
        rule.dst_port = Some(PortRange {
            start: 443,
            end: 80,
        });
        assert!(rule.validate().is_err());
    }

    // ── HTTP matching tests ────────────────────────────────────────

    #[test]
    fn http_method_match() {
        let mut rule = make_http_rule("l7-001", 10);
        rule.matcher = L7Matcher::Http {
            method: Some("POST".to_string()),
            path_pattern: None,
            host_pattern: None,
            content_type: None,
        };

        let parsed = ParsedProtocol::Http(HttpRequest {
            method: "POST".to_string(),
            path: "/api/data".to_string(),
            version: "HTTP/1.1".to_string(),
            host: None,
            content_type: None,
            headers: vec![],
        });
        assert!(rule.matches_l7(&parsed));

        let parsed_get = ParsedProtocol::Http(HttpRequest {
            method: "GET".to_string(),
            path: "/api/data".to_string(),
            version: "HTTP/1.1".to_string(),
            host: None,
            content_type: None,
            headers: vec![],
        });
        assert!(!rule.matches_l7(&parsed_get));
    }

    #[test]
    fn http_path_match() {
        let mut rule = make_http_rule("l7-002", 10);
        rule.matcher = L7Matcher::Http {
            method: None,
            path_pattern: Some("/admin".to_string()),
            host_pattern: None,
            content_type: None,
        };

        let parsed = ParsedProtocol::Http(HttpRequest {
            method: "GET".to_string(),
            path: "/admin/users".to_string(),
            version: "HTTP/1.1".to_string(),
            host: None,
            content_type: None,
            headers: vec![],
        });
        assert!(rule.matches_l7(&parsed));

        let parsed_other = ParsedProtocol::Http(HttpRequest {
            method: "GET".to_string(),
            path: "/api/users".to_string(),
            version: "HTTP/1.1".to_string(),
            host: None,
            content_type: None,
            headers: vec![],
        });
        assert!(!rule.matches_l7(&parsed_other));
    }

    #[test]
    fn http_host_match() {
        let mut rule = make_http_rule("l7-003", 10);
        rule.matcher = L7Matcher::Http {
            method: None,
            path_pattern: None,
            host_pattern: Some(DomainMatcher::new("evil.com").unwrap()),
            content_type: None,
        };

        let parsed = ParsedProtocol::Http(HttpRequest {
            method: "GET".to_string(),
            path: "/".to_string(),
            version: "HTTP/1.1".to_string(),
            host: Some("www.evil.com".to_string()),
            content_type: None,
            headers: vec![],
        });
        assert!(rule.matches_l7(&parsed));

        let parsed_no_host = ParsedProtocol::Http(HttpRequest {
            method: "GET".to_string(),
            path: "/".to_string(),
            version: "HTTP/1.1".to_string(),
            host: None,
            content_type: None,
            headers: vec![],
        });
        assert!(!rule.matches_l7(&parsed_no_host));
    }

    #[test]
    fn http_method_case_insensitive() {
        let mut rule = make_http_rule("l7-004", 10);
        rule.matcher = L7Matcher::Http {
            method: Some("post".to_string()),
            path_pattern: None,
            host_pattern: None,
            content_type: None,
        };

        let parsed = ParsedProtocol::Http(HttpRequest {
            method: "POST".to_string(),
            path: "/".to_string(),
            version: "HTTP/1.1".to_string(),
            host: None,
            content_type: None,
            headers: vec![],
        });
        assert!(rule.matches_l7(&parsed));
    }

    // ── TLS matching tests ─────────────────────────────────────────

    #[test]
    fn tls_sni_match() {
        let rule = L7Rule {
            id: RuleId("l7-tls-001".to_string()),
            priority: 10,
            action: FirewallAction::Deny,
            matcher: L7Matcher::Tls {
                sni_pattern: Some(DomainMatcher::new("malware.example.com").unwrap()),
            },
            src_ip: None,
            dst_ip: None,
            dst_port: None,
            enabled: true,
        };

        let parsed = ParsedProtocol::Tls(TlsClientHello {
            sni: Some("malware.example.com".to_string()),
        });
        assert!(rule.matches_l7(&parsed));

        let parsed_other = ParsedProtocol::Tls(TlsClientHello {
            sni: Some("safe.example.com".to_string()),
        });
        assert!(!rule.matches_l7(&parsed_other));

        let parsed_none = ParsedProtocol::Tls(TlsClientHello { sni: None });
        assert!(!rule.matches_l7(&parsed_none));
    }

    #[test]
    fn tls_wildcard_sni_matches_all() {
        let rule = L7Rule {
            id: RuleId("l7-tls-002".to_string()),
            priority: 10,
            action: FirewallAction::Log,
            matcher: L7Matcher::Tls { sni_pattern: None },
            src_ip: None,
            dst_ip: None,
            dst_port: None,
            enabled: true,
        };

        let parsed = ParsedProtocol::Tls(TlsClientHello {
            sni: Some("anything.com".to_string()),
        });
        assert!(rule.matches_l7(&parsed));

        let parsed_none = ParsedProtocol::Tls(TlsClientHello { sni: None });
        assert!(rule.matches_l7(&parsed_none));
    }

    // ── gRPC matching tests ────────────────────────────────────────

    #[test]
    fn grpc_service_match() {
        let rule = L7Rule {
            id: RuleId("l7-grpc-001".to_string()),
            priority: 10,
            action: FirewallAction::Deny,
            matcher: L7Matcher::Grpc {
                service_pattern: Some("AdminService".to_string()),
                method_pattern: None,
            },
            src_ip: None,
            dst_ip: None,
            dst_port: None,
            enabled: true,
        };

        let parsed = ParsedProtocol::Grpc(GrpcRequest {
            service: "admin.AdminService".to_string(),
            method: "Delete".to_string(),
        });
        assert!(rule.matches_l7(&parsed));

        let parsed_other = ParsedProtocol::Grpc(GrpcRequest {
            service: "user.UserService".to_string(),
            method: "Get".to_string(),
        });
        assert!(!rule.matches_l7(&parsed_other));
    }

    // ── SMTP matching tests ────────────────────────────────────────

    #[test]
    fn smtp_command_match() {
        let rule = L7Rule {
            id: RuleId("l7-smtp-001".to_string()),
            priority: 10,
            action: FirewallAction::Deny,
            matcher: L7Matcher::Smtp {
                command: Some("VRFY".to_string()),
            },
            src_ip: None,
            dst_ip: None,
            dst_port: None,
            enabled: true,
        };

        let parsed = ParsedProtocol::Smtp(SmtpCommand {
            command: "VRFY".to_string(),
            params: "user@example.com".to_string(),
        });
        assert!(rule.matches_l7(&parsed));

        let parsed_other = ParsedProtocol::Smtp(SmtpCommand {
            command: "EHLO".to_string(),
            params: "mail.example.com".to_string(),
        });
        assert!(!rule.matches_l7(&parsed_other));
    }

    // ── Combined L3+L7 matching tests ──────────────────────────────

    #[test]
    fn combined_l3l4_and_l7_match() {
        let mut rule = make_http_rule("l7-combined", 10);
        rule.matcher = L7Matcher::Http {
            method: Some("DELETE".to_string()),
            path_pattern: None,
            host_pattern: None,
            content_type: None,
        };
        rule.src_ip = Some(IpNetwork::V4 {
            addr: 0x0A00_0000, // 10.0.0.0
            prefix_len: 8,
        });
        rule.dst_port = Some(PortRange {
            start: 8080,
            end: 8080,
        });

        // L3/L4 match
        let header = make_packet_header(0x0A00_0001, 0xC0A8_0001, 8080);
        assert!(rule.matches_l3l4(&header));

        // L7 match
        let parsed = ParsedProtocol::Http(HttpRequest {
            method: "DELETE".to_string(),
            path: "/resource".to_string(),
            version: "HTTP/1.1".to_string(),
            host: None,
            content_type: None,
            headers: vec![],
        });
        assert!(rule.matches_l7(&parsed));

        // L3/L4 mismatch (wrong source IP)
        let header_wrong = make_packet_header(0xC0A8_0001, 0xC0A8_0001, 8080);
        assert!(!rule.matches_l3l4(&header_wrong));
    }

    #[test]
    fn wildcard_http_matches_any_request() {
        let rule = make_http_rule("l7-wildcard", 10);

        let parsed = ParsedProtocol::Http(HttpRequest {
            method: "PATCH".to_string(),
            path: "/anything".to_string(),
            version: "HTTP/1.1".to_string(),
            host: Some("any.host".to_string()),
            content_type: Some("text/plain".to_string()),
            headers: vec![],
        });
        assert!(rule.matches_l7(&parsed));
    }

    #[test]
    fn protocol_mismatch_returns_false() {
        let rule = make_http_rule("l7-mismatch", 10);

        let parsed = ParsedProtocol::Tls(TlsClientHello {
            sni: Some("example.com".to_string()),
        });
        assert!(!rule.matches_l7(&parsed));
    }

    #[test]
    fn unknown_protocol_never_matches() {
        let rule = make_http_rule("l7-unknown", 10);
        assert!(!rule.matches_l7(&ParsedProtocol::Unknown));
    }

    // ── SMB matching tests ─────────────────────────────────────────

    #[test]
    fn smb_command_match() {
        let rule = L7Rule {
            id: RuleId("l7-smb-001".to_string()),
            priority: 10,
            action: FirewallAction::Deny,
            matcher: L7Matcher::Smb {
                command: Some(0x05),
                is_smb2: Some(true),
            },
            src_ip: None,
            dst_ip: None,
            dst_port: None,
            enabled: true,
        };

        let parsed = ParsedProtocol::Smb(SmbHeader {
            command: 0x05,
            is_smb2: true,
        });
        assert!(rule.matches_l7(&parsed));

        let parsed_wrong_cmd = ParsedProtocol::Smb(SmbHeader {
            command: 0x06,
            is_smb2: true,
        });
        assert!(!rule.matches_l7(&parsed_wrong_cmd));

        let parsed_wrong_ver = ParsedProtocol::Smb(SmbHeader {
            command: 0x05,
            is_smb2: false,
        });
        assert!(!rule.matches_l7(&parsed_wrong_ver));
    }

    // ── FTP matching tests ─────────────────────────────────────────

    #[test]
    fn ftp_command_match() {
        let rule = L7Rule {
            id: RuleId("l7-ftp-001".to_string()),
            priority: 10,
            action: FirewallAction::Deny,
            matcher: L7Matcher::Ftp {
                command: Some("STOR".to_string()),
            },
            src_ip: None,
            dst_ip: None,
            dst_port: None,
            enabled: true,
        };

        let parsed = ParsedProtocol::Ftp(FtpCommand {
            command: "STOR".to_string(),
            params: "secret.txt".to_string(),
        });
        assert!(rule.matches_l7(&parsed));

        let parsed_other = ParsedProtocol::Ftp(FtpCommand {
            command: "RETR".to_string(),
            params: "file.txt".to_string(),
        });
        assert!(!rule.matches_l7(&parsed_other));
    }
}
