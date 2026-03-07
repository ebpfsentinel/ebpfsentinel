//! L7 (Layer 7) domain configuration structs and conversion logic.

use domain::common::entity::RuleId;
use domain::l7::domain_matcher::DomainMatcher;
use domain::l7::entity::{L7Matcher, L7Rule};
use serde::{Deserialize, Serialize};

use super::common::{ConfigError, default_true, parse_action, parse_cidr};
use super::firewall::PortRangeConfig;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct L7Config {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub ports: Vec<u16>,

    #[serde(default)]
    pub rules: Vec<L7RuleConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L7RuleConfig {
    pub id: String,
    pub priority: u32,
    pub action: String,
    pub protocol: String,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub sni: Option<String>,
    #[serde(default)]
    pub service: Option<String>,
    #[serde(default, rename = "grpc_method")]
    pub grpc_method: Option<String>,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub smb_command: Option<u16>,
    #[serde(default)]
    pub is_smb2: Option<bool>,

    #[serde(default)]
    pub src_ip: Option<String>,
    #[serde(default)]
    pub dst_ip: Option<String>,
    #[serde(default)]
    pub dst_port: Option<PortRangeConfig>,

    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Source country codes (ISO 3166-1 alpha-2) for country-based matching.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src_country_codes: Option<Vec<String>>,

    /// Destination country codes (ISO 3166-1 alpha-2) for country-based matching.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dst_country_codes: Option<Vec<String>>,

    /// Source IP alias reference (resolved from top-level or firewall aliases).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src_ip_alias: Option<String>,

    /// Destination IP alias reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dst_ip_alias: Option<String>,

    /// Destination port alias reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dst_port_alias: Option<String>,
}

impl L7RuleConfig {
    pub(super) fn validate(&self, idx: usize) -> Result<(), ConfigError> {
        let prefix = format!("l7.rules[{idx}]");

        if self.id.is_empty() {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.id"),
                message: "rule ID must not be empty".to_string(),
            });
        }

        parse_action(&self.action).map_err(|()| ConfigError::InvalidValue {
            field: format!("{prefix}.action"),
            value: self.action.clone(),
            expected: "allow, deny, log".to_string(),
        })?;

        parse_l7_protocol(&self.protocol).map_err(|()| ConfigError::InvalidValue {
            field: format!("{prefix}.protocol"),
            value: self.protocol.clone(),
            expected: "http, tls, grpc, smtp, ftp, smb".to_string(),
        })?;

        if let Some(ref cidr) = self.src_ip {
            parse_cidr(cidr).map_err(|e| ConfigError::InvalidCidr {
                value: cidr.clone(),
                reason: e.to_string(),
            })?;
        }
        if let Some(ref cidr) = self.dst_ip {
            parse_cidr(cidr).map_err(|e| ConfigError::InvalidCidr {
                value: cidr.clone(),
                reason: e.to_string(),
            })?;
        }

        // Validate domain patterns (host/sni) at config time
        if let Some(ref host) = self.host {
            DomainMatcher::new(host).map_err(|e| ConfigError::Validation {
                field: format!("{prefix}.host"),
                message: e.to_string(),
            })?;
        }
        if let Some(ref sni) = self.sni {
            DomainMatcher::new(sni).map_err(|e| ConfigError::Validation {
                field: format!("{prefix}.sni"),
                message: e.to_string(),
            })?;
        }

        Ok(())
    }

    pub fn to_domain_rule(&self) -> Result<L7Rule, ConfigError> {
        let action = parse_action(&self.action).map_err(|()| ConfigError::InvalidValue {
            field: "action".to_string(),
            value: self.action.clone(),
            expected: "allow, deny, log".to_string(),
        })?;

        let matcher = self.build_matcher()?;

        let src_ip = self
            .src_ip
            .as_deref()
            .map(parse_cidr)
            .transpose()
            .map_err(|e| ConfigError::InvalidCidr {
                value: self.src_ip.clone().unwrap_or_default(),
                reason: e.to_string(),
            })?;

        let dst_ip = self
            .dst_ip
            .as_deref()
            .map(parse_cidr)
            .transpose()
            .map_err(|e| ConfigError::InvalidCidr {
                value: self.dst_ip.clone().unwrap_or_default(),
                reason: e.to_string(),
            })?;

        let dst_port = self
            .dst_port
            .as_ref()
            .map(PortRangeConfig::to_domain)
            .transpose()?;

        Ok(L7Rule {
            id: RuleId(self.id.clone()),
            priority: self.priority,
            action,
            matcher,
            src_ip,
            dst_ip,
            dst_port,
            enabled: self.enabled,
            src_country_codes: self.src_country_codes.clone(),
            dst_country_codes: self.dst_country_codes.clone(),
            src_ip_alias: self.src_ip_alias.clone(),
            dst_ip_alias: self.dst_ip_alias.clone(),
            dst_port_alias: self.dst_port_alias.clone(),
        })
    }

    fn build_matcher(&self) -> Result<L7Matcher, ConfigError> {
        match self.protocol.to_lowercase().as_str() {
            "http" => {
                let host_pattern = self
                    .host
                    .as_deref()
                    .map(DomainMatcher::new)
                    .transpose()
                    .map_err(|e| ConfigError::Validation {
                        field: "l7.rules.host".to_string(),
                        message: e.to_string(),
                    })?;
                Ok(L7Matcher::Http {
                    method: self.method.clone(),
                    path_pattern: self.path.clone(),
                    host_pattern,
                    content_type: self.content_type.clone(),
                })
            }
            "tls" => {
                let sni_pattern = self
                    .sni
                    .as_deref()
                    .map(DomainMatcher::new)
                    .transpose()
                    .map_err(|e| ConfigError::Validation {
                        field: "l7.rules.sni".to_string(),
                        message: e.to_string(),
                    })?;
                Ok(L7Matcher::Tls { sni_pattern })
            }
            "grpc" => Ok(L7Matcher::Grpc {
                service_pattern: self.service.clone(),
                method_pattern: self.grpc_method.clone(),
            }),
            "smtp" => Ok(L7Matcher::Smtp {
                command: self.command.clone(),
            }),
            "ftp" => Ok(L7Matcher::Ftp {
                command: self.command.clone(),
            }),
            "smb" => Ok(L7Matcher::Smb {
                command: self.smb_command,
                is_smb2: self.is_smb2,
            }),
            other => Err(ConfigError::InvalidValue {
                field: "protocol".to_string(),
                value: other.to_string(),
                expected: "http, tls, grpc, smtp, ftp, smb".to_string(),
            }),
        }
    }
}

fn parse_l7_protocol(s: &str) -> Result<(), ()> {
    match s.to_lowercase().as_str() {
        "http" | "tls" | "grpc" | "smtp" | "ftp" | "smb" => Ok(()),
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Default config ───────────────────────────────────────────────

    #[test]
    fn default_config() {
        let cfg = L7Config::default();
        assert!(!cfg.enabled);
        assert!(cfg.ports.is_empty());
        assert!(cfg.rules.is_empty());
    }

    // ── Helpers ──────────────────────────────────────────────────────

    fn valid_http_rule() -> L7RuleConfig {
        serde_yaml_ng::from_str(
            r#"
id: r1
priority: 10
action: deny
protocol: http
host: "*.example.com"
"#,
        )
        .unwrap()
    }

    // ── validate() ───────────────────────────────────────────────────

    #[test]
    fn validate_empty_id_error() {
        let mut rule = valid_http_rule();
        rule.id = String::new();
        let err = rule.validate(0).unwrap_err();
        assert!(err.to_string().contains("rule ID must not be empty"));
    }

    #[test]
    fn validate_invalid_action_error() {
        let mut rule = valid_http_rule();
        rule.action = "nuke".to_string();
        let err = rule.validate(0).unwrap_err();
        assert!(err.to_string().contains("nuke"));
    }

    #[test]
    fn validate_invalid_protocol_error() {
        let mut rule = valid_http_rule();
        rule.protocol = "quic".to_string();
        let err = rule.validate(0).unwrap_err();
        assert!(err.to_string().contains("quic"));
    }

    #[test]
    fn validate_invalid_src_ip_cidr_error() {
        let mut rule = valid_http_rule();
        rule.src_ip = Some("not-a-cidr".to_string());
        let err = rule.validate(0).unwrap_err();
        assert!(err.to_string().contains("not-a-cidr"));
    }

    #[test]
    fn validate_valid_http_rule_passes() {
        let rule = valid_http_rule();
        rule.validate(0).unwrap();
    }

    // ── to_domain_rule() ─────────────────────────────────────────────

    #[test]
    fn to_domain_http_rule_with_host_pattern() {
        let rule: L7RuleConfig = serde_yaml_ng::from_str(
            r#"
id: http1
priority: 5
action: allow
protocol: http
method: GET
path: "/api/*"
host: "*.example.com"
content_type: application/json
"#,
        )
        .unwrap();
        let domain = rule.to_domain_rule().unwrap();
        assert_eq!(domain.id.0, "http1");
        assert_eq!(domain.priority, 5);
        assert!(matches!(
            domain.action,
            domain::firewall::entity::FirewallAction::Allow
        ));
        match &domain.matcher {
            L7Matcher::Http {
                method,
                path_pattern,
                host_pattern,
                content_type,
            } => {
                assert_eq!(method.as_deref(), Some("GET"));
                assert_eq!(path_pattern.as_deref(), Some("/api/*"));
                assert!(host_pattern.is_some());
                assert_eq!(content_type.as_deref(), Some("application/json"));
            }
            _ => panic!("expected Http matcher"),
        }
    }

    #[test]
    fn to_domain_tls_rule_with_sni_pattern() {
        let rule: L7RuleConfig = serde_yaml_ng::from_str(
            r#"
id: tls1
priority: 1
action: deny
protocol: tls
sni: "*.evil.com"
"#,
        )
        .unwrap();
        let domain = rule.to_domain_rule().unwrap();
        match &domain.matcher {
            L7Matcher::Tls { sni_pattern } => {
                assert!(sni_pattern.is_some());
            }
            _ => panic!("expected Tls matcher"),
        }
    }

    #[test]
    fn to_domain_grpc_rule() {
        let rule: L7RuleConfig = serde_yaml_ng::from_str(
            r#"
id: grpc1
priority: 2
action: allow
protocol: grpc
service: myservice
grpc_method: MyMethod
"#,
        )
        .unwrap();
        let domain = rule.to_domain_rule().unwrap();
        match &domain.matcher {
            L7Matcher::Grpc {
                service_pattern,
                method_pattern,
            } => {
                assert_eq!(service_pattern.as_deref(), Some("myservice"));
                assert_eq!(method_pattern.as_deref(), Some("MyMethod"));
            }
            _ => panic!("expected Grpc matcher"),
        }
    }

    #[test]
    fn to_domain_smtp_rule() {
        let rule: L7RuleConfig = serde_yaml_ng::from_str(
            r#"
id: smtp1
priority: 3
action: log
protocol: smtp
command: EHLO
"#,
        )
        .unwrap();
        let domain = rule.to_domain_rule().unwrap();
        match &domain.matcher {
            L7Matcher::Smtp { command } => {
                assert_eq!(command.as_deref(), Some("EHLO"));
            }
            _ => panic!("expected Smtp matcher"),
        }
    }

    #[test]
    fn to_domain_ftp_rule() {
        let rule: L7RuleConfig = serde_yaml_ng::from_str(
            r#"
id: ftp1
priority: 4
action: deny
protocol: ftp
command: RETR
"#,
        )
        .unwrap();
        let domain = rule.to_domain_rule().unwrap();
        match &domain.matcher {
            L7Matcher::Ftp { command } => {
                assert_eq!(command.as_deref(), Some("RETR"));
            }
            _ => panic!("expected Ftp matcher"),
        }
    }

    #[test]
    fn to_domain_smb_rule() {
        let rule: L7RuleConfig = serde_yaml_ng::from_str(
            r#"
id: smb1
priority: 5
action: deny
protocol: smb
smb_command: 5
is_smb2: true
"#,
        )
        .unwrap();
        let domain = rule.to_domain_rule().unwrap();
        match &domain.matcher {
            L7Matcher::Smb { command, is_smb2 } => {
                assert_eq!(*command, Some(5));
                assert_eq!(*is_smb2, Some(true));
            }
            _ => panic!("expected Smb matcher"),
        }
    }

    #[test]
    fn to_domain_invalid_protocol_error() {
        let rule: L7RuleConfig = serde_yaml_ng::from_str(
            r#"
id: bad1
priority: 1
action: allow
protocol: quic
"#,
        )
        .unwrap();
        assert!(rule.to_domain_rule().is_err());
    }
}
