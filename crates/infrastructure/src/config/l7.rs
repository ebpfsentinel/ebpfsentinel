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
