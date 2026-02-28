//! NAT configuration parsing.

use std::net::IpAddr;

use domain::common::entity::RuleId;
use domain::firewall::entity::PortRange;
use domain::nat::entity::{NatRule, NatType};
use serde::{Deserialize, Serialize};

use super::common::{ConfigError, default_true};
use super::firewall::PortRangeConfig;

/// Maximum NAT rules per direction.
pub(super) const MAX_NAT_RULES: usize = 256;

/// Full NAT configuration section.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NatConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub snat_rules: Vec<NatRuleConfig>,

    #[serde(default)]
    pub dnat_rules: Vec<NatRuleConfig>,
}

impl NatConfig {
    /// Validate the entire NAT section.
    pub(super) fn validate(&self) -> Result<(), ConfigError> {
        for (idx, rule_cfg) in self.snat_rules.iter().enumerate() {
            rule_cfg.validate(idx, "nat.snat_rules")?;
        }
        for (idx, rule_cfg) in self.dnat_rules.iter().enumerate() {
            rule_cfg.validate(idx, "nat.dnat_rules")?;
        }
        Ok(())
    }
}

/// YAML representation of a single NAT rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatRuleConfig {
    pub id: String,

    #[serde(default = "default_true")]
    pub enabled: bool,

    #[serde(default = "default_priority")]
    pub priority: u32,

    /// NAT type: `snat`, `dnat`, `masquerade`, `one_to_one`, `redirect`, `port_forward`.
    #[serde(rename = "type")]
    pub nat_type: String,

    /// Translated address (for `snat`, `dnat`).
    #[serde(default)]
    pub translated_addr: Option<String>,

    /// Translated port (for `dnat`, `redirect`).
    #[serde(default)]
    pub translated_port: Option<u16>,

    /// Port range (for `snat`, `masquerade`).
    #[serde(default)]
    pub port_range: Option<PortRangeConfig>,

    /// Interface (for `masquerade`).
    #[serde(default)]
    pub interface: Option<String>,

    /// External address (for `one_to_one`).
    #[serde(default)]
    pub external_addr: Option<String>,

    /// Internal address (for `one_to_one`, `port_forward`).
    #[serde(default)]
    pub internal_addr: Option<String>,

    /// External port range (for `port_forward`).
    #[serde(default)]
    pub ext_port: Option<PortRangeConfig>,

    /// Internal port range (for `port_forward`).
    #[serde(default)]
    pub int_port: Option<PortRangeConfig>,

    /// Source CIDR to match (None = any).
    #[serde(default)]
    pub match_src: Option<String>,

    /// Destination CIDR to match (None = any).
    #[serde(default)]
    pub match_dst: Option<String>,

    /// Destination port to match (None = any).
    #[serde(default)]
    pub match_dst_port: Option<PortRangeConfig>,

    /// Protocol to match (None = any).
    #[serde(default)]
    pub match_protocol: Option<String>,
}

fn default_priority() -> u32 {
    100
}

impl NatRuleConfig {
    /// Validate this rule config.
    pub(super) fn validate(&self, idx: usize, section: &str) -> Result<(), ConfigError> {
        let prefix = format!("{section}[{idx}]");

        if self.id.is_empty() {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.id"),
                message: "rule ID must not be empty".to_string(),
            });
        }

        if self.priority == 0 {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.priority"),
                message: "priority must be > 0".to_string(),
            });
        }

        match self.nat_type.as_str() {
            "snat" | "dnat" => {
                if self.translated_addr.is_none() {
                    return Err(ConfigError::Validation {
                        field: format!("{prefix}.translated_addr"),
                        message: format!("{} requires translated_addr", self.nat_type),
                    });
                }
                // Validate translated_addr is a valid IP
                if let Some(ref addr) = self.translated_addr {
                    addr.parse::<IpAddr>()
                        .map_err(|e| ConfigError::Validation {
                            field: format!("{prefix}.translated_addr"),
                            message: format!("invalid IP address: {e}"),
                        })?;
                }
            }
            "masquerade" => {
                if self.interface.is_none() {
                    return Err(ConfigError::Validation {
                        field: format!("{prefix}.interface"),
                        message: "masquerade requires interface".to_string(),
                    });
                }
            }
            "one_to_one" => {
                if self.external_addr.is_none() || self.internal_addr.is_none() {
                    return Err(ConfigError::Validation {
                        field: prefix.clone(),
                        message: "one_to_one requires external_addr and internal_addr".to_string(),
                    });
                }
            }
            "redirect" => {
                if self.translated_port.is_none() {
                    return Err(ConfigError::Validation {
                        field: format!("{prefix}.translated_port"),
                        message: "redirect requires translated_port".to_string(),
                    });
                }
            }
            "port_forward" => {
                if self.ext_port.is_none()
                    || self.internal_addr.is_none()
                    || self.int_port.is_none()
                {
                    return Err(ConfigError::Validation {
                        field: prefix.clone(),
                        message: "port_forward requires ext_port, internal_addr, and int_port"
                            .to_string(),
                    });
                }
            }
            other => {
                return Err(ConfigError::InvalidValue {
                    field: format!("{prefix}.type"),
                    value: other.to_string(),
                    expected: "snat, dnat, masquerade, one_to_one, redirect, port_forward"
                        .to_string(),
                });
            }
        }

        Ok(())
    }

    /// Convert to a domain `NatRule`.
    #[allow(clippy::too_many_lines)]
    pub fn to_domain_rule(&self) -> Result<NatRule, ConfigError> {
        let nat_type = match self.nat_type.as_str() {
            "snat" => {
                let addr: IpAddr = self
                    .translated_addr
                    .as_deref()
                    .unwrap_or("")
                    .parse()
                    .map_err(|e| ConfigError::Validation {
                        field: "translated_addr".to_string(),
                        message: format!("invalid IP: {e}"),
                    })?;
                let port_range = self
                    .port_range
                    .as_ref()
                    .map(PortRangeConfig::to_domain)
                    .transpose()?;
                NatType::Snat { addr, port_range }
            }
            "dnat" => {
                let addr: IpAddr = self
                    .translated_addr
                    .as_deref()
                    .unwrap_or("")
                    .parse()
                    .map_err(|e| ConfigError::Validation {
                        field: "translated_addr".to_string(),
                        message: format!("invalid IP: {e}"),
                    })?;
                NatType::Dnat {
                    addr,
                    port: self.translated_port,
                }
            }
            "masquerade" => {
                let port_range = self
                    .port_range
                    .as_ref()
                    .map(PortRangeConfig::to_domain)
                    .transpose()?;
                NatType::Masquerade {
                    interface: self.interface.clone().unwrap_or_default(),
                    port_range,
                }
            }
            "one_to_one" => {
                let external: IpAddr = self
                    .external_addr
                    .as_deref()
                    .unwrap_or("")
                    .parse()
                    .map_err(|e| ConfigError::Validation {
                        field: "external_addr".to_string(),
                        message: format!("invalid IP: {e}"),
                    })?;
                let internal: IpAddr = self
                    .internal_addr
                    .as_deref()
                    .unwrap_or("")
                    .parse()
                    .map_err(|e| ConfigError::Validation {
                        field: "internal_addr".to_string(),
                        message: format!("invalid IP: {e}"),
                    })?;
                NatType::OneToOne { external, internal }
            }
            "redirect" => NatType::Redirect {
                port: self.translated_port.unwrap_or(0),
            },
            "port_forward" => {
                let ext = self
                    .ext_port
                    .as_ref()
                    .map(PortRangeConfig::to_domain)
                    .transpose()?
                    .unwrap_or(PortRange { start: 0, end: 0 });
                let int_addr: IpAddr = self
                    .internal_addr
                    .as_deref()
                    .unwrap_or("")
                    .parse()
                    .map_err(|e| ConfigError::Validation {
                        field: "internal_addr".to_string(),
                        message: format!("invalid IP: {e}"),
                    })?;
                let int = self
                    .int_port
                    .as_ref()
                    .map(PortRangeConfig::to_domain)
                    .transpose()?
                    .unwrap_or(PortRange { start: 0, end: 0 });
                NatType::PortForward {
                    ext_port: ext,
                    int_addr,
                    int_port: int,
                }
            }
            other => {
                return Err(ConfigError::InvalidValue {
                    field: "type".to_string(),
                    value: other.to_string(),
                    expected: "snat, dnat, masquerade, one_to_one, redirect, port_forward"
                        .to_string(),
                });
            }
        };

        let match_dst_port = self
            .match_dst_port
            .as_ref()
            .map(PortRangeConfig::to_domain)
            .transpose()?;

        Ok(NatRule {
            id: RuleId(self.id.clone()),
            priority: self.priority,
            nat_type,
            match_src: self.match_src.clone(),
            match_dst: self.match_dst.clone(),
            match_dst_port,
            match_protocol: self.match_protocol.clone(),
            enabled: self.enabled,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snat_config() -> NatRuleConfig {
        NatRuleConfig {
            id: "snat-1".to_string(),
            enabled: true,
            priority: 10,
            nat_type: "snat".to_string(),
            translated_addr: Some("10.0.0.1".to_string()),
            translated_port: None,
            port_range: None,
            interface: None,
            external_addr: None,
            internal_addr: None,
            ext_port: None,
            int_port: None,
            match_src: Some("192.168.0.0/16".to_string()),
            match_dst: None,
            match_dst_port: None,
            match_protocol: None,
        }
    }

    #[test]
    fn validate_snat_ok() {
        assert!(snat_config().validate(0, "nat.snat_rules").is_ok());
    }

    #[test]
    fn validate_empty_id() {
        let mut cfg = snat_config();
        cfg.id = String::new();
        assert!(cfg.validate(0, "nat.snat_rules").is_err());
    }

    #[test]
    fn validate_zero_priority() {
        let mut cfg = snat_config();
        cfg.priority = 0;
        assert!(cfg.validate(0, "nat.snat_rules").is_err());
    }

    #[test]
    fn validate_snat_no_addr() {
        let mut cfg = snat_config();
        cfg.translated_addr = None;
        assert!(cfg.validate(0, "nat.snat_rules").is_err());
    }

    #[test]
    fn validate_dnat_ok() {
        let cfg = NatRuleConfig {
            id: "dnat-1".to_string(),
            enabled: true,
            priority: 10,
            nat_type: "dnat".to_string(),
            translated_addr: Some("10.0.1.10".to_string()),
            translated_port: Some(80),
            port_range: None,
            interface: None,
            external_addr: None,
            internal_addr: None,
            ext_port: None,
            int_port: None,
            match_src: None,
            match_dst: None,
            match_dst_port: None,
            match_protocol: Some("tcp".to_string()),
        };
        assert!(cfg.validate(0, "nat.dnat_rules").is_ok());
    }

    #[test]
    fn validate_masquerade_no_interface() {
        let cfg = NatRuleConfig {
            id: "masq-1".to_string(),
            enabled: true,
            priority: 10,
            nat_type: "masquerade".to_string(),
            translated_addr: None,
            translated_port: None,
            port_range: None,
            interface: None,
            external_addr: None,
            internal_addr: None,
            ext_port: None,
            int_port: None,
            match_src: None,
            match_dst: None,
            match_dst_port: None,
            match_protocol: None,
        };
        assert!(cfg.validate(0, "nat.snat_rules").is_err());
    }

    #[test]
    fn validate_invalid_type() {
        let mut cfg = snat_config();
        cfg.nat_type = "unknown".to_string();
        assert!(cfg.validate(0, "nat.snat_rules").is_err());
    }

    #[test]
    fn to_domain_snat() {
        let rule = snat_config().to_domain_rule().unwrap();
        assert_eq!(rule.id.0, "snat-1");
        assert!(matches!(rule.nat_type, NatType::Snat { .. }));
    }

    #[test]
    fn to_domain_dnat() {
        let cfg = NatRuleConfig {
            id: "dnat-1".to_string(),
            enabled: true,
            priority: 10,
            nat_type: "dnat".to_string(),
            translated_addr: Some("10.0.1.10".to_string()),
            translated_port: Some(80),
            port_range: None,
            interface: None,
            external_addr: None,
            internal_addr: None,
            ext_port: None,
            int_port: None,
            match_src: None,
            match_dst: None,
            match_dst_port: None,
            match_protocol: Some("tcp".to_string()),
        };
        let rule = cfg.to_domain_rule().unwrap();
        assert!(matches!(
            rule.nat_type,
            NatType::Dnat { port: Some(80), .. }
        ));
    }

    #[test]
    fn default_nat_config_disabled() {
        let cfg = NatConfig::default();
        assert!(!cfg.enabled);
        assert!(cfg.snat_rules.is_empty());
        assert!(cfg.dnat_rules.is_empty());
    }

    #[test]
    fn nat_config_yaml_roundtrip() {
        let yaml = r#"
enabled: true
snat_rules:
  - id: snat-1
    type: snat
    priority: 10
    translated_addr: "10.0.0.1"
    match_src: "192.168.0.0/16"
dnat_rules: []
"#;
        let cfg: NatConfig = serde_yaml_ng::from_str(yaml).unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.snat_rules.len(), 1);
        assert!(cfg.validate().is_ok());
    }
}
