//! NAT configuration parsing.

use std::net::{IpAddr, Ipv6Addr};

use domain::common::entity::RuleId;
use domain::firewall::entity::PortRange;
use domain::nat::entity::{NatRule, NatType, NptV6Rule};
use serde::{Deserialize, Serialize};

use super::common::{ConfigError, default_true};
use super::firewall::PortRangeConfig;

/// Maximum NAT rules per direction.
pub(super) const MAX_NAT_RULES: usize = 256;

/// Maximum `NPTv6` prefix translation rules.
pub(super) const MAX_NPTV6_RULES: usize = 64;

/// Full NAT configuration section.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NatConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub snat_rules: Vec<NatRuleConfig>,

    #[serde(default)]
    pub dnat_rules: Vec<NatRuleConfig>,

    /// `NPTv6` (RFC 6296) prefix translation rules.
    #[serde(default)]
    pub nptv6_rules: Vec<NptV6RuleConfig>,
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
        for (idx, rule_cfg) in self.nptv6_rules.iter().enumerate() {
            rule_cfg.validate(idx)?;
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

    /// Source IP alias reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_src_alias: Option<String>,

    /// Destination IP alias reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_dst_alias: Option<String>,
}

fn default_priority() -> u32 {
    100
}

/// YAML representation of an `NPTv6` (RFC 6296) prefix translation rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NptV6RuleConfig {
    pub id: String,

    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Internal (site-local) IPv6 prefix, e.g. `fd00:1::`.
    pub internal_prefix: String,

    /// External (provider) IPv6 prefix, e.g. `2001:db8:1::`.
    pub external_prefix: String,

    /// Prefix length in bits (1-64).
    pub prefix_len: u8,
}

impl NptV6RuleConfig {
    /// Validate this `NPTv6` rule config.
    pub(super) fn validate(&self, idx: usize) -> Result<(), ConfigError> {
        let prefix = format!("nat.nptv6_rules[{idx}]");

        if self.id.is_empty() {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.id"),
                message: "rule ID must not be empty".to_string(),
            });
        }

        if self.prefix_len == 0 || self.prefix_len > 64 {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.prefix_len"),
                message: format!("prefix_len must be 1..=64, got {}", self.prefix_len),
            });
        }

        self.internal_prefix
            .parse::<Ipv6Addr>()
            .map_err(|e| ConfigError::Validation {
                field: format!("{prefix}.internal_prefix"),
                message: format!("invalid IPv6 address: {e}"),
            })?;

        self.external_prefix
            .parse::<Ipv6Addr>()
            .map_err(|e| ConfigError::Validation {
                field: format!("{prefix}.external_prefix"),
                message: format!("invalid IPv6 address: {e}"),
            })?;

        Ok(())
    }

    /// Convert to a domain `NptV6Rule`.
    pub fn to_domain_rule(&self) -> Result<NptV6Rule, ConfigError> {
        let internal_prefix: Ipv6Addr =
            self.internal_prefix
                .parse()
                .map_err(|e| ConfigError::Validation {
                    field: "internal_prefix".to_string(),
                    message: format!("invalid IPv6: {e}"),
                })?;
        let external_prefix: Ipv6Addr =
            self.external_prefix
                .parse()
                .map_err(|e| ConfigError::Validation {
                    field: "external_prefix".to_string(),
                    message: format!("invalid IPv6: {e}"),
                })?;

        Ok(NptV6Rule {
            id: self.id.clone(),
            enabled: self.enabled,
            internal_prefix,
            external_prefix,
            prefix_len: self.prefix_len,
        })
    }
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
            match_src_alias: self.match_src_alias.clone(),
            match_dst_alias: self.match_dst_alias.clone(),
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
            match_src_alias: None,
            match_dst_alias: None,
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
            match_src_alias: None,
            match_dst_alias: None,
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
            match_src_alias: None,
            match_dst_alias: None,
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
            match_src_alias: None,
            match_dst_alias: None,
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
        assert!(cfg.nptv6_rules.is_empty());
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

    // ── NPTv6 config tests ─────────────────────────────────────────

    fn nptv6_config() -> NptV6RuleConfig {
        NptV6RuleConfig {
            id: "nptv6-1".to_string(),
            enabled: true,
            internal_prefix: "fd00:1::".to_string(),
            external_prefix: "2001:db8:1::".to_string(),
            prefix_len: 48,
        }
    }

    #[test]
    fn nptv6_validate_ok() {
        assert!(nptv6_config().validate(0).is_ok());
    }

    #[test]
    fn nptv6_validate_empty_id() {
        let mut cfg = nptv6_config();
        cfg.id = String::new();
        assert!(nptv6_config().validate(0).is_ok());
        cfg.id = String::new();
        assert!(cfg.validate(0).is_err());
    }

    #[test]
    fn nptv6_validate_prefix_len_zero() {
        let mut cfg = nptv6_config();
        cfg.prefix_len = 0;
        assert!(cfg.validate(0).is_err());
    }

    #[test]
    fn nptv6_validate_prefix_len_65() {
        let mut cfg = nptv6_config();
        cfg.prefix_len = 65;
        assert!(cfg.validate(0).is_err());
    }

    #[test]
    fn nptv6_validate_invalid_internal_prefix() {
        let mut cfg = nptv6_config();
        cfg.internal_prefix = "not-an-ip".to_string();
        assert!(cfg.validate(0).is_err());
    }

    #[test]
    fn nptv6_validate_invalid_external_prefix() {
        let mut cfg = nptv6_config();
        cfg.external_prefix = "not-an-ip".to_string();
        assert!(cfg.validate(0).is_err());
    }

    #[test]
    fn nptv6_to_domain_rule() {
        let rule = nptv6_config().to_domain_rule().unwrap();
        assert_eq!(rule.id, "nptv6-1");
        assert_eq!(rule.prefix_len, 48);
        assert!(rule.enabled);
    }

    #[test]
    fn nptv6_yaml_roundtrip() {
        let yaml = r#"
enabled: true
snat_rules: []
dnat_rules: []
nptv6_rules:
  - id: nptv6-site1
    enabled: true
    internal_prefix: "fd00:1::"
    external_prefix: "2001:db8:1::"
    prefix_len: 48
"#;
        let cfg: NatConfig = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(cfg.nptv6_rules.len(), 1);
        assert!(cfg.validate().is_ok());
        let rule = cfg.nptv6_rules[0].to_domain_rule().unwrap();
        assert_eq!(rule.id, "nptv6-site1");
        assert_eq!(rule.prefix_len, 48);
    }
}
