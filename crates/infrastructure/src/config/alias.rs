//! Alias configuration parsing.

use std::collections::HashMap;

use domain::alias::entity::{Alias, AliasId, AliasKind};
use domain::firewall::entity::PortRange;
use serde::{Deserialize, Serialize};

use super::common::{ConfigError, parse_cidr};

/// Maximum number of aliases.
pub(super) const MAX_ALIASES: usize = 1000;

/// YAML representation of a single alias entry.
///
/// Appears under `firewall.aliases.<name>`:
/// ```yaml
/// rfc1918:
///   type: ip_set
///   values: ["192.168.0.0/16", "10.0.0.0/8"]
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AliasConfig {
    #[serde(rename = "type")]
    pub alias_type: String,

    /// Values for `ip_set` (CIDRs) or `port_set` (ports/ranges).
    #[serde(default)]
    pub values: Vec<serde_yaml_ng::Value>,

    /// Child alias names for `nested` type.
    #[serde(default)]
    pub aliases: Vec<String>,

    /// URL for `url_table` type.
    #[serde(default)]
    pub url: Option<String>,

    /// Refresh interval in seconds for `url_table` and `dynamic_dns`.
    #[serde(default)]
    pub refresh_interval: Option<u64>,

    /// Country codes for `geoip` type (ISO 3166-1 alpha-2).
    #[serde(default)]
    pub country_codes: Vec<String>,

    /// Hostnames for `dynamic_dns` type.
    #[serde(default)]
    pub hostnames: Vec<String>,

    /// Interface names for `interface_group` type.
    #[serde(default)]
    pub interfaces: Vec<String>,

    /// Human-readable description.
    #[serde(default)]
    pub description: Option<String>,
}

impl AliasConfig {
    /// Validate this alias config at the YAML level.
    #[allow(clippy::too_many_lines)]
    pub(super) fn validate(&self, name: &str) -> Result<(), ConfigError> {
        let prefix = format!("firewall.aliases.{name}");

        if name.is_empty() {
            return Err(ConfigError::Validation {
                field: prefix.clone(),
                message: "alias name must not be empty".to_string(),
            });
        }

        match self.alias_type.as_str() {
            "ip_set" => {
                if self.values.is_empty() {
                    return Err(ConfigError::Validation {
                        field: format!("{prefix}.values"),
                        message: "ip_set alias must have at least one value".to_string(),
                    });
                }
                // Validate each CIDR
                for (i, val) in self.values.iter().enumerate() {
                    let s = yaml_value_to_string(val);
                    parse_cidr(&s).map_err(|e| ConfigError::Validation {
                        field: format!("{prefix}.values[{i}]"),
                        message: format!("invalid CIDR: {e}"),
                    })?;
                }
            }
            "port_set" => {
                if self.values.is_empty() {
                    return Err(ConfigError::Validation {
                        field: format!("{prefix}.values"),
                        message: "port_set alias must have at least one value".to_string(),
                    });
                }
            }
            "nested" => {
                if self.aliases.is_empty() {
                    return Err(ConfigError::Validation {
                        field: format!("{prefix}.aliases"),
                        message: "nested alias must reference at least one alias".to_string(),
                    });
                }
            }
            "url_table" => {
                if self.url.as_deref().unwrap_or("").is_empty() {
                    return Err(ConfigError::Validation {
                        field: format!("{prefix}.url"),
                        message: "url_table alias must have a URL".to_string(),
                    });
                }
                if self.refresh_interval.unwrap_or(0) == 0 {
                    return Err(ConfigError::Validation {
                        field: format!("{prefix}.refresh_interval"),
                        message: "refresh_interval must be > 0".to_string(),
                    });
                }
            }
            "geoip" => {
                if self.country_codes.is_empty() {
                    return Err(ConfigError::Validation {
                        field: format!("{prefix}.country_codes"),
                        message: "GeoIP alias must have at least one country code".to_string(),
                    });
                }
                for code in &self.country_codes {
                    if code.len() != 2 || !code.chars().all(|c| c.is_ascii_uppercase()) {
                        return Err(ConfigError::Validation {
                            field: format!("{prefix}.country_codes"),
                            message: format!(
                                "invalid country code: {code} (expected 2-letter ISO)"
                            ),
                        });
                    }
                }
            }
            "dynamic_dns" => {
                if self.hostnames.is_empty() {
                    return Err(ConfigError::Validation {
                        field: format!("{prefix}.hostnames"),
                        message: "dynamic_dns alias must have at least one hostname".to_string(),
                    });
                }
                if self.refresh_interval.unwrap_or(0) == 0 {
                    return Err(ConfigError::Validation {
                        field: format!("{prefix}.refresh_interval"),
                        message: "refresh_interval must be > 0".to_string(),
                    });
                }
            }
            "interface_group" => {
                if self.interfaces.is_empty() {
                    return Err(ConfigError::Validation {
                        field: format!("{prefix}.interfaces"),
                        message: "interface_group must have at least one interface".to_string(),
                    });
                }
            }
            other => {
                return Err(ConfigError::InvalidValue {
                    field: format!("{prefix}.type"),
                    value: other.to_string(),
                    expected:
                        "ip_set, port_set, nested, url_table, geoip, dynamic_dns, interface_group"
                            .to_string(),
                });
            }
        }

        Ok(())
    }

    /// Convert to a domain `Alias`.
    pub fn to_domain_alias(&self, name: &str) -> Result<Alias, ConfigError> {
        let prefix = format!("firewall.aliases.{name}");

        let kind = match self.alias_type.as_str() {
            "ip_set" => {
                let mut ips = Vec::with_capacity(self.values.len());
                for val in &self.values {
                    let s = yaml_value_to_string(val);
                    ips.push(parse_cidr(&s)?);
                }
                AliasKind::IpSet { values: ips }
            }
            "port_set" => {
                let mut ports = Vec::with_capacity(self.values.len());
                for val in &self.values {
                    let s = yaml_value_to_string(val);
                    ports.push(parse_port_value(&s, &prefix)?);
                }
                AliasKind::PortSet { values: ports }
            }
            "nested" => AliasKind::Nested {
                aliases: self.aliases.clone(),
            },
            "url_table" => AliasKind::UrlTable {
                url: self.url.clone().unwrap_or_default(),
                refresh_interval_secs: self.refresh_interval.unwrap_or(3600),
            },
            "geoip" => AliasKind::GeoIp {
                country_codes: self.country_codes.clone(),
            },
            "dynamic_dns" => AliasKind::DynamicDns {
                hostnames: self.hostnames.clone(),
                refresh_interval_secs: self.refresh_interval.unwrap_or(300),
            },
            "interface_group" => AliasKind::InterfaceGroup {
                interfaces: self.interfaces.clone(),
            },
            other => {
                return Err(ConfigError::InvalidValue {
                    field: format!("{prefix}.type"),
                    value: other.to_string(),
                    expected:
                        "ip_set, port_set, nested, url_table, geoip, dynamic_dns, interface_group"
                            .to_string(),
                });
            }
        };

        Ok(Alias {
            id: AliasId(name.to_string()),
            kind,
            description: self.description.clone(),
        })
    }
}

/// Convert aliases map from config to domain aliases.
pub fn aliases_to_domain(
    aliases: &HashMap<String, AliasConfig>,
) -> Result<Vec<Alias>, ConfigError> {
    aliases
        .iter()
        .map(|(name, cfg)| cfg.to_domain_alias(name))
        .collect()
}

/// Parse a YAML value to a string (handles both string and integer values).
fn yaml_value_to_string(val: &serde_yaml_ng::Value) -> String {
    match val {
        serde_yaml_ng::Value::String(s) => s.clone(),
        serde_yaml_ng::Value::Number(n) => n.to_string(),
        other => format!("{other:?}"),
    }
}

/// Parse a port value from a YAML string (single port or range).
fn parse_port_value(s: &str, _prefix: &str) -> Result<PortRange, ConfigError> {
    // Try single port
    if let Ok(port) = s.trim().parse::<u16>() {
        return Ok(PortRange {
            start: port,
            end: port,
        });
    }

    // Try range "start-end"
    let (start_str, end_str) = s
        .split_once('-')
        .ok_or_else(|| ConfigError::InvalidPortRange {
            value: s.to_string(),
            reason: "expected single port or 'start-end' range".to_string(),
        })?;

    let start = start_str
        .trim()
        .parse::<u16>()
        .map_err(|_| ConfigError::InvalidPortRange {
            value: s.to_string(),
            reason: format!("invalid start port: '{start_str}'"),
        })?;
    let end = end_str
        .trim()
        .parse::<u16>()
        .map_err(|_| ConfigError::InvalidPortRange {
            value: s.to_string(),
            reason: format!("invalid end port: '{end_str}'"),
        })?;

    if start > end {
        return Err(ConfigError::InvalidPortRange {
            value: s.to_string(),
            reason: format!("start ({start}) must be <= end ({end})"),
        });
    }

    Ok(PortRange { start, end })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip_set_config() -> AliasConfig {
        AliasConfig {
            alias_type: "ip_set".to_string(),
            values: vec![
                serde_yaml_ng::Value::String("192.168.0.0/16".to_string()),
                serde_yaml_ng::Value::String("10.0.0.0/8".to_string()),
            ],
            aliases: Vec::new(),
            url: None,
            refresh_interval: None,
            country_codes: Vec::new(),
            hostnames: Vec::new(),
            interfaces: Vec::new(),
            description: None,
        }
    }

    #[test]
    fn validate_ip_set_ok() {
        assert!(ip_set_config().validate("rfc1918").is_ok());
    }

    #[test]
    fn validate_ip_set_empty_values() {
        let mut cfg = ip_set_config();
        cfg.values.clear();
        assert!(cfg.validate("empty").is_err());
    }

    #[test]
    fn validate_ip_set_invalid_cidr() {
        let mut cfg = ip_set_config();
        cfg.values = vec![serde_yaml_ng::Value::String("not-a-cidr".to_string())];
        assert!(cfg.validate("bad").is_err());
    }

    #[test]
    fn validate_nested_ok() {
        let cfg = AliasConfig {
            alias_type: "nested".to_string(),
            values: Vec::new(),
            aliases: vec!["a".to_string(), "b".to_string()],
            url: None,
            refresh_interval: None,
            country_codes: Vec::new(),
            hostnames: Vec::new(),
            interfaces: Vec::new(),
            description: None,
        };
        assert!(cfg.validate("combined").is_ok());
    }

    #[test]
    fn validate_nested_empty() {
        let cfg = AliasConfig {
            alias_type: "nested".to_string(),
            values: Vec::new(),
            aliases: Vec::new(),
            url: None,
            refresh_interval: None,
            country_codes: Vec::new(),
            hostnames: Vec::new(),
            interfaces: Vec::new(),
            description: None,
        };
        assert!(cfg.validate("bad").is_err());
    }

    #[test]
    fn validate_url_table_ok() {
        let cfg = AliasConfig {
            alias_type: "url_table".to_string(),
            values: Vec::new(),
            aliases: Vec::new(),
            url: Some("https://example.com/list.txt".to_string()),
            refresh_interval: Some(3600),
            country_codes: Vec::new(),
            hostnames: Vec::new(),
            interfaces: Vec::new(),
            description: None,
        };
        assert!(cfg.validate("blocklist").is_ok());
    }

    #[test]
    fn validate_url_table_missing_url() {
        let cfg = AliasConfig {
            alias_type: "url_table".to_string(),
            values: Vec::new(),
            aliases: Vec::new(),
            url: None,
            refresh_interval: Some(3600),
            country_codes: Vec::new(),
            hostnames: Vec::new(),
            interfaces: Vec::new(),
            description: None,
        };
        assert!(cfg.validate("bad").is_err());
    }

    #[test]
    fn validate_geoip_ok() {
        let cfg = AliasConfig {
            alias_type: "geoip".to_string(),
            values: Vec::new(),
            aliases: Vec::new(),
            url: None,
            refresh_interval: None,
            country_codes: vec!["CN".to_string(), "RU".to_string()],
            hostnames: Vec::new(),
            interfaces: Vec::new(),
            description: None,
        };
        assert!(cfg.validate("blocked").is_ok());
    }

    #[test]
    fn validate_geoip_invalid_code() {
        let cfg = AliasConfig {
            alias_type: "geoip".to_string(),
            values: Vec::new(),
            aliases: Vec::new(),
            url: None,
            refresh_interval: None,
            country_codes: vec!["china".to_string()],
            hostnames: Vec::new(),
            interfaces: Vec::new(),
            description: None,
        };
        assert!(cfg.validate("bad").is_err());
    }

    #[test]
    fn validate_invalid_type() {
        let cfg = AliasConfig {
            alias_type: "unknown".to_string(),
            values: Vec::new(),
            aliases: Vec::new(),
            url: None,
            refresh_interval: None,
            country_codes: Vec::new(),
            hostnames: Vec::new(),
            interfaces: Vec::new(),
            description: None,
        };
        assert!(cfg.validate("bad").is_err());
    }

    #[test]
    fn to_domain_ip_set() {
        let alias = ip_set_config().to_domain_alias("rfc1918").unwrap();
        assert_eq!(alias.id.0, "rfc1918");
        assert!(matches!(alias.kind, AliasKind::IpSet { ref values } if values.len() == 2));
    }

    #[test]
    fn to_domain_port_set() {
        let cfg = AliasConfig {
            alias_type: "port_set".to_string(),
            values: vec![
                serde_yaml_ng::Value::String("80-443".to_string()),
                serde_yaml_ng::Value::Number(serde_yaml_ng::Number::from(8080)),
            ],
            aliases: Vec::new(),
            url: None,
            refresh_interval: None,
            country_codes: Vec::new(),
            hostnames: Vec::new(),
            interfaces: Vec::new(),
            description: None,
        };
        let alias = cfg.to_domain_alias("http_ports").unwrap();
        match alias.kind {
            AliasKind::PortSet { values } => {
                assert_eq!(values.len(), 2);
                assert_eq!(values[0].start, 80);
                assert_eq!(values[0].end, 443);
                assert_eq!(values[1].start, 8080);
                assert_eq!(values[1].end, 8080);
            }
            _ => panic!("expected PortSet"),
        }
    }

    #[test]
    fn to_domain_nested() {
        let cfg = AliasConfig {
            alias_type: "nested".to_string(),
            values: Vec::new(),
            aliases: vec!["a".to_string(), "b".to_string()],
            url: None,
            refresh_interval: None,
            country_codes: Vec::new(),
            hostnames: Vec::new(),
            interfaces: Vec::new(),
            description: None,
        };
        let alias = cfg.to_domain_alias("combined").unwrap();
        assert!(matches!(alias.kind, AliasKind::Nested { ref aliases } if aliases.len() == 2));
    }

    #[test]
    fn aliases_map_to_domain() {
        let mut map = HashMap::new();
        map.insert("test".to_string(), ip_set_config());
        let aliases = aliases_to_domain(&map).unwrap();
        assert_eq!(aliases.len(), 1);
        assert_eq!(aliases[0].id.0, "test");
    }

    #[test]
    fn yaml_roundtrip() {
        let yaml = r#"
type: ip_set
values: ["192.168.0.0/16", "10.0.0.0/8"]
description: "RFC 1918 private networks"
"#;
        let cfg: AliasConfig = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(cfg.alias_type, "ip_set");
        assert_eq!(cfg.values.len(), 2);
        assert_eq!(
            cfg.description.as_deref(),
            Some("RFC 1918 private networks")
        );
    }
}
