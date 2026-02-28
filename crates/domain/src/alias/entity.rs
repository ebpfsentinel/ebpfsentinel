use serde::{Deserialize, Serialize};

use crate::firewall::entity::{IpNetwork, PortRange};

/// Unique identifier for an alias.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AliasId(pub String);

impl AliasId {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.0.is_empty() {
            return Err("alias ID must not be empty");
        }
        if !self
            .0
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            return Err("alias ID must contain only alphanumeric, dashes, underscores");
        }
        Ok(())
    }
}

impl std::fmt::Display for AliasId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The kind of alias — determines how IPs/ports are resolved.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AliasKind {
    /// Static set of IP addresses/CIDRs.
    IpSet { values: Vec<IpNetwork> },
    /// Static set of port ranges.
    PortSet { values: Vec<PortRange> },
    /// References to other aliases (recursive).
    Nested { aliases: Vec<String> },
    /// HTTP URL returning a list of IPs (refreshed periodically).
    UrlTable {
        url: String,
        refresh_interval_secs: u64,
    },
    /// `GeoIP` country-based IP sets (`MaxMind` `GeoLite2`).
    GeoIp { country_codes: Vec<String> },
    /// Dynamic DNS hostnames (refreshed periodically).
    DynamicDns {
        hostnames: Vec<String>,
        refresh_interval_secs: u64,
    },
    /// IPs of network interfaces by name.
    InterfaceGroup { interfaces: Vec<String> },
}

/// A named alias definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alias {
    pub id: AliasId,
    #[serde(flatten)]
    pub kind: AliasKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl Alias {
    pub fn validate(&self) -> Result<(), super::error::AliasError> {
        self.id
            .validate()
            .map_err(|reason| super::error::AliasError::Invalid {
                reason: reason.to_string(),
            })?;

        match &self.kind {
            AliasKind::IpSet { values } => {
                for ip in values {
                    ip.validate()
                        .map_err(|e| super::error::AliasError::Invalid {
                            reason: e.to_string(),
                        })?;
                }
            }
            AliasKind::PortSet { values } => {
                for range in values {
                    range
                        .validate()
                        .map_err(|e| super::error::AliasError::Invalid {
                            reason: e.to_string(),
                        })?;
                }
            }
            AliasKind::Nested { aliases } => {
                if aliases.is_empty() {
                    return Err(super::error::AliasError::Invalid {
                        reason: "nested alias must reference at least one alias".to_string(),
                    });
                }
            }
            AliasKind::UrlTable {
                url,
                refresh_interval_secs,
            } => {
                if url.is_empty() {
                    return Err(super::error::AliasError::Invalid {
                        reason: "URL must not be empty".to_string(),
                    });
                }
                if *refresh_interval_secs == 0 {
                    return Err(super::error::AliasError::Invalid {
                        reason: "refresh interval must be > 0".to_string(),
                    });
                }
            }
            AliasKind::GeoIp { country_codes } => {
                if country_codes.is_empty() {
                    return Err(super::error::AliasError::Invalid {
                        reason: "GeoIP alias must have at least one country code".to_string(),
                    });
                }
                for code in country_codes {
                    if code.len() != 2 || !code.chars().all(|c| c.is_ascii_uppercase()) {
                        return Err(super::error::AliasError::Invalid {
                            reason: format!("invalid country code: {code} (expected 2-letter ISO)"),
                        });
                    }
                }
            }
            AliasKind::DynamicDns {
                hostnames,
                refresh_interval_secs,
            } => {
                if hostnames.is_empty() {
                    return Err(super::error::AliasError::Invalid {
                        reason: "dynamic DNS must have at least one hostname".to_string(),
                    });
                }
                if *refresh_interval_secs == 0 {
                    return Err(super::error::AliasError::Invalid {
                        reason: "refresh interval must be > 0".to_string(),
                    });
                }
            }
            AliasKind::InterfaceGroup { interfaces } => {
                if interfaces.is_empty() {
                    return Err(super::error::AliasError::Invalid {
                        reason: "interface group must have at least one interface".to_string(),
                    });
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alias_id_valid() {
        assert!(AliasId("rfc1918".to_string()).validate().is_ok());
        assert!(AliasId("web-servers".to_string()).validate().is_ok());
        assert!(AliasId("my_alias_1".to_string()).validate().is_ok());
    }

    #[test]
    fn alias_id_empty() {
        assert!(AliasId(String::new()).validate().is_err());
    }

    #[test]
    fn alias_id_special_chars() {
        assert!(AliasId("bad alias".to_string()).validate().is_err());
        assert!(AliasId("bad.alias".to_string()).validate().is_err());
    }

    #[test]
    fn validate_ip_set_ok() {
        let alias = Alias {
            id: AliasId("test".to_string()),
            kind: AliasKind::IpSet {
                values: vec![IpNetwork::V4 {
                    addr: 0xC0A80000,
                    prefix_len: 16,
                }],
            },
            description: None,
        };
        assert!(alias.validate().is_ok());
    }

    #[test]
    fn validate_ip_set_invalid_cidr() {
        let alias = Alias {
            id: AliasId("test".to_string()),
            kind: AliasKind::IpSet {
                values: vec![IpNetwork::V4 {
                    addr: 0,
                    prefix_len: 33,
                }],
            },
            description: None,
        };
        assert!(alias.validate().is_err());
    }

    #[test]
    fn validate_port_set_ok() {
        let alias = Alias {
            id: AliasId("ports".to_string()),
            kind: AliasKind::PortSet {
                values: vec![PortRange {
                    start: 80,
                    end: 443,
                }],
            },
            description: None,
        };
        assert!(alias.validate().is_ok());
    }

    #[test]
    fn validate_port_set_inverted() {
        let alias = Alias {
            id: AliasId("ports".to_string()),
            kind: AliasKind::PortSet {
                values: vec![PortRange {
                    start: 443,
                    end: 80,
                }],
            },
            description: None,
        };
        assert!(alias.validate().is_err());
    }

    #[test]
    fn validate_nested_empty() {
        let alias = Alias {
            id: AliasId("nested".to_string()),
            kind: AliasKind::Nested {
                aliases: Vec::new(),
            },
            description: None,
        };
        assert!(alias.validate().is_err());
    }

    #[test]
    fn validate_nested_ok() {
        let alias = Alias {
            id: AliasId("nested".to_string()),
            kind: AliasKind::Nested {
                aliases: vec!["rfc1918".to_string()],
            },
            description: None,
        };
        assert!(alias.validate().is_ok());
    }

    #[test]
    fn validate_url_table_empty_url() {
        let alias = Alias {
            id: AliasId("url".to_string()),
            kind: AliasKind::UrlTable {
                url: String::new(),
                refresh_interval_secs: 3600,
            },
            description: None,
        };
        assert!(alias.validate().is_err());
    }

    #[test]
    fn validate_url_table_zero_interval() {
        let alias = Alias {
            id: AliasId("url".to_string()),
            kind: AliasKind::UrlTable {
                url: "https://example.com".to_string(),
                refresh_interval_secs: 0,
            },
            description: None,
        };
        assert!(alias.validate().is_err());
    }

    #[test]
    fn validate_geoip_ok() {
        let alias = Alias {
            id: AliasId("geo".to_string()),
            kind: AliasKind::GeoIp {
                country_codes: vec!["CN".to_string(), "RU".to_string()],
            },
            description: None,
        };
        assert!(alias.validate().is_ok());
    }

    #[test]
    fn validate_geoip_invalid_code() {
        let alias = Alias {
            id: AliasId("geo".to_string()),
            kind: AliasKind::GeoIp {
                country_codes: vec!["china".to_string()],
            },
            description: None,
        };
        assert!(alias.validate().is_err());
    }

    #[test]
    fn validate_geoip_empty() {
        let alias = Alias {
            id: AliasId("geo".to_string()),
            kind: AliasKind::GeoIp {
                country_codes: Vec::new(),
            },
            description: None,
        };
        assert!(alias.validate().is_err());
    }

    #[test]
    fn validate_dynamic_dns_ok() {
        let alias = Alias {
            id: AliasId("dns".to_string()),
            kind: AliasKind::DynamicDns {
                hostnames: vec!["vpn.example.com".to_string()],
                refresh_interval_secs: 300,
            },
            description: None,
        };
        assert!(alias.validate().is_ok());
    }

    #[test]
    fn validate_interface_group_empty() {
        let alias = Alias {
            id: AliasId("ifaces".to_string()),
            kind: AliasKind::InterfaceGroup {
                interfaces: Vec::new(),
            },
            description: None,
        };
        assert!(alias.validate().is_err());
    }
}
