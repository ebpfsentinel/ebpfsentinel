//! Zone-based firewall configuration parsing.

use domain::zone::entity::{Zone, ZoneConfig, ZonePair, ZonePolicy};
use serde::{Deserialize, Serialize};

use super::common::ConfigError;

/// Maximum number of zones.
pub(super) const MAX_ZONES: usize = 64;

/// Top-level zone section config.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ZoneSectionConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub zones: Vec<ZoneEntryConfig>,

    #[serde(default)]
    pub policies: Vec<ZonePairConfig>,
}

impl ZoneSectionConfig {
    /// Validate the zone section.
    pub(super) fn validate(&self) -> Result<(), ConfigError> {
        for (idx, zone) in self.zones.iter().enumerate() {
            zone.validate(idx)?;
        }
        for (idx, policy) in self.policies.iter().enumerate() {
            policy.validate(idx)?;
        }

        // Check for duplicate zone IDs
        let mut ids = std::collections::HashSet::new();
        for zone in &self.zones {
            if !ids.insert(&zone.id) {
                return Err(ConfigError::Validation {
                    field: format!("zones.zones.{}", zone.id),
                    message: format!("duplicate zone ID: {}", zone.id),
                });
            }
        }

        // Validate policy references
        for (idx, policy) in self.policies.iter().enumerate() {
            if !ids.contains(&policy.from) {
                return Err(ConfigError::Validation {
                    field: format!("zones.policies[{idx}].from"),
                    message: format!("references unknown zone: {}", policy.from),
                });
            }
            if !ids.contains(&policy.to) {
                return Err(ConfigError::Validation {
                    field: format!("zones.policies[{idx}].to"),
                    message: format!("references unknown zone: {}", policy.to),
                });
            }
        }

        // Check for interface overlap
        let mut iface_zones: std::collections::HashMap<&str, &str> =
            std::collections::HashMap::new();
        for zone in &self.zones {
            for iface in &zone.interfaces {
                if let Some(other_zone) = iface_zones.insert(iface.as_str(), &zone.id) {
                    return Err(ConfigError::Validation {
                        field: format!("zones.zones.{}.interfaces", zone.id),
                        message: format!(
                            "interface '{iface}' assigned to multiple zones: '{}' and '{}'",
                            other_zone, zone.id
                        ),
                    });
                }
            }
        }

        Ok(())
    }

    /// Convert to domain `ZoneConfig`.
    pub fn to_domain_config(&self) -> Result<ZoneConfig, ConfigError> {
        let zones = self
            .zones
            .iter()
            .map(ZoneEntryConfig::to_domain_zone)
            .collect::<Result<Vec<_>, _>>()?;

        let zone_policies = self
            .policies
            .iter()
            .map(ZonePairConfig::to_domain_pair)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(ZoneConfig {
            zones,
            zone_policies,
        })
    }
}

/// YAML representation of a security zone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneEntryConfig {
    pub id: String,
    pub interfaces: Vec<String>,
    #[serde(default = "default_zone_policy")]
    pub default_policy: String,
}

fn default_zone_policy() -> String {
    "deny".to_string()
}

impl ZoneEntryConfig {
    pub(super) fn validate(&self, idx: usize) -> Result<(), ConfigError> {
        let prefix = format!("zones.zones[{idx}]");

        if self.id.is_empty() {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.id"),
                message: "zone ID must not be empty".to_string(),
            });
        }

        if self.interfaces.is_empty() {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.interfaces"),
                message: format!("zone '{}' must have at least one interface", self.id),
            });
        }

        parse_zone_policy(&self.default_policy).map_err(|()| ConfigError::InvalidValue {
            field: format!("{prefix}.default_policy"),
            value: self.default_policy.clone(),
            expected: "allow, deny".to_string(),
        })?;

        Ok(())
    }

    pub fn to_domain_zone(&self) -> Result<Zone, ConfigError> {
        let default_policy =
            parse_zone_policy(&self.default_policy).map_err(|()| ConfigError::InvalidValue {
                field: "default_policy".to_string(),
                value: self.default_policy.clone(),
                expected: "allow, deny".to_string(),
            })?;

        Ok(Zone {
            id: self.id.clone(),
            interfaces: self.interfaces.clone(),
            default_policy,
        })
    }
}

/// YAML representation of a zone pair policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZonePairConfig {
    pub from: String,
    pub to: String,
    pub policy: String,
}

impl ZonePairConfig {
    pub(super) fn validate(&self, idx: usize) -> Result<(), ConfigError> {
        let prefix = format!("zones.policies[{idx}]");

        if self.from.is_empty() || self.to.is_empty() {
            return Err(ConfigError::Validation {
                field: prefix.clone(),
                message: "zone pair must have non-empty from and to".to_string(),
            });
        }

        if self.from == self.to {
            return Err(ConfigError::Validation {
                field: prefix.clone(),
                message: format!("zone pair from and to must differ: '{}'", self.from),
            });
        }

        parse_zone_policy(&self.policy).map_err(|()| ConfigError::InvalidValue {
            field: format!("{prefix}.policy"),
            value: self.policy.clone(),
            expected: "allow, deny".to_string(),
        })?;

        Ok(())
    }

    pub fn to_domain_pair(&self) -> Result<ZonePair, ConfigError> {
        let policy = parse_zone_policy(&self.policy).map_err(|()| ConfigError::InvalidValue {
            field: "policy".to_string(),
            value: self.policy.clone(),
            expected: "allow, deny".to_string(),
        })?;

        Ok(ZonePair {
            from: self.from.clone(),
            to: self.to.clone(),
            policy,
        })
    }
}

fn parse_zone_policy(s: &str) -> Result<ZonePolicy, ()> {
    match s.to_lowercase().as_str() {
        "allow" | "permit" | "accept" => Ok(ZonePolicy::Allow),
        "deny" | "drop" | "reject" => Ok(ZonePolicy::Deny),
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_zone_ok() {
        let cfg = ZoneEntryConfig {
            id: "wan".to_string(),
            interfaces: vec!["eth0".to_string()],
            default_policy: "deny".to_string(),
        };
        assert!(cfg.validate(0).is_ok());
    }

    #[test]
    fn validate_zone_empty_id() {
        let cfg = ZoneEntryConfig {
            id: String::new(),
            interfaces: vec!["eth0".to_string()],
            default_policy: "deny".to_string(),
        };
        assert!(cfg.validate(0).is_err());
    }

    #[test]
    fn validate_zone_no_interfaces() {
        let cfg = ZoneEntryConfig {
            id: "empty".to_string(),
            interfaces: Vec::new(),
            default_policy: "deny".to_string(),
        };
        assert!(cfg.validate(0).is_err());
    }

    #[test]
    fn validate_pair_ok() {
        let cfg = ZonePairConfig {
            from: "lan".to_string(),
            to: "wan".to_string(),
            policy: "allow".to_string(),
        };
        assert!(cfg.validate(0).is_ok());
    }

    #[test]
    fn validate_pair_same_zone() {
        let cfg = ZonePairConfig {
            from: "lan".to_string(),
            to: "lan".to_string(),
            policy: "allow".to_string(),
        };
        assert!(cfg.validate(0).is_err());
    }

    #[test]
    fn validate_section_ok() {
        let cfg = ZoneSectionConfig {
            enabled: true,
            zones: vec![
                ZoneEntryConfig {
                    id: "wan".to_string(),
                    interfaces: vec!["eth0".to_string()],
                    default_policy: "deny".to_string(),
                },
                ZoneEntryConfig {
                    id: "lan".to_string(),
                    interfaces: vec!["eth1".to_string()],
                    default_policy: "allow".to_string(),
                },
            ],
            policies: vec![ZonePairConfig {
                from: "lan".to_string(),
                to: "wan".to_string(),
                policy: "allow".to_string(),
            }],
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn validate_section_duplicate_zones() {
        let cfg = ZoneSectionConfig {
            enabled: true,
            zones: vec![
                ZoneEntryConfig {
                    id: "wan".to_string(),
                    interfaces: vec!["eth0".to_string()],
                    default_policy: "deny".to_string(),
                },
                ZoneEntryConfig {
                    id: "wan".to_string(),
                    interfaces: vec!["eth1".to_string()],
                    default_policy: "deny".to_string(),
                },
            ],
            policies: Vec::new(),
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_section_interface_overlap() {
        let cfg = ZoneSectionConfig {
            enabled: true,
            zones: vec![
                ZoneEntryConfig {
                    id: "wan".to_string(),
                    interfaces: vec!["eth0".to_string()],
                    default_policy: "deny".to_string(),
                },
                ZoneEntryConfig {
                    id: "lan".to_string(),
                    interfaces: vec!["eth0".to_string()],
                    default_policy: "allow".to_string(),
                },
            ],
            policies: Vec::new(),
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_section_unknown_zone_ref() {
        let cfg = ZoneSectionConfig {
            enabled: true,
            zones: vec![ZoneEntryConfig {
                id: "wan".to_string(),
                interfaces: vec!["eth0".to_string()],
                default_policy: "deny".to_string(),
            }],
            policies: vec![ZonePairConfig {
                from: "wan".to_string(),
                to: "nonexistent".to_string(),
                policy: "deny".to_string(),
            }],
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn to_domain_config() {
        let cfg = ZoneSectionConfig {
            enabled: true,
            zones: vec![
                ZoneEntryConfig {
                    id: "wan".to_string(),
                    interfaces: vec!["eth0".to_string()],
                    default_policy: "deny".to_string(),
                },
                ZoneEntryConfig {
                    id: "lan".to_string(),
                    interfaces: vec!["eth1".to_string()],
                    default_policy: "allow".to_string(),
                },
            ],
            policies: vec![ZonePairConfig {
                from: "lan".to_string(),
                to: "wan".to_string(),
                policy: "allow".to_string(),
            }],
        };
        let domain_cfg = cfg.to_domain_config().unwrap();
        assert_eq!(domain_cfg.zones.len(), 2);
        assert_eq!(domain_cfg.zone_policies.len(), 1);
    }

    #[test]
    fn default_section_disabled() {
        let cfg = ZoneSectionConfig::default();
        assert!(!cfg.enabled);
        assert!(cfg.zones.is_empty());
        assert!(cfg.policies.is_empty());
    }

    #[test]
    fn yaml_roundtrip() {
        let yaml = r#"
enabled: true
zones:
  - id: wan
    interfaces: [eth0]
    default_policy: deny
  - id: lan
    interfaces: [eth1, eth2]
    default_policy: allow
policies:
  - from: lan
    to: wan
    policy: allow
"#;
        let cfg: ZoneSectionConfig = serde_yaml_ng::from_str(yaml).unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.zones.len(), 2);
        assert_eq!(cfg.policies.len(), 1);
        assert!(cfg.validate().is_ok());
    }
}
