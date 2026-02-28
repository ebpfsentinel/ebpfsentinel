use serde::{Deserialize, Serialize};

use super::error::ZoneError;

/// Default policy for a security zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ZonePolicy {
    Allow,
    Deny,
}

/// A security zone grouping network interfaces.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Zone {
    pub id: String,
    pub interfaces: Vec<String>,
    pub default_policy: ZonePolicy,
}

impl Zone {
    pub fn validate(&self) -> Result<(), ZoneError> {
        if self.id.is_empty() {
            return Err(ZoneError::Invalid {
                reason: "zone ID must not be empty".to_string(),
            });
        }
        if self.interfaces.is_empty() {
            return Err(ZoneError::Invalid {
                reason: format!("zone '{}' must have at least one interface", self.id),
            });
        }
        Ok(())
    }
}

/// Policy for traffic between two zones.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZonePair {
    pub from: String,
    pub to: String,
    pub policy: ZonePolicy,
}

impl ZonePair {
    pub fn validate(&self) -> Result<(), ZoneError> {
        if self.from.is_empty() || self.to.is_empty() {
            return Err(ZoneError::Invalid {
                reason: "zone pair must have non-empty from and to".to_string(),
            });
        }
        if self.from == self.to {
            return Err(ZoneError::Invalid {
                reason: format!("zone pair from and to must differ: '{}'", self.from),
            });
        }
        Ok(())
    }
}

/// Zone configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneConfig {
    pub zones: Vec<Zone>,
    #[serde(default)]
    pub zone_policies: Vec<ZonePair>,
}

impl ZoneConfig {
    pub fn validate(&self) -> Result<(), ZoneError> {
        // Validate zones
        let mut zone_ids = std::collections::HashSet::new();
        for zone in &self.zones {
            zone.validate()?;
            if !zone_ids.insert(&zone.id) {
                return Err(ZoneError::Duplicate {
                    id: zone.id.clone(),
                });
            }
        }

        // Validate zone pairs reference existing zones
        for pair in &self.zone_policies {
            pair.validate()?;
            if !zone_ids.contains(&pair.from) {
                return Err(ZoneError::NotFound {
                    id: pair.from.clone(),
                });
            }
            if !zone_ids.contains(&pair.to) {
                return Err(ZoneError::NotFound {
                    id: pair.to.clone(),
                });
            }
        }

        // Check for interface overlaps across zones
        let mut iface_zones: std::collections::HashMap<&str, &str> =
            std::collections::HashMap::new();
        for zone in &self.zones {
            for iface in &zone.interfaces {
                if let Some(other_zone) = iface_zones.insert(iface.as_str(), &zone.id) {
                    return Err(ZoneError::Invalid {
                        reason: format!(
                            "interface '{iface}' assigned to multiple zones: '{}' and '{}'",
                            other_zone, zone.id
                        ),
                    });
                }
            }
        }

        Ok(())
    }

    /// Lookup the zone ID for a given interface name.
    pub fn zone_for_interface(&self, iface: &str) -> Option<&str> {
        self.zones
            .iter()
            .find(|z| z.interfaces.iter().any(|i| i == iface))
            .map(|z| z.id.as_str())
    }

    /// Lookup the policy between two zones.
    pub fn policy(&self, from: &str, to: &str) -> Option<ZonePolicy> {
        self.zone_policies
            .iter()
            .find(|p| p.from == from && p.to == to)
            .map(|p| p.policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zone_validate_ok() {
        let zone = Zone {
            id: "wan".to_string(),
            interfaces: vec!["eth0".to_string()],
            default_policy: ZonePolicy::Deny,
        };
        assert!(zone.validate().is_ok());
    }

    #[test]
    fn zone_empty_id() {
        let zone = Zone {
            id: String::new(),
            interfaces: vec!["eth0".to_string()],
            default_policy: ZonePolicy::Deny,
        };
        assert!(zone.validate().is_err());
    }

    #[test]
    fn zone_no_interfaces() {
        let zone = Zone {
            id: "empty".to_string(),
            interfaces: Vec::new(),
            default_policy: ZonePolicy::Allow,
        };
        assert!(zone.validate().is_err());
    }

    #[test]
    fn zone_pair_validate_ok() {
        let pair = ZonePair {
            from: "lan".to_string(),
            to: "wan".to_string(),
            policy: ZonePolicy::Allow,
        };
        assert!(pair.validate().is_ok());
    }

    #[test]
    fn zone_pair_same_zone() {
        let pair = ZonePair {
            from: "lan".to_string(),
            to: "lan".to_string(),
            policy: ZonePolicy::Allow,
        };
        assert!(pair.validate().is_err());
    }

    #[test]
    fn zone_config_ok() {
        let cfg = ZoneConfig {
            zones: vec![
                Zone {
                    id: "wan".to_string(),
                    interfaces: vec!["eth0".to_string()],
                    default_policy: ZonePolicy::Deny,
                },
                Zone {
                    id: "lan".to_string(),
                    interfaces: vec!["eth1".to_string(), "eth2".to_string()],
                    default_policy: ZonePolicy::Allow,
                },
            ],
            zone_policies: vec![
                ZonePair {
                    from: "lan".to_string(),
                    to: "wan".to_string(),
                    policy: ZonePolicy::Allow,
                },
                ZonePair {
                    from: "wan".to_string(),
                    to: "lan".to_string(),
                    policy: ZonePolicy::Deny,
                },
            ],
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn zone_config_duplicate_zone() {
        let cfg = ZoneConfig {
            zones: vec![
                Zone {
                    id: "wan".to_string(),
                    interfaces: vec!["eth0".to_string()],
                    default_policy: ZonePolicy::Deny,
                },
                Zone {
                    id: "wan".to_string(),
                    interfaces: vec!["eth1".to_string()],
                    default_policy: ZonePolicy::Allow,
                },
            ],
            zone_policies: Vec::new(),
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn zone_config_interface_overlap() {
        let cfg = ZoneConfig {
            zones: vec![
                Zone {
                    id: "wan".to_string(),
                    interfaces: vec!["eth0".to_string()],
                    default_policy: ZonePolicy::Deny,
                },
                Zone {
                    id: "lan".to_string(),
                    interfaces: vec!["eth0".to_string()],
                    default_policy: ZonePolicy::Allow,
                },
            ],
            zone_policies: Vec::new(),
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn zone_config_pair_references_unknown_zone() {
        let cfg = ZoneConfig {
            zones: vec![Zone {
                id: "wan".to_string(),
                interfaces: vec!["eth0".to_string()],
                default_policy: ZonePolicy::Deny,
            }],
            zone_policies: vec![ZonePair {
                from: "wan".to_string(),
                to: "nonexistent".to_string(),
                policy: ZonePolicy::Deny,
            }],
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn zone_for_interface_found() {
        let cfg = ZoneConfig {
            zones: vec![
                Zone {
                    id: "wan".to_string(),
                    interfaces: vec!["eth0".to_string()],
                    default_policy: ZonePolicy::Deny,
                },
                Zone {
                    id: "lan".to_string(),
                    interfaces: vec!["eth1".to_string()],
                    default_policy: ZonePolicy::Allow,
                },
            ],
            zone_policies: Vec::new(),
        };
        assert_eq!(cfg.zone_for_interface("eth0"), Some("wan"));
        assert_eq!(cfg.zone_for_interface("eth1"), Some("lan"));
        assert_eq!(cfg.zone_for_interface("eth2"), None);
    }

    #[test]
    fn zone_policy_lookup() {
        let cfg = ZoneConfig {
            zones: vec![
                Zone {
                    id: "wan".to_string(),
                    interfaces: vec!["eth0".to_string()],
                    default_policy: ZonePolicy::Deny,
                },
                Zone {
                    id: "lan".to_string(),
                    interfaces: vec!["eth1".to_string()],
                    default_policy: ZonePolicy::Allow,
                },
            ],
            zone_policies: vec![ZonePair {
                from: "lan".to_string(),
                to: "wan".to_string(),
                policy: ZonePolicy::Allow,
            }],
        };
        assert_eq!(cfg.policy("lan", "wan"), Some(ZonePolicy::Allow));
        assert_eq!(cfg.policy("wan", "lan"), None);
    }
}
