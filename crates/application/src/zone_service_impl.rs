use domain::zone::entity::{Zone, ZoneConfig, ZonePair, ZonePolicy};

/// Application-level zone service.
///
/// Manages security zone configuration and provides read-only access
/// to zones and inter-zone policies. Zone data is loaded from config
/// and synced to eBPF maps at startup; this service exposes it to the
/// REST API layer.
pub struct ZoneAppService {
    config: Option<ZoneConfig>,
    enabled: bool,
}

impl Default for ZoneAppService {
    fn default() -> Self {
        Self::new()
    }
}

impl ZoneAppService {
    pub fn new() -> Self {
        Self {
            config: None,
            enabled: false,
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Reload zone configuration. Validates and stores the config.
    pub fn reload(&mut self, config: ZoneConfig) -> Result<(), domain::common::error::DomainError> {
        config
            .validate()
            .map_err(|e| domain::common::error::DomainError::InvalidConfig(e.to_string()))?;
        self.config = Some(config);
        Ok(())
    }

    /// List all zones.
    pub fn zones(&self) -> &[Zone] {
        self.config.as_ref().map_or(&[], |c| c.zones.as_slice())
    }

    /// List all inter-zone policies.
    pub fn zone_policies(&self) -> &[ZonePair] {
        self.config
            .as_ref()
            .map_or(&[], |c| c.zone_policies.as_slice())
    }

    /// Get the number of zones.
    pub fn zone_count(&self) -> usize {
        self.config.as_ref().map_or(0, |c| c.zones.len())
    }

    /// Get the number of inter-zone policies.
    pub fn policy_count(&self) -> usize {
        self.config.as_ref().map_or(0, |c| c.zone_policies.len())
    }

    /// Look up which zone an interface belongs to.
    pub fn zone_for_interface(&self, iface: &str) -> Option<&str> {
        self.config.as_ref()?.zone_for_interface(iface)
    }

    /// Look up the policy between two zones.
    pub fn policy(&self, from: &str, to: &str) -> Option<ZonePolicy> {
        self.config.as_ref()?.policy(from, to)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config() -> ZoneConfig {
        ZoneConfig {
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
            zone_policies: vec![ZonePair {
                from: "lan".to_string(),
                to: "wan".to_string(),
                policy: ZonePolicy::Allow,
            }],
        }
    }

    #[test]
    fn default_disabled() {
        let svc = ZoneAppService::new();
        assert!(!svc.enabled());
        assert_eq!(svc.zone_count(), 0);
        assert_eq!(svc.policy_count(), 0);
        assert!(svc.zones().is_empty());
        assert!(svc.zone_policies().is_empty());
    }

    #[test]
    fn reload_and_list() {
        let mut svc = ZoneAppService::new();
        svc.reload(make_config()).unwrap();
        assert_eq!(svc.zone_count(), 2);
        assert_eq!(svc.policy_count(), 1);
        assert_eq!(svc.zones()[0].id, "wan");
        assert_eq!(svc.zones()[1].id, "lan");
    }

    #[test]
    fn zone_for_interface_lookup() {
        let mut svc = ZoneAppService::new();
        svc.reload(make_config()).unwrap();
        assert_eq!(svc.zone_for_interface("eth0"), Some("wan"));
        assert_eq!(svc.zone_for_interface("eth1"), Some("lan"));
        assert_eq!(svc.zone_for_interface("eth99"), None);
    }

    #[test]
    fn policy_lookup() {
        let mut svc = ZoneAppService::new();
        svc.reload(make_config()).unwrap();
        assert_eq!(svc.policy("lan", "wan"), Some(ZonePolicy::Allow));
        assert_eq!(svc.policy("wan", "lan"), None);
    }

    #[test]
    fn enable_disable() {
        let mut svc = ZoneAppService::new();
        svc.set_enabled(true);
        assert!(svc.enabled());
        svc.set_enabled(false);
        assert!(!svc.enabled());
    }

    #[test]
    fn reload_replaces_config() {
        let mut svc = ZoneAppService::new();
        svc.reload(make_config()).unwrap();
        assert_eq!(svc.zone_count(), 2);

        let small_config = ZoneConfig {
            zones: vec![Zone {
                id: "dmz".to_string(),
                interfaces: vec!["eth3".to_string()],
                default_policy: ZonePolicy::Deny,
            }],
            zone_policies: Vec::new(),
        };
        svc.reload(small_config).unwrap();
        assert_eq!(svc.zone_count(), 1);
        assert_eq!(svc.zones()[0].id, "dmz");
    }
}
