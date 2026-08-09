use std::sync::Arc;

use domain::zone::entity::{Zone, ZoneConfig, ZonePair, ZonePolicy};
use domain::zone::error::ZoneError;
use ports::secondary::metrics_port::MetricsPort;
use ports::secondary::zone_map_port::ZoneMapPort;

/// Application-level zone service.
///
/// Owns the security zone configuration, exposes it to the REST API layer,
/// and pushes every change down to the datapath. Zoning that lives only in
/// this service decides nothing: the firewall reads the eBPF maps, so a zone
/// added here and not programmed there would be reported and never enforced.
pub struct ZoneAppService {
    config: Option<ZoneConfig>,
    map_port: Option<Box<dyn ZoneMapPort + Send>>,
    metrics: Option<Arc<dyn MetricsPort>>,
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
            map_port: None,
            metrics: None,
            enabled: false,
        }
    }

    /// Set the metrics port for recording zone metrics.
    pub fn set_metrics(&mut self, metrics: Arc<dyn MetricsPort>) {
        self.metrics = Some(metrics);
    }

    /// Set the eBPF map port and program what is already loaded.
    ///
    /// The port usually arrives after the configuration, because the firewall
    /// program is loaded later in startup than the config is parsed.
    pub fn set_map_port(&mut self, port: Box<dyn ZoneMapPort + Send>) {
        self.map_port = Some(port);
        self.sync_maps();
    }

    /// Drop the map port; the firewall program is gone with its maps.
    pub fn clear_map_port(&mut self) {
        self.map_port = None;
    }

    /// Push the current configuration into the datapath.
    ///
    /// A disabled service programs an empty set rather than leaving the last
    /// zones in the maps: switching zoning off has to stop zone posture from
    /// deciding packets, not freeze it.
    fn sync_maps(&mut self) {
        let Some(ref mut port) = self.map_port else {
            return;
        };
        let empty = ZoneConfig {
            zones: Vec::new(),
            zone_policies: Vec::new(),
        };
        let config = match (self.enabled, self.config.as_ref()) {
            (true, Some(cfg)) => cfg,
            _ => &empty,
        };
        if let Err(e) = port.sync(config) {
            tracing::warn!(error = %e, "zone maps not programmed, the datapath keeps the previous zoning");
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        self.sync_maps();
        tracing::info!(enabled, "zone service toggled");
    }

    /// Reload zone configuration. Validates and stores the config.
    pub fn reload(&mut self, config: ZoneConfig) -> Result<(), domain::common::error::DomainError> {
        config
            .validate()
            .map_err(|e| domain::common::error::DomainError::InvalidConfig(e.to_string()))?;
        let total = config.zones.len() + config.zone_policies.len();
        self.config = Some(config);
        self.sync_maps();
        if let Some(ref m) = self.metrics {
            m.set_rules_loaded("zones", total as u64);
            self.publish_zone_gauges(m.as_ref());
        }
        tracing::info!(
            zones = self.zone_count(),
            policies = self.policy_count(),
            "zone config reloaded"
        );
        Ok(())
    }

    /// Add a security zone. Validates the zone id is non-empty and unique.
    pub fn add_zone(&mut self, zone: Zone) -> Result<(), ZoneError> {
        if zone.id.is_empty() {
            return Err(ZoneError::Invalid {
                reason: "zone ID must not be empty".to_string(),
            });
        }
        let cfg = self.config_mut();
        if cfg.zones.iter().any(|z| z.id == zone.id) {
            return Err(ZoneError::Duplicate { id: zone.id });
        }
        cfg.zones.push(zone);
        self.refresh_metrics();
        Ok(())
    }

    /// Remove a security zone by id.
    pub fn remove_zone(&mut self, id: &str) -> Result<(), ZoneError> {
        let cfg = self
            .config
            .as_mut()
            .ok_or_else(|| ZoneError::NotFound { id: id.to_string() })?;
        let before = cfg.zones.len();
        cfg.zones.retain(|z| z.id != id);
        if cfg.zones.len() == before {
            return Err(ZoneError::NotFound { id: id.to_string() });
        }
        self.refresh_metrics();
        Ok(())
    }

    /// Add (or replace) an inter-zone policy for the `(from, to)` pair.
    pub fn add_policy(&mut self, pair: ZonePair) -> Result<(), ZoneError> {
        pair.validate()?;
        let cfg = self.config_mut();
        if let Some(existing) = cfg
            .zone_policies
            .iter_mut()
            .find(|p| p.from == pair.from && p.to == pair.to)
        {
            existing.policy = pair.policy;
        } else {
            cfg.zone_policies.push(pair);
        }
        self.refresh_metrics();
        Ok(())
    }

    /// Remove the inter-zone policy for the `(from, to)` pair.
    pub fn remove_policy(&mut self, from: &str, to: &str) -> Result<(), ZoneError> {
        let cfg = self
            .config
            .as_mut()
            .ok_or_else(|| ZoneError::PairNotFound {
                from: from.to_string(),
                to: to.to_string(),
            })?;
        let before = cfg.zone_policies.len();
        cfg.zone_policies
            .retain(|p| !(p.from == from && p.to == to));
        if cfg.zone_policies.len() == before {
            return Err(ZoneError::PairNotFound {
                from: from.to_string(),
                to: to.to_string(),
            });
        }
        self.refresh_metrics();
        Ok(())
    }

    /// Mutable access to the in-memory config, initialising an empty one if absent.
    fn config_mut(&mut self) -> &mut ZoneConfig {
        self.config.get_or_insert_with(|| ZoneConfig {
            zones: Vec::new(),
            zone_policies: Vec::new(),
        })
    }

    /// Re-publish the loaded-rule gauge and the per-zone gauges after a
    /// mutation. The aggregate alone cannot answer "which zone owns what",
    /// which is the question an operator actually asks.
    fn refresh_metrics(&mut self) {
        self.sync_maps();
        let Some(ref m) = self.metrics else { return };
        let total = self.zone_count() + self.policy_count();
        m.set_rules_loaded("zones", total as u64);
        self.publish_zone_gauges(m.as_ref());
    }

    /// Per-zone interface and policy counts, labelled by zone id.
    fn publish_zone_gauges(&self, m: &dyn MetricsPort) {
        let Some(ref cfg) = self.config else { return };
        for zone in &cfg.zones {
            m.set_zone_interfaces(&zone.id, zone.interfaces.len() as u64);
            let policies = cfg
                .zone_policies
                .iter()
                .filter(|p| p.from == zone.id)
                .count();
            m.set_zone_policies(&zone.id, policies as u64);
        }
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
    use std::sync::Mutex;

    use super::*;

    /// Records what reached the datapath, so a test can tell an accepted
    /// change from an enforced one.
    #[derive(Default)]
    struct RecordingMaps {
        synced: Mutex<Vec<(usize, usize)>>,
    }

    impl RecordingMaps {
        /// (zones, policies) of each sync, in order.
        fn calls(&self) -> Vec<(usize, usize)> {
            self.synced.lock().expect("recording lock").clone()
        }
    }

    /// Port handle sharing one recording with the test.
    struct Recorder(Arc<RecordingMaps>);

    impl ZoneMapPort for Recorder {
        fn sync(&mut self, config: &ZoneConfig) -> Result<(), domain::common::error::DomainError> {
            self.0
                .synced
                .lock()
                .expect("recording lock")
                .push((config.zones.len(), config.zone_policies.len()));
            Ok(())
        }
    }

    /// An enabled service already wired to a recording map port.
    fn wired(maps: &Arc<RecordingMaps>) -> ZoneAppService {
        let mut svc = ZoneAppService::new();
        svc.set_enabled(true);
        svc.set_map_port(Box::new(Recorder(Arc::clone(maps))));
        svc
    }

    #[test]
    fn a_reload_programs_the_datapath() {
        let maps = Arc::new(RecordingMaps::default());
        let mut svc = wired(&maps);
        svc.reload(make_config()).expect("reload");
        assert_eq!(maps.calls().last().copied(), Some((2, 1)));
    }

    #[test]
    fn an_added_zone_reaches_the_datapath() {
        let maps = Arc::new(RecordingMaps::default());
        let mut svc = wired(&maps);
        svc.reload(make_config()).expect("reload");
        svc.add_zone(Zone {
            id: "dmz".to_string(),
            interfaces: vec!["eth3".to_string()],
            default_policy: ZonePolicy::Deny,
        })
        .expect("add zone");
        assert_eq!(maps.calls().last().copied(), Some((3, 1)));
    }

    #[test]
    fn a_removed_policy_reaches_the_datapath() {
        let maps = Arc::new(RecordingMaps::default());
        let mut svc = wired(&maps);
        svc.reload(make_config()).expect("reload");
        svc.remove_policy("lan", "wan").expect("remove policy");
        assert_eq!(maps.calls().last().copied(), Some((2, 0)));
    }

    #[test]
    fn switching_zoning_off_clears_the_datapath() {
        let maps = Arc::new(RecordingMaps::default());
        let mut svc = wired(&maps);
        svc.reload(make_config()).expect("reload");
        svc.set_enabled(false);
        // The configuration is kept, but nothing of it decides packets.
        assert_eq!(maps.calls().last().copied(), Some((0, 0)));
        assert_eq!(svc.zone_count(), 2);
    }

    #[test]
    fn a_port_arriving_after_the_config_still_programs_it() {
        let maps = Arc::new(RecordingMaps::default());
        let mut svc = ZoneAppService::new();
        svc.set_enabled(true);
        svc.reload(make_config()).expect("reload");
        assert!(maps.calls().is_empty());
        svc.set_map_port(Box::new(Recorder(Arc::clone(&maps))));
        assert_eq!(maps.calls(), vec![(2, 1)]);
    }

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

#[cfg(test)]
mod zone_gauge_tests {
    use super::*;
    use ports::secondary::metrics_port::{
        AlertMetrics, AuditMetrics, ConfigMetrics, ConntrackMetrics, ContainerMetrics, CtMetrics,
        DdosMetrics, DlpMetrics, DnsMetrics, DomainMetrics, EventMetrics, FingerprintMetrics,
        FirewallMetrics, IpsMetrics, LbMetrics, PacketMetrics, RoutingMetrics, SystemMetrics,
        ThreatIntelMetrics, ZoneMetrics,
    };
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Default)]
    struct RecordingMetrics {
        interfaces: Mutex<HashMap<String, u64>>,
        policies: Mutex<HashMap<String, u64>>,
    }

    impl PacketMetrics for RecordingMetrics {}
    impl FirewallMetrics for RecordingMetrics {}
    impl AlertMetrics for RecordingMetrics {}
    impl IpsMetrics for RecordingMetrics {}
    impl DnsMetrics for RecordingMetrics {}
    impl DomainMetrics for RecordingMetrics {}
    impl SystemMetrics for RecordingMetrics {}
    impl ConfigMetrics for RecordingMetrics {}
    impl EventMetrics for RecordingMetrics {}
    impl DlpMetrics for RecordingMetrics {}
    impl DdosMetrics for RecordingMetrics {}
    impl ConntrackMetrics for RecordingMetrics {}
    impl RoutingMetrics for RecordingMetrics {}
    impl AuditMetrics for RecordingMetrics {}
    impl LbMetrics for RecordingMetrics {}
    impl FingerprintMetrics for RecordingMetrics {}
    impl ContainerMetrics for RecordingMetrics {}
    impl CtMetrics for RecordingMetrics {}
    impl ThreatIntelMetrics for RecordingMetrics {}
    impl ZoneMetrics for RecordingMetrics {
        fn set_zone_interfaces(&self, zone: &str, count: u64) {
            self.interfaces
                .lock()
                .unwrap()
                .insert(zone.to_string(), count);
        }

        fn set_zone_policies(&self, zone: &str, count: u64) {
            self.policies
                .lock()
                .unwrap()
                .insert(zone.to_string(), count);
        }
    }

    fn zone(id: &str, ifaces: &[&str]) -> Zone {
        Zone {
            id: id.to_string(),
            interfaces: ifaces.iter().map(|s| (*s).to_string()).collect(),
            default_policy: ZonePolicy::Deny,
        }
    }

    #[test]
    fn reload_publishes_a_gauge_per_zone() {
        let metrics = Arc::new(RecordingMetrics::default());
        let mut svc = ZoneAppService::new();
        svc.set_metrics(Arc::clone(&metrics) as Arc<dyn MetricsPort>);

        svc.reload(ZoneConfig {
            zones: vec![
                zone("internal", &["eth0", "eth1"]),
                zone("external", &["eth2"]),
            ],
            zone_policies: vec![ZonePair {
                from: "internal".to_string(),
                to: "external".to_string(),
                policy: ZonePolicy::Allow,
            }],
        })
        .unwrap();

        let ifaces = metrics.interfaces.lock().unwrap();
        assert_eq!(ifaces.get("internal"), Some(&2));
        assert_eq!(ifaces.get("external"), Some(&1));

        let policies = metrics.policies.lock().unwrap();
        // Only counted on the source side, so external has none.
        assert_eq!(policies.get("internal"), Some(&1));
        assert_eq!(policies.get("external"), Some(&0));
    }
}
