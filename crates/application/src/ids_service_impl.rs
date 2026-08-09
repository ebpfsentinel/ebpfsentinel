use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use domain::common::entity::{DomainMode, RuleId};
use domain::common::error::DomainError;
use domain::ids::engine::IdsEngine;
use domain::ids::entity::{IdsRule, SamplingMode, ThresholdConfig};
use ebpf_common::event::PacketEvent;
use ebpf_common::ids::{IDS_ACTION_ALERT, IdsPatternKey};
use ports::secondary::geoip_port::GeoIpPort;
use ports::secondary::ids_map_port::IdsMapPort;
use ports::secondary::metrics_port::MetricsPort;

/// Shared handle to the eBPF map port, behind `Arc<Mutex<..>>` so the
/// service can be cheaply cloned (required by the `ArcSwap` pattern)
/// while the map port remains shared across clones.
type SharedIdsMapPort = Arc<Mutex<Box<dyn IdsMapPort + Send>>>;

/// Identity of one kernel map slot: tenant, port, protocol, and whether the
/// slot lives in the source-port map rather than the destination-port one.
type KernelSlot = (u32, u16, u8, bool);

/// Application-level IDS service.
///
/// Orchestrates the domain engine, optional eBPF map sync, and metrics updates.
/// Designed to be wrapped in `ArcSwap` for lock-free reads.
#[derive(Clone)]
pub struct IdsAppService {
    engine: IdsEngine,
    map_port: Option<SharedIdsMapPort>,
    metrics: Arc<dyn MetricsPort>,
    mode: DomainMode,
    enabled: bool,
    geoip: Option<Arc<dyn GeoIpPort>>,
    /// Index at which the prevention rules begin in the engine rule array.
    ///
    /// The kernel identifies a match by its index in a single rule array, so
    /// the detection rules (`ids.rules`) and the prevention rules
    /// (`ips.rules`) share one array: detection occupies
    /// `[0, prevention_offset)` and prevention the tail. Keeping prevention
    /// last means the two halves can be reloaded independently without
    /// renumbering the other.
    prevention_offset: usize,
}

impl IdsAppService {
    pub fn new(
        engine: IdsEngine,
        map_port: Option<Box<dyn IdsMapPort + Send>>,
        metrics: Arc<dyn MetricsPort>,
    ) -> Self {
        // Whatever the engine already holds is detection: prevention rules
        // only ever arrive through `set_prevention_rules`.
        let prevention_offset = engine.rule_count();
        Self {
            engine,
            map_port: map_port.map(|p| Arc::new(Mutex::new(p))),
            metrics,
            mode: DomainMode::default(),
            enabled: true,
            geoip: None,
            prevention_offset,
        }
    }

    /// Set the `GeoIP` port for country-aware threshold and sampling.
    pub fn set_geoip_port(&mut self, port: Arc<dyn GeoIpPort>) {
        self.geoip = Some(port);
    }

    /// Set the eBPF map port and perform an initial sync.
    pub fn set_map_port(&mut self, port: Box<dyn IdsMapPort + Send>) {
        self.map_port = Some(Arc::new(Mutex::new(port)));
        self.sync_ebpf_maps();
    }

    /// Clear the eBPF map port (program unloaded).
    pub fn clear_map_port(&mut self) {
        self.map_port = None;
    }

    pub fn mode(&self) -> DomainMode {
        self.mode
    }

    pub fn set_mode(&mut self, mode: DomainMode) {
        self.mode = mode;
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        tracing::info!(enabled, "IDS service toggled");
    }

    /// Add a detection rule, keeping it ahead of the prevention rules.
    pub fn add_rule(&mut self, rule: IdsRule) -> Result<(), DomainError> {
        let mut rules = self.engine.rules().to_vec();
        rules.insert(self.prevention_offset, rule);
        self.engine.reload(rules)?;
        self.prevention_offset += 1;
        self.sync_ebpf_maps();
        self.update_metrics();
        Ok(())
    }

    /// Remove a detection rule. Prevention rules are owned by the IPS
    /// configuration and are not reachable through the IDS rule API.
    pub fn remove_rule(&mut self, id: &RuleId) -> Result<(), DomainError> {
        if !self.list_rules().iter().any(|r| r.id == *id) {
            return Err(DomainError::RuleNotFound(id.0.clone()));
        }
        self.engine.remove_rule(id)?;
        self.prevention_offset -= 1;
        self.sync_ebpf_maps();
        self.update_metrics();
        Ok(())
    }

    /// Replace the detection rules, leaving the prevention rules in place.
    pub fn reload_rules(&mut self, rules: Vec<IdsRule>) -> Result<(), DomainError> {
        let count = rules.len();
        let prevention = self.prevention_rules().to_vec();
        let mut all = rules;
        all.extend(prevention);
        self.engine.reload(all)?;
        self.prevention_offset = count;
        self.sync_ebpf_maps();
        self.update_metrics();
        tracing::info!(count, "IDS rules reloaded");
        Ok(())
    }

    /// Replace the prevention rules, leaving the detection rules in place.
    ///
    /// Prevention rules are matched by the same kernel program as detection
    /// rules; what sets them apart is what a match does, which the pipeline
    /// decides from [`Self::is_prevention_index`].
    pub fn set_prevention_rules(&mut self, rules: Vec<IdsRule>) -> Result<(), DomainError> {
        let count = rules.len();
        let mut all = self.list_rules().to_vec();
        all.extend(rules);
        self.engine.reload(all)?;
        self.sync_ebpf_maps();
        self.update_metrics();
        tracing::info!(count, "IPS prevention rules synced to the IDS pattern maps");
        Ok(())
    }

    /// The detection rules, in kernel index order.
    pub fn list_rules(&self) -> &[IdsRule] {
        &self.engine.rules()[..self.prevention_offset]
    }

    /// The prevention rules, in kernel index order.
    pub fn prevention_rules(&self) -> &[IdsRule] {
        &self.engine.rules()[self.prevention_offset..]
    }

    /// Whether a matched rule index belongs to the prevention half.
    #[must_use]
    pub fn is_prevention_index(&self, index: usize) -> bool {
        index >= self.prevention_offset
    }

    /// Number of detection rules.
    pub fn rule_count(&self) -> usize {
        self.prevention_offset
    }

    /// Set the sampling mode for event processing.
    pub fn set_sampling(&mut self, mode: SamplingMode) {
        self.engine.set_sampling(mode);
    }

    /// Evaluate a packet event against loaded IDS rules.
    /// Delegates to the engine's index-based lookup.
    pub fn evaluate_event(&self, event: &PacketEvent) -> Option<(usize, &IdsRule)> {
        self.engine.evaluate_event(event)
    }

    /// Evaluate a packet event with domain and country context.
    /// Returns `(rule_index, rule, matched_domain)` on match.
    pub fn evaluate_event_with_context<'a>(
        &'a self,
        event: &PacketEvent,
        dst_domains: &[String],
        src_country: Option<&str>,
    ) -> Option<(usize, &'a IdsRule, Option<String>)> {
        self.engine
            .evaluate_event_with_context(event, dst_domains, src_country)
    }

    /// Evaluate the captured payload of a TCP segment against the content
    /// rules. Returns `(rule_index, rule)` on match.
    pub fn evaluate_payload_with_context<'a>(
        &'a self,
        event: &PacketEvent,
        payload: &[u8],
        src_country: Option<&str>,
    ) -> Option<(usize, &'a IdsRule)> {
        self.engine
            .evaluate_payload_with_context(event, payload, src_country)
    }

    /// Return `true` if any loaded rule carries a content pattern, so the
    /// L7 path can skip the payload scan when none do.
    #[must_use]
    pub fn has_content_rules(&self) -> bool {
        self.engine.has_content_rules()
    }

    /// Check whether an alert should be emitted after a rule match,
    /// based on the rule's threshold config. Returns `true` to emit.
    pub fn check_threshold(
        &self,
        rule_id: &RuleId,
        threshold: &ThresholdConfig,
        src_ip: u32,
        dst_ip: u32,
    ) -> bool {
        self.engine
            .check_threshold(rule_id, threshold, src_ip, dst_ip)
    }

    /// Country-aware threshold check. Uses per-country threshold overrides
    /// from the rule when available.
    pub fn check_threshold_with_country(
        &self,
        rule: &IdsRule,
        src_ip: u32,
        dst_ip: u32,
        src_country: Option<&str>,
    ) -> bool {
        self.engine
            .check_threshold_with_country(rule, src_ip, dst_ip, src_country)
    }

    /// Return `true` if any loaded rule uses a domain pattern, so the pipeline
    /// can skip the per-event reverse-DNS lookup when none do.
    #[must_use]
    pub fn has_domain_rules(&self) -> bool {
        self.engine.has_domain_rules()
    }

    /// Resolve the country code for an IP address via the `GeoIP` port.
    pub fn resolve_country(&self, src_addr: [u32; 4], is_ipv6: bool) -> Option<String> {
        let geoip = self.geoip.as_ref()?;
        let ip = crate::addr_to_ip(src_addr, is_ipv6);
        geoip.lookup(&ip).and_then(|info| info.country_code)
    }

    /// Record that the IDS verdict terminated a live flow via the
    /// kernel netfilter conntrack path (`bpf_ct_change_status` with
    /// the `IPS_DYING` bit). The actual kernel-side kill happens in
    /// the tc-ids eBPF program; this hook increments the paired
    /// Prometheus counter so operators can observe the enforcement
    /// rate of block-mode policies.
    pub fn record_flow_killed_via_ct(&self) {
        self.metrics.record_ids_ct_dying();
    }

    /// Remove expired threshold tracking entries.
    pub fn cleanup_expired_thresholds(&self) {
        self.engine.cleanup_expired_thresholds();
    }

    /// Full-reload sync: clear the eBPF map and re-insert all engine rules.
    ///
    /// In `Alert` mode, all actions are overridden to `IDS_ACTION_ALERT`
    /// (observation only — no traffic dropped).
    ///
    /// The kernel maps are keyed by `(protocol, port)`, so two rules that
    /// watch the same port cannot both be installed: the later one wins.
    /// Rules are written in array order, which puts the prevention rules last
    /// and lets an IPS rule take over a port an IDS rule also watches. The
    /// losing rule is named in a warning rather than dropped silently.
    fn sync_ebpf_maps(&self) {
        let Some(ref map_port) = self.map_port else {
            return;
        };

        let Ok(mut map) = map_port.lock() else {
            tracing::warn!("IDS map port lock poisoned, skipping eBPF sync");
            return;
        };

        if let Err(e) = map.clear_patterns() {
            tracing::warn!("failed to clear IDS eBPF patterns map: {e}");
            return;
        }
        if let Err(e) = map.clear_src_patterns() {
            tracing::warn!("failed to clear IDS eBPF source-port patterns map: {e}");
            return;
        }

        // Key -> id of the rule currently occupying it, so a collision can
        // name both sides.
        let mut owners: HashMap<KernelSlot, String> = HashMap::new();

        for (idx, rule) in self.engine.rules().iter().enumerate() {
            if !rule.enabled {
                continue;
            }
            #[allow(clippy::cast_possible_truncation)] // rule count bounded well below u32::MAX
            let mut value = rule.to_ebpf_value(idx as u32);
            if self.mode == DomainMode::Alert {
                value.action = IDS_ACTION_ALERT;
            }
            // A rule may match on dst_port, src_port, or both, and a rule
            // that covers every protocol installs one key per protocol the
            // classifier can observe.
            for key in rule.to_ebpf_keys() {
                Self::note_key_owner(&mut owners, key, false, &rule.id.0);
                if let Err(e) = map.insert_pattern(&key, &value) {
                    tracing::warn!(rule_id = %rule.id, "failed to sync IDS rule to eBPF map: {e}");
                }
            }
            for src_key in rule.to_ebpf_src_keys() {
                Self::note_key_owner(&mut owners, src_key, true, &rule.id.0);
                if let Err(e) = map.insert_src_pattern(&src_key, &value) {
                    tracing::warn!(rule_id = %rule.id, "failed to sync IDS src rule to eBPF map: {e}");
                }
            }
        }
    }

    /// Record which rule owns a kernel key, warning when it displaces another.
    fn note_key_owner(
        owners: &mut HashMap<KernelSlot, String>,
        key: IdsPatternKey,
        source_port_map: bool,
        rule_id: &str,
    ) {
        // The two maps share a key type, so which map it is belongs to the
        // identity of the slot.
        let slot = (key.tenant_id, key.dst_port, key.protocol, source_port_map);
        if let Some(previous) = owners.insert(slot, rule_id.to_string())
            && previous != rule_id
        {
            tracing::warn!(
                shadowed_rule = %previous,
                rule_id,
                port = key.dst_port,
                protocol = key.protocol,
                "two rules watch the same port: only the later one is installed in the kernel map"
            );
        }
    }

    fn update_metrics(&self) {
        self.metrics
            .set_rules_loaded("ids", self.prevention_offset as u64);
    }
}

/// Install the prevention rules into the service that owns the kernel pattern
/// maps.
///
/// The IPS keeps the operator-facing copy of its rules, but only one service
/// may write the maps, so the rules are mirrored here whenever they change.
pub fn install_prevention_rules(
    ids: &arc_swap::ArcSwap<IdsAppService>,
    rules: Vec<IdsRule>,
) -> Result<(), DomainError> {
    let mut svc = (**ids.load()).clone();
    svc.set_prevention_rules(rules)?;
    ids.store(Arc::new(svc));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::common::entity::{Protocol, Severity};
    use ports::test_utils::NoopMetrics;

    fn make_rule(id: &str) -> IdsRule {
        IdsRule {
            id: RuleId(id.to_string()),
            description: format!("Test {id}"),
            severity: Severity::Medium,
            mode: DomainMode::Alert,
            protocol: Protocol::Tcp,
            dst_port: Some(22),
            src_port: None,
            pattern: String::new(),
            enabled: true,
            threshold: None,
            domain_pattern: None,
            domain_match_mode: None,
            country_thresholds: None,
            group_mask: 0,
        }
    }

    fn make_service() -> IdsAppService {
        IdsAppService::new(IdsEngine::new(), None, Arc::new(NoopMetrics))
    }

    #[test]
    fn add_and_list_rules() {
        let mut svc = make_service();
        svc.add_rule(make_rule("ids-001")).unwrap();
        svc.add_rule(make_rule("ids-002")).unwrap();
        assert_eq!(svc.list_rules().len(), 2);
        assert_eq!(svc.rule_count(), 2);
    }

    #[test]
    fn add_duplicate_fails() {
        let mut svc = make_service();
        svc.add_rule(make_rule("ids-001")).unwrap();
        assert!(svc.add_rule(make_rule("ids-001")).is_err());
        assert_eq!(svc.rule_count(), 1);
    }

    #[test]
    fn remove_rule_succeeds() {
        let mut svc = make_service();
        svc.add_rule(make_rule("ids-001")).unwrap();
        svc.remove_rule(&RuleId("ids-001".to_string())).unwrap();
        assert_eq!(svc.rule_count(), 0);
    }

    #[test]
    fn remove_nonexistent_fails() {
        let mut svc = make_service();
        assert!(svc.remove_rule(&RuleId("nope".to_string())).is_err());
    }

    #[test]
    fn reload_replaces_all() {
        let mut svc = make_service();
        svc.add_rule(make_rule("old")).unwrap();
        svc.reload_rules(vec![make_rule("new-1"), make_rule("new-2")])
            .unwrap();
        assert_eq!(svc.rule_count(), 2);
        assert_eq!(svc.list_rules()[0].id.0, "new-1");
    }

    #[test]
    fn prevention_rules_sit_after_the_detection_rules() {
        let mut svc = make_service();
        svc.reload_rules(vec![make_rule("ids-001"), make_rule("ids-002")])
            .unwrap();

        svc.set_prevention_rules(vec![make_rule("ips-001")])
            .unwrap();

        assert_eq!(svc.list_rules().len(), 2);
        assert_eq!(svc.rule_count(), 2);
        assert_eq!(svc.prevention_rules().len(), 1);
        assert_eq!(svc.prevention_rules()[0].id.0, "ips-001");
        assert!(!svc.is_prevention_index(1));
        assert!(svc.is_prevention_index(2));
    }

    #[test]
    fn reloading_detection_rules_keeps_the_prevention_rules() {
        let mut svc = make_service();
        svc.reload_rules(vec![make_rule("ids-001")]).unwrap();
        svc.set_prevention_rules(vec![make_rule("ips-001")])
            .unwrap();

        svc.reload_rules(vec![make_rule("ids-002"), make_rule("ids-003")])
            .unwrap();

        assert_eq!(svc.list_rules().len(), 2);
        assert_eq!(svc.prevention_rules()[0].id.0, "ips-001");
        assert!(svc.is_prevention_index(2));
    }

    #[test]
    fn adding_a_detection_rule_keeps_the_prevention_rules_last() {
        let mut svc = make_service();
        svc.reload_rules(vec![make_rule("ids-001")]).unwrap();
        svc.set_prevention_rules(vec![make_rule("ips-001")])
            .unwrap();

        svc.add_rule(make_rule("ids-002")).unwrap();

        assert_eq!(svc.list_rules().len(), 2);
        assert_eq!(svc.prevention_rules()[0].id.0, "ips-001");
        assert!(svc.is_prevention_index(2));
    }

    #[test]
    fn a_prevention_rule_may_not_reuse_a_detection_rule_id() {
        let mut svc = make_service();
        svc.reload_rules(vec![make_rule("shared")]).unwrap();

        assert!(svc.set_prevention_rules(vec![make_rule("shared")]).is_err());
        // The rejected reload leaves the detection half untouched.
        assert_eq!(svc.list_rules().len(), 1);
    }

    #[test]
    fn the_ids_rule_api_does_not_reach_prevention_rules() {
        let mut svc = make_service();
        svc.set_prevention_rules(vec![make_rule("ips-001")])
            .unwrap();

        assert!(svc.remove_rule(&RuleId("ips-001".to_string())).is_err());
        assert_eq!(svc.prevention_rules().len(), 1);
    }

    #[test]
    fn works_without_ebpf_map() {
        let mut svc = make_service();
        svc.add_rule(make_rule("ids-001")).unwrap();
        svc.remove_rule(&RuleId("ids-001".to_string())).unwrap();
    }

    #[test]
    fn mode_and_enabled_getters() {
        let mut svc = make_service();
        assert_eq!(svc.mode(), DomainMode::Alert);
        assert!(svc.enabled());
        svc.set_mode(DomainMode::Block);
        svc.set_enabled(false);
        assert_eq!(svc.mode(), DomainMode::Block);
        assert!(!svc.enabled());
    }

    #[test]
    fn record_flow_killed_via_ct_increments_counter() {
        use ports::secondary::metrics_port::{
            AlertMetrics, AuditMetrics, ConfigMetrics, ConntrackMetrics, ContainerMetrics,
            CtMetrics, DdosMetrics, DlpMetrics, DnsMetrics, DomainMetrics, EventMetrics,
            FingerprintMetrics, FirewallMetrics, IpsMetrics, LbMetrics, PacketMetrics,
            RoutingMetrics, SystemMetrics, ThreatIntelMetrics, ZoneMetrics,
        };
        use std::sync::atomic::{AtomicU64, Ordering};

        struct CountingMetrics {
            ct_dying: AtomicU64,
        }

        impl PacketMetrics for CountingMetrics {}
        impl FirewallMetrics for CountingMetrics {}
        impl AlertMetrics for CountingMetrics {}
        impl IpsMetrics for CountingMetrics {}
        impl DnsMetrics for CountingMetrics {}
        impl DomainMetrics for CountingMetrics {}
        impl SystemMetrics for CountingMetrics {}
        impl ConfigMetrics for CountingMetrics {}
        impl EventMetrics for CountingMetrics {}
        impl DlpMetrics for CountingMetrics {}
        impl DdosMetrics for CountingMetrics {}
        impl ConntrackMetrics for CountingMetrics {}
        impl RoutingMetrics for CountingMetrics {}
        impl AuditMetrics for CountingMetrics {}
        impl LbMetrics for CountingMetrics {}
        impl FingerprintMetrics for CountingMetrics {}
        impl ContainerMetrics for CountingMetrics {}
        impl ThreatIntelMetrics for CountingMetrics {}
        impl ZoneMetrics for CountingMetrics {}
        impl CtMetrics for CountingMetrics {
            fn record_ids_ct_dying(&self) {
                self.ct_dying.fetch_add(1, Ordering::SeqCst);
            }
        }

        let metrics = Arc::new(CountingMetrics {
            ct_dying: AtomicU64::new(0),
        });
        let svc = IdsAppService::new(
            IdsEngine::new(),
            None,
            metrics.clone() as Arc<dyn MetricsPort>,
        );
        svc.record_flow_killed_via_ct();
        svc.record_flow_killed_via_ct();
        assert_eq!(metrics.ct_dying.load(Ordering::SeqCst), 2);
    }
}
