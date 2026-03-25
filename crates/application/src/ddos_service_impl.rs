use std::sync::Arc;

use domain::common::entity::RuleId;
use domain::common::error::DomainError;
use domain::ddos::engine::DdosEngine;
use domain::ddos::entity::{DdosAttack, DdosEnforcementAction, DdosEvent, DdosPolicy};
use ebpf_common::firewall::ACTION_DROP;
use ports::secondary::alias_resolution_port::AliasResolutionPort;
use ports::secondary::geoip_port::GeoIpPort;
use ports::secondary::lpm_coordinator_port::LpmCoordinatorPort;
use ports::secondary::metrics_port::MetricsPort;

/// Application-level `DDoS` detection and mitigation service.
///
/// Orchestrates the `DDoS` domain engine, metrics updates, and periodic ticks.
/// Designed to be wrapped in `ArcSwap` for lock-free reads.
#[derive(Clone)]
pub struct DdosAppService {
    engine: DdosEngine,
    metrics: Arc<dyn MetricsPort>,
    enabled: bool,
    geoip: Option<Arc<dyn GeoIpPort>>,
    lpm_coordinator: Option<Arc<dyn LpmCoordinatorPort>>,
    alias_resolution: Option<Arc<dyn AliasResolutionPort>>,
}

impl DdosAppService {
    pub fn new(engine: DdosEngine, metrics: Arc<dyn MetricsPort>) -> Self {
        Self {
            engine,
            metrics,
            enabled: true,
            geoip: None,
            lpm_coordinator: None,
            alias_resolution: None,
        }
    }

    /// Set the `GeoIP` port for country-aware thresholds.
    pub fn set_geoip_port(&mut self, port: Arc<dyn GeoIpPort>) {
        self.geoip = Some(port);
    }

    /// Set the LPM coordinator for kernel-side country CIDR enforcement.
    pub fn set_lpm_coordinator(&mut self, coordinator: Arc<dyn LpmCoordinatorPort>) {
        self.lpm_coordinator = Some(coordinator);
    }

    /// Set the alias resolution port for `GeoIP` CIDR lookups.
    pub fn set_alias_resolution(&mut self, port: Arc<dyn AliasResolutionPort>) {
        self.alias_resolution = Some(port);
    }

    /// Process a `DDoS` event from the eBPF pipeline.
    /// Returns `true` if an attack state changed (for alerting).
    pub fn process_event(&self, event: &DdosEvent) -> bool {
        if !self.enabled {
            return false;
        }
        let src_country = self.resolve_country(event.src_addr, event.is_ipv6);
        let prev_count = self.engine.active_attack_count();
        let changed = self
            .engine
            .process_event_with_country(event, src_country.as_deref());
        if changed {
            let new_count = self.engine.active_attack_count();
            if new_count > prev_count {
                let attack_type = format!("{:?}", event.attack_type);
                self.metrics.record_ddos_attack_detected(&attack_type);
                tracing::info!(attack_type = %attack_type, active = new_count, "DDoS attack detected");
            }
            self.metrics
                .set_ddos_attacks_active(self.engine.active_attack_count() as u64);
            self.update_metrics();
        }
        self.apply_pending_enforcements();
        changed
    }

    /// Periodic tick — call once per second to update attack statuses.
    pub fn tick(&self) {
        if !self.enabled {
            return;
        }
        self.engine.tick();
        self.update_metrics();
        self.apply_pending_enforcements();
    }

    /// Return a snapshot of all active (non-expired) attacks.
    pub fn active_attacks(&self) -> Vec<DdosAttack> {
        self.engine.active_attacks()
    }

    /// Return the number of active attacks.
    pub fn active_attack_count(&self) -> usize {
        self.engine.active_attack_count()
    }

    /// Return total number of attacks that reached Mitigated or Expired.
    pub fn total_mitigated(&self) -> u64 {
        self.engine.total_mitigated()
    }

    /// Return recent attack history (most recent first).
    pub fn attack_history(&self, limit: usize) -> Vec<DdosAttack> {
        self.engine.attack_history(limit)
    }

    // ── Policy Management ─────────────────────────────────────────

    /// Reload all policies atomically.
    pub fn reload_policies(&mut self, policies: Vec<DdosPolicy>) -> Result<(), DomainError> {
        let count = policies.len();
        self.engine.reload(policies)?;
        self.update_metrics();
        tracing::info!(count, "DDoS policies reloaded");
        Ok(())
    }

    /// Add a `DDoS` policy.
    pub fn add_policy(&mut self, policy: DdosPolicy) -> Result<(), DomainError> {
        self.engine.add_policy(policy)?;
        self.update_metrics();
        Ok(())
    }

    /// Remove a policy by ID.
    pub fn remove_policy(&mut self, id: &RuleId) -> Result<(), DomainError> {
        self.engine.remove_policy(id)?;
        self.update_metrics();
        Ok(())
    }

    /// Return a slice of all loaded policies.
    pub fn policies(&self) -> &[DdosPolicy] {
        self.engine.policies()
    }

    /// Return the number of loaded policies.
    pub fn policy_count(&self) -> usize {
        self.engine.policy_count()
    }

    /// Return whether the `DDoS` service is enabled.
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Set the enabled state.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        tracing::info!(enabled, "DDoS service toggled");
    }

    /// Drain and apply pending enforcement actions from the engine.
    fn apply_pending_enforcements(&self) {
        let enforcements = self.engine.take_pending_enforcements();
        if enforcements.is_empty() {
            return;
        }

        let (Some(coordinator), Some(resolver)) = (&self.lpm_coordinator, &self.alias_resolution)
        else {
            return;
        };

        for action in enforcements {
            match action {
                DdosEnforcementAction::BlockCountry { ref country_code } => {
                    let codes = vec![country_code.clone()];
                    match resolver.lookup_geoip(&codes) {
                        Ok(ips) => {
                            let (v4, v6) = crate::convert_to_lpm_entries(&ips, ACTION_DROP);
                            let source = format!("ddos:{country_code}");
                            if let Err(e) = coordinator.insert_entries(&source, &v4, &v6) {
                                tracing::warn!(
                                    country = country_code,
                                    "DDoS auto-block: failed to inject CIDRs: {e}"
                                );
                            } else {
                                self.metrics.record_ddos_mitigation("block_country");
                                tracing::info!(
                                    country = country_code,
                                    v4 = v4.len(),
                                    v6 = v6.len(),
                                    "DDoS auto-block: injected CIDRs for country"
                                );
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                country = country_code,
                                "DDoS auto-block: GeoIP lookup failed: {e}"
                            );
                        }
                    }
                }
                DdosEnforcementAction::UnblockCountry { ref country_code } => {
                    let source = format!("ddos:{country_code}");
                    if let Err(e) = coordinator.remove_all_for_source(&source) {
                        tracing::warn!(
                            country = country_code,
                            "DDoS auto-unblock: failed to remove CIDRs: {e}"
                        );
                    } else {
                        self.metrics.record_ddos_mitigation("unblock_country");
                        tracing::info!(
                            country = country_code,
                            "DDoS auto-unblock: removed CIDRs for country"
                        );
                    }
                }
            }
        }
    }

    fn update_metrics(&self) {
        self.metrics
            .set_rules_loaded("ddos", self.engine.policy_count() as u64);
        self.metrics
            .set_ddos_attacks_active(self.engine.active_attack_count() as u64);
    }

    fn resolve_country(&self, addr: [u32; 4], is_ipv6: bool) -> Option<String> {
        let geoip = self.geoip.as_ref()?;
        let ip = crate::addr_to_ip(addr, is_ipv6);
        geoip.lookup(&ip).and_then(|info| info.country_code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::ddos::entity::{DdosAttackType, DdosMitigationAction};
    use ports::test_utils::NoopMetrics;

    fn make_service() -> DdosAppService {
        DdosAppService::new(DdosEngine::new(), Arc::new(NoopMetrics))
    }

    fn make_policy(id: &str, attack_type: DdosAttackType, threshold: u64) -> DdosPolicy {
        DdosPolicy {
            id: RuleId(id.to_string()),
            attack_type,
            detection_threshold_pps: threshold,
            mitigation_action: DdosMitigationAction::Block,
            auto_block_duration_secs: 300,
            enabled: true,
            country_thresholds: None,
        }
    }

    fn make_event(attack_type: DdosAttackType, ts: u64) -> DdosEvent {
        DdosEvent {
            timestamp_ns: ts,
            attack_type,
            src_addr: [0xC0A8_0001, 0, 0, 0],
            dst_addr: [0x0A00_0001, 0, 0, 0],
            src_port: 12345,
            dst_port: 80,
            protocol: 6,
            is_ipv6: false,
        }
    }

    #[test]
    fn add_policy_succeeds() {
        let mut svc = make_service();
        assert!(
            svc.add_policy(make_policy("ddos-1", DdosAttackType::SynFlood, 5000))
                .is_ok()
        );
        assert_eq!(svc.policy_count(), 1);
    }

    #[test]
    fn remove_policy_succeeds() {
        let mut svc = make_service();
        svc.add_policy(make_policy("ddos-1", DdosAttackType::SynFlood, 5000))
            .unwrap();
        assert!(svc.remove_policy(&RuleId("ddos-1".to_string())).is_ok());
        assert_eq!(svc.policy_count(), 0);
    }

    #[test]
    fn reload_updates_policies() {
        let mut svc = make_service();
        svc.add_policy(make_policy("ddos-1", DdosAttackType::SynFlood, 5000))
            .unwrap();
        assert_eq!(svc.policy_count(), 1);

        svc.reload_policies(vec![]).unwrap();
        assert_eq!(svc.policy_count(), 0);
    }

    #[test]
    fn enabled_toggle() {
        let mut svc = make_service();
        assert!(svc.enabled());

        svc.set_enabled(false);
        assert!(!svc.enabled());

        svc.set_enabled(true);
        assert!(svc.enabled());
    }

    #[test]
    fn process_event_when_disabled() {
        let mut svc = make_service();
        svc.add_policy(make_policy("ddos-1", DdosAttackType::SynFlood, 5000))
            .unwrap();
        svc.set_enabled(false);

        let event = make_event(DdosAttackType::SynFlood, 1_000_000_000);
        assert!(!svc.process_event(&event));
        assert_eq!(svc.active_attack_count(), 0);
    }

    #[test]
    fn process_event_creates_attack() {
        let mut svc = make_service();
        svc.add_policy(make_policy("ddos-1", DdosAttackType::SynFlood, 5000))
            .unwrap();

        let event = make_event(DdosAttackType::SynFlood, 1_000_000_000);
        assert!(svc.process_event(&event));
        assert_eq!(svc.active_attack_count(), 1);
    }

    #[test]
    fn add_duplicate_fails() {
        let mut svc = make_service();
        svc.add_policy(make_policy("ddos-1", DdosAttackType::SynFlood, 5000))
            .unwrap();
        assert!(
            svc.add_policy(make_policy("ddos-1", DdosAttackType::IcmpFlood, 100))
                .is_err()
        );
    }

    #[test]
    fn policies_returns_correct_slice() {
        let mut svc = make_service();
        svc.add_policy(make_policy("zzz", DdosAttackType::SynFlood, 5000))
            .unwrap();
        svc.add_policy(make_policy("aaa", DdosAttackType::IcmpFlood, 100))
            .unwrap();

        let policies = svc.policies();
        assert_eq!(policies.len(), 2);
        // Sorted by ID
        assert_eq!(policies[0].id.0, "aaa");
        assert_eq!(policies[1].id.0, "zzz");
    }

    #[test]
    fn attack_history_empty_initially() {
        let svc = make_service();
        assert!(svc.attack_history(10).is_empty());
    }

    #[test]
    fn total_mitigated_zero_initially() {
        let svc = make_service();
        assert_eq!(svc.total_mitigated(), 0);
    }
}
