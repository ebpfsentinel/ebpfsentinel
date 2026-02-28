use std::sync::Arc;

use domain::common::entity::RuleId;
use domain::common::error::DomainError;
use domain::ddos::engine::DdosEngine;
use domain::ddos::entity::{DdosAttack, DdosEvent, DdosPolicy};
use ports::secondary::metrics_port::MetricsPort;

/// Application-level `DDoS` detection and mitigation service.
///
/// Orchestrates the `DDoS` domain engine, metrics updates, and periodic ticks.
/// Designed to be wrapped in `RwLock` for shared access.
pub struct DdosAppService {
    engine: DdosEngine,
    metrics: Arc<dyn MetricsPort>,
    enabled: bool,
}

impl DdosAppService {
    pub fn new(engine: DdosEngine, metrics: Arc<dyn MetricsPort>) -> Self {
        Self {
            engine,
            metrics,
            enabled: true,
        }
    }

    /// Process a `DDoS` event from the eBPF pipeline.
    /// Returns `true` if an attack state changed (for alerting).
    pub fn process_event(&mut self, event: &DdosEvent) -> bool {
        if !self.enabled {
            return false;
        }
        let changed = self.engine.process_event(event);
        if changed {
            self.update_metrics();
        }
        changed
    }

    /// Periodic tick — call once per second to update attack statuses.
    pub fn tick(&mut self) {
        if !self.enabled {
            return;
        }
        self.engine.tick();
        self.update_metrics();
    }

    /// Return all active (non-expired) attacks.
    pub fn active_attacks(&self) -> &[DdosAttack] {
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
    pub fn attack_history(&self, limit: usize) -> &[DdosAttack] {
        self.engine.attack_history(limit)
    }

    // ── Policy Management ─────────────────────────────────────────

    /// Reload all policies atomically.
    pub fn reload_policies(&mut self, policies: Vec<DdosPolicy>) -> Result<(), DomainError> {
        self.engine.reload(policies)?;
        self.update_metrics();
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
    }

    fn update_metrics(&self) {
        self.metrics
            .set_rules_loaded("ddos", self.engine.policy_count() as u64);
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
        }
    }

    fn make_event(attack_type: DdosAttackType, ts: u64) -> DdosEvent {
        DdosEvent {
            timestamp_ns: ts,
            attack_type,
            src_addr: [0xC0A80001, 0, 0, 0],
            dst_addr: [0x0A000001, 0, 0, 0],
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
