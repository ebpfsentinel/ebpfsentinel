use std::sync::Arc;

use domain::common::entity::{DomainMode, RuleId};
use domain::common::error::DomainError;
use domain::ids::engine::IdsEngine;
use domain::ids::entity::{IdsRule, SamplingMode, ThresholdConfig};
use ebpf_common::event::PacketEvent;
use ebpf_common::ids::IDS_ACTION_ALERT;
use ports::secondary::ids_map_port::IdsMapPort;
use ports::secondary::metrics_port::MetricsPort;

/// Application-level IDS service.
///
/// Orchestrates the domain engine, optional eBPF map sync, and metrics updates.
/// Designed to be wrapped in `RwLock` for shared access from HTTP handlers.
pub struct IdsAppService {
    engine: IdsEngine,
    map_port: Option<Box<dyn IdsMapPort + Send>>,
    metrics: Arc<dyn MetricsPort>,
    mode: DomainMode,
    enabled: bool,
}

impl IdsAppService {
    pub fn new(
        engine: IdsEngine,
        map_port: Option<Box<dyn IdsMapPort + Send>>,
        metrics: Arc<dyn MetricsPort>,
    ) -> Self {
        Self {
            engine,
            map_port,
            metrics,
            mode: DomainMode::default(),
            enabled: true,
        }
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
    }

    pub fn add_rule(&mut self, rule: IdsRule) -> Result<(), DomainError> {
        self.engine.add_rule(rule)?;
        self.sync_ebpf_maps();
        self.update_metrics();
        Ok(())
    }

    pub fn remove_rule(&mut self, id: &RuleId) -> Result<(), DomainError> {
        self.engine.remove_rule(id)?;
        self.sync_ebpf_maps();
        self.update_metrics();
        Ok(())
    }

    pub fn reload_rules(&mut self, rules: Vec<IdsRule>) -> Result<(), DomainError> {
        self.engine.reload(rules)?;
        self.sync_ebpf_maps();
        self.update_metrics();
        Ok(())
    }

    pub fn list_rules(&self) -> &[IdsRule] {
        self.engine.rules()
    }

    pub fn rule_count(&self) -> usize {
        self.engine.rule_count()
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

    /// Evaluate a packet event with domain context for domain-aware rules.
    /// Returns `(rule_index, rule, matched_domain)` on match.
    pub fn evaluate_event_with_context<'a>(
        &'a self,
        event: &PacketEvent,
        dst_domains: &[String],
    ) -> Option<(usize, &'a IdsRule, Option<String>)> {
        self.engine.evaluate_event_with_context(event, dst_domains)
    }

    /// Check whether an alert should be emitted after a rule match,
    /// based on the rule's threshold config. Returns `true` to emit.
    pub fn check_threshold(
        &mut self,
        rule_id: &RuleId,
        threshold: &ThresholdConfig,
        src_ip: u32,
        dst_ip: u32,
    ) -> bool {
        self.engine
            .check_threshold(rule_id, threshold, src_ip, dst_ip)
    }

    /// Remove expired threshold tracking entries.
    pub fn cleanup_expired_thresholds(&mut self) {
        self.engine.cleanup_expired_thresholds();
    }

    /// Full-reload sync: clear the eBPF map and re-insert all engine rules.
    ///
    /// In `Alert` mode, all actions are overridden to `IDS_ACTION_ALERT`
    /// (observation only — no traffic dropped).
    fn sync_ebpf_maps(&mut self) {
        let Some(ref mut map) = self.map_port else {
            return;
        };

        if let Err(e) = map.clear_patterns() {
            tracing::warn!("failed to clear IDS eBPF patterns map: {e}");
            return;
        }

        for (idx, rule) in self.engine.rules().iter().enumerate() {
            if !rule.enabled {
                continue;
            }
            let Some(key) = rule.to_ebpf_key() else {
                continue; // Wildcard rules not representable in eBPF HashMap
            };
            #[allow(clippy::cast_possible_truncation)] // rule count bounded well below u32::MAX
            let mut value = rule.to_ebpf_value(idx as u32);
            if self.mode == DomainMode::Alert {
                value.action = IDS_ACTION_ALERT;
            }
            if let Err(e) = map.insert_pattern(&key, &value) {
                tracing::warn!(rule_id = %rule.id, "failed to sync IDS rule to eBPF map: {e}");
            }
        }
    }

    fn update_metrics(&self) {
        self.metrics
            .set_rules_loaded("ids", self.engine.rule_count() as u64);
    }
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
            pattern: String::new(),
            enabled: true,
            threshold: None,
            domain_pattern: None,
            domain_match_mode: None,
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
}
