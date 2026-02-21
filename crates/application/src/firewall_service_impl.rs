use std::sync::Arc;

use domain::common::entity::{DomainMode, RuleId};
use domain::common::error::DomainError;
use domain::firewall::engine::FirewallEngine;
use domain::firewall::entity::{FirewallAction, FirewallRule};
use ports::secondary::ebpf_map_port::FirewallArrayMapPort;
use ports::secondary::metrics_port::MetricsPort;

/// Application-level firewall service.
///
/// Orchestrates the domain engine, optional eBPF map sync, and metrics updates.
/// Designed to be wrapped in `RwLock` for shared access from HTTP handlers.
pub struct FirewallAppService {
    engine: FirewallEngine,
    map_port: Option<Box<dyn FirewallArrayMapPort + Send>>,
    metrics: Arc<dyn MetricsPort>,
    mode: DomainMode,
    enabled: bool,
}

impl FirewallAppService {
    pub fn new(
        engine: FirewallEngine,
        map_port: Option<Box<dyn FirewallArrayMapPort + Send>>,
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

    /// Return the current operating mode.
    pub fn mode(&self) -> DomainMode {
        self.mode
    }

    /// Set the operating mode. Call `reload_rules` after changing the mode
    /// to re-apply rules with the new mode semantics.
    pub fn set_mode(&mut self, mode: DomainMode) {
        self.mode = mode;
    }

    /// Return whether the firewall is enabled.
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Set the enabled state.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Set the eBPF map port for kernel map synchronisation.
    ///
    /// Called after eBPF programs are loaded to wire the map manager
    /// into the service so that dynamic rule changes are synced.
    pub fn set_map_port(&mut self, port: Box<dyn FirewallArrayMapPort + Send>) {
        self.map_port = Some(port);
    }

    /// Add a firewall rule. Syncs to eBPF maps and updates metrics.
    pub fn add_rule(&mut self, rule: FirewallRule) -> Result<(), DomainError> {
        self.engine.add_rule(rule)?;
        self.sync_ebpf_maps();
        self.update_metrics();
        Ok(())
    }

    /// Remove a firewall rule by ID. Syncs to eBPF maps and updates metrics.
    pub fn remove_rule(&mut self, id: &RuleId) -> Result<(), DomainError> {
        self.engine.remove_rule(id)?;
        self.sync_ebpf_maps();
        self.update_metrics();
        Ok(())
    }

    /// Reload all rules atomically. Syncs to eBPF maps and updates metrics.
    pub fn reload_rules(&mut self, rules: Vec<FirewallRule>) -> Result<(), DomainError> {
        self.engine.reload(rules)?;
        self.sync_ebpf_maps();
        self.update_metrics();
        Ok(())
    }

    /// Return a slice of all loaded rules (sorted by priority).
    pub fn list_rules(&self) -> &[FirewallRule] {
        self.engine.rules()
    }

    /// Return the number of active rules.
    pub fn rule_count(&self) -> usize {
        self.engine.rules().len()
    }

    /// Full-reload sync: partition rules into V4/V6, apply mode overrides,
    /// and bulk-load into eBPF array maps.
    ///
    /// In `Alert` mode, deny actions are overridden to log (observation only).
    fn sync_ebpf_maps(&mut self) {
        let Some(ref mut map) = self.map_port else {
            return;
        };

        let rules = self.engine.rules();

        // Partition into V4 and V6, applying alert-mode override
        let mut v4_entries = Vec::new();
        let mut v6_entries = Vec::new();

        for rule in rules {
            // In alert mode: override deny -> log (observe without blocking)
            let effective_rule =
                if self.mode == DomainMode::Alert && rule.action == FirewallAction::Deny {
                    let mut alert_rule = rule.clone();
                    alert_rule.action = FirewallAction::Log;
                    alert_rule
                } else {
                    rule.clone()
                };

            if effective_rule.is_v6() {
                v6_entries.push(effective_rule.to_ebpf_entry_v6());
            } else {
                v4_entries.push(effective_rule.to_ebpf_entry());
            }
        }

        // Bulk-load V4
        if let Err(e) = map.load_v4_rules(&v4_entries) {
            tracing::warn!("failed to load V4 rules into eBPF map: {e}");
        }

        // Bulk-load V6
        if let Err(e) = map.load_v6_rules(&v6_entries) {
            tracing::warn!("failed to load V6 rules into eBPF map: {e}");
        }
    }

    fn update_metrics(&self) {
        self.metrics
            .set_rules_loaded("firewall", self.engine.rules().len() as u64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::common::entity::Protocol;
    use domain::firewall::entity::{FirewallAction, Scope};
    use ports::test_utils::NoopMetrics;

    fn make_rule(id: &str, priority: u32) -> FirewallRule {
        FirewallRule {
            id: RuleId(id.to_string()),
            priority,
            action: FirewallAction::Deny,
            protocol: Protocol::Any,
            src_ip: None,
            dst_ip: None,
            src_port: None,
            dst_port: None,
            scope: Scope::Global,
            enabled: true,
            vlan_id: None,
        }
    }

    fn make_service() -> FirewallAppService {
        FirewallAppService::new(FirewallEngine::new(), None, Arc::new(NoopMetrics))
    }

    #[test]
    fn add_and_list_rules() {
        let mut svc = make_service();
        svc.add_rule(make_rule("fw-001", 10)).unwrap();
        svc.add_rule(make_rule("fw-002", 20)).unwrap();

        assert_eq!(svc.list_rules().len(), 2);
        assert_eq!(svc.rule_count(), 2);
    }

    #[test]
    fn add_duplicate_fails() {
        let mut svc = make_service();
        svc.add_rule(make_rule("fw-001", 10)).unwrap();
        assert!(svc.add_rule(make_rule("fw-001", 20)).is_err());
        assert_eq!(svc.rule_count(), 1);
    }

    #[test]
    fn remove_rule_succeeds() {
        let mut svc = make_service();
        svc.add_rule(make_rule("fw-001", 10)).unwrap();
        svc.remove_rule(&RuleId("fw-001".to_string())).unwrap();
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
        svc.add_rule(make_rule("old", 10)).unwrap();
        svc.reload_rules(vec![make_rule("new-1", 1), make_rule("new-2", 2)])
            .unwrap();
        assert_eq!(svc.rule_count(), 2);
        assert_eq!(svc.list_rules()[0].id.0, "new-1");
    }

    #[test]
    fn works_without_ebpf_map() {
        let mut svc = make_service(); // map_port = None
        svc.add_rule(make_rule("fw-001", 10)).unwrap();
        svc.remove_rule(&RuleId("fw-001".to_string())).unwrap();
        // No panic — graceful degraded mode
    }
}
