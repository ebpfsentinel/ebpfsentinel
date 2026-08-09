use std::sync::Arc;

use domain::common::entity::Protocol;
use domain::common::entity::{DomainMode, RuleId};
use domain::common::error::DomainError;
use domain::firewall::engine::FirewallEngine;
use domain::firewall::entity::{FirewallAction, FirewallRule, PortRange, Scope};
use domain::firewall::error::FirewallError;

use crate::firewall_aliases::AliasBindings;
use ports::secondary::conntrack_kill_port::ConnTrackKillPort;
use ports::secondary::ebpf_map_port::FirewallArrayMapPort;
use ports::secondary::metrics_port::MetricsPort;

/// Anti-lockout configuration (mirrors infrastructure config).
#[derive(Debug, Clone)]
pub struct AntiLockoutSettings {
    pub enabled: bool,
    pub interfaces: Vec<String>,
    pub ports: Vec<u16>,
}

impl Default for AntiLockoutSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            interfaces: Vec::new(),
            ports: vec![22, 8080, 50051],
        }
    }
}

/// Application-level firewall service.
///
/// Orchestrates the domain engine, optional eBPF map sync, and metrics updates.
/// Designed to be wrapped in `RwLock` for shared access from HTTP handlers.
pub struct FirewallAppService {
    engine: FirewallEngine,
    map_port: Option<Box<dyn FirewallArrayMapPort + Send>>,
    /// Optional kernel-conntrack kill port. When a deny/reject rule is added
    /// while enforcing, matching ESTABLISHED flows are torn down here — the
    /// XDP drop alone cannot evict an existing conntrack entry.
    kill_port: Option<Box<dyn ConnTrackKillPort + Send>>,
    metrics: Arc<dyn MetricsPort>,
    mode: DomainMode,
    enabled: bool,
    anti_lockout: AntiLockoutSettings,
    /// What the aliases named by rules resolve to. Refreshed by whoever owns
    /// the alias service; the rules themselves keep their alias references.
    alias_bindings: AliasBindings,
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
            kill_port: None,
            metrics,
            mode: DomainMode::default(),
            enabled: true,
            anti_lockout: AntiLockoutSettings::default(),
            alias_bindings: AliasBindings::default(),
        }
    }

    /// Publish what the aliases resolve to and re-project the rules onto the
    /// kernel maps, so a rule naming an alias starts matching as soon as the
    /// alias has content.
    pub fn set_alias_bindings(&mut self, bindings: AliasBindings) {
        let count = bindings.len();
        self.alias_bindings = bindings;
        self.sync_ebpf_maps();
        tracing::debug!(aliases = count, "firewall alias bindings refreshed");
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
        tracing::info!(enabled, "firewall service toggled");
    }

    /// Set the eBPF map port for kernel map synchronisation.
    ///
    /// Called after eBPF programs are loaded to wire the map manager
    /// into the service so that dynamic rule changes are synced.
    pub fn set_map_port(&mut self, port: Box<dyn FirewallArrayMapPort + Send>) {
        self.map_port = Some(port);
    }

    /// Clear the eBPF map port (program unloaded).
    pub fn clear_map_port(&mut self) {
        self.map_port = None;
    }

    /// Set the kernel-conntrack kill port.
    ///
    /// Wired after the netfilter conntrack adapter is built so that adding a
    /// deny/reject rule mid-flow tears down already-established connections
    /// instead of leaving their conntrack entries alive (the XDP datapath
    /// drop runs before netfilter and cannot evict them).
    pub fn set_kill_port(&mut self, port: Box<dyn ConnTrackKillPort + Send>) {
        self.kill_port = Some(port);
    }

    /// Destroy kernel conntrack entries that a newly enforced deny/reject rule
    /// now blocks, so an already-ESTABLISHED flow is actually torn down.
    ///
    /// No-op unless a kill port is wired, the firewall is enforcing (not in
    /// alert mode), the rule is enabled and denies, and it targets a single
    /// concrete protocol + destination port (the shape the kernel conntrack
    /// CLI can match precisely).
    fn enforce_flow_kill(&self, rule: &FirewallRule) {
        let Some(ref kill_port) = self.kill_port else {
            return;
        };
        if self.mode == DomainMode::Alert || !rule.enabled {
            return;
        }
        if !matches!(rule.action, FirewallAction::Deny | FirewallAction::Reject) {
            return;
        }
        let protocol = rule.protocol.to_u8();
        // Only proto-specific, single-port rules can be targeted without risk
        // of deleting unrelated flows.
        if protocol == Protocol::Any.to_u8() {
            return;
        }
        let Some(ref dst_port) = rule.dst_port else {
            return;
        };
        if dst_port.start != dst_port.end {
            return;
        }
        match kill_port.delete_matching(protocol, dst_port.start) {
            Ok(n) if n > 0 => {
                tracing::info!(
                    rule = rule.id.0,
                    protocol,
                    dst_port = dst_port.start,
                    deleted = n,
                    "tore down established flows for new firewall deny rule"
                );
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(
                    rule = rule.id.0,
                    "conntrack flow teardown for deny rule failed: {e}"
                );
            }
        }
    }

    /// Add a firewall rule. Syncs to eBPF maps and updates metrics.
    pub fn add_rule(&mut self, rule: FirewallRule) -> Result<(), DomainError> {
        let rule_id = rule.id.0.clone();
        // Snapshot the fields the conntrack teardown needs before the rule is
        // moved into the engine, so we don't have to look it back up afterwards.
        let kill_snapshot = rule.clone();
        self.engine.add_rule(rule)?;
        self.sync_ebpf_maps();
        // Tear down any already-established flow the new rule now denies.
        self.enforce_flow_kill(&kill_snapshot);
        self.update_metrics();
        tracing::info!(
            id = rule_id,
            total = self.engine.rules().len(),
            "firewall rule added"
        );
        Ok(())
    }

    /// Remove a firewall rule by ID. System rules (anti-lockout) cannot be removed.
    pub fn remove_rule(&mut self, id: &RuleId) -> Result<(), DomainError> {
        // Check if the rule is a system rule (anti-lockout).
        if let Some(rule) = self.engine.rules().iter().find(|r| r.id == *id)
            && rule.system
        {
            return Err(DomainError::from(FirewallError::SystemRuleProtected {
                id: id.0.clone(),
            }));
        }
        self.engine.remove_rule(id)?;
        self.sync_ebpf_maps();
        self.update_metrics();
        tracing::info!(
            id = id.0,
            total = self.engine.rules().len(),
            "firewall rule removed"
        );
        Ok(())
    }

    /// Set anti-lockout configuration.
    pub fn set_anti_lockout(&mut self, settings: AntiLockoutSettings) {
        self.anti_lockout = settings;
    }

    /// Reload all rules atomically. Injects anti-lockout rules if enabled.
    pub fn reload_rules(&mut self, rules: Vec<FirewallRule>) -> Result<(), DomainError> {
        let mut all_rules = self.generate_anti_lockout_rules();
        let user_count = rules.len();
        all_rules.extend(rules);
        self.engine.reload(all_rules)?;
        self.sync_ebpf_maps();
        self.update_metrics();
        tracing::info!(
            rules = user_count,
            total = self.engine.rules().len(),
            "firewall rules reloaded"
        );
        Ok(())
    }

    /// Apply a schedule: enable rules in the active set, disable scheduled rules not in the set.
    /// Unscheduled rules (no `schedule` field) are never touched.
    pub fn apply_schedule(&mut self, active_ids: &std::collections::HashSet<String>) {
        let mut changed = false;
        for rule in self.engine.rules_mut() {
            if rule.schedule.is_some() {
                let should_enable = active_ids.contains(&rule.id.0);
                if rule.enabled != should_enable {
                    rule.enabled = should_enable;
                    changed = true;
                }
            }
        }
        if changed {
            self.sync_ebpf_maps();
            self.update_metrics();
        }
    }

    /// Return a slice of all loaded rules (sorted by priority).
    pub fn list_rules(&self) -> &[FirewallRule] {
        self.engine.rules()
    }

    /// Return the number of active rules.
    pub fn rule_count(&self) -> usize {
        self.engine.rules().len()
    }

    /// Generate anti-lockout rules based on current config.
    ///
    /// Creates one PASS rule per (port, interface) tuple at priority 0 (highest).
    /// These rules are marked with `system: true` so they cannot be deleted via API.
    fn generate_anti_lockout_rules(&self) -> Vec<FirewallRule> {
        if !self.anti_lockout.enabled {
            return Vec::new();
        }

        let interfaces = if self.anti_lockout.interfaces.is_empty() {
            // No specific interfaces → apply on all interfaces (Scope::Global)
            vec![None]
        } else {
            self.anti_lockout
                .interfaces
                .iter()
                .map(|i| Some(i.clone()))
                .collect()
        };

        let mut rules = Vec::new();
        for port in &self.anti_lockout.ports {
            for iface in &interfaces {
                let scope = match iface {
                    Some(name) => Scope::Interface(name.clone()),
                    None => Scope::Global,
                };
                let id_suffix = match iface {
                    Some(name) => format!("anti-lockout-{name}-{port}"),
                    None => format!("anti-lockout-{port}"),
                };
                rules.push(FirewallRule {
                    id: RuleId(id_suffix),
                    enabled: true,
                    priority: 0,
                    action: FirewallAction::Allow,
                    protocol: Protocol::Tcp,
                    src_ip: None,
                    dst_ip: None,
                    src_port: None,
                    src_port_alias: None,
                    dst_port: Some(PortRange {
                        start: *port,
                        end: *port,
                    }),
                    dst_port_alias: None,
                    src_mac_alias: None,
                    dst_mac_alias: None,
                    vlan_id: None,
                    scope,
                    ct_states: None,
                    src_alias: None,
                    dst_alias: None,
                    tcp_flags: None,
                    icmp_type: None,
                    icmp_code: None,
                    negate_src: false,
                    negate_dst: false,
                    dscp_match: None,
                    dscp_mark: None,
                    max_states: None,
                    src_mac: None,
                    dst_mac: None,
                    schedule: None,
                    system: true,
                    route_action: None,
                    group_mask: 0,
                });
            }
        }
        rules
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
        let alias_bindings = &self.alias_bindings;

        // Partition into V4 and V6, applying alert-mode override
        let mut v4_entries = Vec::new();
        let mut v6_entries = Vec::new();

        for rule in rules {
            // In alert mode: override deny/reject -> log (observe without blocking)
            let effective_rule = if self.mode == DomainMode::Alert
                && (rule.action == FirewallAction::Deny || rule.action == FirewallAction::Reject)
            {
                let mut alert_rule = rule.clone();
                alert_rule.action = FirewallAction::Log;
                alert_rule
            } else {
                rule.clone()
            };

            // Alias references name something the kernel cannot look up, so
            // they are resolved into set ids or literal criteria here.
            let kernel_rules =
                match crate::firewall_aliases::expand_for_kernel(&effective_rule, alias_bindings) {
                    Ok(kernel_rules) => kernel_rules,
                    Err(reason) => {
                        tracing::warn!(
                            component = "firewall",
                            rule = %effective_rule.id.0,
                            "rule not installed: {reason}"
                        );
                        continue;
                    }
                };

            for kernel_rule in kernel_rules {
                if kernel_rule.rule.is_v6() {
                    v6_entries.push(kernel_rule.rule.to_ebpf_entry_v6());
                } else {
                    v4_entries.push(
                        kernel_rule.rule.to_ebpf_entry_with_sets(
                            kernel_rule.src_set_id,
                            kernel_rule.dst_set_id,
                        ),
                    );
                }
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
            src_alias: None,
            dst_alias: None,
            src_port_alias: None,
            dst_port_alias: None,
            src_mac_alias: None,
            dst_mac_alias: None,
            ct_states: None,
            tcp_flags: None,
            icmp_type: None,
            icmp_code: None,
            negate_src: false,
            negate_dst: false,
            dscp_match: None,
            dscp_mark: None,
            max_states: None,
            src_mac: None,
            dst_mac: None,
            schedule: None,
            system: false,
            route_action: None,
            group_mask: 0,
        }
    }

    /// Map port that keeps the last bulk load, so tests can inspect what the
    /// kernel would have been given.
    #[derive(Clone, Default)]
    struct RecordingMap {
        v4: Arc<std::sync::Mutex<Vec<ebpf_common::firewall::FirewallRuleEntry>>>,
        v6: Arc<std::sync::Mutex<Vec<ebpf_common::firewall::FirewallRuleEntryV6>>>,
    }

    impl FirewallArrayMapPort for RecordingMap {
        fn load_v4_rules(
            &mut self,
            rules: &[ebpf_common::firewall::FirewallRuleEntry],
        ) -> Result<(), DomainError> {
            *self.v4.lock().unwrap() = rules.to_vec();
            Ok(())
        }

        fn load_v6_rules(
            &mut self,
            rules: &[ebpf_common::firewall::FirewallRuleEntryV6],
        ) -> Result<(), DomainError> {
            *self.v6.lock().unwrap() = rules.to_vec();
            Ok(())
        }

        fn set_default_policy(&mut self, _policy: u8) -> Result<(), DomainError> {
            Ok(())
        }

        fn rule_count(&self) -> Result<usize, DomainError> {
            Ok(self.v4.lock().unwrap().len() + self.v6.lock().unwrap().len())
        }
    }

    fn make_service() -> FirewallAppService {
        let mut svc = FirewallAppService::new(FirewallEngine::new(), None, Arc::new(NoopMetrics));
        // Disable anti-lockout for unit tests to avoid extra synthetic rules.
        svc.set_anti_lockout(AntiLockoutSettings {
            enabled: false,
            ..Default::default()
        });
        svc
    }

    #[test]
    fn set_backed_alias_reaches_the_kernel_entry() {
        let map = RecordingMap::default();
        let mut svc = make_service();
        svc.set_map_port(Box::new(map.clone()));

        let mut rule = make_rule("fw-alias", 10);
        rule.src_alias = Some("blocklist".to_string());
        svc.add_rule(rule).unwrap();

        // Before the alias is bound the rule cannot be installed: matching on
        // an unknown name would mean matching everything.
        assert!(map.v4.lock().unwrap().is_empty());

        let mut bindings = AliasBindings::default();
        bindings.bind_set("blocklist", 4);
        svc.set_alias_bindings(bindings);

        let entries = map.v4.lock().unwrap().clone();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].src_set_id, 4);
        assert_ne!(
            entries[0].match_flags & ebpf_common::firewall::MATCH_SRC_SET,
            0
        );
    }

    #[test]
    fn statically_resolved_alias_expands_into_one_entry_per_network() {
        let map = RecordingMap::default();
        let mut svc = make_service();
        svc.set_map_port(Box::new(map.clone()));

        let mut rule = make_rule("fw-alias", 10);
        rule.src_alias = Some("lan".to_string());
        svc.add_rule(rule).unwrap();

        let mut bindings = AliasBindings::default();
        bindings.bind_ips(
            "lan",
            vec![
                domain::firewall::entity::IpNetwork::V4 {
                    addr: 0x0A00_0000,
                    prefix_len: 24,
                },
                domain::firewall::entity::IpNetwork::V4 {
                    addr: 0xC0A8_0000,
                    prefix_len: 16,
                },
            ],
        );
        svc.set_alias_bindings(bindings);

        let entries = map.v4.lock().unwrap().clone();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|e| e.src_set_id == 0));
        assert_eq!(entries[0].src_ip, 0x0A00_0000);
        assert_eq!(entries[1].src_ip, 0xC0A8_0000);
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
