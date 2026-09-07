use std::sync::Arc;

use domain::common::entity::Protocol;
use domain::common::entity::{DomainMode, RuleId};
use domain::common::error::DomainError;
use domain::firewall::engine::FirewallEngine;
use domain::firewall::entity::{FirewallAction, FirewallRule, PortRange, Scope};
use domain::firewall::error::FirewallError;

use domain::firewall::entity::IpNetwork;
use ebpf_common::firewall::{DEFAULT_POLICY_DROP, DEFAULT_POLICY_PASS};

use crate::firewall_aliases::AliasBindings;
use ports::secondary::conntrack_kill_port::ConnTrackKillPort;
use ports::secondary::ebpf_map_port::FirewallArrayMapPort;
use ports::secondary::metrics_port::MetricsPort;

/// The rule identifiers the deny-all posture installs.
///
/// They are `system` rules, so the API cannot delete them while the posture is
/// in force, and they are named rather than generated so an operator reading
/// `firewall list` on a closed node sees why nothing is getting through.
pub const DENY_ALL_RULE_ID_V4: &str = "fail-closed-deny-all-v4";
pub const DENY_ALL_RULE_ID_V6: &str = "fail-closed-deny-all-v6";

/// What the service puts back when the deny-all posture is lifted.
///
/// The posture changes three things and each of them has to be restored, not
/// recomputed: the rules an operator loaded, the mode the deployment chose, and
/// whether anti-lockout was on. Recomputing any of them from configuration
/// would lose every change made through the API since boot.
struct DenyAllSnapshot {
    rules: Vec<FirewallRule>,
    mode: DomainMode,
    anti_lockout_enabled: bool,
}

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
    /// while enforcing, matching ESTABLISHED flows are torn down here - the
    /// XDP drop alone cannot evict an existing conntrack entry.
    kill_port: Option<Box<dyn ConnTrackKillPort + Send>>,
    metrics: Arc<dyn MetricsPort>,
    mode: DomainMode,
    enabled: bool,
    anti_lockout: AntiLockoutSettings,
    /// What the aliases named by rules resolve to. Refreshed by whoever owns
    /// the alias service; the rules themselves keep their alias references.
    alias_bindings: AliasBindings,
    /// The catch-all byte the datapath falls back to for a packet no rule
    /// matched. Held here as well as in the map because the deny-all posture
    /// overwrites it and has to put the configured one back.
    default_policy: u8,
    /// `Some` while the deny-all posture is in force, carrying what to restore.
    deny_all: Option<DenyAllSnapshot>,
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
            default_policy: DEFAULT_POLICY_PASS,
            deny_all: None,
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

    /// Record the configured catch-all policy and push it to the datapath.
    ///
    /// Called once the map port is wired, because until then the byte the
    /// loader wrote is known to the map manager and to nobody else, and the
    /// deny-all posture needs something to restore.
    pub fn set_default_policy(&mut self, policy: u8) {
        self.default_policy = policy;
        // While the posture is in force the datapath byte is the posture's, and
        // the configured one is what gets restored when it is lifted.
        if self.deny_all.is_none() {
            self.push_default_policy(policy);
        }
    }

    /// Return the configured catch-all policy byte.
    pub fn default_policy(&self) -> u8 {
        self.default_policy
    }

    /// Whether the deny-all posture is currently in force.
    pub fn is_deny_all(&self) -> bool {
        self.deny_all.is_some()
    }

    /// Install the deny-all posture: nothing crosses this node except the
    /// anti-lockout ports.
    ///
    /// Three things make this more than flipping the catch-all byte to drop.
    ///
    /// The datapath passes an ESTABLISHED or RELATED flow before it ever
    /// consults the catch-all, so a node that only flipped the byte would keep
    /// carrying every connection that was already open, which is exactly the
    /// traffic a closed node is closed against. What actually stops them is a
    /// catch-all deny rule with no connection-state match on it, because a rule
    /// that names no state is evaluated against every state.
    ///
    /// A rule carrying no address at all is installed into the v4 array only,
    /// since the array a rule lands in is decided by whether it names a v6
    /// address. So the posture is two rules, `0.0.0.0/0` and `::/0`.
    ///
    /// And a deny is rewritten into a log line in alert mode, so the posture
    /// forces block mode for its duration. An alert-mode node that entered
    /// fail-closed and dropped nothing would be the worst outcome available:
    /// the cluster believes the node is closed and the node is wide open.
    ///
    /// Anti-lockout is forced on for the duration, and that is deliberate.
    /// This posture is entered by the cluster rather than by an operator
    /// command, so a node that closed its own management port would need
    /// somebody physically present to reopen it, and a safety measure with
    /// that cost is a safety measure that gets configured off.
    ///
    /// Repeating the call while the posture is already in force is a no-op, so
    /// a cluster that reports the same degradation twice does not overwrite the
    /// snapshot with the deny-all rules themselves.
    pub fn enter_deny_all(&mut self) -> Result<(), DomainError> {
        if self.deny_all.is_some() {
            return Ok(());
        }

        self.deny_all = Some(DenyAllSnapshot {
            rules: self
                .engine
                .rules()
                .iter()
                .filter(|r| !r.system)
                .cloned()
                .collect(),
            mode: self.mode,
            anti_lockout_enabled: self.anti_lockout.enabled,
        });

        self.mode = DomainMode::Block;
        self.anti_lockout.enabled = true;

        let result = self.reload_rules(Self::deny_all_rules());
        if let Err(ref e) = result {
            tracing::error!(error = %e, "failed to install the deny-all posture");
        }
        self.push_default_policy(DEFAULT_POLICY_DROP);

        tracing::warn!(
            anti_lockout_ports = ?self.anti_lockout.ports,
            "firewall deny-all posture installed: only the anti-lockout ports remain reachable"
        );
        result
    }

    /// Lift the deny-all posture, putting back the rules, the mode, the
    /// anti-lockout setting and the catch-all byte that were in force when it
    /// was installed.
    ///
    /// A no-op when the posture is not installed, so a cluster that reports
    /// recovery without ever having reported degradation does not wipe the
    /// rules an operator loaded in the meantime.
    pub fn exit_deny_all(&mut self) -> Result<(), DomainError> {
        let Some(snapshot) = self.deny_all.take() else {
            return Ok(());
        };

        self.mode = snapshot.mode;
        self.anti_lockout.enabled = snapshot.anti_lockout_enabled;
        let result = self.reload_rules(snapshot.rules);
        if let Err(ref e) = result {
            tracing::error!(error = %e, "failed to lift the deny-all posture");
        }
        self.push_default_policy(self.default_policy);

        tracing::info!("firewall deny-all posture lifted");
        result
    }

    /// The two catch-all denies the posture installs.
    ///
    /// Priority 1 rather than 0: the anti-lockout rules own 0 and are what
    /// keeps the node reachable, so the deny has to sit below them.
    fn deny_all_rules() -> Vec<FirewallRule> {
        [
            (
                DENY_ALL_RULE_ID_V4,
                IpNetwork::V4 {
                    addr: 0,
                    prefix_len: 0,
                },
            ),
            (
                DENY_ALL_RULE_ID_V6,
                IpNetwork::V6 {
                    addr: [0u8; 16],
                    prefix_len: 0,
                },
            ),
        ]
        .into_iter()
        .map(|(id, dst_ip)| FirewallRule {
            id: RuleId(id.to_string()),
            enabled: true,
            priority: 1,
            action: FirewallAction::Deny,
            protocol: Protocol::Any,
            src_ip: None,
            dst_ip: Some(dst_ip),
            src_port: None,
            src_port_alias: None,
            dst_port: None,
            dst_port_alias: None,
            src_mac_alias: None,
            dst_mac_alias: None,
            vlan_id: None,
            scope: Scope::Global,
            // No connection-state match, so the rule is evaluated against
            // every state. This is what closes flows that were already open.
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
            tenant_id: 0,
        })
        .collect()
    }

    /// Write a catch-all policy byte to the datapath without recording it as
    /// the configured one.
    fn push_default_policy(&mut self, policy: u8) {
        if let Some(ref mut map) = self.map_port
            && let Err(e) = map.set_default_policy(policy)
        {
            tracing::warn!("failed to set firewall default policy: {e}");
        }
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
                    tenant_id: 0,
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
            tenant_id: 0,
        }
    }

    /// Map port that keeps the last bulk load, so tests can inspect what the
    /// kernel would have been given.
    #[derive(Clone, Default)]
    struct RecordingMap {
        v4: Arc<std::sync::Mutex<Vec<ebpf_common::firewall::FirewallRuleEntry>>>,
        v6: Arc<std::sync::Mutex<Vec<ebpf_common::firewall::FirewallRuleEntryV6>>>,
        policy: Arc<std::sync::Mutex<Option<u8>>>,
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

        fn set_default_policy(&mut self, policy: u8) -> Result<(), DomainError> {
            *self.policy.lock().unwrap() = Some(policy);
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

    /// A service whose anti-lockout list is empty, so the posture's own rules
    /// are the only ones in the arrays and can be counted.
    fn make_service_without_management_ports() -> FirewallAppService {
        let mut svc = FirewallAppService::new(FirewallEngine::new(), None, Arc::new(NoopMetrics));
        svc.set_anti_lockout(AntiLockoutSettings {
            enabled: false,
            interfaces: Vec::new(),
            ports: Vec::new(),
        });
        svc
    }

    #[test]
    fn deny_all_posture_closes_both_families_and_drops_the_catch_all() {
        let map = RecordingMap::default();
        let mut svc = make_service_without_management_ports();
        svc.set_map_port(Box::new(map.clone()));
        svc.set_default_policy(DEFAULT_POLICY_PASS);
        svc.add_rule(make_rule("allow-web", 10)).unwrap();

        svc.enter_deny_all().unwrap();

        assert!(svc.is_deny_all());
        // One deny in each array: a rule naming no address would only ever be
        // installed into the v4 one, so the v6 half of the estate would stay
        // open.
        assert_eq!(map.v4.lock().unwrap().len(), 1);
        assert_eq!(map.v6.lock().unwrap().len(), 1);
        assert_eq!(*map.policy.lock().unwrap(), Some(DEFAULT_POLICY_DROP));

        let installed: Vec<&str> = svc.list_rules().iter().map(|r| r.id.0.as_str()).collect();
        assert_eq!(installed, vec![DENY_ALL_RULE_ID_V4, DENY_ALL_RULE_ID_V6]);
    }

    #[test]
    fn deny_all_posture_matches_every_connection_state() {
        let mut svc = make_service();
        svc.enter_deny_all().unwrap();

        // The datapath passes an established flow before it consults the
        // catch-all byte, so a posture whose rules named a connection state
        // would leave every open connection running.
        for rule in svc.list_rules() {
            assert!(rule.ct_states.is_none(), "{} names a state", rule.id.0);
        }
    }

    #[test]
    fn deny_all_posture_forces_block_mode_and_restores_the_configured_one() {
        let map = RecordingMap::default();
        let mut svc = make_service_without_management_ports();
        svc.set_map_port(Box::new(map.clone()));
        svc.set_mode(DomainMode::Alert);

        svc.enter_deny_all().unwrap();
        // Alert mode rewrites a deny into a log line, which would make the
        // posture drop nothing at all.
        assert_eq!(svc.mode(), DomainMode::Block);
        assert_eq!(
            map.v4.lock().unwrap()[0].action,
            ebpf_common::firewall::ACTION_DROP,
            "the installed rule was downgraded to a log line"
        );

        svc.exit_deny_all().unwrap();
        assert_eq!(svc.mode(), DomainMode::Alert);
    }

    #[test]
    fn deny_all_posture_keeps_the_management_ports_reachable() {
        let mut svc = FirewallAppService::new(FirewallEngine::new(), None, Arc::new(NoopMetrics));
        svc.set_anti_lockout(AntiLockoutSettings {
            enabled: false,
            interfaces: Vec::new(),
            ports: vec![8080],
        });

        svc.enter_deny_all().unwrap();

        // The posture is entered by the cluster rather than by an operator, so
        // a node closing its own management port would need somebody on site.
        let pass = svc
            .list_rules()
            .iter()
            .find(|r| r.action == FirewallAction::Allow)
            .expect("anti-lockout rule missing under the deny-all posture");
        assert_eq!(pass.priority, 0);
        assert_eq!(pass.dst_port.map(|p| p.start), Some(8080));

        svc.exit_deny_all().unwrap();
        // And the deployment's own choice comes back when the posture lifts.
        assert!(
            svc.list_rules()
                .iter()
                .all(|r| r.action != FirewallAction::Allow)
        );
    }

    #[test]
    fn exiting_the_deny_all_posture_puts_back_what_was_there() {
        let map = RecordingMap::default();
        let mut svc = make_service();
        svc.set_map_port(Box::new(map.clone()));
        svc.set_default_policy(DEFAULT_POLICY_PASS);
        svc.add_rule(make_rule("allow-web", 10)).unwrap();
        svc.add_rule(make_rule("allow-db", 20)).unwrap();

        svc.enter_deny_all().unwrap();
        svc.exit_deny_all().unwrap();

        assert!(!svc.is_deny_all());
        let restored: Vec<&str> = svc.list_rules().iter().map(|r| r.id.0.as_str()).collect();
        assert_eq!(restored, vec!["allow-web", "allow-db"]);
        assert_eq!(*map.policy.lock().unwrap(), Some(DEFAULT_POLICY_PASS));
    }

    #[test]
    fn entering_the_deny_all_posture_twice_does_not_lose_the_rules() {
        let mut svc = make_service();
        svc.add_rule(make_rule("allow-web", 10)).unwrap();

        // A cluster that reports the same degradation twice must not snapshot
        // the posture's own rules over the operator's.
        svc.enter_deny_all().unwrap();
        svc.enter_deny_all().unwrap();
        svc.exit_deny_all().unwrap();

        let restored: Vec<&str> = svc.list_rules().iter().map(|r| r.id.0.as_str()).collect();
        assert_eq!(restored, vec!["allow-web"]);
    }

    #[test]
    fn exiting_a_posture_that_was_never_entered_changes_nothing() {
        let mut svc = make_service();
        svc.add_rule(make_rule("allow-web", 10)).unwrap();

        svc.exit_deny_all().unwrap();

        let kept: Vec<&str> = svc.list_rules().iter().map(|r| r.id.0.as_str()).collect();
        assert_eq!(kept, vec!["allow-web"]);
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
        // No panic - graceful degraded mode
    }
}
