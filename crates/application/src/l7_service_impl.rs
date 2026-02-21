use std::sync::Arc;

use domain::common::entity::RuleId;
use domain::common::error::DomainError;
use domain::firewall::entity::FirewallAction;
use domain::l7::engine::L7Engine;
use domain::l7::entity::{L7Rule, ParsedProtocol};
use ebpf_common::event::PacketEvent;
use ports::secondary::metrics_port::MetricsPort;

/// Application-level L7 firewall service.
///
/// Orchestrates the L7 domain engine and metrics updates.
/// Designed to be wrapped in `RwLock` for shared access.
pub struct L7AppService {
    engine: L7Engine,
    metrics: Arc<dyn MetricsPort>,
    enabled: bool,
}

impl L7AppService {
    pub fn new(engine: L7Engine, metrics: Arc<dyn MetricsPort>) -> Self {
        Self {
            engine,
            metrics,
            enabled: true,
        }
    }

    /// Evaluate a parsed L7 event against all loaded rules.
    ///
    /// Returns the action of the first matching rule, or `None`.
    /// Records a metric with the matched action label.
    pub fn evaluate(
        &self,
        header: &PacketEvent,
        parsed: &ParsedProtocol,
    ) -> Option<FirewallAction> {
        if !self.enabled {
            return None;
        }

        let result = self.engine.evaluate(header, parsed);
        if let Some((_, rule)) = &result {
            let action_label = match rule.action {
                FirewallAction::Allow => "allow",
                FirewallAction::Deny => "deny",
                FirewallAction::Log => "log",
            };
            self.metrics.record_packet("l7", action_label);
        }
        result.map(|(_, rule)| rule.action)
    }

    /// Reload all L7 rules atomically.
    pub fn reload_rules(&mut self, rules: Vec<L7Rule>) -> Result<(), DomainError> {
        self.engine.reload(rules)?;
        self.update_metrics();
        Ok(())
    }

    /// Add an L7 rule.
    pub fn add_rule(&mut self, rule: L7Rule) -> Result<(), DomainError> {
        self.engine.add_rule(rule)?;
        self.update_metrics();
        Ok(())
    }

    /// Remove an L7 rule by ID.
    pub fn remove_rule(&mut self, id: &RuleId) -> Result<(), DomainError> {
        self.engine.remove_rule(id)?;
        self.update_metrics();
        Ok(())
    }

    /// Return a slice of all loaded rules.
    pub fn rules(&self) -> &[L7Rule] {
        self.engine.rules()
    }

    /// Return the number of loaded rules.
    pub fn rule_count(&self) -> usize {
        self.engine.rule_count()
    }

    /// Return whether the L7 service is enabled.
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Set the enabled state.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    fn update_metrics(&self) {
        self.metrics
            .set_rules_loaded("l7", self.engine.rule_count() as u64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::l7::entity::{HttpRequest, L7Matcher, ParsedProtocol};
    use ports::test_utils::NoopMetrics;

    fn make_service() -> L7AppService {
        L7AppService::new(L7Engine::new(), Arc::new(NoopMetrics))
    }

    fn make_header() -> PacketEvent {
        PacketEvent {
            timestamp_ns: 0,
            src_addr: [0xC0A80001, 0, 0, 0],
            dst_addr: [0x0A000001, 0, 0, 0],
            src_port: 12345,
            dst_port: 80,
            protocol: 6,
            event_type: 6,
            action: 0,
            flags: 0,
            vlan_id: 0,
            cpu_id: 0,
            socket_cookie: 0,
            rule_id: 0,
        }
    }

    fn make_http_parsed() -> ParsedProtocol {
        ParsedProtocol::Http(HttpRequest {
            method: "DELETE".to_string(),
            path: "/admin/users".to_string(),
            version: "HTTP/1.1".to_string(),
            host: None,
            content_type: None,
            headers: vec![],
        })
    }

    fn make_deny_rule() -> L7Rule {
        L7Rule {
            id: RuleId("l7-001".to_string()),
            priority: 10,
            action: FirewallAction::Deny,
            matcher: L7Matcher::Http {
                method: Some("DELETE".to_string()),
                path_pattern: None,
                host_pattern: None,
                content_type: None,
            },
            src_ip: None,
            dst_ip: None,
            dst_port: None,
            enabled: true,
        }
    }

    #[test]
    fn evaluate_match_returns_action() {
        let mut svc = make_service();
        svc.add_rule(make_deny_rule()).unwrap();

        let result = svc.evaluate(&make_header(), &make_http_parsed());
        assert_eq!(result, Some(FirewallAction::Deny));
    }

    #[test]
    fn evaluate_no_match_returns_none() {
        let svc = make_service();
        let result = svc.evaluate(&make_header(), &make_http_parsed());
        assert!(result.is_none());
    }

    #[test]
    fn disabled_service_returns_none() {
        let mut svc = make_service();
        svc.add_rule(make_deny_rule()).unwrap();
        svc.set_enabled(false);

        let result = svc.evaluate(&make_header(), &make_http_parsed());
        assert!(result.is_none());
    }

    #[test]
    fn reload_updates_rules() {
        let mut svc = make_service();
        svc.add_rule(make_deny_rule()).unwrap();
        assert_eq!(svc.rule_count(), 1);

        svc.reload_rules(vec![]).unwrap();
        assert_eq!(svc.rule_count(), 0);
    }
}
