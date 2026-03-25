use std::sync::Arc;

use domain::common::entity::RuleId;
use domain::common::error::DomainError;
use domain::firewall::entity::FirewallAction;
use domain::l7::engine::L7Engine;
use domain::l7::entity::{L7Rule, ParsedProtocol};
use ebpf_common::event::PacketEvent;
use ports::secondary::geoip_port::GeoIpPort;
use ports::secondary::metrics_port::MetricsPort;

/// Application-level L7 firewall service.
///
/// Orchestrates the L7 domain engine and metrics updates.
/// Designed to be wrapped in `ArcSwap` for lock-free reads.
#[derive(Clone)]
pub struct L7AppService {
    engine: L7Engine,
    metrics: Arc<dyn MetricsPort>,
    enabled: bool,
    geoip: Option<Arc<dyn GeoIpPort>>,
}

impl L7AppService {
    pub fn new(engine: L7Engine, metrics: Arc<dyn MetricsPort>) -> Self {
        Self {
            engine,
            metrics,
            enabled: true,
            geoip: None,
        }
    }

    /// Set the `GeoIP` port for country-based rule matching.
    pub fn set_geoip_port(&mut self, port: Arc<dyn GeoIpPort>) {
        self.geoip = Some(port);
    }

    /// Evaluate a parsed L7 event against all loaded rules.
    ///
    /// Resolves source and destination countries via the `GeoIP` port
    /// for country-based rule matching. Returns the action and rule ID of the
    /// first matching rule, or `None`.
    pub fn evaluate(
        &self,
        header: &PacketEvent,
        parsed: &ParsedProtocol,
    ) -> Option<(FirewallAction, RuleId)> {
        if !self.enabled {
            return None;
        }

        let src_country = self.resolve_country(header.src_addr, header.is_ipv6());
        let dst_country = self.resolve_country(header.dst_addr, header.is_ipv6());

        let result = self.engine.evaluate_with_country(
            header,
            parsed,
            src_country.as_deref(),
            dst_country.as_deref(),
        );
        if let Some((_, rule)) = &result {
            let action_label = match rule.action {
                FirewallAction::Allow => "allow",
                FirewallAction::Deny => "deny",
                FirewallAction::Log => "log",
                FirewallAction::Reject => "reject",
            };
            self.metrics.record_packet("l7", action_label);
        }
        result.map(|(_, rule)| (rule.action, rule.id.clone()))
    }

    fn resolve_country(&self, addr: [u32; 4], is_ipv6: bool) -> Option<String> {
        let geoip = self.geoip.as_ref()?;
        let ip = crate::addr_to_ip(addr, is_ipv6);
        geoip.lookup(&ip).and_then(|info| info.country_code)
    }

    /// Reload all L7 rules atomically.
    pub fn reload_rules(&mut self, rules: Vec<L7Rule>) -> Result<(), DomainError> {
        let count = rules.len();
        self.engine.reload(rules)?;
        self.update_metrics();
        tracing::info!(count, "L7 rules reloaded");
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
        tracing::info!(enabled, "L7 service toggled");
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
            src_addr: [0xC0A8_0001, 0, 0, 0],
            dst_addr: [0x0A00_0001, 0, 0, 0],
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
            src_country_codes: None,
            dst_country_codes: None,
            src_ip_alias: None,
            dst_ip_alias: None,
            dst_port_alias: None,
        }
    }

    #[test]
    fn evaluate_match_returns_action_and_rule_id() {
        let mut svc = make_service();
        svc.add_rule(make_deny_rule()).unwrap();

        let result = svc.evaluate(&make_header(), &make_http_parsed());
        let (action, rule_id) = result.unwrap();
        assert_eq!(action, FirewallAction::Deny);
        assert_eq!(rule_id.0, "l7-001");
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
