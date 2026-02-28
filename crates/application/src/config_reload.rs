use std::sync::Arc;

use domain::alias::entity::Alias;
use domain::audit::entity::{AuditAction, AuditComponent};
use domain::audit::rule_change::ChangeActor;
use domain::common::entity::DomainMode;
use domain::conntrack::entity::ConnTrackSettings;
use domain::ddos::entity::DdosPolicy;
use domain::firewall::entity::FirewallRule;
use domain::ids::entity::{IdsRule, SamplingMode};
use domain::ips::entity::{IpsPolicy, WhitelistEntry};
use domain::l7::entity::L7Rule;
use domain::nat::entity::NatRule;
use domain::ratelimit::entity::RateLimitPolicy;
use ports::secondary::metrics_port::MetricsPort;
use tokio::sync::{Mutex, RwLock};

use crate::alias_service_impl::AliasAppService;
use crate::audit_service_impl::AuditAppService;
use crate::conntrack_service_impl::ConnTrackAppService;
use crate::ddos_service_impl::DdosAppService;
use crate::firewall_service_impl::FirewallAppService;
use crate::ids_service_impl::IdsAppService;
use crate::ips_service_impl::IpsAppService;
use crate::l7_service_impl::L7AppService;
use crate::nat_service_impl::NatAppService;
use crate::ratelimit_service_impl::RateLimitAppService;
use crate::routing_service_impl::RoutingAppService;
use crate::threatintel_service_impl::ThreatIntelAppService;

/// Application-level service for hot-reloading configuration.
///
/// Wraps reload logic with serialization (one reload at a time),
/// metrics recording, and structured logging.
pub struct ConfigReloadService {
    firewall_service: Arc<RwLock<FirewallAppService>>,
    ids_service: Arc<RwLock<IdsAppService>>,
    ips_service: Arc<RwLock<IpsAppService>>,
    l7_service: Arc<RwLock<L7AppService>>,
    ratelimit_service: Arc<RwLock<RateLimitAppService>>,
    ddos_service: Arc<RwLock<DdosAppService>>,
    threatintel_service: Arc<RwLock<ThreatIntelAppService>>,
    audit_service: Arc<RwLock<AuditAppService>>,
    conntrack_service: Option<Arc<RwLock<ConnTrackAppService>>>,
    nat_service: Option<Arc<RwLock<NatAppService>>>,
    alias_service: Option<Arc<RwLock<AliasAppService>>>,
    routing_service: Option<Arc<RwLock<RoutingAppService>>>,
    metrics: Arc<dyn MetricsPort>,
    reload_mutex: Mutex<()>,
}

impl ConfigReloadService {
    #[allow(clippy::similar_names, clippy::too_many_arguments)]
    pub fn new(
        firewall_service: Arc<RwLock<FirewallAppService>>,
        ids_service: Arc<RwLock<IdsAppService>>,
        ips_service: Arc<RwLock<IpsAppService>>,
        l7_service: Arc<RwLock<L7AppService>>,
        ratelimit_service: Arc<RwLock<RateLimitAppService>>,
        ddos_service: Arc<RwLock<DdosAppService>>,
        threatintel_service: Arc<RwLock<ThreatIntelAppService>>,
        audit_service: Arc<RwLock<AuditAppService>>,
        metrics: Arc<dyn MetricsPort>,
    ) -> Self {
        Self {
            firewall_service,
            ids_service,
            ips_service,
            l7_service,
            ratelimit_service,
            ddos_service,
            threatintel_service,
            audit_service,
            conntrack_service: None,
            nat_service: None,
            alias_service: None,
            routing_service: None,
            metrics,
            reload_mutex: Mutex::new(()),
        }
    }

    /// Set the conntrack service for reload integration.
    pub fn set_conntrack_service(&mut self, svc: Arc<RwLock<ConnTrackAppService>>) {
        self.conntrack_service = Some(svc);
    }

    /// Set the NAT service for reload integration.
    pub fn set_nat_service(&mut self, svc: Arc<RwLock<NatAppService>>) {
        self.nat_service = Some(svc);
    }

    /// Set the alias service for reload integration.
    pub fn set_alias_service(&mut self, svc: Arc<RwLock<AliasAppService>>) {
        self.alias_service = Some(svc);
    }

    /// Set the routing service for reload integration.
    pub fn set_routing_service(&mut self, svc: Arc<RwLock<RoutingAppService>>) {
        self.routing_service = Some(svc);
    }

    /// Reload conntrack settings.
    pub async fn reload_conntrack(
        &self,
        settings: ConnTrackSettings,
        enabled: bool,
    ) -> Result<(), anyhow::Error> {
        let Some(ref ct_svc) = self.conntrack_service else {
            return Ok(());
        };
        let _guard = self.reload_mutex.lock().await;

        let mut svc = ct_svc.write().await;
        svc.set_enabled(enabled);
        svc.reload_settings(settings)
            .map_err(|e| anyhow::anyhow!("conntrack reload failed: {e}"))?;

        self.metrics.record_config_reload("conntrack", "success");
        tracing::info!(enabled, "conntrack configuration reloaded");
        Ok(())
    }

    /// Reload NAT rules.
    pub async fn reload_nat(
        &self,
        dnat_rules: Vec<NatRule>,
        snat_rules: Vec<NatRule>,
        enabled: bool,
    ) -> Result<(), anyhow::Error> {
        let Some(ref nat_svc) = self.nat_service else {
            return Ok(());
        };
        let _guard = self.reload_mutex.lock().await;

        let mut svc = nat_svc.write().await;
        svc.set_enabled(enabled);

        if enabled {
            svc.reload_dnat_rules(dnat_rules)
                .map_err(|e| anyhow::anyhow!("NAT DNAT reload failed: {e}"))?;
            svc.reload_snat_rules(snat_rules)
                .map_err(|e| anyhow::anyhow!("NAT SNAT reload failed: {e}"))?;
        } else {
            svc.reload_dnat_rules(Vec::new())
                .map_err(|e| anyhow::anyhow!("NAT DNAT reload failed: {e}"))?;
            svc.reload_snat_rules(Vec::new())
                .map_err(|e| anyhow::anyhow!("NAT SNAT reload failed: {e}"))?;
        }

        self.metrics.record_config_reload("nat", "success");
        tracing::info!(
            enabled,
            count = svc.rule_count(),
            "NAT configuration reloaded"
        );
        Ok(())
    }

    /// Reload aliases.
    pub async fn reload_aliases(&self, aliases: Vec<Alias>) -> Result<(), anyhow::Error> {
        let Some(ref alias_svc) = self.alias_service else {
            return Ok(());
        };
        let _guard = self.reload_mutex.lock().await;

        let mut svc = alias_svc.write().await;
        let count = aliases.len();
        svc.reload_aliases(aliases)
            .map_err(|e| anyhow::anyhow!("alias reload failed: {e}"))?;

        self.metrics.record_config_reload("aliases", "success");
        tracing::info!(count, "alias configuration reloaded");
        Ok(())
    }

    /// Reload routing gateways.
    pub async fn reload_routing(
        &self,
        gateways: Vec<domain::routing::entity::Gateway>,
        enabled: bool,
    ) -> Result<(), anyhow::Error> {
        let Some(ref routing_svc) = self.routing_service else {
            return Ok(());
        };
        let _guard = self.reload_mutex.lock().await;

        let mut svc = routing_svc.write().await;
        svc.set_enabled(enabled);
        svc.reload_gateways(gateways)
            .map_err(|e| anyhow::anyhow!("routing reload failed: {e}"))?;

        self.metrics.record_config_reload("routing", "success");
        tracing::info!(
            enabled,
            count = svc.gateway_count(),
            "routing configuration reloaded"
        );
        Ok(())
    }

    /// Reload firewall rules atomically with mode and enabled awareness.
    ///
    /// Acquires a serialization lock to ensure only one reload runs at a time.
    /// If `enabled` is false, clears all rules (default-to-pass).
    /// Detects and logs mode transitions.
    pub async fn reload(
        &self,
        rules: Vec<FirewallRule>,
        enabled: bool,
        mode: DomainMode,
    ) -> Result<(), anyhow::Error> {
        // Serialize concurrent reload attempts
        let _guard = self.reload_mutex.lock().await;

        let mut svc = self.firewall_service.write().await;

        // Detect mode transition
        let old_mode = svc.mode();
        if old_mode != mode {
            tracing::info!(
                component = "firewall",
                old_mode = old_mode.as_str(),
                new_mode = mode.as_str(),
                "domain mode changed"
            );
        }

        svc.set_mode(mode);
        svc.set_enabled(enabled);

        // If disabled, clear all rules (default-to-pass behavior)
        let effective_rules = if enabled { rules } else { Vec::new() };
        let rule_count = effective_rules.len();

        match svc.reload_rules(effective_rules) {
            Ok(()) => {
                drop(svc);
                self.metrics.record_config_reload("firewall", "success");
                tracing::info!(
                    rule_count = rule_count,
                    enabled = enabled,
                    mode = mode.as_str(),
                    "firewall configuration reloaded successfully"
                );
                let audit_svc = self.audit_service.read().await;
                audit_svc.record_config_change(
                    AuditAction::ConfigChanged,
                    &format!(
                        "firewall reloaded: {rule_count} rules, mode={}",
                        mode.as_str()
                    ),
                );
                audit_svc.record_rule_change(
                    AuditComponent::Firewall,
                    AuditAction::RuleUpdated,
                    ChangeActor::ConfigReload,
                    "firewall-config",
                    None,
                    Some(format!(
                        "{{\"rule_count\":{rule_count},\"mode\":\"{}\"}}",
                        mode.as_str()
                    )),
                );
                drop(audit_svc);
                Ok(())
            }
            Err(e) => {
                drop(svc);
                self.metrics.record_config_reload("firewall", "failure");
                tracing::warn!(error = %e, "firewall configuration reload failed");
                Err(anyhow::anyhow!("firewall reload failed: {e}"))
            }
        }
    }

    /// Reload IDS rules atomically with mode, sampling, and enabled awareness.
    pub async fn reload_ids(
        &self,
        rules: Vec<IdsRule>,
        enabled: bool,
        mode: DomainMode,
        sampling: SamplingMode,
    ) -> Result<(), anyhow::Error> {
        let _guard = self.reload_mutex.lock().await;

        let mut svc = self.ids_service.write().await;

        let old_mode = svc.mode();
        if old_mode != mode {
            tracing::info!(
                component = "ids",
                old_mode = old_mode.as_str(),
                new_mode = mode.as_str(),
                "domain mode changed"
            );
        }

        svc.set_mode(mode);
        svc.set_enabled(enabled);
        svc.set_sampling(sampling);

        let effective_rules = if enabled { rules } else { Vec::new() };
        let rule_count = effective_rules.len();

        match svc.reload_rules(effective_rules) {
            Ok(()) => {
                drop(svc);
                self.metrics.record_config_reload("ids", "success");
                tracing::info!(
                    rule_count = rule_count,
                    enabled = enabled,
                    mode = mode.as_str(),
                    "IDS configuration reloaded successfully"
                );
                let audit_svc = self.audit_service.read().await;
                audit_svc.record_config_change(
                    AuditAction::ConfigChanged,
                    &format!("ids reloaded: {rule_count} rules, mode={}", mode.as_str()),
                );
                audit_svc.record_rule_change(
                    AuditComponent::Ids,
                    AuditAction::RuleUpdated,
                    ChangeActor::ConfigReload,
                    "ids-config",
                    None,
                    Some(format!(
                        "{{\"rule_count\":{rule_count},\"mode\":\"{}\"}}",
                        mode.as_str()
                    )),
                );
                drop(audit_svc);
                Ok(())
            }
            Err(e) => {
                drop(svc);
                self.metrics.record_config_reload("ids", "failure");
                tracing::warn!(error = %e, "IDS configuration reload failed");
                Err(anyhow::anyhow!("IDS reload failed: {e}"))
            }
        }
    }

    /// Reload IPS rules, whitelist, policy, and mode atomically.
    ///
    /// The fallible operation (`reload_rules`) runs first. Non-fallible
    /// state mutations (mode, enabled, policy, whitelist) are applied only
    /// on success, preventing partial state corruption.
    #[allow(clippy::too_many_arguments)]
    pub async fn reload_ips(
        &self,
        rules: Vec<IdsRule>,
        whitelist: Vec<WhitelistEntry>,
        enabled: bool,
        mode: DomainMode,
        policy: IpsPolicy,
        sampling: SamplingMode,
    ) -> Result<(), anyhow::Error> {
        let _guard = self.reload_mutex.lock().await;

        let mut svc = self.ips_service.write().await;

        // Collect per-rule mode changes before replacing rules
        let rule_mode_changes: Vec<_> = rules
            .iter()
            .filter_map(|new_rule| {
                svc.list_rules()
                    .iter()
                    .find(|r| r.id == new_rule.id)
                    .filter(|old_rule| old_rule.mode != new_rule.mode)
                    .map(|old_rule| (new_rule.id.0.clone(), old_rule.mode, new_rule.mode))
            })
            .collect();

        // Try fallible operation first
        let effective_rules = if enabled { rules } else { Vec::new() };
        let rule_count = effective_rules.len();

        match svc.reload_rules(effective_rules) {
            Ok(()) => {
                // Log global mode transition
                let old_mode = svc.mode();
                if old_mode != mode {
                    tracing::info!(
                        component = "ips",
                        old_mode = old_mode.as_str(),
                        new_mode = mode.as_str(),
                        "domain mode changed"
                    );
                }

                // Log per-rule mode changes
                for (rule_id, old_m, new_m) in &rule_mode_changes {
                    tracing::info!(
                        component = "ips",
                        rule_id = %rule_id,
                        old_mode = old_m.as_str(),
                        new_mode = new_m.as_str(),
                        "rule mode changed"
                    );
                }

                // Apply non-fallible state mutations
                svc.set_mode(mode);
                svc.set_enabled(enabled);
                svc.set_policy(policy);
                svc.reload_whitelist(whitelist);
                svc.set_sampling(sampling);

                drop(svc);
                self.metrics.record_config_reload("ips", "success");
                tracing::info!(
                    rule_count = rule_count,
                    enabled = enabled,
                    mode = mode.as_str(),
                    "IPS configuration reloaded successfully"
                );
                let audit_svc = self.audit_service.read().await;
                audit_svc.record_config_change(
                    AuditAction::ConfigChanged,
                    &format!("ips reloaded: {rule_count} rules, mode={}", mode.as_str()),
                );
                audit_svc.record_rule_change(
                    AuditComponent::Ips,
                    AuditAction::RuleUpdated,
                    ChangeActor::ConfigReload,
                    "ips-config",
                    None,
                    Some(format!(
                        "{{\"rule_count\":{rule_count},\"mode\":\"{}\"}}",
                        mode.as_str()
                    )),
                );
                drop(audit_svc);
                Ok(())
            }
            Err(e) => {
                drop(svc);
                self.metrics.record_config_reload("ips", "failure");
                tracing::warn!(error = %e, "IPS configuration reload failed");
                Err(anyhow::anyhow!("IPS reload failed: {e}"))
            }
        }
    }

    /// Reload L7 rules atomically with enabled awareness.
    pub async fn reload_l7(&self, rules: Vec<L7Rule>, enabled: bool) -> Result<(), anyhow::Error> {
        let _guard = self.reload_mutex.lock().await;

        let mut svc = self.l7_service.write().await;

        svc.set_enabled(enabled);

        let effective_rules = if enabled { rules } else { Vec::new() };
        let rule_count = effective_rules.len();

        match svc.reload_rules(effective_rules) {
            Ok(()) => {
                drop(svc);
                self.metrics.record_config_reload("l7", "success");
                tracing::info!(
                    rule_count = rule_count,
                    enabled = enabled,
                    "L7 configuration reloaded successfully"
                );
                let audit_svc = self.audit_service.read().await;
                audit_svc.record_config_change(
                    AuditAction::ConfigChanged,
                    &format!("l7 reloaded: {rule_count} rules"),
                );
                audit_svc.record_rule_change(
                    AuditComponent::L7,
                    AuditAction::RuleUpdated,
                    ChangeActor::ConfigReload,
                    "l7-config",
                    None,
                    Some(format!("{{\"rule_count\":{rule_count}}}")),
                );
                drop(audit_svc);
                Ok(())
            }
            Err(e) => {
                drop(svc);
                self.metrics.record_config_reload("l7", "failure");
                tracing::warn!(error = %e, "L7 configuration reload failed");
                Err(anyhow::anyhow!("L7 reload failed: {e}"))
            }
        }
    }

    /// Reload rate limit policies atomically with enabled awareness.
    pub async fn reload_ratelimit(
        &self,
        policies: Vec<RateLimitPolicy>,
        enabled: bool,
    ) -> Result<(), anyhow::Error> {
        let _guard = self.reload_mutex.lock().await;

        let mut svc = self.ratelimit_service.write().await;

        svc.set_enabled(enabled);

        let effective_policies = if enabled { policies } else { Vec::new() };
        let policy_count = effective_policies.len();

        match svc.reload_policies(effective_policies) {
            Ok(()) => {
                drop(svc);
                self.metrics.record_config_reload("ratelimit", "success");
                tracing::info!(
                    policy_count = policy_count,
                    enabled = enabled,
                    "ratelimit configuration reloaded successfully"
                );
                let audit_svc = self.audit_service.read().await;
                audit_svc.record_config_change(
                    AuditAction::ConfigChanged,
                    &format!("ratelimit reloaded: {policy_count} policies"),
                );
                audit_svc.record_rule_change(
                    AuditComponent::Ratelimit,
                    AuditAction::RuleUpdated,
                    ChangeActor::ConfigReload,
                    "ratelimit-config",
                    None,
                    Some(format!("{{\"policy_count\":{policy_count}}}")),
                );
                drop(audit_svc);
                Ok(())
            }
            Err(e) => {
                drop(svc);
                self.metrics.record_config_reload("ratelimit", "failure");
                tracing::warn!(error = %e, "ratelimit configuration reload failed");
                Err(anyhow::anyhow!("ratelimit reload failed: {e}"))
            }
        }
    }
    /// Reload `DDoS` policies atomically with enabled awareness.
    pub async fn reload_ddos(
        &self,
        policies: Vec<DdosPolicy>,
        enabled: bool,
    ) -> Result<(), anyhow::Error> {
        let _guard = self.reload_mutex.lock().await;

        let mut svc = self.ddos_service.write().await;

        svc.set_enabled(enabled);

        let effective_policies = if enabled { policies } else { Vec::new() };
        let policy_count = effective_policies.len();

        match svc.reload_policies(effective_policies) {
            Ok(()) => {
                drop(svc);
                self.metrics.record_config_reload("ddos", "success");
                tracing::info!(
                    policy_count = policy_count,
                    enabled = enabled,
                    "DDoS configuration reloaded successfully"
                );
                let audit_svc = self.audit_service.read().await;
                audit_svc.record_config_change(
                    AuditAction::ConfigChanged,
                    &format!("ddos reloaded: {policy_count} policies"),
                );
                audit_svc.record_rule_change(
                    AuditComponent::Ddos,
                    AuditAction::RuleUpdated,
                    ChangeActor::ConfigReload,
                    "ddos-config",
                    None,
                    Some(format!("{{\"policy_count\":{policy_count}}}")),
                );
                drop(audit_svc);
                Ok(())
            }
            Err(e) => {
                drop(svc);
                self.metrics.record_config_reload("ddos", "failure");
                tracing::warn!(error = %e, "DDoS configuration reload failed");
                Err(anyhow::anyhow!("ddos reload failed: {e}"))
            }
        }
    }

    /// Reload threat intel configuration: feeds, enabled, and mode.
    pub async fn reload_threatintel(
        &self,
        feeds: Vec<domain::threatintel::entity::FeedConfig>,
        enabled: bool,
        mode: DomainMode,
    ) -> Result<(), anyhow::Error> {
        let _guard = self.reload_mutex.lock().await;

        let mut svc = self.threatintel_service.write().await;

        let old_mode = svc.mode();
        if old_mode != mode {
            tracing::info!(
                component = "threatintel",
                old_mode = old_mode.as_str(),
                new_mode = mode.as_str(),
                "domain mode changed"
            );
        }

        svc.set_mode(mode);
        svc.set_enabled(enabled);
        svc.set_feeds(feeds);

        if !enabled && let Err(e) = svc.reload_iocs(Vec::new()) {
            drop(svc);
            self.metrics.record_config_reload("threatintel", "failure");
            tracing::warn!(error = %e, "threat intel clear failed");
            return Err(anyhow::anyhow!("threatintel reload failed: {e}"));
        }

        drop(svc);
        self.metrics.record_config_reload("threatintel", "success");
        tracing::info!(
            enabled = enabled,
            mode = mode.as_str(),
            "threat intel configuration reloaded successfully"
        );
        let audit_svc = self.audit_service.read().await;
        audit_svc.record_config_change(
            AuditAction::ConfigChanged,
            &format!(
                "threatintel reloaded: enabled={enabled}, mode={}",
                mode.as_str()
            ),
        );
        audit_svc.record_rule_change(
            AuditComponent::Threatintel,
            AuditAction::RuleUpdated,
            ChangeActor::ConfigReload,
            "threatintel-config",
            None,
            Some(format!(
                "{{\"enabled\":{enabled},\"mode\":\"{}\"}}",
                mode.as_str()
            )),
        );
        drop(audit_svc);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::audit::entity::AuditEntry;
    use domain::audit::error::AuditError;
    use domain::common::entity::{Protocol, RuleId, Severity};
    use domain::ddos::engine::DdosEngine;
    use domain::firewall::engine::FirewallEngine;
    use domain::firewall::entity::{FirewallAction, Scope};
    use domain::ids::engine::IdsEngine;
    use domain::ips::engine::IpsEngine;
    use domain::l7::engine::L7Engine;
    use domain::ratelimit::engine::RateLimitEngine;
    use domain::ratelimit::entity::{RateLimitAction, RateLimitAlgorithm, RateLimitScope};
    use domain::threatintel::engine::ThreatIntelEngine;
    use ports::secondary::audit_sink::AuditSink;
    use ports::secondary::metrics_port::{
        AlertMetrics, ConfigMetrics, DnsMetrics, DomainMetrics, EventMetrics, FirewallMetrics,
        IpsMetrics, PacketMetrics, SystemMetrics,
    };
    use std::sync::atomic::{AtomicU32, Ordering};

    struct TestMetrics {
        success_count: AtomicU32,
        failure_count: AtomicU32,
    }

    impl TestMetrics {
        fn new() -> Self {
            Self {
                success_count: AtomicU32::new(0),
                failure_count: AtomicU32::new(0),
            }
        }
    }

    impl PacketMetrics for TestMetrics {}
    impl FirewallMetrics for TestMetrics {}
    impl AlertMetrics for TestMetrics {}
    impl IpsMetrics for TestMetrics {}
    impl DnsMetrics for TestMetrics {}
    impl DomainMetrics for TestMetrics {}
    impl SystemMetrics for TestMetrics {}
    impl ConfigMetrics for TestMetrics {
        fn record_config_reload(&self, _component: &str, result: &str) {
            match result {
                "success" => self.success_count.fetch_add(1, Ordering::Relaxed),
                "failure" => self.failure_count.fetch_add(1, Ordering::Relaxed),
                _ => 0,
            };
        }
    }
    impl EventMetrics for TestMetrics {}

    fn make_fw_rule(id: &str, priority: u32) -> FirewallRule {
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
        }
    }

    fn make_ids_rule(id: &str) -> IdsRule {
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

    struct NoopAuditSink;
    impl AuditSink for NoopAuditSink {
        fn write_entry(&self, _entry: &AuditEntry) -> Result<(), AuditError> {
            Ok(())
        }
    }

    #[allow(clippy::type_complexity)]
    fn make_services() -> (
        Arc<RwLock<FirewallAppService>>,
        Arc<RwLock<IdsAppService>>,
        Arc<RwLock<IpsAppService>>,
        Arc<RwLock<L7AppService>>,
        Arc<RwLock<RateLimitAppService>>,
        Arc<RwLock<DdosAppService>>,
        Arc<RwLock<ThreatIntelAppService>>,
        Arc<RwLock<AuditAppService>>,
        Arc<TestMetrics>,
    ) {
        let metrics = Arc::new(TestMetrics::new());
        let mut fw_svc = FirewallAppService::new(
            FirewallEngine::new(),
            None,
            Arc::clone(&metrics) as Arc<dyn MetricsPort>,
        );
        // Disable anti-lockout in tests to avoid extra synthetic rules.
        fw_svc.set_anti_lockout(crate::firewall_service_impl::AntiLockoutSettings {
            enabled: false,
            ..Default::default()
        });
        let ids_svc = IdsAppService::new(
            IdsEngine::new(),
            None,
            Arc::clone(&metrics) as Arc<dyn MetricsPort>,
        );
        let ips_svc = IpsAppService::new(
            IpsEngine::default(),
            Arc::clone(&metrics) as Arc<dyn MetricsPort>,
        );
        let l7_svc = L7AppService::new(
            L7Engine::new(),
            Arc::clone(&metrics) as Arc<dyn MetricsPort>,
        );
        let rl_svc = RateLimitAppService::new(
            RateLimitEngine::new(),
            Arc::clone(&metrics) as Arc<dyn MetricsPort>,
        );
        let ddos_svc = DdosAppService::new(
            DdosEngine::new(),
            Arc::clone(&metrics) as Arc<dyn MetricsPort>,
        );
        let ti_svc = ThreatIntelAppService::new(
            ThreatIntelEngine::new(1_000_000),
            Arc::clone(&metrics) as Arc<dyn MetricsPort>,
            vec![],
        );
        let audit_sink: Arc<dyn AuditSink> = Arc::new(NoopAuditSink);
        let audit_svc = AuditAppService::new(audit_sink);
        (
            Arc::new(RwLock::new(fw_svc)),
            Arc::new(RwLock::new(ids_svc)),
            Arc::new(RwLock::new(ips_svc)),
            Arc::new(RwLock::new(l7_svc)),
            Arc::new(RwLock::new(rl_svc)),
            Arc::new(RwLock::new(ddos_svc)),
            Arc::new(RwLock::new(ti_svc)),
            Arc::new(RwLock::new(audit_svc)),
            metrics,
        )
    }

    // ── Firewall reload tests ──────────────────────────────────────

    #[tokio::test]
    async fn reload_success_updates_rules_and_metric() {
        let (fw_svc, ids_svc, ips_svc, l7_svc, rl_svc, ddos_svc, ti_svc, audit_svc, metrics) =
            make_services();
        let reload = ConfigReloadService::new(
            Arc::clone(&fw_svc),
            Arc::clone(&ids_svc),
            Arc::clone(&ips_svc),
            Arc::clone(&l7_svc),
            Arc::clone(&rl_svc),
            Arc::clone(&ddos_svc),
            Arc::clone(&ti_svc),
            Arc::clone(&audit_svc),
            metrics.clone(),
        );

        let rules = vec![make_fw_rule("fw-001", 10), make_fw_rule("fw-002", 20)];
        reload.reload(rules, true, DomainMode::Alert).await.unwrap();

        let svc = fw_svc.read().await;
        assert_eq!(svc.rule_count(), 2);
        assert_eq!(metrics.success_count.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.failure_count.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn reload_replaces_previous_rules() {
        let (fw_svc, ids_svc, ips_svc, l7_svc, rl_svc, ddos_svc, ti_svc, audit_svc, metrics) =
            make_services();
        let reload = ConfigReloadService::new(
            Arc::clone(&fw_svc),
            Arc::clone(&ids_svc),
            Arc::clone(&ips_svc),
            Arc::clone(&l7_svc),
            Arc::clone(&rl_svc),
            Arc::clone(&ddos_svc),
            Arc::clone(&ti_svc),
            Arc::clone(&audit_svc),
            metrics.clone(),
        );

        reload
            .reload(
                vec![make_fw_rule("old-1", 1), make_fw_rule("old-2", 2)],
                true,
                DomainMode::Alert,
            )
            .await
            .unwrap();
        assert_eq!(fw_svc.read().await.rule_count(), 2);

        reload
            .reload(vec![make_fw_rule("new-1", 10)], true, DomainMode::Alert)
            .await
            .unwrap();
        assert_eq!(fw_svc.read().await.rule_count(), 1);
        assert_eq!(fw_svc.read().await.list_rules()[0].id.0, "new-1");

        assert_eq!(metrics.success_count.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn reload_with_duplicate_ids_fails_and_records_metric() {
        let (fw_svc, ids_svc, ips_svc, l7_svc, rl_svc, ddos_svc, ti_svc, audit_svc, metrics) =
            make_services();
        let reload = ConfigReloadService::new(
            Arc::clone(&fw_svc),
            Arc::clone(&ids_svc),
            Arc::clone(&ips_svc),
            Arc::clone(&l7_svc),
            Arc::clone(&rl_svc),
            Arc::clone(&ddos_svc),
            Arc::clone(&ti_svc),
            Arc::clone(&audit_svc),
            metrics.clone(),
        );

        let rules = vec![make_fw_rule("fw-001", 10), make_fw_rule("fw-001", 20)];
        let result = reload.reload(rules, true, DomainMode::Alert).await;

        assert!(result.is_err());
        assert_eq!(metrics.failure_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn reload_disabled_clears_rules() {
        let (fw_svc, ids_svc, ips_svc, l7_svc, rl_svc, ddos_svc, ti_svc, audit_svc, metrics) =
            make_services();
        let reload = ConfigReloadService::new(
            Arc::clone(&fw_svc),
            Arc::clone(&ids_svc),
            Arc::clone(&ips_svc),
            Arc::clone(&l7_svc),
            Arc::clone(&rl_svc),
            Arc::clone(&ddos_svc),
            Arc::clone(&ti_svc),
            Arc::clone(&audit_svc),
            metrics.clone(),
        );

        reload
            .reload(vec![make_fw_rule("fw-001", 10)], true, DomainMode::Block)
            .await
            .unwrap();
        assert_eq!(fw_svc.read().await.rule_count(), 1);

        reload
            .reload(vec![make_fw_rule("fw-001", 10)], false, DomainMode::Block)
            .await
            .unwrap();
        assert_eq!(fw_svc.read().await.rule_count(), 0);
    }

    #[tokio::test]
    async fn reload_mode_change_updates_service() {
        let (fw_svc, ids_svc, ips_svc, l7_svc, rl_svc, ddos_svc, ti_svc, audit_svc, metrics) =
            make_services();
        let reload = ConfigReloadService::new(
            Arc::clone(&fw_svc),
            Arc::clone(&ids_svc),
            Arc::clone(&ips_svc),
            Arc::clone(&l7_svc),
            Arc::clone(&rl_svc),
            Arc::clone(&ddos_svc),
            Arc::clone(&ti_svc),
            Arc::clone(&audit_svc),
            metrics.clone(),
        );

        reload
            .reload(vec![make_fw_rule("fw-001", 10)], true, DomainMode::Alert)
            .await
            .unwrap();
        assert_eq!(fw_svc.read().await.mode(), DomainMode::Alert);

        reload
            .reload(vec![make_fw_rule("fw-001", 10)], true, DomainMode::Block)
            .await
            .unwrap();
        assert_eq!(fw_svc.read().await.mode(), DomainMode::Block);

        assert_eq!(metrics.success_count.load(Ordering::Relaxed), 2);
    }

    // ── IDS reload tests ───────────────────────────────────────────

    #[tokio::test]
    async fn ids_reload_success() {
        let (fw_svc, ids_svc, ips_svc, l7_svc, rl_svc, ddos_svc, ti_svc, audit_svc, metrics) =
            make_services();
        let reload = ConfigReloadService::new(
            Arc::clone(&fw_svc),
            Arc::clone(&ids_svc),
            Arc::clone(&ips_svc),
            Arc::clone(&l7_svc),
            Arc::clone(&rl_svc),
            Arc::clone(&ddos_svc),
            Arc::clone(&ti_svc),
            Arc::clone(&audit_svc),
            metrics.clone(),
        );

        let rules = vec![make_ids_rule("ids-001"), make_ids_rule("ids-002")];
        reload
            .reload_ids(rules, true, DomainMode::Alert, SamplingMode::None)
            .await
            .unwrap();

        let svc = ids_svc.read().await;
        assert_eq!(svc.rule_count(), 2);
        assert_eq!(metrics.success_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn ids_reload_disabled_clears_rules() {
        let (fw_svc, ids_svc, ips_svc, l7_svc, rl_svc, ddos_svc, ti_svc, audit_svc, metrics) =
            make_services();
        let reload = ConfigReloadService::new(
            Arc::clone(&fw_svc),
            Arc::clone(&ids_svc),
            Arc::clone(&ips_svc),
            Arc::clone(&l7_svc),
            Arc::clone(&rl_svc),
            Arc::clone(&ddos_svc),
            Arc::clone(&ti_svc),
            Arc::clone(&audit_svc),
            metrics.clone(),
        );

        reload
            .reload_ids(
                vec![make_ids_rule("ids-001")],
                true,
                DomainMode::Alert,
                SamplingMode::None,
            )
            .await
            .unwrap();
        assert_eq!(ids_svc.read().await.rule_count(), 1);

        reload
            .reload_ids(
                vec![make_ids_rule("ids-001")],
                false,
                DomainMode::Alert,
                SamplingMode::None,
            )
            .await
            .unwrap();
        assert_eq!(ids_svc.read().await.rule_count(), 0);
    }

    #[tokio::test]
    async fn ids_reload_failure_records_metric() {
        let (fw_svc, ids_svc, ips_svc, l7_svc, rl_svc, ddos_svc, ti_svc, audit_svc, metrics) =
            make_services();
        let reload = ConfigReloadService::new(
            Arc::clone(&fw_svc),
            Arc::clone(&ids_svc),
            Arc::clone(&ips_svc),
            Arc::clone(&l7_svc),
            Arc::clone(&rl_svc),
            Arc::clone(&ddos_svc),
            Arc::clone(&ti_svc),
            Arc::clone(&audit_svc),
            metrics.clone(),
        );

        // Duplicate IDs should fail
        let rules = vec![make_ids_rule("ids-001"), make_ids_rule("ids-001")];
        let result = reload
            .reload_ids(rules, true, DomainMode::Alert, SamplingMode::None)
            .await;

        assert!(result.is_err());
        assert_eq!(metrics.failure_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn ids_reload_mode_change() {
        let (fw_svc, ids_svc, ips_svc, l7_svc, rl_svc, ddos_svc, ti_svc, audit_svc, metrics) =
            make_services();
        let reload = ConfigReloadService::new(
            Arc::clone(&fw_svc),
            Arc::clone(&ids_svc),
            Arc::clone(&ips_svc),
            Arc::clone(&l7_svc),
            Arc::clone(&rl_svc),
            Arc::clone(&ddos_svc),
            Arc::clone(&ti_svc),
            Arc::clone(&audit_svc),
            metrics.clone(),
        );

        reload
            .reload_ids(
                vec![make_ids_rule("ids-001")],
                true,
                DomainMode::Alert,
                SamplingMode::None,
            )
            .await
            .unwrap();
        assert_eq!(ids_svc.read().await.mode(), DomainMode::Alert);

        reload
            .reload_ids(
                vec![make_ids_rule("ids-001")],
                true,
                DomainMode::Block,
                SamplingMode::None,
            )
            .await
            .unwrap();
        assert_eq!(ids_svc.read().await.mode(), DomainMode::Block);
    }

    // ── IPS reload tests ───────────────────────────────────────────

    fn make_ips_rule(id: &str, mode: DomainMode) -> IdsRule {
        IdsRule {
            id: RuleId(id.to_string()),
            description: format!("IPS {id}"),
            severity: Severity::High,
            mode,
            protocol: Protocol::Tcp,
            dst_port: Some(22),
            pattern: String::new(),
            enabled: true,
            threshold: None,
            domain_pattern: None,
            domain_match_mode: None,
        }
    }

    #[tokio::test]
    async fn ips_reload_success() {
        let (fw_svc, ids_svc, ips_svc, l7_svc, rl_svc, ddos_svc, ti_svc, audit_svc, metrics) =
            make_services();
        let reload = ConfigReloadService::new(
            Arc::clone(&fw_svc),
            Arc::clone(&ids_svc),
            Arc::clone(&ips_svc),
            Arc::clone(&l7_svc),
            Arc::clone(&rl_svc),
            Arc::clone(&ddos_svc),
            Arc::clone(&ti_svc),
            Arc::clone(&audit_svc),
            metrics.clone(),
        );

        let rules = vec![make_ips_rule("ips-001", DomainMode::Block)];
        reload
            .reload_ips(
                rules,
                Vec::new(),
                true,
                DomainMode::Block,
                IpsPolicy::default(),
                SamplingMode::None,
            )
            .await
            .unwrap();

        let svc = ips_svc.read().await;
        assert_eq!(svc.rule_count(), 1);
        assert_eq!(svc.mode(), DomainMode::Block);
        assert_eq!(metrics.success_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn ips_reload_disabled_clears_rules() {
        let (fw_svc, ids_svc, ips_svc, l7_svc, rl_svc, ddos_svc, ti_svc, audit_svc, metrics) =
            make_services();
        let reload = ConfigReloadService::new(
            Arc::clone(&fw_svc),
            Arc::clone(&ids_svc),
            Arc::clone(&ips_svc),
            Arc::clone(&l7_svc),
            Arc::clone(&rl_svc),
            Arc::clone(&ddos_svc),
            Arc::clone(&ti_svc),
            Arc::clone(&audit_svc),
            metrics.clone(),
        );

        reload
            .reload_ips(
                vec![make_ips_rule("ips-001", DomainMode::Block)],
                Vec::new(),
                true,
                DomainMode::Block,
                IpsPolicy::default(),
                SamplingMode::None,
            )
            .await
            .unwrap();
        assert_eq!(ips_svc.read().await.rule_count(), 1);

        reload
            .reload_ips(
                vec![make_ips_rule("ips-001", DomainMode::Block)],
                Vec::new(),
                false,
                DomainMode::Block,
                IpsPolicy::default(),
                SamplingMode::None,
            )
            .await
            .unwrap();
        assert_eq!(ips_svc.read().await.rule_count(), 0);
    }

    #[tokio::test]
    async fn ips_reload_updates_whitelist() {
        let (fw_svc, ids_svc, ips_svc, l7_svc, rl_svc, ddos_svc, ti_svc, audit_svc, metrics) =
            make_services();
        let reload = ConfigReloadService::new(
            Arc::clone(&fw_svc),
            Arc::clone(&ids_svc),
            Arc::clone(&ips_svc),
            Arc::clone(&l7_svc),
            Arc::clone(&rl_svc),
            Arc::clone(&ddos_svc),
            Arc::clone(&ti_svc),
            Arc::clone(&audit_svc),
            metrics.clone(),
        );

        let wl = vec![
            WhitelistEntry::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
                None,
            )
            .unwrap(),
        ];

        reload
            .reload_ips(
                Vec::new(),
                wl,
                true,
                DomainMode::Alert,
                IpsPolicy::default(),
                SamplingMode::None,
            )
            .await
            .unwrap();

        assert_eq!(metrics.success_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn ips_reload_mode_transition() {
        let (fw_svc, ids_svc, ips_svc, l7_svc, rl_svc, ddos_svc, ti_svc, audit_svc, metrics) =
            make_services();
        let reload = ConfigReloadService::new(
            Arc::clone(&fw_svc),
            Arc::clone(&ids_svc),
            Arc::clone(&ips_svc),
            Arc::clone(&l7_svc),
            Arc::clone(&rl_svc),
            Arc::clone(&ddos_svc),
            Arc::clone(&ti_svc),
            Arc::clone(&audit_svc),
            metrics.clone(),
        );

        reload
            .reload_ips(
                Vec::new(),
                Vec::new(),
                true,
                DomainMode::Alert,
                IpsPolicy::default(),
                SamplingMode::None,
            )
            .await
            .unwrap();
        assert_eq!(ips_svc.read().await.mode(), DomainMode::Alert);

        reload
            .reload_ips(
                Vec::new(),
                Vec::new(),
                true,
                DomainMode::Block,
                IpsPolicy::default(),
                SamplingMode::None,
            )
            .await
            .unwrap();
        assert_eq!(ips_svc.read().await.mode(), DomainMode::Block);
    }

    #[tokio::test]
    async fn ips_reload_failure_records_metric() {
        let (fw_svc, ids_svc, ips_svc, l7_svc, rl_svc, ddos_svc, ti_svc, audit_svc, metrics) =
            make_services();
        let reload = ConfigReloadService::new(
            Arc::clone(&fw_svc),
            Arc::clone(&ids_svc),
            Arc::clone(&ips_svc),
            Arc::clone(&l7_svc),
            Arc::clone(&rl_svc),
            Arc::clone(&ddos_svc),
            Arc::clone(&ti_svc),
            Arc::clone(&audit_svc),
            metrics.clone(),
        );

        // Duplicate IDs should fail
        let rules = vec![
            make_ips_rule("ips-001", DomainMode::Block),
            make_ips_rule("ips-001", DomainMode::Alert),
        ];
        let result = reload
            .reload_ips(
                rules,
                Vec::new(),
                true,
                DomainMode::Block,
                IpsPolicy::default(),
                SamplingMode::None,
            )
            .await;

        assert!(result.is_err());
        assert_eq!(metrics.failure_count.load(Ordering::Relaxed), 1);
    }

    // ── L7 reload tests ─────────────────────────────────────────────

    fn make_l7_rule(id: &str, priority: u32) -> L7Rule {
        use domain::l7::entity::L7Matcher;

        L7Rule {
            id: RuleId(id.to_string()),
            priority,
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

    #[tokio::test]
    async fn l7_reload_success() {
        let (fw_svc, ids_svc, ips_svc, l7_svc, rl_svc, ddos_svc, ti_svc, audit_svc, metrics) =
            make_services();
        let reload = ConfigReloadService::new(
            Arc::clone(&fw_svc),
            Arc::clone(&ids_svc),
            Arc::clone(&ips_svc),
            Arc::clone(&l7_svc),
            Arc::clone(&rl_svc),
            Arc::clone(&ddos_svc),
            Arc::clone(&ti_svc),
            Arc::clone(&audit_svc),
            metrics.clone(),
        );

        let rules = vec![make_l7_rule("l7-001", 10), make_l7_rule("l7-002", 20)];
        reload.reload_l7(rules, true).await.unwrap();

        let svc = l7_svc.read().await;
        assert_eq!(svc.rule_count(), 2);
        assert_eq!(metrics.success_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn l7_reload_disabled_clears_rules() {
        let (fw_svc, ids_svc, ips_svc, l7_svc, rl_svc, ddos_svc, ti_svc, audit_svc, metrics) =
            make_services();
        let reload = ConfigReloadService::new(
            Arc::clone(&fw_svc),
            Arc::clone(&ids_svc),
            Arc::clone(&ips_svc),
            Arc::clone(&l7_svc),
            Arc::clone(&rl_svc),
            Arc::clone(&ddos_svc),
            Arc::clone(&ti_svc),
            Arc::clone(&audit_svc),
            metrics.clone(),
        );

        reload
            .reload_l7(vec![make_l7_rule("l7-001", 10)], true)
            .await
            .unwrap();
        assert_eq!(l7_svc.read().await.rule_count(), 1);

        reload
            .reload_l7(vec![make_l7_rule("l7-001", 10)], false)
            .await
            .unwrap();
        assert_eq!(l7_svc.read().await.rule_count(), 0);
    }

    #[tokio::test]
    async fn l7_reload_failure_records_metric() {
        let (fw_svc, ids_svc, ips_svc, l7_svc, rl_svc, ddos_svc, ti_svc, audit_svc, metrics) =
            make_services();
        let reload = ConfigReloadService::new(
            Arc::clone(&fw_svc),
            Arc::clone(&ids_svc),
            Arc::clone(&ips_svc),
            Arc::clone(&l7_svc),
            Arc::clone(&rl_svc),
            Arc::clone(&ddos_svc),
            Arc::clone(&ti_svc),
            Arc::clone(&audit_svc),
            metrics.clone(),
        );

        // Duplicate IDs should fail
        let rules = vec![make_l7_rule("l7-001", 10), make_l7_rule("l7-001", 20)];
        let result = reload.reload_l7(rules, true).await;

        assert!(result.is_err());
        assert_eq!(metrics.failure_count.load(Ordering::Relaxed), 1);
    }

    // ── Ratelimit reload tests ──────────────────────────────────────

    fn make_rl_policy(id: &str, rate: u64, burst: u64) -> RateLimitPolicy {
        RateLimitPolicy {
            id: RuleId(id.to_string()),
            scope: RateLimitScope::SourceIp,
            rate,
            burst,
            action: RateLimitAction::Drop,
            src_ip: None,
            enabled: true,
            algorithm: RateLimitAlgorithm::default(),
        }
    }

    #[tokio::test]
    async fn ratelimit_reload_success() {
        let (fw_svc, ids_svc, ips_svc, l7_svc, rl_svc, ddos_svc, ti_svc, audit_svc, metrics) =
            make_services();
        let reload = ConfigReloadService::new(
            Arc::clone(&fw_svc),
            Arc::clone(&ids_svc),
            Arc::clone(&ips_svc),
            Arc::clone(&l7_svc),
            Arc::clone(&rl_svc),
            Arc::clone(&ddos_svc),
            Arc::clone(&ti_svc),
            Arc::clone(&audit_svc),
            metrics.clone(),
        );

        let policies = vec![make_rl_policy("rl-001", 1000, 2000)];
        reload.reload_ratelimit(policies, true).await.unwrap();

        let svc = rl_svc.read().await;
        assert_eq!(svc.policy_count(), 1);
        assert_eq!(metrics.success_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn ratelimit_reload_disabled_clears_policies() {
        let (fw_svc, ids_svc, ips_svc, l7_svc, rl_svc, ddos_svc, ti_svc, audit_svc, metrics) =
            make_services();
        let reload = ConfigReloadService::new(
            Arc::clone(&fw_svc),
            Arc::clone(&ids_svc),
            Arc::clone(&ips_svc),
            Arc::clone(&l7_svc),
            Arc::clone(&rl_svc),
            Arc::clone(&ddos_svc),
            Arc::clone(&ti_svc),
            Arc::clone(&audit_svc),
            metrics.clone(),
        );

        reload
            .reload_ratelimit(vec![make_rl_policy("rl-001", 1000, 2000)], true)
            .await
            .unwrap();
        assert_eq!(rl_svc.read().await.policy_count(), 1);

        reload
            .reload_ratelimit(vec![make_rl_policy("rl-001", 1000, 2000)], false)
            .await
            .unwrap();
        assert_eq!(rl_svc.read().await.policy_count(), 0);
    }

    #[tokio::test]
    async fn ratelimit_reload_failure_records_metric() {
        let (fw_svc, ids_svc, ips_svc, l7_svc, rl_svc, ddos_svc, ti_svc, audit_svc, metrics) =
            make_services();
        let reload = ConfigReloadService::new(
            Arc::clone(&fw_svc),
            Arc::clone(&ids_svc),
            Arc::clone(&ips_svc),
            Arc::clone(&l7_svc),
            Arc::clone(&rl_svc),
            Arc::clone(&ddos_svc),
            Arc::clone(&ti_svc),
            Arc::clone(&audit_svc),
            metrics.clone(),
        );

        // Duplicate IDs should fail
        let policies = vec![
            make_rl_policy("rl-001", 1000, 2000),
            make_rl_policy("rl-001", 500, 1000),
        ];
        let result = reload.reload_ratelimit(policies, true).await;

        assert!(result.is_err());
        assert_eq!(metrics.failure_count.load(Ordering::Relaxed), 1);
    }
}
