use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use application::alias_service_impl::AliasAppService;
use application::audit_service_impl::AuditAppService;
use application::conntrack_service_impl::ConnTrackAppService;
use application::ddos_service_impl::DdosAppService;
use application::dlp_service_impl::DlpAppService;
use application::dns_blocklist_service_impl::DnsBlocklistAppService;
use application::dns_cache_service_impl::DnsCacheAppService;
use application::domain_reputation_service_impl::DomainReputationAppService;
use application::firewall_service_impl::FirewallAppService;
use application::ids_service_impl::IdsAppService;
use application::ips_service_impl::IpsAppService;
use application::l7_service_impl::L7AppService;
use application::nat_service_impl::NatAppService;
use application::ratelimit_service_impl::RateLimitAppService;
use application::routing_service_impl::RoutingAppService;
use application::threatintel_service_impl::ThreatIntelAppService;
use infrastructure::config::AgentConfig;
use infrastructure::metrics::AgentMetrics;
use ports::secondary::alert_store::AlertStore;
use ports::secondary::auth_provider::AuthProvider;
use tokio::sync::{RwLock, mpsc};

/// Shared application state for the REST API server.
///
/// Passed to Axum handlers via `State(Arc<AppState>)`.
pub struct AppState {
    pub metrics: Arc<AgentMetrics>,
    pub ebpf_loaded: Arc<AtomicBool>,
    pub start_time: Instant,
    pub version: &'static str,
    pub firewall_service: Arc<RwLock<FirewallAppService>>,
    pub ips_service: Arc<RwLock<IpsAppService>>,
    pub l7_service: Arc<RwLock<L7AppService>>,
    pub ratelimit_service: Arc<RwLock<RateLimitAppService>>,
    pub threatintel_service: Arc<RwLock<ThreatIntelAppService>>,
    pub audit_service: Arc<RwLock<AuditAppService>>,
    pub ids_service: Option<Arc<RwLock<IdsAppService>>>,
    pub conntrack_service: Option<Arc<RwLock<ConnTrackAppService>>>,
    pub ddos_service: Option<Arc<RwLock<DdosAppService>>>,
    pub dlp_service: Option<Arc<RwLock<DlpAppService>>>,
    pub nat_service: Option<Arc<RwLock<NatAppService>>>,
    pub alias_service: Option<Arc<RwLock<AliasAppService>>>,
    pub routing_service: Option<Arc<RwLock<RoutingAppService>>>,
    pub dns_cache_service: Option<Arc<DnsCacheAppService>>,
    pub dns_blocklist_service: Option<Arc<DnsBlocklistAppService>>,
    pub domain_reputation_service: Option<Arc<DomainReputationAppService>>,
    pub alert_store: Option<Arc<dyn AlertStore>>,
    pub auth_provider: Option<Arc<dyn AuthProvider>>,
    pub metrics_auth_required: bool,
    pub config: Arc<RwLock<AgentConfig>>,
    pub reload_trigger: mpsc::Sender<()>,
    pub ebpf_program_status: Arc<RwLock<HashMap<String, bool>>>,
}

impl AppState {
    #[allow(clippy::similar_names, clippy::too_many_arguments)]
    pub fn new(
        metrics: Arc<AgentMetrics>,
        ebpf_loaded: Arc<AtomicBool>,
        firewall_service: Arc<RwLock<FirewallAppService>>,
        ips_service: Arc<RwLock<IpsAppService>>,
        l7_service: Arc<RwLock<L7AppService>>,
        ratelimit_service: Arc<RwLock<RateLimitAppService>>,
        threatintel_service: Arc<RwLock<ThreatIntelAppService>>,
        audit_service: Arc<RwLock<AuditAppService>>,
        config: Arc<RwLock<AgentConfig>>,
        reload_trigger: mpsc::Sender<()>,
        ebpf_program_status: Arc<RwLock<HashMap<String, bool>>>,
    ) -> Self {
        Self {
            metrics,
            ebpf_loaded,
            start_time: Instant::now(),
            version: env!("CARGO_PKG_VERSION"),
            firewall_service,
            ips_service,
            l7_service,
            ratelimit_service,
            threatintel_service,
            audit_service,
            ids_service: None,
            conntrack_service: None,
            ddos_service: None,
            dlp_service: None,
            nat_service: None,
            alias_service: None,
            routing_service: None,
            dns_cache_service: None,
            dns_blocklist_service: None,
            domain_reputation_service: None,
            alert_store: None,
            auth_provider: None,
            metrics_auth_required: false,
            config,
            reload_trigger,
            ebpf_program_status,
        }
    }

    /// Attach an IDS service.
    #[must_use]
    pub fn with_ids_service(mut self, svc: Arc<RwLock<IdsAppService>>) -> Self {
        self.ids_service = Some(svc);
        self
    }

    /// Attach a conntrack service.
    #[must_use]
    pub fn with_conntrack_service(mut self, svc: Arc<RwLock<ConnTrackAppService>>) -> Self {
        self.conntrack_service = Some(svc);
        self
    }

    /// Attach a `DDoS` protection service.
    #[must_use]
    pub fn with_ddos_service(mut self, svc: Arc<RwLock<DdosAppService>>) -> Self {
        self.ddos_service = Some(svc);
        self
    }

    /// Attach a DLP service.
    #[must_use]
    pub fn with_dlp_service(mut self, svc: Arc<RwLock<DlpAppService>>) -> Self {
        self.dlp_service = Some(svc);
        self
    }

    /// Attach a NAT service.
    #[must_use]
    pub fn with_nat_service(mut self, svc: Arc<RwLock<NatAppService>>) -> Self {
        self.nat_service = Some(svc);
        self
    }

    /// Attach an alias service.
    #[must_use]
    pub fn with_alias_service(mut self, svc: Arc<RwLock<AliasAppService>>) -> Self {
        self.alias_service = Some(svc);
        self
    }

    /// Attach a routing service.
    #[must_use]
    pub fn with_routing_service(mut self, svc: Arc<RwLock<RoutingAppService>>) -> Self {
        self.routing_service = Some(svc);
        self
    }

    /// Attach DNS intelligence services.
    #[must_use]
    pub fn with_dns_services(
        mut self,
        cache: Arc<DnsCacheAppService>,
        blocklist: Arc<DnsBlocklistAppService>,
    ) -> Self {
        self.dns_cache_service = Some(cache);
        self.dns_blocklist_service = Some(blocklist);
        self
    }

    /// Attach a domain reputation service.
    #[must_use]
    pub fn with_domain_reputation_service(mut self, svc: Arc<DomainReputationAppService>) -> Self {
        self.domain_reputation_service = Some(svc);
        self
    }

    /// Attach an alert store for false-positive marking and alert queries.
    #[must_use]
    pub fn with_alert_store(mut self, store: Arc<dyn AlertStore>) -> Self {
        self.alert_store = Some(store);
        self
    }

    /// Attach a JWT auth provider and configure metrics auth.
    #[must_use]
    pub fn with_auth_provider(
        mut self,
        provider: Arc<dyn AuthProvider>,
        metrics_auth_required: bool,
    ) -> Self {
        self.auth_provider = Some(provider);
        self.metrics_auth_required = metrics_auth_required;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    use domain::audit::entity::AuditEntry;
    use domain::audit::error::AuditError;
    use domain::firewall::engine::FirewallEngine;
    use domain::ips::engine::IpsEngine;
    use domain::l7::engine::L7Engine;
    use domain::ratelimit::engine::RateLimitEngine;
    use domain::threatintel::engine::ThreatIntelEngine;
    use ports::secondary::audit_sink::AuditSink;
    use ports::secondary::metrics_port::MetricsPort;
    use ports::test_utils::NoopMetrics;

    struct NoopSink;
    impl AuditSink for NoopSink {
        fn write_entry(&self, _entry: &AuditEntry) -> Result<(), AuditError> {
            Ok(())
        }
    }

    #[test]
    fn new_creates_valid_state() {
        let metrics = Arc::new(AgentMetrics::new());
        let ebpf = Arc::new(AtomicBool::new(false));
        let noop: Arc<dyn MetricsPort> = Arc::new(NoopMetrics);
        let fw_svc = FirewallAppService::new(FirewallEngine::new(), None, Arc::clone(&noop));
        let ips_svc = IpsAppService::new(IpsEngine::default(), Arc::clone(&noop));
        let l7_svc = L7AppService::new(L7Engine::new(), Arc::clone(&noop));
        let rl_svc = RateLimitAppService::new(RateLimitEngine::new(), Arc::clone(&noop));
        let ti_svc = ThreatIntelAppService::new(
            ThreatIntelEngine::new(1_000_000),
            Arc::clone(&noop),
            vec![],
        );
        let audit_svc = AuditAppService::new(Arc::new(NoopSink) as Arc<dyn AuditSink>);
        let (reload_tx, _reload_rx) = tokio::sync::mpsc::channel(1);
        let state = AppState::new(
            metrics,
            ebpf,
            Arc::new(RwLock::new(fw_svc)),
            Arc::new(RwLock::new(ips_svc)),
            Arc::new(RwLock::new(l7_svc)),
            Arc::new(RwLock::new(rl_svc)),
            Arc::new(RwLock::new(ti_svc)),
            Arc::new(RwLock::new(audit_svc)),
            Arc::new(RwLock::new(
                AgentConfig::from_yaml("agent:\n  interfaces: [eth0]").unwrap(),
            )),
            reload_tx,
            Arc::new(RwLock::new(HashMap::new())),
        );

        assert!(!state.ebpf_loaded.load(Ordering::Relaxed));
        assert!(!state.version.is_empty());
    }
}
