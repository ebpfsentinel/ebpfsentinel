use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use adapters::alert::email_sender::EmailAlertSender;
use adapters::alert::log_sender::LogAlertSender;
use adapters::alert::webhook_sender::WebhookAlertSender;
use adapters::audit::log_audit_sink::LogAuditSink;
use adapters::auth::jwt_provider::JwtAuthProvider;
use adapters::auth::oidc_provider::{self, OidcAuthProvider};
use adapters::ebpf::{
    ConfigFlagsManager, ConnTrackMapManager, DdosSynConfigManager, DlpEventReader, DnsEventReader,
    EbpfLoader, EbpfMapWriteAdapter, EventReader, FirewallMapManager, IdsMapManager,
    InterfaceGroupsManager, IpSetMapManager, L7PortsManager, LpmCoordinator, MetricsReader,
    NatMapManager, QosMapManager, RateLimitLpmManager, RateLimitMapManager, ScrubConfigManager,
    SyncookieSecretManager, ThreatIntelMapManager,
};
use adapters::grpc::server::{GrpcTlsConfig, run_grpc_server};
use adapters::http::tls::load_rustls_config;
use adapters::http::{AppState, run_http_server};
use adapters::storage::redb_alert_store::RedbAlertStore;
use adapters::storage::redb_audit_store::RedbAuditStore;
use adapters::storage::redb_rule_change_store::RedbRuleChangeStore;
use application::alert_pipeline::AlertPipeline;
use application::alias_service_impl::AliasAppService;
use application::audit_service_impl::AuditAppService;
use application::config_reload::ConfigReloadService;
use application::conntrack_service_impl::ConnTrackAppService;
use application::dlp_service_impl::DlpAppService;
use application::dns_blocklist_service_impl::DnsBlocklistAppService;
use application::dns_cache_service_impl::DnsCacheAppService;
use application::domain_reputation_service_impl::DomainReputationAppService;
use application::firewall_service_impl::FirewallAppService;
use application::ids_service_impl::IdsAppService;
use application::ips_service_impl::{IpsAppService, IpsBlacklistAdapter};
use application::l7_service_impl::L7AppService;
use application::nat_service_impl::NatAppService;
use application::packet_pipeline::{AgentEvent, EventDispatcher};
use application::ratelimit_service_impl::RateLimitAppService;
use application::retry::RetryConfig;
use application::routing_service_impl::RoutingAppService;
use application::schedule_service_impl::ScheduleService;
use application::threatintel_service_impl::ThreatIntelAppService;
use application::zone_service_impl::ZoneAppService;
use arc_swap::ArcSwap;
use domain::alert::circuit_breaker::CircuitBreaker;
use domain::alert::engine::AlertRouter;
use domain::alert::entity::Alert;
use domain::dlp::engine::DlpEngine;
use domain::firewall::engine::FirewallEngine;
use domain::firewall::entity::FirewallRule;
use domain::ids::engine::IdsEngine;
use domain::ips::engine::IpsEngine;
use domain::l7::engine::L7Engine;
use domain::ratelimit::engine::RateLimitEngine;
use domain::threatintel::engine::ThreatIntelEngine;
use infrastructure::config::AgentConfig;
use infrastructure::constants::{
    ALERT_CHANNEL_CAPACITY, EVENT_CHANNEL_CAPACITY, GRACEFUL_SHUTDOWN_TIMEOUT,
};
use infrastructure::logging::init_logging;
use infrastructure::metrics::AgentMetrics;
use infrastructure::system_metrics;
use ports::secondary::alert_sender::AlertSender;
use ports::secondary::alert_store::AlertStore;
use ports::secondary::audit_sink::AuditSink;
use ports::secondary::audit_store::AuditStore;
use ports::secondary::auth_provider::AuthProvider;
use ports::secondary::ebpf_map_port::FirewallArrayMapPort;
use ports::secondary::metrics_port::{FirewallMetrics, MetricsPort};
use ports::secondary::rule_change_store::RuleChangeStore;
use tokio::sync::{RwLock, broadcast, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use infrastructure::config::{LogFormat, LogLevel};

/// Run one threat-intel feed fetch cycle: fetch every enabled feed, reload
/// the IOC set, stamp `last_fetched`, and inject any STIX domain indicators
/// into the DNS blocklist. Shared by the startup fetch, the periodic timer,
/// and the manual refresh trigger.
async fn run_ti_feed_cycle(
    ti_svc: &Arc<ArcSwap<ThreatIntelAppService>>,
    fetcher: &adapters::threatintel::HttpFeedFetcher,
    metrics: &Arc<dyn MetricsPort>,
    dns_blocklist: Option<&Arc<DnsBlocklistAppService>>,
    phase: &'static str,
) {
    let feeds = ti_svc.load().list_feeds().to_vec();
    let result = application::feed_update::fetch_all_feeds_v2(&feeds, fetcher, metrics).await;

    let mut svc = (**ti_svc.load()).clone();
    if !result.iocs.is_empty()
        && let Err(e) = svc.reload_iocs(result.iocs)
    {
        warn!(phase, "feed IOC reload failed: {e}");
    }
    // Stamp the fetch time on every cycle, even when no IOCs changed, so the
    // feed status reflects the most recent fetch attempt.
    svc.mark_fetched();
    ti_svc.store(Arc::new(svc));

    // Distribute STIX domain indicators to the DNS blocklist.
    if let Some(bl_svc) = dns_blocklist {
        for domain in &result.domains {
            let source_tag = domain.source.clone();
            if let Err(e) = bl_svc.add_pattern_with_source(&domain.domain, source_tag) {
                tracing::debug!(domain = %domain.domain, error = %e, "domain blocklist inject skipped");
            }
        }
    }
}

/// Run the agent startup sequence and block until shutdown.
///
/// `log_level_override` and `log_format_override` take precedence over config file values.
#[allow(clippy::too_many_lines, clippy::similar_names)] // startup is inherently sequential and long
pub async fn run(
    config_path: &str,
    log_level_override: Option<LogLevel>,
    log_format_override: Option<LogFormat>,
) -> anyhow::Result<()> {
    // ── 0. Restrict file creation permissions ─────────────────────
    adapters::system::set_restrictive_umask();

    // ── 1. Load config ──────────────────────────────────────────────
    let config = AgentConfig::load(Path::new(config_path))?;

    // ── 2. Initialize logging ───────────────────────────────────────
    // CLI flags take precedence over config file
    let log_level = log_level_override.unwrap_or(config.agent.log_level);
    let log_format = log_format_override.unwrap_or(config.agent.log_format);
    init_logging(log_level, log_format)?;

    // Service root span — fields appear in every subsequent log entry
    let _root_span = tracing::span!(
        tracing::Level::INFO,
        "service",
        service.name = "ebpfsentinel",
        service.version = env!("CARGO_PKG_VERSION"),
    )
    .entered();

    info!(
        config_path,
        log_level = log_level.as_str(),
        log_format = log_format.as_str(),
        xdp_mode = config.agent.xdp_mode.as_str(),
        interfaces = ?config.agent.interfaces,
        "eBPFsentinel agent starting"
    );

    // ── 3. Convert and load firewall rules ──────────────────────────
    let firewall_mode = config.firewall_mode()?;
    let domain_rules = config.firewall_rules()?;
    let mut engine = FirewallEngine::new();
    engine.reload(domain_rules.clone())?;
    info!(
        rule_count = engine.rules().len(),
        default_policy = ?config.firewall.default_policy,
        mode = firewall_mode.as_str(),
        "firewall engine initialized"
    );

    // ── 3b. Convert and load IDS rules ──────────────────────────────
    let ids_mode = config.ids_mode()?;
    let ids_domain_rules = config.ids_rules()?;
    let mut ids_engine = IdsEngine::new();
    if config.ids.enabled {
        ids_engine.reload(ids_domain_rules)?;
    }
    info!(
        rule_count = ids_engine.rule_count(),
        mode = ids_mode.as_str(),
        enabled = config.ids.enabled,
        "IDS engine initialized"
    );

    // ── 4. Initialize metrics ─────────────────────────────────────
    let metrics = Arc::new(AgentMetrics::new());
    metrics.set_rules_loaded("firewall", engine.rules().len() as u64);
    metrics.set_rules_loaded("ids", ids_engine.rule_count() as u64);

    // ── 5. Build shared application state ─────────────────────────
    let ebpf_loaded = Arc::new(AtomicBool::new(false));
    let mut svc =
        FirewallAppService::new(engine, None, Arc::clone(&metrics) as Arc<dyn MetricsPort>);
    svc.set_mode(firewall_mode);
    let firewall_svc = Arc::new(RwLock::new(svc));

    let mut ids_svc = IdsAppService::new(
        ids_engine,
        None,
        Arc::clone(&metrics) as Arc<dyn MetricsPort>,
    );
    ids_svc.set_mode(ids_mode);
    ids_svc.set_enabled(config.ids.enabled);
    let ids_svc = Arc::new(ArcSwap::from_pointee(ids_svc));

    let ips_mode = config.ips_mode()?;
    let ips_policy = config.ips_policy();
    let ips_whitelist = config.ips_whitelist()?;
    let ips_rules = config.ips_rules()?;
    let mut ips_svc = IpsAppService::new(
        IpsEngine::new(ips_policy),
        Arc::clone(&metrics) as Arc<dyn MetricsPort>,
    );
    ips_svc.set_mode(ips_mode);
    ips_svc.set_enabled(config.ips.enabled);
    ips_svc.reload_whitelist(ips_whitelist);
    ips_svc.reload_rules(ips_rules)?;
    let ips_svc = Arc::new(ArcSwap::from_pointee(ips_svc));

    // ── 5b. Build L7 service ────────────────────────────────────────
    let l7_domain_rules = config.l7_rules()?;
    let mut l7_engine = L7Engine::new();
    if config.l7.enabled {
        l7_engine.reload(l7_domain_rules.clone())?;
    }
    let mut l7_svc = L7AppService::new(l7_engine, Arc::clone(&metrics) as Arc<dyn MetricsPort>);
    l7_svc.set_enabled(config.l7.enabled);
    let l7_svc = Arc::new(ArcSwap::from_pointee(l7_svc));
    info!(
        rule_count = l7_domain_rules.len(),
        enabled = config.l7.enabled,
        "L7 engine initialized"
    );

    // ── 5c. Build ratelimit service ─────────────────────────────────
    let rl_policies = config.ratelimit_policies()?;
    let mut rl_engine = RateLimitEngine::new();
    if config.ratelimit.enabled {
        rl_engine.reload(rl_policies.clone())?;
    }
    let mut rl_svc =
        RateLimitAppService::new(rl_engine, Arc::clone(&metrics) as Arc<dyn MetricsPort>);
    rl_svc.set_enabled(config.ratelimit.enabled);
    let rl_svc = Arc::new(RwLock::new(rl_svc));
    info!(
        policy_count = rl_policies.len(),
        enabled = config.ratelimit.enabled,
        "ratelimit engine initialized"
    );

    // ── 5c½. Build DDoS service ──────────────────────────────────────
    let ddos_policies = config.ddos_policies()?;
    let mut ddos_engine = domain::ddos::engine::DdosEngine::new();
    if config.ddos.enabled {
        ddos_engine.reload(ddos_policies.clone())?;
    }
    let mut ddos_svc = application::ddos_service_impl::DdosAppService::new(
        ddos_engine,
        Arc::clone(&metrics) as Arc<dyn MetricsPort>,
    );
    ddos_svc.set_enabled(config.ddos.enabled);
    let ddos_svc = Arc::new(ArcSwap::from_pointee(ddos_svc));
    info!(
        policy_count = ddos_policies.len(),
        enabled = config.ddos.enabled,
        "DDoS engine initialized"
    );

    // ── 5c⅝. Build Load Balancer service ────────────────────────────
    let lb_services_cfg = config.lb_services()?;
    let mut lb_engine = domain::loadbalancer::engine::LbEngine::new();
    if config.loadbalancer.enabled {
        lb_engine.reload(lb_services_cfg.clone())?;
    }
    let mut lb_svc = application::lb_service_impl::LbAppService::new(
        lb_engine,
        Arc::clone(&metrics) as Arc<dyn MetricsPort>,
    );
    lb_svc.set_enabled(config.loadbalancer.enabled);
    let lb_svc = Arc::new(RwLock::new(lb_svc));
    info!(
        service_count = lb_services_cfg.len(),
        enabled = config.loadbalancer.enabled,
        "Load balancer engine initialized"
    );

    // ── 5c⅝¾. Build L2 VIP announcer service ────────────────────────
    let vip_announce_cfg = config.lb_announce()?;
    let vip_svc = {
        let mut svc = application::vip_announcer_service_impl::VipAnnouncerService::new(
            Arc::clone(&metrics) as Arc<dyn MetricsPort>,
        );
        svc.set_mac_resolver(Arc::new(adapters::net::IoctlIfaceMacResolver));
        svc.set_gratuitous_arp(Arc::new(adapters::net::RawSocketGratuitousArp));
        Arc::new(RwLock::new(svc))
    };
    info!(
        role = vip_announce_cfg.role.as_str(),
        vips = vip_announce_cfg.vips.len(),
        "L2 VIP announcer service initialized"
    );

    // ── 5c⅝½. Build QoS service ──────────────────────────────────────
    let qos_svc = {
        let mut svc = application::qos_service_impl::QosAppService::new(
            Arc::clone(&metrics) as Arc<dyn MetricsPort>
        );
        svc.set_enabled(config.qos.enabled);
        Arc::new(RwLock::new(svc))
    };
    info!(enabled = config.qos.enabled, "QoS service initialized");

    // ── 5c¾. Build DLP service ──────────────────────────────────────
    let mut dlp_engine = DlpEngine::new();
    // Always load built-in patterns, alert mode only
    let defaults = domain::dlp::entity::default_patterns();
    let dlp_pattern_count = defaults.len();
    if config.dlp.enabled {
        dlp_engine.reload(defaults)?;
    }
    let mut dlp_svc = DlpAppService::new(dlp_engine, Arc::clone(&metrics) as Arc<dyn MetricsPort>);
    dlp_svc.set_mode(domain::common::entity::DomainMode::Alert)?;
    dlp_svc.set_enabled(config.dlp.enabled);
    let dlp_svc = Arc::new(ArcSwap::from_pointee(dlp_svc));
    info!(
        pattern_count = dlp_pattern_count,
        enabled = config.dlp.enabled,
        "DLP engine initialized"
    );

    // ── 5c⅘. Build ConnTrack service ────────────────────────────────
    let ct_settings = config.conntrack_settings();
    let mut ct_svc = ConnTrackAppService::new(Arc::clone(&metrics) as Arc<dyn MetricsPort>);
    ct_svc.set_enabled(config.conntrack.enabled);
    if config.conntrack.enabled
        && let Err(e) = ct_svc.reload_settings(ct_settings)
    {
        warn!("conntrack settings reload failed (non-fatal): {e}");
    }
    // Inject the kernel netfilter conntrack reader so REST /conntrack
    // endpoints return the kernel's authoritative view (coherent with
    // `conntrack -L`) instead of the BPF shadow.
    let nf_ct_available = adapters::netfilter::conntrack::is_proc_conntrack_available();
    let conntrack_event_tx = if nf_ct_available {
        ct_svc.set_netfilter_port(Box::new(
            adapters::netfilter::conntrack::ProcNetfilterConntrackPort::new(),
        ));
        info!("kernel netfilter conntrack reader injected via /proc/net/nf_conntrack");
        // Broadcast channel created now; poller spawned later after
        // cancel_token exists (see section 6c below).
        let (tx, _) =
            tokio::sync::broadcast::channel::<domain::conntrack::entity::ConntrackEvent>(256);
        Some(tx)
    } else {
        None
    };
    let conntrack_svc = Arc::new(RwLock::new(ct_svc));
    info!(
        enabled = config.conntrack.enabled,
        "ConnTrack service initialized"
    );

    // ── 5c⅚. Build NAT service ──────────────────────────────────────
    let mut nat_svc = NatAppService::new(Arc::clone(&metrics) as Arc<dyn MetricsPort>);
    nat_svc.set_enabled(config.nat.enabled);
    if config.nat.enabled {
        let dnat_rules = config.nat_dnat_rules()?;
        let snat_rules = config.nat_snat_rules()?;
        if let Err(e) = nat_svc.reload_dnat_rules(dnat_rules) {
            warn!("NAT DNAT rules reload failed (non-fatal): {e}");
        }
        if let Err(e) = nat_svc.reload_snat_rules(snat_rules) {
            warn!("NAT SNAT rules reload failed (non-fatal): {e}");
        }
        let nptv6_rules = config.nat_nptv6_rules()?;
        if let Err(e) = nat_svc.reload_nptv6_rules(nptv6_rules) {
            warn!("NAT NPTv6 rules reload failed (non-fatal): {e}");
        }
    }
    let nat_svc = Arc::new(RwLock::new(nat_svc));
    info!(enabled = config.nat.enabled, "NAT service initialized");

    // ── 5c⅞a. Build Zone service ───────────────────────────────────
    let mut zone_svc = ZoneAppService::new();
    zone_svc.set_metrics(Arc::clone(&metrics) as Arc<dyn MetricsPort>);
    zone_svc.set_enabled(config.zones.enabled);
    if config.zones.enabled
        && let Ok(zone_cfg) = config.zone_config()
        && let Err(e) = zone_svc.reload(zone_cfg)
    {
        warn!("Zone config reload failed (non-fatal): {e}");
    }
    let zone_svc = Arc::new(RwLock::new(zone_svc));
    info!(enabled = config.zones.enabled, "Zone service initialized");

    // ── 5c⅞. Build GeoIP adapter (early, needed for alias + alert enrichment) ──
    let geoip_adapter: Option<Arc<adapters::geoip::MaxMindGeoIpAdapter>> =
        if let Some(ref geoip_cfg) = config.geoip {
            if geoip_cfg.enabled {
                match build_geoip_adapter(geoip_cfg) {
                    Ok(adapter) => {
                        info!("GeoIP adapter initialized");
                        Some(Arc::new(adapter))
                    }
                    Err(e) => {
                        warn!("GeoIP adapter initialization failed (degraded mode): {e}");
                        None
                    }
                }
            } else {
                None
            }
        } else {
            None
        };

    // ── 5c⅞. Build Alias service ────────────────────────────────────
    let mut alias_svc = AliasAppService::new(Arc::clone(&metrics) as Arc<dyn MetricsPort>);
    // Wire alias resolution adapter for URL table, DNS, and GeoIP lookups
    let mut alias_resolver =
        adapters::alias::alias_resolution_adapter::AliasResolutionAdapter::new();
    if let Some(ref adapter) = geoip_adapter {
        alias_resolver.set_geoip_adapter(Arc::clone(adapter));
        info!("GeoIP wired into alias resolution adapter");
    }
    let alias_resolver: Arc<dyn ports::secondary::alias_resolution_port::AliasResolutionPort> =
        Arc::new(alias_resolver);
    alias_svc.set_resolution_port(Arc::clone(&alias_resolver));
    let aliases = config.aliases()?;
    if !aliases.is_empty()
        && let Err(e) = alias_svc.reload_aliases(aliases)
    {
        warn!("alias reload failed (non-fatal): {e}");
    }
    let alias_svc = Arc::new(RwLock::new(alias_svc));
    info!("alias service initialized");

    // ── 5c⅞½. Build Routing service ─────────────────────────────────
    let mut routing_svc = RoutingAppService::new();
    routing_svc.set_metrics(Arc::clone(&metrics) as Arc<dyn MetricsPort>);
    routing_svc.set_enabled(config.routing.enabled);
    if config.routing.enabled {
        let gateways: Vec<_> = config
            .routing
            .gateways
            .iter()
            .map(infrastructure::config::GatewayConfig::to_domain)
            .collect();
        if let Err(e) = routing_svc.reload_gateways(gateways) {
            warn!("routing gateways reload failed (non-fatal): {e}");
        }
    }
    let routing_svc = Arc::new(RwLock::new(routing_svc));
    info!(
        gateway_count = config.routing.gateways.len(),
        enabled = config.routing.enabled,
        "routing service initialized"
    );

    // ── 5c⅞¾. Build Schedule service ────────────────────────────────
    let mut schedule_svc = ScheduleService::new();
    schedule_svc.set_metrics(Arc::clone(&metrics) as Arc<dyn MetricsPort>);
    if !config.firewall.schedules.is_empty() {
        use application::schedule_service_impl::{
            Schedule, ScheduleEntry, parse_day, parse_time_range,
        };
        use std::collections::HashMap;

        let mut schedules = HashMap::new();
        let mut rule_schedule = HashMap::new();

        for (id, sched_cfg) in &config.firewall.schedules {
            let entries: Vec<ScheduleEntry> = sched_cfg
                .entries
                .iter()
                .filter_map(|e| {
                    let days: Vec<_> = e.days.iter().filter_map(|d| parse_day(d)).collect();
                    let (start, end) = parse_time_range(&e.time)?;
                    Some(ScheduleEntry {
                        days,
                        start_minutes: start,
                        end_minutes: end,
                    })
                })
                .collect();
            schedules.insert(
                id.clone(),
                Schedule {
                    id: id.clone(),
                    entries,
                },
            );
        }

        // Wire rule → schedule mappings from firewall rules
        for rule_cfg in &config.firewall.rules {
            if let Some(ref sched_id) = rule_cfg.schedule {
                rule_schedule.insert(rule_cfg.id.clone(), sched_id.clone());
            }
        }

        schedule_svc.reload(schedules, rule_schedule);
        info!(
            schedule_count = config.firewall.schedules.len(),
            "schedule service initialized"
        );
    }
    let schedule_svc = Arc::new(RwLock::new(schedule_svc));

    // ── 5d. Build threat intel service ────────────────────────────────
    let ti_mode = config.threatintel_mode()?;
    let ti_feeds = config.threatintel_feeds()?;
    let ti_engine = ThreatIntelEngine::new(1_048_576);
    let mut ti_svc = ThreatIntelAppService::new(
        ti_engine,
        Arc::clone(&metrics) as Arc<dyn MetricsPort>,
        ti_feeds,
    );
    ti_svc.set_mode(ti_mode);
    ti_svc.set_enabled(config.threatintel.enabled);
    let ti_svc = Arc::new(ArcSwap::from_pointee(ti_svc));
    info!(
        enabled = config.threatintel.enabled,
        mode = ti_mode.as_str(),
        "threat intel engine initialized"
    );

    // ── 5e. Build audit service ───────────────────────────────────────
    let audit_sink: Arc<dyn AuditSink> = Arc::new(LogAuditSink);
    let mut audit_svc = AuditAppService::new(audit_sink);
    audit_svc.set_metrics(Arc::clone(&metrics) as Arc<dyn MetricsPort>);
    audit_svc.set_enabled(config.audit.enabled);

    // Attach persistent audit store (redb) — graceful degradation on failure
    let storage_path = Path::new(&config.audit.storage_path);
    match RedbAuditStore::open(storage_path, config.audit.buffer_size) {
        Ok(store) => {
            let store: Arc<dyn AuditStore> = Arc::new(store);
            audit_svc = audit_svc.with_store(store);
            info!(
                path = %config.audit.storage_path,
                buffer_size = config.audit.buffer_size,
                retention_days = config.audit.retention_days,
                "audit store initialized (redb)"
            );
        }
        Err(e) => {
            warn!(
                error = %e,
                path = %config.audit.storage_path,
                "audit store unavailable, running without persistent audit log"
            );
        }
    }

    // Attach rule change store (redb) — graceful degradation on failure
    let rule_change_path = storage_path.with_file_name("rule_changes.redb");
    match RedbRuleChangeStore::open(&rule_change_path) {
        Ok(store) => {
            let store: Arc<dyn RuleChangeStore> = Arc::new(store);
            audit_svc = audit_svc.with_rule_change_store(store);
            info!(
                path = %rule_change_path.display(),
                "rule change store initialized (redb)"
            );
        }
        Err(e) => {
            warn!(
                error = %e,
                path = %rule_change_path.display(),
                "rule change store unavailable, running without rule version history"
            );
        }
    }

    let audit_svc = Arc::new(audit_svc);
    info!(enabled = config.audit.enabled, "audit service initialized");

    // Attach alert store (redb) — graceful degradation on failure
    let alert_store_path = storage_path.with_file_name("alerts.redb");
    let alert_store: Option<Arc<dyn AlertStore>> = match RedbAlertStore::open(&alert_store_path) {
        Ok(store) => {
            info!(path = %alert_store_path.display(), "alert store initialized (redb)");
            Some(Arc::new(store))
        }
        Err(e) => {
            warn!(
                error = %e,
                path = %alert_store_path.display(),
                "alert store unavailable, running without alert persistence"
            );
            None
        }
    };

    // ── 5f. Initialize auth provider (JWT, OIDC, and/or API keys) ────
    let (auth_handle, auth_provider, revocation_handle): (
        Option<crate::reload::AuthProviderHandle>,
        Option<Arc<dyn AuthProvider>>,
        Option<adapters::auth::revocation::RevocationHandle>,
    ) = if config.auth.enabled {
        // Build token-based provider (JWT or OIDC) if configured
        let (token_handle, token_provider): (
            Option<crate::reload::AuthProviderHandle>,
            Option<Arc<dyn AuthProvider>>,
        ) = if let Some(ref oidc) = config.auth.oidc {
            let jwk_set = oidc_provider::fetch_jwks(&oidc.jwks_url)
                .await
                .map_err(|e| anyhow::anyhow!("failed to fetch JWKS: {e}"))?;
            let provider =
                OidcAuthProvider::new(jwk_set, oidc.issuer.as_deref(), oidc.audience.as_deref())
                    .map_err(|e| anyhow::anyhow!("failed to initialize OIDC auth provider: {e}"))?;
            info!(jwks_url = %oidc.jwks_url, "OIDC authentication enabled");
            let arc = Arc::new(provider);
            (
                Some(crate::reload::AuthProviderHandle::Oidc(Arc::clone(&arc))),
                Some(Arc::clone(&arc) as Arc<dyn AuthProvider>),
            )
        } else {
            match config
                .auth
                .jwt
                .key_source()
                .map_err(|e| anyhow::anyhow!("auth.jwt config error: {e}"))?
            {
                infrastructure::config::JwtKeySource::Pem { path } => {
                    let pem_bytes = std::fs::read(&path).map_err(|e| {
                        anyhow::anyhow!("failed to read JWT public key at '{path}': {e}")
                    })?;
                    let provider = match config.auth.jwt.algorithm {
                        infrastructure::config::JwtAlgorithm::RS256 => JwtAuthProvider::new(
                            &pem_bytes,
                            config.auth.jwt.issuer.as_deref(),
                            config.auth.jwt.audience.as_deref(),
                        ),
                        infrastructure::config::JwtAlgorithm::EdDSA => JwtAuthProvider::new_eddsa(
                            &pem_bytes,
                            config.auth.jwt.issuer.as_deref(),
                            config.auth.jwt.audience.as_deref(),
                        ),
                    }
                    .map_err(|e| anyhow::anyhow!("failed to initialize JWT auth provider: {e}"))?;
                    info!(
                        algorithm = ?config.auth.jwt.algorithm,
                        "JWT authentication enabled (static PEM)"
                    );
                    let arc = Arc::new(provider);
                    (
                        Some(crate::reload::AuthProviderHandle::Jwt(Arc::clone(&arc))),
                        Some(Arc::clone(&arc) as Arc<dyn AuthProvider>),
                    )
                }
                infrastructure::config::JwtKeySource::Jwks {
                    ref url,
                    refresh_on_unknown_kid,
                    ..
                } => {
                    let jwk_set = oidc_provider::fetch_jwks(url)
                        .await
                        .map_err(|e| anyhow::anyhow!("failed to fetch JWT JWKS: {e}"))?;
                    let provider = match config.auth.jwt.algorithm {
                        infrastructure::config::JwtAlgorithm::RS256 => OidcAuthProvider::new(
                            jwk_set,
                            config.auth.jwt.issuer.as_deref(),
                            config.auth.jwt.audience.as_deref(),
                        ),
                        infrastructure::config::JwtAlgorithm::EdDSA => {
                            OidcAuthProvider::new_for_eddsa(
                                jwk_set,
                                config.auth.jwt.issuer.as_deref(),
                                config.auth.jwt.audience.as_deref(),
                            )
                        }
                    }
                    .map_err(|e| {
                        anyhow::anyhow!("failed to initialize JWT JWKS auth provider: {e}")
                    })?;
                    let refresher: Arc<dyn oidc_provider::JwksRefresher> =
                        Arc::new(oidc_provider::HttpJwksRefresher::new(url.clone()));
                    let provider = provider.with_refresher(refresher, refresh_on_unknown_kid);
                    info!(
                        algorithm = ?config.auth.jwt.algorithm,
                        jwks_url = %url,
                        refresh_on_unknown_kid,
                        "JWT authentication enabled (JWKS)"
                    );
                    let arc = Arc::new(provider);
                    (
                        Some(crate::reload::AuthProviderHandle::Oidc(Arc::clone(&arc))),
                        Some(Arc::clone(&arc) as Arc<dyn AuthProvider>),
                    )
                }
                infrastructure::config::JwtKeySource::None => (None, None),
            }
        };

        // Build API key provider if configured
        let api_key_provider: Option<Arc<dyn AuthProvider>> = if config.auth.api_keys.is_empty() {
            None
        } else {
            let entries: Vec<_> = config
                .auth
                .api_keys
                .iter()
                .map(|k| {
                    (
                        k.name.clone(),
                        k.key.clone(),
                        k.role.clone(),
                        k.namespaces.clone(),
                    )
                })
                .collect();
            // Use configured salt or read 32 random bytes from /dev/urandom.
            let salt = config.auth.api_key_salt.as_deref().map_or_else(
                || {
                    let mut buf = vec![0u8; 32];
                    std::fs::File::open("/dev/urandom")
                        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut buf))
                        .expect("/dev/urandom should be readable");
                    warn!("no api_key_salt configured — using ephemeral salt, API keys will invalidate on restart");
                    buf
                },
                |s| s.as_bytes().to_vec(),
            );
            info!(key_count = entries.len(), "API key authentication enabled");
            Some(
                Arc::new(adapters::auth::api_key_provider::ApiKeyAuthProvider::new(
                    entries, &salt,
                )) as Arc<dyn AuthProvider>,
            )
        };

        // Combine providers
        let final_provider: Arc<dyn AuthProvider> = match (token_provider, api_key_provider) {
            (Some(tp), Some(akp)) => {
                info!("composite auth: token-based + API keys");
                Arc::new(
                    adapters::auth::composite_provider::CompositeAuthProvider::new(vec![tp, akp]),
                )
            }
            (Some(tp), None) => tp,
            (None, Some(akp)) => akp,
            (None, None) => {
                // Should not happen — config validation catches this
                return Err(anyhow::anyhow!(
                    "auth is enabled but no auth method configured"
                ));
            }
        };

        // Wrap the final provider with token revocation support.
        let revocable = adapters::auth::revocation::RevocableAuthProvider::new(final_provider);
        let revocation_handle = revocable.revocation_handle();
        let final_provider = Arc::new(revocable) as Arc<dyn AuthProvider>;
        info!("token revocation enabled");

        let handle = token_handle.unwrap_or(crate::reload::AuthProviderHandle::ApiKeyOnly);
        (Some(handle), Some(final_provider), Some(revocation_handle))
    } else {
        (None, None, None)
    };

    // Shared config, reload trigger, and eBPF program status for ops endpoints
    let shared_config = Arc::new(RwLock::new(config.clone()));
    let (reload_trigger_tx, reload_trigger_rx) = mpsc::channel::<()>(1);
    // Signalled by the reload task once a reload finishes, so the
    // /config/reload endpoint can wait for completion before returning.
    let reload_complete = Arc::new(tokio::sync::Notify::new());
    // Manual threat-intel feed re-fetch channel. Only wired into AppState
    // when the feed fetcher task actually runs (threat intel enabled with
    // ≥1 feed); otherwise the refresh endpoint reports the feature off.
    let ti_feeds_active = config.threatintel.enabled && !config.threatintel.feeds.is_empty();
    let mut feed_refresh_rx: Option<mpsc::Receiver<()>> = None;
    let feed_refresh_tx = if ti_feeds_active {
        let (tx, rx) = mpsc::channel::<()>(4);
        feed_refresh_rx = Some(rx);
        Some(tx)
    } else {
        None
    };
    let ebpf_program_status: Arc<RwLock<std::collections::HashMap<String, bool>>> =
        Arc::new(RwLock::new(std::collections::HashMap::new()));

    // ── JA4 / JA4S fingerprint caches (optionally redb-backed) ──────
    let fingerprint_cache_ttl = std::time::Duration::from_mins(5);
    let fingerprint_cache_max = 10_000;
    let (ja4_cache, ja4s_cache) = if let Some(ref path) = config.l7.fingerprints.persistence_path {
        match adapters::storage::fingerprint_store_redb::RedbFingerprintStore::open(
            std::path::Path::new(path),
        ) {
            Ok(store) => {
                let store: Arc<adapters::storage::fingerprint_store_redb::RedbFingerprintStore> =
                    Arc::new(store);
                let ja4: Arc<dyn domain::l7::ja4::Ja4Persist> = store.clone();
                let ja4s: Arc<dyn domain::l7::ja4::Ja4sPersist> = store;
                info!(path = %path, "JA4/JA4S fingerprint persistence enabled");
                (
                    Arc::new(domain::l7::ja4::FingerprintCache::with_persist(
                        fingerprint_cache_max,
                        fingerprint_cache_ttl,
                        ja4,
                    )),
                    Arc::new(domain::l7::ja4::Ja4sFingerprintCache::with_persist(
                        fingerprint_cache_max,
                        fingerprint_cache_ttl,
                        ja4s,
                    )),
                )
            }
            Err(e) => {
                tracing::warn!(
                    path = %path,
                    error = %e,
                    "failed to open fingerprint persistence store, falling back to in-memory caches"
                );
                (
                    Arc::new(domain::l7::ja4::FingerprintCache::new(
                        fingerprint_cache_max,
                        fingerprint_cache_ttl,
                    )),
                    Arc::new(domain::l7::ja4::Ja4sFingerprintCache::new(
                        fingerprint_cache_max,
                        fingerprint_cache_ttl,
                    )),
                )
            }
        }
    } else {
        (
            Arc::new(domain::l7::ja4::FingerprintCache::new(
                fingerprint_cache_max,
                fingerprint_cache_ttl,
            )),
            Arc::new(domain::l7::ja4::Ja4sFingerprintCache::new(
                fingerprint_cache_max,
                fingerprint_cache_ttl,
            )),
        )
    };

    let mut app_state = AppState::new(
        Arc::clone(&metrics),
        Arc::clone(&ebpf_loaded),
        Arc::clone(&firewall_svc),
        Arc::clone(&ips_svc),
        Arc::clone(&l7_svc),
        Arc::clone(&rl_svc),
        Arc::clone(&ti_svc),
        Arc::clone(&audit_svc),
        Arc::clone(&shared_config),
        reload_trigger_tx,
        Arc::clone(&ebpf_program_status),
    );
    app_state.config_path = Some(Arc::from(config_path));
    app_state.reload_complete = Some(Arc::clone(&reload_complete));
    if let Some(tx) = feed_refresh_tx {
        app_state = app_state.with_feed_refresh_trigger(tx);
    }
    if let Some(ref store) = alert_store {
        app_state = app_state.with_alert_store(Arc::clone(store));
    }
    if let Some(provider) = auth_provider {
        app_state = app_state.with_auth_provider(
            provider,
            revocation_handle,
            config.auth.metrics_auth_required,
        );
    }

    // Wire capture engine for manual packet capture
    let capture_engine = Arc::new(RwLock::new(
        domain::capture::engine::CaptureEngine::new(300), // max duration: 5 min
    ));
    app_state = app_state.with_capture_engine(Arc::clone(&capture_engine));

    // Wire response engine for manual TTL actions
    let response_engine = Arc::new(RwLock::new(
        domain::response::engine::ResponseEngine::new(86400), // max TTL: 24h
    ));
    app_state = app_state.with_response_engine(Arc::clone(&response_engine));

    // Wire JA4 + JA4S caches built earlier so handlers can report counts
    app_state = app_state
        .with_fingerprint_cache(Arc::clone(&ja4_cache))
        .with_ja4s_fingerprint_cache(Arc::clone(&ja4s_cache));

    // Real-time alert plumbing (broadcast + replay buffer). Created here
    // so AppState can hand them to the SSE handler and the agent can
    // hand the same broadcast clone to the gRPC streaming server below.
    let (alert_stream_tx, _) = broadcast::channel::<Alert>(ALERT_CHANNEL_CAPACITY);
    let alert_replay_buffer = Arc::new(application::alert_replay::AlertReplayBuffer::default());
    app_state = app_state
        .with_alert_stream_tx(alert_stream_tx.clone())
        .with_alert_replay_buffer(Arc::clone(&alert_replay_buffer));

    // Create alert channel early so DNS services can emit alerts
    let (alert_tx, alert_rx) =
        mpsc::channel::<application::alert_event::AlertEvent>(ALERT_CHANNEL_CAPACITY);

    // ── 5b. Wire DNS intelligence and domain reputation services ────
    let mut dns_blocklist_ref: Option<Arc<DnsBlocklistAppService>> = None;
    let mut dns_cache_svc_concrete: Option<Arc<DnsCacheAppService>> = None;
    let dns_cache_for_ids: Option<Arc<dyn ports::secondary::dns_cache_port::DnsCachePort>> =
        if config.dns.enabled {
            let cache_config = config.dns_cache_config();
            let dns_cache_svc = Arc::new(DnsCacheAppService::new(
                cache_config,
                Arc::clone(&metrics) as Arc<dyn MetricsPort>,
            ));
            dns_cache_svc_concrete = Some(Arc::clone(&dns_cache_svc));

            let blocklist_config = config.dns_blocklist_config().unwrap_or_else(|e| {
                tracing::warn!("DNS blocklist config error, using defaults: {e}");
                domain::dns::entity::DomainBlocklistConfig::default()
            });
            let dns_blocklist_svc = DnsBlocklistAppService::new(
                blocklist_config,
                None, // eBPF map writer — wired after tc-threatintel loads
                Arc::clone(&metrics) as Arc<dyn MetricsPort>,
            )
            .with_alert_tx(alert_tx.clone());
            // Wire IPS blacklist adapter when inject_target is "ips"
            let dns_blocklist_svc = if config.dns.blocklist.inject_target == "ips" {
                let adapter = Arc::new(IpsBlacklistAdapter::new(Arc::clone(&ips_svc)));
                dns_blocklist_svc.with_ips_port(
                    adapter as Arc<dyn ports::secondary::ips_blacklist_port::IpsBlacklistPort>,
                )
            } else {
                dns_blocklist_svc
            };
            let dns_blocklist_svc = Arc::new(dns_blocklist_svc);
            dns_blocklist_ref = Some(Arc::clone(&dns_blocklist_svc));

            app_state = app_state
                .with_dns_services(Arc::clone(&dns_cache_svc), Arc::clone(&dns_blocklist_svc));

            if config.dns.reputation.enabled {
                let rep_config = config.dns.reputation.to_domain_config();
                let mut rep_svc = DomainReputationAppService::new(
                    rep_config.clone(),
                    Arc::clone(&metrics) as Arc<dyn MetricsPort>,
                );

                // Wire reputation enforcement when auto-blocking is enabled
                if rep_config.auto_block_enabled {
                    let ips_adapter = Arc::new(IpsBlacklistAdapter::new(Arc::clone(&ips_svc)));
                    let enforcement = Arc::new(
                        application::reputation_enforcement::ReputationEnforcementService::new(
                            &rep_config,
                            Arc::clone(&dns_cache_svc)
                                as Arc<dyn ports::secondary::dns_cache_port::DnsCachePort>,
                            ips_adapter
                                as Arc<dyn ports::secondary::ips_blacklist_port::IpsBlacklistPort>,
                            Arc::clone(&metrics) as Arc<dyn MetricsPort>,
                        )
                        .with_alert_tx(alert_tx.clone()),
                    );
                    rep_svc = rep_svc.with_enforcement(enforcement);
                    tracing::info!(
                        threshold = rep_config.auto_block_threshold,
                        ttl_secs = rep_config.auto_block_ttl_secs,
                        "reputation auto-blocking enabled"
                    );
                }

                app_state = app_state.with_domain_reputation_service(Arc::new(rep_svc));
            }

            Some(dns_cache_svc as Arc<dyn ports::secondary::dns_cache_port::DnsCachePort>)
        } else {
            None
        };

    let mut app_state = app_state
        .with_ids_service(Arc::clone(&ids_svc))
        .with_ddos_service(Arc::clone(&ddos_svc))
        .with_dlp_service(Arc::clone(&dlp_svc))
        .with_conntrack_service(Arc::clone(&conntrack_svc));
    if let Some(ref tx) = conntrack_event_tx {
        app_state = app_state.with_conntrack_event_tx(tx.clone());
    }
    let mut app_state = app_state
        .with_nat_service(Arc::clone(&nat_svc))
        .with_alias_service(Arc::clone(&alias_svc))
        .with_routing_service(Arc::clone(&routing_svc))
        .with_loadbalancer_service(Arc::clone(&lb_svc))
        .with_vip_announcer_service(Arc::clone(&vip_svc))
        .with_qos_service(Arc::clone(&qos_svc))
        .with_zone_service(Arc::clone(&zone_svc));
    if let Some(ref adapter) = geoip_adapter {
        app_state = app_state.with_geoip_port(
            Arc::clone(adapter) as Arc<dyn ports::secondary::geoip_port::GeoIpPort>
        );
    }
    let app_state = Arc::new(app_state);

    // ── 6. Create cancellation token ────────────────────────────────
    let cancel_token = crate::shutdown::create_shutdown_token();

    // ── 6a. Spawn system metrics collection loop ────────────────────
    let _system_metrics_handle = system_metrics::spawn_collection_loop(
        Arc::clone(&metrics) as Arc<dyn MetricsPort>,
        Duration::from_secs(5),
        cancel_token.clone(),
    );

    // ── 6b. Spawn conntrack event poller ─────────────────────────────
    if let Some(ref tx) = conntrack_event_tx {
        let nf_port = adapters::netfilter::conntrack::ProcNetfilterConntrackPort::new();
        let poller_tx = tx.clone();
        let poller_cancel = cancel_token.clone();
        tokio::spawn(async move {
            adapters::netfilter::event_stream::run_conntrack_event_poller(
                nf_port,
                poller_tx,
                std::time::Duration::from_secs(2),
                poller_cancel,
            )
            .await;
        });
        info!("conntrack event poller started (2s interval)");
    }

    // ── 6b. Load TLS configuration ─────────────────────────────────
    // Install the PQ-aware CryptoProvider for all outbound TLS (reqwest, lettre)
    // even when server-side TLS is disabled.
    adapters::http::tls::install_pq_provider(config.agent.tls.pq_mode);

    let tls_config = if config.agent.tls.enabled {
        let rustls_cfg = load_rustls_config(
            Path::new(&config.agent.tls.cert_path),
            Path::new(&config.agent.tls.key_path),
            config.agent.tls.pq_mode,
            config.agent.tls.allow_tls12,
        )?;
        info!(
            cert_path = %config.agent.tls.cert_path,
            key_path = %config.agent.tls.key_path,
            pq_mode = ?config.agent.tls.pq_mode,
            "TLS enabled for HTTP and gRPC servers"
        );
        Some(rustls_cfg)
    } else {
        None
    };

    // ── 6d. Netkit hot-plug watcher is spawned after eBPF loading (section 10½) ──
    // so program FDs are available for dynamic attachment.

    // Install the SIGHUP handler before the HTTP server advertises readiness.
    // `tokio::signal::unix::signal` replaces the default (process-terminating)
    // disposition the instant it is called, so a SIGHUP racing startup is
    // captured instead of killing the agent. The reload task (spawned much
    // later, after eBPF loading) installs its own receiver for operational
    // reloads; this guard only closes the early window between readiness and
    // that task being live.
    #[cfg(unix)]
    let _sighup_guard = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        .expect("failed to install SIGHUP handler");

    // ── 7. Spawn HTTP API server ──────────────────────────────────
    let http_port = config.agent.http_port;
    let http_bind = config.agent.bind_address.clone();
    let http_swagger_ui = config.agent.swagger_ui;
    let state_for_server = Arc::clone(&app_state);
    let http_shutdown = cancel_token.clone();
    let http_tls = tls_config.clone();
    let http_handle = tokio::spawn(async move {
        if let Err(e) = run_http_server(
            state_for_server,
            &http_bind,
            http_port,
            http_swagger_ui,
            http_tls,
            http_shutdown.cancelled_owned(),
        )
        .await
        {
            tracing::error!(error = %e, "HTTP API server failed");
        }
    });

    // ── 8. Spawn config hot-reload task ──────────────────────────────
    let mut reload_service = ConfigReloadService::new(
        Arc::clone(&firewall_svc),
        Arc::clone(&ids_svc),
        Arc::clone(&ips_svc),
        Arc::clone(&l7_svc),
        Arc::clone(&rl_svc),
        Arc::clone(&ddos_svc),
        Arc::clone(&ti_svc),
        Arc::clone(&audit_svc),
        Arc::clone(&metrics) as Arc<dyn MetricsPort>,
    );
    reload_service.set_conntrack_service(Arc::clone(&conntrack_svc));
    reload_service.set_dlp_service(Arc::clone(&dlp_svc));
    reload_service.set_nat_service(Arc::clone(&nat_svc));
    reload_service.set_alias_service(Arc::clone(&alias_svc));
    reload_service.set_routing_service(Arc::clone(&routing_svc));
    reload_service.set_loadbalancer_service(Arc::clone(&lb_svc));
    reload_service.set_vip_announcer_service(Arc::clone(&vip_svc));
    reload_service.set_qos_service(Arc::clone(&qos_svc));
    reload_service.set_zone_service(Arc::clone(&zone_svc));
    reload_service.set_schedule_service(Arc::clone(&schedule_svc));
    let reload_service = Arc::new(reload_service);
    // Clone auth provider for gRPC from the app state
    let grpc_auth: Option<Arc<dyn AuthProvider>> = app_state.auth_provider.clone();

    // reload_handle is spawned after eBPF loading (step 10) to include EbpfMapHolder

    // ── 8b. Spawn gRPC alert streaming server ─────────────────────────
    let grpc_port = config.agent.grpc_port;
    let grpc_bind = config.agent.bind_address.clone();
    let grpc_stream_tx = alert_stream_tx.clone();
    let grpc_shutdown = cancel_token.clone();
    let grpc_tls = if config.agent.tls.enabled {
        let cert_pem = std::fs::read(&config.agent.tls.cert_path)?;
        let key_pem = std::fs::read(&config.agent.tls.key_path)?;
        Some(GrpcTlsConfig { cert_pem, key_pem })
    } else {
        None
    };
    let grpc_reflection = config.agent.grpc_reflection;
    let grpc_handle = tokio::spawn(async move {
        if let Err(e) = run_grpc_server(
            grpc_stream_tx,
            &grpc_bind,
            grpc_port,
            grpc_auth,
            grpc_tls,
            grpc_reflection,
            grpc_shutdown.cancelled_owned(),
        )
        .await
        {
            tracing::error!(error = %e, "gRPC server failed");
        }
    });

    // ── 9. Create event channel ─────────────────────────────────────
    let (event_tx, event_rx) = mpsc::channel::<AgentEvent>(EVENT_CHANNEL_CAPACITY);

    // ── 10. Load eBPF programs ─────────────────────────────────────
    //
    // Kernel version is MANDATORY: 6.9+ is required unconditionally.
    // No "API-only" fallback when the kernel is too old — every eBPF
    // program depends on kfuncs introduced in 6.4 → 6.9 and the
    // verifier rejects them at load time on older kernels. The
    // correct remediation is upgrading the host kernel; running the
    // agent as a pure HTTP frontend on a 6.8 host gives operators a
    // false sense of coverage, so we refuse to boot.
    //
    // The privilege check stays soft: an unprivileged caller can
    // still run the agent in API-only mode (REST/gRPC endpoints
    // live, no eBPF attach). The three BPF loading modes
    // (token / capabilities / privileged) all still work, but only
    // on top of a 6.9+ kernel.
    check_kernel_version()?;
    let ebpf_capable = match check_ebpf_privileges() {
        Ok(()) => true,
        Err(e) => {
            tracing::error!(error = %e, "eBPF unavailable — running in API-only mode");
            false
        }
    };
    let ebpf_dir = resolve_ebpf_program_dir(&config);

    // Bootstrap the BPF loading mode (token / capabilities / privileged).
    // Runs before any program load so the loader can attach the token
    // fd when one is obtained, and so the Prometheus gauge is set
    // before eBPF attachment races with the metrics scrape.
    let bpf_token_cfg = &config.agent.bpf_token;
    let bpf_policy = adapters::ebpf::BpfTokenPolicy::from_config(
        bpf_token_cfg.enabled,
        bpf_token_cfg.bpffs_path.clone(),
        bpf_token_cfg.fallback_allow_capabilities,
    );
    let bpf_handle = if ebpf_capable {
        match adapters::ebpf::bootstrap_bpf(&bpf_policy) {
            Ok(h) => {
                info!(
                    mode = h.mode.as_str(),
                    kernel = h.kernel.version_string(),
                    reason = h.reason,
                    "BPF loading mode selected"
                );
                Some(h)
            }
            Err(e) => {
                error!(error = %e, "BPF token bootstrap failed");
                None
            }
        }
    } else {
        None
    };
    let bpf_mode = bpf_handle
        .as_ref()
        .map_or(adapters::ebpf::BpfLoadingMode::Privileged, |h| h.mode);
    metrics.set_bpf_loading_mode(bpf_mode.metric_value(), bpf_mode.as_str());

    let mut ebpf_state = EbpfState::new();
    if let Some(handle) = bpf_handle {
        ebpf_state.attach_bpf_handle(handle);
    }
    let mut ebpf_map_holder = crate::reload::EbpfMapHolder::new();
    let mut metrics_readers: Vec<MetricsReader> = Vec::new();
    let mut iface_groups_mgr = InterfaceGroupsManager::new();

    // These flags track which eBPF programs loaded successfully.
    // Default to false when eBPF is unavailable (API-only mode).
    let (mut fw_ok, mut rl_ok, mut lb_pre_loaded) = (false, false, false);
    let (mut ids_ok, mut ti_ok, mut dns_ok, mut dlp_ok) = (false, false, false, false);
    let (mut ct_ok, mut nat_ok, mut scrub_ok, mut lb_ok) = (false, false, false, false);
    let mut qos_ok = false;
    let mut vip_announcer_ok = false;
    let mut fw_loader: Option<EbpfLoader> = None;

    if ebpf_capable {
        // Clean up stale pinned maps from a previous crash (if any)
        EbpfLoader::cleanup_pin_path(adapters::ebpf::DEFAULT_BPF_PIN_PATH);

        // 10a. XDP Firewall
        fw_ok = if config.firewall.enabled {
            match try_load_xdp_firewall(&ebpf_dir, &config, &domain_rules) {
                Ok((loader, map_manager, fw_metrics_rdr, reader)) => {
                    let event_tx_clone = event_tx.clone();
                    tokio::spawn(async move {
                        reader.run(event_tx_clone, CancellationToken::new()).await;
                    });
                    let mut svc = firewall_svc.write().await;
                    svc.set_map_port(Box::new(map_manager));
                    if let Some(rdr) = fw_metrics_rdr {
                        metrics_readers.push(rdr);
                    }
                    metrics.set_ebpf_program_status("xdp_firewall", true);
                    ebpf_loaded.store(true, Ordering::Relaxed);
                    info!(
                        interfaces = ?config.agent.interfaces,
                        mode = firewall_mode.as_str(),
                        "eBPF xdp-firewall active"
                    );
                    fw_loader = Some(loader);
                    true
                }
                Err(e) => {
                    warn!("xdp-firewall load failed (degraded mode): {e}");
                    metrics.set_ebpf_program_status("xdp_firewall", false);
                    false
                }
            }
        } else {
            metrics.set_ebpf_program_status("xdp_firewall", false);
            false
        };

        // 10b. XDP Rate Limiter
        rl_ok = if config.ratelimit.enabled {
            match try_load_xdp_ratelimit(&ebpf_dir, &config, fw_ok) {
                Ok((mut rl_loader, rl_mgr_opt, rl_lpm_opt, rl_rdrs, reader)) => {
                    let event_tx_clone = event_tx.clone();
                    tokio::spawn(async move {
                        reader.run(event_tx_clone, CancellationToken::new()).await;
                    });
                    metrics_readers.extend(rl_rdrs);
                    if let Some(rl_mgr) = rl_mgr_opt {
                        let mut svc = rl_svc.write().await;
                        let default_algo =
                            parse_algorithm_byte(&config.ratelimit.default_algorithm);
                        svc.set_defaults(
                            config.ratelimit.default_rate,
                            config.ratelimit.default_burst,
                            default_algo,
                        );
                        svc.set_map_port(Box::new(rl_mgr));
                    }
                    if let Some(rl_lpm) = rl_lpm_opt {
                        let mut svc = rl_svc.write().await;
                        svc.set_lpm_port(Box::new(rl_lpm));
                        svc.set_alias_resolution(Arc::clone(&alias_resolver));
                        // Load initial country tiers
                        if let Ok(tiers) = config.ratelimit_country_tiers()
                            && !tiers.is_empty()
                        {
                            if let Err(e) = svc.reload_country_tiers(&tiers) {
                                warn!("initial country tier load failed (non-fatal): {e}");
                            } else {
                                info!(
                                    count = tiers.len(),
                                    "initial country-tier rate limits loaded"
                                );
                            }
                        }
                    }
                    // Wire tail-call: firewall → ratelimit (if both loaded).
                    if let Some(ref mut fw) = fw_loader {
                        match rl_loader.program_raw_fd("xdp_ratelimit") {
                            Ok(rl_fd) => {
                                if let Err(e) = fw.set_tail_call_raw("XDP_PROG_ARRAY", 0, rl_fd) {
                                    warn!("tail-call wiring failed (non-fatal): {e}");
                                } else {
                                    info!("XDP tail-call: firewall → ratelimit wired");
                                }
                            }
                            Err(e) => warn!("ratelimit fd retrieval failed: {e}"),
                        }
                    }
                    iface_groups_mgr.add_map(rl_loader.ebpf_mut());
                    // Wire tail-call: ratelimit → syncookie (slot 0). Best-effort.
                    match try_load_xdp_ratelimit_syncookie(&ebpf_dir, &mut rl_loader) {
                        Ok(sc_loader) => {
                            ebpf_state.add_loader(sc_loader);
                            info!("XDP tail-call: ratelimit → syncookie wired (slot 0)");
                        }
                        Err(e) => {
                            warn!(
                                "xdp-ratelimit-syncookie load failed (syncookie falls back to DROP): {e}"
                            );
                        }
                    }
                    // Wire tail-call: ratelimit → loadbalancer (slot 1). Best-effort.
                    // Must happen before rl_loader is moved into ebpf_state.
                    // When ratelimit returns XDP_PASS, it tail-calls to the LB so
                    // the LB can DNAT service traffic. Without this, PASS goes
                    // directly to the kernel, bypassing the LB entirely.
                    if config.loadbalancer.enabled {
                        match try_load_xdp_loadbalancer(&ebpf_dir, &config, true) {
                            Ok((lb_loader_early, lb_mgr, lb_metrics_rdr, lb_reader)) => {
                                let event_tx_clone = event_tx.clone();
                                tokio::spawn(async move {
                                    lb_reader
                                        .run(event_tx_clone, CancellationToken::new())
                                        .await;
                                });
                                lb_svc.write().await.set_map_port(Box::new(lb_mgr));
                                if let Some(rdr) = lb_metrics_rdr {
                                    metrics_readers.push(rdr);
                                }
                                if let Ok(lb_fd) =
                                    lb_loader_early.program_raw_fd("xdp_loadbalancer")
                                {
                                    if let Err(e) =
                                        rl_loader.set_tail_call_raw("RL_PROG_ARRAY", 1, lb_fd)
                                    {
                                        warn!("ratelimit → LB tail-call wiring failed: {e}");
                                    } else {
                                        info!(
                                            "XDP tail-call: ratelimit → loadbalancer wired (RL slot 1)"
                                        );
                                    }
                                }
                                // Also wire into firewall (slot 2) for the no-ratelimit fallback path.
                                if let Some(ref mut fw) = fw_loader
                                    && let Ok(lb_fd) =
                                        lb_loader_early.program_raw_fd("xdp_loadbalancer")
                                {
                                    let _ = fw.set_tail_call_raw("XDP_PROG_ARRAY", 2, lb_fd);
                                }
                                ebpf_state.add_loader(lb_loader_early);
                                metrics.set_ebpf_program_status("xdp_loadbalancer", true);
                                info!("eBPF xdp-loadbalancer active (via ratelimit chain)");
                                lb_pre_loaded = true;
                            }
                            Err(e) => {
                                warn!("LB pre-load for RL chain failed (non-fatal): {e}");
                            }
                        }
                    }
                    ebpf_state.add_loader(rl_loader);
                    metrics.set_ebpf_program_status("xdp_ratelimit", true);
                    info!("eBPF xdp-ratelimit active");
                    true
                }
                Err(e) => {
                    warn!("xdp-ratelimit load failed (degraded mode): {e}");
                    metrics.set_ebpf_program_status("xdp_ratelimit", false);
                    false
                }
            }
        } else {
            metrics.set_ebpf_program_status("xdp_ratelimit", false);
            false
        };

        // Wire tail-call: firewall → reject (slot 1). Best-effort: if the reject
        // program fails to load, REJECT rules fall back to DROP silently (the
        // ProgramArray slot stays empty and tail_call is a no-op).
        if let Some(ref mut fw) = fw_loader {
            match try_load_xdp_firewall_reject(&ebpf_dir, fw) {
                Ok(reject_loader) => {
                    ebpf_state.add_loader(reject_loader);
                    info!("XDP tail-call: firewall → reject wired (slot 1)");
                }
                Err(e) => {
                    warn!("xdp-firewall-reject load failed (REJECT falls back to DROP): {e}");
                }
            }
        }

        // Wire LpmCoordinator from xdp-firewall to alias, ddos, ips services (take LPM maps BEFORE others)
        if geoip_adapter.is_some()
            && let Some(ref mut loader) = fw_loader
        {
            match LpmCoordinator::new(loader.ebpf_mut()) {
                Ok(coordinator) => {
                    let coordinator: Arc<
                        dyn ports::secondary::lpm_coordinator_port::LpmCoordinatorPort,
                    > = Arc::new(coordinator);
                    alias_svc
                        .write()
                        .await
                        .set_lpm_coordinator(Arc::clone(&coordinator));
                    {
                        let mut svc = (**ddos_svc.load()).clone();
                        svc.set_lpm_coordinator(Arc::clone(&coordinator));
                        svc.set_alias_resolution(Arc::clone(&alias_resolver));
                        ddos_svc.store(Arc::new(svc));
                    }
                    {
                        let mut svc = (**ips_svc.load()).clone();
                        svc.set_lpm_coordinator(Arc::clone(&coordinator));
                        ips_svc.store(Arc::new(svc));
                    }
                    info!("LPM coordinator wired to alias, DDoS, IPS services");
                }
                Err(e) => {
                    warn!("LPM coordinator maps not available (non-fatal): {e}");
                }
            }
        }

        // Wire IpSetMapManager from xdp-firewall to alias service (best-effort, before move)
        if let Some(ref mut loader) = fw_loader
            && let Ok(ipset_mgr) = IpSetMapManager::new(loader.ebpf_mut())
        {
            alias_svc.write().await.set_ipset_port(Box::new(ipset_mgr));
            info!("alias IP set map wired from xdp-firewall");
        }

        // Take INTERFACE_GROUPS map from xdp-firewall (before loader is moved)
        if let Some(ref mut loader) = fw_loader {
            iface_groups_mgr.add_map(loader.ebpf_mut());
        }

        // Initial dynamic alias refresh (loads GeoIP CIDRs into LPM maps at startup)
        match alias_svc.write().await.refresh_dynamic() {
            Ok(n) if n > 0 => info!(count = n, "initial dynamic alias refresh completed"),
            Ok(_) => {}
            Err(e) => warn!("initial dynamic alias refresh failed: {e}"),
        }

        // Wire FW → LB (slot 2) when ratelimit is NOT active but LB + FW are.
        // When ratelimit IS active, the RL→LB wiring was already done above.
        if fw_ok
            && !rl_ok
            && config.loadbalancer.enabled
            && !lb_pre_loaded
            && let Some(ref mut fw) = fw_loader
        {
            match try_load_xdp_loadbalancer(&ebpf_dir, &config, true) {
                Ok((lb_loader, lb_mgr, lb_metrics_rdr, lb_reader)) => {
                    let event_tx_clone = event_tx.clone();
                    tokio::spawn(async move {
                        lb_reader
                            .run(event_tx_clone, CancellationToken::new())
                            .await;
                    });
                    lb_svc.write().await.set_map_port(Box::new(lb_mgr));
                    if let Some(rdr) = lb_metrics_rdr {
                        metrics_readers.push(rdr);
                    }
                    if let Ok(lb_fd) = lb_loader.program_raw_fd("xdp_loadbalancer") {
                        if let Err(e) = fw.set_tail_call_raw("XDP_PROG_ARRAY", 2, lb_fd) {
                            warn!("firewall → LB tail-call wiring failed: {e}");
                        } else {
                            info!("XDP tail-call: firewall → loadbalancer wired (FW slot 2)");
                        }
                    }
                    ebpf_state.add_loader(lb_loader);
                    metrics.set_ebpf_program_status("xdp_loadbalancer", true);
                    lb_pre_loaded = true;
                    info!("eBPF xdp-loadbalancer active (via firewall chain)");
                }
                Err(e) => warn!("LB load for FW chain failed: {e}"),
            }
        }

        // Wire FW → VIP announcer (slot 3) when the announcer is enabled
        // and the firewall XDP entry point is active. The bounded ARP
        // responder is a separate tail-call target from the LB hot path;
        // xdp-firewall dispatches to it only for ARP frames. Split-brain
        // safety lives in VipAnnouncerService: VIP_SET is populated only
        // while this node is the elected speaker.
        if fw_ok
            && vip_announce_cfg.role != domain::loadbalancer::vip::AnnounceRole::Disabled
            && let Some(ref mut fw) = fw_loader
        {
            match try_load_xdp_vip_announcer(&ebpf_dir) {
                Ok((vip_loader, vip_mgr, binding_mgr)) => {
                    if let Ok(vip_fd) = vip_loader.program_raw_fd("xdp_vip_announcer") {
                        if let Err(e) = fw.set_tail_call_raw("XDP_PROG_ARRAY", 3, vip_fd) {
                            warn!("firewall → VIP announcer tail-call wiring failed: {e}");
                        } else {
                            info!("XDP tail-call: firewall → vip-announcer wired (FW slot 3)");
                        }
                    }
                    {
                        let mut svc = vip_svc.write().await;
                        // Binding port first: set_map_port triggers the
                        // reconcile that also writes SELF_OWNED_BINDINGS.
                        svc.set_binding_port(Box::new(binding_mgr));
                        if let Err(e) = svc.set_map_port(Box::new(vip_mgr)) {
                            warn!("vip announcer map port wiring failed: {e}");
                        }
                        if let Err(e) = svc.configure(vip_announce_cfg.clone()) {
                            warn!("vip announcer configure failed: {e}");
                        }
                    }
                    ebpf_state.add_loader(vip_loader);
                    // Mirror the kernel per-VIP forged-reply counters into
                    // Prometheus on a slow cadence (cumulative gauge).
                    let vip_metrics_svc = Arc::clone(&vip_svc);
                    tokio::spawn(async move {
                        let mut tick = tokio::time::interval(std::time::Duration::from_secs(15));
                        loop {
                            tick.tick().await;
                            if let Err(e) = vip_metrics_svc.read().await.refresh_metrics() {
                                warn!("vip announcer metrics refresh failed: {e}");
                            }
                        }
                    });
                    metrics.set_ebpf_program_status("xdp_vip_announcer", true);
                    vip_announcer_ok = true;
                    info!(
                        role = vip_announce_cfg.role.as_str(),
                        vips = vip_announce_cfg.vips.len(),
                        "eBPF xdp-vip-announcer active (via firewall chain)"
                    );
                }
                Err(e) => {
                    warn!("xdp-vip-announcer load failed (VIP announce disabled): {e}");
                    metrics.set_ebpf_program_status("xdp_vip_announcer", false);
                }
            }
        } else {
            metrics.set_ebpf_program_status("xdp_vip_announcer", false);
        }

        // Move firewall loader into eBPF state (after tail-call wiring)
        if let Some(loader) = fw_loader {
            ebpf_state.add_loader(loader);
        }

        // 10c. TC IDS — also the L7 capture vehicle (TLS ClientHello / HTTP
        // pre-classification feeds the L7 parser and encrypted-DNS detector).
        // L7 payload emission is gated on the L7_PORTS map, not the IDS config
        // flag, so the program must load whenever IDS *or* L7 is enabled.
        ids_ok = if config.ids.enabled || config.l7.enabled {
            match try_load_tc_ids(&ebpf_dir, &config) {
                Ok((mut loader, ids_mgr_opt, l7_mgr_opt, cfg_mgr_opt, ids_rdr, reader)) => {
                    let event_tx_clone = event_tx.clone();
                    tokio::spawn(async move {
                        reader.run(event_tx_clone, CancellationToken::new()).await;
                    });
                    if let Some(ids_mgr) = ids_mgr_opt {
                        {
                            let mut svc = (**ids_svc.load()).clone();
                            svc.set_map_port(Box::new(ids_mgr));
                            ids_svc.store(Arc::new(svc));
                        }
                    }
                    if let Some(l7_mgr) = l7_mgr_opt {
                        ebpf_map_holder.l7_ports = Some(l7_mgr);
                    }
                    if let Some(cfg_mgr) = cfg_mgr_opt {
                        ebpf_map_holder.config_flags.push(cfg_mgr);
                    }
                    if let Some(rdr) = ids_rdr {
                        metrics_readers.push(rdr);
                    }
                    iface_groups_mgr.add_map(loader.ebpf_mut());
                    ebpf_state.add_loader(loader);
                    metrics.set_ebpf_program_status("tc_ids", true);
                    info!("eBPF tc-ids active");
                    true
                }
                Err(e) => {
                    warn!("tc-ids load failed (degraded mode): {e}");
                    metrics.set_ebpf_program_status("tc_ids", false);
                    false
                }
            }
        } else {
            metrics.set_ebpf_program_status("tc_ids", false);
            false
        };

        // 10d. TC Threat Intel
        ti_ok =
            if config.threatintel.enabled {
                match try_load_tc_threatintel(&ebpf_dir, &config) {
                    Ok((loader, ti_mgr_opt, cfg_mgr_opt, ti_rdr, reader)) => {
                        let event_tx_clone = event_tx.clone();
                        tokio::spawn(async move {
                            reader.run(event_tx_clone, CancellationToken::new()).await;
                        });
                        if let Some(rdr) = ti_rdr {
                            metrics_readers.push(rdr);
                        }
                        if let Some(ti_mgr) = ti_mgr_opt {
                            // Extract shared map handles before moving manager to service
                            let (v4, v6, bv4, bv6) = ti_mgr.shared_handles();
                            {
                                let mut svc = (**ti_svc.load()).clone();
                                svc.set_map_port(Box::new(ti_mgr));
                                ti_svc.store(Arc::new(svc));
                            }

                            // Wire EbpfMapWriteAdapter to DNS blocklist service
                            if let Some(ref blocklist) = dns_blocklist_ref {
                                let writer = Arc::new(EbpfMapWriteAdapter::new(v4, v6, bv4, bv6));
                                blocklist.set_map_writer(
                            writer
                                as Arc<dyn ports::secondary::ebpf_map_write_port::EbpfMapWritePort>,
                        );
                                info!("EbpfMapWriteAdapter wired to DNS blocklist service");
                            }
                        }
                        if let Some(cfg_mgr) = cfg_mgr_opt {
                            ebpf_map_holder.config_flags.push(cfg_mgr);
                        }
                        ebpf_state.add_loader(loader);
                        metrics.set_ebpf_program_status("tc_threatintel", true);
                        info!("eBPF tc-threatintel active");
                        true
                    }
                    Err(e) => {
                        warn!("tc-threatintel load failed (degraded mode): {e}");
                        metrics.set_ebpf_program_status("tc_threatintel", false);
                        false
                    }
                }
            } else {
                metrics.set_ebpf_program_status("tc_threatintel", false);
                false
            };

        // 10e. TC DNS
        dns_ok = if config.dns.enabled {
            match try_load_tc_dns(&ebpf_dir, &config) {
                Ok((loader, dns_rdr, reader)) => {
                    let event_tx_clone = event_tx.clone();
                    tokio::spawn(async move {
                        reader.run(event_tx_clone, CancellationToken::new()).await;
                    });
                    if let Some(rdr) = dns_rdr {
                        metrics_readers.push(rdr);
                    }
                    ebpf_state.add_loader(loader);
                    metrics.set_ebpf_program_status("tc_dns", true);
                    info!("eBPF tc-dns active");
                    true
                }
                Err(e) => {
                    warn!("tc-dns load failed (degraded mode): {e}");
                    metrics.set_ebpf_program_status("tc_dns", false);
                    false
                }
            }
        } else {
            metrics.set_ebpf_program_status("tc_dns", false);
            false
        };

        // 10f. Uprobe DLP
        dlp_ok = if config.dlp.enabled {
            match try_load_uprobe_dlp(&ebpf_dir, &config) {
                Ok((loader, dlp_rdr, reader)) => {
                    let event_tx_clone = event_tx.clone();
                    tokio::spawn(async move {
                        reader.run(event_tx_clone, CancellationToken::new()).await;
                    });
                    if let Some(rdr) = dlp_rdr {
                        metrics_readers.push(rdr);
                    }
                    ebpf_state.add_loader(loader);
                    metrics.set_ebpf_program_status("uprobe_dlp", true);
                    info!("eBPF uprobe-dlp active");
                    true
                }
                Err(e) => {
                    warn!("uprobe-dlp load failed (degraded mode): {e}");
                    metrics.set_ebpf_program_status("uprobe_dlp", false);
                    false
                }
            }
        } else {
            metrics.set_ebpf_program_status("uprobe_dlp", false);
            false
        };

        // 10g. TC ConnTrack
        ct_ok = if config.conntrack.enabled {
            match try_load_tc_conntrack(&ebpf_dir, &config) {
                Ok((loader, ct_mgr, ct_rdr, opt_reader)) => {
                    if let Some(reader) = opt_reader {
                        let event_tx_clone = event_tx.clone();
                        tokio::spawn(async move {
                            reader.run(event_tx_clone, CancellationToken::new()).await;
                        });
                    }
                    conntrack_svc.write().await.set_map_port(Box::new(ct_mgr));
                    if let Some(rdr) = ct_rdr {
                        metrics_readers.push(rdr);
                    }
                    ebpf_state.add_loader(loader);
                    metrics.set_ebpf_program_status("tc_conntrack", true);
                    info!("eBPF tc-conntrack active");
                    true
                }
                Err(e) => {
                    warn!("tc-conntrack load failed (degraded mode): {e}");
                    metrics.set_ebpf_program_status("tc_conntrack", false);
                    false
                }
            }
        } else {
            metrics.set_ebpf_program_status("tc_conntrack", false);
            false
        };

        // 10h. TC NAT (ingress + egress)
        nat_ok = if config.nat.enabled {
            match try_load_tc_nat(&ebpf_dir, &config) {
                Ok((mut ingress_loader, mut egress_loader, nat_mgr, nat_rdrs)) => {
                    metrics_readers.extend(nat_rdrs);
                    {
                        let mut svc = nat_svc.write().await;
                        svc.set_map_port(Box::new(nat_mgr));
                        // Re-sync rules to eBPF maps now that maps are wired
                        let dnat = config.nat_dnat_rules().unwrap_or_default();
                        let snat = config.nat_snat_rules().unwrap_or_default();
                        let nptv6 = config.nat_nptv6_rules().unwrap_or_default();
                        let _ = svc.reload_dnat_rules(dnat);
                        let _ = svc.reload_snat_rules(snat);
                        let _ = svc.reload_nptv6_rules(nptv6);
                        // Load hairpin NAT config
                        if let Ok((subnet, mask, snat_ip)) = config.nat_hairpin_parsed() {
                            let hp = ebpf_common::nat::HairpinConfig {
                                internal_subnet: subnet,
                                internal_mask: mask,
                                hairpin_snat_ip: snat_ip,
                                enabled: u8::from(config.nat.hairpin.enabled),
                                _pad: [0; 3],
                            };
                            if let Err(e) = svc.load_hairpin_config(&hp) {
                                tracing::warn!("hairpin NAT config load failed: {e}");
                            }
                        }
                    }
                    iface_groups_mgr.add_map(ingress_loader.ebpf_mut());
                    iface_groups_mgr.add_map(egress_loader.ebpf_mut());
                    ebpf_state.add_loader(ingress_loader);
                    ebpf_state.add_loader(egress_loader);
                    metrics.set_ebpf_program_status("tc_nat_ingress", true);
                    metrics.set_ebpf_program_status("tc_nat_egress", true);
                    info!("eBPF tc-nat-ingress + tc-nat-egress active");
                    true
                }
                Err(e) => {
                    warn!("tc-nat load failed (degraded mode): {e}");
                    metrics.set_ebpf_program_status("tc_nat_ingress", false);
                    metrics.set_ebpf_program_status("tc_nat_egress", false);
                    false
                }
            }
        } else {
            metrics.set_ebpf_program_status("tc_nat_ingress", false);
            metrics.set_ebpf_program_status("tc_nat_egress", false);
            false
        };

        // 10i. TC Scrub
        scrub_ok = if config.firewall.scrub.enabled {
            match try_load_tc_scrub(&ebpf_dir, &config) {
                Ok((loader, scrub_rdr)) => {
                    if let Some(rdr) = scrub_rdr {
                        metrics_readers.push(rdr);
                    }
                    ebpf_state.add_loader(loader);
                    metrics.set_ebpf_program_status("tc_scrub", true);
                    info!("eBPF tc-scrub active");
                    true
                }
                Err(e) => {
                    warn!("tc-scrub load failed (degraded mode): {e}");
                    metrics.set_ebpf_program_status("tc_scrub", false);
                    false
                }
            }
        } else {
            metrics.set_ebpf_program_status("tc_scrub", false);
            false
        };

        // 10j. TC QoS
        qos_ok = if config.qos.enabled {
            match try_load_tc_qos(&ebpf_dir, &config) {
                Ok((mut loader, qos_mgr, qos_rdr, opt_reader)) => {
                    if let Some(reader) = opt_reader {
                        let event_tx_clone = event_tx.clone();
                        tokio::spawn(async move {
                            reader.run(event_tx_clone, CancellationToken::new()).await;
                        });
                    }
                    {
                        let mut svc = qos_svc.write().await;
                        if let Ok(scheduler) = config.qos_scheduler() {
                            svc.set_scheduler(scheduler);
                        }
                        // Bind the eBPF maps, then resync config so the just-wired
                        // maps reflect the pipes/queues/classifiers from config.
                        svc.set_map_port(Box::new(qos_mgr));
                        if let Ok(pipes) = config.qos_pipes() {
                            let _ = svc.reload_pipes(pipes);
                        }
                        if let Ok(queues) = config.qos_queues() {
                            let _ = svc.reload_queues(queues);
                        }
                        if let Ok(classifiers) = config.qos_classifiers() {
                            let _ = svc.reload_classifiers(classifiers);
                        }
                    }
                    if let Some(rdr) = qos_rdr {
                        metrics_readers.push(rdr);
                    }
                    iface_groups_mgr.add_map(loader.ebpf_mut());
                    ebpf_state.add_loader(loader);
                    metrics.set_ebpf_program_status("tc_qos", true);
                    info!("eBPF tc-qos active");
                    true
                }
                Err(e) => {
                    warn!("tc-qos load failed (degraded mode): {e}");
                    metrics.set_ebpf_program_status("tc_qos", false);
                    false
                }
            }
        } else {
            metrics.set_ebpf_program_status("tc_qos", false);
            false
        };

        // 10k. XDP Load Balancer
        // The LB can run standalone (attached to interface) or as a tail-call
        // target in the chain: firewall → ratelimit → loadbalancer.
        // When firewall is active, LB is wired at FW slot 2 (fallback when
        // ratelimit is absent) AND the ratelimit chain also tail-calls LB on PASS.
        let xdp_chain_active = fw_ok || rl_ok;
        lb_ok = if lb_pre_loaded {
            // LB was already loaded and wired during the ratelimit block.
            true
        } else if config.loadbalancer.enabled {
            match try_load_xdp_loadbalancer(&ebpf_dir, &config, xdp_chain_active) {
                Ok((lb_loader, lb_mgr, lb_metrics_rdr, lb_reader)) => {
                    let event_tx_clone = event_tx.clone();
                    tokio::spawn(async move {
                        lb_reader
                            .run(event_tx_clone, CancellationToken::new())
                            .await;
                    });
                    lb_svc.write().await.set_map_port(Box::new(lb_mgr));
                    if let Some(rdr) = lb_metrics_rdr {
                        metrics_readers.push(rdr);
                    }
                    // FW→LB wiring (slot 2) already done during pre-load or not needed.
                    ebpf_state.add_loader(lb_loader);
                    metrics.set_ebpf_program_status("xdp_loadbalancer", true);
                    info!("eBPF xdp-loadbalancer active");
                    true
                }
                Err(e) => {
                    warn!("xdp-loadbalancer load failed (degraded mode): {e}");
                    metrics.set_ebpf_program_status("xdp_loadbalancer", false);
                    false
                }
            }
        } else {
            metrics.set_ebpf_program_status("xdp_loadbalancer", false);
            false
        };

        // ── 10z. Populate INTERFACE_GROUPS maps across all loaded programs ──
        {
            let membership = config.interface_membership();
            let memberships: Vec<(u32, u32)> = config
                .agent
                .interfaces
                .iter()
                .filter_map(|iface| {
                    let ifindex = get_ifindex(iface).ok()?;
                    let groups = membership.get(iface).copied().unwrap_or(0);
                    Some((ifindex, groups))
                })
                .collect();
            if let Err(e) = iface_groups_mgr.set_interface_groups(&memberships) {
                warn!("INTERFACE_GROUPS population failed (non-fatal): {e}");
            } else if !memberships.is_empty() {
                info!(
                    iface_count = memberships.len(),
                    map_count = iface_groups_mgr.map_count(),
                    "interface group memberships loaded into eBPF maps"
                );
            }
        }
        // Store the manager for config reload
        ebpf_map_holder.iface_groups = Some(iface_groups_mgr);
    } // end if ebpf_capable

    // Populate eBPF program status for ops endpoint
    {
        let mut status = ebpf_program_status.write().await;
        status.insert("xdp_firewall".to_string(), fw_ok);
        status.insert("xdp_ratelimit".to_string(), rl_ok);
        status.insert("tc_ids".to_string(), ids_ok);
        status.insert("tc_threatintel".to_string(), ti_ok);
        status.insert("tc_dns".to_string(), dns_ok);
        status.insert("uprobe_dlp".to_string(), dlp_ok);
        status.insert("tc_conntrack".to_string(), ct_ok);
        status.insert("tc_nat_ingress".to_string(), nat_ok);
        status.insert("tc_nat_egress".to_string(), nat_ok);
        status.insert("tc_scrub".to_string(), scrub_ok);
        status.insert("tc_qos".to_string(), qos_ok);
        status.insert("xdp_loadbalancer".to_string(), lb_ok);
        status.insert("xdp_vip_announcer".to_string(), vip_announcer_ok);
    }

    // ── 10½a. Build netkit hot-plug registry + spawn watcher ─────────
    if config.agent.attach_mode != infrastructure::config::AttachMode::Tc && ebpf_capable {
        let tc_program_names = [
            ("tc_ids", ids_ok),
            ("tc_threatintel", ti_ok),
            ("tc_dns", dns_ok),
            ("tc_conntrack", ct_ok),
            ("tc_nat_ingress", nat_ok),
            ("tc_nat_egress", nat_ok),
            ("tc_scrub", scrub_ok),
            ("tc_qos", qos_ok),
        ];

        let mut registry = adapters::ebpf::netkit::NetkitHotPlugRegistry::new();

        for loader in &ebpf_state.loaders {
            for &(name, ok) in &tc_program_names {
                if ok && let Some(fd) = loader.program_fd(name) {
                    registry.register(name.to_string(), fd);
                }
            }
        }

        let registered = registry.program_count();
        if registered > 0 {
            let registry = Arc::new(registry);
            let nk_cancel = cancel_token.clone();
            let nk_registry = Arc::clone(&registry);
            tokio::spawn(async move {
                adapters::ebpf::netkit_discovery::watch_netkit_devices(
                    Box::new(move |iface, new_pods| {
                        nk_registry.attach_all(iface, new_pods);
                    }),
                    std::time::Duration::from_secs(5),
                    nk_cancel,
                )
                .await;
            });
            info!(
                programs = registered,
                "netkit hot-plug watcher started (5s poll, auto-attach enabled)"
            );
        } else {
            info!("netkit hot-plug watcher skipped (no TC programs loaded)");
        }
    }

    // ── 10½b. Build EbpfProgramManager from loaded state ──────────────
    let ebpf_manager = {
        let mut mgr = crate::ebpf_lifecycle::EbpfProgramManager::new(
            event_tx.clone(),
            Arc::new(crate::runtime::ServiceHandles {
                firewall_svc: Arc::clone(&firewall_svc),
                ids_svc: Arc::clone(&ids_svc),
                ips_svc: Arc::clone(&ips_svc),
                rl_svc: Arc::clone(&rl_svc),
                ti_svc: Arc::clone(&ti_svc),
                dns_blocklist_svc: dns_blocklist_ref.clone(),
                l7_svc: Arc::clone(&l7_svc),
                ddos_svc: Arc::clone(&ddos_svc),
                dlp_svc: Arc::clone(&dlp_svc),
                conntrack_svc: Arc::clone(&conntrack_svc),
                nat_svc: Arc::clone(&nat_svc),
                lb_svc: Arc::clone(&lb_svc),
                qos_svc: Arc::clone(&qos_svc),
                zone_svc: Arc::clone(&zone_svc),
                alias_svc: Arc::clone(&alias_svc),
                routing_svc: Arc::clone(&routing_svc),
                schedule_svc: Arc::clone(&schedule_svc),
                audit_svc: Arc::clone(&audit_svc),
                dns_cache_svc: dns_cache_svc_concrete.clone(),
                metrics: Arc::clone(&metrics),
                ebpf_loaded: Arc::clone(&ebpf_loaded),
            }),
            ebpf_dir.clone(),
        );
        // Mark startup-loaded programs so hot-reload doesn't try to re-load them.
        // The actual loaders are kept alive in ebpf_state (moved below).
        if fw_ok {
            mgr.mark_startup_loaded("xdp_firewall");
        }
        if rl_ok {
            mgr.mark_startup_loaded("xdp_ratelimit");
        }
        if ids_ok {
            mgr.mark_startup_loaded("tc_ids");
        }
        if ti_ok {
            mgr.mark_startup_loaded("tc_threatintel");
        }
        if dns_ok {
            mgr.mark_startup_loaded("tc_dns");
        }
        if dlp_ok {
            mgr.mark_startup_loaded("uprobe_dlp");
        }
        if ct_ok {
            mgr.mark_startup_loaded("tc_conntrack");
        }
        if nat_ok {
            mgr.mark_startup_loaded("tc_nat");
        }
        if scrub_ok {
            mgr.mark_startup_loaded("tc_scrub");
        }
        if qos_ok {
            mgr.mark_startup_loaded("tc_qos");
        }
        if lb_ok {
            mgr.mark_startup_loaded("xdp_loadbalancer");
        }
        if vip_announcer_ok {
            mgr.mark_startup_loaded("xdp_vip_announcer");
        }
        // Move map holder fields into the manager
        mgr.config_flags = ebpf_map_holder.config_flags;
        mgr.l7_ports = ebpf_map_holder.l7_ports;
        if let Some(ig) = ebpf_map_holder.iface_groups {
            mgr.iface_groups = ig;
        }
        Arc::new(tokio::sync::Mutex::new(mgr))
    };

    // Spawn config hot-reload task
    let reload_handle = crate::reload::spawn_reload_task(
        config_path.to_string(),
        reload_service,
        auth_handle,
        cancel_token.clone(),
        reload_trigger_rx,
        Arc::clone(&shared_config),
        Arc::clone(&ebpf_manager),
        Arc::clone(&reload_complete),
    );

    // ── 10d. Build container resolver ───────────────────────────────
    let container_resolver = if config.container.resolver.enabled {
        let proc_resolver = Arc::new(adapters::container::ProcContainerResolver::new(
            &config.container.resolver.proc_path,
        )) as Arc<dyn domain::container::engine::CgroupReader>;
        let engine = domain::container::engine::ContainerResolverEngine::new(
            proc_resolver,
            config.container.resolver.cache_size,
        );
        info!(
            cache_size = config.container.resolver.cache_size,
            proc_path = %config.container.resolver.proc_path,
            "Container resolver initialized"
        );
        Some(Arc::new(engine))
    } else {
        info!("Container resolver disabled via config");
        None
    };

    // ── 10e. Build Docker metadata enricher (optional) ──────────────
    let docker_enricher: Option<
        Arc<dyn ports::secondary::metadata_enricher_port::MetadataEnricher>,
    > = if config.container.docker.enabled {
        let socket_path = std::path::Path::new(&config.container.docker.socket);
        if !socket_path.exists() {
            warn!(
                socket = %config.container.docker.socket,
                "Docker socket not found — enricher will stay dormant until it appears"
            );
        }
        let client = adapters::container::DockerClient::new(
            &config.container.docker.socket,
            config.container.docker.timeout_ms,
        );
        let cache = adapters::container::DockerCache::new(
            config.container.docker.cache_size,
            Duration::from_secs(config.container.docker.cache_ttl_seconds),
        );
        let enricher = adapters::container::DockerEnricher::new(client, cache);
        info!(
            socket = %config.container.docker.socket,
            cache_size = config.container.docker.cache_size,
            cache_ttl_seconds = config.container.docker.cache_ttl_seconds,
            "Docker metadata enricher initialized"
        );
        Some(Arc::new(enricher) as _)
    } else {
        None
    };

    // ── 10f. Build Kubernetes enricher (optional, auto-detected) ────
    #[cfg(feature = "kubernetes")]
    let kubernetes_enricher: Option<
        Arc<dyn ports::secondary::metadata_enricher_port::MetadataEnricher>,
    > = if config.container.kubernetes.enabled {
        if !adapters::container::is_running_in_kubernetes() {
            info!("kubernetes.enabled=true but no KUBERNETES_SERVICE_HOST — enricher disabled");
            None
        } else if let Some(client) = adapters::container::try_build_client().await {
            let cache = Arc::new(adapters::container::PodCache::new());
            let enricher = adapters::container::KubernetesEnricher::with_cache(Arc::clone(&cache));
            let metrics_handle = enricher.metrics();
            let node_name = if config.container.kubernetes.node_name.is_empty() {
                adapters::container::resolve_node_name()
            } else {
                config.container.kubernetes.node_name.clone()
            };
            let _watcher = adapters::container::spawn_pod_watcher(
                client,
                node_name.clone(),
                cache,
                metrics_handle,
            );
            info!(
                node = %node_name,
                "Kubernetes metadata enricher initialized"
            );
            Some(Arc::new(enricher) as _)
        } else {
            warn!("kubernetes enricher failed to build kube client — disabled");
            None
        }
    } else {
        None
    };
    #[cfg(not(feature = "kubernetes"))]
    let kubernetes_enricher: Option<
        Arc<dyn ports::secondary::metadata_enricher_port::MetadataEnricher>,
    > = None;

    // ── 11. Spawn event dispatcher (replaces flat event consumer) ───
    let dispatcher = EventDispatcher::new(
        Arc::clone(&ids_svc),
        Arc::clone(&l7_svc),
        Arc::clone(&ti_svc),
        Arc::clone(&audit_svc),
        Arc::clone(&metrics) as Arc<dyn MetricsPort>,
        alert_tx.clone(),
        dns_cache_for_ids,
    )
    .with_ips_service(Arc::clone(&ips_svc))
    .with_ddos_service(Arc::clone(&ddos_svc))
    .with_dlp_service(Arc::clone(&dlp_svc))
    .with_doh_resolvers(&config.dns.doh_resolvers)
    .with_fingerprint_cache(Arc::clone(&ja4_cache))
    .with_ja4s_fingerprint_cache(Arc::clone(&ja4s_cache));
    // Wire DNS services into the dispatcher for DNS response processing
    let dispatcher = if let Some(ref svc) = dns_cache_svc_concrete {
        dispatcher.with_dns_cache_svc(Arc::clone(svc))
    } else {
        dispatcher
    };
    let dispatcher = if let Some(ref svc) = dns_blocklist_ref {
        dispatcher.with_dns_blocklist_svc(Arc::clone(svc))
    } else {
        dispatcher
    };
    let dispatcher = if let Some(ref resolver) = container_resolver {
        dispatcher.with_container_resolver(Arc::clone(resolver))
    } else {
        dispatcher
    };

    // ── 10g. Build L7 stream reassembler (optional) ─────────────────
    let stream_reassembler: Option<Arc<domain::l7::reassembler::StreamReassembler>> =
        if config.l7.reassembly.enabled {
            let reassembler = Arc::new(domain::l7::reassembler::StreamReassembler::new(
                config.l7.reassembly.to_domain(),
            ));
            info!(
                max_flows = config.l7.reassembly.max_flows,
                max_buffer_per_flow = config.l7.reassembly.max_buffer_per_flow,
                idle_timeout_secs = config.l7.reassembly.idle_timeout_secs,
                sweep_interval_secs = config.l7.reassembly.sweep_interval_secs,
                "L7 stream reassembler enabled"
            );
            Some(reassembler)
        } else {
            None
        };
    let dispatcher = if let Some(ref reassembler) = stream_reassembler {
        dispatcher.with_stream_reassembler(Arc::clone(reassembler))
    } else {
        dispatcher
    };

    // Periodic sweep task: flush flows that went idle past the
    // configured timeout so their partial buffers can still be parsed.
    if stream_reassembler.is_some() {
        let sweep_dispatcher = dispatcher.clone();
        let sweep_interval = Duration::from_secs(config.l7.reassembly.sweep_interval_secs.max(1));
        let sweep_cancel = cancel_token.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(sweep_interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    () = sweep_cancel.cancelled() => break,
                    _ = ticker.tick() => {
                        let now_ns = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX));
                        let count = sweep_dispatcher.flush_reassembled(now_ns);
                        if count > 0 {
                            tracing::debug!(count, "l7 reassembler flushed + parsed idle flows");
                        }
                    }
                }
            }
        });
    }

    let dispatcher_cancel = cancel_token.clone();
    let event_workers = config.agent.event_workers;
    let dispatcher_handle = tokio::spawn(async move {
        dispatcher
            .run_parallel(event_workers, event_rx, dispatcher_cancel)
            .await;
    });

    // ── 11b. Build AlertRouter and spawn AlertPipeline ──────────────
    let routing_rules = config.alerting_routes()?;
    let alert_router = AlertRouter::new(
        routing_rules,
        Duration::from_secs(config.alerting.dedup_window_secs),
        Duration::from_secs(config.alerting.throttle_window_secs),
        config.alerting.throttle_max,
    );
    let mut alert_pipeline = AlertPipeline::new(
        alert_router,
        Arc::clone(&metrics) as Arc<dyn MetricsPort>,
        Arc::clone(&audit_svc),
    )
    .with_stream_sender(alert_stream_tx)
    .with_replay_buffer(Arc::clone(&alert_replay_buffer));
    if let Some(store) = alert_store {
        alert_pipeline = alert_pipeline.with_alert_store(store);
    }
    if let Some(enricher) = kubernetes_enricher.clone() {
        alert_pipeline = alert_pipeline.with_metadata_enricher(enricher);
    }
    if let Some(enricher) = docker_enricher.clone() {
        alert_pipeline = alert_pipeline.with_metadata_enricher(enricher);
    }

    // Cast the already-built GeoIP adapter to the GeoIpPort trait for alert enrichment
    let geoip_port: Option<Arc<dyn ports::secondary::geoip_port::GeoIpPort>> = geoip_adapter
        .as_ref()
        .map(|a| Arc::clone(a) as Arc<dyn ports::secondary::geoip_port::GeoIpPort>);

    // Wire DNS alert enricher (best-effort: only if DNS cache is available)
    if let Some(ref dns_cache) = app_state.dns_cache_service {
        let mut enricher = application::alert_enrichment::DnsAlertEnricher::new(
            Arc::clone(dns_cache) as Arc<dyn ports::secondary::dns_cache_port::DnsCachePort>,
            app_state.domain_reputation_service.as_ref().map(|svc| {
                Arc::clone(svc)
                    as Arc<dyn ports::secondary::domain_reputation_port::DomainReputationPort>
            }),
        );
        if let Some(ref geoip) = geoip_port {
            enricher = enricher.with_geoip(Arc::clone(geoip));
            info!("GeoIP alert enrichment enabled");
        }
        alert_pipeline = alert_pipeline.with_enricher(Arc::new(enricher));
        info!("DNS alert enricher initialized");
    }

    // Wire simple auto-response (OSS)
    if config.auto_response.enabled && !config.auto_response.policies.is_empty() {
        let policies: Vec<domain::response::entity::SimpleResponsePolicy> = config
            .auto_response
            .policies
            .iter()
            .map(|p| {
                let min_severity = match p.min_severity.as_str() {
                    "low" => domain::common::entity::Severity::Low,
                    "medium" => domain::common::entity::Severity::Medium,
                    "critical" => domain::common::entity::Severity::Critical,
                    _ => domain::common::entity::Severity::High,
                };
                let action = if p.action == "throttle" {
                    domain::response::entity::ResponseActionType::ThrottleIp
                } else {
                    domain::response::entity::ResponseActionType::BlockIp
                };
                domain::response::entity::SimpleResponsePolicy {
                    name: p.name.clone(),
                    min_severity,
                    components: p.components.clone(),
                    action,
                    ttl_secs: p.ttl_secs,
                    rate_pps: p.rate_pps,
                }
            })
            .collect();
        info!(
            policy_count = policies.len(),
            "auto-response policies loaded"
        );
        alert_pipeline = alert_pipeline.with_auto_response(policies, Arc::clone(&ips_svc));
    }

    // Wire simple auto-capture (OSS)
    if config.auto_capture.enabled {
        let iface = config
            .auto_capture
            .interface
            .clone()
            .unwrap_or_else(|| config.agent.interfaces[0].clone());
        let min_severity = match config.auto_capture.min_severity.as_str() {
            "low" => domain::common::entity::Severity::Low,
            "medium" => domain::common::entity::Severity::Medium,
            "critical" => domain::common::entity::Severity::Critical,
            _ => domain::common::entity::Severity::High,
        };
        let policy = domain::capture::entity::AutoCapturePolicy {
            name: "auto-capture".to_string(),
            min_severity,
            components: config.auto_capture.components.clone(),
            duration_secs: config.auto_capture.duration_secs,
            snap_length: config.auto_capture.snap_length,
            interface: iface,
        };

        let (capture_tx, mut capture_rx) =
            tokio::sync::mpsc::channel::<domain::capture::entity::AutoCaptureRequest>(4);

        alert_pipeline =
            alert_pipeline.with_auto_capture(policy, Arc::clone(&capture_engine), capture_tx);

        // Spawn capture receiver — bridges application → adapters layer.
        let cap_engine_clone = Arc::clone(&capture_engine);
        tokio::spawn(async move {
            while let Some(req) = capture_rx.recv().await {
                let s = req.session;
                #[cfg(feature = "pcap-capture")]
                {
                    let engine = Arc::clone(&cap_engine_clone);
                    tokio::spawn(adapters::http::capture_handler::run_pcap_capture(
                        s.id,
                        s.interface,
                        s.filter,
                        s.duration_secs,
                        s.snap_length,
                        s.output_path,
                        engine,
                    ));
                }
                #[cfg(not(feature = "pcap-capture"))]
                {
                    tracing::warn!(
                        capture_id = %s.id,
                        "auto-capture: pcap-capture feature not enabled"
                    );
                    cap_engine_clone.write().await.fail(&s.id);
                }
            }
        });

        info!("auto-capture wired");
    }

    // Wire GeoIP to domain services
    if let Some(ref geoip) = geoip_port {
        {
            let mut svc = (**ddos_svc.load()).clone();
            svc.set_geoip_port(Arc::clone(geoip));
            ddos_svc.store(Arc::new(svc));
        }
        {
            let mut svc = (**ips_svc.load()).clone();
            svc.set_geoip_port(Arc::clone(geoip));
            ips_svc.store(Arc::new(svc));
        }
        {
            let mut svc = (**ids_svc.load()).clone();
            svc.set_geoip_port(Arc::clone(geoip));
            ids_svc.store(Arc::new(svc));
        }
        {
            let mut svc = (**l7_svc.load()).clone();
            svc.set_geoip_port(Arc::clone(geoip));
            l7_svc.store(Arc::new(svc));
        }
        {
            let mut svc = (**ti_svc.load()).clone();
            svc.set_geoip_port(Arc::clone(geoip));
            ti_svc.store(Arc::new(svc));
        }
        rl_svc.write().await.set_geoip_port(Arc::clone(geoip));
        routing_svc.write().await.set_geoip_port(Arc::clone(geoip));
        info!("GeoIP wired to DDoS, IPS, IDS, L7, ThreatIntel, RateLimit, Routing");
    }

    // Wire ThreatIntel country confidence boost from config
    if let Some(ref boost) = config.threatintel.country_confidence_boost {
        let mut svc = (**ti_svc.load()).clone();
        svc.engine_mut().set_country_confidence_boost(boost.clone());
        ti_svc.store(Arc::new(svc));
    }

    // Wire DNS blocklist GeoIP reputation
    if let Some(ref geoip) = geoip_port
        && let Some(ref dns_bl) = dns_blocklist_ref
    {
        dns_bl.set_geoip_port(Arc::clone(geoip));
        if let Some(ref rep_svc) = app_state.domain_reputation_service {
            dns_bl.set_reputation_port(Arc::clone(rep_svc)
                as Arc<dyn ports::secondary::domain_reputation_port::DomainReputationPort>);
        }
        dns_bl.set_high_risk_countries(config.dns.reputation.high_risk_countries.clone());
    }

    // Wire alert senders
    let retry_config = RetryConfig::default();

    // Log sender (always available)
    let log_sender: Arc<dyn AlertSender> = Arc::new(LogAlertSender);
    alert_pipeline = alert_pipeline.with_log_sender(log_sender);
    info!("log alert sender initialized");

    // Webhook sender (if any webhook routes exist)
    let has_webhook_routes = config
        .alerting
        .routes
        .iter()
        .any(|r| r.destination.eq_ignore_ascii_case("webhook"));
    if has_webhook_routes {
        let cb = CircuitBreaker::new(5, Duration::from_mins(1));
        let webhook_sender: Arc<dyn AlertSender> = Arc::new(WebhookAlertSender::new(
            cb,
            retry_config.clone(),
            Arc::clone(&metrics) as Arc<dyn MetricsPort>,
            "webhook".to_string(),
        ));
        alert_pipeline = alert_pipeline.with_webhook_sender(webhook_sender);
        info!("webhook alert sender initialized");
    }

    // Email sender (if SMTP config present and email routes exist)
    let has_email_routes = config
        .alerting
        .routes
        .iter()
        .any(|r| r.destination.eq_ignore_ascii_case("email"));
    if has_email_routes && let Some(ref smtp) = config.alerting.smtp {
        let cb = CircuitBreaker::new(5, Duration::from_mins(1));
        let email_sender = EmailAlertSender::new(
            &smtp.host,
            smtp.port,
            smtp.username.as_deref(),
            smtp.password.as_deref(),
            smtp.tls,
            smtp.from_address.clone(),
            cb,
            retry_config,
            Arc::clone(&metrics) as Arc<dyn MetricsPort>,
            "email".to_string(),
        )?;
        let email_sender: Arc<dyn AlertSender> = Arc::new(email_sender);
        alert_pipeline = alert_pipeline.with_email_sender(email_sender);
        info!(
            smtp_host = %smtp.host,
            smtp_port = smtp.port,
            "email alert sender initialized"
        );
    }

    // OTLP sender (if otlp config present and otlp routes exist)
    let has_otlp_routes = config
        .alerting
        .routes
        .iter()
        .any(|r| r.destination.eq_ignore_ascii_case("otlp"));
    if has_otlp_routes {
        if let Some(ref otlp_cfg) = config.alerting.otlp {
            let otlp_sender = adapters::alert::otlp_sender::OtlpAlertSender::new(
                &otlp_cfg.endpoint,
                &otlp_cfg.protocol,
                std::time::Duration::from_millis(otlp_cfg.timeout_ms),
                Arc::clone(&metrics) as Arc<dyn MetricsPort>,
            )?;
            alert_pipeline = alert_pipeline.with_otlp_sender(Arc::new(otlp_sender));
            info!(
                endpoint = %otlp_cfg.endpoint,
                protocol = %otlp_cfg.protocol,
                "OTLP alert sender initialized"
            );
        } else {
            tracing::warn!("OTLP route configured but no [alerting.otlp] config — skipping");
        }
    }

    info!(
        route_count = config.alerting.routes.len(),
        dedup_window_secs = config.alerting.dedup_window_secs,
        throttle_max = config.alerting.throttle_max,
        "alert pipeline initialized"
    );
    let alert_cancel = cancel_token.clone();
    let alert_handle = tokio::spawn(async move {
        alert_pipeline.run(alert_rx, alert_cancel).await;
    });

    // ── 11c. Spawn threat intel feed fetcher (periodic) ───────────────
    let _feed_fetch_handle = if config.threatintel.enabled && !config.threatintel.feeds.is_empty() {
        let fetcher = adapters::threatintel::HttpFeedFetcher::default();
        let feed_ti_svc = Arc::clone(&ti_svc);
        let feed_metrics = Arc::clone(&metrics) as Arc<dyn MetricsPort>;
        let feed_cancel = cancel_token.clone();
        let feed_dns_blocklist = dns_blocklist_ref.clone();
        // Use the minimum refresh interval across all enabled feeds (floor: 60s).
        let refresh_secs = config
            .threatintel
            .feeds
            .iter()
            .filter(|f| f.enabled)
            .map(|f| f.refresh_interval_secs)
            .filter(|s| *s > 0)
            .min()
            .unwrap_or(3600)
            .max(60);
        info!(
            refresh_interval_secs = refresh_secs,
            feed_count = config.threatintel.feeds.len(),
            "threat intel feed fetcher starting"
        );
        let mut refresh_rx = feed_refresh_rx
            .take()
            .expect("feed refresh rx present when feeds active");
        Some(tokio::spawn(async move {
            // Initial fetch at startup.
            run_ti_feed_cycle(
                &feed_ti_svc,
                &fetcher,
                &feed_metrics,
                feed_dns_blocklist.as_ref(),
                "initial",
            )
            .await;

            let mut interval = tokio::time::interval(Duration::from_secs(refresh_secs));
            interval.tick().await; // skip the first immediate tick (already fetched above)
            loop {
                tokio::select! {
                    () = feed_cancel.cancelled() => break,
                    _ = interval.tick() => {
                        run_ti_feed_cycle(
                            &feed_ti_svc,
                            &fetcher,
                            &feed_metrics,
                            feed_dns_blocklist.as_ref(),
                            "periodic",
                        )
                        .await;
                    }
                    msg = refresh_rx.recv() => match msg {
                        Some(()) => {
                            info!("manual threat intel feed refresh triggered");
                            run_ti_feed_cycle(
                                &feed_ti_svc,
                                &fetcher,
                                &feed_metrics,
                                feed_dns_blocklist.as_ref(),
                                "manual",
                            )
                            .await;
                        }
                        // All refresh senders dropped — happens only at shutdown.
                        None => break,
                    },
                }
            }
        }))
    } else {
        None
    };

    // ── 11c½. Spawn eBPF kernel metrics reader (periodic, every 10s) ──
    if !metrics_readers.is_empty() {
        info!(
            reader_count = metrics_readers.len(),
            maps = ?metrics_readers.iter().map(MetricsReader::map_name).collect::<Vec<_>>(),
            "eBPF kernel metrics reader starting"
        );
        let kr_cancel = cancel_token.clone();
        let kr_metrics = Arc::clone(&metrics) as Arc<dyn MetricsPort>;
        let shared_readers = Arc::new(RwLock::new(metrics_readers));
        tokio::spawn(async move {
            crate::ebpf_metrics::run_kernel_metrics_loop(
                shared_readers,
                kr_metrics,
                Duration::from_secs(10),
                kr_cancel,
            )
            .await;
        });
    }

    // ── 11d. Spawn schedule evaluator (periodic, every 60s) ──────────
    let _schedule_handle = if config.firewall.schedules.is_empty() {
        None
    } else {
        let sched_svc = Arc::clone(&schedule_svc);
        let sched_fw_svc = Arc::clone(&firewall_svc);
        let sched_cancel = cancel_token.clone();
        info!(
            schedule_count = config.firewall.schedules.len(),
            "schedule evaluator starting (60s interval)"
        );
        Some(tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_mins(1));
            loop {
                tokio::select! {
                    () = sched_cancel.cancelled() => break,
                    _ = interval.tick() => {}
                }
                let (day, minutes) = crate::schedule_eval::local_day_and_minutes();
                let changed = sched_svc.write().await.evaluate_at(day, minutes);
                if let Some(ref active_ids) = changed {
                    tracing::info!(
                        active_count = active_ids.len(),
                        "schedule change: active rule set updated"
                    );
                    tracing::debug!(?active_ids, "active scheduled rule IDs");
                    sched_fw_svc.write().await.apply_schedule(active_ids);
                }
            }
        }))
    };

    // ── 11e. Spawn IPS/IDS cleanup task (every 60s) ──────────────────
    {
        let cleanup_ips = Arc::clone(&ips_svc);
        let cleanup_ids = Arc::clone(&ids_svc);
        let cleanup_cancel = cancel_token.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_mins(1));
            interval.tick().await; // skip first immediate tick
            loop {
                tokio::select! {
                    () = cleanup_cancel.cancelled() => break,
                    _ = interval.tick() => {}
                }
                // IPS: remove expired blacklist entries
                let actions = cleanup_ips.load().cleanup_expired();
                if !actions.is_empty() {
                    tracing::info!(
                        expired_count = actions.len(),
                        "IPS cleanup: removed expired blacklist entries"
                    );
                }
                // IDS: remove expired threshold tracking entries
                cleanup_ids.load().cleanup_expired_thresholds();
            }
        });
    }

    // ── 11f. Spawn periodic dynamic alias refresh (GeoIP + URL tables) ──
    {
        let refresh_interval_secs = config
            .geoip
            .as_ref()
            .filter(|c| c.enabled)
            .map_or(0, |c| c.refresh_interval_hours * 3600);

        if refresh_interval_secs > 0 {
            let alias_svc_clone = Arc::clone(&alias_svc);
            let refresh_cancel = cancel_token.clone();
            tokio::spawn(async move {
                let mut interval =
                    tokio::time::interval(Duration::from_secs(refresh_interval_secs));
                interval.tick().await; // skip first (already done at startup)
                loop {
                    tokio::select! {
                        () = refresh_cancel.cancelled() => break,
                        _ = interval.tick() => {}
                    }
                    match alias_svc_clone.write().await.refresh_dynamic() {
                        Ok(n) => info!(count = n, "periodic dynamic alias refresh completed"),
                        Err(e) => warn!("periodic dynamic alias refresh failed: {e}"),
                    }
                }
            });
            info!(
                interval_hours = config
                    .geoip
                    .as_ref()
                    .map_or(0, |c| c.refresh_interval_hours),
                "periodic dynamic alias refresh task spawned"
            );
        }
    }

    // ── 12. Ready — wait for cancellation ───────────────────────────
    info!("agent ready, waiting for shutdown signal");
    cancel_token.cancelled().await;

    // ── 13. Ordered shutdown sequence ───────────────────────────────
    info!("shutdown phase 1: cancelling tasks");
    // Token is already cancelled — all tasks received the signal.

    info!("shutdown phase 2: draining HTTP and gRPC connections");
    let _ = tokio::time::timeout(GRACEFUL_SHUTDOWN_TIMEOUT, http_handle).await;
    let _ = tokio::time::timeout(GRACEFUL_SHUTDOWN_TIMEOUT, grpc_handle).await;

    info!("shutdown phase 3: stopping config watcher");
    let _ = tokio::time::timeout(Duration::from_secs(1), reload_handle).await;

    info!("shutdown phase 4: detaching eBPF programs");
    ebpf_manager.lock().await.detach_all().await;
    drop(ebpf_state); // Drop startup loaders (detaches legacy programs)

    info!("shutdown phase 5: draining events and alerts");
    drop(event_tx); // close event channel so dispatcher sees channel closed
    let _ = tokio::time::timeout(Duration::from_secs(2), dispatcher_handle).await;
    drop(alert_tx); // close alert channel so alert consumer sees channel closed
    let _ = tokio::time::timeout(Duration::from_secs(1), alert_handle).await;

    info!("agent stopped");
    Ok(())
}

/// Holds eBPF resources that must live for the duration of the agent.
///
/// When dropped, all loaders are dropped and their eBPF programs are detached.
/// On kernel >= 6.6 (TCX), TC link FDs auto-close even on SIGKILL, so programs
/// do not persist after a crash. Pinned maps are cleaned up as defense-in-depth.
pub struct EbpfState {
    pub loaders: Vec<EbpfLoader>,
    /// BPF token + bpffs fds kept alive for the lifetime of the
    /// process. Dropping them would invalidate any programs loaded
    /// through the token.
    pub bpf_handle: Option<adapters::ebpf::BpfLoadingHandle>,
}

impl Default for EbpfState {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for EbpfState {
    fn drop(&mut self) {
        // Loaders are dropped first (aya detaches programs via link FDs).
        // Then clean up any pinned maps left on the BPF filesystem.
        self.loaders.clear();
        EbpfLoader::cleanup_pin_path(adapters::ebpf::DEFAULT_BPF_PIN_PATH);
    }
}

impl EbpfState {
    pub fn new() -> Self {
        Self {
            loaders: Vec::new(),
            bpf_handle: None,
        }
    }

    pub fn add_loader(&mut self, loader: EbpfLoader) {
        self.loaders.push(loader);
    }

    pub fn attach_bpf_handle(&mut self, handle: adapters::ebpf::BpfLoadingHandle) {
        self.bpf_handle = Some(handle);
    }
}

/// Verify the process has sufficient privileges to load eBPF programs.
///
/// Checks for root (UID 0) or the required Linux capabilities
/// (`CAP_BPF` + `CAP_NET_ADMIN`, or `CAP_SYS_ADMIN`).
/// Fails fast with a clear error instead of waiting for cryptic kernel errors.
fn check_ebpf_privileges() -> anyhow::Result<()> {
    const CAP_NET_ADMIN: u64 = 1 << 12;
    const CAP_SYS_ADMIN: u64 = 1 << 21;
    const CAP_BPF: u64 = 1 << 39;

    let status = std::fs::read_to_string("/proc/self/status")
        .map_err(|e| anyhow::anyhow!("cannot read /proc/self/status: {e}"))?;

    // Check if running as root
    let is_root = status
        .lines()
        .any(|line| line.starts_with("Uid:") && line.split_whitespace().nth(1) == Some("0"));
    if is_root {
        return Ok(());
    }

    // Check effective capabilities for CAP_BPF(39)+CAP_NET_ADMIN(12) or CAP_SYS_ADMIN(21)
    let cap_eff = status
        .lines()
        .find(|line| line.starts_with("CapEff:"))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|hex| u64::from_str_radix(hex, 16).ok())
        .unwrap_or(0);

    let has_sys_admin = cap_eff & CAP_SYS_ADMIN != 0;
    let has_bpf_and_net = cap_eff & CAP_BPF != 0 && cap_eff & CAP_NET_ADMIN != 0;

    if has_sys_admin || has_bpf_and_net {
        return Ok(());
    }

    Err(anyhow::anyhow!(
        "insufficient privileges to load eBPF programs — \
         run as root or grant CAP_BPF + CAP_NET_ADMIN capabilities"
    ))
}

/// Verify the kernel version is **>= 6.9**.
///
/// The 6.9 floor is mandatory — there is **no graceful fallback on
/// older kernels**. The agent relies on the following kernel features
/// across every eBPF program:
///
/// - `BPF_TOKEN_CREATE` + `BPF_F_TOKEN_FD` (6.9) — container-aware
///   least-privilege loading
/// - `bpf_task_get_cgroup1` kfunc (6.8) — cgroup1 inode enrichment
/// - `bpf_xdp_metadata_rx_vlan_tag` / `bpf_xdp_get_xfrm_state` /
///   `bpf_iter_css_task` kfuncs (6.7 / 6.8)
/// - netfilter conntrack lookup / alloc / NAT delegation kfuncs
///   (5.18 / 6.0 / 6.1) consumed via `ebpf_helpers::kfuncs`
/// - dynptr skb / xdp slice helpers (6.4 / 6.5)
///
/// A kernel that fails this check **cannot** run the agent in a
/// degraded mode — the eBPF verifier rejects every program at load
/// time because the kfuncs are not present in `vmlinux` BTF. The
/// correct response is to upgrade the kernel. The three BPF loading
/// modes (token / capabilities / privileged) all still work, but
/// only on top of a 6.9+ kernel.
fn check_kernel_version() -> anyhow::Result<()> {
    check_kernel_version_from(std::path::Path::new("/proc/sys/kernel/osrelease"))
}

/// Mandatory kernel minimum: **6.9**. Exposed as a const so tests
/// and docs cite a single source of truth.
pub const MIN_KERNEL_MAJOR: u32 = 6;
pub const MIN_KERNEL_MINOR: u32 = 9;

fn check_kernel_version_from(path: &std::path::Path) -> anyhow::Result<()> {
    let release = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("cannot read kernel version from {}: {e}", path.display()))?;

    let version = release.trim();
    let mut parts = version.split(|c: char| !c.is_ascii_digit());
    let major = parts
        .next()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);
    let minor = parts
        .next()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);

    if major > MIN_KERNEL_MAJOR || (major == MIN_KERNEL_MAJOR && minor >= MIN_KERNEL_MINOR) {
        return Ok(());
    }

    Err(anyhow::anyhow!(
        "kernel {version} is below the mandatory minimum {MIN_KERNEL_MAJOR}.{MIN_KERNEL_MINOR} — \
         eBPFsentinel refuses to start. Required features: BPF token delegation, \
         cgroup1 kfunc, XDP metadata kfuncs, netfilter conntrack kfuncs, dynptr \
         helpers. No fallback path exists — upgrade the host kernel \
         to 6.9+ and restart the agent."
    ))
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod kernel_version_tests {
    use super::*;
    use std::io::Write;

    fn write_osrelease(dir: &tempfile::TempDir, contents: &str) -> std::path::PathBuf {
        let p = dir.path().join("osrelease");
        let mut f = std::fs::File::create(&p).expect("create osrelease stub");
        f.write_all(contents.as_bytes()).expect("write osrelease");
        p
    }

    #[test]
    fn accepts_kernel_6_9_exact() {
        let tmp = tempfile::tempdir().unwrap();
        let p = write_osrelease(&tmp, "6.9.0-060900-generic\n");
        assert!(check_kernel_version_from(&p).is_ok());
    }

    #[test]
    fn accepts_kernel_6_10() {
        let tmp = tempfile::tempdir().unwrap();
        let p = write_osrelease(&tmp, "6.10.4-generic\n");
        assert!(check_kernel_version_from(&p).is_ok());
    }

    #[test]
    fn accepts_kernel_7_0() {
        let tmp = tempfile::tempdir().unwrap();
        let p = write_osrelease(&tmp, "7.0.0-experimental\n");
        assert!(check_kernel_version_from(&p).is_ok());
    }

    #[test]
    fn rejects_kernel_6_8() {
        let tmp = tempfile::tempdir().unwrap();
        let p = write_osrelease(&tmp, "6.8.0-ubuntu-24.04\n");
        let err = check_kernel_version_from(&p).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("below the mandatory minimum 6.9"));
        assert!(msg.contains("No fallback path exists"));
    }

    #[test]
    fn rejects_kernel_6_6() {
        let tmp = tempfile::tempdir().unwrap();
        let p = write_osrelease(&tmp, "6.6.0\n");
        assert!(check_kernel_version_from(&p).is_err());
    }

    #[test]
    fn rejects_kernel_5_15() {
        let tmp = tempfile::tempdir().unwrap();
        let p = write_osrelease(&tmp, "5.15.149-generic\n");
        assert!(check_kernel_version_from(&p).is_err());
    }

    #[test]
    fn rejects_missing_osrelease_path() {
        let bogus = std::path::Path::new("/nonexistent/kernel/osrelease");
        assert!(check_kernel_version_from(bogus).is_err());
    }

    #[test]
    fn rejects_malformed_content() {
        let tmp = tempfile::tempdir().unwrap();
        let p = write_osrelease(&tmp, "not-a-version\n");
        // parse yields (0, 0) → below minimum → Err
        assert!(check_kernel_version_from(&p).is_err());
    }
}

/// Resolve the directory containing compiled eBPF program binaries.
///
/// Precedence: `EBPF_PROGRAM_DIR` env var > `agent.ebpf_program_dir` config
/// > production default (`/usr/local/lib/ebpfsentinel`)
/// > dev fallback (`target/bpfel-unknown-none/release`).
pub fn resolve_ebpf_program_dir(config: &AgentConfig) -> String {
    use infrastructure::constants::{DEFAULT_EBPF_PROGRAM_DIR, DEFAULT_EBPF_PROGRAM_DIR_DEV};

    // 1. Env var (highest priority, set in Dockerfile / systemd unit)
    if let Ok(dir) = std::env::var("EBPF_PROGRAM_DIR") {
        return dir;
    }
    // Legacy single-file env var: derive directory from it
    if let Ok(path) = std::env::var("EBPF_PROGRAM_PATH")
        && let Some(parent) = Path::new(&path).parent()
    {
        return parent.to_string_lossy().into_owned();
    }
    // 2. Config file
    if let Some(ref dir) = config.agent.ebpf_program_dir {
        return dir.clone();
    }
    // 3. Production default, fall back to dev path
    if Path::new(DEFAULT_EBPF_PROGRAM_DIR).is_dir() {
        DEFAULT_EBPF_PROGRAM_DIR.to_string()
    } else {
        DEFAULT_EBPF_PROGRAM_DIR_DEV.to_string()
    }
}

/// Read a single eBPF program binary from the program directory.
pub fn read_ebpf_program(dir: &str, name: &str) -> anyhow::Result<Vec<u8>> {
    let path = Path::new(dir).join(name);
    std::fs::read(&path)
        .map_err(|e| anyhow::anyhow!("failed to read eBPF program '{}': {e}", path.display()))
}

// ── Per-program load functions ───────────────────────────────────────

/// Load the XDP firewall program: attach XDP, populate rules, create event reader.
pub fn try_load_xdp_firewall(
    ebpf_dir: &str,
    config: &AgentConfig,
    domain_rules: &[FirewallRule],
) -> anyhow::Result<(
    EbpfLoader,
    FirewallMapManager,
    Option<MetricsReader>,
    EventReader,
)> {
    use ebpf_common::firewall::{DEFAULT_POLICY_DROP, DEFAULT_POLICY_PASS};
    use infrastructure::config::DefaultPolicy;

    let program_bytes = read_ebpf_program(ebpf_dir, "xdp-firewall")?;
    let mut loader = EbpfLoader::load_with_pin_path_dev_bound(
        &program_bytes,
        adapters::ebpf::DEFAULT_BPF_PIN_PATH,
        metadata_dev_bound_ifindex(config),
    )?;

    let xdp_flags = adapters::ebpf::xdp_mode_to_flags(config.agent.xdp_mode);
    for iface in &config.agent.interfaces {
        loader.attach_xdp(iface, xdp_flags)?;
    }

    let mut map_manager = FirewallMapManager::new(loader.ebpf_mut())?;

    // Push nf_conn BTF offsets to xdp-firewall so it can read kernel
    // CT status via bpf_probe_read_kernel (replaces CT_TABLE shadow).
    if let Ok(offsets) = resolve_nf_conn_offsets()
        && let Err(e) =
            adapters::ebpf::conntrack_map_manager::push_nf_conn_offsets(loader.ebpf_mut(), offsets)
    {
        warn!("xdp-firewall: nf_conn offset push failed: {e}");
    }

    let policy_byte = match config.firewall.default_policy {
        DefaultPolicy::Drop => DEFAULT_POLICY_DROP,
        DefaultPolicy::Pass => DEFAULT_POLICY_PASS,
    };
    map_manager.set_default_policy(policy_byte)?;

    let mut v4_entries = Vec::new();
    let mut v6_entries = Vec::new();
    for rule in domain_rules {
        if !rule.enabled {
            continue;
        }
        if rule.is_v6() {
            v6_entries.push(rule.to_ebpf_entry_v6());
        } else {
            v4_entries.push(rule.to_ebpf_entry());
        }
    }
    map_manager.load_v4_rules(&v4_entries)?;
    map_manager.load_v6_rules(&v6_entries)?;

    // Populate ZONE_MAP (ifindex → zone_id) if zone config is present
    if config.zones.enabled
        && let Ok(zone_cfg) = config.zone_config()
    {
        adapters::ebpf::map_manager::populate_zone_map(loader.ebpf_mut(), &zone_cfg);
    }

    // Populate DDOS_CPUMAP with all online CPUs for DDoS CPU steering.
    adapters::ebpf::cpumap::populate_cpumap(loader.ebpf_mut(), "DDOS_CPUMAP");

    let metrics_rdr = MetricsReader::new(loader.ebpf_mut(), "FIREWALL_METRICS").ok();

    let reader = EventReader::new(loader.ebpf_mut())?;

    Ok((loader, map_manager, metrics_rdr, reader))
}

/// Load the xdp-firewall-reject program and wire it as a tail-call target.
///
/// The reject program is loaded with the same pin path so that `PKT_CTX` and
/// `FIREWALL_METRICS` maps are shared with xdp-firewall. It is loaded but NOT
/// attached to any interface — it is invoked only via tail-call from
/// xdp-firewall (`ProgramArray` slot 1).
pub fn try_load_xdp_firewall_reject(
    ebpf_dir: &str,
    fw_loader: &mut EbpfLoader,
) -> anyhow::Result<EbpfLoader> {
    let program_bytes = read_ebpf_program(ebpf_dir, "xdp-firewall-reject")?;
    // Raw load so this tail-call target matches the kfunc-raw-loaded
    // xdp-firewall owner of XDP_PROG_ARRAY (see `load_xdp_raw_with_pin_path`).
    let mut reject_loader = EbpfLoader::load_xdp_raw_with_pin_path(
        &program_bytes,
        adapters::ebpf::DEFAULT_BPF_PIN_PATH,
    )?;

    // Load the XDP program (verifier check) but don't attach to an interface.
    reject_loader.load_xdp_program("xdp_firewall_reject")?;

    // Wire into firewall's ProgramArray at slot 1.
    let reject_fd = reject_loader.program_raw_fd("xdp_firewall_reject")?;
    fw_loader.set_tail_call_raw("XDP_PROG_ARRAY", 1, reject_fd)?;

    Ok(reject_loader)
}

/// Load result for xdp-ratelimit: loader, map manager, LPM manager, metrics readers, event reader.
pub type XdpRatelimitResult = (
    EbpfLoader,
    Option<RateLimitMapManager>,
    Option<RateLimitLpmManager>,
    Vec<MetricsReader>,
    EventReader,
);

/// Load the xdp-ratelimit-syncookie program and wire it as a tail-call target.
///
/// Shared maps: `SYNCOOKIE_CTX`, `SYNCOOKIE_SECRET`, `DDOS_METRICS`.
/// Loaded but NOT attached — invoked via tail-call from xdp-ratelimit (`RL_PROG_ARRAY` slot 0).
pub fn try_load_xdp_ratelimit_syncookie(
    ebpf_dir: &str,
    rl_loader: &mut EbpfLoader,
) -> anyhow::Result<EbpfLoader> {
    let program_bytes = read_ebpf_program(ebpf_dir, "xdp-ratelimit-syncookie")?;
    // Raw load so this tail-call target matches the kfunc-raw-loaded
    // xdp-ratelimit owner of RL_PROG_ARRAY (see `load_xdp_raw_with_pin_path`).
    let mut sc_loader = EbpfLoader::load_xdp_raw_with_pin_path(
        &program_bytes,
        adapters::ebpf::DEFAULT_BPF_PIN_PATH,
    )?;
    sc_loader.load_xdp_program("xdp_ratelimit_syncookie")?;
    let sc_fd = sc_loader.program_raw_fd("xdp_ratelimit_syncookie")?;
    rl_loader.set_tail_call_raw("RL_PROG_ARRAY", 0, sc_fd)?;
    Ok(sc_loader)
}

pub fn try_load_xdp_ratelimit(
    ebpf_dir: &str,
    config: &AgentConfig,
    firewall_active: bool,
) -> anyhow::Result<XdpRatelimitResult> {
    let program_bytes = read_ebpf_program(ebpf_dir, "xdp-ratelimit")?;
    let mut loader = EbpfLoader::load_with_pin_path_dev_bound(
        &program_bytes,
        adapters::ebpf::DEFAULT_BPF_PIN_PATH,
        metadata_dev_bound_ifindex(config),
    )?;

    if firewall_active {
        // Firewall is active: load the program (verifier check) but do NOT
        // attach to any interface. The firewall tail-calls into ratelimit
        // via XDP_PROG_ARRAY slot 0.
        loader.load_xdp_program("xdp_ratelimit")?;
        info!("xdp-ratelimit loaded as tail-call target (firewall active)");
    } else {
        // Standalone mode: attach directly to the interface.
        let xdp_flags = adapters::ebpf::xdp_mode_to_flags(config.agent.xdp_mode);
        for iface in &config.agent.interfaces {
            loader.attach_xdp_program("xdp_ratelimit", iface, xdp_flags)?;
        }
    }

    let rl_mgr_opt = match RateLimitMapManager::new(loader.ebpf_mut()) {
        Ok(mut rl_mgr) => {
            let policies = config.ratelimit_policies()?;
            let default_algo = parse_algorithm_byte(&config.ratelimit.default_algorithm);
            rl_mgr.load_policies(
                &policies,
                config.ratelimit.default_rate,
                config.ratelimit.default_burst,
                default_algo,
            )?;
            Some(rl_mgr)
        }
        Err(e) => {
            warn!("RATELIMIT_CONFIG map not available: {e}");
            None
        }
    };

    let rl_lpm_opt = match RateLimitLpmManager::new(loader.ebpf_mut()) {
        Ok(lpm_mgr) => Some(lpm_mgr),
        Err(e) => {
            warn!("rate limit LPM maps not available: {e}");
            None
        }
    };

    // Set SYN cookie secret (random 32-byte key for cookie generation/validation)
    match SyncookieSecretManager::new(loader.ebpf_mut()) {
        Ok(mut mgr) => {
            // The SYN-cookie PRF is only unforgeable if its key is
            // unpredictable, so seed it from the kernel CSPRNG rather than a
            // guessable clock value. Read 32 bytes from /dev/urandom into the
            // eight key words (native endianness — the key is opaque).
            let mut key_bytes = [0u8; 32];
            std::fs::File::open("/dev/urandom")
                .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut key_bytes))
                .expect("/dev/urandom should be readable");
            let mut key = [0u32; 8];
            for (slot, chunk) in key.iter_mut().zip(key_bytes.chunks_exact(4)) {
                *slot = u32::from_ne_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            }
            let secret = ebpf_common::ddos::SyncookieSecret { key };
            if let Err(e) = mgr.set_secret(&secret) {
                warn!("SYN cookie secret write failed (non-fatal): {e}");
            }
        }
        Err(e) => {
            warn!("SYNCOOKIE_SECRET map not available (non-fatal): {e}");
        }
    }

    // Arm SYN-cookie protection: the xdp-ratelimit `check_syn_flood` path
    // reads `DDOS_SYN_CONFIG` (zeroed → disabled by default), so it never
    // forges cookies unless userspace writes `enabled = 1` here.
    if config.ddos.enabled && config.ddos.syn_protection.enabled {
        match DdosSynConfigManager::new(loader.ebpf_mut()) {
            Ok(mut mgr) => {
                let syn_cfg = ebpf_common::ddos::DdosSynConfig {
                    enabled: 1,
                    threshold_mode: u8::from(config.ddos.syn_protection.threshold_mode),
                    _pad: [0; 6],
                    threshold_pps: config.ddos.syn_protection.threshold_pps,
                };
                if let Err(e) = mgr.set_config(&syn_cfg) {
                    warn!("DDOS_SYN_CONFIG write failed (syncookie disabled): {e}");
                }
            }
            Err(e) => {
                warn!("DDOS_SYN_CONFIG map not available (non-fatal): {e}");
            }
        }
    }

    let mut rdrs = Vec::new();
    if let Ok(r) = MetricsReader::new(loader.ebpf_mut(), "RATELIMIT_METRICS") {
        rdrs.push(r);
    }
    if let Ok(r) = MetricsReader::new(loader.ebpf_mut(), "DDOS_METRICS") {
        rdrs.push(r);
    }

    let reader = EventReader::new(loader.ebpf_mut())?;

    Ok((loader, rl_mgr_opt, rl_lpm_opt, rdrs, reader))
}

/// IDS program load result: loader, IDS map manager, L7 ports manager, config flags manager, metrics reader, event reader.
pub type TcIdsResult = (
    EbpfLoader,
    Option<IdsMapManager>,
    Option<L7PortsManager>,
    Option<ConfigFlagsManager>,
    Option<MetricsReader>,
    EventReader,
);

/// Load the TC IDS program: attach TC ingress, set up maps, create event reader.
pub fn try_load_tc_ids(ebpf_dir: &str, config: &AgentConfig) -> anyhow::Result<TcIdsResult> {
    let program_bytes = read_ebpf_program(ebpf_dir, "tc-ids")?;
    let mut loader =
        EbpfLoader::load_with_pin_path(&program_bytes, adapters::ebpf::DEFAULT_BPF_PIN_PATH)?;

    for iface in &config.agent.interfaces {
        attach_tc_auto(&mut loader, "tc_ids", iface, config.agent.attach_mode)?;
    }

    // IDS map manager (best-effort: non-fatal if maps not present)
    let ids_mgr_opt = match IdsMapManager::new(loader.ebpf_mut()) {
        Ok(ids_mgr) => {
            info!("tc-ids IDS_PATTERNS map initialized");
            Some(ids_mgr)
        }
        Err(e) => {
            warn!("IDS_PATTERNS map not available: {e}");
            None
        }
    };
    let l7_mgr_opt = match L7PortsManager::new(loader.ebpf_mut()) {
        Ok(mut l7_mgr) => {
            let ports = config.l7_ports();
            if let Err(e) = l7_mgr.set_ports(&ports) {
                warn!("failed to set L7 ports: {e}");
            }
            Some(l7_mgr)
        }
        Err(e) => {
            warn!("L7_PORTS map not available: {e}");
            None
        }
    };
    let cfg_mgr_opt = match ConfigFlagsManager::new(loader.ebpf_mut()) {
        Ok(mut cfg_mgr) => {
            let flags = build_config_flags(config);
            if let Err(e) = cfg_mgr.set_flags(&flags) {
                warn!("failed to set CONFIG_FLAGS: {e}");
            }
            Some(cfg_mgr)
        }
        Err(e) => {
            warn!("CONFIG_FLAGS map not available in tc-ids: {e}");
            None
        }
    };

    let ids_metrics_rdr = MetricsReader::new(loader.ebpf_mut(), "IDS_METRICS").ok();

    let reader = EventReader::new(loader.ebpf_mut())?;

    Ok((
        loader,
        ids_mgr_opt,
        l7_mgr_opt,
        cfg_mgr_opt,
        ids_metrics_rdr,
        reader,
    ))
}

/// Load the TC threat intel program: attach TC ingress, set up maps, create event reader.
/// Threat intel program load result.
pub type TcThreatIntelResult = (
    EbpfLoader,
    Option<ThreatIntelMapManager>,
    Option<ConfigFlagsManager>,
    Option<MetricsReader>,
    EventReader,
);

pub fn try_load_tc_threatintel(
    ebpf_dir: &str,
    config: &AgentConfig,
) -> anyhow::Result<TcThreatIntelResult> {
    let program_bytes = read_ebpf_program(ebpf_dir, "tc-threatintel")?;
    let mut loader =
        EbpfLoader::load_with_pin_path(&program_bytes, adapters::ebpf::DEFAULT_BPF_PIN_PATH)?;

    for iface in &config.agent.interfaces {
        attach_tc_auto(
            &mut loader,
            "tc_threatintel",
            iface,
            config.agent.attach_mode,
        )?;
    }

    let ti_mgr_opt = match ThreatIntelMapManager::new(loader.ebpf_mut()) {
        Ok(ti_mgr) => {
            info!("tc-threatintel maps initialized");
            Some(ti_mgr)
        }
        Err(e) => {
            warn!("THREATINTEL_IOCS map not available: {e}");
            None
        }
    };
    let cfg_mgr_opt = match ConfigFlagsManager::new(loader.ebpf_mut()) {
        Ok(mut cfg_mgr) => {
            let flags = build_config_flags(config);
            if let Err(e) = cfg_mgr.set_flags(&flags) {
                warn!("failed to set CONFIG_FLAGS: {e}");
            }
            Some(cfg_mgr)
        }
        Err(e) => {
            warn!("CONFIG_FLAGS map not available in tc-threatintel: {e}");
            None
        }
    };

    let ti_metrics_rdr = MetricsReader::new(loader.ebpf_mut(), "THREATINTEL_METRICS").ok();

    let reader = EventReader::new(loader.ebpf_mut())?;

    Ok((loader, ti_mgr_opt, cfg_mgr_opt, ti_metrics_rdr, reader))
}

/// Load the TC DNS program: attach TC ingress, create DNS event reader.
pub fn try_load_tc_dns(
    ebpf_dir: &str,
    config: &AgentConfig,
) -> anyhow::Result<(EbpfLoader, Option<MetricsReader>, DnsEventReader)> {
    let program_bytes = read_ebpf_program(ebpf_dir, "tc-dns")?;
    let mut loader =
        EbpfLoader::load_with_pin_path(&program_bytes, adapters::ebpf::DEFAULT_BPF_PIN_PATH)?;

    for iface in &config.agent.interfaces {
        attach_tc_auto(&mut loader, "tc_dns", iface, config.agent.attach_mode)?;
    }

    let dns_metrics_rdr = MetricsReader::new(loader.ebpf_mut(), "DNS_METRICS").ok();

    let reader = DnsEventReader::new(loader.ebpf_mut())?;

    Ok((loader, dns_metrics_rdr, reader))
}

/// Load the uprobe DLP program: attach uprobes to SSL functions, start DLP event reader.
/// Known SSL/TLS library candidates for uprobe attachment.
/// Checked in order: OpenSSL 3, OpenSSL 1.1, generic libssl, `BoringSSL`.
const SSL_LIBRARY_CANDIDATES: &[&str] = &[
    "libssl.so.3",     // OpenSSL 3.x (Debian 12+, Ubuntu 22.04+, Fedora 36+)
    "libssl.so.1.1",   // OpenSSL 1.1.x (Debian 11, Ubuntu 20.04, CentOS 8)
    "libssl.so",       // Generic symlink (some distros)
    "libboringssl.so", // BoringSSL (Google services, Envoy proxy)
];

pub fn try_load_uprobe_dlp(
    ebpf_dir: &str,
    _config: &AgentConfig,
) -> anyhow::Result<(EbpfLoader, Option<MetricsReader>, DlpEventReader)> {
    let program_bytes = read_ebpf_program(ebpf_dir, "uprobe-dlp")?;
    let mut loader =
        EbpfLoader::load_with_pin_path(&program_bytes, adapters::ebpf::DEFAULT_BPF_PIN_PATH)?;

    // Probe for a usable SSL library on the system (full path needed for aya).
    let ssl_path = find_ssl_library_path();
    let ssl_path = match ssl_path {
        Some(path) => {
            info!(library = %path, "SSL library found for DLP uprobe");
            path
        }
        None => {
            anyhow::bail!(
                "no SSL library found on system (tried: {}). \
                 DLP uprobe requires OpenSSL or BoringSSL. \
                 Install libssl-dev or equivalent package.",
                SSL_LIBRARY_CANDIDATES.join(", ")
            );
        }
    };

    loader.attach_uprobe("ssl_write", "SSL_write", &ssl_path, false)?;
    loader.attach_uprobe("ssl_read_entry", "SSL_read", &ssl_path, false)?;
    loader.attach_uprobe("ssl_read_ret", "SSL_read", &ssl_path, true)?;

    let dlp_metrics_rdr = MetricsReader::new(loader.ebpf_mut(), "DLP_METRICS").ok();

    let reader = DlpEventReader::new(loader.ebpf_mut())?;

    info!(library = %ssl_path, "uprobe-dlp attached");
    Ok((loader, dlp_metrics_rdr, reader))
}

/// Search for a usable SSL/TLS shared library on the system.
///
/// Parses `ldconfig -p` to extract the full path for each candidate,
/// then falls back to common library directories. Returns the absolute
/// path to the first library found, which aya needs for uprobe attach.
fn find_ssl_library_path() -> Option<String> {
    use std::process::Command;

    // Try ldconfig -p first (most reliable — gives full paths)
    if let Ok(output) = Command::new("ldconfig").arg("-p").output() {
        let cache = String::from_utf8_lossy(&output.stdout);
        for candidate in SSL_LIBRARY_CANDIDATES {
            // ldconfig format: "libssl.so.3 (libc6,x86-64) => /lib/x86_64-linux-gnu/libssl.so.3"
            for line in cache.lines() {
                if line.contains(candidate)
                    && let Some(path) = line.split("=> ").nth(1)
                {
                    let path = path.trim();
                    if std::path::Path::new(path).exists() {
                        return Some(path.to_string());
                    }
                }
            }
        }
    }

    // Fallback: check common paths directly
    let search_dirs = [
        "/usr/lib/x86_64-linux-gnu",
        "/usr/lib/aarch64-linux-gnu",
        "/usr/lib64",
        "/usr/lib",
        "/lib/x86_64-linux-gnu",
        "/lib64",
        "/lib",
    ];
    for candidate in SSL_LIBRARY_CANDIDATES {
        for dir in &search_dirs {
            let path = format!("{dir}/{candidate}");
            if std::path::Path::new(&path).exists() {
                return Some(path);
            }
        }
    }

    None
}

/// Build `ConfigFlags` from the agent config for eBPF programs.
pub fn build_config_flags(config: &AgentConfig) -> ebpf_common::config_flags::ConfigFlags {
    ebpf_common::config_flags::ConfigFlags {
        firewall_enabled: u8::from(config.firewall.enabled),
        ids_enabled: u8::from(config.ids.enabled),
        ips_enabled: u8::from(config.ips.enabled),
        dlp_enabled: u8::from(config.dlp.enabled),
        ratelimit_enabled: u8::from(config.ratelimit.enabled),
        threatintel_enabled: u8::from(config.threatintel.enabled),
        conntrack_enabled: u8::from(config.conntrack.enabled),
        nat_enabled: u8::from(config.nat.enabled),
    }
}

/// Resolve the ifindex of a network interface by reading from sysfs.
pub fn get_ifindex(iface: &str) -> Result<u32, anyhow::Error> {
    let path = format!("/sys/class/net/{iface}/ifindex");
    let s = std::fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("failed to read ifindex for '{iface}': {e}"))?;
    s.trim()
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid ifindex for '{iface}': {e}"))
}

/// Device-bound target ifindex for an XDP program that calls `bpf_xdp_metadata_rx_*`.
///
/// A device-bound load binds the program to ONE netdev so those kfuncs resolve
/// against its `xdp_metadata_ops`. That only fits when exactly one interface is
/// configured; with multiple (or none) we return `None` so the loader
/// neutralizes the metadata kfuncs and a single program fd attaches to every
/// interface. Returns `None` if the lone interface's ifindex can't be read
/// (the loader then neutralizes too).
fn metadata_dev_bound_ifindex(config: &AgentConfig) -> Option<u32> {
    match config.agent.interfaces.as_slice() {
        [iface] => get_ifindex(iface).ok(),
        _ => None,
    }
}

/// Convert ratelimit algorithm string to the eBPF u8 constant.
pub fn parse_algorithm_byte(algorithm: &str) -> u8 {
    match algorithm.to_lowercase().as_str() {
        "fixed_window" | "fixedwindow" => ebpf_common::ratelimit::ALGO_FIXED_WINDOW,
        "sliding_window" | "slidingwindow" => ebpf_common::ratelimit::ALGO_SLIDING_WINDOW,
        "leaky_bucket" | "leakybucket" => ebpf_common::ratelimit::ALGO_LEAKY_BUCKET,
        _ => ebpf_common::ratelimit::ALGO_TOKEN_BUCKET,
    }
}

/// Load the TC conntrack program: attach TC ingress, create map manager, create event reader.
pub fn try_load_tc_conntrack(
    ebpf_dir: &str,
    config: &AgentConfig,
) -> anyhow::Result<(
    EbpfLoader,
    ConnTrackMapManager,
    Option<MetricsReader>,
    Option<EventReader>,
)> {
    let program_bytes = read_ebpf_program(ebpf_dir, "tc-conntrack")?;
    let mut loader =
        EbpfLoader::load_with_pin_path(&program_bytes, adapters::ebpf::DEFAULT_BPF_PIN_PATH)?;

    for iface in &config.agent.interfaces {
        attach_tc_auto(&mut loader, "tc_conntrack", iface, config.agent.attach_mode)?;
    }

    let ct_mgr = ConnTrackMapManager::new(loader.ebpf_mut())?;
    let ct_metrics_rdr = MetricsReader::new(loader.ebpf_mut(), "CT_METRICS").ok();

    // Resolve nf_conn field offsets from vmlinux BTF and push to the
    // CT_NF_CONN_OFFSETS array map so tc-conntrack can read kernel CT
    // fields via bpf_probe_read_kernel at the correct offsets.
    if let Ok(offsets) = resolve_nf_conn_offsets() {
        if let Err(e) =
            adapters::ebpf::conntrack_map_manager::push_nf_conn_offsets(loader.ebpf_mut(), offsets)
        {
            warn!("failed to push nf_conn offsets to BPF: {e}");
        } else {
            info!(
                status_offset = offsets.status_offset,
                mark_offset = offsets.mark_offset,
                "nf_conn BTF offsets resolved and pushed to BPF"
            );
        }
    } else {
        warn!("failed to resolve nf_conn BTF offsets — kernel CT field reads disabled");
    }

    // tc-conntrack has no EVENTS RingBuf (pure state tracking, no events).
    // EventReader is optional — skip if the map doesn't exist.
    let opt_reader = EventReader::new(loader.ebpf_mut()).ok();

    Ok((loader, ct_mgr, ct_metrics_rdr, opt_reader))
}

/// Resolve `nf_conn.status` and `nf_conn.mark` field offsets from the
/// running kernel's vmlinux BTF. Uses `bpftool btf dump -j` to parse
/// the type info rather than linking against libbpf.
fn resolve_nf_conn_offsets() -> anyhow::Result<ebpf_common::conntrack::NfConnOffsets> {
    let output = std::process::Command::new("bpftool")
        .args(["btf", "dump", "file", "/sys/kernel/btf/vmlinux", "-j"])
        .output()
        .map_err(|e| anyhow::anyhow!("bpftool not found: {e}"))?;
    if !output.status.success() {
        anyhow::bail!("bpftool btf dump failed");
    }
    let json: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let types = json["types"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("no types array in BTF dump"))?;

    for t in types {
        if t["name"].as_str() == Some("nf_conn") && t["kind"].as_str() == Some("STRUCT") {
            let members = t["members"]
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("no members in nf_conn"))?;
            let mut status_offset: Option<u32> = None;
            let mut mark_offset: Option<u32> = None;
            for m in members {
                let name = m["name"].as_str().unwrap_or("");
                #[allow(clippy::cast_possible_truncation)]
                let offset_bytes = (m["bits_offset"].as_u64().unwrap_or(0) / 8) as u32;
                match name {
                    "status" => status_offset = Some(offset_bytes),
                    "mark" => mark_offset = Some(offset_bytes),
                    _ => {}
                }
            }
            return Ok(ebpf_common::conntrack::NfConnOffsets {
                status_offset: status_offset
                    .ok_or_else(|| anyhow::anyhow!("nf_conn.status not found in BTF"))?,
                mark_offset: mark_offset
                    .ok_or_else(|| anyhow::anyhow!("nf_conn.mark not found in BTF"))?,
                valid: 1,
                _pad: 0,
            });
        }
    }
    anyhow::bail!("struct nf_conn not found in vmlinux BTF")
}

/// Load the TC NAT programs (ingress + egress): attach TC, create map manager.
pub fn try_load_tc_nat(
    ebpf_dir: &str,
    config: &AgentConfig,
) -> anyhow::Result<(EbpfLoader, EbpfLoader, NatMapManager, Vec<MetricsReader>)> {
    let ingress_bytes = read_ebpf_program(ebpf_dir, "tc-nat-ingress")?;
    let mut ingress_loader =
        EbpfLoader::load_with_pin_path(&ingress_bytes, adapters::ebpf::DEFAULT_BPF_PIN_PATH)?;

    for iface in &config.agent.interfaces {
        attach_tc_auto(
            &mut ingress_loader,
            "tc_nat_ingress",
            iface,
            config.agent.attach_mode,
        )?;
    }

    let egress_bytes = read_ebpf_program(ebpf_dir, "tc-nat-egress")?;
    let mut egress_loader =
        EbpfLoader::load_with_pin_path(&egress_bytes, adapters::ebpf::DEFAULT_BPF_PIN_PATH)?;

    for iface in &config.agent.interfaces {
        attach_tc_auto(
            &mut egress_loader,
            "tc_nat_egress",
            iface,
            config.agent.attach_mode,
        )?;
    }

    let nat_mgr =
        NatMapManager::from_ingress_egress(ingress_loader.ebpf_mut(), egress_loader.ebpf_mut())?;

    // NAT_METRICS from ingress loader (egress shares via pinning or separate map)
    let mut rdrs = Vec::new();
    if let Ok(r) = MetricsReader::new(ingress_loader.ebpf_mut(), "NAT_METRICS") {
        rdrs.push(r);
    }

    Ok((ingress_loader, egress_loader, nat_mgr, rdrs))
}

/// Load the TC scrub program: attach TC ingress, write scrub config to eBPF map.
pub fn try_load_tc_scrub(
    ebpf_dir: &str,
    config: &AgentConfig,
) -> anyhow::Result<(EbpfLoader, Option<MetricsReader>)> {
    let program_bytes = read_ebpf_program(ebpf_dir, "tc-scrub")?;
    let mut loader =
        EbpfLoader::load_with_pin_path(&program_bytes, adapters::ebpf::DEFAULT_BPF_PIN_PATH)?;

    for iface in &config.agent.interfaces {
        attach_tc_auto(&mut loader, "tc_scrub", iface, config.agent.attach_mode)?;
    }

    // Write scrub config to the SCRUB_CONFIG eBPF Array map
    if let Ok(mut scrub_mgr) = ScrubConfigManager::new(loader.ebpf_mut()) {
        let flags = build_scrub_flags(config);
        if let Err(e) = scrub_mgr.set_flags(&flags) {
            warn!("failed to set SCRUB_CONFIG: {e}");
        }
    }

    let scrub_metrics_rdr = MetricsReader::new(loader.ebpf_mut(), "SCRUB_METRICS").ok();

    Ok((loader, scrub_metrics_rdr))
}

/// Load the TC `QoS` program: attach TC, acquire the `QoS` maps, and create
/// the metrics + event readers. The caller binds the returned map manager to
/// the `QoS` service and syncs pipes/queues/classifiers from config.
pub fn try_load_tc_qos(
    ebpf_dir: &str,
    config: &AgentConfig,
) -> anyhow::Result<(
    EbpfLoader,
    QosMapManager,
    Option<MetricsReader>,
    Option<EventReader>,
)> {
    let program_bytes = read_ebpf_program(ebpf_dir, "tc-qos")?;
    let mut loader =
        EbpfLoader::load_with_pin_path(&program_bytes, adapters::ebpf::DEFAULT_BPF_PIN_PATH)?;

    for iface in &config.agent.interfaces {
        attach_tc_auto(&mut loader, "tc_qos", iface, config.agent.attach_mode)?;
    }

    let qos_mgr = QosMapManager::new(loader.ebpf_mut())?;
    let qos_metrics_rdr = MetricsReader::new(loader.ebpf_mut(), "QOS_METRICS").ok();
    let opt_reader = EventReader::new(loader.ebpf_mut()).ok();

    Ok((loader, qos_mgr, qos_metrics_rdr, opt_reader))
}

/// Build `ScrubFlags` from the agent config's scrub section.
pub fn build_scrub_flags(config: &AgentConfig) -> ebpf_common::scrub::ScrubFlags {
    let scrub = &config.firewall.scrub;
    ebpf_common::scrub::ScrubFlags {
        enabled: u8::from(scrub.enabled),
        min_ttl: scrub.min_ttl.unwrap_or(0),
        clear_df: u8::from(scrub.clear_df),
        random_ip_id: u8::from(scrub.random_ip_id),
        max_mss: scrub.max_mss.unwrap_or(0),
        min_hop_limit: scrub.min_hop_limit.unwrap_or(0),
        scrub_tcp_flags: u8::from(scrub.scrub_tcp_flags),
        strip_ecn: u8::from(scrub.strip_ecn),
        normalize_tos: u8::from(scrub.normalize_tos),
        tos_value: scrub.tos_value.unwrap_or(0),
        strip_tcp_timestamps: u8::from(scrub.strip_tcp_timestamps),
        _pad: [0; 2],
    }
}

/// Build a `GeoIP` adapter from the config's source mode.
///
/// Only handles the `File` mode synchronously. `Url` and `MaxMindAccount`
/// modes require async downloads and are not supported at startup (they
/// will log a warning and return an error).
pub fn build_geoip_adapter(
    cfg: &infrastructure::config::GeoIpConfig,
) -> anyhow::Result<adapters::geoip::MaxMindGeoIpAdapter> {
    match &cfg.source {
        infrastructure::config::GeoIpSource::File {
            city_path,
            asn_path,
        } => adapters::geoip::MaxMindGeoIpAdapter::from_files(
            Path::new(city_path),
            asn_path.as_deref().map(Path::new),
        ),
        infrastructure::config::GeoIpSource::Url { .. } => {
            anyhow::bail!(
                "GeoIP URL mode requires async download — use `file` mode or pre-download databases"
            );
        }
        infrastructure::config::GeoIpSource::MaxMindAccount { .. } => {
            anyhow::bail!(
                "GeoIP MaxMind account mode requires async download — use `file` mode or pre-download databases"
            );
        }
    }
}

/// Load the XDP load balancer program.
///
/// When `xdp_chain_active` is true (firewall or ratelimit is on the same
/// interfaces), the LB is loaded without attaching — it will be invoked
/// via tail-call from the upstream program. When false, it attaches
/// directly to the interfaces (standalone mode).
pub fn try_load_xdp_loadbalancer(
    ebpf_dir: &str,
    config: &AgentConfig,
    xdp_chain_active: bool,
) -> anyhow::Result<(
    EbpfLoader,
    adapters::ebpf::LbMapManager,
    Option<MetricsReader>,
    EventReader,
)> {
    let program_bytes = read_ebpf_program(ebpf_dir, "xdp-loadbalancer")?;
    // Device-bound only in standalone mode: a tail-call target must match its
    // caller's dev-bound state, and the non-kfunc reject/syncookie targets in
    // the XDP chain cannot be device-bound, so the chained form is neutralized.
    let dev_bound = if xdp_chain_active {
        None
    } else {
        metadata_dev_bound_ifindex(config)
    };
    let mut loader = EbpfLoader::load_with_pin_path_dev_bound(
        &program_bytes,
        adapters::ebpf::DEFAULT_BPF_PIN_PATH,
        dev_bound,
    )?;

    if xdp_chain_active {
        // Another XDP program owns the interface — load only (tail-call target).
        loader.load_xdp_program("xdp_loadbalancer")?;
        info!("xdp-loadbalancer loaded as tail-call target (XDP chain active)");
    } else {
        // Standalone mode — attach directly.
        let xdp_flags = adapters::ebpf::xdp_mode_to_flags(config.agent.xdp_mode);
        for iface in &config.agent.interfaces {
            loader.attach_xdp_program("xdp_loadbalancer", iface, xdp_flags)?;
        }
    }

    let lb_mgr = adapters::ebpf::LbMapManager::new(loader.ebpf_mut())?;

    // MetricsReader for LB per-CPU metrics
    let metrics_rdr = MetricsReader::new(loader.ebpf_mut(), "LB_METRICS").ok();

    // EventReader for LB events from RingBuf
    let reader = EventReader::new(loader.ebpf_mut())?;

    Ok((loader, lb_mgr, metrics_rdr, reader))
}

/// Load the bounded XDP VIP announcer program.
///
/// The announcer is never attached directly: it is always invoked via
/// tail-call from the `xdp-firewall` entry point (slot 3,
/// `PROG_IDX_VIP_ARP`) when an ARP frame is seen. It therefore only
/// makes sense when the firewall XDP chain is active; the caller gates
/// on that. Returns the loader (kept alive for the tail-call FD) and the
/// `VipMapManager` over `VIP_SET` / `IFACE_MAC` / `VIP_ARP_REPLIES`
/// plus the `SelfBindingManager` over `SELF_OWNED_BINDINGS`.
pub fn try_load_xdp_vip_announcer(
    ebpf_dir: &str,
) -> anyhow::Result<(
    EbpfLoader,
    adapters::ebpf::VipMapManager,
    adapters::ebpf::SelfBindingManager,
)> {
    let program_bytes = read_ebpf_program(ebpf_dir, "xdp-vip-announcer")?;
    // Raw load so this tail-call target matches the kfunc-raw-loaded
    // xdp-firewall owner of XDP_PROG_ARRAY (see `load_xdp_raw_with_pin_path`).
    let mut loader = EbpfLoader::load_xdp_raw_with_pin_path(
        &program_bytes,
        adapters::ebpf::DEFAULT_BPF_PIN_PATH,
    )?;
    loader.load_xdp_program("xdp_vip_announcer")?;
    info!("xdp-vip-announcer loaded as tail-call target (firewall ARP path)");
    let vip_mgr = adapters::ebpf::VipMapManager::new(loader.ebpf_mut())?;
    let binding_mgr = adapters::ebpf::SelfBindingManager::new(loader.ebpf_mut())?;
    Ok((loader, vip_mgr, binding_mgr))
}

/// Attach a TC program to an interface, dispatching based on
/// [`AttachMode`]. Auto mode tries netkit first for netkit devices,
/// falls back to TC clsact.
fn attach_tc_auto(
    loader: &mut adapters::ebpf::loader::EbpfLoader,
    program_name: &str,
    iface: &str,
    mode: infrastructure::config::AttachMode,
) -> anyhow::Result<()> {
    use infrastructure::config::AttachMode;

    match mode {
        AttachMode::Netkit => {
            loader.attach_tc_via_netkit(program_name, iface)?;
        }
        AttachMode::Tc => {
            loader.attach_tc_program(program_name, iface)?;
        }
        AttachMode::Auto => {
            if adapters::ebpf::netkit::is_netkit_device(iface) {
                match loader.attach_tc_via_netkit(program_name, iface) {
                    Ok(()) => {}
                    Err(e) => {
                        warn!(
                            program_name, iface, error = %e,
                            "netkit attach failed, falling back to TC"
                        );
                        loader.attach_tc_program(program_name, iface)?;
                    }
                }
            } else {
                loader.attach_tc_program(program_name, iface)?;
            }
        }
    }
    Ok(())
}
