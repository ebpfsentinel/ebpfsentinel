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
    ConfigFlagsManager, ConnTrackMapManager, DlpEventReader, DnsEventReader, EbpfLoader,
    EbpfMapWriteAdapter, EventReader, FirewallMapManager, IdsMapManager, IpSetMapManager,
    L7PortsManager, MetricsReader, NatMapManager, RateLimitMapManager, ScrubConfigManager,
    ThreatIntelMapManager,
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
use domain::alert::circuit_breaker::CircuitBreaker;
use domain::alert::engine::AlertRouter;
use domain::alert::entity::Alert;
use domain::dlp::engine::DlpEngine;
use domain::firewall::engine::FirewallEngine;
use domain::firewall::entity::FirewallRule;
use domain::ids::engine::IdsEngine;
use domain::ids::entity::IdsAlert;
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
use tracing::{info, warn};

use crate::cli::Cli;

/// Run the agent startup sequence and block until shutdown.
#[allow(clippy::too_many_lines, clippy::similar_names)] // startup is inherently sequential and long
pub async fn run(cli: &Cli) -> anyhow::Result<()> {
    // ── 1. Load config ──────────────────────────────────────────────
    let config = AgentConfig::load(Path::new(&cli.config))?;

    // ── 2. Initialize logging ───────────────────────────────────────
    // CLI flags take precedence over config file
    let log_level = cli.log_level.unwrap_or(config.agent.log_level);
    let log_format = cli.log_format.unwrap_or(config.agent.log_format);
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
        config_path = %cli.config,
        log_level = log_level.as_str(),
        log_format = log_format.as_str(),
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
    let ids_svc = Arc::new(RwLock::new(ids_svc));

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
    let ips_svc = Arc::new(RwLock::new(ips_svc));

    // ── 5b. Build L7 service ────────────────────────────────────────
    let l7_domain_rules = config.l7_rules()?;
    let mut l7_engine = L7Engine::new();
    if config.l7.enabled {
        l7_engine.reload(l7_domain_rules.clone())?;
    }
    let mut l7_svc = L7AppService::new(l7_engine, Arc::clone(&metrics) as Arc<dyn MetricsPort>);
    l7_svc.set_enabled(config.l7.enabled);
    let l7_svc = Arc::new(RwLock::new(l7_svc));
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
    let ddos_svc = Arc::new(RwLock::new(ddos_svc));
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

    // ── 5c¾. Build DLP service ──────────────────────────────────────
    let dlp_mode = config.dlp_mode()?;
    let dlp_patterns = config.dlp_patterns()?;
    let mut dlp_engine = DlpEngine::new();
    if config.dlp.enabled {
        dlp_engine.reload(dlp_patterns)?;
    }
    let mut dlp_svc = DlpAppService::new(dlp_engine, Arc::clone(&metrics) as Arc<dyn MetricsPort>);
    dlp_svc.set_mode(dlp_mode);
    dlp_svc.set_enabled(config.dlp.enabled);
    let dlp_svc = Arc::new(RwLock::new(dlp_svc));
    info!(
        pattern_count = config.dlp.patterns.len(),
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
    }
    let nat_svc = Arc::new(RwLock::new(nat_svc));
    info!(enabled = config.nat.enabled, "NAT service initialized");

    // ── 5c⅞. Build Alias service ────────────────────────────────────
    let mut alias_svc = AliasAppService::new(Arc::clone(&metrics) as Arc<dyn MetricsPort>);
    // Wire alias resolution adapter for URL table, DNS, and GeoIP lookups
    let alias_resolver =
        Arc::new(adapters::alias::alias_resolution_adapter::AliasResolutionAdapter::new());
    alias_svc.set_resolution_port(alias_resolver);
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
    let ti_svc = Arc::new(RwLock::new(ti_svc));
    info!(
        enabled = config.threatintel.enabled,
        mode = ti_mode.as_str(),
        "threat intel engine initialized"
    );

    // ── 5e. Build audit service ───────────────────────────────────────
    let audit_sink: Arc<dyn AuditSink> = Arc::new(LogAuditSink);
    let mut audit_svc = AuditAppService::new(audit_sink);
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

    let audit_svc = Arc::new(RwLock::new(audit_svc));
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
    let (auth_handle, auth_provider): (
        Option<crate::reload::AuthProviderHandle>,
        Option<Arc<dyn AuthProvider>>,
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
        } else if !config.auth.jwt.public_key_path.is_empty() {
            let pem_bytes = std::fs::read(&config.auth.jwt.public_key_path).map_err(|e| {
                anyhow::anyhow!(
                    "failed to read JWT public key at '{}': {e}",
                    config.auth.jwt.public_key_path
                )
            })?;
            let provider = JwtAuthProvider::new(
                &pem_bytes,
                config.auth.jwt.issuer.as_deref(),
                config.auth.jwt.audience.as_deref(),
            )
            .map_err(|e| anyhow::anyhow!("failed to initialize JWT auth provider: {e}"))?;
            info!("JWT authentication enabled");
            let arc = Arc::new(provider);
            (
                Some(crate::reload::AuthProviderHandle::Jwt(Arc::clone(&arc))),
                Some(Arc::clone(&arc) as Arc<dyn AuthProvider>),
            )
        } else {
            (None, None)
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
            info!(key_count = entries.len(), "API key authentication enabled");
            Some(
                Arc::new(adapters::auth::api_key_provider::ApiKeyAuthProvider::new(
                    entries,
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

        let handle = token_handle.unwrap_or(crate::reload::AuthProviderHandle::ApiKeyOnly);
        (Some(handle), Some(final_provider))
    } else {
        (None, None)
    };

    // Shared config, reload trigger, and eBPF program status for ops endpoints
    let shared_config = Arc::new(RwLock::new(config.clone()));
    let (reload_trigger_tx, reload_trigger_rx) = mpsc::channel::<()>(1);
    let ebpf_program_status: Arc<RwLock<std::collections::HashMap<String, bool>>> =
        Arc::new(RwLock::new(std::collections::HashMap::new()));

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
    if let Some(ref store) = alert_store {
        app_state = app_state.with_alert_store(Arc::clone(store));
    }
    if let Some(provider) = auth_provider {
        app_state = app_state.with_auth_provider(provider, config.auth.metrics_auth_required);
    }

    // ── 5b. Wire DNS intelligence and domain reputation services ────
    let mut dns_blocklist_ref: Option<Arc<DnsBlocklistAppService>> = None;
    let dns_cache_for_ids: Option<Arc<dyn ports::secondary::dns_cache_port::DnsCachePort>> =
        if config.dns.enabled {
            let cache_config = config.dns_cache_config();
            let dns_cache_svc = Arc::new(DnsCacheAppService::new(
                cache_config,
                Arc::clone(&metrics) as Arc<dyn MetricsPort>,
            ));

            let blocklist_config = config.dns_blocklist_config().unwrap_or_else(|e| {
                tracing::warn!("DNS blocklist config error, using defaults: {e}");
                domain::dns::entity::DomainBlocklistConfig::default()
            });
            let dns_blocklist_svc = DnsBlocklistAppService::new(
                blocklist_config,
                None, // eBPF map writer — wired after tc-threatintel loads
                Arc::clone(&metrics) as Arc<dyn MetricsPort>,
            );
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
                        ),
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

    let app_state = app_state
        .with_ids_service(Arc::clone(&ids_svc))
        .with_ddos_service(Arc::clone(&ddos_svc))
        .with_dlp_service(Arc::clone(&dlp_svc))
        .with_conntrack_service(Arc::clone(&conntrack_svc))
        .with_nat_service(Arc::clone(&nat_svc))
        .with_alias_service(Arc::clone(&alias_svc))
        .with_routing_service(Arc::clone(&routing_svc))
        .with_loadbalancer_service(Arc::clone(&lb_svc));
    let app_state = Arc::new(app_state);

    // ── 6. Create cancellation token ────────────────────────────────
    let cancel_token = crate::shutdown::create_shutdown_token();

    // ── 6a. Spawn system metrics collection loop ────────────────────
    let _system_metrics_handle = system_metrics::spawn_collection_loop(
        Arc::clone(&metrics) as Arc<dyn MetricsPort>,
        Duration::from_secs(5),
        cancel_token.clone(),
    );

    // ── 6b. Load TLS configuration ─────────────────────────────────
    let tls_config = if config.agent.tls.enabled {
        let rustls_cfg = load_rustls_config(
            Path::new(&config.agent.tls.cert_path),
            Path::new(&config.agent.tls.key_path),
        )?;
        info!(
            cert_path = %config.agent.tls.cert_path,
            key_path = %config.agent.tls.key_path,
            "TLS enabled for HTTP and gRPC servers"
        );
        Some(rustls_cfg)
    } else {
        None
    };

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
    reload_service.set_nat_service(Arc::clone(&nat_svc));
    reload_service.set_alias_service(Arc::clone(&alias_svc));
    reload_service.set_routing_service(Arc::clone(&routing_svc));
    reload_service.set_loadbalancer_service(Arc::clone(&lb_svc));
    let reload_service = Arc::new(reload_service);
    // Clone auth provider for gRPC from the app state
    let grpc_auth: Option<Arc<dyn AuthProvider>> = app_state.auth_provider.clone();

    // reload_handle is spawned after eBPF loading (step 10) to include EbpfMapHolder

    // ── 8b. Spawn gRPC alert streaming server ─────────────────────────
    let (alert_stream_tx, _) = broadcast::channel::<Alert>(ALERT_CHANNEL_CAPACITY);
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
    let grpc_handle = tokio::spawn(async move {
        if let Err(e) = run_grpc_server(
            grpc_stream_tx,
            &grpc_bind,
            grpc_port,
            grpc_auth,
            grpc_tls,
            grpc_shutdown.cancelled_owned(),
        )
        .await
        {
            tracing::error!(error = %e, "gRPC server failed");
        }
    });

    // ── 9. Create event + alert channels ──────────────────────────────
    let (event_tx, event_rx) = mpsc::channel::<AgentEvent>(EVENT_CHANNEL_CAPACITY);
    let (alert_tx, alert_rx) = mpsc::channel::<IdsAlert>(ALERT_CHANNEL_CAPACITY);

    // ── 10. Load eBPF programs (each with graceful degradation) ────
    let ebpf_dir = resolve_ebpf_program_dir(&config);
    let mut ebpf_state = EbpfState::new();
    let mut ebpf_map_holder = crate::reload::EbpfMapHolder::new();
    let mut metrics_readers: Vec<MetricsReader> = Vec::new();

    // 10a. XDP Firewall
    let mut fw_loader: Option<EbpfLoader> = None;
    let fw_ok = if config.firewall.enabled {
        match try_load_xdp_firewall(&ebpf_dir, &config, &domain_rules, event_tx.clone()) {
            Ok((loader, map_manager, fw_metrics_rdr)) => {
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
    let rl_ok = if config.ratelimit.enabled {
        match try_load_xdp_ratelimit(&ebpf_dir, &config, event_tx.clone()) {
            Ok((rl_loader, rl_mgr_opt, rl_rdrs)) => {
                metrics_readers.extend(rl_rdrs);
                if let Some(rl_mgr) = rl_mgr_opt {
                    let mut svc = rl_svc.write().await;
                    let default_algo = parse_algorithm_byte(&config.ratelimit.default_algorithm);
                    svc.set_defaults(
                        config.ratelimit.default_rate,
                        config.ratelimit.default_burst,
                        default_algo,
                    );
                    svc.set_map_port(Box::new(rl_mgr));
                }
                // Wire tail-call: firewall → ratelimit (if both loaded).
                if let Some(ref mut fw) = fw_loader {
                    match rl_loader.xdp_program_fd("xdp_ratelimit") {
                        Ok(rl_fd) => {
                            if let Err(e) = fw.set_tail_call_target("XDP_PROG_ARRAY", 0, &rl_fd) {
                                warn!("tail-call wiring failed (non-fatal): {e}");
                            } else {
                                info!("XDP tail-call: firewall → ratelimit wired");
                            }
                        }
                        Err(e) => warn!("ratelimit fd retrieval failed: {e}"),
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

    // Wire IpSetMapManager from xdp-firewall to alias service (best-effort, before move)
    if let Some(ref mut loader) = fw_loader
        && let Ok(ipset_mgr) = IpSetMapManager::new(loader.ebpf_mut())
    {
        alias_svc.write().await.set_ipset_port(Box::new(ipset_mgr));
        info!("alias IP set map wired from xdp-firewall");
    }

    // Move firewall loader into eBPF state (after tail-call wiring)
    if let Some(loader) = fw_loader {
        ebpf_state.add_loader(loader);
    }

    // 10c. TC IDS
    let ids_ok = if config.ids.enabled {
        match try_load_tc_ids(&ebpf_dir, &config, event_tx.clone()) {
            Ok((loader, ids_mgr_opt, l7_mgr_opt, cfg_mgr_opt, ids_rdr)) => {
                if let Some(ids_mgr) = ids_mgr_opt {
                    ids_svc.write().await.set_map_port(Box::new(ids_mgr));
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
    let ti_ok = if config.threatintel.enabled {
        match try_load_tc_threatintel(&ebpf_dir, &config, event_tx.clone()) {
            Ok((loader, ti_mgr_opt, cfg_mgr_opt, ti_rdr)) => {
                if let Some(rdr) = ti_rdr {
                    metrics_readers.push(rdr);
                }
                if let Some(ti_mgr) = ti_mgr_opt {
                    // Extract shared map handles before moving manager to service
                    let (v4, v6, bv4, bv6) = ti_mgr.shared_handles();
                    ti_svc.write().await.set_map_port(Box::new(ti_mgr));

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
    let dns_ok = if config.dns.enabled {
        match try_load_tc_dns(&ebpf_dir, &config, event_tx.clone()) {
            Ok((loader, dns_rdr)) => {
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
    let dlp_ok = if config.dlp.enabled {
        match try_load_uprobe_dlp(&ebpf_dir, &config, event_tx.clone()) {
            Ok((loader, dlp_rdr)) => {
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
    let ct_ok = if config.conntrack.enabled {
        match try_load_tc_conntrack(&ebpf_dir, &config, event_tx.clone()) {
            Ok((loader, ct_mgr, ct_rdr)) => {
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
    let nat_ok = if config.nat.enabled {
        match try_load_tc_nat(&ebpf_dir, &config) {
            Ok((ingress_loader, egress_loader, nat_mgr, nat_rdrs)) => {
                metrics_readers.extend(nat_rdrs);
                {
                    let mut svc = nat_svc.write().await;
                    svc.set_map_port(Box::new(nat_mgr));
                    // Re-sync rules to eBPF maps now that maps are wired
                    let dnat = config.nat_dnat_rules().unwrap_or_default();
                    let snat = config.nat_snat_rules().unwrap_or_default();
                    let _ = svc.reload_dnat_rules(dnat);
                    let _ = svc.reload_snat_rules(snat);
                }
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
    let scrub_ok = if config.firewall.scrub.enabled {
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

    // 10k. XDP Load Balancer
    let lb_ok = if config.loadbalancer.enabled {
        match try_load_xdp_loadbalancer(&ebpf_dir, &config) {
            Ok((loader, lb_mgr)) => {
                lb_svc.write().await.set_map_port(Box::new(lb_mgr));
                ebpf_state.add_loader(loader);
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
        status.insert("xdp_loadbalancer".to_string(), lb_ok);
    }

    // ── 10½. Spawn config hot-reload task (after eBPF loading for EbpfMapHolder) ──
    let reload_handle = crate::reload::spawn_reload_task(
        cli.config.clone(),
        reload_service,
        auth_handle,
        cancel_token.clone(),
        reload_trigger_rx,
        Arc::clone(&shared_config),
        ebpf_map_holder,
    );

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
    .with_dlp_service(Arc::clone(&dlp_svc));
    let dispatcher_cancel = cancel_token.clone();
    let dispatcher_handle = tokio::spawn(async move {
        dispatcher.run(event_rx, dispatcher_cancel).await;
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
    .with_stream_sender(alert_stream_tx);
    if let Some(store) = alert_store {
        alert_pipeline = alert_pipeline.with_alert_store(store);
    }

    // Wire DNS alert enricher (best-effort: only if DNS cache is available)
    if let Some(ref dns_cache) = app_state.dns_cache_service {
        let enricher = application::alert_enrichment::DnsAlertEnricher::new(
            Arc::clone(dns_cache) as Arc<dyn ports::secondary::dns_cache_port::DnsCachePort>,
            app_state.domain_reputation_service.as_ref().map(|svc| {
                Arc::clone(svc)
                    as Arc<dyn ports::secondary::domain_reputation_port::DomainReputationPort>
            }),
        );
        alert_pipeline = alert_pipeline.with_enricher(Arc::new(enricher));
        info!("DNS alert enricher initialized");
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
        let cb = CircuitBreaker::new(5, Duration::from_secs(60));
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
        let cb = CircuitBreaker::new(5, Duration::from_secs(60));
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
        Some(tokio::spawn(async move {
            // Initial fetch at startup
            {
                let feeds = feed_ti_svc.read().await.list_feeds().to_vec();
                let iocs =
                    application::feed_update::fetch_all_feeds(&feeds, &fetcher, &feed_metrics)
                        .await;
                if !iocs.is_empty()
                    && let Err(e) = feed_ti_svc.write().await.reload_iocs(iocs)
                {
                    warn!("initial feed IOC reload failed: {e}");
                }
            }

            let mut interval = tokio::time::interval(Duration::from_secs(refresh_secs));
            interval.tick().await; // skip the first immediate tick (already fetched above)
            loop {
                tokio::select! {
                    () = feed_cancel.cancelled() => break,
                    _ = interval.tick() => {}
                }
                let feeds = feed_ti_svc.read().await.list_feeds().to_vec();
                let iocs =
                    application::feed_update::fetch_all_feeds(&feeds, &fetcher, &feed_metrics)
                        .await;
                if !iocs.is_empty()
                    && let Err(e) = feed_ti_svc.write().await.reload_iocs(iocs)
                {
                    warn!("periodic feed IOC reload failed: {e}");
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
        tokio::spawn(async move {
            crate::ebpf_metrics::run_kernel_metrics_loop(
                metrics_readers,
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
        let sched_cancel = cancel_token.clone();
        info!(
            schedule_count = config.firewall.schedules.len(),
            "schedule evaluator starting (60s interval)"
        );
        Some(tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
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
                }
            }
        }))
    };

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
    drop(ebpf_state);

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
struct EbpfState {
    loaders: Vec<EbpfLoader>,
}

impl EbpfState {
    fn new() -> Self {
        Self {
            loaders: Vec::new(),
        }
    }

    fn add_loader(&mut self, loader: EbpfLoader) {
        self.loaders.push(loader);
    }
}

/// Resolve the directory containing compiled eBPF program binaries.
///
/// Precedence: `EBPF_PROGRAM_DIR` env var > `agent.ebpf_program_dir` config
/// > production default (`/usr/local/lib/ebpfsentinel`)
/// > dev fallback (`target/bpfel-unknown-none/release`).
fn resolve_ebpf_program_dir(config: &AgentConfig) -> String {
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
fn read_ebpf_program(dir: &str, name: &str) -> anyhow::Result<Vec<u8>> {
    let path = Path::new(dir).join(name);
    std::fs::read(&path)
        .map_err(|e| anyhow::anyhow!("failed to read eBPF program '{}': {e}", path.display()))
}

// ── Per-program load functions ───────────────────────────────────────

/// Load the XDP firewall program: attach XDP, populate rules, start event reader.
fn try_load_xdp_firewall(
    ebpf_dir: &str,
    config: &AgentConfig,
    domain_rules: &[FirewallRule],
    event_tx: mpsc::Sender<AgentEvent>,
) -> anyhow::Result<(EbpfLoader, FirewallMapManager, Option<MetricsReader>)> {
    use ebpf_common::firewall::{DEFAULT_POLICY_DROP, DEFAULT_POLICY_PASS};
    use infrastructure::config::DefaultPolicy;

    let program_bytes = read_ebpf_program(ebpf_dir, "xdp-firewall")?;
    let mut loader = EbpfLoader::load(&program_bytes)?;

    for iface in &config.agent.interfaces {
        loader.attach_xdp(iface)?;
    }

    let mut map_manager = FirewallMapManager::new(loader.ebpf_mut())?;

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

    let metrics_rdr = MetricsReader::new(loader.ebpf_mut(), "FIREWALL_METRICS").ok();

    let reader = EventReader::new(loader.ebpf_mut())?;
    tokio::spawn(async move { reader.run(event_tx).await });

    Ok((loader, map_manager, metrics_rdr))
}

/// Load the XDP rate limiter program: attach XDP, populate policies, start event reader.
fn try_load_xdp_ratelimit(
    ebpf_dir: &str,
    config: &AgentConfig,
    event_tx: mpsc::Sender<AgentEvent>,
) -> anyhow::Result<(EbpfLoader, Option<RateLimitMapManager>, Vec<MetricsReader>)> {
    let program_bytes = read_ebpf_program(ebpf_dir, "xdp-ratelimit")?;
    let mut loader = EbpfLoader::load(&program_bytes)?;

    for iface in &config.agent.interfaces {
        loader.attach_xdp_program("xdp_ratelimit", iface)?;
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

    let mut rdrs = Vec::new();
    if let Ok(r) = MetricsReader::new(loader.ebpf_mut(), "RATELIMIT_METRICS") {
        rdrs.push(r);
    }
    if let Ok(r) = MetricsReader::new(loader.ebpf_mut(), "DDOS_METRICS") {
        rdrs.push(r);
    }

    let reader = EventReader::new(loader.ebpf_mut())?;
    tokio::spawn(async move { reader.run(event_tx).await });

    Ok((loader, rl_mgr_opt, rdrs))
}

/// IDS program load result: loader, IDS map manager, L7 ports manager, config flags manager, metrics reader.
type TcIdsResult = (
    EbpfLoader,
    Option<IdsMapManager>,
    Option<L7PortsManager>,
    Option<ConfigFlagsManager>,
    Option<MetricsReader>,
);

/// Load the TC IDS program: attach TC ingress, set up maps, start event reader.
fn try_load_tc_ids(
    ebpf_dir: &str,
    config: &AgentConfig,
    event_tx: mpsc::Sender<AgentEvent>,
) -> anyhow::Result<TcIdsResult> {
    let program_bytes = read_ebpf_program(ebpf_dir, "tc-ids")?;
    let mut loader = EbpfLoader::load(&program_bytes)?;

    for iface in &config.agent.interfaces {
        loader.attach_tc_program("tc_ids", iface)?;
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
    tokio::spawn(async move { reader.run(event_tx).await });

    Ok((
        loader,
        ids_mgr_opt,
        l7_mgr_opt,
        cfg_mgr_opt,
        ids_metrics_rdr,
    ))
}

/// Load the TC threat intel program: attach TC ingress, set up maps, start event reader.
/// Threat intel program load result.
type TcThreatIntelResult = (
    EbpfLoader,
    Option<ThreatIntelMapManager>,
    Option<ConfigFlagsManager>,
    Option<MetricsReader>,
);

fn try_load_tc_threatintel(
    ebpf_dir: &str,
    config: &AgentConfig,
    event_tx: mpsc::Sender<AgentEvent>,
) -> anyhow::Result<TcThreatIntelResult> {
    let program_bytes = read_ebpf_program(ebpf_dir, "tc-threatintel")?;
    let mut loader = EbpfLoader::load(&program_bytes)?;

    for iface in &config.agent.interfaces {
        loader.attach_tc_program("tc_threatintel", iface)?;
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
    tokio::spawn(async move { reader.run(event_tx).await });

    Ok((loader, ti_mgr_opt, cfg_mgr_opt, ti_metrics_rdr))
}

/// Load the TC DNS program: attach TC ingress, start DNS event reader.
fn try_load_tc_dns(
    ebpf_dir: &str,
    config: &AgentConfig,
    event_tx: mpsc::Sender<AgentEvent>,
) -> anyhow::Result<(EbpfLoader, Option<MetricsReader>)> {
    let program_bytes = read_ebpf_program(ebpf_dir, "tc-dns")?;
    let mut loader = EbpfLoader::load(&program_bytes)?;

    for iface in &config.agent.interfaces {
        loader.attach_tc_program("tc_dns", iface)?;
    }

    let dns_metrics_rdr = MetricsReader::new(loader.ebpf_mut(), "DNS_METRICS").ok();

    let reader = DnsEventReader::new(loader.ebpf_mut())?;
    tokio::spawn(async move { reader.run(event_tx).await });

    Ok((loader, dns_metrics_rdr))
}

/// Load the uprobe DLP program: attach uprobes to SSL functions, start DLP event reader.
fn try_load_uprobe_dlp(
    ebpf_dir: &str,
    _config: &AgentConfig,
    event_tx: mpsc::Sender<AgentEvent>,
) -> anyhow::Result<(EbpfLoader, Option<MetricsReader>)> {
    let program_bytes = read_ebpf_program(ebpf_dir, "uprobe-dlp")?;
    let mut loader = EbpfLoader::load(&program_bytes)?;

    // Default SSL library target (OpenSSL)
    let ssl_target = "libssl.so.3";

    loader.attach_uprobe("uprobe_ssl_write", "SSL_write", ssl_target, false)?;
    loader.attach_uprobe("uprobe_ssl_read_entry", "SSL_read", ssl_target, false)?;
    loader.attach_uprobe("uretprobe_ssl_read", "SSL_read", ssl_target, true)?;

    let dlp_metrics_rdr = MetricsReader::new(loader.ebpf_mut(), "DLP_METRICS").ok();

    let reader = DlpEventReader::new(loader.ebpf_mut())?;
    tokio::spawn(async move { reader.run(event_tx).await });

    Ok((loader, dlp_metrics_rdr))
}

/// Build `ConfigFlags` from the agent config for eBPF programs.
pub(crate) fn build_config_flags(config: &AgentConfig) -> ebpf_common::config_flags::ConfigFlags {
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

/// Convert ratelimit algorithm string to the eBPF u8 constant.
fn parse_algorithm_byte(algorithm: &str) -> u8 {
    match algorithm.to_lowercase().as_str() {
        "fixed_window" | "fixedwindow" => ebpf_common::ratelimit::ALGO_FIXED_WINDOW,
        "sliding_window" | "slidingwindow" => ebpf_common::ratelimit::ALGO_SLIDING_WINDOW,
        "leaky_bucket" | "leakybucket" => ebpf_common::ratelimit::ALGO_LEAKY_BUCKET,
        _ => ebpf_common::ratelimit::ALGO_TOKEN_BUCKET,
    }
}

/// Load the TC conntrack program: attach TC ingress, create map manager, start event reader.
fn try_load_tc_conntrack(
    ebpf_dir: &str,
    config: &AgentConfig,
    event_tx: mpsc::Sender<AgentEvent>,
) -> anyhow::Result<(EbpfLoader, ConnTrackMapManager, Option<MetricsReader>)> {
    let program_bytes = read_ebpf_program(ebpf_dir, "tc-conntrack")?;
    let mut loader = EbpfLoader::load(&program_bytes)?;

    for iface in &config.agent.interfaces {
        loader.attach_tc_program("tc_conntrack", iface)?;
    }

    let ct_mgr = ConnTrackMapManager::new(loader.ebpf_mut())?;
    let ct_metrics_rdr = MetricsReader::new(loader.ebpf_mut(), "CT_METRICS").ok();

    let reader = EventReader::new(loader.ebpf_mut())?;
    tokio::spawn(async move { reader.run(event_tx).await });

    Ok((loader, ct_mgr, ct_metrics_rdr))
}

/// Load the TC NAT programs (ingress + egress): attach TC, create map manager.
fn try_load_tc_nat(
    ebpf_dir: &str,
    config: &AgentConfig,
) -> anyhow::Result<(EbpfLoader, EbpfLoader, NatMapManager, Vec<MetricsReader>)> {
    let ingress_bytes = read_ebpf_program(ebpf_dir, "tc-nat-ingress")?;
    let mut ingress_loader = EbpfLoader::load(&ingress_bytes)?;

    for iface in &config.agent.interfaces {
        ingress_loader.attach_tc_program("tc_nat_ingress", iface)?;
    }

    let egress_bytes = read_ebpf_program(ebpf_dir, "tc-nat-egress")?;
    let mut egress_loader = EbpfLoader::load(&egress_bytes)?;

    for iface in &config.agent.interfaces {
        egress_loader.attach_tc_program("tc_nat_egress", iface)?;
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
fn try_load_tc_scrub(
    ebpf_dir: &str,
    config: &AgentConfig,
) -> anyhow::Result<(EbpfLoader, Option<MetricsReader>)> {
    let program_bytes = read_ebpf_program(ebpf_dir, "tc-scrub")?;
    let mut loader = EbpfLoader::load(&program_bytes)?;

    for iface in &config.agent.interfaces {
        loader.attach_tc_program("tc_scrub", iface)?;
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

/// Build `ScrubFlags` from the agent config's scrub section.
fn build_scrub_flags(config: &AgentConfig) -> ebpf_common::scrub::ScrubFlags {
    let scrub = &config.firewall.scrub;
    ebpf_common::scrub::ScrubFlags {
        enabled: u8::from(scrub.enabled),
        min_ttl: scrub.min_ttl.unwrap_or(0),
        clear_df: u8::from(scrub.clear_df),
        random_ip_id: u8::from(scrub.random_ip_id),
        max_mss: scrub.max_mss.unwrap_or(0),
        min_hop_limit: scrub.min_hop_limit.unwrap_or(0),
        _pad: 0,
    }
}

/// Load and attach the XDP load balancer program.
fn try_load_xdp_loadbalancer(
    ebpf_dir: &str,
    config: &AgentConfig,
) -> anyhow::Result<(EbpfLoader, adapters::ebpf::LbMapManager)> {
    let program_bytes = read_ebpf_program(ebpf_dir, "xdp-loadbalancer")?;
    let mut loader = EbpfLoader::load(&program_bytes)?;

    for iface in &config.agent.interfaces {
        loader.attach_xdp_program("xdp_loadbalancer", iface)?;
    }

    let lb_mgr = adapters::ebpf::LbMapManager::new(loader.ebpf_mut())?;

    Ok((loader, lb_mgr))
}
