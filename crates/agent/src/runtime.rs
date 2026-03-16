//! Reusable OSS agent runtime — service handles and lifecycle control.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use application::alias_service_impl::AliasAppService;
use application::audit_service_impl::AuditAppService;
use application::conntrack_service_impl::ConnTrackAppService;
use application::dlp_service_impl::DlpAppService;
use application::dns_blocklist_service_impl::DnsBlocklistAppService;
use application::dns_cache_service_impl::DnsCacheAppService;
use application::firewall_service_impl::FirewallAppService;
use application::ids_service_impl::IdsAppService;
use application::ips_service_impl::{IpsAppService, IpsBlacklistAdapter};
use application::l7_service_impl::L7AppService;
use application::nat_service_impl::NatAppService;
use application::ratelimit_service_impl::RateLimitAppService;
use application::routing_service_impl::RoutingAppService;
use application::schedule_service_impl::ScheduleService;
use application::threatintel_service_impl::ThreatIntelAppService;
use application::zone_service_impl::ZoneAppService;
use domain::dlp::engine::DlpEngine;
use domain::firewall::engine::FirewallEngine;
use domain::ids::engine::IdsEngine;
use domain::ips::engine::IpsEngine;
use domain::l7::engine::L7Engine;
use domain::ratelimit::engine::RateLimitEngine;
use domain::threatintel::engine::ThreatIntelEngine;
use infrastructure::config::AgentConfig;
use infrastructure::metrics::AgentMetrics;
use ports::secondary::metrics_port::{FirewallMetrics, MetricsPort};
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Handles to all core OSS agent services.
///
/// Created by [`build_services`] from an [`AgentConfig`]. Each service is
/// wrapped in `Arc<RwLock<...>>` for concurrent access from eBPF event
/// readers, HTTP handlers, config reload, and HA replication consumers.
#[allow(clippy::struct_field_names)]
pub struct ServiceHandles {
    // ── Core security services (replicated in HA) ─────────────────
    pub firewall_svc: Arc<RwLock<FirewallAppService>>,
    pub ids_svc: Arc<RwLock<IdsAppService>>,
    pub ips_svc: Arc<RwLock<IpsAppService>>,
    pub rl_svc: Arc<RwLock<RateLimitAppService>>,
    pub ti_svc: Arc<RwLock<ThreatIntelAppService>>,
    pub dns_blocklist_svc: Option<Arc<DnsBlocklistAppService>>,

    // ── Additional services ──────────────────────────────────────
    pub l7_svc: Arc<RwLock<L7AppService>>,
    pub ddos_svc: Arc<RwLock<application::ddos_service_impl::DdosAppService>>,
    pub dlp_svc: Arc<RwLock<DlpAppService>>,
    pub conntrack_svc: Arc<RwLock<ConnTrackAppService>>,
    pub nat_svc: Arc<RwLock<NatAppService>>,
    pub lb_svc: Arc<RwLock<application::lb_service_impl::LbAppService>>,
    pub qos_svc: Arc<RwLock<application::qos_service_impl::QosAppService>>,
    pub zone_svc: Arc<RwLock<ZoneAppService>>,
    pub alias_svc: Arc<RwLock<AliasAppService>>,
    pub routing_svc: Arc<RwLock<RoutingAppService>>,
    pub schedule_svc: Arc<RwLock<ScheduleService>>,
    pub audit_svc: Arc<RwLock<AuditAppService>>,

    // ── DNS services (optional) ──────────────────────────────────
    pub dns_cache_svc: Option<Arc<DnsCacheAppService>>,

    // ── Infrastructure ───────────────────────────────────────────
    pub metrics: Arc<AgentMetrics>,
    pub ebpf_loaded: Arc<AtomicBool>,
}

/// Build all domain engines and application services from config.
///
/// This creates the services in their initial state (rules loaded, modes set)
/// but does NOT attach eBPF programs, start HTTP/gRPC servers, or launch
/// event pipelines. Those are handled separately by the caller.
///
/// # Errors
///
/// Returns an error if config validation or initial rule loading fails.
#[allow(clippy::too_many_lines, clippy::similar_names)]
pub fn build_services(config: &AgentConfig) -> anyhow::Result<ServiceHandles> {
    // ── Metrics ──────────────────────────────────────────────────
    let metrics = Arc::new(AgentMetrics::new());
    let ebpf_loaded = Arc::new(AtomicBool::new(false));

    // ── Firewall ─────────────────────────────────────────────────
    let firewall_mode = config.firewall_mode()?;
    let domain_rules = config.firewall_rules()?;
    let mut engine = FirewallEngine::new();
    engine.reload(domain_rules)?;
    let rule_count = engine.rules().len();
    metrics.set_rules_loaded("firewall", rule_count as u64);
    let mut svc =
        FirewallAppService::new(engine, None, Arc::clone(&metrics) as Arc<dyn MetricsPort>);
    svc.set_mode(firewall_mode);
    let firewall_svc = Arc::new(RwLock::new(svc));
    info!(
        rule_count,
        mode = firewall_mode.as_str(),
        "firewall engine initialized"
    );

    // ── IDS ──────────────────────────────────────────────────────
    let ids_mode = config.ids_mode()?;
    let ids_domain_rules = config.ids_rules()?;
    let mut ids_engine = IdsEngine::new();
    if config.ids.enabled {
        ids_engine.reload(ids_domain_rules)?;
    }
    metrics.set_rules_loaded("ids", ids_engine.rule_count() as u64);
    let mut ids_svc = IdsAppService::new(
        ids_engine,
        None,
        Arc::clone(&metrics) as Arc<dyn MetricsPort>,
    );
    ids_svc.set_mode(ids_mode);
    ids_svc.set_enabled(config.ids.enabled);
    let ids_svc = Arc::new(RwLock::new(ids_svc));
    info!(
        enabled = config.ids.enabled,
        mode = ids_mode.as_str(),
        "IDS engine initialized"
    );

    // ── IPS ──────────────────────────────────────────────────────
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

    // ── L7 ───────────────────────────────────────────────────────
    let l7_domain_rules = config.l7_rules()?;
    let mut l7_engine = L7Engine::new();
    if config.l7.enabled {
        l7_engine.reload(l7_domain_rules)?;
    }
    let mut l7_svc = L7AppService::new(l7_engine, Arc::clone(&metrics) as Arc<dyn MetricsPort>);
    l7_svc.set_enabled(config.l7.enabled);
    let l7_svc = Arc::new(RwLock::new(l7_svc));

    // ── Rate Limit ───────────────────────────────────────────────
    let rl_policies = config.ratelimit_policies()?;
    let mut rl_engine = RateLimitEngine::new();
    if config.ratelimit.enabled {
        rl_engine.reload(rl_policies)?;
    }
    let mut rl_svc =
        RateLimitAppService::new(rl_engine, Arc::clone(&metrics) as Arc<dyn MetricsPort>);
    rl_svc.set_enabled(config.ratelimit.enabled);
    let rl_svc = Arc::new(RwLock::new(rl_svc));

    // ── DDoS ─────────────────────────────────────────────────────
    let ddos_policies = config.ddos_policies()?;
    let mut ddos_engine = domain::ddos::engine::DdosEngine::new();
    if config.ddos.enabled {
        ddos_engine.reload(ddos_policies)?;
    }
    let mut ddos_svc = application::ddos_service_impl::DdosAppService::new(
        ddos_engine,
        Arc::clone(&metrics) as Arc<dyn MetricsPort>,
    );
    ddos_svc.set_enabled(config.ddos.enabled);
    let ddos_svc = Arc::new(RwLock::new(ddos_svc));

    // ── Load Balancer ────────────────────────────────────────────
    let lb_services_cfg = config.lb_services()?;
    let mut lb_engine = domain::loadbalancer::engine::LbEngine::new();
    if config.loadbalancer.enabled {
        lb_engine.reload(lb_services_cfg)?;
    }
    let mut lb_svc = application::lb_service_impl::LbAppService::new(
        lb_engine,
        Arc::clone(&metrics) as Arc<dyn MetricsPort>,
    );
    lb_svc.set_enabled(config.loadbalancer.enabled);
    let lb_svc = Arc::new(RwLock::new(lb_svc));

    // ── QoS ──────────────────────────────────────────────────────
    let mut qos_svc = application::qos_service_impl::QosAppService::new(
        Arc::clone(&metrics) as Arc<dyn MetricsPort>
    );
    qos_svc.set_enabled(config.qos.enabled);
    let qos_svc = Arc::new(RwLock::new(qos_svc));

    // ── DLP ──────────────────────────────────────────────────────
    let mut dlp_engine = DlpEngine::new();
    let defaults = domain::dlp::entity::default_patterns();
    if config.dlp.enabled {
        dlp_engine.reload(defaults)?;
    }
    let mut dlp_svc = DlpAppService::new(dlp_engine, Arc::clone(&metrics) as Arc<dyn MetricsPort>);
    dlp_svc.set_mode(domain::common::entity::DomainMode::Alert)?;
    dlp_svc.set_enabled(config.dlp.enabled);
    let dlp_svc = Arc::new(RwLock::new(dlp_svc));

    // ── ConnTrack ────────────────────────────────────────────────
    let ct_settings = config.conntrack_settings();
    let mut ct_svc = ConnTrackAppService::new(Arc::clone(&metrics) as Arc<dyn MetricsPort>);
    ct_svc.set_enabled(config.conntrack.enabled);
    if config.conntrack.enabled
        && let Err(e) = ct_svc.reload_settings(ct_settings)
    {
        warn!("conntrack settings reload failed (non-fatal): {e}");
    }
    let conntrack_svc = Arc::new(RwLock::new(ct_svc));

    // ── NAT ──────────────────────────────────────────────────────
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

    // ── Zone ─────────────────────────────────────────────────────
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

    // ── Alias ────────────────────────────────────────────────────
    let mut alias_svc = AliasAppService::new(Arc::clone(&metrics) as Arc<dyn MetricsPort>);
    let alias_resolver = adapters::alias::alias_resolution_adapter::AliasResolutionAdapter::new();
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

    // ── Routing ──────────────────────────────────────────────────
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

    // ── Schedule ─────────────────────────────────────────────────
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
        for rule_cfg in &config.firewall.rules {
            if let Some(ref sched_id) = rule_cfg.schedule {
                rule_schedule.insert(rule_cfg.id.clone(), sched_id.clone());
            }
        }
        schedule_svc.reload(schedules, rule_schedule);
    }
    let schedule_svc = Arc::new(RwLock::new(schedule_svc));

    // ── Threat Intel ─────────────────────────────────────────────
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

    // ── Audit ────────────────────────────────────────────────────
    let audit_sink: Arc<dyn ports::secondary::audit_sink::AuditSink> =
        Arc::new(adapters::audit::log_audit_sink::LogAuditSink);
    let mut audit_svc = AuditAppService::new(audit_sink);
    audit_svc.set_metrics(Arc::clone(&metrics) as Arc<dyn MetricsPort>);
    audit_svc.set_enabled(config.audit.enabled);

    let storage_path = Path::new(&config.audit.storage_path);
    match adapters::storage::redb_audit_store::RedbAuditStore::open(
        storage_path,
        config.audit.buffer_size,
    ) {
        Ok(store) => {
            let store: Arc<dyn ports::secondary::audit_store::AuditStore> = Arc::new(store);
            audit_svc = audit_svc.with_store(store);
        }
        Err(e) => {
            warn!(error = %e, "audit store unavailable, running without persistent audit log");
        }
    }

    let rule_change_path = storage_path.with_file_name("rule_changes.redb");
    match adapters::storage::redb_rule_change_store::RedbRuleChangeStore::open(&rule_change_path) {
        Ok(store) => {
            let store: Arc<dyn ports::secondary::rule_change_store::RuleChangeStore> =
                Arc::new(store);
            audit_svc = audit_svc.with_rule_change_store(store);
        }
        Err(e) => {
            warn!(error = %e, "rule change store unavailable");
        }
    }
    let audit_svc = Arc::new(RwLock::new(audit_svc));

    // ── DNS services (conditional) ───────────────────────────────
    let (dns_cache_svc, dns_blocklist_svc) = if config.dns.enabled {
        let cache_config = config.dns_cache_config();
        let dns_cache = Arc::new(DnsCacheAppService::new(
            cache_config,
            Arc::clone(&metrics) as Arc<dyn MetricsPort>,
        ));

        let blocklist_config = config.dns_blocklist_config().unwrap_or_else(|e| {
            warn!("DNS blocklist config error, using defaults: {e}");
            domain::dns::entity::DomainBlocklistConfig::default()
        });
        let dns_blocklist = DnsBlocklistAppService::new(
            blocklist_config,
            None,
            Arc::clone(&metrics) as Arc<dyn MetricsPort>,
        );
        let dns_blocklist = if config.dns.blocklist.inject_target == "ips" {
            let adapter = Arc::new(IpsBlacklistAdapter::new(Arc::clone(&ips_svc)));
            dns_blocklist.with_ips_port(
                adapter as Arc<dyn ports::secondary::ips_blacklist_port::IpsBlacklistPort>,
            )
        } else {
            dns_blocklist
        };
        let dns_blocklist = Arc::new(dns_blocklist);

        (Some(dns_cache), Some(dns_blocklist))
    } else {
        (None, None)
    };

    Ok(ServiceHandles {
        firewall_svc,
        ids_svc,
        ips_svc,
        rl_svc,
        ti_svc,
        dns_blocklist_svc,
        l7_svc,
        ddos_svc,
        dlp_svc,
        conntrack_svc,
        nat_svc,
        lb_svc,
        qos_svc,
        zone_svc,
        alias_svc,
        routing_svc,
        schedule_svc,
        audit_svc,
        dns_cache_svc,
        metrics,
        ebpf_loaded,
    })
}
