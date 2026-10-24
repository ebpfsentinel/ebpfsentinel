use std::os::fd::AsRawFd;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::http::agent_handler::{ContainerCoverage, EnricherState};
use crate::http::tls::load_rustls_config;
use crate::http::{AppState, run_http_server, run_metrics_server};
use adapters::alert::email_sender::EmailAlertSender;
use adapters::alert::log_sender::LogAlertSender;
use adapters::alert::webhook_sender::WebhookAlertSender;
use adapters::audit::log_audit_sink::LogAuditSink;
use adapters::ebpf::{
    AmpProtectConfigManager, ConfigFlagsManager, ConnTrackMapManager, DdosConnTrackConfigManager,
    DdosSynConfigManager, DlpEventReader, DnsEventReader, EbpfLoader, EbpfMapWriteAdapter,
    EventReader, FirewallMapManager, IcmpConfigManager, IdsMapManager, InterfaceGroupsManager,
    IpSetMapManager, L7PortsManager, LpmCoordinator, MetricsReader, NatMapManager, QosMapManager,
    RateLimitLpmManager, RateLimitMapManager, RingBufObserver, ScrubConfigManager,
    ThreatIntelMapManager, ZoneMapManager,
};
use adapters::grpc::server::{GrpcTlsConfig, run_grpc_server};
use adapters::metrics::AgentMetrics;
use adapters::storage::redb_alert_store::RedbAlertStore;
use adapters::storage::redb_audit_store::RedbAuditStore;
use adapters::storage::redb_mitigation_store::RedbMitigationStore;
use adapters::storage::redb_rule_change_store::RedbRuleChangeStore;
use adapters::system_metrics;
use application::alert_pipeline::AlertPipeline;
use application::alias_service_impl::AliasAppService;
use application::audit_service_impl::AuditAppService;
use application::config_reload::ConfigReloadService;
use application::conntrack_service_impl::ConnTrackAppService;
use application::dlp_service_impl::DlpAppService;
use application::dns_blocklist_service_impl::DnsBlocklistAppService;
use application::dns_cache_service_impl::DnsCacheAppService;
use application::domain_reputation_service_impl::DomainReputationAppService;
use application::firewall_service_impl::{
    AntiLockoutSettings, FirewallAppService, InterfaceScopeBits,
};
use application::ids_service_impl::IdsAppService;
use application::ips_service_impl::{IpsAppService, IpsBlacklistAdapter};
use application::l7_service_impl::L7AppService;
use application::nat_service_impl::NatAppService;
use application::packet_pipeline::{AgentEvent, EventDispatcher};
use application::ratelimit_service_impl::RateLimitAppService;
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
use domain::ids::engine::IdsEngine;
use domain::ips::engine::IpsEngine;
use domain::l7::engine::L7Engine;
use domain::ratelimit::engine::RateLimitEngine;
use domain::threatintel::engine::ThreatIntelEngine;
use infrastructure::config::AgentConfig;
use infrastructure::constants::{
    ALERT_CHANNEL_CAPACITY, CAPTURE_STOP_TIMEOUT, CONTAINER_LABEL_CHANNEL_CAPACITY,
    EVENT_CHANNEL_CAPACITY, GRACEFUL_SHUTDOWN_TIMEOUT, WORKLOAD_DENIAL_CHANNEL_CAPACITY,
    WORKLOAD_DENIAL_READ_INTERVAL, WORKLOAD_DNS_CHANNEL_CAPACITY, WORKLOAD_FQDN_SWEEP_INTERVAL,
};
use infrastructure::logging::init_logging;
use infrastructure::retry::RetryConfig;
use ports::secondary::alert_sender::AlertSender;
use ports::secondary::alert_store::{AlertStore, AlertTriageStore};
use ports::secondary::audit_sink::AuditSink;
use ports::secondary::audit_store::AuditStore;
use ports::secondary::auth_provider::AuthProvider;
use ports::secondary::ebpf_map_port::FirewallArrayMapPort;
use ports::secondary::metrics_port::{ContainerMetrics, FirewallMetrics, MetricsPort};
use ports::secondary::mitigation_store::MitigationStore;
use ports::secondary::rule_change_store::RuleChangeStore;
use tokio::sync::{RwLock, broadcast, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use infrastructure::config::{LogFormat, LogLevel};

/// Raises the shared "a feed cycle is fetching" flag for as long as it is held.
///
/// The manual refresh route reads that flag to refuse a second outbound fetch,
/// so the flag has to fall again however the cycle ends - which is what makes
/// this a guard rather than a pair of stores around the call.
struct FeedCycleGuard(Arc<AtomicBool>);

impl FeedCycleGuard {
    fn claim(flag: &Arc<AtomicBool>) -> Self {
        flag.store(true, Ordering::SeqCst);
        Self(Arc::clone(flag))
    }
}

impl Drop for FeedCycleGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

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
    // Retain URL indicators so they surface read-only via the API (the
    // IP-only threat-intel engine has no place for them).
    svc.reload_urls(result.urls);
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

/// Translate the configured DNS blocklist feeds into fetch specs.
///
/// The format string is validated at config load, so anything other than
/// `hosts` is the plaintext layout.
fn dns_feed_specs(
    feeds: &[infrastructure::config::DnsBlocklistFeedConfig],
) -> Vec<application::dns_feed_update::DnsFeedSpec> {
    use domain::dns::blocklist::BlocklistFeedFormat;

    feeds
        .iter()
        .map(|feed| application::dns_feed_update::DnsFeedSpec {
            name: feed.name.clone(),
            url: feed.url.clone(),
            format: if feed.format == "hosts" {
                BlocklistFeedFormat::Hosts
            } else {
                BlocklistFeedFormat::Plaintext
            },
        })
        .collect()
}

/// Distinct bpffs pin path for uprobe-dlp, so its `EVENTS` ring buffer is a
/// separate kernel object from the shared packet `EVENTS` (same ELF map name).
/// uprobe-dlp's other maps (`SSL_READ_ARGS`, `DLP_METRICS`) are DLP-internal and
/// shared with nothing, so an isolated pin path is strictly correct.
pub(crate) const DLP_PIN_PATH: &str = "/sys/fs/bpf/ebpfsentinel-dlp";

/// The warden control socket path when the agent runs against a privilege broker,
/// or `None` when it runs standalone (host root). A set-but-empty value is treated
/// as unset.
fn warden_sock_from_env() -> Option<std::path::PathBuf> {
    std::env::var_os("EBPFSENTINEL_WARDEN_SOCK")
        .map(std::path::PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
}

/// Host proc filesystem root used for cross-container DLP discovery. Defaults to
/// `/proc`; set `EBPFSENTINEL_HOST_PROC` (e.g. `/host/proc`) when the host proc is
/// bind-mounted into the agent container so it can resolve neighbouring
/// containers' SSL libraries. A set-but-empty value is treated as unset.
fn host_proc_root() -> std::path::PathBuf {
    std::env::var_os("EBPFSENTINEL_HOST_PROC")
        .map(std::path::PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::PathBuf::from("/proc"))
}

/// The procfs the container resolver walks to map a cgroup id to a container.
///
/// The configuration wins wherever it names something other than the default: a
/// deployment that wrote the key meant it. Where it did not, the agent follows
/// `EBPFSENTINEL_HOST_PROC`, so a container holding the host procfs resolves the
/// node's processes without the config file having to repeat the mount point -
/// which is what lets the same file serve a host and a container, and what lets
/// a pod drop the host pid namespace without losing container attribution.
fn resolver_proc_path(configured: &str, host_proc: &std::path::Path) -> std::path::PathBuf {
    if configured == "/proc" {
        host_proc.to_path_buf()
    } else {
        std::path::PathBuf::from(configured)
    }
}

/// The service that compiles IDS rules scoped to workloads into the
/// classifier's two tables, reading cgroup paths through the same procfs the
/// container resolver walks.
pub(crate) fn ids_workload_scope_service(
    config: &AgentConfig,
) -> Arc<application::ids_workload_scope_service::IdsWorkloadScopeService> {
    let proc_root = resolver_proc_path(&config.container.resolver.proc_path, &host_proc_root());
    Arc::new(
        application::ids_workload_scope_service::IdsWorkloadScopeService::new().with_cgroups(
            Arc::new(adapters::container::ProcContainerResolver::new(&proc_root)),
        ),
    )
}

/// Hand a freshly loaded tc-ids object's scope tables to the scope service,
/// or tell it there are none, before the pattern map is handed over: the
/// pattern sync is what decides whether a scoped rule can be installed.
pub(crate) fn install_ids_workload_scope(
    scope: &application::ids_workload_scope_service::IdsWorkloadScopeService,
    loader: &mut EbpfLoader,
) {
    match adapters::ebpf::IdsWorkloadScopeMaps::new(loader.ebpf_mut()) {
        Ok(maps) => scope.set_maps(Box::new(maps)),
        Err(e) => {
            scope.clear_maps();
            warn!(
                "IDS workload scope tables not available, rules scoped to a workload are left out: {e}"
            );
        }
    }
}

/// Build a capture-socket pool from the warden when the delegation handshake
/// provisioned none and the agent runs against a warden (`EBPFSENTINEL_WARDEN_SOCK`
/// set). The warden performs the privileged `socket(AF_PACKET)`; the agent rebinds
/// and filters per capture. Returns `None` outside warden mode or when the warden
/// serves no socket, leaving capture gracefully unavailable.
fn warden_pcap_pool(
    config: &AgentConfig,
) -> Option<std::sync::Arc<adapters::net::pcap_capture::PcapSocketPool>> {
    let sock = warden_sock_from_env()?;
    let iface = config.agent.interfaces.first()?;
    adapters::warden::pcap::pool_from_warden(&sock, iface, 2)
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

    // Service root span - fields appear in every subsequent log entry
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

    // ── 2b. Refuse to be the second agent on this state directory ────
    // Startup wipes the pins it finds and opens the redb stores for writing,
    // so a second process here does not share the node with the first one: it
    // unpins the maps the first is still serving from. The lock is released by
    // the kernel when this process ends, so a crash leaves nothing behind for
    // the next start to clean up or guess at.
    let lock_path = Path::new(&config.audit.storage_path).with_file_name("agent.lock");
    let _instance_lock = match adapters::system::acquire_instance_lock(&lock_path) {
        Ok(lock) => {
            debug!(path = %lock.path().display(), "state directory claimed");
            lock
        }
        Err(e) => {
            error!(
                path = %lock_path.display(),
                "refusing to start: {e}; stop the running agent or point this one at its own state directory"
            );
            return Err(anyhow::anyhow!("{e}"));
        }
    };

    // ── 3. Convert and load firewall rules ──────────────────────────
    let firewall_mode = config.firewall_mode()?;
    let domain_rules = config.firewall_rules()?;
    // Read off the same rules, before they move into the engine: a workload
    // rule is a firewall rule with a selector on it, and the kernel object
    // that carries it out is loaded only when the document holds one.
    let workload_policy = domain::firewall::workload::WorkloadPolicy::from_rules(&domain_rules)?
        .with_dns(config.workload_dns()?)?;

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
    metrics.set_rules_loaded("ids", ids_engine.rule_count() as u64);

    // ── 5. Build shared application state ─────────────────────────
    let ebpf_loaded = Arc::new(AtomicBool::new(false));
    // The rules go in through the service rather than straight into the
    // engine, because the service is what adds the anti-lockout rules.
    let mut svc = FirewallAppService::new(
        FirewallEngine::new(),
        None,
        Arc::clone(&metrics) as Arc<dyn MetricsPort>,
    );
    svc.set_mode(firewall_mode);
    svc.set_interface_scope(firewall_interface_scope(&config));
    svc.set_anti_lockout(firewall_anti_lockout(&config));
    svc.reload_rules(domain_rules)?;
    info!(
        rule_count = svc.list_rules().len(),
        default_policy = ?config.firewall.default_policy,
        mode = firewall_mode.as_str(),
        "firewall engine initialized"
    );
    // Wire kernel-conntrack teardown so a deny rule added mid-flow evicts
    // already-established connections (the XDP drop runs before netfilter and
    // cannot remove an existing conntrack entry on its own).
    svc.set_kill_port(Box::new(
        adapters::netfilter::conntrack::ProcNetfilterConntrackPort::new(),
    ));
    let firewall_svc = Arc::new(RwLock::new(svc));

    let ids_workload_scope = ids_workload_scope_service(&config);
    let mut ids_svc = IdsAppService::new(
        ids_engine,
        None,
        Arc::clone(&metrics) as Arc<dyn MetricsPort>,
    );
    ids_svc.set_workload_scope(Arc::clone(&ids_workload_scope));
    ids_svc.set_mode(ids_mode);
    ids_svc.set_enabled(config.ids.enabled);
    ids_svc.set_sampling(config.ids_sampling()?);
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
    ips_svc.set_sampling(config.ips_sampling()?);
    ips_svc.reload_whitelist(ips_whitelist);
    ips_svc.reload_rules(ips_rules.clone())?;
    let ips_svc = Arc::new(ArcSwap::from_pointee(ips_svc));

    // IPS rules are matched by the same kernel program as the IDS rules, so
    // the service that owns the pattern maps carries both sets.
    application::ids_service_impl::install_prevention_rules(&ids_svc, ips_rules)?;

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

    // The engine counts events as they arrive and judges an attack once a
    // second: confirmed, mitigated, expired. Without this tick an attack
    // never left the active list and its rate froze at its last event.
    {
        let ddos_svc = Arc::clone(&ddos_svc);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
            loop {
                tick.tick().await;
                ddos_svc.load().tick();
            }
        });
    }

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
    let vip_bgp_cfg = config.lb_announce_bgp()?;
    let vip_svc = {
        let mut svc = application::vip_announcer_service_impl::VipAnnouncerService::new(
            Arc::clone(&metrics) as Arc<dyn MetricsPort>,
        );
        svc.set_mac_resolver(Arc::new(adapters::net::IoctlIfaceMacResolver));
        // Rootless warden-client mode cannot open an AF_PACKET socket to emit the
        // takeover ARP, so route it through the warden; otherwise broadcast it
        // directly from a raw socket.
        let arp_port: Arc<dyn ports::secondary::vip_announcer_port::GratuitousArpPort> =
            match warden_sock_from_env() {
                Some(sock) => Arc::new(adapters::warden::arp::WardenGratuitousArp::new(sock)),
                None => Arc::new(adapters::net::RawSocketGratuitousArp),
            };
        svc.set_gratuitous_arp(arp_port);
        let bgp = &config.loadbalancer.announce.bgp;
        svc.set_bgp_port(Arc::new(adapters::net::bird::BirdDaemon::new(
            &bgp.socket,
            &bgp.config_path,
        )));
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
    // The built-in patterns, with whatever the config restates folded in.
    let patterns = config.dlp_patterns()?;
    let dlp_pattern_count = patterns.len();
    if config.dlp.enabled {
        dlp_engine.reload(patterns)?;
    }
    let mut dlp_svc = DlpAppService::new(dlp_engine, Arc::clone(&metrics) as Arc<dyn MetricsPort>);
    // Block mode is enterprise-only and the config validator has already
    // refused it, so this only ever sets alert on an OSS agent.
    dlp_svc.set_mode(config.dlp_mode()?)?;
    dlp_svc.set_enabled(config.dlp.enabled);
    let dlp_svc = Arc::new(ArcSwap::from_pointee(dlp_svc));
    // Before the eBPF load, because the load is what installs the maps it
    // writes: a probe armed before the scope exists reads the whole node.
    let dlp_scope_svc = crate::runtime::build_dlp_scope_service(&config)?;
    info!(
        pattern_count = dlp_pattern_count,
        enabled = config.dlp.enabled,
        "DLP engine initialized"
    );

    // ── 5c⅘. Build ConnTrack service ────────────────────────────────
    let ct_settings = config.conntrack_settings();
    let mut ct_svc = ConnTrackAppService::new(Arc::clone(&metrics) as Arc<dyn MetricsPort>);
    ct_svc.set_enabled(config.conntrack.enabled);
    // Inject the kernel netfilter conntrack port. It owns both the
    // authoritative read view (coherent with `conntrack -L`) and the kernel
    // sysctl writes (timeouts + tcp_loose hardening). Wire it whenever
    // conntrack is enabled, BEFORE reload_settings, so the settings sync
    // actually reaches the kernel - those writes are no-ops until the port is
    // present. On kernels without CONFIG_NF_CONNTRACK_PROCFS the sysctl knobs
    // still exist but /proc/net/nf_conntrack does not, and the port falls back
    // to dumping through conntrack-tools.
    if config.conntrack.enabled {
        ct_svc.set_netfilter_port(Box::new(
            adapters::netfilter::conntrack::ProcNetfilterConntrackPort::new(),
        ));
    }
    let nf_ct_available = adapters::netfilter::conntrack::is_conntrack_readable();
    let conntrack_event_tx = if nf_ct_available {
        info!(
            proc_interface = adapters::netfilter::conntrack::is_proc_conntrack_available(),
            "kernel netfilter conntrack reader injected"
        );
        // Broadcast channel created now; poller spawned later after
        // cancel_token exists (see section 6c below).
        let (tx, _) =
            tokio::sync::broadcast::channel::<domain::conntrack::entity::ConntrackEvent>(256);
        Some(tx)
    } else {
        // Say so rather than leaving the endpoint's 404 as the only evidence:
        // the stream going missing is a host capability gap, and an operator
        // reading the boot log should not have to probe an endpoint to find it.
        warn!(
            "conntrack table unreadable (no /proc/net/nf_conntrack and no \
             usable conntrack-tools): event stream disabled"
        );
        None
    };
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
        let nptv6_rules = config.nat_nptv6_rules()?;
        if let Err(e) = nat_svc.reload_nptv6_rules(nptv6_rules) {
            warn!("NAT NPTv6 rules reload failed (non-fatal): {e}");
        }
        match config.nat_hairpin_parsed() {
            Ok((subnet, mask, snat_ip)) => {
                let hp = ebpf_common::nat::HairpinConfig {
                    internal_subnet: subnet,
                    internal_mask: mask,
                    hairpin_snat_ip: snat_ip,
                    enabled: u8::from(config.nat.hairpin.enabled),
                    _pad: [0; 3],
                };
                if let Err(e) = nat_svc.load_hairpin_config(&hp) {
                    warn!("hairpin NAT config load failed: {e}");
                }
            }
            Err(e) => warn!("hairpin NAT config invalid, not loaded: {e}"),
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
                        Some(Arc::new(
                            adapter.with_metrics(Arc::clone(&metrics) as Arc<dyn MetricsPort>),
                        ))
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
    // The IPS whitelist was installed above with its literal entries only: the
    // aliases it can also name are unknown until the alias service has loaded.
    application::ips_whitelist::apply_whitelist_aliases(
        &ips_svc,
        config.ips_whitelist()?,
        &config.ips.whitelist_aliases,
        &alias_svc,
    );
    // NAT rules were loaded above with their alias references intact, for the
    // same reason: the data plane matches CIDRs, so they are resolved here.
    if config.nat.enabled {
        application::nat_aliases::apply_rule_aliases(&mut *nat_svc.write().await, &alias_svc);
    }
    // And L7 rules, which is the same problem one layer up: a rule whose only
    // source restriction is an alias name carries no criterion at all until
    // that name is resolved, so it matches every address there is.
    if config.l7.enabled {
        let mut svc = (**l7_svc.load()).clone();
        application::l7_aliases::apply_rule_aliases(&mut svc, &alias_svc);
        l7_svc.store(Arc::new(svc));
    }
    let alias_svc = Arc::new(RwLock::new(alias_svc));
    info!("alias service initialized");

    // ── 5c⅞½. Build Routing service ─────────────────────────────────
    let mut routing_svc = RoutingAppService::new();
    routing_svc.set_metrics(Arc::clone(&metrics) as Arc<dyn MetricsPort>);
    routing_svc.set_enabled(config.routing.enabled);
    if config.routing.enabled {
        // Election only becomes failover once the kernel forwards through the
        // elected gateway, so give the service the port that writes the route.
        routing_svc.set_route_port(Arc::new(adapters::net::IpDefaultRoute::new())
            as Arc<dyn ports::secondary::default_route_port::DefaultRoutePort>);
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

    // Attach persistent audit store (redb) - graceful degradation on failure
    let storage_path = Path::new(&config.audit.storage_path);
    // Kept beside the service because the process-signal service writes its
    // own records: a kill that an operator cannot find afterwards is a kill
    // nobody can answer for.
    let mut audit_store_handle: Option<Arc<dyn AuditStore>> = None;
    match RedbAuditStore::open(storage_path, config.audit.buffer_size) {
        Ok(store) => {
            let store: Arc<dyn AuditStore> = Arc::new(store);
            audit_store_handle = Some(Arc::clone(&store));
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

    // Attach rule change store (redb) - graceful degradation on failure
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

    // Attach alert store (redb) - graceful degradation on failure
    let alert_store_path = storage_path.with_file_name("alerts.redb");
    let redb_alerts: Option<Arc<RedbAlertStore>> = match RedbAlertStore::open(&alert_store_path) {
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
    let alert_store: Option<Arc<dyn AlertStore>> = redb_alerts
        .as_ref()
        .map(|s| Arc::clone(s) as Arc<dyn AlertStore>);
    let alert_triage: Option<Arc<dyn AlertTriageStore>> = redb_alerts
        .as_ref()
        .map(|s| Arc::clone(s) as Arc<dyn AlertTriageStore>);

    // Attach the mitigation store (redb) - graceful degradation on failure.
    //
    // This is what keeps a blocked source blocked across a restart. Losing it
    // costs the agent its memory of the decisions it took, never the decisions
    // themselves: every write through it logs and carries on, so an unwritable
    // disk degrades containment to what it was before the store existed.
    let mitigation_store_path = storage_path.with_file_name("mitigations.redb");
    let mitigation_store: Option<Arc<dyn MitigationStore>> =
        match RedbMitigationStore::open(&mitigation_store_path) {
            Ok(store) => {
                info!(
                    path = %mitigation_store_path.display(),
                    "mitigation store initialized (redb)"
                );
                Some(Arc::new(store) as Arc<dyn MitigationStore>)
            }
            Err(e) => {
                warn!(
                    error = %e,
                    path = %mitigation_store_path.display(),
                    "mitigation store unavailable, blocks and responses will not survive a restart"
                );
                None
            }
        };
    if let Some(ref store) = mitigation_store {
        let mut svc = (**ips_svc.load()).clone();
        svc.set_mitigation_store(Arc::clone(store));
        ips_svc.store(Arc::new(svc));
    }

    // ── 5f. Initialize auth provider (JWT, OIDC, and/or API keys) ────
    let crate::auth_bootstrap::AuthStack {
        handle: auth_handle,
        provider: auth_provider,
        revocation: revocation_handle,
    } = crate::auth_bootstrap::build_auth_stack(&config.auth).await?;

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
    // Raised for as long as a feed cycle is fetching, so the manual refresh
    // route can refuse a second outbound fetch rather than queue one behind the
    // first. Shared with the fetcher task below, which clears it when the cycle
    // it started ends.
    let feed_refresh_in_flight = Arc::new(AtomicBool::new(false));
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
        app_state = app_state.with_feed_refresh_trigger(tx, Arc::clone(&feed_refresh_in_flight));
    }
    if let Some(ref store) = alert_store {
        app_state = app_state.with_alert_store(Arc::clone(store));
    }
    if let Some(triage) = alert_triage {
        app_state = app_state.with_alert_triage(triage);
    }
    if let Some(provider) = auth_provider {
        app_state = app_state.with_auth_provider(
            provider,
            revocation_handle,
            config.auth.metrics_auth_required,
        );
    }

    // Wire capture engine for manual packet capture. The ceiling is the
    // `capture.max_duration_secs` key, validated at load, and the engine also
    // carries what the files it writes are allowed to cost on disk.
    let capture_engine = Arc::new(RwLock::new(domain::capture::engine::CaptureEngine::new(
        config.capture.max_duration_secs,
        config.capture.retention(),
    )));
    app_state = app_state.with_capture_engine(Arc::clone(&capture_engine));

    // Capture files outlive the process that wrote them, so a restart finds
    // whatever the last run left in the directory: adopt each one as an
    // interrupted session, so the API accounts for a short file instead of
    // leaving an operator to guess, then sweep what is past its retention.
    {
        let dir = std::path::Path::new(adapters::capture::retention_fs::CAPTURE_DIR);
        let mut engine = capture_engine.write().await;
        let known = engine.known_ids();
        let adopted = adapters::capture::retention_fs::orphan_sessions(
            dir,
            &known,
            std::time::SystemTime::now(),
        );
        if !adopted.is_empty() {
            info!(
                captures = adopted.len(),
                "capture files from an earlier run listed as interrupted"
            );
            for session in adopted {
                engine.adopt(session);
            }
        }
        let outcome = adapters::capture::retention_fs::sweep(
            dir,
            &engine.retention(),
            &engine.files_in_use(),
        );
        if outcome.deleted > 0 || outcome.failed > 0 {
            info!(
                deleted = outcome.deleted,
                bytes_freed = outcome.bytes_freed,
                failed = outcome.failed,
                "capture retention sweep at startup"
            );
        }
    }

    // Adopt the AF_PACKET sockets the privileged launcher pre-opened for
    // rootless packet capture (advertised via EBPFSENTINEL_PCAP_FDS). Absent in
    // a non-launcher run - fall back to the warden (rootless warden-client mode),
    // which performs the privileged socket() and hands the fd over SCM_RIGHTS;
    // capture degrades gracefully when neither source provisions a socket.
    let pcap_pool = adapters::net::pcap_capture::PcapSocketPool::from_env()
        .or_else(|| warden_pcap_pool(&config));
    if let Some(ref pool) = pcap_pool {
        // The pool is a fixed budget handed to this process, so how much of it
        // is borrowed is worth a gauge: a capture that refuses to start because
        // every socket is out reads as a full pool rather than as a broken one.
        pool.attach_metrics(
            Arc::clone(&metrics) as Arc<dyn ports::secondary::metrics_port::MetricsPort>
        );
        app_state = app_state.with_pcap_pool(Arc::clone(pool));
    }

    // Wire response engine for manual TTL actions. The ceiling is the
    // `response.max_ttl_secs` key, validated at load.
    let response_engine = Arc::new(RwLock::new(domain::response::engine::ResponseEngine::new(
        config.response.max_ttl_secs,
    )));
    app_state = app_state.with_response_engine(Arc::clone(&response_engine));
    if let Some(ref store) = mitigation_store {
        app_state = app_state.with_mitigation_store(Arc::clone(store));
    }

    // Background sweeper: lift response actions whose TTL has elapsed off the
    // data plane and emit a `responses` audit entry for each genuine expiry
    // (revokes are lifted and audited at revoke time, so they are skipped here
    // to avoid a duplicate event).
    {
        let sweeper_engine = Arc::clone(&response_engine);
        let sweeper_audit = Arc::clone(&audit_svc);
        let sweeper_ips = Arc::clone(&ips_svc);
        let sweeper_rl = Arc::clone(&rl_svc);
        let sweeper_store = mitigation_store.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(2));
            loop {
                tick.tick().await;
                let now_ns = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
                    .try_into()
                    .unwrap_or(u64::MAX);
                let expired = {
                    let mut engine = sweeper_engine.write().await;
                    engine.drain_expired(now_ns)
                };
                for action in expired {
                    if action.revoked {
                        continue;
                    }
                    crate::http::response_handler::withdraw(&sweeper_ips, &sweeper_rl, &action)
                        .await;
                    crate::http::response_handler::forget(sweeper_store.as_ref(), &action.id);
                    sweeper_audit.record_response_action(
                        domain::audit::entity::AuditAction::RuleRemoved,
                        &action.target,
                        &action.rule_id,
                        &format!("response on {} expired after ttl", action.target),
                    );
                }
            }
        });
    }

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

    // ── Multi-WAN active health-probe loop ──────────────────────────
    // Probe each gateway's configured health-check target, drive the routing
    // service's consecutive failure/success counters (which flip a gateway to
    // Down past its failure_threshold), and raise a single critical
    // WAN_ALL_DOWN alert the first time every enabled gateway is down.
    //
    // The gateway list is read afresh on every tick rather than snapshotted at
    // boot, because a gateway added through the HTTP API carries a health check
    // of its own: a snapshot left it reporting healthy for ever with nothing
    // probing it, went on probing one that had been removed, and never started
    // at all when no gateway in the file carried a check.
    if config.routing.enabled {
        let probe_routing = Arc::clone(&routing_svc);
        let probe_alert_tx = alert_tx.clone();
        tokio::spawn(async move {
            use domain::routing::entity::HealthCheckProto;
            use std::collections::HashMap;
            // One tick a second, with each gateway probed on the interval it
            // was configured with: a tick shared across the estate charged the
            // shortest interval in it to every other gateway.
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut was_all_down = false;
            let mut due: HashMap<u8, tokio::time::Instant> = HashMap::new();
            loop {
                tick.tick().await;
                let probe_specs: Vec<(u8, String, domain::routing::entity::HealthCheck)> = {
                    let svc = probe_routing.read().await;
                    svc.list_gateways()
                        .into_iter()
                        .filter(|s| s.gateway.enabled)
                        .filter_map(|s| {
                            s.gateway
                                .health_check
                                .clone()
                                .map(|hc| (s.gateway.id, s.gateway.interface.clone(), hc))
                        })
                        .collect()
                };
                due.retain(|id, _| probe_specs.iter().any(|(spec_id, _, _)| spec_id == id));
                for (id, interface, hc) in &probe_specs {
                    let now = tokio::time::Instant::now();
                    let next = due.entry(*id).or_insert(now);
                    if *next > now {
                        continue;
                    }
                    *next = now + Duration::from_secs(u64::from(hc.interval_secs).max(1));
                    let timeout = Duration::from_secs(u64::from(hc.timeout_secs).max(1));
                    let ok = match hc.protocol {
                        HealthCheckProto::Tcp { port } => {
                            let addr = format!("{}:{port}", hc.target);
                            matches!(
                                tokio::time::timeout(
                                    timeout,
                                    tokio::net::TcpStream::connect(&addr)
                                )
                                .await,
                                Ok(Ok(_))
                            )
                        }
                        HealthCheckProto::Icmp => {
                            if is_safe_probe_target(&hc.target) {
                                let secs = timeout.as_secs().max(1).to_string();
                                let mut probe = tokio::process::Command::new("ping");
                                probe.args(["-c", "1", "-W", &secs]);
                                // Tokio leaves a child running when its handle
                                // is dropped. This await is inside a task that
                                // a shutdown cancels and inside the timeout
                                // below, and either path drops the handle: with
                                // nothing here, a `ping` that outlived its own
                                // -W bound would stay on the process table with
                                // nobody left to reap it, one per probe
                                // interval per WAN.
                                probe.kill_on_drop(true);
                                // A probe leaving by whatever path the default
                                // route currently takes measures the elected
                                // gateway rather than this one, so every WAN
                                // reads healthy until the last of them drops.
                                if is_safe_interface_name(interface) {
                                    probe.args(["-I", interface]);
                                }
                                // `--` terminates option parsing so a target
                                // beginning with `-` can never be read as a flag.
                                probe
                                    .args(["--", &hc.target])
                                    .stdout(std::process::Stdio::null())
                                    .stderr(std::process::Stdio::null());
                                // `-W` bounds how long ping waits for a reply,
                                // not how long the process can take: a probe on
                                // an interface that stops answering ioctls
                                // hangs before it ever sends. The TCP arm above
                                // is bounded by its own timeout, so this one is
                                // too, and the child is killed by the drop
                                // rather than left behind.
                                matches!(
                                    tokio::time::timeout(
                                        timeout + std::time::Duration::from_secs(1),
                                        probe.status()
                                    )
                                    .await,
                                    Ok(Ok(status)) if status.success()
                                )
                            } else {
                                tracing::warn!(
                                    target = %hc.target,
                                    "skipping ICMP health probe: invalid target"
                                );
                                false
                            }
                        }
                    };
                    // Recording a probe can elect another gateway, and that
                    // writes the default route - through the warden in a
                    // rootless deployment, so blocking and the slowest thing
                    // this loop does. It runs off the worker and under a bound,
                    // or a warden that stopped answering would stop every
                    // gateway in the estate from being probed at all.
                    let routing = Arc::clone(&probe_routing);
                    let gateway_id = *id;
                    if let Err(e) = crate::brokered::brokered("gateway probe record", move || {
                        let mut svc = routing.blocking_write();
                        let _ = if ok {
                            svc.record_probe_success(gateway_id)
                        } else {
                            svc.record_probe_failure(gateway_id)
                        };
                    })
                    .await
                    {
                        tracing::warn!(error = %e, gateway = gateway_id, "gateway probe result not recorded");
                    }
                }

                // Edge-detect the all-down transition under one lock.
                let down_names: Vec<String> = {
                    let svc = probe_routing.read().await;
                    let gws = svc.list_gateways();
                    let enabled: Vec<_> = gws.iter().filter(|s| s.gateway.enabled).collect();
                    let all_down = !enabled.is_empty()
                        && enabled
                            .iter()
                            .all(|s| s.status == domain::routing::entity::GatewayStatus::Down);
                    if all_down {
                        enabled.iter().map(|s| s.gateway.name.clone()).collect()
                    } else {
                        Vec::new()
                    }
                };

                if !down_names.is_empty() && !was_all_down {
                    was_all_down = true;
                    let now_ns = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos()
                        .try_into()
                        .unwrap_or(u64::MAX);
                    let alert = domain::alert::entity::Alert::wan_all_down(&down_names, now_ns);
                    let _ = probe_alert_tx
                        .send(application::alert_event::AlertEvent::System(Box::new(
                            alert,
                        )))
                        .await;
                    tracing::warn!(gateways = ?down_names, "multi-WAN all gateways down");
                } else if down_names.is_empty() {
                    was_all_down = false;
                }
            }
        });
        info!("multi-WAN health-probe loop started");
    }

    // ── Load-balancer backend health-probe loop ─────────────────────
    // Probe every enabled backend of every service that configures a
    // health check, and drive the LB engine's consecutive failure /
    // success counters. The engine drops a backend past its failure
    // threshold out of the balancing set and the map port mirrors the
    // flag into eBPF, so an unreachable backend stops receiving traffic
    // without an operator editing anything.
    //
    // The spec is a startup snapshot: a service created through the HTTP
    // API carries no health check, so there is nothing later to pick up.
    if config.loadbalancer.enabled {
        type LbBackendProbe = (String, std::net::IpAddr, u16);
        type LbProbeSpec = (
            String,
            domain::routing::entity::HealthCheck,
            Vec<LbBackendProbe>,
        );

        let probe_specs: Vec<LbProbeSpec> = {
            let svc = lb_svc.read().await;
            svc.services()
                .into_iter()
                .filter(|s| s.enabled)
                .filter_map(|s| {
                    let hc = s.health_check.clone()?;
                    let backends: Vec<LbBackendProbe> = s
                        .backends
                        .iter()
                        .filter(|b| b.enabled)
                        .map(|b| (b.id.clone(), b.addr, b.port))
                        .collect();
                    (!backends.is_empty()).then(|| (s.id.to_string(), hc, backends))
                })
                .collect()
        };

        if !probe_specs.is_empty() {
            let probe_lb = Arc::clone(&lb_svc);
            let tick_secs = probe_specs
                .iter()
                .map(|(_, hc, _)| u64::from(hc.interval_secs).max(1))
                .min()
                .unwrap_or(10);
            let backend_count: usize = probe_specs.iter().map(|(_, _, b)| b.len()).sum();
            let service_count = probe_specs.len();
            tokio::spawn(async move {
                use domain::routing::entity::HealthCheckProto;
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(tick_secs));
                loop {
                    tick.tick().await;
                    for (service_id, hc, backends) in &probe_specs {
                        let timeout =
                            std::time::Duration::from_secs(u64::from(hc.timeout_secs).max(1));
                        for (backend_id, addr, port) in backends {
                            let ok = match hc.protocol {
                                // The health check carries no target of
                                // its own: each backend is probed on the
                                // address and port it serves on.
                                HealthCheckProto::Tcp { .. } => {
                                    let target = std::net::SocketAddr::new(*addr, *port);
                                    matches!(
                                        tokio::time::timeout(
                                            timeout,
                                            tokio::net::TcpStream::connect(target)
                                        )
                                        .await,
                                        Ok(Ok(_))
                                    )
                                }
                                HealthCheckProto::Icmp => {
                                    let secs = timeout.as_secs().max(1).to_string();
                                    let target = addr.to_string();
                                    // `--` terminates option parsing; the
                                    // target is a parsed IP either way.
                                    let mut probe = tokio::process::Command::new("ping");
                                    probe
                                        .args(["-c", "1", "-W", &secs, "--", &target])
                                        .stdout(std::process::Stdio::null())
                                        .stderr(std::process::Stdio::null())
                                        // Same two reasons as the WAN probe:
                                        // `-W` does not bound the process, and
                                        // a dropped handle leaves the child
                                        // running unless this is set. One
                                        // backend per interval is one orphan
                                        // per interval.
                                        .kill_on_drop(true);
                                    matches!(
                                        tokio::time::timeout(
                                            timeout + std::time::Duration::from_secs(1),
                                            probe.status()
                                        )
                                        .await,
                                        Ok(Ok(status)) if status.success()
                                    )
                                }
                            };

                            let threshold = if ok {
                                hc.recovery_threshold
                            } else {
                                hc.failure_threshold
                            };
                            let mut svc = probe_lb.write().await;
                            if let Err(e) = svc.update_backend_health(
                                service_id,
                                backend_id,
                                ok,
                                threshold.max(1),
                            ) {
                                tracing::debug!(
                                    service = %service_id,
                                    backend = %backend_id,
                                    "load balancer backend health update skipped: {e}"
                                );
                            }
                        }
                    }
                }
            });
            info!(
                services = service_count,
                backends = backend_count,
                "load balancer backend health-probe loop started"
            );
        }
    }

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
                None, // eBPF map writer - wired after tc-threatintel loads
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
    // Filled once the resolver and the enrichers have decided, below. A status
    // read before that answers `starting` rather than a setting read back.
    let container_coverage = Arc::clone(&app_state.container_coverage);

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
    crate::http::tls::install_pq_provider(config.agent.tls.pq_mode);

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
    let http_rate_limit = config.agent.api_rate_limit;

    // Loud startup warning when the control plane is served unauthenticated on a
    // network-reachable address. Config validation already refuses this unless
    // the operator opted in with `allow_unauthenticated_api=true`; that escape
    // hatch is preserved, but the exposure must not be silent.
    let bind_is_loopback = http_bind
        .parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.is_loopback());
    if !config.auth.enabled && !bind_is_loopback {
        tracing::warn!(
            bind_address = %http_bind,
            "control plane is UNAUTHENTICATED on a non-loopback address \
             (auth.enabled=false, allow_unauthenticated_api=true): firewall, \
             IPS and config-reload APIs are reachable without credentials - \
             ensure the port is fenced off by other means"
        );
    }

    // The same courtesy for the other half of the fence: validation refuses a
    // plaintext non-loopback listener unless the operator opted in, and the
    // opt-in must not be silent either - every call to this port carries a
    // credential readable by anything on the path.
    if !config.agent.tls.enabled && !bind_is_loopback {
        tracing::warn!(
            bind_address = %http_bind,
            "control plane is served in the CLEAR on a non-loopback address \
             (agent.tls.enabled=false, allow_plaintext_api=true): API keys and \
             configuration cross the network readable by anything on the path - \
             set agent.tls with a certificate and key"
        );
    }

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
            http_rate_limit,
            http_shutdown.cancelled_owned(),
        )
        .await
        {
            tracing::error!(error = %e, "HTTP API server failed");
        }
    });

    // ── 7b. Spawn dedicated metrics server on `agent.metrics_port` ─────
    // A separate listener so the metrics port can be exposed to a scraper
    // (Prometheus) while the control-API port is firewalled off.
    let metrics_state = Arc::clone(&app_state);
    let metrics_bind = config.agent.bind_address.clone();
    let metrics_port = config.agent.metrics_port;
    let metrics_shutdown = cancel_token.clone();
    let metrics_tls = tls_config.clone();
    let metrics_handle = tokio::spawn(async move {
        if let Err(e) = run_metrics_server(
            metrics_state,
            &metrics_bind,
            metrics_port,
            metrics_tls,
            metrics_shutdown.cancelled_owned(),
        )
        .await
        {
            tracing::error!(error = %e, "metrics server failed");
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
        Some(GrpcTlsConfig {
            cert_pem,
            key_pem,
            pq_mode: config.agent.tls.pq_mode,
            allow_tls12: config.agent.tls.allow_tls12,
        })
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
    // No "API-only" fallback when the kernel is too old - every eBPF
    // program depends on kfuncs introduced in 6.4 → 6.9 and the
    // verifier rejects them at load time on older kernels. The
    // correct remediation is upgrading the host kernel; running the
    // agent as a pure HTTP frontend on a 6.8 host gives operators a
    // false sense of coverage, so we refuse to boot.
    //
    // eBPF is loaded EXCLUSIVELY through a BPF token (kernel 6.9+). The
    // agent never loads programs with CAP_BPF / CAP_NET_ADMIN: the
    // self-bootstrap has had the warden delegate a bpffs and mounted it
    // before this runtime started, and the agent - which may run fully
    // unprivileged - creates the token against it. If the
    // token cannot be created the agent stays up in API-only mode
    // (REST/gRPC live, no eBPF attach); there is deliberately no
    // capability-based fallback.
    // Rootless split: the agent loads its OWN programs against the delegated
    // bpffs the warden mounted for it (the self-bootstrap trampoline created the
    // user namespace, had the warden delegate the bpffs, and mounted it before
    // this runtime started). `EBPFSENTINEL_WARDEN_SOCK` no longer means "load
    // nothing" - the agent still loads here; it only proxies the host-network ops
    // it cannot perform from its user namespace (conntrack teardown, routes,
    // gratuitous ARP, packet capture) to the warden over that socket.
    let warden_sock = warden_sock_from_env();
    // Reading a TCX chain back needs a capability this namespace lacks; the
    // warden answers for it, so every TC attach can verify where it landed.
    if let Some(sock) = &warden_sock {
        adapters::ebpf::tcx_order::use_warden(sock.clone());
    }

    check_kernel_version()?;

    // Ask the running kernel what it actually offers, once, before anything
    // loads. The version check above is a proxy for capability: vendors
    // backport helpers into older trees and distributions compile features
    // out, so version and truth drift apart. A gap found here names the
    // helper, the object and the program type; the same gap found at load
    // time is an opaque verifier rejection.
    //
    // The probe itself needs CAP_BPF, which the token-only loading path does
    // not hold, so on the normal path this reports "not probed" and changes
    // nothing. That is the intended outcome: an unknown must never read as a
    // missing helper.
    let helper_report = adapters::ebpf::init_kernel_helpers();
    info!("{}", helper_report.summary());
    for gap in &helper_report.missing_required {
        warn!(%gap, "required BPF helper unavailable on this kernel");
    }

    let ebpf_dir = resolve_ebpf_program_dir(&config);

    // Bootstrap the BPF token before any program load, so the loader can
    // attach the token fd and the Prometheus gauge is set before eBPF
    // attachment races with the metrics scrape.
    let bpf_policy = adapters::ebpf::BpfTokenPolicy::new(config.agent.bpf_token.bpffs_path.clone());
    let bpf_handle = match adapters::ebpf::bootstrap_bpf(&bpf_policy) {
        Ok(h) => {
            info!(
                kernel = h.kernel.version_string(),
                reason = h.reason,
                warden = warden_sock.is_some(),
                "eBPF loading via BPF token"
            );
            Some(h)
        }
        Err(e) => {
            error!(
                error = %e,
                "BPF token unavailable - running in API-only mode (no eBPF). The warden \
                 delegates the bpffs: start the agent with EBPFSENTINEL_WARDEN_SOCK pointing \
                 at a running warden."
            );
            None
        }
    };
    let ebpf_capable = bpf_handle.is_some();
    metrics.set_bpf_token_used(ebpf_capable);

    // Register the token fd process-wide BEFORE any eBPF load so every
    // map/BTF/program syscall (aya and the kfunc loader) is authorized by
    // the token. The token fd is kept alive for the process lifetime by
    // `ebpf_state.bpf_handle`.
    if let Some(handle) = bpf_handle.as_ref() {
        adapters::ebpf::set_bpf_token_fd(handle.token_fd.as_raw_fd());
    }

    // In BPF-token mode the agent cannot open a kernel module's BTF object fd
    // itself (BTF_GET_FD_BY_ID needs CAP_SYS_ADMIN, which the token does not
    // grant), yet that fd is required to load programs that call module kfuncs
    // (e.g. conntrack). A privileged setup component opens those fds and passes
    // them in, inherited across exec, advertised via `EBPF_MODULE_BTF_FDS` as a
    // comma-separated `module=fd` list. Register each so the kfunc loader can
    // splice it into the program-load `fd_array`.
    register_module_btf_fds();

    let mut ebpf_state = EbpfState::new();
    // Every task spawned below outlives the loaders unless something stops
    // it, and each one holds a map taken out of this generation. Hand them
    // the state's token so a detach closes their descriptors with it.
    let readers = ebpf_state.readers.clone();
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
    let mut attribution_ok = false;
    // One resolver, shared by everything that names a workload: the alert
    // pipeline, the conntrack listing and the reload manager all hold a
    // clone, and both halves are installed into it as they come up. A clone
    // taken before the hooks attach starts answering the moment they do.
    let workloads = application::workload_resolver::WorkloadResolver::new();
    // The cgroup links live here until the manager takes them over: dropping
    // the attacher detaches every hook, so it must outlive the load.
    let mut attribution_attacher: Option<adapters::ebpf::AttributionAttacher> = None;
    let mut process_tracing_ok = false;
    // The workload firewall's links, kept the same way the attribution ones
    // are, and the service the process table names each exec to.
    let mut workload_firewall_attacher: Option<
        adapters::ebpf::workload_firewall_attach::WorkloadFirewallAttacher,
    > = None;
    let mut netpol_replay: Option<Arc<application::netpol_replay_service::NetpolReplayService>> =
        None;
    let mut workload_policy_service: Option<
        Arc<application::workload_policy_service::WorkloadPolicyService>,
    > = None;
    // The tracepoint links live here until the manager takes them over.
    let mut process_attacher: Option<adapters::ebpf::ProcessTracingAttacher> = None;
    // The signal link and the service that arms through it. The attacher is
    // held for the life of the agent rather than handed to the lifecycle
    // manager: the capability is decided at start-up, because a reload that
    // turned it on would be a reload that granted the right to kill.
    let mut signal_attacher: Option<adapters::ebpf::SignalAttacher> = None;
    let mut process_signal_svc: Option<
        Arc<application::process_signal_service::ProcessSignalService>,
    > = None;
    // The quarantine service, which arms through maps in the workload
    // firewall's own object rather than one of its own: the hooks that answer
    // a `connect()` are the ones already attached there.
    let mut quarantine_svc: Option<Arc<application::quarantine_service::QuarantineService>> = None;
    // What the startup firewall handed over, for the reload path to keep.
    let mut fw_lpm_coordinator: Option<
        Arc<dyn ports::secondary::lpm_coordinator_port::LpmCoordinatorPort>,
    > = None;
    let mut fw_ipset_wired = false;
    let mut fw_loader: Option<EbpfLoader> = None;
    // Loaders the lifecycle manager takes over once it exists, each with the
    // token its readers run under, so a reload that disables one program
    // detaches that program and stops only its readers.
    let mut managed: Vec<(&'static str, EbpfLoader, CancellationToken)> = Vec::new();
    let fw_cancel = readers.child_token();
    let rl_cancel = readers.child_token();
    let lb_cancel = readers.child_token();
    let ids_cancel = readers.child_token();
    let ti_cancel = readers.child_token();
    let dns_cancel = readers.child_token();
    let dlp_cancel = readers.child_token();
    let ct_cancel = readers.child_token();
    let attribution_cancel = readers.child_token();
    let process_cancel = readers.child_token();
    let workload_cancel = readers.child_token();
    // Decided before the programs load, because the workload firewall reads
    // it through the same proc root the container resolver does and both are
    // built from it further down.
    let coverage_proc = resolver_proc_path(&config.container.resolver.proc_path, &host_proc_root());
    // The exec and exit events cross from the ring-buffer reader to the table
    // here. The table is built further down, once the container resolver and
    // the enrichers exist, so the buffer is what holds the first execs of the
    // node until it does.
    let (process_tx, process_rx) =
        tokio::sync::mpsc::channel::<domain::process::entity::ProcessLifecycleEvent>(4096);

    if ebpf_capable {
        // Pins from a previous generation cannot be inspected - the kernel
        // offers no way to ask whether one is still held - so startup wipes
        // rather than adopts. Links are the other half of that state and are
        // handled the opposite way: they are inspected, and an attach that
        // finds its own program already in place readopts it.
        EbpfLoader::cleanup_pin_path_because(
            adapters::ebpf::DEFAULT_BPF_PIN_PATH,
            "startup: previous generation's pins are not introspectable",
        );
        EbpfLoader::cleanup_pin_path_because(
            DLP_PIN_PATH,
            "startup: previous generation's pins are not introspectable",
        );

        // The kernel-filled tables take their capacity from the configuration
        // at create time, so the plan has to be in force before the first
        // object is loaded. This is the path every agent takes at start; the
        // HA activate path installs the same plan, and whichever runs first
        // wins, because a map keeps the capacity it was created with.
        let sizing = adapters::ebpf::map_sizing::MapSizing::from_config(&config);
        match adapters::ebpf::map_sizing::install(&sizing) {
            Ok(()) => info!(plan = %sizing.describe(), "eBPF table capacities"),
            Err(in_force) => warn!(
                in_force = %in_force.describe(),
                configured = %sizing.describe(),
                "eBPF table capacities changed in the configuration; they apply at the next \
                 agent start"
            ),
        }

        // 10a. XDP Firewall
        fw_ok = if config.firewall.enabled {
            match try_load_xdp_firewall(&ebpf_dir, &config) {
                Ok((loader, map_manager, fw_metrics_rdr, reader, zone_mgr, zone_rdrs)) => {
                    let event_tx_clone = event_tx.clone();
                    let rb_obs = RingBufObserver::new(
                        "xdp-firewall",
                        Arc::clone(&metrics) as Arc<dyn MetricsPort>,
                    );
                    let task_cancel_1 = fw_cancel.clone();
                    tokio::spawn(async move {
                        reader.run(event_tx_clone, task_cancel_1, rb_obs).await;
                    });
                    let mut svc = firewall_svc.write().await;
                    svc.set_map_port(Box::new(map_manager));
                    if let Some(rdr) = fw_metrics_rdr {
                        metrics_readers.push(rdr);
                    }
                    if let Some(mgr) = zone_mgr {
                        // Programs the zones loaded above and every later change.
                        zone_svc.write().await.set_map_port(Box::new(mgr));
                    }
                    if let Some((passed, dropped)) = zone_rdrs {
                        // Stops with this load: a reload that unloads the
                        // firewall starts a loop of its own over the new maps.
                        let zm_cancel = fw_cancel.clone();
                        let zm_metrics = Arc::clone(&metrics) as Arc<dyn MetricsPort>;
                        let zm_svc = Arc::clone(&zone_svc);
                        info!("per-zone datapath counters exported");
                        tokio::spawn(async move {
                            crate::ebpf_metrics::run_zone_metrics_loop(
                                passed,
                                dropped,
                                zm_svc,
                                zm_metrics,
                                Duration::from_secs(10),
                                zm_cancel,
                            )
                            .await;
                        });
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
            // Cleared rather than published as zero: zero is a program this
            // build asked the kernel for and did not get, which is an
            // incident, and a feature nobody turned on is not one. The status
            // map below keeps every program, so the endpoint and the
            // heartbeat still answer for this one.
            metrics.clear_ebpf_program_status("xdp_firewall");
            false
        };

        // 10b. XDP Rate Limiter
        rl_ok = if config.ratelimit.enabled {
            match try_load_xdp_ratelimit(&ebpf_dir, &config, fw_ok) {
                Ok((mut rl_loader, rl_mgr_opt, rl_lpm_opt, rl_rdrs, reader)) => {
                    let event_tx_clone = event_tx.clone();
                    let rb_obs = RingBufObserver::new(
                        "xdp-ratelimit",
                        Arc::clone(&metrics) as Arc<dyn MetricsPort>,
                    );
                    let task_cancel_2 = rl_cancel.clone();
                    tokio::spawn(async move {
                        reader.run(event_tx_clone, task_cancel_2, rb_obs).await;
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
                            managed.push((
                                "xdp_ratelimit_syncookie",
                                sc_loader,
                                readers.child_token(),
                            ));
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
                                let rb_obs = RingBufObserver::new(
                                    "xdp-loadbalancer",
                                    Arc::clone(&metrics) as Arc<dyn MetricsPort>,
                                );
                                let task_cancel_3 = lb_cancel.clone();
                                tokio::spawn(async move {
                                    lb_reader.run(event_tx_clone, task_cancel_3, rb_obs).await;
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
                                managed.push((
                                    "xdp_loadbalancer",
                                    lb_loader_early,
                                    lb_cancel.clone(),
                                ));
                                metrics.set_ebpf_program_status("xdp_loadbalancer", true);
                                info!("eBPF xdp-loadbalancer active (via ratelimit chain)");
                                lb_pre_loaded = true;
                            }
                            Err(e) => {
                                warn!("LB pre-load for RL chain failed (non-fatal): {e}");
                            }
                        }
                    }
                    managed.push(("xdp_ratelimit", rl_loader, rl_cancel.clone()));
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
            metrics.clear_ebpf_program_status("xdp_ratelimit");
            false
        };

        // Wire tail-call: firewall → reject (slot 1). Best-effort: if the reject
        // program fails to load, REJECT rules fall back to DROP silently (the
        // ProgramArray slot stays empty and tail_call is a no-op).
        if let Some(ref mut fw) = fw_loader {
            match try_load_xdp_firewall_reject(&ebpf_dir, fw) {
                Ok(reject_loader) => {
                    managed.push(("xdp_firewall_reject", reject_loader, readers.child_token()));
                    info!("XDP tail-call: firewall → reject wired (slot 1)");
                }
                Err(e) => {
                    warn!("xdp-firewall-reject load failed (REJECT falls back to DROP): {e}");
                }
            }
        }

        // Wire LpmCoordinator from xdp-firewall to alias, ddos, ips services (take LPM maps BEFORE others)
        // Not gated on GeoIP: the IPS blacklist and the DDoS auto-block install
        // LPM entries of their own, which have nothing to do with country data.
        if let Some(ref mut loader) = fw_loader {
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
                    fw_lpm_coordinator = Some(coordinator);
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
            fw_ipset_wired = true;
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

        // Firewall rules name aliases, which the kernel cannot look up: the
        // service is told what each name covers so those rules match on
        // addresses, ports and MACs instead of being left unrestricted.
        {
            let bindings =
                application::firewall_aliases::collect_bindings(&*alias_svc.read().await);
            firewall_svc.write().await.set_alias_bindings(bindings);
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
                    let rb_obs = RingBufObserver::new(
                        "xdp-loadbalancer",
                        Arc::clone(&metrics) as Arc<dyn MetricsPort>,
                    );
                    let task_cancel_4 = lb_cancel.clone();
                    tokio::spawn(async move {
                        lb_reader.run(event_tx_clone, task_cancel_4, rb_obs).await;
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
                    managed.push(("xdp_loadbalancer", lb_loader, lb_cancel.clone()));
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
                        if let Err(e) = svc.configure_bgp(vip_bgp_cfg.clone()) {
                            warn!("vip announcer bgp configure failed: {e}");
                        }
                    }
                    managed.push(("xdp_vip_announcer", vip_loader, readers.child_token()));
                    // Lapse unrenewed speaker grants and mirror the kernel
                    // per-VIP forged-reply counters into Prometheus.
                    tokio::spawn(crate::ebpf_lifecycle::vip_announcer_tick(
                        Arc::clone(&vip_svc),
                        readers.child_token(),
                    ));
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
            metrics.clear_ebpf_program_status("xdp_vip_announcer");
        }

        // Move firewall loader into eBPF state (after tail-call wiring)
        if let Some(loader) = fw_loader {
            managed.push(("xdp_firewall", loader, fw_cancel.clone()));
        }

        // 10c. TC IDS - also the L7 capture vehicle (TLS ClientHello / HTTP
        // pre-classification feeds the L7 parser and encrypted-DNS detector).
        // L7 payload emission is gated on the L7_PORTS map, not the IDS config
        // flag, so the program must load whenever IDS *or* L7 is enabled.
        ids_ok = if config.ids.enabled || config.l7.enabled {
            match try_load_tc_ids(&ebpf_dir, &config) {
                Ok((mut loader, ids_mgr_opt, l7_mgr_opt, cfg_mgr_opt, ids_rdr, reader)) => {
                    let event_tx_clone = event_tx.clone();
                    let rb_obs = RingBufObserver::new(
                        "tc-ids",
                        Arc::clone(&metrics) as Arc<dyn MetricsPort>,
                    );
                    let task_cancel_5 = ids_cancel.clone();
                    tokio::spawn(async move {
                        reader.run(event_tx_clone, task_cancel_5, rb_obs).await;
                    });
                    install_ids_workload_scope(&ids_workload_scope, &mut loader);
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
                        ebpf_map_holder.config_flags.push(("tc_ids", cfg_mgr));
                    }
                    if let Some(rdr) = ids_rdr {
                        metrics_readers.push(rdr);
                    }
                    iface_groups_mgr.add_map(loader.ebpf_mut());
                    managed.push(("tc_ids", loader, ids_cancel.clone()));
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
            metrics.clear_ebpf_program_status("tc_ids");
            false
        };

        // 10d. TC Threat Intel
        ti_ok =
            if config.threatintel.enabled {
                match try_load_tc_threatintel(&ebpf_dir, &config) {
                    Ok((loader, ti_mgr_opt, cfg_mgr_opt, ti_rdr, reader)) => {
                        let event_tx_clone = event_tx.clone();
                        let rb_obs = RingBufObserver::new(
                            "tc-threatintel",
                            Arc::clone(&metrics) as Arc<dyn MetricsPort>,
                        );
                        let task_cancel_6 = ti_cancel.clone();
                        tokio::spawn(async move {
                            reader.run(event_tx_clone, task_cancel_6, rb_obs).await;
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
                            ebpf_map_holder
                                .config_flags
                                .push(("tc_threatintel", cfg_mgr));
                        }
                        managed.push(("tc_threatintel", loader, ti_cancel.clone()));
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
                metrics.clear_ebpf_program_status("tc_threatintel");
                false
            };

        // 10e. TC DNS
        dns_ok = if config.dns.enabled {
            match try_load_tc_dns(&ebpf_dir, &config) {
                Ok((loader, dns_rdr, reader)) => {
                    let event_tx_clone = event_tx.clone();
                    let rb_obs = RingBufObserver::new(
                        "tc-dns",
                        Arc::clone(&metrics) as Arc<dyn MetricsPort>,
                    );
                    let task_cancel_7 = dns_cancel.clone();
                    tokio::spawn(async move {
                        reader.run(event_tx_clone, task_cancel_7, rb_obs).await;
                    });
                    if let Some(rdr) = dns_rdr {
                        metrics_readers.push(rdr);
                    }
                    managed.push(("tc_dns", loader, dns_cancel.clone()));
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
            metrics.clear_ebpf_program_status("tc_dns");
            false
        };

        // 10f. Uprobe DLP
        dlp_ok = if config.dlp.enabled {
            match try_load_uprobe_dlp(&ebpf_dir, &config, DLP_PIN_PATH, dlp_scope_svc.as_ref()) {
                // No extended-TLS consumer on this path; see the hot-reload
                // path for why dropping an attacher that never attached is safe.
                Ok((loader, dlp_rdr, reader, attacher, _extended)) => {
                    let event_tx_clone = event_tx.clone();
                    let rb_obs = RingBufObserver::new(
                        "uprobe-dlp",
                        Arc::clone(&metrics) as Arc<dyn MetricsPort>,
                    );
                    let task_cancel_8 = dlp_cancel.clone();
                    tokio::spawn(async move {
                        reader.run(event_tx_clone, task_cancel_8, rb_obs).await;
                    });
                    // Lifecycle watcher: attach SSL uprobes to containers as they
                    // appear and detach them on teardown.
                    let task_cancel_9 = dlp_cancel.clone();
                    tokio::spawn(async move {
                        attacher
                            .watch(adapters::ebpf::DLP_ATTACH_POLL_INTERVAL, task_cancel_9)
                            .await;
                    });
                    if let Some(rdr) = dlp_rdr {
                        metrics_readers.push(rdr);
                    }
                    managed.push(("uprobe_dlp", loader, dlp_cancel.clone()));
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
            metrics.clear_ebpf_program_status("uprobe_dlp");
            false
        };

        // 10f-bis. Socket attribution (cgroup hooks)
        attribution_ok = if config.attribution.enabled {
            match try_load_cgroup_attribution(&ebpf_dir, &config) {
                Ok((loader, metrics_rdr, socket_reader, attacher, status)) => {
                    let attached = status.attached;
                    if attached {
                        attribution_attacher = Some(attacher);
                        if let Some(rdr) = metrics_rdr {
                            metrics_readers.push(rdr);
                        }
                        if let Some(reader) = socket_reader {
                            workloads.install_sockets(Box::new(reader));
                        }
                        managed.push(("cgroup_attribution", loader, attribution_cancel.clone()));
                        metrics.set_ebpf_program_status("cgroup_attribution", true);
                        info!("eBPF cgroup-attribution active");
                    } else {
                        // The object loaded and the kernel refused the attach.
                        // Dropping both leaves the agent with no socket table
                        // and no half-attached hooks, which is the degraded
                        // posture the status now describes.
                        metrics.set_ebpf_program_status("cgroup_attribution", false);
                    }
                    attached
                }
                Err(e) => {
                    warn!("cgroup-attribution load failed (degraded mode): {e}");
                    adapters::ebpf::attribution_attach::publish_status(
                        adapters::ebpf::AttributionStatus {
                            attached: false,
                            cgroup: config.attribution.cgroup_root.clone(),
                            hooks: Vec::new(),
                            reason: Some(e.to_string()),
                            brokered: false,
                        },
                    );
                    metrics.set_ebpf_program_status("cgroup_attribution", false);
                    false
                }
            }
        } else {
            metrics.clear_ebpf_program_status("cgroup_attribution");
            adapters::ebpf::attribution_attach::publish_status(
                adapters::ebpf::AttributionStatus::default(),
            );
            false
        };

        // 10f-bis-b. The workload firewall (cgroup bind and connect hooks)
        //
        // Driven by the rules rather than by a key of its own: a document
        // with no workload rule loads nothing, and one that carries a rule
        // that refuses means it. That is also why a kernel refusing the
        // attach is survivable for a policy that only observes and fatal for
        // one that does not - an agent reporting healthy while the rule in
        // the file enforces nothing is the outcome worth refusing to start
        // over.
        //
        // The quarantine rides in the same object, so an operator who turned
        // it on gets it loaded whether or not the document carries a workload
        // rule: the hooks that answer a `connect()` are these, and a node with
        // no rules has nothing else to attach them for.
        //
        // `NetworkPolicy` rides in it too, on the packet hooks of the same
        // cgroup, so turning it on loads the object on its own as well.
        let netpol_mode = config.container.kubernetes.network_policy.mode;
        let netpol_on = netpol_mode != infrastructure::config::NetworkPolicyMode::Off;
        // A container's labels are policy too, so reading them loads the
        // object even while the file carries no workload rule.
        let label_policy = config.container.docker.label_policy;
        if workload_policy.is_empty()
            && !config.response.quarantine.enabled
            && !netpol_on
            && !label_policy
        {
            metrics.clear_ebpf_program_status("cgroup_workload_firewall");
            adapters::ebpf::workload_firewall_attach::publish_status(
                adapters::ebpf::workload_firewall_attach::WorkloadFirewallStatus::default(),
            );
            adapters::ebpf::quarantine_map_manager::publish_status(
                adapters::ebpf::QuarantineStatus {
                    reason: Some("quarantining a workload is off in the configuration".to_string()),
                    ..adapters::ebpf::QuarantineStatus::default()
                },
            );
        } else {
            let outcome = try_load_cgroup_workload_firewall(&ebpf_dir, &config);
            let refused = match outcome {
                Ok((mut loader, metrics_rdr, manager, reader, attacher, status))
                    if status.attached =>
                {
                    workload_firewall_attacher = Some(attacher);
                    if let Some(rdr) = metrics_rdr {
                        metrics_readers.push(rdr);
                    }
                    let service = Arc::new(
                        application::workload_policy_service::WorkloadPolicyService::new(
                            workload_policy.clone(),
                        )
                        .with_maps(Box::new(manager))
                        .with_cgroups(Arc::new(
                            adapters::container::ProcContainerResolver::new(&coverage_proc),
                        )),
                    );
                    // The rules go in before the table starts naming tasks,
                    // so no task is resolved against an empty rule array.
                    service.apply(workload_policy.clone())?;

                    // Every refusal becomes an alert naming the rule that
                    // refused it. The record carries a slot rather than a
                    // rule identifier, because the kernel walks an array,
                    // so the policy in force is what turns one into the
                    // other and a record that crossed a reload is dropped
                    // rather than named after whoever inherited its slot.
                    let (denial_tx, mut denial_rx) =
                        mpsc::channel::<domain::firewall::workload::WorkloadDenialRecord>(
                            WORKLOAD_DENIAL_CHANNEL_CAPACITY,
                        );
                    let rb_obs = RingBufObserver::new(
                        adapters::ebpf::workload_event_reader::RINGBUF_SOURCE,
                        Arc::clone(&metrics) as Arc<dyn MetricsPort>,
                    );
                    let reader_cancel = workload_cancel.clone();
                    tokio::spawn(async move {
                        reader.run(denial_tx, reader_cancel, rb_obs).await;
                    });
                    let naming = Arc::clone(&service);
                    let denial_alert_tx = alert_tx.clone();
                    tokio::spawn(async move {
                        while let Some(record) = denial_rx.recv().await {
                            let Some(denial) = naming.name_denial(record) else {
                                continue;
                            };
                            // The task is named by the pipeline, off the
                            // thread group the hook reported: a socket hook
                            // has no flow to look the workload up by.
                            let alert =
                                domain::alert::entity::Alert::from_workload_denial(&denial, None);
                            if denial_alert_tx
                                .send(application::alert_event::AlertEvent::WorkloadDenial(
                                    Box::new(alert),
                                ))
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                    });

                    // The answers named workloads are given, read so the
                    // addresses a rule names by DNS name open for the pod
                    // that asked. Without the reader those rules stay
                    // closed, which is the side a failure belongs on.
                    match adapters::ebpf::WorkloadDnsReader::new(loader.ebpf_mut()) {
                        Ok(dns_reader) => {
                            let (dns_tx, mut dns_rx) =
                                mpsc::channel::<domain::firewall::fqdn::DnsCapture>(
                                    WORKLOAD_DNS_CHANNEL_CAPACITY,
                                );
                            let dns_obs = RingBufObserver::new(
                                adapters::ebpf::workload_dns_reader::RINGBUF_SOURCE,
                                Arc::clone(&metrics) as Arc<dyn MetricsPort>,
                            );
                            let dns_cancel = workload_cancel.clone();
                            tokio::spawn(async move {
                                dns_reader.run(dns_tx, dns_cancel, dns_obs).await;
                            });
                            let learning = Arc::clone(&service);
                            tokio::spawn(async move {
                                while let Some(capture) = dns_rx.recv().await {
                                    learning.observe_dns(&capture);
                                }
                            });
                            let sweeping = Arc::clone(&service);
                            let fqdn_cancel = workload_cancel.clone();
                            tokio::spawn(async move {
                                let mut ticker =
                                    tokio::time::interval(WORKLOAD_FQDN_SWEEP_INTERVAL);
                                loop {
                                    tokio::select! {
                                        () = fqdn_cancel.cancelled() => break,
                                        _ = ticker.tick() => {}
                                    }
                                    sweeping.sweep_fqdn(
                                        adapters::ebpf::ringbuf_observer::boottime_now_ns(),
                                    );
                                }
                            });
                        }
                        Err(e) => {
                            warn!(
                                "workload DNS answers unreadable, rules naming a destination by name stay closed: {e}"
                            );
                        }
                    }

                    // The per-rule counters are the kernel's own and are
                    // read rather than counted off the records, because the
                    // ring can drop one under load and a security count
                    // that quietly loses a refusal is worse than none. What
                    // goes to Prometheus is the difference between two
                    // readings, and a rule whose count went backwards was
                    // republished rather than refused a negative number of
                    // times.
                    let counting = Arc::clone(&service);
                    let counter_metrics = Arc::clone(&metrics) as Arc<dyn MetricsPort>;
                    let counter_cancel = workload_cancel.clone();
                    tokio::spawn(async move {
                        use std::collections::HashMap;

                        let mut seen: HashMap<String, u64> = HashMap::new();
                        let mut ticker = tokio::time::interval(WORKLOAD_DENIAL_READ_INTERVAL);
                        loop {
                            tokio::select! {
                                () = counter_cancel.cancelled() => break,
                                _ = ticker.tick() => {}
                            }
                            let counts = match counting.denials_by_rule() {
                                Ok(counts) => counts,
                                Err(e) => {
                                    warn!("workload denial counters unreadable: {e}");
                                    continue;
                                }
                            };
                            let enforcing = counting.policy();
                            for (rule, total) in counts {
                                let previous = seen.get(&rule.0).copied().unwrap_or(0);
                                let delta = total.saturating_sub(previous);
                                seen.insert(rule.0.clone(), total);
                                if delta == 0 {
                                    continue;
                                }
                                let enforced = enforcing
                                    .rules()
                                    .iter()
                                    .find(|candidate| candidate.id == rule)
                                    .is_some_and(
                                        domain::firewall::workload::WorkloadRule::enforces,
                                    );
                                counter_metrics.record_workload_denials(&rule.0, enforced, delta);
                            }
                        }
                    });

                    // The quarantine's own two maps, taken from the same
                    // object. Turned off, they are left in it: an unused map
                    // costs its own size and nothing else, and a manager
                    // nobody holds cannot arm anything.
                    if config.response.quarantine.enabled {
                        match adapters::ebpf::QuarantineMapManager::new(loader.ebpf_mut()) {
                            Ok(maps) => {
                                if let Ok(rdr) =
                                    MetricsReader::new(loader.ebpf_mut(), "QUARANTINE_METRICS")
                                {
                                    metrics_readers.push(rdr);
                                }
                                let quarantine = &config.response.quarantine;
                                let root = &config.attribution.cgroup_root;
                                let guard =
                                    domain::response::quarantine::CgroupQuarantineGuard::new(
                                        adapters::container::self_cgroup_id(root).unwrap_or(0),
                                        adapters::container::root_cgroup_id(root).unwrap_or(0),
                                        &quarantine.protected_paths,
                                        &quarantine.protected_ids,
                                    );
                                let settings =
                                    application::quarantine_service::QuarantineSettings {
                                        window: Duration::from_secs(quarantine.window_secs),
                                        max_window: Duration::from_secs(quarantine.max_window_secs),
                                        max_flows_scanned: quarantine.max_flows_scanned,
                                    };
                                let mut svc = application::quarantine_service::QuarantineService::new(
                                    Arc::new(tokio::sync::Mutex::new(maps))
                                        as Arc<tokio::sync::Mutex<dyn ports::secondary::quarantine_map_port::QuarantineMapPort>>,
                                    Arc::new(adapters::container::CgroupfsResolver::new(
                                        root.clone(),
                                    )),
                                    guard,
                                    settings,
                                );
                                if let Some(store) = audit_store_handle.clone() {
                                    svc = svc.with_audit(store);
                                }
                                if quarantine.tear_down_flows {
                                    // One port for both halves: the table a
                                    // teardown reads and the delete it then
                                    // issues are the same netfilter view, so
                                    // a row that was there to read is a row
                                    // this can name.
                                    let nf = Arc::new(
                                        adapters::netfilter::conntrack::ProcNetfilterConntrackPort::new(),
                                    );
                                    svc = svc.with_flow_teardown(
                                        Arc::clone(&nf)
                                            as Arc<dyn ports::secondary::conntrack_map_port::ConnTrackMapPort>,
                                        nf as Arc<dyn ports::secondary::conntrack_kill_port::ConnTrackKillPort>,
                                        workloads.clone(),
                                    );
                                }
                                let svc = Arc::new(svc);

                                // The kernel stops refusing at the deadline it
                                // was given whether or not this runs, so the
                                // sweep is what keeps the map from filling and
                                // what makes a listed quarantine a live one.
                                let sweeper = Arc::clone(&svc);
                                let sweep_cancel = workload_cancel.clone();
                                let sweep_interval =
                                    Duration::from_secs(quarantine.sweep_interval_secs);
                                tokio::spawn(async move {
                                    let mut ticker = tokio::time::interval(sweep_interval);
                                    loop {
                                        tokio::select! {
                                            () = sweep_cancel.cancelled() => break,
                                            _ = ticker.tick() => {}
                                        }
                                        if let Err(e) = sweeper.sweep_expired("expiry").await {
                                            warn!("lapsed quarantines not swept: {e}");
                                        }
                                    }
                                });

                                let tears_down = svc.tears_flows_down();
                                adapters::ebpf::quarantine_map_manager::publish_status(
                                    adapters::ebpf::QuarantineStatus {
                                        armed: true,
                                        reason: None,
                                        window_ms: quarantine.window_secs.saturating_mul(1_000),
                                        tears_down_flows: tears_down,
                                        protected: svc.protected_count(),
                                    },
                                );
                                quarantine_svc = Some(svc);
                                warn!(
                                    window_secs = quarantine.window_secs,
                                    tear_down_flows = tears_down,
                                    "quarantining a workload is armed: a matching rule can cut a running workload off the network"
                                );
                            }
                            Err(e) => {
                                // The rules still work: the object attached,
                                // and only the maps this capability needs are
                                // absent. A rule asking for a quarantine is
                                // then refused by a service nobody built.
                                adapters::ebpf::quarantine_map_manager::publish_status(
                                    adapters::ebpf::QuarantineStatus {
                                        reason: Some(format!(
                                            "the workload firewall object carries no quarantine map: {e}"
                                        )),
                                        ..adapters::ebpf::QuarantineStatus::default()
                                    },
                                );
                                warn!("quarantine unavailable, its maps were not acquired: {e}");
                            }
                        }
                    } else {
                        adapters::ebpf::quarantine_map_manager::publish_status(
                            adapters::ebpf::QuarantineStatus {
                                reason: Some(
                                    "quarantining a workload is off in the configuration"
                                        .to_string(),
                                ),
                                ..adapters::ebpf::QuarantineStatus::default()
                            },
                        );
                    }

                    if netpol_on {
                        netpol_replay = start_network_policy(
                            &mut loader,
                            &config,
                            &mut metrics_readers,
                            workload_cancel.clone(),
                        )
                        .await?;
                    }

                    workload_policy_service = Some(service);
                    managed.push(("cgroup_workload_firewall", loader, workload_cancel.clone()));
                    metrics.set_ebpf_program_status("cgroup_workload_firewall", true);
                    info!(
                        rules = workload_policy.rules().len(),
                        enforcing = workload_policy.enforces(),
                        "eBPF cgroup-workload-firewall active"
                    );
                    None
                }
                Ok((_, _, _, _, _, status)) => Some(
                    status
                        .reason
                        .unwrap_or_else(|| "the kernel refused the attach".to_string()),
                ),
                Err(e) => Some(e.to_string()),
            };
            if let Some(reason) = refused {
                metrics.set_ebpf_program_status("cgroup_workload_firewall", false);
                adapters::ebpf::workload_firewall_attach::publish_status(
                    adapters::ebpf::workload_firewall_attach::WorkloadFirewallStatus {
                        attached: false,
                        cgroup: config.attribution.cgroup_root.clone(),
                        hooks: Vec::new(),
                        reason: Some(reason.clone()),
                        brokered: false,
                    },
                );
                if config.response.quarantine.enabled {
                    // Said in the quarantine's own words rather than left to
                    // be inferred from the firewall block: an operator who
                    // armed a quarantine and reads "not attached" against the
                    // rules has no reason to think it covers them too.
                    adapters::ebpf::quarantine_map_manager::publish_status(
                        adapters::ebpf::QuarantineStatus {
                            reason: Some(format!(
                                "the hooks a quarantine refuses at are not attached: {reason}"
                            )),
                            ..adapters::ebpf::QuarantineStatus::default()
                        },
                    );
                }
                if workload_policy.enforces() {
                    return Err(anyhow::anyhow!(
                        adapters::ebpf::workload_firewall_attach::enforcement_unavailable(&reason)
                    ));
                }
                if netpol_mode == infrastructure::config::NetworkPolicyMode::Enforce {
                    return Err(anyhow::anyhow!(network_policy_unavailable(&reason)));
                }
                if label_policy {
                    // A label may say enforce on any container started later,
                    // and nothing at that point could refuse it.
                    return Err(anyhow::anyhow!(
                        "container.docker.label_policy is on and the cgroup hooks that would \
                         carry a container's labels did not attach: {reason}"
                    ));
                }
                if netpol_on {
                    warn!(
                        "network policy observes nothing, the cgroup hooks did not attach: {reason}"
                    );
                }
                warn!(
                    "workload firewall not loaded, the rules that observe observe nothing: {reason}"
                );
            }
        }

        // 10f-ter. Process tracing (exec and exit tracepoints)
        process_tracing_ok = if config.process_table.enabled {
            match try_load_process_tracing(&ebpf_dir, &config) {
                Ok((loader, metrics_rdr, reader, attacher, status)) => {
                    let attached = status.attached;
                    if attached {
                        process_attacher = Some(attacher);
                        if let Some(rdr) = metrics_rdr {
                            metrics_readers.push(rdr);
                        }
                        let tx = process_tx.clone();
                        let rb_obs = RingBufObserver::new(
                            "tracepoint-process",
                            Arc::clone(&metrics) as Arc<dyn MetricsPort>,
                        );
                        let task_cancel = process_cancel.clone();
                        tokio::spawn(async move {
                            reader.run(tx, task_cancel, rb_obs).await;
                        });
                        managed.push(("tracepoint_process", loader, process_cancel.clone()));
                        metrics.set_ebpf_program_status("tracepoint_process", true);
                        info!("eBPF process tracing active");
                    } else {
                        // The object loaded and the kernel refused the attach,
                        // so the table would fill from one tracepoint or from
                        // neither. Both go, and the status carries the reason.
                        metrics.set_ebpf_program_status("tracepoint_process", false);
                    }
                    attached
                }
                Err(e) => {
                    warn!("process tracing load failed (degraded mode): {e}");
                    adapters::ebpf::process_attach::publish_status(
                        adapters::ebpf::ProcessTracingStatus {
                            attached: false,
                            tracepoints: Vec::new(),
                            reason: Some(e.to_string()),
                            command_line: config.process_table.capture_command_line,
                        },
                    );
                    metrics.set_ebpf_program_status("tracepoint_process", false);
                    false
                }
            }
        } else {
            metrics.clear_ebpf_program_status("tracepoint_process");
            adapters::ebpf::process_attach::publish_status(adapters::ebpf::ProcessTracingStatus {
                attached: false,
                tracepoints: Vec::new(),
                reason: Some("the process table is turned off in the configuration".to_string()),
                command_line: false,
            });
            false
        };

        // 10f-quinquies. Stopping the process behind a flow
        if config.response.kill_process.enabled {
            match try_load_signal(&ebpf_dir) {
                Ok((loader, metrics_rdr, maps, attacher, status)) => {
                    if status.attached {
                        let kill = &config.response.kill_process;
                        let guard = domain::response::signal::ProcessSignalGuard::new(
                            std::process::id(),
                            &kill.protected_commands,
                            &kill.protected_pids,
                        );
                        // Read before the guard is handed over, because the
                        // endpoint reports how many ids the kernel refuses and
                        // the guard is the only thing that knows.
                        let protected = guard.kernel_protected_pids().len();
                        let executables = Arc::new(adapters::container::ProcExecutableResolver::new(
                            &coverage_proc,
                        ))
                            as Arc<dyn ports::secondary::process_executable_port::ProcessExecutableReader>;
                        let settings = application::process_signal_service::ProcessSignalSettings {
                            signal: kill.signal,
                            window: Duration::from_millis(kill.window_ms),
                            poll_interval: Duration::from_millis(
                                (kill.window_ms / 20).clamp(5, 100),
                            ),
                        };
                        match application::process_signal_service::ProcessSignalService::new(
                            Arc::new(tokio::sync::Mutex::new(maps))
                                as Arc<tokio::sync::Mutex<dyn ports::secondary::process_signal_map_port::ProcessSignalMapPort>>,
                            executables,
                            audit_store_handle.clone(),
                            guard,
                            settings,
                        )
                        .await
                        {
                            Ok(svc) => {
                                process_signal_svc = Some(Arc::new(svc));
                                signal_attacher = Some(attacher);
                                if let Some(rdr) = metrics_rdr {
                                    metrics_readers.push(rdr);
                                }
                                ebpf_state.add_loader(loader);
                                metrics.set_ebpf_program_status("tracepoint_signal", true);
                                adapters::ebpf::signal_attach::publish_status(
                                    adapters::ebpf::SignalStatus {
                                        attached: true,
                                        reason: None,
                                        signal: kill.signal,
                                        window_ms: kill.window_ms,
                                        protected,
                                    },
                                );
                                warn!(
                                    signal = kill.signal,
                                    window_ms = kill.window_ms,
                                    "stopping the process behind a flow is armed: a matching rule can terminate a running process"
                                );
                            }
                            Err(e) => {
                                // The protected set could not be written, so
                                // the kernel's own fence is absent: the
                                // capability goes rather than running without
                                // the one check configuration cannot remove.
                                warn!("process signalling disabled, the protected set was refused: {e}");
                                metrics.set_ebpf_program_status("tracepoint_signal", false);
                                adapters::ebpf::signal_attach::publish_status(
                                    adapters::ebpf::SignalStatus {
                                        attached: false,
                                        reason: Some(format!(
                                            "the kernel refused the protected set: {e}"
                                        )),
                                        ..adapters::ebpf::SignalStatus::default()
                                    },
                                );
                            }
                        }
                    } else {
                        let reason = status
                            .reason
                            .unwrap_or_else(|| "the kernel refused the attach".to_string());
                        warn!("process signalling unavailable: {reason}");
                        metrics.set_ebpf_program_status("tracepoint_signal", false);
                    }
                }
                Err(e) => {
                    warn!("process signalling load failed: {e}");
                    metrics.set_ebpf_program_status("tracepoint_signal", false);
                    adapters::ebpf::signal_attach::publish_status(adapters::ebpf::SignalStatus {
                        attached: false,
                        reason: Some(format!("the object did not load: {e}")),
                        ..adapters::ebpf::SignalStatus::default()
                    });
                }
            }
        } else {
            metrics.clear_ebpf_program_status("tracepoint_signal");
            adapters::ebpf::signal_attach::publish_status(adapters::ebpf::SignalStatus {
                attached: false,
                reason: Some("stopping a process is turned off in the configuration".to_string()),
                ..adapters::ebpf::SignalStatus::default()
            });
        }

        // 10g. TC ConnTrack
        ct_ok = if config.conntrack.enabled {
            match try_load_tc_conntrack(&ebpf_dir, &config) {
                Ok((loader, ct_mgr, ct_rdr, opt_reader)) => {
                    if let Some(reader) = opt_reader {
                        let event_tx_clone = event_tx.clone();
                        let rb_obs = RingBufObserver::new(
                            "tc-conntrack",
                            Arc::clone(&metrics) as Arc<dyn MetricsPort>,
                        );
                        let task_cancel_10 = ct_cancel.clone();
                        tokio::spawn(async move {
                            reader.run(event_tx_clone, task_cancel_10, rb_obs).await;
                        });
                    }
                    conntrack_svc.write().await.set_map_port(Box::new(ct_mgr));
                    if let Some(rdr) = ct_rdr {
                        metrics_readers.push(rdr);
                    }
                    managed.push(("tc_conntrack", loader, ct_cancel.clone()));
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
            metrics.clear_ebpf_program_status("tc_conntrack");
            false
        };

        // 10h. TC NAT (ingress + egress)
        nat_ok = if config.nat.enabled {
            match try_load_tc_nat(&ebpf_dir, &config) {
                Ok((mut ingress_loader, mut egress_loader, nat_mgr, nat_rdrs)) => {
                    metrics_readers.extend(nat_rdrs);
                    {
                        // Pushes the rules the service holds, which are
                        // alias-expanded, and the hairpin configuration.
                        nat_svc.write().await.set_map_port(Box::new(nat_mgr));
                    }
                    iface_groups_mgr.add_map(ingress_loader.ebpf_mut());
                    iface_groups_mgr.add_map(egress_loader.ebpf_mut());
                    // Ingress and egress are one program to the lifecycle
                    // manager: disabling "tc_nat" removes both.
                    let nat_cancel = readers.child_token();
                    managed.push(("tc_nat", ingress_loader, nat_cancel.clone()));
                    managed.push(("tc_nat_egress", egress_loader, nat_cancel));
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
            metrics.clear_ebpf_program_status("tc_nat_ingress");
            metrics.clear_ebpf_program_status("tc_nat_egress");
            false
        };

        // 10i. TC Scrub
        scrub_ok = if config.firewall.scrub.enabled {
            match try_load_tc_scrub(&ebpf_dir, &config) {
                Ok((loader, scrub_rdr)) => {
                    if let Some(rdr) = scrub_rdr {
                        metrics_readers.push(rdr);
                    }
                    managed.push(("tc_scrub", loader, readers.child_token()));
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
            metrics.clear_ebpf_program_status("tc_scrub");
            false
        };

        // 10j. TC QoS
        qos_ok = if config.qos.enabled {
            match try_load_tc_qos(&ebpf_dir, &config) {
                Ok((mut loader, qos_mgr, qos_rdr, opt_reader)) => {
                    if let Some(reader) = opt_reader {
                        let event_tx_clone = event_tx.clone();
                        let rb_obs = RingBufObserver::new(
                            "tc-qos",
                            Arc::clone(&metrics) as Arc<dyn MetricsPort>,
                        );
                        let task_cancel_11 = readers.clone();
                        tokio::spawn(async move {
                            reader.run(event_tx_clone, task_cancel_11, rb_obs).await;
                        });
                    }
                    {
                        let mut svc = qos_svc.write().await;
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
            metrics.clear_ebpf_program_status("tc_qos");
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
                    let rb_obs = RingBufObserver::new(
                        "xdp-loadbalancer",
                        Arc::clone(&metrics) as Arc<dyn MetricsPort>,
                    );
                    let task_cancel_12 = lb_cancel.clone();
                    tokio::spawn(async move {
                        lb_reader.run(event_tx_clone, task_cancel_12, rb_obs).await;
                    });
                    lb_svc.write().await.set_map_port(Box::new(lb_mgr));
                    if let Some(rdr) = lb_metrics_rdr {
                        metrics_readers.push(rdr);
                    }
                    // FW→LB wiring (slot 2) already done during pre-load or not needed.
                    managed.push(("xdp_loadbalancer", lb_loader, lb_cancel.clone()));
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
            metrics.clear_ebpf_program_status("xdp_loadbalancer");
            false
        };

        // ── 10z. Populate INTERFACE_GROUPS maps across all loaded programs ──
        {
            let membership = config.kernel_interface_membership();
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

    // Populate eBPF program status for the ops endpoint and the heartbeat.
    //
    // Both of those are read outside the agent, so the names here are the
    // published ones rather than the symbols the loader is asked for: an
    // operator reading `/api/v1/ebpf/status` and an operator reading `/metrics`
    // have to be looking at the same word for the same program.
    {
        let mut status = ebpf_program_status.write().await;
        status.insert("xdp-firewall".to_string(), fw_ok);
        status.insert("xdp-ratelimit".to_string(), rl_ok);
        status.insert("tc-ids".to_string(), ids_ok);
        status.insert("tc-threatintel".to_string(), ti_ok);
        status.insert("tc-dns".to_string(), dns_ok);
        status.insert("uprobe-dlp".to_string(), dlp_ok);
        status.insert("tc-conntrack".to_string(), ct_ok);
        status.insert("tc-nat-ingress".to_string(), nat_ok);
        status.insert("tc-nat-egress".to_string(), nat_ok);
        status.insert("tc-scrub".to_string(), scrub_ok);
        status.insert("tc-qos".to_string(), qos_ok);
        status.insert("xdp-loadbalancer".to_string(), lb_ok);
        status.insert("xdp-vip-announcer".to_string(), vip_announcer_ok);
        status.insert("cgroup-attribution".to_string(), attribution_ok);
        status.insert("tracepoint-process".to_string(), process_tracing_ok);
        status.insert(
            "tracepoint-signal".to_string(),
            adapters::ebpf::signal_attach::status().attached,
        );
        status.insert(
            "cgroup-workload-firewall".to_string(),
            adapters::ebpf::workload_firewall_attach::status().attached,
        );
    }

    // ── Anonymous usage telemetry ───────────────────────────────
    //
    // Spawned here rather than earlier because it reports which programs are
    // loaded, and the map above is the only place that answer exists. A build
    // carrying no endpoint has nowhere to report, which is what a community
    // build of these sources is.
    if config.telemetry.is_active() {
        match adapters::telemetry::beacon_http::HttpTelemetryBeacon::from_build() {
            Ok(beacon) => {
                let service = application::telemetry_service::TelemetryService::new(
                    Arc::new(beacon),
                    Arc::new(
                        adapters::telemetry::installation_file::FileInstallationStore::new(
                            &config.telemetry.state_path,
                        )
                        .with_machine_id(
                            config.telemetry.machine_id().map(std::path::PathBuf::from),
                        ),
                    ),
                    Arc::new(
                        adapters::telemetry::program_inventory::SharedProgramInventory::new(
                            Arc::clone(&ebpf_program_status),
                        ),
                    ),
                    env!("CARGO_PKG_VERSION"),
                );
                let telemetry_cancel = cancel_token.clone();
                tokio::spawn(service.run(telemetry_cancel));
            }
            Err(e) => debug!("telemetry not enabled in this build: {e}"),
        }
    }

    // ── Build link hot-plug registry + spawn watcher ─────────
    if ebpf_capable {
        use adapters::ebpf::link_watcher::{
            HookPolicy, HookSide, LinkHotPlugRegistry, LinkTable, OwnerReporting,
        };
        use infrastructure::config::AttachMode;
        use ports::secondary::ids_workload_scope_port::WorkloadLinkSink;

        // Each side in the order the chain runs on a configured interface:
        // programs on one hook run in the order they were attached.
        let ids_egress = config.ids.inspect_egress || config.container.resolver.enabled;
        let tc_programs = [
            ("tc_ids", ids_ok, HookSide::Ingress),
            ("tc_threatintel", ti_ok, HookSide::Ingress),
            ("tc_dns", dns_ok, HookSide::Ingress),
            ("tc_conntrack", ct_ok, HookSide::Ingress),
            ("tc_nat_ingress", nat_ok, HookSide::Ingress),
            ("tc_scrub", scrub_ok, HookSide::Ingress),
            ("tc_qos_ingress", qos_ok, HookSide::Ingress),
            ("tc_ids", ids_ok && ids_egress, HookSide::Egress),
            ("tc_nat_egress", nat_ok, HookSide::Egress),
            ("tc_qos", qos_ok, HookSide::Egress),
        ];

        let mut registry = LinkHotPlugRegistry::new();
        for &(name, ok, side) in &tc_programs {
            if !ok {
                continue;
            }
            if let Some(fd) = ebpf_state
                .loaders
                .iter()
                .find_map(|loader| loader.program_fd(name))
            {
                registry.register(name.to_string(), fd, side);
            }
        }

        let registered = registry.program_count();
        if registered > 0 {
            let policy = match config.agent.attach_mode {
                AttachMode::Auto => HookPolicy::Auto,
                AttachMode::Tc => HookPolicy::Tcx,
                AttachMode::Netkit => HookPolicy::Netkit,
            };
            let table = LinkTable::new(policy, config.agent.interfaces.iter().cloned());
            // A packet on the host side of a container link carries no
            // socket, so the classifier learns the workload from the link;
            // the process holding it is fed to the process table as well, so
            // the scope knows the workload before anything in it execs.
            let mut owners = OwnerReporting::new(
                Arc::clone(&ids_workload_scope) as Arc<dyn WorkloadLinkSink>,
                config.container.resolver.cgroup_root.clone().into(),
                host_proc_root(),
            );
            if config.process_table.enabled {
                owners = owners.with_processes(process_tx.clone());
            }
            registry.report_owners(owners);
            // Workload namespaces are found through the host procfs, which is
            // a mount rather than a shared pid namespace in a pod that runs
            // without hostPID.
            tokio::spawn(adapters::ebpf::link_watcher::watch_links(
                Arc::new(registry),
                table,
                host_proc_root(),
                Arc::clone(&metrics) as Arc<dyn ContainerMetrics>,
                cancel_token.clone(),
            ));
            info!(
                programs = registered,
                ?policy,
                "link hot-plug watcher started (rtnetlink, veth/netkit/macvlan/ipvlan/bridge members)"
            );
        } else {
            info!("link hot-plug watcher skipped (no TC programs loaded)");
        }
    }

    // ── 10½b. Build EbpfProgramManager from loaded state ──────────────
    let ebpf_manager = {
        let mut mgr = crate::ebpf_lifecycle::EbpfProgramManager::new(
            event_tx.clone(),
            Arc::new(crate::runtime::ServiceHandles {
                firewall_svc: Arc::clone(&firewall_svc),
                ids_svc: Arc::clone(&ids_svc),
                ids_workload_scope: Arc::clone(&ids_workload_scope),
                ips_svc: Arc::clone(&ips_svc),
                rl_svc: Arc::clone(&rl_svc),
                ti_svc: Arc::clone(&ti_svc),
                dns_blocklist_svc: dns_blocklist_ref.clone(),
                l7_svc: Arc::clone(&l7_svc),
                ddos_svc: Arc::clone(&ddos_svc),
                dlp_svc: Arc::clone(&dlp_svc),
                dlp_scope_svc: dlp_scope_svc.clone(),
                conntrack_svc: Arc::clone(&conntrack_svc),
                nat_svc: Arc::clone(&nat_svc),
                lb_svc: Arc::clone(&lb_svc),
                qos_svc: Arc::clone(&qos_svc),
                zone_svc: Arc::clone(&zone_svc),
                alias_svc: Arc::clone(&alias_svc),
                alias_resolver: Arc::clone(&alias_resolver),
                routing_svc: Arc::clone(&routing_svc),
                schedule_svc: Arc::clone(&schedule_svc),
                audit_svc: Arc::clone(&audit_svc),
                dns_cache_svc: dns_cache_svc_concrete.clone(),
                process_signal_svc: process_signal_svc.clone(),
                quarantine_svc: quarantine_svc.clone(),
                metrics: Arc::clone(&metrics),
                ebpf_loaded: Arc::clone(&ebpf_loaded),
            }),
            ebpf_dir.clone(),
        );
        // Every program with a lifecycle is handed over with its loader, so a
        // reload can detach it and move the XDP root. tc-qos has none: it is
        // loaded here or not at all, and its loader stays in `ebpf_state`.
        for (name, loader, cancel) in managed {
            mgr.register_program(name, loader, cancel);
        }
        // The kernel metrics loop reads the manager's list, so a program
        // enabled by a reload is counted and one disabled stops being read.
        mgr.metrics_readers = Arc::new(RwLock::new(metrics_readers));
        // The status endpoint reads the same map the manager updates, so a
        // program a reload loads or unloads is reported as it now is.
        mgr.program_status = Arc::clone(&ebpf_program_status);
        // A firewall a reload loads needs both to put back what the startup
        // load wired: country blocks resolve through aliases, and the VIP
        // announcer is reached through the firewall's ARP path.
        mgr.vip_svc = Some(Arc::clone(&vip_svc));
        // The firewall's shared maps are pinned: a firewall a reload loads
        // again reuses them, so the managers handed over here stay valid.
        mgr.lpm_coordinator = fw_lpm_coordinator;
        mgr.ipset_wired = fw_ipset_wired;
        // The cgroup links come across with the loader that owns the
        // programs, so a reload that turns attribution off detaches them.
        mgr.attribution = attribution_attacher;
        // The workload firewall's links travel the same way, so they outlive
        // start-up and a reload that unloads the object takes them with it.
        mgr.workload_firewall = workload_firewall_attacher;
        // A reload that loads the hooks again hands the new tables to the
        // same resolver, and one that unloads them takes the old tables away
        // from every reader in the same instant.
        mgr.workloads = workloads.clone();
        // Same for the tracepoint links, with the channel the reader a
        // reload spawns writes into: the table itself keeps draining it
        // across a program that goes away and comes back.
        mgr.process_tracing = process_attacher;
        mgr.process_events = Some(process_tx.clone());
        // Move map holder fields into the manager
        mgr.config_flags = ebpf_map_holder.config_flags;
        mgr.l7_ports = ebpf_map_holder.l7_ports;
        if let Some(ig) = ebpf_map_holder.iface_groups {
            mgr.iface_groups = ig;
        }
        Arc::new(tokio::sync::Mutex::new(mgr))
    };

    // The screen and the command answering "what may this workload reach"
    // read the policy in force rather than the document, because a rule the
    // kernel refused to take is a rule that answers nothing.
    if let Some(replay) = netpol_replay {
        app_state.install_netpol_replay(replay);
    }
    if let Some(ref workload) = workload_policy_service {
        app_state.install_workload_policy_service(Arc::clone(workload));
    }

    // The workload policy goes through the same reload path as every other
    // rule set, and only where the hooks are there to carry it out: a reload
    // on a host that refused the attach has nothing to write to, and the
    // reload path refuses a file that would need it.
    if let Some(ref workload) = workload_policy_service {
        reload_service.set_workload_service(Arc::clone(workload));
    }
    let reload_service = Arc::new(reload_service);

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
        let resolver_proc = coverage_proc.clone();
        let proc_resolver = Arc::new(adapters::container::ProcContainerResolver::new(
            &resolver_proc,
        )) as Arc<dyn domain::container::engine::CgroupReader>;
        let id_resolver = Arc::new(adapters::container::CgroupfsResolver::new(
            &config.container.resolver.cgroup_root,
        )) as Arc<dyn domain::container::engine::CgroupIdResolver>;
        let engine = domain::container::engine::ContainerResolverEngine::new(
            proc_resolver,
            config.container.resolver.cache_size,
        )
        .with_id_resolver(id_resolver);
        info!(
            cache_size = config.container.resolver.cache_size,
            proc_path = %resolver_proc.display(),
            cgroup_root = %config.container.resolver.cgroup_root,
            "Container resolver initialized"
        );
        Some(Arc::new(engine))
    } else {
        info!("Container resolver disabled via config");
        None
    };

    // ── 10e. Build Docker metadata enricher (optional) ──────────────
    let mut docker_state = EnricherState::OffByConfiguration;
    let docker_enricher: Option<
        Arc<dyn ports::secondary::metadata_enricher_port::MetadataEnricher>,
    > = if config.container.docker.enabled {
        let socket_path = std::path::Path::new(&config.container.docker.socket);
        if socket_path.exists() {
            let client = adapters::container::DockerClient::new(
                &config.container.docker.socket,
                config.container.docker.timeout_ms,
            );
            let cache = Arc::new(adapters::container::DockerCache::new(
                config.container.docker.cache_size,
                Duration::from_secs(config.container.docker.cache_ttl_seconds),
            ));
            // The watcher writes the same cache the enricher reads, so a
            // container is named on the first packet of its life rather than
            // on the first inspect. It lives as long as the agent does.
            let labels = if config.container.docker.label_policy {
                workload_policy_service
                    .as_ref()
                    .map(follow_container_labels)
            } else {
                None
            };
            let _watcher = adapters::container::DockerEventWatcher::spawn_with_labels(
                &config.container.docker.socket,
                Arc::clone(&cache),
                labels,
            );
            let enricher = adapters::container::DockerEnricher::new(client, cache);
            info!(
                socket = %config.container.docker.socket,
                cache_size = config.container.docker.cache_size,
                cache_ttl_seconds = config.container.docker.cache_ttl_seconds,
                "Docker metadata enricher initialized, reading the Docker event stream"
            );
            docker_state = EnricherState::On;
            Some(Arc::new(enricher) as _)
        } else {
            // Said once, at startup, rather than discovered later from alerts
            // that carry no container name.
            warn!(
                socket = %config.container.docker.socket,
                "Docker container enrichment is off: the socket is not there. \
                 Alerts keep their container id and lose the container name, \
                 image and labels. Mount the socket read-only, or set \
                 container.docker.enabled to false to stop asking for it"
            );
            if config.container.docker.label_policy {
                warn!(
                    socket = %config.container.docker.socket,
                    "container.docker.label_policy is on and no container label is read: \
                     the socket is not there"
                );
            }
            docker_state = EnricherState::OffNoSocket;
            None
        }
    } else {
        info!(
            "Docker container enrichment is off by configuration: alerts keep \
             their container id and lose the container name, image and labels"
        );
        None
    };

    // ── 10f. Build Kubernetes enricher (optional, auto-detected) ────
    #[cfg(feature = "kubernetes")]
    let mut kubernetes_state = EnricherState::OffByConfiguration;
    // Moves each time a pod or a namespace the enricher answers from
    // changes, so the process table can resolve its running containers again.
    #[cfg(feature = "kubernetes")]
    let mut kubernetes_changes: Option<tokio::sync::watch::Receiver<u64>> = None;
    #[cfg(feature = "kubernetes")]
    let kubernetes_enricher: Option<
        Arc<dyn ports::secondary::metadata_enricher_port::MetadataEnricher>,
    > = if config.container.kubernetes.enabled {
        if !adapters::container::is_running_in_kubernetes() {
            info!("kubernetes.enabled=true but no KUBERNETES_SERVICE_HOST - enricher disabled");
            kubernetes_state = EnricherState::OffNotInCluster;
            None
        } else if let Some(client) = adapters::container::try_build_client().await {
            let cache = Arc::new(adapters::container::PodCache::new());
            kubernetes_changes = Some(cache.changes());
            let enricher = adapters::container::KubernetesEnricher::with_cache(Arc::clone(&cache));
            let metrics_handle = enricher.metrics();
            let node_name = if config.container.kubernetes.node_name.is_empty() {
                adapters::container::resolve_node_name()
            } else {
                config.container.kubernetes.node_name.clone()
            };
            // The watcher takes the selector the API server understands: the
            // configured `k=v` pairs joined by commas, empty for every pod.
            let label_selector = config.container.kubernetes.label_filter.join(",");
            let _namespaces = adapters::container::spawn_namespace_watcher(
                client.clone(),
                Arc::clone(&cache),
                Arc::clone(&metrics_handle),
            );
            let _watcher = adapters::container::spawn_pod_watcher(
                client,
                node_name.clone(),
                label_selector.clone(),
                cache,
                metrics_handle,
            );
            info!(
                node = %node_name,
                labels = %label_selector,
                "Kubernetes metadata enricher initialized"
            );
            kubernetes_state = EnricherState::On;
            Some(Arc::new(enricher) as _)
        } else {
            warn!("kubernetes enricher failed to build kube client - disabled");
            kubernetes_state = EnricherState::OffUnavailable;
            None
        }
    } else {
        None
    };
    #[cfg(not(feature = "kubernetes"))]
    let kubernetes_state = EnricherState::OffNotBuilt;
    #[cfg(not(feature = "kubernetes"))]
    let kubernetes_changes: Option<tokio::sync::watch::Receiver<u64>> = None;
    #[cfg(not(feature = "kubernetes"))]
    let kubernetes_enricher: Option<
        Arc<dyn ports::secondary::metadata_enricher_port::MetadataEnricher>,
    > = None;

    // A workload rule naming pods, namespaces or a service account is
    // decided against what the Kubernetes enricher read. Without it the rule
    // loads and matches nothing, which is the safe failure for an allow and a
    // silent one for a deny, so the reason is said once, here.
    if !matches!(kubernetes_state, EnricherState::On) {
        let naming: Vec<&str> = config
            .firewall
            .rules
            .iter()
            .filter(|rule| {
                rule.workload.as_ref().is_some_and(|workload| {
                    workload.pods.is_some()
                        || workload.namespaces.is_some()
                        || workload.service_account.is_some()
                })
            })
            .map(|rule| rule.id.as_str())
            .collect();
        if !naming.is_empty() {
            warn!(
                rules = %naming.join(","),
                enricher = ?kubernetes_state,
                "workload rules name pods, namespaces or service accounts and the Kubernetes \
                 enricher is not running on this node: they match no task until it is"
            );
        }
    }

    // What the deployment matrix claims about this node, answered by the node.
    container_coverage.store(Arc::new(ContainerCoverage {
        proc_root: coverage_proc.display().to_string(),
        host_proc: coverage_proc != std::path::Path::new("/proc"),
        resolver: container_resolver.is_some(),
        docker: docker_state,
        kubernetes: kubernetes_state,
    }));

    // ── 10f-bis. The process table ──────────────────────────────────
    //
    // Built here rather than beside the tracepoints, because what a process
    // is includes the container it runs in, and the resolver and enrichers
    // that answer that have only just been decided. The events the reader
    // produced in between waited in the channel.
    // Kept for the learning collector, which names a pid the same way.
    let mut process_table_for_learning: Option<
        Arc<application::process_table_service::ProcessTableService>,
    > = None;
    if config.process_table.enabled {
        let mut svc = application::process_table_service::ProcessTableService::new(
            config.process_table.capacity,
            config.process_table.capture_command_line,
        )
        .with_executables(Arc::new(adapters::container::ProcExecutableResolver::new(
            &coverage_proc,
        )))
        .with_details(Arc::new(adapters::container::ProcDetailsResolver::new(
            &coverage_proc,
        )));
        if let Some(ref resolver) = container_resolver {
            svc = svc.with_containers(Arc::clone(resolver));
        }
        if let Some(ref enricher) = docker_enricher {
            svc = svc.with_metadata_enricher(Arc::clone(enricher));
        }
        if let Some(ref enricher) = kubernetes_enricher {
            svc = svc.with_metadata_enricher(Arc::clone(enricher));
        }
        // A pod is labelled, relabelled and its namespace changed while its
        // processes run, and a selector naming labels must follow it.
        if let Some(changes) = kubernetes_changes {
            svc = svc.with_metadata_changes(changes);
        }
        // The table is where an exec is learned of, so it is where the
        // kernel's idea of which workload a task is gets written.
        if let Some(ref workload) = workload_policy_service {
            svc = svc.with_workload_policy(Arc::clone(workload));
        }
        svc = svc.with_ids_workload_scope(Arc::clone(&ids_workload_scope));
        // Only when a rule names an executable: an exec event carries the
        // binary and nothing else the scope needs, so a scope with no such
        // rule has no reason to hear about every exec on the node.
        if let Some(ref scope) = dlp_scope_svc
            && scope.needs_executables()
        {
            svc = svc.with_dlp_scope(Arc::clone(scope));
        }
        let svc = Arc::new(svc);
        // And the other way for a reload: a new policy renumbers the bits,
        // so it is replayed over the tasks already running rather than
        // waiting for each of them to exec again.
        if let Some(ref workload) = workload_policy_service {
            workload.watch_processes(&svc);
        }
        app_state.install_process_table_service(Arc::clone(&svc));
        // The table is what turns a pid into a path, a container and a pod,
        // so the resolver gains the second half here.
        workloads.install_processes(Arc::clone(&svc));
        process_table_for_learning = Some(Arc::clone(&svc));
        let table_cancel = cancel_token.clone();
        tokio::spawn(async move {
            svc.run(process_rx, table_cancel).await;
        });
        info!(
            capacity = config.process_table.capacity,
            command_line = config.process_table.capture_command_line,
            "process table running"
        );
    } else {
        // Nothing writes into the channel when the table is off, and the
        // receiver going out of scope here is what makes that explicit.
        drop(process_rx);
    }

    // ── 10f-quater. The DLP scope refresh ───────────────────────────
    //
    // Here rather than beside the load, because a selector naming a pod or a
    // container is only decidable once the resolver and the enrichers that
    // answer those questions exist, and they have only just been decided.
    // Until this runs the probes read the configured cgroups alone.
    if let Some(ref scope) = dlp_scope_svc {
        let mut scanner =
            adapters::container::CgroupWorkloadScanner::new(&config.container.resolver.cgroup_root);
        if let Some(ref enricher) = docker_enricher {
            scanner = scanner.with_enricher(Arc::clone(enricher));
        }
        if let Some(ref enricher) = kubernetes_enricher {
            scanner = scanner.with_enricher(Arc::clone(enricher));
        }
        scope.set_source(Arc::new(scanner));
        // The route reports what the resolver decided, so it is handed over
        // here and not at the load: before the source exists the answer would
        // be the configured cgroups presented as the whole scope.
        app_state.install_dlp_scope_service(Arc::clone(scope));
        let scope_cancel = cancel_token.clone();
        let refresh = Duration::from_secs(config.dlp.scope.refresh_seconds);
        let scope_task = Arc::clone(scope);
        tokio::spawn(async move {
            scope_task.watch(refresh, scope_cancel).await;
        });
    }

    // ── 10f-ter. Learning mode ──────────────────────────────────────
    //
    // Built after the process table because an edge is only worth writing
    // down once a pid can be turned into a workload, and before the
    // dispatcher because a window taken back from disk must be open again
    // before the first sample runs. Nothing is observed until an operator
    // opens a window, so the collector is spawned whether or not one is.
    if config.learning.enabled {
        let mut svc = application::learning_service::LearningAppService::new(
            config.learning.max_edges,
            Arc::clone(&metrics) as Arc<dyn MetricsPort>,
        );
        // Graceful degradation, the way every other store here degrades: a
        // window that cannot be written down is a window that does not
        // survive a restart, which the progress report states as a gap
        // rather than hiding.
        if !config.learning.storage_path.is_empty() {
            let learning_path = Path::new(&config.learning.storage_path);
            match adapters::storage::redb_learning_store::RedbLearningStore::open(learning_path) {
                Ok(store) => {
                    svc = svc.with_store(Arc::new(store)
                        as Arc<dyn ports::secondary::learning_store_port::LearningStorePort>);
                    info!(
                        path = %config.learning.storage_path,
                        "learning store initialized (redb)"
                    );
                }
                Err(e) => warn!(
                    error = %e,
                    path = %config.learning.storage_path,
                    "learning store unavailable, a window will not survive a restart"
                ),
            }
        }
        let svc = Arc::new(svc);
        svc.restore(application::learning_service::now_ns());
        app_state.install_learning_service(Arc::clone(&svc));
        let collector = Arc::new(application::learning_collector::LearningCollector::new(
            Arc::clone(&svc),
            Arc::clone(&conntrack_svc),
            workloads.clone(),
        ));
        if let Some(ref table) = process_table_for_learning {
            collector.install_processes(Arc::clone(table));
        }
        let interval = Duration::from_secs(config.learning.sample_interval_secs);
        let learning_cancel = cancel_token.clone();
        tokio::spawn(async move {
            collector.run(interval, learning_cancel).await;
        });
        info!(
            max_edges = config.learning.max_edges,
            sample_interval_secs = config.learning.sample_interval_secs,
            "learning mode available"
        );
    }

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
    // The same procfs the container resolver walks, so an agent holding the
    // host's `/proc` names the node's binaries rather than its own.
    let dispatcher = dispatcher.with_executable_reader(Arc::new(
        adapters::container::ProcExecutableResolver::new(&coverage_proc),
    )
        as Arc<dyn ports::secondary::process_executable_port::ProcessExecutableReader>);

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
    .with_replay_buffer(Arc::clone(&alert_replay_buffer))
    .with_workload_resolver(workloads.clone());
    // The same resolver behind the connection listing, so a flow an operator
    // reads in `conntrack` and the alert raised on it name the same process.
    conntrack_svc
        .write()
        .await
        .set_workload_resolver(workloads.clone());

    // ── Flow export: IPFIX records off the conntrack readings ────────
    // The exporter reads the same broadcast the SSE stream reads, so the
    // flow a SOC sees in IPFIX and the flow an operator watches on the
    // events route are the same reading rather than two pollers of one
    // table. A host whose conntrack table cannot be read has no flow source
    // at all, and says so here rather than exporting nothing in silence.
    if config.flow_export.enabled {
        let mut sinks: Vec<Arc<dyn ports::secondary::flow_sink_port::FlowSink>> =
            adapters::flow::ipfix_sink::IpfixSink::from_config(&config.flow_export.ipfix)
                .into_iter()
                .map(|sink| sink as Arc<dyn ports::secondary::flow_sink_port::FlowSink>)
                .collect();
        // The OTLP sink carries no endpoint of its own: it exports to the
        // collector the alerting section names, so an estate that configured
        // one collector has one place where its address is written.
        if let Some(sink) = adapters::flow::otlp_sink::OtlpFlowSink::from_config(
            &config.flow_export,
            config.alerting.otlp.as_ref(),
        ) {
            sinks.push(sink as Arc<dyn ports::secondary::flow_sink_port::FlowSink>);
        }
        // Syslog and CEF share one adapter, so the host name in the header
        // and the version in the CEF one are read once here rather than by
        // each sink. A certificate file that cannot be read is a startup
        // failure naming the path: a sink that was asked for and silently
        // not built is how an estate discovers at audit time that nothing
        // was exported.
        let node_name = crate::http::agent_handler::hostname();
        for (section, format) in [
            (
                &config.flow_export.syslog,
                adapters::flow::text_sink::TextFormat::Syslog,
            ),
            (
                &config.flow_export.cef,
                adapters::flow::text_sink::TextFormat::Cef,
            ),
        ] {
            match adapters::flow::text_sink::TextSink::from_config(
                section,
                format,
                &node_name,
                env!("CARGO_PKG_VERSION"),
                config.flow_export.sampling,
                config.agent.tls.pq_mode,
            ) {
                Ok(built) => sinks.extend(
                    built
                        .into_iter()
                        .map(|sink| sink as Arc<dyn ports::secondary::flow_sink_port::FlowSink>),
                ),
                Err(error) => {
                    anyhow::bail!("flow export sink could not be built: {error}");
                }
            }
        }
        sinks.extend(
            adapters::flow::jsonl_sink::JsonLinesSink::from_config(
                &config.flow_export.json_lines,
                config.flow_export.sampling,
            )
            .into_iter()
            .map(|sink| sink as Arc<dyn ports::secondary::flow_sink_port::FlowSink>),
        );
        match conntrack_event_tx.as_ref() {
            Some(tx) if !sinks.is_empty() => {
                let settings = application::flow_export_service::FlowExportSettings {
                    limits: domain::flow::entity::FlowTableLimits {
                        capacity: config.flow_export.table_capacity,
                        active_timeout_ms: config
                            .flow_export
                            .active_timeout_secs
                            .saturating_mul(1_000),
                        idle_timeout_ms: config.flow_export.idle_timeout_secs.saturating_mul(1_000),
                        sampling: config.flow_export.sampling,
                    },
                    queue_depth: config.flow_export.queue_depth,
                    batch_size: config.flow_export.batch_size,
                    tick_interval: Duration::from_secs(config.flow_export.tick_interval_secs),
                };
                if let Some(handle) = application::flow_export_service::spawn_flow_export(
                    settings,
                    workloads.clone(),
                    sinks,
                    Arc::clone(&metrics) as Arc<dyn MetricsPort>,
                    tx.subscribe(),
                    cancel_token.clone(),
                ) {
                    app_state.flow_export.store(Some(Arc::new(handle)));
                }
            }
            Some(_) => warn!("flow export enabled with no sink configured: nothing is exported"),
            None => warn!(
                "flow export enabled but this host's conntrack table is unreadable: no flow source"
            ),
        }
    }
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
        alert_pipeline =
            alert_pipeline.with_auto_response(policies, Arc::clone(&ips_svc), Arc::clone(&rl_svc));
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

        // Spawn capture receiver - bridges application → adapters layer.
        let cap_engine_clone = Arc::clone(&capture_engine);
        #[cfg(feature = "pcap-capture")]
        let cap_pcap_pool = pcap_pool.clone();
        tokio::spawn(async move {
            while let Some(req) = capture_rx.recv().await {
                let s = req.session;
                #[cfg(feature = "pcap-capture")]
                {
                    if let Some(ref pool) = cap_pcap_pool {
                        let engine = Arc::clone(&cap_engine_clone);
                        tokio::spawn(crate::http::capture_handler::run_pcap_capture(
                            Arc::clone(pool),
                            s,
                            req.stop,
                            engine,
                        ));
                    } else {
                        tracing::warn!(
                            capture_id = %s.id,
                            "auto-capture: no AF_PACKET socket provisioned by the launcher"
                        );
                        cap_engine_clone.write().await.fail(&s.id);
                    }
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
        info!("GeoIP wired to DDoS, IPS, IDS, L7, ThreatIntel, RateLimit");
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
    // A route with no collector block is refused by configuration validation
    // rather than dropped here, so what reaches this point either exports or
    // is not asked to.
    if has_otlp_routes && let Some(ref otlp_cfg) = config.alerting.otlp {
        let otlp_sender = adapters::alert::otlp_sender::OtlpAlertSender::new(
            otlp_cfg,
            Arc::clone(&metrics) as Arc<dyn MetricsPort>,
        )?;
        alert_pipeline = alert_pipeline.with_otlp_sender(Arc::new(otlp_sender));
        info!(
            endpoint = %otlp_cfg.endpoint,
            protocol = %otlp_cfg.protocol,
            "OTLP alert sender initialized"
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
        let cycle_flag = Arc::clone(&feed_refresh_in_flight);
        Some(tokio::spawn(async move {
            // Initial fetch at startup.
            {
                let _running = FeedCycleGuard::claim(&cycle_flag);
                run_ti_feed_cycle(
                    &feed_ti_svc,
                    &fetcher,
                    &feed_metrics,
                    feed_dns_blocklist.as_ref(),
                    "initial",
                )
                .await;
            }

            let mut interval = tokio::time::interval(Duration::from_secs(refresh_secs));
            interval.tick().await; // skip the first immediate tick (already fetched above)
            loop {
                tokio::select! {
                    () = feed_cancel.cancelled() => break,
                    _ = interval.tick() => {
                        let _running = FeedCycleGuard::claim(&cycle_flag);
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
                            // The route already claimed the slot before queueing
                            // this message; claiming again keeps the flag raised
                            // for the whole cycle and releases it on the way out.
                            let _running = FeedCycleGuard::claim(&cycle_flag);
                            run_ti_feed_cycle(
                                &feed_ti_svc,
                                &fetcher,
                                &feed_metrics,
                                feed_dns_blocklist.as_ref(),
                                "manual",
                            )
                            .await;
                        }
                        // All refresh senders dropped - happens only at shutdown.
                        None => break,
                    },
                }
            }
        }))
    } else {
        None
    };

    // ── 11c¼. Spawn DNS blocklist feed fetcher (periodic) ─────────────
    let _dns_feed_handle = match dns_blocklist_ref.clone() {
        Some(dns_bl) if !config.dns.blocklist.feeds.is_empty() => {
            let specs = dns_feed_specs(&config.dns.blocklist.feeds);
            // Every feed shares one timer, ticking at the shortest interval any
            // of them asked for, so no feed is refreshed later than configured.
            let refresh_secs = config
                .dns
                .blocklist
                .feeds
                .iter()
                .map(|f| f.refresh_interval_secs)
                .min()
                .unwrap_or(3600)
                .max(60);
            let fetcher = adapters::threatintel::HttpFeedFetcher::default();
            let feed_cancel = cancel_token.clone();
            info!(
                refresh_interval_secs = refresh_secs,
                feed_count = specs.len(),
                "DNS blocklist feed fetcher starting"
            );
            Some(tokio::spawn(async move {
                application::dns_feed_update::refresh_dns_blocklist_feeds(
                    &specs, &fetcher, &dns_bl,
                )
                .await;

                let mut interval = tokio::time::interval(Duration::from_secs(refresh_secs));
                interval.tick().await; // the first tick is immediate, already done above
                loop {
                    tokio::select! {
                        () = feed_cancel.cancelled() => break,
                        _ = interval.tick() => {
                            application::dns_feed_update::refresh_dns_blocklist_feeds(
                                &specs, &fetcher, &dns_bl,
                            )
                            .await;
                        }
                    }
                }
            }))
        }
        _ => None,
    };

    // ── 11c½. Spawn eBPF kernel metrics reader (periodic, every 10s) ──
    // Wherever eBPF can load at all, even with nothing loaded yet: a reload
    // may enable a program, and its readers join the list this loop reads.
    if ebpf_capable {
        let shared_readers = ebpf_manager.lock().await.shared_metrics_readers();
        {
            let current = shared_readers.read().await;
            info!(
                reader_count = current.len(),
                maps = ?current.iter().map(MetricsReader::map_name).collect::<Vec<_>>(),
                "eBPF kernel metrics reader starting"
            );
        }
        let kr_cancel = cancel_token.clone();
        let kr_metrics = Arc::clone(&metrics) as Arc<dyn MetricsPort>;
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

    // ── 11c¾. Spawn datapath state reader (periodic, every 30s) ──────
    // What the kernel granted, rather than what the configuration asked for:
    // programs that loaded and were refused an attachment, and the XDP mode
    // each interface ended up in. Only where eBPF is in play at all, because on
    // a build running without it every answer would be "nothing attached",
    // which is configuration rather than a measurement.
    if ebpf_loaded.load(Ordering::Relaxed) {
        let ds_cancel = cancel_token.clone();
        let ds_metrics = Arc::clone(&metrics) as Arc<dyn MetricsPort>;
        let ds_interfaces = config.agent.interfaces.clone();
        info!(
            interfaces = ?ds_interfaces,
            "datapath state reader starting (30s interval)"
        );
        tokio::spawn(async move {
            crate::ebpf_metrics::run_datapath_state_loop(
                ds_interfaces,
                ds_metrics,
                Duration::from_secs(30),
                ds_cancel,
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

    // ── 11d½. Put back what was in force before the restart ─────────
    //
    // Here rather than where the store is opened, because a block is only in
    // force once the firewall's LPM tries exist and a throttle only once the
    // rate limiter holds its map: restored earlier, both would be in a
    // service's memory and in no kernel map.
    if let Some(ref store) = mitigation_store {
        crate::mitigation_restore::restore_mitigations(
            store,
            &ips_svc,
            &rl_svc,
            &response_engine,
            &audit_svc,
            std::time::SystemTime::now(),
        )
        .await;
    }

    // ── 11d¾. Feed the service watchdog, if there is one ─────────────
    //
    // After the readers are spawned, so the first ping is sent against a
    // datapath that is already passing. Nothing is spawned when the
    // environment carries no NOTIFY_SOCKET, which is every deployment but a
    // systemd unit with WatchdogSec.
    if let Some(watchdog) = crate::watchdog::Watchdog::from_env() {
        let watchdog_cancel = cancel_token.clone();
        tokio::spawn(async move { watchdog.run(watchdog_cancel).await });
    }

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
            let fw_svc_clone = Arc::clone(&firewall_svc);
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
                    // A refresh can give an alias its first content, and with
                    // it the IP set the firewall rules naming it match against.
                    let bindings = application::firewall_aliases::collect_bindings(
                        &*alias_svc_clone.read().await,
                    );
                    fw_svc_clone.write().await.set_alias_bindings(bindings);
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

    // ── 12. Ready - wait for cancellation ───────────────────────────
    info!("agent ready, waiting for shutdown signal");
    cancel_token.cancelled().await;

    // ── 13. Ordered shutdown sequence ───────────────────────────────
    info!("shutdown phase 1: cancelling tasks");
    // Token is already cancelled - all tasks received the signal.

    info!("shutdown phase 2: draining HTTP and gRPC connections");
    let _ = tokio::time::timeout(GRACEFUL_SHUTDOWN_TIMEOUT, http_handle).await;
    let _ = tokio::time::timeout(GRACEFUL_SHUTDOWN_TIMEOUT, metrics_handle).await;
    let _ = tokio::time::timeout(GRACEFUL_SHUTDOWN_TIMEOUT, grpc_handle).await;

    info!("shutdown phase 3: stopping config watcher");
    let _ = tokio::time::timeout(Duration::from_secs(1), reload_handle).await;

    // A capture reads packets on a socket of its own and owes nothing to the
    // eBPF programs, but it is stopped before they are detached because the
    // operator reading the file afterwards will compare it against the alerts
    // the datapath raised, and a capture that outlived the datapath records a
    // window nothing was watching.
    let interrupted = capture_engine.write().await.interrupt_running();
    if !interrupted.is_empty() {
        info!(
            captures = ?interrupted,
            "shutdown phase 4: stopping packet captures"
        );
        let deadline = tokio::time::Instant::now() + CAPTURE_STOP_TIMEOUT;
        loop {
            if capture_engine.read().await.unfinished().is_empty() {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                warn!(
                    captures = ?capture_engine.read().await.unfinished(),
                    timeout_secs = CAPTURE_STOP_TIMEOUT.as_secs(),
                    "these captures had not closed their file when the window closed"
                );
                break;
            }
            tokio::time::sleep(adapters::net::pcap_capture::POLL_INTERVAL).await;
        }
    }

    info!("shutdown phase 5: detaching eBPF programs");
    if let Some(mut attacher) = signal_attacher.take() {
        // Taken down first: once the link is gone no armed target can be
        // signalled, whatever is still in the map on the way out.
        attacher.detach();
    }
    ebpf_manager.lock().await.detach_all().await;
    drop(ebpf_state); // Drop startup loaders (detaches legacy programs)

    info!("shutdown phase 6: draining events and alerts");
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
    /// Cancels every task this generation spawned: ring-buffer readers and
    /// the DLP uprobe watcher.
    ///
    /// Those tasks own map handles taken out of the loaders, so dropping the
    /// loaders alone does not close the descriptors - the reader keeps polling
    /// a ring buffer whose programs are gone. In a long-lived process that
    /// re-attaches (HA promotion, config reload), each generation would leave
    /// its readers behind and the map descriptors would pile up for the
    /// lifetime of the agent.
    pub readers: CancellationToken,
}

impl Default for EbpfState {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for EbpfState {
    fn drop(&mut self) {
        // Readers first: they hold map handles this generation handed them, and
        // a still-running reader keeps those descriptors open past the detach.
        self.readers.cancel();
        // Loaders are dropped next (aya detaches programs via link FDs).
        // Then clean up any pinned maps left on the BPF filesystem.
        self.loaders.clear();
        EbpfLoader::cleanup_pin_path_because(
            adapters::ebpf::DEFAULT_BPF_PIN_PATH,
            "eBPF state dropped",
        );
    }
}

impl EbpfState {
    pub fn new() -> Self {
        Self {
            loaders: Vec::new(),
            bpf_handle: None,
            readers: CancellationToken::new(),
        }
    }

    pub fn add_loader(&mut self, loader: EbpfLoader) {
        self.loaders.push(loader);
    }

    pub fn attach_bpf_handle(&mut self, handle: adapters::ebpf::BpfLoadingHandle) {
        self.bpf_handle = Some(handle);
    }
}

/// Validate a health-check probe target before passing it to `ping`.
///
/// The target is config/API-sourced and lands in a `Command` argument
/// array (no shell), so the only risk is argument injection - a value
/// beginning with `-` being parsed as a `ping` flag. We pair `--` at the
/// call site with this allow-list (valid IPv4/IPv6/hostname characters,
/// never leading `-`) for defense in depth.
/// Whether a name is one the kernel could carry on an interface.
///
/// The health probe binds to it, so an empty or malformed name leaves the
/// probe unbound rather than failing every gateway that carries one.
fn is_safe_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() < 16
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'@'))
}

fn is_safe_probe_target(target: &str) -> bool {
    if target.is_empty() || target.len() > 253 || target.starts_with('-') {
        return false;
    }
    target
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'))
}

/// Verify the kernel version is **>= 6.9**.
///
/// The 6.9 floor is mandatory - there is **no graceful fallback on
/// older kernels**. The agent relies on the following kernel features
/// across every eBPF program:
///
/// - `BPF_TOKEN_CREATE` + `BPF_F_TOKEN_FD` (6.9) - container-aware
///   least-privilege loading
/// - `bpf_task_get_cgroup1` kfunc (6.8) - cgroup1 inode enrichment
/// - `bpf_xdp_metadata_rx_vlan_tag` / `bpf_xdp_get_xfrm_state` /
///   `bpf_iter_css_task` kfuncs (6.7 / 6.8)
/// - netfilter conntrack lookup / alloc / NAT delegation kfuncs
///   (5.18 / 6.0 / 6.1) consumed via `ebpf_helpers::kfuncs`
/// - dynptr skb / xdp slice helpers (6.4 / 6.5)
///
/// A kernel that fails this check **cannot** run the agent in a
/// degraded mode - the eBPF verifier rejects every program at load
/// time because the kfuncs are not present in `vmlinux` BTF. The
/// correct response is to upgrade the kernel. `BPF_TOKEN_CREATE` -
/// the agent's only eBPF loading path - also requires 6.9+.
fn check_kernel_version() -> anyhow::Result<()> {
    check_kernel_version_from(std::path::Path::new("/proc/sys/kernel/osrelease"))
}

fn check_kernel_version_from(path: &std::path::Path) -> anyhow::Result<()> {
    use adapters::ebpf::{MIN_KERNEL_MAJOR, MIN_KERNEL_MINOR, probe_kernel_features_from};

    // The version floor + parsing live in `adapters::ebpf::kernel_probe`,
    // the single source of truth. BTF presence is irrelevant to the gate,
    // so a missing `/sys/kernel/btf/vmlinux` is non-fatal here - only the
    // version comparison decides pass/fail.
    probe_kernel_features_from(path, std::path::Path::new("/sys/kernel/btf/vmlinux")).map_err(
        |e| {
            anyhow::anyhow!(
                "kernel is below the mandatory minimum {MIN_KERNEL_MAJOR}.{MIN_KERNEL_MINOR} \
                 ({e}) - eBPFsentinel refuses to start. Required features: BPF token \
                 delegation, cgroup1 kfunc, XDP metadata kfuncs, netfilter conntrack kfuncs, \
                 dynptr helpers. No fallback path exists - upgrade the host kernel to 6.9+ \
                 and restart the agent."
            )
        },
    )?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod ebpf_state_tests {
    use super::*;

    /// The ring-buffer readers and the DLP watcher own map handles taken out of
    /// the loaders, so detaching without stopping them leaves the descriptors
    /// open. A process that re-attaches - HA promotion, config reload - would
    /// then accumulate one set of map fds per generation.
    #[test]
    fn dropping_the_state_stops_the_tasks_it_spawned() {
        let state = EbpfState::new();
        let readers = state.readers.clone();

        assert!(!readers.is_cancelled());
        drop(state);
        assert!(readers.is_cancelled());
    }
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

    #[test]
    fn probe_target_accepts_ip_and_hostname() {
        assert!(is_safe_probe_target("8.8.8.8"));
        assert!(is_safe_probe_target("2001:db8::1"));
        assert!(is_safe_probe_target("gw.internal.example.com"));
        assert!(is_safe_probe_target("router-1"));
    }

    #[test]
    fn probe_target_rejects_option_injection() {
        // A leading '-' would be parsed by ping as a flag.
        assert!(!is_safe_probe_target("-O"));
        assert!(!is_safe_probe_target("--flood"));
    }

    #[test]
    fn probe_target_rejects_shell_and_empty() {
        assert!(!is_safe_probe_target(""));
        assert!(!is_safe_probe_target("8.8.8.8; rm -rf /"));
        assert!(!is_safe_probe_target("$(whoami)"));
        assert!(!is_safe_probe_target("a b"));
        assert!(!is_safe_probe_target(&"a".repeat(254)));
    }

    #[test]
    fn probe_binds_to_a_real_interface_name_only() {
        assert!(is_safe_interface_name("eth0"));
        assert!(is_safe_interface_name("wan-1"));
        assert!(is_safe_interface_name("eth0.100"));
        assert!(is_safe_interface_name("br_lan"));
        // An empty name is the API default, meaning the agent's own path.
        assert!(!is_safe_interface_name(""));
        // Longer than IFNAMSIZ, so no interface could carry it.
        assert!(!is_safe_interface_name("aaaaaaaaaaaaaaaa"));
        assert!(!is_safe_interface_name("eth0; rm -rf /"));
        assert!(!is_safe_interface_name("eth 0"));
    }
}

/// Resolve the directory containing compiled eBPF program binaries.
///
/// Precedence: `EBPF_PROGRAM_DIR` env var > `agent.ebpf_program_dir` config
/// > the installed directories, in the order [`installed_program_dir`] states
/// > dev fallback (`target/bpfel-unknown-none/release`).
pub fn resolve_ebpf_program_dir(config: &AgentConfig) -> String {
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
    // 3. Whichever install form put the objects on this host, dev path last
    installed_program_dir(&|dir| Path::new(dir).is_dir()).to_string()
}

/// Pick the first installed object directory that exists on this host.
///
/// Two install forms put the objects in two places, and a host can carry
/// both: the tarball's `install.sh` writes `/usr/local/lib/ebpfsentinel`,
/// while a `.deb` or an `.rpm` may not write under `/usr/local` at all and
/// uses `/usr/lib/ebpfsentinel`. The tarball comes first because it is the
/// one an administrator put there by hand, so a manual install placed beside
/// a package is the one that wins rather than the one silently ignored.
fn installed_program_dir(exists: &dyn Fn(&str) -> bool) -> &'static str {
    use infrastructure::constants::{
        DEFAULT_EBPF_PROGRAM_DIR, DEFAULT_EBPF_PROGRAM_DIR_DEV, DEFAULT_EBPF_PROGRAM_DIR_PACKAGE,
    };

    [DEFAULT_EBPF_PROGRAM_DIR, DEFAULT_EBPF_PROGRAM_DIR_PACKAGE]
        .into_iter()
        .find(|dir| exists(dir))
        .unwrap_or(DEFAULT_EBPF_PROGRAM_DIR_DEV)
}

#[cfg(test)]
mod program_dir_tests {
    use super::installed_program_dir;
    use infrastructure::constants::{
        DEFAULT_EBPF_PROGRAM_DIR, DEFAULT_EBPF_PROGRAM_DIR_DEV, DEFAULT_EBPF_PROGRAM_DIR_PACKAGE,
    };

    #[test]
    fn a_manual_install_is_preferred_to_a_package() {
        let both = |_: &str| true;

        assert_eq!(installed_program_dir(&both), DEFAULT_EBPF_PROGRAM_DIR);
    }

    #[test]
    fn a_package_only_host_finds_the_objects_the_package_installed() {
        let package_only = |dir: &str| dir == DEFAULT_EBPF_PROGRAM_DIR_PACKAGE;

        assert_eq!(
            installed_program_dir(&package_only),
            DEFAULT_EBPF_PROGRAM_DIR_PACKAGE
        );
    }

    #[test]
    fn a_working_tree_with_no_install_falls_back_to_the_build_output() {
        let nothing_installed = |_: &str| false;

        assert_eq!(
            installed_program_dir(&nothing_installed),
            DEFAULT_EBPF_PROGRAM_DIR_DEV
        );
    }
}

/// Read a single eBPF program binary from the program directory.
///
/// The helper gate sits here because every loader funnels through this one
/// function with the object's name, so a single check covers all of them.
pub fn read_ebpf_program(dir: &str, name: &str) -> anyhow::Result<Vec<u8>> {
    check_required_helpers(name)?;
    let path = Path::new(dir).join(name);
    std::fs::read(&path)
        .map_err(|e| anyhow::anyhow!("failed to read eBPF program '{}': {e}", path.display()))
}

/// Refuse an object whose kernel-side helpers the probe reported missing.
///
/// Silent when the probe never ran. `NotProbed` means "unknown", and turning
/// an unknown into a refusal would keep the agent off kernels that load every
/// program perfectly well - which is every host on the token-only path, since
/// the probe needs a capability that path does not hold.
fn check_required_helpers(name: &str) -> anyhow::Result<()> {
    let Some(report) = adapters::ebpf::cached_kernel_helpers() else {
        return Ok(());
    };
    let gaps: Vec<String> = report.gaps_for(name).map(ToString::to_string).collect();
    if gaps.is_empty() {
        return Ok(());
    }
    Err(anyhow::anyhow!(
        "{}. Loading it would be rejected by the verifier with an opaque 'invalid func' error, \
         so it is refused up front. Upgrade the host kernel, or disable the feature that needs \
         this program.",
        gaps.join("; ")
    ))
}

// ── Per-program load functions ───────────────────────────────────────

/// Load the XDP firewall program: attach XDP, populate rules, create event reader.
/// Per-zone passed/dropped counter readers. `None` when the maps are absent.
/// The zone names that label them are derived from the zone service at read
/// time, so a zone added after startup is labelled correctly.
pub type ZoneMetricsSource = (MetricsReader, MetricsReader);

/// Everything `try_load_xdp_firewall` hands back: the loader, the map
/// manager the firewall service writes through, the firewall counter reader,
/// the event reader, the zone map manager the zone service programs through,
/// and the per-zone counter readers.
pub type XdpFirewallLoad = (
    EbpfLoader,
    FirewallMapManager,
    Option<MetricsReader>,
    EventReader,
    Option<ZoneMapManager>,
    Option<ZoneMetricsSource>,
);

/// The datapath byte for the configured catch-all policy.
///
/// Read by the loader that writes it into the map and by the runtime that tells
/// the firewall service what to restore after a deny-all posture is lifted, so
/// the two cannot disagree about what "configured" means.
pub fn firewall_policy_byte(policy: infrastructure::config::DefaultPolicy) -> u8 {
    use ebpf_common::firewall::{DEFAULT_POLICY_DROP, DEFAULT_POLICY_PASS};
    use infrastructure::config::DefaultPolicy;

    match policy {
        DefaultPolicy::Drop => DEFAULT_POLICY_DROP,
        DefaultPolicy::Pass => DEFAULT_POLICY_PASS,
    }
}

/// The group bit each monitored interface carries in the kernel, for the
/// firewall service to narrow an interface-scoped rule with. It is read from
/// the same two tables the `INTERFACE_GROUPS` maps are written from, so the
/// bit a rule is installed with is the bit its interface was given.
pub fn firewall_interface_scope(config: &AgentConfig) -> InterfaceScopeBits {
    InterfaceScopeBits {
        bits: config.interface_scope_bits(),
        membership: config.kernel_interface_membership(),
    }
}

/// The anti-lockout settings `firewall.anti_lockout` configures, with the
/// agent's own REST and gRPC ports always among the ports kept open: an
/// agent moved off the default ports must not be able to lock its own API
/// out because the list was not edited to follow it.
pub fn firewall_anti_lockout(config: &AgentConfig) -> AntiLockoutSettings {
    let anti_lockout = &config.firewall.anti_lockout;
    let mut ports = anti_lockout.ports.clone();
    for port in [config.agent.http_port, config.agent.grpc_port] {
        if !ports.contains(&port) {
            ports.push(port);
        }
    }
    AntiLockoutSettings {
        enabled: anti_lockout.enabled,
        interfaces: anti_lockout.interfaces.clone(),
        ports,
    }
}

pub fn try_load_xdp_firewall(
    ebpf_dir: &str,
    config: &AgentConfig,
) -> anyhow::Result<XdpFirewallLoad> {
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

    map_manager.set_default_policy(firewall_policy_byte(config.firewall.default_policy))?;

    // The rule arrays are written by the firewall service when it is handed
    // this manager, not here: a rule is only what the kernel should see once
    // its aliases are resolved and its interface scope is turned into a group
    // bit, and writing the configured rules raw would install an alias rule
    // unrestricted and an interface-scoped rule on every interface.

    let mut zone_metrics_readers: Option<ZoneMetricsSource> = None;
    let mut zone_map_manager: Option<ZoneMapManager> = None;

    // Hand the zone maps to a manager rather than writing them here: the zone
    // service reprograms them on every reload and API change, which a
    // one-shot population at startup could not do.
    if config.zones.enabled {
        match ZoneMapManager::new(loader.ebpf_mut()) {
            Ok(mgr) => zone_map_manager = Some(mgr),
            Err(e) => warn!("zone maps unavailable, zoning will not be enforced: {e}"),
        }

        // Mirror the datapath's per-zone counters into Prometheus.
        match (
            MetricsReader::new(loader.ebpf_mut(), "ZONE_METRICS_PASSED"),
            MetricsReader::new(loader.ebpf_mut(), "ZONE_METRICS_DROPPED"),
        ) {
            (Ok(passed), Ok(dropped)) => {
                zone_metrics_readers = Some((passed, dropped));
            }
            _ => {
                tracing::debug!("zone counter maps unavailable, per-zone metrics not exported");
            }
        }
    }

    if zone_map_manager.is_none() {
        // Nothing will ever assign an interface to a zone on this run, either
        // because zoning is off or because the maps could not be taken, so the
        // datapath reaches the same verdict without reading them.
        adapters::ebpf::feature_gates::publish(adapters::ebpf::FirewallFeature::Zones, true);
    }

    let metrics_rdr = MetricsReader::new(loader.ebpf_mut(), "FIREWALL_METRICS").ok();

    let reader = EventReader::new(loader.ebpf_mut())?;

    Ok((
        loader,
        map_manager,
        metrics_rdr,
        reader,
        zone_map_manager,
        zone_metrics_readers,
    ))
}

/// Load the xdp-firewall-reject program and wire it as a tail-call target.
///
/// The reject program is loaded with the same pin path so that `PKT_CTX` and
/// `FIREWALL_METRICS` maps are shared with xdp-firewall. It is loaded but NOT
/// attached to any interface - it is invoked only via tail-call from
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
/// Shared maps: `SYNCOOKIE_CTX`, `DDOS_METRICS`.
/// Loaded but NOT attached - invoked via tail-call from xdp-ratelimit (`RL_PROG_ARRAY` slot 0).
pub fn try_load_xdp_ratelimit_syncookie(
    ebpf_dir: &str,
    rl_loader: &mut EbpfLoader,
) -> anyhow::Result<EbpfLoader> {
    let program_bytes = read_ebpf_program(ebpf_dir, "xdp-ratelimit-syncookie")?;
    // Raw load so this kfunc-free tail-call target matches the kfunc-loaded
    // (outside-aya) xdp-ratelimit owner of RL_PROG_ARRAY, exactly as the reject
    // target matches the firewall owner of XDP_PROG_ARRAY.
    let mut sc_loader = EbpfLoader::load_xdp_raw_with_pin_path(
        &program_bytes,
        adapters::ebpf::DEFAULT_BPF_PIN_PATH,
    )?;
    sc_loader.load_xdp_program("xdp_ratelimit_syncookie")?;
    let sc_fd = sc_loader.program_raw_fd("xdp_ratelimit_syncookie")?;
    rl_loader.set_tail_call_raw("RL_PROG_ARRAY", 0, sc_fd)?;
    Ok(sc_loader)
}

/// Populate the xdp-ratelimit `DDoS` config Array maps from `config`.
///
/// `check_syn_flood` / `process_icmp` / `process_conntrack` each read a
/// single-entry Array map and bail when `enabled == 0`. The maps default
/// to zeroed, so these writes are what actually arm the protections.
/// All writes are best-effort (non-fatal): a missing map or write error
/// just leaves that protection disabled.
fn arm_ddos_ebpf_configs(loader: &mut EbpfLoader, config: &AgentConfig) {
    if !config.ddos.enabled {
        return;
    }

    if config.ddos.syn_protection.enabled {
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
            Err(e) => warn!("DDOS_SYN_CONFIG map not available (non-fatal): {e}"),
        }

        // The XDP syncookie path issues kernel cookies via
        // `bpf_tcp_raw_gen_syncookie`; the kernel only completes a legitimate
        // client's handshake from the passed cookie-ACK when it always
        // validates syncookies (mode 2 - mode 1 engages only on SYN-backlog
        // overflow, which never happens because XDP absorbs the flood SYNs).
        // In the default token deployment the privileged launcher already set
        // this before the user-namespace unshare; this best-effort write only
        // succeeds in the CAP_NET_ADMIN fallback, so a failure here is expected.
        match std::fs::write("/proc/sys/net/ipv4/tcp_syncookies", "2\n") {
            Ok(()) => info!("net.ipv4.tcp_syncookies=2 set for SYN-cookie handshake completion"),
            Err(e) => {
                debug!("tcp_syncookies sysctl not writable here (set by the launcher): {e}");
            }
        }
    }

    if config.ddos.icmp_protection.enabled {
        match IcmpConfigManager::new(loader.ebpf_mut()) {
            Ok(mut mgr) => {
                let icmp_cfg = ebpf_common::ddos::IcmpConfig {
                    enabled: 1,
                    _pad: 0,
                    max_payload_size: config.ddos.icmp_protection.max_payload_size,
                    max_pps: config.ddos.icmp_protection.max_pps,
                };
                if let Err(e) = mgr.set_config(&icmp_cfg) {
                    warn!("ICMP_CONFIG write failed (ICMP protection disabled): {e}");
                }
            }
            Err(e) => warn!("ICMP_CONFIG map not available (non-fatal): {e}"),
        }
    }

    if config.ddos.connection_tracking.enabled {
        match DdosConnTrackConfigManager::new(loader.ebpf_mut()) {
            Ok(mut mgr) => {
                let ct = &config.ddos.connection_tracking;
                let ct_cfg = ebpf_common::ddos::DdosConnTrackConfig {
                    enabled: 1,
                    _pad: [0; 3],
                    half_open_threshold: ct.half_open_threshold,
                    rst_threshold: ct.rst_threshold,
                    fin_threshold: ct.fin_threshold,
                    ack_threshold: ct.ack_threshold,
                    _pad2: [0; 4],
                    // 60s entry timeout (the eBPF path does not yet expire on
                    // this value; kept sane for when it does).
                    timeout_ns: 60_000_000_000,
                };
                if let Err(e) = mgr.set_config(&ct_cfg) {
                    warn!("CONNTRACK_CONFIG write failed (CT flood protection disabled): {e}");
                }
            }
            Err(e) => warn!("CONNTRACK_CONFIG map not available (non-fatal): {e}"),
        }
    }

    if config.ddos.amplification_protection.enabled
        && !config.ddos.amplification_protection.ports.is_empty()
    {
        // IANA protocol number for UDP; the eBPF amp path is UDP-only, which
        // is why the configuration refuses any other protocol on these ports.
        const PROTO_UDP: u8 = 17;
        match AmpProtectConfigManager::new(loader.ebpf_mut()) {
            Ok(mut mgr) => {
                for p in &config.ddos.amplification_protection.ports {
                    if let Err(e) = mgr.set_port(p.port, PROTO_UDP, p.max_pps) {
                        warn!(port = p.port, "AMP_PROTECT_CONFIG write failed: {e}");
                    }
                }
            }
            Err(e) => warn!("AMP_PROTECT_CONFIG map not available (non-fatal): {e}"),
        }
    }
}

pub fn try_load_xdp_ratelimit(
    ebpf_dir: &str,
    config: &AgentConfig,
    firewall_active: bool,
) -> anyhow::Result<XdpRatelimitResult> {
    let program_bytes = read_ebpf_program(ebpf_dir, "xdp-ratelimit")?;
    // A tail-call target must match its caller's device-bound state. When the
    // firewall is active it owns XDP_PROG_ARRAY and is loaded raw (non
    // device-bound, since the non-kfunc reject/syncookie chain cannot be
    // device-bound), so a device-bound ratelimit fd is rejected with EINVAL
    // when wired into slot 0 - leaving the firewall→ratelimit hop dead and
    // every DDoS/syncookie check unreachable. Neutralize the dev-bind in the
    // chained form (mirrors `try_load_xdp_loadbalancer`); only device-bind in
    // standalone mode where ratelimit attaches to the interface directly.
    let dev_bound = if firewall_active {
        None
    } else {
        metadata_dev_bound_ifindex(config)
    };
    let mut loader = EbpfLoader::load_with_pin_path_dev_bound(
        &program_bytes,
        adapters::ebpf::DEFAULT_BPF_PIN_PATH,
        dev_bound,
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

    // SYN cookies are now issued and validated by the kernel
    // `bpf_tcp_raw_*_syncookie` helpers, so there is no userspace secret to
    // seed - the kernel keeps its own cookie key.

    // Arm the xdp-ratelimit DDoS protections gated by zeroed config maps
    // (SYN cookie, ICMP flood, conntrack flood). Without these writes the
    // eBPF reads `enabled == 0` and each protection is a silent no-op.
    arm_ddos_ebpf_configs(&mut loader, config);

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

    // Also attach tc-ids on egress so locally-originated (e.g. container
    // outbound) traffic is seen with the originating socket's cgroup available
    // via `bpf_skb_cgroup_id` - the ingress softirq path cannot recover it.
    // This is needed for container attribution, so it fires whenever the
    // container resolver is on; `inspect_egress` keeps it available even when
    // attribution is off. NOTE: an egress-attached tc-ids also enforces IDS
    // verdicts on outbound traffic, not only ingress.
    if config.ids.inspect_egress || config.container.resolver.enabled {
        for iface in &config.agent.interfaces {
            if let Err(e) = loader.attach_tc_egress("tc_ids", iface) {
                warn!("tc-ids egress attach on '{iface}' failed: {e}");
            }
        }
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

/// What loading the socket-attribution object hands back: the loader keeping
/// the programs alive, the counters, the reader over the two tables, the
/// attacher holding the links, and what can be said about the attach.
pub type LoadedAttribution = (
    EbpfLoader,
    Option<MetricsReader>,
    Option<adapters::ebpf::EbpfSocketIdentityReader>,
    adapters::ebpf::AttributionAttacher,
    adapters::ebpf::AttributionStatus,
);

/// Load the socket-attribution object and attach its hooks to the cgroup.
///
/// Returns the loader, the attacher holding the links, and what can be said
/// about the result. A kernel that refuses the attach comes back as a status
/// carrying the reason rather than as an error: the agent runs on without a
/// workload block, which is a degradation and not a failure.
pub fn try_load_cgroup_attribution(
    ebpf_dir: &str,
    config: &AgentConfig,
) -> anyhow::Result<LoadedAttribution> {
    let program_bytes = read_ebpf_program(ebpf_dir, "cgroup-attribution")?;
    // The join hook is loaded optionally: a kernel that refuses it still
    // takes the six hooks that name the socket, and the status says what the
    // refusal costs instead of the object failing whole.
    let mut loader = EbpfLoader::load_with_pin_path_optional(
        &program_bytes,
        adapters::ebpf::DEFAULT_BPF_PIN_PATH,
        &[adapters::ebpf::ATTRIBUTION_JOIN_HOOK],
    )?;
    let metrics_rdr = MetricsReader::new(loader.ebpf_mut(), "ATTRIBUTION_METRICS").ok();
    // The two tables leave the loader the way the counters do: the kernel
    // maps stay linked into the programs, so taking the userspace handles out
    // costs the hooks nothing and gives the reader something that outlives
    // the builder.
    let socket_reader = match adapters::ebpf::EbpfSocketIdentityReader::new(loader.ebpf_mut()) {
        Ok(reader) => Some(reader),
        Err(e) => {
            warn!("socket attribution tables unreadable, flows stay unattributed: {e}");
            None
        }
    };

    // Rootless posture: the agent dropped the capability the cgroup attach
    // needs, and the hierarchy it can see is not the host's, so the warden
    // resolves the path and creates the link.
    let mut attacher = adapters::ebpf::AttributionAttacher::new();
    if let Some(sock) = warden_sock_from_env() {
        attacher = attacher.with_warden_socket(sock);
    }
    let status = attacher.attach_all(&loader, &config.attribution.cgroup_root);
    Ok((loader, metrics_rdr, socket_reader, attacher, status))
}

/// Load the workload firewall and attach its eight cgroup hooks.
///
/// Returns the loader, the counters, the map manager the policy is written
/// through, the reader draining the refusals, the attacher holding the links,
/// and what can be said about the result. A kernel that refuses the attach comes back as a status carrying
/// the reason rather than as an error, because whether that is survivable is
/// the policy's business and not this function's: a policy that only observes
/// runs on, and one that refuses stops the agent at the caller.
///
/// It is loaded off the rules rather than off a configuration key, because a
/// workload rule is already the switch: a file with none loads nothing, and a
/// file with one means it.
pub fn try_load_cgroup_workload_firewall(
    ebpf_dir: &str,
    config: &AgentConfig,
) -> anyhow::Result<(
    EbpfLoader,
    Option<MetricsReader>,
    adapters::ebpf::workload_policy_map_manager::WorkloadPolicyMapManager,
    adapters::ebpf::WorkloadEventReader,
    adapters::ebpf::workload_firewall_attach::WorkloadFirewallAttacher,
    adapters::ebpf::workload_firewall_attach::WorkloadFirewallStatus,
)> {
    let program_bytes = read_ebpf_program(ebpf_dir, "cgroup-workload-firewall")?;
    let mut loader =
        EbpfLoader::load_with_pin_path(&program_bytes, adapters::ebpf::DEFAULT_BPF_PIN_PATH)?;
    let metrics_rdr = MetricsReader::new(loader.ebpf_mut(), "WORKLOAD_METRICS").ok();
    // Taken before anything attaches: a hook deciding a syscall against a
    // table userspace never got hold of would refuse on an empty policy.
    let manager = adapters::ebpf::workload_policy_map_manager::WorkloadPolicyMapManager::new(
        loader.ebpf_mut(),
    )?;
    let reader = adapters::ebpf::WorkloadEventReader::new(loader.ebpf_mut())?;

    // Same posture as the attribution hooks: rootless, the agent dropped the
    // capability the cgroup attach needs and the warden resolves the path.
    let mut attacher = adapters::ebpf::workload_firewall_attach::WorkloadFirewallAttacher::new();
    if let Some(sock) = warden_sock_from_env() {
        attacher = attacher.with_warden_socket(sock);
    }
    let status = attacher.attach_all(&loader, &config.attribution.cgroup_root);
    Ok((loader, metrics_rdr, manager, reader, attacher, status))
}

/// Forward what the Docker watcher learns of each container's labels into
/// the workload policy, and hand back the channel the watcher writes.
fn follow_container_labels(
    workload: &Arc<application::workload_policy_service::WorkloadPolicyService>,
) -> mpsc::Sender<adapters::container::LabelUpdate> {
    let (tx, mut rx) =
        mpsc::channel::<adapters::container::LabelUpdate>(CONTAINER_LABEL_CHANNEL_CAPACITY);
    let workload = Arc::clone(workload);
    tokio::spawn(async move {
        while let Some(update) = rx.recv().await {
            let outcome = match update {
                adapters::container::LabelUpdate::Seen { id, name, labels } => {
                    workload.observe_container(&id, &name, &labels)
                }
                adapters::container::LabelUpdate::Gone { id } => workload.forget_container(&id),
                adapters::container::LabelUpdate::Snapshot(containers) => {
                    workload.reconcile_containers(&containers)
                }
            };
            if let Err(e) = outcome {
                warn!("container label policy not applied: {e}");
            }
        }
    });
    info!("container label policy followed through the Docker event stream");
    tx
}

/// Why an agent told to enforce `NetworkPolicy` refuses to start.
fn network_policy_unavailable(reason: &str) -> String {
    format!(
        "container.kubernetes.network_policy.mode is enforce, and the agent cannot enforce it, so \
         it would run with every pod of this node open while the cluster believes otherwise: \
         {reason}"
    )
}

/// Start compiling the cluster's `NetworkPolicy` into the workload firewall
/// object, once its hooks are attached.
///
/// The policy is read and compiled here, on the agent, rather than handed
/// down in the configuration: the pods a policy selects change with every
/// rollout, and a document that changed with them would restart every agent
/// of the cluster each time. In enforce mode every way of not getting there
/// stops the agent; in observe mode it is said and the agent runs on.
///
/// What comes back is the replay, which reads the same cluster cache, and
/// nothing when the cluster could not be read.
#[cfg(feature = "kubernetes")]
async fn start_network_policy(
    loader: &mut EbpfLoader,
    config: &AgentConfig,
    metrics_readers: &mut Vec<MetricsReader>,
    cancel: tokio_util::sync::CancellationToken,
) -> anyhow::Result<Option<Arc<application::netpol_replay_service::NetpolReplayService>>> {
    let enforce = config.container.kubernetes.network_policy.mode
        == infrastructure::config::NetworkPolicyMode::Enforce;
    let refuse = |reason: String| {
        if enforce {
            Err(anyhow::anyhow!(network_policy_unavailable(&reason)))
        } else {
            warn!("network policy observes nothing: {reason}");
            Ok(None)
        }
    };
    if !adapters::container::is_running_in_kubernetes() {
        return refuse("the agent is not running in a Kubernetes cluster".to_string());
    }
    let Some(client) = adapters::container::try_build_client().await else {
        return refuse("no Kubernetes client could be built".to_string());
    };
    let maps = match adapters::ebpf::NetpolMapManager::new(loader.ebpf_mut()) {
        Ok(maps) => maps,
        Err(e) => {
            return refuse(format!(
                "the workload firewall object carries no policy map: {e}"
            ));
        }
    };
    if let Ok(rdr) = MetricsReader::new(loader.ebpf_mut(), "NETPOL_METRICS") {
        metrics_readers.push(rdr);
    }

    let cache = Arc::new(adapters::container::NetpolClusterCache::default());
    let changes = cache.subscribe();
    let _watchers = adapters::container::spawn_netpol_watchers(&client, &cache);
    let replay = Arc::new(
        application::netpol_replay_service::NetpolReplayService::new(
            Arc::clone(&cache) as Arc<dyn ports::secondary::netpol_map_port::ClusterViewPort>,
            Box::new(adapters::container::NetworkPolicyManifests),
        ),
    );
    let service = application::netpol_service::NetpolService::new(
        cache,
        Arc::new(adapters::container::PodCgroupScanner::new(
            config.attribution.cgroup_root.clone(),
        )),
        Box::new(maps),
        enforce,
    );
    tokio::spawn(service.run(changes, cancel));
    Ok(Some(replay))
}

#[cfg(not(feature = "kubernetes"))]
async fn start_network_policy(
    _loader: &mut EbpfLoader,
    config: &AgentConfig,
    _metrics_readers: &mut Vec<MetricsReader>,
    _cancel: tokio_util::sync::CancellationToken,
) -> anyhow::Result<Option<Arc<application::netpol_replay_service::NetpolReplayService>>> {
    let reason = "this agent was built without Kubernetes support";
    if config.container.kubernetes.network_policy.mode
        == infrastructure::config::NetworkPolicyMode::Enforce
    {
        return Err(anyhow::anyhow!(network_policy_unavailable(reason)));
    }
    warn!("network policy observes nothing: {reason}");
    Ok(None)
}

/// Load the process-tracing object and attach its two tracepoints.
///
/// Returns the loader, the counters, the ring-buffer reader, the attacher
/// holding the links and what can be said about the result. A kernel that
/// refuses the attach comes back as a status carrying the reason: the table
/// stays empty and the agent runs on, which is a degradation and not a
/// failure.
pub fn try_load_process_tracing(
    ebpf_dir: &str,
    config: &AgentConfig,
) -> anyhow::Result<(
    EbpfLoader,
    Option<MetricsReader>,
    adapters::ebpf::ProcessEventReader,
    adapters::ebpf::ProcessTracingAttacher,
    adapters::ebpf::ProcessTracingStatus,
)> {
    let program_bytes = read_ebpf_program(ebpf_dir, "tracepoint-process")?;
    let mut loader =
        EbpfLoader::load_with_pin_path(&program_bytes, adapters::ebpf::DEFAULT_BPF_PIN_PATH)?;
    let metrics_rdr = MetricsReader::new(loader.ebpf_mut(), "PROCESS_METRICS").ok();
    let reader = adapters::ebpf::ProcessEventReader::new(loader.ebpf_mut())?;

    // The tracepoints read the current task and nothing else, so no cgroup
    // path is resolved and the warden has nothing to broker: the BPF token
    // the agent loaded with is what the attach is checked against.
    let mut attacher = adapters::ebpf::ProcessTracingAttacher::new();
    let status = attacher.attach_all(&loader, config.process_table.capture_command_line);
    Ok((loader, metrics_rdr, reader, attacher, status))
}

/// Load the signal object, take its maps and attach its tracepoint.
///
/// Returns the loader, the maps the service arms through, the attacher
/// holding the link and what can be said about the attach. A kernel that
/// refuses it comes back as a status carrying the reason, and the capability
/// is then absent rather than silently inert: a rule asking to stop a process
/// is refused by a service that was never built.
pub fn try_load_signal(
    ebpf_dir: &str,
) -> anyhow::Result<(
    EbpfLoader,
    Option<MetricsReader>,
    adapters::ebpf::SignalMapManager,
    adapters::ebpf::SignalAttacher,
    adapters::ebpf::SignalStatus,
)> {
    let program_bytes = read_ebpf_program(ebpf_dir, "tracepoint-signal")?;
    let mut loader =
        EbpfLoader::load_with_pin_path(&program_bytes, adapters::ebpf::DEFAULT_BPF_PIN_PATH)?;
    let metrics_rdr = MetricsReader::new(loader.ebpf_mut(), "SIGNAL_METRICS").ok();
    let maps = adapters::ebpf::SignalMapManager::new(loader.ebpf_mut())?;
    let mut attacher = adapters::ebpf::SignalAttacher::new();
    let status = attacher.attach(&loader);
    Ok((loader, metrics_rdr, maps, attacher, status))
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
    config: &AgentConfig,
    pin_path: &str,
    scope: Option<&Arc<application::dlp_scope_service::DlpScopeService>>,
) -> anyhow::Result<(
    EbpfLoader,
    Option<MetricsReader>,
    DlpEventReader,
    adapters::ebpf::DlpUprobeAttacher,
    adapters::ebpf::DlpUprobeAttacher,
)> {
    let program_bytes = read_ebpf_program(ebpf_dir, "uprobe-dlp")?;
    let mut loader = EbpfLoader::load_with_pin_path(&program_bytes, pin_path)?;

    // The cgroup scope goes in before anything attaches. A probe armed first
    // and scoped afterwards reads every container on the node for the width of
    // that window, which on a shared node is a neighbour's plaintext in this
    // agent's ring buffer.
    push_dlp_cgroup_scope(&mut loader, config, scope)?;

    // Discover SSL libraries through the host proc root (`/host/proc` when the
    // host proc is bind-mounted into the agent), so the DLP uprobe sees
    // neighbouring containers' TLS, not only the agent's own. The same path is
    // valid in the warden's namespace when the host proc is mounted there too, so
    // a brokered attach needs no path translation.
    let proc_root = host_proc_root();
    let mut attacher = adapters::ebpf::DlpUprobeAttacher::with_programs(&proc_root, &loader)?;
    // Second attacher over the same programs, for libraries the symbol scan
    // cannot find because they export neither `SSL_write` nor `SSL_read`. It
    // discovers nothing on its own: a caller hands it a path and the offsets it
    // resolved. Separate from the scan attacher so a reconcile pass, which
    // detaches whatever no live process maps, cannot tear down a probe placed
    // from a plan, and so each publishes its own half of the inventory.
    let mut extended = adapters::ebpf::DlpUprobeAttacher::with_programs(&proc_root, &loader)?
        .with_owner(adapters::ebpf::UPROBE_OWNER_EXTENDED_TLS);

    // Rootless posture: discovery (reading other processes' `/proc`) and the
    // privileged uprobe `BPF_LINK_CREATE` are both brokered to the warden. The
    // brokered `/proc` scan can be slow on a busy node, so it MUST NOT run on the
    // synchronous startup path - the lifecycle watcher (spawned by the caller)
    // performs the first scan and every attach asynchronously. Startup only arms
    // the module.
    if let Some(sock) = warden_sock_from_env() {
        extended = extended.with_warden_socket(sock.clone());
        attacher = attacher.with_warden_socket(sock);
    } else {
        // Direct posture: the agent scans `/proc` itself (fast, local). Attach to
        // every mapped SSL library now, and fall back to a system library so a
        // single host arms before any TLS workload appears.
        let mut attached = attacher.reconcile().attached;
        if attached == 0
            && let Some(ssl_path) = find_ssl_library_path(&proc_root)
        {
            info!(library = %ssl_path, "no mapped SSL library found; attaching to system library");
            attacher.attach_fallback_path(&ssl_path)?;
            attached = 1;
        }
        if attached == 0 {
            anyhow::bail!(
                "no SSL library found (no process maps one, and none on the system - tried: {}). \
                 DLP uprobe requires OpenSSL or BoringSSL. \
                 Install libssl-dev or equivalent package.",
                SSL_LIBRARY_CANDIDATES.join(", ")
            );
        }
    }

    // Kernel TLS plaintext sits behind a message iterator whose member offsets
    // the probe cannot resolve itself, so they go in before anything attaches.
    // A kernel with no `iov_iter` to describe is not a failure of the DLP
    // module: the uprobes carry on and only the kernel hook stays blind.
    match resolve_ktls_iter_offsets() {
        Ok(offsets) => {
            if let Err(e) = adapters::ebpf::push_ktls_iter_offsets(loader.ebpf_mut(), offsets) {
                warn!("failed to push kernel TLS iterator offsets to BPF: {e}");
            } else {
                info!(
                    msg_iter = offsets.msg_iter,
                    count = offsets.count,
                    "kernel TLS iterator BTF offsets resolved and pushed to BPF"
                );
            }
        }
        Err(e) => warn!("failed to resolve kernel TLS iterator BTF offsets: {e}"),
    }

    // The socket behind a kernel TLS call is what lets a DLP alert name a
    // destination. Same BTF reason as the iterator above, and the same
    // posture on failure: the probes keep reporting the leak and report no
    // flow, rather than reading a five-tuple out of the wrong offsets.
    match resolve_sock_offsets() {
        Ok(offsets) => {
            if let Err(e) = adapters::ebpf::push_sock_offsets(loader.ebpf_mut(), offsets) {
                warn!("failed to push socket BTF offsets to BPF: {e}");
            } else {
                info!(
                    skc_daddr = offsets.skc_daddr,
                    skc_dport = offsets.skc_dport,
                    "socket BTF offsets resolved and pushed to BPF"
                );
            }
        }
        Err(e) => {
            warn!("failed to resolve socket BTF offsets: {e}; DLP alerts will name no destination");
        }
    }

    let dlp_metrics_rdr = MetricsReader::new(loader.ebpf_mut(), "DLP_METRICS").ok();

    let reader = DlpEventReader::new(loader.ebpf_mut())?;

    info!("uprobe-dlp armed (discovery + attach run via the lifecycle watcher)");
    Ok((loader, dlp_metrics_rdr, reader, attacher, extended))
}

/// Resolve everything the kernel TLS probes need to walk a `struct msghdr`
/// from the running kernel's vmlinux BTF: the offset of the message iterator
/// inside the header, the iterator's own members, the `iovec` pair a vectored
/// iterator points at, and the two `enum iter_type` discriminants the probe
/// compares against.
///
/// The discriminants are read rather than written down because their order
/// changed between 6.4 and 6.5, so a constant compiled in here would describe
/// the wrong iterator kind on half the kernels this agent runs on.
///
/// # Errors
///
/// Returns an error if any member or enumerator is missing from the blob. A
/// partially-resolved layout is refused rather than pushed, because a probe
/// reading one wrong offset reports plaintext that was never sent.
/// Write the configured DLP cgroup scope into the datapath maps.
///
/// `all` keeps the mode the probes default to and touches the allow list not at
/// all. `workloads` resolves each configured cgroup path under the resolver's
/// cgroup root to its id and refuses to arm the probes when none of them exists
/// on this node, since an allow list that matches nothing captures nothing
/// while every counter says DLP is loaded.
fn push_dlp_cgroup_scope(
    loader: &mut EbpfLoader,
    config: &AgentConfig,
    service: Option<&Arc<application::dlp_scope_service::DlpScopeService>>,
) -> anyhow::Result<()> {
    if !config.dlp.scope.is_workload_scoped() {
        return Ok(());
    }

    // With a resolver, the maps become its own: it writes the configured
    // cgroups now and widens to the workloads the selectors name on its first
    // refresh. Narrowest first, because the window between the two is a
    // window in which the probes are armed.
    if let Some(service) = service {
        let maps = adapters::ebpf::DlpScopeMapManager::new(loader.ebpf_mut())?;
        service.install_maps(Box::new(maps))?;
        info!(
            "DLP plaintext capture scoped to the configured cgroups, pending selector resolution"
        );
        return Ok(());
    }

    let cgroup_root = Path::new(&config.container.resolver.cgroup_root);
    let scope = adapters::ebpf::resolve_cgroup_scope(cgroup_root, &config.dlp.scope.cgroups);
    if !scope.missing.is_empty() {
        warn!(
            missing = scope.missing.len(),
            "DLP scope names cgroups that do not exist on this node; those workloads are not read"
        );
    }
    adapters::ebpf::push_dlp_scope(loader.ebpf_mut(), &scope)?;
    info!(
        cgroups = scope.cgroups.len(),
        cgroup_root = %cgroup_root.display(),
        "DLP plaintext capture scoped to the configured cgroups"
    );
    Ok(())
}

fn resolve_ktls_iter_offsets() -> anyhow::Result<ebpf_common::dlp::KtlsIterOffsets> {
    use adapters::ebpf::kfunc::{vmlinux_enum_values, vmlinux_struct_member_offsets};

    fn member(
        offsets: &[Option<u32>],
        type_name: &str,
        names: &[&str],
        index: usize,
    ) -> anyhow::Result<u32> {
        offsets
            .get(index)
            .copied()
            .flatten()
            .ok_or_else(|| anyhow::anyhow!("{type_name}.{} not found in BTF", names[index]))
    }

    const MSGHDR: [&str; 1] = ["msg_iter"];
    const ITER: [&str; 4] = ["iter_type", "iov_offset", "__ubuf_iovec", "count"];
    const IOVEC: [&str; 2] = ["iov_base", "iov_len"];
    const KINDS: [&str; 2] = ["ITER_UBUF", "ITER_IOVEC"];

    let msghdr = vmlinux_struct_member_offsets("msghdr", &MSGHDR)?;
    let iter = vmlinux_struct_member_offsets("iov_iter", &ITER)?;
    let iovec = vmlinux_struct_member_offsets("iovec", &IOVEC)?;
    let kinds = vmlinux_enum_values("iter_type", &KINDS)?;

    let kind = |index: usize| -> anyhow::Result<u8> {
        let value =
            kinds.get(index).copied().flatten().ok_or_else(|| {
                anyhow::anyhow!("enum iter_type::{} not found in BTF", KINDS[index])
            })?;
        u8::try_from(value).map_err(|_| {
            anyhow::anyhow!("enum iter_type::{} is {value}, outside a u8", KINDS[index])
        })
    };

    Ok(ebpf_common::dlp::KtlsIterOffsets {
        msg_iter: member(&msghdr, "msghdr", &MSGHDR, 0)?,
        iter_type: member(&iter, "iov_iter", &ITER, 0)?,
        iov_offset: member(&iter, "iov_iter", &ITER, 1)?,
        iov_union: member(&iter, "iov_iter", &ITER, 2)?,
        count: member(&iter, "iov_iter", &ITER, 3)?,
        iovec_base: member(&iovec, "iovec", &IOVEC, 0)?,
        iovec_len: member(&iovec, "iovec", &IOVEC, 1)?,
        iter_ubuf: kind(0)?,
        iter_iovec: kind(1)?,
        valid: 1,
        _pad: 0,
    })
}

/// Resolve the `struct sock` members the kernel TLS probes read to name a
/// destination: the embedded `sock_common`, its address pair in both families
/// and its port pair.
///
/// `sock_common` nests the addresses inside anonymous unions, which the BTF
/// walk descends into, so `skc_rcv_saddr` and `skc_daddr` are found at their
/// real offsets rather than at the union's.
///
/// # Errors
///
/// Returns an error if any member is missing from the blob. A partial layout
/// is refused rather than pushed: a probe reading one wrong offset reports a
/// destination the data never went to, which is worse than reporting none.
fn resolve_sock_offsets() -> anyhow::Result<ebpf_common::dlp::SockOffsets> {
    use adapters::ebpf::kfunc::vmlinux_struct_member_offsets;

    fn member(
        offsets: &[Option<u32>],
        type_name: &str,
        names: &[&str],
        index: usize,
    ) -> anyhow::Result<u32> {
        offsets
            .get(index)
            .copied()
            .flatten()
            .ok_or_else(|| anyhow::anyhow!("{type_name}.{} not found in BTF", names[index]))
    }

    const SOCK: [&str; 1] = ["__sk_common"];
    const COMMON: [&str; 6] = [
        "skc_rcv_saddr",
        "skc_daddr",
        "skc_num",
        "skc_dport",
        "skc_family",
        "skc_v6_rcv_saddr",
    ];
    const COMMON_V6_DADDR: [&str; 1] = ["skc_v6_daddr"];

    let sock = vmlinux_struct_member_offsets("sock", &SOCK)?;
    let common = vmlinux_struct_member_offsets("sock_common", &COMMON)?;
    let v6_daddr = vmlinux_struct_member_offsets("sock_common", &COMMON_V6_DADDR)?;

    Ok(ebpf_common::dlp::SockOffsets {
        sk_common: member(&sock, "sock", &SOCK, 0)?,
        skc_rcv_saddr: member(&common, "sock_common", &COMMON, 0)?,
        skc_daddr: member(&common, "sock_common", &COMMON, 1)?,
        skc_num: member(&common, "sock_common", &COMMON, 2)?,
        skc_dport: member(&common, "sock_common", &COMMON, 3)?,
        skc_family: member(&common, "sock_common", &COMMON, 4)?,
        skc_v6_rcv_saddr: member(&common, "sock_common", &COMMON, 5)?,
        skc_v6_daddr: member(&v6_daddr, "sock_common", &COMMON_V6_DADDR, 0)?,
        valid: 1,
        _pad: [0; 3],
    })
}

/// Search for a usable SSL/TLS shared library on the system.
///
/// Parses `ldconfig -p` to extract the full path for each candidate,
/// then falls back to common library directories. Returns the absolute
/// path to the first library found, which aya needs for uprobe attach.
/// Parse `EBPF_MODULE_BTF_FDS` (a comma-separated `module=fd` list passed in by
/// a privileged setup component in BPF-token mode) and register each module BTF
/// object fd with the kfunc loader. A malformed entry is logged and skipped so
/// one bad pair never blocks the rest. Absent or empty env is the normal case
/// (privileged mode resolves the fds itself) and does nothing.
fn register_module_btf_fds() {
    let Ok(raw) = std::env::var("EBPF_MODULE_BTF_FDS") else {
        return;
    };
    for entry in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let Some((module, fd_str)) = entry.split_once('=') else {
            warn!(
                entry,
                "ignoring malformed EBPF_MODULE_BTF_FDS entry (no '=')"
            );
            continue;
        };
        match fd_str.trim().parse::<std::os::fd::RawFd>() {
            Ok(fd) if fd >= 0 => {
                adapters::ebpf::set_module_btf_fd(module.trim(), fd);
                info!(module = module.trim(), fd, "registered module BTF fd");
            }
            _ => warn!(
                entry,
                "ignoring malformed EBPF_MODULE_BTF_FDS entry (bad fd)"
            ),
        }
    }
}

fn find_ssl_library_path(proc_root: &std::path::Path) -> Option<String> {
    use std::process::Command;

    const SEARCH_DIRS: &[&str] = &[
        "usr/lib/x86_64-linux-gnu",
        "usr/lib/aarch64-linux-gnu",
        "usr/lib64",
        "usr/lib",
        "lib/x86_64-linux-gnu",
        "lib64",
        "lib",
    ];

    // First search under the host init's root (`{proc_root}/1/root`). When the
    // host proc is mounted, this is the host's library tree - and the same path
    // is valid in the warden's namespace, so a brokered attach reaches it. Skipped
    // silently when unreadable (e.g. no host proc, or insufficient access).
    let host_root = proc_root.join("1").join("root");
    for candidate in SSL_LIBRARY_CANDIDATES {
        for dir in SEARCH_DIRS {
            let path = host_root.join(dir).join(candidate);
            if path.exists() {
                return Some(path.to_string_lossy().into_owned());
            }
        }
    }

    // Then the agent's own rootfs: ldconfig (most reliable - gives full paths),
    // then the bare directories. Used in the direct (non-brokered) posture.
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

    for candidate in SSL_LIBRARY_CANDIDATES {
        for dir in SEARCH_DIRS {
            let path = format!("/{dir}/{candidate}");
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
        warn!("failed to resolve nf_conn BTF offsets - kernel CT field reads disabled");
    }

    // tc-conntrack has no EVENTS RingBuf (pure state tracking, no events).
    // EventReader is optional - skip if the map doesn't exist.
    let opt_reader = EventReader::new(loader.ebpf_mut()).ok();

    Ok((loader, ct_mgr, ct_metrics_rdr, opt_reader))
}

/// Resolve `nf_conn.status` and `nf_conn.mark` field offsets from the
/// running kernel's vmlinux BTF, read off the sysfs blob by the same walker
/// that resolves kfuncs. No `bpftool` is spawned: the JSON dump this used to
/// parse cost the agent about 330 MB of heap it never gave back.
fn resolve_nf_conn_offsets() -> anyhow::Result<ebpf_common::conntrack::NfConnOffsets> {
    let offsets =
        adapters::ebpf::kfunc::vmlinux_struct_member_offsets("nf_conn", &["status", "mark"])?;
    let member = |index: usize, name: &str| {
        offsets
            .get(index)
            .copied()
            .flatten()
            .ok_or_else(|| anyhow::anyhow!("nf_conn.{name} not found in BTF"))
    };
    Ok(ebpf_common::conntrack::NfConnOffsets {
        status_offset: member(0, "status")?,
        mark_offset: member(1, "mark")?,
        valid: 1,
        _pad: 0,
    })
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

    // Egress hook: the SNAT rewrite has to see the packet after routing, on
    // the device it leaves by. Attached on ingress it only ever met the
    // forwarded half of a flow and never a locally originated one.
    for iface in &config.agent.interfaces {
        attach_tc_egress_auto(
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

    // Egress is the hook shaping belongs on: EDT pacing hands the packet to
    // the interface's fq qdisc, which only exists on the way out. Ingress
    // carries the same program under a second entry point so a pipe declared
    // `ingress` or `both` is enforced; each entry point only honours pipes
    // that name its own direction.
    for iface in &config.agent.interfaces {
        attach_tc_egress_auto(&mut loader, "tc_qos", iface, config.agent.attach_mode)?;
        attach_tc_auto(
            &mut loader,
            "tc_qos_ingress",
            iface,
            config.agent.attach_mode,
        )?;
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
        drop_fragments: u8::from(scrub.drop_fragments),
        _pad: [0; 1],
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
                "GeoIP URL mode requires async download - use `file` mode or pre-download databases"
            );
        }
        infrastructure::config::GeoIpSource::MaxMindAccount { .. } => {
            anyhow::bail!(
                "GeoIP MaxMind account mode requires async download - use `file` mode or pre-download databases"
            );
        }
    }
}

/// Load the XDP load balancer program.
///
/// When `xdp_chain_active` is true (firewall or ratelimit is on the same
/// interfaces), the LB is loaded without attaching - it will be invoked
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
        // Another XDP program owns the interface - load only (tail-call target).
        loader.load_xdp_program("xdp_loadbalancer")?;
        info!("xdp-loadbalancer loaded as tail-call target (XDP chain active)");
    } else {
        // Standalone mode - attach directly.
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

/// Attach a TC program to the EGRESS hook of an interface, dispatching on
/// [`AttachMode`] the same way [`attach_tc_auto`] does for ingress. Netkit
/// devices take the peer side of the pair; everything else takes TCX egress.
fn attach_tc_egress_auto(
    loader: &mut adapters::ebpf::loader::EbpfLoader,
    program_name: &str,
    iface: &str,
    mode: infrastructure::config::AttachMode,
) -> anyhow::Result<()> {
    use infrastructure::config::AttachMode;

    match mode {
        AttachMode::Netkit => {
            loader.attach_tc_egress_via_netkit(program_name, iface)?;
        }
        AttachMode::Tc => {
            loader.attach_tc_egress(program_name, iface)?;
        }
        AttachMode::Auto => {
            if adapters::ebpf::netkit::is_netkit_device(iface) {
                match loader.attach_tc_egress_via_netkit(program_name, iface) {
                    Ok(()) => {}
                    Err(e) => {
                        warn!(
                            program_name, iface, error = %e,
                            "netkit egress attach failed, falling back to TC"
                        );
                        loader.attach_tc_egress(program_name, iface)?;
                    }
                }
            } else {
                loader.attach_tc_egress(program_name, iface)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_agent_api_ports_are_always_kept_open() {
        let yaml = "agent:\n  interfaces: [eth0]\n  http_port: 9443\n  grpc_port: 9444\nfirewall:\n  anti_lockout:\n    ports: [22, 9443]\n";
        let config = AgentConfig::from_yaml(yaml).unwrap();
        assert_eq!(firewall_anti_lockout(&config).ports, [22, 9443, 9444]);
    }

    #[test]
    fn the_default_keeps_ssh_and_the_default_api_ports() {
        let config = AgentConfig::from_yaml("agent:\n  interfaces: [eth0]\n").unwrap();
        let settings = firewall_anti_lockout(&config);
        assert!(settings.enabled);
        assert_eq!(
            settings.ports,
            [22, config.agent.http_port, config.agent.grpc_port]
        );
    }

    #[test]
    fn an_unset_resolver_proc_path_follows_the_host_proc_mount() {
        assert_eq!(
            super::resolver_proc_path("/proc", std::path::Path::new("/host/proc")),
            std::path::PathBuf::from("/host/proc")
        );
    }

    #[test]
    fn a_configured_resolver_proc_path_wins_over_the_host_proc_mount() {
        assert_eq!(
            super::resolver_proc_path("/fixture/proc", std::path::Path::new("/host/proc")),
            std::path::PathBuf::from("/fixture/proc")
        );
    }

    #[test]
    fn a_host_without_a_mounted_proc_keeps_the_default() {
        assert_eq!(
            super::resolver_proc_path("/proc", std::path::Path::new("/proc")),
            std::path::PathBuf::from("/proc")
        );
    }
}
