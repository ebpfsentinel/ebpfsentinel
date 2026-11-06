//! Reusable OSS agent runtime - service handles and lifecycle control.
//!
//! Provides [`ServiceHandles`] + [`build_services`] for creating all OSS
//! services, and [`load_ebpf_programs`] + [`EbpfLoadResult`] for attaching
//! eBPF programs with full map wiring.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use adapters::metrics::AgentMetrics;
use application::alias_service_impl::AliasAppService;
use application::audit_service_impl::AuditAppService;
use application::conntrack_service_impl::ConnTrackAppService;
use application::dlp_service_impl::DlpAppService;
use application::dns_blocklist_service_impl::DnsBlocklistAppService;
use application::dns_cache_service_impl::DnsCacheAppService;
use application::firewall_service_impl::FirewallAppService;
use application::ids_service_impl::IdsAppService;
use application::ids_workload_scope_service::IdsWorkloadScopeService;
use application::ips_service_impl::{IpsAppService, IpsBlacklistAdapter};
use application::l7_service_impl::L7AppService;
use application::nat_service_impl::NatAppService;
use application::ratelimit_service_impl::RateLimitAppService;
use application::routing_service_impl::RoutingAppService;
use application::schedule_service_impl::ScheduleService;
use application::threatintel_service_impl::ThreatIntelAppService;
use application::zone_service_impl::ZoneAppService;
use arc_swap::ArcSwap;
use domain::dlp::engine::DlpEngine;
use domain::firewall::engine::FirewallEngine;
use domain::ids::engine::IdsEngine;
use domain::ips::engine::IpsEngine;
use domain::l7::engine::L7Engine;
use domain::ratelimit::engine::RateLimitEngine;
use domain::threatintel::engine::ThreatIntelEngine;
use infrastructure::config::AgentConfig;
use ports::secondary::alias_resolution_port::AliasResolutionPort;
use ports::secondary::lpm_coordinator_port::LpmCoordinatorPort;
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
    pub ids_svc: Arc<ArcSwap<IdsAppService>>,
    pub ids_workload_scope: Arc<IdsWorkloadScopeService>,
    pub ips_svc: Arc<ArcSwap<IpsAppService>>,
    pub rl_svc: Arc<RwLock<RateLimitAppService>>,
    pub ti_svc: Arc<ArcSwap<ThreatIntelAppService>>,
    pub dns_blocklist_svc: Option<Arc<DnsBlocklistAppService>>,

    // ── Additional services ──────────────────────────────────────
    pub l7_svc: Arc<ArcSwap<L7AppService>>,
    pub ddos_svc: Arc<ArcSwap<application::ddos_service_impl::DdosAppService>>,
    pub dlp_svc: Arc<ArcSwap<DlpAppService>>,
    /// Which workloads DLP reads, when the configuration scopes it. `None`
    /// when `dlp.scope.mode` is `all`, where there is nothing to resolve.
    pub dlp_scope_svc: Option<Arc<application::dlp_scope_service::DlpScopeService>>,
    pub conntrack_svc: Arc<RwLock<ConnTrackAppService>>,
    pub nat_svc: Arc<RwLock<NatAppService>>,
    pub lb_svc: Arc<RwLock<application::lb_service_impl::LbAppService>>,
    pub qos_svc: Arc<RwLock<application::qos_service_impl::QosAppService>>,
    /// The workloads held to the rates `qos.cgroup_shaping` names. Its
    /// tables are handed over by each load of tc-qos and taken back when that
    /// generation goes.
    pub cgroup_shaping: Arc<application::qos_cgroup_shaping_service::QosCgroupShapingService>,
    /// The L2 VIP announcer. Each load behind a firewall hands it the
    /// announcer's maps; a load without one takes them back.
    pub vip_svc: Arc<RwLock<application::vip_announcer_service_impl::VipAnnouncerService>>,
    pub zone_svc: Arc<RwLock<ZoneAppService>>,
    pub alias_svc: Arc<RwLock<AliasAppService>>,
    pub alias_resolver: Arc<dyn AliasResolutionPort>,
    pub routing_svc: Arc<RwLock<RoutingAppService>>,
    pub schedule_svc: Arc<RwLock<ScheduleService>>,
    pub audit_svc: Arc<AuditAppService>,

    // ── DNS services (optional) ──────────────────────────────────
    pub dns_cache_svc: Option<Arc<DnsCacheAppService>>,

    /// Stopping the process behind a flow. `None` whenever the capability is
    /// off, the object did not load or the kernel refused the attach, and a
    /// caller holding `None` has no way to signal anything.
    pub process_signal_svc: Option<Arc<application::process_signal_service::ProcessSignalService>>,

    /// Cutting a workload off the network while leaving it running. `None`
    /// whenever the capability is off, the workload firewall did not load or
    /// its quarantine maps were not acquired, and a caller holding `None`
    /// cannot quarantine anything.
    pub quarantine_svc: Option<Arc<application::quarantine_service::QuarantineService>>,

    /// Which workload sits behind a socket, shared with every reader of a
    /// flow. Empty until a load attaches the attribution hooks and hands it
    /// the kernel tables, and emptied again when that generation goes, so a
    /// holder never answers from a map the kernel has freed.
    pub workloads: application::workload_resolver::WorkloadResolver,
    /// The addresses of the other nodes, as the console last handed them.
    /// Empty on a node no console has reached, which names no peer.
    pub remote_identities: Arc<application::remote_identity_store::RemoteIdentityStore>,

    /// Which pods each workload link belongs to and whether the datapath
    /// reaches them, fed by the link hot-plug watcher of each load and by the
    /// pod inventory once one is installed.
    pub pod_coverage: Arc<application::pod_coverage_service::PodCoverageService>,
    /// The guests behind the node's tap and macvtap devices, fed by the link
    /// hot-plug watcher of each load.
    pub guests: Arc<application::guest_inventory_service::GuestInventoryService>,
    /// The owner of each workload link the watcher finds, relayed to the
    /// process table once [`start_host_observation`] starts one.
    pub link_processes: Arc<ProcessRelay>,

    // ── Infrastructure ───────────────────────────────────────────
    pub metrics: Arc<AgentMetrics>,
    pub ebpf_loaded: Arc<AtomicBool>,
}

impl ServiceHandles {
    /// The reload service over these handles, for a caller that owns the
    /// services but not the standalone startup path.
    ///
    /// It carries every service the handles hold.
    #[must_use]
    pub fn config_reload_service(&self) -> application::config_reload::ConfigReloadService {
        let mut reload_service = application::config_reload::ConfigReloadService::new(
            Arc::clone(&self.firewall_svc),
            Arc::clone(&self.ids_svc),
            Arc::clone(&self.ips_svc),
            Arc::clone(&self.l7_svc),
            Arc::clone(&self.rl_svc),
            Arc::clone(&self.ddos_svc),
            Arc::clone(&self.ti_svc),
            Arc::clone(&self.audit_svc),
            Arc::clone(&self.metrics) as Arc<dyn MetricsPort>,
        );
        reload_service.set_conntrack_service(Arc::clone(&self.conntrack_svc));
        reload_service.set_dlp_service(Arc::clone(&self.dlp_svc));
        reload_service.set_nat_service(Arc::clone(&self.nat_svc));
        reload_service.set_alias_service(Arc::clone(&self.alias_svc));
        reload_service.set_routing_service(Arc::clone(&self.routing_svc));
        reload_service.set_loadbalancer_service(Arc::clone(&self.lb_svc));
        reload_service.set_qos_service(Arc::clone(&self.qos_svc));
        reload_service.set_cgroup_shaping_service(Arc::clone(&self.cgroup_shaping));
        reload_service.set_vip_announcer_service(Arc::clone(&self.vip_svc));
        reload_service.set_zone_service(Arc::clone(&self.zone_svc));
        reload_service.set_schedule_service(Arc::clone(&self.schedule_svc));
        reload_service
    }
}

/// Load the VIP announcer behind this load's firewall when the configuration
/// names a role, and otherwise take the previous generation's maps back from
/// the service, so a VIP is never written into a table nothing reads.
async fn load_vip_announcer(
    config: &AgentConfig,
    services: &ServiceHandles,
    ebpf_dir: &str,
    fw: Option<&mut EbpfLoader>,
    readers: &tokio_util::sync::CancellationToken,
) -> Option<EbpfLoader> {
    let wanted = match config.lb_announce().and_then(|announce| {
        let bgp = config.lb_announce_bgp()?;
        Ok((announce, bgp))
    }) {
        Ok((announce, bgp))
            if announce.role != domain::loadbalancer::vip::AnnounceRole::Disabled =>
        {
            Some((announce, bgp))
        }
        Ok(_) => None,
        Err(e) => {
            warn!("VIP announce configuration unreadable (VIP announce disabled): {e}");
            None
        }
    };
    let asked = wanted.is_some();
    let started = match (fw, wanted) {
        (Some(fw), Some((announce, bgp))) => startup::start_vip_announcer(
            ebpf_dir,
            fw,
            &services.vip_svc,
            announce,
            bgp,
            readers.child_token(),
        )
        .await
        .map_err(|e| warn!("xdp-vip-announcer load failed (VIP announce disabled): {e}"))
        .ok(),
        _ => None,
    };
    if started.is_none() {
        let mut svc = services.vip_svc.write().await;
        svc.clear_map_port();
        svc.clear_binding_port();
    }
    if asked {
        services
            .metrics
            .set_ebpf_program_status("xdp_vip_announcer", started.is_some());
    } else {
        services
            .metrics
            .clear_ebpf_program_status("xdp_vip_announcer");
    }
    started
}

/// Process events relayed from a producer that starts before the process
/// table to the table, once it exists. A send that finds the relay full is
/// dropped, as every producer of these events already drops one.
pub struct ProcessRelay {
    tx: mpsc::Sender<domain::process::entity::ProcessLifecycleEvent>,
    rx: std::sync::Mutex<Option<mpsc::Receiver<domain::process::entity::ProcessLifecycleEvent>>>,
}

impl ProcessRelay {
    pub(crate) fn new() -> Self {
        let (tx, rx) = mpsc::channel(1024);
        Self {
            tx,
            rx: std::sync::Mutex::new(Some(rx)),
        }
    }

    /// The sending half, for a producer.
    #[must_use]
    pub fn sender(&self) -> mpsc::Sender<domain::process::entity::ProcessLifecycleEvent> {
        self.tx.clone()
    }

    /// Forward everything relayed to `table` until `cancel`. Only the first
    /// caller gets the events: a second table would split them.
    fn forward_to(
        &self,
        table: mpsc::Sender<domain::process::entity::ProcessLifecycleEvent>,
        cancel: &tokio_util::sync::CancellationToken,
    ) {
        // The guarded value is an `Option` taken whole, so a panic while it
        // was held cannot have left it half written.
        let taken = self
            .rx
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let Some(mut rx) = taken else {
            return;
        };
        let cancel = cancel.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = cancel.cancelled() => break,
                    event = rx.recv() => match event {
                        Some(event) => {
                            if table.send(event).await.is_err() {
                                break;
                            }
                        }
                        None => break,
                    },
                }
            }
        });
    }
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
/// The resolver that turns DLP workload selectors into cgroup ids.
///
/// `None` when DLP is off or its scope mode is `all`: every task on the node
/// is read, so there is nothing to resolve and nothing to keep refreshing,
/// and the probes' own default is the policy.
///
/// The cgroup tree is the source here. A node that can also name a pod or a
/// container hands the service a richer source once the container resolver
/// and the metadata enrichers have been decided, which happens later in
/// startup than this.
///
/// # Errors
///
/// Returns an error when a selector is malformed, which is the same refusal
/// configuration validation already raised.
pub fn build_dlp_scope_service(
    config: &AgentConfig,
) -> anyhow::Result<Option<Arc<application::dlp_scope_service::DlpScopeService>>> {
    use application::dlp_scope_service::{ConfiguredCgroup, DlpScopeService};
    use domain::dlp::scope::DlpScopeMode;

    if !config.dlp.enabled || !config.dlp.scope.is_workload_scoped() {
        return Ok(None);
    }

    let policy = config.dlp.scope.to_policy()?;
    let cgroup_root = std::path::Path::new(&config.container.resolver.cgroup_root);
    let resolved = adapters::ebpf::resolve_cgroup_scope(cgroup_root, &config.dlp.scope.cgroups);
    for missing in &resolved.missing {
        warn!(
            path = %missing.display(),
            "DLP scope names a cgroup that does not exist on this node; its tasks are not read"
        );
    }
    let configured: Vec<ConfiguredCgroup> = resolved
        .cgroups
        .iter()
        .map(|cgroup| ConfiguredCgroup {
            path: cgroup.path.display().to_string(),
            id: cgroup.id,
        })
        .collect();

    let scanner = adapters::container::CgroupWorkloadScanner::new(cgroup_root);
    let service = DlpScopeService::new(DlpScopeMode::Workloads, policy, configured)
        .with_source(Arc::new(scanner));
    info!(
        cgroups = resolved.cgroups.len(),
        selectors = config.dlp.scope.selectors.len(),
        cgroup_root = %cgroup_root.display(),
        "DLP scope resolver initialized"
    );
    Ok(Some(Arc::new(service)))
}

/// This node's addresses and who holds each, read through the procfs the
/// container resolver walks and the workloads the process table knows.
///
/// The run's epoch is the moment it was built: a reader holding versions of
/// an earlier run of the agent is handed the whole list rather than a delta
/// computed against a journal it never saw.
#[must_use]
pub fn build_address_identities(
    config: &AgentConfig,
    services: &ServiceHandles,
) -> application::address_identity_service::AddressIdentityService {
    let proc_root = startup::resolver_proc_path(
        &config.container.resolver.proc_path,
        &startup::host_proc_root(),
    );
    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(1, |since| {
            u64::try_from(since.as_nanos()).unwrap_or(u64::MAX)
        });
    application::address_identity_service::AddressIdentityService::new(
        services.workloads.clone(),
        Arc::new(adapters::container::proc_namespaces::ProcNamespaceAddresses::new(proc_root)),
        epoch,
    )
}

/// The workload source a selector is resolved against, naming each cgroup's
/// container and pod where the node can say.
///
/// For a binary that does not run the agent's own start-up path, which builds
/// the same enrichers inline beside the rest of the container tracking.
pub async fn build_workload_source(
    config: &AgentConfig,
) -> adapters::container::CgroupWorkloadScanner {
    build_workload_enrichers(config).await.into_iter().fold(
        adapters::container::CgroupWorkloadScanner::new(&config.container.resolver.cgroup_root),
        adapters::container::CgroupWorkloadScanner::with_enricher,
    )
}

/// What names a container and a pod on this node.
///
/// Docker is read when its socket is there, Kubernetes when the agent runs in
/// a cluster and was built with it; without any, a selector naming a pod or a
/// container matches nothing, which is said once here.
pub async fn build_workload_enrichers(
    config: &AgentConfig,
) -> Vec<Arc<dyn ports::secondary::metadata_enricher_port::MetadataEnricher>> {
    let mut enrichers: Vec<Arc<dyn ports::secondary::metadata_enricher_port::MetadataEnricher>> =
        Vec::new();

    let docker = &config.container.docker;
    if docker.enabled && Path::new(&docker.socket).exists() {
        let client = adapters::container::DockerClient::new(&docker.socket, docker.timeout_ms);
        let cache = Arc::new(adapters::container::DockerCache::new(
            docker.cache_size,
            std::time::Duration::from_secs(docker.cache_ttl_seconds),
        ));
        let _watcher = adapters::container::DockerEventWatcher::spawn_with_labels(
            &docker.socket,
            Arc::clone(&cache),
            None,
        );
        enrichers.push(Arc::new(adapters::container::DockerEnricher::new(
            client, cache,
        )));
    }

    if let (_, Some(podman)) = build_podman_enricher(config) {
        enrichers.push(podman);
    }

    if let (_, Some(lxc)) = build_lxc_enricher(config) {
        enrichers.push(lxc);
    }

    #[cfg(feature = "kubernetes")]
    if config.container.kubernetes.enabled
        && adapters::container::is_running_in_kubernetes()
        && let Some(client) = adapters::container::try_build_client().await
    {
        let cache = Arc::new(adapters::container::PodCache::new());
        let enricher = adapters::container::KubernetesEnricher::with_cache(Arc::clone(&cache));
        let metrics = enricher.metrics();
        let node_name = if config.container.kubernetes.node_name.is_empty() {
            adapters::container::resolve_node_name()
        } else {
            config.container.kubernetes.node_name.clone()
        };
        let _namespaces = adapters::container::spawn_namespace_watcher(
            client.clone(),
            Arc::clone(&cache),
            Arc::clone(&metrics),
        );
        let _pods = adapters::container::spawn_pod_watcher(
            client,
            node_name,
            config.container.kubernetes.label_filter.join(","),
            cache,
            metrics,
        );
        enrichers.push(Arc::new(enricher));
    }

    if enrichers.is_empty() {
        warn!(
            "no container runtime or cluster answers on this node, so a workload selector \
             naming a pod or a container matches nothing; cgroups and units still resolve"
        );
    }
    enrichers
}

/// The Podman enricher, and what it means for the node.
///
/// Built without asking the runtime anything: a user's socket appears when
/// they log in or enable `podman.socket`, long after the agent started, so
/// each one is gone to the first time one of that user's containers is seen.
/// Root's socket missing with rootless turned off is the one case decided
/// here, because then nothing could ever be named.
pub fn build_podman_enricher(
    config: &AgentConfig,
) -> (
    crate::http::agent_handler::EnricherState,
    Option<Arc<adapters::container::PodmanEnricher>>,
) {
    use crate::http::agent_handler::EnricherState;
    let podman = &config.container.podman;
    if !podman.enabled {
        return (EnricherState::OffByConfiguration, None);
    }
    if !podman.rootless && !Path::new(&podman.socket).exists() {
        warn!(
            socket = %podman.socket,
            "Podman container enrichment is off: the socket is not there and rootless \
             runtimes are not asked. Alerts keep their container id and lose the container \
             name, image and labels. Enable podman.socket, mount it read-only, or set \
             container.podman.enabled to false to stop asking for it"
        );
        return (EnricherState::OffNoSocket, None);
    }
    let cache = Arc::new(adapters::container::DockerCache::new(
        podman.cache_size,
        std::time::Duration::from_secs(podman.cache_ttl_seconds),
    ));
    let enricher = adapters::container::PodmanEnricher::new(
        &podman.socket,
        podman
            .rootless
            .then(|| std::path::PathBuf::from(&podman.run_user_root)),
        podman.timeout_ms,
        cache,
    );
    info!(
        socket = %podman.socket,
        rootless = podman.rootless,
        run_user_root = %podman.run_user_root,
        "Podman metadata enricher initialized: each owner's runtime is reached the first time \
         one of their containers is seen"
    );
    (EnricherState::On, Some(Arc::new(enricher)))
}

/// The LXC enricher: Proxmox CTs, Incus instances and plain LXC.
///
/// Nothing is asked here. The name is in the cgroup path, so the enricher
/// names every LXC container whether or not a source is mounted, and the
/// Proxmox directory and the Incus socket are each read the first time a
/// container needs them, which is how a node that is neither still names
/// its containers.
pub fn build_lxc_enricher(
    config: &AgentConfig,
) -> (
    crate::http::agent_handler::EnricherState,
    Option<Arc<adapters::container::LxcEnricher>>,
) {
    use crate::http::agent_handler::EnricherState;
    let lxc = &config.container.lxc;
    if !lxc.enabled {
        return (EnricherState::OffByConfiguration, None);
    }
    let path = |p: &str| (!p.is_empty()).then(|| std::path::PathBuf::from(p));
    let enricher = adapters::container::LxcEnricher::new(
        path(&lxc.proxmox_dir),
        path(&lxc.incus_socket),
        lxc.timeout_ms,
        adapters::container::DockerCache::new(
            lxc.cache_size,
            std::time::Duration::from_secs(lxc.cache_ttl_seconds),
        ),
    );
    (EnricherState::On, Some(Arc::new(enricher)))
}

#[allow(clippy::too_many_lines, clippy::similar_names)]
pub fn build_services(config: &AgentConfig) -> anyhow::Result<ServiceHandles> {
    // ── Metrics ──────────────────────────────────────────────────
    let metrics = Arc::new(AgentMetrics::new());
    let ebpf_loaded = Arc::new(AtomicBool::new(false));

    // ── Firewall ─────────────────────────────────────────────────
    let firewall_mode = config.firewall_mode()?;
    let domain_rules = config.firewall_rules()?;
    // The rules go in through the service rather than straight into the
    // engine, because the service is what adds the anti-lockout rules.
    let mut svc = FirewallAppService::new(
        FirewallEngine::new(),
        None,
        Arc::clone(&metrics) as Arc<dyn MetricsPort>,
    );
    svc.set_mode(firewall_mode);
    svc.set_interface_scope(startup::firewall_interface_scope(config));
    svc.set_anti_lockout(startup::firewall_anti_lockout(config));
    svc.reload_rules(domain_rules)?;
    let rule_count = svc.list_rules().len();
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
    let ids_workload_scope = startup::ids_workload_scope_service(config);
    ids_svc.set_workload_scope(Arc::clone(&ids_workload_scope));
    ids_svc.set_mode(ids_mode);
    ids_svc.set_enabled(config.ids.enabled);
    ids_svc.set_sampling(config.ids_sampling()?);
    if config.ids.enabled {
        ids_svc.set_suricata_imports(config.ids_suricata_reports());
    }
    let ids_svc = Arc::new(ArcSwap::from_pointee(ids_svc));
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
    ips_svc.set_sampling(config.ips_sampling()?);
    ips_svc.reload_whitelist(ips_whitelist);
    ips_svc.reload_rules(ips_rules.clone())?;
    let ips_svc = Arc::new(ArcSwap::from_pointee(ips_svc));

    // IPS rules are matched by the same kernel program as the IDS rules, so
    // the service that owns the pattern maps carries both sets.
    application::ids_service_impl::install_prevention_rules(&ids_svc, ips_rules)?;

    // ── L7 ───────────────────────────────────────────────────────
    let l7_domain_rules = config.l7_rules()?;
    let mut l7_engine = L7Engine::new();
    if config.l7.enabled {
        l7_engine.reload(l7_domain_rules)?;
    }
    let mut l7_svc = L7AppService::new(l7_engine, Arc::clone(&metrics) as Arc<dyn MetricsPort>);
    l7_svc.set_enabled(config.l7.enabled);
    let l7_svc = Arc::new(ArcSwap::from_pointee(l7_svc));

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
    let ddos_svc = Arc::new(ArcSwap::from_pointee(ddos_svc));

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
    // The built-in patterns, with whatever the config restates folded in.
    if config.dlp.enabled {
        dlp_engine.reload(config.dlp_patterns()?)?;
    }
    let mut dlp_svc = DlpAppService::new(dlp_engine, Arc::clone(&metrics) as Arc<dyn MetricsPort>);
    // Block mode is enterprise-only and the config validator has already
    // refused it, so this only ever sets alert on an OSS agent.
    dlp_svc.set_mode(config.dlp_mode()?)?;
    dlp_svc.set_enabled(config.dlp.enabled);
    let dlp_svc = Arc::new(ArcSwap::from_pointee(dlp_svc));
    let dlp_scope_svc = build_dlp_scope_service(config)?;

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
    let alias_resolver: Arc<dyn AliasResolutionPort> = Arc::new(alias_resolver);
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
    let ti_svc = Arc::new(ArcSwap::from_pointee(ti_svc));

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
    let audit_svc = Arc::new(audit_svc);

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

    let remote_identities =
        Arc::new(application::remote_identity_store::RemoteIdentityStore::new());
    let cgroup_shaping = startup::cgroup_shaping_service(config, &metrics)?;
    let guests = startup::guest_inventory_service(config, &ids_workload_scope);
    let vip_svc = startup::vip_announcer_service(config, &metrics);
    Ok(ServiceHandles {
        firewall_svc,
        ids_svc,
        ids_workload_scope,
        ips_svc,
        rl_svc,
        ti_svc,
        dns_blocklist_svc,
        l7_svc,
        ddos_svc,
        dlp_svc,
        dlp_scope_svc,
        conntrack_svc,
        nat_svc,
        lb_svc,
        qos_svc,
        cgroup_shaping,
        vip_svc,
        zone_svc,
        alias_svc,
        alias_resolver,
        routing_svc,
        schedule_svc,
        audit_svc,
        dns_cache_svc,
        // Nothing is loaded here, so there is no map to arm through: the
        // capability exists only where the object was loaded and attached.
        process_signal_svc: None,
        quarantine_svc: None,
        workloads: {
            let workloads = application::workload_resolver::WorkloadResolver::new();
            workloads.install_remote(Arc::clone(&remote_identities));
            workloads
        },
        metrics,
        ebpf_loaded,
        remote_identities,
        pod_coverage: Arc::new(application::pod_coverage_service::PodCoverageService::new()),
        guests,
        link_processes: Arc::new(ProcessRelay::new()),
    })
}

// ── eBPF lifecycle ──────────────────────────────────────────────

use adapters::ebpf::{
    EbpfLoader, IdsMirrorMapManager, InterfaceGroupsManager, MetricsReader, RingBufObserver,
    TenantCgroupMapManager, TenantIfindexMapManager, TenantSubnetMapManager, TenantVlanMapManager,
};
use application::packet_pipeline::AgentEvent;
use tokio::sync::mpsc;

use crate::reload::EbpfMapHolder;
use crate::startup::{self, EbpfState};

/// Result of loading all eBPF programs.
pub struct EbpfLoadResult {
    /// eBPF loaders - dropping this detaches all programs.
    pub state: EbpfState,
    /// Map managers needed for config hot-reload.
    pub map_holder: EbpfMapHolder,
    /// Per-program kernel metrics readers.
    pub metrics_readers: Vec<MetricsReader>,
    /// Per-program load status.
    pub program_status: std::collections::HashMap<String, bool>,
    /// Receive end of the event channel (for the event dispatcher).
    ///
    /// Wrapped in `Option` so a caller can `take()` it out to drive an event
    /// dispatcher while keeping the rest of the result (map managers, loader
    /// state) alive. `None` once taken.
    pub event_rx: Option<mpsc::Receiver<AgentEvent>>,
    /// Manager for `TENANT_VLAN_MAP` maps across all loaded programs.
    ///
    /// Enterprise callers can populate this with `(vlan_id, tenant_id)` pairs
    /// after loading to wire multi-tenant VLAN identification.
    pub tenant_vlan_mgr: TenantVlanMapManager,
    /// Manager for `TENANT_IFINDEX_MAP` maps across all loaded programs.
    ///
    /// Enterprise callers populate this with `(ifindex, tenant_id)` pairs after
    /// loading to wire interface-based tenant identification, which the kernel
    /// consults after the VLAN map and before the subnet tries.
    pub tenant_ifindex_mgr: TenantIfindexMapManager,
    /// Offset-driven DLP uprobe attacher, present when `uprobe-dlp` loaded.
    ///
    /// The OSS scan finds a TLS library by its exported `SSL_write` /
    /// `SSL_read`. A caller that resolved a library's write and read entry
    /// points some other way - a `GnuTLS` build, a statically linked `BoringSSL` -
    /// attaches through this one instead. It is held here, with the generation
    /// that loaded the programs, so a teardown detaches those probes with all
    /// the others rather than leaving links on a program nothing else owns.
    pub extended_tls_attacher: Option<adapters::ebpf::DlpUprobeAttacher>,
    /// Manager for `TENANT_SUBNET_V4` LPM trie maps across all loaded programs.
    ///
    /// Enterprise callers can populate this with `(ip, prefix_len, tenant_id)`
    /// tuples after loading to wire subnet-based tenant identification.
    pub tenant_subnet_mgr: TenantSubnetMapManager,
    /// Manager for the `TENANT_CGROUP_MAP` map in `tc-ids`.
    ///
    /// Enterprise callers populate this with `(cgroup_id, tenant_id)` pairs to
    /// attribute a container's egress traffic to its tenant, and drop the entry
    /// when the container exits. Cgroup resolution is the last fallback in the
    /// kernel's order and only fires on egress, where the skb still carries the
    /// originating socket.
    pub tenant_cgroup_mgr: TenantCgroupMapManager,
    /// Manager for the `IDS_MIRROR_CONFIG` map in `tc-ids`.
    ///
    /// Present only when `tc-ids` was loaded successfully. Enterprise callers
    /// use this to enable/disable forensic packet mirroring at runtime without
    /// reloading the eBPF program.
    pub ids_mirror_mgr: Option<IdsMirrorMapManager>,
    /// The guard on this generation's own maps and links, `None` where the
    /// BPF LSM is not active. Declared last so it is dropped after every
    /// other field: until then no other task is handed a descriptor to the
    /// generation's objects.
    pub bpf_guard: Option<adapters::ebpf::bpf_guard::BpfGuardAttacher>,
}

/// What a trace in `direction` runs on the generation `loaders` hold:
/// duplicates of the loaded programs' fds, in the order the hooks run them,
/// and the programs of that direction the generation did not load, which is
/// all of them when nothing is loaded. `ids_egress` is whether the IDS
/// classifier is attached on egress as well.
#[must_use]
pub fn trace_plan(
    loaders: &[EbpfLoader],
    direction: domain::trace::TraceDirection,
    ids_egress: bool,
) -> adapters::ebpf::datapath_trace::TracePlan {
    use adapters::ebpf::datapath_trace::{TracePlan, TracedProgram};
    use domain::trace::{TraceDirection, TraceHook};
    let fd = |name: &str| {
        loaders
            .iter()
            .find_map(|loader| loader.program_fd_owned(name))
    };
    let mut plan = TracePlan::default();
    let mut take = |name: &str, hook: TraceHook| match fd(name) {
        Some(fd) => plan.programs.push(TracedProgram {
            name: name.to_string(),
            hook,
            fd,
        }),
        None => plan.not_loaded.push(name.to_string()),
    };
    match direction {
        TraceDirection::Ingress => {
            // The XDP entry program follows the tail calls itself, so
            // only the first one attached is run.
            let root = crate::ebpf_lifecycle::XDP_ROOTS
                .iter()
                .find(|name| fd(name).is_some())
                .unwrap_or(&crate::ebpf_lifecycle::XDP_ROOTS[0]);
            take(root, TraceHook::Xdp);
            for (_, name) in crate::ebpf_lifecycle::TC_INGRESS {
                take(name, TraceHook::TcIngress);
            }
            take("tc_qos_ingress", TraceHook::TcIngress);
        }
        TraceDirection::Egress => {
            if ids_egress {
                take("tc_ids", TraceHook::TcEgress);
            }
            take("tc_nat_egress", TraceHook::TcEgress);
            take("tc_qos", TraceHook::TcEgress);
        }
    }
    plan
}

/// Hand the firewall's shared maps to the services that write into them.
///
/// The pins were wiped before this load, so every map here is new and the
/// services still hold managers over the previous generation's. A fresh
/// coordinator is correct for the same reason: the tries it tracks start
/// empty, and each service puts back what it kept - the IPS its blacklist,
/// the anti-DDoS service its country blocks, the alias service its external
/// sets - before the resolved aliases are handed to the firewall.
async fn wire_firewall_consumers(services: &ServiceHandles, loader: &mut EbpfLoader) {
    match adapters::ebpf::LpmCoordinator::new(loader.ebpf_mut()) {
        Ok(coordinator) => {
            let coordinator: Arc<dyn LpmCoordinatorPort> = Arc::new(coordinator);
            services
                .alias_svc
                .write()
                .await
                .set_lpm_coordinator(Arc::clone(&coordinator));
            let mut ddos = (**services.ddos_svc.load()).clone();
            ddos.set_lpm_coordinator(Arc::clone(&coordinator));
            ddos.set_alias_resolution(Arc::clone(&services.alias_resolver));
            ddos.reinstall_country_blocks();
            services.ddos_svc.store(Arc::new(ddos));
            let mut ips = (**services.ips_svc.load()).clone();
            ips.set_lpm_coordinator(coordinator);
            services.ips_svc.store(Arc::new(ips));
        }
        Err(e) => warn!("LPM coordinator maps not available (non-fatal): {e}"),
    }

    if let Ok(ipset_mgr) = adapters::ebpf::IpSetMapManager::new(loader.ebpf_mut()) {
        services
            .alias_svc
            .write()
            .await
            .set_ipset_port(Box::new(ipset_mgr));
    }

    let mut aliases = services.alias_svc.write().await;
    if let Err(e) = aliases.refresh_dynamic() {
        warn!("dynamic alias refresh after firewall load failed: {e}");
    }
    let bindings = application::firewall_aliases::collect_bindings(&aliases);
    drop(aliases);
    services
        .firewall_svc
        .write()
        .await
        .set_alias_bindings(bindings);
}

/// Load and attach all eBPF programs, wiring map managers to services.
///
/// Returns an [`EbpfLoadResult`] whose `state` field must be kept alive
/// for the programs to remain attached. Dropping it detaches everything.
///
/// # Errors
///
/// Individual program failures are non-fatal (graceful degradation).
/// Returns `Err` only if a critical setup step fails.
#[allow(clippy::too_many_lines)]
pub async fn load_ebpf_programs(
    config: &AgentConfig,
    services: &ServiceHandles,
) -> anyhow::Result<EbpfLoadResult> {
    let ebpf_dir = startup::resolve_ebpf_program_dir(config);
    // An HA activate lands here after some other node's deactivate, or after
    // this node's own. Either way the pins on this host belong to a generation
    // that is gone and cannot be interrogated, so they go.
    EbpfLoader::cleanup_pin_path_because(
        adapters::ebpf::DEFAULT_BPF_PIN_PATH,
        "activate: pins from the previous generation",
    );
    EbpfLoader::cleanup_pin_path_because(
        startup::DLP_PIN_PATH,
        "activate: pins from the previous generation",
    );

    // The kernel-filled tables take their capacity from the configuration at
    // create time, so the plan has to be in force before the first object is
    // loaded. The process keeps the first plan it was given: a later
    // configuration that sizes them differently is reported, and applies
    // when the agent next starts.
    let sizing = adapters::ebpf::map_sizing::MapSizing::from_config(config);
    match adapters::ebpf::map_sizing::install(&sizing) {
        Ok(()) => info!(plan = %sizing.describe(), "eBPF table capacities"),
        Err(in_force) => warn!(
            in_force = %in_force.describe(),
            configured = %sizing.describe(),
            "eBPF table capacities changed in the configuration; they apply at the next agent start"
        ),
    }

    let mut ebpf_state = EbpfState::new();
    // Every task spawned below outlives the loaders unless something stops
    // it, and each one holds a map taken out of this generation. Hand them
    // the state's token so a detach closes their descriptors with it.
    let readers = ebpf_state.readers.clone();
    let mut ebpf_map_holder = EbpfMapHolder::new();
    let mut metrics_readers: Vec<MetricsReader> = Vec::new();
    let mut iface_groups_mgr = InterfaceGroupsManager::new();
    let mut tenant_vlan_mgr = TenantVlanMapManager::new();
    let mut tenant_ifindex_mgr = TenantIfindexMapManager::new();
    let mut extended_tls_attacher: Option<adapters::ebpf::DlpUprobeAttacher> = None;
    let mut tenant_subnet_mgr = TenantSubnetMapManager::new();
    let mut tenant_cgroup_mgr = TenantCgroupMapManager::new();
    let mut program_status = std::collections::HashMap::new();
    let mut ids_mirror_mgr: Option<IdsMirrorMapManager> = None;

    let (event_tx, event_rx) = mpsc::channel::<AgentEvent>(4096);

    // ── XDP Firewall ────────────────────────────────────────────
    let mut fw_loader: Option<EbpfLoader> = None;
    let fw_ok = if config.firewall.enabled {
        match startup::try_load_xdp_firewall(&ebpf_dir, config) {
            Ok((mut loader, map_manager, fw_metrics_rdr, reader, zone_mgr, zone_rdrs)) => {
                let event_tx_clone = event_tx.clone();
                let rb_obs = RingBufObserver::new(
                    "xdp-firewall",
                    Arc::clone(&services.metrics) as Arc<dyn MetricsPort>,
                );
                let task_cancel_1 = readers.clone();
                tokio::spawn(async move {
                    reader.run(event_tx_clone, task_cancel_1, rb_obs).await;
                });
                let mut svc = services.firewall_svc.write().await;
                svc.set_map_port(Box::new(map_manager));
                // The loader wrote the catch-all byte into the map; the service
                // needs to know it too, because the deny-all posture overwrites
                // it and has to put this one back.
                svc.set_default_policy(startup::firewall_policy_byte(
                    config.firewall.default_policy,
                ));
                if let Some(rdr) = fw_metrics_rdr {
                    metrics_readers.push(rdr);
                }
                if let Some(mgr) = zone_mgr {
                    // Zoning decides nothing until the maps carry it.
                    services.zone_svc.write().await.set_map_port(Box::new(mgr));
                }
                drop(svc);
                if let Some((passed, dropped)) = zone_rdrs {
                    let zones = Arc::clone(&services.zone_svc);
                    let metrics = Arc::clone(&services.metrics) as Arc<dyn MetricsPort>;
                    let c = readers.clone();
                    tokio::spawn(async move {
                        crate::ebpf_metrics::run_zone_metrics_loop(
                            passed,
                            dropped,
                            zones,
                            metrics,
                            std::time::Duration::from_secs(10),
                            c,
                        )
                        .await;
                    });
                }
                wire_firewall_consumers(services, &mut loader).await;
                services
                    .metrics
                    .set_ebpf_program_status("xdp_firewall", true);
                services.ebpf_loaded.store(true, Ordering::Relaxed);
                fw_loader = Some(loader);
                true
            }
            Err(e) => {
                warn!("xdp-firewall load failed (degraded mode): {e}");
                services
                    .metrics
                    .set_ebpf_program_status("xdp_firewall", false);
                false
            }
        }
    } else {
        // A reload that turns a feature off would otherwise leave the gauge
        // frozen at the value the program last had, which reads as a datapath
        // still running what has just been detached.
        services.metrics.clear_ebpf_program_status("xdp_firewall");
        false
    };
    program_status.insert("xdp_firewall".to_string(), fw_ok);

    // ── XDP Rate Limiter ────────────────────────────────────────
    let rl_ok = if config.ratelimit.enabled {
        match startup::try_load_xdp_ratelimit(&ebpf_dir, config, fw_ok) {
            Ok((mut rl_loader, rl_mgr_opt, rl_lpm_opt, rl_rdrs, reader)) => {
                let event_tx_clone = event_tx.clone();
                let rb_obs = RingBufObserver::new(
                    "xdp-ratelimit",
                    Arc::clone(&services.metrics) as Arc<dyn MetricsPort>,
                );
                let task_cancel_2 = readers.clone();
                tokio::spawn(async move {
                    reader.run(event_tx_clone, task_cancel_2, rb_obs).await;
                });
                metrics_readers.extend(rl_rdrs);
                if let Some(rl_mgr) = rl_mgr_opt {
                    let mut svc = services.rl_svc.write().await;
                    let default_algo =
                        startup::parse_algorithm_byte(&config.ratelimit.default_algorithm);
                    svc.set_defaults(
                        config.ratelimit.default_rate,
                        config.ratelimit.default_burst,
                        default_algo,
                    );
                    svc.set_map_port(Box::new(rl_mgr));
                }
                if let Some(rl_lpm) = rl_lpm_opt {
                    // The pins were wiped before this load, so the country
                    // tiers go into maps that start empty.
                    let mut svc = services.rl_svc.write().await;
                    svc.set_lpm_port(Box::new(rl_lpm));
                    svc.set_alias_resolution(Arc::clone(&services.alias_resolver));
                    match config.ratelimit_country_tiers() {
                        Ok(tiers) if !tiers.is_empty() => {
                            if let Err(e) = svc.reload_country_tiers(&tiers) {
                                warn!("country tier load failed (non-fatal): {e}");
                            }
                        }
                        Ok(_) => {}
                        Err(e) => warn!("country tiers unreadable: {e}"),
                    }
                }
                // Wire tail-call: firewall → ratelimit
                if let Some(ref mut fw) = fw_loader
                    && let Ok(rl_fd) = rl_loader.program_raw_fd("xdp_ratelimit")
                {
                    let _ = fw.set_tail_call_raw("XDP_PROG_ARRAY", 0, rl_fd);
                }
                iface_groups_mgr.add_map(rl_loader.ebpf_mut());
                tenant_vlan_mgr.add_map(rl_loader.ebpf_mut());
                tenant_ifindex_mgr.add_map(rl_loader.ebpf_mut());
                tenant_subnet_mgr.add_map(rl_loader.ebpf_mut());
                tenant_subnet_mgr.add_v6_map(rl_loader.ebpf_mut());
                ebpf_state.add_loader(rl_loader);
                true
            }
            Err(e) => {
                warn!("xdp-ratelimit load failed (degraded mode): {e}");
                false
            }
        }
    } else {
        services.metrics.clear_ebpf_program_status("xdp_ratelimit");
        false
    };
    program_status.insert("xdp_ratelimit".to_string(), rl_ok);

    // Take INTERFACE_GROUPS and tenant maps from xdp-firewall before moving loader
    if let Some(ref mut loader) = fw_loader {
        iface_groups_mgr.add_map(loader.ebpf_mut());
        tenant_vlan_mgr.add_map(loader.ebpf_mut());
        tenant_ifindex_mgr.add_map(loader.ebpf_mut());
        tenant_subnet_mgr.add_map(loader.ebpf_mut());
        tenant_subnet_mgr.add_v6_map(loader.ebpf_mut());
    }
    // ── XDP VIP announcer, reached through the firewall's ARP slot ──
    let vip_ok = load_vip_announcer(config, services, &ebpf_dir, fw_loader.as_mut(), &readers)
        .await
        .map(|loader| ebpf_state.add_loader(loader))
        .is_some();
    program_status.insert("xdp_vip_announcer".to_string(), vip_ok);
    if let Some(loader) = fw_loader {
        ebpf_state.add_loader(loader);
    }

    // ── TC IDS ──────────────────────────────────────────────────
    let ids_ok = if config.ids.enabled {
        match startup::try_load_tc_ids(&ebpf_dir, config) {
            Ok((mut loader, ids_mgr_opt, l7_mgr_opt, cfg_mgr_opt, ids_rdr, reader)) => {
                let event_tx_clone = event_tx.clone();
                let rb_obs = RingBufObserver::new(
                    "tc-ids",
                    Arc::clone(&services.metrics) as Arc<dyn MetricsPort>,
                );
                let task_cancel_3 = readers.clone();
                tokio::spawn(async move {
                    reader.run(event_tx_clone, task_cancel_3, rb_obs).await;
                });
                startup::install_ids_workload_scope(&services.ids_workload_scope, &mut loader);
                if let Some(ids_mgr) = ids_mgr_opt {
                    let mut svc = (**services.ids_svc.load()).clone();
                    svc.set_map_port(Box::new(ids_mgr));
                    services.ids_svc.store(Arc::new(svc));
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
                // Take IDS_MIRROR_CONFIG before consuming the loader.
                // Enterprise callers use this to enable/disable forensic
                // packet mirroring at runtime without reloading tc-ids.
                ids_mirror_mgr = IdsMirrorMapManager::new(loader.ebpf_mut());
                iface_groups_mgr.add_map(loader.ebpf_mut());
                tenant_vlan_mgr.add_map(loader.ebpf_mut());
                tenant_ifindex_mgr.add_map(loader.ebpf_mut());
                tenant_subnet_mgr.add_map(loader.ebpf_mut());
                tenant_subnet_mgr.add_v6_map(loader.ebpf_mut());
                tenant_cgroup_mgr.add_map(loader.ebpf_mut());
                ebpf_state.add_loader(loader);
                true
            }
            Err(e) => {
                warn!("tc-ids load failed (degraded mode): {e}");
                false
            }
        }
    } else {
        services.metrics.clear_ebpf_program_status("tc_ids");
        false
    };
    program_status.insert("tc_ids".to_string(), ids_ok);

    // ── TC Threat Intel ─────────────────────────────────────────
    let ti_ok = if config.threatintel.enabled {
        match startup::try_load_tc_threatintel(&ebpf_dir, config) {
            Ok((mut loader, ti_mgr_opt, cfg_mgr_opt, ti_rdr, reader)) => {
                let event_tx_clone = event_tx.clone();
                let rb_obs = RingBufObserver::new(
                    "tc-threatintel",
                    Arc::clone(&services.metrics) as Arc<dyn MetricsPort>,
                );
                let task_cancel_4 = readers.clone();
                tokio::spawn(async move {
                    reader.run(event_tx_clone, task_cancel_4, rb_obs).await;
                });
                if let Some(rdr) = ti_rdr {
                    metrics_readers.push(rdr);
                }
                if let Some(ti_mgr) = ti_mgr_opt {
                    let mut svc = (**services.ti_svc.load()).clone();
                    svc.set_map_port(Box::new(ti_mgr));
                    services.ti_svc.store(Arc::new(svc));
                }
                if let Some(cfg_mgr) = cfg_mgr_opt {
                    ebpf_map_holder
                        .config_flags
                        .push(("tc_threatintel", cfg_mgr));
                }
                tenant_vlan_mgr.add_map(loader.ebpf_mut());
                tenant_ifindex_mgr.add_map(loader.ebpf_mut());
                ebpf_state.add_loader(loader);
                true
            }
            Err(e) => {
                warn!("tc-threatintel load failed (degraded mode): {e}");
                false
            }
        }
    } else {
        services.metrics.clear_ebpf_program_status("tc_threatintel");
        false
    };
    program_status.insert("tc_threatintel".to_string(), ti_ok);

    // ── TC DNS ──────────────────────────────────────────────────
    let dns_ok = if config.dns.enabled {
        match startup::try_load_tc_dns(&ebpf_dir, config) {
            Ok((mut loader, dns_rdr, reader)) => {
                let event_tx_clone = event_tx.clone();
                let rb_obs = RingBufObserver::new(
                    "tc-dns",
                    Arc::clone(&services.metrics) as Arc<dyn MetricsPort>,
                );
                let task_cancel_5 = readers.clone();
                tokio::spawn(async move {
                    reader.run(event_tx_clone, task_cancel_5, rb_obs).await;
                });
                if let Some(rdr) = dns_rdr {
                    metrics_readers.push(rdr);
                }
                tenant_vlan_mgr.add_map(loader.ebpf_mut());
                tenant_ifindex_mgr.add_map(loader.ebpf_mut());
                ebpf_state.add_loader(loader);
                true
            }
            Err(e) => {
                warn!("tc-dns load failed (degraded mode): {e}");
                false
            }
        }
    } else {
        services.metrics.clear_ebpf_program_status("tc_dns");
        false
    };
    program_status.insert("tc_dns".to_string(), dns_ok);

    // ── Uprobe DLP ──────────────────────────────────────────────
    let dlp_ok = if config.dlp.enabled {
        match startup::try_load_uprobe_dlp(
            &ebpf_dir,
            config,
            startup::DLP_PIN_PATH,
            services.dlp_scope_svc.as_ref(),
        ) {
            Ok((mut loader, dlp_rdr, reader, attacher, extended)) => {
                extended_tls_attacher = Some(extended);
                let event_tx_clone = event_tx.clone();
                let rb_obs = RingBufObserver::new(
                    "uprobe-dlp",
                    Arc::clone(&services.metrics) as Arc<dyn MetricsPort>,
                );
                let task_cancel_6 = readers.clone();
                tokio::spawn(async move {
                    reader.run(event_tx_clone, task_cancel_6, rb_obs).await;
                });
                // Lifecycle watcher: attach SSL uprobes to containers as they
                // appear and detach them on teardown.
                let task_cancel_7 = readers.clone();
                tokio::spawn(async move {
                    attacher
                        .watch(adapters::ebpf::DLP_ATTACH_POLL_INTERVAL, task_cancel_7)
                        .await;
                });
                if let Some(rdr) = dlp_rdr {
                    metrics_readers.push(rdr);
                }
                // The maps are installed, so the selectors can start widening
                // the scope from the configured cgroups to the workloads they
                // name. Shares the readers' cancel, so an unload stops it.
                if let Some(scope) = services.dlp_scope_svc.clone() {
                    let scope_cancel = readers.clone();
                    let refresh = std::time::Duration::from_secs(config.dlp.scope.refresh_seconds);
                    tokio::spawn(async move {
                        scope.watch(refresh, scope_cancel).await;
                    });
                }
                tenant_vlan_mgr.add_map(loader.ebpf_mut());
                tenant_ifindex_mgr.add_map(loader.ebpf_mut());
                ebpf_state.add_loader(loader);
                true
            }
            Err(e) => {
                warn!("uprobe-dlp load failed (degraded mode): {e}");
                false
            }
        }
    } else {
        services.metrics.clear_ebpf_program_status("uprobe_dlp");
        false
    };
    program_status.insert("uprobe_dlp".to_string(), dlp_ok);

    // ── Socket attribution ──────────────────────────────────────
    // Loaded here as well as at start-up, so a binary that drives the
    // datapath through this function names the workload behind a flow too.
    // The links and the socket tables belong to this generation: the state
    // holds the attacher and empties the resolver when it is dropped.
    let attribution_ok = if config.attribution.enabled {
        match startup::try_load_cgroup_attribution(&ebpf_dir, config) {
            Ok((loader, metrics_rdr, socket_reader, attacher, status)) => {
                if status.attached {
                    if let Some(rdr) = metrics_rdr {
                        metrics_readers.push(rdr);
                    }
                    if let Some(reader) = socket_reader {
                        services.workloads.install_sockets(Box::new(reader));
                        ebpf_state.workloads = Some(services.workloads.clone());
                    }
                    ebpf_state.attribution = Some(attacher);
                    ebpf_state.add_loader(loader);
                    services
                        .metrics
                        .set_ebpf_program_status("cgroup_attribution", true);
                    true
                } else {
                    services
                        .metrics
                        .set_ebpf_program_status("cgroup_attribution", false);
                    false
                }
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
                services
                    .metrics
                    .set_ebpf_program_status("cgroup_attribution", false);
                false
            }
        }
    } else {
        services
            .metrics
            .clear_ebpf_program_status("cgroup_attribution");
        adapters::ebpf::attribution_attach::publish_status(
            adapters::ebpf::AttributionStatus::default(),
        );
        false
    };
    program_status.insert("cgroup_attribution".to_string(), attribution_ok);

    // ── TC ConnTrack ────────────────────────────────────────────
    let ct_ok = if config.conntrack.enabled {
        match startup::try_load_tc_conntrack(&ebpf_dir, config) {
            Ok((mut loader, ct_mgr, ct_rdr, opt_reader)) => {
                if let Some(reader) = opt_reader {
                    let event_tx_clone = event_tx.clone();
                    let rb_obs = RingBufObserver::new(
                        "tc-conntrack",
                        Arc::clone(&services.metrics) as Arc<dyn MetricsPort>,
                    );
                    let task_cancel_8 = readers.clone();
                    tokio::spawn(async move {
                        reader.run(event_tx_clone, task_cancel_8, rb_obs).await;
                    });
                }
                services
                    .conntrack_svc
                    .write()
                    .await
                    .set_map_port(Box::new(ct_mgr));
                if let Some(rdr) = ct_rdr {
                    metrics_readers.push(rdr);
                }
                tenant_vlan_mgr.add_map(loader.ebpf_mut());
                tenant_ifindex_mgr.add_map(loader.ebpf_mut());
                ebpf_state.add_loader(loader);
                true
            }
            Err(e) => {
                warn!("tc-conntrack load failed (degraded mode): {e}");
                false
            }
        }
    } else {
        services.metrics.clear_ebpf_program_status("tc_conntrack");
        false
    };
    program_status.insert("tc_conntrack".to_string(), ct_ok);

    // ── TC NAT ──────────────────────────────────────────────────
    let nat_ok = if config.nat.enabled {
        match startup::try_load_tc_nat(&ebpf_dir, config) {
            Ok((mut ingress_loader, mut egress_loader, nat_mgr, nat_rdrs)) => {
                metrics_readers.extend(nat_rdrs);
                services
                    .nat_svc
                    .write()
                    .await
                    .set_map_port(Box::new(nat_mgr));
                iface_groups_mgr.add_map(ingress_loader.ebpf_mut());
                iface_groups_mgr.add_map(egress_loader.ebpf_mut());
                tenant_vlan_mgr.add_map(ingress_loader.ebpf_mut());
                tenant_ifindex_mgr.add_map(ingress_loader.ebpf_mut());
                tenant_vlan_mgr.add_map(egress_loader.ebpf_mut());
                tenant_ifindex_mgr.add_map(egress_loader.ebpf_mut());
                tenant_subnet_mgr.add_map(ingress_loader.ebpf_mut());
                tenant_subnet_mgr.add_v6_map(ingress_loader.ebpf_mut());
                tenant_subnet_mgr.add_map(egress_loader.ebpf_mut());
                tenant_subnet_mgr.add_v6_map(egress_loader.ebpf_mut());
                ebpf_state.add_loader(ingress_loader);
                ebpf_state.add_loader(egress_loader);
                true
            }
            Err(e) => {
                warn!("tc-nat load failed (degraded mode): {e}");
                false
            }
        }
    } else {
        services.metrics.clear_ebpf_program_status("tc_nat_ingress");
        services.metrics.clear_ebpf_program_status("tc_nat_egress");
        false
    };
    program_status.insert("tc_nat_ingress".to_string(), nat_ok);
    program_status.insert("tc_nat_egress".to_string(), nat_ok);

    // ── TC Scrub ────────────────────────────────────────────────
    let scrub_ok = if config.firewall.scrub.enabled {
        match startup::try_load_tc_scrub(&ebpf_dir, config) {
            Ok((mut loader, scrub_rdr)) => {
                if let Some(rdr) = scrub_rdr {
                    metrics_readers.push(rdr);
                }
                tenant_vlan_mgr.add_map(loader.ebpf_mut());
                tenant_ifindex_mgr.add_map(loader.ebpf_mut());
                ebpf_state.add_loader(loader);
                true
            }
            Err(e) => {
                warn!("tc-scrub load failed (degraded mode): {e}");
                false
            }
        }
    } else {
        services.metrics.clear_ebpf_program_status("tc_scrub");
        false
    };
    program_status.insert("tc_scrub".to_string(), scrub_ok);

    // ── TC QoS ──────────────────────────────────────────────────
    let qos_ok = if config.qos.enabled {
        match startup::try_load_tc_qos(&ebpf_dir, config) {
            Ok((mut loader, qos_mgr, qos_rdr, opt_reader)) => {
                if let Some(reader) = opt_reader {
                    let event_tx_clone = event_tx.clone();
                    let rb_obs = RingBufObserver::new(
                        "tc-qos",
                        Arc::clone(&services.metrics) as Arc<dyn MetricsPort>,
                    );
                    let task_cancel = readers.clone();
                    tokio::spawn(async move {
                        reader.run(event_tx_clone, task_cancel, rb_obs).await;
                    });
                }
                {
                    let mut svc = services.qos_svc.write().await;
                    // Bind the maps, then resync the configuration so they
                    // carry the pipes, queues and classifiers it names.
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
                startup::install_cgroup_shaping(&services.cgroup_shaping, &mut loader);
                iface_groups_mgr.add_map(loader.ebpf_mut());
                tenant_vlan_mgr.add_map(loader.ebpf_mut());
                tenant_ifindex_mgr.add_map(loader.ebpf_mut());
                ebpf_state.add_loader(loader);
                info!("eBPF tc-qos active");
                true
            }
            Err(e) => {
                warn!("tc-qos load failed (degraded mode): {e}");
                services.cgroup_shaping.clear_maps();
                false
            }
        }
    } else {
        services.metrics.clear_ebpf_program_status("tc_qos");
        services.cgroup_shaping.clear_maps();
        false
    };
    program_status.insert("tc_qos".to_string(), qos_ok);
    if qos_ok && services.cgroup_shaping.supported() {
        // The achieved rate is the bytes counted between two reads over the
        // time between them, on the agent's own monotonic clock.
        let polling = Arc::clone(&services.cgroup_shaping);
        let poll_cancel = readers.clone();
        tokio::spawn(async move {
            let started = std::time::Instant::now();
            let mut ticker =
                tokio::time::interval(infrastructure::constants::CGROUP_SHAPING_READ_INTERVAL);
            loop {
                tokio::select! {
                    () = poll_cancel.cancelled() => break,
                    _ = ticker.tick() => {}
                }
                let now_ns = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
                polling.poll(now_ns);
            }
        });
    }

    // ── XDP Load Balancer ───────────────────────────────────────
    let lb_ok = if config.loadbalancer.enabled {
        match startup::try_load_xdp_loadbalancer(&ebpf_dir, config, fw_ok || rl_ok) {
            Ok((mut loader, lb_mgr, lb_metrics_rdr, reader)) => {
                let event_tx_clone = event_tx.clone();
                let rb_obs = RingBufObserver::new(
                    "xdp-loadbalancer",
                    Arc::clone(&services.metrics) as Arc<dyn MetricsPort>,
                );
                let task_cancel_9 = readers.clone();
                tokio::spawn(async move {
                    reader.run(event_tx_clone, task_cancel_9, rb_obs).await;
                });
                services.lb_svc.write().await.set_map_port(Box::new(lb_mgr));
                if let Some(rdr) = lb_metrics_rdr {
                    metrics_readers.push(rdr);
                }
                tenant_vlan_mgr.add_map(loader.ebpf_mut());
                tenant_ifindex_mgr.add_map(loader.ebpf_mut());
                ebpf_state.add_loader(loader);
                true
            }
            Err(e) => {
                warn!("xdp-loadbalancer load failed (degraded mode): {e}");
                false
            }
        }
    } else {
        services
            .metrics
            .clear_ebpf_program_status("xdp_loadbalancer");
        false
    };
    program_status.insert("xdp_loadbalancer".to_string(), lb_ok);

    // ── Populate interface groups across all programs ────────────
    {
        let membership = config.kernel_interface_membership();
        let memberships: Vec<(u32, u32)> = config
            .agent
            .interfaces
            .iter()
            .filter_map(|iface| {
                let ifindex = startup::get_ifindex(iface).ok()?;
                let groups = membership.get(iface).copied().unwrap_or(0);
                Some((ifindex, groups))
            })
            .collect();
        if let Err(e) = iface_groups_mgr.set_interface_groups(&memberships) {
            warn!("INTERFACE_GROUPS population failed (non-fatal): {e}");
        }
    }
    ebpf_map_holder.iface_groups = Some(iface_groups_mgr);

    // ── Workload links ──────────────────────────────────────────
    // The chain this generation loaded, attached on each workload link as it
    // appears, or inside each selected pod for a pod profile, for as long as
    // the generation lives.
    {
        use adapters::ebpf::link_watcher::HookSide;
        let loaded = |name: &str| program_status.get(name).copied().unwrap_or(false);
        let ids_egress = config.ids.inspect_egress || config.container.resolver.enabled;
        let wanted = [
            ("tc_ids", loaded("tc_ids"), HookSide::Ingress),
            (
                "tc_threatintel",
                loaded("tc_threatintel"),
                HookSide::Ingress,
            ),
            ("tc_dns", loaded("tc_dns"), HookSide::Ingress),
            ("tc_conntrack", loaded("tc_conntrack"), HookSide::Ingress),
            (
                "tc_nat_ingress",
                loaded("tc_nat_ingress"),
                HookSide::Ingress,
            ),
            ("tc_scrub", loaded("tc_scrub"), HookSide::Ingress),
            ("tc_qos_ingress", loaded("tc_qos"), HookSide::Ingress),
            ("tc_ids", loaded("tc_ids") && ids_egress, HookSide::Egress),
            ("tc_nat_egress", loaded("tc_nat_egress"), HookSide::Egress),
            ("tc_qos", loaded("tc_qos"), HookSide::Egress),
        ];
        let chain = startup::TcChain::collect(&wanted, ebpf_state.loaders.iter());
        if config.agent.profile == infrastructure::config::AgentProfile::Pod {
            startup::spawn_pod_tc_attacher(config, &services.pod_coverage, &chain, readers.clone());
        } else {
            startup::start_link_watcher(
                config,
                &chain,
                startup::LinkSinks {
                    ids_workload_scope: &services.ids_workload_scope,
                    cgroup_shaping: &services.cgroup_shaping,
                    pod_coverage: &services.pod_coverage,
                    guests: &services.guests,
                    processes: config
                        .process_table
                        .enabled
                        .then(|| services.link_processes.sender()),
                },
                &services.metrics,
                &readers,
            );
        }
    }

    info!(
        program_count = ebpf_state.loaders.len(),
        "eBPF programs loaded via load_ebpf_programs()"
    );

    // ── Guard ──────────────────────────────────────────────────
    // Loaded last, so that its first reading of the agent's descriptors
    // already names every object this generation loaded.
    let bpf_guard = match startup::start_bpf_guard(&ebpf_dir) {
        Ok(started) => {
            let startup::BpfGuardStarted {
                loader,
                metrics_rdr,
                maps,
                attacher,
                tasks,
            } = started;
            if let Some(rdr) = metrics_rdr {
                metrics_readers.push(rdr);
            }
            services
                .metrics
                .set_ebpf_program_status("lsm_bpf_guard", true);
            tokio::spawn(startup::refresh_bpf_guard(
                maps,
                tasks,
                readers.child_token(),
            ));
            ebpf_state.add_loader(loader);
            Some(attacher)
        }
        Err(reason) => {
            services
                .metrics
                .set_ebpf_program_status("lsm_bpf_guard", false);
            warn!(
                "the agent's maps and links are unprotected: any task holding CAP_SYS_ADMIN can detach or rewrite them; {reason}"
            );
            adapters::ebpf::bpf_guard::publish_status(adapters::ebpf::bpf_guard::BpfGuardStatus {
                reason: Some(reason),
                ..adapters::ebpf::bpf_guard::BpfGuardStatus::default()
            });
            None
        }
    };

    Ok(EbpfLoadResult {
        state: ebpf_state,
        map_holder: ebpf_map_holder,
        metrics_readers,
        program_status,
        event_rx: Some(event_rx),
        tenant_vlan_mgr,
        tenant_ifindex_mgr,
        extended_tls_attacher,
        tenant_subnet_mgr,
        tenant_cgroup_mgr,
        ids_mirror_mgr,
        bpf_guard,
    })
}

/// Detach all eBPF programs and clean up pinned maps.
pub fn detach_ebpf(state: EbpfState) {
    let count = state.loaders.len();
    drop(state);
    EbpfLoader::cleanup_pin_path_because(
        adapters::ebpf::DEFAULT_BPF_PIN_PATH,
        "deactivate: releasing this generation's state",
    );
    EbpfLoader::cleanup_pin_path_because(
        startup::DLP_PIN_PATH,
        "deactivate: releasing this generation's state",
    );
    // Blocks describe attachments that no longer exist. Carrying them into the
    // next activate would keep readiness pinned to a conflict the agent has
    // already stopped competing for.
    adapters::ebpf::clear_attach_blocks();
    // And for the map handles held for the fullness measurement: the maps died
    // with the loaders, so walking them would report a datapath that is gone.
    adapters::ebpf::clear_map_fills();
    // Same reasoning for the DLP uprobe set: the links died with the loaders, so
    // continuing to publish them would report TLS inspection that is not running.
    adapters::ebpf::clear_uprobe_inventory();
    info!(program_count = count, "eBPF programs detached");
}

// ── Host observation ────────────────────────────────────────────

/// The process table and the host rules evaluated on what it learns, kept
/// running for as long as this value is held.
///
/// Built apart from [`load_ebpf_programs`] because a host's processes are
/// observed on every node whatever its datapath role: a standby still runs
/// processes, and a rule watching them must not wait for a promotion.
pub struct HostObservation {
    /// The table every exec and exit lands in.
    pub processes: Arc<application::process_table_service::ProcessTableService>,
    /// The rules evaluated on it, with their shadow readings.
    pub host_rules: Arc<application::host_rule_service::HostRuleService>,
    /// The mass encryption verdict, fed by the file watch and the table;
    /// absent where the file watch is off.
    pub ransom: Option<Arc<application::ransom_service::RansomService>>,
    // The tracepoints stay attached while these live.
    _tracing: Option<(EbpfLoader, adapters::ebpf::ProcessTracingAttacher)>,
    // And the probes counting calls into the crypto libraries.
    _crypto: Option<EbpfLoader>,
}

/// Start the process table and the host rules, for a binary that does not
/// run the agent's own start-up path.
///
/// `None` when the configuration turns the process table off. A kernel that
/// refuses the tracepoints still gets the table and the rules, which then
/// learn nothing, and the reason is published where the host rule routes
/// read it, so every rule reports why it cannot match rather than sitting
/// silent. Matches go to `alerts`; the tasks end with `cancel`.
///
/// # Errors
///
/// Returns an error when the host rules do not compile, which validating the
/// configuration refuses first.
pub async fn start_host_observation(
    config: &AgentConfig,
    services: &ServiceHandles,
    alerts: mpsc::Sender<application::alert_event::AlertEvent>,
    workload: Option<&Arc<application::workload_policy_service::WorkloadPolicyService>>,
    cancel: tokio_util::sync::CancellationToken,
) -> anyhow::Result<Option<HostObservation>> {
    if !config.process_table.enabled {
        adapters::ebpf::process_attach::publish_status(adapters::ebpf::ProcessTracingStatus {
            attached: false,
            tracepoints: Vec::new(),
            reason: Some("the process table is turned off in the configuration".to_string()),
            command_line: false,
            lineage: false,
            lineage_reason: None,
        });
        return Ok(None);
    }
    let host_rules_set = config.host_rules.compile()?;
    let proc_root = startup::resolver_proc_path(
        &config.container.resolver.proc_path,
        &startup::host_proc_root(),
    );
    let (process_tx, process_rx) =
        mpsc::channel::<domain::process::entity::ProcessLifecycleEvent>(4096);

    services
        .link_processes
        .forward_to(process_tx.clone(), &cancel);
    let tracing = start_process_tracing(config, services, process_tx, &cancel);

    let mut table = process_table(config, services, &proc_root).await;
    let alerts_for_ransom = alerts.clone();
    let host_rules = Arc::new(
        application::host_rule_service::HostRuleService::new(host_rules_set, alerts).with_facts(
            Arc::new(adapters::container::ProcFactsReader::new(&proc_root)),
        ),
    );
    // Attached even with no rule: a binary running this path may hand the
    // service a set later, and an empty one costs a lookup per event.
    info!(
        rules = host_rules.rules().rules().len(),
        "host rules loaded"
    );
    table = table.with_host_rules(Arc::clone(&host_rules));
    // The mass encryption verdict lives where the file watch hands it each
    // change, and the table each exec whose command line destroys backups.
    let ransom = config
        .file_watch
        .enabled
        .then(|| startup::mass_encryption_service(config, alerts_for_ransom));
    if let Some(ref ransom) = ransom {
        table = table.with_ransom(Arc::clone(ransom));
    }
    // The table is where an exec is learned of, so it is where the kernel's
    // idea of which workload a task is gets written.
    if let Some(workload) = workload {
        table = table.with_workload_policy(Arc::clone(workload));
    }
    let processes = Arc::new(table);
    // A new policy renumbers the bits, so it is replayed over the tasks
    // already running rather than waiting for each of them to exec again.
    if let Some(workload) = workload {
        workload.watch_processes(&processes);
    }
    services.workloads.install_processes(Arc::clone(&processes));
    if let Some(ref ransom) = ransom {
        startup::install_mass_encryption_stop(
            config,
            ransom,
            services.process_signal_svc.as_ref(),
            &processes,
        );
    }
    // The calls into the crypto libraries are read against the same table,
    // so they are counted only where mass encryption is.
    let crypto = ransom.as_ref().and_then(|ransom| {
        startup::start_crypto_calls(
            &startup::resolve_ebpf_program_dir(config),
            &startup::host_proc_root(),
            &services.metrics,
            Arc::clone(ransom),
            Arc::clone(&processes),
            cancel.clone(),
        )
    });
    let writer = Arc::clone(&processes);
    tokio::spawn(async move {
        writer.run(process_rx, cancel).await;
    });
    info!(
        capacity = config.process_table.capacity,
        command_line = config.process_table.capture_command_line,
        "process table running"
    );
    Ok(Some(HostObservation {
        processes,
        host_rules,
        ransom,
        _tracing: tracing,
        _crypto: crypto,
    }))
}

/// The process table, resolving what each entry runs, where it runs and
/// which scopes read it, before any detection is attached to it.
async fn process_table(
    config: &AgentConfig,
    services: &ServiceHandles,
    proc_root: &std::path::Path,
) -> application::process_table_service::ProcessTableService {
    let mut table = application::process_table_service::ProcessTableService::new(
        config.process_table.capacity,
        config.process_table.capture_command_line,
    )
    .with_executables(Arc::new(adapters::container::ProcExecutableResolver::new(
        proc_root,
    )))
    .with_digester(Arc::new(adapters::container::ProcExecutableDigester::new(
        proc_root,
    )))
    .with_details(Arc::new(adapters::container::ProcDetailsResolver::new(
        proc_root,
    )))
    .with_ids_workload_scope(Arc::clone(&services.ids_workload_scope))
    .with_cgroup_shaping(Arc::clone(&services.cgroup_shaping));
    if let Some(resolver) = startup::container_resolver(config, proc_root) {
        table = table.with_containers(resolver);
    }
    for enricher in build_workload_enrichers(config).await {
        table = table.with_metadata_enricher(enricher);
    }
    if let Some(ref scope) = services.dlp_scope_svc
        && scope.needs_executables()
    {
        table = table.with_dlp_scope(Arc::clone(scope));
    }
    table
}

/// A workload firewall loaded for a binary that does not run the agent's own
/// start-up path. The hooks stay attached while this lives.
pub struct WorkloadFirewall {
    /// The policy in force, what it refused and the remote tables.
    pub service: Arc<application::workload_policy_service::WorkloadPolicyService>,
    /// Quarantining a workload, armed off the same object when the
    /// configuration turns it on: the response that cuts a workload off
    /// reaches the kernel through it, and refuses without it.
    pub quarantine: Option<Arc<application::quarantine_service::QuarantineService>>,
    /// What the cluster's `NetworkPolicy` lets a workload reach, read off
    /// the same cluster cache the policy is compiled from, when network
    /// policy is turned on and the cluster could be read.
    pub netpol_replay: Option<Arc<application::netpol_replay_service::NetpolReplayService>>,
    _loader: EbpfLoader,
    _attacher: adapters::ebpf::workload_firewall_attach::WorkloadFirewallAttacher,
}

/// Read what the package managers say is installed, in the host's root and
/// in every container's, through the warden when there is one, on the
/// configured interval until `cancel`. `None` when the reading is turned
/// off in the configuration.
#[must_use]
pub fn start_package_inventory(
    config: &AgentConfig,
    cancel: &tokio_util::sync::CancellationToken,
) -> Option<Arc<application::package_inventory_service::PackageInventoryService>> {
    if !config.package_inventory.enabled {
        return None;
    }
    let proc_root = startup::resolver_proc_path(
        &config.container.resolver.proc_path,
        &startup::host_proc_root(),
    );
    let reader = Arc::new(
        adapters::warden::package_inventory::WardenPackageReader::new(
            ebpfsentinel_warden::rooted_read::file_roots,
            ebpfsentinel_warden::rooted_read::read_rooted_file,
            ebpfsentinel_warden::go_executables::scan,
            ebpfsentinel_warden::process_maps::scan,
            proc_root,
        ),
    );
    let inventory =
        Arc::new(application::package_inventory_service::PackageInventoryService::new(reader));
    let interval = std::time::Duration::from_secs(config.package_inventory.interval_secs);
    info!(
        interval_secs = config.package_inventory.interval_secs,
        source = inventory.source(),
        "package inventory reading"
    );
    let running = Arc::clone(&inventory);
    let cancel = cancel.clone();
    tokio::spawn(async move {
        running.run(interval, cancel).await;
    });
    Some(inventory)
}

/// Load the workload firewall off the configuration's workload rules, for a
/// binary that does not run the agent's own start-up path.
///
/// `None` when the configuration carries no workload rule, arms no
/// quarantine and turns network policy off, or when the kernel refused the
/// hooks under a policy that only observes: the reason is published where the
/// status route reads it either way. The rules' DNS answers, refusals and
/// counters are read until `cancel`, the remote tables follow
/// `services.remote_identities`, and the cluster's `NetworkPolicy` is
/// compiled into the same object when the configuration turns it on.
///
/// # Errors
///
/// Returns an error when the rules do not convert, when the policy cannot be
/// written to the kernel's tables, and when the hooks did not attach, or the
/// cluster could not be read, under a policy that refuses: an agent reporting
/// healthy while a rule in the file enforces nothing is the outcome worth
/// refusing to start over.
pub async fn start_workload_firewall(
    config: &AgentConfig,
    services: &ServiceHandles,
    alerts: mpsc::Sender<application::alert_event::AlertEvent>,
    cancel: &tokio_util::sync::CancellationToken,
) -> anyhow::Result<Option<WorkloadFirewall>> {
    let policy = domain::firewall::workload::WorkloadPolicy::from_rules(&config.firewall_rules()?)?
        .with_dns(config.workload_dns()?)?;
    // A quarantine and `NetworkPolicy` ride on the same object, so turning
    // either on loads the object even while the file carries no workload
    // rule.
    let netpol_mode = config.container.kubernetes.network_policy.mode;
    let netpol_on = netpol_mode != infrastructure::config::NetworkPolicyMode::Off;
    if policy.is_empty() && !config.response.quarantine.enabled && !netpol_on {
        services
            .metrics
            .clear_ebpf_program_status("cgroup_workload_firewall");
        adapters::ebpf::workload_firewall_attach::publish_status(
            adapters::ebpf::workload_firewall_attach::WorkloadFirewallStatus::default(),
        );
        return Ok(None);
    }
    let ebpf_dir = startup::resolve_ebpf_program_dir(config);
    let reason = match startup::try_load_cgroup_workload_firewall(&ebpf_dir, config) {
        Ok((mut loader, metrics_rdr, manager, reader, attacher, status)) if status.attached => {
            let proc_root = startup::resolver_proc_path(
                &config.container.resolver.proc_path,
                &startup::host_proc_root(),
            );
            let service = Arc::new(
                application::workload_policy_service::WorkloadPolicyService::new(policy.clone())
                    .with_maps(Box::new(manager))
                    .with_cgroups(Arc::new(adapters::container::ProcContainerResolver::new(
                        &proc_root,
                    ))),
            );
            // The rules go in before the table starts naming tasks, so no
            // task is resolved against an empty rule array.
            service.apply(policy.clone())?;
            spawn_workload_firewall_tasks(
                &service,
                &mut loader,
                reader,
                &services.metrics,
                alerts,
                &services.remote_identities,
                cancel,
            );
            let (quarantine, quarantine_metrics) = startup::arm_quarantine(
                &mut loader,
                config,
                services.audit_svc.store(),
                &services.workloads,
                cancel,
            );
            let mut readers: Vec<_> = metrics_rdr.into_iter().chain(quarantine_metrics).collect();
            let netpol_replay = if netpol_on {
                startup::start_network_policy(&mut loader, config, &mut readers, cancel.clone())
                    .await?
            } else {
                None
            };
            poll_kernel_counters(readers, &services.metrics, cancel);
            services
                .metrics
                .set_ebpf_program_status("cgroup_workload_firewall", true);
            info!(
                rules = policy.rules().len(),
                enforcing = policy.enforces(),
                "eBPF cgroup-workload-firewall active"
            );
            return Ok(Some(WorkloadFirewall {
                service,
                quarantine,
                netpol_replay,
                _loader: loader,
                _attacher: attacher,
            }));
        }
        Ok((_, _, _, _, _, status)) => status
            .reason
            .unwrap_or_else(|| "the kernel refused the attach".to_string()),
        Err(e) => e.to_string(),
    };
    publish_unattached(config, services, &reason);
    if policy.enforces() {
        return Err(anyhow::anyhow!(
            adapters::ebpf::workload_firewall_attach::enforcement_unavailable(&reason)
        ));
    }
    if netpol_mode == infrastructure::config::NetworkPolicyMode::Enforce {
        return Err(anyhow::anyhow!(startup::network_policy_unavailable(
            &reason
        )));
    }
    if netpol_on {
        warn!("network policy observes nothing, the cgroup hooks did not attach: {reason}");
    }
    warn!("workload firewall not loaded, the rules that observe observe nothing: {reason}");
    Ok(None)
}

/// Say on the status routes that the workload firewall object did not
/// attach, and that a quarantine riding on it is not armed either.
fn publish_unattached(config: &AgentConfig, services: &ServiceHandles, reason: &str) {
    services
        .metrics
        .set_ebpf_program_status("cgroup_workload_firewall", false);
    adapters::ebpf::workload_firewall_attach::publish_status(
        adapters::ebpf::workload_firewall_attach::WorkloadFirewallStatus {
            attached: false,
            cgroup: config.attribution.cgroup_root.clone(),
            hooks: Vec::new(),
            reason: Some(reason.to_string()),
            brokered: false,
        },
    );
    if config.response.quarantine.enabled {
        adapters::ebpf::quarantine_map_manager::publish_status(adapters::ebpf::QuarantineStatus {
            reason: Some(format!(
                "the workload firewall object the quarantine rides on did not attach: {reason}"
            )),
            ..adapters::ebpf::QuarantineStatus::default()
        });
    }
}

/// Read the answers named workloads are given, so the addresses a rule names
/// by DNS name open for the pod that asked, and sweep the ones whose time ran
/// out. Without the reader those rules stay closed, which is the side a
/// failure belongs on.
fn spawn_workload_dns_tasks(
    service: &Arc<application::workload_policy_service::WorkloadPolicyService>,
    loader: &mut EbpfLoader,
    metrics: &Arc<AgentMetrics>,
    cancel: &tokio_util::sync::CancellationToken,
) {
    match adapters::ebpf::WorkloadDnsReader::new(loader.ebpf_mut()) {
        Ok(dns_reader) => {
            let (dns_tx, mut dns_rx) = mpsc::channel::<domain::firewall::fqdn::DnsCapture>(
                infrastructure::constants::WORKLOAD_DNS_CHANNEL_CAPACITY,
            );
            let dns_obs = RingBufObserver::new(
                adapters::ebpf::workload_dns_reader::RINGBUF_SOURCE,
                Arc::clone(metrics) as Arc<dyn MetricsPort>,
            );
            let dns_cancel = cancel.clone();
            tokio::spawn(async move {
                dns_reader.run(dns_tx, dns_cancel, dns_obs).await;
            });
            let learning = Arc::clone(service);
            tokio::spawn(async move {
                while let Some(capture) = dns_rx.recv().await {
                    learning.observe_dns(&capture);
                }
            });
            let sweeping = Arc::clone(service);
            let fqdn_cancel = cancel.clone();
            tokio::spawn(async move {
                let mut ticker =
                    tokio::time::interval(infrastructure::constants::WORKLOAD_FQDN_SWEEP_INTERVAL);
                loop {
                    tokio::select! {
                        () = fqdn_cancel.cancelled() => break,
                        _ = ticker.tick() => {}
                    }
                    sweeping.sweep_fqdn(adapters::ebpf::ringbuf_observer::boottime_now_ns());
                }
            });
        }
        Err(e) => {
            warn!(
                "workload DNS answers unreadable, rules naming a destination by name stay closed: {e}"
            );
        }
    }
}

/// Run what a loaded workload firewall needs beside its hooks: the alerts
/// its refusals raise, the DNS answers its rules on names learn from, the
/// per-rule counters, and the remote tables kept in step with the list of
/// remote identities.
///
/// Every task ends with `cancel`.
pub fn spawn_workload_firewall_tasks(
    service: &Arc<application::workload_policy_service::WorkloadPolicyService>,
    loader: &mut EbpfLoader,
    reader: adapters::ebpf::WorkloadEventReader,
    metrics: &Arc<AgentMetrics>,
    alerts: mpsc::Sender<application::alert_event::AlertEvent>,
    remote_identities: &Arc<application::remote_identity_store::RemoteIdentityStore>,
    cancel: &tokio_util::sync::CancellationToken,
) {
    // Every refusal becomes an alert naming the rule that
    // refused it. The record carries a slot rather than a
    // rule identifier, because the kernel walks an array,
    // so the policy in force is what turns one into the
    // other and a record that crossed a reload is dropped
    // rather than named after whoever inherited its slot.
    let (denial_tx, mut denial_rx) =
        mpsc::channel::<domain::firewall::workload::WorkloadDenialRecord>(
            infrastructure::constants::WORKLOAD_DENIAL_CHANNEL_CAPACITY,
        );
    let rb_obs = RingBufObserver::new(
        adapters::ebpf::workload_event_reader::RINGBUF_SOURCE,
        Arc::clone(metrics) as Arc<dyn MetricsPort>,
    );
    let reader_cancel = cancel.clone();
    tokio::spawn(async move {
        reader.run(denial_tx, reader_cancel, rb_obs).await;
    });
    let naming = Arc::clone(service);
    let denial_alert_tx = alerts;
    tokio::spawn(async move {
        while let Some(record) = denial_rx.recv().await {
            let Some(denial) = naming.name_denial(record) else {
                continue;
            };
            // The task is named by the pipeline, off the
            // thread group the hook reported: a socket hook
            // has no flow to look the workload up by.
            let alert = domain::alert::entity::Alert::from_workload_denial(&denial, None);
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

    spawn_workload_dns_tasks(service, loader, metrics, cancel);

    // The per-rule counters are the kernel's own and are
    // read rather than counted off the records, because the
    // ring can drop one under load and a security count
    // that quietly loses a refusal is worse than none. What
    // goes to Prometheus is the difference between two
    // readings, and a rule whose count went backwards was
    // republished rather than refused a negative number of
    // times.
    let counting = Arc::clone(service);
    let counter_metrics = Arc::clone(metrics) as Arc<dyn MetricsPort>;
    let counter_cancel = cancel.clone();
    tokio::spawn(async move {
        use std::collections::HashMap;

        let mut seen: HashMap<String, u64> = HashMap::new();
        let mut ticker =
            tokio::time::interval(infrastructure::constants::WORKLOAD_DENIAL_READ_INTERVAL);
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
                    .is_some_and(domain::firewall::workload::WorkloadRule::enforces);
                counter_metrics.record_workload_denials(&rule.0, enforced, delta);
            }
        }
    });

    // A rule naming a workload on another node reaches it through the list
    // a console hands this one. The tables are written again whenever the
    // list or the policy moves, and emptied when no list is held, which
    // leaves such a rule matching no address rather than a stale one.
    let syncing = Arc::clone(service);
    let remote = Arc::clone(remote_identities);
    let peer_cancel = cancel.clone();
    tokio::spawn(async move {
        let mut ticker =
            tokio::time::interval(infrastructure::constants::WORKLOAD_PEER_SYNC_INTERVAL);
        loop {
            tokio::select! {
                () = peer_cancel.cancelled() => break,
                _ = ticker.tick() => {}
            }
            if let Err(e) = syncing.sync_peers(remote.current().as_deref()) {
                warn!("remote workload tables not written: {e}");
            }
        }
    });
}

/// Load and attach the process tracepoints, feeding `process_tx` until
/// `cancel`. `None` when the kernel refused them, with the reason published.
fn start_process_tracing(
    config: &AgentConfig,
    services: &ServiceHandles,
    process_tx: mpsc::Sender<domain::process::entity::ProcessLifecycleEvent>,
    cancel: &tokio_util::sync::CancellationToken,
) -> Option<(EbpfLoader, adapters::ebpf::ProcessTracingAttacher)> {
    let ebpf_dir = startup::resolve_ebpf_program_dir(config);
    match startup::try_load_process_tracing(&ebpf_dir, config) {
        // The program's own counters are left unread: this binary polls the
        // datapath's readers, and the exec rate is not one of its figures.
        Ok((loader, _metrics, reader, attacher, status)) if status.attached => {
            let observer = RingBufObserver::new(
                "tracepoint-process",
                Arc::clone(&services.metrics) as Arc<dyn MetricsPort>,
            );
            let reader_cancel = cancel.clone();
            tokio::spawn(async move {
                reader.run(process_tx, reader_cancel, observer).await;
            });
            services
                .metrics
                .set_ebpf_program_status("tracepoint_process", true);
            info!("eBPF process tracing active");
            Some((loader, attacher))
        }
        Ok(_) => {
            services
                .metrics
                .set_ebpf_program_status("tracepoint_process", false);
            None
        }
        Err(e) => {
            warn!("process tracing load failed (degraded mode): {e}");
            adapters::ebpf::process_attach::publish_status(adapters::ebpf::ProcessTracingStatus {
                attached: false,
                tracepoints: Vec::new(),
                reason: Some(e.to_string()),
                command_line: config.process_table.capture_command_line,
                lineage: false,
                lineage_reason: None,
            });
            services
                .metrics
                .set_ebpf_program_status("tracepoint_process", false);
            None
        }
    }
}

/// Poll a program's own counters until `cancel`, the way every other
/// program's are: a per-CPU array wakes nobody.
fn poll_kernel_counters(
    readers: Vec<MetricsReader>,
    metrics: &Arc<AgentMetrics>,
    cancel: &tokio_util::sync::CancellationToken,
) {
    if readers.is_empty() {
        return;
    }
    let readers = Arc::new(RwLock::new(readers));
    let port = Arc::clone(metrics) as Arc<dyn MetricsPort>;
    let cancel = cancel.clone();
    tokio::spawn(async move {
        crate::ebpf_metrics::run_kernel_metrics_loop(
            readers,
            port,
            infrastructure::constants::KERNEL_METRICS_INTERVAL,
            cancel,
        )
        .await;
    });
}

/// The executables allowed to reach the network, put in force for a binary
/// that does not run the agent's own start-up path. The hooks stay attached
/// while this lives.
pub struct NetworkExecutables {
    _loader: EbpfLoader,
    _attacher: adapters::ebpf::exec_network::ExecNetworkAttacher,
}

/// Put `firewall.network_executables` in force: the set written, the hooks
/// attached, every refusal raised as an alert on `alerts`, and the set kept on
/// the files the paths name until `cancel`.
///
/// `None` when the configuration carries no list, or when a list that only
/// observes cannot be applied on this host: the reason is published where
/// the status route reads it either way.
///
/// # Errors
///
/// Returns an error when the list does not convert, and when a list that
/// enforces cannot be applied here: an enforcing list that is not in force is
/// a promise the node does not keep.
pub fn start_network_executables(
    config: &AgentConfig,
    services: &ServiceHandles,
    alerts: mpsc::Sender<application::alert_event::AlertEvent>,
    cancel: &tokio_util::sync::CancellationToken,
) -> anyhow::Result<Option<NetworkExecutables>> {
    use adapters::ebpf::exec_network::{ExecNetworkStatus, publish_status};

    let Some(list) = config.network_executables()? else {
        services
            .metrics
            .clear_ebpf_program_status("lsm_exec_network");
        publish_status(ExecNetworkStatus {
            reason: Some(
                "the network executables list is turned off in the configuration".to_string(),
            ),
            ..ExecNetworkStatus::default()
        });
        return Ok(None);
    };
    let enforce = list.mode == domain::firewall::workload::WorkloadMode::Enforce;
    let ebpf_dir = startup::resolve_ebpf_program_dir(config);
    let started = match startup::start_exec_network(&ebpf_dir, &list, enforce) {
        Ok(started) => started,
        Err(reason) => {
            services
                .metrics
                .set_ebpf_program_status("lsm_exec_network", false);
            publish_status(ExecNetworkStatus {
                reason: Some(reason.clone()),
                ..ExecNetworkStatus::default()
            });
            if enforce {
                anyhow::bail!(
                    "firewall.network_executables is set to enforce and cannot be applied here: {reason}"
                );
            }
            warn!("network executables unavailable, nothing is observed: {reason}");
            return Ok(None);
        }
    };
    let startup::ExecNetworkStarted {
        loader,
        metrics_rdr,
        maps,
        attacher,
        reader,
    } = started;
    poll_kernel_counters(metrics_rdr.into_iter().collect(), &services.metrics, cancel);
    services
        .metrics
        .set_ebpf_program_status("lsm_exec_network", true);

    let (record_tx, mut record_rx) =
        mpsc::channel::<domain::firewall::exec_network::ExecNetworkRecord>(
            infrastructure::constants::WORKLOAD_DENIAL_CHANNEL_CAPACITY,
        );
    let rb_obs = RingBufObserver::new(
        adapters::ebpf::exec_network::EXEC_NETWORK_OBJECT,
        Arc::clone(&services.metrics) as Arc<dyn MetricsPort>,
    );
    let reader_cancel = cancel.clone();
    tokio::spawn(async move {
        reader.run(record_tx, reader_cancel, rb_obs).await;
    });
    tokio::spawn(async move {
        while let Some(record) = record_rx.recv().await {
            // Named by the pipeline off the thread group, like a workload
            // refusal: the hook has no flow to look the workload up by.
            let alert = domain::alert::entity::Alert::from_exec_network(&record);
            if alerts
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
    tokio::spawn(startup::refresh_exec_network(
        maps,
        list.executables.clone(),
        enforce,
        cancel.clone(),
    ));
    if enforce {
        warn!(
            executables = list.executables.len(),
            "network executables enforce: an executable outside the list is refused an internet socket"
        );
    } else {
        info!(
            executables = list.executables.len(),
            "network executables observe: an executable outside the list is reported, not refused"
        );
    }
    Ok(Some(NetworkExecutables {
        _loader: loader,
        _attacher: attacher,
    }))
}

/// Cluster addresses resolved at `connect()`, for a binary that does not run
/// the agent's own start-up path. The hooks stay attached while this lives.
pub struct ClusterAddresses {
    _loader: EbpfLoader,
    _attacher: adapters::ebpf::clusterip::ClusterIpAttacher,
}

/// Resolve cluster addresses at `connect()` for the workloads the
/// configuration names, kept equal to the cluster until `cancel`.
///
/// `None` when the configuration turns it off, or when the object could not
/// be attached: every connection then keeps going through kube-proxy, and the
/// reason is published where the status route reads it.
pub async fn start_cluster_addresses(
    config: &AgentConfig,
    services: &ServiceHandles,
    cancel: &tokio_util::sync::CancellationToken,
) -> Option<ClusterAddresses> {
    if !config.container.kubernetes.cluster_ip.enabled {
        services
            .metrics
            .clear_ebpf_program_status("cgroup_clusterip");
        adapters::ebpf::clusterip::publish_status(
            adapters::ebpf::clusterip::ClusterIpStatus::default(),
        );
        return None;
    }
    let ebpf_dir = startup::resolve_ebpf_program_dir(config);
    let mut readers = Vec::new();
    match startup::start_cluster_ip(&ebpf_dir, config, &mut readers, cancel.clone()).await {
        Ok((loader, attacher)) => {
            poll_kernel_counters(readers, &services.metrics, cancel);
            services
                .metrics
                .set_ebpf_program_status("cgroup_clusterip", true);
            Some(ClusterAddresses {
                _loader: loader,
                _attacher: attacher,
            })
        }
        Err(e) => {
            services
                .metrics
                .set_ebpf_program_status("cgroup_clusterip", false);
            startup::publish_cluster_ip_refusal(config, &e);
            None
        }
    }
}

/// Answer the governed containers' DNS from the allow-list, until `cancel`,
/// when the configuration turns it on.
///
/// # Errors
///
/// Returns an error when the section is incomplete or the listener cannot be
/// bound: a container told to ask this resolver would otherwise resolve
/// nothing.
pub async fn start_dns_allowlist(
    config: &AgentConfig,
    services: &ServiceHandles,
    alerts: &mpsc::Sender<application::alert_event::AlertEvent>,
    cancel: &tokio_util::sync::CancellationToken,
) -> anyhow::Result<()> {
    if !config.dns.allowlist.enabled {
        return Ok(());
    }
    startup::spawn_dns_allowlist_resolver(config, &services.metrics, alerts, cancel.clone()).await
}

/// The pods this node runs, read from the Kubernetes API, for the pod
/// coverage a status route reports and the pods a pod profile attaches in.
///
/// `None` when Kubernetes is off in the configuration, when the agent does
/// not run in a cluster, or when no client could be built.
pub async fn start_pod_inventory(
    config: &AgentConfig,
) -> Option<Arc<dyn ports::secondary::pod_coverage_port::PodInventoryPort>> {
    #[cfg(feature = "kubernetes")]
    if config.container.kubernetes.enabled
        && adapters::container::is_running_in_kubernetes()
        && let Some(client) = adapters::container::try_build_client().await
    {
        let cache = Arc::new(adapters::container::PodCache::new());
        let metrics =
            adapters::container::KubernetesEnricher::with_cache(Arc::clone(&cache)).metrics();
        let node_name = if config.container.kubernetes.node_name.is_empty() {
            adapters::container::resolve_node_name()
        } else {
            config.container.kubernetes.node_name.clone()
        };
        let _namespaces = adapters::container::spawn_namespace_watcher(
            client.clone(),
            Arc::clone(&cache),
            Arc::clone(&metrics),
        );
        let _pods = adapters::container::spawn_pod_watcher(
            client,
            node_name,
            config.container.kubernetes.label_filter.join(","),
            Arc::clone(&cache),
            metrics,
        );
        return Some(cache);
    }
    let _ = config;
    None
}

/// The connection events the kernel's conntrack table yields, polled until
/// `cancel`, for the event stream and whatever else subscribes.
///
/// `None` when this host's conntrack table cannot be read, which is said.
#[must_use]
pub fn start_conntrack_events(
    cancel: &tokio_util::sync::CancellationToken,
) -> Option<tokio::sync::broadcast::Sender<domain::conntrack::entity::ConntrackEvent>> {
    if !adapters::netfilter::conntrack::is_conntrack_readable() {
        warn!(
            "conntrack table unreadable (no /proc/net/nf_conntrack and no \
             usable conntrack-tools): event stream disabled"
        );
        return None;
    }
    let (tx, _) = tokio::sync::broadcast::channel::<domain::conntrack::entity::ConntrackEvent>(256);
    let poller_tx = tx.clone();
    let poller_cancel = cancel.clone();
    tokio::spawn(async move {
        adapters::netfilter::event_stream::run_conntrack_event_poller(
            adapters::netfilter::conntrack::ProcNetfilterConntrackPort::new(),
            poller_tx,
            std::time::Duration::from_secs(2),
            poller_cancel,
        )
        .await;
    });
    info!("conntrack event poller started (2s interval)");
    Some(tx)
}

/// Learning mode, for a binary that does not run the agent's own start-up
/// path: a window an operator opens records the edges the node's workloads
/// use, sampled until `cancel`. `None` when the configuration turns it off.
#[must_use]
pub fn start_learning(
    config: &AgentConfig,
    services: &ServiceHandles,
    processes: Option<&Arc<application::process_table_service::ProcessTableService>>,
    cancel: &tokio_util::sync::CancellationToken,
) -> Option<Arc<application::learning_service::LearningAppService>> {
    if !config.learning.enabled {
        return None;
    }
    let mut svc = application::learning_service::LearningAppService::new(
        config.learning.max_edges,
        Arc::clone(&services.metrics) as Arc<dyn MetricsPort>,
    );
    // A window that cannot be written down is a window that does not
    // survive a restart, which the progress report states as a gap.
    if !config.learning.storage_path.is_empty() {
        let path = Path::new(&config.learning.storage_path);
        match adapters::storage::redb_learning_store::RedbLearningStore::open(path) {
            Ok(store) => {
                svc = svc.with_store(Arc::new(store)
                    as Arc<dyn ports::secondary::learning_store_port::LearningStorePort>);
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
    let collector = Arc::new(application::learning_collector::LearningCollector::new(
        Arc::clone(&svc),
        Arc::clone(&services.conntrack_svc),
        services.workloads.clone(),
    ));
    if let Some(table) = processes {
        collector.install_processes(Arc::clone(table));
    }
    let interval = std::time::Duration::from_secs(config.learning.sample_interval_secs);
    let cancel = cancel.clone();
    tokio::spawn(async move {
        collector.run(interval, cancel).await;
    });
    info!(
        max_edges = config.learning.max_edges,
        sample_interval_secs = config.learning.sample_interval_secs,
        "learning mode ready"
    );
    Some(svc)
}

/// The reputation each resolved domain earns, scored from the DNS blocklist's
/// `GeoIP` factors and, when auto-blocking is on, enforced through the IPS
/// blacklist with its alerts on `alerts`. `None` when DNS or the reputation
/// is turned off in the configuration.
#[must_use]
pub fn start_domain_reputation(
    config: &AgentConfig,
    services: &ServiceHandles,
    geoip: Option<&Arc<dyn ports::secondary::geoip_port::GeoIpPort>>,
    alerts: Option<&mpsc::Sender<application::alert_event::AlertEvent>>,
) -> Option<Arc<application::domain_reputation_service_impl::DomainReputationAppService>> {
    if !config.dns.enabled || !config.dns.reputation.enabled {
        return None;
    }
    let (Some(cache), Some(blocklist)) = (
        services.dns_cache_svc.as_ref(),
        services.dns_blocklist_svc.as_ref(),
    ) else {
        return None;
    };
    let rep_config = config.dns.reputation.to_domain_config();
    let mut rep_svc = application::domain_reputation_service_impl::DomainReputationAppService::new(
        rep_config.clone(),
        Arc::clone(&services.metrics) as Arc<dyn MetricsPort>,
    );
    if rep_config.auto_block_enabled {
        let ips = Arc::new(IpsBlacklistAdapter::new(Arc::clone(&services.ips_svc)));
        let mut enforcement =
            application::reputation_enforcement::ReputationEnforcementService::new(
                &rep_config,
                Arc::clone(cache) as Arc<dyn ports::secondary::dns_cache_port::DnsCachePort>,
                ips as Arc<dyn ports::secondary::ips_blacklist_port::IpsBlacklistPort>,
                Arc::clone(&services.metrics) as Arc<dyn MetricsPort>,
            );
        if let Some(alerts) = alerts {
            enforcement = enforcement.with_alert_tx(alerts.clone());
        }
        rep_svc = rep_svc.with_enforcement(Arc::new(enforcement));
        info!(
            threshold = rep_config.auto_block_threshold,
            ttl_secs = rep_config.auto_block_ttl_secs,
            "reputation auto-blocking enabled"
        );
    }
    let rep_svc = Arc::new(rep_svc);
    if let Some(geoip) = geoip {
        blocklist.set_geoip_port(Arc::clone(geoip));
        blocklist.set_reputation_port(Arc::clone(&rep_svc)
            as Arc<dyn ports::secondary::domain_reputation_port::DomainReputationPort>);
        blocklist.set_high_risk_countries(config.dns.reputation.high_risk_countries.clone());
    }
    Some(rep_svc)
}
