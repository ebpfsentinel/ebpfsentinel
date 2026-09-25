use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use adapters::auth::jwt_provider::JwtAuthProvider;
use adapters::auth::oidc_provider::{self, OidcAuthProvider};
use application::config_reload::ConfigReloadService;
use infrastructure::config::AgentConfig;
use notify::Watcher as _;
use tokio::sync::{Mutex, Notify, RwLock, mpsc};
use tokio_util::sync::CancellationToken;

use adapters::ebpf::{ConfigFlagsManager, InterfaceGroupsManager, L7PortsManager};

use crate::ebpf_lifecycle::{EbpfProgramManager, program_config_map};

/// Typed handle so the reload task knows which auth provider variant to refresh.
pub enum AuthProviderHandle {
    Jwt(Arc<JwtAuthProvider>),
    Oidc(Arc<OidcAuthProvider>),
    /// API keys only - no key rotation needed (keys live in config YAML).
    ApiKeyOnly,
}

/// Temporary data-transfer struct used during startup to collect eBPF map
/// managers before they are moved into the [`EbpfProgramManager`].
pub struct EbpfMapHolder {
    pub l7_ports: Option<L7PortsManager>,
    /// `CONFIG_FLAGS` managers, each with the program whose map it holds.
    pub config_flags: Vec<(&'static str, ConfigFlagsManager)>,
    pub iface_groups: Option<InterfaceGroupsManager>,
}

impl Default for EbpfMapHolder {
    fn default() -> Self {
        Self::new()
    }
}

impl EbpfMapHolder {
    pub fn new() -> Self {
        Self {
            l7_ports: None,
            config_flags: Vec::new(),
            iface_groups: None,
        }
    }
}

/// How long a burst of file events is left to settle before the
/// configuration is read. One save is several events - the write, the
/// permissions set on it, the rename over the old file - and each of them
/// deserves the same single reload.
const WATCH_DEBOUNCE: Duration = Duration::from_millis(500);

/// Watch the configuration file and send one notification per change.
///
/// The watch is put on the directory holding the configuration rather than on
/// the file itself, because a write here is an atomic replace: the API's own
/// write stages a file and renames it over the configuration, and a watch on
/// a file follows the inode that was replaced, so it would go deaf after the
/// first change it reported. Every other name in that directory is dropped on
/// the way in.
///
/// A read is never a change. The kernel reports opens as well as writes, and
/// a reload opens the configuration to parse it, so a watcher reacting to
/// every event reloads because it has just reloaded, for ever, at the pace of
/// its own debounce. Access is excluded rather than a list of kinds being
/// admitted, because a backend reporting a change as something this code has
/// never heard of must still be heard.
///
/// A failure only disables the file-watch trigger - SIGHUP and API-driven
/// reloads keep working - so it is logged rather than fatal. The returned
/// watcher must be held for as long as events are wanted; dropping it stops
/// them.
fn watch_config_file(
    config_path: &str,
    notify_tx: mpsc::Sender<()>,
) -> Option<notify::RecommendedWatcher> {
    let watched_name: Option<OsString> = Path::new(config_path)
        .file_name()
        .map(std::ffi::OsStr::to_os_string);
    let watched_dir: PathBuf = Path::new(config_path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);

    let mut watcher =
        match notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
            let Ok(event) = res else { return };
            if matches!(event.kind, notify::EventKind::Access(_)) {
                return;
            }
            let touched = event.paths.iter().any(|p| {
                watched_name
                    .as_deref()
                    .is_some_and(|n| p.file_name() == Some(n))
            });
            if touched {
                // A full channel already holds a reload nobody has run yet,
                // so a dropped notification costs nothing. This runs on the
                // watcher's own thread, which must never block.
                let _ = notify_tx.try_send(());
            }
        }) {
            Ok(w) => w,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "failed to create file watcher, file-driven hot-reload disabled"
                );
                return None;
            }
        };

    match watcher.watch(&watched_dir, notify::RecursiveMode::NonRecursive) {
        Ok(()) => {
            tracing::info!(path = %config_path, "config file watcher started");
            Some(watcher)
        }
        Err(e) => {
            tracing::warn!(
                path = %config_path,
                error = %e,
                "failed to watch config file, file-driven hot-reload disabled"
            );
            None
        }
    }
}

/// Spawn a background task that watches the config file for changes,
/// listens for SIGHUP signals, and accepts API-triggered reloads via
/// the `api_trigger` channel.
///
/// Returns the `JoinHandle` so the caller can await cleanup on shutdown.
#[allow(clippy::too_many_arguments)]
pub fn spawn_reload_task(
    config_path: String,
    reload_service: Arc<ConfigReloadService>,
    auth_handle: Option<AuthProviderHandle>,
    cancel_token: CancellationToken,
    api_trigger: mpsc::Receiver<()>,
    shared_config: Arc<RwLock<AgentConfig>>,
    ebpf_manager: Arc<Mutex<EbpfProgramManager>>,
    reload_complete: Arc<Notify>,
) -> tokio::task::JoinHandle<()> {
    let auth_handle = auth_handle.map(Arc::new);
    let path = config_path.clone();
    spawn_reload_loop(
        config_path,
        cancel_token,
        api_trigger,
        reload_complete,
        move || {
            let path = path.clone();
            let reload_service = Arc::clone(&reload_service);
            let auth_handle = auth_handle.clone();
            let shared_config = Arc::clone(&shared_config);
            let ebpf_manager = Arc::clone(&ebpf_manager);
            async move {
                perform_reload(
                    &path,
                    &reload_service,
                    auth_handle.as_deref(),
                    &shared_config,
                    &ebpf_manager,
                )
                .await;
            }
        },
    )
}

/// Run `on_reload` every time the configuration should be read again.
///
/// Three triggers, one action: a change to the file (debounced, so one save
/// is one reload), SIGHUP, and a message on `api_trigger`. What a reload
/// does is the caller's: the standalone agent also loads and unloads
/// programs, a caller whose datapath is owned elsewhere only re-applies the
/// rules and the kernel maps. A closed `api_trigger` disables that trigger
/// rather than spinning, so a caller with no reload route passes a receiver
/// whose sender it dropped.
///
/// `reload_complete` is notified after each reload, for a caller blocked on
/// one it asked for.
///
/// # Panics
///
/// Panics if the SIGHUP handler cannot be installed, which only happens when
/// the process has no signal driver at all.
pub fn spawn_reload_loop<F, Fut>(
    config_path: String,
    cancel_token: CancellationToken,
    mut api_trigger: mpsc::Receiver<()>,
    reload_complete: Arc<Notify>,
    mut on_reload: F,
) -> tokio::task::JoinHandle<()>
where
    F: FnMut() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send,
{
    // Receiver for operational SIGHUP-driven reloads. The default
    // (process-terminating) disposition is already overridden earlier in
    // startup (before the HTTP server advertises readiness); a SIGHUP racing
    // startup is therefore captured by that earlier guard rather than killing
    // the agent. This stream handles every reload signal once the task is live.
    #[cfg(unix)]
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        .expect("failed to install SIGHUP handler");

    tokio::spawn(async move {
        // Channel for file watcher events → async task
        let (notify_tx, mut notify_rx) = tokio::sync::mpsc::channel::<()>(4);

        let _watcher = watch_config_file(&config_path, notify_tx.clone());
        // Keep `notify_tx` alive so the watcher channel never closes (a closed
        // channel would make `notify_rx.recv()` return immediately and spin).
        let _notify_tx_keepalive = notify_tx;

        loop {
            let mut from_watcher = false;
            #[cfg(unix)]
            {
                tokio::select! {
                    () = cancel_token.cancelled() => {
                        tracing::info!("config watcher shutting down");
                        break;
                    }
                    _ = notify_rx.recv() => {
                        from_watcher = true;
                    }
                    _ = sighup.recv() => {
                        tracing::info!("SIGHUP received, reloading configuration");
                    }
                    Some(()) = api_trigger.recv() => {
                        tracing::info!("API reload trigger received, reloading configuration");
                    }
                }
            }

            #[cfg(not(unix))]
            {
                tokio::select! {
                    () = cancel_token.cancelled() => {
                        tracing::info!("config watcher shutting down");
                        break;
                    }
                    _ = notify_rx.recv() => {
                        from_watcher = true;
                    }
                    Some(()) = api_trigger.recv() => {
                        tracing::info!("API reload trigger received, reloading configuration");
                    }
                }
            }

            // If we broke out due to cancellation, don't reload
            if cancel_token.is_cancelled() {
                break;
            }

            if from_watcher {
                // Let the rest of the burst land, then take the whole of it
                // as the one change it is.
                tokio::time::sleep(WATCH_DEBOUNCE).await;
                while notify_rx.try_recv().is_ok() {}
                tracing::info!("config file change detected, reloading");
            }

            on_reload().await;

            // Wake any caller (e.g. the API reload handler) blocked waiting for
            // this reload to be applied to the shared config.
            reload_complete.notify_waiters();
        }
    })
}

/// Perform a single standalone reload: the rules, the kernel maps, the
/// program set, then the configuration the ops endpoints read.
async fn perform_reload(
    config_path: &str,
    reload_service: &ConfigReloadService,
    auth_handle: Option<&AuthProviderHandle>,
    shared_config: &RwLock<AgentConfig>,
    ebpf_manager: &Mutex<EbpfProgramManager>,
) {
    let Some(config) = apply_config_file(config_path, reload_service, auth_handle).await else {
        return;
    };

    // Re-sync eBPF kernel maps (L7_PORTS, CONFIG_FLAGS, INTERFACE_GROUPS)
    {
        let mut guard = ebpf_manager.lock().await;
        let mgr: &mut EbpfProgramManager = &mut guard;
        sync_kernel_maps(
            mgr.l7_ports.as_mut(),
            &mut mgr.config_flags,
            Some(&mut mgr.iface_groups),
            &config,
        );
    }

    // eBPF program lifecycle - load/unload programs based on enabled flags
    {
        let mut mgr = ebpf_manager.lock().await;

        // Category A: independent TC/uprobe programs
        for (program_name, config_enabled) in program_config_map(&config) {
            let currently_loaded = mgr.is_loaded(program_name);
            match (currently_loaded, config_enabled) {
                (false, true) => {
                    if let Err(e) = mgr.enable_program(program_name, &config).await {
                        tracing::warn!(
                            program = program_name,
                            error = %e,
                            "eBPF program hot-load failed"
                        );
                    }
                }
                (true, false) => {
                    if let Err(e) = mgr.disable_program(program_name).await {
                        tracing::warn!(
                            program = program_name,
                            error = %e,
                            "eBPF program hot-unload failed"
                        );
                    }
                }
                _ => {}
            }
        }

        // Category B: XDP chain programs, which may move the root.
        if mgr.reconcile_xdp(&config).await {
            tracing::info!("XDP chain topology changed, tail-calls rewired");
        }
    }

    // Update shared config for ops endpoints
    *shared_config.write().await = config;
}

/// Write the kernel maps that are read straight off the configuration rather
/// than through a service: the L7 capture ports, each program's
/// `CONFIG_FLAGS`, and the interface group membership.
///
/// A manager that is absent is a program that is not loaded, and is skipped.
pub fn sync_kernel_maps(
    l7_ports: Option<&mut L7PortsManager>,
    config_flags: &mut [(&'static str, ConfigFlagsManager)],
    iface_groups: Option<&mut InterfaceGroupsManager>,
    config: &AgentConfig,
) {
    if let Some(l7_mgr) = l7_ports {
        let ports = config.l7_ports();
        if let Err(e) = l7_mgr.set_ports(&ports) {
            tracing::warn!(error = %e, "L7_PORTS reload failed");
        } else {
            tracing::debug!(port_count = ports.len(), "L7_PORTS reloaded");
        }
    }

    let flags = crate::startup::build_config_flags(config);
    for (_, cfg_mgr) in config_flags.iter_mut() {
        if let Err(e) = cfg_mgr.set_flags(&flags) {
            tracing::warn!(error = %e, "CONFIG_FLAGS reload failed");
        }
    }

    if let Some(groups) = iface_groups {
        let membership = config.kernel_interface_membership();
        let memberships: Vec<(u32, u32)> = config
            .agent
            .interfaces
            .iter()
            .filter_map(|iface| {
                let ifindex = crate::startup::get_ifindex(iface).ok()?;
                let groups = membership.get(iface).copied().unwrap_or(0);
                Some((ifindex, groups))
            })
            .collect();
        if let Err(e) = groups.set_interface_groups(&memberships) {
            tracing::warn!(error = %e, "INTERFACE_GROUPS reload failed");
        } else if !memberships.is_empty() {
            tracing::debug!(
                iface_count = memberships.len(),
                map_count = groups.map_count(),
                "INTERFACE_GROUPS reloaded"
            );
        }
    }
}

/// Read the configuration file and apply it to the services.
///
/// Every conversion that can reject the file runs before anything is
/// applied, so a rejected file leaves the running rules whole and returns
/// `None`. On success the rules of every service are replaced and the auth
/// keys rotated, and the parsed configuration is returned for the caller to
/// apply to whatever datapath it owns: this touches no kernel map that is
/// written straight off the configuration, and loads or unloads no program.
#[allow(clippy::too_many_lines, clippy::similar_names)] // reload is inherently sequential with many phases
pub async fn apply_config_file(
    config_path: &str,
    reload_service: &ConfigReloadService,
    auth_handle: Option<&AuthProviderHandle>,
) -> Option<AgentConfig> {
    // Phase 1: serde deserialization
    let config = match AgentConfig::load(Path::new(config_path)) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "config reload rejected: invalid YAML");
            return None;
        }
    };

    // Phase 2: domain validation (convert config rules to domain entities)
    let rules = match config.firewall_rules() {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "config reload rejected: invalid rules");
            return None;
        }
    };

    // Phase 3: parse firewall mode
    let mode = match config.firewall_mode() {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(error = %e, "config reload rejected: invalid firewall mode");
            return None;
        }
    };

    // Every other conversion that can reject the file runs here, before
    // anything is applied, so a rejected reload leaves the running
    // configuration whole rather than half of it swapped.
    let ids_rules = match config.ids_rules() {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "config reload rejected: invalid IDS rules");
            return None;
        }
    };

    let ids_mode = match config.ids_mode() {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(error = %e, "config reload rejected: invalid IDS mode");
            return None;
        }
    };

    let ids_sampling = match config.ids_sampling() {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "config reload rejected: invalid IDS sampling");
            return None;
        }
    };

    let l7_rules = match config.l7_rules() {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "config reload rejected: invalid L7 rules");
            return None;
        }
    };

    let dlp_patterns = match config.dlp_patterns() {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "config reload rejected: invalid DLP patterns");
            return None;
        }
    };

    let dlp_mode = match config.dlp_mode() {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(error = %e, "config reload rejected: invalid DLP mode");
            return None;
        }
    };

    let rl_policies = match config.ratelimit_policies() {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "config reload rejected: invalid ratelimit policies");
            return None;
        }
    };

    let ddos_policies = match config.ddos_policies() {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "config reload rejected: invalid DDoS policies");
            return None;
        }
    };

    let dnat_rules = match config.nat_dnat_rules() {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "config reload rejected: invalid NAT DNAT rules");
            return None;
        }
    };

    let snat_rules = match config.nat_snat_rules() {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "config reload rejected: invalid NAT SNAT rules");
            return None;
        }
    };

    let nptv6_rules = match config.nat_nptv6_rules() {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "config reload rejected: invalid NAT NPTv6 rules");
            return None;
        }
    };

    let aliases = match config.aliases() {
        Ok(a) => a,
        Err(e) => {
            tracing::warn!(error = %e, "config reload rejected: invalid aliases");
            return None;
        }
    };

    let lb_services = match config.lb_services() {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "config reload rejected: invalid LB services");
            return None;
        }
    };

    let vip_announce = match config.lb_announce() {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "config reload rejected: invalid VIP announce config");
            return None;
        }
    };

    let qos_pipes = match config.qos_pipes() {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "config reload rejected: invalid QoS pipes");
            return None;
        }
    };

    let qos_queues = match config.qos_queues() {
        Ok(q) => q,
        Err(e) => {
            tracing::warn!(error = %e, "config reload rejected: invalid QoS queues");
            return None;
        }
    };

    let qos_classifiers = match config.qos_classifiers() {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "config reload rejected: invalid QoS classifiers");
            return None;
        }
    };

    let ips_rules = match config.ips_rules() {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "config reload rejected: invalid IPS rules");
            return None;
        }
    };

    let ips_mode = match config.ips_mode() {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(error = %e, "config reload rejected: invalid IPS mode");
            return None;
        }
    };

    let ips_whitelist = match config.ips_whitelist() {
        Ok(w) => w,
        Err(e) => {
            tracing::warn!(error = %e, "config reload rejected: invalid IPS whitelist");
            return None;
        }
    };

    let ips_sampling = match config.ips_sampling() {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "config reload rejected: invalid IPS sampling");
            return None;
        }
    };

    let ti_feeds = match config.threatintel_feeds() {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(error = %e, "config reload rejected: invalid threat intel feeds");
            return None;
        }
    };

    let ti_mode = match config.threatintel_mode() {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(error = %e, "config reload rejected: invalid threat intel mode");
            return None;
        }
    };

    // Apply firewall reload. The interface bits go first: they are what an
    // interface-scoped rule in the new set is narrowed with.
    reload_service
        .set_firewall_interface_scope(crate::startup::firewall_interface_scope(&config))
        .await;
    reload_service
        .set_firewall_anti_lockout(crate::startup::firewall_anti_lockout(&config))
        .await;
    if let Err(e) = reload_service
        .reload(rules, config.firewall.enabled, mode)
        .await
    {
        tracing::warn!(error = %e, "firewall config reload failed at application level");
    }

    // Phase 3½: Schedule reload
    {
        use application::schedule_service_impl::{
            Schedule, ScheduleEntry, parse_day, parse_time_range,
        };

        let mut schedules = std::collections::HashMap::new();
        let mut rule_schedule = std::collections::HashMap::new();

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

        if let Err(e) = reload_service
            .reload_schedules(schedules, rule_schedule)
            .await
        {
            tracing::warn!(error = %e, "schedule config reload failed at application level");
        }
    }

    // Phase 4: IDS reload

    if let Err(e) = reload_service
        .reload_ids(ids_rules, config.ids.enabled, ids_mode, ids_sampling)
        .await
    {
        tracing::warn!(error = %e, "IDS config reload failed at application level");
    }

    // Phase 5: L7 reload

    if let Err(e) = reload_service.reload_l7(l7_rules, config.l7.enabled).await {
        tracing::warn!(error = %e, "L7 config reload failed at application level");
    }

    // Phase 6: Ratelimit reload

    if let Err(e) = reload_service
        .reload_ratelimit(
            rl_policies,
            config.ratelimit.enabled,
            (
                config.ratelimit.default_rate,
                config.ratelimit.default_burst,
                crate::startup::parse_algorithm_byte(&config.ratelimit.default_algorithm),
            ),
        )
        .await
    {
        tracing::warn!(error = %e, "ratelimit config reload failed at application level");
    }

    // Phase 6a: Ratelimit country tiers reload
    if let Ok(tiers) = config.ratelimit_country_tiers()
        && !tiers.is_empty()
        && let Err(e) = reload_service.reload_ratelimit_country_tiers(tiers).await
    {
        tracing::warn!(error = %e, "ratelimit country tiers reload failed");
    }

    // Phase 6b: DDoS reload

    if let Err(e) = reload_service
        .reload_ddos(ddos_policies, config.ddos.enabled)
        .await
    {
        tracing::warn!(error = %e, "DDoS config reload failed at application level");
    }

    // Phase 6b½: DLP reload
    //
    // The same patterns and mode startup loads, so a reload keeps a
    // configured `block` mode and the patterns the file re-tunes.
    if let Err(e) = reload_service
        .reload_dlp(dlp_patterns, dlp_mode, config.dlp.enabled)
        .await
    {
        tracing::warn!(error = %e, "DLP config reload failed at application level");
    }

    // Phase 6c: ConnTrack reload
    let ct_settings = config.conntrack_settings();
    if let Err(e) = reload_service
        .reload_conntrack(ct_settings, config.conntrack.enabled)
        .await
    {
        tracing::warn!(error = %e, "conntrack config reload failed at application level");
    }

    // Phase 6d: NAT reload
    let hairpin_cfg = match config.nat_hairpin_parsed() {
        Ok((subnet, mask, snat_ip)) => Some(ebpf_common::nat::HairpinConfig {
            internal_subnet: subnet,
            internal_mask: mask,
            hairpin_snat_ip: snat_ip,
            enabled: u8::from(config.nat.hairpin.enabled),
            _pad: [0; 3],
        }),
        Err(e) => {
            tracing::warn!(error = %e, "config reload: invalid hairpin NAT config, skipping");
            None
        }
    };
    if let Err(e) = reload_service
        .reload_nat(
            dnat_rules,
            snat_rules,
            nptv6_rules,
            hairpin_cfg,
            config.nat.enabled,
        )
        .await
    {
        tracing::warn!(error = %e, "NAT config reload failed at application level");
    }

    // Phase 6e: Alias reload
    if let Err(e) = reload_service.reload_aliases(aliases).await {
        tracing::warn!(error = %e, "alias config reload failed at application level");
    }

    // Phase 6f: Routing reload
    let gateways: Vec<_> = config
        .routing
        .gateways
        .iter()
        .map(infrastructure::config::GatewayConfig::to_domain)
        .collect();
    if let Err(e) = reload_service
        .reload_routing(gateways, config.routing.enabled)
        .await
    {
        tracing::warn!(error = %e, "routing config reload failed at application level");
    }

    // Phase 6f¼: Zone reload
    if let Ok(zone_cfg) = config.zone_config()
        && let Err(e) = reload_service
            .reload_zones(zone_cfg, config.zones.enabled)
            .await
    {
        tracing::warn!(error = %e, "zone config reload failed at application level");
    }

    // Phase 6f½: Load Balancer reload
    if let Err(e) = reload_service
        .reload_loadbalancer(lb_services, config.loadbalancer.enabled)
        .await
    {
        tracing::warn!(error = %e, "load balancer config reload failed at application level");
    }

    // Phase 6f⅔: L2 VIP announcer reload
    if let Err(e) = reload_service.reload_vip_announcer(vip_announce).await {
        tracing::warn!(error = %e, "VIP announcer config reload failed at application level");
    }

    // Phase 6f¾: QoS reload
    if let Err(e) = reload_service
        .reload_qos(qos_pipes, qos_queues, qos_classifiers, config.qos.enabled)
        .await
    {
        tracing::warn!(error = %e, "QoS config reload failed at application level");
    }

    // Phase 6g: IPS reload
    let ips_policy = config.ips_policy();
    if let Err(e) = reload_service
        .reload_ips(
            ips_rules,
            ips_whitelist,
            config.ips.whitelist_aliases.clone(),
            config.ips.enabled,
            ips_mode,
            ips_policy,
            ips_sampling,
        )
        .await
    {
        tracing::warn!(error = %e, "IPS config reload failed");
    }

    // Phase 6h: Threat Intel reload
    let ti_country_boost = config
        .threatintel
        .country_confidence_boost
        .clone()
        .unwrap_or_default();
    if let Err(e) = reload_service
        .reload_threatintel(
            ti_feeds,
            config.threatintel.enabled,
            ti_mode,
            ti_country_boost,
        )
        .await
    {
        tracing::warn!(error = %e, "threat intel config reload failed");
    }

    // Phase 7: Auth key/JWKS rotation
    if let Some(handle) = auth_handle {
        match handle {
            AuthProviderHandle::Jwt(provider) => {
                if config.auth.enabled && !config.auth.jwt.public_key_path.is_empty() {
                    match std::fs::read(&config.auth.jwt.public_key_path) {
                        Ok(pem_bytes) => match provider.rotate_key(&pem_bytes) {
                            Ok(()) => {
                                tracing::info!(
                                    path = %config.auth.jwt.public_key_path,
                                    "JWT public key rotated successfully"
                                );
                            }
                            Err(e) => {
                                tracing::warn!(
                                    error = %e,
                                    path = %config.auth.jwt.public_key_path,
                                    "JWT key rotation failed, keeping current key"
                                );
                            }
                        },
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                path = %config.auth.jwt.public_key_path,
                                "failed to read JWT public key for rotation, keeping current key"
                            );
                        }
                    }
                }
            }
            AuthProviderHandle::Oidc(provider) => {
                if let Some(ref oidc) = config.auth.oidc {
                    match oidc_provider::fetch_jwks(&oidc.jwks_url).await {
                        Ok(jwk_set) => {
                            provider.rotate_keys(jwk_set);
                            tracing::info!(
                                jwks_url = %oidc.jwks_url,
                                "OIDC JWKS rotated successfully"
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                jwks_url = %oidc.jwks_url,
                                "OIDC JWKS rotation failed, keeping current keys"
                            );
                        }
                    }
                }
            }
            AuthProviderHandle::ApiKeyOnly => {
                // The key table is hashed once at startup; a key added,
                // removed or changed in the file takes effect at the next start.
                tracing::debug!("API key auth: keys apply at the next start");
            }
        }
    }

    Some(config)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn counting_loop(
        api_trigger: mpsc::Receiver<()>,
        cancel: CancellationToken,
        reload_complete: Arc<Notify>,
    ) -> (Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
        let dir = std::env::temp_dir().join(format!("reload-loop-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("agent.yaml").to_string_lossy().into_owned();
        let count = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&count);
        let handle = spawn_reload_loop(path, cancel, api_trigger, reload_complete, move || {
            let seen = Arc::clone(&seen);
            async move {
                seen.fetch_add(1, Ordering::SeqCst);
            }
        });
        (count, handle)
    }

    #[tokio::test]
    async fn an_api_trigger_runs_the_reload_once() {
        let (tx, rx) = mpsc::channel(1);
        let cancel = CancellationToken::new();
        let done = Arc::new(Notify::new());
        let (count, handle) = counting_loop(rx, cancel.clone(), Arc::clone(&done));

        let applied = done.notified();
        tx.send(()).await.expect("loop is listening");
        tokio::time::timeout(Duration::from_secs(5), applied)
            .await
            .expect("reload completes");
        assert_eq!(count.load(Ordering::SeqCst), 1);

        cancel.cancel();
        handle.await.expect("loop stops on cancel");
    }

    #[tokio::test]
    async fn a_closed_api_trigger_is_not_a_reload() {
        let (tx, rx) = mpsc::channel::<()>(1);
        drop(tx);
        let cancel = CancellationToken::new();
        let (count, handle) = counting_loop(rx, cancel.clone(), Arc::new(Notify::new()));

        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(count.load(Ordering::SeqCst), 0);

        cancel.cancel();
        handle.await.expect("loop stops on cancel");
    }

    #[tokio::test]
    async fn a_reload_keeps_the_dlp_patterns_the_file_re_tunes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.yaml");
        let yaml = "agent:\n  interfaces: [lo]\ndlp:\n  enabled: true\n  patterns:\n    \
                    - id: dlp-pci-visa\n      name: Visa re-tuned\n      \
                    regex: '4[0-9]{15}'\n      severity: low\n      data_type: pci\n";
        std::fs::write(&path, yaml).unwrap();
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .unwrap();

        let mut config = AgentConfig::load(&path).unwrap();
        // The audit stores land in the test's directory, not under the crate.
        config.audit.storage_path = dir.path().join("audit.redb").display().to_string();
        let services = crate::runtime::build_services(&config).unwrap();
        let visa_name = |services: &crate::runtime::ServiceHandles| {
            services
                .dlp_svc
                .load()
                .list_patterns()
                .iter()
                .find(|p| p.id.0 == "dlp-pci-visa")
                .map(|p| p.name.clone())
        };
        assert_eq!(visa_name(&services).as_deref(), Some("Visa re-tuned"));

        let reload_service = services.config_reload_service();
        let applied = apply_config_file(path.to_str().unwrap(), &reload_service, None).await;

        assert!(applied.is_some());
        assert_eq!(
            visa_name(&services).as_deref(),
            Some("Visa re-tuned"),
            "a reload must load the patterns startup loads, not the built-in set alone"
        );
    }
}
