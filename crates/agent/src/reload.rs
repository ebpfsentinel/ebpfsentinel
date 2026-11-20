use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use adapters::auth::jwt_provider::JwtAuthProvider;
use adapters::auth::oidc_provider::{self, OidcAuthProvider};
use application::config_reload::ConfigReloadService;
use infrastructure::config::AgentConfig;
use notify::Watcher as _;
use tokio::sync::{Mutex, Notify, RwLock, mpsc, watch};
use tokio_util::sync::CancellationToken;

use adapters::ebpf::{
    ConfigFlagsManager, InterfaceGroupsManager, L7PortsManager, ScrubConfigManager,
};

use crate::ddos_guards::DdosGuards;
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
    /// The xdp-ratelimit anti-DDoS guard maps.
    pub ddos_guards: Option<DdosGuards>,
    /// The tc-scrub `SCRUB_CONFIG` map.
    pub scrub: Option<ScrubConfigManager>,
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
            ddos_guards: None,
            scrub: None,
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

/// What the reload task has done, for a caller that triggered a reload and
/// waits for its verdict.
///
/// Reloads run one at a time, so `started` and `finished` count the same
/// sequence: a caller that read `started` before it triggered waits until
/// `finished` passes that number, and then the last reload read the file
/// after the caller's write. `refused` is the reason the last finished
/// reload kept the running configuration, `None` when it applied the file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReloadOutcome {
    /// Reloads begun since start.
    pub started: u64,
    /// Reloads ended since start.
    pub finished: u64,
    /// Why the last finished reload refused the file.
    pub refused: Option<String>,
}

/// Spawn a background task that watches the config file for changes,
/// listens for SIGHUP signals, and accepts API-triggered reloads via
/// the `api_trigger` channel.
///
/// Each reload is counted on `outcome` when it starts and again when it
/// ends, with the reason when the file was refused, so a caller that asked
/// for one can tell whether the agent runs the file it wrote.
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
    outcome: watch::Sender<ReloadOutcome>,
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
            let outcome = outcome.clone();
            async move {
                outcome.send_modify(|o| o.started += 1);
                let verdict = perform_reload(
                    &path,
                    &reload_service,
                    auth_handle.as_deref(),
                    &shared_config,
                    &ebpf_manager,
                )
                .await;
                outcome.send_modify(|o| {
                    o.finished = o.started;
                    o.refused = verdict.err();
                });
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
///
/// A refused file leaves everything as it ran and comes back as the reason.
async fn perform_reload(
    config_path: &str,
    reload_service: &ConfigReloadService,
    auth_handle: Option<&AuthProviderHandle>,
    shared_config: &RwLock<AgentConfig>,
    ebpf_manager: &Mutex<EbpfProgramManager>,
) -> Result<(), String> {
    let config =
        apply_config_file_checked(config_path, reload_service, auth_handle, |_| Ok(())).await?;

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
        if let Some(guards) = mgr.ddos_guards.as_mut() {
            guards.write(&config);
        }
        sync_scrub(mgr.scrub.as_mut(), &config);
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
    Ok(())
}

/// Write the kernel maps that are read straight off the configuration rather
/// than through a service: the L7 capture ports, each program's
/// `CONFIG_FLAGS`, and the interface group membership.
///
/// A manager that is absent is a program that is not loaded, and is skipped.
/// Rewrite the tc-scrub parameters from `config`, when tc-scrub is loaded.
pub fn sync_scrub(scrub: Option<&mut ScrubConfigManager>, config: &AgentConfig) {
    if let Some(scrub) = scrub
        && let Err(e) = scrub.set_flags(&crate::startup::build_scrub_flags(config))
    {
        tracing::warn!(error = %e, "SCRUB_CONFIG re-sync failed");
    }
}

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
pub async fn apply_config_file(
    config_path: &str,
    reload_service: &ConfigReloadService,
    auth_handle: Option<&AuthProviderHandle>,
) -> Option<AgentConfig> {
    apply_config_file_prepared(config_path, reload_service, auth_handle, |_| Ok(())).await
}

/// [`apply_config_file`], with `prepare` run on the parsed configuration
/// before anything is converted or applied.
///
/// A binary that adds rules of its own to the configuration, compiled from
/// sources this agent does not read, adds them here so they are validated
/// and applied with the rest. A `prepare` that fails rejects the file like
/// any other refusal, and the running rules stay whole.
pub async fn apply_config_file_prepared(
    config_path: &str,
    reload_service: &ConfigReloadService,
    auth_handle: Option<&AuthProviderHandle>,
    prepare: impl FnOnce(&mut AgentConfig) -> Result<(), String>,
) -> Option<AgentConfig> {
    apply_config_file_checked(config_path, reload_service, auth_handle, prepare)
        .await
        .ok()
}

/// The checks a configuration must pass before the agent runs it: the
/// conversions start-up refuses to start without, run the way the reload
/// runs them before it applies anything.
///
/// A configuration write and an API reload validate a file with this after
/// [`AgentConfig::load`], so a file they accept is one the running agent
/// applies and the next start accepts. The one refusal that is not about
/// the file is included: a workload rule that refuses, on a host whose
/// cgroup hooks did not attach.
///
/// # Errors
///
/// The first conversion that refuses, named.
pub fn validate_config(config: &AgentConfig) -> Result<(), String> {
    convert_config(config).map(|_| ())
}

/// How much of one top-level block of the configuration a reload reads
/// again.
enum Reread {
    /// Every key of the block.
    All,
    /// Every key but these, which are read once at start.
    AllBut(&'static [&'static str]),
    /// These keys alone; the rest of the block is read once at start.
    Only(&'static [&'static str]),
}

/// What [`perform_reload`] applies, by block. A block absent from this table
/// is read once at start, and an edit to it waits for a restart.
const REREAD: &[(&str, Reread)] = &[
    ("firewall", Reread::All),
    ("ids", Reread::All),
    ("ips", Reread::All),
    ("l7", Reread::All),
    ("ratelimit", Reread::All),
    ("ddos", Reread::All),
    ("conntrack", Reread::All),
    ("nat", Reread::All),
    ("aliases", Reread::All),
    ("routing", Reread::All),
    ("zones", Reread::All),
    ("loadbalancer", Reread::All),
    ("interface_groups", Reread::All),
    ("dlp", Reread::AllBut(&["scope"])),
    ("qos", Reread::AllBut(&["enabled"])),
    ("threatintel", Reread::AllBut(&["crowdsec", "max_entries"])),
    ("dns", Reread::Only(&["enabled"])),
    ("attribution", Reread::Only(&["enabled"])),
    ("process_table", Reread::Only(&["enabled"])),
    (
        "container",
        Reread::Only(&["kubernetes.cluster_ip.enabled"]),
    ),
    (
        "auth",
        Reread::Only(&["jwt.public_key_path", "oidc.jwks_url"]),
    ),
    ("agent", Reread::Only(&["config_writes"])),
];

/// The parts of `now` that differ from `boot`, the configuration the agent
/// started with, and that a reload does not apply: they are in the file and
/// not in what the agent runs until it restarts.
///
/// Blocks are named by their key, a key inside a block a reload otherwise
/// applies by its dotted path. The kernel tables sized at start are named by
/// the setting that sizes them: a reload writes their entries but cannot
/// change how many they hold. The list is sorted and empty when the agent
/// runs everything the file says.
#[must_use]
pub fn pending_restart(boot: &AgentConfig, now: &AgentConfig) -> Vec<String> {
    use adapters::ebpf::map_sizing::{MapSizing, SIZED_MAPS};
    use serde_json::Value;

    let (Ok(Value::Object(boot_blocks)), Ok(Value::Object(now_blocks))) =
        (serde_json::to_value(boot), serde_json::to_value(now))
    else {
        return Vec::new();
    };
    let pointer = |path: &str| format!("/{}", path.replace('.', "/"));
    let mut pending = std::collections::BTreeSet::new();

    let keys: std::collections::BTreeSet<&String> =
        boot_blocks.keys().chain(now_blocks.keys()).collect();
    for key in keys {
        let mut before = boot_blocks.get(key).cloned().unwrap_or(Value::Null);
        let mut after = now_blocks.get(key).cloned().unwrap_or(Value::Null);
        match REREAD.iter().find(|(block, _)| *block == key.as_str()) {
            Some((_, Reread::All)) => {}
            Some((_, Reread::AllBut(fixed))) => {
                for path in *fixed {
                    if before.pointer(&pointer(path)) != after.pointer(&pointer(path)) {
                        pending.insert(format!("{key}.{path}"));
                    }
                }
            }
            Some((_, Reread::Only(reread))) => {
                for path in *reread {
                    drop_path(&mut before, path);
                    drop_path(&mut after, path);
                }
                if before != after {
                    pending.insert(key.clone());
                }
            }
            None => {
                if before != after {
                    pending.insert(key.clone());
                }
            }
        }
    }

    let (boot_sizes, now_sizes) = (MapSizing::from_config(boot), MapSizing::from_config(now));
    for (map, field) in SIZED_MAPS {
        if boot_sizes.get(map) != now_sizes.get(map) {
            pending.insert((*field).to_string());
        }
    }

    pending.into_iter().collect()
}

/// Remove the key at the dotted `path` inside `value`, when it is there.
fn drop_path(value: &mut serde_json::Value, path: &str) {
    let (parent, last) = match path.rsplit_once('.') {
        Some((parent, last)) => (
            value.pointer_mut(&format!("/{}", parent.replace('.', "/"))),
            last,
        ),
        None => (Some(value), path),
    };
    if let Some(object) = parent.and_then(serde_json::Value::as_object_mut) {
        object.remove(last);
    }
}

/// Everything the reload converts out of a parsed configuration before it
/// applies any of it.
struct ConvertedConfig {
    rules: Vec<domain::firewall::entity::FirewallRule>,
    workload_policy: domain::firewall::workload::WorkloadPolicy,
    dns_rule: Option<adapters::ebpf::workload_firewall_attach::DnsRuleStatus>,
    mode: domain::common::entity::DomainMode,
    ids_rules: Vec<domain::ids::entity::IdsRule>,
    ids_mode: domain::common::entity::DomainMode,
    ids_sampling: domain::ids::entity::SamplingMode,
    l7_rules: Vec<domain::l7::entity::L7Rule>,
    dlp_patterns: Vec<domain::dlp::entity::DlpPattern>,
    dlp_mode: domain::common::entity::DomainMode,
    rl_policies: Vec<domain::ratelimit::entity::RateLimitPolicy>,
    ddos_policies: Vec<domain::ddos::entity::DdosPolicy>,
    dnat_rules: Vec<domain::nat::entity::NatRule>,
    snat_rules: Vec<domain::nat::entity::NatRule>,
    nptv6_rules: Vec<domain::nat::entity::NptV6Rule>,
    aliases: Vec<domain::alias::entity::Alias>,
    lb_services: Vec<domain::loadbalancer::entity::LbService>,
    vip_announce: domain::loadbalancer::vip::VipAnnounceConfig,
    vip_bgp: domain::loadbalancer::bgp::BgpConfig,
    qos_pipes: Vec<domain::qos::entity::QosPipe>,
    qos_queues: Vec<domain::qos::entity::QosQueue>,
    qos_classifiers: Vec<domain::qos::entity::QosClassifier>,
    qos_cgroup_shaping: Vec<domain::qos::cgroup_shaping::CgroupShapingRule>,
    ips_rules: Vec<domain::ids::entity::IdsRule>,
    ips_mode: domain::common::entity::DomainMode,
    ips_whitelist: Vec<domain::ips::entity::WhitelistEntry>,
    ips_sampling: domain::ids::entity::SamplingMode,
    ti_feeds: Vec<domain::threatintel::entity::FeedConfig>,
    ti_mode: domain::common::entity::DomainMode,
}

/// A conversion's refusal, named by what it converts.
fn refused<T, E: std::fmt::Display>(result: Result<T, E>, what: &str) -> Result<T, String> {
    result.map_err(|e| format!("invalid {what}: {e}"))
}

/// Run every conversion that can reject a configuration, in the order the
/// reload has always run them, and keep what they produced.
fn convert_config(config: &AgentConfig) -> Result<ConvertedConfig, String> {
    use adapters::ebpf::workload_firewall_attach as workload_attach;

    let rules = refused(config.firewall_rules(), "firewall rules")?;

    // The workload half of those rules, and the one refusal that is not
    // about the file being malformed.
    //
    // A rule that refuses is only worth anything where the cgroup hooks
    // attached: a file adding one on a host that refused them would leave the
    // operator reading a deny rule the kernel never sees. Rejecting the file
    // keeps the rules in force and says why, which is the same answer
    // start-up gives. An agent that started with no rule loaded the object
    // and kept its hooks, and they are attached by the reload, once nothing
    // else in the file can reject it.
    let workload_policy = refused(
        domain::firewall::workload::WorkloadPolicy::from_rules(&rules),
        "workload rules",
    )?;
    let workload_policy = refused(
        config
            .workload_dns()
            .map_err(|e| e.to_string())
            .and_then(|dns| workload_policy.with_dns(dns).map_err(|e| e.to_string())),
        "workload DNS settings",
    )?;
    let dns_rule = refused(config.dns_clients(), "dns_clients")?
        .as_ref()
        .map(workload_attach::DnsRuleStatus::of);
    if workload_policy.enforces()
        && !workload_attach::status().attached
        && !workload_attach::attach_pending()
    {
        let reason = workload_attach::status()
            .reason
            .unwrap_or_else(|| "the hooks are not attached on this host".to_string());
        return Err(workload_attach::enforcement_unavailable(&reason));
    }

    Ok(ConvertedConfig {
        rules,
        workload_policy,
        dns_rule,
        mode: refused(config.firewall_mode(), "firewall mode")?,
        ids_rules: refused(config.ids_rules(), "IDS rules")?,
        ids_mode: refused(config.ids_mode(), "IDS mode")?,
        ids_sampling: refused(config.ids_sampling(), "IDS sampling")?,
        l7_rules: refused(config.l7_rules(), "L7 rules")?,
        dlp_patterns: refused(config.dlp_patterns(), "DLP patterns")?,
        dlp_mode: refused(config.dlp_mode(), "DLP mode")?,
        rl_policies: refused(config.ratelimit_policies(), "ratelimit policies")?,
        ddos_policies: refused(config.ddos_policies(), "DDoS policies")?,
        dnat_rules: refused(config.nat_dnat_rules(), "NAT DNAT rules")?,
        snat_rules: refused(config.nat_snat_rules(), "NAT SNAT rules")?,
        nptv6_rules: refused(config.nat_nptv6_rules(), "NAT NPTv6 rules")?,
        aliases: refused(config.aliases(), "aliases")?,
        lb_services: refused(config.lb_services(), "LB services")?,
        vip_announce: refused(config.lb_announce(), "VIP announce config")?,
        vip_bgp: refused(config.lb_announce_bgp(), "BGP announce config")?,
        qos_pipes: refused(config.qos_pipes(), "QoS pipes")?,
        qos_queues: refused(config.qos_queues(), "QoS queues")?,
        qos_classifiers: refused(config.qos_classifiers(), "QoS classifiers")?,
        qos_cgroup_shaping: refused(
            config.qos.to_domain_cgroup_shaping(),
            "per-workload shaping",
        )?,
        ips_rules: refused(config.ips_rules(), "IPS rules")?,
        ips_mode: refused(config.ips_mode(), "IPS mode")?,
        ips_whitelist: refused(config.ips_whitelist(), "IPS whitelist")?,
        ips_sampling: refused(config.ips_sampling(), "IPS sampling")?,
        ti_feeds: refused(config.threatintel_feeds(), "threat intel feeds")?,
        ti_mode: refused(config.threatintel_mode(), "threat intel mode")?,
    })
}

/// [`apply_config_file_prepared`], answering why a refused file was
/// refused.
///
/// The reload loop hands the refusal to whoever asked for the reload, so an
/// API caller is told the file was not applied instead of reading `ok` while
/// the agent kept the rules it had.
///
/// # Errors
///
/// The reason the file was refused: unreadable or invalid, a `prepare`
/// that failed, a conversion that refused, or a workload hook the kernel
/// would not attach for a rule that refuses. Nothing was applied.
#[allow(clippy::too_many_lines, clippy::similar_names)] // reload is inherently sequential with many phases
pub async fn apply_config_file_checked(
    config_path: &str,
    reload_service: &ConfigReloadService,
    auth_handle: Option<&AuthProviderHandle>,
    prepare: impl FnOnce(&mut AgentConfig) -> Result<(), String>,
) -> Result<AgentConfig, String> {
    // Phase 1: serde deserialization
    let (mut config, digest) = match AgentConfig::load_with_digest(Path::new(config_path)) {
        Ok(loaded) => loaded,
        Err(e) => {
            tracing::warn!(error = %e, "config reload rejected: invalid YAML");
            return Err(format!("invalid configuration: {e}"));
        }
    };
    if let Err(e) = prepare(&mut config) {
        tracing::warn!(error = %e, "config reload rejected");
        return Err(e);
    }

    // Phase 2: every conversion that can reject the file runs here, before
    // anything is applied, so a rejected reload leaves the running
    // configuration whole rather than half of it swapped.
    let ConvertedConfig {
        rules,
        workload_policy,
        dns_rule,
        mode,
        ids_rules,
        ids_mode,
        ids_sampling,
        l7_rules,
        dlp_patterns,
        dlp_mode,
        rl_policies,
        ddos_policies,
        dnat_rules,
        snat_rules,
        nptv6_rules,
        aliases,
        lb_services,
        vip_announce,
        vip_bgp,
        qos_pipes,
        qos_queues,
        qos_classifiers,
        qos_cgroup_shaping,
        ips_rules,
        ips_mode,
        ips_whitelist,
        ips_sampling,
        ti_feeds,
        ti_mode,
    } = match convert_config(&config) {
        Ok(converted) => converted,
        Err(e) => {
            tracing::warn!(error = %e, "config reload rejected");
            return Err(e);
        }
    };

    // The first workload rule since start attaches the hooks kept for it.
    // Before the rules go in, while the tables still hold the empty policy
    // the agent started with, so nothing is refused that no rule explains;
    // and a refused attach rejects a file whose rule refuses, as start-up
    // does.
    if !workload_policy.is_empty()
        && let Some(status) = adapters::ebpf::workload_firewall_attach::attach_deferred()
        && !status.attached
    {
        let reason = status
            .reason
            .unwrap_or_else(|| "the kernel refused the attach".to_string());
        if workload_policy.enforces() {
            let refusal =
                adapters::ebpf::workload_firewall_attach::enforcement_unavailable(&reason);
            tracing::warn!("config reload rejected: {refusal}");
            return Err(refusal);
        }
        tracing::warn!(
            "workload firewall hooks did not attach, the rules that observe observe nothing: \
             {reason}"
        );
    }

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
        .reload_ids(
            ids_rules,
            config.ids_suricata_reports(),
            config.ids.enabled,
            ids_mode,
            ids_sampling,
        )
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

    // Phase 6b¾: the workload policy
    //
    // After the firewall's own rules rather than before: the two come out of
    // the same list, and a policy in force naming rules the engine has not
    // got yet is a window where the kernel refuses what no rule explains.
    match reload_service.reload_workload(workload_policy).await {
        Ok(()) => adapters::ebpf::workload_firewall_attach::publish_dns_rule(dns_rule),
        Err(e) => {
            tracing::warn!(error = %e, "workload policy reload failed at application level");
        }
    }

    // Phase 6c: ConnTrack reload
    let ct_settings = config.conntrack_settings();
    if let Err(e) = reload_service
        .reload_conntrack(ct_settings, config.conntrack.enabled)
        .await
    {
        tracing::warn!(error = %e, "conntrack config reload failed at application level");
    }
    // The per-source ceilings the reload may have added or removed: the
    // firewall keeps reading conntrack state for them, and the reconciler
    // ages their rate over the window now configured.
    reload_service
        .set_firewall_source_limits(crate::startup::source_limits_enforced(&config))
        .await;
    adapters::ebpf::connection_limits::set_rate_window(Duration::from_secs(u64::from(
        config.conntrack.conn_rate_window_secs,
    )));

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
    if let Err(e) = reload_service
        .reload_vip_announcer(vip_announce, vip_bgp)
        .await
    {
        tracing::warn!(error = %e, "VIP announcer config reload failed at application level");
    }

    // Phase 6f¾: QoS reload
    if let Err(e) = reload_service
        .reload_qos(
            qos_pipes,
            qos_queues,
            qos_classifiers,
            qos_cgroup_shaping,
            config.qos.enabled,
        )
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
                    match crate::auth_bootstrap::static_ml_dsa_key(&config.auth) {
                        Ok(Some(key)) => {
                            if let Err(e) = provider.rotate_ml_dsa_key(key) {
                                tracing::warn!(error = %e, "ML-DSA-65 key rotation failed, keeping current key");
                            }
                        }
                        Ok(None) => {}
                        Err(e) => tracing::warn!(
                            error = %e,
                            "ML-DSA-65 key rotation failed, keeping current key"
                        ),
                    }
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

    infrastructure::config::provenance::record_load(digest);
    Ok(config)
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

    #[test]
    fn validation_refuses_what_parsing_accepts_and_start_up_refuses() {
        let yaml = "agent:\n  interfaces: [lo]\nfirewall:\n  rules:\n    - id: deny-eth9\n      \
                    priority: 10\n      action: deny\n      scope: { interface: eth9 }\n";
        let parsed = AgentConfig::from_yaml(yaml).expect("the file parses");
        let err = validate_config(&parsed).expect_err("start-up refuses this rule");
        assert!(err.starts_with("invalid firewall rules"), "{err}");
        assert!(err.contains("eth9"), "{err}");

        let fine = AgentConfig::from_yaml(&yaml.replace("eth9", "lo")).expect("the file parses");
        assert_eq!(validate_config(&fine), Ok(()));
    }

    #[tokio::test]
    async fn a_refused_reload_answers_why_and_keeps_the_running_rules() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.yaml");
        std::fs::write(&path, "agent:\n  interfaces: [lo]\n").unwrap();
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .unwrap();
        let mut config = AgentConfig::load(&path).unwrap();
        config.audit.storage_path = dir.path().join("audit.redb").display().to_string();
        let services = crate::runtime::build_services(&config).unwrap();
        let reload_service = services.config_reload_service();
        let before: Vec<String> = services
            .firewall_svc
            .read()
            .await
            .list_rules()
            .iter()
            .map(|r| r.id.to_string())
            .collect();

        std::fs::write(
            &path,
            "agent:\n  interfaces: [lo]\nfirewall:\n  rules:\n    - id: deny-eth9\n      \
             priority: 10\n      action: deny\n      scope: { interface: eth9 }\n",
        )
        .unwrap();
        let verdict =
            apply_config_file_checked(path.to_str().unwrap(), &reload_service, None, |_| Ok(()))
                .await;

        let err = verdict.expect_err("a rule start-up refuses is refused by the reload");
        assert!(err.contains("eth9"), "{err}");
        let after: Vec<String> = services
            .firewall_svc
            .read()
            .await
            .list_rules()
            .iter()
            .map(|r| r.id.to_string())
            .collect();
        assert_eq!(
            after, before,
            "a refused file leaves the running rules as they were"
        );
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

    #[tokio::test]
    async fn a_prepared_reload_applies_the_rules_prepare_adds_or_rejects_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.yaml");
        std::fs::write(&path, "agent:\n  interfaces: [lo]\n").unwrap();
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .unwrap();

        let mut config = AgentConfig::load(&path).unwrap();
        config.audit.storage_path = dir.path().join("audit.redb").display().to_string();
        let services = crate::runtime::build_services(&config).unwrap();
        let reload_service = services.config_reload_service();
        let has_added = |services: &crate::runtime::ServiceHandles| {
            services
                .ids_svc
                .load()
                .list_rules()
                .iter()
                .any(|r| r.id.0 == "added-by-prepare")
        };

        let rejected =
            apply_config_file_prepared(path.to_str().unwrap(), &reload_service, None, |_| {
                Err("the added rules did not compile".to_string())
            })
            .await;
        assert!(rejected.is_none());

        let applied =
            apply_config_file_prepared(path.to_str().unwrap(), &reload_service, None, |config| {
                let mut imported = (*config.ids.imported).clone();
                imported.rules.push(domain::ids::entity::IdsRule {
                    id: domain::common::entity::RuleId("added-by-prepare".to_string()),
                    description: "added".to_string(),
                    severity: domain::common::entity::Severity::High,
                    mode: domain::common::entity::DomainMode::Alert,
                    protocol: domain::common::entity::Protocol::Tcp,
                    dst_port: Some(4444),
                    src_port: None,
                    pattern: String::new(),
                    enabled: true,
                    threshold: None,
                    domain_pattern: None,
                    domain_match_mode: None,
                    country_thresholds: None,
                    group_mask: 0,
                    tenant_id: 0,
                    workload: None,
                    kill_process: false,
                    imported: Some(Box::default()),
                });
                config.ids.imported = std::sync::Arc::new(imported);
                Ok(())
            })
            .await;
        assert!(applied.is_some());
        assert!(has_added(&services));
    }

    /// Firewall map port that keeps only the last word on the per-source
    /// ceilings.
    #[derive(Clone, Default)]
    struct SourceLimitsMap {
        enforced: Arc<std::sync::Mutex<Option<bool>>>,
    }

    mod source_limits_map {
        use domain::common::error::DomainError;
        use domain::trace::RulePlacement;
        use ebpf_common::firewall::{FirewallRuleEntry, FirewallRuleEntryV6};
        use ports::secondary::ebpf_map_port::{FirewallArrayMapPort, ShadowCounts};

        fn placements(len: usize) -> Vec<RulePlacement> {
            (0..len)
                .map(|i| RulePlacement::Array(u32::try_from(i).unwrap()))
                .collect()
        }

        impl FirewallArrayMapPort for super::SourceLimitsMap {
            fn load_v4_rules(
                &mut self,
                rules: &[FirewallRuleEntry],
            ) -> Result<Vec<RulePlacement>, DomainError> {
                Ok(placements(rules.len()))
            }

            fn load_v6_rules(
                &mut self,
                rules: &[FirewallRuleEntryV6],
            ) -> Result<Vec<RulePlacement>, DomainError> {
                Ok(placements(rules.len()))
            }

            fn set_default_policy(&mut self, _policy: u8) -> Result<(), DomainError> {
                Ok(())
            }

            fn rule_count(&self) -> Result<usize, DomainError> {
                Ok(0)
            }

            fn load_shadow_rules(
                &mut self,
                _v4: &[FirewallRuleEntry],
                _v6: &[FirewallRuleEntryV6],
            ) -> Result<bool, DomainError> {
                Ok(false)
            }

            fn read_shadow(&self) -> Result<ShadowCounts, DomainError> {
                Ok(ShadowCounts::default())
            }

            fn set_source_limits(&mut self, enforced: bool) {
                *self.enforced.lock().unwrap() = Some(enforced);
            }
        }
    }

    #[tokio::test]
    async fn a_source_ceiling_added_by_reload_opens_the_firewall_gate() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.yaml");
        std::fs::write(&path, "agent:\n  interfaces: [lo]\n").unwrap();
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .unwrap();

        let mut config = AgentConfig::load(&path).unwrap();
        config.audit.storage_path = dir.path().join("audit.redb").display().to_string();
        let services = crate::runtime::build_services(&config).unwrap();
        let map = SourceLimitsMap::default();
        services
            .firewall_svc
            .write()
            .await
            .set_map_port(Box::new(map.clone()));
        let reload_service = services.config_reload_service();

        let applied = apply_config_file(path.to_str().unwrap(), &reload_service, None).await;
        assert!(applied.is_some());
        assert_eq!(*map.enforced.lock().unwrap(), Some(false));

        std::fs::write(
            &path,
            "agent:\n  interfaces: [lo]\nconntrack:\n  enabled: true\n  max_src_states: 10\n",
        )
        .unwrap();
        let applied = apply_config_file(path.to_str().unwrap(), &reload_service, None).await;
        assert!(applied.is_some());
        assert_eq!(
            *map.enforced.lock().unwrap(),
            Some(true),
            "a ceiling added by reload must be enforced without a restart"
        );
    }
}
