use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use adapters::auth::jwt_provider::JwtAuthProvider;
use adapters::auth::oidc_provider::{self, OidcAuthProvider};
use adapters::ebpf::{ConfigFlagsManager, L7PortsManager};
use application::config_reload::ConfigReloadService;
use infrastructure::config::AgentConfig;
use notify_debouncer_mini::{DebouncedEventKind, new_debouncer};
use tokio::sync::{RwLock, mpsc};
use tokio_util::sync::CancellationToken;

/// Typed handle so the reload task knows which auth provider variant to refresh.
pub enum AuthProviderHandle {
    Jwt(Arc<JwtAuthProvider>),
    Oidc(Arc<OidcAuthProvider>),
    /// API keys only — no key rotation needed (keys live in config YAML).
    ApiKeyOnly,
}

/// Holds eBPF map managers that need re-sync on config hot-reload.
///
/// These managers are created during eBPF program loading in startup and
/// passed to the reload task so that config changes propagate to kernel maps.
pub struct EbpfMapHolder {
    /// L7 ports manager from tc-ids (re-syncs `L7_PORTS` map).
    pub l7_ports: Option<L7PortsManager>,
    /// `CONFIG_FLAGS` managers from tc-ids and tc-threatintel.
    pub config_flags: Vec<ConfigFlagsManager>,
}

impl EbpfMapHolder {
    pub fn new() -> Self {
        Self {
            l7_ports: None,
            config_flags: Vec::new(),
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
    mut api_trigger: mpsc::Receiver<()>,
    shared_config: Arc<RwLock<AgentConfig>>,
    mut ebpf_maps: EbpfMapHolder,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // Channel for file watcher events → async task
        let (notify_tx, mut notify_rx) = tokio::sync::mpsc::channel::<()>(4);

        // File watcher with 500ms debounce
        let tx_for_watcher = notify_tx.clone();
        let mut debouncer = match new_debouncer(
            Duration::from_millis(500),
            move |res: Result<Vec<notify_debouncer_mini::DebouncedEvent>, notify::Error>| {
                if let Ok(events) = res {
                    for event in &events {
                        if event.kind == DebouncedEventKind::Any {
                            let _ = tx_for_watcher.blocking_send(());
                            return; // one notification per batch is enough
                        }
                    }
                }
            },
        ) {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(error = %e, "failed to create file watcher, hot-reload disabled");
                return;
            }
        };

        if let Err(e) = debouncer
            .watcher()
            .watch(Path::new(&config_path), notify::RecursiveMode::NonRecursive)
        {
            tracing::warn!(
                path = %config_path,
                error = %e,
                "failed to watch config file, hot-reload disabled"
            );
            return;
        }

        tracing::info!(path = %config_path, "config file watcher started");

        // SIGHUP handler
        #[cfg(unix)]
        let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
            .expect("failed to install SIGHUP handler");

        loop {
            #[cfg(unix)]
            {
                tokio::select! {
                    () = cancel_token.cancelled() => {
                        tracing::info!("config watcher shutting down");
                        break;
                    }
                    _ = notify_rx.recv() => {
                        tracing::info!("config file change detected, reloading");
                    }
                    _ = sighup.recv() => {
                        tracing::info!("SIGHUP received, reloading configuration");
                    }
                    _ = api_trigger.recv() => {
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
                        tracing::info!("config file change detected, reloading");
                    }
                    _ = api_trigger.recv() => {
                        tracing::info!("API reload trigger received, reloading configuration");
                    }
                }
            }

            // If we broke out due to cancellation, don't reload
            if cancel_token.is_cancelled() {
                break;
            }

            // 2-phase validation: serde (phase 1) then domain (phase 2)
            perform_reload(
                &config_path,
                &reload_service,
                auth_handle.as_ref(),
                &shared_config,
                &mut ebpf_maps,
            )
            .await;
        }
    })
}

/// Perform a single config reload: load YAML, convert to domain rules, apply.
#[allow(clippy::too_many_lines, clippy::similar_names)] // reload is inherently sequential with many phases
async fn perform_reload(
    config_path: &str,
    reload_service: &ConfigReloadService,
    auth_handle: Option<&AuthProviderHandle>,
    shared_config: &RwLock<AgentConfig>,
    ebpf_maps: &mut EbpfMapHolder,
) {
    // Phase 1: serde deserialization
    let config = match AgentConfig::load(Path::new(config_path)) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "config reload rejected: invalid YAML");
            return;
        }
    };

    // Phase 2: domain validation (convert config rules to domain entities)
    let rules = match config.firewall_rules() {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "config reload rejected: invalid rules");
            return;
        }
    };

    // Phase 3: parse firewall mode
    let mode = match config.firewall_mode() {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(error = %e, "config reload rejected: invalid firewall mode");
            return;
        }
    };

    // Apply firewall reload
    if let Err(e) = reload_service
        .reload(rules, config.firewall.enabled, mode)
        .await
    {
        tracing::warn!(error = %e, "firewall config reload failed at application level");
    }

    // Phase 4: IDS reload
    let ids_rules = match config.ids_rules() {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "config reload rejected: invalid IDS rules");
            return;
        }
    };

    let ids_mode = match config.ids_mode() {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(error = %e, "config reload rejected: invalid IDS mode");
            return;
        }
    };

    let ids_sampling = match config.ids_sampling() {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "config reload rejected: invalid IDS sampling");
            return;
        }
    };

    if let Err(e) = reload_service
        .reload_ids(ids_rules, config.ids.enabled, ids_mode, ids_sampling)
        .await
    {
        tracing::warn!(error = %e, "IDS config reload failed at application level");
    }

    // Phase 5: L7 reload
    let l7_rules = match config.l7_rules() {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "config reload rejected: invalid L7 rules");
            return;
        }
    };

    if let Err(e) = reload_service.reload_l7(l7_rules, config.l7.enabled).await {
        tracing::warn!(error = %e, "L7 config reload failed at application level");
    }

    // Phase 6: Ratelimit reload
    let rl_policies = match config.ratelimit_policies() {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "config reload rejected: invalid ratelimit policies");
            return;
        }
    };

    if let Err(e) = reload_service
        .reload_ratelimit(rl_policies, config.ratelimit.enabled)
        .await
    {
        tracing::warn!(error = %e, "ratelimit config reload failed at application level");
    }

    // Phase 6b: DDoS reload
    let ddos_policies = match config.ddos_policies() {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "config reload rejected: invalid DDoS policies");
            return;
        }
    };

    if let Err(e) = reload_service
        .reload_ddos(ddos_policies, config.ddos.enabled)
        .await
    {
        tracing::warn!(error = %e, "DDoS config reload failed at application level");
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
    let dnat_rules = match config.nat_dnat_rules() {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "config reload rejected: invalid NAT DNAT rules");
            return;
        }
    };
    let snat_rules = match config.nat_snat_rules() {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "config reload rejected: invalid NAT SNAT rules");
            return;
        }
    };
    if let Err(e) = reload_service
        .reload_nat(dnat_rules, snat_rules, config.nat.enabled)
        .await
    {
        tracing::warn!(error = %e, "NAT config reload failed at application level");
    }

    // Phase 6e: Alias reload
    let aliases = match config.aliases() {
        Ok(a) => a,
        Err(e) => {
            tracing::warn!(error = %e, "config reload rejected: invalid aliases");
            return;
        }
    };
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

    // Phase 6f½: Load Balancer reload
    let lb_services = match config.lb_services() {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "config reload rejected: invalid LB services");
            return;
        }
    };
    if let Err(e) = reload_service
        .reload_loadbalancer(lb_services, config.loadbalancer.enabled)
        .await
    {
        tracing::warn!(error = %e, "load balancer config reload failed at application level");
    }

    // Phase 6g: IPS reload
    let ips_rules = match config.ips_rules() {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "config reload rejected: invalid IPS rules");
            return;
        }
    };
    let ips_mode = match config.ips_mode() {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(error = %e, "config reload rejected: invalid IPS mode");
            return;
        }
    };
    let ips_whitelist = match config.ips_whitelist() {
        Ok(w) => w,
        Err(e) => {
            tracing::warn!(error = %e, "config reload rejected: invalid IPS whitelist");
            return;
        }
    };
    let ips_sampling = match config.ips_sampling() {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "config reload rejected: invalid IPS sampling");
            return;
        }
    };
    let ips_policy = config.ips_policy();
    if let Err(e) = reload_service
        .reload_ips(
            ips_rules,
            ips_whitelist,
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
    let ti_feeds = match config.threatintel_feeds() {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(error = %e, "config reload rejected: invalid threat intel feeds");
            return;
        }
    };
    let ti_mode = match config.threatintel_mode() {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(error = %e, "config reload rejected: invalid threat intel mode");
            return;
        }
    };
    if let Err(e) = reload_service
        .reload_threatintel(ti_feeds, config.threatintel.enabled, ti_mode)
        .await
    {
        tracing::warn!(error = %e, "threat intel config reload failed");
    }

    // Phase 6i: Re-sync eBPF kernel maps (L7_PORTS, CONFIG_FLAGS)
    if let Some(ref mut l7_mgr) = ebpf_maps.l7_ports {
        let ports = config.l7_ports();
        if let Err(e) = l7_mgr.set_ports(&ports) {
            tracing::warn!(error = %e, "L7_PORTS reload failed");
        } else {
            tracing::debug!(port_count = ports.len(), "L7_PORTS reloaded");
        }
    }
    let flags = crate::startup::build_config_flags(&config);
    for cfg_mgr in &mut ebpf_maps.config_flags {
        if let Err(e) = cfg_mgr.set_flags(&flags) {
            tracing::warn!(error = %e, "CONFIG_FLAGS reload failed");
        }
    }
    if !ebpf_maps.config_flags.is_empty() {
        tracing::debug!(
            count = ebpf_maps.config_flags.len(),
            "CONFIG_FLAGS reloaded across eBPF programs"
        );
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
                // API keys are reloaded from config — no separate rotation needed.
                // A full config reload (phases 1-6) already picks up new YAML values.
                tracing::debug!("API key auth: no key rotation required");
            }
        }
    }

    // Phase 8: Update shared config for ops endpoints
    *shared_config.write().await = config;
}
