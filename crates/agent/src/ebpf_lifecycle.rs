use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use adapters::ebpf::{
    ConfigFlagsManager, EbpfLoader, InterfaceGroupsManager, L7PortsManager, MetricsReader,
    TenantSubnetMapManager, TenantVlanMapManager,
};
use application::packet_pipeline::AgentEvent;
use infrastructure::config::AgentConfig;
use ports::secondary::metrics_port::FirewallMetrics;
use tokio::sync::{RwLock, mpsc};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::runtime::ServiceHandles;
use crate::startup;

/// Resources belonging to a single loaded eBPF program.
pub struct ProgramHandle {
    pub name: String,
    pub loader: EbpfLoader,
    pub reader_cancel: CancellationToken,
    pub reader_handles: Vec<JoinHandle<()>>,
}

/// Manages the lifecycle of all eBPF programs at runtime.
///
/// Enables loading/unloading individual eBPF programs in response to
/// configuration changes without restarting the agent.
pub struct EbpfProgramManager {
    programs: HashMap<String, ProgramHandle>,
    event_tx: mpsc::Sender<AgentEvent>,
    services: Arc<ServiceHandles>,
    ebpf_dir: String,
    /// Cross-program config flags managers (from tc-ids, tc-threatintel).
    pub config_flags: Vec<ConfigFlagsManager>,
    /// L7 ports manager (from tc-ids).
    pub l7_ports: Option<L7PortsManager>,
    /// Cross-program interface groups manager.
    pub iface_groups: InterfaceGroupsManager,
    /// Cross-program tenant VLAN map manager.
    pub tenant_vlan: TenantVlanMapManager,
    /// Cross-program tenant subnet map manager.
    pub tenant_subnet: TenantSubnetMapManager,
    /// Shared metrics readers — the kernel metrics loop reads from this.
    pub metrics_readers: Arc<RwLock<Vec<MetricsReader>>>,
    /// Programs loaded during startup (loaders kept alive in `EbpfState`).
    /// These are tracked by name so `is_loaded()` returns true without
    /// needing a `ProgramHandle`.
    startup_loaded: HashSet<String>,
}

impl EbpfProgramManager {
    pub fn new(
        event_tx: mpsc::Sender<AgentEvent>,
        services: Arc<ServiceHandles>,
        ebpf_dir: String,
    ) -> Self {
        Self {
            programs: HashMap::new(),
            event_tx,
            services,
            ebpf_dir,
            config_flags: Vec::new(),
            l7_ports: None,
            iface_groups: InterfaceGroupsManager::new(),
            tenant_vlan: TenantVlanMapManager::new(),
            tenant_subnet: TenantSubnetMapManager::new(),
            metrics_readers: Arc::new(RwLock::new(Vec::new())),
            startup_loaded: HashSet::new(),
        }
    }

    /// Get a clone of the shared metrics readers handle (for the kernel metrics loop).
    pub fn shared_metrics_readers(&self) -> Arc<RwLock<Vec<MetricsReader>>> {
        Arc::clone(&self.metrics_readers)
    }

    /// Register a pre-loaded program (used during startup to migrate from legacy path).
    pub fn register_program(&mut self, name: String, loader: EbpfLoader) {
        let handle = ProgramHandle {
            name: name.clone(),
            loader,
            reader_cancel: CancellationToken::new(),
            reader_handles: Vec::new(),
        };
        self.programs.insert(name, handle);
    }

    /// Mark a program as loaded at startup (without transferring a loader).
    ///
    /// Used for programs loaded by the legacy startup path whose loaders are
    /// kept alive separately in `EbpfState`. Prevents Phase 9 from trying to
    /// re-load them.
    /// Mark a program as loaded during startup (loader kept alive in EbpfState).
    pub fn mark_startup_loaded(&mut self, name: &str) {
        self.startup_loaded.insert(name.to_string());
    }

    /// Add metrics readers (used during startup migration).
    pub async fn add_metrics_readers(&self, readers: Vec<MetricsReader>) {
        let mut lock = self.metrics_readers.write().await;
        lock.extend(readers);
    }

    /// Check if a program is currently loaded (either via hot-reload or startup).
    pub fn is_loaded(&self, name: &str) -> bool {
        self.programs.contains_key(name) || self.startup_loaded.contains(name)
    }

    /// Return the load status of all known programs.
    pub fn program_status(&self) -> HashMap<String, bool> {
        let all_programs = [
            "xdp_firewall",
            "xdp_ratelimit",
            "xdp_loadbalancer",
            "tc_ids",
            "tc_threatintel",
            "tc_dns",
            "tc_conntrack",
            "tc_nat",
            "tc_scrub",
            "uprobe_dlp",
        ];
        all_programs
            .iter()
            .map(|&name| (name.to_string(), self.programs.contains_key(name)))
            .collect()
    }

    /// Enable a Category A (independent TC/uprobe) program by name.
    ///
    /// Loads the eBPF program, attaches it to interfaces, creates map managers,
    /// wires them into services, and starts event readers.
    pub async fn enable_program(&mut self, name: &str, config: &AgentConfig) -> anyhow::Result<()> {
        if self.programs.contains_key(name) {
            info!(program = name, "program already loaded, skipping");
            return Ok(());
        }

        match name {
            "tc_ids" => self.enable_tc_ids(config).await,
            "tc_threatintel" => self.enable_tc_threatintel(config).await,
            "tc_dns" => self.enable_tc_dns(config).await,
            "tc_conntrack" => self.enable_tc_conntrack(config).await,
            "tc_nat" => self.enable_tc_nat(config).await,
            "tc_scrub" => self.enable_tc_scrub(config).await,
            "uprobe_dlp" => self.enable_uprobe_dlp(config).await,
            _ => {
                warn!(
                    program = name,
                    "enable_program not implemented for this program"
                );
                Ok(())
            }
        }
    }

    /// Disable a program by name: cancel readers, clear map ports, drop loader.
    pub async fn disable_program(&mut self, name: &str) -> anyhow::Result<()> {
        let Some(handle) = self.programs.remove(name) else {
            info!(program = name, "program not loaded, skipping disable");
            return Ok(());
        };

        // Cancel event readers
        handle.reader_cancel.cancel();
        for jh in &handle.reader_handles {
            jh.abort();
        }

        // Clear map ports from services
        match name {
            "tc_ids" => {
                let mut svc = (**self.services.ids_svc.load()).clone();
                svc.clear_map_port();
                self.services.ids_svc.store(Arc::new(svc));
            }
            "tc_threatintel" => {
                let mut svc = (**self.services.ti_svc.load()).clone();
                svc.clear_map_port();
                self.services.ti_svc.store(Arc::new(svc));
            }
            "tc_conntrack" => {
                self.services.conntrack_svc.write().await.clear_map_port();
            }
            "tc_nat" => {
                self.services.nat_svc.write().await.clear_map_port();
            }
            _ => {}
        }

        // Drop the loader — this detaches the eBPF program from interfaces
        drop(handle);

        self.services.metrics.set_ebpf_program_status(name, false);
        info!(program = name, "eBPF program disabled and detached");
        Ok(())
    }

    /// Re-sync `CONFIG_FLAGS` eBPF maps from the current config.
    pub fn sync_config_flags(&mut self, config: &AgentConfig) {
        let flags = startup::build_config_flags(config);
        for cfg_mgr in &mut self.config_flags {
            if let Err(e) = cfg_mgr.set_flags(&flags) {
                warn!(error = %e, "CONFIG_FLAGS reload failed");
            }
        }
    }

    /// Detach all programs (shutdown).
    pub async fn detach_all(&mut self) {
        let names: Vec<String> = self.programs.keys().cloned().collect();
        for name in &names {
            if let Some(handle) = self.programs.remove(name) {
                handle.reader_cancel.cancel();
                for jh in handle.reader_handles {
                    let _ = tokio::time::timeout(Duration::from_secs(1), jh).await;
                }
            }
        }
        EbpfLoader::cleanup_pin_path(adapters::ebpf::DEFAULT_BPF_PIN_PATH);
        info!("all eBPF programs detached");
    }

    /// Get the mutable loader for a program (needed for tail-call wiring).
    pub fn loader_mut(&mut self, name: &str) -> Option<&mut EbpfLoader> {
        self.programs.get_mut(name).map(|h| &mut h.loader)
    }

    // ── Per-program enable implementations ─────────────────────────

    async fn enable_tc_ids(&mut self, config: &AgentConfig) -> anyhow::Result<()> {
        let (mut loader, ids_mgr_opt, l7_mgr_opt, cfg_mgr_opt, ids_rdr, reader) =
            startup::try_load_tc_ids(&self.ebpf_dir, config)?;

        let cancel = CancellationToken::new();
        let tx = self.event_tx.clone();
        let c = cancel.clone();
        let jh = tokio::spawn(async move { reader.run(tx, c).await });

        if let Some(ids_mgr) = ids_mgr_opt {
            {
                let mut svc = (**self.services.ids_svc.load()).clone();
                svc.set_map_port(Box::new(ids_mgr));
                self.services.ids_svc.store(Arc::new(svc));
            }
        }
        if let Some(l7_mgr) = l7_mgr_opt {
            self.l7_ports = Some(l7_mgr);
        }
        if let Some(cfg_mgr) = cfg_mgr_opt {
            self.config_flags.push(cfg_mgr);
        }
        if let Some(rdr) = ids_rdr {
            self.metrics_readers.write().await.push(rdr);
        }

        self.iface_groups.add_map(loader.ebpf_mut());
        self.tenant_vlan.add_map(loader.ebpf_mut());
        self.tenant_subnet.add_map(loader.ebpf_mut());
        self.tenant_subnet.add_v6_map(loader.ebpf_mut());

        self.services
            .metrics
            .set_ebpf_program_status("tc_ids", true);

        self.programs.insert(
            "tc_ids".to_string(),
            ProgramHandle {
                name: "tc_ids".to_string(),
                loader,
                reader_cancel: cancel,
                reader_handles: vec![jh],
            },
        );

        info!("tc-ids enabled via hot-reload");
        Ok(())
    }

    async fn enable_tc_threatintel(&mut self, config: &AgentConfig) -> anyhow::Result<()> {
        let (mut loader, ti_mgr_opt, cfg_mgr_opt, ti_rdr, reader) =
            startup::try_load_tc_threatintel(&self.ebpf_dir, config)?;

        let cancel = CancellationToken::new();
        let tx = self.event_tx.clone();
        let c = cancel.clone();
        let jh = tokio::spawn(async move { reader.run(tx, c).await });

        if let Some(ti_mgr) = ti_mgr_opt {
            let mut svc = (**self.services.ti_svc.load()).clone();
            svc.set_map_port(Box::new(ti_mgr));
            self.services.ti_svc.store(Arc::new(svc));
        }
        if let Some(cfg_mgr) = cfg_mgr_opt {
            self.config_flags.push(cfg_mgr);
        }
        if let Some(rdr) = ti_rdr {
            self.metrics_readers.write().await.push(rdr);
        }

        self.tenant_vlan.add_map(loader.ebpf_mut());

        self.services
            .metrics
            .set_ebpf_program_status("tc_threatintel", true);

        self.programs.insert(
            "tc_threatintel".to_string(),
            ProgramHandle {
                name: "tc_threatintel".to_string(),
                loader,
                reader_cancel: cancel,
                reader_handles: vec![jh],
            },
        );

        info!("tc-threatintel enabled via hot-reload");
        Ok(())
    }

    async fn enable_tc_dns(&mut self, config: &AgentConfig) -> anyhow::Result<()> {
        let (mut loader, dns_rdr, reader) = startup::try_load_tc_dns(&self.ebpf_dir, config)?;

        let cancel = CancellationToken::new();
        let tx = self.event_tx.clone();
        let c = cancel.clone();
        let jh = tokio::spawn(async move { reader.run(tx, c).await });

        if let Some(rdr) = dns_rdr {
            self.metrics_readers.write().await.push(rdr);
        }

        self.tenant_vlan.add_map(loader.ebpf_mut());

        self.services
            .metrics
            .set_ebpf_program_status("tc_dns", true);

        self.programs.insert(
            "tc_dns".to_string(),
            ProgramHandle {
                name: "tc_dns".to_string(),
                loader,
                reader_cancel: cancel,
                reader_handles: vec![jh],
            },
        );

        info!("tc-dns enabled via hot-reload");
        Ok(())
    }

    async fn enable_tc_conntrack(&mut self, config: &AgentConfig) -> anyhow::Result<()> {
        let (mut loader, ct_mgr, ct_rdr, opt_reader) =
            startup::try_load_tc_conntrack(&self.ebpf_dir, config)?;

        let cancel = CancellationToken::new();
        let mut handles = Vec::new();
        if let Some(reader) = opt_reader {
            let tx = self.event_tx.clone();
            let c = cancel.clone();
            handles.push(tokio::spawn(async move { reader.run(tx, c).await }));
        }

        self.services
            .conntrack_svc
            .write()
            .await
            .set_map_port(Box::new(ct_mgr));
        if let Some(rdr) = ct_rdr {
            self.metrics_readers.write().await.push(rdr);
        }

        self.tenant_vlan.add_map(loader.ebpf_mut());

        self.services
            .metrics
            .set_ebpf_program_status("tc_conntrack", true);

        self.programs.insert(
            "tc_conntrack".to_string(),
            ProgramHandle {
                name: "tc_conntrack".to_string(),
                loader,
                reader_cancel: cancel,
                reader_handles: handles,
            },
        );

        info!("tc-conntrack enabled via hot-reload");
        Ok(())
    }

    async fn enable_tc_nat(&mut self, config: &AgentConfig) -> anyhow::Result<()> {
        let (mut ingress_loader, mut egress_loader, nat_mgr, nat_rdrs) =
            startup::try_load_tc_nat(&self.ebpf_dir, config)?;

        self.services
            .nat_svc
            .write()
            .await
            .set_map_port(Box::new(nat_mgr));

        {
            let mut lock = self.metrics_readers.write().await;
            lock.extend(nat_rdrs);
        }

        self.iface_groups.add_map(ingress_loader.ebpf_mut());
        self.iface_groups.add_map(egress_loader.ebpf_mut());
        self.tenant_vlan.add_map(ingress_loader.ebpf_mut());
        self.tenant_vlan.add_map(egress_loader.ebpf_mut());
        self.tenant_subnet.add_map(ingress_loader.ebpf_mut());
        self.tenant_subnet.add_v6_map(ingress_loader.ebpf_mut());
        self.tenant_subnet.add_map(egress_loader.ebpf_mut());
        self.tenant_subnet.add_v6_map(egress_loader.ebpf_mut());

        self.services
            .metrics
            .set_ebpf_program_status("tc_nat_ingress", true);
        self.services
            .metrics
            .set_ebpf_program_status("tc_nat_egress", true);

        // NAT uses two loaders — store ingress as the primary handle, egress as a second.
        let cancel = CancellationToken::new();
        self.programs.insert(
            "tc_nat".to_string(),
            ProgramHandle {
                name: "tc_nat".to_string(),
                loader: ingress_loader,
                reader_cancel: cancel.clone(),
                reader_handles: Vec::new(),
            },
        );
        self.programs.insert(
            "tc_nat_egress".to_string(),
            ProgramHandle {
                name: "tc_nat_egress".to_string(),
                loader: egress_loader,
                reader_cancel: cancel,
                reader_handles: Vec::new(),
            },
        );

        info!("tc-nat enabled via hot-reload");
        Ok(())
    }

    async fn enable_tc_scrub(&mut self, config: &AgentConfig) -> anyhow::Result<()> {
        let (mut loader, scrub_rdr) = startup::try_load_tc_scrub(&self.ebpf_dir, config)?;

        if let Some(rdr) = scrub_rdr {
            self.metrics_readers.write().await.push(rdr);
        }

        self.tenant_vlan.add_map(loader.ebpf_mut());

        self.services
            .metrics
            .set_ebpf_program_status("tc_scrub", true);

        self.programs.insert(
            "tc_scrub".to_string(),
            ProgramHandle {
                name: "tc_scrub".to_string(),
                loader,
                reader_cancel: CancellationToken::new(),
                reader_handles: Vec::new(),
            },
        );

        info!("tc-scrub enabled via hot-reload");
        Ok(())
    }

    async fn enable_uprobe_dlp(&mut self, config: &AgentConfig) -> anyhow::Result<()> {
        let (mut loader, dlp_rdr, reader) = startup::try_load_uprobe_dlp(&self.ebpf_dir, config)?;

        let cancel = CancellationToken::new();
        let tx = self.event_tx.clone();
        let c = cancel.clone();
        let jh = tokio::spawn(async move { reader.run(tx, c).await });

        if let Some(rdr) = dlp_rdr {
            self.metrics_readers.write().await.push(rdr);
        }

        self.tenant_vlan.add_map(loader.ebpf_mut());

        self.services
            .metrics
            .set_ebpf_program_status("uprobe_dlp", true);

        self.programs.insert(
            "uprobe_dlp".to_string(),
            ProgramHandle {
                name: "uprobe_dlp".to_string(),
                loader,
                reader_cancel: cancel,
                reader_handles: vec![jh],
            },
        );

        info!("uprobe-dlp enabled via hot-reload");
        Ok(())
    }

    // ── XDP chain management (Phase 2) ─────────────────────────────

    /// Recalculate and rewire the entire XDP tail-call chain based on
    /// which XDP programs are currently loaded.
    ///
    /// # Topology
    ///
    /// ```text
    /// firewall (root) ─┬─ slot 0 → ratelimit ─┬─ slot 0 → syncookie
    ///                   │                       └─ slot 1 → loadbalancer
    ///                   ├─ slot 1 → reject
    ///                   └─ slot 2 → loadbalancer (fallback when RL absent)
    ///
    /// ratelimit (root, standalone) ─┬─ slot 0 → syncookie
    ///                               └─ slot 1 → loadbalancer
    ///
    /// loadbalancer (root, standalone)
    /// ```
    pub async fn rewire_xdp_chain(&mut self, _config: &AgentConfig) -> anyhow::Result<()> {
        let fw_loaded = self.is_loaded("xdp_firewall");
        let rl_loaded = self.is_loaded("xdp_ratelimit");
        let lb_loaded = self.is_loaded("xdp_loadbalancer");

        // Wire firewall → ratelimit (slot 0)
        if fw_loaded && rl_loaded {
            let rl_fd = {
                let rl = self
                    .programs
                    .get("xdp_ratelimit")
                    .ok_or_else(|| anyhow::anyhow!("xdp_ratelimit not loaded"))?;
                rl.loader.xdp_program_fd("xdp_ratelimit")?
            };
            if let Some(fw) = self.programs.get_mut("xdp_firewall") {
                fw.loader
                    .set_tail_call_target("XDP_PROG_ARRAY", 0, &rl_fd)?;
                info!("XDP chain: firewall → ratelimit wired (slot 0)");
            }
        } else if fw_loaded {
            // Ratelimit absent — clear slot 0
            if let Some(fw) = self.programs.get_mut("xdp_firewall") {
                let _ = fw.loader.clear_tail_call_target("XDP_PROG_ARRAY", 0);
            }
        }

        // Wire firewall → loadbalancer (slot 2, fallback when RL absent)
        if fw_loaded && lb_loaded && !rl_loaded {
            let lb_fd = {
                let lb = self
                    .programs
                    .get("xdp_loadbalancer")
                    .ok_or_else(|| anyhow::anyhow!("xdp_loadbalancer not loaded"))?;
                lb.loader.xdp_program_fd("xdp_loadbalancer")?
            };
            if let Some(fw) = self.programs.get_mut("xdp_firewall") {
                fw.loader
                    .set_tail_call_target("XDP_PROG_ARRAY", 2, &lb_fd)?;
                info!("XDP chain: firewall → loadbalancer wired (slot 2)");
            }
        } else if fw_loaded {
            if let Some(fw) = self.programs.get_mut("xdp_firewall") {
                let _ = fw.loader.clear_tail_call_target("XDP_PROG_ARRAY", 2);
            }
        }

        // Wire ratelimit → loadbalancer (RL slot 1)
        if rl_loaded && lb_loaded {
            let lb_fd = {
                let lb = self
                    .programs
                    .get("xdp_loadbalancer")
                    .ok_or_else(|| anyhow::anyhow!("xdp_loadbalancer not loaded"))?;
                lb.loader.xdp_program_fd("xdp_loadbalancer")?
            };
            if let Some(rl) = self.programs.get_mut("xdp_ratelimit") {
                rl.loader.set_tail_call_target("RL_PROG_ARRAY", 1, &lb_fd)?;
                info!("XDP chain: ratelimit → loadbalancer wired (RL slot 1)");
            }
        } else if rl_loaded {
            if let Some(rl) = self.programs.get_mut("xdp_ratelimit") {
                let _ = rl.loader.clear_tail_call_target("RL_PROG_ARRAY", 1);
            }
        }

        Ok(())
    }

    /// Enable an XDP program and rewire the chain.
    pub async fn enable_xdp_program(
        &mut self,
        name: &str,
        config: &AgentConfig,
    ) -> anyhow::Result<()> {
        if self.programs.contains_key(name) {
            return Ok(());
        }

        match name {
            "xdp_firewall" => {
                let domain_rules = config.firewall_rules().unwrap_or_default();
                let (mut loader, map_manager, metrics_rdr, reader) =
                    startup::try_load_xdp_firewall(&self.ebpf_dir, config, &domain_rules)?;

                let cancel = CancellationToken::new();
                let tx = self.event_tx.clone();
                let c = cancel.clone();
                let jh = tokio::spawn(async move { reader.run(tx, c).await });

                self.services
                    .firewall_svc
                    .write()
                    .await
                    .set_map_port(Box::new(map_manager));
                if let Some(rdr) = metrics_rdr {
                    self.metrics_readers.write().await.push(rdr);
                }

                self.iface_groups.add_map(loader.ebpf_mut());
                self.tenant_vlan.add_map(loader.ebpf_mut());
                self.tenant_subnet.add_map(loader.ebpf_mut());
                self.tenant_subnet.add_v6_map(loader.ebpf_mut());

                // Load reject helper as tail-call target (best-effort)
                if let Ok(reject_loader) =
                    startup::try_load_xdp_firewall_reject(&self.ebpf_dir, &mut loader)
                {
                    self.programs.insert(
                        "xdp_firewall_reject".to_string(),
                        ProgramHandle {
                            name: "xdp_firewall_reject".to_string(),
                            loader: reject_loader,
                            reader_cancel: CancellationToken::new(),
                            reader_handles: Vec::new(),
                        },
                    );
                }

                self.services
                    .metrics
                    .set_ebpf_program_status("xdp_firewall", true);

                self.programs.insert(
                    "xdp_firewall".to_string(),
                    ProgramHandle {
                        name: "xdp_firewall".to_string(),
                        loader,
                        reader_cancel: cancel,
                        reader_handles: vec![jh],
                    },
                );

                info!("xdp-firewall enabled via hot-reload");
            }
            "xdp_ratelimit" => {
                let fw_active = self.is_loaded("xdp_firewall");
                let (mut loader, rl_mgr_opt, _rl_lpm_opt, rl_rdrs, reader) =
                    startup::try_load_xdp_ratelimit(&self.ebpf_dir, config, fw_active)?;

                let cancel = CancellationToken::new();
                let tx = self.event_tx.clone();
                let c = cancel.clone();
                let jh = tokio::spawn(async move { reader.run(tx, c).await });

                if let Some(rl_mgr) = rl_mgr_opt {
                    self.services
                        .rl_svc
                        .write()
                        .await
                        .set_map_port(Box::new(rl_mgr));
                }
                {
                    let mut lock = self.metrics_readers.write().await;
                    lock.extend(rl_rdrs);
                }

                self.iface_groups.add_map(loader.ebpf_mut());
                self.tenant_vlan.add_map(loader.ebpf_mut());
                self.tenant_subnet.add_map(loader.ebpf_mut());
                self.tenant_subnet.add_v6_map(loader.ebpf_mut());

                // Load syncookie tail-call target (best-effort)
                if let Ok(sc_loader) =
                    startup::try_load_xdp_ratelimit_syncookie(&self.ebpf_dir, &mut loader)
                {
                    self.programs.insert(
                        "xdp_ratelimit_syncookie".to_string(),
                        ProgramHandle {
                            name: "xdp_ratelimit_syncookie".to_string(),
                            loader: sc_loader,
                            reader_cancel: CancellationToken::new(),
                            reader_handles: Vec::new(),
                        },
                    );
                }

                self.services
                    .metrics
                    .set_ebpf_program_status("xdp_ratelimit", true);

                self.programs.insert(
                    "xdp_ratelimit".to_string(),
                    ProgramHandle {
                        name: "xdp_ratelimit".to_string(),
                        loader,
                        reader_cancel: cancel,
                        reader_handles: vec![jh],
                    },
                );

                info!("xdp-ratelimit enabled via hot-reload");
            }
            "xdp_loadbalancer" => {
                let xdp_chain_active =
                    self.is_loaded("xdp_firewall") || self.is_loaded("xdp_ratelimit");
                let (mut loader, lb_mgr, lb_metrics_rdr, reader) =
                    startup::try_load_xdp_loadbalancer(&self.ebpf_dir, config, xdp_chain_active)?;

                let cancel = CancellationToken::new();
                let tx = self.event_tx.clone();
                let c = cancel.clone();
                let jh = tokio::spawn(async move { reader.run(tx, c).await });

                self.services
                    .lb_svc
                    .write()
                    .await
                    .set_map_port(Box::new(lb_mgr));
                if let Some(rdr) = lb_metrics_rdr {
                    self.metrics_readers.write().await.push(rdr);
                }

                self.tenant_vlan.add_map(loader.ebpf_mut());

                self.services
                    .metrics
                    .set_ebpf_program_status("xdp_loadbalancer", true);

                self.programs.insert(
                    "xdp_loadbalancer".to_string(),
                    ProgramHandle {
                        name: "xdp_loadbalancer".to_string(),
                        loader,
                        reader_cancel: cancel,
                        reader_handles: vec![jh],
                    },
                );

                info!("xdp-loadbalancer enabled via hot-reload");
            }
            _ => {
                warn!(program = name, "enable_xdp_program: unknown XDP program");
            }
        }

        // Rewire the tail-call chain after any XDP program change
        self.rewire_xdp_chain(config).await?;
        Ok(())
    }

    /// Disable an XDP program and rewire the chain.
    pub async fn disable_xdp_program(
        &mut self,
        name: &str,
        config: &AgentConfig,
    ) -> anyhow::Result<()> {
        // Remove the program and its helpers
        match name {
            "xdp_firewall" => {
                self.programs.remove("xdp_firewall_reject");
                if let Some(handle) = self.programs.remove("xdp_firewall") {
                    handle.reader_cancel.cancel();
                    for jh in &handle.reader_handles {
                        jh.abort();
                    }
                }
                self.services.firewall_svc.write().await.clear_map_port();
                self.services
                    .metrics
                    .set_ebpf_program_status("xdp_firewall", false);
            }
            "xdp_ratelimit" => {
                self.programs.remove("xdp_ratelimit_syncookie");
                if let Some(handle) = self.programs.remove("xdp_ratelimit") {
                    handle.reader_cancel.cancel();
                    for jh in &handle.reader_handles {
                        jh.abort();
                    }
                }
                self.services.rl_svc.write().await.clear_map_port();
                self.services
                    .metrics
                    .set_ebpf_program_status("xdp_ratelimit", false);
            }
            "xdp_loadbalancer" => {
                if let Some(handle) = self.programs.remove("xdp_loadbalancer") {
                    handle.reader_cancel.cancel();
                    for jh in &handle.reader_handles {
                        jh.abort();
                    }
                }
                self.services.lb_svc.write().await.clear_map_port();
                self.services
                    .metrics
                    .set_ebpf_program_status("xdp_loadbalancer", false);
            }
            _ => {}
        }

        info!(program = name, "XDP program disabled");

        // Rewire the tail-call chain after removal
        self.rewire_xdp_chain(config).await?;
        Ok(())
    }
}

/// Build the mapping from program names to their config enabled flags.
///
/// Only includes Category A (independent TC/uprobe) programs.
/// XDP chain programs are handled by [`xdp_config_map`].
pub fn program_config_map(config: &AgentConfig) -> Vec<(&'static str, bool)> {
    vec![
        ("tc_ids", config.ids.enabled),
        ("tc_threatintel", config.threatintel.enabled),
        ("tc_dns", config.dns.enabled),
        ("tc_conntrack", config.conntrack.enabled),
        ("tc_nat", config.nat.enabled),
        ("tc_scrub", config.firewall.scrub.enabled),
        ("uprobe_dlp", config.dlp.enabled),
    ]
}

/// Build the XDP program config map.
pub fn xdp_config_map(config: &AgentConfig) -> Vec<(&'static str, bool)> {
    vec![
        ("xdp_firewall", config.firewall.enabled),
        ("xdp_ratelimit", config.ratelimit.enabled),
        ("xdp_loadbalancer", config.loadbalancer.enabled),
    ]
}
