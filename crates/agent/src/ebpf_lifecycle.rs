use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use adapters::ebpf::{
    ConfigFlagsManager, EbpfLoader, InterfaceGroupsManager, L7PortsManager, MetricsReader,
    RingBufObserver, TenantCgroupMapManager, TenantIfindexMapManager, TenantSubnetMapManager,
    TenantVlanMapManager,
};
use application::packet_pipeline::AgentEvent;
use infrastructure::config::AgentConfig;
use ports::secondary::metrics_port::{FirewallMetrics, MetricsPort};
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
    /// Config flags managers, each with the program whose map it holds
    /// (tc-ids, tc-threatintel), so unloading a program releases its own.
    pub config_flags: Vec<(&'static str, ConfigFlagsManager)>,
    /// L7 ports manager (from tc-ids).
    pub l7_ports: Option<L7PortsManager>,
    /// Cross-program interface groups manager.
    pub iface_groups: InterfaceGroupsManager,
    /// Cross-program tenant VLAN map manager.
    pub tenant_vlan: TenantVlanMapManager,
    /// Cross-program tenant interface map manager.
    pub tenant_ifindex: TenantIfindexMapManager,
    /// Cross-program tenant subnet map manager.
    pub tenant_subnet: TenantSubnetMapManager,
    /// Tenant cgroup map manager (from tc-ids, the only program that resolves
    /// a tenant from the originating cgroup).
    pub tenant_cgroup: TenantCgroupMapManager,
    /// Shared metrics readers - the kernel metrics loop reads from this.
    pub metrics_readers: Arc<RwLock<Vec<MetricsReader>>>,
    /// Load state per published program name, as `/api/v1/ebpf/status` and
    /// the anonymous heartbeat read it.
    pub program_status: Arc<RwLock<HashMap<String, bool>>>,
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
            tenant_ifindex: TenantIfindexMapManager::new(),
            tenant_subnet: TenantSubnetMapManager::new(),
            tenant_cgroup: TenantCgroupMapManager::new(),
            metrics_readers: Arc::new(RwLock::new(Vec::new())),
            program_status: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Record a program's load state everywhere it is published: the
    /// Prometheus gauge and the map the status endpoint reads.
    async fn set_status(&self, program: &str, loaded: bool) {
        self.services
            .metrics
            .set_ebpf_program_status(program, loaded);
        self.program_status
            .write()
            .await
            .insert(adapters::ebpf::published_program_name(program), loaded);
    }

    /// Get a clone of the shared metrics readers handle (for the kernel metrics loop).
    pub fn shared_metrics_readers(&self) -> Arc<RwLock<Vec<MetricsReader>>> {
        Arc::clone(&self.metrics_readers)
    }

    /// Ring-buffer accounting for the reader a hot-reload is about to spawn,
    /// labelled by the program that feeds it.
    fn ringbuf_observer(&self, source: &'static str) -> RingBufObserver {
        RingBufObserver::new(
            source,
            Arc::clone(&self.services.metrics) as Arc<dyn MetricsPort>,
        )
    }

    /// Hold the `CONFIG_FLAGS` manager of a program just loaded, in place of
    /// any manager left from an earlier load of the same program.
    fn set_config_flags(&mut self, program: &'static str, manager: ConfigFlagsManager) {
        self.config_flags.retain(|(owner, _)| *owner != program);
        self.config_flags.push((program, manager));
    }

    /// Take over a program startup loaded, with the token its readers run under.
    pub fn register_program(&mut self, name: &str, loader: EbpfLoader, cancel: CancellationToken) {
        let handle = ProgramHandle {
            name: name.to_string(),
            loader,
            reader_cancel: cancel,
            reader_handles: Vec::new(),
        };
        self.programs.insert(name.to_string(), handle);
    }

    /// Check if a program is currently loaded.
    pub fn is_loaded(&self, name: &str) -> bool {
        self.programs.contains_key(name)
    }

    /// Stop reading the kernel counters of a program being unloaded.
    ///
    /// Counter maps are pinned by name, so a program loaded again shares the
    /// same map: a reader left behind would count every packet twice.
    async fn drop_metrics_readers(&self, program: &str) {
        let maps = metrics_maps(program);
        if maps.is_empty() {
            return;
        }
        self.metrics_readers
            .write()
            .await
            .retain(|r| !maps.contains(&r.map_name()));
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
        self.drop_metrics_readers(name).await;
        self.config_flags.retain(|(program, _)| *program != name);

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
                // The egress half shares the ingress half's lifecycle.
                self.programs.remove("tc_nat_egress");
                self.set_status("tc_nat_ingress", false).await;
                self.set_status("tc_nat_egress", false).await;
            }
            _ => {}
        }

        // Drop the loader - this detaches the eBPF program from interfaces
        drop(handle);

        // tc-nat is published as its two halves, set above.
        if name != "tc_nat" {
            self.set_status(name, false).await;
        }
        info!(program = name, "eBPF program disabled and detached");
        Ok(())
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
        EbpfLoader::cleanup_pin_path_because(
            adapters::ebpf::DEFAULT_BPF_PIN_PATH,
            "shutdown: all programs detached",
        );
        EbpfLoader::cleanup_pin_path_because(
            startup::DLP_PIN_PATH,
            "shutdown: all programs detached",
        );
        adapters::ebpf::clear_attach_blocks();
        adapters::ebpf::clear_map_fills();
        info!("all eBPF programs detached");
    }

    // ── Per-program enable implementations ─────────────────────────

    async fn enable_tc_ids(&mut self, config: &AgentConfig) -> anyhow::Result<()> {
        let (mut loader, ids_mgr_opt, l7_mgr_opt, cfg_mgr_opt, ids_rdr, reader) =
            startup::try_load_tc_ids(&self.ebpf_dir, config)?;

        let cancel = CancellationToken::new();
        let tx = self.event_tx.clone();
        let c = cancel.clone();
        let obs = self.ringbuf_observer("tc-ids");
        let jh = tokio::spawn(async move { reader.run(tx, c, obs).await });

        let reader_handles = vec![jh];

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
            self.set_config_flags("tc_ids", cfg_mgr);
        }
        if let Some(rdr) = ids_rdr {
            self.metrics_readers.write().await.push(rdr);
        }

        self.iface_groups.add_map(loader.ebpf_mut());
        self.tenant_vlan.add_map(loader.ebpf_mut());
        self.tenant_ifindex.add_map(loader.ebpf_mut());
        self.tenant_subnet.add_map(loader.ebpf_mut());
        self.tenant_subnet.add_v6_map(loader.ebpf_mut());
        self.tenant_cgroup.add_map(loader.ebpf_mut());

        self.set_status("tc_ids", true).await;

        self.programs.insert(
            "tc_ids".to_string(),
            ProgramHandle {
                name: "tc_ids".to_string(),
                loader,
                reader_cancel: cancel,
                reader_handles,
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
        let obs = self.ringbuf_observer("tc-threatintel");
        let jh = tokio::spawn(async move { reader.run(tx, c, obs).await });

        if let Some(ti_mgr) = ti_mgr_opt {
            let mut svc = (**self.services.ti_svc.load()).clone();
            svc.set_map_port(Box::new(ti_mgr));
            self.services.ti_svc.store(Arc::new(svc));
        }
        if let Some(cfg_mgr) = cfg_mgr_opt {
            self.set_config_flags("tc_threatintel", cfg_mgr);
        }
        if let Some(rdr) = ti_rdr {
            self.metrics_readers.write().await.push(rdr);
        }

        self.tenant_vlan.add_map(loader.ebpf_mut());
        self.tenant_ifindex.add_map(loader.ebpf_mut());

        self.set_status("tc_threatintel", true).await;

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
        let obs = self.ringbuf_observer("tc-dns");
        let jh = tokio::spawn(async move { reader.run(tx, c, obs).await });

        let reader_handles = vec![jh];

        if let Some(rdr) = dns_rdr {
            self.metrics_readers.write().await.push(rdr);
        }

        self.tenant_vlan.add_map(loader.ebpf_mut());
        self.tenant_ifindex.add_map(loader.ebpf_mut());

        self.set_status("tc_dns", true).await;

        self.programs.insert(
            "tc_dns".to_string(),
            ProgramHandle {
                name: "tc_dns".to_string(),
                loader,
                reader_cancel: cancel,
                reader_handles,
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
            let obs = self.ringbuf_observer("tc-conntrack");
            handles.push(tokio::spawn(async move { reader.run(tx, c, obs).await }));
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
        self.tenant_ifindex.add_map(loader.ebpf_mut());

        self.set_status("tc_conntrack", true).await;

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
        self.tenant_ifindex.add_map(ingress_loader.ebpf_mut());
        self.tenant_vlan.add_map(egress_loader.ebpf_mut());
        self.tenant_ifindex.add_map(egress_loader.ebpf_mut());
        self.tenant_subnet.add_map(ingress_loader.ebpf_mut());
        self.tenant_subnet.add_v6_map(ingress_loader.ebpf_mut());
        self.tenant_subnet.add_map(egress_loader.ebpf_mut());
        self.tenant_subnet.add_v6_map(egress_loader.ebpf_mut());

        self.set_status("tc_nat_ingress", true).await;
        self.set_status("tc_nat_egress", true).await;

        // NAT uses two loaders - store ingress as the primary handle, egress as a second.
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
        self.tenant_ifindex.add_map(loader.ebpf_mut());

        self.set_status("tc_scrub", true).await;

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
        // The offset-driven attacher is dropped here: nothing on the hot-reload
        // path feeds it plans, and an attacher that never attached holds no
        // links, so dropping it detaches nothing.
        let (mut loader, dlp_rdr, reader, attacher, _extended) =
            startup::try_load_uprobe_dlp(&self.ebpf_dir, config, startup::DLP_PIN_PATH)?;

        let cancel = CancellationToken::new();
        let tx = self.event_tx.clone();
        let c = cancel.clone();
        let obs = self.ringbuf_observer("uprobe-dlp");
        let jh = tokio::spawn(async move { reader.run(tx, c, obs).await });

        // Lifecycle watcher: attach SSL uprobes to containers as they appear and
        // detach them on teardown. Shares the reader's cancel so a hot-reload
        // disable stops it too.
        let watch_cancel = cancel.clone();
        let watch_jh = tokio::spawn(async move {
            attacher
                .watch(adapters::ebpf::DLP_ATTACH_POLL_INTERVAL, watch_cancel)
                .await;
        });

        let reader_handles = vec![jh, watch_jh];

        if let Some(rdr) = dlp_rdr {
            self.metrics_readers.write().await.push(rdr);
        }

        self.tenant_vlan.add_map(loader.ebpf_mut());
        self.tenant_ifindex.add_map(loader.ebpf_mut());

        self.set_status("uprobe_dlp", true).await;

        self.programs.insert(
            "uprobe_dlp".to_string(),
            ProgramHandle {
                name: "uprobe_dlp".to_string(),
                loader,
                reader_cancel: cancel,
                reader_handles,
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
    pub fn rewire_xdp_chain(&mut self, _config: &AgentConfig) -> anyhow::Result<()> {
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
                rl.loader.program_raw_fd("xdp_ratelimit")?
            };
            if let Some(fw) = self.programs.get_mut("xdp_firewall") {
                fw.loader.set_tail_call_raw("XDP_PROG_ARRAY", 0, rl_fd)?;
                info!("XDP chain: firewall → ratelimit wired (slot 0)");
            }
        } else if fw_loaded {
            // Ratelimit absent - clear slot 0
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
                lb.loader.program_raw_fd("xdp_loadbalancer")?
            };
            if let Some(fw) = self.programs.get_mut("xdp_firewall") {
                fw.loader.set_tail_call_raw("XDP_PROG_ARRAY", 2, lb_fd)?;
                info!("XDP chain: firewall → loadbalancer wired (slot 2)");
            }
        } else if fw_loaded && let Some(fw) = self.programs.get_mut("xdp_firewall") {
            let _ = fw.loader.clear_tail_call_target("XDP_PROG_ARRAY", 2);
        }

        // Wire ratelimit → loadbalancer (RL slot 1)
        if rl_loaded && lb_loaded {
            let lb_fd = {
                let lb = self
                    .programs
                    .get("xdp_loadbalancer")
                    .ok_or_else(|| anyhow::anyhow!("xdp_loadbalancer not loaded"))?;
                lb.loader.program_raw_fd("xdp_loadbalancer")?
            };
            if let Some(rl) = self.programs.get_mut("xdp_ratelimit") {
                rl.loader.set_tail_call_raw("RL_PROG_ARRAY", 1, lb_fd)?;
                info!("XDP chain: ratelimit → loadbalancer wired (RL slot 1)");
            }
        } else if rl_loaded && let Some(rl) = self.programs.get_mut("xdp_ratelimit") {
            let _ = rl.loader.clear_tail_call_target("RL_PROG_ARRAY", 1);
        }

        // Wire firewall → VIP announcer (slot 3). The announcer outlives a
        // firewall reload, so a firewall loaded again finds it here.
        if fw_loaded && let Some(vip) = self.programs.get("xdp_vip_announcer") {
            let vip_fd = vip.loader.program_raw_fd("xdp_vip_announcer")?;
            if let Some(fw) = self.programs.get_mut("xdp_firewall") {
                fw.loader.set_tail_call_raw("XDP_PROG_ARRAY", 3, vip_fd)?;
                info!("XDP chain: firewall → vip-announcer wired (slot 3)");
            }
        }

        Ok(())
    }

    /// Bring the loaded XDP programs in line with the configuration.
    ///
    /// Only the root of the chain is attached to the interfaces; the others
    /// are loaded as tail-call targets. When the root stays the same, the
    /// programs removed are detached and the ones added are loaded behind it.
    /// When the root changes, a program loaded as a target would have to be
    /// attached and the old root detached, so the chain is rebuilt: every XDP
    /// program is unloaded and the wanted ones loaded again, root first. The
    /// lookup maps are pinned, so the rules survive the rebuild; traffic
    /// crosses the interfaces unfiltered for as long as it takes.
    ///
    /// Returns whether anything changed.
    pub async fn reconcile_xdp(&mut self, config: &AgentConfig) -> bool {
        let wanted: Vec<&'static str> = xdp_config_map(config)
            .into_iter()
            .filter_map(|(name, enabled)| enabled.then_some(name))
            .collect();
        let loaded: Vec<&'static str> = XDP_CHAIN
            .iter()
            .copied()
            .filter(|name| self.is_loaded(name))
            .collect();
        if wanted == loaded {
            return false;
        }

        let (to_disable, to_enable) = plan_xdp(&wanted, &loaded);
        if let (Some(from), Some(to)) = (loaded.first(), wanted.first())
            && from != to
        {
            info!(
                from = *from,
                to = *to,
                "XDP chain root changes, rebuilding the chain"
            );
        }

        // Leaves first, so no attached program tail-calls into one going away.
        for name in to_disable.iter().rev() {
            if let Err(e) = self.disable_xdp_program(name, config).await {
                warn!(program = name, "XDP program disable failed: {e}");
            }
        }
        // Root first, so the programs behind it load as targets.
        for name in &to_enable {
            if let Err(e) = self.enable_xdp_program(name, config).await {
                warn!(program = name, "XDP program enable failed: {e}");
            }
        }
        true
    }

    /// Enable an XDP program and rewire the chain.
    #[allow(clippy::too_many_lines)]
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
                let (mut loader, map_manager, metrics_rdr, reader, zone_mgr, _zone_rdrs) =
                    startup::try_load_xdp_firewall(&self.ebpf_dir, config)?;

                let cancel = CancellationToken::new();
                let tx = self.event_tx.clone();
                let c = cancel.clone();
                let obs = self.ringbuf_observer("xdp-firewall");
                let jh = tokio::spawn(async move { reader.run(tx, c, obs).await });

                self.services
                    .firewall_svc
                    .write()
                    .await
                    .set_map_port(Box::new(map_manager));
                if let Some(rdr) = metrics_rdr {
                    self.metrics_readers.write().await.push(rdr);
                }
                if let Some(mgr) = zone_mgr {
                    // The program is new, so its zone maps are empty: the
                    // service reprograms them from the config it still holds.
                    self.services
                        .zone_svc
                        .write()
                        .await
                        .set_map_port(Box::new(mgr));
                }

                self.iface_groups.add_map(loader.ebpf_mut());
                self.tenant_vlan.add_map(loader.ebpf_mut());
                self.tenant_ifindex.add_map(loader.ebpf_mut());
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

                self.set_status("xdp_firewall", true).await;

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
                let obs = self.ringbuf_observer("xdp-ratelimit");
                let jh = tokio::spawn(async move { reader.run(tx, c, obs).await });

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
                self.tenant_ifindex.add_map(loader.ebpf_mut());
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

                self.set_status("xdp_ratelimit", true).await;

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
                let obs = self.ringbuf_observer("xdp-loadbalancer");
                let jh = tokio::spawn(async move { reader.run(tx, c, obs).await });

                self.services
                    .lb_svc
                    .write()
                    .await
                    .set_map_port(Box::new(lb_mgr));
                if let Some(rdr) = lb_metrics_rdr {
                    self.metrics_readers.write().await.push(rdr);
                }

                self.tenant_vlan.add_map(loader.ebpf_mut());
                self.tenant_ifindex.add_map(loader.ebpf_mut());

                self.set_status("xdp_loadbalancer", true).await;

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
        self.rewire_xdp_chain(config)?;
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
                self.drop_metrics_readers("xdp_firewall").await;
                self.set_status("xdp_firewall", false).await;
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
                self.drop_metrics_readers("xdp_ratelimit").await;
                self.set_status("xdp_ratelimit", false).await;
            }
            "xdp_loadbalancer" => {
                if let Some(handle) = self.programs.remove("xdp_loadbalancer") {
                    handle.reader_cancel.cancel();
                    for jh in &handle.reader_handles {
                        jh.abort();
                    }
                }
                self.services.lb_svc.write().await.clear_map_port();
                self.drop_metrics_readers("xdp_loadbalancer").await;
                self.set_status("xdp_loadbalancer", false).await;
            }
            _ => {}
        }

        info!(program = name, "XDP program disabled");

        // Rewire the tail-call chain after removal
        self.rewire_xdp_chain(config)?;
        Ok(())
    }
}

/// Build the mapping from program names to their config enabled flags.
///
/// Only includes Category A (independent TC/uprobe) programs.
/// XDP chain programs are handled by [`xdp_config_map`].
pub fn program_config_map(config: &AgentConfig) -> Vec<(&'static str, bool)> {
    vec![
        // tc-ids is also the vehicle of L7 capture.
        ("tc_ids", config.ids.enabled || config.l7.enabled),
        ("tc_threatintel", config.threatintel.enabled),
        ("tc_dns", config.dns.enabled),
        ("tc_conntrack", config.conntrack.enabled),
        ("tc_nat", config.nat.enabled),
        ("tc_scrub", config.firewall.scrub.enabled),
        ("uprobe_dlp", config.dlp.enabled),
    ]
}

/// The XDP programs that can be the root of the chain, in chain order.
const XDP_CHAIN: [&str; 3] = ["xdp_firewall", "xdp_ratelimit", "xdp_loadbalancer"];

/// What to unload and what to load, both in chain order, to go from the XDP
/// programs `loaded` to the ones `wanted`. The same root keeps the programs
/// both lists share; a different root unloads everything and loads again.
fn plan_xdp(wanted: &[&'static str], loaded: &[&'static str]) -> XdpPlan {
    if wanted.first() == loaded.first() {
        (
            loaded
                .iter()
                .copied()
                .filter(|n| !wanted.contains(n))
                .collect(),
            wanted
                .iter()
                .copied()
                .filter(|n| !loaded.contains(n))
                .collect(),
        )
    } else {
        (loaded.to_vec(), wanted.to_vec())
    }
}

type XdpPlan = (Vec<&'static str>, Vec<&'static str>);

/// The kernel counter maps a program's metrics readers read.
fn metrics_maps(program: &str) -> &'static [&'static str] {
    match program {
        "xdp_firewall" => &["FIREWALL_METRICS"],
        "xdp_ratelimit" => &["RATELIMIT_METRICS", "DDOS_METRICS"],
        "xdp_loadbalancer" => &["LB_METRICS"],
        "tc_ids" => &["IDS_METRICS"],
        "tc_threatintel" => &["THREATINTEL_METRICS"],
        "tc_dns" => &["DNS_METRICS"],
        "tc_conntrack" => &["CT_METRICS"],
        "tc_nat" => &["NAT_METRICS"],
        "tc_scrub" => &["SCRUB_METRICS"],
        "uprobe_dlp" => &["DLP_METRICS"],
        _ => &[],
    }
}

/// Build the XDP program config map, in chain order.
pub fn xdp_config_map(config: &AgentConfig) -> Vec<(&'static str, bool)> {
    vec![
        ("xdp_firewall", config.firewall.enabled),
        ("xdp_ratelimit", config.ratelimit.enabled),
        ("xdp_loadbalancer", config.loadbalancer.enabled),
    ]
}

#[cfg(test)]
mod tests {
    use super::plan_xdp;

    const FW: &str = "xdp_firewall";
    const RL: &str = "xdp_ratelimit";
    const LB: &str = "xdp_loadbalancer";

    #[test]
    fn the_same_root_keeps_what_both_chains_share() {
        assert_eq!(plan_xdp(&[FW, LB], &[FW, RL]), (vec![RL], vec![LB]));
        assert_eq!(plan_xdp(&[FW, RL, LB], &[FW]), (vec![], vec![RL, LB]));
    }

    #[test]
    fn a_new_root_rebuilds_the_chain() {
        assert_eq!(
            plan_xdp(&[RL, LB], &[FW, RL, LB]),
            (vec![FW, RL, LB], vec![RL, LB])
        );
        assert_eq!(plan_xdp(&[FW, LB], &[LB]), (vec![LB], vec![FW, LB]));
    }

    #[test]
    fn an_empty_side_only_loads_or_only_unloads() {
        assert_eq!(plan_xdp(&[RL], &[]), (vec![], vec![RL]));
        assert_eq!(plan_xdp(&[], &[FW, RL]), (vec![FW, RL], vec![]));
    }
}
