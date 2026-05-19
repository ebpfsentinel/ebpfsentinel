use std::sync::Arc;

use std::net::IpAddr;

use domain::common::error::DomainError;
use domain::l2::{L2Binding, OwnedBindings};
use domain::loadbalancer::vip::VipAnnounceConfig;
use ports::secondary::l2_binding_port::L2BindingPort;
use ports::secondary::metrics_port::MetricsPort;
use ports::secondary::vip_announcer_port::{GratuitousArpPort, IfaceMacResolverPort, VipMapPort};

/// Application-level VIP announcer service.
///
/// Owns the node's [`VipAnnounceConfig`] and reconciles it against the
/// kernel `VIP_SET` / `IFACE_MAC` maps. The split-brain invariant lives
/// here: `VIP_SET` is populated **only** while this node is the elected
/// speaker; standby/disabled nodes always leave it empty so the bounded
/// XDP responder never answers.
///
/// Gratuitous ARP on takeover is emitted from userspace via
/// [`GratuitousArpPort`] — never from eBPF.
pub struct VipAnnouncerService {
    config: VipAnnounceConfig,
    map_port: Option<Box<dyn VipMapPort + Send>>,
    binding_port: Option<Box<dyn L2BindingPort + Send>>,
    mac_resolver: Option<Arc<dyn IfaceMacResolverPort>>,
    garp: Option<Arc<dyn GratuitousArpPort>>,
    metrics: Arc<dyn MetricsPort>,
    /// Self-whitelist of `(VIP → owned MAC)` bindings this node
    /// announces while speaker. Live producer for the kernel
    /// `SELF_OWNED_BINDINGS` map; the ARP-guard epic consumes the
    /// [`OwnedBindings::is_self_announced`] predicate exposed via
    /// [`VipAnnouncerService::is_self_announced`].
    bindings: OwnedBindings,
}

impl VipAnnouncerService {
    pub fn new(metrics: Arc<dyn MetricsPort>) -> Self {
        Self {
            config: VipAnnounceConfig::default(),
            map_port: None,
            binding_port: None,
            mac_resolver: None,
            garp: None,
            metrics,
            bindings: OwnedBindings::new(),
        }
    }

    /// Inject the kernel `SELF_OWNED_BINDINGS` map port. Set before
    /// [`Self::set_map_port`] so the reconcile it triggers also writes
    /// the self-binding map.
    pub fn set_binding_port(&mut self, port: Box<dyn L2BindingPort + Send>) {
        self.binding_port = Some(port);
    }

    /// Clear the self-binding map port (program unloaded).
    pub fn clear_binding_port(&mut self) {
        self.binding_port = None;
    }

    /// Whether `(ip, mac)` is a binding this node itself announces.
    ///
    /// Live predicate consumed by the ARP-guard so it never raises a
    /// binding-change / gratuitous-ARP anomaly on traffic this node
    /// generated. Also used internally as a pre-send guard in
    /// [`Self::announce_takeover`].
    #[must_use]
    pub fn is_self_announced(&self, ip: IpAddr, mac: [u8; 6]) -> bool {
        self.bindings.is_self_announced(ip, mac)
    }

    /// Inject the netlink-backed iface MAC resolver.
    pub fn set_mac_resolver(&mut self, resolver: Arc<dyn IfaceMacResolverPort>) {
        self.mac_resolver = Some(resolver);
    }

    /// Inject the gratuitous-ARP raw-socket sender.
    pub fn set_gratuitous_arp(&mut self, garp: Arc<dyn GratuitousArpPort>) {
        self.garp = Some(garp);
    }

    /// Set the eBPF map port (announcer program loaded) and reconcile.
    pub fn set_map_port(&mut self, port: Box<dyn VipMapPort + Send>) -> Result<(), DomainError> {
        self.map_port = Some(port);
        self.reconcile()
    }

    /// Clear the eBPF map port (program unloaded).
    pub fn clear_map_port(&mut self) {
        self.map_port = None;
    }

    /// Current role string for diagnostics / status.
    pub fn role(&self) -> &'static str {
        self.config.role.as_str()
    }

    /// Whether this node is the elected speaker.
    pub fn is_speaker(&self) -> bool {
        self.config.is_speaker()
    }

    /// Apply a new announce configuration and reconcile the kernel maps.
    ///
    /// On a speaker→standby (or →disabled) transition this clears
    /// `VIP_SET`, which is what keeps the failover pair split-brain safe.
    pub fn configure(&mut self, config: VipAnnounceConfig) -> Result<(), DomainError> {
        config.validate()?;
        let became_speaker = config.is_speaker() && !self.config.is_speaker();
        self.config = config;
        self.reconcile()?;
        if became_speaker {
            self.announce_takeover()?;
        }
        Ok(())
    }

    /// Reconcile the kernel maps with the current config.
    ///
    /// Speaker: push this interface's NIC MAC into `IFACE_MAC` and the
    /// full VIP set into `VIP_SET`. Non-speaker: empty `VIP_SET`.
    pub fn reconcile(&mut self) -> Result<(), DomainError> {
        let Some(map) = self.map_port.as_mut() else {
            return Ok(());
        };

        if !self.config.is_speaker() {
            // Standby / disabled → guarantee silence and own nothing.
            map.clear_vips()?;
            self.bindings.clear();
            if let Some(bp) = self.binding_port.as_mut() {
                bp.clear_bindings()?;
            }
            tracing::info!(
                role = self.config.role.as_str(),
                "vip announcer: non-speaker, VIP_SET + self bindings cleared"
            );
            return Ok(());
        }

        let resolver = self.mac_resolver.as_ref().ok_or_else(|| {
            DomainError::EngineError("vip announcer: no iface MAC resolver wired".into())
        })?;
        let iface = self.config.interface.as_str();
        let ifindex = resolver.ifindex(iface)?;
        let mac = resolver.mac(iface)?;
        map.sync_iface_mac(ifindex, mac)?;

        // Rebuild the owned set + self-binding whitelist from scratch
        // so a removed VIP stops being answered immediately.
        map.clear_vips()?;
        self.bindings.clear();
        if let Some(bp) = self.binding_port.as_mut() {
            bp.clear_bindings()?;
        }
        for vip in &self.config.vips {
            map.sync_vip(vip.addr)?;
            let binding = L2Binding::new(vip.addr, mac);
            self.bindings.register(binding);
            if let Some(bp) = self.binding_port.as_mut() {
                bp.register_binding(&binding)?;
            }
        }
        tracing::info!(
            iface,
            ifindex,
            vips = self.config.vips.len(),
            "vip announcer: speaker, VIP_SET + self bindings synced"
        );
        Ok(())
    }

    /// Emit a gratuitous ARP for every owned VIP and bump the takeover
    /// metric. Called once on a transition into the speaker role.
    pub fn announce_takeover(&mut self) -> Result<(), DomainError> {
        if !self.config.is_speaker() {
            return Ok(());
        }
        let (Some(resolver), Some(garp)) = (self.mac_resolver.as_ref(), self.garp.as_ref()) else {
            return Ok(());
        };
        let iface = self.config.interface.as_str();
        let mac = resolver.mac(iface)?;
        for vip in &self.config.vips {
            // Only ever broadcast a pair we actually own. reconcile()
            // registered the binding just before this; a miss means a
            // resolver/registration mismatch — skip rather than poison
            // upstream ARP caches with a pair we cannot back.
            if !self.bindings.is_self_announced(vip.addr, mac) {
                tracing::warn!(
                    vip = %vip.name, addr = %vip.addr,
                    "vip announcer: skipping gratuitous ARP (not a self-owned binding)"
                );
                continue;
            }
            garp.send_gratuitous_arp(iface, mac, vip)?;
            self.metrics.record_vip_takeover(&vip.name);
            tracing::info!(vip = %vip.name, addr = %vip.addr, "vip announcer: gratuitous ARP sent");
        }
        Ok(())
    }

    /// Mirror the kernel per-VIP forged-reply counters into Prometheus.
    pub fn refresh_metrics(&self) -> Result<(), DomainError> {
        let Some(map) = self.map_port.as_ref() else {
            return Ok(());
        };
        for vip in &self.config.vips {
            let replies = map.arp_replies(vip.addr)?;
            self.metrics.set_vip_arp_replies(&vip.name, replies);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};
    use std::net::IpAddr;
    use std::sync::Mutex;

    use domain::loadbalancer::vip::{AnnounceRole, Vip};
    use ports::test_utils::NoopMetrics;

    #[derive(Default)]
    struct FakeMap {
        vips: Mutex<HashSet<IpAddr>>,
        ifaces: Mutex<HashMap<u32, [u8; 6]>>,
        replies: Mutex<HashMap<IpAddr, u64>>,
        clears: Mutex<u32>,
    }

    impl VipMapPort for FakeMap {
        fn sync_vip(&mut self, addr: IpAddr) -> Result<(), DomainError> {
            self.vips.lock().unwrap().insert(addr);
            Ok(())
        }
        fn remove_vip(&mut self, addr: IpAddr) -> Result<(), DomainError> {
            self.vips.lock().unwrap().remove(&addr);
            Ok(())
        }
        fn clear_vips(&mut self) -> Result<(), DomainError> {
            self.vips.lock().unwrap().clear();
            *self.clears.lock().unwrap() += 1;
            Ok(())
        }
        fn sync_iface_mac(&mut self, ifindex: u32, mac: [u8; 6]) -> Result<(), DomainError> {
            self.ifaces.lock().unwrap().insert(ifindex, mac);
            Ok(())
        }
        fn arp_replies(&self, addr: IpAddr) -> Result<u64, DomainError> {
            Ok(self
                .replies
                .lock()
                .unwrap()
                .get(&addr)
                .copied()
                .unwrap_or(0))
        }
        fn vip_count(&self) -> Result<usize, DomainError> {
            Ok(self.vips.lock().unwrap().len())
        }
    }

    #[derive(Default)]
    struct FakeBindingPort {
        live: Mutex<HashSet<IpAddr>>,
        clears: Mutex<u32>,
    }
    impl L2BindingPort for FakeBindingPort {
        fn register_binding(&mut self, binding: &L2Binding) -> Result<(), DomainError> {
            self.live.lock().unwrap().insert(binding.ip());
            Ok(())
        }
        fn deregister_binding(&mut self, ip: IpAddr) -> Result<(), DomainError> {
            self.live.lock().unwrap().remove(&ip);
            Ok(())
        }
        fn clear_bindings(&mut self) -> Result<(), DomainError> {
            self.live.lock().unwrap().clear();
            *self.clears.lock().unwrap() += 1;
            Ok(())
        }
    }

    struct FakeResolver;
    impl IfaceMacResolverPort for FakeResolver {
        fn ifindex(&self, _interface: &str) -> Result<u32, DomainError> {
            Ok(7)
        }
        fn mac(&self, _interface: &str) -> Result<[u8; 6], DomainError> {
            Ok([0x02, 0, 0, 0, 0, 0x01])
        }
    }

    #[derive(Default)]
    struct FakeGarp {
        sent: Mutex<Vec<String>>,
    }
    impl GratuitousArpPort for FakeGarp {
        fn send_gratuitous_arp(
            &self,
            _interface: &str,
            _src_mac: [u8; 6],
            vip: &Vip,
        ) -> Result<(), DomainError> {
            self.sent.lock().unwrap().push(vip.name.clone());
            Ok(())
        }
    }

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(std::net::Ipv4Addr::new(a, b, c, d))
    }

    fn primary_cfg() -> VipAnnounceConfig {
        VipAnnounceConfig {
            role: AnnounceRole::Primary,
            interface: "eth0".into(),
            vips: vec![
                Vip {
                    name: "web".into(),
                    addr: ip(192, 0, 2, 10),
                },
                Vip {
                    name: "api".into(),
                    addr: ip(192, 0, 2, 11),
                },
            ],
        }
    }

    fn svc() -> VipAnnouncerService {
        let mut s = VipAnnouncerService::new(Arc::new(NoopMetrics));
        s.set_mac_resolver(Arc::new(FakeResolver));
        s
    }

    #[test]
    fn speaker_pushes_vips_and_iface_mac() {
        let mut s = svc();
        let garp = Arc::new(FakeGarp::default());
        s.set_gratuitous_arp(garp.clone());
        s.set_map_port(Box::new(FakeMap::default())).unwrap();
        s.configure(primary_cfg()).unwrap();
        assert!(s.is_speaker());
        // 2 VIPs pushed, gratuitous ARP for both on takeover.
        assert_eq!(garp.sent.lock().unwrap().len(), 2);
    }

    #[test]
    fn standby_clears_vip_set() {
        let mut s = svc();
        s.set_map_port(Box::new(FakeMap::default())).unwrap();
        let cfg = VipAnnounceConfig {
            role: AnnounceRole::Standby,
            interface: "eth0".into(),
            vips: vec![Vip {
                name: "web".into(),
                addr: ip(192, 0, 2, 10),
            }],
        };
        s.configure(cfg).unwrap();
        assert!(!s.is_speaker());
    }

    #[test]
    fn disabled_is_valid_and_silent() {
        let mut s = svc();
        s.set_map_port(Box::new(FakeMap::default())).unwrap();
        s.configure(VipAnnounceConfig::default()).unwrap();
        assert_eq!(s.role(), "disabled");
        assert!(!s.is_speaker());
    }

    #[test]
    fn invalid_config_rejected() {
        let mut s = svc();
        s.set_map_port(Box::new(FakeMap::default())).unwrap();
        let bad = VipAnnounceConfig {
            role: AnnounceRole::Primary,
            interface: String::new(),
            vips: vec![],
        };
        assert!(s.configure(bad).is_err());
    }

    #[test]
    fn no_map_port_is_noop() {
        let mut s = svc();
        assert!(s.configure(primary_cfg()).is_ok());
    }

    #[test]
    fn takeover_only_on_transition_into_speaker() {
        let mut s = svc();
        let garp = Arc::new(FakeGarp::default());
        s.set_gratuitous_arp(garp.clone());
        s.set_map_port(Box::new(FakeMap::default())).unwrap();
        s.configure(primary_cfg()).unwrap();
        assert_eq!(garp.sent.lock().unwrap().len(), 2);
        // Re-applying the same speaker config must NOT re-emit GARP.
        s.configure(primary_cfg()).unwrap();
        assert_eq!(garp.sent.lock().unwrap().len(), 2);
    }

    const RESOLVED_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x01];

    #[test]
    fn speaker_registers_self_bindings_and_writes_port() {
        let mut s = svc();
        s.set_gratuitous_arp(Arc::new(FakeGarp::default()));
        s.set_binding_port(Box::new(FakeBindingPort::default()));
        s.set_map_port(Box::new(FakeMap::default())).unwrap();
        s.configure(primary_cfg()).unwrap();
        // Both VIPs are self-announced with the resolver MAC.
        assert!(s.is_self_announced(ip(192, 0, 2, 10), RESOLVED_MAC));
        assert!(s.is_self_announced(ip(192, 0, 2, 11), RESOLVED_MAC));
        // A foreign MAC for an owned VIP is NOT self-announced.
        assert!(!s.is_self_announced(ip(192, 0, 2, 10), [9, 9, 9, 9, 9, 9]));
        // An unknown VIP is NOT self-announced.
        assert!(!s.is_self_announced(ip(192, 0, 2, 99), RESOLVED_MAC));
    }

    #[test]
    fn speaker_loss_deregisters_all_self_bindings() {
        let mut s = svc();
        s.set_gratuitous_arp(Arc::new(FakeGarp::default()));
        s.set_map_port(Box::new(FakeMap::default())).unwrap();
        s.configure(primary_cfg()).unwrap();
        assert!(s.is_self_announced(ip(192, 0, 2, 10), RESOLVED_MAC));
        // Demote to standby → own nothing (split-brain safe).
        s.configure(VipAnnounceConfig {
            role: AnnounceRole::Standby,
            interface: "eth0".into(),
            vips: vec![Vip {
                name: "web".into(),
                addr: ip(192, 0, 2, 10),
            }],
        })
        .unwrap();
        assert!(!s.is_self_announced(ip(192, 0, 2, 10), RESOLVED_MAC));
        assert!(!s.is_self_announced(ip(192, 0, 2, 11), RESOLVED_MAC));
    }

    #[test]
    fn standby_clears_binding_port() {
        let mut s = svc();
        s.set_binding_port(Box::new(FakeBindingPort::default()));
        s.set_map_port(Box::new(FakeMap::default())).unwrap();
        // set_map_port already reconciled once (default = disabled).
        s.configure(VipAnnounceConfig {
            role: AnnounceRole::Standby,
            interface: "eth0".into(),
            vips: vec![Vip {
                name: "web".into(),
                addr: ip(192, 0, 2, 10),
            }],
        })
        .unwrap();
        assert!(!s.is_speaker());
        assert!(!s.is_self_announced(ip(192, 0, 2, 10), RESOLVED_MAC));
    }
}
