use crate::ebpf::map_store::MapStore;
use aya::maps::{DevMap, HashMap, MapData};
use domain::common::error::DomainError;
use ebpf_common::loadbalancer::{
    BackendMac, LbBackendEntry, LbServiceConfigV2, LbServiceKey, MAGLEV_RING_SIZE, MaglevLookup,
};
use ports::secondary::loadbalancer_map_port::LoadBalancerMapPort;
use tracing::{debug, info};

/// Manages the load balancer eBPF maps: `LB_SERVICES` and `LB_BACKENDS`.
///
/// Provides typed wrappers for inserting, updating, and removing service
/// and backend entries. The `LB_RR_STATE` and `LB_METRICS` maps are managed
/// by the kernel program; userspace only pushes config.
pub struct LbMapManager {
    services_map: HashMap<MapData, LbServiceKey, LbServiceConfigV2>,
    backends_map: HashMap<MapData, u32, LbBackendEntry>,
    /// `DevMap` for XDP redirect to backend interfaces.
    /// When populated, the eBPF program uses `redirect()` for wire-speed
    /// forwarding instead of MAC swap + `XDP_TX`.
    devmap: Option<DevMap<MapData>>,
    /// `LB_MAGLEV`: per-service Maglev lookup ring (consistent hashing).
    /// Optional — only present in the `xdp-loadbalancer` program.
    maglev_map: Option<HashMap<MapData, u32, MaglevLookup>>,
    /// `LB_BACKEND_MAC`: resolved backend MACs for L2 DSR forwarding.
    /// Optional — only present in the `xdp-loadbalancer` program.
    backend_mac_map: Option<HashMap<MapData, u32, BackendMac>>,
}

impl LbMapManager {
    /// Create a new `LbMapManager` by taking ownership of the
    /// `LB_SERVICES` and `LB_BACKENDS` maps from the loaded eBPF program.
    pub fn new(ebpf: &mut dyn MapStore) -> Result<Self, anyhow::Error> {
        let svc_map = ebpf
            .take_map("LB_SERVICES")
            .ok_or_else(|| anyhow::anyhow!("map 'LB_SERVICES' not found in eBPF object"))?;
        let services_map = HashMap::try_from(svc_map)?;

        let be_map = ebpf
            .take_map("LB_BACKENDS")
            .ok_or_else(|| anyhow::anyhow!("map 'LB_BACKENDS' not found in eBPF object"))?;
        let backends_map = HashMap::try_from(be_map)?;

        // DevMap is optional — only present in xdp-loadbalancer programs.
        let devmap = ebpf
            .take_map("LB_DEVMAP")
            .and_then(|m| DevMap::try_from(m).ok());
        if devmap.is_some() {
            info!("LB_DEVMAP acquired for XDP redirect forwarding");
        }

        // LB_MAGLEV is optional — only the xdp-loadbalancer program has it.
        let maglev_map = ebpf
            .take_map("LB_MAGLEV")
            .and_then(|m| HashMap::try_from(m).ok());
        if maglev_map.is_some() {
            info!("LB_MAGLEV acquired for consistent-hash selection");
        }

        // LB_BACKEND_MAC is optional — only the xdp-loadbalancer has it.
        let backend_mac_map = ebpf
            .take_map("LB_BACKEND_MAC")
            .and_then(|m| HashMap::try_from(m).ok());
        if backend_mac_map.is_some() {
            info!("LB_BACKEND_MAC acquired for L2 DSR forwarding");
        }

        info!("LB_SERVICES and LB_BACKENDS maps acquired");
        Ok(Self {
            services_map,
            backends_map,
            devmap,
            maglev_map,
            backend_mac_map,
        })
    }

    /// Insert or update a service's Maglev lookup ring.
    pub fn sync_maglev_table(
        &mut self,
        svc_index: u32,
        table: &[u16],
    ) -> Result<(), anyhow::Error> {
        let Some(ref mut map) = self.maglev_map else {
            return Ok(());
        };
        if table.len() != MAGLEV_RING_SIZE {
            return Err(anyhow::anyhow!(
                "maglev table length {} != ring size {MAGLEV_RING_SIZE}",
                table.len()
            ));
        }
        // Heap-allocate the 128 KiB ring to keep it off the stack.
        let mut lookup = Box::new(MaglevLookup::empty());
        lookup.entries.copy_from_slice(table);
        map.insert(svc_index, lookup.as_ref(), 0)
            .map_err(|e| anyhow::anyhow!("LB_MAGLEV insert failed: {e}"))?;
        Ok(())
    }

    /// Remove a service's Maglev ring (best-effort — a missing entry is fine).
    pub fn remove_maglev_table(&mut self, svc_index: u32) -> Result<(), anyhow::Error> {
        if let Some(ref mut map) = self.maglev_map
            && let Err(e) = map.remove(&svc_index)
        {
            debug!(svc_index, error = %e, "LB_MAGLEV remove (entry absent)");
        }
        Ok(())
    }

    /// Insert or update a backend's resolved MAC (L2 DSR).
    pub fn sync_backend_mac(&mut self, backend_id: u32, mac: [u8; 6]) -> Result<(), anyhow::Error> {
        let Some(ref mut map) = self.backend_mac_map else {
            return Ok(());
        };
        map.insert(backend_id, BackendMac::new(mac), 0)
            .map_err(|e| anyhow::anyhow!("LB_BACKEND_MAC insert failed: {e}"))?;
        Ok(())
    }

    /// Remove a backend's MAC (best-effort — a missing entry is fine).
    pub fn remove_backend_mac(&mut self, backend_id: u32) -> Result<(), anyhow::Error> {
        if let Some(ref mut map) = self.backend_mac_map
            && let Err(e) = map.remove(&backend_id)
        {
            debug!(backend_id, error = %e, "LB_BACKEND_MAC remove (entry absent)");
        }
        Ok(())
    }

    /// Insert or update a service entry.
    pub fn sync_service(
        &mut self,
        key: &LbServiceKey,
        config: &LbServiceConfigV2,
    ) -> Result<(), anyhow::Error> {
        self.services_map
            .insert(*key, *config, 0)
            .map_err(|e| anyhow::anyhow!("LB_SERVICES insert failed: {e}"))?;
        Ok(())
    }

    /// Remove a service entry.
    pub fn remove_service(&mut self, key: &LbServiceKey) -> Result<(), anyhow::Error> {
        self.services_map
            .remove(key)
            .map_err(|e| anyhow::anyhow!("LB_SERVICES remove failed: {e}"))?;
        Ok(())
    }

    /// Insert or update a backend entry.
    /// Also populates the `DevMap` with the backend's resolved ifindex if available.
    pub fn sync_backend(
        &mut self,
        backend_id: u32,
        entry: &LbBackendEntry,
    ) -> Result<(), anyhow::Error> {
        self.backends_map
            .insert(backend_id, *entry, 0)
            .map_err(|e| anyhow::anyhow!("LB_BACKENDS insert failed: {e}"))?;

        // Populate DevMap for XDP redirect. Resolve ifindex from the backend IP.
        // If resolution fails, the eBPF program falls back to MAC swap + XDP_TX.
        if let Some(ref mut dm) = self.devmap {
            match resolve_ifindex_for_ip(entry.addr_v4, entry.is_ipv6 == 1) {
                Some(ifindex) => {
                    if let Err(e) = dm.set(backend_id, ifindex, None, 0) {
                        debug!(backend_id, error = %e, "LB_DEVMAP set failed (fallback to XDP_TX)");
                    }
                }
                None => {
                    debug!(
                        backend_id,
                        "no ifindex resolved for backend (fallback to XDP_TX)"
                    );
                }
            }
        }

        // Populate LB_BACKEND_MAC for L2 DSR. Resolved unconditionally so
        // the map is current if the service is (or becomes) `l2dsr`; the
        // eBPF data plane only reads it in `LB_MODE_L2DSR` and falls back
        // to DNAT when the MAC is absent (no regression for `dnat`).
        if self.backend_mac_map.is_some() {
            match resolve_mac_for_ip(entry.addr_v4, &entry.addr_v6, entry.is_ipv6 == 1) {
                Some(mac) => {
                    if let Err(e) = self.sync_backend_mac(backend_id, mac) {
                        debug!(backend_id, error = %e, "LB_BACKEND_MAC set failed (DSR falls back to DNAT)");
                    }
                }
                None => {
                    debug!(
                        backend_id,
                        "no MAC resolved for backend (DSR falls back to DNAT)"
                    );
                }
            }
        }

        Ok(())
    }

    /// Remove a backend entry and its `DevMap` redirect.
    pub fn remove_backend(&mut self, backend_id: u32) -> Result<(), anyhow::Error> {
        self.backends_map
            .remove(&backend_id)
            .map_err(|e| anyhow::anyhow!("LB_BACKENDS remove failed: {e}"))?;
        // Clean up DevMap entry
        if let Some(ref mut dm) = self.devmap {
            let _ = dm.set(backend_id, 0, None, 0); // setting ifindex 0 effectively disables redirect
        }
        // Clean up L2 DSR MAC entry
        self.remove_backend_mac(backend_id)?;
        Ok(())
    }

    /// Update only the `healthy` field of a backend entry.
    pub fn update_backend_health(
        &mut self,
        backend_id: u32,
        healthy: bool,
    ) -> Result<(), anyhow::Error> {
        let existing = self
            .backends_map
            .get(&backend_id, 0)
            .map_err(|e| anyhow::anyhow!("LB_BACKENDS get failed for id {backend_id}: {e}"))?;
        let mut updated = existing;
        updated.healthy = u8::from(healthy);
        self.backends_map
            .insert(backend_id, updated, 0)
            .map_err(|e| anyhow::anyhow!("LB_BACKENDS health update failed: {e}"))?;
        Ok(())
    }

    /// Remove all service and backend entries.
    pub fn clear_all(&mut self) -> Result<(), anyhow::Error> {
        let svc_keys: Vec<LbServiceKey> = self.services_map.keys().filter_map(Result::ok).collect();
        for key in &svc_keys {
            self.services_map
                .remove(key)
                .map_err(|e| anyhow::anyhow!("LB_SERVICES clear failed: {e}"))?;
        }

        let be_keys: Vec<u32> = self.backends_map.keys().filter_map(Result::ok).collect();
        for key in &be_keys {
            self.backends_map
                .remove(key)
                .map_err(|e| anyhow::anyhow!("LB_BACKENDS clear failed: {e}"))?;
        }

        if let Some(ref mut map) = self.maglev_map {
            let mg_keys: Vec<u32> = map.keys().filter_map(Result::ok).collect();
            for key in &mg_keys {
                map.remove(key)
                    .map_err(|e| anyhow::anyhow!("LB_MAGLEV clear failed: {e}"))?;
            }
        }

        if let Some(ref mut map) = self.backend_mac_map {
            let mac_keys: Vec<u32> = map.keys().filter_map(Result::ok).collect();
            for key in &mac_keys {
                map.remove(key)
                    .map_err(|e| anyhow::anyhow!("LB_BACKEND_MAC clear failed: {e}"))?;
            }
        }

        Ok(())
    }

    /// Return the number of service entries in the map.
    pub fn service_count(&self) -> usize {
        self.services_map.keys().filter_map(Result::ok).count()
    }
}

impl LoadBalancerMapPort for LbMapManager {
    fn sync_service(
        &mut self,
        key: &LbServiceKey,
        config: &LbServiceConfigV2,
    ) -> Result<(), DomainError> {
        self.sync_service(key, config)
            .map_err(|e| DomainError::EngineError(format!("lb service sync failed: {e}")))
    }

    fn remove_service(&mut self, key: &LbServiceKey) -> Result<(), DomainError> {
        self.remove_service(key)
            .map_err(|e| DomainError::EngineError(format!("lb service remove failed: {e}")))
    }

    fn sync_backend(&mut self, backend_id: u32, entry: &LbBackendEntry) -> Result<(), DomainError> {
        self.sync_backend(backend_id, entry)
            .map_err(|e| DomainError::EngineError(format!("lb backend sync failed: {e}")))
    }

    fn remove_backend(&mut self, backend_id: u32) -> Result<(), DomainError> {
        self.remove_backend(backend_id)
            .map_err(|e| DomainError::EngineError(format!("lb backend remove failed: {e}")))
    }

    fn update_backend_health(&mut self, backend_id: u32, healthy: bool) -> Result<(), DomainError> {
        self.update_backend_health(backend_id, healthy)
            .map_err(|e| DomainError::EngineError(format!("lb backend health update failed: {e}")))
    }

    fn sync_maglev_table(&mut self, svc_index: u32, table: &[u16]) -> Result<(), DomainError> {
        self.sync_maglev_table(svc_index, table)
            .map_err(|e| DomainError::EngineError(format!("lb maglev sync failed: {e}")))
    }

    fn remove_maglev_table(&mut self, svc_index: u32) -> Result<(), DomainError> {
        self.remove_maglev_table(svc_index)
            .map_err(|e| DomainError::EngineError(format!("lb maglev remove failed: {e}")))
    }

    fn sync_backend_mac(&mut self, backend_id: u32, mac: [u8; 6]) -> Result<(), DomainError> {
        self.sync_backend_mac(backend_id, mac)
            .map_err(|e| DomainError::EngineError(format!("lb backend mac sync failed: {e}")))
    }

    fn remove_backend_mac(&mut self, backend_id: u32) -> Result<(), DomainError> {
        self.remove_backend_mac(backend_id)
            .map_err(|e| DomainError::EngineError(format!("lb backend mac remove failed: {e}")))
    }

    fn clear_all(&mut self) -> Result<(), DomainError> {
        self.clear_all()
            .map_err(|e| DomainError::EngineError(format!("lb clear failed: {e}")))
    }

    fn service_count(&self) -> Result<usize, DomainError> {
        Ok(self.service_count())
    }
}

/// Resolve the link-layer (MAC) address for a backend IP via the kernel
/// neighbor table (`ip neigh show <ip>`). Used to populate
/// `LB_BACKEND_MAC` for L2 DSR forwarding. Returns `None` when the
/// neighbor is not yet resolved — the eBPF data plane then falls back to
/// the DNAT path with no regression.
fn resolve_mac_for_ip(addr_v4: u32, addr_v6: &[u32; 4], is_ipv6: bool) -> Option<[u8; 6]> {
    let ip = if is_ipv6 {
        let mut octets = [0u8; 16];
        for (i, word) in addr_v6.iter().enumerate() {
            octets[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        std::net::Ipv6Addr::from(octets).to_string()
    } else if addr_v4 == 0 {
        return None;
    } else {
        std::net::Ipv4Addr::from(addr_v4).to_string()
    };

    let output = std::process::Command::new("ip")
        .args(["neigh", "show", &ip])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Line form: "<ip> dev <if> lladdr aa:bb:cc:dd:ee:ff REACHABLE"
    let mut tokens = stdout.split_whitespace();
    let mac_str = loop {
        match tokens.next() {
            Some("lladdr") => break tokens.next()?,
            Some(_) => {}
            None => return None,
        }
    };

    let mut mac = [0u8; 6];
    let mut parts = mac_str.split(':');
    for byte in &mut mac {
        *byte = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    // Reject if there are extra octets (malformed) or an all-zero MAC.
    if parts.next().is_some() || mac == [0u8; 6] {
        return None;
    }
    Some(mac)
}

/// Resolve the network interface index for a given backend IP address.
/// Uses the system routing table to determine which interface would be used
/// to reach the backend. Returns `None` if resolution fails.
fn resolve_ifindex_for_ip(addr_v4: u32, is_ipv6: bool) -> Option<u32> {
    if is_ipv6 {
        // IPv6 ifindex resolution would require parsing /proc/net/ipv6_route
        // or using netlink. For now, skip DevMap redirect for IPv6 backends.
        return None;
    }
    if addr_v4 == 0 {
        return None;
    }

    // Convert host-order u32 to IP string for route lookup
    let ip = std::net::Ipv4Addr::from(addr_v4);

    // Use `ip route get` to resolve the output interface
    let output = std::process::Command::new("ip")
        .args(["route", "get", &ip.to_string()])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Parse "... dev eth0 ..." from the output
    let dev_name = stdout
        .split_whitespace()
        .zip(stdout.split_whitespace().skip(1))
        .find(|(key, _)| *key == "dev")
        .map(|(_, val)| val)?;

    // Validate interface name to prevent path traversal (kernel limit: IFNAMSIZ-1 = 15,
    // allowed chars: alphanumeric, underscore, hyphen, dot, colon).
    if dev_name.is_empty()
        || dev_name.len() > 15
        || !dev_name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.' || b == b':')
    {
        return None;
    }

    // Resolve interface name to ifindex
    let ifindex_str = std::fs::read_to_string(format!("/sys/class/net/{dev_name}/ifindex")).ok()?;
    ifindex_str.trim().parse::<u32>().ok()
}
