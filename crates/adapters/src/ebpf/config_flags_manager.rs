use crate::ebpf::map_store::MapStore;
use aya::maps::{Array, HashMap, MapData};
use ebpf_common::config_flags::ConfigFlags;
use ebpf_common::ddos::{
    AmpProtectConfig, AmpProtectKey, DdosConnTrackConfig, DdosSynConfig, IcmpConfig,
    SyncookieSecret,
};
use ebpf_common::scrub::ScrubFlags;
use tracing::info;

/// Manages a `CONFIG_FLAGS` eBPF `Array` map.
///
/// Each eBPF program with a `CONFIG_FLAGS` map gets its own instance.
/// Stores a single `ConfigFlags` struct at index 0.
pub struct ConfigFlagsManager {
    flags_map: Array<MapData, ConfigFlags>,
}

impl ConfigFlagsManager {
    /// Create a new `ConfigFlagsManager` by taking ownership of the
    /// `CONFIG_FLAGS` map from the loaded eBPF program.
    pub fn new(ebpf: &mut dyn MapStore) -> Result<Self, anyhow::Error> {
        let map = ebpf
            .take_map("CONFIG_FLAGS")
            .ok_or_else(|| anyhow::anyhow!("map 'CONFIG_FLAGS' not found in eBPF object"))?;
        let flags_map = Array::try_from(map)?;
        info!("CONFIG_FLAGS map acquired");
        Ok(Self { flags_map })
    }

    /// Write the full `ConfigFlags` struct to index 0.
    pub fn set_flags(&mut self, flags: &ConfigFlags) -> Result<(), anyhow::Error> {
        self.flags_map
            .set(0, *flags, 0)
            .map_err(|e| anyhow::anyhow!("CONFIG_FLAGS set failed: {e}"))?;
        info!("CONFIG_FLAGS updated");
        Ok(())
    }

    /// Read the `ConfigFlags` struct from index 0.
    pub fn get_flags(&self) -> Result<ConfigFlags, anyhow::Error> {
        self.flags_map
            .get(&0, 0)
            .map_err(|e| anyhow::anyhow!("CONFIG_FLAGS get failed: {e}"))
    }
}

/// Manages a `SCRUB_CONFIG` eBPF `Array` map.
///
/// Stores a single `ScrubFlags` struct at index 0, controlling
/// the tc-scrub packet normalization behavior.
pub struct ScrubConfigManager {
    flags_map: Array<MapData, ScrubFlags>,
}

impl ScrubConfigManager {
    /// Create a new `ScrubConfigManager` by taking ownership of the
    /// `SCRUB_CONFIG` map from the loaded eBPF program.
    pub fn new(ebpf: &mut dyn MapStore) -> Result<Self, anyhow::Error> {
        let map = ebpf
            .take_map("SCRUB_CONFIG")
            .ok_or_else(|| anyhow::anyhow!("map 'SCRUB_CONFIG' not found in eBPF object"))?;
        let flags_map = Array::try_from(map)?;
        info!("SCRUB_CONFIG map acquired");
        Ok(Self { flags_map })
    }

    /// Write the `ScrubFlags` struct to index 0.
    pub fn set_flags(&mut self, flags: &ScrubFlags) -> Result<(), anyhow::Error> {
        self.flags_map
            .set(0, *flags, 0)
            .map_err(|e| anyhow::anyhow!("SCRUB_CONFIG set failed: {e}"))?;
        info!("SCRUB_CONFIG updated");
        Ok(())
    }
}

/// Manages the `SYNCOOKIE_SECRET` eBPF `Array` map.
///
/// Stores a 32-byte random key used by xdp-ratelimit for SYN cookie
/// generation and validation.
pub struct SyncookieSecretManager {
    secret_map: Array<MapData, SyncookieSecret>,
}

impl SyncookieSecretManager {
    /// Create a new manager by taking ownership of the `SYNCOOKIE_SECRET` map.
    pub fn new(ebpf: &mut dyn MapStore) -> Result<Self, anyhow::Error> {
        let map = ebpf
            .take_map("SYNCOOKIE_SECRET")
            .ok_or_else(|| anyhow::anyhow!("map 'SYNCOOKIE_SECRET' not found in eBPF object"))?;
        let secret_map = Array::try_from(map)?;
        info!("SYNCOOKIE_SECRET map acquired");
        Ok(Self { secret_map })
    }

    /// Write a random secret key to index 0.
    pub fn set_secret(&mut self, secret: &SyncookieSecret) -> Result<(), anyhow::Error> {
        self.secret_map
            .set(0, *secret, 0)
            .map_err(|e| anyhow::anyhow!("SYNCOOKIE_SECRET set failed: {e}"))?;
        info!("SYN cookie secret initialized");
        Ok(())
    }
}

/// Manages the `DDOS_SYN_CONFIG` eBPF `Array` map.
///
/// Stores a single [`DdosSynConfig`] at index 0, which gates the
/// xdp-ratelimit SYN-cookie path: `check_syn_flood` reads `enabled`
/// (off by default) plus the threshold-mode parameters. Without this
/// write the map stays zeroed and SYN-cookie generation never fires.
pub struct DdosSynConfigManager {
    config_map: Array<MapData, DdosSynConfig>,
}

impl DdosSynConfigManager {
    /// Create a new manager by taking ownership of the `DDOS_SYN_CONFIG` map.
    pub fn new(ebpf: &mut dyn MapStore) -> Result<Self, anyhow::Error> {
        let map = ebpf
            .take_map("DDOS_SYN_CONFIG")
            .ok_or_else(|| anyhow::anyhow!("map 'DDOS_SYN_CONFIG' not found in eBPF object"))?;
        let config_map = Array::try_from(map)?;
        info!("DDOS_SYN_CONFIG map acquired");
        Ok(Self { config_map })
    }

    /// Write the `DdosSynConfig` struct to index 0.
    pub fn set_config(&mut self, config: &DdosSynConfig) -> Result<(), anyhow::Error> {
        self.config_map
            .set(0, *config, 0)
            .map_err(|e| anyhow::anyhow!("DDOS_SYN_CONFIG set failed: {e}"))?;
        info!(
            enabled = config.enabled,
            threshold_mode = config.threshold_mode,
            threshold_pps = config.threshold_pps,
            "DDOS_SYN_CONFIG updated"
        );
        Ok(())
    }
}

/// Manages the `ICMP_CONFIG` eBPF `Array` map.
///
/// Stores a single [`IcmpConfig`] at index 0, which gates the
/// xdp-ratelimit ICMP-flood path: `process_icmp` reads `enabled`
/// (off by default). Without this write the map stays zeroed and ICMP
/// flood protection never engages.
pub struct IcmpConfigManager {
    config_map: Array<MapData, IcmpConfig>,
}

impl IcmpConfigManager {
    /// Create a new manager by taking ownership of the `ICMP_CONFIG` map.
    pub fn new(ebpf: &mut dyn MapStore) -> Result<Self, anyhow::Error> {
        let map = ebpf
            .take_map("ICMP_CONFIG")
            .ok_or_else(|| anyhow::anyhow!("map 'ICMP_CONFIG' not found in eBPF object"))?;
        let config_map = Array::try_from(map)?;
        info!("ICMP_CONFIG map acquired");
        Ok(Self { config_map })
    }

    /// Write the `IcmpConfig` struct to index 0.
    pub fn set_config(&mut self, config: &IcmpConfig) -> Result<(), anyhow::Error> {
        self.config_map
            .set(0, *config, 0)
            .map_err(|e| anyhow::anyhow!("ICMP_CONFIG set failed: {e}"))?;
        info!(
            enabled = config.enabled,
            max_pps = config.max_pps,
            max_payload_size = config.max_payload_size,
            "ICMP_CONFIG updated"
        );
        Ok(())
    }
}

/// Manages the xdp-ratelimit `CONNTRACK_CONFIG` eBPF `Array` map.
///
/// Stores a single [`DdosConnTrackConfig`] at index 0, which gates the
/// xdp-ratelimit RST/FIN/ACK/half-open flood path: `process_conntrack`
/// reads `enabled` (off by default). This is distinct from the
/// tc-conntrack `CT_CONFIG` map (see `ConnTrackMapManager`).
pub struct DdosConnTrackConfigManager {
    config_map: Array<MapData, DdosConnTrackConfig>,
}

impl DdosConnTrackConfigManager {
    /// Create a new manager by taking ownership of the `CONNTRACK_CONFIG` map.
    pub fn new(ebpf: &mut dyn MapStore) -> Result<Self, anyhow::Error> {
        let map = ebpf
            .take_map("CONNTRACK_CONFIG")
            .ok_or_else(|| anyhow::anyhow!("map 'CONNTRACK_CONFIG' not found in eBPF object"))?;
        let config_map = Array::try_from(map)?;
        info!("CONNTRACK_CONFIG map acquired");
        Ok(Self { config_map })
    }

    /// Write the `DdosConnTrackConfig` struct to index 0.
    pub fn set_config(&mut self, config: &DdosConnTrackConfig) -> Result<(), anyhow::Error> {
        self.config_map
            .set(0, *config, 0)
            .map_err(|e| anyhow::anyhow!("CONNTRACK_CONFIG set failed: {e}"))?;
        info!(
            enabled = config.enabled,
            half_open_threshold = config.half_open_threshold,
            rst_threshold = config.rst_threshold,
            fin_threshold = config.fin_threshold,
            ack_threshold = config.ack_threshold,
            "CONNTRACK_CONFIG updated"
        );
        Ok(())
    }
}

/// Manages the `AMP_PROTECT_CONFIG` eBPF `HashMap` map.
///
/// Keyed by `{source port, protocol}`, it gates the xdp-ratelimit UDP
/// amplification path: `check_udp_amplification` looks up the packet's
/// source port and bails when the entry is missing or `enabled == 0`.
/// One entry must be inserted per configured amplification vector port.
pub struct AmpProtectConfigManager {
    config_map: HashMap<MapData, AmpProtectKey, AmpProtectConfig>,
}

impl AmpProtectConfigManager {
    /// Create a new manager by taking ownership of the `AMP_PROTECT_CONFIG` map.
    pub fn new(ebpf: &mut dyn MapStore) -> Result<Self, anyhow::Error> {
        let map = ebpf
            .take_map("AMP_PROTECT_CONFIG")
            .ok_or_else(|| anyhow::anyhow!("map 'AMP_PROTECT_CONFIG' not found in eBPF object"))?;
        let config_map = HashMap::try_from(map)?;
        info!("AMP_PROTECT_CONFIG map acquired");
        Ok(Self { config_map })
    }

    /// Enable amplification protection for one source port (host-order)
    /// over the given IP protocol, capped at `max_pps` per source IP.
    pub fn set_port(&mut self, port: u16, protocol: u8, max_pps: u32) -> Result<(), anyhow::Error> {
        let key = AmpProtectKey {
            port,
            protocol,
            _pad: 0,
        };
        let cfg = AmpProtectConfig {
            enabled: 1,
            _pad: [0; 3],
            max_pps,
        };
        self.config_map
            .insert(key, cfg, 0)
            .map_err(|e| anyhow::anyhow!("AMP_PROTECT_CONFIG insert failed: {e}"))?;
        info!(port, protocol, max_pps, "AMP_PROTECT_CONFIG port armed");
        Ok(())
    }
}

/// Manages `INTERFACE_GROUPS` eBPF `HashMap` maps across multiple programs.
///
/// Each eBPF program that supports interface group scoping has an
/// `INTERFACE_GROUPS` map (key = ifindex, value = group bitmask).
/// This manager collects all such maps and provides a single method
/// to update them atomically when interface group configuration changes.
pub struct InterfaceGroupsManager {
    maps: Vec<HashMap<MapData, u32, u32>>,
}

impl InterfaceGroupsManager {
    /// Create a new, empty `InterfaceGroupsManager`.
    pub fn new() -> Self {
        Self { maps: Vec::new() }
    }

    /// Take the `INTERFACE_GROUPS` map from the loaded eBPF program and
    /// register it for group membership updates. No-op if the map does
    /// not exist in the program (e.g., programs that do not support groups).
    pub fn add_map(&mut self, ebpf: &mut dyn MapStore) {
        if let Some(map) = ebpf.take_map("INTERFACE_GROUPS") {
            match HashMap::try_from(map) {
                Ok(hm) => {
                    self.maps.push(hm);
                    info!("INTERFACE_GROUPS map acquired");
                }
                Err(e) => {
                    tracing::warn!("INTERFACE_GROUPS map conversion failed: {e}");
                }
            }
        }
    }

    /// Set interface group membership for all registered maps.
    ///
    /// `memberships` is a slice of `(ifindex, group_bitmask)` pairs.
    /// Each map is updated with every pair (existing entries are overwritten).
    pub fn set_interface_groups(
        &mut self,
        memberships: &[(u32, u32)],
    ) -> Result<(), anyhow::Error> {
        for map in &mut self.maps {
            for &(ifindex, groups) in memberships {
                map.insert(ifindex, groups, 0)
                    .map_err(|e| anyhow::anyhow!("INTERFACE_GROUPS insert failed: {e}"))?;
            }
        }
        if !memberships.is_empty() {
            info!(
                map_count = self.maps.len(),
                iface_count = memberships.len(),
                "INTERFACE_GROUPS updated"
            );
        }
        Ok(())
    }

    /// Return the number of registered maps.
    pub fn map_count(&self) -> usize {
        self.maps.len()
    }
}

impl Default for InterfaceGroupsManager {
    fn default() -> Self {
        Self::new()
    }
}
