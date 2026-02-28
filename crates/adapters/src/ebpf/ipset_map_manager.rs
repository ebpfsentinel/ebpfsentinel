use aya::Ebpf;
use aya::maps::{HashMap, MapData};
use domain::common::error::DomainError;
use ebpf_common::firewall::IpSetKeyV4;
use ports::secondary::nat_map_port::IpSetMapPort;
use tracing::info;

/// Manages the eBPF IP set maps used for alias matching.
///
/// Uses 1 map:
/// - `FW_IPSET_V4`: `HashMap<IpSetKeyV4, u8>` (IPv4 IP set entries)
pub struct IpSetMapManager {
    ipset_v4: HashMap<MapData, IpSetKeyV4, u8>,
    cached_count: usize,
}

impl IpSetMapManager {
    /// Create a new `IpSetMapManager` by taking ownership of the IP set map.
    pub fn new(ebpf: &mut Ebpf) -> Result<Self, anyhow::Error> {
        let ipset_v4 = HashMap::try_from(
            ebpf.take_map("FW_IPSET_V4")
                .ok_or_else(|| anyhow::anyhow!("map 'FW_IPSET_V4' not found"))?,
        )?;

        info!("IP set map acquired (FW_IPSET_V4)");
        Ok(Self {
            ipset_v4,
            cached_count: 0,
        })
    }
}

impl IpSetMapPort for IpSetMapManager {
    fn load_ipset_v4(&mut self, set_id: u8, addrs: &[u32]) -> Result<(), DomainError> {
        // Clear existing entries for this set_id
        self.clear_ipset_v4(set_id)?;

        // Insert new entries
        for &addr in addrs {
            let key = IpSetKeyV4 {
                set_id: u16::from(set_id),
                _pad: [0; 2],
                addr,
            };
            self.ipset_v4.insert(key, 1, 0).map_err(|e| {
                DomainError::EngineError(format!("ipset V4 insert set_id={set_id} failed: {e}"))
            })?;
        }

        // Update cached count
        self.cached_count = self.ipset_v4.keys().filter_map(Result::ok).count();
        info!(set_id, count = addrs.len(), "IPv4 IP set loaded");
        Ok(())
    }

    fn clear_ipset_v4(&mut self, set_id: u8) -> Result<(), DomainError> {
        let set_id_u16 = u16::from(set_id);
        let keys_to_remove: Vec<IpSetKeyV4> = self
            .ipset_v4
            .keys()
            .filter_map(Result::ok)
            .filter(|k| k.set_id == set_id_u16)
            .collect();

        for key in &keys_to_remove {
            let _ = self.ipset_v4.remove(key);
        }

        self.cached_count = self.ipset_v4.keys().filter_map(Result::ok).count();
        Ok(())
    }

    fn ipset_entry_count(&self) -> Result<usize, DomainError> {
        Ok(self.cached_count)
    }
}
