use aya::Ebpf;
use aya::maps::MapData;
use aya::maps::lpm_trie::{Key, LpmTrie};
use domain::common::error::DomainError;
use ebpf_common::firewall::{FirewallLpmEntryV4, FirewallLpmEntryV6, LpmValue};
use ports::secondary::geoip_lpm_port::GeoIpLpmPort;
use tracing::info;

/// Manages the 4 LPM Trie maps for `GeoIP` CIDR-based firewall blocking.
///
/// Takes ownership of `FW_LPM_SRC_V4`, `FW_LPM_DST_V4`, `FW_LPM_SRC_V6`,
/// `FW_LPM_DST_V6` from the xdp-firewall eBPF program.
///
/// Must be created **before** `FirewallMapManager` since `take_map()` is
/// destructive.
#[allow(clippy::struct_field_names)]
pub struct GeoIpLpmManager {
    lpm_src_v4: LpmTrie<MapData, [u8; 4], LpmValue>,
    lpm_dst_v4: LpmTrie<MapData, [u8; 4], LpmValue>,
    lpm_src_v6: LpmTrie<MapData, [u8; 16], LpmValue>,
    lpm_dst_v6: LpmTrie<MapData, [u8; 16], LpmValue>,
}

impl GeoIpLpmManager {
    /// Create a new `GeoIpLpmManager` by taking ownership of the 4 LPM Trie
    /// maps from the loaded xdp-firewall eBPF program.
    pub fn new(ebpf: &mut Ebpf) -> Result<Self, anyhow::Error> {
        let lpm_src_v4 = LpmTrie::try_from(
            ebpf.take_map("FW_LPM_SRC_V4")
                .ok_or_else(|| anyhow::anyhow!("map 'FW_LPM_SRC_V4' not found"))?,
        )?;
        let lpm_dst_v4 = LpmTrie::try_from(
            ebpf.take_map("FW_LPM_DST_V4")
                .ok_or_else(|| anyhow::anyhow!("map 'FW_LPM_DST_V4' not found"))?,
        )?;
        let lpm_src_v6 = LpmTrie::try_from(
            ebpf.take_map("FW_LPM_SRC_V6")
                .ok_or_else(|| anyhow::anyhow!("map 'FW_LPM_SRC_V6' not found"))?,
        )?;
        let lpm_dst_v6 = LpmTrie::try_from(
            ebpf.take_map("FW_LPM_DST_V6")
                .ok_or_else(|| anyhow::anyhow!("map 'FW_LPM_DST_V6' not found"))?,
        )?;

        info!("GeoIP LPM Trie maps acquired from xdp-firewall");
        Ok(Self {
            lpm_src_v4,
            lpm_dst_v4,
            lpm_src_v6,
            lpm_dst_v6,
        })
    }
}

impl GeoIpLpmPort for GeoIpLpmManager {
    fn load_lpm_v4_rules(
        &mut self,
        src_rules: &[FirewallLpmEntryV4],
        dst_rules: &[FirewallLpmEntryV4],
    ) -> Result<(), DomainError> {
        // Clear existing src LPM entries
        let src_keys: Vec<Key<[u8; 4]>> = self.lpm_src_v4.keys().filter_map(Result::ok).collect();
        for key in &src_keys {
            let _ = self.lpm_src_v4.remove(key);
        }
        // Insert src rules
        for entry in src_rules {
            let key = Key::new(entry.prefix_len, entry.addr);
            let value = LpmValue {
                action: entry.action,
                _padding: [0; 3],
            };
            self.lpm_src_v4
                .insert(&key, value, 0)
                .map_err(|e| DomainError::EngineError(format!("LPM src V4 insert failed: {e}")))?;
        }

        // Clear existing dst LPM entries
        let dst_keys: Vec<Key<[u8; 4]>> = self.lpm_dst_v4.keys().filter_map(Result::ok).collect();
        for key in &dst_keys {
            let _ = self.lpm_dst_v4.remove(key);
        }
        // Insert dst rules
        for entry in dst_rules {
            let key = Key::new(entry.prefix_len, entry.addr);
            let value = LpmValue {
                action: entry.action,
                _padding: [0; 3],
            };
            self.lpm_dst_v4
                .insert(&key, value, 0)
                .map_err(|e| DomainError::EngineError(format!("LPM dst V4 insert failed: {e}")))?;
        }

        info!(
            src_count = src_rules.len(),
            dst_count = dst_rules.len(),
            "GeoIP LPM V4 rules loaded"
        );
        Ok(())
    }

    fn load_lpm_v6_rules(
        &mut self,
        src_rules: &[FirewallLpmEntryV6],
        dst_rules: &[FirewallLpmEntryV6],
    ) -> Result<(), DomainError> {
        // Clear existing src LPM entries
        let src_keys: Vec<Key<[u8; 16]>> = self.lpm_src_v6.keys().filter_map(Result::ok).collect();
        for key in &src_keys {
            let _ = self.lpm_src_v6.remove(key);
        }
        // Insert src rules
        for entry in src_rules {
            let key = Key::new(entry.prefix_len, entry.addr);
            let value = LpmValue {
                action: entry.action,
                _padding: [0; 3],
            };
            self.lpm_src_v6
                .insert(&key, value, 0)
                .map_err(|e| DomainError::EngineError(format!("LPM src V6 insert failed: {e}")))?;
        }

        // Clear existing dst LPM entries
        let dst_keys: Vec<Key<[u8; 16]>> = self.lpm_dst_v6.keys().filter_map(Result::ok).collect();
        for key in &dst_keys {
            let _ = self.lpm_dst_v6.remove(key);
        }
        // Insert dst rules
        for entry in dst_rules {
            let key = Key::new(entry.prefix_len, entry.addr);
            let value = LpmValue {
                action: entry.action,
                _padding: [0; 3],
            };
            self.lpm_dst_v6
                .insert(&key, value, 0)
                .map_err(|e| DomainError::EngineError(format!("LPM dst V6 insert failed: {e}")))?;
        }

        info!(
            src_count = src_rules.len(),
            dst_count = dst_rules.len(),
            "GeoIP LPM V6 rules loaded"
        );
        Ok(())
    }
}
