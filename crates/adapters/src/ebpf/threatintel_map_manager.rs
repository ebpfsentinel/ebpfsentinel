use aya::Ebpf;
use aya::maps::{BloomFilter, HashMap, MapData};
use domain::common::error::DomainError;
use domain::threatintel::entity::Ioc;
use ebpf_common::threatintel::{
    THREATINTEL_ACTION_ALERT, THREATINTEL_ACTION_DROP, ThreatIntelKey, ThreatIntelKeyV6,
    ThreatIntelValue,
};
use ports::secondary::threatintel_map_port::ThreatIntelMapPort;
use tracing::{info, warn};

/// Manages the `THREATINTEL_IOCS` (IPv4) and `THREATINTEL_IOCS_V6` (IPv6)
/// eBPF `HashMap` maps.
///
/// Provides typed wrappers around the raw eBPF maps for inserting,
/// removing, and reloading threat intelligence IOCs. All writes are
/// serialized through `&mut self` (single writer pattern).
pub struct ThreatIntelMapManager {
    iocs_map: HashMap<MapData, ThreatIntelKey, ThreatIntelValue>,
    iocs_v6_map: Option<HashMap<MapData, ThreatIntelKeyV6, ThreatIntelValue>>,
    bloom_v4: Option<BloomFilter<MapData, ThreatIntelKey>>,
    bloom_v6: Option<BloomFilter<MapData, ThreatIntelKeyV6>>,
}

impl ThreatIntelMapManager {
    /// Create a new `ThreatIntelMapManager` by taking ownership of the
    /// `THREATINTEL_IOCS` map from the loaded eBPF program.
    ///
    /// Also attempts to take the `THREATINTEL_IOCS_V6` map (graceful if absent).
    pub fn new(ebpf: &mut Ebpf) -> Result<Self, anyhow::Error> {
        let map = ebpf
            .take_map("THREATINTEL_IOCS")
            .ok_or_else(|| anyhow::anyhow!("map 'THREATINTEL_IOCS' not found in eBPF object"))?;
        let iocs_map = HashMap::try_from(map)?;

        let iocs_v6_map = ebpf
            .take_map("THREATINTEL_IOCS_V6")
            .and_then(|m| HashMap::try_from(m).ok());

        // Bloom filters are optional — graceful if absent (older eBPF object).
        let bloom_v4 = ebpf
            .take_map("THREATINTEL_BLOOM_V4")
            .and_then(|m| BloomFilter::try_from(m).ok());
        let bloom_v6 = ebpf
            .take_map("THREATINTEL_BLOOM_V6")
            .and_then(|m| BloomFilter::try_from(m).ok());

        info!(
            v6 = iocs_v6_map.is_some(),
            bloom_v4 = bloom_v4.is_some(),
            bloom_v6 = bloom_v6.is_some(),
            "threat intel maps acquired"
        );
        Ok(Self {
            iocs_map,
            iocs_v6_map,
            bloom_v4,
            bloom_v6,
        })
    }

    /// Insert an IPv6 IOC into the V6 map.
    pub fn insert_ioc_v6(
        &mut self,
        key: &ThreatIntelKeyV6,
        value: &ThreatIntelValue,
    ) -> Result<(), DomainError> {
        let v6_map = self.iocs_v6_map.as_mut().ok_or_else(|| {
            DomainError::EngineError("THREATINTEL_IOCS_V6 map not available".to_string())
        })?;
        v6_map
            .insert(key, value, 0)
            .map_err(|e| DomainError::EngineError(format!("eBPF V6 map insert failed: {e}")))?;
        Ok(())
    }

    /// Remove an IPv6 IOC from the V6 map.
    pub fn remove_ioc_v6(&mut self, key: &ThreatIntelKeyV6) -> Result<(), DomainError> {
        let v6_map = self.iocs_v6_map.as_mut().ok_or_else(|| {
            DomainError::EngineError("THREATINTEL_IOCS_V6 map not available".to_string())
        })?;
        v6_map
            .remove(key)
            .map_err(|e| DomainError::EngineError(format!("eBPF V6 map remove failed: {e}")))?;
        Ok(())
    }

    /// Atomically reload all IOCs: clear existing, then insert all new IOCs.
    ///
    /// Partitions IOCs by IP version: V4 goes to `THREATINTEL_IOCS`,
    /// V6 goes to `THREATINTEL_IOCS_V6` (skipped if V6 map not present).
    ///
    /// `block_mode` determines the eBPF action for all entries:
    /// - `true` -> `THREATINTEL_ACTION_DROP` (block + alert)
    /// - `false` -> `THREATINTEL_ACTION_ALERT` (alert only, pass traffic)
    pub fn load_iocs(&mut self, iocs: &[Ioc], block_mode: bool) -> Result<(), DomainError> {
        self.clear_iocs()?;
        let action = if block_mode {
            THREATINTEL_ACTION_DROP
        } else {
            THREATINTEL_ACTION_ALERT
        };

        let mut v4_count = 0usize;
        let mut v6_count = 0usize;

        for (idx, ioc) in iocs.iter().enumerate() {
            let value = ThreatIntelValue {
                action,
                #[allow(clippy::cast_possible_truncation)]
                feed_id: (idx % 256) as u8, // intentional: wraps index into u8
                confidence: ioc.confidence,
                threat_type: ioc.threat_type.to_u8(),
            };

            match ioc.ip {
                std::net::IpAddr::V4(v4) => {
                    let key = ThreatIntelKey { ip: u32::from(v4) };
                    self.insert_ioc(&key, &value)?;
                    // Best-effort bloom filter insert (non-fatal on error).
                    if let Some(ref mut bloom) = self.bloom_v4
                        && let Err(e) = bloom.insert(key, 0)
                    {
                        warn!(ip = %v4, "bloom V4 insert failed: {e}");
                    }
                    v4_count += 1;
                }
                std::net::IpAddr::V6(v6) => {
                    if self.iocs_v6_map.is_some() {
                        let octets = v6.octets();
                        let key = ThreatIntelKeyV6 {
                            ip: [
                                u32::from_be_bytes([octets[0], octets[1], octets[2], octets[3]]),
                                u32::from_be_bytes([octets[4], octets[5], octets[6], octets[7]]),
                                u32::from_be_bytes([octets[8], octets[9], octets[10], octets[11]]),
                                u32::from_be_bytes([
                                    octets[12], octets[13], octets[14], octets[15],
                                ]),
                            ],
                        };
                        self.insert_ioc_v6(&key, &value)?;
                        // Best-effort bloom filter insert (non-fatal on error).
                        if let Some(ref mut bloom) = self.bloom_v6
                            && let Err(e) = bloom.insert(key, 0)
                        {
                            warn!(ip = %v6, "bloom V6 insert failed: {e}");
                        }
                        v6_count += 1;
                    }
                    // Silently skip V6 IOCs when V6 map is not present
                }
            }
        }

        info!(
            v4_count,
            v6_count,
            total = iocs.len(),
            "threat intel IOCs loaded into eBPF maps"
        );
        Ok(())
    }
}

impl ThreatIntelMapPort for ThreatIntelMapManager {
    fn insert_ioc(
        &mut self,
        key: &ThreatIntelKey,
        value: &ThreatIntelValue,
    ) -> Result<(), DomainError> {
        self.iocs_map
            .insert(key, value, 0)
            .map_err(|e| DomainError::EngineError(format!("eBPF map insert failed: {e}")))?;
        Ok(())
    }

    fn remove_ioc(&mut self, key: &ThreatIntelKey) -> Result<(), DomainError> {
        self.iocs_map
            .remove(key)
            .map_err(|e| DomainError::EngineError(format!("eBPF map remove failed: {e}")))?;
        Ok(())
    }

    fn clear_iocs(&mut self) -> Result<(), DomainError> {
        // Clear V4 map
        let keys: Vec<ThreatIntelKey> = self.iocs_map.keys().filter_map(Result::ok).collect();
        for key in &keys {
            self.iocs_map
                .remove(key)
                .map_err(|e| DomainError::EngineError(format!("eBPF map clear failed: {e}")))?;
        }

        // Clear V6 map (if present)
        if let Some(ref mut v6_map) = self.iocs_v6_map {
            let v6_keys: Vec<ThreatIntelKeyV6> = v6_map.keys().filter_map(Result::ok).collect();
            for key in &v6_keys {
                v6_map.remove(key).map_err(|e| {
                    DomainError::EngineError(format!("eBPF V6 map clear failed: {e}"))
                })?;
            }
        }

        Ok(())
    }

    fn ioc_count(&self) -> Result<usize, DomainError> {
        let v4_count = self.iocs_map.keys().filter_map(Result::ok).count();
        let v6_count = self
            .iocs_v6_map
            .as_ref()
            .map_or(0, |m| m.keys().filter_map(Result::ok).count());
        Ok(v4_count + v6_count)
    }
}
