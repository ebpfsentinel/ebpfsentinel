use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use aya::maps::{BloomFilter, HashMap, MapData};
use domain::common::error::DomainError;
use ebpf_common::threatintel::{
    THREATINTEL_ACTION_DROP, ThreatIntelKey, ThreatIntelKeyV6, ThreatIntelValue,
};
use ports::secondary::ebpf_map_write_port::{EbpfMapWritePort, IocMetadata};
use tracing::{info, warn};

/// Adapter implementing `EbpfMapWritePort` for dynamic eBPF map writes.
///
/// Used by the DNS blocklist service to inject/remove IPs from the
/// threat intelligence eBPF maps at runtime. Maps are shared with
/// `ThreatIntelMapManager` via `Arc<Mutex<>>`.
pub struct EbpfMapWriteAdapter {
    threatintel_v4: Arc<Mutex<HashMap<MapData, ThreatIntelKey, ThreatIntelValue>>>,
    threatintel_v6: Option<Arc<Mutex<HashMap<MapData, ThreatIntelKeyV6, ThreatIntelValue>>>>,
    bloom_v4: Option<Arc<Mutex<BloomFilter<MapData, ThreatIntelKey>>>>,
    bloom_v6: Option<Arc<Mutex<BloomFilter<MapData, ThreatIntelKeyV6>>>>,
}

impl EbpfMapWriteAdapter {
    /// Create a new adapter with shared access to the threat intel maps.
    pub fn new(
        threatintel_v4: Arc<Mutex<HashMap<MapData, ThreatIntelKey, ThreatIntelValue>>>,
        threatintel_v6: Option<Arc<Mutex<HashMap<MapData, ThreatIntelKeyV6, ThreatIntelValue>>>>,
        bloom_v4: Option<Arc<Mutex<BloomFilter<MapData, ThreatIntelKey>>>>,
        bloom_v6: Option<Arc<Mutex<BloomFilter<MapData, ThreatIntelKeyV6>>>>,
    ) -> Self {
        info!("EbpfMapWriteAdapter initialized");
        Self {
            threatintel_v4,
            threatintel_v6,
            bloom_v4,
            bloom_v6,
        }
    }
}

impl EbpfMapWritePort for EbpfMapWriteAdapter {
    fn inject_threatintel_ip(&self, ip: IpAddr, metadata: &IocMetadata) -> Result<(), DomainError> {
        let value = ThreatIntelValue {
            action: THREATINTEL_ACTION_DROP,
            feed_id: 0, // DNS blocklist feed
            confidence: metadata.confidence,
            threat_type: 0, // THREAT_TYPE_OTHER
        };

        match ip {
            IpAddr::V4(v4) => {
                let key = ThreatIntelKey { ip: u32::from(v4) };
                let mut map = self.threatintel_v4.lock().map_err(|e| {
                    DomainError::EngineError(format!("threatintel V4 map lock poisoned: {e}"))
                })?;
                map.insert(key, value, 0).map_err(|e| {
                    DomainError::EngineError(format!("threatintel V4 insert failed: {e}"))
                })?;
                // Best-effort bloom filter insert.
                if let Some(ref bloom) = self.bloom_v4
                    && let Ok(mut b) = bloom.lock()
                {
                    let _ = b.insert(key, 0);
                }
            }
            IpAddr::V6(v6) => {
                let Some(ref v6_map) = self.threatintel_v6 else {
                    warn!(ip = %ip, "V6 threatintel map not available, skipping inject");
                    return Ok(());
                };
                let octets = v6.octets();
                let key = ThreatIntelKeyV6 {
                    ip: [
                        u32::from_be_bytes([octets[0], octets[1], octets[2], octets[3]]),
                        u32::from_be_bytes([octets[4], octets[5], octets[6], octets[7]]),
                        u32::from_be_bytes([octets[8], octets[9], octets[10], octets[11]]),
                        u32::from_be_bytes([octets[12], octets[13], octets[14], octets[15]]),
                    ],
                };
                let mut map = v6_map.lock().map_err(|e| {
                    DomainError::EngineError(format!("threatintel V6 map lock poisoned: {e}"))
                })?;
                map.insert(key, value, 0).map_err(|e| {
                    DomainError::EngineError(format!("threatintel V6 insert failed: {e}"))
                })?;
                // Best-effort bloom filter insert.
                if let Some(ref bloom) = self.bloom_v6
                    && let Ok(mut b) = bloom.lock()
                {
                    let _ = b.insert(key, 0);
                }
            }
        }

        Ok(())
    }

    fn remove_threatintel_ip(&self, ip: IpAddr) -> Result<(), DomainError> {
        match ip {
            IpAddr::V4(v4) => {
                let key = ThreatIntelKey { ip: u32::from(v4) };
                let mut map = self.threatintel_v4.lock().map_err(|e| {
                    DomainError::EngineError(format!("threatintel V4 map lock poisoned: {e}"))
                })?;
                map.remove(&key).map_err(|e| {
                    DomainError::EngineError(format!("threatintel V4 remove failed: {e}"))
                })?;
            }
            IpAddr::V6(v6) => {
                let Some(ref v6_map) = self.threatintel_v6 else {
                    return Ok(());
                };
                let octets = v6.octets();
                let key = ThreatIntelKeyV6 {
                    ip: [
                        u32::from_be_bytes([octets[0], octets[1], octets[2], octets[3]]),
                        u32::from_be_bytes([octets[4], octets[5], octets[6], octets[7]]),
                        u32::from_be_bytes([octets[8], octets[9], octets[10], octets[11]]),
                        u32::from_be_bytes([octets[12], octets[13], octets[14], octets[15]]),
                    ],
                };
                let mut map = v6_map.lock().map_err(|e| {
                    DomainError::EngineError(format!("threatintel V6 map lock poisoned: {e}"))
                })?;
                map.remove(&key).map_err(|e| {
                    DomainError::EngineError(format!("threatintel V6 remove failed: {e}"))
                })?;
            }
        }

        Ok(())
    }

    fn inject_firewall_drop(&self, ip: IpAddr) -> Result<(), DomainError> {
        // Firewall uses Array-based maps with atomic bulk-load protocol.
        // Dynamic single-IP injection is not architecturally supported.
        warn!(ip = %ip, "inject_firewall_drop is a no-op: firewall uses Array maps");
        Ok(())
    }

    fn remove_firewall_drop(&self, ip: IpAddr) -> Result<(), DomainError> {
        warn!(ip = %ip, "remove_firewall_drop is a no-op: firewall uses Array maps");
        Ok(())
    }
}
