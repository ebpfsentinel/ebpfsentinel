use std::os::fd::{AsFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::ebpf::feature_gates::{self, Feature};
use crate::ebpf::map_batch::{self, MAX_CHUNK};
use crate::ebpf::map_store::MapStore;
use aya::maps::{BloomFilter, HashMap, MapData};
use domain::common::entity::DomainMode;
use domain::common::error::DomainError;
use domain::threatintel::entity::Ioc;
use ebpf_common::threatintel::{
    THREATINTEL_ACTION_ALERT, THREATINTEL_ACTION_DROP, ThreatIntelKey, ThreatIntelKeyV6,
    ThreatIntelValue,
};
use ports::secondary::threatintel_map_port::ThreatIntelMapPort;
use tracing::{debug, info, warn};

/// Shared handle to the threat intel IPv4 map.
pub type SharedTiV4Map = Arc<Mutex<HashMap<MapData, ThreatIntelKey, ThreatIntelValue>>>;
/// Shared handle to the threat intel IPv6 map.
pub type SharedTiV6Map = Arc<Mutex<HashMap<MapData, ThreatIntelKeyV6, ThreatIntelValue>>>;
/// Shared handle to the IPv4 bloom filter.
pub type SharedBloomV4 = Arc<Mutex<BloomFilter<MapData, ThreatIntelKey>>>;
/// Shared handle to the IPv6 bloom filter.
pub type SharedBloomV6 = Arc<Mutex<BloomFilter<MapData, ThreatIntelKeyV6>>>;

/// Manages the `THREATINTEL_IOCS` (IPv4) and `THREATINTEL_IOCS_V6` (IPv6)
/// eBPF `HashMap` maps.
///
/// Maps are wrapped in `Arc<Mutex<>>` so they can be shared with
/// `EbpfMapWriteAdapter` for DNS blocklist IP injection.
pub struct ThreatIntelMapManager {
    iocs_map: SharedTiV4Map,
    iocs_v6_map: Option<SharedTiV6Map>,
    bloom_v4: Option<SharedBloomV4>,
    bloom_v6: Option<SharedBloomV6>,
    /// Descriptors kept beside the typed maps, because the batched commands
    /// are raw `bpf(2)` calls and aya exposes no descriptor through its typed
    /// wrapper. They are duplicates: closing one closes nothing.
    iocs_fd: Option<OwnedFd>,
    iocs_v6_fd: Option<OwnedFd>,
}

/// Set once a batched command comes back as absent, so a kernel without them
/// pays one refused syscall per process rather than one per reload.
static BATCH_ABSENT: AtomicBool = AtomicBool::new(false);

/// Elements per batched call. Four thousand keys of this size is a copy of a
/// few hundred kilobytes into the kernel, which is the point of a ceiling.
const BATCH_CHUNK: usize = MAX_CHUNK;

impl ThreatIntelMapManager {
    /// Create a new `ThreatIntelMapManager` by taking ownership of the
    /// `THREATINTEL_IOCS` map from the loaded eBPF program.
    ///
    /// Also attempts to take the `THREATINTEL_IOCS_V6` map (graceful if absent).
    pub fn new(ebpf: &mut dyn MapStore) -> Result<Self, anyhow::Error> {
        let map = ebpf
            .take_map("THREATINTEL_IOCS")
            .ok_or_else(|| anyhow::anyhow!("map 'THREATINTEL_IOCS' not found in eBPF object"))?;
        let iocs_fd = duplicate_fd(&map, "THREATINTEL_IOCS");
        let iocs_map = Arc::new(Mutex::new(HashMap::try_from(map)?));

        let mut iocs_v6_fd = None;
        let iocs_v6_map = ebpf
            .take_map("THREATINTEL_IOCS_V6")
            .and_then(|m| {
                iocs_v6_fd = duplicate_fd(&m, "THREATINTEL_IOCS_V6");
                HashMap::try_from(m).ok()
            })
            .map(|m| Arc::new(Mutex::new(m)));

        // Bloom filters are optional - graceful if absent (older eBPF object).
        let bloom_v4 = ebpf
            .take_map("THREATINTEL_BLOOM_V4")
            .and_then(|m| BloomFilter::try_from(m).ok())
            .map(|m| Arc::new(Mutex::new(m)));
        let bloom_v6 = ebpf
            .take_map("THREATINTEL_BLOOM_V6")
            .and_then(|m| BloomFilter::try_from(m).ok())
            .map(|m| Arc::new(Mutex::new(m)));

        // The sets are shared by pin, so a previous run's indicators can still
        // be in them. Count what is actually there rather than assuming a
        // fresh map, because a gate published against an assumption would skip
        // a probe that would have hit.
        if let Ok(map) = iocs_map.lock() {
            feature_gates::publish(Feature::ThreatIocsV4, map.keys().next().is_none());
        }
        // A v6 set this manager never got hold of is left looked up: the map
        // is in the object either way, and closing a lookup on a table nothing
        // here can account for is the half of the trade that is not safe.
        if let Some(ref v6) = iocs_v6_map
            && let Ok(map) = v6.lock()
        {
            feature_gates::publish(Feature::ThreatIocsV6, map.keys().next().is_none());
        }

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
            iocs_fd,
            iocs_v6_fd,
        })
    }

    /// Return shared handles to the underlying maps for use by
    /// `EbpfMapWriteAdapter` (DNS blocklist injection).
    pub fn shared_handles(
        &self,
    ) -> (
        SharedTiV4Map,
        Option<SharedTiV6Map>,
        Option<SharedBloomV4>,
        Option<SharedBloomV6>,
    ) {
        (
            Arc::clone(&self.iocs_map),
            self.iocs_v6_map.as_ref().map(Arc::clone),
            self.bloom_v4.as_ref().map(Arc::clone),
            self.bloom_v6.as_ref().map(Arc::clone),
        )
    }

    /// Insert an IPv6 IOC into the V6 map.
    pub fn insert_ioc_v6(
        &mut self,
        key: &ThreatIntelKeyV6,
        value: &ThreatIntelValue,
    ) -> Result<(), DomainError> {
        // Open the probe before the insert, so an indicator is never written
        // behind a gate that is still saying the set is empty.
        feature_gates::publish(Feature::ThreatIocsV6, false);
        let v6_arc = self.iocs_v6_map.as_ref().ok_or_else(|| {
            DomainError::EngineError("THREATINTEL_IOCS_V6 map not available".to_string())
        })?;
        let mut v6_map = v6_arc
            .lock()
            .map_err(|e| DomainError::EngineError(format!("V6 map lock poisoned: {e}")))?;
        v6_map
            .insert(key, value, 0)
            .map_err(|e| DomainError::EngineError(format!("eBPF V6 map insert failed: {e}")))?;
        Ok(())
    }

    /// Remove an IPv6 IOC from the V6 map.
    pub fn remove_ioc_v6(&mut self, key: &ThreatIntelKeyV6) -> Result<(), DomainError> {
        let v6_arc = self.iocs_v6_map.as_ref().ok_or_else(|| {
            DomainError::EngineError("THREATINTEL_IOCS_V6 map not available".to_string())
        })?;
        let mut v6_map = v6_arc
            .lock()
            .map_err(|e| DomainError::EngineError(format!("V6 map lock poisoned: {e}")))?;
        v6_map
            .remove(key)
            .map_err(|e| DomainError::EngineError(format!("eBPF V6 map remove failed: {e}")))?;
        Ok(())
    }

    /// Write every `keys[i] -> values[i]` pair into the IPv4 set.
    ///
    /// One batched call per [`BATCH_CHUNK`] elements, which turns a feed of a
    /// million indicators from a million syscalls into a few hundred. A kernel
    /// with no batched update says so on the first chunk and the write falls
    /// back to one element at a time, which is slow and correct.
    fn write_v4(
        &self,
        keys: &[ThreatIntelKey],
        values: &[ThreatIntelValue],
    ) -> Result<(), DomainError> {
        if keys.is_empty() {
            return Ok(());
        }
        // Open the probe before the write, so an indicator is never in the set
        // behind a gate still saying the set is empty.
        feature_gates::publish(Feature::ThreatIocsV4, false);
        let mut map = self
            .iocs_map
            .lock()
            .map_err(|e| DomainError::EngineError(format!("V4 map lock poisoned: {e}")))?;

        if let Some(fd) = self.iocs_fd.as_ref()
            && !BATCH_ABSENT.load(Ordering::Relaxed)
        {
            match map_batch::update_batch("THREATINTEL_IOCS", fd.as_fd(), keys, values, BATCH_CHUNK)
            {
                Ok(written) => {
                    debug!(written, "IPv4 indicators written in batches");
                    return Ok(());
                }
                Err(e) if e.is_unsupported() => {
                    BATCH_ABSENT.store(true, Ordering::Relaxed);
                    warn!("batched map updates unavailable, writing one by one: {e}");
                }
                Err(e) => return Err(DomainError::EngineError(e.to_string())),
            }
        }

        for (key, value) in keys.iter().zip(values) {
            map.insert(key, value, 0)
                .map_err(|e| DomainError::EngineError(format!("eBPF map insert failed: {e}")))?;
        }
        Ok(())
    }

    /// The IPv6 half of [`Self::write_v4`]. Silently nothing when the object
    /// carries no v6 set, which is how the rest of this manager treats it.
    fn write_v6(
        &self,
        keys: &[ThreatIntelKeyV6],
        values: &[ThreatIntelValue],
    ) -> Result<(), DomainError> {
        let Some(v6_arc) = self.iocs_v6_map.as_ref() else {
            return Ok(());
        };
        if keys.is_empty() {
            return Ok(());
        }
        feature_gates::publish(Feature::ThreatIocsV6, false);
        let mut map = v6_arc
            .lock()
            .map_err(|e| DomainError::EngineError(format!("V6 map lock poisoned: {e}")))?;

        if let Some(fd) = self.iocs_v6_fd.as_ref()
            && !BATCH_ABSENT.load(Ordering::Relaxed)
        {
            match map_batch::update_batch(
                "THREATINTEL_IOCS_V6",
                fd.as_fd(),
                keys,
                values,
                BATCH_CHUNK,
            ) {
                Ok(written) => {
                    debug!(written, "IPv6 indicators written in batches");
                    return Ok(());
                }
                Err(e) if e.is_unsupported() => {
                    BATCH_ABSENT.store(true, Ordering::Relaxed);
                    warn!("batched map updates unavailable, writing one by one: {e}");
                }
                Err(e) => return Err(DomainError::EngineError(e.to_string())),
            }
        }

        for (key, value) in keys.iter().zip(values) {
            map.insert(key, value, 0)
                .map_err(|e| DomainError::EngineError(format!("eBPF V6 map insert failed: {e}")))?;
        }
        Ok(())
    }

    /// Atomically reload all IOCs: clear existing, then insert all new IOCs.
    ///
    /// Partitions IOCs by IP version: V4 goes to `THREATINTEL_IOCS`,
    /// V6 goes to `THREATINTEL_IOCS_V6` (skipped if V6 map not present).
    ///
    /// Each IOC carries the mode it is enforced in, because a feed may override
    /// the global one:
    /// - `DomainMode::Block` -> `THREATINTEL_ACTION_DROP` (block + alert)
    /// - `DomainMode::Alert` -> `THREATINTEL_ACTION_ALERT` (alert only, pass traffic)
    pub fn load_iocs(&mut self, iocs: &[(Ioc, DomainMode)]) -> Result<(), DomainError> {
        self.clear_iocs()?;

        let mut v4_keys: Vec<ThreatIntelKey> = Vec::new();
        let mut v4_values: Vec<ThreatIntelValue> = Vec::new();
        let mut v6_keys: Vec<ThreatIntelKeyV6> = Vec::new();
        let mut v6_values: Vec<ThreatIntelValue> = Vec::new();
        let mut blocking = 0usize;
        let v6_present = self.iocs_v6_map.is_some();

        for (idx, (ioc, mode)) in iocs.iter().enumerate() {
            let action = if *mode == DomainMode::Block {
                blocking += 1;
                THREATINTEL_ACTION_DROP
            } else {
                THREATINTEL_ACTION_ALERT
            };
            let value = ThreatIntelValue {
                action,
                #[allow(clippy::cast_possible_truncation)]
                feed_id: (idx % 256) as u8, // intentional: wraps index into u8
                confidence: ioc.confidence,
                threat_type: ioc.threat_type.to_u8(),
            };

            match ioc.ip {
                std::net::IpAddr::V4(v4) => {
                    v4_keys.push(ThreatIntelKey { ip: u32::from(v4) });
                    v4_values.push(value);
                }
                std::net::IpAddr::V6(v6) => {
                    // Silently skip V6 indicators when the V6 set is absent.
                    if v6_present {
                        let octets = v6.octets();
                        v6_keys.push(ThreatIntelKeyV6 {
                            ip: [
                                u32::from_be_bytes([octets[0], octets[1], octets[2], octets[3]]),
                                u32::from_be_bytes([octets[4], octets[5], octets[6], octets[7]]),
                                u32::from_be_bytes([octets[8], octets[9], octets[10], octets[11]]),
                                u32::from_be_bytes([
                                    octets[12], octets[13], octets[14], octets[15],
                                ]),
                            ],
                        });
                        v6_values.push(value);
                    }
                }
            }
        }

        self.write_v4(&v4_keys, &v4_values)?;
        self.write_v6(&v6_keys, &v6_values)?;

        // The filters in front of the sets take one insert per indicator: a
        // bloom filter is a set of bits with no key to batch on, and a miss
        // there costs a lookup the set would have answered anyway.
        if let Some(ref bloom_arc) = self.bloom_v4
            && let Ok(mut bloom) = bloom_arc.lock()
        {
            for key in &v4_keys {
                if let Err(e) = bloom.insert(key, 0) {
                    warn!("bloom V4 insert failed: {e}");
                }
            }
        }
        if let Some(ref bloom_arc) = self.bloom_v6
            && let Ok(mut bloom) = bloom_arc.lock()
        {
            for key in &v6_keys {
                if let Err(e) = bloom.insert(key, 0) {
                    warn!("bloom V6 insert failed: {e}");
                }
            }
        }

        info!(
            v4_count = v4_keys.len(),
            v6_count = v6_keys.len(),
            blocking,
            total = iocs.len(),
            "threat intel IOCs loaded into eBPF maps"
        );
        Ok(())
    }
}

/// Duplicate a map's descriptor before the typed wrapper takes ownership.
///
/// A failure is not fatal: the batched commands are an optimisation, and the
/// per-element path writes the same set.
fn duplicate_fd(map: &aya::maps::Map, name: &str) -> Option<OwnedFd> {
    let fd = map_batch::map_fd(map)?;
    match fd.try_clone_to_owned() {
        Ok(owned) => Some(owned),
        Err(e) => {
            warn!(map = name, "batched writes unavailable, no descriptor: {e}");
            None
        }
    }
}

impl ThreatIntelMapPort for ThreatIntelMapManager {
    fn load_all_iocs(&mut self, iocs: &[(Ioc, DomainMode)]) -> Result<(), DomainError> {
        self.load_iocs(iocs)
    }

    fn insert_ioc(
        &mut self,
        key: &ThreatIntelKey,
        value: &ThreatIntelValue,
    ) -> Result<(), DomainError> {
        feature_gates::publish(Feature::ThreatIocsV4, false);
        let mut map = self
            .iocs_map
            .lock()
            .map_err(|e| DomainError::EngineError(format!("V4 map lock poisoned: {e}")))?;
        map.insert(key, value, 0)
            .map_err(|e| DomainError::EngineError(format!("eBPF map insert failed: {e}")))?;
        Ok(())
    }

    fn remove_ioc(&mut self, key: &ThreatIntelKey) -> Result<(), DomainError> {
        let mut map = self
            .iocs_map
            .lock()
            .map_err(|e| DomainError::EngineError(format!("V4 map lock poisoned: {e}")))?;
        map.remove(key)
            .map_err(|e| DomainError::EngineError(format!("eBPF map remove failed: {e}")))?;
        Ok(())
    }

    fn clear_iocs(&mut self) -> Result<(), DomainError> {
        // Clear V4 map. A reload clears a set the size of the feed, so the
        // delete is batched the same way the write is.
        {
            let mut map = self
                .iocs_map
                .lock()
                .map_err(|e| DomainError::EngineError(format!("V4 map lock poisoned: {e}")))?;
            let keys: Vec<ThreatIntelKey> = map.keys().filter_map(Result::ok).collect();
            let mut batched = false;
            if let Some(fd) = self.iocs_fd.as_ref()
                && !keys.is_empty()
                && !BATCH_ABSENT.load(Ordering::Relaxed)
            {
                match map_batch::delete_batch("THREATINTEL_IOCS", fd.as_fd(), &keys, BATCH_CHUNK) {
                    Ok(removed) => {
                        debug!(removed, "IPv4 indicators cleared in batches");
                        batched = true;
                    }
                    Err(e) if e.is_unsupported() => {
                        BATCH_ABSENT.store(true, Ordering::Relaxed);
                        warn!("batched map deletes unavailable, clearing one by one: {e}");
                    }
                    Err(e) => return Err(DomainError::EngineError(e.to_string())),
                }
            }
            if !batched {
                for key in &keys {
                    map.remove(key).map_err(|e| {
                        DomainError::EngineError(format!("eBPF map clear failed: {e}"))
                    })?;
                }
            }
        }
        // Every key is gone. The bloom filter in front of the set cannot be
        // cleared a bit at a time, so without this the datapath would go on
        // probing a filter whose every answer is now a false positive.
        feature_gates::publish(Feature::ThreatIocsV4, true);

        // Clear V6 map (if present)
        if let Some(ref v6_arc) = self.iocs_v6_map {
            let mut v6_map = v6_arc
                .lock()
                .map_err(|e| DomainError::EngineError(format!("V6 map lock poisoned: {e}")))?;
            let v6_keys: Vec<ThreatIntelKeyV6> = v6_map.keys().filter_map(Result::ok).collect();
            let mut batched = false;
            if let Some(fd) = self.iocs_v6_fd.as_ref()
                && !v6_keys.is_empty()
                && !BATCH_ABSENT.load(Ordering::Relaxed)
            {
                match map_batch::delete_batch(
                    "THREATINTEL_IOCS_V6",
                    fd.as_fd(),
                    &v6_keys,
                    BATCH_CHUNK,
                ) {
                    Ok(removed) => {
                        debug!(removed, "IPv6 indicators cleared in batches");
                        batched = true;
                    }
                    Err(e) if e.is_unsupported() => {
                        BATCH_ABSENT.store(true, Ordering::Relaxed);
                        warn!("batched map deletes unavailable, clearing one by one: {e}");
                    }
                    Err(e) => return Err(DomainError::EngineError(e.to_string())),
                }
            }
            if !batched {
                for key in &v6_keys {
                    v6_map.remove(key).map_err(|e| {
                        DomainError::EngineError(format!("eBPF V6 map clear failed: {e}"))
                    })?;
                }
            }
            feature_gates::publish(Feature::ThreatIocsV6, true);
        }

        Ok(())
    }

    fn ioc_count(&self) -> Result<usize, DomainError> {
        let map = self
            .iocs_map
            .lock()
            .map_err(|e| DomainError::EngineError(format!("V4 map lock poisoned: {e}")))?;
        let v4_count = map.keys().filter_map(Result::ok).count();
        let v6_count: usize =
            self.iocs_v6_map
                .as_ref()
                .map_or(Ok::<usize, DomainError>(0), |v6_arc| {
                    let v6_map = v6_arc.lock().map_err(|e| {
                        DomainError::EngineError(format!("V6 map lock poisoned: {e}"))
                    })?;
                    Ok(v6_map.keys().filter_map(Result::ok).count())
                })?;
        Ok(v4_count + v6_count)
    }
}
