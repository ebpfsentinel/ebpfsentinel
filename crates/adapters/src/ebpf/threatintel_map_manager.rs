//! The kernel copy of the threat-intelligence set.
//!
//! `tc-threatintel` declares two slots, A and B, each an address table and a
//! range trie per family, and an array naming the slot it reads. A reload
//! writes the slot the datapath is not reading, flips the selector, then
//! empties the slot it left: a packet is matched against the set before the
//! reload or the set after it, never against a set half written. A set larger
//! than the tables is refused before anything is written, and the set in
//! force stays; nothing is ever evicted to make room.
//!
//! Addresses the DNS blocklist resolves are injected beside the feeds through
//! [`crate::ebpf::EbpfMapWriteAdapter`], which shares these tables: they are
//! kept apart from the feed set so a feed reload carries them over and
//! removing one restores whatever a feed says about the same address.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv6Addr};
use std::os::fd::{AsFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::ebpf::feature_gates::{self, Feature};
use crate::ebpf::map_batch::{self, MAX_CHUNK};
use crate::ebpf::map_store::MapStore;
use aya::maps::lpm_trie::Key;
use aya::maps::{Array, HashMap, LpmTrie, Map, MapData};
use domain::common::entity::DomainMode;
use domain::common::error::DomainError;
use domain::threatintel::entity::Ioc;
use ebpf_common::threatintel::{
    THREATINTEL_ACTION_ALERT, THREATINTEL_ACTION_DROP, THREATINTEL_SLOT_A, THREATINTEL_SLOT_B,
    ThreatIntelKey, ThreatIntelKeyV6, ThreatIntelValue,
};
use ports::secondary::threatintel_map_port::ThreatIntelMapPort;
use tracing::{debug, info, warn};

/// Set once a batched command comes back as absent, so a kernel without them
/// pays one refused syscall per process rather than one per reload.
static BATCH_ABSENT: AtomicBool = AtomicBool::new(false);

/// How long a reload waits after flipping the selector before it empties the
/// slot it left. A packet that read the selector just before the flip is
/// still looking that slot up; a classifier runs for microseconds, so this is
/// three orders of magnitude of margin, paid once per reload.
const DRAIN: Duration = Duration::from_millis(20);

/// One indicator set, as the tables hold it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IndicatorSet {
    /// IPv4 address (host order) to value.
    pub v4: BTreeMap<u32, ThreatIntelValue>,
    /// IPv6 address to value.
    pub v6: BTreeMap<[u32; 4], ThreatIntelValue>,
    /// IPv4 range, as (network in network byte order, prefix length).
    pub nets_v4: BTreeMap<([u8; 4], u8), ThreatIntelValue>,
    /// IPv6 range, as (network in network byte order, prefix length).
    pub nets_v6: BTreeMap<([u8; 16], u8), ThreatIntelValue>,
}

impl IndicatorSet {
    /// Build the set the tables hold for these indicators.
    ///
    /// Each indicator carries the mode it is enforced in, because a feed may
    /// override the global one: `Block` writes a drop, `Alert` an alert. Two
    /// indicators on one key keep the stronger action, the first one on a tie.
    #[must_use]
    pub fn from_iocs(iocs: &[(Ioc, DomainMode)]) -> Self {
        let mut set = Self::default();
        for (idx, (ioc, mode)) in iocs.iter().enumerate() {
            let value = ThreatIntelValue {
                action: if *mode == DomainMode::Block {
                    THREATINTEL_ACTION_DROP
                } else {
                    THREATINTEL_ACTION_ALERT
                },
                #[allow(clippy::cast_possible_truncation)]
                feed_id: (idx % 256) as u8, // intentional: wraps index into u8
                confidence: ioc.confidence,
                threat_type: ioc.threat_type.to_u8(),
            };
            match (ioc.ip, ioc.prefix_len) {
                (IpAddr::V4(v4), None) => keep_stronger(&mut set.v4, u32::from(v4), value),
                (IpAddr::V6(v6), None) => keep_stronger(&mut set.v6, v6_key(&v6), value),
                (IpAddr::V4(v4), Some(len)) => {
                    keep_stronger(&mut set.nets_v4, (v4.octets(), len), value);
                }
                (IpAddr::V6(v6), Some(len)) => {
                    keep_stronger(&mut set.nets_v6, (v6.octets(), len), value);
                }
            }
        }
        set
    }

    /// Entries in the largest of the four tables, which is what a capacity
    /// shared by all four has to hold.
    #[must_use]
    pub fn largest_table(&self) -> usize {
        self.v4
            .len()
            .max(self.v6.len())
            .max(self.nets_v4.len())
            .max(self.nets_v6.len())
    }

    /// Indicators in the set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len() + self.nets_v4.len() + self.nets_v6.len()
    }

    /// Whether the set holds no indicator.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// This set with the injected addresses laid over it, the stronger
    /// action winning where both name one address.
    #[must_use]
    pub fn with_injected(&self, injected: &BTreeMap<IpAddr, ThreatIntelValue>) -> Self {
        let mut merged = self.clone();
        for (ip, value) in injected {
            match ip {
                IpAddr::V4(v4) => keep_stronger(&mut merged.v4, u32::from(*v4), *value),
                IpAddr::V6(v6) => keep_stronger(&mut merged.v6, v6_key(v6), *value),
            }
        }
        merged
    }
}

fn keep_stronger<K: Ord>(map: &mut BTreeMap<K, ThreatIntelValue>, key: K, value: ThreatIntelValue) {
    match map.get(&key) {
        Some(held) if held.action >= value.action => {}
        _ => {
            map.insert(key, value);
        }
    }
}

fn v6_key(v6: &Ipv6Addr) -> [u32; 4] {
    let o = v6.octets();
    [
        u32::from_be_bytes([o[0], o[1], o[2], o[3]]),
        u32::from_be_bytes([o[4], o[5], o[6], o[7]]),
        u32::from_be_bytes([o[8], o[9], o[10], o[11]]),
        u32::from_be_bytes([o[12], o[13], o[14], o[15]]),
    ]
}

/// Refuse a set the tables cannot hold, before a byte of it is written.
///
/// # Errors
///
/// `EngineError` naming the table that overflows and the capacity to raise.
pub fn check_capacity(set: &IndicatorSet, capacity: u32) -> Result<(), DomainError> {
    let capacity = capacity as usize;
    for (table, len) in [
        ("IPv4 address", set.v4.len()),
        ("IPv6 address", set.v6.len()),
        ("IPv4 range", set.nets_v4.len()),
        ("IPv6 range", set.nets_v6.len()),
    ] {
        if len > capacity {
            return Err(DomainError::EngineError(format!(
                "threat intel set refused: {len} {table} indicators, the kernel table holds \
                 {capacity}; raise threatintel.max_entries, the set in force is kept"
            )));
        }
    }
    Ok(())
}

/// The four tables of one slot.
struct Slot {
    name: char,
    v4: HashMap<MapData, ThreatIntelKey, ThreatIntelValue>,
    v6: HashMap<MapData, ThreatIntelKeyV6, ThreatIntelValue>,
    nets_v4: LpmTrie<MapData, [u8; 4], ThreatIntelValue>,
    nets_v6: LpmTrie<MapData, [u8; 16], ThreatIntelValue>,
    /// Descriptors kept beside the typed maps, because the batched commands
    /// are raw `bpf(2)` calls and aya exposes no descriptor through its typed
    /// wrapper. They are duplicates: closing one closes nothing.
    v4_fd: Option<OwnedFd>,
    v6_fd: Option<OwnedFd>,
}

impl Slot {
    fn take(ebpf: &mut dyn MapStore, name: char) -> Result<(Self, u32), anyhow::Error> {
        let v4 = take(ebpf, &format!("THREATINTEL_IOCS_{name}"))?;
        let v6 = take(ebpf, &format!("THREATINTEL_IOCS_V6_{name}"))?;
        let nets_v4 = take(ebpf, &format!("THREATINTEL_NETS_{name}"))?;
        let nets_v6 = take(ebpf, &format!("THREATINTEL_NETS_V6_{name}"))?;
        let capacity = [&v4, &v6, &nets_v4, &nets_v6]
            .into_iter()
            .filter_map(|m| max_entries(m))
            .min()
            .ok_or_else(|| anyhow::anyhow!("threat intel slot {name}: no table size readable"))?;
        let v4_fd = duplicate_fd(&v4, "THREATINTEL_IOCS");
        let v6_fd = duplicate_fd(&v6, "THREATINTEL_IOCS_V6");
        let slot = Self {
            name,
            v4: HashMap::try_from(v4)?,
            v6: HashMap::try_from(v6)?,
            nets_v4: LpmTrie::try_from(nets_v4)?,
            nets_v6: LpmTrie::try_from(nets_v6)?,
            v4_fd,
            v6_fd,
        };
        Ok((slot, capacity))
    }

    /// Write `set` into this slot, which the datapath is not reading.
    fn write(&mut self, set: &IndicatorSet) -> Result<(), DomainError> {
        let (keys, values): (Vec<_>, Vec<_>) = set
            .v4
            .iter()
            .map(|(ip, v)| (ThreatIntelKey { ip: *ip }, *v))
            .unzip();
        write_hash(&mut self.v4, self.v4_fd.as_ref(), "IPv4", &keys, &values)?;

        let (keys, values): (Vec<_>, Vec<_>) = set
            .v6
            .iter()
            .map(|(ip, v)| (ThreatIntelKeyV6 { ip: *ip }, *v))
            .unzip();
        write_hash(&mut self.v6, self.v6_fd.as_ref(), "IPv6", &keys, &values)?;

        for ((net, len), value) in &set.nets_v4 {
            self.nets_v4
                .insert(&Key::new(u32::from(*len), *net), value, 0)
                .map_err(|e| engine(format!("IPv4 range insert failed: {e}")))?;
        }
        for ((net, len), value) in &set.nets_v6 {
            self.nets_v6
                .insert(&Key::new(u32::from(*len), *net), value, 0)
                .map_err(|e| engine(format!("IPv6 range insert failed: {e}")))?;
        }
        Ok(())
    }

    /// Remove every entry of the slot, whatever wrote it.
    fn clear(&mut self) -> Result<(), DomainError> {
        let keys: Vec<ThreatIntelKey> = self.v4.keys().filter_map(Result::ok).collect();
        clear_hash(&mut self.v4, self.v4_fd.as_ref(), "IPv4", &keys)?;
        let keys: Vec<ThreatIntelKeyV6> = self.v6.keys().filter_map(Result::ok).collect();
        clear_hash(&mut self.v6, self.v6_fd.as_ref(), "IPv6", &keys)?;
        let keys: Vec<Key<[u8; 4]>> = self.nets_v4.keys().filter_map(Result::ok).collect();
        for key in &keys {
            self.nets_v4
                .remove(key)
                .map_err(|e| engine(format!("IPv4 range clear failed: {e}")))?;
        }
        let keys: Vec<Key<[u8; 16]>> = self.nets_v6.keys().filter_map(Result::ok).collect();
        for key in &keys {
            self.nets_v6
                .remove(key)
                .map_err(|e| engine(format!("IPv6 range clear failed: {e}")))?;
        }
        Ok(())
    }
}

fn engine(msg: String) -> DomainError {
    DomainError::EngineError(msg)
}

fn take(ebpf: &mut dyn MapStore, name: &str) -> Result<Map, anyhow::Error> {
    ebpf.take_map(name)
        .ok_or_else(|| anyhow::anyhow!("map '{name}' not found in eBPF object"))
}

fn max_entries(map: &Map) -> Option<u32> {
    match map {
        Map::HashMap(data) | Map::LpmTrie(data) => data.info().ok().map(|i| i.max_entries()),
        _ => None,
    }
}

/// Write `keys[i] -> values[i]` into an address table.
///
/// One batched call per [`MAX_CHUNK`] elements, which turns a feed of a
/// million indicators from a million syscalls into a few hundred. A kernel
/// with no batched update says so on the first chunk and the write falls back
/// to one element at a time, which is slow and correct.
fn write_hash<K: aya::Pod>(
    map: &mut HashMap<MapData, K, ThreatIntelValue>,
    fd: Option<&OwnedFd>,
    family: &str,
    keys: &[K],
    values: &[ThreatIntelValue],
) -> Result<(), DomainError> {
    if keys.is_empty() {
        return Ok(());
    }
    if let Some(fd) = fd
        && !BATCH_ABSENT.load(Ordering::Relaxed)
    {
        match map_batch::update_batch("THREATINTEL_IOCS", fd.as_fd(), keys, values, MAX_CHUNK) {
            Ok(written) => {
                debug!(written, family, "indicators written in batches");
                return Ok(());
            }
            Err(e) if e.is_unsupported() => {
                BATCH_ABSENT.store(true, Ordering::Relaxed);
                warn!("batched map updates unavailable, writing one by one: {e}");
            }
            Err(e) => return Err(engine(e.to_string())),
        }
    }
    for (key, value) in keys.iter().zip(values) {
        map.insert(key, value, 0)
            .map_err(|e| engine(format!("{family} indicator insert failed: {e}")))?;
    }
    Ok(())
}

fn clear_hash<K: aya::Pod>(
    map: &mut HashMap<MapData, K, ThreatIntelValue>,
    fd: Option<&OwnedFd>,
    family: &str,
    keys: &[K],
) -> Result<(), DomainError> {
    if keys.is_empty() {
        return Ok(());
    }
    if let Some(fd) = fd
        && !BATCH_ABSENT.load(Ordering::Relaxed)
    {
        match map_batch::delete_batch("THREATINTEL_IOCS", fd.as_fd(), keys, MAX_CHUNK) {
            Ok(removed) => {
                debug!(removed, family, "indicators cleared in batches");
                return Ok(());
            }
            Err(e) if e.is_unsupported() => {
                BATCH_ABSENT.store(true, Ordering::Relaxed);
                warn!("batched map deletes unavailable, clearing one by one: {e}");
            }
            Err(e) => return Err(engine(e.to_string())),
        }
    }
    for key in keys {
        map.remove(key)
            .map_err(|e| engine(format!("{family} indicator clear failed: {e}")))?;
    }
    Ok(())
}

/// Duplicate a map's descriptor before the typed wrapper takes ownership.
///
/// A failure is not fatal: the batched commands are an optimisation, and the
/// per-element path writes the same set.
fn duplicate_fd(map: &Map, name: &str) -> Option<OwnedFd> {
    let fd = map_batch::map_fd(map)?;
    match fd.try_clone_to_owned() {
        Ok(owned) => Some(owned),
        Err(e) => {
            warn!(map = name, "batched writes unavailable, no descriptor: {e}");
            None
        }
    }
}

/// Both slots, the selector, and the sets they were written from.
pub struct ThreatIntelTables {
    slots: [Slot; 2],
    selector: Array<MapData, u32>,
    /// Index into `slots` of the one the datapath reads.
    active: usize,
    /// Entries each table holds, read off the loaded maps.
    capacity: u32,
    /// The feed set last written.
    feeds: IndicatorSet,
    /// Addresses the DNS blocklist resolved, laid over the feed set.
    injected: BTreeMap<IpAddr, ThreatIntelValue>,
}

/// Shared handle to the tables, held by the manager and the DNS write adapter.
pub type SharedThreatIntelTables = Arc<Mutex<ThreatIntelTables>>;

impl ThreatIntelTables {
    /// Entries each table holds.
    #[must_use]
    pub fn capacity(&self) -> u32 {
        self.capacity
    }

    /// Indicators in force, feeds and injected addresses together.
    #[must_use]
    pub fn len(&self) -> usize {
        self.feeds.with_injected(&self.injected).len()
    }

    /// Whether no indicator is in force.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Replace the feed set: write the idle slot, flip, empty the old one.
    fn reload(&mut self, feeds: IndicatorSet) -> Result<(), DomainError> {
        let set = feeds.with_injected(&self.injected);
        check_capacity(&set, self.capacity)?;

        let next = 1 - self.active;
        // The idle slot is emptied after every flip; a clear that failed
        // then is finished here, so the slot holds the new set and nothing
        // else.
        let idle = &mut self.slots[next];
        let written = idle.clear().and_then(|()| idle.write(&set));
        if let Err(e) = written {
            if let Err(clear) = self.slots[next].clear() {
                warn!("threat intel idle slot not emptied after a failed write: {clear}");
            }
            return Err(e);
        }

        // The datapath reads the selector before the gates, so a gate is
        // opened over a table the new slot fills before the flip and closed
        // over one it leaves empty only after the old slot is gone.
        publish_gates(&set, false);
        let slot_id = if next == 0 {
            THREATINTEL_SLOT_A
        } else {
            THREATINTEL_SLOT_B
        };
        if let Err(e) = self.selector.set(0, &slot_id, 0) {
            if let Err(clear) = self.slots[next].clear() {
                warn!("threat intel idle slot not emptied after a failed flip: {clear}");
            }
            return Err(engine(format!(
                "threat intel slot selector not written: {e}"
            )));
        }
        let left = self.active;
        self.active = next;
        self.feeds = feeds;

        std::thread::sleep(DRAIN);
        if let Err(e) = self.slots[left].clear() {
            // The datapath no longer reads it; the next reload empties it
            // before writing.
            warn!(
                slot = %self.slots[left].name,
                "threat intel slot left behind not emptied: {e}"
            );
        }
        publish_gates(&set, true);

        info!(
            slot = %self.slots[next].name,
            v4 = set.v4.len(),
            v6 = set.v6.len(),
            nets_v4 = set.nets_v4.len(),
            nets_v6 = set.nets_v6.len(),
            capacity = self.capacity,
            "threat intel indicators in force"
        );
        Ok(())
    }

    /// Lay an address the DNS blocklist resolved over the slot in force.
    ///
    /// # Errors
    ///
    /// `EngineError` when the table is full or the write fails; the address
    /// is then not retained either.
    pub fn inject(&mut self, ip: IpAddr, value: ThreatIntelValue) -> Result<(), DomainError> {
        let mut injected = self.injected.clone();
        injected.insert(ip, value);
        let set = self.feeds.with_injected(&injected);
        check_capacity(&set, self.capacity)?;
        let slot = &mut self.slots[self.active];
        match ip {
            IpAddr::V4(v4) => {
                let ip = u32::from(v4);
                if let Some(v) = set.v4.get(&ip) {
                    feature_gates::publish(Feature::ThreatIocsV4, false);
                    slot.v4
                        .insert(&ThreatIntelKey { ip }, v, 0)
                        .map_err(|e| engine(format!("IPv4 indicator insert failed: {e}")))?;
                }
            }
            IpAddr::V6(v6) => {
                let ip = v6_key(&v6);
                if let Some(v) = set.v6.get(&ip) {
                    feature_gates::publish(Feature::ThreatIocsV6, false);
                    slot.v6
                        .insert(&ThreatIntelKeyV6 { ip }, v, 0)
                        .map_err(|e| engine(format!("IPv6 indicator insert failed: {e}")))?;
                }
            }
        }
        self.injected = injected;
        Ok(())
    }

    /// Take back an injected address: the slot in force then holds what the
    /// feeds say about it, or nothing.
    ///
    /// # Errors
    ///
    /// `EngineError` when the table write fails.
    pub fn withdraw(&mut self, ip: IpAddr) -> Result<(), DomainError> {
        if self.injected.remove(&ip).is_none() {
            return Ok(());
        }
        let set = self.feeds.with_injected(&self.injected);
        let slot = &mut self.slots[self.active];
        match ip {
            IpAddr::V4(v4) => {
                let key = ThreatIntelKey { ip: u32::from(v4) };
                match set.v4.get(&key.ip) {
                    Some(v) => slot.v4.insert(&key, v, 0),
                    None => slot.v4.remove(&key),
                }
                .map_err(|e| engine(format!("IPv4 indicator withdraw failed: {e}")))?;
                if set.v4.is_empty() {
                    feature_gates::publish(Feature::ThreatIocsV4, true);
                }
            }
            IpAddr::V6(v6) => {
                let key = ThreatIntelKeyV6 { ip: v6_key(&v6) };
                match set.v6.get(&key.ip) {
                    Some(v) => slot.v6.insert(&key, v, 0),
                    None => slot.v6.remove(&key),
                }
                .map_err(|e| engine(format!("IPv6 indicator withdraw failed: {e}")))?;
                if set.v6.is_empty() {
                    feature_gates::publish(Feature::ThreatIocsV6, true);
                }
            }
        }
        Ok(())
    }
}

/// Publish the gate of every table `set` leaves empty as `empty` (closing),
/// or of every table it fills as open when `empty` is false.
fn publish_gates(set: &IndicatorSet, empty: bool) {
    for (feature, len) in [
        (Feature::ThreatIocsV4, set.v4.len()),
        (Feature::ThreatIocsV6, set.v6.len()),
        (Feature::ThreatNetsV4, set.nets_v4.len()),
        (Feature::ThreatNetsV6, set.nets_v6.len()),
    ] {
        if empty && len == 0 {
            feature_gates::publish(feature, true);
        } else if !empty && len > 0 {
            feature_gates::publish(feature, false);
        }
    }
}

/// Owns the threat-intelligence tables of a loaded `tc-threatintel`.
pub struct ThreatIntelMapManager {
    tables: SharedThreatIntelTables,
}

impl ThreatIntelMapManager {
    /// Take both slots and the selector from the loaded object, point the
    /// datapath at slot A and empty both.
    ///
    /// # Errors
    ///
    /// When a table or the selector is missing from the object, or a table's
    /// size cannot be read.
    pub fn new(ebpf: &mut dyn MapStore) -> Result<Self, anyhow::Error> {
        let (a, cap_a) = Slot::take(ebpf, 'A')?;
        let (b, cap_b) = Slot::take(ebpf, 'B')?;
        let mut selector: Array<MapData, u32> = Array::try_from(take(ebpf, "THREATINTEL_SLOT")?)?;
        selector.set(0, &THREATINTEL_SLOT_A, 0)?;

        let mut tables = ThreatIntelTables {
            slots: [a, b],
            selector,
            active: 0,
            capacity: cap_a.min(cap_b),
            feeds: IndicatorSet::default(),
            injected: BTreeMap::new(),
        };
        for slot in &mut tables.slots {
            slot.clear().map_err(|e| anyhow::anyhow!("{e}"))?;
        }
        publish_gates(&IndicatorSet::default(), true);

        info!(
            capacity = tables.capacity,
            "threat intel tables acquired, slot A in force"
        );
        Ok(Self {
            tables: Arc::new(Mutex::new(tables)),
        })
    }

    /// The tables, for the DNS blocklist's write adapter.
    #[must_use]
    pub fn shared_tables(&self) -> SharedThreatIntelTables {
        Arc::clone(&self.tables)
    }
}

impl ThreatIntelMapPort for ThreatIntelMapManager {
    fn load_all_iocs(&mut self, iocs: &[(Ioc, DomainMode)]) -> Result<(), DomainError> {
        let set = IndicatorSet::from_iocs(iocs);
        self.tables
            .lock()
            .map_err(|e| engine(format!("threat intel tables lock poisoned: {e}")))?
            .reload(set)
    }

    fn ioc_count(&self) -> Result<usize, DomainError> {
        Ok(self
            .tables
            .lock()
            .map_err(|e| engine(format!("threat intel tables lock poisoned: {e}")))?
            .len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::threatintel::entity::ThreatType;

    fn ioc(target: &str) -> Ioc {
        let (ip, prefix_len) = domain::threatintel::entity::parse_target(target).unwrap();
        Ioc {
            ip,
            prefix_len,
            feed_id: "f".to_string(),
            confidence: 90,
            threat_type: ThreatType::Malware,
            last_seen: 0,
            source_feed: "f".to_string(),
        }
    }

    #[test]
    fn addresses_and_ranges_go_to_their_own_tables() {
        let set = IndicatorSet::from_iocs(&[
            (ioc("192.0.2.1"), DomainMode::Block),
            (ioc("198.51.100.0/24"), DomainMode::Block),
            (ioc("2001:db8::1"), DomainMode::Alert),
            (ioc("2001:db8:1::/48"), DomainMode::Alert),
        ]);
        assert_eq!(set.v4.len(), 1);
        assert_eq!(set.v6.len(), 1);
        assert_eq!(set.nets_v4.keys().next(), Some(&([198, 51, 100, 0], 24u8)));
        assert_eq!(set.nets_v6.len(), 1);
        assert_eq!(set.len(), 4);
        assert_eq!(set.largest_table(), 1);
        let v6 = set.v6.values().next().unwrap();
        assert_eq!(v6.action, THREATINTEL_ACTION_ALERT);
    }

    #[test]
    fn a_drop_wins_over_an_alert_on_one_key() {
        let set = IndicatorSet::from_iocs(&[
            (ioc("192.0.2.1"), DomainMode::Alert),
            (ioc("192.0.2.1"), DomainMode::Block),
        ]);
        assert_eq!(
            set.v4.values().next().unwrap().action,
            THREATINTEL_ACTION_DROP
        );
    }

    #[test]
    fn an_injected_address_is_laid_over_the_feeds_and_the_stronger_wins() {
        let feeds = IndicatorSet::from_iocs(&[(ioc("192.0.2.1"), DomainMode::Alert)]);
        let drop = ThreatIntelValue {
            action: THREATINTEL_ACTION_DROP,
            feed_id: 0,
            confidence: 50,
            threat_type: 0,
        };
        let mut injected = BTreeMap::new();
        injected.insert("192.0.2.1".parse().unwrap(), drop);
        injected.insert("192.0.2.2".parse().unwrap(), drop);
        let merged = feeds.with_injected(&injected);
        assert_eq!(merged.v4.len(), 2);
        assert!(
            merged
                .v4
                .values()
                .all(|v| v.action == THREATINTEL_ACTION_DROP)
        );
        // The feed set itself is untouched, so withdrawing restores it.
        assert_eq!(
            feeds.v4.values().next().unwrap().action,
            THREATINTEL_ACTION_ALERT
        );
    }

    #[test]
    fn a_set_larger_than_a_table_is_refused_before_any_write() {
        let set = IndicatorSet::from_iocs(&[
            (ioc("198.51.100.0/24"), DomainMode::Block),
            (ioc("203.0.113.0/24"), DomainMode::Block),
            (ioc("192.0.2.1"), DomainMode::Block),
        ]);
        assert!(check_capacity(&set, 2).is_ok());
        let err = check_capacity(&set, 1).unwrap_err().to_string();
        assert!(err.contains("IPv4 range"), "{err}");
        assert!(err.contains("threatintel.max_entries"), "{err}");
    }
}
