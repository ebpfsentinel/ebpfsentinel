use std::collections::HashMap;
use std::sync::Mutex;

use crate::ebpf::feature_gates::{self, Feature};
use crate::ebpf::map_store::MapStore;
use aya::maps::MapData;
use aya::maps::lpm_trie::{Key, LpmTrie};
use domain::common::error::DomainError;
use ebpf_common::firewall::{FirewallLpmEntryV4, FirewallLpmEntryV6, LpmValue};
use ports::secondary::lpm_coordinator_port::LpmCoordinatorPort;
use tracing::info;

/// Direction of an LPM entry (source vs destination).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    Src,
    Dst,
}

/// A tracked LPM entry with its provenance metadata.
#[derive(Debug, Clone)]
enum TrackedEntry {
    V4 {
        prefix_len: u32,
        addr: [u8; 4],
        action: u8,
        direction: Direction,
    },
    V6 {
        prefix_len: u32,
        addr: [u8; 16],
        action: u8,
        direction: Direction,
    },
}

/// Internal state protected by a mutex.
struct Inner {
    lpm_src_v4: LpmTrie<MapData, [u8; 4], LpmValue>,
    lpm_dst_v4: LpmTrie<MapData, [u8; 4], LpmValue>,
    lpm_src_v6: LpmTrie<MapData, [u8; 16], LpmValue>,
    lpm_dst_v6: LpmTrie<MapData, [u8; 16], LpmValue>,
    /// Entries tracked by source tag.
    entries_by_source: HashMap<String, Vec<TrackedEntry>>,
}

/// Coordinated multi-source manager for the 4 firewall LPM Trie maps.
///
/// Tracks the provenance (source tag) of every entry so that reloading
/// one source does not erase entries belonging to another.
///
/// All public methods take `&self` and use an internal `Mutex` for the
/// tracking state. The underlying `LpmTrie` operations are individually
/// thread-safe (kernel BPF map locking).
pub struct LpmCoordinator {
    inner: Mutex<Inner>,
}

impl LpmCoordinator {
    /// Create a new `LpmCoordinator` by taking ownership of the 4 LPM Trie
    /// maps from the loaded xdp-firewall eBPF program.
    ///
    /// Must be created **before** `FirewallMapManager` since `take_map()` is
    /// destructive.
    pub fn new(ebpf: &mut dyn MapStore) -> Result<Self, anyhow::Error> {
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

        // The four tries were just created by this load, so nothing is in them
        // and the datapath can reach the same verdict without reading them.
        feature_gates::publish(Feature::LpmV4, true);
        feature_gates::publish(Feature::LpmV6, true);

        info!("LPM Coordinator acquired 4 LPM Trie maps from xdp-firewall");
        Ok(Self {
            inner: Mutex::new(Inner {
                lpm_src_v4,
                lpm_dst_v4,
                lpm_src_v6,
                lpm_dst_v6,
                entries_by_source: HashMap::new(),
            }),
        })
    }
}

impl TrackedEntry {
    fn v4(entry: &FirewallLpmEntryV4, direction: Direction) -> Self {
        Self::V4 {
            prefix_len: entry.prefix_len,
            addr: entry.addr,
            action: entry.action,
            direction,
        }
    }

    fn v6(entry: &FirewallLpmEntryV6, direction: Direction) -> Self {
        Self::V6 {
            prefix_len: entry.prefix_len,
            addr: entry.addr,
            action: entry.action,
            direction,
        }
    }

    /// Whether both name the same key of the same trie, whatever the verdict.
    fn same_slot(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::V4 {
                    prefix_len: p1,
                    addr: a1,
                    direction: d1,
                    ..
                },
                Self::V4 {
                    prefix_len: p2,
                    addr: a2,
                    direction: d2,
                    ..
                },
            ) => p1 == p2 && a1 == a2 && d1 == d2,
            (
                Self::V6 {
                    prefix_len: p1,
                    addr: a1,
                    direction: d1,
                    ..
                },
                Self::V6 {
                    prefix_len: p2,
                    addr: a2,
                    direction: d2,
                    ..
                },
            ) => p1 == p2 && a1 == a2 && d1 == d2,
            _ => false,
        }
    }
}

impl LpmCoordinatorPort for LpmCoordinator {
    fn replace_source_entries(
        &self,
        source: &str,
        src_v4: &[FirewallLpmEntryV4],
        dst_v4: &[FirewallLpmEntryV4],
        src_v6: &[FirewallLpmEntryV6],
        dst_v6: &[FirewallLpmEntryV6],
    ) -> Result<(), DomainError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|e| DomainError::EngineError(format!("LPM coordinator lock poisoned: {e}")))?;

        open_lookups();

        // The new entries go in before the old ones come out, so a prefix
        // present in both is never absent from the trie in between.
        let tracked: Vec<TrackedEntry> = src_v4
            .iter()
            .map(|e| TrackedEntry::v4(e, Direction::Src))
            .chain(dst_v4.iter().map(|e| TrackedEntry::v4(e, Direction::Dst)))
            .chain(src_v6.iter().map(|e| TrackedEntry::v6(e, Direction::Src)))
            .chain(dst_v6.iter().map(|e| TrackedEntry::v6(e, Direction::Dst)))
            .collect();
        let mut first_error = None;
        for entry in &tracked {
            if let Err(e) = write(&mut inner, entry) {
                first_error.get_or_insert(e);
            }
        }
        let old = inner
            .entries_by_source
            .insert(source.to_string(), tracked)
            .unwrap_or_default();
        for entry in old {
            let kept = inner
                .entries_by_source
                .get(source)
                .is_some_and(|new| new.iter().any(|n| n.same_slot(&entry)));
            if !kept {
                release(&mut inner, &entry);
            }
        }
        republish(&inner);
        if let Some(e) = first_error {
            return Err(e);
        }

        info!(
            source,
            src_v4 = src_v4.len(),
            dst_v4 = dst_v4.len(),
            src_v6 = src_v6.len(),
            dst_v6 = dst_v6.len(),
            "LPM coordinator replaced entries for source"
        );
        Ok(())
    }

    fn insert_entries(
        &self,
        source: &str,
        src_v4: &[FirewallLpmEntryV4],
        src_v6: &[FirewallLpmEntryV6],
    ) -> Result<(), DomainError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|e| DomainError::EngineError(format!("LPM coordinator lock poisoned: {e}")))?;

        open_lookups();

        let inner = &mut *inner;
        for entry in src_v4 {
            insert_v4(&mut inner.lpm_src_v4, entry, "LPM src V4")?;
        }
        for entry in src_v6 {
            insert_v6(&mut inner.lpm_src_v6, entry, "LPM src V6")?;
        }

        let tracked = inner
            .entries_by_source
            .entry(source.to_string())
            .or_default();
        for entry in src_v4 {
            tracked.push(TrackedEntry::V4 {
                prefix_len: entry.prefix_len,
                addr: entry.addr,
                action: entry.action,
                direction: Direction::Src,
            });
        }
        for entry in src_v6 {
            tracked.push(TrackedEntry::V6 {
                prefix_len: entry.prefix_len,
                addr: entry.addr,
                action: entry.action,
                direction: Direction::Src,
            });
        }

        republish(inner);

        info!(
            source,
            src_v4 = src_v4.len(),
            src_v6 = src_v6.len(),
            "LPM coordinator inserted entries for source"
        );
        Ok(())
    }

    fn remove_entries(
        &self,
        source: &str,
        src_v4: &[FirewallLpmEntryV4],
        src_v6: &[FirewallLpmEntryV6],
    ) -> Result<(), DomainError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|e| DomainError::EngineError(format!("LPM coordinator lock poisoned: {e}")))?;

        // Out of this source's books first, so a prefix another source still
        // holds is written back with that source's verdict.
        if let Some(tracked) = inner.entries_by_source.get_mut(source) {
            tracked.retain(|t| {
                !matches_any_v4(t, src_v4, Direction::Src)
                    && !matches_any_v6(t, src_v6, Direction::Src)
            });
        }
        let gone: Vec<TrackedEntry> = src_v4
            .iter()
            .map(|e| TrackedEntry::v4(e, Direction::Src))
            .chain(src_v6.iter().map(|e| TrackedEntry::v6(e, Direction::Src)))
            .collect();
        for entry in &gone {
            release(&mut inner, entry);
        }

        republish(&inner);

        info!(
            source,
            src_v4 = src_v4.len(),
            src_v6 = src_v6.len(),
            "LPM coordinator removed specific entries for source"
        );
        Ok(())
    }

    fn remove_all_for_source(&self, source: &str) -> Result<(), DomainError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|e| DomainError::EngineError(format!("LPM coordinator lock poisoned: {e}")))?;

        remove_source_entries_inner(&mut inner, source);
        republish(&inner);

        info!(source, "LPM coordinator removed all entries for source");
        Ok(())
    }
}

/// Tell the datapath both families are worth looking up.
///
/// Called before a mutation rather than after it, so a write that fails
/// half-way leaves the datapath reading tries it did not have to read, which
/// is slower and never wrong.
fn open_lookups() {
    feature_gates::publish(Feature::LpmV4, false);
    feature_gates::publish(Feature::LpmV6, false);
}

/// Recompute, from what every source is tracking, whether either family holds
/// a prefix, and tell the datapath.
fn republish(inner: &Inner) {
    let mut v4 = false;
    let mut v6 = false;
    for entries in inner.entries_by_source.values() {
        for entry in entries {
            match entry {
                TrackedEntry::V4 { .. } => v4 = true,
                TrackedEntry::V6 { .. } => v6 = true,
            }
        }
    }
    feature_gates::publish(Feature::LpmV4, !v4);
    feature_gates::publish(Feature::LpmV6, !v6);
}

/// Remove all tracked entries for a source from the kernel maps.
fn remove_source_entries_inner(inner: &mut Inner, source: &str) {
    if let Some(entries) = inner.entries_by_source.remove(source) {
        for entry in &entries {
            release(inner, entry);
        }
    }
}

/// Take a prefix no longer held by the source that let it go out of its
/// trie, unless another source still holds the same prefix in the same
/// direction: that source's verdict is written back instead, so one source
/// letting go never lifts another's block.
fn release(inner: &mut Inner, entry: &TrackedEntry) {
    let holder = inner
        .entries_by_source
        .values()
        .flatten()
        .find(|t| t.same_slot(entry))
        .cloned();
    if let Some(holder) = holder {
        if let Err(e) = write(inner, &holder) {
            tracing::warn!("LPM coordinator could not restore a shared prefix: {e}");
        }
        return;
    }
    match entry {
        TrackedEntry::V4 {
            prefix_len,
            addr,
            direction,
            ..
        } => {
            let key = Key::new(*prefix_len, *addr);
            let map = match direction {
                Direction::Src => &mut inner.lpm_src_v4,
                Direction::Dst => &mut inner.lpm_dst_v4,
            };
            let _ = map.remove(&key);
        }
        TrackedEntry::V6 {
            prefix_len,
            addr,
            direction,
            ..
        } => {
            let key = Key::new(*prefix_len, *addr);
            let map = match direction {
                Direction::Src => &mut inner.lpm_src_v6,
                Direction::Dst => &mut inner.lpm_dst_v6,
            };
            let _ = map.remove(&key);
        }
    }
}

/// Put one tracked entry in its trie.
fn write(inner: &mut Inner, entry: &TrackedEntry) -> Result<(), DomainError> {
    match *entry {
        TrackedEntry::V4 {
            prefix_len,
            addr,
            action,
            direction,
        } => {
            let e = FirewallLpmEntryV4 {
                prefix_len,
                addr,
                action,
            };
            match direction {
                Direction::Src => insert_v4(&mut inner.lpm_src_v4, &e, "LPM src V4"),
                Direction::Dst => insert_v4(&mut inner.lpm_dst_v4, &e, "LPM dst V4"),
            }
        }
        TrackedEntry::V6 {
            prefix_len,
            addr,
            action,
            direction,
        } => {
            let e = FirewallLpmEntryV6 {
                prefix_len,
                addr,
                action,
            };
            match direction {
                Direction::Src => insert_v6(&mut inner.lpm_src_v6, &e, "LPM src V6"),
                Direction::Dst => insert_v6(&mut inner.lpm_dst_v6, &e, "LPM dst V6"),
            }
        }
    }
}

fn insert_v4(
    map: &mut LpmTrie<MapData, [u8; 4], LpmValue>,
    entry: &FirewallLpmEntryV4,
    label: &str,
) -> Result<(), DomainError> {
    let key = Key::new(entry.prefix_len, entry.addr);
    let value = LpmValue {
        action: entry.action,
        _padding: [0; 3],
    };
    map.insert(&key, &value, 0)
        .map_err(|e| DomainError::EngineError(format!("{label} insert failed: {e}")))
}

fn insert_v6(
    map: &mut LpmTrie<MapData, [u8; 16], LpmValue>,
    entry: &FirewallLpmEntryV6,
    label: &str,
) -> Result<(), DomainError> {
    let key = Key::new(entry.prefix_len, entry.addr);
    let value = LpmValue {
        action: entry.action,
        _padding: [0; 3],
    };
    map.insert(&key, &value, 0)
        .map_err(|e| DomainError::EngineError(format!("{label} insert failed: {e}")))
}

/// Check if a tracked entry matches any of the given V4 entries in the specified direction.
fn matches_any_v4(tracked: &TrackedEntry, entries: &[FirewallLpmEntryV4], dir: Direction) -> bool {
    match tracked {
        TrackedEntry::V4 {
            prefix_len,
            addr,
            direction,
            ..
        } if *direction == dir => entries
            .iter()
            .any(|e| e.prefix_len == *prefix_len && e.addr == *addr),
        _ => false,
    }
}

/// Check if a tracked entry matches any of the given V6 entries in the specified direction.
fn matches_any_v6(tracked: &TrackedEntry, entries: &[FirewallLpmEntryV6], dir: Direction) -> bool {
    match tracked {
        TrackedEntry::V6 {
            prefix_len,
            addr,
            direction,
            ..
        } if *direction == dir => entries
            .iter()
            .any(|e| e.prefix_len == *prefix_len && e.addr == *addr),
        _ => false,
    }
}
