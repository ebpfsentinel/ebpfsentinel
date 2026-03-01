use std::collections::HashMap;
use std::sync::Mutex;

use aya::Ebpf;
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
#[allow(dead_code)]
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

        // Remove old entries for this source
        remove_source_entries_inner(&mut inner, source);

        // Insert new entries
        let mut tracked = Vec::new();

        for entry in src_v4 {
            insert_v4(&mut inner.lpm_src_v4, entry, "LPM src V4")?;
            tracked.push(TrackedEntry::V4 {
                prefix_len: entry.prefix_len,
                addr: entry.addr,
                action: entry.action,
                direction: Direction::Src,
            });
        }
        for entry in dst_v4 {
            insert_v4(&mut inner.lpm_dst_v4, entry, "LPM dst V4")?;
            tracked.push(TrackedEntry::V4 {
                prefix_len: entry.prefix_len,
                addr: entry.addr,
                action: entry.action,
                direction: Direction::Dst,
            });
        }
        for entry in src_v6 {
            insert_v6(&mut inner.lpm_src_v6, entry, "LPM src V6")?;
            tracked.push(TrackedEntry::V6 {
                prefix_len: entry.prefix_len,
                addr: entry.addr,
                action: entry.action,
                direction: Direction::Src,
            });
        }
        for entry in dst_v6 {
            insert_v6(&mut inner.lpm_dst_v6, entry, "LPM dst V6")?;
            tracked.push(TrackedEntry::V6 {
                prefix_len: entry.prefix_len,
                addr: entry.addr,
                action: entry.action,
                direction: Direction::Dst,
            });
        }

        inner.entries_by_source.insert(source.to_string(), tracked);

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

        for entry in src_v4 {
            let key = Key::new(entry.prefix_len, entry.addr);
            let _ = inner.lpm_src_v4.remove(&key);
        }
        for entry in src_v6 {
            let key = Key::new(entry.prefix_len, entry.addr);
            let _ = inner.lpm_src_v6.remove(&key);
        }

        // Remove from tracking
        if let Some(tracked) = inner.entries_by_source.get_mut(source) {
            tracked.retain(|t| {
                !matches_any_v4(t, src_v4, Direction::Src)
                    && !matches_any_v6(t, src_v6, Direction::Src)
            });
        }

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

        info!(source, "LPM coordinator removed all entries for source");
        Ok(())
    }
}

/// Remove all tracked entries for a source from the kernel maps.
fn remove_source_entries_inner(inner: &mut Inner, source: &str) {
    if let Some(entries) = inner.entries_by_source.remove(source) {
        for entry in &entries {
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
    map.insert(&key, value, 0)
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
    map.insert(&key, value, 0)
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
