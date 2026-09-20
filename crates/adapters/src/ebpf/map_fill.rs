//! How full the eBPF maps an operator can actually fill are.
//!
//! A map that refuses an insert drops the rule, the flow or the prefix on the
//! floor, and every surface above it goes on reporting a healthy datapath. That
//! is only true of maps the kernel refuses: an LRU map is full by design and
//! evicts rather than refusing, so its occupancy says nothing anybody can act
//! on and it is left out of the measurement entirely.
//!
//! The registry is process-global for the same reason
//! [`super::attach_inspect`] is: the loaders that hold the map handles are
//! created deep in the startup path and the metrics loop that reads them is
//! spawned beside the others, and threading a handle between the two would put
//! a datapath detail through the whole agent.
//!
//! Nothing here reports a zero it did not measure. A map that could not be
//! walked is absent, which the surfaces above read as never measured rather
//! than as empty.

use std::collections::HashMap;
use std::hash::BuildHasher;
use std::os::fd::{AsFd, OwnedFd};
use std::sync::{Mutex, OnceLock};

use aya::maps::{MapData, MapType};

use super::kfunc_loader::count_map_entries;

/// One map's occupancy at the moment it was read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapFill {
    /// The map's full ELF name, which is what every other surface calls it.
    pub name: String,
    /// Entries the walk found.
    pub used: u64,
    /// Entries the map was created with room for.
    pub capacity: u32,
}

impl MapFill {
    /// Occupancy in parts per thousand, saturating at 1000.
    ///
    /// Per thousand rather than per cent because the maps worth watching hold
    /// tens of thousands of entries, and a whole percentage point there is
    /// hundreds of rules.
    #[must_use]
    pub fn permille(&self) -> u16 {
        if self.capacity == 0 {
            return 0;
        }
        let permille = self.used.saturating_mul(1000) / u64::from(self.capacity);
        u16::try_from(permille.min(1000)).unwrap_or(1000)
    }
}

/// A registered map: its own handle, plus the two figures the walk needs.
struct Probe {
    data: MapData,
    key_size: u32,
    capacity: u32,
}

fn probes() -> &'static Mutex<HashMap<String, Probe>> {
    static PROBES: OnceLock<Mutex<HashMap<String, Probe>>> = OnceLock::new();
    PROBES.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Whether running out of room in a map of this type is a fault worth counting.
///
/// A hash map and an LPM trie refuse the insert, so a full one is a rule that
/// never reached the kernel. An LRU map of either kind evicts instead, so it
/// sits at its ceiling in normal service and reporting that as a fault would
/// bury the two that mean something. Arrays cannot fill at all.
fn fills_rather_than_evicts(map_type: MapType) -> bool {
    matches!(
        map_type,
        MapType::Hash | MapType::PerCpuHash | MapType::LpmTrie
    )
}

/// Register every map in a loaded object that can be measured.
///
/// Takes its own handle on each map rather than borrowing the loader's, because
/// the loader hands its maps to the managers and the measurement outlives that.
/// A name already registered is kept: the shareable maps are one kernel object
/// reached through several objects' pins, and counting one of them twice would
/// say the datapath holds twice what it does.
pub fn register<S: BuildHasher>(maps: &HashMap<String, OwnedFd, S>) {
    let Ok(mut guard) = probes().lock() else {
        return;
    };
    for (name, fd) in maps {
        if guard.contains_key(name) {
            continue;
        }
        let Ok(duplicate) = fd.try_clone() else {
            continue;
        };
        let Ok(data) = MapData::from_fd(duplicate) else {
            continue;
        };
        let Ok(info) = data.info() else {
            continue;
        };
        let Ok(map_type) = info.map_type() else {
            continue;
        };
        if !fills_rather_than_evicts(map_type) || info.max_entries() == 0 {
            continue;
        }
        let probe = Probe {
            key_size: info.key_size(),
            capacity: info.max_entries(),
            data,
        };
        guard.insert(name.clone(), probe);
    }
}

/// Walk every registered map and report what it holds.
///
/// A map whose walk did not complete is left out rather than reported at zero.
/// An empty answer therefore means nothing could be measured, which is the
/// answer a build with no datapath owes.
#[must_use]
pub fn measure() -> Vec<MapFill> {
    let Ok(guard) = probes().lock() else {
        return Vec::new();
    };
    let mut fills: Vec<MapFill> = guard
        .iter()
        .filter_map(|(name, probe)| {
            let used = count_map_entries(probe.data.fd().as_fd(), probe.key_size, probe.capacity)?;
            Some(MapFill {
                name: name.clone(),
                used,
                capacity: probe.capacity,
            })
        })
        .collect();
    fills.sort_by(|a, b| a.name.cmp(&b.name));
    fills
}

/// Forget every registered map.
///
/// Called when the whole eBPF state is torn down, so an HA deactivate does not
/// leave the next activate measuring maps that no longer exist.
pub fn clear_all() {
    if let Ok(mut guard) = probes().lock() {
        guard.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::{MapFill, MapType, fills_rather_than_evicts, measure};

    fn fill(used: u64, capacity: u32) -> MapFill {
        MapFill {
            name: "SOME_MAP".to_string(),
            used,
            capacity,
        }
    }

    #[test]
    fn occupancy_is_reported_per_thousand() {
        assert_eq!(fill(0, 1000).permille(), 0);
        assert_eq!(fill(1, 10_240).permille(), 0);
        assert_eq!(fill(512, 1024).permille(), 500);
        assert_eq!(fill(10_240, 10_240).permille(), 1000);
    }

    #[test]
    fn a_map_holding_more_than_it_was_sized_for_still_reports_full() {
        // The walk is bounded by the map's own ceiling, so this cannot happen
        // from a walk; it can from a capacity read that disagrees, and a
        // percentage above the top would read as a different fault.
        assert_eq!(fill(20_000, 10_240).permille(), 1000);
    }

    #[test]
    fn a_map_with_no_room_at_all_is_not_reported_as_full() {
        // Dividing by the capacity is the whole computation, so the map that
        // was never sized has to answer before it.
        assert_eq!(fill(0, 0).permille(), 0);
    }

    #[test]
    fn only_the_maps_that_refuse_an_insert_are_measured() {
        assert!(fills_rather_than_evicts(MapType::Hash));
        assert!(fills_rather_than_evicts(MapType::PerCpuHash));
        assert!(fills_rather_than_evicts(MapType::LpmTrie));
        // An LRU map sits at its ceiling in normal service.
        assert!(!fills_rather_than_evicts(MapType::LruHash));
        assert!(!fills_rather_than_evicts(MapType::LruPerCpuHash));
        // An array is allocated full and cannot refuse anything.
        assert!(!fills_rather_than_evicts(MapType::Array));
        assert!(!fills_rather_than_evicts(MapType::PerCpuArray));
        assert!(!fills_rather_than_evicts(MapType::RingBuf));
    }

    #[test]
    fn a_process_that_loaded_no_datapath_measures_nothing_rather_than_zero() {
        // Absence is what the surfaces above read as never measured. A zero
        // here would be a map somebody could fill sitting empty, which is a
        // different and much better piece of news than no eBPF at all.
        assert!(measure().is_empty());
    }
}
