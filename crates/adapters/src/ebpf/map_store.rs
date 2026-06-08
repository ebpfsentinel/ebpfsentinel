//! Abstraction over "where a map comes from" so the map managers work the same
//! whether the agent loaded eBPF via aya (capability mode) or via the raw BPF
//! token loader (token mode, no `CAP_BPF`).
//!
//! In capability mode the maps live inside an [`aya::Ebpf`]; in token mode they
//! are created by [`super::kfunc_loader::load_object_token`] and handed over as
//! [`aya::maps::Map`] values. Both expose the same `take_map` / `map` /
//! `map_mut` surface the managers use, so they consume a `&mut dyn MapStore`
//! and never need to know which path produced the map.

use std::collections::HashMap;

use aya::Ebpf;
use aya::maps::Map;

/// The three map-access operations the map managers and event readers need.
pub trait MapStore {
    /// Remove and return the named map (destructive — each map is taken once).
    fn take_map(&mut self, name: &str) -> Option<Map>;
    /// Borrow the named map.
    fn map(&self, name: &str) -> Option<&Map>;
    /// Borrow the named map mutably.
    fn map_mut(&mut self, name: &str) -> Option<&mut Map>;
}

impl MapStore for Ebpf {
    fn take_map(&mut self, name: &str) -> Option<Map> {
        Ebpf::take_map(self, name)
    }
    fn map(&self, name: &str) -> Option<&Map> {
        Ebpf::map(self, name)
    }
    fn map_mut(&mut self, name: &str) -> Option<&mut Map> {
        Ebpf::map_mut(self, name)
    }
}

/// Token-mode map collection: the maps the raw token loader created, keyed by
/// full ELF name. Owns the [`aya::maps::Map`] values so the typed-map
/// conversions (`Array::try_from`, …) in the managers work unchanged.
#[derive(Default)]
pub struct TokenMaps {
    maps: HashMap<String, Map>,
}

impl TokenMaps {
    /// Build a store from a name → map collection (from `load_object_token`).
    #[must_use]
    pub fn new(maps: HashMap<String, Map>) -> Self {
        Self { maps }
    }

    /// Merge another object's maps in. Shared maps (same pinned name) are
    /// reused, so the first insert wins and later identical entries are
    /// dropped — they wrap the same kernel object.
    pub fn extend(&mut self, maps: HashMap<String, Map>) {
        for (name, map) in maps {
            self.maps.entry(name).or_insert(map);
        }
    }
}

impl MapStore for TokenMaps {
    fn take_map(&mut self, name: &str) -> Option<Map> {
        self.maps.remove(name)
    }
    fn map(&self, name: &str) -> Option<&Map> {
        self.maps.get(name)
    }
    fn map_mut(&mut self, name: &str) -> Option<&mut Map> {
        self.maps.get_mut(name)
    }
}
