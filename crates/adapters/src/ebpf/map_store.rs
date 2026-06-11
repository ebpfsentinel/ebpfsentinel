//! Abstraction over the maps the raw BPF-token loader produced, so the map
//! managers and event readers consume a uniform `&mut dyn MapStore`.
//!
//! eBPF is loaded only via [`super::kfunc_loader::load_object_token`], which
//! creates the maps and hands them over as [`aya::maps::Map`] values (aya is
//! used purely as the typed-map wrapper, never to load). [`TokenMaps`] exposes
//! the `take_map` / `map` / `map_mut` surface the managers use.

use std::collections::HashMap;

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
