//! Load-time sizing of the kernel tables whose capacity is a configuration
//! choice rather than a property of the program.
//!
//! Every eBPF object declares its maps with a `max_entries` baked in at
//! compile time. For a rule array that is the right place: the number is the
//! ceiling the userspace side writes up to. For a table the kernel fills on
//! its own - IOCs loaded from feeds, rate-limit buckets, per-source `DDoS`
//! counters, the `DDoS` connection table - it is a sizing decision, and locked
//! memory is paid for every slot whether or not it is ever used: a million
//! IOC slots on an agent with no feed cost 168 MB, and a per-CPU table costs
//! its slots once per online CPU, so a figure that fits a 4-vCPU test VM is
//! sixteen times larger on a 64-core node.
//!
//! This module turns the relevant configuration fields into one plan, `map
//! name -> max_entries`, installed once per process before the first object
//! is loaded and read by the loader at every `BPF_MAP_CREATE`. Only the map
//! types the plan names and [`is_resizable`] admits are touched; arrays,
//! per-CPU arrays, program arrays and ring buffers keep what the object says.
//!
//! A pinned map keeps the size it was created with, which is why the plan is
//! applied at agent start, after the previous generation's pins are cleared,
//! and why a size changed by a hot reload is reported rather than applied.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use aya_obj::generated::bpf_map_type;
use infrastructure::config::AgentConfig;

/// The maps the plan sizes, with the configuration field each one follows.
///
/// Names are the ELF map names, which is what the loader sees and what
/// `bpftool map show` prints. A name absent from the object it is expected
/// in is not an error: the plan is a lookup the loader consults, not a
/// contract the object must honour.
pub const SIZED_MAPS: &[(&str, &str)] = &[
    ("THREATINTEL_IOCS", "threatintel.max_entries"),
    ("THREATINTEL_IOCS_V6", "threatintel.max_entries"),
    ("THREATINTEL_BLOOM_V4", "threatintel.max_entries"),
    ("THREATINTEL_BLOOM_V6", "threatintel.max_entries"),
    ("RL_BUCKETS", "ratelimit.max_buckets"),
    ("SYN_RATE_TRACKER", "ddos.max_tracked_sources"),
    ("ICMP_RATE_BUCKETS", "ddos.max_tracked_sources"),
    ("AMP_RATE_BUCKETS", "ddos.max_tracked_sources"),
    ("HALF_OPEN_COUNTERS", "ddos.max_tracked_sources"),
    ("FLOOD_COUNTERS", "ddos.max_tracked_sources"),
    ("CONN_TABLE", "ddos.connection_tracking.max_entries"),
];

/// The capacity every sized map is created with, derived from one
/// configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapSizing {
    entries: BTreeMap<&'static str, u32>,
}

impl MapSizing {
    /// Derive the plan from the configuration.
    #[must_use]
    pub fn from_config(config: &AgentConfig) -> Self {
        let threatintel = config.threatintel.capacity();
        let buckets = config.ratelimit.max_buckets;
        let sources = config.ddos.max_tracked_sources;
        let conn_table = config.ddos.connection_tracking.capacity();
        let entries = SIZED_MAPS
            .iter()
            .map(|(name, field)| {
                let n = match *field {
                    "threatintel.max_entries" => threatintel,
                    "ratelimit.max_buckets" => buckets,
                    "ddos.max_tracked_sources" => sources,
                    "ddos.connection_tracking.max_entries" => conn_table,
                    other => unreachable!("unmapped sizing field {other}"),
                };
                (*name, n)
            })
            .collect();
        Self { entries }
    }

    /// The capacity the plan holds for a map, by ELF name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<u32> {
        self.entries.get(name).copied()
    }

    /// Every sized map with its capacity, in name order.
    pub fn iter(&self) -> impl Iterator<Item = (&'static str, u32)> + '_ {
        self.entries.iter().map(|(n, v)| (*n, *v))
    }

    /// The plan as one line for the start-up log.
    #[must_use]
    pub fn describe(&self) -> String {
        self.iter()
            .map(|(n, v)| format!("{n}={v}"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Whether a map type takes its capacity from the plan.
///
/// Hash tables, their LRU and per-CPU variants, LPM tries and bloom filters
/// are the kernel-filled tables the plan is about. An array's `max_entries`
/// is an index space the userspace writer and the program agree on, and a
/// ring buffer's is its byte size, so neither may move.
#[must_use]
pub fn is_resizable(map_type: u32) -> bool {
    use bpf_map_type::{
        BPF_MAP_TYPE_BLOOM_FILTER, BPF_MAP_TYPE_HASH, BPF_MAP_TYPE_LPM_TRIE, BPF_MAP_TYPE_LRU_HASH,
        BPF_MAP_TYPE_LRU_PERCPU_HASH, BPF_MAP_TYPE_PERCPU_HASH,
    };
    [
        BPF_MAP_TYPE_HASH,
        BPF_MAP_TYPE_PERCPU_HASH,
        BPF_MAP_TYPE_LRU_HASH,
        BPF_MAP_TYPE_LRU_PERCPU_HASH,
        BPF_MAP_TYPE_LPM_TRIE,
        BPF_MAP_TYPE_BLOOM_FILTER,
    ]
    .iter()
    .any(|t| *t as u32 == map_type)
}

/// The capacity `plan` assigns to a map of this name and type, if any.
#[must_use]
pub fn planned_capacity(plan: Option<&MapSizing>, name: &str, map_type: u32) -> Option<u32> {
    if !is_resizable(map_type) {
        return None;
    }
    plan?.get(name)
}

static INSTALLED: OnceLock<MapSizing> = OnceLock::new();

/// Install the process-wide plan. The first call wins: a later plan that
/// differs is handed back so the caller can say it applies at the next start.
///
/// # Errors
///
/// Returns the plan already in force when one is installed and differs from
/// `plan`.
pub fn install(plan: &MapSizing) -> Result<(), &'static MapSizing> {
    if INSTALLED.set(plan.clone()).is_ok() {
        return Ok(());
    }
    let current = INSTALLED.get().expect("set failed, so a plan is installed");
    if *current == *plan {
        Ok(())
    } else {
        Err(current)
    }
}

/// The plan in force, once one is installed.
#[must_use]
pub fn installed() -> Option<&'static MapSizing> {
    INSTALLED.get()
}

/// The capacity the installed plan assigns to a map, by name and type.
#[must_use]
pub fn override_for(name: &str, map_type: u32) -> Option<u32> {
    planned_capacity(installed(), name, map_type)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> AgentConfig {
        AgentConfig::from_yaml("agent:\n  interfaces: [eth0]\n").expect("minimal config parses")
    }

    fn plan() -> MapSizing {
        MapSizing::from_config(&default_config())
    }

    #[test]
    fn every_sized_map_has_a_capacity_in_the_default_plan() {
        let p = plan();
        for (name, _) in SIZED_MAPS {
            assert!(p.get(name).is_some(), "{name} missing from plan");
        }
        assert_eq!(p.iter().count(), SIZED_MAPS.len());
    }

    #[test]
    fn the_default_plan_follows_the_configuration_defaults() {
        let p = plan();
        assert_eq!(p.get("THREATINTEL_IOCS"), Some(4_096));
        assert_eq!(p.get("THREATINTEL_BLOOM_V6"), Some(4_096));
        assert_eq!(p.get("RL_BUCKETS"), Some(65_536));
        assert_eq!(p.get("SYN_RATE_TRACKER"), Some(16_384));
        assert_eq!(p.get("FLOOD_COUNTERS"), Some(16_384));
        assert_eq!(p.get("CONN_TABLE"), Some(65_536));
    }

    #[test]
    fn the_plan_moves_with_the_configuration() {
        let mut config = default_config();
        config.ratelimit.max_buckets = 2_048;
        config.ddos.max_tracked_sources = 4_096;
        config.ddos.connection_tracking.max_entries = Some(8_192);
        config.threatintel.max_entries = Some(262_144);
        let p = MapSizing::from_config(&config);
        assert_eq!(p.get("RL_BUCKETS"), Some(2_048));
        assert_eq!(p.get("ICMP_RATE_BUCKETS"), Some(4_096));
        assert_eq!(p.get("CONN_TABLE"), Some(8_192));
        assert_eq!(p.get("THREATINTEL_IOCS_V6"), Some(262_144));
    }

    #[test]
    fn only_kernel_filled_table_types_are_resized() {
        use bpf_map_type::*;
        for t in [
            BPF_MAP_TYPE_HASH,
            BPF_MAP_TYPE_PERCPU_HASH,
            BPF_MAP_TYPE_LRU_HASH,
            BPF_MAP_TYPE_LRU_PERCPU_HASH,
            BPF_MAP_TYPE_LPM_TRIE,
            BPF_MAP_TYPE_BLOOM_FILTER,
        ] {
            assert!(is_resizable(t as u32), "{t:?}");
        }
        for t in [
            BPF_MAP_TYPE_ARRAY,
            BPF_MAP_TYPE_PERCPU_ARRAY,
            BPF_MAP_TYPE_PROG_ARRAY,
            BPF_MAP_TYPE_RINGBUF,
            BPF_MAP_TYPE_CPUMAP,
            BPF_MAP_TYPE_DEVMAP,
        ] {
            assert!(!is_resizable(t as u32), "{t:?}");
        }
    }

    #[test]
    fn a_planned_capacity_never_reaches_an_array_or_an_unplanned_map() {
        use bpf_map_type::*;
        let p = plan();
        assert_eq!(
            planned_capacity(Some(&p), "RL_BUCKETS", BPF_MAP_TYPE_LRU_PERCPU_HASH as u32),
            Some(65_536)
        );
        // Same name, array type: the plan does not apply.
        assert_eq!(
            planned_capacity(Some(&p), "RL_BUCKETS", BPF_MAP_TYPE_ARRAY as u32),
            None
        );
        // A hash table the plan does not name keeps the object's figure.
        assert_eq!(
            planned_capacity(Some(&p), "FW_HASH_5TUPLE", BPF_MAP_TYPE_HASH as u32),
            None
        );
        assert_eq!(
            planned_capacity(None, "RL_BUCKETS", BPF_MAP_TYPE_LRU_PERCPU_HASH as u32),
            None
        );
    }

    #[test]
    fn describe_is_one_line_in_name_order() {
        let d = plan().describe();
        assert!(d.starts_with("AMP_RATE_BUCKETS=16384 "));
        assert!(!d.contains('\n'));
    }
}
