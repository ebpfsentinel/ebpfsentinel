use std::collections::{HashMap, HashSet};

use aya::maps::{HashMap as AyaHashMap, MapData, PerCpuHashMap, PerCpuValues};
use domain::common::error::DomainError;
use domain::qos::cgroup_shaping::CgroupShapingCounters;
use ebpf_common::qos::{
    MAX_QOS_CGROUP_LINKS, MAX_QOS_CGROUP_SHAPES, MAX_QOS_EDT_INTERFACES, QosCgroupCounters,
    QosCgroupShape, qos_ps_per_byte,
};
use ports::secondary::qos_cgroup_shaping_port::QosCgroupShapingMapPort;
use tracing::info;

use crate::ebpf::map_store::MapStore;

/// Holds the maps of a loaded tc-qos object that shape a workload's egress
/// by its cgroup: the cgroup behind each container link, the rate of each
/// shaped cgroup, the interfaces it acts on, the next departure time the datapath keeps
/// per cgroup and what it counted.
///
/// Owned rather than borrowed because workloads come and go long after the
/// load, and a borrowed map cannot outlive the loader.
pub struct QosCgroupShapingMaps {
    links: AyaHashMap<MapData, u32, u64>,
    shapes: AyaHashMap<MapData, u64, QosCgroupShape>,
    edt: AyaHashMap<MapData, u64, u64>,
    counters: PerCpuHashMap<MapData, u64, QosCgroupCounters>,
    interfaces: AyaHashMap<MapData, u32, u8>,
}

impl QosCgroupShapingMaps {
    /// Take the maps out of a loaded tc-qos object.
    ///
    /// # Errors
    ///
    /// Returns an error when a map is missing, which means the object
    /// predates cgroup shaping, or has another shape than the one declared
    /// here.
    pub fn new(ebpf: &mut dyn MapStore) -> anyhow::Result<Self> {
        let mut take = |name: &str| {
            ebpf.take_map(name)
                .ok_or_else(|| anyhow::anyhow!("map '{name}' not found"))
        };
        let links = AyaHashMap::try_from(take("QOS_CGROUP_LINKS")?)?;
        let shapes = AyaHashMap::try_from(take("QOS_CGROUP_SHAPES")?)?;
        let edt = AyaHashMap::try_from(take("QOS_CGROUP_EDT")?)?;
        let counters = PerCpuHashMap::try_from(take("QOS_CGROUP_COUNTERS")?)?;
        let interfaces = AyaHashMap::try_from(take("QOS_EDT_INTERFACES")?)?;
        info!("QoS cgroup shaping tables acquired");
        Ok(Self {
            links,
            shapes,
            edt,
            counters,
            interfaces,
        })
    }
}

impl QosCgroupShapingMapPort for QosCgroupShapingMaps {
    fn publish_links(&mut self, links: &[(u32, u64)]) -> Result<(), DomainError> {
        within(
            links.len(),
            MAX_QOS_CGROUP_LINKS,
            "container links",
            "the shaper's link table",
        )?;
        let wanted: HashMap<u32, u64> = links.iter().copied().collect();
        // Collected before the first removal because the iterator borrows the
        // map. A removal that fails is a key already gone, which is what the
        // removal was for.
        let present: Vec<u32> = self.links.keys().filter_map(Result::ok).collect();
        for ifindex in stale(present, |k| wanted.contains_key(k)) {
            let _ = self.links.remove(&ifindex);
        }
        for (ifindex, cgroup_id) in &wanted {
            self.links.insert(ifindex, cgroup_id, 0).map_err(|e| {
                DomainError::EngineError(format!("QOS_CGROUP_LINKS write failed: {e}"))
            })?;
        }
        Ok(())
    }

    fn publish_shapes(&mut self, shapes: &[(u64, u64, u64)]) -> Result<(), DomainError> {
        within(
            shapes.len(),
            MAX_QOS_CGROUP_SHAPES,
            "shaped cgroups",
            "the shape table",
        )?;
        let wanted = shape_table(shapes);
        let present: Vec<u64> = self.shapes.keys().filter_map(Result::ok).collect();
        for cgroup_id in stale(present, |k| wanted.contains_key(k)) {
            let _ = self.shapes.remove(&cgroup_id);
            // The departure clock and the counters of a cgroup no longer
            // shaped go with it, so an id the kernel hands to the next
            // container starts from nothing.
            let _ = self.edt.remove(&cgroup_id);
            let _ = self.counters.remove(&cgroup_id);
        }
        for (cgroup_id, shape) in &wanted {
            self.shapes.insert(cgroup_id, shape, 0).map_err(|e| {
                DomainError::EngineError(format!("QOS_CGROUP_SHAPES write failed: {e}"))
            })?;
        }
        Ok(())
    }

    fn publish_interfaces(&mut self, ifindexes: &[u32]) -> Result<(), DomainError> {
        within(
            ifindexes.len(),
            MAX_QOS_EDT_INTERFACES,
            "interfaces",
            "the shaper's interface table",
        )?;
        let wanted: HashSet<u32> = ifindexes.iter().copied().collect();
        let present: Vec<u32> = self.interfaces.keys().filter_map(Result::ok).collect();
        for ifindex in stale(present, |k| wanted.contains(k)) {
            let _ = self.interfaces.remove(&ifindex);
        }
        for ifindex in &wanted {
            self.interfaces.insert(ifindex, &1u8, 0).map_err(|e| {
                DomainError::EngineError(format!("QOS_EDT_INTERFACES write failed: {e}"))
            })?;
        }
        Ok(())
    }

    fn read_counters(&self) -> Result<Vec<(u64, CgroupShapingCounters)>, DomainError> {
        let mut out = Vec::new();
        for entry in &self.counters {
            let (cgroup_id, values): (u64, PerCpuValues<QosCgroupCounters>) =
                entry.map_err(|e| {
                    DomainError::EngineError(format!("QOS_CGROUP_COUNTERS read failed: {e}"))
                })?;
            out.push((cgroup_id, sum_per_cpu(values.iter())));
        }
        Ok(out)
    }
}

/// Refuse a set larger than the kernel table it is written into, before a
/// single entry is written, so a table is never left half replaced.
fn within(len: usize, max: u32, what: &str, table: &str) -> Result<(), DomainError> {
    if len > max as usize {
        return Err(DomainError::InvalidConfig(format!(
            "{len} {what}, more than the {max} {table} holds"
        )));
    }
    Ok(())
}

/// The keys present in a table that the wanted set no longer names.
fn stale<K>(present: Vec<K>, wanted: impl Fn(&K) -> bool) -> Vec<K> {
    present.into_iter().filter(|k| !wanted(k)).collect()
}

/// The shape each cgroup is written with, keyed by cgroup; a cgroup named
/// twice keeps the last rate given for it.
fn shape_table(shapes: &[(u64, u64, u64)]) -> HashMap<u64, QosCgroupShape> {
    shapes
        .iter()
        .map(|&(cgroup_id, rate_bps, horizon_ns)| {
            (
                cgroup_id,
                QosCgroupShape {
                    ps_per_byte: qos_ps_per_byte(rate_bps),
                    horizon_ns,
                },
            )
        })
        .collect()
}

/// One cgroup's counts summed over every CPU, saturating rather than
/// wrapping.
fn sum_per_cpu<'a>(values: impl Iterator<Item = &'a QosCgroupCounters>) -> CgroupShapingCounters {
    values.fold(CgroupShapingCounters::default(), |acc, c| {
        CgroupShapingCounters {
            bytes: acc.bytes.saturating_add(c.bytes),
            packets: acc.packets.saturating_add(c.packets),
            dropped_horizon: acc.dropped_horizon.saturating_add(c.dropped_horizon),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ebpf::map_store::TokenMaps;

    #[test]
    fn an_object_without_the_shaping_tables_is_refused_by_name() {
        let mut maps = TokenMaps::default();
        let err = QosCgroupShapingMaps::new(&mut maps)
            .err()
            .expect("an empty object has no shaping table");
        assert!(err.to_string().contains("QOS_CGROUP_LINKS"), "{err}");
    }

    #[test]
    fn a_set_at_the_table_size_is_accepted_and_one_more_is_refused() {
        assert!(within(16, 16, "links", "the table").is_ok());
        assert!(within(0, 16, "links", "the table").is_ok());
        let err = within(17, 16, "container links", "the shaper's link table")
            .expect_err("one entry over the table size");
        let DomainError::InvalidConfig(message) = err else {
            panic!("a set too large is a configuration error, got {err:?}");
        };
        assert_eq!(
            message,
            "17 container links, more than the 16 the shaper's link table holds"
        );
    }

    #[test]
    fn the_shipped_tables_bound_what_each_publish_accepts() {
        assert!(within(MAX_QOS_CGROUP_LINKS as usize, MAX_QOS_CGROUP_LINKS, "", "").is_ok());
        assert!(
            within(
                MAX_QOS_CGROUP_LINKS as usize + 1,
                MAX_QOS_CGROUP_LINKS,
                "",
                ""
            )
            .is_err()
        );
        assert!(
            within(
                MAX_QOS_CGROUP_SHAPES as usize + 1,
                MAX_QOS_CGROUP_SHAPES,
                "",
                ""
            )
            .is_err()
        );
        assert!(
            within(
                MAX_QOS_EDT_INTERFACES as usize + 1,
                MAX_QOS_EDT_INTERFACES,
                "",
                ""
            )
            .is_err()
        );
    }

    #[test]
    fn only_the_keys_no_longer_wanted_are_removed() {
        let wanted: HashSet<u32> = [2, 3].into_iter().collect();
        let mut gone = stale(vec![1, 2, 3, 4], |k| wanted.contains(k));
        gone.sort_unstable();
        assert_eq!(gone, vec![1, 4]);
        assert!(stale(vec![2, 3], |k| wanted.contains(k)).is_empty());
        assert_eq!(stale(vec![9], |_: &u32| false), vec![9]);
    }

    #[test]
    fn each_cgroup_is_written_with_its_rate_and_horizon() {
        let table = shape_table(&[(7, 8_000_000, 2_000_000_000), (9, 1_000_000_000, 5)]);
        assert_eq!(table.len(), 2);
        let seven = table.get(&7).expect("cgroup 7 is shaped");
        assert_eq!(seven.ps_per_byte, qos_ps_per_byte(8_000_000));
        assert_eq!(seven.horizon_ns, 2_000_000_000);
        let nine = table.get(&9).expect("cgroup 9 is shaped");
        assert_eq!(nine.ps_per_byte, qos_ps_per_byte(1_000_000_000));
        assert_eq!(nine.horizon_ns, 5);
        // A faster rate leaves fewer picoseconds between two bytes.
        assert!(nine.ps_per_byte < seven.ps_per_byte);
    }

    #[test]
    fn a_cgroup_named_twice_keeps_the_last_rate() {
        let table = shape_table(&[(7, 8_000_000, 1), (7, 16_000_000, 2)]);
        assert_eq!(table.len(), 1);
        let shape = table.get(&7).expect("cgroup 7 is shaped");
        assert_eq!(shape.ps_per_byte, qos_ps_per_byte(16_000_000));
        assert_eq!(shape.horizon_ns, 2);
    }

    #[test]
    fn counts_are_summed_over_every_cpu_and_saturate() {
        let per_cpu = [
            QosCgroupCounters {
                bytes: 100,
                packets: 2,
                dropped_horizon: 0,
            },
            QosCgroupCounters {
                bytes: 50,
                packets: 1,
                dropped_horizon: 3,
            },
        ];
        assert_eq!(
            sum_per_cpu(per_cpu.iter()),
            CgroupShapingCounters {
                bytes: 150,
                packets: 3,
                dropped_horizon: 3,
            }
        );
        let full = [
            QosCgroupCounters {
                bytes: u64::MAX,
                packets: 1,
                dropped_horizon: 0,
            },
            QosCgroupCounters {
                bytes: 1,
                packets: 1,
                dropped_horizon: 0,
            },
        ];
        assert_eq!(sum_per_cpu(full.iter()).bytes, u64::MAX);
        assert_eq!(
            sum_per_cpu(std::iter::empty()),
            CgroupShapingCounters::default()
        );
    }
}
