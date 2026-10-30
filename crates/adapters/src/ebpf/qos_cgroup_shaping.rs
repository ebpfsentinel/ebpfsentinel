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
        if links.len() > MAX_QOS_CGROUP_LINKS as usize {
            return Err(DomainError::InvalidConfig(format!(
                "{} container links, more than the {MAX_QOS_CGROUP_LINKS} the shaper's link table holds",
                links.len()
            )));
        }
        let wanted: HashMap<u32, u64> = links.iter().copied().collect();
        // Collected before the first removal because the iterator borrows the
        // map. A removal that fails is a key already gone, which is what the
        // removal was for.
        let present: Vec<u32> = self.links.keys().filter_map(Result::ok).collect();
        for ifindex in present {
            if !wanted.contains_key(&ifindex) {
                let _ = self.links.remove(&ifindex);
            }
        }
        for (ifindex, cgroup_id) in &wanted {
            self.links.insert(ifindex, cgroup_id, 0).map_err(|e| {
                DomainError::EngineError(format!("QOS_CGROUP_LINKS write failed: {e}"))
            })?;
        }
        Ok(())
    }

    fn publish_shapes(&mut self, shapes: &[(u64, u64, u64)]) -> Result<(), DomainError> {
        if shapes.len() > MAX_QOS_CGROUP_SHAPES as usize {
            return Err(DomainError::InvalidConfig(format!(
                "{} shaped cgroups, more than the {MAX_QOS_CGROUP_SHAPES} the shape table holds",
                shapes.len()
            )));
        }
        let wanted: HashMap<u64, QosCgroupShape> = shapes
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
            .collect();
        let present: Vec<u64> = self.shapes.keys().filter_map(Result::ok).collect();
        for cgroup_id in present {
            if !wanted.contains_key(&cgroup_id) {
                let _ = self.shapes.remove(&cgroup_id);
                // The departure clock and the counters of a cgroup no longer
                // shaped go with it, so an id the kernel hands to the next
                // container starts from nothing.
                let _ = self.edt.remove(&cgroup_id);
                let _ = self.counters.remove(&cgroup_id);
            }
        }
        for (cgroup_id, shape) in &wanted {
            self.shapes.insert(cgroup_id, shape, 0).map_err(|e| {
                DomainError::EngineError(format!("QOS_CGROUP_SHAPES write failed: {e}"))
            })?;
        }
        Ok(())
    }

    fn publish_interfaces(&mut self, ifindexes: &[u32]) -> Result<(), DomainError> {
        if ifindexes.len() > MAX_QOS_EDT_INTERFACES as usize {
            return Err(DomainError::InvalidConfig(format!(
                "{} interfaces, more than the {MAX_QOS_EDT_INTERFACES} the shaper's interface table holds",
                ifindexes.len()
            )));
        }
        let wanted: HashSet<u32> = ifindexes.iter().copied().collect();
        let present: Vec<u32> = self.interfaces.keys().filter_map(Result::ok).collect();
        for ifindex in present {
            if !wanted.contains(&ifindex) {
                let _ = self.interfaces.remove(&ifindex);
            }
        }
        for ifindex in &wanted {
            self.interfaces.insert(ifindex, 1u8, 0).map_err(|e| {
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
            let sum = values
                .iter()
                .fold(CgroupShapingCounters::default(), |acc, c| {
                    CgroupShapingCounters {
                        bytes: acc.bytes.saturating_add(c.bytes),
                        packets: acc.packets.saturating_add(c.packets),
                        dropped_horizon: acc.dropped_horizon.saturating_add(c.dropped_horizon),
                    }
                });
            out.push((cgroup_id, sum));
        }
        Ok(out)
    }
}
