//! What the firewall datapath is allowed to stop looking up.
//!
//! `xdp-firewall` carries a table per optional feature - the two LPM tries per
//! address family, the two exact-match fast paths, the zone map, the three
//! tenant maps, the interface-group map, the overload set - and reads them on
//! every packet. A deployment using none of them pays five to eight hash or
//! LPM misses per packet for tables that are empty. Userspace is the only
//! thing that knows they are empty, so it publishes a bitmask into the
//! program's `FW_EMPTY_FEATURES` array and the datapath skips what has
//! nothing in it.
//!
//! Two properties make the shortcut safe:
//!
//! - The sense is inverted. A bit *set* means empty, so a map that was never
//!   written, or an object loaded by a userspace that never heard of it, reads
//!   zero and every lookup still happens. A stale mask can only be slower,
//!   never wrong.
//! - Every writer of a gated map publishes on every mutation, and publishes
//!   "not empty" before a mutation it has not yet checked, so a failed or
//!   half-applied write leaves the datapath doing the work rather than
//!   skipping it.
//!
//! The mask is a process-global rather than a handle threaded through the
//! seven managers that own those maps: `take_map` is destructive, so one map
//! has exactly one owner, and the gate bits come from seven different owners
//! constructed at three different points in startup. `map_sizing` holds its
//! plan the same way and for the same reason.

use aya::maps::{Array, MapData};
use ebpf_common::firewall::{
    FW_EMPTY_AMP_PORTS, FW_EMPTY_HASH_5TUPLE, FW_EMPTY_HASH_PORT, FW_EMPTY_IDS_PATTERNS,
    FW_EMPTY_IDS_SRC_PATTERNS, FW_EMPTY_IFACE_GROUPS, FW_EMPTY_L7_PORTS, FW_EMPTY_LPM_V4,
    FW_EMPTY_LPM_V6, FW_EMPTY_QOS_CLASSIFIERS, FW_EMPTY_RL_TIERS_V4, FW_EMPTY_RL_TIERS_V6,
    FW_EMPTY_SRC_LIMITS, FW_EMPTY_TENANTS, FW_EMPTY_THREAT_IOCS_V4, FW_EMPTY_THREAT_IOCS_V6,
    FW_EMPTY_ZONES,
};
use std::sync::{Mutex, OnceLock};
use tracing::{debug, info};

/// One gated table, or one of the three sources that feed a single gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Feature {
    /// `FW_LPM_SRC_V4` and `FW_LPM_DST_V4`, which are filled together.
    LpmV4,
    /// `FW_LPM_SRC_V6` and `FW_LPM_DST_V6`.
    LpmV6,
    /// `FW_HASH_5TUPLE`.
    Hash5Tuple,
    /// `FW_HASH_PORT`.
    HashPort,
    /// `ZONE_MAP`.
    Zones,
    /// `TENANT_VLAN_MAP`.
    TenantVlan,
    /// `TENANT_IFINDEX_MAP`.
    TenantIfindex,
    /// `TENANT_SUBNET_V4` and `TENANT_SUBNET_V6`.
    TenantSubnet,
    /// `TENANT_CGROUP_MAP`, the last resort of the resolution order and the
    /// only one of the four the firewall itself cannot reach.
    TenantCgroup,
    /// `INTERFACE_GROUPS`.
    InterfaceGroups,
    /// The per-source connection ceilings in `CT_CONFIG`, which are the only
    /// thing that ever writes the overload set the datapath probes.
    SourceLimits,
    /// `RL_LPM_SRC_V4`, the rate limiter's country-tier trie.
    RateLimitTiersV4,
    /// `RL_LPM_SRC_V6`.
    RateLimitTiersV6,
    /// `AMP_PROTECT_CONFIG`, the armed UDP amplification vector ports.
    AmpProtectPorts,
    /// `IDS_PATTERNS`, the classifier's destination-port rules.
    IdsPatterns,
    /// `IDS_SRC_PATTERNS`, its reply-leg rules.
    IdsSrcPatterns,
    /// `L7_PORTS`, the service ports whose payload is captured.
    L7Ports,
    /// `THREATINTEL_IOCS` and the v4 bloom filter in front of it.
    ThreatIocsV4,
    /// `THREATINTEL_IOCS_V6` and the v6 bloom filter in front of it.
    ThreatIocsV6,
    /// `QOS_CLASSIFIERS`, the shaper's rules.
    QosClassifiers,
}

const FEATURE_COUNT: usize = 20;

impl Feature {
    const fn slot(self) -> usize {
        match self {
            Feature::LpmV4 => 0,
            Feature::LpmV6 => 1,
            Feature::Hash5Tuple => 2,
            Feature::HashPort => 3,
            Feature::Zones => 4,
            Feature::TenantVlan => 5,
            Feature::TenantIfindex => 6,
            Feature::TenantSubnet => 7,
            Feature::InterfaceGroups => 8,
            Feature::SourceLimits => 9,
            Feature::RateLimitTiersV4 => 10,
            Feature::RateLimitTiersV6 => 11,
            Feature::AmpProtectPorts => 12,
            Feature::TenantCgroup => 13,
            Feature::IdsPatterns => 14,
            Feature::IdsSrcPatterns => 15,
            Feature::L7Ports => 16,
            Feature::ThreatIocsV4 => 17,
            Feature::ThreatIocsV6 => 18,
            Feature::QosClassifiers => 19,
        }
    }
}

/// Which features are known to be empty.
///
/// Every slot starts `false`, which is "not known to be empty" and leaves the
/// datapath doing the lookup. Only a writer that has just looked at its own
/// table may set one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EmptyFeatures {
    empty: [bool; FEATURE_COUNT],
}

impl EmptyFeatures {
    /// Record whether the tables behind `feature` hold no entry.
    pub fn set(&mut self, feature: Feature, empty: bool) {
        self.empty[feature.slot()] = empty;
    }

    /// Whether `feature` is currently known to be empty.
    #[must_use]
    pub fn is_empty(&self, feature: Feature) -> bool {
        self.empty[feature.slot()]
    }

    /// The bitmask the datapath reads.
    ///
    /// The four tenant sources fold into one bit, because the datapath
    /// resolves a tenant through all four in turn and can skip the chain only
    /// when none of them holds anything. The firewall reaches only the first
    /// three, so folding the fourth in can leave a lookup it would have been
    /// able to skip, which is the slower half of the trade and the only one
    /// safe to get wrong.
    #[must_use]
    pub fn mask(&self) -> u32 {
        let mut mask = 0u32;
        if self.is_empty(Feature::LpmV4) {
            mask |= FW_EMPTY_LPM_V4;
        }
        if self.is_empty(Feature::LpmV6) {
            mask |= FW_EMPTY_LPM_V6;
        }
        if self.is_empty(Feature::Hash5Tuple) {
            mask |= FW_EMPTY_HASH_5TUPLE;
        }
        if self.is_empty(Feature::HashPort) {
            mask |= FW_EMPTY_HASH_PORT;
        }
        if self.is_empty(Feature::Zones) {
            mask |= FW_EMPTY_ZONES;
        }
        if self.is_empty(Feature::TenantVlan)
            && self.is_empty(Feature::TenantIfindex)
            && self.is_empty(Feature::TenantSubnet)
            && self.is_empty(Feature::TenantCgroup)
        {
            mask |= FW_EMPTY_TENANTS;
        }
        if self.is_empty(Feature::InterfaceGroups) {
            mask |= FW_EMPTY_IFACE_GROUPS;
        }
        if self.is_empty(Feature::SourceLimits) {
            mask |= FW_EMPTY_SRC_LIMITS;
        }
        if self.is_empty(Feature::RateLimitTiersV4) {
            mask |= FW_EMPTY_RL_TIERS_V4;
        }
        if self.is_empty(Feature::RateLimitTiersV6) {
            mask |= FW_EMPTY_RL_TIERS_V6;
        }
        if self.is_empty(Feature::AmpProtectPorts) {
            mask |= FW_EMPTY_AMP_PORTS;
        }
        if self.is_empty(Feature::IdsPatterns) {
            mask |= FW_EMPTY_IDS_PATTERNS;
        }
        if self.is_empty(Feature::IdsSrcPatterns) {
            mask |= FW_EMPTY_IDS_SRC_PATTERNS;
        }
        if self.is_empty(Feature::L7Ports) {
            mask |= FW_EMPTY_L7_PORTS;
        }
        if self.is_empty(Feature::ThreatIocsV4) {
            mask |= FW_EMPTY_THREAT_IOCS_V4;
        }
        if self.is_empty(Feature::ThreatIocsV6) {
            mask |= FW_EMPTY_THREAT_IOCS_V6;
        }
        if self.is_empty(Feature::QosClassifiers) {
            mask |= FW_EMPTY_QOS_CLASSIFIERS;
        }
        mask
    }
}

struct Gates {
    features: EmptyFeatures,
    map: Option<Array<MapData, u32>>,
}

fn gates() -> &'static Mutex<Gates> {
    static GATES: OnceLock<Mutex<Gates>> = OnceLock::new();
    GATES.get_or_init(|| {
        Mutex::new(Gates {
            features: EmptyFeatures::default(),
            map: None,
        })
    })
}

/// Take the `FW_EMPTY_FEATURES` array and publish whatever is already known.
///
/// Called once per load, by the one manager that owns the firewall's own
/// configuration maps. Nothing before this point can reach the datapath, so
/// the bits published earlier are flushed here.
pub fn adopt(map: Array<MapData, u32>) {
    let Ok(mut gates) = gates().lock() else {
        return;
    };
    gates.map = Some(map);
    let mask = gates.features.mask();
    write(&mut gates, mask);
    info!(
        mask = format!("{mask:#010b}"),
        "firewall feature gates armed"
    );
}

/// State whether the tables behind `feature` hold no entry.
///
/// A writer calls this with `false` before a mutation it has not yet applied
/// and with the recomputed answer once the mutation succeeded, so a write that
/// fails half way leaves the datapath looking the entries up.
pub fn publish(feature: Feature, empty: bool) {
    let Ok(mut gates) = gates().lock() else {
        return;
    };
    if gates.features.is_empty(feature) == empty {
        return;
    }
    gates.features.set(feature, empty);
    let mask = gates.features.mask();
    write(&mut gates, mask);
    debug!(
        ?feature,
        empty,
        mask = format!("{mask:#010b}"),
        "firewall feature gate published"
    );
}

/// The mask as it stands, whether or not a map has been adopted.
#[must_use]
pub fn mask() -> u32 {
    gates().lock().map_or(0, |gates| gates.features.mask())
}

fn write(gates: &mut Gates, mask: u32) {
    if let Some(ref mut map) = gates.map
        && let Err(e) = map.set(0, mask, 0)
    {
        // The datapath keeps whatever it last read, which is at worst the
        // slower path, so this is worth a line and nothing more.
        info!(error = %e, "firewall feature gates not written, datapath keeps looking up");
    }
}

/// Whether `feature` is currently published as empty.
///
/// Test-only: the folded tenant bit means the mask cannot answer this for one
/// of the three sources on its own.
#[cfg(test)]
#[must_use]
pub fn is_empty(feature: Feature) -> bool {
    gates()
        .lock()
        .is_ok_and(|gates| gates.features.is_empty(feature))
}

/// Forget every published bit and drop the map handle.
///
/// Test-only: the gates are a process-global, so a test that publishes must
/// not leave its answer behind for the next one.
#[cfg(test)]
pub fn reset() {
    if let Ok(mut gates) = gates().lock() {
        gates.features = EmptyFeatures::default();
        gates.map = None;
    }
}

/// Serialise the tests that drive the process-global gates.
///
/// The gates are one value for the whole process, so two tests publishing at
/// once would each read the other's answer. Every test that publishes, and
/// every test that builds something which publishes, takes this first.
#[cfg(test)]
pub fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_published_leaves_every_lookup_in_place() {
        assert_eq!(EmptyFeatures::default().mask(), 0);
    }

    #[test]
    fn each_feature_sets_its_own_bit() {
        for (feature, bit) in [
            (Feature::LpmV4, FW_EMPTY_LPM_V4),
            (Feature::LpmV6, FW_EMPTY_LPM_V6),
            (Feature::Hash5Tuple, FW_EMPTY_HASH_5TUPLE),
            (Feature::HashPort, FW_EMPTY_HASH_PORT),
            (Feature::Zones, FW_EMPTY_ZONES),
            (Feature::InterfaceGroups, FW_EMPTY_IFACE_GROUPS),
            (Feature::SourceLimits, FW_EMPTY_SRC_LIMITS),
            (Feature::RateLimitTiersV4, FW_EMPTY_RL_TIERS_V4),
            (Feature::RateLimitTiersV6, FW_EMPTY_RL_TIERS_V6),
            (Feature::AmpProtectPorts, FW_EMPTY_AMP_PORTS),
            (Feature::IdsPatterns, FW_EMPTY_IDS_PATTERNS),
            (Feature::IdsSrcPatterns, FW_EMPTY_IDS_SRC_PATTERNS),
            (Feature::L7Ports, FW_EMPTY_L7_PORTS),
            (Feature::ThreatIocsV4, FW_EMPTY_THREAT_IOCS_V4),
            (Feature::ThreatIocsV6, FW_EMPTY_THREAT_IOCS_V6),
            (Feature::QosClassifiers, FW_EMPTY_QOS_CLASSIFIERS),
        ] {
            let mut features = EmptyFeatures::default();
            features.set(feature, true);
            assert_eq!(features.mask(), bit, "{feature:?}");
        }
    }

    #[test]
    fn the_tenant_bit_needs_all_four_sources_empty() {
        let mut features = EmptyFeatures::default();
        features.set(Feature::TenantVlan, true);
        features.set(Feature::TenantIfindex, true);
        assert_eq!(features.mask() & FW_EMPTY_TENANTS, 0);

        features.set(Feature::TenantSubnet, true);
        assert_eq!(features.mask() & FW_EMPTY_TENANTS, 0);

        features.set(Feature::TenantCgroup, true);
        assert_eq!(features.mask() & FW_EMPTY_TENANTS, FW_EMPTY_TENANTS);

        // One source filling again reopens the whole chain.
        features.set(Feature::TenantIfindex, false);
        assert_eq!(features.mask() & FW_EMPTY_TENANTS, 0);
    }

    #[test]
    fn a_feature_filling_again_reopens_its_lookup() {
        let mut features = EmptyFeatures::default();
        features.set(Feature::Hash5Tuple, true);
        features.set(Feature::HashPort, true);
        assert_eq!(features.mask(), FW_EMPTY_HASH_5TUPLE | FW_EMPTY_HASH_PORT);

        features.set(Feature::Hash5Tuple, false);
        assert_eq!(features.mask(), FW_EMPTY_HASH_PORT);
    }

    #[test]
    fn bits_are_distinct() {
        let mut seen = 0u32;
        for feature in [
            Feature::LpmV4,
            Feature::LpmV6,
            Feature::Hash5Tuple,
            Feature::HashPort,
            Feature::Zones,
            Feature::InterfaceGroups,
            Feature::SourceLimits,
            Feature::RateLimitTiersV4,
            Feature::RateLimitTiersV6,
            Feature::AmpProtectPorts,
            Feature::IdsPatterns,
            Feature::IdsSrcPatterns,
            Feature::L7Ports,
            Feature::ThreatIocsV4,
            Feature::ThreatIocsV6,
            Feature::QosClassifiers,
        ] {
            let mut features = EmptyFeatures::default();
            features.set(feature, true);
            let bit = features.mask();
            assert_eq!(seen & bit, 0, "{feature:?} shares a bit");
            seen |= bit;
        }
    }
}
