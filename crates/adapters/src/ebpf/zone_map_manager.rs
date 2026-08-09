//! Security-zone eBPF maps: `ZONE_MAP`, `ZONE_DEFAULT_POLICY`, `ZONE_POLICY_MAP`.
//!
//! The three maps have to agree on what a zone id means, and the id is
//! positional: the zone declared first is id 1, and 0 means "unzoned". Holding
//! them together in one manager is what keeps that agreement true after a
//! reload, when a removed zone renumbers everything that followed it.

use aya::maps::{HashMap, MapData};
use domain::common::error::DomainError;
use domain::zone::entity::{ZoneConfig, ZonePolicy};
use ebpf_common::zone::{ZONE_POLICY_ALLOW, ZONE_POLICY_DENY, zone_pair_key};
use ports::secondary::zone_map_port::ZoneMapPort;
use tracing::info;

use crate::ebpf::map_store::MapStore;
use crate::net::iface_mac::resolve_ifindex;

/// Owns the zone maps of the loaded xdp-firewall program.
pub struct ZoneMapManager {
    /// Ingress `ifindex` → `zone_id`.
    zones: HashMap<MapData, u32, u8>,
    /// `zone_id` → default policy byte.
    defaults: HashMap<MapData, u8, u8>,
    /// `zone_pair_key(from, to)` → policy byte.
    pairs: HashMap<MapData, u16, u8>,
}

impl ZoneMapManager {
    /// Take the zone maps out of the loaded eBPF object.
    ///
    /// # Errors
    ///
    /// Returns an error when a map is missing from the object or carries a
    /// different key/value type than the datapath declares.
    pub fn new(ebpf: &mut dyn MapStore) -> Result<Self, anyhow::Error> {
        let zones = HashMap::try_from(
            ebpf.take_map("ZONE_MAP")
                .ok_or_else(|| anyhow::anyhow!("map 'ZONE_MAP' not found in eBPF object"))?,
        )?;
        let defaults =
            HashMap::try_from(ebpf.take_map("ZONE_DEFAULT_POLICY").ok_or_else(|| {
                anyhow::anyhow!("map 'ZONE_DEFAULT_POLICY' not found in eBPF object")
            })?)?;
        let pairs =
            HashMap::try_from(ebpf.take_map("ZONE_POLICY_MAP").ok_or_else(|| {
                anyhow::anyhow!("map 'ZONE_POLICY_MAP' not found in eBPF object")
            })?)?;
        info!("zone maps acquired");
        Ok(Self {
            zones,
            defaults,
            pairs,
        })
    }

    /// The 1-based datapath id of a zone, by name.
    ///
    /// Public because the per-zone counters are indexed by the same id, so
    /// anything labelling those counters has to derive names the same way.
    #[must_use]
    pub fn zone_ids(config: &ZoneConfig) -> Vec<(u32, String)> {
        config
            .zones
            .iter()
            .enumerate()
            .map(|(idx, zone)| (u32::try_from(idx + 1).unwrap_or(0), zone.id.clone()))
            .collect()
    }

    /// Drop every entry so the rewrite below cannot inherit a stale zone.
    fn clear(&mut self) -> Result<(), DomainError> {
        let ifindexes: Vec<u32> = self.zones.keys().filter_map(Result::ok).collect();
        for ifindex in &ifindexes {
            self.zones
                .remove(ifindex)
                .map_err(|e| DomainError::EngineError(format!("ZONE_MAP clear failed: {e}")))?;
        }
        let ids: Vec<u8> = self.defaults.keys().filter_map(Result::ok).collect();
        for id in &ids {
            self.defaults.remove(id).map_err(|e| {
                DomainError::EngineError(format!("ZONE_DEFAULT_POLICY clear failed: {e}"))
            })?;
        }
        let keys: Vec<u16> = self.pairs.keys().filter_map(Result::ok).collect();
        for key in &keys {
            self.pairs.remove(key).map_err(|e| {
                DomainError::EngineError(format!("ZONE_POLICY_MAP clear failed: {e}"))
            })?;
        }
        Ok(())
    }
}

/// Policy byte the datapath compares against.
fn policy_byte(policy: ZonePolicy) -> u8 {
    match policy {
        ZonePolicy::Deny => ZONE_POLICY_DENY,
        ZonePolicy::Allow => ZONE_POLICY_ALLOW,
    }
}

impl ZoneMapPort for ZoneMapManager {
    fn sync(&mut self, config: &ZoneConfig) -> Result<(), DomainError> {
        self.clear()?;

        let mut interfaces = 0u32;
        for (index, zone) in config.zones.iter().enumerate() {
            // Ids are 1-based; 0 is what the datapath reads as "unzoned".
            let zone_id = u8::try_from(index + 1).map_err(|_| {
                DomainError::EngineError(format!(
                    "zone '{}' is beyond the {} zones the datapath can address",
                    zone.id,
                    u8::MAX
                ))
            })?;
            self.defaults
                .insert(zone_id, policy_byte(zone.default_policy), 0)
                .map_err(|e| {
                    DomainError::EngineError(format!(
                        "ZONE_DEFAULT_POLICY insert failed for '{}': {e}",
                        zone.id
                    ))
                })?;
            for iface in &zone.interfaces {
                // An interface that is not up yet has no ifindex. Failing the
                // whole sync over it would take the zones that do resolve down
                // with it, so it is reported and skipped.
                let Ok(ifindex) = resolve_ifindex(iface) else {
                    tracing::warn!(
                        iface = %iface,
                        zone = %zone.id,
                        "interface has no ifindex, it stays unzoned until the next reload"
                    );
                    continue;
                };
                self.zones.insert(ifindex, zone_id, 0).map_err(|e| {
                    DomainError::EngineError(format!(
                        "ZONE_MAP insert failed for '{iface}' in zone '{}': {e}",
                        zone.id
                    ))
                })?;
                interfaces += 1;
            }
        }

        let zone_id = |name: &str| -> Option<u8> {
            config
                .zones
                .iter()
                .position(|z| z.id == name)
                .and_then(|idx| u8::try_from(idx + 1).ok())
        };

        let mut policies = 0u32;
        for pair in &config.zone_policies {
            // Config validation rejects unknown references, but the REST API
            // mutates the same config in place: an id 0 here would mean
            // "unzoned", which is not what the operator asked for.
            let (Some(from), Some(to)) = (zone_id(&pair.from), zone_id(&pair.to)) else {
                tracing::warn!(
                    from = %pair.from,
                    to = %pair.to,
                    "inter-zone policy names an unknown zone, skipping"
                );
                continue;
            };
            self.pairs
                .insert(zone_pair_key(from, to), policy_byte(pair.policy), 0)
                .map_err(|e| {
                    DomainError::EngineError(format!(
                        "ZONE_POLICY_MAP insert failed for '{}' -> '{}': {e}",
                        pair.from, pair.to
                    ))
                })?;
            policies += 1;
        }

        info!(
            zones = config.zones.len(),
            interfaces, policies, "zone maps programmed"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::zone::entity::{Zone, ZonePair};

    fn config() -> ZoneConfig {
        ZoneConfig {
            zones: vec![
                Zone {
                    id: "wan".to_string(),
                    interfaces: vec!["eth0".to_string()],
                    default_policy: ZonePolicy::Deny,
                },
                Zone {
                    id: "lan".to_string(),
                    interfaces: vec!["eth1".to_string()],
                    default_policy: ZonePolicy::Allow,
                },
            ],
            zone_policies: vec![ZonePair {
                from: "lan".to_string(),
                to: "wan".to_string(),
                policy: ZonePolicy::Allow,
            }],
        }
    }

    #[test]
    fn zone_ids_are_one_based_and_follow_config_order() {
        assert_eq!(
            ZoneMapManager::zone_ids(&config()),
            vec![(1, "wan".to_string()), (2, "lan".to_string())]
        );
    }

    #[test]
    fn an_empty_config_names_no_zone() {
        assert!(
            ZoneMapManager::zone_ids(&ZoneConfig {
                zones: Vec::new(),
                zone_policies: Vec::new(),
            })
            .is_empty()
        );
    }

    #[test]
    fn policy_bytes_match_what_the_datapath_compares_against() {
        assert_eq!(policy_byte(ZonePolicy::Deny), ZONE_POLICY_DENY);
        assert_eq!(policy_byte(ZonePolicy::Allow), ZONE_POLICY_ALLOW);
    }
}
