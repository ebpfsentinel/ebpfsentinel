use aya::Ebpf;
use aya::maps::{Array, HashMap, MapData};
use domain::common::error::DomainError;
use ebpf_common::firewall::{
    FirewallRuleEntry, FirewallRuleEntryV6, FwHashKey5Tuple, FwHashKeyPort, FwHashValue,
    MATCH_DST_IP, MATCH_DST_PORT, MATCH_PROTO, MATCH_SRC_IP, MATCH_SRC_PORT, MAX_FIREWALL_RULES,
};
use ports::secondary::ebpf_map_port::FirewallArrayMapPort;
use tracing::info;

/// Manages the array-based eBPF firewall maps.
///
/// Uses 5 maps:
/// - `FIREWALL_RULES`: `Array<FirewallRuleEntry>` (V4 rules, indexed 0..count)
/// - `FIREWALL_RULE_COUNT`: `Array<u32>` (single element: number of active V4 rules)
/// - `FIREWALL_RULES_V6`: `Array<FirewallRuleEntryV6>` (V6 rules)
/// - `FIREWALL_RULE_COUNT_V6`: `Array<u32>` (number of active V6 rules)
/// - `FIREWALL_DEFAULT_POLICY`: `Array<u8>` (single element: default action)
///
/// LPM Trie maps for CIDR-only rules (`GeoIP` blocking) are managed
/// separately by `GeoIpLpmManager`.
///
/// Atomic reload protocol: write count=0 → write entries → write count=n.
pub struct FirewallMapManager {
    rules_v4: Array<MapData, FirewallRuleEntry>,
    rule_count_v4: Array<MapData, u32>,
    rules_v6: Array<MapData, FirewallRuleEntryV6>,
    rule_count_v6: Array<MapData, u32>,
    default_policy: Array<MapData, u8>,
    /// Fast-path: 5-tuple exact-match `HashMap`.
    hash_5tuple: Option<HashMap<MapData, FwHashKey5Tuple, FwHashValue>>,
    /// Fast-path: protocol+port `HashMap`.
    hash_port: Option<HashMap<MapData, FwHashKeyPort, FwHashValue>>,
    /// Cached counts for `rule_count()` without map reads.
    cached_v4_count: usize,
    cached_v6_count: usize,
}

impl FirewallMapManager {
    /// Create a new `FirewallMapManager` by taking ownership of the
    /// five array-based firewall maps from the loaded eBPF program.
    ///
    /// LPM Trie maps must be taken **before** calling this constructor
    /// (see `GeoIpLpmManager`), as `take_map()` is destructive.
    pub fn new(ebpf: &mut Ebpf) -> Result<Self, anyhow::Error> {
        let rules_v4 = Array::try_from(
            ebpf.take_map("FIREWALL_RULES")
                .ok_or_else(|| anyhow::anyhow!("map 'FIREWALL_RULES' not found"))?,
        )?;
        let rule_count_v4 = Array::try_from(
            ebpf.take_map("FIREWALL_RULE_COUNT")
                .ok_or_else(|| anyhow::anyhow!("map 'FIREWALL_RULE_COUNT' not found"))?,
        )?;
        let rules_v6 = Array::try_from(
            ebpf.take_map("FIREWALL_RULES_V6")
                .ok_or_else(|| anyhow::anyhow!("map 'FIREWALL_RULES_V6' not found"))?,
        )?;
        let rule_count_v6 = Array::try_from(
            ebpf.take_map("FIREWALL_RULE_COUNT_V6")
                .ok_or_else(|| anyhow::anyhow!("map 'FIREWALL_RULE_COUNT_V6' not found"))?,
        )?;
        let default_policy = Array::try_from(
            ebpf.take_map("FIREWALL_DEFAULT_POLICY")
                .ok_or_else(|| anyhow::anyhow!("map 'FIREWALL_DEFAULT_POLICY' not found"))?,
        )?;

        // Fast-path HashMap maps (optional — absent if program doesn't have them)
        let hash_5tuple = ebpf
            .take_map("FW_HASH_5TUPLE")
            .and_then(|m| HashMap::try_from(m).ok());
        let hash_port = ebpf
            .take_map("FW_HASH_PORT")
            .and_then(|m| HashMap::try_from(m).ok());

        if hash_5tuple.is_some() {
            info!("FW_HASH_5TUPLE fast-path map acquired");
        }
        if hash_port.is_some() {
            info!("FW_HASH_PORT fast-path map acquired");
        }

        info!("firewall array maps acquired (rules + default_policy)");
        Ok(Self {
            rules_v4,
            rule_count_v4,
            rules_v6,
            rule_count_v6,
            default_policy,
            hash_5tuple,
            hash_port,
            cached_v4_count: 0,
            cached_v6_count: 0,
        })
    }
}

impl FirewallMapManager {
    /// Flush fast-path `HashMap` entries before reload.
    ///
    /// eBPF `HashMap` maps don't have a bulk-clear API, so we drain all existing keys.
    /// This prevents stale 5-tuple/port rules from persisting across reloads.
    fn clear_hash_maps(&mut self) {
        if let Some(ref mut map) = self.hash_5tuple {
            let keys: Vec<FwHashKey5Tuple> = map.keys().filter_map(Result::ok).collect();
            for key in &keys {
                let _ = map.remove(key);
            }
        }
        if let Some(ref mut map) = self.hash_port {
            let keys: Vec<FwHashKeyPort> = map.keys().filter_map(Result::ok).collect();
            for key in &keys {
                let _ = map.remove(key);
            }
        }
    }
}

impl FirewallArrayMapPort for FirewallMapManager {
    #[allow(clippy::cast_possible_truncation)] // count ≤ MAX_FIREWALL_RULES (4096)
    fn load_v4_rules(&mut self, rules: &[FirewallRuleEntry]) -> Result<(), DomainError> {
        // Flush fast-path HashMaps before reload to remove stale entries.
        self.clear_hash_maps();

        // Classify rules into fast-path HashMaps vs array fallback.
        let mut array_rules: Vec<FirewallRuleEntry> = Vec::new();
        let mut hash_5tuple_count = 0u32;
        let mut hash_port_count = 0u32;

        for rule in rules {
            let flags = rule.match_flags;
            let has_extended = rule.match_flags2 != 0
                || rule.vlan_id != 0
                || rule.ct_state_mask != 0
                || rule.group_mask != 0
                || rule.src_set_id != 0
                || rule.dst_set_id != 0;

            if !has_extended
                && flags
                    == (MATCH_SRC_IP | MATCH_DST_IP | MATCH_SRC_PORT | MATCH_DST_PORT | MATCH_PROTO)
                && rule.src_port_start == rule.src_port_end
                && rule.dst_port_start == rule.dst_port_end
                && rule.src_mask == 0xFFFF_FFFF
                && rule.dst_mask == 0xFFFF_FFFF
            {
                // Exact 5-tuple match → fast-path HashMap
                if let Some(ref mut map) = self.hash_5tuple {
                    let key = FwHashKey5Tuple {
                        src_ip: rule.src_ip,
                        dst_ip: rule.dst_ip,
                        src_port: rule.src_port_start,
                        dst_port: rule.dst_port_start,
                        protocol: rule.protocol,
                        _pad: [0; 3],
                    };
                    let val = FwHashValue {
                        action: rule.action,
                        _pad: [0; 3],
                    };
                    let _ = map.insert(key, val, 0);
                    hash_5tuple_count += 1;
                    continue;
                }
            } else if !has_extended
                && flags == (MATCH_DST_PORT | MATCH_PROTO)
                && rule.dst_port_start == rule.dst_port_end
            {
                // Protocol+port match → fast-path HashMap
                if let Some(ref mut map) = self.hash_port {
                    let key = FwHashKeyPort {
                        dst_port: rule.dst_port_start,
                        protocol: rule.protocol,
                        _pad: 0,
                    };
                    let val = FwHashValue {
                        action: rule.action,
                        _pad: [0; 3],
                    };
                    let _ = map.insert(key, val, 0);
                    hash_port_count += 1;
                    continue;
                }
            }

            // Fallback: complex rule → array scan
            array_rules.push(*rule);
        }

        // Load remaining rules into the array
        let count = array_rules.len().min(MAX_FIREWALL_RULES as usize);

        self.rule_count_v4
            .set(0, 0u32, 0)
            .map_err(|e| DomainError::EngineError(format!("set V4 count=0 failed: {e}")))?;

        for (i, rule) in array_rules.iter().take(count).enumerate() {
            self.rules_v4
                .set(i as u32, *rule, 0)
                .map_err(|e| DomainError::EngineError(format!("set V4 rule[{i}] failed: {e}")))?;
        }

        self.rule_count_v4
            .set(0, count as u32, 0)
            .map_err(|e| DomainError::EngineError(format!("set V4 count={count} failed: {e}")))?;

        self.cached_v4_count = count + hash_5tuple_count as usize + hash_port_count as usize;
        info!(
            array_count = count,
            hash_5tuple = hash_5tuple_count,
            hash_port = hash_port_count,
            "V4 firewall rules loaded (multi-level)"
        );
        Ok(())
    }

    #[allow(clippy::cast_possible_truncation)] // count ≤ MAX_FIREWALL_RULES (4096)
    fn load_v6_rules(&mut self, rules: &[FirewallRuleEntryV6]) -> Result<(), DomainError> {
        let count = rules.len().min(MAX_FIREWALL_RULES as usize);

        self.rule_count_v6
            .set(0, 0u32, 0)
            .map_err(|e| DomainError::EngineError(format!("set V6 count=0 failed: {e}")))?;

        for (i, rule) in rules.iter().take(count).enumerate() {
            self.rules_v6
                .set(i as u32, *rule, 0)
                .map_err(|e| DomainError::EngineError(format!("set V6 rule[{i}] failed: {e}")))?;
        }

        self.rule_count_v6
            .set(0, count as u32, 0)
            .map_err(|e| DomainError::EngineError(format!("set V6 count={count} failed: {e}")))?;

        self.cached_v6_count = count;
        info!(count, "V6 firewall rules loaded into eBPF array");
        Ok(())
    }

    fn set_default_policy(&mut self, policy: u8) -> Result<(), DomainError> {
        self.default_policy
            .set(0, policy, 0)
            .map_err(|e| DomainError::EngineError(format!("set default policy failed: {e}")))?;
        info!(policy, "firewall default policy set");
        Ok(())
    }

    fn rule_count(&self) -> Result<usize, DomainError> {
        Ok(self.cached_v4_count + self.cached_v6_count)
    }
}

/// Populate the `ZONE_MAP` (`HashMap<u32, u8>`) in the xdp-firewall eBPF
/// program with (ifindex → `zone_id`) entries derived from `ZoneConfig`.
///
/// Zone IDs are 1-based (0 = unzoned). Interface names are resolved to
/// ifindex via `/sys/class/net/<iface>/ifindex`.
///
/// Best-effort: logs warnings for unresolvable interfaces.
pub fn populate_zone_map(ebpf: &mut Ebpf, zone_cfg: &domain::zone::entity::ZoneConfig) {
    use aya::maps::HashMap;

    let Some(map) = ebpf.take_map("ZONE_MAP") else {
        tracing::warn!("ZONE_MAP not found in eBPF object, skipping zone wiring");
        return;
    };
    let Ok(mut zone_map) = HashMap::<_, u32, u8>::try_from(map) else {
        tracing::warn!("ZONE_MAP type mismatch");
        return;
    };

    let mut count = 0u32;
    for (zone_idx, zone) in zone_cfg.zones.iter().enumerate() {
        #[allow(clippy::cast_possible_truncation)]
        let zone_id = (zone_idx as u8).wrapping_add(1); // 1-based
        for iface in &zone.interfaces {
            match resolve_ifindex(iface) {
                Some(ifindex) => {
                    if let Err(e) = zone_map.insert(ifindex, zone_id, 0) {
                        tracing::warn!(
                            iface = %iface,
                            ifindex,
                            zone = %zone.id,
                            "ZONE_MAP insert failed: {e}"
                        );
                    } else {
                        count += 1;
                    }
                }
                None => {
                    tracing::warn!(
                        iface = %iface,
                        zone = %zone.id,
                        "cannot resolve ifindex for interface"
                    );
                }
            }
        }
    }

    if count > 0 {
        info!(
            entries = count,
            zones = zone_cfg.zones.len(),
            "ZONE_MAP populated"
        );
    }
}

/// Resolve a network interface name to its ifindex via sysfs.
fn resolve_ifindex(iface: &str) -> Option<u32> {
    let path = format!("/sys/class/net/{iface}/ifindex");
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
}
