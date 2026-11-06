use std::collections::HashSet;

use crate::ebpf::feature_gates::{self, Feature};
use crate::ebpf::map_store::MapStore;
use aya::maps::{Array, HashMap, MapData, PerCpuArray, PerCpuValues};
use domain::common::error::DomainError;
use domain::trace::RulePlacement;
use ebpf_common::firewall::{
    ACTION_PASS, DSCP_MARK_NONE, FirewallRuleEntry, FirewallRuleEntryV6, FwHashKey5Tuple,
    FwHashKeyPort, FwHashValue, MATCH_CT_STATE, MATCH_DST_IP, MATCH_DST_PORT, MATCH_PROTO,
    MATCH_SRC_IP, MATCH_SRC_PORT, MAX_FIREWALL_RULES, MAX_SHADOW_RULES, SHADOW_FAMILY_V4,
    SHADOW_FAMILY_V6, ShadowFlowKey, ShadowRuleStats, ShadowSample, VLAN_ANY,
};
use ports::secondary::ebpf_map_port::{FirewallArrayMapPort, ShadowCounts};
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
    /// Single-entry gate telling the datapath whether the conntrack probe can
    /// still change a verdict. Absent on an object built before the gate.
    ct_gate: Option<Array<MapData, u8>>,
    /// Whether a loaded V4 rule reads conntrack state.
    v4_needs_ct: bool,
    /// Whether a loaded V6 rule reads conntrack state.
    v6_needs_ct: bool,
    /// Whether the default policy needs the ESTABLISHED/RELATED bypass, which
    /// is exactly the case where it is not `pass`.
    policy_needs_ct: bool,
    /// The maps of the rules read after the verdict. Absent on an object built
    /// before them, in which case loading a shadow rule is refused.
    shadow: Option<ShadowMaps>,
}

/// The maps behind the shadow rules, taken together or not at all.
struct ShadowMaps {
    rules_v4: Array<MapData, FirewallRuleEntry>,
    rules_v6: Array<MapData, FirewallRuleEntryV6>,
    count: Array<MapData, u32>,
    stats: PerCpuArray<MapData, ShadowRuleStats>,
    flows: HashMap<MapData, ShadowFlowKey, u8>,
    sample: HashMap<MapData, ShadowFlowKey, ShadowSample>,
    /// What was last loaded, so an identical load keeps its counters.
    loaded_v4: Vec<FirewallRuleEntry>,
    loaded_v6: Vec<FirewallRuleEntryV6>,
    /// Whether a loaded shadow rule reads conntrack state. Starts asserted,
    /// like every other half of the gate.
    needs_ct: bool,
}

impl ShadowMaps {
    fn take(ebpf: &mut dyn MapStore) -> Option<Self> {
        let rules_v4 = Array::try_from(ebpf.take_map("FW_SHADOW_RULES")?).ok()?;
        let rules_v6 = Array::try_from(ebpf.take_map("FW_SHADOW_RULES_V6")?).ok()?;
        let count = Array::try_from(ebpf.take_map("FW_SHADOW_COUNT")?).ok()?;
        let stats = PerCpuArray::try_from(ebpf.take_map("FW_SHADOW_STATS")?).ok()?;
        let flows = HashMap::try_from(ebpf.take_map("FW_SHADOW_FLOWS")?).ok()?;
        let sample = HashMap::try_from(ebpf.take_map("FW_SHADOW_SAMPLE")?).ok()?;
        Some(Self {
            rules_v4,
            rules_v6,
            count,
            stats,
            flows,
            sample,
            loaded_v4: Vec::new(),
            loaded_v6: Vec::new(),
            needs_ct: true,
        })
    }

    /// Replace the shadow rules: hide both families, write the entries, start
    /// every counter and the sample afresh, then publish the counts.
    #[allow(clippy::cast_possible_truncation)] // both ≤ MAX_SHADOW_RULES (64)
    fn load(
        &mut self,
        v4: &[FirewallRuleEntry],
        v6: &[FirewallRuleEntryV6],
    ) -> Result<(), DomainError> {
        let err = |what: &str, e: aya::maps::MapError| {
            DomainError::EngineError(format!("shadow rules: {what} failed: {e}"))
        };
        self.count
            .set(SHADOW_FAMILY_V4, &0, 0)
            .map_err(|e| err("hiding v4", e))?;
        self.count
            .set(SHADOW_FAMILY_V6, &0, 0)
            .map_err(|e| err("hiding v6", e))?;
        for (i, entry) in v4.iter().enumerate() {
            self.rules_v4
                .set(i as u32, entry, 0)
                .map_err(|e| err("writing a v4 rule", e))?;
        }
        for (i, entry) in v6.iter().enumerate() {
            self.rules_v6
                .set(i as u32, entry, 0)
                .map_err(|e| err("writing a v6 rule", e))?;
        }
        let cpus = aya::util::nr_cpus()
            .map_err(|(_, e)| DomainError::EngineError(format!("shadow rules: CPU count: {e}")))
            .and_then(|n| {
                usize::try_from(n.get())
                    .map_err(|e| DomainError::EngineError(format!("shadow rules: CPU count: {e}")))
            })?;
        for slot in 0..MAX_SHADOW_RULES * 2 {
            let zero = PerCpuValues::try_from(vec![ShadowRuleStats::default(); cpus])
                .map_err(|e| err("zeroing counters", e.into()))?;
            self.stats
                .set(slot, zero, 0)
                .map_err(|e| err("zeroing counters", e))?;
        }
        let flows: Vec<ShadowFlowKey> = self.flows.keys().filter_map(Result::ok).collect();
        for key in &flows {
            let _ = self.flows.remove(key);
        }
        let sampled: Vec<ShadowFlowKey> = self.sample.keys().filter_map(Result::ok).collect();
        for key in &sampled {
            let _ = self.sample.remove(key);
        }
        self.count
            .set(SHADOW_FAMILY_V4, &(v4.len() as u32), 0)
            .map_err(|e| err("publishing the v4 count", e))?;
        self.count
            .set(SHADOW_FAMILY_V6, &(v6.len() as u32), 0)
            .map_err(|e| err("publishing the v6 count", e))?;
        self.loaded_v4 = v4.to_vec();
        self.loaded_v6 = v6.to_vec();
        Ok(())
    }

    #[allow(clippy::cast_possible_truncation)] // slots < 2 * MAX_SHADOW_RULES
    fn read(&self) -> Result<ShadowCounts, DomainError> {
        let slot = |index: u32| -> Result<ShadowRuleStats, DomainError> {
            let values = self
                .stats
                .get(&index, 0)
                .map_err(|e| DomainError::EngineError(format!("shadow counters not read: {e}")))?;
            Ok(values
                .iter()
                .fold(ShadowRuleStats::default(), |mut sum, cpu| {
                    sum.packets += cpu.packets;
                    sum.flows += cpu.flows;
                    sum.changed_packets += cpu.changed_packets;
                    sum.changed_flows += cpu.changed_flows;
                    sum
                }))
        };
        let v4 = (0..self.loaded_v4.len() as u32)
            .map(slot)
            .collect::<Result<Vec<_>, _>>()?;
        let v6 = (0..self.loaded_v6.len() as u32)
            .map(|i| slot(MAX_SHADOW_RULES + i))
            .collect::<Result<Vec<_>, _>>()?;
        let sample = self
            .sample
            .iter()
            .filter_map(Result::ok)
            .map(|(key, mut flow)| {
                flow.first_seen_ns =
                    super::ringbuf_observer::boottime_to_epoch_ns(flow.first_seen_ns);
                flow.last_seen_ns =
                    super::ringbuf_observer::boottime_to_epoch_ns(flow.last_seen_ns);
                (key, flow)
            })
            .collect();
        Ok(ShadowCounts { v4, v6, sample })
    }
}

impl FirewallMapManager {
    /// Create a new `FirewallMapManager` by taking ownership of the
    /// five array-based firewall maps from the loaded eBPF program.
    ///
    /// LPM Trie maps must be taken **before** calling this constructor
    /// (see `GeoIpLpmManager`), as `take_map()` is destructive.
    pub fn new(ebpf: &mut dyn MapStore) -> Result<Self, anyhow::Error> {
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

        // Fast-path HashMap maps (optional - absent if program doesn't have them)
        let hash_5tuple = ebpf
            .take_map("FW_HASH_5TUPLE")
            .and_then(|m| HashMap::try_from(m).ok());
        let hash_port = ebpf
            .take_map("FW_HASH_PORT")
            .and_then(|m| HashMap::try_from(m).ok());
        let ct_gate = ebpf
            .take_map("FW_CT_GATE")
            .and_then(|m| Array::try_from(m).ok());
        let shadow = ShadowMaps::take(ebpf);

        // The datapath's empty-feature mask. This manager adopts it because it
        // is the one that owns the firewall's own configuration maps; the
        // other six publishers reach it through the module. The maps behind
        // the two fast paths have just been created by this load, so nothing
        // is in them until `load_v4_rules` says otherwise - and a fast path
        // this object does not carry is one nothing can ever write to.
        if let Some(map) = ebpf
            .take_map("FW_EMPTY_FEATURES")
            .and_then(|m| Array::try_from(m).ok())
        {
            feature_gates::publish(Feature::Hash5Tuple, true);
            feature_gates::publish(Feature::HashPort, true);
            feature_gates::adopt(map);
        }

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
            ct_gate,
            // Every half starts asserted so the gate is open until a load has
            // actually proved otherwise. A firewall that probes conntrack it
            // did not need is slow; one that skips a probe it needed is wrong.
            v4_needs_ct: true,
            v6_needs_ct: true,
            policy_needs_ct: true,
            shadow,
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

    /// Publish whether the datapath still has to probe conntrack.
    ///
    /// Called after every load and after the default policy moves, because the
    /// answer is a property of the two together. A failed write leaves the
    /// previous value, which is why the gate defaults open: the worst outcome
    /// of a stale gate is a probe nobody needed.
    fn sync_ct_gate(&mut self) {
        let open = self.v4_needs_ct
            || self.v6_needs_ct
            || self.policy_needs_ct
            || self.shadow.as_ref().is_some_and(|s| s.needs_ct);
        if let Some(ref mut map) = self.ct_gate {
            if let Err(e) = map.set(0, &u8::from(open), 0) {
                info!(error = %e, "conntrack gate not written, datapath keeps probing");
                return;
            }
            info!(open, "conntrack gate published");
        }
    }
}

/// Whether a rule's verdict can depend on the packet's conntrack state.
///
/// Two criteria reach it: an explicit `ct_state` match, and a connection
/// ceiling, which is only enforced on a flow the datapath believes is new.
fn rule_reads_ct(match_flags: u8, max_states: u16) -> bool {
    (match_flags & MATCH_CT_STATE) != 0 || max_states > 0
}

/// Whether a rule carries a criterion the fast-path hash maps cannot express,
/// so it has to go through the linear array scan instead.
///
/// The hash keys hold a tuple and nothing else. A rule scoped to an interface
/// group or to a tenant would therefore have its verdict served to traffic the
/// scope excludes - and for a tenant that is the whole point of the scope,
/// since two tenants may run the same private range behind the same ports.
///
/// A per-rule state ceiling goes the same way: the datapath counts those
/// against a rule index, and a fast-path hit answers with an action and no
/// index, so a ceiling served from there would be a number nothing enforces.
/// A DSCP mark is read off the matched rule by index for the same reason, so a
/// marking rule on the fast path would pass its traffic unmarked.
fn has_extended_match(rule: &FirewallRuleEntry) -> bool {
    rule.match_flags2 != 0
        || rule.vlan_id != VLAN_ANY
        || rule.ct_state_mask != 0
        || rule.group_mask != 0
        || rule.tenant_id != 0
        || rule.src_set_id != 0
        || rule.dst_set_id != 0
        || rule.max_states != 0
        || rule.dscp_mark != DSCP_MARK_NONE
}

/// The exact five-tuple a fast-path entry is keyed on.
type FiveTupleKey = (u32, u32, u16, u16, u8);

/// Where the loader puts one IPv4 rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Route {
    /// The exact five-tuple map.
    FiveTuple(FiveTupleKey),
    /// The protocol and destination port map.
    Port((u16, u8)),
    /// A rule before it holds the same fast-path key and matches every packet
    /// this one would, so this one is never reached and is written nowhere.
    Covered,
    /// The array the datapath scans in priority order.
    Array,
}

/// Route each rule, given in ascending priority, to a fast-path map or to the
/// array.
///
/// The datapath checks the O(1) hash fast-paths BEFORE the linear array scan,
/// so a rule may only be fast-pathed while no higher-priority rule has already
/// been routed to the array - otherwise the hash hit would short-circuit and
/// skip that higher-priority rule (e.g. a broad whitelist `allow` losing to a
/// narrow `reject` on the same port). Once the first array-bound rule is seen,
/// every subsequent fast-path candidate is demoted to the array so priority
/// order is preserved.
///
/// A map holds one action per key, so a later rule on a key already taken
/// would overwrite the earlier rule's action and reverse their priority. The
/// earlier rule matches everything the later one does, which leaves the later
/// one nothing to decide: it is covered rather than written.
fn route_v4(rules: &[FirewallRuleEntry], five_tuple_map: bool, port_map: bool) -> Vec<Route> {
    let mut routes = Vec::with_capacity(rules.len());
    let mut five_tuples: HashSet<FiveTupleKey> = HashSet::new();
    let mut ports: HashSet<(u16, u8)> = HashSet::new();
    let mut seen_array_rule = false;
    for rule in rules {
        let flags = rule.match_flags;
        let fast = !seen_array_rule && !has_extended_match(rule);
        let route = if fast
            && five_tuple_map
            && flags
                == (MATCH_SRC_IP | MATCH_DST_IP | MATCH_SRC_PORT | MATCH_DST_PORT | MATCH_PROTO)
            && rule.src_port_start == rule.src_port_end
            && rule.dst_port_start == rule.dst_port_end
            && rule.src_mask == 0xFFFF_FFFF
            && rule.dst_mask == 0xFFFF_FFFF
        {
            let key = (
                rule.src_ip,
                rule.dst_ip,
                rule.src_port_start,
                rule.dst_port_start,
                rule.protocol,
            );
            if five_tuples.insert(key) {
                Route::FiveTuple(key)
            } else {
                Route::Covered
            }
        } else if fast
            && port_map
            && flags == (MATCH_DST_PORT | MATCH_PROTO)
            && rule.dst_port_start == rule.dst_port_end
        {
            let key = (rule.dst_port_start, rule.protocol);
            if ports.insert(key) {
                Route::Port(key)
            } else {
                Route::Covered
            }
        } else {
            seen_array_rule = true;
            Route::Array
        };
        routes.push(route);
    }
    routes
}

impl FirewallArrayMapPort for FirewallMapManager {
    #[allow(clippy::cast_possible_truncation)] // count ≤ MAX_FIREWALL_RULES (4096)
    fn load_v4_rules(
        &mut self,
        rules: &[FirewallRuleEntry],
    ) -> Result<Vec<RulePlacement>, DomainError> {
        // Say both fast paths may hold something before touching them, so a
        // load that fails part way leaves the datapath reading them rather
        // than skipping entries it has just written.
        feature_gates::publish(Feature::Hash5Tuple, false);
        feature_gates::publish(Feature::HashPort, false);

        // Flush fast-path HashMaps before reload to remove stale entries.
        self.clear_hash_maps();

        // Classify rules into fast-path HashMaps vs array fallback; `rules`
        // arrive sorted by ascending priority (lowest number wins).
        let mut array_rules: Vec<FirewallRuleEntry> = Vec::new();
        let mut placements = Vec::with_capacity(rules.len());
        let mut hash_5tuple_count = 0u32;
        let mut hash_port_count = 0u32;

        let routes = route_v4(rules, self.hash_5tuple.is_some(), self.hash_port.is_some());
        for (rule, route) in rules.iter().zip(routes) {
            let val = FwHashValue {
                action: rule.action,
                _pad: [0; 3],
            };
            match route {
                Route::FiveTuple((src_ip, dst_ip, src_port, dst_port, protocol)) => {
                    if let Some(ref mut map) = self.hash_5tuple {
                        let key = FwHashKey5Tuple {
                            src_ip,
                            dst_ip,
                            src_port,
                            dst_port,
                            protocol,
                            _pad: [0; 3],
                        };
                        placements.push(if map.insert(&key, &val, 0).is_ok() {
                            RulePlacement::Hash5Tuple
                        } else {
                            RulePlacement::NotInstalled
                        });
                        hash_5tuple_count += 1;
                    }
                }
                Route::Port((dst_port, protocol)) => {
                    if let Some(ref mut map) = self.hash_port {
                        let key = FwHashKeyPort {
                            dst_port,
                            protocol,
                            _pad: 0,
                        };
                        placements.push(if map.insert(&key, &val, 0).is_ok() {
                            RulePlacement::HashPort
                        } else {
                            RulePlacement::NotInstalled
                        });
                        hash_port_count += 1;
                    }
                }
                Route::Covered => placements.push(RulePlacement::NotInstalled),
                Route::Array => {
                    placements.push(if array_rules.len() < MAX_FIREWALL_RULES as usize {
                        RulePlacement::Array(array_rules.len() as u32)
                    } else {
                        RulePlacement::NotInstalled
                    });
                    array_rules.push(*rule);
                }
            }
        }

        // Load remaining rules into the array
        let count = array_rules.len().min(MAX_FIREWALL_RULES as usize);

        self.rule_count_v4
            .set(0, &0u32, 0)
            .map_err(|e| DomainError::EngineError(format!("set V4 count=0 failed: {e}")))?;

        for (i, rule) in array_rules.iter().take(count).enumerate() {
            self.rules_v4
                .set(i as u32, rule, 0)
                .map_err(|e| DomainError::EngineError(format!("set V4 rule[{i}] failed: {e}")))?;
        }

        self.rule_count_v4
            .set(0, &(count as u32), 0)
            .map_err(|e| DomainError::EngineError(format!("set V4 count={count} failed: {e}")))?;

        self.cached_v4_count = count + hash_5tuple_count as usize + hash_port_count as usize;
        feature_gates::publish(Feature::Hash5Tuple, hash_5tuple_count == 0);
        feature_gates::publish(Feature::HashPort, hash_port_count == 0);
        self.v4_needs_ct = rules
            .iter()
            .any(|r| rule_reads_ct(r.match_flags, r.max_states));
        self.sync_ct_gate();
        info!(
            array_count = count,
            hash_5tuple = hash_5tuple_count,
            hash_port = hash_port_count,
            "V4 firewall rules loaded (multi-level)"
        );
        Ok(placements)
    }

    #[allow(clippy::cast_possible_truncation)] // count ≤ MAX_FIREWALL_RULES (4096)
    fn load_v6_rules(
        &mut self,
        rules: &[FirewallRuleEntryV6],
    ) -> Result<Vec<RulePlacement>, DomainError> {
        let count = rules.len().min(MAX_FIREWALL_RULES as usize);

        self.rule_count_v6
            .set(0, &0u32, 0)
            .map_err(|e| DomainError::EngineError(format!("set V6 count=0 failed: {e}")))?;

        for (i, rule) in rules.iter().take(count).enumerate() {
            self.rules_v6
                .set(i as u32, rule, 0)
                .map_err(|e| DomainError::EngineError(format!("set V6 rule[{i}] failed: {e}")))?;
        }

        self.rule_count_v6
            .set(0, &(count as u32), 0)
            .map_err(|e| DomainError::EngineError(format!("set V6 count={count} failed: {e}")))?;

        self.cached_v6_count = count;
        self.v6_needs_ct = rules
            .iter()
            .any(|r| rule_reads_ct(r.match_flags, r.max_states));
        self.sync_ct_gate();
        info!(count, "V6 firewall rules loaded into eBPF array");
        Ok((0..rules.len())
            .map(|i| {
                if i < count {
                    RulePlacement::Array(i as u32)
                } else {
                    RulePlacement::NotInstalled
                }
            })
            .collect())
    }

    fn set_default_policy(&mut self, policy: u8) -> Result<(), DomainError> {
        self.default_policy
            .set(0, &policy, 0)
            .map_err(|e| DomainError::EngineError(format!("set default policy failed: {e}")))?;
        self.policy_needs_ct = policy != ACTION_PASS;
        self.sync_ct_gate();
        info!(policy, "firewall default policy set");
        Ok(())
    }

    fn rule_count(&self) -> Result<usize, DomainError> {
        Ok(self.cached_v4_count + self.cached_v6_count)
    }

    fn load_shadow_rules(
        &mut self,
        v4: &[FirewallRuleEntry],
        v6: &[FirewallRuleEntryV6],
    ) -> Result<bool, DomainError> {
        let limit = MAX_SHADOW_RULES as usize;
        if v4.len() > limit || v6.len() > limit {
            return Err(DomainError::InvalidRule(format!(
                "too many shadow rules: {} IPv4 and {} IPv6, the datapath holds {limit} of each",
                v4.len(),
                v6.len()
            )));
        }
        let Some(shadow) = self.shadow.as_mut() else {
            if v4.is_empty() && v6.is_empty() {
                return Ok(false);
            }
            return Err(DomainError::EngineError(
                "shadow rules: the loaded firewall program carries no shadow maps".to_string(),
            ));
        };
        if shadow.loaded_v4 == v4 && shadow.loaded_v6 == v6 {
            return Ok(false);
        }
        shadow.load(v4, v6)?;
        shadow.needs_ct = v4
            .iter()
            .any(|r| rule_reads_ct(r.match_flags, r.max_states))
            || v6
                .iter()
                .any(|r| rule_reads_ct(r.match_flags, r.max_states));
        self.sync_ct_gate();
        info!(v4 = v4.len(), v6 = v6.len(), "firewall shadow rules loaded");
        Ok(true)
    }

    fn read_shadow(&self) -> Result<ShadowCounts, DomainError> {
        match self.shadow.as_ref() {
            Some(shadow) => shadow.read(),
            None => Ok(ShadowCounts::default()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An exact 5-tuple rule, the shape the fast path exists for.
    fn fast_path_candidate() -> FirewallRuleEntry {
        FirewallRuleEntry {
            src_ip: 0x0A00_0001,
            src_mask: 0xFFFF_FFFF,
            dst_ip: 0x0A00_0002,
            dst_mask: 0xFFFF_FFFF,
            src_port_start: 1024,
            src_port_end: 1024,
            dst_port_start: 443,
            dst_port_end: 443,
            protocol: 6,
            match_flags: MATCH_SRC_IP
                | MATCH_DST_IP
                | MATCH_SRC_PORT
                | MATCH_DST_PORT
                | MATCH_PROTO,
            vlan_id: VLAN_ANY,
            action: 0,
            ct_state_mask: 0,
            src_set_id: 0,
            dst_set_id: 0,
            tcp_flags_match: 0,
            tcp_flags_mask: 0,
            icmp_type: 0,
            icmp_code: 0,
            match_flags2: 0,
            dscp_match: 0,
            max_states: 0,
            src_mac: [0; 6],
            dst_mac: [0; 6],
            dscp_mark: DSCP_MARK_NONE,
            _reserved: [0; 3],
            group_mask: 0,
            tenant_id: 0,
        }
    }

    #[test]
    fn a_global_exact_tuple_rule_stays_on_the_fast_path() {
        assert!(!has_extended_match(&fast_path_candidate()));
    }

    #[test]
    fn a_tenant_scoped_rule_is_demoted_to_the_array_scan() {
        let mut rule = fast_path_candidate();
        rule.tenant_id = 3;
        // The hash key holds no tenant, so a cached verdict here would reach
        // every tenant using the same tuple.
        assert!(has_extended_match(&rule));
    }

    #[test]
    fn an_interface_scoped_rule_is_demoted_the_same_way() {
        let mut rule = fast_path_candidate();
        rule.group_mask = 0b10;
        assert!(has_extended_match(&rule));
    }

    #[test]
    fn a_plain_rule_lets_the_conntrack_gate_close() {
        assert!(!rule_reads_ct(MATCH_DST_PORT | MATCH_PROTO, 0));
    }

    #[test]
    fn a_ct_state_match_holds_the_conntrack_gate_open() {
        assert!(rule_reads_ct(MATCH_DST_PORT | MATCH_CT_STATE, 0));
    }

    #[test]
    fn a_state_ceiling_holds_the_conntrack_gate_open_on_its_own() {
        // The ceiling is enforced only on a flow the datapath believes is new,
        // so it reads conntrack even with no ct_state criterion on the rule.
        assert!(rule_reads_ct(MATCH_DST_PORT, 32));
    }

    #[test]
    fn a_rule_carrying_a_state_ceiling_is_demoted_too() {
        let mut rule = fast_path_candidate();
        rule.max_states = 128;
        // The ceiling is counted per rule index, and the fast path has none to
        // count against, so serving the verdict from there drops the ceiling.
        assert!(has_extended_match(&rule));
    }

    #[test]
    fn a_rule_carrying_a_dscp_mark_is_demoted_too() {
        let mut rule = fast_path_candidate();
        rule.dscp_mark = 46;
        // The mark is read off the matched rule index, which a fast-path hit
        // does not have, so the traffic would pass unmarked.
        assert!(has_extended_match(&rule));
    }

    /// A rule on the protocol and destination port alone, the shape the port
    /// map exists for.
    fn port_rule(dst_port: u16, action: u8) -> FirewallRuleEntry {
        FirewallRuleEntry {
            src_ip: 0,
            src_mask: 0,
            dst_ip: 0,
            dst_mask: 0,
            src_port_start: 0,
            src_port_end: 0,
            dst_port_start: dst_port,
            dst_port_end: dst_port,
            match_flags: MATCH_DST_PORT | MATCH_PROTO,
            action,
            ..fast_path_candidate()
        }
    }

    #[test]
    fn a_later_rule_on_a_port_already_taken_does_not_overwrite_it() {
        // An allow at a better priority and a deny on the same port later on,
        // the shape a tier ordered before another one compiles to.
        let routes = route_v4(&[port_rule(9997, 1), port_rule(9997, 2)], true, true);
        assert_eq!(routes, vec![Route::Port((9997, 6)), Route::Covered]);
    }

    #[test]
    fn a_later_exact_tuple_already_taken_is_covered_the_same_way() {
        let rule = fast_path_candidate();
        let routes = route_v4(&[rule, rule], true, true);
        assert!(matches!(routes[0], Route::FiveTuple(_)));
        assert_eq!(routes[1], Route::Covered);
    }

    #[test]
    fn a_fast_path_rule_after_an_array_rule_is_demoted() {
        let mut ranged = port_rule(80, 1);
        ranged.dst_port_end = 90;
        let routes = route_v4(&[ranged, port_rule(85, 2)], true, true);
        assert_eq!(routes, vec![Route::Array, Route::Array]);
    }

    #[test]
    fn without_the_port_map_a_port_rule_goes_to_the_array() {
        assert_eq!(
            route_v4(&[port_rule(53, 1)], true, false),
            vec![Route::Array]
        );
    }
}
