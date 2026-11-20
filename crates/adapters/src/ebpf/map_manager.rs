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
    SHADOW_FAMILY_V6, ShadowFlowKey, ShadowRuleStats, ShadowSample, VLAN_ANY, bank_base,
    generation_bank, rule_generation,
};
use ports::secondary::ebpf_map_port::{FirewallArrayMapPort, ShadowCounts};
use tracing::{info, warn};

/// Manages the array-based eBPF firewall maps.
///
/// Uses 5 maps:
/// - `FIREWALL_RULES`: `Array<FirewallRuleEntry>` (V4 rules, two banks)
/// - `FIREWALL_RULE_COUNT`: `Array<u32>` (V4 generation word: bank and count)
/// - `FIREWALL_RULES_V6`: `Array<FirewallRuleEntryV6>` (V6 rules, two banks)
/// - `FIREWALL_RULE_COUNT_V6`: `Array<u32>` (V6 generation word)
/// - `FIREWALL_DEFAULT_POLICY`: `Array<u8>` (single element: default action)
///
/// LPM Trie maps for CIDR-only rules are written separately, by the LPM
/// coordinator.
///
/// Reload protocol: the datapath reads the bank the generation word names.
/// A reload writes the other bank in full, fast-path keys included, then
/// flips the word in one write, then removes the old bank's keys. A write
/// that fails before the flip leaves the word, and so every rule the
/// datapath enforces, as it was.
// Each flag is one independent reason the conntrack gate stays open.
#[allow(clippy::struct_excessive_bools)]
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
    /// The bank each family's generation word names, the one being enforced.
    bank_v4: u32,
    bank_v6: u32,
    /// Fast-path entries of the enforced IPv4 bank, five-tuple then port, so
    /// an abandoned reload can publish the gates of the set still in force.
    hash_counts_v4: (u32, u32),
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
    /// Whether a per-source connection ceiling is configured: without the
    /// conntrack state every packet of a flow reads as its first one.
    source_limits_need_ct: bool,
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
    /// The LPM Trie maps are not taken here, so the LPM coordinator can take
    /// them from the same object; `take_map()` is destructive.
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

        // The maps of a fresh load read zero, which is bank 0 holding nothing,
        // and a reused pinned map names whichever bank it was left on.
        let bank_v4 = rule_count_v4.get(&0, 0).map_or(0, generation_bank);
        let bank_v6 = rule_count_v6.get(&0, 0).map_or(0, generation_bank);

        crate::ebpf::connection_limits::publish_live_banks(bank_v4, bank_v6);

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
            bank_v4,
            bank_v6,
            hash_counts_v4: (0, 0),
            ct_gate,
            // Every half starts asserted so the gate is open until a load has
            // actually proved otherwise. A firewall that probes conntrack it
            // did not need is slow; one that skips a probe it needed is wrong.
            v4_needs_ct: true,
            v6_needs_ct: true,
            policy_needs_ct: true,
            source_limits_need_ct: false,
            shadow,
        })
    }
}

impl FirewallMapManager {
    /// Remove every fast-path entry belonging to `bank`.
    ///
    /// eBPF `HashMap` maps have no bulk clear, so the keys are walked. Called
    /// on the bank about to be written, to drop what an abandoned reload left
    /// there, and on the bank just retired. Neither is the bank the datapath
    /// reads, so a key left behind by a failed removal decides nothing.
    fn drop_hash_bank(&mut self, bank: u8) {
        if let Some(ref mut map) = self.hash_5tuple {
            let keys: Vec<FwHashKey5Tuple> = map
                .keys()
                .filter_map(Result::ok)
                .filter(|k| k.bank == bank)
                .collect();
            for key in &keys {
                let _ = map.remove(key);
            }
        }
        if let Some(ref mut map) = self.hash_port {
            let keys: Vec<FwHashKeyPort> = map
                .keys()
                .filter_map(Result::ok)
                .filter(|k| k.bank == bank)
                .collect();
            for key in &keys {
                let _ = map.remove(key);
            }
        }
    }

    /// Publish which fast paths the enforced IPv4 bank leaves empty.
    fn publish_hash_gates(&self) {
        feature_gates::publish(Feature::Hash5Tuple, self.hash_counts_v4.0 == 0);
        feature_gates::publish(Feature::HashPort, self.hash_counts_v4.1 == 0);
    }

    /// Say whether a per-source connection ceiling is configured, so the
    /// conntrack gate stays open for it.
    pub fn set_source_limits(&mut self, configured: bool) {
        self.source_limits_need_ct = configured;
        self.sync_ct_gate();
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
            || self.source_limits_need_ct
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
        let flags = routing_flags(rule);
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

/// The match flags a rule is routed by. An address matched under a zero
/// mask matches every address, which is what a rule naming `0.0.0.0/0` says
/// (the anti-lockout rules name it so their IPv4 copy is told from the IPv6
/// one), so it routes as a rule naming no address: otherwise every default
/// configuration starts with an array rule and demotes each fast-path rule
/// after it.
fn routing_flags(rule: &FirewallRuleEntry) -> u8 {
    let mut flags = rule.match_flags;
    if rule.src_mask == 0 {
        flags &= !MATCH_SRC_IP;
    }
    if rule.dst_mask == 0 {
        flags &= !MATCH_DST_IP;
    }
    flags
}

/// Called after each map write of a reload. Production passes one that does
/// nothing; the in-kernel test passes one that runs a packet through the
/// program at that point, and one that fails, to stand in for a refused write.
pub(crate) type ReloadStep<'a> = &'a mut dyn FnMut() -> Result<(), DomainError>;

/// What a bank write left: the placements, the array count, and the
/// five-tuple and port entry counts.
type WrittenBank = (Vec<RulePlacement>, usize, (u32, u32));

fn map_err(what: String) -> impl FnOnce(aya::maps::MapError) -> DomainError {
    move |e| DomainError::EngineError(format!("{what} failed: {e}"))
}

impl FirewallMapManager {
    /// Load the IPv4 rules into the bank the datapath does not read, then
    /// publish that bank. See the type's reload protocol.
    #[allow(clippy::cast_possible_truncation)] // count ≤ MAX_FIREWALL_RULES (4096), bank ≤ 1
    pub(crate) fn load_v4_stepwise(
        &mut self,
        rules: &[FirewallRuleEntry],
        step: ReloadStep<'_>,
    ) -> Result<Vec<RulePlacement>, DomainError> {
        let current = self.bank_v4;
        let next = 1 - current;
        // Both fast paths may hold entries of the next bank from here on, so
        // neither may be skipped until the flip says which bank is read.
        feature_gates::publish(Feature::Hash5Tuple, false);
        feature_gates::publish(Feature::HashPort, false);
        self.drop_hash_bank(next as u8);

        match self.write_v4_bank(rules, next, step) {
            Ok((placements, count, hash_counts)) => {
                self.bank_v4 = next;
                crate::ebpf::connection_limits::publish_live_banks(self.bank_v4, self.bank_v6);
                self.hash_counts_v4 = hash_counts;
                self.drop_hash_bank(current as u8);
                self.publish_hash_gates();
                self.cached_v4_count = count + (hash_counts.0 + hash_counts.1) as usize;
                self.v4_needs_ct = rules
                    .iter()
                    .any(|r| rule_reads_ct(r.match_flags, r.max_states));
                self.sync_ct_gate();
                info!(
                    bank = next,
                    array_count = count,
                    hash_5tuple = hash_counts.0,
                    hash_port = hash_counts.1,
                    "V4 firewall rules loaded (multi-level)"
                );
                Ok(placements)
            }
            Err(e) => {
                // The generation word was never flipped: the datapath still
                // enforces the previous set, whole.
                self.drop_hash_bank(next as u8);
                self.publish_hash_gates();
                warn!(error = %e, bank = current, "V4 reload abandoned, the previous rules stay enforced");
                Err(e)
            }
        }
    }

    /// Write `rules` into `bank`, fast-path keys and array, and flip the
    /// generation word to it as the last write. Returns the placements, the
    /// array count and the fast-path counts.
    #[allow(clippy::cast_possible_truncation)] // count ≤ MAX_FIREWALL_RULES (4096), bank ≤ 1
    fn write_v4_bank(
        &mut self,
        rules: &[FirewallRuleEntry],
        bank: u32,
        step: ReloadStep<'_>,
    ) -> Result<WrittenBank, DomainError> {
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
                            bank: bank as u8,
                            _pad: [0; 2],
                        };
                        map.insert(&key, &val, 0)
                            .map_err(map_err("insert V4 five-tuple entry".into()))?;
                        step()?;
                        placements.push(RulePlacement::Hash5Tuple);
                        hash_5tuple_count += 1;
                    }
                }
                Route::Port((dst_port, protocol)) => {
                    if let Some(ref mut map) = self.hash_port {
                        let key = FwHashKeyPort {
                            dst_port,
                            protocol,
                            bank: bank as u8,
                        };
                        map.insert(&key, &val, 0)
                            .map_err(map_err("insert V4 port entry".into()))?;
                        step()?;
                        placements.push(RulePlacement::HashPort);
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

        let count = array_rules.len().min(MAX_FIREWALL_RULES as usize);
        let base = bank_base(bank);
        for (i, rule) in array_rules.iter().take(count).enumerate() {
            self.rules_v4
                .set(base + i as u32, rule, 0)
                .map_err(map_err(format!("set V4 rule[{i}]")))?;
            step()?;
        }
        self.rule_count_v4
            .set(0, &rule_generation(bank, count as u32), 0)
            .map_err(map_err("publish the V4 rules".into()))?;
        step()?;
        Ok((placements, count, (hash_5tuple_count, hash_port_count)))
    }

    /// Load the IPv6 rules into the bank the datapath does not read, then
    /// publish that bank, as `load_v4_stepwise` does.
    #[allow(clippy::cast_possible_truncation)] // count ≤ MAX_FIREWALL_RULES (4096)
    pub(crate) fn load_v6_stepwise(
        &mut self,
        rules: &[FirewallRuleEntryV6],
        step: ReloadStep<'_>,
    ) -> Result<Vec<RulePlacement>, DomainError> {
        let next = 1 - self.bank_v6;
        let count = rules.len().min(MAX_FIREWALL_RULES as usize);
        let base = bank_base(next);
        let written = (|| {
            for (i, rule) in rules.iter().take(count).enumerate() {
                self.rules_v6
                    .set(base + i as u32, rule, 0)
                    .map_err(map_err(format!("set V6 rule[{i}]")))?;
                step()?;
            }
            self.rule_count_v6
                .set(0, &rule_generation(next, count as u32), 0)
                .map_err(map_err("publish the V6 rules".into()))?;
            step()
        })();
        if let Err(e) = written {
            warn!(error = %e, bank = self.bank_v6, "V6 reload abandoned, the previous rules stay enforced");
            return Err(e);
        }

        self.bank_v6 = next;
        crate::ebpf::connection_limits::publish_live_banks(self.bank_v4, self.bank_v6);
        self.cached_v6_count = count;
        self.v6_needs_ct = rules
            .iter()
            .any(|r| rule_reads_ct(r.match_flags, r.max_states));
        self.sync_ct_gate();
        info!(
            bank = next,
            count, "V6 firewall rules loaded into eBPF array"
        );
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
}

impl FirewallArrayMapPort for FirewallMapManager {
    fn load_v4_rules(
        &mut self,
        rules: &[FirewallRuleEntry],
    ) -> Result<Vec<RulePlacement>, DomainError> {
        self.load_v4_stepwise(rules, &mut || Ok(()))
    }

    fn load_v6_rules(
        &mut self,
        rules: &[FirewallRuleEntryV6],
    ) -> Result<Vec<RulePlacement>, DomainError> {
        self.load_v6_stepwise(rules, &mut || Ok(()))
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

    fn set_source_limits(&mut self, enforced: bool) {
        FirewallMapManager::set_source_limits(self, enforced);
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
    fn a_port_rule_naming_any_ipv4_address_stays_on_the_port_map() {
        // The shape of an anti-lockout rule: every default configuration
        // starts with one, and the isolation that follows keeps its 5-tuple.
        let mut any = port_rule(22, 1);
        any.match_flags |= MATCH_DST_IP;
        any.dst_ip = 0;
        any.dst_mask = 0;
        let routes = route_v4(&[any, fast_path_candidate()], true, true);
        assert_eq!(routes[0], Route::Port((22, 6)));
        assert!(matches!(routes[1], Route::FiveTuple(_)));
    }

    #[test]
    fn without_the_port_map_a_port_rule_goes_to_the_array() {
        assert_eq!(
            route_v4(&[port_rule(53, 1)], true, false),
            vec![Route::Array]
        );
    }

    /// The in-kernel half: the firewall object loaded for real, and a packet
    /// a rule denies pushed through it after every single map write of a
    /// reload. Needs the built objects and the privilege to load them; without
    /// either it says so and returns, as the program harness does, except
    /// where `EBPFSENTINEL_EBPF_DIR` names the objects: a job that set it
    /// promised them, and their absence there is a broken build step.
    mod in_kernel {
        use super::*;
        use crate::ebpf::loader::EbpfLoader;
        use crate::ebpf::prog_test_run::{self, XDP_DROP};
        use ebpf_common::firewall::ACTION_DROP;
        use std::os::fd::{AsFd, OwnedFd};
        use std::path::PathBuf;

        fn object() -> Option<Vec<u8>> {
            let dir = std::env::var("EBPFSENTINEL_EBPF_DIR").map_or_else(
                |_| {
                    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                        .join("../../target/bpfel-unknown-none/release")
                },
                PathBuf::from,
            );
            let bytes = std::fs::read(dir.join("xdp-firewall")).ok();
            if bytes.is_none() {
                assert!(
                    std::env::var_os("EBPFSENTINEL_EBPF_DIR").is_none(),
                    "EBPFSENTINEL_EBPF_DIR names {}, which holds no xdp-firewall object",
                    dir.display()
                );
                eprintln!("skipped: no xdp-firewall object in {}", dir.display());
            }
            bytes
        }

        /// The firewall loaded, its maps handed to a manager, its entry
        /// program's descriptor, and a pass-by-default policy, so a drop can
        /// only come from a rule.
        fn firewall() -> Option<(EbpfLoader, FirewallMapManager, OwnedFd)> {
            let bytes = object()?;
            let mut loaded = match EbpfLoader::load_unpinned(&bytes) {
                Ok(loaded) => loaded,
                Err(e) => {
                    eprintln!("skipped: cannot load eBPF objects here: {e}");
                    return None;
                }
            };
            let mut manager = FirewallMapManager::new(loaded.ebpf_mut()).expect("firewall maps");
            manager
                .set_default_policy(ACTION_PASS)
                .expect("default policy");
            let fd = loaded
                .program_fd_owned("xdp_firewall")
                .expect("xdp_firewall entry program");
            Some((loaded, manager, fd))
        }

        /// 10.0.0.1:1024 to 10.0.0.2:80, or `fd00::1` to `fd00::2`.
        fn syn(v6: bool) -> Vec<u8> {
            let mut pkt = vec![0x02, 0, 0, 0, 0, 0x01, 0x02, 0, 0, 0, 0, 0x02];
            if v6 {
                pkt.extend_from_slice(&[0x86, 0xdd, 0x60, 0, 0, 0, 0x00, 0x14, 0x06, 0x40]);
                pkt.extend_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
                pkt.extend_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
            } else {
                pkt.extend_from_slice(&[0x08, 0x00, 0x45, 0x00, 0x00, 0x28, 0x00, 0x01]);
                pkt.extend_from_slice(&[0x00, 0x00, 0x40, 0x06, 0x00, 0x00]);
                pkt.extend_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
            }
            pkt.extend_from_slice(&[0x04, 0x00, 0x00, 0x50, 0, 0, 0, 1, 0, 0, 0, 0]);
            pkt.extend_from_slice(&[0x50, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00]);
            pkt
        }

        /// Whether the program drops `packet`, or `None` where the kernel
        /// will not run it here.
        fn drops(fd: &OwnedFd, packet: &[u8]) -> Option<bool> {
            match prog_test_run::run(fd.as_fd(), packet, 1) {
                Ok(outcome) => Some(outcome.retval == XDP_DROP),
                Err(e) if e.is_unavailable() => {
                    eprintln!("skipped: {e}");
                    None
                }
                Err(e) => panic!("xdp_firewall could not be run: {e}"),
            }
        }

        /// A TCP rule on a destination port range, with `action`.
        fn ports(start: u16, end: u16, action: u8) -> FirewallRuleEntry {
            let mut rule = port_rule(start, action);
            rule.dst_port_end = end;
            rule
        }

        fn ports_v6(start: u16, end: u16, action: u8) -> FirewallRuleEntryV6 {
            FirewallRuleEntryV6 {
                src_addr: [0; 4],
                src_mask: [0; 4],
                dst_addr: [0; 4],
                dst_mask: [0; 4],
                src_port_start: 0,
                src_port_end: 0,
                dst_port_start: start,
                dst_port_end: end,
                protocol: 6,
                match_flags: MATCH_DST_PORT | MATCH_PROTO,
                vlan_id: VLAN_ANY,
                action,
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
        fn a_denied_packet_stays_denied_through_every_step_of_a_reload() {
            let Some((_loaded, mut manager, fd)) = firewall() else {
                return;
            };
            let packet = syn(false);
            // The deny on port 80 sits on the port fast path in one set and
            // in the array behind a ranged allow in the other, so a reload
            // between them moves it from one map to another. Before the
            // banks, both directions opened port 80 for a moment: the fast
            // path was flushed before the array was written, and the array
            // was read with its count at zero while it was rewritten.
            let on_fast_path = [port_rule(80, ACTION_DROP), ports(8000, 8100, ACTION_DROP)];
            let in_array = [
                ports(20, 23, ACTION_PASS),
                port_rule(80, ACTION_DROP),
                ports(1, 65535, ACTION_PASS),
            ];
            manager.load_v4_rules(&on_fast_path).expect("first load");
            let Some(dropped) = drops(&fd, &packet) else {
                return;
            };
            assert!(dropped, "the first set must deny port 80");

            for (name, rules) in [
                ("into the array", &in_array[..]),
                ("onto the fast path", &on_fast_path[..]),
                ("into the array again", &in_array[..]),
            ] {
                let mut steps = 0usize;
                manager
                    .load_v4_stepwise(rules, &mut || {
                        steps += 1;
                        assert_eq!(
                            drops(&fd, &packet),
                            Some(true),
                            "port 80 opened at write {steps} of the reload {name}"
                        );
                        Ok(())
                    })
                    .expect("reload");
                assert!(steps > 1, "the reload {name} wrote nothing");
                assert_eq!(drops(&fd, &packet), Some(true), "after the reload {name}");
            }
        }

        #[test]
        fn a_reload_refused_part_way_leaves_the_previous_rules_enforced() {
            let Some((_loaded, mut manager, fd)) = firewall() else {
                return;
            };
            let packet = syn(false);
            manager
                .load_v4_rules(&[ports(70, 90, ACTION_DROP)])
                .expect("first load");
            let Some(true) = drops(&fd, &packet) else {
                return;
            };
            // The new set would let port 80 through; the second write is
            // refused, so it must never take effect.
            let allow = [ports(1, 65535, ACTION_PASS), ports(70, 90, ACTION_DROP)];
            let mut steps = 0usize;
            let refused = manager.load_v4_stepwise(&allow, &mut || {
                steps += 1;
                if steps == 2 {
                    return Err(DomainError::EngineError("refused".into()));
                }
                Ok(())
            });
            assert!(refused.is_err(), "a refused write is the reload's error");
            assert_eq!(drops(&fd, &packet), Some(true), "the previous deny holds");
            // The bank left half written is rewritten whole by the next load.
            manager
                .load_v4_rules(&allow)
                .expect("reload after a refusal");
            assert_eq!(drops(&fd, &packet), Some(false), "the new set took effect");
        }

        #[test]
        fn an_ipv6_reload_keeps_the_deny_through_every_step() {
            let Some((_loaded, mut manager, fd)) = firewall() else {
                return;
            };
            let packet = syn(true);
            manager
                .load_v6_rules(&[ports_v6(80, 80, ACTION_DROP)])
                .expect("first load");
            let Some(true) = drops(&fd, &packet) else {
                return;
            };
            let shifted = [
                ports_v6(20, 23, ACTION_PASS),
                ports_v6(80, 80, ACTION_DROP),
                ports_v6(1, 65535, ACTION_PASS),
            ];
            let mut steps = 0usize;
            manager
                .load_v6_stepwise(&shifted, &mut || {
                    steps += 1;
                    assert_eq!(
                        drops(&fd, &packet),
                        Some(true),
                        "port 80 opened at write {steps} of the IPv6 reload"
                    );
                    Ok(())
                })
                .expect("reload");
            assert_eq!(drops(&fd, &packet), Some(true));
        }
    }
}
