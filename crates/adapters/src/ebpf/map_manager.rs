use aya::Ebpf;
use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::{Array, MapData};
use domain::common::error::DomainError;
use ebpf_common::firewall::{
    FirewallLpmEntryV4, FirewallLpmEntryV6, FirewallRuleEntry, FirewallRuleEntryV6, LpmValue,
    MAX_FIREWALL_RULES,
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
/// Atomic reload protocol: write count=0 → write entries → write count=n.
pub struct FirewallMapManager {
    rules_v4: Array<MapData, FirewallRuleEntry>,
    rule_count_v4: Array<MapData, u32>,
    rules_v6: Array<MapData, FirewallRuleEntryV6>,
    rule_count_v6: Array<MapData, u32>,
    default_policy: Array<MapData, u8>,
    lpm_src_v4: LpmTrie<MapData, [u8; 4], LpmValue>,
    lpm_dst_v4: LpmTrie<MapData, [u8; 4], LpmValue>,
    lpm_src_v6: LpmTrie<MapData, [u8; 16], LpmValue>,
    lpm_dst_v6: LpmTrie<MapData, [u8; 16], LpmValue>,
    /// Cached counts for `rule_count()` without map reads.
    cached_v4_count: usize,
    cached_v6_count: usize,
}

impl FirewallMapManager {
    /// Create a new `FirewallMapManager` by taking ownership of the
    /// five firewall maps from the loaded eBPF program.
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
        let lpm_src_v4 = LpmTrie::try_from(
            ebpf.take_map("FW_LPM_SRC_V4")
                .ok_or_else(|| anyhow::anyhow!("map 'FW_LPM_SRC_V4' not found"))?,
        )?;
        let lpm_dst_v4 = LpmTrie::try_from(
            ebpf.take_map("FW_LPM_DST_V4")
                .ok_or_else(|| anyhow::anyhow!("map 'FW_LPM_DST_V4' not found"))?,
        )?;
        let lpm_src_v6 = LpmTrie::try_from(
            ebpf.take_map("FW_LPM_SRC_V6")
                .ok_or_else(|| anyhow::anyhow!("map 'FW_LPM_SRC_V6' not found"))?,
        )?;
        let lpm_dst_v6 = LpmTrie::try_from(
            ebpf.take_map("FW_LPM_DST_V6")
                .ok_or_else(|| anyhow::anyhow!("map 'FW_LPM_DST_V6' not found"))?,
        )?;

        info!("firewall maps acquired (arrays + LPM tries + default_policy)");
        Ok(Self {
            rules_v4,
            rule_count_v4,
            rules_v6,
            rule_count_v6,
            default_policy,
            lpm_src_v4,
            lpm_dst_v4,
            lpm_src_v6,
            lpm_dst_v6,
            cached_v4_count: 0,
            cached_v6_count: 0,
        })
    }
}

impl FirewallArrayMapPort for FirewallMapManager {
    #[allow(clippy::cast_possible_truncation)] // count ≤ MAX_FIREWALL_RULES (4096)
    fn load_v4_rules(&mut self, rules: &[FirewallRuleEntry]) -> Result<(), DomainError> {
        let count = rules.len().min(MAX_FIREWALL_RULES as usize);

        // Step 1: Set count to 0 (atomic: XDP sees 0 rules during update)
        self.rule_count_v4
            .set(0, 0u32, 0)
            .map_err(|e| DomainError::EngineError(format!("set V4 count=0 failed: {e}")))?;

        // Step 2: Write entries
        for (i, rule) in rules.iter().take(count).enumerate() {
            self.rules_v4
                .set(i as u32, *rule, 0)
                .map_err(|e| DomainError::EngineError(format!("set V4 rule[{i}] failed: {e}")))?;
        }

        // Step 3: Set count to n (atomic: XDP now sees all rules)
        self.rule_count_v4
            .set(0, count as u32, 0)
            .map_err(|e| DomainError::EngineError(format!("set V4 count={count} failed: {e}")))?;

        self.cached_v4_count = count;
        info!(count, "V4 firewall rules loaded into eBPF array");
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

    fn load_lpm_v4_rules(
        &mut self,
        src_rules: &[FirewallLpmEntryV4],
        dst_rules: &[FirewallLpmEntryV4],
    ) -> Result<(), DomainError> {
        // Clear existing src LPM entries
        let src_keys: Vec<Key<[u8; 4]>> = self.lpm_src_v4.keys().filter_map(Result::ok).collect();
        for key in &src_keys {
            let _ = self.lpm_src_v4.remove(key);
        }
        // Insert src rules
        for entry in src_rules {
            let key = Key::new(entry.prefix_len, entry.addr);
            let value = LpmValue {
                action: entry.action,
                _padding: [0; 3],
            };
            self.lpm_src_v4
                .insert(&key, value, 0)
                .map_err(|e| DomainError::EngineError(format!("LPM src V4 insert failed: {e}")))?;
        }

        // Clear existing dst LPM entries
        let dst_keys: Vec<Key<[u8; 4]>> = self.lpm_dst_v4.keys().filter_map(Result::ok).collect();
        for key in &dst_keys {
            let _ = self.lpm_dst_v4.remove(key);
        }
        // Insert dst rules
        for entry in dst_rules {
            let key = Key::new(entry.prefix_len, entry.addr);
            let value = LpmValue {
                action: entry.action,
                _padding: [0; 3],
            };
            self.lpm_dst_v4
                .insert(&key, value, 0)
                .map_err(|e| DomainError::EngineError(format!("LPM dst V4 insert failed: {e}")))?;
        }

        info!(
            src_count = src_rules.len(),
            dst_count = dst_rules.len(),
            "LPM V4 firewall rules loaded"
        );
        Ok(())
    }

    fn load_lpm_v6_rules(
        &mut self,
        src_rules: &[FirewallLpmEntryV6],
        dst_rules: &[FirewallLpmEntryV6],
    ) -> Result<(), DomainError> {
        // Clear existing src LPM entries
        let src_keys: Vec<Key<[u8; 16]>> = self.lpm_src_v6.keys().filter_map(Result::ok).collect();
        for key in &src_keys {
            let _ = self.lpm_src_v6.remove(key);
        }
        // Insert src rules
        for entry in src_rules {
            let key = Key::new(entry.prefix_len, entry.addr);
            let value = LpmValue {
                action: entry.action,
                _padding: [0; 3],
            };
            self.lpm_src_v6
                .insert(&key, value, 0)
                .map_err(|e| DomainError::EngineError(format!("LPM src V6 insert failed: {e}")))?;
        }

        // Clear existing dst LPM entries
        let dst_keys: Vec<Key<[u8; 16]>> = self.lpm_dst_v6.keys().filter_map(Result::ok).collect();
        for key in &dst_keys {
            let _ = self.lpm_dst_v6.remove(key);
        }
        // Insert dst rules
        for entry in dst_rules {
            let key = Key::new(entry.prefix_len, entry.addr);
            let value = LpmValue {
                action: entry.action,
                _padding: [0; 3],
            };
            self.lpm_dst_v6
                .insert(&key, value, 0)
                .map_err(|e| DomainError::EngineError(format!("LPM dst V6 insert failed: {e}")))?;
        }

        info!(
            src_count = src_rules.len(),
            dst_count = dst_rules.len(),
            "LPM V6 firewall rules loaded"
        );
        Ok(())
    }
}
