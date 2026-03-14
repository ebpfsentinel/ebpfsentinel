use aya::Ebpf;
use aya::maps::{Array, MapData};
use domain::common::error::DomainError;
use ebpf_common::nat::{HairpinConfig, NatRuleEntry, NatRuleEntryV6, NptV6RuleEntry};
use ports::secondary::nat_map_port::NatMapPort;
use tracing::info;

/// Manages the eBPF NAT rule maps.
///
/// Uses 4 maps across two programs:
/// - `NAT_DNAT_RULES` + `NAT_DNAT_RULE_COUNT` from tc-nat-ingress
/// - `NAT_SNAT_RULES` + `NAT_SNAT_RULE_COUNT` from tc-nat-egress
///
/// Atomic reload protocol: count=0 → write entries → count=n.
pub struct NatMapManager {
    dnat_rules: Array<MapData, NatRuleEntry>,
    dnat_count: Array<MapData, u32>,
    snat_rules: Array<MapData, NatRuleEntry>,
    snat_count: Array<MapData, u32>,
    dnat_rules_v6: Array<MapData, NatRuleEntryV6>,
    dnat_count_v6: Array<MapData, u32>,
    snat_rules_v6: Array<MapData, NatRuleEntryV6>,
    snat_count_v6: Array<MapData, u32>,
    nptv6_rules_ingress: Array<MapData, NptV6RuleEntry>,
    nptv6_count_ingress: Array<MapData, u32>,
    nptv6_rules_egress: Array<MapData, NptV6RuleEntry>,
    nptv6_count_egress: Array<MapData, u32>,
    hairpin_config: Array<MapData, HairpinConfig>,
    cached_dnat_count: usize,
    cached_snat_count: usize,
    cached_dnat_count_v6: usize,
    cached_snat_count_v6: usize,
    cached_nptv6_count: usize,
}

impl NatMapManager {
    /// Create a `NatMapManager` by taking maps from both ingress and egress programs.
    pub fn from_ingress_egress(
        ingress: &mut Ebpf,
        egress: &mut Ebpf,
    ) -> Result<Self, anyhow::Error> {
        let dnat_rules = Array::try_from(
            ingress
                .take_map("NAT_DNAT_RULES")
                .ok_or_else(|| anyhow::anyhow!("map 'NAT_DNAT_RULES' not found in ingress"))?,
        )?;
        let dnat_count =
            Array::try_from(ingress.take_map("NAT_DNAT_RULE_COUNT").ok_or_else(|| {
                anyhow::anyhow!("map 'NAT_DNAT_RULE_COUNT' not found in ingress")
            })?)?;
        let dnat_rules_v6 = Array::try_from(
            ingress
                .take_map("NAT_DNAT_RULES_V6")
                .ok_or_else(|| anyhow::anyhow!("map 'NAT_DNAT_RULES_V6' not found in ingress"))?,
        )?;
        let dnat_count_v6 =
            Array::try_from(ingress.take_map("NAT_DNAT_RULE_COUNT_V6").ok_or_else(|| {
                anyhow::anyhow!("map 'NAT_DNAT_RULE_COUNT_V6' not found in ingress")
            })?)?;
        let snat_rules = Array::try_from(
            egress
                .take_map("NAT_SNAT_RULES")
                .ok_or_else(|| anyhow::anyhow!("map 'NAT_SNAT_RULES' not found in egress"))?,
        )?;
        let snat_count =
            Array::try_from(egress.take_map("NAT_SNAT_RULE_COUNT").ok_or_else(|| {
                anyhow::anyhow!("map 'NAT_SNAT_RULE_COUNT' not found in egress")
            })?)?;
        let snat_rules_v6 = Array::try_from(
            egress
                .take_map("NAT_SNAT_RULES_V6")
                .ok_or_else(|| anyhow::anyhow!("map 'NAT_SNAT_RULES_V6' not found in egress"))?,
        )?;
        let snat_count_v6 =
            Array::try_from(egress.take_map("NAT_SNAT_RULE_COUNT_V6").ok_or_else(|| {
                anyhow::anyhow!("map 'NAT_SNAT_RULE_COUNT_V6' not found in egress")
            })?)?;

        let nptv6_rules_ingress = Array::try_from(
            ingress
                .take_map("NPTV6_RULES")
                .ok_or_else(|| anyhow::anyhow!("map 'NPTV6_RULES' not found in ingress"))?,
        )?;
        let nptv6_count_ingress = Array::try_from(
            ingress
                .take_map("NPTV6_RULE_COUNT")
                .ok_or_else(|| anyhow::anyhow!("map 'NPTV6_RULE_COUNT' not found in ingress"))?,
        )?;
        let nptv6_rules_egress = Array::try_from(
            egress
                .take_map("NPTV6_RULES")
                .ok_or_else(|| anyhow::anyhow!("map 'NPTV6_RULES' not found in egress"))?,
        )?;
        let nptv6_count_egress = Array::try_from(
            egress
                .take_map("NPTV6_RULE_COUNT")
                .ok_or_else(|| anyhow::anyhow!("map 'NPTV6_RULE_COUNT' not found in egress"))?,
        )?;

        let hairpin_config =
            Array::try_from(ingress.take_map("NAT_HAIRPIN_CONFIG").ok_or_else(|| {
                anyhow::anyhow!("map 'NAT_HAIRPIN_CONFIG' not found in ingress")
            })?)?;

        info!("NAT maps acquired (DNAT/SNAT V4+V6 + NPTv6 + hairpin from ingress/egress)");
        Ok(Self {
            dnat_rules,
            dnat_count,
            snat_rules,
            snat_count,
            dnat_rules_v6,
            dnat_count_v6,
            snat_rules_v6,
            snat_count_v6,
            nptv6_rules_ingress,
            nptv6_count_ingress,
            nptv6_rules_egress,
            nptv6_count_egress,
            hairpin_config,
            cached_dnat_count: 0,
            cached_snat_count: 0,
            cached_dnat_count_v6: 0,
            cached_snat_count_v6: 0,
            cached_nptv6_count: 0,
        })
    }
}

impl NatMapPort for NatMapManager {
    #[allow(clippy::cast_possible_truncation)]
    fn load_dnat_rules(&mut self, rules: &[NatRuleEntry]) -> Result<(), DomainError> {
        let count = rules.len().min(ebpf_common::nat::MAX_NAT_RULES as usize);

        // Step 1: Set count to 0
        self.dnat_count
            .set(0, 0u32, 0)
            .map_err(|e| DomainError::EngineError(format!("set DNAT count=0 failed: {e}")))?;

        // Step 2: Write entries
        for (i, rule) in rules.iter().take(count).enumerate() {
            self.dnat_rules
                .set(i as u32, *rule, 0)
                .map_err(|e| DomainError::EngineError(format!("set DNAT rule[{i}] failed: {e}")))?;
        }

        // Step 3: Set count to n
        self.dnat_count
            .set(0, count as u32, 0)
            .map_err(|e| DomainError::EngineError(format!("set DNAT count={count} failed: {e}")))?;

        self.cached_dnat_count = count;
        info!(count, "DNAT rules loaded into eBPF array");
        Ok(())
    }

    #[allow(clippy::cast_possible_truncation)]
    fn load_snat_rules(&mut self, rules: &[NatRuleEntry]) -> Result<(), DomainError> {
        let count = rules.len().min(ebpf_common::nat::MAX_NAT_RULES as usize);

        // Step 1: Set count to 0
        self.snat_count
            .set(0, 0u32, 0)
            .map_err(|e| DomainError::EngineError(format!("set SNAT count=0 failed: {e}")))?;

        // Step 2: Write entries
        for (i, rule) in rules.iter().take(count).enumerate() {
            self.snat_rules
                .set(i as u32, *rule, 0)
                .map_err(|e| DomainError::EngineError(format!("set SNAT rule[{i}] failed: {e}")))?;
        }

        // Step 3: Set count to n
        self.snat_count
            .set(0, count as u32, 0)
            .map_err(|e| DomainError::EngineError(format!("set SNAT count={count} failed: {e}")))?;

        self.cached_snat_count = count;
        info!(count, "SNAT rules loaded into eBPF array");
        Ok(())
    }

    #[allow(clippy::cast_possible_truncation)]
    fn load_dnat_rules_v6(&mut self, rules: &[NatRuleEntryV6]) -> Result<(), DomainError> {
        let count = rules.len().min(ebpf_common::nat::MAX_NAT_RULES_V6 as usize);

        self.dnat_count_v6
            .set(0, 0u32, 0)
            .map_err(|e| DomainError::EngineError(format!("set DNAT V6 count=0 failed: {e}")))?;

        for (i, rule) in rules.iter().take(count).enumerate() {
            self.dnat_rules_v6.set(i as u32, *rule, 0).map_err(|e| {
                DomainError::EngineError(format!("set DNAT V6 rule[{i}] failed: {e}"))
            })?;
        }

        self.dnat_count_v6.set(0, count as u32, 0).map_err(|e| {
            DomainError::EngineError(format!("set DNAT V6 count={count} failed: {e}"))
        })?;

        self.cached_dnat_count_v6 = count;
        info!(count, "DNAT V6 rules loaded into eBPF array");
        Ok(())
    }

    #[allow(clippy::cast_possible_truncation)]
    fn load_snat_rules_v6(&mut self, rules: &[NatRuleEntryV6]) -> Result<(), DomainError> {
        let count = rules.len().min(ebpf_common::nat::MAX_NAT_RULES_V6 as usize);

        self.snat_count_v6
            .set(0, 0u32, 0)
            .map_err(|e| DomainError::EngineError(format!("set SNAT V6 count=0 failed: {e}")))?;

        for (i, rule) in rules.iter().take(count).enumerate() {
            self.snat_rules_v6.set(i as u32, *rule, 0).map_err(|e| {
                DomainError::EngineError(format!("set SNAT V6 rule[{i}] failed: {e}"))
            })?;
        }

        self.snat_count_v6.set(0, count as u32, 0).map_err(|e| {
            DomainError::EngineError(format!("set SNAT V6 count={count} failed: {e}"))
        })?;

        self.cached_snat_count_v6 = count;
        info!(count, "SNAT V6 rules loaded into eBPF array");
        Ok(())
    }

    #[allow(clippy::cast_possible_truncation)]
    fn load_nptv6_rules(&mut self, rules: &[NptV6RuleEntry]) -> Result<(), DomainError> {
        let count = rules.len().min(ebpf_common::nat::MAX_NPTV6_RULES as usize);

        // Ingress: count=0 -> write entries -> count=n
        self.nptv6_count_ingress.set(0, 0u32, 0).map_err(|e| {
            DomainError::EngineError(format!("set NPTv6 ingress count=0 failed: {e}"))
        })?;
        for (i, rule) in rules.iter().take(count).enumerate() {
            self.nptv6_rules_ingress
                .set(i as u32, *rule, 0)
                .map_err(|e| {
                    DomainError::EngineError(format!("set NPTv6 ingress rule[{i}] failed: {e}"))
                })?;
        }
        self.nptv6_count_ingress
            .set(0, count as u32, 0)
            .map_err(|e| {
                DomainError::EngineError(format!("set NPTv6 ingress count={count} failed: {e}"))
            })?;

        // Egress: count=0 -> write entries -> count=n
        self.nptv6_count_egress.set(0, 0u32, 0).map_err(|e| {
            DomainError::EngineError(format!("set NPTv6 egress count=0 failed: {e}"))
        })?;
        for (i, rule) in rules.iter().take(count).enumerate() {
            self.nptv6_rules_egress
                .set(i as u32, *rule, 0)
                .map_err(|e| {
                    DomainError::EngineError(format!("set NPTv6 egress rule[{i}] failed: {e}"))
                })?;
        }
        self.nptv6_count_egress
            .set(0, count as u32, 0)
            .map_err(|e| {
                DomainError::EngineError(format!("set NPTv6 egress count={count} failed: {e}"))
            })?;

        self.cached_nptv6_count = count;
        info!(
            count,
            "NPTv6 rules loaded into eBPF arrays (ingress + egress)"
        );
        Ok(())
    }

    fn load_hairpin_config(&mut self, config: &HairpinConfig) -> Result<(), DomainError> {
        self.hairpin_config
            .set(0, *config, 0)
            .map_err(|e| DomainError::EngineError(format!("set NAT_HAIRPIN_CONFIG failed: {e}")))?;
        info!(
            enabled = config.enabled,
            "Hairpin NAT config loaded into eBPF array"
        );
        Ok(())
    }

    fn set_enabled(&mut self, enabled: bool) -> Result<(), DomainError> {
        if !enabled {
            // Disable by setting all counts to 0
            self.dnat_count
                .set(0, 0u32, 0)
                .map_err(|e| DomainError::EngineError(format!("disable DNAT failed: {e}")))?;
            self.snat_count
                .set(0, 0u32, 0)
                .map_err(|e| DomainError::EngineError(format!("disable SNAT failed: {e}")))?;
            self.dnat_count_v6
                .set(0, 0u32, 0)
                .map_err(|e| DomainError::EngineError(format!("disable DNAT V6 failed: {e}")))?;
            self.snat_count_v6
                .set(0, 0u32, 0)
                .map_err(|e| DomainError::EngineError(format!("disable SNAT V6 failed: {e}")))?;
            self.nptv6_count_ingress.set(0, 0u32, 0).map_err(|e| {
                DomainError::EngineError(format!("disable NPTv6 ingress failed: {e}"))
            })?;
            self.nptv6_count_egress.set(0, 0u32, 0).map_err(|e| {
                DomainError::EngineError(format!("disable NPTv6 egress failed: {e}"))
            })?;
            self.cached_dnat_count = 0;
            self.cached_snat_count = 0;
            self.cached_dnat_count_v6 = 0;
            self.cached_snat_count_v6 = 0;
            self.cached_nptv6_count = 0;
            info!("NAT disabled (all rule counts set to 0)");
        }
        Ok(())
    }

    fn rule_count(&self) -> Result<usize, DomainError> {
        Ok(self.cached_dnat_count
            + self.cached_snat_count
            + self.cached_dnat_count_v6
            + self.cached_snat_count_v6
            + self.cached_nptv6_count)
    }
}
