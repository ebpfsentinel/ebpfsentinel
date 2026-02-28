use aya::Ebpf;
use aya::maps::{Array, MapData};
use domain::common::error::DomainError;
use ebpf_common::nat::NatRuleEntry;
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
    cached_dnat_count: usize,
    cached_snat_count: usize,
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
        let snat_rules = Array::try_from(
            egress
                .take_map("NAT_SNAT_RULES")
                .ok_or_else(|| anyhow::anyhow!("map 'NAT_SNAT_RULES' not found in egress"))?,
        )?;
        let snat_count =
            Array::try_from(egress.take_map("NAT_SNAT_RULE_COUNT").ok_or_else(|| {
                anyhow::anyhow!("map 'NAT_SNAT_RULE_COUNT' not found in egress")
            })?)?;

        info!("NAT maps acquired (DNAT from ingress, SNAT from egress)");
        Ok(Self {
            dnat_rules,
            dnat_count,
            snat_rules,
            snat_count,
            cached_dnat_count: 0,
            cached_snat_count: 0,
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

    fn set_enabled(&mut self, enabled: bool) -> Result<(), DomainError> {
        if !enabled {
            // Disable by setting both counts to 0
            self.dnat_count
                .set(0, 0u32, 0)
                .map_err(|e| DomainError::EngineError(format!("disable DNAT failed: {e}")))?;
            self.snat_count
                .set(0, 0u32, 0)
                .map_err(|e| DomainError::EngineError(format!("disable SNAT failed: {e}")))?;
            self.cached_dnat_count = 0;
            self.cached_snat_count = 0;
            info!("NAT disabled (rule counts set to 0)");
        }
        Ok(())
    }

    fn rule_count(&self) -> Result<usize, DomainError> {
        Ok(self.cached_dnat_count + self.cached_snat_count)
    }
}
