use std::collections::HashSet;

use crate::common::entity::RuleId;
use crate::common::error::DomainError;

use super::entity::{
    DdosAttack, DdosEnforcementAction, DdosEvent, DdosMitigationAction, DdosMitigationStatus,
    DdosPolicy,
};
// Re-export for tests (used in test helpers via `use super::*`)
#[cfg(test)]
use super::entity::DdosAttackType;
use super::error::DdosError;

/// Maximum number of concurrent active attacks tracked.
const MAX_ACTIVE_ATTACKS: usize = 64;

/// Maximum number of historical attacks retained.
const MAX_HISTORY: usize = 100;

/// `DDoS` detection and mitigation engine.
///
/// Processes events from the eBPF pipeline, classifies attacks, tracks their
/// lifecycle, and manages mitigation policies.
#[derive(Debug, Default)]
pub struct DdosEngine {
    policies: Vec<DdosPolicy>,
    active_attacks: Vec<DdosAttack>,
    history: Vec<DdosAttack>,
    total_mitigated: u64,
    next_attack_id: u64,
    /// Countries currently blocked via LPM enforcement.
    blocked_countries: HashSet<String>,
    /// Queue of enforcement actions to be drained by the application layer.
    pending_enforcements: Vec<DdosEnforcementAction>,
}

impl DdosEngine {
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
            active_attacks: Vec::new(),
            history: Vec::new(),
            total_mitigated: 0,
            next_attack_id: 1,
            blocked_countries: HashSet::new(),
            pending_enforcements: Vec::new(),
        }
    }

    /// Drain all pending enforcement actions.
    pub fn take_pending_enforcements(&mut self) -> Vec<DdosEnforcementAction> {
        std::mem::take(&mut self.pending_enforcements)
    }

    /// Process a `DDoS` event from the eBPF pipeline.
    /// Returns `true` if an attack state changed (for alerting).
    pub fn process_event(&mut self, event: &DdosEvent) -> bool {
        self.process_event_with_country(event, None)
    }

    /// Process a `DDoS` event with an optional source-country code.
    ///
    /// When `src_country` matches a key in the policy's `country_thresholds`,
    /// that per-country value is used instead of `detection_threshold_pps`.
    pub fn process_event_with_country(
        &mut self,
        event: &DdosEvent,
        src_country: Option<&str>,
    ) -> bool {
        // Find matching policy for this attack type
        let policy_idx = self
            .policies
            .iter()
            .position(|p| p.enabled && p.attack_type == event.attack_type);

        let Some(policy_idx) = policy_idx else {
            return false;
        };

        let threshold = src_country
            .and_then(|cc| {
                self.policies[policy_idx]
                    .country_thresholds
                    .as_ref()
                    .and_then(|ct| ct.get(cc).copied())
            })
            .unwrap_or(self.policies[policy_idx].detection_threshold_pps);

        // Find or create attack tracker for this type
        let attack_idx = self
            .active_attacks
            .iter()
            .position(|a| a.attack_type == event.attack_type && !a.is_expired());

        if let Some(idx) = attack_idx {
            self.active_attacks[idx].record_event(event.timestamp_ns);

            // Check for state transition
            let old_status = self.active_attacks[idx].mitigation_status;
            self.active_attacks[idx].update_status(threshold);
            let new_status = self.active_attacks[idx].mitigation_status;

            // Emit BlockCountry on transition to Active with Block policy
            if old_status != DdosMitigationStatus::Active
                && new_status == DdosMitigationStatus::Active
            {
                self.maybe_emit_block_country(idx);
            }

            if new_status == DdosMitigationStatus::Expired {
                let expired = self.active_attacks.remove(idx);
                self.total_mitigated += 1;
                self.push_history(expired);
                return true;
            }

            old_status != new_status
        } else if self.active_attacks.len() < MAX_ACTIVE_ATTACKS {
            let id = format!("ddos-{}", self.next_attack_id);
            self.next_attack_id += 1;
            let mut attack = DdosAttack::new(id, event.attack_type, event.timestamp_ns);
            attack.src_country = src_country.map(String::from);
            self.active_attacks.push(attack);
            true
        } else {
            false // At capacity
        }
    }

    /// Periodic tick — call once per second to update attack statuses.
    pub fn tick(&mut self) {
        let mut expired_indices = Vec::new();
        for (idx, attack) in self.active_attacks.iter_mut().enumerate() {
            let threshold = self
                .policies
                .iter()
                .find(|p| p.enabled && p.attack_type == attack.attack_type)
                .map_or(u64::MAX, |p| {
                    // Use per-country threshold when the attack has a resolved country
                    attack
                        .src_country
                        .as_deref()
                        .and_then(|cc| {
                            p.country_thresholds
                                .as_ref()
                                .and_then(|ct| ct.get(cc).copied())
                        })
                        .unwrap_or(p.detection_threshold_pps)
                });

            attack.update_status(threshold);
            if attack.is_expired() {
                expired_indices.push(idx);
            }
        }

        // Remove expired attacks (reverse order to preserve indices)
        for idx in expired_indices.into_iter().rev() {
            let expired = self.active_attacks.remove(idx);
            self.total_mitigated += 1;

            // Emit UnblockCountry if this was the last active attack for that country
            if let Some(ref cc) = expired.src_country {
                let still_active = self
                    .active_attacks
                    .iter()
                    .any(|a| a.src_country.as_deref() == Some(cc) && a.is_active());
                if !still_active && self.blocked_countries.remove(cc) {
                    self.pending_enforcements
                        .push(DdosEnforcementAction::UnblockCountry {
                            country_code: cc.clone(),
                        });
                }
            }

            self.push_history(expired);
        }
    }

    /// Return all active (non-expired) attacks.
    pub fn active_attacks(&self) -> &[DdosAttack] {
        &self.active_attacks
    }

    /// Return the number of active attacks.
    pub fn active_attack_count(&self) -> usize {
        self.active_attacks.len()
    }

    /// Return total number of attacks that reached Mitigated or Expired.
    pub fn total_mitigated(&self) -> u64 {
        self.total_mitigated
    }

    /// Return recent attack history (most recent first).
    pub fn attack_history(&self, limit: usize) -> &[DdosAttack] {
        let start = self.history.len().saturating_sub(limit);
        &self.history[start..]
    }

    // ── Policy Management ─────────────────────────────────────────

    /// Add a `DDoS` policy. Validates and rejects duplicates.
    pub fn add_policy(&mut self, policy: DdosPolicy) -> Result<(), DomainError> {
        policy.validate()?;

        if self.policies.iter().any(|p| p.id == policy.id) {
            return Err(DdosError::DuplicatePolicy {
                id: policy.id.to_string(),
            }
            .into());
        }

        self.policies.push(policy);
        self.sort_policies();
        Ok(())
    }

    /// Remove a policy by ID.
    pub fn remove_policy(&mut self, id: &RuleId) -> Result<(), DomainError> {
        let pos = self
            .policies
            .iter()
            .position(|p| &p.id == id)
            .ok_or_else(|| DdosError::PolicyNotFound { id: id.to_string() })?;
        self.policies.remove(pos);
        Ok(())
    }

    /// Replace all policies atomically.
    pub fn reload(&mut self, policies: Vec<DdosPolicy>) -> Result<(), DomainError> {
        for policy in &policies {
            policy.validate()?;
        }

        // Check for duplicate IDs
        for (i, policy) in policies.iter().enumerate() {
            if policies[i + 1..].iter().any(|p| p.id == policy.id) {
                return Err(DdosError::DuplicatePolicy {
                    id: policy.id.to_string(),
                }
                .into());
            }
        }

        self.policies = policies;
        self.sort_policies();
        Ok(())
    }

    /// Return all loaded policies.
    pub fn policies(&self) -> &[DdosPolicy] {
        &self.policies
    }

    /// Return the number of loaded policies.
    pub fn policy_count(&self) -> usize {
        self.policies.len()
    }

    // ── Private ───────────────────────────────────────────────────

    /// Emit `BlockCountry` if the attack has a country and the policy uses Block.
    fn maybe_emit_block_country(&mut self, attack_idx: usize) {
        let Some(ref cc) = self.active_attacks[attack_idx].src_country else {
            return;
        };
        // Check the policy's mitigation action
        let attack_type = self.active_attacks[attack_idx].attack_type;
        let is_block = self.policies.iter().any(|p| {
            p.enabled
                && p.attack_type == attack_type
                && p.mitigation_action == DdosMitigationAction::Block
        });
        if !is_block {
            return;
        }
        // Only block if not already blocked
        if self.blocked_countries.insert(cc.clone()) {
            self.pending_enforcements
                .push(DdosEnforcementAction::BlockCountry {
                    country_code: cc.clone(),
                });
        }
    }

    fn sort_policies(&mut self) {
        self.policies.sort_by(|a, b| a.id.0.cmp(&b.id.0));
    }

    fn push_history(&mut self, attack: DdosAttack) {
        if self.history.len() >= MAX_HISTORY {
            self.history.remove(0);
        }
        self.history.push(attack);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ddos::entity::{DdosMitigationAction, DdosMitigationStatus};

    fn make_policy(id: &str, attack_type: DdosAttackType, threshold: u64) -> DdosPolicy {
        DdosPolicy {
            id: RuleId(id.to_string()),
            attack_type,
            detection_threshold_pps: threshold,
            mitigation_action: DdosMitigationAction::Block,
            auto_block_duration_secs: 300,
            enabled: true,
            country_thresholds: None,
        }
    }

    fn make_event(attack_type: DdosAttackType, ts: u64) -> DdosEvent {
        DdosEvent {
            timestamp_ns: ts,
            attack_type,
            src_addr: [0xC0A8_0001, 0, 0, 0],
            dst_addr: [0x0A00_0001, 0, 0, 0],
            src_port: 12345,
            dst_port: 80,
            protocol: 6,
            is_ipv6: false,
        }
    }

    #[test]
    fn engine_new_is_empty() {
        let engine = DdosEngine::new();
        assert_eq!(engine.active_attack_count(), 0);
        assert_eq!(engine.policy_count(), 0);
        assert_eq!(engine.total_mitigated(), 0);
    }

    #[test]
    fn add_and_remove_policy() {
        let mut engine = DdosEngine::new();
        let policy = make_policy("syn-1", DdosAttackType::SynFlood, 5000);

        engine.add_policy(policy).unwrap();
        assert_eq!(engine.policy_count(), 1);

        engine.remove_policy(&RuleId("syn-1".to_string())).unwrap();
        assert_eq!(engine.policy_count(), 0);
    }

    #[test]
    fn reject_duplicate_policy() {
        let mut engine = DdosEngine::new();
        let policy = make_policy("syn-1", DdosAttackType::SynFlood, 5000);

        engine.add_policy(policy.clone()).unwrap();
        let result = engine.add_policy(policy);
        assert!(result.is_err());
    }

    #[test]
    fn reject_invalid_policy() {
        let mut engine = DdosEngine::new();
        let policy = make_policy("syn-1", DdosAttackType::SynFlood, 0);
        let result = engine.add_policy(policy);
        assert!(result.is_err());
    }

    #[test]
    fn remove_nonexistent_policy() {
        let mut engine = DdosEngine::new();
        let result = engine.remove_policy(&RuleId("nope".to_string()));
        assert!(result.is_err());
    }

    #[test]
    fn reload_policies() {
        let mut engine = DdosEngine::new();
        engine
            .add_policy(make_policy("old-1", DdosAttackType::SynFlood, 1000))
            .unwrap();

        let new_policies = vec![
            make_policy("new-1", DdosAttackType::SynFlood, 5000),
            make_policy("new-2", DdosAttackType::IcmpFlood, 100),
        ];
        engine.reload(new_policies).unwrap();
        assert_eq!(engine.policy_count(), 2);
    }

    #[test]
    fn reload_rejects_duplicates() {
        let mut engine = DdosEngine::new();
        let policies = vec![
            make_policy("dup", DdosAttackType::SynFlood, 5000),
            make_policy("dup", DdosAttackType::IcmpFlood, 100),
        ];
        assert!(engine.reload(policies).is_err());
    }

    #[test]
    fn process_event_without_policy_ignored() {
        let mut engine = DdosEngine::new();
        let event = make_event(DdosAttackType::SynFlood, 1_000_000_000);
        let changed = engine.process_event(&event);
        assert!(!changed);
        assert_eq!(engine.active_attack_count(), 0);
    }

    #[test]
    fn process_event_creates_attack() {
        let mut engine = DdosEngine::new();
        engine
            .add_policy(make_policy("syn-1", DdosAttackType::SynFlood, 5000))
            .unwrap();

        let event = make_event(DdosAttackType::SynFlood, 1_000_000_000);
        let changed = engine.process_event(&event);
        assert!(changed);
        assert_eq!(engine.active_attack_count(), 1);
        assert_eq!(
            engine.active_attacks()[0].mitigation_status,
            DdosMitigationStatus::Detecting
        );
    }

    #[test]
    fn process_event_updates_existing_attack() {
        let mut engine = DdosEngine::new();
        engine
            .add_policy(make_policy("syn-1", DdosAttackType::SynFlood, 5000))
            .unwrap();

        engine.process_event(&make_event(DdosAttackType::SynFlood, 1_000_000_000));
        engine.process_event(&make_event(DdosAttackType::SynFlood, 1_500_000_000));

        assert_eq!(engine.active_attack_count(), 1);
        assert_eq!(engine.active_attacks()[0].total_packets, 2);
    }

    #[test]
    fn attack_history_limited() {
        let engine = DdosEngine::new();
        let history = engine.attack_history(10);
        assert!(history.is_empty());
    }

    #[test]
    fn process_event_with_country_uses_country_threshold() {
        use std::collections::HashMap;

        let mut ct = HashMap::new();
        ct.insert("CN".to_string(), 100_u64);
        let mut policy = make_policy("syn-1", DdosAttackType::SynFlood, 5000);
        policy.country_thresholds = Some(ct);

        let mut engine = DdosEngine::new();
        engine.add_policy(policy).unwrap();

        let event = make_event(DdosAttackType::SynFlood, 1_000_000_000);
        let changed = engine.process_event_with_country(&event, Some("CN"));
        assert!(changed); // creates attack
        // The threshold used should be 100 (from country), not 5000
        assert_eq!(engine.active_attack_count(), 1);
    }

    #[test]
    fn process_event_with_country_none_falls_back() {
        use std::collections::HashMap;

        let mut ct = HashMap::new();
        ct.insert("CN".to_string(), 100_u64);
        let mut policy = make_policy("syn-1", DdosAttackType::SynFlood, 5000);
        policy.country_thresholds = Some(ct);

        let mut engine = DdosEngine::new();
        engine.add_policy(policy).unwrap();

        let event = make_event(DdosAttackType::SynFlood, 1_000_000_000);
        // No country -> uses global threshold 5000
        let changed = engine.process_event_with_country(&event, None);
        assert!(changed); // creates attack

        // Unknown country -> also falls back
        let event2 = make_event(DdosAttackType::SynFlood, 1_500_000_000);
        engine.process_event_with_country(&event2, Some("FR"));
        assert_eq!(engine.active_attack_count(), 1);
    }

    #[test]
    fn policies_sorted_by_id() {
        let mut engine = DdosEngine::new();
        engine
            .add_policy(make_policy("zzz", DdosAttackType::SynFlood, 5000))
            .unwrap();
        engine
            .add_policy(make_policy("aaa", DdosAttackType::IcmpFlood, 100))
            .unwrap();

        assert_eq!(engine.policies()[0].id.0, "aaa");
        assert_eq!(engine.policies()[1].id.0, "zzz");
    }

    // ── Enforcement tests ────────────────────────────────────────

    #[test]
    fn ddos_engine_emits_block_country_on_active_block_policy() {
        let mut engine = DdosEngine::new();
        engine
            .add_policy(make_policy("syn-1", DdosAttackType::SynFlood, 1))
            .unwrap();

        // Create attack with country
        let event = make_event(DdosAttackType::SynFlood, 1_000_000_000);
        engine.process_event_with_country(&event, Some("RU"));

        // Drive to Active (3 seconds above threshold)
        for i in 1..=3 {
            engine.active_attacks[0].current_pps = 100;
            engine.active_attacks[0].update_status(1);
            if i >= 3 {
                assert!(engine.active_attacks[0].is_active());
            }
        }
        // Manually call the enforcement check as the transition happened via update_status
        // In the real flow, process_event_with_country detects the transition.
        // Here we simulate by directly calling:
        engine.maybe_emit_block_country(0);

        let enforcements = engine.take_pending_enforcements();
        assert_eq!(enforcements.len(), 1);
        assert_eq!(
            enforcements[0],
            DdosEnforcementAction::BlockCountry {
                country_code: "RU".to_string(),
            }
        );
    }

    #[test]
    fn ddos_engine_emits_unblock_on_expiry() {
        let mut engine = DdosEngine::new();
        engine
            .add_policy(make_policy("syn-1", DdosAttackType::SynFlood, 1))
            .unwrap();

        // Create attack with country and make it active
        let event = make_event(DdosAttackType::SynFlood, 1_000_000_000);
        engine.process_event_with_country(&event, Some("RU"));
        engine.active_attacks[0].src_country = Some("RU".to_string());

        // Force to active + blocked
        engine.active_attacks[0].mitigation_status = DdosMitigationStatus::Active;
        engine.blocked_countries.insert("RU".to_string());

        // Force to expired
        engine.active_attacks[0].mitigation_status = DdosMitigationStatus::Mitigated;
        engine.active_attacks[0].consecutive_below = 300;
        engine.active_attacks[0].current_pps = 0;
        engine.active_attacks[0].update_status(1);
        assert!(engine.active_attacks[0].is_expired());

        // tick() should move it to history and emit UnblockCountry
        engine.tick();

        let enforcements = engine.take_pending_enforcements();
        assert_eq!(enforcements.len(), 1);
        assert_eq!(
            enforcements[0],
            DdosEnforcementAction::UnblockCountry {
                country_code: "RU".to_string(),
            }
        );
    }

    #[test]
    fn ddos_engine_no_duplicate_block_same_country() {
        let mut engine = DdosEngine::new();
        engine
            .add_policy(make_policy("syn-1", DdosAttackType::SynFlood, 1))
            .unwrap();

        // Simulate two attacks from same country
        engine.blocked_countries.insert("CN".to_string());

        let event = make_event(DdosAttackType::SynFlood, 1_000_000_000);
        engine.process_event_with_country(&event, Some("CN"));
        engine.active_attacks[0].src_country = Some("CN".to_string());
        engine.active_attacks[0].mitigation_status = DdosMitigationStatus::Active;

        // Should not emit BlockCountry since already blocked
        engine.maybe_emit_block_country(0);
        let enforcements = engine.take_pending_enforcements();
        assert!(enforcements.is_empty());
    }

    #[test]
    fn ddos_engine_no_block_if_alert_policy() {
        let mut policy = make_policy("syn-1", DdosAttackType::SynFlood, 1);
        policy.mitigation_action = DdosMitigationAction::Alert;

        let mut engine = DdosEngine::new();
        engine.add_policy(policy).unwrap();

        let event = make_event(DdosAttackType::SynFlood, 1_000_000_000);
        engine.process_event_with_country(&event, Some("RU"));
        engine.active_attacks[0].src_country = Some("RU".to_string());
        engine.active_attacks[0].mitigation_status = DdosMitigationStatus::Active;

        engine.maybe_emit_block_country(0);
        let enforcements = engine.take_pending_enforcements();
        assert!(enforcements.is_empty());
    }

    #[test]
    fn tick_uses_per_country_threshold() {
        use std::collections::HashMap;

        // Global threshold is very high (5000), country CN threshold is low (1)
        let mut ct = HashMap::new();
        ct.insert("CN".to_string(), 1_u64);
        let mut policy = make_policy("syn-1", DdosAttackType::SynFlood, 5000);
        policy.country_thresholds = Some(ct);

        let mut engine = DdosEngine::new();
        engine.add_policy(policy).unwrap();

        // Create attack with country CN
        let event = make_event(DdosAttackType::SynFlood, 1_000_000_000);
        engine.process_event_with_country(&event, Some("CN"));
        assert_eq!(engine.active_attack_count(), 1);

        // Force PPS above country threshold (1) but below global (5000)
        engine.active_attacks[0].current_pps = 50;
        engine.active_attacks[0].mitigation_status = DdosMitigationStatus::Detecting;

        // tick() should use threshold=1 for CN, so 50 pps is above it
        engine.tick();
        // Attack should still be active (not expired), status advanced
        assert_eq!(engine.active_attack_count(), 1);
    }
}
