use crate::common::entity::RuleId;
use crate::common::error::DomainError;

use super::entity::{DdosAttack, DdosAttackType, DdosEvent, DdosMitigationStatus, DdosPolicy};
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
}

impl DdosEngine {
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
            active_attacks: Vec::new(),
            history: Vec::new(),
            total_mitigated: 0,
            next_attack_id: 1,
        }
    }

    /// Process a `DDoS` event from the eBPF pipeline.
    /// Returns `true` if an attack state changed (for alerting).
    pub fn process_event(&mut self, event: &DdosEvent) -> bool {
        // Find matching policy for this attack type
        let policy = self
            .policies
            .iter()
            .find(|p| p.enabled && p.attack_type == event.attack_type);

        let threshold = match policy {
            Some(p) => p.detection_threshold_pps,
            None => return false, // No policy for this attack type
        };

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
            let attack = DdosAttack::new(id, event.attack_type, event.timestamp_ns);
            self.active_attacks.push(attack);
            true
        } else {
            false // At capacity
        }
    }

    /// Periodic tick — call once per second to update attack statuses.
    pub fn tick(&mut self) {
        let mut thresholds: Vec<(DdosAttackType, u64)> = Vec::new();
        for p in &self.policies {
            if p.enabled {
                thresholds.push((p.attack_type, p.detection_threshold_pps));
            }
        }

        let mut expired_indices = Vec::new();
        for (idx, attack) in self.active_attacks.iter_mut().enumerate() {
            let threshold = thresholds
                .iter()
                .find(|(at, _)| *at == attack.attack_type)
                .map_or(u64::MAX, |(_, t)| *t);

            attack.update_status(threshold);
            if attack.is_expired() {
                expired_indices.push(idx);
            }
        }

        // Remove expired attacks (reverse order to preserve indices)
        for idx in expired_indices.into_iter().rev() {
            let expired = self.active_attacks.remove(idx);
            self.total_mitigated += 1;
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
        }
    }

    fn make_event(attack_type: DdosAttackType, ts: u64) -> DdosEvent {
        DdosEvent {
            timestamp_ns: ts,
            attack_type,
            src_addr: [0xC0A80001, 0, 0, 0],
            dst_addr: [0x0A000001, 0, 0, 0],
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
}
