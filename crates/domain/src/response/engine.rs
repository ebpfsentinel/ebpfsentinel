use std::collections::HashMap;

use super::entity::ResponseAction;

/// In-memory store for active manual response actions.
pub struct ResponseEngine {
    actions: HashMap<String, ResponseAction>,
    max_ttl_secs: u64,
}

impl ResponseEngine {
    pub fn new(max_ttl_secs: u64) -> Self {
        Self {
            actions: HashMap::new(),
            max_ttl_secs,
        }
    }

    /// Maximum allowed TTL in seconds.
    pub fn max_ttl_secs(&self) -> u64 {
        self.max_ttl_secs
    }

    /// Register a new response action. Returns error if TTL exceeds max.
    pub fn add(&mut self, action: ResponseAction) -> Result<(), String> {
        if action.ttl_secs > self.max_ttl_secs {
            return Err(format!(
                "TTL {}s exceeds maximum {}s",
                action.ttl_secs, self.max_ttl_secs
            ));
        }
        self.actions.insert(action.id.clone(), action);
        Ok(())
    }

    /// Revoke an action by ID. Returns the action if found and not already revoked.
    pub fn revoke(&mut self, id: &str) -> Option<ResponseAction> {
        let action = self.actions.get_mut(id)?;
        if action.revoked {
            return None;
        }
        action.revoked = true;
        Some(action.clone())
    }

    /// List all actions (active and expired).
    pub fn list(&self) -> Vec<&ResponseAction> {
        self.actions.values().collect()
    }

    /// List only active (non-expired, non-revoked) actions.
    pub fn list_active(&self, now_ns: u64) -> Vec<&ResponseAction> {
        self.actions
            .values()
            .filter(|a| !a.is_expired(now_ns))
            .collect()
    }

    /// Remove and return all expired actions.
    pub fn drain_expired(&mut self, now_ns: u64) -> Vec<ResponseAction> {
        let expired_ids: Vec<String> = self
            .actions
            .iter()
            .filter(|(_, a)| a.is_expired(now_ns))
            .map(|(id, _)| id.clone())
            .collect();

        expired_ids
            .into_iter()
            .filter_map(|id| self.actions.remove(&id))
            .collect()
    }

    /// Get an action by ID.
    pub fn get(&self, id: &str) -> Option<&ResponseAction> {
        self.actions.get(id)
    }

    /// Number of active (non-expired) actions.
    pub fn active_count(&self, now_ns: u64) -> usize {
        self.actions
            .values()
            .filter(|a| !a.is_expired(now_ns))
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::response::entity::ResponseActionType;

    fn make_action(id: &str, ttl_secs: u64, now_ns: u64) -> ResponseAction {
        ResponseAction {
            id: id.to_string(),
            action_type: ResponseActionType::BlockIp,
            target: "1.2.3.4".to_string(),
            ttl_secs,
            created_at_ns: now_ns,
            expires_at_ns: now_ns + ttl_secs * 1_000_000_000,
            rule_id: format!("response-{id}"),
            rate_pps: None,
            revoked: false,
        }
    }

    #[test]
    fn add_and_list() {
        let mut engine = ResponseEngine::new(86400);
        let now = 1_000_000_000_000u64;
        engine.add(make_action("a1", 3600, now)).unwrap();
        engine.add(make_action("a2", 7200, now)).unwrap();
        assert_eq!(engine.list().len(), 2);
        assert_eq!(engine.active_count(now), 2);
    }

    #[test]
    fn ttl_exceeds_max() {
        let mut engine = ResponseEngine::new(3600);
        let now = 1_000_000_000_000u64;
        let result = engine.add(make_action("a1", 7200, now));
        assert!(result.is_err());
    }

    #[test]
    fn revoke_action() {
        let mut engine = ResponseEngine::new(86400);
        let now = 1_000_000_000_000u64;
        engine.add(make_action("a1", 3600, now)).unwrap();
        let revoked = engine.revoke("a1");
        assert!(revoked.is_some());
        assert!(engine.get("a1").unwrap().revoked);
        // Second revoke returns None
        assert!(engine.revoke("a1").is_none());
    }

    #[test]
    fn drain_expired() {
        let mut engine = ResponseEngine::new(86400);
        let now = 1_000_000_000_000u64;
        engine.add(make_action("a1", 60, now)).unwrap();
        engine.add(make_action("a2", 3600, now)).unwrap();

        let after = now + 120 * 1_000_000_000; // 120s later
        let expired = engine.drain_expired(after);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].id, "a1");
        assert_eq!(engine.list().len(), 1); // a2 still present
    }

    #[test]
    fn list_active_excludes_expired() {
        let mut engine = ResponseEngine::new(86400);
        let now = 1_000_000_000_000u64;
        engine.add(make_action("a1", 60, now)).unwrap();
        engine.add(make_action("a2", 3600, now)).unwrap();

        let after = now + 120 * 1_000_000_000;
        let active = engine.list_active(after);
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].id, "a2");
    }

    #[test]
    fn list_active_excludes_revoked() {
        let mut engine = ResponseEngine::new(86400);
        let now = 1_000_000_000_000u64;
        engine.add(make_action("a1", 3600, now)).unwrap();
        engine.revoke("a1");
        assert_eq!(engine.active_count(now), 0);
    }
}
