use std::net::IpAddr;

use domain::common::error::DomainError;
use domain::ips::entity::PersistedBlock;
use domain::response::entity::ResponseAction;

/// Secondary port for the containment decisions that must outlive the process
/// that took them.
///
/// A blocked source and a manual response are the two decisions an operator
/// expects to still be in force after an agent restart: both are written down
/// when they are taken, read back at startup, and dropped on the way in when
/// their TTL elapsed while the agent was down. Everything else about the
/// detection path is rebuilt from the configuration and needs no store.
///
/// Every method is best-effort from the caller's side: an unavailable store
/// must cost the agent its memory of a decision, never the decision itself.
pub trait MitigationStore: Send + Sync {
    /// Write down a blocked source, or update the record of one.
    fn save_block(&self, block: &PersistedBlock) -> Result<(), DomainError>;

    /// Forget a blocked source, because it was lifted or expired.
    fn remove_block(&self, ip: IpAddr) -> Result<(), DomainError>;

    /// Forget every blocked source.
    fn clear_blocks(&self) -> Result<(), DomainError>;

    /// Every blocked source that was written down, expired ones included: what
    /// is still in force is for the caller to decide against its own clock.
    fn load_blocks(&self) -> Result<Vec<PersistedBlock>, DomainError>;

    /// Write down a response action, or update the record of one.
    fn save_action(&self, action: &ResponseAction) -> Result<(), DomainError>;

    /// Forget a response action, because it was revoked or expired.
    fn remove_action(&self, id: &str) -> Result<(), DomainError>;

    /// Every response action that was written down, expired ones included.
    fn load_actions(&self) -> Result<Vec<ResponseAction>, DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Default)]
    struct InMemoryStore {
        blocks: Mutex<HashMap<IpAddr, PersistedBlock>>,
        actions: Mutex<HashMap<String, ResponseAction>>,
    }

    impl MitigationStore for InMemoryStore {
        fn save_block(&self, block: &PersistedBlock) -> Result<(), DomainError> {
            self.blocks.lock().unwrap().insert(block.ip, block.clone());
            Ok(())
        }

        fn remove_block(&self, ip: IpAddr) -> Result<(), DomainError> {
            self.blocks.lock().unwrap().remove(&ip);
            Ok(())
        }

        fn clear_blocks(&self) -> Result<(), DomainError> {
            self.blocks.lock().unwrap().clear();
            Ok(())
        }

        fn load_blocks(&self) -> Result<Vec<PersistedBlock>, DomainError> {
            Ok(self.blocks.lock().unwrap().values().cloned().collect())
        }

        fn save_action(&self, action: &ResponseAction) -> Result<(), DomainError> {
            self.actions
                .lock()
                .unwrap()
                .insert(action.id.clone(), action.clone());
            Ok(())
        }

        fn remove_action(&self, id: &str) -> Result<(), DomainError> {
            self.actions.lock().unwrap().remove(id);
            Ok(())
        }

        fn load_actions(&self) -> Result<Vec<ResponseAction>, DomainError> {
            Ok(self.actions.lock().unwrap().values().cloned().collect())
        }
    }

    fn a_block(ip: &str) -> PersistedBlock {
        PersistedBlock {
            ip: ip.parse().unwrap(),
            reason: "test".to_string(),
            auto_generated: true,
            added_at_ns: 1_700_000_000_000_000_000,
            ttl_secs: 600,
            detection_count: 3,
        }
    }

    #[test]
    fn a_block_written_down_reads_back_as_itself() {
        let store = InMemoryStore::default();
        let block = a_block("203.0.113.7");
        store.save_block(&block).unwrap();
        assert_eq!(store.load_blocks().unwrap(), vec![block.clone()]);

        store.remove_block(block.ip).unwrap();
        assert!(store.load_blocks().unwrap().is_empty());
    }

    #[test]
    fn clearing_forgets_every_block() {
        let store = InMemoryStore::default();
        store.save_block(&a_block("203.0.113.8")).unwrap();
        store.save_block(&a_block("203.0.113.9")).unwrap();
        store.clear_blocks().unwrap();
        assert!(store.load_blocks().unwrap().is_empty());
    }

    #[test]
    fn an_action_written_down_reads_back_as_itself() {
        use domain::response::entity::{ResponseAction, ResponseActionType};

        let store = InMemoryStore::default();
        let action = ResponseAction {
            id: "resp-1".to_string(),
            action_type: ResponseActionType::BlockIp,
            target: "203.0.113.10".to_string(),
            ttl_secs: 300,
            created_at_ns: 1_700_000_000_000_000_000,
            expires_at_ns: 1_700_000_300_000_000_000,
            rule_id: "response-resp-1".to_string(),
            rate_pps: None,
            revoked: false,
        };
        store.save_action(&action).unwrap();
        assert_eq!(store.load_actions().unwrap().len(), 1);

        store.remove_action(&action.id).unwrap();
        assert!(store.load_actions().unwrap().is_empty());
    }

    #[test]
    fn object_safe() {
        fn _check(_: &dyn MitigationStore) {}
    }
}
