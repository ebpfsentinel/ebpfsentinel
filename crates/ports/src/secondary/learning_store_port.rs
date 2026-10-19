use domain::common::error::DomainError;
use domain::learning::engine::LearningSession;

/// Where a learning session is written down so that it survives the agent.
///
/// A window silently reset by a redeploy produces a policy missing a day,
/// which is the worst output this feature has, so the session is persisted
/// as it runs rather than at the end: what comes back after a restart is
/// either the session with the hole recorded, or nothing at all, and never a
/// window pretending to have watched what it did not.
pub trait LearningStorePort: Send + Sync {
    /// Write the session down, replacing whatever was stored under its id.
    fn save(&self, session: &LearningSession) -> Result<(), DomainError>;

    /// Read every session the store holds.
    fn load_all(&self) -> Result<Vec<LearningSession>, DomainError>;

    /// Forget one session.
    fn delete(&self, id: &str) -> Result<(), DomainError>;
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use domain::learning::entity::LearningScope;

    use super::*;

    struct InMemoryLearningStore {
        sessions: Mutex<Vec<LearningSession>>,
    }

    impl LearningStorePort for InMemoryLearningStore {
        fn save(&self, session: &LearningSession) -> Result<(), DomainError> {
            let mut sessions = self.sessions.lock().unwrap();
            sessions.retain(|s| s.id != session.id);
            sessions.push(session.clone());
            Ok(())
        }

        fn load_all(&self) -> Result<Vec<LearningSession>, DomainError> {
            Ok(self.sessions.lock().unwrap().clone())
        }

        fn delete(&self, id: &str) -> Result<(), DomainError> {
            self.sessions.lock().unwrap().retain(|s| s.id != id);
            Ok(())
        }
    }

    #[test]
    fn a_session_saved_twice_is_stored_once() {
        let store = InMemoryLearningStore {
            sessions: Mutex::new(Vec::new()),
        };
        let mut session =
            LearningSession::new("l-1".to_string(), LearningScope::Node, 600, 64, 0).unwrap();
        store.save(&session).unwrap();
        session.touch(1_000);
        store.save(&session).unwrap();

        let loaded = store.load_all().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].last_observation_ns, 1_000);

        store.delete("l-1").unwrap();
        assert!(store.load_all().unwrap().is_empty());
    }
}
