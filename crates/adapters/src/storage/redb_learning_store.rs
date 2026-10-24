use std::path::Path;
use std::sync::Mutex;

use domain::common::error::DomainError;
use domain::learning::engine::LearningSession;
use ports::secondary::learning_store_port::LearningStorePort;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

const SESSIONS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("learning_sessions");

/// redb-backed persistence for learning sessions.
///
/// The session is written after every sample rather than at the end of the
/// window, because the output of this feature is a description of a window
/// and a window interrupted halfway is still worth the half it watched. What
/// is written is the whole session, aggregate included: an edge is a few
/// dozen bytes and a window holds thousands of them, not millions.
pub struct RedbLearningStore {
    db: Database,
    write_lock: Mutex<()>,
}

impl RedbLearningStore {
    /// Open or create the store.
    ///
    /// # Errors
    ///
    /// Returns the redb error when the file cannot be created or the table
    /// cannot be opened.
    pub fn open(path: &Path) -> Result<Self, redb::Error> {
        let db = super::create_database(path)?;
        let txn = db.begin_write()?;
        {
            let _ = txn.open_table(SESSIONS_TABLE)?;
        }
        txn.commit()?;
        Ok(Self {
            db,
            write_lock: Mutex::new(()),
        })
    }
}

fn storage_error(what: &str, e: &dyn std::fmt::Display) -> DomainError {
    DomainError::EngineError(format!("learning store {what} failed: {e}"))
}

impl LearningStorePort for RedbLearningStore {
    fn save(&self, session: &LearningSession) -> Result<(), DomainError> {
        let _lock = self
            .write_lock
            .lock()
            .map_err(|e| storage_error("lock", &e))?;
        let encoded =
            serde_json::to_vec(session).map_err(|e| storage_error("serialisation", &e))?;
        let txn = self
            .db
            .begin_write()
            .map_err(|e| storage_error("write transaction", &e))?;
        {
            let mut table = txn
                .open_table(SESSIONS_TABLE)
                .map_err(|e| storage_error("table open", &e))?;
            table
                .insert(session.id.as_str(), encoded.as_slice())
                .map_err(|e| storage_error("insert", &e))?;
        }
        txn.commit().map_err(|e| storage_error("commit", &e))
    }

    fn load_all(&self) -> Result<Vec<LearningSession>, DomainError> {
        let txn = self
            .db
            .begin_read()
            .map_err(|e| storage_error("read transaction", &e))?;
        let table = txn
            .open_table(SESSIONS_TABLE)
            .map_err(|e| storage_error("table open", &e))?;
        let mut sessions = Vec::new();
        for entry in table.iter().map_err(|e| storage_error("iteration", &e))? {
            let (_, value) = entry.map_err(|e| storage_error("read", &e))?;
            match serde_json::from_slice::<LearningSession>(value.value()) {
                Ok(session) => sessions.push(session),
                Err(e) => {
                    // A session written by a build whose shape has since
                    // changed is skipped rather than taking the whole store
                    // down with it: the operator loses one window, not the
                    // agent.
                    tracing::warn!(error = %e, "unreadable learning session skipped");
                }
            }
        }
        Ok(sessions)
    }

    fn delete(&self, id: &str) -> Result<(), DomainError> {
        let _lock = self
            .write_lock
            .lock()
            .map_err(|e| storage_error("lock", &e))?;
        let txn = self
            .db
            .begin_write()
            .map_err(|e| storage_error("write transaction", &e))?;
        {
            let mut table = txn
                .open_table(SESSIONS_TABLE)
                .map_err(|e| storage_error("table open", &e))?;
            table.remove(id).map_err(|e| storage_error("remove", &e))?;
        }
        txn.commit().map_err(|e| storage_error("commit", &e))
    }
}

#[cfg(test)]
mod tests {
    use domain::common::entity::Protocol;
    use domain::learning::entity::{LearningScope, ObservedFlow, ObservedWorkload};

    use super::*;

    fn session(id: &str) -> LearningSession {
        LearningSession::new(id.to_string(), LearningScope::Node, 600, 64, 0).unwrap()
    }

    fn flow() -> ObservedFlow {
        ObservedFlow {
            workload: ObservedWorkload {
                unit: Some("nginx.service".to_string()),
                ..ObservedWorkload::default()
            },
            source: "10.9.0.2".parse().unwrap(),
            destination: "10.0.0.1".parse().unwrap(),
            port: 443,
            protocol: Protocol::Tcp,
        }
    }

    #[test]
    fn a_session_survives_the_store_with_its_aggregate() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = RedbLearningStore::open(&dir.path().join("learning.redb")).expect("open");

        let mut written = session("l-1");
        written.observe(&flow(), 1_000);
        store.save(&written).expect("save");

        let loaded = store.load_all().expect("load");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, "l-1");
        assert_eq!(loaded[0].aggregate.len(), 1);
        assert_eq!(loaded[0].aggregate.edges()[0].port, 443);
        assert_eq!(loaded[0].last_observation_ns, 1_000);
    }

    #[test]
    fn saving_the_same_session_again_replaces_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = RedbLearningStore::open(&dir.path().join("learning.redb")).expect("open");

        let mut written = session("l-1");
        store.save(&written).expect("save");
        written.observe(&flow(), 2_000);
        store.save(&written).expect("save again");

        let loaded = store.load_all().expect("load");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].observations, 1);
    }

    #[test]
    fn a_deleted_session_is_gone() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = RedbLearningStore::open(&dir.path().join("learning.redb")).expect("open");
        store.save(&session("l-1")).expect("save");
        store.save(&session("l-2")).expect("save");

        store.delete("l-1").expect("delete");

        let loaded = store.load_all().expect("load");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, "l-2");
    }

    #[test]
    fn the_store_reopens_what_a_previous_run_wrote() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("learning.redb");
        {
            let store = RedbLearningStore::open(&path).expect("open");
            store.save(&session("l-1")).expect("save");
        }
        let reopened = RedbLearningStore::open(&path).expect("reopen");
        assert_eq!(reopened.load_all().expect("load").len(), 1);
    }
}
