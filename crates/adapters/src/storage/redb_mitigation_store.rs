use std::net::IpAddr;
use std::path::Path;
use std::sync::{Mutex, PoisonError};

use domain::common::error::DomainError;
use domain::ips::entity::PersistedBlock;
use domain::response::entity::ResponseAction;
use ports::secondary::mitigation_store::MitigationStore;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

const BLOCK_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("ips_blocks");
const ACTION_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("response_actions");

/// redb-backed persistence for the containment decisions in force.
///
/// Two tables share one database, keyed the way each decision is addressed
/// everywhere else: a block by its address, a response action by its id. Both
/// records date themselves on the wall clock, because the question asked of
/// them is how much of a TTL is left after a restart and a monotonic reading
/// cannot answer it.
///
/// A record is dropped on a read it cannot be deserialised from rather than
/// failing the load: a half-written or older record must not be what keeps the
/// rest of the blocks from coming back.
pub struct RedbMitigationStore {
    db: Database,
    write_lock: Mutex<()>,
}

fn storage_error(what: &str, e: &dyn std::fmt::Display) -> DomainError {
    DomainError::EngineError(format!("mitigation store: {what}: {e}"))
}

impl RedbMitigationStore {
    pub fn open(path: &Path) -> Result<Self, redb::Error> {
        let db = super::create_database(path)?;
        let txn = db.begin_write()?;
        {
            let _ = txn.open_table(BLOCK_TABLE)?;
            let _ = txn.open_table(ACTION_TABLE)?;
        }
        txn.commit()?;
        Ok(Self {
            db,
            write_lock: Mutex::new(()),
        })
    }

    fn put(
        &self,
        table: TableDefinition<&str, &[u8]>,
        key: &str,
        bytes: &[u8],
    ) -> Result<(), DomainError> {
        // A poisoned lock is a panic in an earlier write, not a reason to stop
        // writing down decisions: the data it guards is one redb transaction
        // away and redb serialises writers itself.
        let _lock = self
            .write_lock
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let txn = self
            .db
            .begin_write()
            .map_err(|e| storage_error("could not start a write", &e))?;
        {
            let mut table = txn
                .open_table(table)
                .map_err(|e| storage_error("could not open the table", &e))?;
            table
                .insert(key, bytes)
                .map_err(|e| storage_error("could not write the record", &e))?;
        }
        txn.commit()
            .map_err(|e| storage_error("could not commit the write", &e))
    }

    fn forget(&self, table: TableDefinition<&str, &[u8]>, key: &str) -> Result<(), DomainError> {
        // A poisoned lock is a panic in an earlier write, not a reason to stop
        // writing down decisions: the data it guards is one redb transaction
        // away and redb serialises writers itself.
        let _lock = self
            .write_lock
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let txn = self
            .db
            .begin_write()
            .map_err(|e| storage_error("could not start a write", &e))?;
        {
            let mut table = txn
                .open_table(table)
                .map_err(|e| storage_error("could not open the table", &e))?;
            table
                .remove(key)
                .map_err(|e| storage_error("could not remove the record", &e))?;
        }
        txn.commit()
            .map_err(|e| storage_error("could not commit the removal", &e))
    }

    fn all<T: serde::de::DeserializeOwned>(
        &self,
        table: TableDefinition<&str, &[u8]>,
    ) -> Result<Vec<T>, DomainError> {
        let txn = self
            .db
            .begin_read()
            .map_err(|e| storage_error("could not start a read", &e))?;
        let table = txn
            .open_table(table)
            .map_err(|e| storage_error("could not open the table", &e))?;
        let iter = table
            .iter()
            .map_err(|e| storage_error("could not walk the table", &e))?;
        Ok(iter
            .filter_map(Result::ok)
            .filter_map(|(_k, v)| serde_json::from_slice::<T>(v.value()).ok())
            .collect())
    }
}

impl MitigationStore for RedbMitigationStore {
    fn save_block(&self, block: &PersistedBlock) -> Result<(), DomainError> {
        let bytes = serde_json::to_vec(block)
            .map_err(|e| storage_error("could not serialise the block", &e))?;
        self.put(BLOCK_TABLE, &block.ip.to_string(), &bytes)
    }

    fn remove_block(&self, ip: IpAddr) -> Result<(), DomainError> {
        self.forget(BLOCK_TABLE, &ip.to_string())
    }

    fn clear_blocks(&self) -> Result<(), DomainError> {
        // A poisoned lock is a panic in an earlier write, not a reason to stop
        // writing down decisions: the data it guards is one redb transaction
        // away and redb serialises writers itself.
        let _lock = self
            .write_lock
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let txn = self
            .db
            .begin_write()
            .map_err(|e| storage_error("could not start a write", &e))?;
        {
            let mut table = txn
                .open_table(BLOCK_TABLE)
                .map_err(|e| storage_error("could not open the table", &e))?;
            table
                .retain(|_, _| false)
                .map_err(|e| storage_error("could not clear the table", &e))?;
        }
        txn.commit()
            .map_err(|e| storage_error("could not commit the clear", &e))
    }

    fn load_blocks(&self) -> Result<Vec<PersistedBlock>, DomainError> {
        self.all(BLOCK_TABLE)
    }

    fn save_action(&self, action: &ResponseAction) -> Result<(), DomainError> {
        let bytes = serde_json::to_vec(action)
            .map_err(|e| storage_error("could not serialise the action", &e))?;
        self.put(ACTION_TABLE, &action.id, &bytes)
    }

    fn remove_action(&self, id: &str) -> Result<(), DomainError> {
        self.forget(ACTION_TABLE, id)
    }

    fn load_actions(&self) -> Result<Vec<ResponseAction>, DomainError> {
        self.all(ACTION_TABLE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::response::entity::ResponseActionType;

    fn a_block(ip: &str) -> PersistedBlock {
        PersistedBlock {
            ip: ip.parse().expect("an address"),
            reason: "ids threshold reached".to_string(),
            auto_generated: true,
            added_at_ns: 1_700_000_000_000_000_000,
            ttl_secs: 1800,
            detection_count: 5,
        }
    }

    fn an_action(id: &str) -> ResponseAction {
        ResponseAction {
            id: id.to_string(),
            action_type: ResponseActionType::ThrottleIp,
            target: "198.51.100.4".to_string(),
            ttl_secs: 600,
            created_at_ns: 1_700_000_000_000_000_000,
            expires_at_ns: 1_700_000_600_000_000_000,
            rule_id: format!("response-{id}"),
            rate_pps: Some(100),
            revoked: false,
        }
    }

    #[test]
    fn what_was_written_before_the_restart_is_what_comes_back() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("mitigations.redb");

        {
            let store = RedbMitigationStore::open(&path).expect("a fresh store");
            store.save_block(&a_block("203.0.113.1")).expect("a block");
            store.save_block(&a_block("203.0.113.2")).expect("a block");
            store.save_action(&an_action("resp-1")).expect("an action");
        }

        // A second process opening the same file is the case that matters.
        let store = RedbMitigationStore::open(&path).expect("a reopened store");
        let mut blocks = store.load_blocks().expect("the blocks");
        blocks.sort_by_key(|b| b.ip);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].ip.to_string(), "203.0.113.1");
        assert_eq!(blocks[0].ttl_secs, 1800);
        assert_eq!(blocks[0].reason, "ids threshold reached");
        assert!(blocks[0].auto_generated);

        let actions = store.load_actions().expect("the actions");
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].id, "resp-1");
        assert_eq!(actions[0].rate_pps, Some(100));
    }

    #[test]
    fn a_lifted_block_is_forgotten() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let store =
            RedbMitigationStore::open(&dir.path().join("mitigations.redb")).expect("a store");
        let block = a_block("203.0.113.3");
        store.save_block(&block).expect("a block");
        store.remove_block(block.ip).expect("the removal");
        assert!(store.load_blocks().expect("the blocks").is_empty());

        // Removing what is not there is not an error: the sweeper and an
        // operator can both lift the same block.
        store.remove_block(block.ip).expect("a second removal");
    }

    #[test]
    fn re_saving_a_block_replaces_rather_than_duplicates_it() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let store =
            RedbMitigationStore::open(&dir.path().join("mitigations.redb")).expect("a store");
        store.save_block(&a_block("203.0.113.4")).expect("a block");
        let mut again = a_block("203.0.113.4");
        again.detection_count = 11;
        store.save_block(&again).expect("the same block again");

        let blocks = store.load_blocks().expect("the blocks");
        assert_eq!(blocks.len(), 1, "one address is one record");
        assert_eq!(blocks[0].detection_count, 11);
    }

    #[test]
    fn clearing_empties_the_blocks_and_leaves_the_actions() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let store =
            RedbMitigationStore::open(&dir.path().join("mitigations.redb")).expect("a store");
        store.save_block(&a_block("203.0.113.5")).expect("a block");
        store.save_action(&an_action("resp-2")).expect("an action");

        store.clear_blocks().expect("the clear");
        assert!(store.load_blocks().expect("the blocks").is_empty());
        assert_eq!(
            store.load_actions().expect("the actions").len(),
            1,
            "clearing the blacklist does not revoke a manual response"
        );
    }

    #[test]
    fn a_record_that_cannot_be_read_is_skipped_rather_than_fatal() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("mitigations.redb");
        let store = RedbMitigationStore::open(&path).expect("a store");
        store.save_block(&a_block("203.0.113.6")).expect("a block");
        store
            .put(BLOCK_TABLE, "203.0.113.99", b"not json at all")
            .expect("the damaged record");

        let blocks = store.load_blocks().expect("the blocks");
        assert_eq!(
            blocks.len(),
            1,
            "the readable block comes back and the damaged one is dropped"
        );
        assert_eq!(blocks[0].ip.to_string(), "203.0.113.6");
    }

    #[test]
    fn a_revoked_action_is_forgotten() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let store =
            RedbMitigationStore::open(&dir.path().join("mitigations.redb")).expect("a store");
        store.save_action(&an_action("resp-3")).expect("an action");
        store.remove_action("resp-3").expect("the removal");
        assert!(store.load_actions().expect("the actions").is_empty());
    }
}
