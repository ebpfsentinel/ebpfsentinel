//! The last reading of every watched path, kept in redb by path.
//!
//! A baseline is written on first sight and after every change, so the store
//! holds what each path named the last time it was read and nothing older:
//! history belongs to the alerts a difference raises, not to the baseline.

use std::path::Path;
use std::sync::Mutex;

use domain::common::error::DomainError;
use domain::file_watch::FileBaseline;
use ports::secondary::file_watch_port::FileBaselineStore;
use redb::{Database, ReadableDatabase, ReadableTableMetadata, TableDefinition};

const BASELINES_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("file_baselines");

/// redb-backed file baselines.
pub struct RedbFileBaselineStore {
    db: Database,
    write_lock: Mutex<()>,
}

impl RedbFileBaselineStore {
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
            let _ = txn.open_table(BASELINES_TABLE)?;
        }
        txn.commit()?;
        Ok(Self {
            db,
            write_lock: Mutex::new(()),
        })
    }
}

fn storage_error(what: &str, e: &dyn std::fmt::Display) -> DomainError {
    DomainError::EngineError(format!("file baseline store {what} failed: {e}"))
}

impl FileBaselineStore for RedbFileBaselineStore {
    fn get(&self, path: &str) -> Result<Option<FileBaseline>, DomainError> {
        let txn = self
            .db
            .begin_read()
            .map_err(|e| storage_error("read transaction", &e))?;
        let table = txn
            .open_table(BASELINES_TABLE)
            .map_err(|e| storage_error("table open", &e))?;
        let Some(value) = table.get(path).map_err(|e| storage_error("read", &e))? else {
            return Ok(None);
        };
        match serde_json::from_slice::<FileBaseline>(value.value()) {
            Ok(baseline) => Ok(Some(baseline)),
            Err(e) => {
                // A baseline written by a build whose shape has since changed
                // is read as absent: the path is seen afresh rather than
                // compared against something the agent cannot read.
                tracing::warn!(path, error = %e, "unreadable file baseline skipped");
                Ok(None)
            }
        }
    }

    fn put(&self, path: &str, baseline: &FileBaseline) -> Result<(), DomainError> {
        let _lock = self
            .write_lock
            .lock()
            .map_err(|e| storage_error("lock", &e))?;
        let encoded =
            serde_json::to_vec(baseline).map_err(|e| storage_error("serialisation", &e))?;
        let txn = self
            .db
            .begin_write()
            .map_err(|e| storage_error("write transaction", &e))?;
        {
            let mut table = txn
                .open_table(BASELINES_TABLE)
                .map_err(|e| storage_error("table open", &e))?;
            table
                .insert(path, encoded.as_slice())
                .map_err(|e| storage_error("insert", &e))?;
        }
        txn.commit().map_err(|e| storage_error("commit", &e))
    }

    fn remove(&self, path: &str) -> Result<bool, DomainError> {
        let _lock = self
            .write_lock
            .lock()
            .map_err(|e| storage_error("lock", &e))?;
        let txn = self
            .db
            .begin_write()
            .map_err(|e| storage_error("write transaction", &e))?;
        let removed = {
            let mut table = txn
                .open_table(BASELINES_TABLE)
                .map_err(|e| storage_error("table open", &e))?;
            table
                .remove(path)
                .map_err(|e| storage_error("remove", &e))?
                .is_some()
        };
        txn.commit().map_err(|e| storage_error("commit", &e))?;
        Ok(removed)
    }

    fn count(&self) -> Result<u64, DomainError> {
        let txn = self
            .db
            .begin_read()
            .map_err(|e| storage_error("read transaction", &e))?;
        let table = txn
            .open_table(BASELINES_TABLE)
            .map_err(|e| storage_error("table open", &e))?;
        table.len().map_err(|e| storage_error("count", &e))
    }
}

#[cfg(test)]
mod tests {
    use domain::file_watch::FileType;

    use super::*;

    fn baseline(size: u64) -> FileBaseline {
        FileBaseline {
            file_type: FileType::Regular,
            size,
            mtime_ns: 1,
            mode: 0o644,
            uid: 0,
            gid: 0,
            dev: 1,
            ino: 2,
            link_target: None,
            sha256: None,
            hash_unread: Some("permission denied".into()),
            xattrs: Vec::new(),
            xattrs_unread: None,
        }
    }

    #[test]
    fn a_baseline_is_kept_replaced_and_forgotten_across_a_reopen() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let path = dir.path().join("data").join("file_baselines.redb");
        {
            let store = RedbFileBaselineStore::open(&path).unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(store.get("/etc/hosts").ok(), Some(None));
            assert!(store.put("/etc/hosts", &baseline(1)).is_ok());
            assert!(store.put("/etc/hosts", &baseline(2)).is_ok());
            assert!(store.put("/etc/passwd", &baseline(3)).is_ok());
            assert_eq!(store.count().ok(), Some(2));
        }
        let store = RedbFileBaselineStore::open(&path).unwrap_or_else(|e| panic!("{e}"));
        let kept = store.get("/etc/hosts").ok().flatten();
        assert_eq!(kept, Some(baseline(2)));
        assert_eq!(
            kept.and_then(|b| b.hash_unread).as_deref(),
            Some("permission denied"),
            "a missing hash is kept with its reason"
        );
        assert_eq!(store.remove("/etc/hosts").ok(), Some(true));
        assert_eq!(store.remove("/etc/hosts").ok(), Some(false));
        assert_eq!(store.count().ok(), Some(1));
    }
}
