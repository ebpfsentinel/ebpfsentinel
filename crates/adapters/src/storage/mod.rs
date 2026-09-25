pub mod fingerprint_store_redb;
pub mod redb_alert_store;
pub mod redb_audit_store;
pub mod redb_rule_change_store;

use std::path::Path;

use redb::{Database, DatabaseError, StorageError};

/// Open (or create) a redb file, creating its parent directory first.
///
/// The default stores are relative paths under `data/`, and a state directory
/// mounted empty (a fresh volume, a new host path) has no `data/` in it yet.
fn create_database(path: &Path) -> Result<Database, DatabaseError> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .map_err(|e| DatabaseError::Storage(StorageError::from(e)))?;
    }
    Database::create(path)
}

#[cfg(test)]
mod tests {
    use super::create_database;

    #[test]
    fn creates_missing_parent_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("data").join("nested").join("store.redb");
        create_database(&path).expect("created");
        assert!(path.exists());
    }

    #[test]
    fn accepts_a_bare_file_name() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("store.redb");
        create_database(&path).expect("created");
        assert!(path.exists());
    }
}
