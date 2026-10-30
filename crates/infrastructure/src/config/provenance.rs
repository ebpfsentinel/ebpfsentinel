//! Where the running configuration came from, and what changed it since.
//!
//! An agent run by an orchestrator is handed one document, and whoever wrote
//! that document wants to know two things about each node: whether the node
//! is running that document rather than an older one, and whether anything
//! changed the node's policy since without going through the document. The
//! first is the digest of the bytes the agent last loaded, which the writer
//! compares with the digest of what it wrote. The second is every policy
//! write the agent's own API accepted, counted since the process started.
//!
//! The count is never reset by a reload: a reload replays the document's
//! rules, but not every runtime write is a rule the document owns, so a
//! reload is not proof that the node is back to the document. A restart is.

use std::sync::{PoisonError, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use sha2::{Digest, Sha256};

/// One write the agent's API accepted outside the document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RuntimeWrite {
    /// HTTP method of the request.
    pub method: String,
    /// The route as requested, without its query string.
    pub path: String,
    /// When it was accepted, in seconds since the Unix epoch.
    pub at: u64,
}

/// What [`provenance`] answers.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ConfigProvenance {
    /// Lowercase hex SHA-256 of the document's bytes as last loaded, absent
    /// until a document has been loaded.
    pub document_sha256: Option<String>,
    /// When that document was loaded, in seconds since the Unix epoch.
    pub loaded_at: Option<u64>,
    /// Policy writes accepted through the API since the process started.
    pub runtime_writes: u64,
    /// The last of those writes.
    pub last_runtime_write: Option<RuntimeWrite>,
}

static PROVENANCE: RwLock<ConfigProvenance> = RwLock::new(ConfigProvenance {
    document_sha256: None,
    loaded_at: None,
    runtime_writes: 0,
    last_runtime_write: None,
});

/// Lowercase hex SHA-256 of a document.
#[must_use]
pub fn document_digest(document: &str) -> String {
    use std::fmt::Write;

    Sha256::digest(document.as_bytes())
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Record that the document with this digest is now the one running.
///
/// Every field of the record is valid on its own, so a writer that panicked
/// half way leaves nothing inconsistent to read and the poison is ignored.
pub fn record_load(digest: String) {
    let mut guard = PROVENANCE.write().unwrap_or_else(PoisonError::into_inner);
    guard.document_sha256 = Some(digest);
    guard.loaded_at = Some(now());
}

/// Record a policy write the API accepted.
pub fn record_runtime_write(method: &str, path: &str) {
    let mut guard = PROVENANCE.write().unwrap_or_else(PoisonError::into_inner);
    guard.runtime_writes = guard.runtime_writes.saturating_add(1);
    guard.last_runtime_write = Some(RuntimeWrite {
        method: method.to_owned(),
        path: path.to_owned(),
        at: now(),
    });
}

/// The record as it stands.
#[must_use]
pub fn provenance() -> ConfigProvenance {
    PROVENANCE
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_digest_is_the_sha256_of_the_bytes() {
        assert_eq!(
            document_digest(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_ne!(document_digest("a: 1"), document_digest("a: 2"));
    }

    #[test]
    fn a_load_keeps_the_count_and_a_write_adds_to_it() {
        let before = provenance().runtime_writes;
        record_runtime_write("POST", "/api/v1/firewall/rules");
        record_load(document_digest("agent: {}"));
        let after = provenance();
        assert!(after.runtime_writes > before, "the write was not counted");
        assert!(after.document_sha256.is_some());
        assert!(after.loaded_at.is_some());
        assert!(after.last_runtime_write.is_some());
    }
}
