//! The list of peer addresses this node holds, swapped whole.
//!
//! A reader takes the list as it stands, and a list being handed over is
//! never seen half applied: the new one replaces the old in one swap or not
//! at all, and a refused list leaves the old one in place.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwapOption;
use domain::identity::remote::{RemoteEntry, RemoteIdentities, RemoteRefusal, RemoteSnapshot};

/// What a node says about the list it holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteStatus {
    /// `None` until a first list arrives.
    pub version: Option<String>,
    pub received_at: Option<u64>,
    pub age_seconds: Option<u64>,
    pub entries: usize,
    pub conflicts: usize,
}

/// Holds the last list handed to this node.
#[derive(Debug, Default)]
pub struct RemoteIdentityStore {
    held: ArcSwapOption<RemoteIdentities>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl RemoteIdentityStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Take a list in place of the one held.
    pub fn replace(&self, snapshot: RemoteSnapshot) -> Result<RemoteStatus, RemoteRefusal> {
        self.replace_at(snapshot, now())
    }

    fn replace_at(&self, snapshot: RemoteSnapshot, at: u64) -> Result<RemoteStatus, RemoteRefusal> {
        let taken = RemoteIdentities::accept(snapshot, at)?;
        self.held.store(Some(Arc::new(taken)));
        Ok(self.status_at(at))
    }

    /// The list as it stands, for a reader that consults it many times.
    #[must_use]
    pub fn current(&self) -> Option<Arc<RemoteIdentities>> {
        self.held.load_full()
    }

    /// The peer the held list names at `address`.
    #[must_use]
    pub fn lookup(&self, address: IpAddr) -> Option<RemoteEntry> {
        self.held.load().as_ref()?.get(address).cloned()
    }

    #[must_use]
    pub fn status(&self) -> RemoteStatus {
        self.status_at(now())
    }

    fn status_at(&self, at: u64) -> RemoteStatus {
        match self.held.load().as_ref() {
            Some(held) => RemoteStatus {
                version: Some(held.version().to_owned()),
                received_at: Some(held.received_at()),
                age_seconds: Some(held.age(at)),
                entries: held.len(),
                conflicts: held.conflicts(),
            },
            None => RemoteStatus {
                version: None,
                received_at: None,
                age_seconds: None,
                entries: 0,
                conflicts: 0,
            },
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn snapshot(version: &str, addresses: &[&str]) -> RemoteSnapshot {
        let entries = addresses
            .iter()
            .map(|a| serde_json::json!({"address": a, "kind": "pod", "pod": "web-0", "node": "b"}))
            .collect::<Vec<_>>();
        serde_json::from_value(serde_json::json!({"version": version, "entries": entries})).unwrap()
    }

    #[test]
    fn a_node_with_no_list_names_nobody() {
        let store = RemoteIdentityStore::new();
        assert_eq!(store.status().version, None);
        assert!(store.lookup("10.0.0.2".parse().unwrap()).is_none());
        assert!(store.current().is_none());
    }

    #[test]
    fn a_refused_list_leaves_the_last_one_in_place() {
        let store = RemoteIdentityStore::new();
        let status = store
            .replace_at(snapshot("v1", &["10.0.0.2"]), 100)
            .unwrap();
        assert_eq!(status.version.as_deref(), Some("v1"));
        assert_eq!(status.entries, 1);
        assert!(
            store
                .replace_at(snapshot("v2", &["10.0.0.3", "10.0.0.3"]), 200)
                .is_err()
        );
        assert_eq!(store.status_at(400).version.as_deref(), Some("v1"));
        assert_eq!(store.status_at(400).age_seconds, Some(300));
        assert!(store.lookup("10.0.0.2".parse().unwrap()).is_some());
        store
            .replace_at(snapshot("v3", &["10.0.0.4"]), 500)
            .unwrap();
        assert!(store.lookup("10.0.0.2".parse().unwrap()).is_none());
        assert_eq!(store.current().unwrap().version(), "v3");
    }
}
