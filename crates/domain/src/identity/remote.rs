//! What this node was told about the addresses of the other nodes.
//!
//! The console reads every node's own addresses and hands each node the
//! addresses of its peers. What a node holds is exactly the last list it was
//! handed, whole: a list is taken entire or refused entire, so a node never
//! holds half of one version and half of another, and an address the list
//! does not carry is an address with no name. Nothing is inferred from a
//! neighbouring address, a subnet or an older list.
//!
//! The list is kept for as long as no newer one arrives. A node cut off from
//! the console keeps naming its peers from the last version and says how old
//! that version is, because a remote rule falling silent the moment a console
//! restarts would be worse than one reading a list some minutes old.

use std::collections::HashMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{AddressIdentity, is_publishable};

/// The most remote addresses one node holds. A list past it is refused, and
/// the node keeps the one it had.
pub const REMOTE_IDENTITIES_MAX: usize = 65_536;

/// One address of another node, and the node holding it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteEntry {
    /// The name of the node the address is on, as the console knows it.
    pub node: String,
    #[serde(flatten)]
    pub identity: AddressIdentity,
}

/// A list as the console hands it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteSnapshot {
    /// The console's name for this list. The same entries carry the same
    /// version.
    pub version: String,
    pub entries: Vec<RemoteEntry>,
    /// Addresses two nodes claimed, which the console named to nobody.
    #[serde(default)]
    pub conflicts: usize,
}

/// Why a list was not taken.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RemoteRefusal {
    #[error("the list carries no version")]
    NoVersion,
    #[error("the list carries {held} addresses, more than the {max} a node holds")]
    TooMany { held: usize, max: usize },
    #[error("the list names {0} twice")]
    Duplicate(IpAddr),
    #[error("the list names {0}, which no other node can reach")]
    Unreachable(IpAddr),
}

/// The list a node holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteIdentities {
    version: String,
    received_at: u64,
    conflicts: usize,
    entries: HashMap<IpAddr, RemoteEntry>,
}

impl RemoteIdentities {
    /// Take a list handed at `now`, in seconds since the epoch, whole or
    /// not at all.
    pub fn accept(snapshot: RemoteSnapshot, now: u64) -> Result<Self, RemoteRefusal> {
        if snapshot.version.trim().is_empty() {
            return Err(RemoteRefusal::NoVersion);
        }
        if snapshot.entries.len() > REMOTE_IDENTITIES_MAX {
            return Err(RemoteRefusal::TooMany {
                held: snapshot.entries.len(),
                max: REMOTE_IDENTITIES_MAX,
            });
        }
        let mut entries = HashMap::with_capacity(snapshot.entries.len());
        for entry in snapshot.entries {
            let address = entry.identity.address;
            if !is_publishable(address) {
                return Err(RemoteRefusal::Unreachable(address));
            }
            if entries.insert(address, entry).is_some() {
                return Err(RemoteRefusal::Duplicate(address));
            }
        }
        Ok(Self {
            version: snapshot.version,
            received_at: now,
            conflicts: snapshot.conflicts,
            entries,
        })
    }

    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// When the list was taken, in seconds since the epoch.
    #[must_use]
    pub fn received_at(&self) -> u64 {
        self.received_at
    }

    /// How old the list is at `now`.
    #[must_use]
    pub fn age(&self, now: u64) -> u64 {
        now.saturating_sub(self.received_at)
    }

    #[must_use]
    pub fn conflicts(&self) -> usize {
        self.conflicts
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The workload the list names at `address`, and nothing for an
    /// address it does not carry.
    #[must_use]
    pub fn get(&self, address: IpAddr) -> Option<&RemoteEntry> {
        self.entries.get(&address)
    }

    /// Every address the list carries, in no particular order.
    pub fn entries(&self) -> impl Iterator<Item = &RemoteEntry> {
        self.entries.values()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::identity::IdentityKind;

    fn entry(address: &str, node: &str) -> RemoteEntry {
        let mut identity = AddressIdentity::bare(address.parse().unwrap(), IdentityKind::Pod);
        identity.pod = Some("web-0".into());
        identity.namespace = Some("shop".into());
        RemoteEntry {
            node: node.into(),
            identity,
        }
    }

    fn snapshot(entries: Vec<RemoteEntry>) -> RemoteSnapshot {
        RemoteSnapshot {
            version: "v1".into(),
            entries,
            conflicts: 2,
        }
    }

    #[test]
    fn a_list_is_taken_whole_and_names_only_what_it_carries() {
        let held = RemoteIdentities::accept(snapshot(vec![entry("10.0.0.2", "b")]), 1_000).unwrap();
        assert_eq!(held.version(), "v1");
        assert_eq!(held.len(), 1);
        assert_eq!(held.conflicts(), 2);
        assert_eq!(held.age(1_090), 90);
        assert_eq!(held.age(10), 0);
        let found = held.get("10.0.0.2".parse().unwrap()).unwrap();
        assert_eq!(found.node, "b");
        assert_eq!(found.identity.pod.as_deref(), Some("web-0"));
        assert!(held.get("10.0.0.3".parse().unwrap()).is_none());
    }

    #[test]
    fn a_list_is_refused_whole() {
        let twice = snapshot(vec![entry("10.0.0.2", "b"), entry("10.0.0.2", "c")]);
        assert_eq!(
            RemoteIdentities::accept(twice, 0),
            Err(RemoteRefusal::Duplicate("10.0.0.2".parse().unwrap()))
        );
        let loopback = snapshot(vec![entry("127.0.0.1", "b")]);
        assert!(matches!(
            RemoteIdentities::accept(loopback, 0),
            Err(RemoteRefusal::Unreachable(_))
        ));
        let mut unnamed = snapshot(Vec::new());
        unnamed.version = " ".into();
        assert_eq!(
            RemoteIdentities::accept(unnamed, 0),
            Err(RemoteRefusal::NoVersion)
        );
    }

    #[test]
    fn the_wire_shape_is_the_identity_with_its_node() {
        let wire = serde_json::json!({
            "version": "abc",
            "entries": [{"address": "10.0.0.9", "kind": "container", "container": "db", "node": "n2"}]
        });
        let parsed: RemoteSnapshot = serde_json::from_value(wire).unwrap();
        assert_eq!(parsed.conflicts, 0);
        assert_eq!(parsed.entries[0].node, "n2");
        assert_eq!(parsed.entries[0].identity.container.as_deref(), Some("db"));
        let back = serde_json::to_value(&parsed.entries[0]).unwrap();
        assert_eq!(back["node"], "n2");
        assert_eq!(back["address"], "10.0.0.9");
    }
}
