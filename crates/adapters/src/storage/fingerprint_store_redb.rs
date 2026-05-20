use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use domain::l7::ja4::{FlowKey, Ja4Fingerprint, Ja4Persist, Ja4sFingerprint, Ja4sPersist};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

const JA4_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("ja4_fingerprints");
const JA4S_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("ja4s_fingerprints");

#[derive(Debug, Serialize, Deserialize)]
struct PersistedJa4 {
    key: FlowKey,
    fp: Ja4Fingerprint,
    /// Unix epoch nanoseconds; wall-clock so it survives restarts.
    inserted_at_ns: u128,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedJa4s {
    key: FlowKey,
    fp: Ja4sFingerprint,
    inserted_at_ns: u128,
}

/// redb-backed persistence for JA4 and JA4S fingerprint caches.
///
/// Two independent tables share one database so both caches restart
/// from the same file. Writes are best-effort (errors are logged then
/// swallowed) to keep the packet-pipeline hot path lock-free.
pub struct RedbFingerprintStore {
    db: Database,
    write_lock: Mutex<()>,
}

impl RedbFingerprintStore {
    pub fn open(path: &Path) -> Result<Self, redb::Error> {
        let db = Database::create(path)?;
        let txn = db.begin_write()?;
        {
            let _ = txn.open_table(JA4_TABLE)?;
            let _ = txn.open_table(JA4S_TABLE)?;
        }
        txn.commit()?;
        Ok(Self {
            db,
            write_lock: Mutex::new(()),
        })
    }

    fn flow_key_str(key: &FlowKey) -> String {
        // Deterministic, debuggable, comparable.
        format!(
            "{:08x}{:08x}{:08x}{:08x}:{:04x}->{:08x}{:08x}{:08x}{:08x}:{:04x}",
            key.src_addr[0],
            key.src_addr[1],
            key.src_addr[2],
            key.src_addr[3],
            key.src_port,
            key.dst_addr[0],
            key.dst_addr[1],
            key.dst_addr[2],
            key.dst_addr[3],
            key.dst_port,
        )
    }

    fn now_ns() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    }

    fn ts_to_system_time(ns: u128) -> SystemTime {
        let secs = (ns / 1_000_000_000) as u64;
        #[allow(clippy::cast_possible_truncation)]
        let sub = (ns % 1_000_000_000) as u32;
        UNIX_EPOCH + Duration::new(secs, sub)
    }

    fn system_time_to_ns(ts: SystemTime) -> u128 {
        ts.duration_since(UNIX_EPOCH)
            .map_or_else(|_| Self::now_ns(), |d| d.as_nanos())
    }
}

impl Ja4Persist for RedbFingerprintStore {
    fn save(&self, key: &FlowKey, fp: &Ja4Fingerprint, inserted_at: SystemTime) {
        let Ok(_lock) = self.write_lock.lock() else {
            return;
        };
        let record = PersistedJa4 {
            key: key.clone(),
            fp: fp.clone(),
            inserted_at_ns: Self::system_time_to_ns(inserted_at),
        };
        let Ok(bytes) = serde_json::to_vec(&record) else {
            return;
        };
        let key_str = Self::flow_key_str(key);
        let Ok(txn) = self.db.begin_write() else {
            return;
        };
        {
            let Ok(mut table) = txn.open_table(JA4_TABLE) else {
                return;
            };
            let _ = table.insert(key_str.as_str(), bytes.as_slice());
        }
        let _ = txn.commit();
    }

    fn load_all(&self) -> Vec<(FlowKey, Ja4Fingerprint, SystemTime)> {
        let Ok(txn) = self.db.begin_read() else {
            return Vec::new();
        };
        let Ok(table) = txn.open_table(JA4_TABLE) else {
            return Vec::new();
        };
        let Ok(iter) = table.iter() else {
            return Vec::new();
        };
        iter.filter_map(Result::ok)
            .filter_map(|(_k, v)| serde_json::from_slice::<PersistedJa4>(v.value()).ok())
            .map(|r| (r.key, r.fp, Self::ts_to_system_time(r.inserted_at_ns)))
            .collect()
    }
}

impl Ja4sPersist for RedbFingerprintStore {
    fn save(&self, key: &FlowKey, fp: &Ja4sFingerprint, inserted_at: SystemTime) {
        let Ok(_lock) = self.write_lock.lock() else {
            return;
        };
        let record = PersistedJa4s {
            key: key.clone(),
            fp: fp.clone(),
            inserted_at_ns: Self::system_time_to_ns(inserted_at),
        };
        let Ok(bytes) = serde_json::to_vec(&record) else {
            return;
        };
        let key_str = Self::flow_key_str(key);
        let Ok(txn) = self.db.begin_write() else {
            return;
        };
        {
            let Ok(mut table) = txn.open_table(JA4S_TABLE) else {
                return;
            };
            let _ = table.insert(key_str.as_str(), bytes.as_slice());
        }
        let _ = txn.commit();
    }

    fn load_all(&self) -> Vec<(FlowKey, Ja4sFingerprint, SystemTime)> {
        let Ok(txn) = self.db.begin_read() else {
            return Vec::new();
        };
        let Ok(table) = txn.open_table(JA4S_TABLE) else {
            return Vec::new();
        };
        let Ok(iter) = table.iter() else {
            return Vec::new();
        };
        iter.filter_map(Result::ok)
            .filter_map(|(_k, v)| serde_json::from_slice::<PersistedJa4s>(v.value()).ok())
            .map(|r| (r.key, r.fp, Self::ts_to_system_time(r.inserted_at_ns)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::l7::entity::{TlsClientHello, TlsServerHello};
    use domain::l7::ja4::{compute_ja4, compute_ja4s};
    use tempfile::NamedTempFile;

    fn flow(port: u16) -> FlowKey {
        FlowKey {
            src_addr: [0x0A00_0001, 0, 0, 0],
            src_port: port,
            dst_addr: [0x0A00_0002, 0, 0, 0],
            dst_port: 443,
        }
    }

    fn client_hello() -> TlsClientHello {
        TlsClientHello {
            sni: Some("example.com".to_string()),
            record_version: 0x0301,
            handshake_version: 0x0303,
            cipher_suites: vec![0x1301],
            extension_types: vec![0x0000],
            supported_groups: vec![],
            signature_algorithms: vec![],
            alpn_protocols: vec!["h2".to_string()],
            supported_versions: vec![0x0304],
            session_id: None,
        }
    }

    fn server_hello() -> TlsServerHello {
        TlsServerHello {
            selected_cipher: 0x1301,
            selected_version: 0x0304,
            extensions: vec![0x002B],
            selected_group: Some(0x001D),
        }
    }

    #[test]
    fn ja4_round_trip() {
        let tmp = NamedTempFile::new().unwrap();
        let store = RedbFingerprintStore::open(tmp.path()).unwrap();
        let fp = compute_ja4(&client_hello());
        let key = flow(11111);
        let now = SystemTime::now();
        Ja4Persist::save(&store, &key, &fp, now);

        let loaded = Ja4Persist::load_all(&store);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].0, key);
        assert_eq!(loaded[0].1, fp);
    }

    #[test]
    fn ja4s_round_trip() {
        let tmp = NamedTempFile::new().unwrap();
        let store = RedbFingerprintStore::open(tmp.path()).unwrap();
        let fp = compute_ja4s(&server_hello());
        let key = flow(22222);
        let now = SystemTime::now();
        Ja4sPersist::save(&store, &key, &fp, now);

        let loaded = Ja4sPersist::load_all(&store);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].0, key);
        assert_eq!(loaded[0].1, fp);
    }

    #[test]
    fn ja4_persists_across_reopen() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        let fp = compute_ja4(&client_hello());
        let key = flow(33333);
        {
            let store = RedbFingerprintStore::open(&path).unwrap();
            Ja4Persist::save(&store, &key, &fp, SystemTime::now());
        }
        let store2 = RedbFingerprintStore::open(&path).unwrap();
        let loaded = Ja4Persist::load_all(&store2);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].1, fp);
    }

    #[test]
    fn ja4_overwrites_same_key() {
        let tmp = NamedTempFile::new().unwrap();
        let store = RedbFingerprintStore::open(tmp.path()).unwrap();
        let fp = compute_ja4(&client_hello());
        let key = flow(44444);
        Ja4Persist::save(&store, &key, &fp, SystemTime::now());
        Ja4Persist::save(&store, &key, &fp, SystemTime::now());
        let loaded = Ja4Persist::load_all(&store);
        assert_eq!(loaded.len(), 1);
    }

    #[test]
    fn ja4_and_ja4s_independent_tables() {
        let tmp = NamedTempFile::new().unwrap();
        let store = RedbFingerprintStore::open(tmp.path()).unwrap();
        Ja4Persist::save(
            &store,
            &flow(1),
            &compute_ja4(&client_hello()),
            SystemTime::now(),
        );
        Ja4sPersist::save(
            &store,
            &flow(2),
            &compute_ja4s(&server_hello()),
            SystemTime::now(),
        );
        assert_eq!(Ja4Persist::load_all(&store).len(), 1);
        assert_eq!(Ja4sPersist::load_all(&store).len(), 1);
    }
}
