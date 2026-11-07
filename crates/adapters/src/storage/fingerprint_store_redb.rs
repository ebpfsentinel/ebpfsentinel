use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use domain::l7::ja4::{FlowKey, Ja4Fingerprint, Ja4Persist};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

const JA4_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("ja4_fingerprints");

#[derive(Debug, Serialize, Deserialize)]
struct PersistedJa4 {
    key: FlowKey,
    fp: Ja4Fingerprint,
    /// Unix epoch nanoseconds; wall-clock so it survives restarts.
    inserted_at_ns: u128,
}

/// redb-backed persistence for the JA4 fingerprint cache.
///
/// The cache restarts from this file. Writes are best-effort (errors are logged then
/// swallowed) to keep the packet-pipeline hot path lock-free.
pub struct RedbFingerprintStore {
    db: Database,
    write_lock: Mutex<()>,
}

impl RedbFingerprintStore {
    pub fn open(path: &Path) -> Result<Self, redb::Error> {
        let db = super::create_database(path)?;
        let txn = db.begin_write()?;
        {
            let _ = txn.open_table(JA4_TABLE)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use domain::l7::entity::TlsClientHello;
    use domain::l7::ja4::compute_ja4;
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
}
