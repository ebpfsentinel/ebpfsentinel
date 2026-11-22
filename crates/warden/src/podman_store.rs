//! One Podman container's record, read from its owner's container store.
//!
//! Podman is daemonless: unless its owner enabled `podman.socket`, nothing
//! answers on a socket. What every Podman writes whatever its socket is its
//! store. Podman 4.8 and later keep their own state in `<store>/db.sql`, a
//! SQLite database whose `ContainerConfig` table holds each container's
//! configuration as JSON, labels included, and whose `ContainerState` table
//! holds its state. Under it, `containers/storage` lists every container in
//! `<store>/<driver>-containers/containers.json`, with its name and image
//! and without labels; it is read where the database is not there or cannot
//! be opened, which is what an older Podman on `BoltDB` leaves.
//!
//! The store is root's to read: `0700` and owned by root for root's
//! containers, under the user's home for a user's. The agent runs in a user
//! namespace of its own where neither is in reach, so the warden reads it and
//! hands back the name, the image, the labels, the creation time and the
//! state of the one container asked, nothing else: never a descriptor, never
//! a path, never another container.
//!
//! The agent names a user and a store relative to that user's home, never a
//! file: the home is read from the password file here. A store directory not
//! owned by the container's owner, or a database or list that is a link or
//! owned by somebody else, is not read, so a user cannot point the read at a
//! store that is not theirs. Nothing is written to the store; a database
//! the read cannot walk, one caught mid-write included, is a miss and the
//! list is read instead.
//!
//! The database is walked by the same first-party reader the package
//! inventory walks the rpm database with: no SQLite library is linked, and
//! nothing but the two rows of the one container is decoded beyond the
//! page walk.

use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use domain::inventory::sqlite::{Database, Value};
use ebpfsentinel_warden_proto::{PodmanRecord, PodmanStoreRead, valid_podman_id};
use serde::Deserialize;

/// Where each user's home is read from.
pub const PASSWD: &str = "/etc/passwd";

/// Podman's own database, under the store.
const DATABASE: &str = "db.sql";

/// Largest database or container list read. A store holding tens of
/// thousands of containers is a few megabytes; anything larger is not one.
const MAX_STORE_BYTES: u64 = 64 * 1024 * 1024;

/// The container `id` as the store of `uid`, `None` for root, records it.
///
/// `store` is root's store directory, absolute, or the user's store relative
/// to the home `passwd` gives them; neither may climb with `..`.
#[must_use]
pub fn read(passwd: &Path, uid: Option<u32>, store: &str, id: &str) -> PodmanStoreRead {
    match store_dir(passwd, uid, store) {
        Some(dir) => read_record(&dir, uid.unwrap_or(0), id),
        None => PodmanStoreRead::NoStore,
    }
}

/// The store directory of `uid`, `None` for root, or `None` when `store` is
/// not one this owner may name.
#[must_use]
pub fn store_dir(passwd: &Path, uid: Option<u32>, store: &str) -> Option<PathBuf> {
    let path = Path::new(store);
    if store.is_empty() || path.components().any(|c| c == Component::ParentDir) {
        return None;
    }
    match uid {
        None => path.is_absolute().then(|| path.to_path_buf()),
        // Root's store is named as root's, never as a user's.
        Some(0) => None,
        Some(uid) => {
            if path.is_absolute() {
                return None;
            }
            let passwd = std::fs::read_to_string(passwd).ok()?;
            Some(home_of(&passwd, uid)?.join(path))
        }
    }
}

/// The home directory the password file gives `uid`.
#[must_use]
pub fn home_of(passwd: &str, uid: u32) -> Option<PathBuf> {
    let uid = uid.to_string();
    passwd.lines().find_map(|line| {
        let fields: Vec<&str> = line.split(':').collect();
        (fields.len() >= 7 && fields[2] == uid && fields[5].starts_with('/'))
            .then(|| PathBuf::from(fields[5]))
    })
}

/// The container `id` in the store at `dir`, which `owner` must own.
#[must_use]
pub fn read_record(dir: &Path, owner: u32, id: &str) -> PodmanStoreRead {
    if !valid_podman_id(id) {
        return PodmanStoreRead::Missing;
    }
    match std::fs::metadata(dir) {
        Ok(meta) if meta.is_dir() && meta.uid() == owner => {}
        _ => return PodmanStoreRead::NoStore,
    }
    if let Some(record) =
        read_owned(&dir.join(DATABASE), owner).and_then(|bytes| from_database(&bytes, id))
    {
        return PodmanStoreRead::Found(record);
    }
    from_lists(dir, owner, id).map_or(PodmanStoreRead::Missing, PodmanStoreRead::Found)
}

/// The bytes of `path` when it is a plain file owned by `owner`, not a link,
/// and of a size a store writes.
fn read_owned(path: &Path, owner: u32) -> Option<Vec<u8>> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.file_type().is_file() || meta.uid() != owner || meta.len() > MAX_STORE_BYTES {
        return None;
    }
    std::fs::read(path).ok()
}

/// A container's configuration as Podman stores it in its database.
#[derive(Deserialize)]
struct StoredConfig {
    #[serde(default)]
    name: String,
    #[serde(default)]
    labels: Option<BTreeMap<String, String>>,
    #[serde(default, rename = "rootfsImageName")]
    image_name: String,
    #[serde(default, rename = "rootfsImageID")]
    image_id: String,
    #[serde(default, rename = "createdTime")]
    created: String,
}

/// A container's state as Podman stores it in its database.
#[derive(Deserialize)]
struct StoredState {
    #[serde(default)]
    state: i64,
}

/// The name Podman's API gives the state it stores as a number. A
/// container configured and not yet initialised is reported as created, as
/// Podman reports it.
fn state_name(state: i64) -> &'static str {
    match state {
        1 | 2 => "created",
        3 => "running",
        4 => "stopped",
        5 => "paused",
        6 => "exited",
        7 => "removing",
        8 => "stopping",
        _ => "",
    }
}

/// The bytes of column `index` of `row`, text or blob: Podman binds its JSON
/// as a byte slice, which SQLite stores as a blob.
fn text(columns: &[Value], index: usize) -> Option<&[u8]> {
    match columns.get(index)? {
        Value::Text(t) | Value::Blob(t) => Some(t),
        _ => None,
    }
}

/// The JSON column of the row of `table` whose first column, its id, is `id`.
/// Both tables Podman keeps a container in are rowid tables keyed by a text
/// id, with the JSON last, so the table is walked rather than its index.
fn json_of(db: &Database<'_>, table: &str, id: &str, json: usize) -> Option<Vec<u8>> {
    let rows = db.rows(db.table_root(table).ok()?).ok()?;
    rows.into_iter().find_map(|row| {
        (text(&row.columns, 0)? == id.as_bytes())
            .then(|| text(&row.columns, json).map(<[u8]>::to_vec))?
    })
}

/// The container `id` in the bytes of Podman's database, walked by the
/// reader the package inventory uses rather than by a linked SQLite.
fn from_database(bytes: &[u8], id: &str) -> Option<PodmanRecord> {
    let db = Database::open(bytes).ok()?;
    // ContainerConfig(ID, Name, PodID, JSON).
    let config: StoredConfig =
        serde_json::from_slice(&json_of(&db, "ContainerConfig", id, 3)?).ok()?;
    // ContainerState(ID, State, ExitCode, JSON): the state the JSON records
    // is the one Podman keeps current.
    let state = json_of(&db, "ContainerState", id, 3)
        .and_then(|json| serde_json::from_slice::<StoredState>(&json).ok())
        .map_or(0, |s| s.state);
    Some(PodmanRecord {
        name: config.name,
        image: if config.image_name.is_empty() {
            config.image_id
        } else {
            config.image_name
        },
        labels: config.labels.unwrap_or_default().into_iter().collect(),
        labels_read: true,
        created: config.created,
        status: state_name(state).to_owned(),
    })
}

/// One entry of `containers/storage`'s container list.
#[derive(Deserialize)]
struct ListedContainer {
    id: String,
    #[serde(default)]
    names: Vec<String>,
    #[serde(default)]
    image: String,
    #[serde(default)]
    metadata: String,
    #[serde(default)]
    created: String,
}

/// The part of a list entry's metadata string Podman fills.
#[derive(Deserialize, Default)]
struct ListedMetadata {
    #[serde(default, rename = "image-name")]
    image_name: String,
}

fn from_lists(dir: &Path, owner: u32, id: &str) -> Option<PodmanRecord> {
    std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .filter(|entry| entry.file_name().to_string_lossy().ends_with("-containers"))
        .find_map(|entry| {
            find_listed(
                &read_owned(&entry.path().join("containers.json"), owner)?,
                id,
            )
        })
}

/// The container `id` in one `containers.json`.
#[must_use]
fn find_listed(bytes: &[u8], id: &str) -> Option<PodmanRecord> {
    let listed: Vec<ListedContainer> = serde_json::from_slice(bytes).ok()?;
    let c = listed.into_iter().find(|c| c.id == id)?;
    let meta: ListedMetadata = serde_json::from_str(&c.metadata).unwrap_or_default();
    Some(PodmanRecord {
        name: c.names.into_iter().next().unwrap_or_default(),
        image: if meta.image_name.is_empty() {
            c.image
        } else {
            meta.image_name
        },
        labels: Vec::new(),
        labels_read: false,
        created: c.created,
        status: String::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A store Podman 5 wrote: `shop-front` created with two labels,
    /// `shop-back` running with one, `batch` exited without any. Written by
    /// `tests/fixtures/make-podman-db.sh`, which prints the ids below.
    const DB: &[u8] = include_bytes!("../tests/fixtures/podman-db.sqlite");
    const CREATED: &str = "91cc0e1d480f880f85305a968913b924d4a3b16f35b58aa2e7cd426f1ec4c813";
    const RUNNING: &str = "4042b1292d417efd87a72b02b936d667ce79642811512435fc4f624097bca743";
    const EXITED: &str = "c4115bb3d86734609da9ad5666f2cbcf9ecd7a3c639e2a61a5e62739b6f2c7e1";
    const ID: &str = "9c503e64bd42f67b7b1592f98d2fc3443149c7b875cc39327b13e2ad8df85c33";

    fn me() -> u32 {
        let dir = tempfile::tempdir().unwrap();
        std::fs::metadata(dir.path()).unwrap().uid()
    }

    fn found(read: PodmanStoreRead) -> PodmanRecord {
        match read {
            PodmanStoreRead::Found(record) => record,
            other => panic!("expected a record, got {other:?}"),
        }
    }

    fn list(dir: &Path, name: &str) {
        std::fs::create_dir_all(dir.join("overlay-containers")).unwrap();
        std::fs::write(
            dir.join("overlay-containers/containers.json"),
            format!(
                r#"[{{"id":"{ID}","names":["{name}"],"image":"abc","metadata":"{{\"image-name\":\"docker.io/library/nginx:1.27\"}}","created":"2026-11-22T00:04:04Z"}}]"#
            ),
        )
        .unwrap();
    }

    #[test]
    fn a_containers_name_image_labels_and_state_come_from_podmans_database() {
        let front = from_database(DB, CREATED).unwrap();
        assert_eq!(front.name, "shop-front");
        assert_eq!(front.image, "docker.io/library/busybox:1.36");
        assert_eq!(
            front.labels,
            vec![
                ("app".to_owned(), "shop".to_owned()),
                ("tier".to_owned(), "front".to_owned())
            ]
        );
        assert!(front.labels_read);
        assert_eq!(front.status, "created");
        assert!(front.created.starts_with("2026-11-22T00:45:12"));

        let back = from_database(DB, RUNNING).unwrap();
        assert_eq!(
            (back.name.as_str(), back.status.as_str()),
            ("shop-back", "running")
        );
        assert_eq!(back.labels, vec![("app".to_owned(), "shop".to_owned())]);

        let batch = from_database(DB, EXITED).unwrap();
        assert_eq!(batch.status, "exited");
        assert!(batch.labels.is_empty() && batch.labels_read);

        assert!(from_database(DB, ID).is_none());
    }

    #[test]
    fn a_truncated_or_foreign_database_is_a_miss_not_a_panic() {
        for cut in [0, 100, 4096, DB.len() / 2] {
            let _ = from_database(&DB[..cut], RUNNING);
        }
        assert!(from_database(b"not a database at all", RUNNING).is_none());
    }

    #[test]
    fn the_store_is_read_from_its_database_and_from_its_list_where_there_is_none() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(DATABASE), DB).unwrap();
        list(dir.path(), "listed");
        assert_eq!(
            found(read_record(dir.path(), me(), RUNNING)).name,
            "shop-back"
        );
        let listed = found(read_record(dir.path(), me(), ID));
        assert_eq!(listed.name, "listed");
        assert_eq!(listed.image, "docker.io/library/nginx:1.27");
        assert!(!listed.labels_read);
        assert_eq!(
            read_record(dir.path(), me(), &"0".repeat(64)),
            PodmanStoreRead::Missing
        );
        assert_eq!(
            read_record(dir.path(), me(), "web"),
            PodmanStoreRead::Missing
        );
    }

    #[test]
    fn a_store_somebody_else_owns_is_never_read() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(DATABASE), DB).unwrap();
        assert_eq!(
            read_record(dir.path(), me().wrapping_add(1), RUNNING),
            PodmanStoreRead::NoStore
        );
    }

    #[test]
    fn a_database_or_list_that_is_a_link_is_never_followed() {
        let elsewhere = tempfile::tempdir().unwrap();
        std::fs::write(elsewhere.path().join("db"), DB).unwrap();
        list(elsewhere.path(), "linked");
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(elsewhere.path().join("db"), dir.path().join(DATABASE)).unwrap();
        std::fs::create_dir(dir.path().join("overlay-containers")).unwrap();
        std::os::unix::fs::symlink(
            elsewhere.path().join("overlay-containers/containers.json"),
            dir.path().join("overlay-containers/containers.json"),
        )
        .unwrap();
        assert_eq!(
            read_record(dir.path(), me(), RUNNING),
            PodmanStoreRead::Missing
        );
        assert_eq!(read_record(dir.path(), me(), ID), PodmanStoreRead::Missing);
    }

    #[test]
    fn a_store_is_named_under_its_owner_and_never_climbs_out() {
        let passwd = "root:x:0:0::/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/sh\nodd:x:1001:1001::relative:/bin/sh\n";
        assert_eq!(home_of(passwd, 1000), Some(PathBuf::from("/home/alice")));
        assert_eq!(home_of(passwd, 1001), None);
        assert_eq!(home_of(passwd, 2000), None);

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("passwd");
        std::fs::write(&file, passwd).unwrap();
        assert_eq!(
            store_dir(&file, Some(1000), ".local/share/containers/storage"),
            Some(PathBuf::from("/home/alice/.local/share/containers/storage"))
        );
        assert_eq!(
            store_dir(&file, None, "/var/lib/containers/storage"),
            Some(PathBuf::from("/var/lib/containers/storage"))
        );
        assert_eq!(store_dir(&file, None, "var/lib/containers/storage"), None);
        assert_eq!(store_dir(&file, None, "/var/lib/../../etc"), None);
        assert_eq!(
            store_dir(&file, Some(1000), "/var/lib/containers/storage"),
            None
        );
        assert_eq!(store_dir(&file, Some(1000), "../bob/store"), None);
        assert_eq!(store_dir(&file, Some(0), "store"), None);
        assert_eq!(store_dir(&file, Some(1000), ""), None);
        assert_eq!(
            read(&file, Some(2000), "store", RUNNING),
            PodmanStoreRead::NoStore
        );
    }

    #[test]
    fn podmans_states_are_named_as_its_api_names_them() {
        assert_eq!(state_name(1), "created");
        assert_eq!(state_name(3), "running");
        assert_eq!(state_name(6), "exited");
        assert_eq!(state_name(0), "");
        assert_eq!(state_name(99), "");
    }
}
