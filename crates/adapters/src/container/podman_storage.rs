//! Podman's own record of its containers, read without its API.
//!
//! Podman is daemonless: unless an owner enabled `podman.socket`, nothing
//! answers on a socket, and the enricher has no API to ask. What every
//! Podman writes whatever its socket is its container store: root's under
//! `/var/lib/containers/storage`, a user's under their home,
//! `~/.local/share/containers/storage`. Its `db.sql` carries each
//! container's name, image, labels and state; an older Podman on `BoltDB`
//! leaves only `containers/storage`'s list, with the name and the image and
//! without the labels.
//!
//! The store is root's to read and the agent runs in a user namespace of its
//! own, so where a warden runs it reads the store and hands back the one
//! record asked ([`ebpfsentinel_warden::podman_store`]). Without one, the
//! agent runs as root on the host and reads it itself, with the same code.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use domain::container::entity::DockerMetadata;
use ebpfsentinel_warden::podman_store;
use ebpfsentinel_warden_client::{PodmanRecord, PodmanStoreRead, ReconnectingClient};

/// Root's container store.
pub const DEFAULT_STORAGE_ROOT: &str = "/var/lib/containers/storage";
/// A user's container store, relative to their home.
pub const DEFAULT_ROOTLESS_STORAGE: &str = ".local/share/containers/storage";
/// Where each user's home is read from.
pub const PASSWD: &str = podman_store::PASSWD;

/// Root's and each user's container store, read on demand.
pub struct PodmanStorage {
    /// `None` when root's store is not read.
    root: Option<PathBuf>,
    /// Relative to each user's home; `None` when users' stores are not read.
    rootless: Option<PathBuf>,
    passwd: PathBuf,
    /// The warden that reads the stores, in a rootless deployment.
    warden: Option<Arc<Mutex<ReconnectingClient>>>,
    /// Who owns root's store: root, but whoever runs the tests in them.
    root_owner: u32,
}

impl PodmanStorage {
    #[must_use]
    pub fn new(root: Option<PathBuf>, rootless: Option<PathBuf>, passwd: PathBuf) -> Self {
        Self {
            root,
            rootless,
            passwd,
            warden: None,
            root_owner: 0,
        }
    }

    /// Read the stores through `warden` when there is one.
    #[must_use]
    pub fn through(mut self, warden: Option<Arc<Mutex<ReconnectingClient>>>) -> Self {
        self.warden = warden;
        self
    }

    /// Take root's store as owned by `uid`, which is who runs the tests.
    #[cfg(test)]
    #[must_use]
    pub fn owned_by(mut self, uid: u32) -> Self {
        self.root_owner = uid;
        self
    }

    /// Whether any store is read at all.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.root.is_some() || self.rootless.is_some()
    }

    /// The container `id` as the store of `uid`, `None` for root, records it.
    /// Blocking: a file read, or a round trip to the warden.
    #[must_use]
    pub fn lookup(&self, uid: Option<u32>, id: &str) -> PodmanStoreRead {
        let store = match uid {
            None => self.root.as_deref(),
            Some(_) => self.rootless.as_deref(),
        };
        let Some(store) = store.and_then(Path::to_str) else {
            return PodmanStoreRead::NoStore;
        };
        if let Some(warden) = &self.warden {
            let mut warden = warden.lock().unwrap_or_else(PoisonError::into_inner);
            return warden
                .read_podman_record(uid, store, id)
                .unwrap_or(PodmanStoreRead::NoStore);
        }
        match podman_store::store_dir(&self.passwd, uid, store) {
            Some(dir) => podman_store::read_record(&dir, uid.unwrap_or(self.root_owner), id),
            None => PodmanStoreRead::NoStore,
        }
    }
}

/// A store record as the container cache holds one.
#[must_use]
pub fn metadata_of(record: PodmanRecord) -> DockerMetadata {
    DockerMetadata {
        name: record.name,
        image: record.image,
        labels: record.labels,
        created_at: record.created,
        status: record.status,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "9c503e64bd42f67b7b1592f98d2fc3443149c7b875cc39327b13e2ad8df85c33";

    /// Who runs the tests: the owner of a directory they just made.
    fn me() -> u32 {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::metadata(dir.path()).unwrap().uid()
    }

    fn list(dir: &Path, name: &str) {
        std::fs::create_dir_all(dir.join("vfs-containers")).unwrap();
        std::fs::write(
            dir.join("vfs-containers/containers.json"),
            format!(
                r#"[{{"id":"{ID}","names":["{name}"],"image":"abc","created":"2026-11-22T00:04:04Z"}}]"#
            ),
        )
        .unwrap();
    }

    #[test]
    fn roots_and_a_users_store_are_read_in_process_without_a_warden() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root-store");
        list(&root, "web");
        let home = dir.path().join("home/alice");
        list(&home.join("store"), "mine");
        let passwd = dir.path().join("passwd");
        std::fs::write(
            &passwd,
            format!("alice:x:{0}:{0}::{1}:/bin/sh\n", me(), home.display()),
        )
        .unwrap();

        let storage =
            PodmanStorage::new(Some(root), Some(PathBuf::from("store")), passwd).owned_by(me());
        assert!(matches!(storage.lookup(None, ID), PodmanStoreRead::Found(r) if r.name == "web"));
        assert!(
            matches!(storage.lookup(Some(me()), ID), PodmanStoreRead::Found(r) if r.name == "mine")
        );
        assert_eq!(
            storage.lookup(Some(me().wrapping_add(1)), ID),
            PodmanStoreRead::NoStore
        );
        assert_eq!(
            storage.lookup(None, &"0".repeat(64)),
            PodmanStoreRead::Missing
        );
    }

    #[test]
    fn a_store_turned_off_is_never_read() {
        let storage = PodmanStorage::new(None, None, PathBuf::from(PASSWD));
        assert!(!storage.enabled());
        assert_eq!(storage.lookup(None, ID), PodmanStoreRead::NoStore);
        assert_eq!(storage.lookup(Some(1000), ID), PodmanStoreRead::NoStore);
    }

    #[test]
    fn a_record_keeps_its_labels_and_state_in_the_cache() {
        let md = metadata_of(PodmanRecord {
            name: "web".into(),
            image: "nginx:1.27".into(),
            labels: vec![("tier".into(), "front".into())],
            labels_read: true,
            created: "2026-11-22T00:04:04Z".into(),
            status: "running".into(),
        });
        assert_eq!(md.labels, vec![("tier".to_owned(), "front".to_owned())]);
        assert_eq!(md.status, "running");
        assert!(!md.created_at.is_empty());
    }
}
