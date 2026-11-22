//! Podman's own record of its containers, read without its API.
//!
//! Podman is daemonless: unless an owner enabled `podman.socket`, nothing
//! answers on a socket, and the enricher has no API to ask. What every
//! Podman writes whatever its socket is the container store of
//! `containers/storage`, `<graphroot>/<driver>-containers/containers.json`,
//! which lists each container's id, its names and, in a metadata string
//! Podman fills, the image it was created from. Root's store is under
//! `/var/lib/containers/storage`; a user's is under their home,
//! `~/.local/share/containers/storage`, the home being read from the
//! password file.
//!
//! The store carries no labels: those are in Podman's own database, which
//! only its API reads. A container named from the store therefore carries
//! its name and image and an empty label set, and the runtime report says
//! which of the two answered.
//!
//! Each file is parsed again only when its modification time or its length
//! changes, so a lookup on a quiet host is one `stat` per store.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::SystemTime;

use serde::Deserialize;

use domain::container::entity::DockerMetadata;

/// Root's container store.
pub const DEFAULT_STORAGE_ROOT: &str = "/var/lib/containers/storage";
/// A user's container store, relative to their home.
pub const DEFAULT_ROOTLESS_STORAGE: &str = ".local/share/containers/storage";
/// Where each user's home is read from.
pub const PASSWD: &str = "/etc/passwd";

/// Largest store file read. A store listing tens of thousands of containers
/// is a few megabytes; anything larger is not one.
const MAX_STORE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Deserialize)]
struct StoredContainer {
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

#[derive(Deserialize, Default)]
struct PodmanMetadata {
    #[serde(default, rename = "image-name")]
    image_name: String,
}

/// The containers one store file lists, by id.
///
/// An entry Podman did not create (a Buildah working container, say) still
/// has an id and names, and is kept: the cgroup names it as Podman's only if
/// Podman runs it.
#[must_use]
pub fn parse_store(bytes: &[u8]) -> HashMap<String, DockerMetadata> {
    let Ok(stored) = serde_json::from_slice::<Vec<StoredContainer>>(bytes) else {
        return HashMap::new();
    };
    stored
        .into_iter()
        .filter(|c| !c.id.is_empty())
        .map(|c| {
            let meta: PodmanMetadata = serde_json::from_str(&c.metadata).unwrap_or_default();
            let image = if meta.image_name.is_empty() {
                c.image
            } else {
                meta.image_name
            };
            let md = DockerMetadata {
                name: c.names.into_iter().next().unwrap_or_default(),
                image,
                labels: Vec::new(),
                created_at: c.created,
                status: String::new(),
            };
            (c.id, md)
        })
        .collect()
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

struct Parsed {
    modified: SystemTime,
    len: u64,
    containers: HashMap<String, DockerMetadata>,
}

/// Root's and each user's container store, read on demand.
pub struct PodmanStorage {
    /// `None` when root's store is not read.
    root: Option<PathBuf>,
    /// Relative to each user's home; `None` when users' stores are not read.
    rootless: Option<PathBuf>,
    passwd: PathBuf,
    parsed: Mutex<HashMap<PathBuf, Parsed>>,
}

impl PodmanStorage {
    #[must_use]
    pub fn new(root: Option<PathBuf>, rootless: Option<PathBuf>, passwd: PathBuf) -> Self {
        Self {
            root,
            rootless,
            passwd,
            parsed: Mutex::new(HashMap::new()),
        }
    }

    /// Whether any store is read at all.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.root.is_some() || self.rootless.is_some()
    }

    /// The store directory of `uid`'s runtime, `None` for root.
    #[must_use]
    pub fn store_of(&self, uid: Option<u32>) -> Option<PathBuf> {
        match uid {
            None => self.root.clone(),
            Some(uid) => {
                let rel = self.rootless.as_ref()?;
                let passwd = std::fs::read_to_string(&self.passwd).ok()?;
                Some(home_of(&passwd, uid)?.join(rel))
            }
        }
    }

    /// The container `id` in `uid`'s store, `None` for root's, and the store
    /// file that named it.
    #[must_use]
    pub fn lookup(&self, uid: Option<u32>, id: &str) -> Option<(DockerMetadata, PathBuf)> {
        let store = self.store_of(uid)?;
        let entries = std::fs::read_dir(&store).ok()?;
        for entry in entries.flatten() {
            let name = entry.file_name();
            if !name.to_string_lossy().ends_with("-containers") {
                continue;
            }
            let file = entry.path().join("containers.json");
            if let Some(md) = self.find_in(&file, id) {
                return Some((md, file));
            }
        }
        None
    }

    fn find_in(&self, file: &Path, id: &str) -> Option<DockerMetadata> {
        let meta = std::fs::metadata(file).ok()?;
        if !meta.is_file() || meta.len() > MAX_STORE_BYTES {
            return None;
        }
        let modified = meta.modified().ok()?;
        let mut parsed = self.parsed.lock().unwrap_or_else(PoisonError::into_inner);
        let fresh = parsed
            .get(file)
            .is_some_and(|p| p.modified == modified && p.len == meta.len());
        if !fresh {
            let bytes = std::fs::read(file).ok()?;
            parsed.insert(
                file.to_path_buf(),
                Parsed {
                    modified,
                    len: meta.len(),
                    containers: parse_store(&bytes),
                },
            );
        }
        parsed.get(file)?.containers.get(id).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "9c503e64bd42f67b7b1592f98d2fc3443149c7b875cc39327b13e2ad8df85c33";

    /// The file as Podman 6 wrote it for `podman run -d --name web busybox`.
    fn store(id: &str, name: &str) -> String {
        format!(
            r#"[{{"id":"{id}","names":["{name}"],"image":"b116e155074440ffd9e449559433feb4cd2341eb3554b1da1c638c976e56451d","layer":"4fdbe49ff815c926d37088fb2a425e14d3834c8b69d0674fd73c888e5914a87f","metadata":"{{\"image-name\":\"docker.io/library/busybox:1.36\",\"image-id\":\"b116e155074440ffd9e449559433feb4cd2341eb3554b1da1c638c976e56451d\",\"name\":\"{name}\",\"created-at\":1795305844}}","created":"2026-11-22T00:04:04.279496233Z","flags":{{"MountLabel":"","ProcessLabel":""}}}}]"#
        )
    }

    #[test]
    fn a_store_entry_gives_the_name_and_the_image_podman_recorded() {
        let parsed = parse_store(store(ID, "web").as_bytes());
        let md = parsed.get(ID).unwrap();
        assert_eq!(md.name, "web");
        assert_eq!(md.image, "docker.io/library/busybox:1.36");
        assert!(md.labels.is_empty());
        assert_eq!(md.created_at, "2026-11-22T00:04:04.279496233Z");
    }

    #[test]
    fn without_podmans_metadata_the_image_is_its_id() {
        let parsed =
            parse_store(format!(r#"[{{"id":"{ID}","names":["w"],"image":"abc"}}]"#).as_bytes());
        assert_eq!(parsed.get(ID).unwrap().image, "abc");
    }

    #[test]
    fn a_file_that_is_not_a_store_names_nothing() {
        assert!(parse_store(b"{}").is_empty());
        assert!(parse_store(b"not json").is_empty());
        assert!(parse_store(br#"[{"names":["x"]}]"#).is_empty());
    }

    #[test]
    fn the_home_is_read_from_the_users_line() {
        let passwd = "root:x:0:0:root:/root:/bin/bash\n\
                      alice:x:1000:1000:Alice,,,:/home/alice:/bin/bash\n\
                      odd:x:1001:1001::relative:/bin/sh\n";
        assert_eq!(home_of(passwd, 1000), Some(PathBuf::from("/home/alice")));
        assert_eq!(home_of(passwd, 0), Some(PathBuf::from("/root")));
        assert_eq!(home_of(passwd, 1001), None);
        assert_eq!(home_of(passwd, 4242), None);
    }

    #[test]
    fn roots_and_a_users_store_are_found_under_their_driver_directory() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root-store");
        std::fs::create_dir_all(root.join("overlay-containers")).unwrap();
        std::fs::write(
            root.join("overlay-containers/containers.json"),
            store(ID, "web"),
        )
        .unwrap();
        let home = dir.path().join("home/alice");
        std::fs::create_dir_all(home.join("store/vfs-containers")).unwrap();
        std::fs::write(
            home.join("store/vfs-containers/containers.json"),
            store(ID, "mine"),
        )
        .unwrap();
        let passwd = dir.path().join("passwd");
        std::fs::write(
            &passwd,
            format!("alice:x:1000:1000::{}:/bin/sh\n", home.display()),
        )
        .unwrap();

        let storage = PodmanStorage::new(Some(root.clone()), Some(PathBuf::from("store")), passwd);
        let (md, file) = storage.lookup(None, ID).unwrap();
        assert_eq!(md.name, "web");
        assert_eq!(file, root.join("overlay-containers/containers.json"));
        assert_eq!(storage.lookup(Some(1000), ID).unwrap().0.name, "mine");
        assert!(storage.lookup(Some(1001), ID).is_none());
        assert!(storage.lookup(None, "unknown").is_none());
    }

    #[test]
    fn a_rewritten_store_is_read_again() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("overlay-containers/containers.json");
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, "[]").unwrap();
        let storage =
            PodmanStorage::new(Some(dir.path().to_path_buf()), None, PathBuf::from(PASSWD));
        assert!(storage.lookup(None, ID).is_none());
        std::fs::write(&file, store(ID, "late")).unwrap();
        assert_eq!(storage.lookup(None, ID).unwrap().0.name, "late");
    }

    #[test]
    fn a_store_turned_off_is_never_read() {
        let storage = PodmanStorage::new(None, None, PathBuf::from(PASSWD));
        assert!(!storage.enabled());
        assert!(storage.lookup(None, ID).is_none());
        assert!(storage.lookup(Some(1000), ID).is_none());
    }
}
