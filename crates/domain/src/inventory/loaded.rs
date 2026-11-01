//! Which installed files are actually mapped, and by whom.
//!
//! A package that is installed and never mapped into a live process runs
//! nowhere. Every file a process maps executable is joined here to the
//! package its root's database says owns it, once per file however many
//! processes map it.

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::entity::{PackageManager, RootInventory, RootScope};

/// The most pids named per mapped object.
pub const LOADED_PIDS_MAX: usize = 16;

/// The most mapped objects one sweep lists.
pub const LOADED_OBJECTS_MAX: usize = 65_536;

/// One file mapped executable, as `/proc/<pid>/maps` names it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MappedObject {
    pub dev: u64,
    pub ino: u64,
    /// Inside the root of the process mapping it.
    pub path: String,
    /// Unlinked since it was mapped: an upgrade replaced it on disk and the
    /// process still runs the old one.
    pub deleted: bool,
}

/// What one process maps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessObjects {
    pub pid: u32,
    /// The pid naming the root it runs in, as [`RootInventory::pid`] does;
    /// `None` when that root was not read.
    pub root_pid: Option<u32>,
    pub objects: Vec<Arc<MappedObject>>,
}

/// The package a database says owns a path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageRef {
    pub manager: PackageManager,
    pub name: String,
    pub version: String,
}

/// One mapped file and the processes mapping it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoadedObject {
    /// The root it was mapped in; `None` when that root was not read.
    pub scope: Option<RootScope>,
    /// The pid naming that root.
    pub root_pid: Option<u32>,
    pub path: String,
    pub deleted: bool,
    /// The package owning `path` in that root, `None` when no database
    /// read there lists it. For a deleted file it is the package owning
    /// the path now, which may be a later version than the one mapped.
    pub owner: Option<PackageRef>,
    /// The processes mapping it, lowest first, at most [`LOADED_PIDS_MAX`].
    pub pids: Vec<u32>,
    /// How many processes map it in all.
    pub processes: u32,
}

/// Every mapped object of one sweep.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoadedObjects {
    pub objects: Vec<LoadedObject>,
    /// Objects past [`LOADED_OBJECTS_MAX`], left out.
    pub not_listed: u32,
}

/// The path a package database and `/proc/<pid>/maps` agree on: on a merged
/// `/usr` system `/lib/x/libc.so.6` and `/usr/lib/x/libc.so.6` are one file,
/// and the database may write either.
fn canonical(path: &str) -> std::borrow::Cow<'_, str> {
    for top in ["/bin/", "/sbin/", "/lib/", "/lib32/", "/lib64/", "/libx32/"] {
        if path.starts_with(top) {
            return format!("/usr{path}").into();
        }
    }
    path.into()
}

/// The owner of every path the databases of `root` list.
fn owners(root: &RootInventory) -> HashMap<String, PackageRef> {
    let mut out = HashMap::new();
    for package in root.packages() {
        let Some(files) = &package.files else {
            continue;
        };
        for file in files {
            out.entry(canonical(file).into_owned())
                .or_insert_with(|| PackageRef {
                    manager: package.manager,
                    name: package.name.clone(),
                    version: package.version.clone(),
                });
        }
    }
    out
}

struct Group {
    object: Arc<MappedObject>,
    pids: Vec<u32>,
    processes: u32,
}

/// Join what `processes` map to the packages of `roots`.
#[must_use]
pub fn loaded_objects(roots: &[RootInventory], processes: &[ProcessObjects]) -> LoadedObjects {
    let mut order: Vec<&ProcessObjects> = processes.iter().collect();
    order.sort_by_key(|p| p.pid);
    let mut groups: HashMap<(Option<u32>, u64, u64), Group> = HashMap::new();
    for process in order {
        for object in &process.objects {
            let group = groups
                .entry((process.root_pid, object.dev, object.ino))
                .or_insert_with(|| Group {
                    object: Arc::clone(object),
                    pids: Vec::new(),
                    processes: 0,
                });
            // One process can map one file under two names; it counts once.
            if group.pids.last() == Some(&process.pid) {
                continue;
            }
            if group.pids.len() < LOADED_PIDS_MAX {
                group.pids.push(process.pid);
            }
            group.processes = group.processes.saturating_add(1);
        }
    }
    let by_pid: HashMap<u32, (usize, &RootInventory)> = roots
        .iter()
        .enumerate()
        .map(|(i, r)| (r.pid, (i, r)))
        .collect();
    let mut indexes: HashMap<u32, HashMap<String, PackageRef>> = HashMap::new();
    let mut rows: Vec<(usize, LoadedObject)> = groups
        .into_iter()
        .map(|((root_pid, _, _), group)| {
            let root = root_pid.and_then(|pid| by_pid.get(&pid).copied());
            let owner = root.and_then(|(_, root)| {
                indexes
                    .entry(root.pid)
                    .or_insert_with(|| owners(root))
                    .get(canonical(&group.object.path).as_ref())
                    .cloned()
            });
            let rank = root.map_or(usize::MAX, |(i, _)| i);
            (
                rank,
                LoadedObject {
                    scope: root.map(|(_, r)| r.scope.clone()),
                    root_pid: root.map(|(_, r)| r.pid),
                    path: group.object.path.clone(),
                    deleted: group.object.deleted,
                    owner,
                    pids: group.pids,
                    processes: group.processes,
                },
            )
        })
        .collect();
    rows.sort_by(|(a, x), (b, y)| a.cmp(b).then_with(|| x.path.cmp(&y.path)));
    let not_listed =
        u32::try_from(rows.len().saturating_sub(LOADED_OBJECTS_MAX)).unwrap_or(u32::MAX);
    rows.truncate(LOADED_OBJECTS_MAX);
    LoadedObjects {
        objects: rows.into_iter().map(|(_, o)| o).collect(),
        not_listed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::entity::{DatabaseOutcome, DatabaseReading, Package, PackageState};

    fn package(name: &str, files: Option<&[&str]>) -> Package {
        Package {
            manager: PackageManager::Dpkg,
            name: name.into(),
            version: "1.0".into(),
            arch: None,
            state: PackageState::Installed,
            files: files.map(|f| f.iter().map(ToString::to_string).collect()),
        }
    }

    fn host(packages: Vec<Package>) -> RootInventory {
        RootInventory {
            scope: RootScope::Host,
            pid: 1,
            databases: vec![DatabaseReading {
                manager: PackageManager::Dpkg,
                path: "/var/lib/dpkg/status".into(),
                outcome: DatabaseOutcome::Read { packages },
            }],
            error: None,
        }
    }

    fn object(ino: u64, path: &str, deleted: bool) -> Arc<MappedObject> {
        Arc::new(MappedObject {
            dev: 2049,
            ino,
            path: path.into(),
            deleted,
        })
    }

    fn process(pid: u32, objects: &[&Arc<MappedObject>]) -> ProcessObjects {
        ProcessObjects {
            pid,
            root_pid: Some(1),
            objects: objects.iter().map(|o| Arc::clone(o)).collect(),
        }
    }

    #[test]
    fn a_package_owning_an_object_mapped_by_three_processes_is_named_once() {
        let ssl = object(10, "/usr/lib/x86_64-linux-gnu/libssl.so.3", false);
        let roots = [host(vec![package(
            "libssl3t64",
            Some(&["/usr/lib/x86_64-linux-gnu/libssl.so.3"]),
        )])];
        let loaded = loaded_objects(
            &roots,
            &[
                process(30, &[&ssl]),
                process(10, &[&ssl]),
                process(20, &[&ssl]),
            ],
        );
        assert_eq!(loaded.objects.len(), 1);
        let o = &loaded.objects[0];
        assert_eq!(o.pids, [10, 20, 30]);
        assert_eq!(o.processes, 3);
        assert_eq!(
            o.owner.as_ref().map(|p| p.name.as_str()),
            Some("libssl3t64")
        );
        assert_eq!(o.scope, Some(RootScope::Host));
    }

    #[test]
    fn a_merged_usr_path_finds_the_package_listing_the_short_one() {
        let libc = object(11, "/usr/lib/x86_64-linux-gnu/libc.so.6", false);
        let roots = [host(vec![package(
            "libc6",
            Some(&["/lib/x86_64-linux-gnu/libc.so.6"]),
        )])];
        let loaded = loaded_objects(&roots, &[process(5, &[&libc])]);
        assert_eq!(
            loaded.objects[0].owner.as_ref().map(|p| p.name.as_str()),
            Some("libc6")
        );
    }

    #[test]
    fn a_deleted_object_is_named_with_the_package_owning_its_path_now() {
        let old = object(12, "/usr/lib/libz.so.1", true);
        let roots = [host(vec![package("zlib1g", Some(&["/usr/lib/libz.so.1"]))])];
        let loaded = loaded_objects(&roots, &[process(5, &[&old])]);
        assert!(loaded.objects[0].deleted);
        assert_eq!(
            loaded.objects[0].owner.as_ref().map(|p| p.name.as_str()),
            Some("zlib1g")
        );
    }

    #[test]
    fn an_object_no_package_owns_and_a_package_listing_no_files_leave_the_owner_empty() {
        let built = object(13, "/opt/app/libapp.so", false);
        let listed_none = object(14, "/usr/lib/libquiet.so", false);
        let roots = [host(vec![package("quiet", None)])];
        let loaded = loaded_objects(&roots, &[process(5, &[&built, &listed_none])]);
        assert_eq!(loaded.objects.len(), 2);
        assert!(loaded.objects.iter().all(|o| o.owner.is_none()));
    }

    #[test]
    fn two_processes_mapping_one_inode_are_one_object_and_two_roots_are_two() {
        let lib = object(15, "/usr/lib/libx.so", false);
        let other_root = ProcessObjects {
            pid: 900,
            root_pid: Some(900),
            objects: vec![Arc::clone(&lib)],
        };
        let unread = ProcessObjects {
            pid: 901,
            root_pid: None,
            objects: vec![Arc::clone(&lib)],
        };
        let mut container = host(Vec::new());
        container.pid = 900;
        container.scope = RootScope::Other;
        let roots = [host(Vec::new()), container];
        let loaded = loaded_objects(
            &roots,
            &[process(7, &[&lib]), process(8, &[&lib]), other_root, unread],
        );
        assert_eq!(loaded.objects.len(), 3);
        assert_eq!(loaded.objects[0].pids, [7, 8]);
        assert_eq!(loaded.objects[1].root_pid, Some(900));
        assert_eq!(loaded.objects[2].scope, None);
    }
}
