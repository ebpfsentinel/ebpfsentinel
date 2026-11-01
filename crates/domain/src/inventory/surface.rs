//! The counts of one host's surface: what is installed, what of it a live
//! process maps, and what a process maps that nothing installed.

use std::collections::HashSet;

use super::entity::{InventorySweep, PackageManager};

/// What one reading says about the host's packages and the files its
/// processes map.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MappedCounts {
    /// Roots whose databases were read.
    pub roots: u32,
    /// Packages the databases list, every root together.
    pub packages_installed: u32,
    /// Of those, the packages owning at least one file a live process maps
    /// in the same root.
    pub packages_mapped: u32,
    /// Distinct files mapped, once per root.
    pub files_mapped: u32,
    /// Files mapped that no database in their root lists.
    pub files_unowned: u32,
    /// Files mapped that were unlinked since.
    pub files_deleted: u32,
}

impl MappedCounts {
    /// Installed packages no live process maps a file of.
    #[must_use]
    pub fn packages_not_mapped(&self) -> u32 {
        self.packages_installed.saturating_sub(self.packages_mapped)
    }
}

/// Count `sweep`. A package is counted mapped in the root it is installed
/// in, so the same name and version in two containers counts twice, once
/// per root, the way it counts installed.
#[must_use]
pub fn mapped_counts(sweep: &InventorySweep) -> MappedCounts {
    let installed: usize = sweep
        .roots
        .iter()
        .flat_map(|root| &root.databases)
        .map(|db| db.packages().len())
        .sum();
    let mut mapped: HashSet<(u32, PackageManager, &str, &str)> = HashSet::new();
    let mut counts = MappedCounts {
        roots: count(sweep.roots.len()),
        packages_installed: count(installed),
        ..MappedCounts::default()
    };
    for object in &sweep.loaded.objects {
        counts.files_mapped += 1;
        if object.deleted {
            counts.files_deleted += 1;
        }
        match (&object.owner, object.root_pid) {
            (Some(owner), Some(root)) => {
                mapped.insert((root, owner.manager, &owner.name, &owner.version));
            }
            _ => counts.files_unowned += 1,
        }
    }
    counts.packages_mapped = count(mapped.len());
    counts
}

fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::{
        DatabaseOutcome, DatabaseReading, LoadedObject, LoadedObjects, Package, PackageRef,
        PackageState, RootInventory, RootScope,
    };

    fn package(name: &str) -> Package {
        Package {
            manager: PackageManager::Dpkg,
            name: name.into(),
            version: "1".into(),
            arch: None,
            state: PackageState::Installed,
            files: None,
        }
    }

    fn object(path: &str, owner: Option<&str>, deleted: bool) -> LoadedObject {
        LoadedObject {
            scope: Some(RootScope::Host),
            root_pid: Some(1),
            path: path.into(),
            deleted,
            owner: owner.map(|name| PackageRef {
                manager: PackageManager::Dpkg,
                name: name.into(),
                version: "1".into(),
            }),
            pids: vec![10],
            processes: 1,
        }
    }

    #[test]
    fn an_installed_package_no_process_maps_counts_as_not_mapped() {
        let sweep = InventorySweep {
            roots: vec![RootInventory {
                scope: RootScope::Host,
                pid: 1,
                databases: vec![DatabaseReading {
                    manager: PackageManager::Dpkg,
                    path: "/var/lib/dpkg/status".into(),
                    outcome: DatabaseOutcome::Read {
                        packages: vec![package("libc6"), package("openssl"), package("vim")],
                    },
                }],
                error: None,
            }],
            loaded: LoadedObjects {
                objects: vec![
                    object("/usr/lib/libc.so.6", Some("libc6"), false),
                    object("/usr/lib/libm.so.6", Some("libc6"), false),
                    object("/usr/lib/libssl.so.3", Some("openssl"), true),
                    object("/opt/app/server", None, false),
                ],
                ..LoadedObjects::default()
            },
            ..InventorySweep::default()
        };
        let counts = mapped_counts(&sweep);
        assert_eq!(counts.roots, 1);
        assert_eq!(counts.packages_installed, 3);
        assert_eq!(counts.packages_mapped, 2, "libc6 is counted once");
        assert_eq!(counts.packages_not_mapped(), 1, "vim");
        assert_eq!(counts.files_mapped, 4);
        assert_eq!(counts.files_unowned, 1);
        assert_eq!(counts.files_deleted, 1);
    }

    #[test]
    fn nothing_read_counts_nothing() {
        assert_eq!(
            mapped_counts(&InventorySweep::default()),
            MappedCounts::default()
        );
    }
}
