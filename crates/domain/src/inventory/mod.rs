//! What the package managers say is installed.
//!
//! Each filesystem root the agent can see, the host's and every running
//! container's, carries its own package databases, and the agent reads them
//! as bytes handed up from that root: the dpkg status file and its file
//! lists, the Alpine installed database, and the rpm database in its SQLite
//! form. Those bytes come from inside a container and are parsed as
//! untrusted input, here and nowhere else.
//!
//! Two rpm database formats are found and not read: the Berkeley DB
//! `Packages` file of older distributions and the `Packages.db` of the ndb
//! backend. Either is reported as present and unreadable, with that reason,
//! rather than as a root with nothing installed.
//!
//! Nothing here names a vulnerability, a severity or a score. A package is a
//! name, a version, an architecture and the files it owns.

pub mod apk;
pub mod dpkg;
pub mod entity;
pub mod error;
pub mod gobuild;
pub mod rpm;
pub mod sqlite;

pub use apk::parse_apk_installed;
pub use dpkg::{DpkgEntry, parse_dpkg_list, parse_dpkg_status};
pub use entity::{
    DatabaseOutcome, DatabaseReading, GoExecutableReading, GoOutcome, InventorySweep, Package,
    PackageManager, PackageState, RootInventory, RootScope,
};
pub use error::InventoryError;
pub use gobuild::{GoBuildInfo, GoModule, GoReplacement, parse_go_buildinfo};
pub use rpm::{parse_rpm_header, read_rpm_sqlite};

/// Where the dpkg status file sits in a root.
pub const DPKG_STATUS_PATH: &str = "/var/lib/dpkg/status";
/// Where the dpkg file lists sit in a root.
pub const DPKG_INFO_DIR: &str = "/var/lib/dpkg/info";

/// What a root is: the host's when it is pid 1's, a container's when the
/// cgroup of the process it was reached through names one, another root
/// otherwise.
#[must_use]
pub fn scope_of(host: bool, cgroup: &str, pid: u32) -> RootScope {
    if host {
        return RootScope::Host;
    }
    match crate::container::engine::parse_cgroup_payload(cgroup, pid) {
        Some(crate::container::entity::ContainerInfo::Container {
            container_id,
            runtime,
            ..
        }) => RootScope::Container {
            container_id,
            runtime,
        },
        _ => RootScope::Other,
    }
}

/// A database read in full, or the reason it was not.
fn reading(
    manager: PackageManager,
    path: &str,
    parsed: Result<Vec<Package>, InventoryError>,
) -> DatabaseReading {
    DatabaseReading {
        manager,
        path: path.to_string(),
        outcome: match parsed {
            Ok(packages) => DatabaseOutcome::Read { packages },
            Err(err) => DatabaseOutcome::Unreadable {
                reason: err.to_string(),
            },
        },
    }
}

/// One running Go executable: the section's bytes parsed, or the reason
/// they were not handed over.
#[must_use]
pub fn go_reading(
    scope: RootScope,
    path: String,
    pids: Vec<u32>,
    section: Result<&[u8], String>,
) -> GoExecutableReading {
    let outcome = match section.map(parse_go_buildinfo) {
        Ok(Ok(build)) => GoOutcome::Read { build },
        Ok(Err(err)) => GoOutcome::Unreadable {
            reason: err.to_string(),
        },
        Err(reason) => GoOutcome::Unreadable { reason },
    };
    GoExecutableReading {
        scope,
        path,
        pids,
        outcome,
    }
}

/// A database found at `path` and not read, for `reason`.
#[must_use]
pub fn unreadable(
    manager: PackageManager,
    path: &str,
    reason: impl Into<String>,
) -> DatabaseReading {
    DatabaseReading {
        manager,
        path: path.to_string(),
        outcome: DatabaseOutcome::Unreadable {
            reason: reason.into(),
        },
    }
}

/// The dpkg database of a root: its status file, and for each package the
/// list `list` hands back by list name, `None` where there is none.
#[must_use]
pub fn dpkg_reading(
    status: &[u8],
    mut list: impl FnMut(&str) -> Option<Vec<u8>>,
) -> DatabaseReading {
    let parsed = std::str::from_utf8(status)
        .map_err(|_| InventoryError::Corrupt("the status file is not UTF-8".into()))
        .map(|status| {
            parse_dpkg_status(status)
                .into_iter()
                .map(|entry| {
                    let files = list(&entry.list_name())
                        .map(|bytes| parse_dpkg_list(&String::from_utf8_lossy(&bytes)));
                    entry.into_package(files)
                })
                .collect()
        });
    reading(PackageManager::Dpkg, DPKG_STATUS_PATH, parsed)
}

/// The Alpine database found at `path`.
#[must_use]
pub fn apk_reading(path: &str, bytes: &[u8]) -> DatabaseReading {
    let parsed = std::str::from_utf8(bytes)
        .map_err(|_| InventoryError::Corrupt("the installed database is not UTF-8".into()))
        .map(parse_apk_installed);
    reading(PackageManager::Apk, path, parsed)
}

/// The rpm SQLite database found at `path`.
#[must_use]
pub fn rpm_sqlite_reading(path: &str, bytes: &[u8]) -> DatabaseReading {
    reading(PackageManager::Rpm, path, read_rpm_sqlite(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/inventory");

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!("{FIXTURES}/{name}")).unwrap_or_else(|e| panic!("{name}: {e}"))
    }

    fn find<'a>(packages: &'a [Package], name: &str) -> &'a Package {
        packages
            .iter()
            .find(|p| p.name == name)
            .unwrap_or_else(|| panic!("{name} is listed"))
    }

    #[test]
    fn dpkg_keeps_what_is_on_disk_and_reads_each_list_by_its_name() {
        let mut asked = Vec::new();
        let db = dpkg_reading(&fixture("dpkg-status"), |name| {
            asked.push(name.to_string());
            std::fs::read(format!(
                "{FIXTURES}/dpkg-info/{}.list",
                name.replace(':', "_")
            ))
            .ok()
        });
        let packages = db.packages();
        let names: Vec<&str> = packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(
            names,
            ["base-files", "bash", "libc6", "libssl3t64", "zlib1g"],
            "a package removed with its configuration kept owns no file"
        );
        assert!(
            asked.contains(&"libc6:amd64".to_string()),
            "Multi-Arch: same"
        );
        assert!(asked.contains(&"bash".to_string()), "Multi-Arch: foreign");

        let libc = find(packages, "libc6");
        assert_eq!(libc.version, "2.41-12+deb13u4");
        assert_eq!(libc.arch.as_deref(), Some("amd64"));
        assert_eq!(libc.state, PackageState::Installed);
        let files = libc.files.as_deref().unwrap_or_default();
        assert!(files.iter().any(|f| f.ends_with("/libc.so.6")));
        assert!(!files.iter().any(|f| f == "/."));

        let zlib = find(packages, "zlib1g");
        assert_eq!(zlib.state, PackageState::Partial, "half-configured");
        assert_eq!(zlib.files, None, "no list was handed back for it");
    }

    #[test]
    fn a_multi_line_field_does_not_open_a_stanza() {
        let status = "Package: a\nStatus: install ok installed\nVersion: 1:2.0-1\n\
                      Description: short\n Package: not-a-package\n .\n Version: 9\n";
        let entries = parse_dpkg_status(status);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "a");
        assert_eq!(entries[0].version, "1:2.0-1", "the epoch stays");
        assert_eq!(entries[0].arch, None);
    }

    #[test]
    fn apk_joins_each_file_to_the_directory_above_it() {
        let db = apk_reading("/lib/apk/db/installed", &fixture("apk-installed"));
        let packages = db.packages();
        assert_eq!(packages.len(), 16);
        let ssl = find(packages, "libssl3");
        assert_eq!(ssl.version, "3.5.8-r0");
        assert_eq!(ssl.arch.as_deref(), Some("x86_64"));
        let files = ssl.files.as_deref().unwrap_or_default();
        assert!(
            files.iter().any(|f| f.starts_with("/usr/lib/libssl.so.3")),
            "{files:?}"
        );
        assert!(packages.iter().all(|p| p.manager == PackageManager::Apk));
    }

    #[test]
    fn rpm_reads_every_header_and_leaves_the_keys_out() {
        let db = rpm_sqlite_reading(
            "/usr/lib/sysimage/rpm/rpmdb.sqlite",
            &fixture("rpmdb.sqlite"),
        );
        let packages = db.packages();
        assert_eq!(packages.len(), 19, "twenty rows, one of them a public key");
        assert!(packages.iter().all(|p| p.name != "gpg-pubkey"));

        let ssl = find(packages, "openssl-libs");
        assert_eq!(ssl.version, "1:3.5.7-2.fc43");
        assert_eq!(ssl.arch.as_deref(), Some("x86_64"));
        let files = ssl.files.as_deref().unwrap_or_default();
        assert_eq!(files.len(), 39);
        assert_eq!(files[0], "/etc/pki/tls");

        assert_eq!(find(packages, "gdbm-libs").version, "1:1.23-10.fc43");
        assert_eq!(
            find(packages, "zlib-ng-compat")
                .files
                .as_ref()
                .map(Vec::len),
            Some(5)
        );
        assert_eq!(
            find(packages, "libattr")
                .files
                .as_deref()
                .and_then(|f| f.first())
                .map(String::as_str),
            Some("/etc/xattr.conf")
        );
        assert_eq!(
            find(packages, "publicsuffix-list-dafsa").arch.as_deref(),
            Some("noarch")
        );
    }

    #[test]
    fn a_truncated_rpm_database_is_unreadable_with_its_reason() {
        let bytes = fixture("rpmdb.sqlite");
        let db = rpm_sqlite_reading("/var/lib/rpm/rpmdb.sqlite", &bytes[..4096]);
        let DatabaseOutcome::Unreadable { reason } = &db.outcome else {
            panic!("a database cut short is not read as empty");
        };
        assert!(reason.starts_with("corrupt"), "{reason}");
    }

    #[test]
    fn every_cut_of_a_real_database_ends_in_a_reading_or_a_reason() {
        let bytes = fixture("rpmdb.sqlite");
        for len in (0..bytes.len()).step_by(997) {
            let _ = read_rpm_sqlite(&bytes[..len]);
        }
        let apk = fixture("apk-installed");
        for len in (0..apk.len()).step_by(101) {
            let _ = parse_apk_installed(&String::from_utf8_lossy(&apk[..len]));
        }
    }

    #[test]
    fn a_root_is_the_hosts_a_containers_or_another() {
        let id = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let docker = format!("0::/system.slice/docker-{id}.scope\n");
        assert_eq!(scope_of(true, &docker, 1), RootScope::Host);
        assert!(matches!(
            scope_of(false, &docker, 42),
            RootScope::Container { container_id, .. } if container_id == id
        ));
        assert_eq!(
            scope_of(false, "0::/system.slice/nginx.service\n", 7),
            RootScope::Other
        );
        assert_eq!(scope_of(false, "", 7), RootScope::Other);
    }

    #[test]
    fn nothing_a_reading_serialises_names_a_vulnerability() {
        let db = rpm_sqlite_reading(
            "/usr/lib/sysimage/rpm/rpmdb.sqlite",
            &fixture("rpmdb.sqlite"),
        );
        let root = RootInventory {
            scope: RootScope::Host,
            pid: 1,
            databases: vec![
                db,
                unreadable(PackageManager::Rpm, "/var/lib/rpm/Packages", "x"),
            ],
            error: None,
        };
        let json = serde_json::to_string(&root)
            .unwrap_or_default()
            .to_lowercase();
        for word in ["cve", "severity", "score", "vulnerab", "cvss"] {
            assert!(!json.contains(&format!("\"{word}")), "{word}");
        }
    }
}
