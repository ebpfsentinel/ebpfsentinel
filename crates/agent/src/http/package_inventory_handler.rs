use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use domain::inventory::{
    DatabaseOutcome, DatabaseReading, GoExecutableReading, GoModule, GoOutcome, LoadedObject,
    Package, PackageState, RootInventory, RootScope,
};
use serde::Serialize;
use utoipa::ToSchema;

use super::error::ErrorBody;
use super::state::AppState;

/// One package a database says is installed.
#[derive(Debug, Serialize, ToSchema)]
pub struct PackageBody {
    pub name: String,
    /// As the database writes it, epoch included where there is one.
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    /// `installed`, or `partial` for a package dpkg has not finished
    /// installing or configuring.
    pub state: &'static str,
    /// How many files the database says it owns. Absent when no file list
    /// could be read for it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files: Option<usize>,
}

/// One package database found in a root.
#[derive(Debug, Serialize, ToSchema)]
pub struct PackageDatabaseBody {
    /// `dpkg`, `rpm` or `apk`.
    pub manager: &'static str,
    /// Where it was found, inside the root.
    pub path: String,
    /// Why it could not be read. Its packages are then empty, which says
    /// nothing about what is installed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unreadable: Option<String>,
    pub packages: Vec<PackageBody>,
}

/// The package databases of one filesystem root.
#[derive(Debug, Serialize, ToSchema)]
pub struct PackageRootBody {
    /// `host`, `container`, or `other` for a root no container runtime
    /// names.
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
    /// The process whose root was read.
    pub pid: u32,
    /// Why the root could not be read at all.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// One entry per database found; none means no database this reader
    /// knows of is there.
    pub databases: Vec<PackageDatabaseBody>,
}

/// One module a Go executable was linked from.
#[derive(Debug, Serialize, ToSchema)]
pub struct GoModuleBody {
    pub path: String,
    /// `(devel)` for a module built from a working tree.
    pub version: String,
    /// Whether it is the module the main package belongs to.
    pub main: bool,
    /// What a `replace` directive put in its place, `path version`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replaced_by: Option<String>,
}

/// One running Go executable and the modules it states.
#[derive(Debug, Serialize, ToSchema)]
pub struct GoExecutableBody {
    /// The root of the lowest process running it: `host`, `container` or
    /// `other`.
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
    /// Its path inside that root.
    pub path: String,
    /// Processes running it, lowest first, at most sixteen.
    pub pids: Vec<u32>,
    /// Why its build information could not be read. Its modules are then
    /// empty.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unreadable: Option<String>,
    /// The toolchain it was built with.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub go_version: Option<String>,
    /// The import path of its main package.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub main_package: Option<String>,
    /// The main module first, then every dependency.
    pub modules: Vec<GoModuleBody>,
}

/// What the package managers say is installed, root by root.
#[derive(Debug, Serialize, ToSchema)]
pub struct PackagesResponse {
    /// Whether the databases are read.
    pub reading: bool,
    /// Where the readings come from: `warden` or `local`. Absent when the
    /// inventory is off.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<&'static str>,
    /// When the last sweep was made, in nanoseconds since the epoch, `0`
    /// before the first.
    pub scanned_at_ns: u64,
    /// Why the last sweep failed. The result is then the sweep before.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// Roots found beyond the number one sweep reads.
    pub roots_not_read: u32,
    pub roots: Vec<PackageRootBody>,
    /// Distinct running executables opened to look for Go build
    /// information, Go or not.
    pub executables_examined: u32,
    /// Go executables found past what one sweep carries.
    pub go_executables_not_read: u32,
    /// Every running Go executable, once per file.
    pub go_executables: Vec<GoExecutableBody>,
}

/// The package a database says owns a mapped file.
#[derive(Debug, Serialize, ToSchema)]
pub struct OwnerBody {
    /// `dpkg`, `rpm` or `apk`.
    pub manager: &'static str,
    pub name: String,
    pub version: String,
}

/// One file mapped executable by live processes, once per file and root.
#[derive(Debug, Serialize, ToSchema)]
pub struct LoadedObjectBody {
    /// The root it is mapped in: `host`, `container`, `other`, or `unread`
    /// for a root past what one sweep reads.
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
    /// The process naming that root, as in the package inventory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_pid: Option<u32>,
    /// Its path inside that root.
    pub path: String,
    /// Unlinked since it was mapped: an upgrade replaced it on disk and the
    /// processes below still run the old file.
    pub deleted: bool,
    /// The package owning the path in that root. Absent when no database
    /// read there lists it. For a deleted file it is the package owning
    /// the path now, which may be a later version than the one mapped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<OwnerBody>,
    /// Processes mapping it, lowest first, at most sixteen.
    pub pids: Vec<u32>,
    /// How many processes map it in all.
    pub processes: u32,
}

/// What live processes have mapped executable, and the package owning
/// each file.
#[derive(Debug, Serialize, ToSchema)]
pub struct LoadedResponse {
    /// Whether the inventory is read.
    pub reading: bool,
    /// When the last sweep was made, in nanoseconds since the epoch, `0`
    /// before the first.
    pub scanned_at_ns: u64,
    /// Why the last sweep failed. The result is then the sweep before.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// Live processes listed in the last sweep.
    pub processes_listed: u32,
    /// Of those, the ones read again because they started, mapped or
    /// unmapped something since the sweep before.
    pub processes_reread: u32,
    /// Live processes whose mappings are not below: unreadable, or past
    /// what one sweep reads.
    pub processes_not_read: u32,
    /// Files past the number one sweep lists.
    pub objects_not_listed: u32,
    /// Root first, then by path.
    pub objects: Vec<LoadedObjectBody>,
}

fn package(p: &Package) -> PackageBody {
    PackageBody {
        name: p.name.clone(),
        version: p.version.clone(),
        arch: p.arch.clone(),
        state: match p.state {
            PackageState::Installed => "installed",
            PackageState::Partial => "partial",
        },
        files: p.files.as_ref().map(Vec::len),
    }
}

fn database(db: &DatabaseReading) -> PackageDatabaseBody {
    PackageDatabaseBody {
        manager: db.manager.as_str(),
        path: db.path.clone(),
        unreadable: match &db.outcome {
            DatabaseOutcome::Read { .. } => None,
            DatabaseOutcome::Unreadable { reason } => Some(reason.clone()),
        },
        packages: db.packages().iter().map(package).collect(),
    }
}

/// A root's kind, container id and runtime.
fn scope(scope: &RootScope) -> (&'static str, Option<String>, Option<String>) {
    match scope {
        RootScope::Host => ("host", None, None),
        RootScope::Container {
            container_id,
            runtime,
        } => (
            "container",
            Some(container_id.clone()),
            Some(runtime.to_string()),
        ),
        RootScope::Other => ("other", None, None),
    }
}

fn loaded(o: &LoadedObject) -> LoadedObjectBody {
    let (kind, container_id, runtime) = o.scope.as_ref().map_or(("unread", None, None), scope);
    LoadedObjectBody {
        kind,
        container_id,
        runtime,
        root_pid: o.root_pid,
        path: o.path.clone(),
        deleted: o.deleted,
        owner: o.owner.as_ref().map(|p| OwnerBody {
            manager: p.manager.as_str(),
            name: p.name.clone(),
            version: p.version.clone(),
        }),
        pids: o.pids.clone(),
        processes: o.processes,
    }
}

fn module(m: &GoModule, main: bool) -> GoModuleBody {
    GoModuleBody {
        path: m.path.clone(),
        version: m.version.clone(),
        main,
        replaced_by: m
            .replaced_by
            .as_ref()
            .map(|r| format!("{} {}", r.path, r.version)),
    }
}

fn go_executable(e: &GoExecutableReading) -> GoExecutableBody {
    let (kind, container_id, runtime) = scope(&e.scope);
    let mut body = GoExecutableBody {
        kind,
        container_id,
        runtime,
        path: e.path.clone(),
        pids: e.pids.clone(),
        unreadable: None,
        go_version: None,
        main_package: None,
        modules: Vec::new(),
    };
    match &e.outcome {
        GoOutcome::Read { build } => {
            body.go_version = Some(build.go_version.clone());
            body.main_package.clone_from(&build.main_package);
            body.modules = build
                .main_module
                .iter()
                .map(|m| module(m, true))
                .chain(build.dependencies.iter().map(|m| module(m, false)))
                .collect();
        }
        GoOutcome::Unreadable { reason } => body.unreadable = Some(reason.clone()),
    }
    body
}

fn root(r: &RootInventory) -> PackageRootBody {
    let (kind, container_id, runtime) = scope(&r.scope);
    PackageRootBody {
        kind,
        container_id,
        runtime,
        pid: r.pid,
        error: r.error.clone(),
        databases: r.databases.iter().map(database).collect(),
    }
}

/// `GET /api/v1/surface/packages` - what the package managers say is
/// installed, in the host's root and every container's.
#[utoipa::path(
    get, path = "/api/v1/surface/packages",
    tag = "Operations",
    responses((status = 200, description = "The packages the dpkg, rpm and Alpine databases list in every root, and the modules every running Go executable states, with the reason a database or an executable could not be read", body = PackagesResponse),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn get_packages(State(state): State<Arc<AppState>>) -> Json<PackagesResponse> {
    let Some(service) = state.package_inventory.load_full() else {
        return Json(PackagesResponse {
            reading: false,
            source: None,
            scanned_at_ns: 0,
            last_error: None,
            roots_not_read: 0,
            roots: Vec::new(),
            executables_examined: 0,
            go_executables_not_read: 0,
            go_executables: Vec::new(),
        });
    };
    let report = service.report();
    Json(PackagesResponse {
        reading: true,
        source: Some(service.source()),
        scanned_at_ns: report.scanned_at_ns,
        last_error: report.error.clone(),
        roots_not_read: report.sweep.roots_not_read,
        roots: report.sweep.roots.iter().map(root).collect(),
        executables_examined: report.sweep.executables_examined,
        go_executables_not_read: report.sweep.go_executables_not_read,
        go_executables: report
            .sweep
            .go_executables
            .iter()
            .map(go_executable)
            .collect(),
    })
}

#[utoipa::path(
    get, path = "/api/v1/surface/loaded",
    tag = "Operations",
    responses((status = 200, description = "Every file live processes have mapped executable, once per file and root, with the processes mapping it and the package owning it in that root", body = LoadedResponse),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn get_loaded(State(state): State<Arc<AppState>>) -> Json<LoadedResponse> {
    let Some(service) = state.package_inventory.load_full() else {
        return Json(LoadedResponse {
            reading: false,
            scanned_at_ns: 0,
            last_error: None,
            processes_listed: 0,
            processes_reread: 0,
            processes_not_read: 0,
            objects_not_listed: 0,
            objects: Vec::new(),
        });
    };
    let report = service.report();
    let sweep = &report.sweep;
    Json(LoadedResponse {
        reading: true,
        scanned_at_ns: report.scanned_at_ns,
        last_error: report.error.clone(),
        processes_listed: sweep.processes_listed,
        processes_reread: sweep.processes_reread,
        processes_not_read: sweep.processes_not_read,
        objects_not_listed: sweep.loaded.not_listed,
        objects: sweep.loaded.objects.iter().map(loaded).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::container::entity::ContainerRuntime;
    use domain::inventory::PackageManager;

    fn sample() -> RootInventory {
        RootInventory {
            scope: RootScope::Container {
                container_id: "ab".repeat(32),
                runtime: ContainerRuntime::Containerd,
            },
            pid: 4242,
            databases: vec![
                DatabaseReading {
                    manager: PackageManager::Apk,
                    path: "/lib/apk/db/installed".into(),
                    outcome: DatabaseOutcome::Read {
                        packages: vec![Package {
                            manager: PackageManager::Apk,
                            name: "musl".into(),
                            version: "1.2.5-r10".into(),
                            arch: Some("x86_64".into()),
                            state: PackageState::Installed,
                            files: Some(vec!["/lib/ld-musl-x86_64.so.1".into()]),
                        }],
                    },
                },
                domain::inventory::unreadable(
                    PackageManager::Rpm,
                    "/var/lib/rpm/Packages",
                    "the rpm database is in its Berkeley DB format, which is not read",
                ),
            ],
            error: None,
        }
    }

    #[test]
    fn a_root_names_its_container_and_counts_each_package_s_files() {
        let b = root(&sample());
        assert_eq!((b.kind, b.pid), ("container", 4242));
        assert_eq!(b.runtime.as_deref(), Some("containerd"));
        assert_eq!(b.databases[0].manager, "apk");
        assert_eq!(b.databases[0].packages[0].files, Some(1));
        assert_eq!(b.databases[0].packages[0].state, "installed");
        assert!(
            b.databases[1]
                .unreadable
                .as_deref()
                .is_some_and(|r| r.contains("Berkeley"))
        );
    }

    fn go_sample() -> GoExecutableReading {
        domain::inventory::go_reading(
            RootScope::Other,
            "/usr/bin/app".into(),
            vec![7],
            Ok(&std::fs::read(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../domain/tests/fixtures/inventory/go/replaced.buildinfo"
            ))
            .unwrap_or_default()),
        )
    }

    #[test]
    fn a_go_executable_lists_its_main_module_first_and_names_a_replacement() {
        let b = go_executable(&go_sample());
        assert_eq!(b.kind, "other");
        assert_eq!(b.go_version.as_deref(), Some("go1.27.1"));
        assert_eq!(b.main_package.as_deref(), Some("example.com/app"));
        assert_eq!(b.modules.len(), 2);
        assert!(b.modules[0].main);
        assert_eq!(b.modules[1].path, "example.com/lib");
        assert_eq!(b.modules[1].replaced_by.as_deref(), Some("../lib (devel)"));
        assert!(b.unreadable.is_none());
    }

    #[test]
    fn no_field_names_a_vulnerability_a_severity_or_a_score() {
        let json = serde_json::to_string(&PackagesResponse {
            reading: true,
            source: Some("local"),
            scanned_at_ns: 1,
            last_error: None,
            roots_not_read: 0,
            roots: vec![root(&sample())],
            executables_examined: 1,
            go_executables_not_read: 0,
            go_executables: vec![go_executable(&go_sample())],
        })
        .unwrap_or_default()
        .to_lowercase();
        for word in ["cve", "severity", "score", "vulnerab", "cvss", "risk"] {
            assert!(!json.contains(&format!("\"{word}")), "{word}");
        }
    }

    #[test]
    fn a_mapped_file_names_its_owner_and_an_unread_root_says_so() {
        let owned = LoadedObject {
            scope: Some(RootScope::Host),
            root_pid: Some(1),
            path: "/usr/lib/libz.so.1".into(),
            deleted: true,
            owner: Some(domain::inventory::PackageRef {
                manager: PackageManager::Dpkg,
                name: "zlib1g".into(),
                version: "1:1.3".into(),
            }),
            pids: vec![7, 9],
            processes: 2,
        };
        let b = loaded(&owned);
        assert_eq!((b.kind, b.root_pid, b.deleted), ("host", Some(1), true));
        assert_eq!(b.owner.as_ref().map(|o| o.manager), Some("dpkg"));
        let unread = loaded(&LoadedObject {
            scope: None,
            root_pid: None,
            owner: None,
            ..owned
        });
        assert_eq!(unread.kind, "unread");
        let json = serde_json::to_value(&unread).unwrap_or_default();
        assert!(json.get("owner").is_none() && json.get("root_pid").is_none());
    }
}
