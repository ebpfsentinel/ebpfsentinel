use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use domain::inventory::{
    DatabaseOutcome, DatabaseReading, GoExecutableReading, GoModule, GoOutcome, Package,
    PackageState, RootInventory, RootScope,
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
}
