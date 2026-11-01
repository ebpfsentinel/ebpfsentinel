use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use domain::inventory::{
    DatabaseOutcome, DatabaseReading, Package, PackageState, RootInventory, RootScope,
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

fn root(r: &RootInventory) -> PackageRootBody {
    let (kind, container_id, runtime) = match &r.scope {
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
    };
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
    responses((status = 200, description = "The packages the dpkg, rpm and Alpine databases list in every root, with the reason a database could not be read", body = PackagesResponse),
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

    #[test]
    fn no_field_names_a_vulnerability_a_severity_or_a_score() {
        let json = serde_json::to_string(&PackagesResponse {
            reading: true,
            source: Some("local"),
            scanned_at_ns: 1,
            last_error: None,
            roots_not_read: 0,
            roots: vec![root(&sample())],
        })
        .unwrap_or_default()
        .to_lowercase();
        for word in ["cve", "severity", "score", "vulnerab", "cvss", "risk"] {
            assert!(!json.contains(&format!("\"{word}")), "{word}");
        }
    }
}
