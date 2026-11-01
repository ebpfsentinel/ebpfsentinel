use serde::{Deserialize, Serialize};

use crate::container::entity::ContainerRuntime;

/// The package manager whose database a package was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PackageManager {
    Dpkg,
    Rpm,
    Apk,
}

impl PackageManager {
    /// The name the API and the CLI print.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dpkg => "dpkg",
            Self::Rpm => "rpm",
            Self::Apk => "apk",
        }
    }
}

/// Whether the package manager finished installing a package.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PackageState {
    /// Installed and configured.
    Installed,
    /// Unpacked or half-way through installation or configuration: its
    /// files may be on disk, so it is reported rather than left out.
    Partial,
}

/// One package a database says is installed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Package {
    pub manager: PackageManager,
    pub name: String,
    /// As the database writes it, epoch included where there is one.
    pub version: String,
    pub arch: Option<String>,
    pub state: PackageState,
    /// Absolute paths, inside the root the database belongs to, that the
    /// database says the package owns; `None` when it lists none for it.
    pub files: Option<Vec<String>>,
}

/// What reading one database gave.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "lowercase")]
pub enum DatabaseOutcome {
    /// The packages it lists.
    Read { packages: Vec<Package> },
    /// It exists and could not be read, and why.
    Unreadable { reason: String },
}

/// One package database found in a root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabaseReading {
    pub manager: PackageManager,
    /// Where it was found, inside the root.
    pub path: String,
    #[serde(flatten)]
    pub outcome: DatabaseOutcome,
}

impl DatabaseReading {
    /// The packages read, none when the database was unreadable.
    #[must_use]
    pub fn packages(&self) -> &[Package] {
        match &self.outcome {
            DatabaseOutcome::Read { packages } => packages,
            DatabaseOutcome::Unreadable { .. } => &[],
        }
    }
}

/// The filesystem root a set of databases was read from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum RootScope {
    /// The host's own root.
    Host,
    /// A container's root, reached through one of its processes.
    Container {
        container_id: String,
        runtime: ContainerRuntime,
    },
    /// A root no container runtime names, such as a chroot or a service
    /// confined to a directory of its own.
    Other,
}

/// Every package database of one root, read through process `pid`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootInventory {
    pub scope: RootScope,
    /// The process whose root was read.
    pub pid: u32,
    /// One entry per database found; none found is an empty list.
    pub databases: Vec<DatabaseReading>,
    /// The root could not be reached at all, and why.
    pub error: Option<String>,
}

impl RootInventory {
    /// Every package read in this root, across its databases.
    pub fn packages(&self) -> impl Iterator<Item = &Package> {
        self.databases.iter().flat_map(DatabaseReading::packages)
    }
}

/// Every root read in one sweep.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventorySweep {
    /// The host's root first, then the others by pid.
    pub roots: Vec<RootInventory>,
    /// Roots found beyond the number one sweep reads, left for none.
    pub roots_not_read: u32,
}
