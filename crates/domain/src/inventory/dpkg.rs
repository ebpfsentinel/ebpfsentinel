//! The dpkg status file and the per-package file lists beside it.
//!
//! `/var/lib/dpkg/status` is a sequence of RFC 822 style stanzas, one per
//! package dpkg knows of, including packages removed with their
//! configuration kept and packages it never installed. The files a package
//! owns are not in it: each is listed in `info/<package>.list`, named with
//! the architecture as well for a `Multi-Arch: same` package, which is why
//! a stanza says which name its list goes by.

use super::entity::{Package, PackageManager, PackageState};

/// One package the status file says is on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DpkgEntry {
    pub name: String,
    pub version: String,
    pub arch: Option<String>,
    pub state: PackageState,
    /// `Multi-Arch: same`, whose list file carries the architecture.
    pub multi_arch_same: bool,
}

impl DpkgEntry {
    /// The name of this package's file list under `info/`, without the
    /// `.list` suffix.
    #[must_use]
    pub fn list_name(&self) -> String {
        match (&self.arch, self.multi_arch_same) {
            (Some(arch), true) => format!("{}:{arch}", self.name),
            _ => self.name.clone(),
        }
    }

    /// The package, with the files its list named or `None` when no list
    /// could be read for it.
    #[must_use]
    pub fn into_package(self, files: Option<Vec<String>>) -> Package {
        Package {
            manager: PackageManager::Dpkg,
            name: self.name,
            version: self.version,
            arch: self.arch,
            state: self.state,
            files,
        }
    }
}

/// The state a `Status:` line's third word puts a package in, `None` for a
/// package whose files are not on disk.
fn state(status: &str) -> Option<PackageState> {
    match status.split_whitespace().nth(2)? {
        "installed" | "triggers-awaited" | "triggers-pending" => Some(PackageState::Installed),
        "half-installed" | "unpacked" | "half-configured" => Some(PackageState::Partial),
        _ => None,
    }
}

/// Every package `status` says has files on disk, in file order. A stanza
/// with no name, no version or no status is skipped.
#[must_use]
pub fn parse_dpkg_status(status: &str) -> Vec<DpkgEntry> {
    let mut out = Vec::new();
    for stanza in status.split("\n\n") {
        let mut name = None;
        let mut version = None;
        let mut arch = None;
        let mut status_line = None;
        let mut multi_arch_same = false;
        for line in stanza.lines() {
            // Continuation lines of a multi-line field start with white
            // space and belong to the field above, never to a new one.
            if line.starts_with([' ', '\t']) {
                continue;
            }
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            let value = value.trim();
            match key {
                "Package" => name = Some(value.to_string()),
                "Version" => version = Some(value.to_string()),
                "Architecture" => arch = Some(value.to_string()),
                "Status" => status_line = Some(value.to_string()),
                "Multi-Arch" => multi_arch_same = value == "same",
                _ => {}
            }
        }
        let (Some(name), Some(version), Some(status_line)) = (name, version, status_line) else {
            continue;
        };
        let Some(state) = state(&status_line) else {
            continue;
        };
        out.push(DpkgEntry {
            name,
            version,
            arch,
            state,
            multi_arch_same,
        });
    }
    out
}

/// The paths a `.list` file names, the root's own `/.` left out.
#[must_use]
pub fn parse_dpkg_list(list: &str) -> Vec<String> {
    list.lines()
        .filter(|l| l.starts_with('/') && *l != "/.")
        .map(str::to_string)
        .collect()
}
