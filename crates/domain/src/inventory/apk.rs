//! The Alpine installed database, `lib/apk/db/installed`.
//!
//! One stanza per package, one `letter:value` line per field, separated by a
//! blank line. The files a package owns are in the same stanza: an `F:` line
//! opens a directory and each `R:` line after it names a file in it.

use super::entity::{Package, PackageManager, PackageState};

/// Every package the database lists, with the directories and files it owns.
/// A stanza with no name or no version is skipped.
#[must_use]
pub fn parse_apk_installed(installed: &str) -> Vec<Package> {
    let mut out = Vec::new();
    for stanza in installed.split("\n\n") {
        let mut name = None;
        let mut version = None;
        let mut arch = None;
        let mut files = Vec::new();
        let mut dir: Option<String> = None;
        for line in stanza.lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            match key {
                "P" => name = Some(value.to_string()),
                "V" => version = Some(value.to_string()),
                "A" => arch = Some(value.to_string()),
                "F" => {
                    let path = format!("/{}", value.trim_matches('/'));
                    files.push(path.clone());
                    dir = Some(path);
                }
                "R" => files.push(match &dir {
                    Some(d) if d != "/" => format!("{d}/{value}"),
                    _ => format!("/{value}"),
                }),
                _ => {}
            }
        }
        let (Some(name), Some(version)) = (name, version) else {
            continue;
        };
        out.push(Package {
            manager: PackageManager::Apk,
            name,
            version,
            arch,
            state: PackageState::Installed,
            files: Some(files),
        });
    }
    out
}
