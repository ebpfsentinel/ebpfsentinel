//! The build information a Go linker writes into its executable.
//!
//! Since Go 1.18 the `.go.buildinfo` section opens on a 32-byte header,
//! `\xff Go buildinf:` then the pointer size and a flags byte, followed by
//! two length-prefixed strings: the toolchain version and the module list.
//! Earlier toolchains wrote two pointers in place of the strings, which
//! would mean reading the executable's data at addresses it chose; that
//! form is reported as not read rather than followed.
//!
//! The module list is the one `go version -m` prints: one line per fact,
//! tab-separated, `path` for the main package, `mod` for the main module,
//! `dep` for each dependency and `=>` for the replacement of the line before.

use serde::{Deserialize, Serialize};

use super::error::InventoryError;

/// What opens the section.
const MAGIC: &[u8] = b"\xff Go buildinf:";
/// The header's length, strings follow it.
const HEADER_LEN: usize = 32;
/// The flag saying the strings follow the header rather than sit behind
/// pointers.
const FLAG_INLINE: u8 = 0x2;
/// The length of each sentinel the module list is wrapped in.
const SENTINEL_LEN: usize = 16;
/// The most modules read from one executable.
const MODULES_MAX: usize = 4096;

/// One module, as the linker recorded it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoModule {
    pub path: String,
    /// `(devel)` for a module built from a working tree.
    pub version: String,
    /// What a `replace` directive substituted for it, when one did: a
    /// module path and version, or a directory and `(devel)`.
    pub replaced_by: Option<GoReplacement>,
}

/// The module a `replace` directive put in another's place.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoReplacement {
    pub path: String,
    pub version: String,
}

/// What one executable says it was built from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoBuildInfo {
    /// The toolchain, `go1.22.5` and the like.
    pub go_version: String,
    /// The import path of the main package, when recorded.
    pub main_package: Option<String>,
    /// The module the main package belongs to.
    pub main_module: Option<GoModule>,
    /// Every module linked in, in the order the linker wrote them.
    pub dependencies: Vec<GoModule>,
}

impl GoBuildInfo {
    /// The main module, then every dependency.
    pub fn modules(&self) -> impl Iterator<Item = &GoModule> {
        self.main_module.iter().chain(&self.dependencies)
    }
}

/// An unsigned LEB128 varint at the start of `data`, and its length.
fn uvarint(data: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    for (i, &byte) in data.iter().enumerate().take(10) {
        value |= u64::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
    }
    None
}

/// A length-prefixed string at the start of `data`, and what follows it.
fn prefixed(data: &[u8]) -> Result<(&[u8], &[u8]), InventoryError> {
    let (len, used) = uvarint(data)
        .ok_or_else(|| InventoryError::Corrupt("a string length does not end".into()))?;
    let rest = &data[used..];
    let len = usize::try_from(len)
        .ok()
        .filter(|&len| len <= rest.len())
        .ok_or_else(|| InventoryError::Corrupt("a string runs past the section".into()))?;
    Ok(rest.split_at(len))
}

/// The module list without the sentinels the linker wraps it in.
fn unwrap_sentinels(modinfo: &[u8]) -> &[u8] {
    let len = modinfo.len();
    if len > 2 * SENTINEL_LEN && modinfo[len - SENTINEL_LEN - 1] == b'\n' {
        &modinfo[SENTINEL_LEN..len - SENTINEL_LEN]
    } else {
        modinfo
    }
}

/// A module line's path and version, the hash after them ignored.
fn module(fields: &[&str]) -> Option<(String, String)> {
    match fields {
        [path, version, ..] if !path.is_empty() => Some(((*path).into(), (*version).into())),
        _ => None,
    }
}

/// Read a `.go.buildinfo` section's bytes.
///
/// # Errors
///
/// [`InventoryError::NotThisFormat`] when the bytes do not open on the
/// header or carry the strings behind pointers, [`InventoryError::Corrupt`]
/// when they open on it and break it.
pub fn parse_go_buildinfo(section: &[u8]) -> Result<GoBuildInfo, InventoryError> {
    if section.len() < HEADER_LEN || !section.starts_with(MAGIC) {
        return Err(InventoryError::NotThisFormat(
            "the section does not open on the Go build information header".into(),
        ));
    }
    if section[MAGIC.len() + 1] & FLAG_INLINE == 0 {
        return Err(InventoryError::NotThisFormat(
            "the build information predates Go 1.18 and its strings sit behind pointers, which are not followed".into(),
        ));
    }
    let (version, rest) = prefixed(&section[HEADER_LEN..])?;
    let (modinfo, _) = prefixed(rest)?;
    let go_version = std::str::from_utf8(version)
        .map_err(|_| InventoryError::Corrupt("the toolchain version is not UTF-8".into()))?
        .to_owned();
    let modinfo = std::str::from_utf8(unwrap_sentinels(modinfo))
        .map_err(|_| InventoryError::Corrupt("the module list is not UTF-8".into()))?;
    let mut info = GoBuildInfo {
        go_version,
        main_package: None,
        main_module: None,
        dependencies: Vec::new(),
    };
    // Where the line before a `=>` put its module, for the replacement to
    // land on.
    let mut last_is_main = false;
    for line in modinfo.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        match fields.as_slice() {
            ["path", path, ..] => info.main_package = Some((*path).to_owned()),
            ["mod", rest @ ..] => {
                if let Some((path, version)) = module(rest) {
                    info.main_module = Some(GoModule {
                        path,
                        version,
                        replaced_by: None,
                    });
                    last_is_main = true;
                }
            }
            ["dep", rest @ ..] => {
                if info.dependencies.len() >= MODULES_MAX {
                    return Err(InventoryError::Corrupt(format!(
                        "more than {MODULES_MAX} modules are listed"
                    )));
                }
                if let Some((path, version)) = module(rest) {
                    info.dependencies.push(GoModule {
                        path,
                        version,
                        replaced_by: None,
                    });
                    last_is_main = false;
                }
            }
            ["=>", rest @ ..] => {
                let Some((path, version)) = module(rest) else {
                    continue;
                };
                let target = if last_is_main {
                    info.main_module.as_mut()
                } else {
                    info.dependencies.last_mut()
                };
                match target {
                    Some(target) if target.replaced_by.is_none() => {
                        target.replaced_by = Some(GoReplacement { path, version });
                    }
                    _ => {
                        return Err(InventoryError::Corrupt(
                            "a replacement follows no module".into(),
                        ));
                    }
                }
            }
            _ => {}
        }
    }
    Ok(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/inventory/go");

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!("{FIXTURES}/{name}")).unwrap()
    }

    #[test]
    fn a_released_tool_states_its_toolchain_and_every_module() {
        let info = parse_go_buildinfo(&fixture("goimports.buildinfo")).unwrap();
        assert_eq!(info.go_version, "go1.26.4");
        assert_eq!(
            info.main_package.as_deref(),
            Some("golang.org/x/tools/cmd/goimports")
        );
        let main = info.main_module.as_ref().unwrap();
        assert_eq!(
            (main.path.as_str(), main.version.as_str()),
            ("golang.org/x/tools", "v0.47.0")
        );
        let deps: Vec<(&str, &str)> = info
            .dependencies
            .iter()
            .map(|m| (m.path.as_str(), m.version.as_str()))
            .collect();
        assert_eq!(
            deps,
            [
                ("golang.org/x/mod", "v0.37.0"),
                ("golang.org/x/sync", "v0.21.0"),
                (
                    "golang.org/x/telemetry",
                    "v0.0.0-20260625142307-59b4966ccb57"
                ),
            ]
        );
        assert_eq!(info.modules().count(), 4);
    }

    #[test]
    fn a_replaced_dependency_names_what_took_its_place() {
        let info = parse_go_buildinfo(&fixture("replaced.buildinfo")).unwrap();
        assert_eq!(info.go_version, "go1.27.1");
        assert_eq!(info.main_module.as_ref().unwrap().version, "(devel)");
        let [lib] = info.dependencies.as_slice() else {
            panic!("one dependency");
        };
        assert_eq!(
            (lib.path.as_str(), lib.version.as_str()),
            ("example.com/lib", "v1.4.0")
        );
        assert_eq!(
            lib.replaced_by,
            Some(GoReplacement {
                path: "../lib".into(),
                version: "(devel)".into()
            })
        );
    }

    #[test]
    fn the_pointer_form_is_named_rather_than_followed() {
        let mut section = fixture("goimports.buildinfo");
        section[MAGIC.len() + 1] &= !FLAG_INLINE;
        assert!(matches!(
            parse_go_buildinfo(&section),
            Err(InventoryError::NotThisFormat(reason)) if reason.contains("1.18")
        ));
    }

    #[test]
    fn a_length_past_the_section_is_corrupt_not_a_panic() {
        let section = fixture("goimports.buildinfo");
        for cut in HEADER_LEN..section.len() {
            let _ = parse_go_buildinfo(&section[..cut]);
        }
        let mut huge = section[..HEADER_LEN].to_vec();
        huge.extend_from_slice(&[0xff; 12]);
        assert!(matches!(
            parse_go_buildinfo(&huge),
            Err(InventoryError::Corrupt(_))
        ));
        assert!(matches!(
            parse_go_buildinfo(b"not a section at all, long enough to pass"),
            Err(InventoryError::NotThisFormat(_))
        ));
    }

    #[test]
    fn a_replacement_with_no_module_before_it_is_corrupt() {
        let modinfo = "=>\t../lib\t(devel)\t\n";
        let mut section = MAGIC.to_vec();
        section.extend_from_slice(&[8, FLAG_INLINE]);
        section.resize(HEADER_LEN, 0);
        section.push(8);
        section.extend_from_slice(b"go1.22.5");
        section.push(u8::try_from(modinfo.len()).unwrap());
        section.extend_from_slice(modinfo.as_bytes());
        assert!(matches!(
            parse_go_buildinfo(&section),
            Err(InventoryError::Corrupt(_))
        ));
    }
}
