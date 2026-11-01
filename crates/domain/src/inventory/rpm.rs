//! The rpm database: an SQLite file whose `Packages` table holds one rpm
//! header per installed package.
//!
//! A header is an index of `(tag, type, offset, count)` entries followed by
//! the data they point into. The name, version, release, epoch and
//! architecture are single entries; the files are three parallel arrays, a
//! base name per file, a directory per distinct directory and, per file, the
//! index of its directory, with the older single array of full paths still
//! read where a header carries it instead.
//!
//! rpm also writes the public keys it trusts as `gpg-pubkey` headers in the
//! same table. They own no file and are not software, so they are left out.

use super::entity::{Package, PackageManager, PackageState};
use super::error::InventoryError;
use super::sqlite::{Database, Value};

const TAG_NAME: i32 = 1000;
const TAG_VERSION: i32 = 1001;
const TAG_RELEASE: i32 = 1002;
const TAG_EPOCH: i32 = 1003;
const TAG_ARCH: i32 = 1022;
const TAG_OLDFILENAMES: i32 = 1027;
const TAG_DIRINDEXES: i32 = 1116;
const TAG_BASENAMES: i32 = 1117;
const TAG_DIRNAMES: i32 = 1118;

const TYPE_INT32: u32 = 4;
const TYPE_STRING: u32 = 6;
const TYPE_STRING_ARRAY: u32 = 8;
const TYPE_I18NSTRING: u32 = 9;

/// rpm refuses a header with more entries than this.
const MAX_ENTRIES: usize = 0xffff;

/// The name rpm stores each trusted public key under.
const PUBKEY_NAME: &str = "gpg-pubkey";

/// The table rpm keeps its headers in.
const PACKAGES_TABLE: &str = "Packages";

#[derive(Debug, Clone, Copy)]
struct Entry {
    kind: u32,
    offset: usize,
    count: usize,
}

/// One rpm header, indexed by tag.
struct Header<'a> {
    entries: Vec<(i32, Entry)>,
    data: &'a [u8],
}

fn corrupt(what: impl Into<String>) -> InventoryError {
    InventoryError::Corrupt(what.into())
}

fn word(bytes: &[u8], at: usize) -> Result<[u8; 4], InventoryError> {
    let b = bytes
        .get(at..at + 4)
        .ok_or_else(|| corrupt("a header runs past its blob"))?;
    Ok([b[0], b[1], b[2], b[3]])
}

impl<'a> Header<'a> {
    fn parse(blob: &'a [u8]) -> Result<Self, InventoryError> {
        let entries = u32::from_be_bytes(word(blob, 0)?) as usize;
        let data_len = u32::from_be_bytes(word(blob, 4)?) as usize;
        if entries > MAX_ENTRIES {
            return Err(corrupt(format!("a header claims {entries} entries")));
        }
        let data_start = 8 + entries * 16;
        let data = blob
            .get(data_start..data_start + data_len)
            .ok_or_else(|| corrupt("a header's data runs past its blob"))?;
        let mut index = Vec::with_capacity(entries);
        for i in 0..entries {
            let at = 8 + i * 16;
            let tag = i32::from_be_bytes(word(blob, at)?);
            let kind = u32::from_be_bytes(word(blob, at + 4)?);
            let offset = i32::from_be_bytes(word(blob, at + 8)?);
            let count = u32::from_be_bytes(word(blob, at + 12)?) as usize;
            // A negative offset belongs to the region trailer entries,
            // which carry nothing read here.
            let Ok(offset) = usize::try_from(offset) else {
                continue;
            };
            index.push((
                tag,
                Entry {
                    kind,
                    offset,
                    count,
                },
            ));
        }
        Ok(Self {
            entries: index,
            data,
        })
    }

    fn entry(&self, tag: i32) -> Option<Entry> {
        self.entries
            .iter()
            .find(|(t, _)| *t == tag)
            .map(|(_, e)| *e)
    }

    /// The `count` NUL-terminated strings starting at `offset`.
    fn strings(&self, entry: Entry) -> Result<Vec<String>, InventoryError> {
        let mut out = Vec::with_capacity(entry.count.min(self.data.len()));
        let mut at = entry.offset;
        for _ in 0..entry.count {
            let rest = self
                .data
                .get(at..)
                .ok_or_else(|| corrupt("a string runs past its header"))?;
            let end = rest
                .iter()
                .position(|b| *b == 0)
                .ok_or_else(|| corrupt("a string is not terminated"))?;
            out.push(String::from_utf8_lossy(&rest[..end]).into_owned());
            at += end + 1;
        }
        Ok(out)
    }

    /// The single string of `tag`, `None` when the header lacks it.
    fn string(&self, tag: i32) -> Result<Option<String>, InventoryError> {
        let Some(entry) = self.entry(tag) else {
            return Ok(None);
        };
        if !matches!(
            entry.kind,
            TYPE_STRING | TYPE_I18NSTRING | TYPE_STRING_ARRAY
        ) {
            return Err(corrupt(format!("tag {tag} is not a string")));
        }
        Ok(self
            .strings(Entry { count: 1, ..entry })?
            .into_iter()
            .next())
    }

    fn string_array(&self, tag: i32) -> Result<Option<Vec<String>>, InventoryError> {
        match self.entry(tag) {
            None => Ok(None),
            Some(e) if e.kind == TYPE_STRING_ARRAY => self.strings(e).map(Some),
            Some(_) => Err(corrupt(format!("tag {tag} is not a string array"))),
        }
    }

    fn int32_array(&self, tag: i32) -> Result<Option<Vec<i32>>, InventoryError> {
        let Some(entry) = self.entry(tag) else {
            return Ok(None);
        };
        if entry.kind != TYPE_INT32 {
            return Err(corrupt(format!("tag {tag} is not an int32 array")));
        }
        let len = entry
            .count
            .checked_mul(4)
            .ok_or_else(|| corrupt("an int32 array is too large"))?;
        let bytes = self
            .data
            .get(entry.offset..entry.offset + len)
            .ok_or_else(|| corrupt("an int32 array runs past its header"))?;
        Ok(Some(
            bytes
                .as_chunks::<4>()
                .0
                .iter()
                .map(|c| i32::from_be_bytes(*c))
                .collect(),
        ))
    }

    /// Every path the header says the package owns.
    fn files(&self) -> Result<Vec<String>, InventoryError> {
        if let Some(base) = self.string_array(TAG_BASENAMES)? {
            let dirs = self.string_array(TAG_DIRNAMES)?.unwrap_or_default();
            let index = self.int32_array(TAG_DIRINDEXES)?.unwrap_or_default();
            if index.len() != base.len() {
                return Err(corrupt("base names and directory indexes differ in length"));
            }
            return base
                .into_iter()
                .zip(index)
                .map(|(name, i)| {
                    let dir = usize::try_from(i)
                        .ok()
                        .and_then(|i| dirs.get(i))
                        .ok_or_else(|| corrupt("a directory index points nowhere"))?;
                    Ok(format!("{dir}{name}"))
                })
                .collect();
        }
        Ok(self.string_array(TAG_OLDFILENAMES)?.unwrap_or_default())
    }
}

/// The package one rpm header describes, `None` for a public key.
///
/// # Errors
///
/// The header is corrupt or lacks a name or a version.
pub fn parse_rpm_header(blob: &[u8]) -> Result<Option<Package>, InventoryError> {
    let header = Header::parse(blob)?;
    let name = header
        .string(TAG_NAME)?
        .ok_or_else(|| corrupt("a header has no name"))?;
    if name == PUBKEY_NAME {
        return Ok(None);
    }
    let version = header
        .string(TAG_VERSION)?
        .ok_or_else(|| corrupt("a header has no version"))?;
    let release = header.string(TAG_RELEASE)?;
    let epoch = header
        .int32_array(TAG_EPOCH)?
        .and_then(|e| e.first().copied());
    let mut full = match epoch {
        Some(e) => format!("{e}:{version}"),
        None => version,
    };
    if let Some(release) = release {
        full = format!("{full}-{release}");
    }
    Ok(Some(Package {
        manager: PackageManager::Rpm,
        name,
        version: full,
        arch: header.string(TAG_ARCH)?,
        state: PackageState::Installed,
        files: Some(header.files()?),
    }))
}

/// Every package an rpm SQLite database holds.
///
/// # Errors
///
/// The file is not an rpm SQLite database, or a page or a header is corrupt.
pub fn read_rpm_sqlite(bytes: &[u8]) -> Result<Vec<Package>, InventoryError> {
    let db = Database::open(bytes)?;
    let root = db.table_root(PACKAGES_TABLE)?;
    let mut out = Vec::new();
    for row in db.rows(root)? {
        // `hnum` is the rowid alias and is stored as NULL; the header is
        // the second column.
        let Some(Value::Blob(blob)) = row.columns.get(1) else {
            return Err(corrupt(format!("row {} holds no header blob", row.rowid)));
        };
        if let Some(package) = parse_rpm_header(blob)? {
            out.push(package);
        }
    }
    Ok(out)
}
