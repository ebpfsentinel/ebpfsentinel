//! A read-only walk of one rowid table in an SQLite database file.
//!
//! The rpm database has been an SQLite file since rpm 4.16, and the agent
//! reads it the way it reads every other package database: as bytes taken
//! from inside a container, which makes them untrusted input. Linking a C
//! library to read them would put a second parser of hostile bytes in the
//! agent, and the one table rpm keeps its headers in is a plain rowid table,
//! so this walks the file format directly: the schema on page 1, the table's
//! b-tree, the records on its leaves and the overflow chains a large record
//! spills into. Nothing is written, no index is used and no SQL is parsed.
//!
//! Every page number, offset and length read from the file is checked
//! against the file before it is followed, a page is never visited twice,
//! and a record is never assembled beyond the size the file itself could
//! hold, so a corrupt or crafted file ends in an error rather than a loop
//! or an allocation the file did not pay for.

use std::collections::HashSet;

use super::error::InventoryError;

/// The sixteen bytes every SQLite 3 database file begins with.
const MAGIC: &[u8; 16] = b"SQLite format 3\0";
/// The database header that precedes the b-tree header on page 1.
const FILE_HEADER_LEN: usize = 100;
/// The smallest page size the format allows.
const MIN_PAGE_SIZE: usize = 512;

const INTERIOR_TABLE: u8 = 0x05;
const LEAF_TABLE: u8 = 0x0d;

/// One value of a record, as the serial type stored it.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Integer(i64),
    Real(f64),
    Blob(Vec<u8>),
    Text(Vec<u8>),
}

/// One row of a rowid table: its rowid and its columns in schema order.
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    pub rowid: i64,
    pub columns: Vec<Value>,
}

/// An SQLite database held in memory, checked for its header.
pub struct Database<'a> {
    bytes: &'a [u8],
    page_size: usize,
    usable: usize,
    pages: usize,
}

fn corrupt(what: impl Into<String>) -> InventoryError {
    InventoryError::Corrupt(what.into())
}

fn be_u16(bytes: &[u8], at: usize) -> Result<u16, InventoryError> {
    bytes
        .get(at..at + 2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]))
        .ok_or_else(|| corrupt("a two-byte field runs past its page"))
}

fn be_u32(bytes: &[u8], at: usize) -> Result<u32, InventoryError> {
    bytes
        .get(at..at + 4)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or_else(|| corrupt("a four-byte field runs past its page"))
}

/// Decode the variable-length integer at `at`, returning it and the bytes it
/// took: seven bits a byte, high bit set to continue, the ninth byte whole.
fn varint(bytes: &[u8], at: usize) -> Result<(u64, usize), InventoryError> {
    let mut value: u64 = 0;
    for i in 0..9 {
        let byte = *bytes
            .get(at + i)
            .ok_or_else(|| corrupt("a varint runs past its page"))?;
        if i == 8 {
            return Ok(((value << 8) | u64::from(byte), 9));
        }
        value = (value << 7) | u64::from(byte & 0x7f);
        if byte & 0x80 == 0 {
            return Ok((value, i + 1));
        }
    }
    Err(corrupt("a varint runs past its page"))
}

impl<'a> Database<'a> {
    /// Check the header of `bytes` and size its pages.
    ///
    /// # Errors
    ///
    /// The bytes are not an SQLite 3 file, or their header is inconsistent.
    pub fn open(bytes: &'a [u8]) -> Result<Self, InventoryError> {
        if bytes.len() < FILE_HEADER_LEN || &bytes[..16] != MAGIC {
            return Err(InventoryError::NotThisFormat(
                "not an SQLite 3 database".into(),
            ));
        }
        let page_size = match be_u16(bytes, 16)? {
            1 => 65_536,
            n => usize::from(n),
        };
        if page_size < MIN_PAGE_SIZE || !page_size.is_power_of_two() {
            return Err(corrupt(format!(
                "page size {page_size} is not one SQLite writes"
            )));
        }
        let reserved = usize::from(bytes[20]);
        let usable = page_size
            .checked_sub(reserved)
            .filter(|u| *u >= 480)
            .ok_or_else(|| corrupt("the reserved space leaves no usable page"))?;
        let pages = bytes.len() / page_size;
        if pages == 0 {
            return Err(corrupt("the file holds no whole page"));
        }
        Ok(Self {
            bytes,
            page_size,
            usable,
            pages,
        })
    }

    /// The bytes of page `number`, counted from 1.
    fn page(&self, number: u32) -> Result<&'a [u8], InventoryError> {
        let index = usize::try_from(number).map_err(|_| corrupt("page number too large"))?;
        if index == 0 || index > self.pages {
            return Err(corrupt(format!("page {number} is outside the file")));
        }
        let start = (index - 1) * self.page_size;
        Ok(&self.bytes[start..start + self.page_size])
    }

    /// The root page of the rowid table named `table`, from the schema.
    ///
    /// # Errors
    ///
    /// The schema cannot be read, or names no such table.
    pub fn table_root(&self, table: &str) -> Result<u32, InventoryError> {
        for row in self.rows(1)? {
            let [kind, name, _, root, ..] = row.columns.as_slice() else {
                continue;
            };
            let is_table = matches!(kind, Value::Text(t) if t == b"table");
            let named = matches!(name, Value::Text(n) if n == table.as_bytes());
            if is_table && named {
                return match root {
                    Value::Integer(r) => {
                        u32::try_from(*r).map_err(|_| corrupt("a root page is out of range"))
                    }
                    _ => Err(corrupt("a table's root page is not an integer")),
                };
            }
        }
        Err(InventoryError::NotThisFormat(format!(
            "the database holds no table named {table}"
        )))
    }

    /// Every row of the rowid table rooted at `root`, in rowid order.
    ///
    /// # Errors
    ///
    /// A page of the table or of an overflow chain is corrupt.
    pub fn rows(&self, root: u32) -> Result<Vec<Row>, InventoryError> {
        let mut rows = Vec::new();
        let mut visited: HashSet<u32> = HashSet::new();
        let mut stack = vec![root];
        while let Some(number) = stack.pop() {
            if !visited.insert(number) {
                return Err(corrupt(format!("page {number} is reached twice")));
            }
            let page = self.page(number)?;
            let header = if number == 1 { FILE_HEADER_LEN } else { 0 };
            let kind = *page
                .get(header)
                .ok_or_else(|| corrupt("a page has no b-tree header"))?;
            let cells = usize::from(be_u16(page, header + 3)?);
            match kind {
                LEAF_TABLE => {
                    for i in 0..cells {
                        let at = usize::from(be_u16(page, header + 8 + 2 * i)?);
                        rows.push(self.leaf_cell(page, at, &mut visited)?);
                    }
                }
                INTERIOR_TABLE => {
                    // Children are pushed right to left so the stack hands
                    // them back in key order.
                    stack.push(be_u32(page, header + 8)?);
                    for i in (0..cells).rev() {
                        let at = usize::from(be_u16(page, header + 12 + 2 * i)?);
                        stack.push(be_u32(page, at)?);
                    }
                }
                other => {
                    return Err(corrupt(format!(
                        "page {number} is of type {other:#04x}, not a table b-tree page"
                    )));
                }
            }
        }
        Ok(rows)
    }

    /// Decode the table leaf cell at `at`: payload size, rowid, the local
    /// part of the payload and, when it spilled, its overflow chain.
    fn leaf_cell(
        &self,
        page: &[u8],
        at: usize,
        visited: &mut HashSet<u32>,
    ) -> Result<Row, InventoryError> {
        let (size, a) = varint(page, at)?;
        let (rowid, b) = varint(page, at + a)?;
        let size = usize::try_from(size).map_err(|_| corrupt("a record is too large"))?;
        if size > self.bytes.len() {
            return Err(corrupt("a record is larger than the file holding it"));
        }
        let start = at + a + b;
        let local = self.local_len(size);
        let mut payload = Vec::with_capacity(size);
        payload.extend_from_slice(
            page.get(start..start + local)
                .ok_or_else(|| corrupt("a record runs past its page"))?,
        );
        if local < size {
            let mut next = be_u32(page, start + local)?;
            while payload.len() < size {
                if next == 0 {
                    return Err(corrupt("an overflow chain ends before its record"));
                }
                if !visited.insert(next) {
                    return Err(corrupt(format!("overflow page {next} is reached twice")));
                }
                let overflow = self.page(next)?;
                let take = (size - payload.len()).min(self.usable - 4);
                payload.extend_from_slice(&overflow[4..4 + take]);
                next = be_u32(overflow, 0)?;
            }
        }
        Ok(Row {
            // A rowid is a signed 64-bit integer stored as its two's
            // complement bits.
            rowid: i64::from_ne_bytes(rowid.to_ne_bytes()),
            columns: record(&payload)?,
        })
    }

    /// How much of a table leaf payload of `size` bytes stays on its page.
    fn local_len(&self, size: usize) -> usize {
        let u = self.usable;
        let max_local = u - 35;
        if size <= max_local {
            return size;
        }
        let min_local = ((u - 12) * 32 / 255) - 23;
        let k = min_local + ((size - min_local) % (u - 4));
        if k <= max_local { k } else { min_local }
    }
}

/// Decode a record: a header of serial types, then the values they size.
fn record(payload: &[u8]) -> Result<Vec<Value>, InventoryError> {
    let (header_len, mut at) = varint(payload, 0)?;
    let header_len =
        usize::try_from(header_len).map_err(|_| corrupt("a record header is too large"))?;
    if header_len > payload.len() || header_len < at {
        return Err(corrupt("a record header runs past its record"));
    }
    let mut body = header_len;
    let mut values = Vec::new();
    while at < header_len {
        let (serial, n) = varint(payload, at)?;
        at += n;
        let (value, len) = value(serial, payload, body)?;
        values.push(value);
        body += len;
    }
    Ok(values)
}

/// The value of serial type `serial` stored at `at`, and its length.
fn value(serial: u64, payload: &[u8], at: usize) -> Result<(Value, usize), InventoryError> {
    let int = |len: usize| -> Result<(Value, usize), InventoryError> {
        let bytes = payload
            .get(at..at + len)
            .ok_or_else(|| corrupt("an integer runs past its record"))?;
        let mut v: i64 = if bytes[0] & 0x80 == 0 { 0 } else { -1 };
        for byte in bytes {
            v = (v << 8) | i64::from(*byte);
        }
        Ok((Value::Integer(v), len))
    };
    match serial {
        0 => Ok((Value::Null, 0)),
        1 => int(1),
        2 => int(2),
        3 => int(3),
        4 => int(4),
        5 => int(6),
        6 => int(8),
        7 => {
            let bytes = payload
                .get(at..at + 8)
                .ok_or_else(|| corrupt("a real runs past its record"))?;
            let mut raw = [0u8; 8];
            raw.copy_from_slice(bytes);
            Ok((Value::Real(f64::from_be_bytes(raw)), 8))
        }
        8 => Ok((Value::Integer(0), 0)),
        9 => Ok((Value::Integer(1), 0)),
        10 | 11 => Err(corrupt("a record uses a reserved serial type")),
        n => {
            let len = usize::try_from((n - 12) / 2).map_err(|_| corrupt("a value is too large"))?;
            let bytes = payload
                .get(at..at + len)
                .ok_or_else(|| corrupt("a value runs past its record"))?
                .to_vec();
            Ok((
                if n % 2 == 0 {
                    Value::Blob(bytes)
                } else {
                    Value::Text(bytes)
                },
                len,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints_follow_the_format() {
        assert_eq!(varint(&[0x05], 0).ok(), Some((5, 1)));
        assert_eq!(varint(&[0x81, 0x00], 0).ok(), Some((128, 2)));
        assert_eq!(varint(&[0xff; 9], 0).ok(), Some((u64::MAX, 9)));
        assert!(varint(&[0x81], 0).is_err());
    }

    #[test]
    fn a_record_decodes_every_serial_type_it_uses() {
        // Header: length 5, NULL, 1-byte int, 3-byte text, 2-byte blob.
        let payload = [5, 0, 1, 19, 16, 0xfe, b'a', b'b', b'c', 0xca, 0xfe];
        let Ok(values) = record(&payload) else {
            panic!("the record decodes");
        };
        assert_eq!(
            values,
            vec![
                Value::Null,
                Value::Integer(-2),
                Value::Text(b"abc".to_vec()),
                Value::Blob(vec![0xca, 0xfe]),
            ]
        );
    }

    #[test]
    fn something_that_is_not_sqlite_is_said_so() {
        assert!(matches!(
            Database::open(b"not a database at all, and nowhere near long enough"),
            Err(InventoryError::NotThisFormat(_))
        ));
    }

    #[test]
    fn a_page_reached_twice_ends_the_walk() {
        // A 512-byte database whose page 1 is an interior table page whose
        // only child is page 1 itself.
        let mut db = vec![0u8; 512];
        db[..16].copy_from_slice(MAGIC);
        db[16..18].copy_from_slice(&512u16.to_be_bytes());
        db[100] = INTERIOR_TABLE;
        db[108..112].copy_from_slice(&1u32.to_be_bytes());
        let Ok(database) = Database::open(&db) else {
            panic!("the header is valid");
        };
        assert!(database.rows(1).is_err());
    }
}
