//! HPACK header block decoding (RFC 7541).
//!
//! One decoder holds the dynamic table of one direction of one connection.
//! Every header block of that direction must pass through it in order, or
//! the table drifts from the encoder's and later indexes name the wrong
//! fields; the connection reader therefore never skips a header block.

use std::collections::VecDeque;

use super::huffman::{self, HuffmanError};

/// The 61 entries of the static table, RFC 7541 Appendix A, index 1 first.
const STATIC_TABLE: [(&str, &str); 61] = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

/// Dynamic table size an encoder starts with (RFC 7540, section 6.5.2).
const INITIAL_TABLE_SIZE: usize = 4096;

/// Largest dynamic table a size update may ask for. A peer may advertise
/// more, but a table this size already holds far more than a request needs,
/// and the cap bounds what one connection costs the agent.
pub const MAX_TABLE_SIZE: usize = 64 * 1024;

/// Largest sum of decoded name and value lengths in one header block.
pub const MAX_DECODED_BLOCK: usize = 64 * 1024;

/// Per-entry overhead counted in the table size (RFC 7541, section 4.1).
const ENTRY_OVERHEAD: usize = 32;

/// Why a header block could not be decoded. After any of these the
/// decoder's table may differ from the encoder's, so the connection is no
/// longer readable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HpackError {
    /// The block ended inside a representation.
    Truncated,
    /// An integer did not fit in 32 bits.
    IntegerOverflow,
    /// Index zero, or past the end of both tables.
    BadIndex,
    /// A size update above the cap, or one after the first field.
    BadSizeUpdate,
    /// A Huffman string that does not decode.
    Huffman(HuffmanError),
    /// The decoded fields exceed [`MAX_DECODED_BLOCK`].
    TooLarge,
}

impl From<HuffmanError> for HpackError {
    fn from(e: HuffmanError) -> Self {
        Self::Huffman(e)
    }
}

/// One decoded header field.
pub type Field = (Vec<u8>, Vec<u8>);

/// The decoder of one direction of one connection.
#[derive(Debug, Clone)]
pub struct Decoder {
    entries: VecDeque<Field>,
    size: usize,
    max_size: usize,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder {
    pub fn new() -> Self {
        Self {
            entries: VecDeque::new(),
            size: 0,
            max_size: INITIAL_TABLE_SIZE,
        }
    }

    /// Decode one complete header block into its fields, in order.
    pub fn decode(&mut self, block: &[u8]) -> Result<Vec<Field>, HpackError> {
        let mut fields = Vec::new();
        let mut decoded = 0usize;
        let mut pos = 0usize;
        while pos < block.len() {
            let first = block[pos];
            if first & 0x80 != 0 {
                let index = read_int(block, &mut pos, 7)?;
                let field = self.lookup(index)?;
                decoded = add_size(decoded, &field)?;
                fields.push(field);
            } else if first & 0xc0 == 0x40 {
                let field = self.read_literal(block, &mut pos, 6)?;
                decoded = add_size(decoded, &field)?;
                self.insert(field.clone());
                fields.push(field);
            } else if first & 0xe0 == 0x20 {
                // A size update may only open a block.
                if !fields.is_empty() {
                    return Err(HpackError::BadSizeUpdate);
                }
                let size = read_int(block, &mut pos, 5)?;
                if size > MAX_TABLE_SIZE {
                    return Err(HpackError::BadSizeUpdate);
                }
                self.max_size = size;
                self.evict(0);
            } else {
                // Literal without indexing (0000) or never indexed (0001).
                let field = self.read_literal(block, &mut pos, 4)?;
                decoded = add_size(decoded, &field)?;
                fields.push(field);
            }
        }
        Ok(fields)
    }

    fn read_literal(&self, block: &[u8], pos: &mut usize, prefix: u8) -> Result<Field, HpackError> {
        let index = read_int(block, pos, prefix)?;
        let name = if index == 0 {
            read_string(block, pos)?
        } else {
            self.lookup(index)?.0
        };
        let value = read_string(block, pos)?;
        Ok((name, value))
    }

    fn lookup(&self, index: usize) -> Result<Field, HpackError> {
        if index == 0 {
            return Err(HpackError::BadIndex);
        }
        if let Some((name, value)) = STATIC_TABLE.get(index - 1) {
            return Ok((name.as_bytes().to_vec(), value.as_bytes().to_vec()));
        }
        self.entries
            .get(index - 1 - STATIC_TABLE.len())
            .cloned()
            .ok_or(HpackError::BadIndex)
    }

    fn insert(&mut self, field: Field) {
        let size = field.0.len() + field.1.len() + ENTRY_OVERHEAD;
        if size > self.max_size {
            // An entry larger than the table empties it (section 4.4).
            self.entries.clear();
            self.size = 0;
            return;
        }
        self.evict(size);
        self.size += size;
        self.entries.push_front(field);
    }

    /// Drop the oldest entries until `room` more bytes fit.
    fn evict(&mut self, room: usize) {
        while self.size + room > self.max_size {
            let Some((name, value)) = self.entries.pop_back() else {
                self.size = 0;
                return;
            };
            self.size -= name.len() + value.len() + ENTRY_OVERHEAD;
        }
    }

    /// Entries in the dynamic table, newest first. For tests.
    #[cfg(test)]
    fn dynamic(&self) -> Vec<Field> {
        self.entries.iter().cloned().collect()
    }
}

fn add_size(decoded: usize, field: &Field) -> Result<usize, HpackError> {
    let total = decoded + field.0.len() + field.1.len();
    if total > MAX_DECODED_BLOCK {
        return Err(HpackError::TooLarge);
    }
    Ok(total)
}

/// Read an integer with an `prefix`-bit prefix (RFC 7541, section 5.1).
fn read_int(block: &[u8], pos: &mut usize, prefix: u8) -> Result<usize, HpackError> {
    let mask = (1u64 << prefix) - 1;
    let first = *block.get(*pos).ok_or(HpackError::Truncated)?;
    *pos += 1;
    let mut value = u64::from(first) & mask;
    if value < mask {
        return usize::try_from(value).map_err(|_| HpackError::IntegerOverflow);
    }
    let mut shift = 0u32;
    loop {
        let byte = *block.get(*pos).ok_or(HpackError::Truncated)?;
        *pos += 1;
        value += u64::from(byte & 0x7f) << shift;
        if value > u64::from(u32::MAX) {
            return Err(HpackError::IntegerOverflow);
        }
        if byte & 0x80 == 0 {
            return usize::try_from(value).map_err(|_| HpackError::IntegerOverflow);
        }
        shift += 7;
        if shift > 28 {
            return Err(HpackError::IntegerOverflow);
        }
    }
}

/// Read a string literal, Huffman-coded or not (RFC 7541, section 5.2).
fn read_string(block: &[u8], pos: &mut usize) -> Result<Vec<u8>, HpackError> {
    let huffman = block.get(*pos).ok_or(HpackError::Truncated)? & 0x80 != 0;
    let len = read_int(block, pos, 7)?;
    if len > MAX_DECODED_BLOCK {
        return Err(HpackError::TooLarge);
    }
    let end = pos.checked_add(len).ok_or(HpackError::Truncated)?;
    let raw = block.get(*pos..end).ok_or(HpackError::Truncated)?;
    *pos = end;
    if huffman {
        Ok(huffman::decode(raw)?)
    } else {
        Ok(raw.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn text(fields: &[Field]) -> Vec<(String, String)> {
        fields
            .iter()
            .map(|(n, v)| {
                (
                    String::from_utf8(n.clone()).unwrap(),
                    String::from_utf8(v.clone()).unwrap(),
                )
            })
            .collect()
    }

    fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter()
            .map(|(n, v)| ((*n).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn rfc_7541_c_3_requests_without_huffman() {
        let mut d = Decoder::new();
        let first = d
            .decode(&hex("828684410f7777772e6578616d706c652e636f6d"))
            .unwrap();
        assert_eq!(
            text(&first),
            pairs(&[
                (":method", "GET"),
                (":scheme", "http"),
                (":path", "/"),
                (":authority", "www.example.com"),
            ])
        );
        let second = d.decode(&hex("828684be58086e6f2d6361636865")).unwrap();
        assert_eq!(
            text(&second),
            pairs(&[
                (":method", "GET"),
                (":scheme", "http"),
                (":path", "/"),
                (":authority", "www.example.com"),
                ("cache-control", "no-cache"),
            ])
        );
        let third = d
            .decode(&hex(
                "828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565",
            ))
            .unwrap();
        assert_eq!(
            text(&third),
            pairs(&[
                (":method", "GET"),
                (":scheme", "https"),
                (":path", "/index.html"),
                (":authority", "www.example.com"),
                ("custom-key", "custom-value"),
            ])
        );
        assert_eq!(
            text(&d.dynamic()),
            pairs(&[
                ("custom-key", "custom-value"),
                ("cache-control", "no-cache"),
                (":authority", "www.example.com"),
            ])
        );
    }

    #[test]
    fn rfc_7541_c_4_requests_with_huffman() {
        let mut d = Decoder::new();
        let first = d
            .decode(&hex("828684418cf1e3c2e5f23a6ba0ab90f4ff"))
            .unwrap();
        assert_eq!(
            text(&first)[3],
            pairs(&[(":authority", "www.example.com")])[0]
        );
        let second = d.decode(&hex("828684be5886a8eb10649cbf")).unwrap();
        assert_eq!(text(&second)[4], pairs(&[("cache-control", "no-cache")])[0]);
        let third = d
            .decode(&hex("828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf"))
            .unwrap();
        assert_eq!(text(&third)[4], pairs(&[("custom-key", "custom-value")])[0]);
    }

    #[test]
    fn rfc_7541_c_5_eviction_with_a_small_table() {
        // Responses of C.5, with the table capped at 256 bytes by a size
        // update at the head of the first block.
        let mut d = Decoder::new();
        let mut first = hex("3fe101");
        first.extend(hex(
            "4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d706c652e636f6d",
        ));
        d.decode(&first).unwrap();
        d.decode(&hex("4803333037c1c0bf")).unwrap();
        let third = d
            .decode(&hex(
                "88c1611d4d6f6e2c203231204f637420323031332032303a31333a323220474d54c05a04677a69707738666f6f3d4153444a4b48514b425a584f5157454f50495541585157454f49553b206d61782d6167653d333630303b2076657273696f6e3d31",
            ))
            .unwrap();
        assert_eq!(third.len(), 6);
        assert_eq!(
            text(&d.dynamic())
                .iter()
                .map(|(n, _)| n.as_str())
                .collect::<Vec<_>>(),
            vec!["set-cookie", "content-encoding", "date"]
        );
    }

    #[test]
    fn index_zero_is_refused() {
        assert_eq!(Decoder::new().decode(&[0x80]), Err(HpackError::BadIndex));
    }

    #[test]
    fn index_past_both_tables_is_refused() {
        // Index 62 with an empty dynamic table.
        assert_eq!(Decoder::new().decode(&[0xbe]), Err(HpackError::BadIndex));
    }

    #[test]
    fn size_update_above_the_cap_is_refused() {
        // 5-bit prefix all ones, then 131072 - 31 in continuation bytes.
        let mut block = vec![0x3f];
        let mut rest = (MAX_TABLE_SIZE * 2 - 31) as u32;
        while rest >= 0x80 {
            block.push((rest as u8 & 0x7f) | 0x80);
            rest >>= 7;
        }
        block.push(rest as u8);
        assert_eq!(
            Decoder::new().decode(&block),
            Err(HpackError::BadSizeUpdate)
        );
    }

    #[test]
    fn size_update_after_a_field_is_refused() {
        assert_eq!(
            Decoder::new().decode(&[0x82, 0x20]),
            Err(HpackError::BadSizeUpdate)
        );
    }

    #[test]
    fn an_integer_past_32_bits_is_refused() {
        assert_eq!(
            Decoder::new().decode(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]),
            Err(HpackError::IntegerOverflow)
        );
    }

    #[test]
    fn a_string_running_past_the_block_is_refused() {
        // Literal, new name of length 10, only 2 bytes present.
        assert_eq!(
            Decoder::new().decode(&[0x00, 0x0a, b'a', b'b']),
            Err(HpackError::Truncated)
        );
    }
}
