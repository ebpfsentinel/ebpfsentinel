//! Huffman decoding of HPACK string literals (RFC 7541, section 5.2 and
//! Appendix B).
//!
//! The code is canonical: sorted by length then value, each code is the
//! previous one plus one, shifted left when the length grows. Decoding walks
//! the bits once and, at each length, checks whether the bits read so far fall
//! in the range of codes of that length, so it needs no tree.

use std::sync::LazyLock;

use super::huffman_table::CODES;

/// Longest code in the table, in bits.
const MAX_CODE_LEN: usize = 30;

/// Symbol index of end-of-string, which never appears inside a string.
const EOS: u16 = 256;

/// Why a Huffman string could not be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HuffmanError {
    /// A run of more than 30 bits matched no code.
    UnknownCode,
    /// The end-of-string symbol appeared inside the string.
    EndOfStringInside,
    /// The final bits were not a prefix of end-of-string of at most 7 bits.
    BadPadding,
}

/// For each code length, the first code of that length, how many codes have
/// it, and where they start in `symbols`.
struct Canonical {
    first_code: [u32; MAX_CODE_LEN + 1],
    count: [u32; MAX_CODE_LEN + 1],
    first_index: [usize; MAX_CODE_LEN + 1],
    symbols: Vec<u16>,
}

static CANONICAL: LazyLock<Canonical> = LazyLock::new(|| {
    let mut symbols: Vec<u16> = (0..=EOS).collect();
    symbols.sort_by_key(|&s| {
        let (code, len) = CODES[usize::from(s)];
        (len, code)
    });
    let mut first_code = [0u32; MAX_CODE_LEN + 1];
    let mut count = [0u32; MAX_CODE_LEN + 1];
    let mut first_index = [0usize; MAX_CODE_LEN + 1];
    for (index, &symbol) in symbols.iter().enumerate() {
        let (code, len) = CODES[usize::from(symbol)];
        let len = usize::from(len);
        if count[len] == 0 {
            first_code[len] = code;
            first_index[len] = index;
        }
        count[len] += 1;
    }
    Canonical {
        first_code,
        count,
        first_index,
        symbols,
    }
});

/// Decode a Huffman-coded string literal.
pub fn decode(input: &[u8]) -> Result<Vec<u8>, HuffmanError> {
    let table = &*CANONICAL;
    // Every code is at least 5 bits, so the output is at most 8/5 the input.
    let mut out = Vec::with_capacity(input.len() * 8 / 5 + 1);
    let mut code: u32 = 0;
    let mut len: usize = 0;
    for &byte in input {
        for shift in (0..8).rev() {
            code = (code << 1) | u32::from((byte >> shift) & 1);
            len += 1;
            if len > MAX_CODE_LEN {
                return Err(HuffmanError::UnknownCode);
            }
            let n = table.count[len];
            if n == 0 {
                continue;
            }
            let offset = code.wrapping_sub(table.first_code[len]);
            if code >= table.first_code[len] && offset < n {
                let symbol = table.symbols[table.first_index[len] + offset as usize];
                if symbol == EOS {
                    return Err(HuffmanError::EndOfStringInside);
                }
                // Every symbol below EOS is an octet.
                out.push(symbol as u8);
                code = 0;
                len = 0;
            }
        }
    }
    // What is left must be padding: the most significant bits of
    // end-of-string, all ones, shorter than a byte.
    if len > 7 || code != (1u32 << len) - 1 {
        return Err(HuffmanError::BadPadding);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode with the same table, for round trips.
    fn encode(input: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut acc: u64 = 0;
        let mut bits: u32 = 0;
        for &b in input {
            let (code, len) = CODES[usize::from(b)];
            acc = (acc << len) | u64::from(code);
            bits += u32::from(len);
            while bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
            }
        }
        if bits > 0 {
            let pad = 8 - bits;
            acc = (acc << pad) | ((1u64 << pad) - 1);
            out.push(acc as u8);
        }
        out
    }

    #[test]
    fn rfc_7541_c_4_1_authority() {
        // "www.example.com", RFC 7541 Appendix C.4.1.
        let coded = [
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ];
        assert_eq!(decode(&coded).unwrap(), b"www.example.com");
    }

    #[test]
    fn rfc_7541_c_4_2_cache_control() {
        // "no-cache", RFC 7541 Appendix C.4.2.
        let coded = [0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf];
        assert_eq!(decode(&coded).unwrap(), b"no-cache");
    }

    #[test]
    fn rfc_7541_c_4_3_custom_value() {
        // "custom-value", RFC 7541 Appendix C.4.3.
        let coded = [0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf];
        assert_eq!(decode(&coded).unwrap(), b"custom-value");
    }

    #[test]
    fn every_octet_round_trips() {
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(decode(&encode(&all)).unwrap(), all);
    }

    #[test]
    fn a_grpc_path_round_trips() {
        let path = b"/admin.AdminService/DeleteUser";
        assert_eq!(decode(&encode(path)).unwrap(), path);
    }

    #[test]
    fn padding_of_zeros_is_refused() {
        // "a" is 00011 (5 bits); pad with zeros instead of ones.
        assert_eq!(decode(&[0b0001_1000]), Err(HuffmanError::BadPadding));
    }

    #[test]
    fn padding_of_a_whole_byte_is_refused() {
        let mut coded = encode(b"a");
        coded.push(0xff);
        assert_eq!(decode(&coded), Err(HuffmanError::BadPadding));
    }

    #[test]
    fn end_of_string_inside_is_refused() {
        // Thirty one-bits are end-of-string; two more bytes of ones follow.
        assert_eq!(
            decode(&[0xff, 0xff, 0xff, 0xfc]),
            Err(HuffmanError::EndOfStringInside)
        );
    }

    #[test]
    fn the_empty_string_decodes() {
        assert_eq!(decode(&[]).unwrap(), b"");
    }
}
