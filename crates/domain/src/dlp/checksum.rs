//! Check-digit confirmation for the built-in national identifier patterns.
//!
//! A national identifier is mostly digits, and a regex alone cannot tell a
//! French social security number from any other fifteen digits in a payload.
//! Almost every scheme carries a check digit or a check letter for exactly
//! that reason, so a regex hit on one of these patterns is only reported once
//! the matched text passes the scheme's own check. That is what keeps a
//! pattern for nine separated digits from alerting on every phone number.
//!
//! The confirmation is keyed by the built-in pattern id, so it applies to
//! whichever engine produced the match - the OSS `regex` engine and the
//! Enterprise multi-pattern scanner both report a byte range, and both pass
//! that range through [`confirms`] before raising anything.

/// Built-in pattern ids whose matches are confirmed by a check digit.
pub const FR_NIR: &str = "dlp-pii-fr-nir";
pub const UK_NINO: &str = "dlp-pii-uk-nino";
pub const ES_DNI_NIE: &str = "dlp-pii-es-dni";
pub const IT_CODICE_FISCALE: &str = "dlp-pii-it-cf";
pub const CA_SIN: &str = "dlp-pii-ca-sin";
pub const BE_NATIONAL_NUMBER: &str = "dlp-pii-be-nrn";
pub const BR_CPF: &str = "dlp-pii-br-cpf";
pub const IN_AADHAAR: &str = "dlp-pii-in-aadhaar";
pub const US_SSN: &str = "dlp-pii-ssn";

/// Whether a regex match for `pattern_id` is a real identifier.
///
/// Patterns with no check scheme are confirmed unconditionally, so this is
/// safe to call on every match.
#[must_use]
pub fn confirms(pattern_id: &str, matched: &[u8]) -> bool {
    match pattern_id {
        FR_NIR => fr_nir(matched),
        UK_NINO => uk_nino(matched),
        ES_DNI_NIE => es_dni_nie(matched),
        IT_CODICE_FISCALE => it_codice_fiscale(matched),
        CA_SIN => ca_sin(&digits(matched)),
        BE_NATIONAL_NUMBER => be_national_number(&digits(matched)),
        BR_CPF => br_cpf(&digits(matched)),
        IN_AADHAAR => verhoeff(&digits(matched)),
        US_SSN => us_ssn(&digits(matched)),
        _ => true,
    }
}

/// The matched text with every separator (space, dot, hyphen) removed.
fn compact(matched: &[u8]) -> Vec<u8> {
    matched
        .iter()
        .copied()
        .filter(|b| !matches!(b, b' ' | b'.' | b'-' | b'\t'))
        .collect()
}

/// The decimal digits of the matched text, as values `0..=9`.
fn digits(matched: &[u8]) -> Vec<u8> {
    matched
        .iter()
        .filter(|b| b.is_ascii_digit())
        .map(|b| b - b'0')
        .collect()
}

/// Fold a run of digit values into an integer.
fn to_number(ds: &[u8]) -> u64 {
    ds.iter().fold(0u64, |n, &d| n * 10 + u64::from(d))
}

/// French NIR: thirteen digits then a two-digit key, `97 - (n mod 97)`.
/// Corsica's department codes `2A` and `2B` count as 19 and 18.
fn fr_nir(matched: &[u8]) -> bool {
    let c = compact(matched);
    if c.len() != 15 {
        return false;
    }
    let mut body = Vec::with_capacity(13);
    for (i, &b) in c[..13].iter().enumerate() {
        match b {
            b'0'..=b'9' => body.push(b - b'0'),
            b'A' | b'a' if i == 6 => {
                body.pop();
                body.extend([1, 9]);
            }
            b'B' | b'b' if i == 6 => {
                body.pop();
                body.extend([1, 8]);
            }
            _ => return false,
        }
    }
    let key = digits(&c[13..]);
    if key.len() != 2 {
        return false;
    }
    97 - to_number(&body) % 97 == to_number(&key)
}

/// UK National Insurance number: the regex fixes the shape, and these two
/// letter prefixes were never issued.
fn uk_nino(matched: &[u8]) -> bool {
    let c = compact(matched);
    let Some(prefix) = c.get(..2) else {
        return false;
    };
    !matches!(
        prefix,
        b"BG" | b"GB" | b"KN" | b"NK" | b"NT" | b"TN" | b"ZZ"
    )
}

/// Spanish DNI (eight digits) or NIE (`X`, `Y` or `Z` then seven digits),
/// closed by the letter at `n mod 23`.
fn es_dni_nie(matched: &[u8]) -> bool {
    const LETTERS: &[u8; 23] = b"TRWAGMYFPDXBNJZSQVHLCKE";
    let c = compact(matched);
    let Some((&letter, body)) = c.split_last() else {
        return false;
    };
    let lead = match body.first() {
        Some(b'X') => Some(0),
        Some(b'Y') => Some(1),
        Some(b'Z') => Some(2),
        _ => None,
    };
    let mut ds = Vec::with_capacity(8);
    if let Some(l) = lead {
        ds.push(l);
    }
    let rest = if lead.is_some() { &body[1..] } else { body };
    if !rest.iter().all(u8::is_ascii_digit) {
        return false;
    }
    ds.extend(rest.iter().map(|b| b - b'0'));
    if ds.len() != 8 {
        return false;
    }
    let idx = (to_number(&ds) % 23) as usize;
    LETTERS[idx] == letter.to_ascii_uppercase()
}

/// Italian codice fiscale: fifteen characters then a check letter, from a
/// table that weighs odd and even positions differently.
fn it_codice_fiscale(matched: &[u8]) -> bool {
    const ODD: [u32; 26] = [
        1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 2, 4, 18, 20, 11, 3, 6, 8, 12, 14, 16, 10, 22, 25, 24,
        23,
    ];
    let c: Vec<u8> = compact(matched)
        .iter()
        .map(u8::to_ascii_uppercase)
        .collect();
    if c.len() != 16 {
        return false;
    }
    let mut sum = 0u32;
    for (i, &b) in c[..15].iter().enumerate() {
        let v = match b {
            b'0'..=b'9' => u32::from(b - b'0'),
            b'A'..=b'Z' => u32::from(b - b'A'),
            _ => return false,
        };
        // Positions are counted from one, so index 0 is an odd position.
        sum += if i % 2 == 0 { ODD[v as usize] } else { v };
    }
    u32::from(c[15]) == u32::from(b'A') + sum % 26
}

/// Luhn over a digit run.
fn luhn(ds: &[u8]) -> bool {
    let sum: u32 = ds
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            let d = u32::from(d);
            if i % 2 == 1 {
                let x = d * 2;
                if x > 9 { x - 9 } else { x }
            } else {
                d
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

/// Canadian Social Insurance Number: nine digits under Luhn. No number
/// starting with 0 or 8 is issued.
fn ca_sin(ds: &[u8]) -> bool {
    ds.len() == 9 && !matches!(ds.first(), Some(0 | 8)) && luhn(ds)
}

/// Belgian national register number: nine digits then `97 - (n mod 97)`,
/// with a leading `2` prepended for anyone born from 2000 on.
fn be_national_number(ds: &[u8]) -> bool {
    if ds.len() != 11 {
        return false;
    }
    let body = to_number(&ds[..9]);
    let key = to_number(&ds[9..]);
    97 - body % 97 == key || 97 - (2_000_000_000 + body) % 97 == key
}

/// Brazilian CPF: two mod-11 check digits. A run of one repeated digit
/// passes the arithmetic and is never issued.
fn br_cpf(ds: &[u8]) -> bool {
    if ds.len() != 11 || ds.iter().all(|&d| d == ds[0]) {
        return false;
    }
    let check = |n: usize| {
        let sum: u32 = ds[..n]
            .iter()
            .enumerate()
            .map(|(i, &d)| u32::from(d) * (n as u32 + 1 - i as u32))
            .sum();
        (sum * 10 % 11 % 10) as u8
    };
    check(9) == ds[9] && check(10) == ds[10]
}

/// Verhoeff, the check scheme of the Indian Aadhaar number.
fn verhoeff(ds: &[u8]) -> bool {
    const D: [[u8; 10]; 10] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
        [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
        [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
        [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
        [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
        [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
        [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
        [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
        [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
    ];
    const P: [[u8; 10]; 8] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
        [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
        [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
        [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
        [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
        [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
        [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
    ];
    if ds.len() != 12 {
        return false;
    }
    let c = ds.iter().rev().enumerate().fold(0u8, |c, (i, &d)| {
        D[c as usize][P[i % 8][d as usize] as usize]
    });
    c == 0
}

/// US Social Security Number: no check digit, but area 000, 666 and 900-999,
/// group 00 and serial 0000 are never issued.
fn us_ssn(ds: &[u8]) -> bool {
    if ds.len() != 9 {
        return false;
    }
    let area = to_number(&ds[..3]);
    let group = to_number(&ds[3..5]);
    let serial = to_number(&ds[5..]);
    area != 0 && area != 666 && area < 900 && group != 0 && serial != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_patterns_are_confirmed() {
        assert!(confirms("dlp-pci-visa", b"4111111111111111"));
        assert!(confirms("custom-anything", b""));
    }

    #[test]
    fn french_nir() {
        assert!(confirms(FR_NIR, b"1 85 05 78 006 084 91"));
        assert!(confirms(FR_NIR, b"185057800608491"));
        assert!(confirms(FR_NIR, b"2 69 05 2A 123 456 88"));
        assert!(!confirms(FR_NIR, b"1 85 05 78 006 084 92"));
    }

    #[test]
    fn uk_nino() {
        assert!(confirms(UK_NINO, b"AB 12 34 56 C"));
        assert!(confirms(UK_NINO, b"JG103759A"));
        assert!(!confirms(UK_NINO, b"GB123456A"));
        assert!(!confirms(UK_NINO, b"NT 12 34 56 A"));
    }

    #[test]
    fn spanish_dni_and_nie() {
        assert!(confirms(ES_DNI_NIE, b"12345678Z"));
        assert!(confirms(ES_DNI_NIE, b"12345678-Z"));
        assert!(confirms(ES_DNI_NIE, b"X1234567L"));
        assert!(confirms(ES_DNI_NIE, b"Y1234567X"));
        assert!(!confirms(ES_DNI_NIE, b"12345678A"));
        assert!(!confirms(ES_DNI_NIE, b"X1234567A"));
    }

    #[test]
    fn italian_codice_fiscale() {
        assert!(confirms(IT_CODICE_FISCALE, b"RSSMRA85T10A562S"));
        assert!(confirms(IT_CODICE_FISCALE, b"MRTMTT25D09F205Z"));
        assert!(!confirms(IT_CODICE_FISCALE, b"RSSMRA85T10A562T"));
    }

    #[test]
    fn canadian_sin() {
        assert!(confirms(CA_SIN, b"293 456 786"));
        assert!(confirms(CA_SIN, b"130-692-544"));
        assert!(!confirms(CA_SIN, b"293 456 787"));
        // Luhn-valid, but no SIN starts with 0.
        assert!(!confirms(CA_SIN, b"046 454 286"));
        // Luhn-valid but never issued.
        assert!(!confirms(CA_SIN, b"000 000 000"));
    }

    #[test]
    fn belgian_national_number() {
        assert!(confirms(BE_NATIONAL_NUMBER, b"85.07.30-033.28"));
        assert!(confirms(BE_NATIONAL_NUMBER, b"17.07.30-033.84"));
        assert!(!confirms(BE_NATIONAL_NUMBER, b"85.07.30-033.29"));
    }

    #[test]
    fn brazilian_cpf() {
        assert!(confirms(BR_CPF, b"529.982.247-25"));
        assert!(confirms(BR_CPF, b"111.444.777-35"));
        assert!(!confirms(BR_CPF, b"529.982.247-26"));
        assert!(!confirms(BR_CPF, b"111.111.111-11"));
    }

    #[test]
    fn indian_aadhaar() {
        assert!(confirms(IN_AADHAAR, b"2341 2341 2346"));
        assert!(!confirms(IN_AADHAAR, b"2341 2341 2347"));
    }

    #[test]
    fn us_ssn() {
        assert!(confirms(US_SSN, b"123-45-6789"));
        assert!(!confirms(US_SSN, b"000-45-6789"));
        assert!(!confirms(US_SSN, b"666-45-6789"));
        assert!(!confirms(US_SSN, b"900-45-6789"));
        assert!(!confirms(US_SSN, b"123-00-6789"));
        assert!(!confirms(US_SSN, b"123-45-0000"));
    }
}
