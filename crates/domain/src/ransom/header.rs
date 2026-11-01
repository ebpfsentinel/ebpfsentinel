//! A file whose first bytes no longer say what its name says.
//!
//! Four leading bytes are read on a file the watch is already reading, and set
//! against the formats its extension claims. Legitimate software does not
//! leave a file named `.docx` that is not a ZIP archive or an encrypted Office
//! container, which is why a mismatch counted across files is decisive, and why
//! it survives an encryption that leaves the entropy of a sample flat: a run
//! that encrypts only the start of each file breaks the header first.
//!
//! The table covers only extensions whose header is fixed at the first byte.
//! Left out, because their header is not: MP3 (an ID3 tag or a bare frame),
//! MP4 and MOV (the signature sits at byte four), plain text, CSV, JSON, XML
//! and HTML (no signature at all), and `.db`, which a dozen engines share.

/// Leading bytes read from a regular file to compare with its extension.
pub const HEADER_BYTES: usize = 4;

const ZIP: &[&[u8]] = &[b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"];
/// A password-protected Office Open XML file is an OLE compound file, not a
/// ZIP archive, so both are what those names may hold.
const OOXML: &[&[u8]] = &[
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"PK\x07\x08",
    b"\xD0\xCF\x11\xE0",
];
const OLE: &[&[u8]] = &[b"\xD0\xCF\x11\xE0"];
const PDF: &[&[u8]] = &[b"%PDF"];
const PNG: &[&[u8]] = &[b"\x89PNG"];
const JPEG: &[&[u8]] = &[b"\xFF\xD8\xFF"];
const GIF: &[&[u8]] = &[b"GIF8"];
const TIFF: &[&[u8]] = &[b"II*\x00", b"MM\x00*"];
const BMP: &[&[u8]] = &[b"BM"];
const PSD: &[&[u8]] = &[b"8BPS"];
const RIFF: &[&[u8]] = &[b"RIFF"];
const FLAC: &[&[u8]] = &[b"fLaC"];
const OGG: &[&[u8]] = &[b"OggS"];
const GZIP: &[&[u8]] = &[b"\x1F\x8B"];
const BZIP2: &[&[u8]] = &[b"BZh"];
const XZ: &[&[u8]] = &[b"\xFD7zX"];
const ZSTD: &[&[u8]] = &[b"\x28\xB5\x2F\xFD"];
const SEVEN_ZIP: &[&[u8]] = &[b"7z\xBC\xAF"];
const RAR: &[&[u8]] = &[b"Rar!"];
const SQLITE: &[&[u8]] = &[b"SQLi"];
const RTF: &[&[u8]] = &[b"{\\rt"];

/// The headers a file named with `extension`, lower-cased, may start with;
/// nothing for an extension the table does not cover.
#[must_use]
pub fn expected_headers(extension: &str) -> Option<&'static [&'static [u8]]> {
    Some(match extension {
        "zip" | "jar" | "apk" | "epub" | "odt" | "ods" | "odp" | "odg" => ZIP,
        "docx" | "xlsx" | "pptx" | "docm" | "xlsm" | "pptm" => OOXML,
        "doc" | "xls" | "ppt" | "msg" => OLE,
        "pdf" => PDF,
        "png" => PNG,
        "jpg" | "jpeg" => JPEG,
        "gif" => GIF,
        "tif" | "tiff" => TIFF,
        "bmp" => BMP,
        "psd" => PSD,
        "wav" | "avi" | "webp" => RIFF,
        "flac" => FLAC,
        "ogg" | "oga" | "ogv" | "opus" => OGG,
        "gz" | "tgz" => GZIP,
        "bz2" | "tbz2" => BZIP2,
        "xz" | "txz" => XZ,
        "zst" => ZSTD,
        "7z" => SEVEN_ZIP,
        "rar" => RAR,
        "sqlite" | "sqlite3" => SQLITE,
        "rtf" => RTF,
        _ => return None,
    })
}

/// The extension of the last component of `path`, lower-cased, where the
/// name is not one the table must never judge.
fn judged_extension(path: &str) -> Option<String> {
    let name = path.rsplit('/').next().unwrap_or(path);
    // An Office owner file (`~$report.docx`) holds the editor's name, not a
    // document, and a dotfile has a name but no extension.
    if name.starts_with("~$") || name.starts_with('.') {
        return None;
    }
    let (_, extension) = name.rsplit_once('.')?;
    Some(extension.to_ascii_lowercase())
}

/// Whether the file at `path`, starting with `head`, holds something other
/// than what its extension names. A head the reader did not get, a file
/// shorter than [`HEADER_BYTES`], a head of zeros (a file preallocated and
/// not yet written, the way download and torrent clients reserve space) and
/// an extension the table does not cover are never a mismatch.
#[must_use]
pub fn header_mismatch(path: &str, head: Option<[u8; HEADER_BYTES]>) -> bool {
    let Some(head) = head else {
        return false;
    };
    if head == [0; HEADER_BYTES] {
        return false;
    }
    let Some(expected) = judged_extension(path).as_deref().and_then(expected_headers) else {
        return false;
    };
    !expected.iter().any(|magic| head.starts_with(magic))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_document_that_is_what_it_says_is_no_mismatch() {
        assert!(!header_mismatch("/srv/a.pdf", Some(*b"%PDF")));
        assert!(!header_mismatch("/srv/b.DOCX", Some(*b"PK\x03\x04")));
        assert!(!header_mismatch("/srv/c.docx", Some(*b"\xD0\xCF\x11\xE0")));
        assert!(!header_mismatch("/srv/d.jpg", Some(*b"\xFF\xD8\xFF\xE0")));
        assert!(!header_mismatch("/srv/e.bmp", Some(*b"BM6\x00")));
    }

    #[test]
    fn ciphertext_under_a_known_name_is_a_mismatch() {
        assert!(header_mismatch(
            "/srv/a.pdf",
            Some([0x9A, 0x13, 0x7F, 0x02])
        ));
        assert!(header_mismatch("/srv/b.xlsx", Some(*b"%PDF")));
        assert!(header_mismatch(
            "/srv/c.png",
            Some([0xFF, 0xD8, 0xFF, 0xE0])
        ));
    }

    #[test]
    fn what_the_table_cannot_judge_is_never_a_mismatch() {
        assert!(!header_mismatch("/srv/a.pdf", None));
        assert!(!header_mismatch("/srv/a.pdf", Some([0; 4])));
        assert!(!header_mismatch("/srv/notes.txt", Some([0x9A, 1, 2, 3])));
        assert!(!header_mismatch("/srv/song.mp3", Some([0x9A, 1, 2, 3])));
        assert!(!header_mismatch("/srv/~$report.docx", Some(*b"\x0Bmax")));
        assert!(!header_mismatch("/srv/.pdf", Some([0x9A, 1, 2, 3])));
        assert!(!header_mismatch("/srv/noext", Some([0x9A, 1, 2, 3])));
        assert!(!header_mismatch("/srv/a.pdf.locked", Some([0x9A, 1, 2, 3])));
    }

    #[test]
    fn every_covered_header_fits_in_the_bytes_read() {
        for ext in [
            "zip", "docx", "doc", "pdf", "png", "jpg", "gif", "tif", "bmp", "psd", "wav", "flac",
            "ogg", "gz", "bz2", "xz", "zst", "7z", "rar", "sqlite", "rtf",
        ] {
            let headers = expected_headers(ext).unwrap();
            assert!(
                headers
                    .iter()
                    .all(|h| !h.is_empty() && h.len() <= HEADER_BYTES)
            );
        }
    }
}
