//! Which file offsets the warden lets the agent put a uprobe on.
//!
//! A uprobe reads the memory of every process that runs the probed code, so
//! the link the warden creates for the rootless agent is a privilege of its
//! own: on any offset of any file it would read a password out of `sshd` as
//! readily as a request out of `libssl`. The agent only ever probes the write
//! and read calls of a TLS library and the encrypt calls of a crypto library;
//! the warden holds it to that, from the file itself rather than from what the
//! agent says the offset is.
//!
//! An offset is admitted when it falls inside a function the file names
//! ([`PROBED_FUNCTIONS`]), in its dynamic or its full symbol table. A file
//! that names no function there - a statically linked or Go binary stripped of
//! its symbols, whose offsets the agent took from a signed catalogue or from the
//! Go function table - is admitted only on executable code, and only when the
//! file carries a TLS stack of its own ([`STATIC_TLS_MARKERS`]). An offset
//! inside a function the file names and the list does not is refused, as is
//! anything that is not a regular file.

use std::fs::File;

use object::elf::PF_X;
use object::{Object, ObjectSection, ObjectSegment, ObjectSymbol, SegmentFlags, SymbolKind};

/// The functions the agent probes: TLS write and read calls, then the crypto
/// libraries' encrypt calls, then Go's `crypto/tls`.
pub const PROBED_FUNCTIONS: &[&str] = &[
    "SSL_write",
    "SSL_read",
    "gnutls_record_send",
    "gnutls_record_recv",
    "wolfSSL_write",
    "wolfSSL_read",
    "mbedtls_ssl_write",
    "mbedtls_ssl_read",
    "s2n_send",
    "s2n_recv",
    "PR_Write",
    "PR_Read",
    "EVP_EncryptUpdate",
    "gcry_cipher_encrypt",
    "crypto_aead_xchacha20poly1305_ietf_encrypt",
    "crypto_secretstream_xchacha20poly1305_push",
    "crypto/tls.(*Conn).Write",
    "crypto/tls.(*Conn).Read",
];

/// Strings a TLS stack linked into a binary leaves behind once its symbols are
/// stripped: Go's function table keeps the name, `OpenSSL` and `BoringSSL` their
/// source file names in error records, the others their version banner.
pub const STATIC_TLS_MARKERS: &[&[u8]] = &[
    b"crypto/tls.(*Conn).Write",
    b"ssl_lib.c",
    b"wolfSSL",
    b"mbed TLS",
    b"s2n_connection",
];

/// The sections those strings live in: read-only data, and Go's function table.
const MARKER_SECTIONS: &[&str] = &[".rodata", ".gopclntab"];

/// Admit or refuse a uprobe at `offset` in the file open as `file`.
///
/// # Errors
///
/// Says why the offset is refused, in words the agent logs as they are.
pub fn admit(file: &File, offset: u64) -> Result<(), String> {
    let meta = file
        .metadata()
        .map_err(|e| format!("the uprobe target cannot be read: {e}"))?;
    if !meta.is_file() {
        return Err("the uprobe target is not a regular file".into());
    }
    let cache = object::read::ReadCache::new(file);
    let elf = object::File::parse(&cache)
        .map_err(|e| format!("the uprobe target is not an ELF file: {e}"))?;
    let named = functions_at(&elf, offset);
    if named
        .iter()
        .any(|name| PROBED_FUNCTIONS.contains(&name.as_str()))
    {
        return Ok(());
    }
    if let Some(name) = named.first() {
        return Err(format!(
            "offset {offset:#x} lies in {name}, which is not a TLS or crypto call the agent probes"
        ));
    }
    if !in_executable_segment(&elf, offset) {
        return Err(format!("offset {offset:#x} lies in no executable code"));
    }
    if carries_tls_stack(&elf) {
        return Ok(());
    }
    Err(format!(
        "offset {offset:#x} lies in a file that names no function there and carries no TLS stack"
    ))
}

/// Names of the functions whose file range holds `offset`, from both symbol
/// tables. A symbol of size zero holds only its first byte.
fn functions_at<'d, R: object::ReadRef<'d>>(elf: &object::File<'d, R>, offset: u64) -> Vec<String> {
    elf.dynamic_symbols()
        .chain(elf.symbols())
        .filter(|s| s.kind() == SymbolKind::Text && s.is_definition())
        .filter_map(|s| {
            let start = file_offset(elf, s.address())?;
            let end = start.checked_add(s.size().max(1))?;
            (start..end)
                .contains(&offset)
                .then(|| s.name().ok().map(str::to_owned))
                .flatten()
        })
        .collect()
}

/// The file offset of a virtual address, through the load segment holding it.
fn file_offset<'d, R: object::ReadRef<'d>>(elf: &object::File<'d, R>, addr: u64) -> Option<u64> {
    elf.segments().find_map(|seg| {
        let start = seg.address();
        let (file_off, file_size) = seg.file_range();
        (addr >= start && addr - start < file_size).then(|| addr - start + file_off)
    })
}

/// Whether `offset` lies in the file bytes of an executable load segment.
fn in_executable_segment<'d, R: object::ReadRef<'d>>(
    elf: &object::File<'d, R>,
    offset: u64,
) -> bool {
    elf.segments().any(|seg| {
        let executable =
            matches!(seg.flags(), SegmentFlags::Elf { p_flags, .. } if p_flags.0 & PF_X.0 != 0);
        let (file_off, file_size) = seg.file_range();
        executable && offset >= file_off && offset - file_off < file_size
    })
}

/// Whether the file carries one of [`STATIC_TLS_MARKERS`].
fn carries_tls_stack<'d, R: object::ReadRef<'d>>(elf: &object::File<'d, R>) -> bool {
    MARKER_SECTIONS.iter().any(|name| {
        elf.section_by_name(name)
            .and_then(|section| section.data().ok())
            .is_some_and(|data| {
                STATIC_TLS_MARKERS
                    .iter()
                    .any(|marker| data.windows(marker.len()).any(|w| w == *marker))
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The first executable file offset of an ELF, and the function there.
    fn first_function(path: &str) -> Option<(u64, String)> {
        let file = File::open(path).ok()?;
        let cache = object::read::ReadCache::new(&file);
        let elf = object::File::parse(&cache).ok()?;
        elf.dynamic_symbols()
            .filter(|s| s.kind() == SymbolKind::Text && s.is_definition() && s.size() > 0)
            .find_map(|s| Some((file_offset(&elf, s.address())?, s.name().ok()?.to_owned())))
    }

    /// The libc this test links against: present on every host the tests run on.
    fn libc_path() -> Option<String> {
        let maps = std::fs::read_to_string("/proc/self/maps").ok()?;
        maps.lines()
            .filter_map(|l| l.split_whitespace().nth(5))
            .find(|p| p.contains("libc.so"))
            .map(str::to_owned)
    }

    #[test]
    fn a_function_outside_the_list_is_refused_by_name() {
        let Some(libc) = libc_path() else { return };
        let (offset, name) = first_function(&libc).expect("libc names a function");
        let file = File::open(&libc).expect("opens");
        let refused = admit(&file, offset).expect_err("libc is not probed");
        assert!(refused.contains(&name), "{refused}");
    }

    #[test]
    fn an_offset_outside_executable_code_is_refused() {
        let Some(libc) = libc_path() else { return };
        let file = File::open(&libc).expect("opens");
        // The ELF header itself: no function, and in a read-only segment.
        let refused = admit(&file, 0).expect_err("header is not code");
        assert!(
            refused.contains("no executable code") || refused.contains("lies in"),
            "{refused}"
        );
    }

    #[test]
    fn a_directory_is_refused() {
        let dir = File::open("/").expect("opens");
        let refused = admit(&dir, 0).expect_err("a directory");
        assert!(refused.contains("regular file"), "{refused}");
    }

    #[test]
    fn the_list_covers_every_probed_family() {
        for name in ["SSL_write", "EVP_EncryptUpdate", "crypto/tls.(*Conn).Read"] {
            assert!(PROBED_FUNCTIONS.contains(&name), "{name}");
        }
    }
}
