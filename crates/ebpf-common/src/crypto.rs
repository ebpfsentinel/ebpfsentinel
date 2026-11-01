//! Counting calls into the system cryptographic libraries, per process.
//!
//! A run that encrypts a filesystem calls a symmetric cipher once or more for
//! every file it rewrites. One uprobe on each library's encryption entry point
//! adds one to a per-CPU counter keyed by the calling thread group, and that
//! counter is all the kernel keeps: the program never reads an argument, so a
//! key, a buffer or a length has no way into a map. A binary carrying its own
//! cipher or linked statically calls none of these symbols and is not counted.

/// Thread groups counted at once. The map is least-recently-used, so a
/// process that stops calling is the first to go.
pub const CRYPTO_CALLS_MAX_TASKS: usize = 16_384;

/// The program attached to every entry point below.
pub const CRYPTO_PROGRAM: &str = "crypto_call";

/// The map the program counts into, read by the agent.
pub const CRYPTO_CALLS_MAP: &str = "CRYPTO_CALLS";

/// Symmetric encryption entry points, by the library name that carries them.
/// TLS inside OpenSSL goes through the record layer's own cipher calls rather
/// than `EVP_EncryptUpdate`, so a busy web server is not what this counts.
pub const CRYPTO_ENTRY_POINTS: &[(&str, &[&str])] = &[
    ("libcrypto.so", &["EVP_EncryptUpdate"]),
    ("libgcrypt.so", &["gcry_cipher_encrypt"]),
    (
        "libsodium.so",
        &[
            "crypto_secretstream_xchacha20poly1305_push",
            "crypto_aead_xchacha20poly1305_ietf_encrypt",
        ],
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_library_names_at_least_one_entry_point() {
        assert_eq!(CRYPTO_ENTRY_POINTS.len(), 3);
        for (library, symbols) in CRYPTO_ENTRY_POINTS {
            assert!(library.ends_with(".so"));
            assert!(!symbols.is_empty());
        }
    }
}
