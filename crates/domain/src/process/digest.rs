//! The digest of the file a process is running, which is what a path is not.
//!
//! A path says where a binary sits, and anything able to write a file can
//! put other bytes under a name a rule trusts. A digest says what the bytes
//! are. Two ways of obtaining one are kept apart in the type, because they
//! are not the same claim and are not computed by the same command:
//!
//! - [`DigestSource::FsVerity`] is the file's fs-verity digest, asked of the
//!   kernel. The file is read-only for as long as verity is on and every page
//!   read from it is checked against that digest, so the answer holds for the
//!   life of the process. `fsverity digest <file>` prints it.
//! - [`DigestSource::Content`] is the SHA-256 of the file's contents, read by
//!   the agent once per file and kept until the file changes. It is what
//!   `sha256sum <file>` prints and what a release's `SHA256SUMS` lists, and it
//!   holds as of the read: a file rewritten afterwards is read again.
//!
//! The written form carries the source as a prefix, `fsverity-sha256:` or
//! `sha256:`, so a rule written against one can never match the other by
//! accident: the two are different functions of the same file.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Length of a SHA-256 digest, in bytes.
pub const SHA256_LEN: usize = 32;

/// Prefix of a digest the kernel's fs-verity answered.
const FSVERITY_PREFIX: &str = "fsverity-sha256:";

/// Prefix of a digest read from the file's contents.
const CONTENT_PREFIX: &str = "sha256:";

/// How a digest was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DigestSource {
    /// The kernel's fs-verity measurement of a file that has verity on.
    FsVerity,
    /// The SHA-256 of the file's contents, read by the agent.
    Content,
}

impl DigestSource {
    /// The word an API response and an alert use.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FsVerity => "fsverity",
            Self::Content => "content",
        }
    }
}

/// The digest of an executable, and how it was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ExeHash {
    source: DigestSource,
    digest: [u8; SHA256_LEN],
}

/// Why a written digest was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExeHashError {
    /// Neither `fsverity-sha256:` nor `sha256:` in front.
    #[error("a digest starts with `sha256:` or `fsverity-sha256:`")]
    UnknownPrefix,
    /// Not 64 hexadecimal characters after the prefix.
    #[error("a SHA-256 digest is 64 hexadecimal characters")]
    BadDigest,
}

impl ExeHash {
    /// A digest from its parts.
    #[must_use]
    pub fn new(source: DigestSource, digest: [u8; SHA256_LEN]) -> Self {
        Self { source, digest }
    }

    /// How the digest was obtained.
    #[must_use]
    pub fn source(&self) -> DigestSource {
        self.source
    }

    /// The raw digest.
    #[must_use]
    pub fn digest(&self) -> &[u8; SHA256_LEN] {
        &self.digest
    }

    /// Read a written digest, upper or lower case, surrounding blanks
    /// ignored.
    ///
    /// # Errors
    ///
    /// [`ExeHashError::UnknownPrefix`] without one of the two prefixes, and
    /// [`ExeHashError::BadDigest`] when what follows is not 64 hexadecimal
    /// characters.
    pub fn parse(written: &str) -> Result<Self, ExeHashError> {
        let written = written.trim();
        let lower = written.to_ascii_lowercase();
        let (source, hex) = if let Some(hex) = lower.strip_prefix(FSVERITY_PREFIX) {
            (DigestSource::FsVerity, hex)
        } else if let Some(hex) = lower.strip_prefix(CONTENT_PREFIX) {
            (DigestSource::Content, hex)
        } else {
            return Err(ExeHashError::UnknownPrefix);
        };
        if hex.len() != SHA256_LEN * 2 {
            return Err(ExeHashError::BadDigest);
        }
        let mut digest = [0u8; SHA256_LEN];
        for (i, byte) in digest.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                .map_err(|_| ExeHashError::BadDigest)?;
        }
        Ok(Self { source, digest })
    }
}

impl fmt::Display for ExeHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.source {
            DigestSource::FsVerity => FSVERITY_PREFIX,
            DigestSource::Content => CONTENT_PREFIX,
        })?;
        for byte in &self.digest {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl From<ExeHash> for String {
    fn from(hash: ExeHash) -> Self {
        hash.to_string()
    }
}

impl TryFrom<String> for ExeHash {
    type Error = ExeHashError;

    fn try_from(written: String) -> Result<Self, Self::Error> {
        Self::parse(&written)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn a_digest_reads_back_as_it_was_written() {
        for prefix in ["sha256:", "fsverity-sha256:"] {
            let written = format!("{prefix}{HEX}");
            assert_eq!(ExeHash::parse(&written).unwrap().to_string(), written);
        }
    }

    #[test]
    fn upper_case_and_blanks_are_the_same_digest() {
        let upper = format!("  SHA256:{}\n", HEX.to_ascii_uppercase());
        assert_eq!(
            ExeHash::parse(&upper).unwrap(),
            ExeHash::parse(&format!("sha256:{HEX}")).unwrap()
        );
    }

    #[test]
    fn the_two_sources_never_compare_equal() {
        let content = ExeHash::parse(&format!("sha256:{HEX}")).unwrap();
        let verity = ExeHash::parse(&format!("fsverity-sha256:{HEX}")).unwrap();
        assert_ne!(content, verity);
        assert_eq!(verity.source(), DigestSource::FsVerity);
        assert_eq!(content.source(), DigestSource::Content);
    }

    #[test]
    fn a_bare_digest_or_a_short_one_is_refused() {
        assert_eq!(ExeHash::parse(HEX), Err(ExeHashError::UnknownPrefix));
        assert_eq!(
            ExeHash::parse("md5:d41d8cd98f00b204e9800998ecf8427e"),
            Err(ExeHashError::UnknownPrefix)
        );
        assert_eq!(
            ExeHash::parse(&format!("sha256:{}", &HEX[..63])),
            Err(ExeHashError::BadDigest)
        );
        assert_eq!(
            ExeHash::parse(&format!("sha256:{}zz", &HEX[..62])),
            Err(ExeHashError::BadDigest)
        );
    }

    #[test]
    fn it_travels_as_its_written_form() {
        let hash = ExeHash::parse(&format!("fsverity-sha256:{HEX}")).unwrap();
        let json = serde_json::to_string(&hash).unwrap();
        assert_eq!(json, format!("\"fsverity-sha256:{HEX}\""));
        assert_eq!(serde_json::from_str::<ExeHash>(&json).unwrap(), hash);
        assert!(serde_json::from_str::<ExeHash>("\"sha1:abc\"").is_err());
    }
}
