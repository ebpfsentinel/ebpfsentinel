//! The API key an agent gives itself when nobody configured one.
//!
//! The control plane authenticates by default, which only works if a key
//! exists before the first request. One is drawn at first start and kept in a
//! file the agent owns, `0600` inside a `0700` directory, because the key is
//! what the firewall, the IPS and config reload answer to.
//!
//! The file is the key's only home: it is printed once, when it is drawn, and
//! never again. A restart reads it back rather than drawing another, so the
//! tooling an operator wrote on the first day keeps working on the hundredth.

use std::fs;
use std::io::Read as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

/// Where the key lives when nothing says otherwise.
pub const DEFAULT_BOOTSTRAP_KEY_PATH: &str = "/var/lib/ebpfsentinel/auth/api-key";

/// The name the generated key carries in the key list, and in an audit line.
pub const BOOTSTRAP_KEY_NAME: &str = "bootstrap";

/// How many random bytes the key is drawn from.
const KEY_BYTES: usize = 32;

/// The prefix every generated key carries, so a key pasted into a bug report
/// is recognisable as one of ours and can be revoked rather than puzzled over.
const KEY_PREFIX: &str = "sk-";

/// The most this reads off disk before deciding the file is not ours.
///
/// A key is `sk-` and sixty-four hex characters; a file an order of magnitude
/// past that is something else somebody left there, and reading it whole would
/// be the agent loading an arbitrary file into memory as a credential.
const MAX_FILE_BYTES: u64 = 512;

/// Whether the key handed back was already there or has just been drawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyOrigin {
    /// Read from the file a previous start wrote.
    Loaded,
    /// Drawn now, and printed once by the caller.
    Generated,
}

/// A key and where it came from.
#[derive(Debug, Clone)]
pub struct BootstrapKey {
    /// The key itself, as a caller presents it in `Authorization: Bearer`.
    pub key: String,
    /// Whether this start drew it.
    pub origin: KeyOrigin,
}

/// The one file holding the generated key.
#[derive(Debug, Clone)]
pub struct BootstrapKeyFile {
    path: PathBuf,
}

impl BootstrapKeyFile {
    /// Points the store at one path.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Points the store at [`DEFAULT_BOOTSTRAP_KEY_PATH`].
    #[must_use]
    pub fn at_default_path() -> Self {
        Self::new(DEFAULT_BOOTSTRAP_KEY_PATH)
    }

    /// Where the key is kept, for the one line that says so at startup.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads the key a previous start wrote, or draws and keeps one.
    ///
    /// # Errors
    ///
    /// Returns an error when the file exists but holds something that is not a
    /// key this agent wrote, and when the directory or the file cannot be
    /// created, written or narrowed to its mode. A key the agent cannot keep
    /// is refused rather than used, because a key that disappears on restart
    /// locks an operator out of their own agent on the second boot.
    pub fn load_or_create(&self) -> std::io::Result<BootstrapKey> {
        if let Some(key) = self.load()? {
            return Ok(BootstrapKey {
                key,
                origin: KeyOrigin::Loaded,
            });
        }

        let key = draw_key()?;
        self.save(&key)?;
        Ok(BootstrapKey {
            key,
            origin: KeyOrigin::Generated,
        })
    }

    /// Reads the key, `None` when the file is not there yet.
    fn load(&self) -> std::io::Result<Option<String>> {
        let mut buffer = String::new();
        match fs::File::open(&self.path) {
            Ok(file) => {
                file.take(MAX_FILE_BYTES).read_to_string(&mut buffer)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        }

        let key = buffer.trim().to_owned();
        if !is_well_formed(&key) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "{} does not hold a key this agent wrote: expected '{KEY_PREFIX}' and {} \
                     hexadecimal characters. Delete the file to have one drawn again, or \
                     configure auth.api_keys and leave auth.bootstrap_key_path empty",
                    self.path.display(),
                    KEY_BYTES * 2
                ),
            ));
        }
        Ok(Some(key))
    }

    /// Writes the key, then narrows the directory and the file.
    fn save(&self, key: &str) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
        fs::write(&self.path, key)?;
        fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600))
    }
}

/// Draws [`KEY_BYTES`] from the kernel and renders them as one key.
fn draw_key() -> std::io::Result<String> {
    let mut bytes = [0u8; KEY_BYTES];
    fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;

    let mut key = String::with_capacity(KEY_PREFIX.len() + KEY_BYTES * 2);
    key.push_str(KEY_PREFIX);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(key, "{byte:02x}");
    }
    Ok(key)
}

/// Whether a string is shaped like a key this agent drew.
fn is_well_formed(key: &str) -> bool {
    key.strip_prefix(KEY_PREFIX)
        .is_some_and(|hex| hex.len() == KEY_BYTES * 2 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a_temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ebpfsentinel-bootstrap-key-{name}"));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn a_first_start_draws_a_key_and_says_it_drew_it() {
        let dir = a_temp_dir("first");
        let file = BootstrapKeyFile::new(dir.join("api-key"));

        let drawn = file.load_or_create().expect("drawn");
        assert_eq!(drawn.origin, KeyOrigin::Generated);
        assert!(is_well_formed(&drawn.key));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_restart_answers_with_the_key_the_first_start_drew() {
        let dir = a_temp_dir("restart");
        let file = BootstrapKeyFile::new(dir.join("api-key"));

        let first = file.load_or_create().expect("drawn");
        let second = file.load_or_create().expect("read");

        assert_eq!(first.key, second.key);
        assert_eq!(second.origin, KeyOrigin::Loaded);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn two_agents_do_not_draw_the_same_key() {
        let dir = a_temp_dir("distinct");
        let one = BootstrapKeyFile::new(dir.join("one/api-key"))
            .load_or_create()
            .expect("drawn");
        let other = BootstrapKeyFile::new(dir.join("other/api-key"))
            .load_or_create()
            .expect("drawn");

        assert_ne!(one.key, other.key);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_file_and_its_directory_are_closed_to_everybody_else() {
        let dir = a_temp_dir("modes");
        let path = dir.join("api-key");
        BootstrapKeyFile::new(&path)
            .load_or_create()
            .expect("drawn");

        let file_mode = fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        let dir_mode = fs::metadata(&dir).expect("stat").permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600);
        assert_eq!(dir_mode, 0o700);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_file_holding_something_else_is_refused_rather_than_used() {
        let dir = a_temp_dir("edited");
        let path = dir.join("api-key");
        fs::create_dir_all(&dir).expect("created");
        fs::write(&path, "hunter2").expect("written");

        let refused = BootstrapKeyFile::new(&path).load_or_create();
        assert!(refused.is_err());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_file_far_larger_than_a_key_is_not_read_whole() {
        let dir = a_temp_dir("huge");
        let path = dir.join("api-key");
        fs::create_dir_all(&dir).expect("created");
        fs::write(&path, "a".repeat(64 * 1024)).expect("written");

        assert!(BootstrapKeyFile::new(&path).load_or_create().is_err());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_trailing_newline_an_editor_added_does_not_change_the_key() {
        let dir = a_temp_dir("newline");
        let path = dir.join("api-key");
        let drawn = BootstrapKeyFile::new(&path)
            .load_or_create()
            .expect("drawn");
        fs::write(&path, format!("{}\n", drawn.key)).expect("written");

        let read = BootstrapKeyFile::new(&path).load_or_create().expect("read");
        assert_eq!(read.key, drawn.key);

        let _ = fs::remove_dir_all(&dir);
    }
}
