//! Keeping the installation identifier across restarts.
//!
//! The machine's own identifier is read first, so that a machine whose state
//! directory was lost answers to the name it already had; the file is what a
//! machine without one falls back on, and what keeps a derived name when the
//! identifier later stops being readable. One small file holding thirty-two hex
//! characters. It is written `0600`
//! inside a `0700` directory - not because the identifier is a secret, but
//! because a world-readable file in `/var/lib` is a file somebody copies onto
//! a golden image, and then a thousand machines report as one installation.

use std::fs;
use std::io::Read as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use domain::telemetry::entity::InstallationId;
use domain::telemetry::error::TelemetryError;
use ports::secondary::telemetry_port::InstallationStore;

/// Where the identifier lives when nothing says otherwise.
pub const DEFAULT_INSTALLATION_PATH: &str = "/var/lib/ebpfsentinel/telemetry/installation";

/// Where systemd, and every distribution following it, keeps the machine's own
/// identifier.
pub const DEFAULT_MACHINE_ID_PATH: &str = "/etc/machine-id";

/// The most this reads off disk before deciding the file is not ours.
///
/// The identifier is thirty-two characters; anything an order of magnitude
/// past that is a file somebody put there, and reading it whole would be this
/// process loading an arbitrary file into memory on behalf of telemetry.
const MAX_FILE_BYTES: u64 = 512;

/// Keeps the identifier in one file.
#[derive(Debug, Clone)]
pub struct FileInstallationStore {
    path: PathBuf,
    machine_id: Option<PathBuf>,
}

impl FileInstallationStore {
    /// Points the store at one path, reading the machine identifier at
    /// [`DEFAULT_MACHINE_ID_PATH`].
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            machine_id: Some(PathBuf::from(DEFAULT_MACHINE_ID_PATH)),
        }
    }

    /// Reads the machine identifier somewhere else, or nowhere when `None`.
    #[must_use]
    pub fn with_machine_id(mut self, path: Option<PathBuf>) -> Self {
        self.machine_id = path;
        self
    }

    /// Points the store at [`DEFAULT_INSTALLATION_PATH`].
    #[must_use]
    pub fn at_default_path() -> Self {
        Self::new(DEFAULT_INSTALLATION_PATH)
    }
}

/// Reads at most [`MAX_FILE_BYTES`] of one file.
fn read_bounded(path: &Path) -> std::io::Result<String> {
    let mut buffer = String::new();
    fs::File::open(path)?
        .take(MAX_FILE_BYTES)
        .read_to_string(&mut buffer)?;
    Ok(buffer)
}

impl InstallationStore for FileInstallationStore {
    fn load(&self) -> Result<Option<InstallationId>, TelemetryError> {
        match read_bounded(&self.path) {
            Ok(buffer) => InstallationId::parse(&buffer).map(Some),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(TelemetryError::Persistence(format!(
                "{}: {e}",
                self.path.display()
            ))),
        }
    }

    fn machine_identity(&self) -> Option<String> {
        read_bounded(self.machine_id.as_deref()?).ok()
    }

    fn save(&self, id: &InstallationId) -> Result<(), TelemetryError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| TelemetryError::Persistence(format!("{}: {e}", parent.display())))?;
            restrict(parent, 0o700)?;
        }

        fs::write(&self.path, id.as_str())
            .map_err(|e| TelemetryError::Persistence(format!("{}: {e}", self.path.display())))?;
        restrict(&self.path, 0o600)
    }

    fn random_bytes(&self) -> Result<[u8; 16], TelemetryError> {
        let mut bytes = [0u8; 16];
        let mut urandom = fs::File::open("/dev/urandom").map_err(|e| {
            TelemetryError::Persistence(format!("/dev/urandom could not be opened: {e}"))
        })?;

        std::io::Read::read_exact(&mut urandom, &mut bytes).map_err(|e| {
            TelemetryError::Persistence(format!("/dev/urandom could not be read: {e}"))
        })?;

        Ok(bytes)
    }
}

/// Narrows a path's mode, saying which path failed when it cannot.
fn restrict(path: &Path, mode: u32) -> Result<(), TelemetryError> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|e| TelemetryError::Persistence(format!("{}: {e}", path.display())))
}

#[cfg(test)]
mod tests {
    use domain::telemetry::entity::INSTALLATION_ID_CHARS;

    use super::*;

    fn a_temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ebpfsentinel-telemetry-{name}"));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn a_first_boot_finds_nothing_rather_than_failing() {
        let store = FileInstallationStore::new(a_temp_dir("first").join("installation"));
        assert!(store.load().expect("read").is_none());
    }

    #[test]
    fn what_is_written_is_what_comes_back() {
        let dir = a_temp_dir("roundtrip");
        let store = FileInstallationStore::new(dir.join("installation"));
        let id = InstallationId::from_bytes(store.random_bytes().expect("drawn"));

        store.save(&id).expect("written");
        assert_eq!(store.load().expect("read"), Some(id));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_file_and_its_directory_are_closed_to_everybody_else() {
        let dir = a_temp_dir("modes");
        let path = dir.join("installation");
        let store = FileInstallationStore::new(&path);
        store
            .save(&InstallationId::from_bytes([0x01; 16]))
            .expect("written");

        let file_mode = fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        let dir_mode = fs::metadata(&dir).expect("stat").permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600);
        assert_eq!(dir_mode, 0o700);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_file_somebody_edited_is_refused_rather_than_sent() {
        let dir = a_temp_dir("edited");
        let path = dir.join("installation");
        fs::create_dir_all(&dir).expect("created");
        fs::write(&path, "prod-gateway-01").expect("written");

        assert!(FileInstallationStore::new(&path).load().is_err());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_file_far_larger_than_an_identifier_is_not_read_whole() {
        let dir = a_temp_dir("huge");
        let path = dir.join("installation");
        fs::create_dir_all(&dir).expect("created");
        fs::write(&path, "a".repeat(64 * 1024)).expect("written");

        assert!(FileInstallationStore::new(&path).load().is_err());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_machine_identifier_is_read_where_it_was_pointed() {
        let dir = a_temp_dir("machine");
        fs::create_dir_all(&dir).expect("created");
        let machine_id = dir.join("machine-id");
        fs::write(&machine_id, "4c4c4544003958108052b4c04f4e3732\n").expect("written");

        let store =
            FileInstallationStore::new(dir.join("installation")).with_machine_id(Some(machine_id));
        assert_eq!(
            store.machine_identity().as_deref(),
            Some("4c4c4544003958108052b4c04f4e3732\n")
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_machine_identifier_that_is_absent_or_switched_off_is_none() {
        let dir = a_temp_dir("no-machine");
        let absent = FileInstallationStore::new(dir.join("installation"))
            .with_machine_id(Some(dir.join("machine-id")));
        let off = FileInstallationStore::new(dir.join("installation")).with_machine_id(None);

        assert!(absent.machine_identity().is_none());
        assert!(off.machine_identity().is_none());
    }

    #[test]
    fn two_draws_do_not_come_back_the_same() {
        let store = FileInstallationStore::at_default_path();
        let first = store.random_bytes().expect("drawn");
        let second = store.random_bytes().expect("drawn");
        assert_ne!(first, second);
        assert_eq!(
            InstallationId::from_bytes(first).as_str().len(),
            INSTALLATION_ID_CHARS
        );
    }
}
