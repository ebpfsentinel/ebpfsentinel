//! The keyring the kernel checks the agent's signed loaders against.
//!
//! The release build signs every loader program with a key made for that
//! build and destroyed after it; the X.509 certificate of that key ships in
//! the warden's image. Before it confines itself, the warden makes a keyring
//! of its own, inside its process keyring, which no other process possesses,
//! adds that certificate to it, and opens it to every user for view, read and
//! search only: nobody but the warden can add a key to it, unlink one from it
//! or link it elsewhere. The agent names the keyring's serial in every signed
//! `BPF_PROG_LOAD`, so the kernel checks the loader against the certificate
//! the warden brought, never against one the agent chose.
//!
//! `add_key` and `keyctl` stay killed by the seccomp filter: the keyring is
//! made once, before the filter is installed, and nothing later may touch it.

use std::ffi::CString;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Where the images and `install.sh` put the DER certificate the loaders
/// are signed for.
pub const DEFAULT_CERT_PATH: &str = "/usr/local/share/ebpfsentinel/loader-signing.der";

/// Where the distribution packages put it.
pub const PACKAGE_CERT_PATH: &str = "/usr/share/ebpfsentinel/loader-signing.der";

/// Override of [`DEFAULT_CERT_PATH`], for a host install that keeps it
/// elsewhere.
pub const CERT_PATH_ENV: &str = "EBPFSENTINEL_LOADER_CERT";

/// The variable the agent's bootstrap trampoline passes the serial in across
/// its re-exec, the way it passes the module BTF descriptors.
pub const LOADER_KEYRING_ENV: &str = "EBPFSENTINEL_LOADER_KEYRING";

/// The description the keyring carries in `/proc/keys`.
const KEYRING_DESCRIPTION: &str = "ebpfsentinel:loaders";
/// The description the certificate key carries in `/proc/keys`.
const CERT_DESCRIPTION: &str = "ebpfsentinel:loader-signing";

/// `KEY_SPEC_PROCESS_KEYRING`: the calling process's own keyring, created on
/// first use and possessed by no other process.
const KEY_SPEC_PROCESS_KEYRING: i32 = -2;
/// `KEYCTL_SETPERM`.
const KEYCTL_SETPERM: libc::c_long = 5;

/// `KEY_POS_ALL`: the possessor (the warden) keeps every right.
const KEY_POS_ALL: u32 = 0x3f00_0000;
/// `KEY_USR_VIEW | KEY_USR_READ | KEY_USR_SEARCH`.
const KEY_USR_VIEW_READ_SEARCH: u32 = 0x000b_0000;
/// `KEY_OTH_VIEW | KEY_OTH_READ | KEY_OTH_SEARCH`.
const KEY_OTH_VIEW_READ_SEARCH: u32 = 0x0000_000b;

/// The permission mask the keyring and the certificate get: everything for
/// the warden that possesses them, view, read and search for every other
/// user, and nothing for a group. No write, no link, no attribute change for
/// anyone but the possessor.
pub const KEYRING_PERM: u32 = KEY_POS_ALL | KEY_USR_VIEW_READ_SEARCH | KEY_OTH_VIEW_READ_SEARCH;

/// The keyring this warden made, once made.
static INSTALLED: OnceLock<Option<i32>> = OnceLock::new();

/// The serial handed to every agent in `Delegated`, `None` when no keyring
/// was made.
#[must_use]
pub fn installed() -> Option<i32> {
    INSTALLED.get().copied().flatten()
}

/// The certificate path: [`CERT_PATH_ENV`] when set and not empty, else
/// [`PACKAGE_CERT_PATH`] when only that one exists, else
/// [`DEFAULT_CERT_PATH`].
#[must_use]
pub fn cert_path() -> PathBuf {
    if let Some(path) = std::env::var_os(CERT_PATH_ENV).filter(|v| !v.is_empty()) {
        return PathBuf::from(path);
    }
    let package = Path::new(PACKAGE_CERT_PATH);
    if !Path::new(DEFAULT_CERT_PATH).exists() && package.exists() {
        return package.to_path_buf();
    }
    PathBuf::from(DEFAULT_CERT_PATH)
}

/// Make the keyring from the certificate at `path` and remember its serial
/// for every `Delegated`. A missing certificate is a build that ships none
/// (a development image), answered with `Ok(None)`; a kernel without the
/// asymmetric key type refuses the certificate and fails here. Called once,
/// before [`crate::confine::confine`].
///
/// # Errors
///
/// The certificate could not be read, or the kernel refused the keyring, the
/// key or the permission change.
pub fn install(path: &Path) -> Result<Option<i32>, String> {
    let cert = match std::fs::read(path) {
        Ok(cert) => cert,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let _ = INSTALLED.set(None);
            return Ok(None);
        }
        Err(e) => return Err(format!("read {}: {e}", path.display())),
    };
    let serial = create(&cert)?;
    let _ = INSTALLED.set(Some(serial));
    Ok(Some(serial))
}

/// [`install`] from [`cert_path`], logging the outcome under `tag` (the
/// binary's log prefix). Both wardens call it from their `serve`, after the
/// last privileged setup and before [`crate::confine::confine`]. A failure is
/// logged and the agent loads unsigned: the kernel then has no keyring to
/// check against, which the agent's signing posture reports.
pub fn install_from_image(tag: &str) {
    let path = cert_path();
    match install(&path) {
        Ok(Some(serial)) => eprintln!(
            "{tag} loader keyring {serial} holds the certificate at {}",
            path.display()
        ),
        Ok(None) => eprintln!(
            "{tag} no loader certificate at {}; agents load unsigned",
            path.display()
        ),
        Err(e) => eprintln!("{tag} loader keyring not made: {e}; agents load unsigned"),
    }
}

/// Create the keyring, add `cert_der` to it as an `asymmetric` key, and set
/// [`KEYRING_PERM`] on both.
fn create(cert_der: &[u8]) -> Result<i32, String> {
    let keyring = add_key(
        "keyring",
        KEYRING_DESCRIPTION,
        &[],
        KEY_SPEC_PROCESS_KEYRING,
    )
    .map_err(|e| format!("add_key keyring: {e}"))?;
    let key = add_key("asymmetric", CERT_DESCRIPTION, cert_der, keyring)
        .map_err(|e| format!("add_key asymmetric certificate: {e}"))?;
    set_perm(key, KEYRING_PERM).map_err(|e| format!("keyctl setperm certificate: {e}"))?;
    set_perm(keyring, KEYRING_PERM).map_err(|e| format!("keyctl setperm keyring: {e}"))?;
    Ok(keyring)
}

fn add_key(kind: &str, description: &str, payload: &[u8], into: i32) -> io::Result<i32> {
    let kind = CString::new(kind).map_err(io::Error::other)?;
    let description = CString::new(description).map_err(io::Error::other)?;
    let data = if payload.is_empty() {
        std::ptr::null()
    } else {
        payload.as_ptr()
    };
    // SAFETY: both strings are NUL-terminated and live through the call; the
    // payload pointer is null with a zero length or names `payload.len()`
    // readable bytes; the kernel copies all three before returning.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_add_key,
            kind.as_ptr(),
            description.as_ptr(),
            data,
            payload.len(),
            libc::c_long::from(into),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    i32::try_from(rc).map_err(io::Error::other)
}

fn set_perm(serial: i32, perm: u32) -> io::Result<()> {
    // SAFETY: `keyctl(KEYCTL_SETPERM, serial, perm)` takes integers only.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_keyctl,
            KEYCTL_SETPERM,
            libc::c_long::from(serial),
            libc::c_long::from(perm),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `KEY_*_WRITE` and `KEY_*_LINK` and `KEY_*_SETATTR` for one class,
    /// shifted to that class's byte.
    fn forbidden(shift: u32) -> u32 {
        (0x04 | 0x10 | 0x20) << shift
    }

    #[test]
    fn others_and_the_owner_may_view_read_and_search_only() {
        for shift in [16, 0] {
            let class = (KEYRING_PERM >> shift) & 0xff;
            assert_eq!(class, 0x0b, "view, read and search at shift {shift}");
            assert_eq!(
                KEYRING_PERM & forbidden(shift),
                0,
                "no write, link or setattr"
            );
        }
    }

    #[test]
    fn a_group_gets_nothing() {
        assert_eq!((KEYRING_PERM >> 8) & 0xff, 0);
    }

    #[test]
    fn the_possessor_keeps_every_right() {
        assert_eq!(KEYRING_PERM >> 24, 0x3f);
    }

    #[test]
    fn the_mask_is_the_one_the_kernel_record_proved() {
        assert_eq!(KEYRING_PERM, 0x3f0b_000b);
    }

    #[test]
    fn a_build_without_a_certificate_makes_no_keyring() {
        let dir = tempfile::tempdir().expect("tempdir");
        let got = install(&dir.path().join("absent.der")).expect("absent is not an error");
        assert_eq!(got, None);
    }

    #[test]
    fn the_env_names_another_certificate() {
        // Only read here: no other test in this binary sets the variable.
        if std::env::var_os(CERT_PATH_ENV).is_none() {
            assert_eq!(cert_path(), PathBuf::from(DEFAULT_CERT_PATH));
        }
    }
}
