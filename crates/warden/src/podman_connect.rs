//! Connecting to a user's rootless Podman API.
//!
//! A user's Podman serves its API on `/run/user/<uid>/podman/podman.sock`,
//! mode `0600` inside a `0700` directory. The agent runs as root inside a user
//! namespace of its own, where an inode owned by any other uid is out of reach
//! whatever its capabilities, so it cannot name a single rootless container.
//! The warden runs in the initial user namespace and connects for it, then
//! hands the connected stream over.
//!
//! The path is built here from the uid alone, so the agent names a user and
//! never a file. Two checks keep the connection to that one user's runtime: the
//! socket must be owned by `uid`, and once connected the process listening on
//! it must run as `uid`, read off the connection itself, so a path swapped
//! between the two checks still cannot hand over somebody else's runtime.
//! Root's runtime is never served here: it is reachable without the warden,
//! and a connection to it is a connection to everything.

use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

/// Where users' runtime directories sit on a host.
pub const RUN_USER_ROOT: &str = "/run/user";

/// The socket user `uid`'s Podman serves its API on, under `run_user_root`.
#[must_use]
pub fn socket_path(run_user_root: &Path, uid: u32) -> PathBuf {
    run_user_root
        .join(uid.to_string())
        .join("podman")
        .join("podman.sock")
}

/// A stream connected to user `uid`'s Podman API under `run_user_root`.
///
/// # Errors
///
/// A message naming the user when `uid` is root, the socket is absent or not
/// a socket, it is owned by another uid, the connect fails, or the listener
/// does not run as `uid`.
pub fn connect(run_user_root: &Path, uid: u32) -> Result<UnixStream, String> {
    if uid == 0 {
        return Err("root's Podman runtime is not connected through the warden".to_owned());
    }
    let path = socket_path(run_user_root, uid);
    let meta = std::fs::metadata(&path)
        .map_err(|e| format!("Podman socket of uid {uid} ({}): {e}", path.display()))?;
    if !meta.file_type().is_socket() {
        return Err(format!("{} is not a socket", path.display()));
    }
    if meta.uid() != uid {
        return Err(format!(
            "{} is owned by uid {}, not {uid}",
            path.display(),
            meta.uid()
        ));
    }
    let stream = UnixStream::connect(&path)
        .map_err(|e| format!("Podman socket of uid {uid} ({}): {e}", path.display()))?;
    match crate::server::peer_uid(&stream) {
        Some(peer) if peer == uid => Ok(stream),
        Some(peer) => Err(format!(
            "{} is served by uid {peer}, not {uid}",
            path.display()
        )),
        None => Err(format!(
            "{}: the listener's credentials could not be read",
            path.display()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    fn current_uid() -> u32 {
        // SAFETY: `getuid` takes nothing and cannot fail.
        unsafe { libc::getuid() }
    }

    #[test]
    fn a_users_socket_owned_and_served_by_that_user_is_connected() {
        let uid = current_uid();
        if uid == 0 {
            return; // root's runtime is refused by design; asserted below
        }
        let dir = tempfile::tempdir().unwrap();
        let path = socket_path(dir.path(), uid);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let _listener = UnixListener::bind(&path).unwrap();
        assert!(connect(dir.path(), uid).is_ok());
    }

    #[test]
    fn a_socket_owned_by_another_user_is_refused() {
        let uid = current_uid();
        let other = uid + 1;
        let dir = tempfile::tempdir().unwrap();
        let path = socket_path(dir.path(), other);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let _listener = UnixListener::bind(&path).unwrap();
        let err = connect(dir.path(), other).unwrap_err();
        assert!(err.contains(&format!("owned by uid {uid}")), "{err}");
    }

    #[test]
    fn a_user_without_a_socket_is_refused_with_the_path() {
        let dir = tempfile::tempdir().unwrap();
        let err = connect(dir.path(), 4242).unwrap_err();
        assert!(err.contains("4242/podman/podman.sock"), "{err}");
    }

    #[test]
    fn a_file_where_the_socket_should_be_is_refused() {
        let uid = current_uid().max(1);
        let dir = tempfile::tempdir().unwrap();
        let path = socket_path(dir.path(), uid);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"").unwrap();
        let err = connect(dir.path(), uid).unwrap_err();
        assert!(
            err.contains("not a socket") || err.contains("owned by"),
            "{err}"
        );
    }

    #[test]
    fn roots_runtime_is_never_connected() {
        let err = connect(Path::new("/run/user"), 0).unwrap_err();
        assert!(err.contains("root"), "{err}");
    }
}
