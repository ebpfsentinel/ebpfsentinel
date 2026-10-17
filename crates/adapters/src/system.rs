#![allow(unsafe_code)] // Required for libc::umask and libc::flock FFI calls

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

/// Set a restrictive umask (0077) so files created by the agent
/// are readable only by the owner (mode 0600 for files, 0700 for dirs).
#[cfg(unix)]
pub fn set_restrictive_umask() {
    // Safety: umask is a trivial POSIX syscall with no invariants.
    unsafe {
        libc::umask(0o077);
    }
}

#[cfg(not(unix))]
pub fn set_restrictive_umask() {
    // No-op on non-Unix platforms.
}

/// Why a second agent was refused the state directory.
#[derive(Debug)]
pub enum InstanceLockError {
    /// Another agent holds it, and its pid where the lock file still names one.
    Held {
        /// The pid the holder wrote when it took the lock.
        pid: Option<u32>,
        /// The lock file both processes went for.
        path: PathBuf,
    },
    /// The lock file could not be opened or locked for some other reason.
    Io(std::io::Error),
}

impl std::fmt::Display for InstanceLockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Held {
                pid: Some(pid),
                path,
            } => write!(
                f,
                "another agent already holds {} (pid {pid})",
                path.display()
            ),
            Self::Held { pid: None, path } => {
                write!(f, "another agent already holds {}", path.display())
            }
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for InstanceLockError {}

/// An exclusive claim on one agent's state directory, held until the process
/// ends.
///
/// Two agents on one node are not two deployments: they share the state
/// directory and the pin path, and startup wipes the pins it finds there
/// because the kernel offers no way to ask whether one is still held. The
/// second process would therefore unpin the maps the first one is still
/// serving from, and neither would report anything wrong. The lock is what
/// turns that into a refusal to start.
///
/// It is an `flock` and not a pid file: the kernel releases it when the holder
/// dies, however it dies, so a crashed agent leaves nothing to clean up and no
/// staleness to guess at. The pid inside the file is for the message only and
/// is never trusted.
#[derive(Debug)]
pub struct InstanceLock {
    /// Dropping the handle closes the fd, which is what releases the lock.
    _file: File,
    path: PathBuf,
}

impl InstanceLock {
    /// Where the claim is recorded, for the log line that says it was taken.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Claim `path` for this process, or say who holds it.
///
/// What this does not cover is stated rather than implied: two agents pointed
/// at two different state directories are two locks and neither sees the
/// other. There is no shared file to lock on the other resource they would
/// collide over, because each agent mounts its own bpffs inside its own mount
/// namespace, so the guard is keyed on the state directory and a deployment
/// that duplicates both is a deployment that gets what it asked for.
pub fn acquire_instance_lock(path: &Path) -> Result<InstanceLock, InstanceLockError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(InstanceLockError::Io)?;
    }

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(InstanceLockError::Io)?;

    // Safety: flock takes a raw fd this scope owns and a flag constant; the
    // only effect is on the open file description behind that fd.
    let locked = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if locked != 0 {
        let e = std::io::Error::last_os_error();
        let would_block = matches!(
            e.raw_os_error(),
            Some(code) if code == libc::EWOULDBLOCK || code == libc::EAGAIN
        );
        if !would_block {
            return Err(InstanceLockError::Io(e));
        }
        // The holder wrote its pid when it took the lock. It is read without
        // the lock and is advisory: by the time it is printed the process may
        // be gone, which is why the refusal does not depend on it.
        let mut held = String::new();
        let pid = File::open(path)
            .and_then(|mut f| f.read_to_string(&mut held))
            .ok()
            .and_then(|_| held.trim().parse::<u32>().ok());
        return Err(InstanceLockError::Held {
            pid,
            path: path.to_path_buf(),
        });
    }

    // Record who holds it, for the other process's refusal message. The
    // truncate happens after the lock is held, so a failed claim never empties
    // the holder's own pid.
    file.set_len(0).map_err(InstanceLockError::Io)?;
    file.rewind().map_err(InstanceLockError::Io)?;
    writeln!(file, "{}", std::process::id()).map_err(InstanceLockError::Io)?;
    file.flush().map_err(InstanceLockError::Io)?;

    Ok(InstanceLock {
        _file: file,
        path: path.to_path_buf(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_agent_takes_it_and_says_where() {
        let dir = tempfile::tempdir().expect("a directory");
        let path = dir.path().join("agent.lock");
        let lock = acquire_instance_lock(&path).expect("the first claim");
        assert_eq!(lock.path(), path);
        let written = std::fs::read_to_string(&path).expect("the pid file");
        assert_eq!(
            written.trim().parse::<u32>().ok(),
            Some(std::process::id()),
            "the holder records itself so the next one can name it"
        );
    }

    #[test]
    fn a_second_claim_in_this_process_is_refused_with_the_pid() {
        // flock is per open file description, not per process, so a second
        // open of the same path contends with the first even here - which is
        // exactly the case a second agent on one node presents.
        let dir = tempfile::tempdir().expect("a directory");
        let path = dir.path().join("agent.lock");
        let _held = acquire_instance_lock(&path).expect("the first claim");

        match acquire_instance_lock(&path) {
            Err(InstanceLockError::Held { pid, path: refused }) => {
                assert_eq!(pid, Some(std::process::id()));
                assert_eq!(refused, path);
            }
            Err(e) => panic!("refused for the wrong reason: {e}"),
            Ok(_) => panic!("two agents cannot both hold one state directory"),
        }
    }

    #[test]
    fn the_lock_comes_back_when_the_holder_goes() {
        let dir = tempfile::tempdir().expect("a directory");
        let path = dir.path().join("agent.lock");
        let first = acquire_instance_lock(&path).expect("the first claim");
        drop(first);
        assert!(
            acquire_instance_lock(&path).is_ok(),
            "a restart must not need the lock file cleaned up by hand"
        );
    }

    #[test]
    fn a_missing_directory_is_created_rather_than_refused() {
        let dir = tempfile::tempdir().expect("a directory");
        let path = dir.path().join("data").join("agent.lock");
        assert!(acquire_instance_lock(&path).is_ok());
        assert!(path.exists());
    }

    #[test]
    fn a_refusal_without_a_pid_still_names_the_path() {
        let path = PathBuf::from("/var/lib/ebpfsentinel/data/agent.lock");
        let message = InstanceLockError::Held {
            pid: None,
            path: path.clone(),
        }
        .to_string();
        assert!(message.contains("agent.lock"), "{message}");
        assert!(!message.contains("pid"), "{message}");
    }
}
