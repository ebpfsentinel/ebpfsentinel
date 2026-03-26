#![allow(unsafe_code)] // Required for libc::umask FFI call

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
