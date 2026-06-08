#![allow(unsafe_code)] // Required for libc::syscall(SYS_bpf) raw syscall

//! BPF token delegation (kernel 6.9+).
//!
//! BPF tokens let a privileged process create a token fd that scopes
//! which map types, program types, and attach types an unprivileged
//! consumer is allowed to load — without giving the consumer
//! `CAP_BPF` / `CAP_NET_ADMIN`. This module wraps `BPF_TOKEN_CREATE`
//! directly via `libc::syscall(SYS_bpf, …)` because aya 0.13 does not
//! expose the syscall yet (upstream PR #1515 is in-flight at time of
//! writing).
//!
//! Usage pattern:
//!
//! 1. Operator mounts `bpffs` with the `delegate_*` options at
//!    `/sys/fs/bpf/ebpfsentinel` (helper provided below).
//! 2. The enterprise orchestrator calls [`create_token`] with an fd on
//!    that bpffs directory → returns a token fd.
//! 3. The consumer process is launched with the token fd inherited
//!    and the `LIBBPF_BPF_TOKEN_PATH` env var pointing at the bpffs
//!    mount, so the aya loader automatically attaches the token when
//!    loading programs.
//!
//! The module is pure FFI around `bpf(2)`; every path returns a
//! [`BpfTokenError`] on failure so the caller can decide whether to
//! fall back to root capabilities.

use std::ffi::CString;
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::Path;

/// `bpf(2)` command number for `BPF_TOKEN_CREATE`, kernel 6.9+.
///
/// Constant taken from `include/uapi/linux/bpf.h` commit
/// `35f4f85f9f9d` ("bpf: Introduce BPF token object", 6.9-rc1).
const BPF_TOKEN_CREATE: u32 = 36;

/// `BPF_F_TOKEN_FD` flag passed when loading programs / creating maps
/// that expect a token fd in the request. Kernel 6.9+.
pub const BPF_F_TOKEN_FD: u32 = 1 << 16;

/// Process-global BPF token fd, set once after `BPF_TOKEN_CREATE`. The raw
/// token loader reads it to authorize every map/BTF/program load it issues,
/// the way libbpf's `LIBBPF_BPF_TOKEN_PATH` applies one token process-wide.
/// `-1` means no token (capability-based loading via aya).
static GLOBAL_TOKEN_FD: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);

/// Register the process-global BPF token fd. The caller must keep the fd open
/// for as long as eBPF objects are loaded.
pub fn set_global_token_fd(fd: std::os::fd::RawFd) {
    GLOBAL_TOKEN_FD.store(fd, std::sync::atomic::Ordering::Relaxed);
}

/// The process-global BPF token fd, or `None` when loading via capabilities.
#[must_use]
pub fn global_token_fd() -> Option<std::os::fd::RawFd> {
    let fd = GLOBAL_TOKEN_FD.load(std::sync::atomic::Ordering::Relaxed);
    (fd >= 0).then_some(fd)
}

/// Errors surfaced by the thin syscall wrapper.
#[derive(Debug, thiserror::Error)]
pub enum BpfTokenError {
    #[error("bpffs path `{path}` does not exist")]
    BpffsMissing { path: String },

    #[error("failed to open bpffs path `{path}`: {source}")]
    OpenBpffs {
        path: String,
        #[source]
        source: io::Error,
    },

    #[error("BPF_TOKEN_CREATE failed ({errno}): {message}")]
    SyscallFailed { errno: i32, message: String },

    #[error("BPF_TOKEN_CREATE returned invalid fd {0}")]
    InvalidFd(i64),
}

/// Arguments for `BPF_TOKEN_CREATE`. The kernel's `token_create` attr
/// is only `{ flags, bpffs_fd }` — the set of delegated commands, maps,
/// programs, and attach types is **not** part of the syscall; it is
/// configured through the bpffs *mount* options (`delegate_cmds`,
/// `delegate_maps`, `delegate_progs`, `delegate_attachs`) when the
/// delegated bpffs is mounted (see `ebpfsentinel-token-setup.sh`).
#[derive(Debug, Clone, Copy)]
pub struct TokenCreateAttr {
    pub flags: u32,
    pub bpffs_fd: RawFd,
}

impl TokenCreateAttr {
    /// Create a token against the supplied delegated-bpffs directory fd.
    /// Delegation scope comes from the mount options, so there is nothing
    /// else to specify here.
    #[must_use]
    pub const fn enterprise_default(bpffs_fd: RawFd) -> Self {
        Self { flags: 0, bpffs_fd }
    }
}

/// Kernel-matching layout for the `token_create` branch of
/// `union bpf_attr` (kernel 6.9+):
///
/// ```c
/// struct { /* BPF_TOKEN_CREATE */
///     __u32 flags;
///     __u32 bpffs_fd;
/// } token_create;
/// ```
///
/// Only these two fields exist — passing any non-zero trailing bytes
/// makes the kernel reject the syscall with `EINVAL`. Keeping it
/// private + `#[repr(C)]` so we control the layout passed to `bpf(2)`.
#[repr(C)]
#[derive(Clone, Copy)]
struct BpfAttrTokenCreate {
    flags: u32,
    bpffs_fd: u32,
}

/// Call `bpf(BPF_TOKEN_CREATE, …)` with the supplied attributes and
/// return the owned token fd on success.
///
/// # Errors
///
/// Returns [`BpfTokenError::SyscallFailed`] on any kernel-side error
/// (including `ENOSYS` when the host kernel is not 6.9+), or
/// [`BpfTokenError::InvalidFd`] if the syscall returns a negative or
/// out-of-range value despite a zero errno.
pub fn create_token(attr: &TokenCreateAttr) -> Result<OwnedFd, BpfTokenError> {
    #[allow(clippy::cast_sign_loss)]
    let bpffs_fd_u32 = attr.bpffs_fd as u32;
    let kernel_attr = BpfAttrTokenCreate {
        flags: attr.flags,
        bpffs_fd: bpffs_fd_u32,
    };
    let attr_ptr: *const BpfAttrTokenCreate = &raw const kernel_attr;
    #[allow(clippy::cast_possible_truncation)]
    let size = mem::size_of::<BpfAttrTokenCreate>() as u32;

    // SAFETY: we pass a valid `bpf_attr` region of the correct size
    // (`size_of::<BpfAttrTokenCreate>()`), the kernel interprets the
    // attr as the `token_create` union member when command is
    // `BPF_TOKEN_CREATE`, and we stop using the pointer before it
    // escapes the stack frame. Errors are reported via `errno`.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            libc::c_int::try_from(BPF_TOKEN_CREATE).unwrap_or(36),
            attr_ptr as usize,
            size as usize,
        )
    };
    if rc < 0 {
        let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(BpfTokenError::SyscallFailed {
            errno,
            message: io::Error::last_os_error().to_string(),
        });
    }
    if rc > i64::from(i32::MAX) {
        return Err(BpfTokenError::InvalidFd(rc));
    }
    #[allow(clippy::cast_possible_truncation)]
    let raw = rc as RawFd;
    // SAFETY: `rc >= 0` and fits in `i32`, so it is a valid fd owned
    // by this process.
    let owned = unsafe { <OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(raw) };
    Ok(owned)
}

/// Open a directory on a bpffs mount and return its fd for use as the
/// `bpffs_fd` argument of `BPF_TOKEN_CREATE`.
///
/// # Errors
///
/// Returns [`BpfTokenError::BpffsMissing`] when the path doesn't exist
/// and [`BpfTokenError::OpenBpffs`] when `open(2)` fails (usually
/// because the path is not actually a bpffs mount or the caller
/// lacks permission).
pub fn open_bpffs_dir(path: &Path) -> Result<OwnedFd, BpfTokenError> {
    if !path.exists() {
        return Err(BpfTokenError::BpffsMissing {
            path: path.display().to_string(),
        });
    }
    let c_path = CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| {
        BpfTokenError::OpenBpffs {
            path: path.display().to_string(),
            source: io::Error::other("path contains interior NUL byte"),
        }
    })?;
    // SAFETY: c_path lives until after the syscall returns. The bpffs
    // dir fd must be a regular open fd — BPF_TOKEN_CREATE inspects the
    // file's superblock magic and rejects an O_PATH fd with EBADF, so we
    // open it O_RDONLY | O_DIRECTORY.
    let raw = unsafe {
        libc::open(
            c_path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(BpfTokenError::OpenBpffs {
            path: path.display().to_string(),
            source: io::Error::last_os_error(),
        });
    }
    // SAFETY: `raw >= 0` and was returned by `open(2)`.
    Ok(unsafe { <OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(raw) })
}

/// Convenience helper: given a path to a bpffs directory, open it and
/// create a token with [`TokenCreateAttr::enterprise_default`].
///
/// Returns both fds so the caller can keep them alive for the lifetime
/// of the child process that will consume the token.
///
/// # Errors
///
/// Surfaces [`BpfTokenError::BpffsMissing`] / [`BpfTokenError::OpenBpffs`]
/// from the `open_bpffs_dir` step and [`BpfTokenError::SyscallFailed`]
/// from the `BPF_TOKEN_CREATE` call.
pub fn create_enterprise_token(bpffs_path: &Path) -> Result<(OwnedFd, OwnedFd), BpfTokenError> {
    let dir_fd = open_bpffs_dir(bpffs_path)?;
    let attr = TokenCreateAttr::enterprise_default(dir_fd.as_raw_fd());
    let token_fd = create_token(&attr)?;
    Ok((dir_fd, token_fd))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attr_layout_matches_kernel() {
        // The kernel's token_create attr is exactly { __u32 flags;
        // __u32 bpffs_fd; } = 8 bytes. Any non-zero trailing bytes make
        // BPF_TOKEN_CREATE fail with EINVAL.
        assert_eq!(mem::size_of::<BpfAttrTokenCreate>(), 8);
        assert_eq!(mem::align_of::<BpfAttrTokenCreate>(), 4);
    }

    #[test]
    fn enterprise_default_carries_only_fd_and_flags() {
        let attr = TokenCreateAttr::enterprise_default(7);
        assert_eq!(attr.flags, 0);
        assert_eq!(attr.bpffs_fd, 7);
    }

    #[test]
    fn open_bpffs_dir_rejects_missing_path() {
        let result = open_bpffs_dir(Path::new("/nonexistent/bpffs/path"));
        assert!(matches!(result, Err(BpfTokenError::BpffsMissing { .. })));
    }

    #[test]
    fn create_token_propagates_errno_on_bad_fd() {
        // Passing fd=-1 triggers EBADF on any kernel — we just need to
        // observe that the wrapper reports a `SyscallFailed` variant
        // rather than silently returning Ok.
        let attr = TokenCreateAttr::enterprise_default(-1);
        match create_token(&attr) {
            Err(BpfTokenError::SyscallFailed { .. } | BpfTokenError::InvalidFd(_)) => {}
            Err(e) => panic!("expected SyscallFailed, got {e:?}"),
            Ok(_) => panic!("expected failure with fd=-1"),
        }
    }
}
