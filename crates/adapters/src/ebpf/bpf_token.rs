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

/// Bitmask of allowed BPF command numbers the consumer may invoke with
/// the returned token. Defaults to the command set the enterprise
/// loader actually needs.
#[derive(Debug, Clone, Copy)]
pub struct TokenCreateAttr {
    pub flags: u32,
    pub bpffs_fd: RawFd,
    pub allowed_cmds: u64,
    pub allowed_maps: u64,
    pub allowed_progs: u64,
    pub allowed_attachs: u64,
}

impl TokenCreateAttr {
    /// Enterprise default: allow map/prog load commands only, no
    /// `BPF_OBJ_PIN`, no `BPF_LINK_*` create from the consumer side.
    #[must_use]
    pub const fn enterprise_default(bpffs_fd: RawFd) -> Self {
        // Allow MAP_CREATE, PROG_LOAD, BTF_LOAD, OBJ_GET_INFO_BY_FD.
        // Numbers come from `enum bpf_cmd` in linux/bpf.h.
        let allowed_cmds: u64 = (1 << 0) // MAP_CREATE
            | (1 << 5)   // PROG_LOAD
            | (1 << 18)  // BTF_LOAD
            | (1 << 15); // OBJ_GET_INFO_BY_FD
        Self {
            flags: 0,
            bpffs_fd,
            allowed_cmds,
            // All map + prog + attach types left wide open so the
            // enterprise crate can load the same 14 programs the
            // root-capable binary loads.
            allowed_maps: u64::MAX,
            allowed_progs: u64::MAX,
            allowed_attachs: u64::MAX,
        }
    }
}

/// Kernel-matching layout for the `token_create` branch of
/// `union bpf_attr`. Keeping it private + `#[repr(C)]` so we control
/// the memory layout passed to the syscall.
#[repr(C)]
#[derive(Clone, Copy)]
struct BpfAttrTokenCreate {
    flags: u32,
    bpffs_fd: u32,
    allowed_cmds: u64,
    allowed_maps: u64,
    allowed_progs: u64,
    allowed_attachs: u64,
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
        allowed_cmds: attr.allowed_cmds,
        allowed_maps: attr.allowed_maps,
        allowed_progs: attr.allowed_progs,
        allowed_attachs: attr.allowed_attachs,
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
    // SAFETY: c_path lives until after the syscall returns; O_PATH is
    // correct for a directory fd passed to `bpf(BPF_TOKEN_CREATE)`.
    let raw = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
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
        // 4 + 4 + 8 + 8 + 8 + 8 = 40 bytes. The kernel expects at
        // least this many bytes for the token_create attr union.
        assert_eq!(mem::size_of::<BpfAttrTokenCreate>(), 40);
        assert_eq!(mem::align_of::<BpfAttrTokenCreate>(), 8);
    }

    #[test]
    fn enterprise_default_sets_expected_cmds() {
        let attr = TokenCreateAttr::enterprise_default(-1);
        // MAP_CREATE (bit 0) + PROG_LOAD (bit 5) + OBJ_GET_INFO_BY_FD (bit 15) + BTF_LOAD (bit 18)
        let expected = 1_u64 | (1 << 5) | (1 << 15) | (1 << 18);
        assert_eq!(attr.allowed_cmds, expected);
        assert_eq!(attr.allowed_maps, u64::MAX);
        assert_eq!(attr.allowed_progs, u64::MAX);
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
