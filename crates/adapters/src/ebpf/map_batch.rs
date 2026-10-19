#![allow(unsafe_code)] // Raw bpf() syscalls for the BPF_MAP_*_BATCH commands.

//! Batched map updates and deletes, for the tables that are rewritten whole.
//!
//! A threat intelligence feed is millions of indicators, and writing them one
//! `BPF_MAP_UPDATE_ELEM` at a time is one syscall per indicator: the reload
//! costs minutes of a core and the set is half old and half new for the whole
//! of it. `BPF_MAP_UPDATE_BATCH` takes an array of keys and an array of values
//! in one call, which is the same work with a few hundred syscalls instead of
//! a few million.
//!
//! The chunk size is bounded rather than "the whole feed". The kernel copies
//! the arrays in before it does anything, so one unbounded call is one
//! allocation the size of the feed inside the kernel; a bounded chunk also
//! means a failure reports how far it got, and the caller can say which
//! indicator the reload stopped on.
//!
//! The commands landed in 5.6 and a map type may still refuse them, so the
//! first chunk refusing the command is reported as [`BatchError::Unsupported`]
//! and the caller falls back to writing element by element. A refusal after
//! the first chunk is a real failure and is reported as one.

use std::os::fd::{AsRawFd, BorrowedFd};

use aya::Pod;
use aya::maps::{Map, MapData};
use thiserror::Error;

use super::kfunc_attach::bpf;

const BPF_MAP_UPDATE_BATCH: u32 = 26;
const BPF_MAP_DELETE_BATCH: u32 = 27;

/// Largest number of elements handed to the kernel in one call.
///
/// The kernel copies the whole chunk in before it writes anything, so this is
/// also the ceiling on the kernel-side allocation a reload can ask for.
pub const MAX_CHUNK: usize = 4096;

/// The `bpf_attr` member the `BPF_MAP_*_BATCH` commands read.
#[repr(C)]
#[derive(Default)]
struct BatchAttr {
    in_batch: u64,
    out_batch: u64,
    keys: u64,
    values: u64,
    count: u32,
    map_fd: u32,
    elem_flags: u64,
    flags: u64,
}

/// What a batched write can go wrong with.
#[derive(Debug, Error)]
pub enum BatchError {
    /// The kernel or this map type has no batched form of the command.
    #[error("the kernel refused the batched {op} on `{map}`: {message}")]
    Unsupported {
        /// `update` or `delete`.
        op: &'static str,
        /// The map the command was aimed at.
        map: String,
        /// The error the kernel reported.
        message: String,
    },
    /// The kernel accepted part of the batch and then stopped.
    #[error("batched {op} on `{map}` wrote {done} of {total} elements: {message}")]
    Partial {
        /// `update` or `delete`.
        op: &'static str,
        /// The map the command was aimed at.
        map: String,
        /// How many elements the kernel reported as written.
        done: usize,
        /// How many were offered.
        total: usize,
        /// The raw errno, for a caller that wants to branch on it.
        errno: i32,
        /// The error the kernel reported.
        message: String,
    },
}

impl BatchError {
    /// True when the command itself is absent, so a per-element fallback is
    /// the right answer rather than a failed reload.
    #[must_use]
    pub const fn is_unsupported(&self) -> bool {
        matches!(self, Self::Unsupported { .. })
    }
}

/// An errno that means "this kernel does not have the command", as opposed to
/// "this call was wrong". `ENOTSUPP` is the kernel-internal 524 the batch path
/// returns for a map type with no batch operations.
fn means_absent(errno: i32) -> bool {
    matches!(errno, libc::EINVAL | libc::EOPNOTSUPP | libc::ENOSYS | 524)
}

/// Borrow the file descriptor behind a map, for the commands aya does not
/// expose. `None` for a map kind that keeps no descriptor of its own.
#[must_use]
pub fn map_fd(map: &Map) -> Option<BorrowedFd<'_>> {
    fn fd(data: &MapData) -> BorrowedFd<'_> {
        std::os::fd::AsFd::as_fd(data.fd())
    }
    match map {
        Map::Array(data)
        | Map::PerCpuArray(data)
        | Map::HashMap(data)
        | Map::PerCpuHashMap(data)
        | Map::LruHashMap(data)
        | Map::BloomFilter(data) => Some(fd(data)),
        _ => None,
    }
}

/// Write `keys[i] -> values[i]` in chunks of at most `chunk` elements.
///
/// Both slices are walked to the length of the shorter one, so a caller that
/// built them from one iteration cannot read past either.
///
/// # Errors
///
/// [`BatchError::Unsupported`] when the first chunk shows the kernel has no
/// batched update for this map, and [`BatchError::Partial`] when a chunk fails
/// after some elements landed.
pub fn update_batch<K: Pod, V: Pod>(
    map: &str,
    fd: BorrowedFd<'_>,
    keys: &[K],
    values: &[V],
    chunk: usize,
) -> Result<usize, BatchError> {
    let total = keys.len().min(values.len());
    let chunk = chunk.clamp(1, MAX_CHUNK);
    let mut done = 0usize;

    while done < total {
        let span = chunk.min(total - done);
        let mut attr = BatchAttr {
            keys: keys[done..].as_ptr() as u64,
            values: values[done..].as_ptr() as u64,
            count: u32::try_from(span).unwrap_or(u32::MAX),
            map_fd: as_u32(fd),
            ..BatchAttr::default()
        };
        // SAFETY: attr is a live BatchAttr of exactly the size passed, and the
        // two pointers address `span` elements each of the layout the map was
        // created with.
        let ret = unsafe {
            bpf(
                BPF_MAP_UPDATE_BATCH,
                std::ptr::from_mut(&mut attr).cast(),
                size_of::<BatchAttr>(),
            )
        };
        if ret < 0 {
            let written = attr.count as usize;
            return Err(failure("update", map, done + written, total, done == 0));
        }
        done += span;
    }
    Ok(done)
}

/// Delete `keys` in chunks of at most `chunk` elements.
///
/// # Errors
///
/// As [`update_batch`], for the delete command.
pub fn delete_batch<K: Pod>(
    map: &str,
    fd: BorrowedFd<'_>,
    keys: &[K],
    chunk: usize,
) -> Result<usize, BatchError> {
    let total = keys.len();
    let chunk = chunk.clamp(1, MAX_CHUNK);
    let mut done = 0usize;

    while done < total {
        let span = chunk.min(total - done);
        let mut attr = BatchAttr {
            keys: keys[done..].as_ptr() as u64,
            count: u32::try_from(span).unwrap_or(u32::MAX),
            map_fd: as_u32(fd),
            ..BatchAttr::default()
        };
        // SAFETY: as in update_batch, with no values array for this command.
        let ret = unsafe {
            bpf(
                BPF_MAP_DELETE_BATCH,
                std::ptr::from_mut(&mut attr).cast(),
                size_of::<BatchAttr>(),
            )
        };
        if ret < 0 {
            let deleted = attr.count as usize;
            return Err(failure("delete", map, done + deleted, total, done == 0));
        }
        done += span;
    }
    Ok(done)
}

/// The descriptor as the kernel wants it in `bpf_attr`.
#[allow(clippy::cast_sign_loss)] // A file descriptor is never negative here.
fn as_u32(fd: BorrowedFd<'_>) -> u32 {
    fd.as_raw_fd() as u32
}

/// Read the errno the syscall just set and shape it into the right variant.
fn failure(op: &'static str, map: &str, done: usize, total: usize, first: bool) -> BatchError {
    let err = std::io::Error::last_os_error();
    let errno = err.raw_os_error().unwrap_or(0);
    if first && means_absent(errno) {
        return BatchError::Unsupported {
            op,
            map: map.to_string(),
            message: err.to_string(),
        };
    }
    BatchError::Partial {
        op,
        map: map.to_string(),
        done,
        total,
        errno,
        message: err.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_attr_matches_the_union_member_the_kernel_reads() {
        assert_eq!(size_of::<BatchAttr>(), 56);
        let attr = BatchAttr::default();
        let base = std::ptr::from_ref(&attr) as usize;
        assert_eq!(std::ptr::from_ref(&attr.in_batch) as usize - base, 0);
        assert_eq!(std::ptr::from_ref(&attr.out_batch) as usize - base, 8);
        assert_eq!(std::ptr::from_ref(&attr.keys) as usize - base, 16);
        assert_eq!(std::ptr::from_ref(&attr.values) as usize - base, 24);
        assert_eq!(std::ptr::from_ref(&attr.count) as usize - base, 32);
        assert_eq!(std::ptr::from_ref(&attr.map_fd) as usize - base, 36);
        assert_eq!(std::ptr::from_ref(&attr.elem_flags) as usize - base, 40);
        assert_eq!(std::ptr::from_ref(&attr.flags) as usize - base, 48);
    }

    #[test]
    fn a_missing_command_is_told_apart_from_a_rejected_call() {
        assert!(means_absent(libc::EINVAL));
        assert!(means_absent(libc::EOPNOTSUPP));
        assert!(means_absent(524));
        assert!(!means_absent(libc::E2BIG));
        assert!(!means_absent(libc::ENOMEM));
    }

    #[test]
    fn only_the_first_chunk_may_report_the_command_as_absent() {
        let later = failure("update", "THREATINTEL_IOCS", 4096, 8192, false);
        assert!(!later.is_unsupported());
        match later {
            BatchError::Partial { done, total, .. } => {
                assert_eq!((done, total), (4096, 8192));
            }
            BatchError::Unsupported { .. } => panic!("a later chunk is never a missing command"),
        }
    }

    #[test]
    fn a_chunk_is_bounded_both_ways() {
        assert_eq!(0usize.clamp(1, MAX_CHUNK), 1);
        assert_eq!(usize::MAX.clamp(1, MAX_CHUNK), MAX_CHUNK);
        assert_eq!(512usize.clamp(1, MAX_CHUNK), 512);
    }
}
