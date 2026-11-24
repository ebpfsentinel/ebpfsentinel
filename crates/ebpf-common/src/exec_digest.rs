//! The SHA-256 of an executable, taken by the kernel at exec.
//!
//! Userspace hashes the file a process runs once it has read the exec event,
//! which leaves a process that exits first with no digest, and a rootless
//! agent with no way to open a binary outside its user namespace without the
//! warden. The kernel has the file in hand at the exec itself.
//!
//! One sleepable LSM program on `bprm_committed_creds`, which runs once the
//! new image is the task's executable and before it runs a line, takes a
//! reference on that file with `bpf_get_task_exe_file` and asks IMA for its
//! hash with `bpf_ima_file_hash`. IMA hashes the whole contents with the
//! host's IMA algorithm, so a digest is kept only when the kernel says that
//! algorithm is SHA-256: it is then the same function of the same bytes as
//! `sha256sum`, and a rule written against one matches the other.
//!
//! The answer is kept per file, keyed by inode and device, with the size and
//! both change times it was taken at. The next exec of the same unchanged file
//! reads the times and costs no hash. Two more hooks drop the entry before
//! the file can change: `file_open` for a write-open and `path_truncate` for
//! a truncation by path. The kernel refuses a write-open of a file being
//! executed and refuses an exec of a file open for writing, so an entry is
//! never taken while a writer exists, and every writer passes a hook that
//! drops it.
//!
//! A file with fs-verity on is left alone: its digest is the kernel's verity
//! measurement, a different function that userspace asks for, and a
//! content hash beside it would let one kind of rule match the other.

/// Index of the single slot in `EXEC_DIGEST_CONFIG`.
pub const EXEC_DIGEST_CONFIG_SLOT: u32 = 0;

/// How many files the kernel remembers. LRU: a forgotten file costs one more
/// hash at its next exec and nothing else.
pub const EXEC_DIGEST_MAX_FILES: u32 = 8_192;

/// Files larger than this are not hashed in the kernel. The hash runs inside
/// the exec, which waits for it, so the bound is on the delay a first exec
/// may take; a larger file is left to userspace, which reads it beside the
/// process rather than in front of it.
pub const EXEC_DIGEST_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// What `bpf_ima_file_hash` returns for SHA-256: `HASH_ALGO_SHA256` in the
/// kernel's `enum hash_algo`.
pub const EXEC_DIGEST_ALGO_SHA256: i32 = 4;

/// `S_VERITY` in `inode.i_flags`: the file has fs-verity on.
pub const EXEC_DIGEST_S_VERITY: u32 = 1 << 16;

/// `FMODE_WRITE` in `file.f_mode`.
pub const EXEC_DIGEST_FMODE_WRITE: u32 = 1 << 1;

/// `I_CTIME_QUERIED`, a flag the kernel keeps in the top bit of
/// `inode.i_ctime_nsec`, which is not part of the time.
pub const EXEC_DIGEST_CTIME_QUERIED: u32 = 1 << 31;

/// Metric index: execs the program saw with a complete configuration.
pub const EXEC_DIGEST_METRIC_EXECS: u32 = 0;
/// Metric index: files hashed as SHA-256.
pub const EXEC_DIGEST_METRIC_COMPUTED: u32 = 1;
/// Metric index: execs answered from a file's unchanged entry.
pub const EXEC_DIGEST_METRIC_REUSED: u32 = 2;
/// Metric index: files IMA hashed with another algorithm or could not hash.
pub const EXEC_DIGEST_METRIC_UNAVAILABLE: u32 = 3;
/// Metric index: files with fs-verity on, left to the verity measurement.
pub const EXEC_DIGEST_METRIC_VERITY: u32 = 4;
/// Metric index: files above [`EXEC_DIGEST_MAX_BYTES`].
pub const EXEC_DIGEST_METRIC_TOO_LARGE: u32 = 5;
/// Metric index: execs whose file or inode could not be read.
pub const EXEC_DIGEST_METRIC_UNREADABLE: u32 = 6;
/// Metric index: entries dropped because their file was opened for writing
/// or truncated.
pub const EXEC_DIGEST_METRIC_INVALIDATED: u32 = 7;
/// How many counters the metrics array holds.
pub const EXEC_DIGEST_METRIC_COUNT: u32 = 8;

/// One file, as the kernel names it: inode number and the kernel's encoding
/// of its superblock's device, `(major << 20) | minor`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ExecDigestKey {
    pub ino: u64,
    pub dev: u32,
    pub _pad: u32,
}

/// What the kernel answered for one version of one file.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExecDigestEntry {
    /// The hash IMA wrote, meaningful only when `algo` is
    /// [`EXEC_DIGEST_ALGO_SHA256`].
    pub digest: [u8; 32],
    /// `inode.i_size` when it was taken.
    pub size: u64,
    /// `inode.i_mtime_sec`.
    pub mtime_sec: i64,
    /// `inode.i_ctime_sec`.
    pub ctime_sec: i64,
    /// `inode.i_mtime_nsec`.
    pub mtime_nsec: u32,
    /// `inode.i_ctime_nsec` without [`EXEC_DIGEST_CTIME_QUERIED`].
    pub ctime_nsec: u32,
    /// What `bpf_ima_file_hash` returned: the algorithm, or a negative error.
    /// Kept either way, so a host whose IMA hashes with another algorithm
    /// pays for one attempt per file rather than one per exec.
    pub algo: i32,
    pub _pad: u32,
}

/// The offsets the hooks read, from the running kernel's BTF.
///
/// The exec hook reads its inode through `task_struct.mm` and
/// `mm_struct.exe_file` as plain kernel memory, the same file the kfunc hands
/// IMA, so the reference the kfunc returns is only ever passed back to the
/// kernel and never offset.
///
/// `valid` stays zero until userspace has written a complete layout, and a
/// hook reading an invalid slot does nothing.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExecDigestConfig {
    /// `task_struct.mm`
    pub task_mm: u32,
    /// `mm_struct.exe_file`
    pub mm_exe_file: u32,
    /// `file.f_inode`
    pub file_inode: u32,
    /// `file.f_mode`
    pub file_mode: u32,
    /// `inode.i_ino`
    pub inode_ino: u32,
    /// `inode.i_sb`
    pub inode_sb: u32,
    /// `super_block.s_dev`
    pub sb_dev: u32,
    /// `inode.i_size`
    pub inode_size: u32,
    /// `inode.i_flags`
    pub inode_flags: u32,
    /// `inode.i_mtime_sec`
    pub inode_mtime_sec: u32,
    /// `inode.i_mtime_nsec`
    pub inode_mtime_nsec: u32,
    /// `inode.i_ctime_sec`
    pub inode_ctime_sec: u32,
    /// `inode.i_ctime_nsec`
    pub inode_ctime_nsec: u32,
    /// `path.dentry`
    pub path_dentry: u32,
    /// `dentry.d_inode`
    pub dentry_inode: u32,
    /// Non-zero once the slot is complete.
    pub valid: u32,
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for ExecDigestKey {}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for ExecDigestEntry {}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for ExecDigestConfig {}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn the_key_is_sixteen_bytes_with_no_implicit_padding() {
        assert_eq!(mem::size_of::<ExecDigestKey>(), 16);
        assert_eq!(mem::offset_of!(ExecDigestKey, dev), 8);
    }

    #[test]
    fn the_entry_is_seventy_two_bytes_with_no_implicit_padding() {
        assert_eq!(mem::size_of::<ExecDigestEntry>(), 72);
        assert_eq!(mem::offset_of!(ExecDigestEntry, size), 32);
        assert_eq!(mem::offset_of!(ExecDigestEntry, mtime_nsec), 56);
        assert_eq!(mem::offset_of!(ExecDigestEntry, algo), 64);
    }

    #[test]
    fn the_config_is_sixteen_words_with_valid_last() {
        assert_eq!(mem::size_of::<ExecDigestConfig>(), 64);
        assert_eq!(mem::offset_of!(ExecDigestConfig, valid), 60);
    }

    #[test]
    fn the_flags_are_the_kernels() {
        assert_eq!(EXEC_DIGEST_S_VERITY, 0x1_0000);
        assert_eq!(EXEC_DIGEST_FMODE_WRITE, 0x2);
        assert_eq!(EXEC_DIGEST_CTIME_QUERIED, 0x8000_0000);
    }
}
