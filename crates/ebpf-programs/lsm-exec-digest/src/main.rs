//! The SHA-256 of each executable, asked of IMA at exec and kept per file.
//!
//! Inert until userspace writes a valid slot. See `ebpf_common::exec_digest`
//! for why the hash is only kept when IMA answers SHA-256, and why a file
//! with fs-verity on is left out.
//!
//! The exec hook is sleepable, because IMA reads the file to hash it, and it
//! never refuses: it returns nothing and the exec has already been committed.
//! The two invalidation hooks are not sleepable, decide nothing, and return
//! the verdict of the program before them unchanged.

#![no_std]
#![no_main]

use aya_ebpf::helpers::generated::{
    bpf_get_current_task, bpf_get_current_task_btf, bpf_ima_file_hash, bpf_probe_read_kernel,
};
use aya_ebpf::{
    btf_maps::{Array, LruHashMap, PerCpuArray},
    macros::{btf_map, lsm},
    programs::LsmContext,
};
use ebpf_common::exec_digest::{
    EXEC_DIGEST_ALGO_SHA256, EXEC_DIGEST_CONFIG_SLOT, EXEC_DIGEST_CTIME_QUERIED,
    EXEC_DIGEST_FMODE_WRITE, EXEC_DIGEST_MAX_BYTES, EXEC_DIGEST_MAX_FILES,
    EXEC_DIGEST_METRIC_COMPUTED, EXEC_DIGEST_METRIC_COUNT, EXEC_DIGEST_METRIC_EXECS,
    EXEC_DIGEST_METRIC_INVALIDATED, EXEC_DIGEST_METRIC_REUSED, EXEC_DIGEST_METRIC_TOO_LARGE,
    EXEC_DIGEST_METRIC_UNAVAILABLE, EXEC_DIGEST_METRIC_UNREADABLE, EXEC_DIGEST_METRIC_VERITY,
    EXEC_DIGEST_S_VERITY, ExecDigestConfig, ExecDigestEntry, ExecDigestKey,
};
use ebpf_helpers::increment_metric;
use ebpf_helpers::kfuncs::{bpf_get_task_exe_file, bpf_put_file, task_struct};

/// The field offsets, written by userspace once it has read them off the
/// running kernel's BTF.
#[btf_map]
static EXEC_DIGEST_CONFIG: Array<ExecDigestConfig, 1> = Array::new();

/// What IMA answered for each file, with the version it answered for.
#[btf_map]
static EXEC_DIGEST_FILES: LruHashMap<
    ExecDigestKey,
    ExecDigestEntry,
    { EXEC_DIGEST_MAX_FILES as usize },
> = LruHashMap::new();

/// Per-CPU counters. Index: 0=execs, 1=computed, 2=reused, 3=unavailable,
/// 4=verity, 5=too_large, 6=unreadable, 7=invalidated.
#[btf_map]
static EXEC_DIGEST_METRICS: PerCpuArray<u64, { EXEC_DIGEST_METRIC_COUNT as usize }> =
    PerCpuArray::new();

/// `LSM_HOOK(void, LSM_RET_VOID, bprm_committed_creds, const struct linux_binprm *bprm)`
///
/// By here the new image is the task's executable and its address space is
/// the task's own; nothing of it has run.
#[lsm(hook = "bprm_committed_creds", sleepable)]
pub fn exec_digest_exec(_ctx: LsmContext) -> i32 {
    let Some(config) = config() else {
        return 0;
    };
    increment_metric!(EXEC_DIGEST_METRICS, EXEC_DIGEST_METRIC_EXECS);

    let Some((key, version)) = current_executable(&config) else {
        increment_metric!(EXEC_DIGEST_METRICS, EXEC_DIGEST_METRIC_UNREADABLE);
        return 0;
    };
    if version.flags & EXEC_DIGEST_S_VERITY != 0 {
        forget(&key);
        increment_metric!(EXEC_DIGEST_METRICS, EXEC_DIGEST_METRIC_VERITY);
        return 0;
    }
    if version.size < 0 || version.size as u64 > EXEC_DIGEST_MAX_BYTES {
        forget(&key);
        increment_metric!(EXEC_DIGEST_METRICS, EXEC_DIGEST_METRIC_TOO_LARGE);
        return 0;
    }
    if let Some(known) = unsafe { EXEC_DIGEST_FILES.get(&key) }
        && version.matches(known)
    {
        increment_metric!(EXEC_DIGEST_METRICS, EXEC_DIGEST_METRIC_REUSED);
        return 0;
    }

    let mut entry = version.entry();
    // SAFETY: the helper takes no argument and returns the current task as a
    // pointer the verifier tracks as trusted for the whole program.
    let task = unsafe { bpf_get_current_task_btf() };
    // SAFETY: `task` is the trusted current task. The kfunc returns a
    // referenced file or null, and every path below that holds a non-null
    // file passes it to `bpf_put_file` exactly once.
    let file = unsafe { bpf_get_task_exe_file(task.cast::<task_struct>()) };
    if file.is_null() {
        forget(&key);
        increment_metric!(EXEC_DIGEST_METRICS, EXEC_DIGEST_METRIC_UNREADABLE);
        return 0;
    }
    // SAFETY: `file` is the referenced, non-null file the kfunc returned, the
    // destination is the 32 bytes of `entry.digest` on this stack, and the
    // helper writes at most that many.
    let algo = unsafe {
        bpf_ima_file_hash(
            file.cast(),
            entry.digest.as_mut_ptr().cast(),
            entry.digest.len() as u32,
        )
    };
    // SAFETY: releases the single reference taken above.
    unsafe { bpf_put_file(file) };

    entry.algo = algo as i32;
    let _ = EXEC_DIGEST_FILES.insert(&key, &entry, 0);
    if entry.algo == EXEC_DIGEST_ALGO_SHA256 {
        increment_metric!(EXEC_DIGEST_METRICS, EXEC_DIGEST_METRIC_COMPUTED);
    } else {
        increment_metric!(EXEC_DIGEST_METRICS, EXEC_DIGEST_METRIC_UNAVAILABLE);
    }
    0
}

/// `LSM_HOOK(int, 0, file_open, struct file *file)`
///
/// A write-open is the first step of every change made through a file
/// descriptor, `O_TRUNC` included.
#[lsm(hook = "file_open")]
pub fn exec_digest_file_open(ctx: LsmContext) -> i32 {
    let previous: i32 = ctx.arg(1);
    let Some(config) = config() else {
        return previous;
    };
    let file: *const u8 = ctx.arg(0);
    let Some(mode) = read_value::<u32>(file, config.file_mode) else {
        return previous;
    };
    if mode & EXEC_DIGEST_FMODE_WRITE == 0 {
        return previous;
    }
    if let Some(inode) = read_ptr(file, config.file_inode)
        && let Some(key) = key_of(&config, inode)
    {
        invalidate(&key);
    }
    previous
}

/// `LSM_HOOK(int, 0, path_truncate, const struct path *path)`
///
/// `truncate(2)` by path, which changes a file without opening it.
#[lsm(hook = "path_truncate")]
pub fn exec_digest_path_truncate(ctx: LsmContext) -> i32 {
    let previous: i32 = ctx.arg(1);
    let Some(config) = config() else {
        return previous;
    };
    let path: *const u8 = ctx.arg(0);
    if let Some(dentry) = read_ptr(path, config.path_dentry)
        && let Some(inode) = read_ptr(dentry, config.dentry_inode)
        && let Some(key) = key_of(&config, inode)
    {
        invalidate(&key);
    }
    previous
}

/// The size and times an entry is valid for, and the flags that decide
/// whether one is taken at all.
struct Version {
    size: i64,
    flags: u32,
    mtime_sec: i64,
    ctime_sec: i64,
    mtime_nsec: u32,
    ctime_nsec: u32,
}

impl Version {
    #[inline(always)]
    fn matches(&self, entry: &ExecDigestEntry) -> bool {
        entry.size == self.size as u64
            && entry.mtime_sec == self.mtime_sec
            && entry.ctime_sec == self.ctime_sec
            && entry.mtime_nsec == self.mtime_nsec
            && entry.ctime_nsec == self.ctime_nsec
    }

    #[inline(always)]
    fn entry(&self) -> ExecDigestEntry {
        ExecDigestEntry {
            digest: [0; 32],
            size: self.size as u64,
            mtime_sec: self.mtime_sec,
            ctime_sec: self.ctime_sec,
            mtime_nsec: self.mtime_nsec,
            ctime_nsec: self.ctime_nsec,
            algo: 0,
            _pad: 0,
        }
    }
}

#[inline(always)]
fn config() -> Option<ExecDigestConfig> {
    match EXEC_DIGEST_CONFIG.get(EXEC_DIGEST_CONFIG_SLOT) {
        Some(c) if c.valid != 0 => Some(*c),
        _ => None,
    }
}

/// The current task's executable and its version, read as plain kernel
/// memory through `task->mm->exe_file`.
#[inline(always)]
fn current_executable(config: &ExecDigestConfig) -> Option<(ExecDigestKey, Version)> {
    // SAFETY: the helper takes no argument; the address it returns is only
    // ever read through `bpf_probe_read_kernel`, which cannot fault.
    let task = unsafe { bpf_get_current_task() } as *const u8;
    let mm = read_ptr(task, config.task_mm)?;
    let exe_file = read_ptr(mm, config.mm_exe_file)?;
    let inode = read_ptr(exe_file, config.file_inode)?;
    let key = key_of(config, inode)?;
    let ctime_nsec: u32 = read_value(inode, config.inode_ctime_nsec)?;
    let version = Version {
        size: read_value(inode, config.inode_size)?,
        flags: read_value(inode, config.inode_flags)?,
        mtime_sec: read_value(inode, config.inode_mtime_sec)?,
        ctime_sec: read_value(inode, config.inode_ctime_sec)?,
        mtime_nsec: read_value(inode, config.inode_mtime_nsec)?,
        ctime_nsec: ctime_nsec & !EXEC_DIGEST_CTIME_QUERIED,
    };
    Some((key, version))
}

/// An inode's number and its superblock's device.
#[inline(always)]
fn key_of(config: &ExecDigestConfig, inode: *const u8) -> Option<ExecDigestKey> {
    let sb = read_ptr(inode, config.inode_sb)?;
    let ino: u64 = read_value(inode, config.inode_ino)?;
    let dev: u32 = read_value(sb, config.sb_dev)?;
    Some(ExecDigestKey { ino, dev, _pad: 0 })
}

/// Drop an entry because its file is about to change, counting it.
#[inline(always)]
fn invalidate(key: &ExecDigestKey) {
    // A lookup takes no lock, a delete takes the bucket's: most write-opens
    // are of files that were never executed.
    if unsafe { EXEC_DIGEST_FILES.get(key) }.is_some() {
        forget(key);
        increment_metric!(EXEC_DIGEST_METRICS, EXEC_DIGEST_METRIC_INVALIDATED);
    }
}

/// Drop an entry the exec hook will not renew, so userspace never reads an
/// answer for a version of the file that is gone.
#[inline(always)]
fn forget(key: &ExecDigestKey) {
    let _ = EXEC_DIGEST_FILES.remove(key);
}

/// Read the pointer at `offset` into `base`, refusing a null.
#[inline(always)]
fn read_ptr(base: *const u8, offset: u32) -> Option<*const u8> {
    let value: u64 = read_value(base, offset)?;
    if value == 0 {
        return None;
    }
    Some(value as *const u8)
}

#[inline(always)]
fn read_value<T: Default>(base: *const u8, offset: u32) -> Option<T> {
    let mut out = T::default();
    // SAFETY: the destination is `out` on this stack and exactly its size;
    // the source is any kernel address, which the helper reads without
    // faulting and reports a failure for.
    let rc = unsafe {
        bpf_probe_read_kernel(
            &raw mut out as *mut core::ffi::c_void,
            core::mem::size_of::<T>() as u32,
            base.wrapping_add(offset as usize) as *const core::ffi::c_void,
        )
    };
    if rc < 0 { None } else { Some(out) }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
