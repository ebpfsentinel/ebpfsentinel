#![no_std]
#![no_main]

use aya_ebpf::{
    btf_maps::{Array, HashMap, PerCpuArray, RingBuf},
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_task, bpf_ktime_get_boot_ns},
    macros::{btf_map, lsm},
    programs::LsmContext,
};
use aya_ebpf_bindings::helpers::{
    bpf_get_current_cgroup_id, bpf_probe_read_kernel, bpf_probe_read_kernel_str,
};
use ebpf_common::write_refusal::{
    WRITE_REFUSAL_BY_CGROUP, WRITE_REFUSAL_CONFIG_SLOT, WRITE_REFUSAL_EVENTS_RINGBUF_BYTES,
    WRITE_REFUSAL_FMODE_WRITE, WRITE_REFUSAL_HOOK_OPEN, WRITE_REFUSAL_MAX_EXPECTED_WRITERS,
    WRITE_REFUSAL_METRIC_EXPECTED, WRITE_REFUSAL_REGIME_SYSTEM, WRITE_REFUSAL_HOOK_TRUNCATE,
    WRITE_REFUSAL_MAX_DEPTH, WRITE_REFUSAL_MAX_DIRECTORIES, WRITE_REFUSAL_MAX_WRITERS,
    WRITE_REFUSAL_METRIC_CHECKED, WRITE_REFUSAL_METRIC_COUNT, WRITE_REFUSAL_METRIC_EVENT_LOST,
    WRITE_REFUSAL_METRIC_REFUSED, WRITE_REFUSAL_METRIC_TABLE_FULL, WRITE_REFUSAL_METRIC_UNRESOLVED,
    WRITE_REFUSAL_METRIC_WATCHED, WRITE_REFUSAL_METRIC_WOULD_REFUSE, WRITE_REFUSAL_MODE_ENFORCE,
    WRITE_REFUSAL_NAME_BYTES, WRITE_REFUSAL_REFUSAL, WriteRefusalConfig, WriteRefusalCount,
    WriteRefusalDir, WriteRefusalEvent, write_refusal_count_key, write_refusal_step,
    write_refusal_threshold,
};
use ebpf_helpers::increment_metric;

/// The decision's parameters and the field offsets, written by userspace once
/// it has read them off the running kernel's BTF.
#[btf_map]
static WRITE_REFUSAL_CONFIG: Array<WriteRefusalConfig, 1> = Array::new();

/// The watched directories, each with its regime: a data path counted to the
/// threshold, a system path refused at the first unexpected write.
#[btf_map]
static WRITE_REFUSAL_DIRS: HashMap<
    WriteRefusalDir,
    u8,
    { WRITE_REFUSAL_MAX_DIRECTORIES as usize },
> = HashMap::new();

/// The executables expected to write under a system path, by the device and
/// inode of their file: a package manager, the configuration tool of the
/// estate. Their writes there are let through and counted as expected.
#[btf_map]
static WRITE_REFUSAL_WRITERS: HashMap<
    WriteRefusalDir,
    u8,
    { WRITE_REFUSAL_MAX_EXPECTED_WRITERS as usize },
> = HashMap::new();

/// Each writer's count inside its window, keyed by thread group or by cgroup
/// as configured. A plain hash rather than an LRU: an LRU would evict the
/// writer being counted under exactly the load a run produces, so a full map
/// lets the newcomer through and says so instead.
#[btf_map]
static WRITE_REFUSAL_COUNTS: HashMap<
    u64,
    WriteRefusalCount,
    { WRITE_REFUSAL_MAX_WRITERS as usize },
> = HashMap::new();

/// Writers that reached the threshold, once per writer and window.
#[btf_map]
static WRITE_REFUSAL_EVENTS: RingBuf<
    WriteRefusalEvent,
    { WRITE_REFUSAL_EVENTS_RINGBUF_BYTES as usize },
> = RingBuf::new();

/// Per-CPU counters. Index: 0=checked, 1=watched, 2=refused,
/// 3=would_refuse, 4=unresolved, 5=table_full, 6=event_lost, 7=expected.
#[btf_map]
static WRITE_REFUSAL_METRICS: PerCpuArray<u64, { WRITE_REFUSAL_METRIC_COUNT as usize }> =
    PerCpuArray::new();

/// `LSM_HOOK(int, 0, file_open, struct file *file)`
#[lsm(hook = "file_open")]
pub fn write_refusal_file_open(ctx: LsmContext) -> i32 {
    let previous: i32 = ctx.arg(1);
    if previous != 0 {
        return previous;
    }
    let Some(config) = config() else {
        return 0;
    };
    let file: *const u8 = ctx.arg(0);
    let Some(mode) = read_value::<u32>(file, config.file_mode) else {
        return 0;
    };
    if mode & WRITE_REFUSAL_FMODE_WRITE == 0 {
        return 0;
    }
    let path = file.wrapping_add(config.file_path as usize);
    decide(&config, path, WRITE_REFUSAL_HOOK_OPEN)
}

/// `LSM_HOOK(int, 0, path_truncate, const struct path *path)`
#[lsm(hook = "path_truncate")]
pub fn write_refusal_path_truncate(ctx: LsmContext) -> i32 {
    let previous: i32 = ctx.arg(1);
    if previous != 0 {
        return previous;
    }
    let Some(config) = config() else {
        return 0;
    };
    let path: *const u8 = ctx.arg(0);
    decide(&config, path, WRITE_REFUSAL_HOOK_TRUNCATE)
}

/// The slot, or `None` until userspace has written a complete one: an
/// attached program with no slot lets every write through.
#[inline(always)]
fn config() -> Option<WriteRefusalConfig> {
    match WRITE_REFUSAL_CONFIG.get(WRITE_REFUSAL_CONFIG_SLOT) {
        Some(c) if c.valid != 0 => Some(*c),
        _ => None,
    }
}

/// The decision both hooks share, from the `struct path` being written: zero
/// to let the write through, the refusal otherwise.
#[inline(always)]
fn decide(config: &WriteRefusalConfig, path: *const u8, hook: u8) -> i32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    if tgid == config.agent_tgid {
        return 0;
    }
    increment_metric!(WRITE_REFUSAL_METRICS, WRITE_REFUSAL_METRIC_CHECKED);

    let Some(dentry) = read_ptr(path, config.path_dentry) else {
        increment_metric!(WRITE_REFUSAL_METRICS, WRITE_REFUSAL_METRIC_UNRESOLVED);
        return 0;
    };
    let Some(file) = inode_key(config, dentry) else {
        increment_metric!(WRITE_REFUSAL_METRICS, WRITE_REFUSAL_METRIC_UNRESOLVED);
        return 0;
    };
    // A watched file is its own entry: `/etc/passwd` is named, not `/etc`.
    let own = unsafe { WRITE_REFUSAL_DIRS.get(&file) }.map(|regime| *regime);
    let walk = match own {
        Some(regime) => Walk::Watched(file, regime),
        None => watched_root(config, dentry),
    };
    let (dir, regime) = match walk {
        Walk::Watched(dir, regime) => (dir, regime),
        Walk::Outside => return 0,
        Walk::Unresolved => {
            increment_metric!(WRITE_REFUSAL_METRICS, WRITE_REFUSAL_METRIC_UNRESOLVED);
            return 0;
        }
    };
    increment_metric!(WRITE_REFUSAL_METRICS, WRITE_REFUSAL_METRIC_WATCHED);
    if regime == WRITE_REFUSAL_REGIME_SYSTEM {
        match current_executable(config) {
            Executable::Kernel => {
                increment_metric!(WRITE_REFUSAL_METRICS, WRITE_REFUSAL_METRIC_EXPECTED);
                return 0;
            }
            Executable::File(exe) => {
                if unsafe { WRITE_REFUSAL_WRITERS.get(&exe) }.is_some() {
                    increment_metric!(WRITE_REFUSAL_METRICS, WRITE_REFUSAL_METRIC_EXPECTED);
                    return 0;
                }
            }
            Executable::Unresolved => {
                increment_metric!(WRITE_REFUSAL_METRICS, WRITE_REFUSAL_METRIC_UNRESOLVED);
                return 0;
            }
        }
    }

    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let writer = if config.count_by == WRITE_REFUSAL_BY_CGROUP {
        cgroup_id
    } else {
        u64::from(tgid)
    };
    let now_ns = unsafe { bpf_ktime_get_boot_ns() };
    let key = write_refusal_count_key(writer, regime);
    let previous = unsafe { WRITE_REFUSAL_COUNTS.get(&key) }.copied();
    let threshold = write_refusal_threshold(regime, config.threshold);
    let step = write_refusal_step(previous, now_ns, config.window_ns, threshold);
    if WRITE_REFUSAL_COUNTS.insert(&key, &step.next, 0).is_err() {
        increment_metric!(WRITE_REFUSAL_METRICS, WRITE_REFUSAL_METRIC_TABLE_FULL);
        return 0;
    }
    if !step.over {
        return 0;
    }

    let enforce = config.mode == WRITE_REFUSAL_MODE_ENFORCE;
    if enforce {
        increment_metric!(WRITE_REFUSAL_METRICS, WRITE_REFUSAL_METRIC_REFUSED);
    } else {
        increment_metric!(WRITE_REFUSAL_METRICS, WRITE_REFUSAL_METRIC_WOULD_REFUSE);
    }
    if step.report {
        report(&Report {
            config,
            dentry,
            file,
            dir,
            tgid,
            cgroup_id,
            now_ns,
            count: step.next.count,
            hook,
            regime,
            refused: enforce,
        });
    }
    if enforce { WRITE_REFUSAL_REFUSAL } else { 0 }
}

/// Where the walk up from a written file ended.
enum Walk {
    /// Under this watched directory, in this regime.
    Watched(WriteRefusalDir, u8),
    /// At the root of its filesystem without meeting one.
    Outside,
    /// A step could not be read, or the chain ran deeper than the walk goes.
    Unresolved,
}

/// Walk up from `dentry`'s parent to the root of its filesystem, looking for
/// a watched directory, at most `WRITE_REFUSAL_MAX_DEPTH` steps.
#[inline(always)]
fn watched_root(config: &WriteRefusalConfig, dentry: *const u8) -> Walk {
    let Some(mut current) = read_ptr(dentry, config.dentry_parent) else {
        return Walk::Unresolved;
    };
    let mut child = dentry;
    for _ in 0..WRITE_REFUSAL_MAX_DEPTH {
        if current == child {
            return Walk::Outside;
        }
        let Some(key) = inode_key(config, current) else {
            return Walk::Unresolved;
        };
        if let Some(regime) = unsafe { WRITE_REFUSAL_DIRS.get(&key) } {
            return Walk::Watched(key, *regime);
        }
        let Some(parent) = read_ptr(current, config.dentry_parent) else {
            return Walk::Unresolved;
        };
        child = current;
        current = parent;
    }
    Walk::Unresolved
}

/// What the writing task runs.
enum Executable {
    /// A kernel thread: no memory map, no file, and a write the kernel makes
    /// on its own behalf.
    Kernel,
    /// The device and inode of the executable's file.
    File(WriteRefusalDir),
    /// A step could not be read.
    Unresolved,
}

/// The executable of the current task, read through `task->mm->exe_file`.
#[inline(always)]
fn current_executable(config: &WriteRefusalConfig) -> Executable {
    let task = unsafe { bpf_get_current_task() } as *const u8;
    let Some(mm) = read_value::<u64>(task, config.task_mm) else {
        return Executable::Unresolved;
    };
    if mm == 0 {
        return Executable::Kernel;
    }
    let Some(exe) = read_ptr(mm as *const u8, config.mm_exe_file) else {
        return Executable::Unresolved;
    };
    let Some(inode) = read_ptr(exe, config.file_inode) else {
        return Executable::Unresolved;
    };
    let Some(sb) = read_ptr(inode, config.inode_sb) else {
        return Executable::Unresolved;
    };
    let (Some(ino), Some(dev)) = (
        read_value::<u64>(inode, config.inode_ino),
        read_value::<u32>(sb, config.sb_dev),
    ) else {
        return Executable::Unresolved;
    };
    Executable::File(WriteRefusalDir { ino, dev, _pad: 0 })
}

/// The inode and device a dentry names, `None` for a negative dentry or a
/// step that cannot be read.
#[inline(always)]
fn inode_key(config: &WriteRefusalConfig, dentry: *const u8) -> Option<WriteRefusalDir> {
    let inode = read_ptr(dentry, config.dentry_inode)?;
    let sb = read_ptr(inode, config.inode_sb)?;
    let ino: u64 = read_value(inode, config.inode_ino)?;
    let dev: u32 = read_value(sb, config.sb_dev)?;
    Some(WriteRefusalDir { ino, dev, _pad: 0 })
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
    let rc = unsafe {
        bpf_probe_read_kernel(
            &raw mut out as *mut core::ffi::c_void,
            core::mem::size_of::<T>() as u32,
            base.wrapping_add(offset as usize) as *const core::ffi::c_void,
        )
    };
    if rc < 0 { None } else { Some(out) }
}

/// What one record carries.
struct Report<'a> {
    config: &'a WriteRefusalConfig,
    dentry: *const u8,
    file: WriteRefusalDir,
    dir: WriteRefusalDir,
    tgid: u32,
    cgroup_id: u64,
    now_ns: u64,
    count: u32,
    hook: u8,
    regime: u8,
    refused: bool,
}

/// Write one record, counting the loss when the ring is full. The decision
/// is taken whatever happens here.
#[inline(always)]
fn report(r: &Report<'_>) {
    let Some(mut entry) = WRITE_REFUSAL_EVENTS.reserve(0) else {
        increment_metric!(WRITE_REFUSAL_METRICS, WRITE_REFUSAL_METRIC_EVENT_LOST);
        return;
    };
    let mut event = WriteRefusalEvent {
        at_ns: r.now_ns,
        cgroup_id: r.cgroup_id,
        file_ino: r.file.ino,
        dir_ino: r.dir.ino,
        tgid: r.tgid,
        file_dev: r.file.dev,
        dir_dev: r.dir.dev,
        count: r.count,
        hook: r.hook,
        refused: u8::from(r.refused),
        regime: r.regime,
        _pad: [0; 5],
        name: [0; WRITE_REFUSAL_NAME_BYTES],
    };
    if let Some(name) = read_ptr(r.dentry, r.config.dentry_name) {
        unsafe {
            bpf_probe_read_kernel_str(
                event.name.as_mut_ptr() as *mut core::ffi::c_void,
                WRITE_REFUSAL_NAME_BYTES as u32,
                name as *const core::ffi::c_void,
            );
        }
    }
    entry.write(event);
    entry.submit(0);
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
