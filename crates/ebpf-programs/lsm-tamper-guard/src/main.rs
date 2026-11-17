//! Nobody but the agent stops it, traces it or takes its pins away.
//!
//! Inert until userspace writes a valid slot. See `ebpf_common::tamper_guard`
//! for what each hook decides and why the stop window passes all of them but
//! the trace.
//!
//! Every hook first returns the verdict of the program before it, so a
//! refusal by another LSM program is never turned into an admission here.
//! The verdict sits after the hook's own parameters, and the five hooks have
//! kept their parameter counts since the agent's kernel floor; userspace
//! checks the counts against the running kernel's BTF before it attaches.

#![no_std]
#![no_main]

use aya_ebpf::helpers::generated::{bpf_probe_read_kernel, bpf_probe_read_kernel_str};
use aya_ebpf::{
    btf_maps::{Array, HashMap, PerCpuArray, RingBuf},
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_task, bpf_ktime_get_boot_ns,
    },
    macros::{btf_map, lsm},
    programs::LsmContext,
};
use ebpf_common::bpf_guard::BpfGuardTask;
use ebpf_common::tamper_guard::{
    TAMPER_GUARD_CONFIG_SLOT, TAMPER_GUARD_EVENTS_RINGBUF_BYTES, TAMPER_GUARD_FMODE_WRITE,
    TAMPER_GUARD_INODE_CGROUP, TAMPER_GUARD_INODE_DIRECTORY, TAMPER_GUARD_KIND_CGROUP,
    TAMPER_GUARD_KIND_PTRACE, TAMPER_GUARD_KIND_RENAME, TAMPER_GUARD_KIND_SIGNAL,
    TAMPER_GUARD_KIND_UNLINK, TAMPER_GUARD_MAX_INODES, TAMPER_GUARD_MAX_TASKS,
    TAMPER_GUARD_METRIC_CHECKED, TAMPER_GUARD_METRIC_COUNT, TAMPER_GUARD_METRIC_EVENT_LOST,
    TAMPER_GUARD_METRIC_REFUSED, TAMPER_GUARD_METRIC_WINDOW, TAMPER_GUARD_NAME_BYTES,
    TAMPER_GUARD_PID_NS_LEVELS, TAMPER_GUARD_PTRACE_MODE_ATTACH, TAMPER_GUARD_REFUSAL,
    TAMPER_GUARD_UPID_SIZE, TamperGuardConfig, TamperGuardEvent, TamperGuardInode,
    tamper_guard_signal_bit,
};
use ebpf_helpers::increment_metric;

/// The signal set and the offsets, written last by userspace.
#[btf_map]
static TAMPER_GUARD_CONFIG: Array<TamperGuardConfig, 1> = Array::new();

/// The protected thread groups, each in the pid namespace userspace stat-ed.
#[btf_map]
static TAMPER_GUARD_TASKS: Array<BpfGuardTask, { TAMPER_GUARD_MAX_TASKS as usize }> = Array::new();

/// The protected inodes and what each protects.
#[btf_map]
static TAMPER_GUARD_INODES: HashMap<TamperGuardInode, u8, { TAMPER_GUARD_MAX_INODES as usize }> =
    HashMap::new();

/// The end of the stop window, in `bpf_ktime_get_boot_ns`. Zero or past is
/// closed.
#[btf_map]
static TAMPER_GUARD_WINDOW: Array<u64, 1> = Array::new();

/// Every refusal, for the alert.
#[btf_map]
static TAMPER_GUARD_EVENTS: RingBuf<
    TamperGuardEvent,
    { TAMPER_GUARD_EVENTS_RINGBUF_BYTES as usize },
> = RingBuf::new();

/// Per-CPU counters. Index: 0=checked, 1=refused, 2=window, 3=event_lost.
#[btf_map]
static TAMPER_GUARD_METRICS: PerCpuArray<u64, { TAMPER_GUARD_METRIC_COUNT as usize }> =
    PerCpuArray::new();

/// `LSM_HOOK(int, 0, task_kill, struct task_struct *p, struct kernel_siginfo
/// *info, int sig, const struct cred *cred)`
#[lsm(hook = "task_kill")]
pub fn tamper_guard_task_kill(ctx: LsmContext) -> i32 {
    let previous: i32 = ctx.arg(4);
    if previous != 0 {
        return previous;
    }
    let Some(config) = config() else {
        return 0;
    };
    let signal: i32 = ctx.arg(2);
    if signal <= 0 || config.signals & tamper_guard_signal_bit(signal as u32) == 0 {
        return 0;
    }
    let target: *const u8 = ctx.arg(0);
    let Some(target_tgid) = protected_task(&config, target) else {
        return 0;
    };
    increment_metric!(TAMPER_GUARD_METRICS, TAMPER_GUARD_METRIC_CHECKED);
    if caller_protected(&config) {
        return 0;
    }
    if window_open() {
        increment_metric!(TAMPER_GUARD_METRICS, TAMPER_GUARD_METRIC_WINDOW);
        return 0;
    }
    refuse(&Refusal {
        kind: TAMPER_GUARD_KIND_SIGNAL,
        target_tgid,
        detail: signal as u32,
        inode: TamperGuardInode::default(),
        name: core::ptr::null(),
    })
}

/// `LSM_HOOK(int, 0, ptrace_access_check, struct task_struct *child,
/// unsigned int mode)`
#[lsm(hook = "ptrace_access_check")]
pub fn tamper_guard_ptrace(ctx: LsmContext) -> i32 {
    let previous: i32 = ctx.arg(2);
    if previous != 0 {
        return previous;
    }
    let Some(config) = config() else {
        return 0;
    };
    let mode: u32 = ctx.arg(1);
    if mode & TAMPER_GUARD_PTRACE_MODE_ATTACH == 0 {
        return 0;
    }
    let child: *const u8 = ctx.arg(0);
    let Some(target_tgid) = protected_task(&config, child) else {
        return 0;
    };
    increment_metric!(TAMPER_GUARD_METRICS, TAMPER_GUARD_METRIC_CHECKED);
    if caller_protected(&config) {
        return 0;
    }
    // No window: an authorised stop never needs the agent's memory.
    refuse(&Refusal {
        kind: TAMPER_GUARD_KIND_PTRACE,
        target_tgid,
        detail: mode,
        inode: TamperGuardInode::default(),
        name: core::ptr::null(),
    })
}

/// `LSM_HOOK(int, 0, inode_unlink, struct inode *dir, struct dentry *dentry)`
#[lsm(hook = "inode_unlink")]
pub fn tamper_guard_unlink(ctx: LsmContext) -> i32 {
    let previous: i32 = ctx.arg(2);
    if previous != 0 {
        return previous;
    }
    let Some(config) = config() else {
        return 0;
    };
    let dir: *const u8 = ctx.arg(0);
    let dentry: *const u8 = ctx.arg(1);
    decide_entry(&config, dir, dentry, TAMPER_GUARD_KIND_UNLINK)
}

/// `LSM_HOOK(int, 0, inode_rename, struct inode *old_dir, struct dentry
/// *old_dentry, struct inode *new_dir, struct dentry *new_dentry)`
#[lsm(hook = "inode_rename")]
pub fn tamper_guard_rename(ctx: LsmContext) -> i32 {
    let previous: i32 = ctx.arg(4);
    if previous != 0 {
        return previous;
    }
    let Some(config) = config() else {
        return 0;
    };
    let old_dir: *const u8 = ctx.arg(0);
    let old_dentry: *const u8 = ctx.arg(1);
    let verdict = decide_entry(&config, old_dir, old_dentry, TAMPER_GUARD_KIND_RENAME);
    if verdict != 0 {
        return verdict;
    }
    // A rename onto a protected file replaces it as surely as an unlink.
    let new_dentry: *const u8 = ctx.arg(3);
    let Some(target) = dentry_key(&config, new_dentry) else {
        return 0;
    };
    match unsafe { TAMPER_GUARD_INODES.get(&target) } {
        Some(kind) if *kind != TAMPER_GUARD_INODE_CGROUP => {
            gate(&config, TAMPER_GUARD_KIND_RENAME, target, new_dentry)
        }
        _ => 0,
    }
}

/// `LSM_HOOK(int, 0, file_open, struct file *file)`
#[lsm(hook = "file_open")]
pub fn tamper_guard_file_open(ctx: LsmContext) -> i32 {
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
    if mode & TAMPER_GUARD_FMODE_WRITE == 0 {
        return 0;
    }
    let Some(dentry) = read_ptr(file, config.file_dentry) else {
        return 0;
    };
    let Some(parent) = read_ptr(dentry, config.dentry_parent) else {
        return 0;
    };
    let Some(dir) = dentry_key(&config, parent) else {
        return 0;
    };
    match unsafe { TAMPER_GUARD_INODES.get(&dir) } {
        Some(kind) if *kind == TAMPER_GUARD_INODE_CGROUP => {}
        _ => return 0,
    }
    if !names_kill_or_freeze(&config, dentry) {
        return 0;
    }
    gate(&config, TAMPER_GUARD_KIND_CGROUP, dir, dentry)
}

/// Removing or moving `dentry` out of `dir`: refused when `dir` is a
/// protected directory or the entry is a protected file.
#[inline(always)]
fn decide_entry(config: &TamperGuardConfig, dir: *const u8, dentry: *const u8, kind: u8) -> i32 {
    if let Some(key) = inode_key(config, dir)
        && let Some(found) = unsafe { TAMPER_GUARD_INODES.get(&key) }
        && *found == TAMPER_GUARD_INODE_DIRECTORY
    {
        // The directory is what userspace knows by path; the entry's own
        // name travels in the record.
        return gate(config, kind, key, dentry);
    }
    if let Some(key) = dentry_key(config, dentry)
        && let Some(found) = unsafe { TAMPER_GUARD_INODES.get(&key) }
        && *found != TAMPER_GUARD_INODE_CGROUP
    {
        return gate(config, kind, key, dentry);
    }
    0
}

/// The decision on a protected inode: a protected caller and an open window
/// pass, anybody else is refused and reported.
#[inline(always)]
fn gate(config: &TamperGuardConfig, kind: u8, inode: TamperGuardInode, dentry: *const u8) -> i32 {
    increment_metric!(TAMPER_GUARD_METRICS, TAMPER_GUARD_METRIC_CHECKED);
    if caller_protected(config) {
        return 0;
    }
    if window_open() {
        increment_metric!(TAMPER_GUARD_METRICS, TAMPER_GUARD_METRIC_WINDOW);
        return 0;
    }
    let name = read_ptr(dentry, config.dentry_name).unwrap_or(core::ptr::null());
    refuse(&Refusal {
        kind,
        target_tgid: 0,
        detail: 0,
        inode,
        name,
    })
}

/// Whether the dentry's name is `cgroup.kill` or `cgroup.freeze`.
#[inline(always)]
fn names_kill_or_freeze(config: &TamperGuardConfig, dentry: *const u8) -> bool {
    let Some(name) = read_ptr(dentry, config.dentry_name) else {
        return false;
    };
    let mut buf = [0u8; TAMPER_GUARD_NAME_BYTES];
    let rc = unsafe {
        bpf_probe_read_kernel_str(
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            TAMPER_GUARD_NAME_BYTES as u32,
            name as *const core::ffi::c_void,
        )
    };
    if rc <= 0 {
        return false;
    }
    starts_with(&buf, b"cgroup.kill\0") || starts_with(&buf, b"cgroup.freeze\0")
}

#[inline(always)]
fn starts_with(buf: &[u8; TAMPER_GUARD_NAME_BYTES], word: &[u8]) -> bool {
    let mut i = 0;
    while i < word.len() && i < TAMPER_GUARD_NAME_BYTES {
        if buf[i] != word[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// The slot, or `None` until userspace has written a complete one.
#[inline(always)]
fn config() -> Option<TamperGuardConfig> {
    match TAMPER_GUARD_CONFIG.get(TAMPER_GUARD_CONFIG_SLOT) {
        Some(c) if c.valid != 0 => Some(*c),
        _ => None,
    }
}

#[inline(always)]
fn window_open() -> bool {
    match TAMPER_GUARD_WINDOW.get(TAMPER_GUARD_CONFIG_SLOT) {
        Some(until) => *until != 0 && unsafe { bpf_ktime_get_boot_ns() } < *until,
        None => false,
    }
}

/// The calling task belongs to a protected thread group.
#[inline(always)]
fn caller_protected(config: &TamperGuardConfig) -> bool {
    let task = unsafe { bpf_get_current_task() } as *const u8;
    protected_task(config, task).is_some()
}

/// The thread group `task` belongs to, as its protected entry numbers it,
/// when it is one of the protected tasks.
#[inline(always)]
fn protected_task(config: &TamperGuardConfig, task: *const u8) -> Option<u32> {
    let leader = read_ptr(task, config.task_group_leader)?;
    let pid = read_ptr(leader, config.task_thread_pid)?;
    let level = read_value::<u32>(pid, config.pid_level)?;
    let mut slot = 0u32;
    while slot < TAMPER_GUARD_MAX_TASKS {
        if let Some(entry) = TAMPER_GUARD_TASKS.get(slot)
            && entry.tgid != 0
            && number_in(config, pid, level, entry.ns_ino) == Some(entry.tgid)
        {
            return Some(entry.tgid);
        }
        slot += 1;
    }
    None
}

/// The number `pid` carries in the namespace whose inode is `ns_ino`, read
/// off each level of its `numbers` array.
#[inline(always)]
fn number_in(config: &TamperGuardConfig, pid: *const u8, level: u32, ns_ino: u64) -> Option<u32> {
    let mut depth = 0u32;
    while depth < TAMPER_GUARD_PID_NS_LEVELS {
        if depth > level {
            return None;
        }
        let upid = pid.wrapping_add((config.pid_numbers + depth * TAMPER_GUARD_UPID_SIZE) as usize);
        if let Some(ns) = read_ptr(upid, config.upid_ns)
            && let Some(inum) = read_value::<u32>(ns, config.pid_namespace_inum)
            && u64::from(inum) == ns_ino
        {
            return read_value::<u32>(upid, 0);
        }
        depth += 1;
    }
    None
}

/// The inode `dentry` names, `None` for a negative dentry.
#[inline(always)]
fn dentry_key(config: &TamperGuardConfig, dentry: *const u8) -> Option<TamperGuardInode> {
    let inode = read_ptr(dentry, config.dentry_inode)?;
    inode_key(config, inode)
}

#[inline(always)]
fn inode_key(config: &TamperGuardConfig, inode: *const u8) -> Option<TamperGuardInode> {
    let sb = read_ptr(inode, config.inode_sb)?;
    let ino: u64 = read_value(inode, config.inode_ino)?;
    let dev: u32 = read_value(sb, config.sb_dev)?;
    Some(TamperGuardInode { ino, dev, _pad: 0 })
}

/// What one refusal reports.
struct Refusal {
    kind: u8,
    target_tgid: u32,
    detail: u32,
    inode: TamperGuardInode,
    name: *const u8,
}

/// Count, report and refuse. The refusal stands whether the ring had room.
#[inline(always)]
fn refuse(r: &Refusal) -> i32 {
    increment_metric!(TAMPER_GUARD_METRICS, TAMPER_GUARD_METRIC_REFUSED);
    let Some(mut entry) = TAMPER_GUARD_EVENTS.reserve(0) else {
        increment_metric!(TAMPER_GUARD_METRICS, TAMPER_GUARD_METRIC_EVENT_LOST);
        return TAMPER_GUARD_REFUSAL;
    };
    let mut event = TamperGuardEvent {
        at_ns: unsafe { bpf_ktime_get_boot_ns() },
        ino: r.inode.ino,
        caller_tgid: (bpf_get_current_pid_tgid() >> 32) as u32,
        target_tgid: r.target_tgid,
        dev: r.inode.dev,
        detail: r.detail,
        kind: r.kind,
        _pad: [0; 7],
        comm: bpf_get_current_comm().unwrap_or([0u8; TAMPER_GUARD_NAME_BYTES]),
        name: [0; TAMPER_GUARD_NAME_BYTES],
    };
    if !r.name.is_null() {
        unsafe {
            bpf_probe_read_kernel_str(
                event.name.as_mut_ptr() as *mut core::ffi::c_void,
                TAMPER_GUARD_NAME_BYTES as u32,
                r.name as *const core::ffi::c_void,
            );
        }
    }
    entry.write(event);
    entry.submit(0);
    TAMPER_GUARD_REFUSAL
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

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
