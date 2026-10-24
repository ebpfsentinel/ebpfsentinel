//! Only the executables in the set reach the network.
//!
//! Two LSM hooks, one decision. `socket_create` refuses an internet socket to
//! a task whose executable is outside the set, and `socket_connect` refuses
//! the connection, which is the one that matters for a socket handed over by
//! a parent that was allowed to create it.
//!
//! The executable is read in the kernel, from the task making the call, so a
//! process that execs and connects at once is decided like any other: there
//! is no userspace lookup to race. What is compared is the inode of
//! `current->mm->exe_file` and the device it lives on, against keys userspace
//! wrote by stat-ing the configured paths.
//!
//! An LSM program loads only where the kernel runs the BPF LSM, which is a
//! boot parameter rather than a kernel version. The agent asks the host
//! before loading and refuses to start an enforcing configuration it cannot
//! attach, so nothing here has to guess.

#![no_std]
#![no_main]

use aya_ebpf::{
    btf_maps::{Array, HashMap, LruHashMap, PerCpuArray, RingBuf},
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_task, bpf_ktime_get_boot_ns},
    macros::{btf_map, lsm},
    programs::LsmContext,
};
use aya_ebpf_bindings::helpers::bpf_probe_read_kernel;
use ebpf_common::exec_network::{
    EXEC_NET_AF_INET, EXEC_NET_AF_INET6, EXEC_NET_CONFIG_SLOT, EXEC_NET_EVENTS_RINGBUF_BYTES,
    EXEC_NET_HOOK_CONNECT, EXEC_NET_HOOK_CREATE, EXEC_NET_MAX_EXECUTABLES, EXEC_NET_MAX_REPORTED,
    EXEC_NET_METRIC_ALLOWED, EXEC_NET_METRIC_CHECKED, EXEC_NET_METRIC_COUNT,
    EXEC_NET_METRIC_EVENT_LOST, EXEC_NET_METRIC_REFUSED, EXEC_NET_METRIC_UNREADABLE,
    EXEC_NET_METRIC_WOULD_REFUSE, EXEC_NET_MODE_ENFORCE, EXEC_NET_REFUSAL,
    EXEC_NET_REPORT_INTERVAL_NS, ExecNetConfig, ExecNetEvent, ExecNetKey,
};
use ebpf_helpers::increment_metric;

/// The mode and the field offsets, written by userspace once it has read them
/// off the running kernel's BTF.
#[btf_map]
static EXEC_NET_CONFIG: Array<ExecNetConfig, 1> = Array::new();

/// The executables in the set. The value is unread: a key being present is
/// the whole statement.
#[btf_map]
static EXEC_NET_ALLOWED: HashMap<ExecNetKey, u8, { EXEC_NET_MAX_EXECUTABLES as usize }> =
    HashMap::new();

/// When each `(thread group, hook)` was last reported, keyed
/// `tgid << 8 | hook`. LRU, because a forgotten entry costs one more record
/// and nothing else.
#[btf_map]
static EXEC_NET_REPORTED: LruHashMap<u64, u64, { EXEC_NET_MAX_REPORTED as usize }> =
    LruHashMap::new();

/// Calls outside the set, for the alert userspace writes.
#[btf_map]
static EXEC_NET_EVENTS: RingBuf<ExecNetEvent, { EXEC_NET_EVENTS_RINGBUF_BYTES as usize }> =
    RingBuf::new();

/// Per-CPU counters. Index: 0=checked, 1=allowed, 2=refused,
/// 3=would_refuse, 4=unreadable, 5=event_lost.
#[btf_map]
static EXEC_NET_METRICS: PerCpuArray<u64, { EXEC_NET_METRIC_COUNT as usize }> = PerCpuArray::new();

/// `LSM_HOOK(int, 0, socket_create, int family, int type, int protocol, int kern)`
#[lsm(hook = "socket_create")]
pub fn exec_network_socket_create(ctx: LsmContext) -> i32 {
    let previous: i32 = ctx.arg(4);
    if previous != 0 {
        return previous;
    }
    let kern: i32 = ctx.arg(3);
    if kern != 0 {
        return 0;
    }
    let family: i32 = ctx.arg(0);
    decide(family as u16, EXEC_NET_HOOK_CREATE)
}

/// `LSM_HOOK(int, 0, socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)`
#[lsm(hook = "socket_connect")]
pub fn exec_network_socket_connect(ctx: LsmContext) -> i32 {
    let previous: i32 = ctx.arg(3);
    if previous != 0 {
        return previous;
    }
    let address: *const core::ffi::c_void = ctx.arg(1);
    let mut family: u16 = 0;
    let read = unsafe {
        bpf_probe_read_kernel(
            &raw mut family as *mut core::ffi::c_void,
            core::mem::size_of::<u16>() as u32,
            address,
        )
    };
    if read < 0 {
        return 0;
    }
    decide(family, EXEC_NET_HOOK_CONNECT)
}

/// The decision both hooks share: zero to let the call through, the refusal
/// otherwise.
#[inline(always)]
fn decide(family: u16, hook: u8) -> i32 {
    if family != EXEC_NET_AF_INET && family != EXEC_NET_AF_INET6 {
        return 0;
    }
    let config = match EXEC_NET_CONFIG.get(EXEC_NET_CONFIG_SLOT) {
        Some(c) if c.valid != 0 => *c,
        _ => return 0,
    };
    increment_metric!(EXEC_NET_METRICS, EXEC_NET_METRIC_CHECKED);

    let key = match current_executable(&config) {
        Identity::Kernel => return 0,
        Identity::Executable(k) => {
            if unsafe { EXEC_NET_ALLOWED.get(&k) }.is_some() {
                increment_metric!(EXEC_NET_METRICS, EXEC_NET_METRIC_ALLOWED);
                return 0;
            }
            k
        }
        Identity::Unreadable => {
            increment_metric!(EXEC_NET_METRICS, EXEC_NET_METRIC_UNREADABLE);
            ExecNetKey::default()
        }
    };

    let enforce = config.mode == EXEC_NET_MODE_ENFORCE;
    if enforce {
        increment_metric!(EXEC_NET_METRICS, EXEC_NET_METRIC_REFUSED);
    } else {
        increment_metric!(EXEC_NET_METRICS, EXEC_NET_METRIC_WOULD_REFUSE);
    }
    report(key, hook, family, enforce);
    if enforce { EXEC_NET_REFUSAL } else { 0 }
}

/// Who is making the call.
enum Identity {
    /// A kernel thread, which has no address space and so no executable. It
    /// is the kernel acting for itself and is never decided.
    Kernel,
    /// A task running this executable.
    Executable(ExecNetKey),
    /// A task whose executable could not be read.
    Unreadable,
}

/// The inode and device of the current task's executable.
#[inline(always)]
fn current_executable(config: &ExecNetConfig) -> Identity {
    let task = unsafe { bpf_get_current_task() } as *const u8;
    let Some(mm) = read_value::<u64>(task, config.task_mm) else {
        return Identity::Unreadable;
    };
    if mm == 0 {
        return Identity::Kernel;
    }
    match executable_of(config, mm as *const u8) {
        Some(key) => Identity::Executable(key),
        None => Identity::Unreadable,
    }
}

/// Walk from an address space to its executable's inode, `None` when any
/// step fails or lands on a null pointer.
#[inline(always)]
fn executable_of(config: &ExecNetConfig, mm: *const u8) -> Option<ExecNetKey> {
    let exe_file: *const u8 = read_ptr(mm, config.mm_exe_file)?;
    let inode: *const u8 = read_ptr(exe_file, config.file_inode)?;
    let sb: *const u8 = read_ptr(inode, config.inode_sb)?;
    let ino: u64 = read_value(inode, config.inode_ino)?;
    let dev: u32 = read_value(sb, config.sb_dev)?;
    Some(ExecNetKey { ino, dev, _pad: 0 })
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

/// Write one record, at most once a minute per task and hook, counting the
/// loss when the ring is full.
#[inline(always)]
fn report(key: ExecNetKey, hook: u8, family: u16, refused: bool) {
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let now_ns = unsafe { bpf_ktime_get_boot_ns() };
    let slot = (u64::from(tgid) << 8) | u64::from(hook);
    if let Some(last) = unsafe { EXEC_NET_REPORTED.get(&slot) }
        && now_ns.saturating_sub(*last) < EXEC_NET_REPORT_INTERVAL_NS
    {
        return;
    }
    let _ = EXEC_NET_REPORTED.insert(&slot, &now_ns, 0);

    let Some(mut entry) = EXEC_NET_EVENTS.reserve(0) else {
        increment_metric!(EXEC_NET_METRICS, EXEC_NET_METRIC_EVENT_LOST);
        return;
    };
    entry.write(ExecNetEvent {
        at_ns: now_ns,
        ino: key.ino,
        tgid,
        dev: key.dev,
        hook,
        refused: u8::from(refused),
        family,
        _pad: 0,
    });
    entry.submit(0);
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
