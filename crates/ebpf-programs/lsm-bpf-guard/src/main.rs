//! Nobody but the agent detaches its links or writes its maps.
//!
//! `bpf_map` decides every map descriptor the kernel hands out, by id or
//! from a pinned path, and refuses a writable one on a protected map. `bpf`
//! decides every `bpf(2)` call and refuses a descriptor to a protected link,
//! which is what detaching it or swapping the program behind it needs.
//!
//! Both answer the same question first: is the calling thread group one of
//! the tasks userspace wrote, as the kernel numbers it in that task's own pid
//! namespace. The answer is the kernel's, so a process elsewhere carrying the
//! same number in its own namespace is not mistaken for the agent.
//!
//! An LSM program loads only where the kernel runs the BPF LSM, which is a
//! boot parameter rather than a kernel version. The agent asks the host
//! before loading and reports a node without it as unprotected.

#![no_std]
#![no_main]

use aya_ebpf::bindings::bpf_pidns_info;
use aya_ebpf::helpers::generated::{bpf_get_ns_current_pid_tgid, bpf_probe_read_kernel};
use aya_ebpf::{
    btf_maps::{Array, HashMap, PerCpuArray},
    macros::{btf_map, lsm},
    programs::LsmContext,
};
use ebpf_common::bpf_guard::{
    BPF_GUARD_CMD_LINK_GET_FD_BY_ID, BPF_GUARD_CONFIG_SLOT, BPF_GUARD_FMODE_WRITE,
    BPF_GUARD_MAX_LINKS, BPF_GUARD_MAX_MAPS, BPF_GUARD_MAX_TASKS, BPF_GUARD_METRIC_CHECKED,
    BPF_GUARD_METRIC_COUNT, BPF_GUARD_METRIC_REFUSED_LINK, BPF_GUARD_METRIC_REFUSED_MAP,
    BPF_GUARD_REFUSAL, BpfGuardConfig, BpfGuardTask,
};
use ebpf_helpers::increment_metric;

/// The argument layout and whether the guard is armed.
#[btf_map]
static BPF_GUARD_CONFIG: Array<BpfGuardConfig, 1> = Array::new();

/// The thread groups allowed to act on the protected objects.
#[btf_map]
static BPF_GUARD_TASKS: Array<BpfGuardTask, { BPF_GUARD_MAX_TASKS as usize }> = Array::new();

/// The maps the agent holds, by id. The value is unread.
#[btf_map]
static BPF_GUARD_MAPS: HashMap<u32, u8, { BPF_GUARD_MAX_MAPS as usize }> = HashMap::new();

/// The links the agent holds, by id. The value is unread.
#[btf_map]
static BPF_GUARD_LINKS: HashMap<u32, u8, { BPF_GUARD_MAX_LINKS as usize }> = HashMap::new();

/// Per-CPU counters. Index: 0=checked, 1=refused_map, 2=refused_link.
#[btf_map]
static BPF_GUARD_METRICS: PerCpuArray<u64, { BPF_GUARD_METRIC_COUNT as usize }> =
    PerCpuArray::new();

/// `LSM_HOOK(int, 0, bpf_map, struct bpf_map *map, fmode_t fmode)`
#[lsm(hook = "bpf_map")]
pub fn bpf_guard_map(ctx: LsmContext) -> i32 {
    let previous: i32 = ctx.arg(2);
    if previous != 0 {
        return previous;
    }
    let fmode: u32 = ctx.arg(1);
    if fmode & BPF_GUARD_FMODE_WRITE == 0 {
        return 0;
    }
    let Some(config) = armed() else {
        return 0;
    };
    let map: *const u8 = ctx.arg(0);
    let Some(id) = read_u32(map, config.map_id) else {
        return 0;
    };
    if unsafe { BPF_GUARD_MAPS.get(&id) }.is_none() {
        return 0;
    }
    increment_metric!(BPF_GUARD_METRICS, BPF_GUARD_METRIC_CHECKED);
    if allowed() {
        return 0;
    }
    increment_metric!(BPF_GUARD_METRICS, BPF_GUARD_METRIC_REFUSED_MAP);
    BPF_GUARD_REFUSAL
}

/// `LSM_HOOK(int, 0, bpf, int cmd, union bpf_attr *attr, unsigned int size)`
#[lsm(hook = "bpf")]
pub fn bpf_guard_cmd3(ctx: LsmContext) -> i32 {
    let previous: i32 = ctx.arg(3);
    if previous != 0 {
        return previous;
    }
    decide_cmd(&ctx)
}

/// `LSM_HOOK(int, 0, bpf, int cmd, union bpf_attr *attr, unsigned int size,
/// bool kernel)`
#[lsm(hook = "bpf")]
pub fn bpf_guard_cmd4(ctx: LsmContext) -> i32 {
    let previous: i32 = ctx.arg(4);
    if previous != 0 {
        return previous;
    }
    // A call the kernel makes on its own behalf is no task's to refuse.
    let kernel: u8 = ctx.arg(3);
    if kernel != 0 {
        return 0;
    }
    decide_cmd(&ctx)
}

/// Refuse a descriptor to a protected link to anybody not allowed.
#[inline(always)]
fn decide_cmd(ctx: &LsmContext) -> i32 {
    let cmd: i32 = ctx.arg(0);
    if cmd != BPF_GUARD_CMD_LINK_GET_FD_BY_ID {
        return 0;
    }
    if armed().is_none() {
        return 0;
    }
    // The attribute block is the kernel's copy of what userspace passed, and
    // `link_id` is its first word for this command.
    let attr: *const u8 = ctx.arg(1);
    let Some(id) = read_u32(attr, 0) else {
        return 0;
    };
    if unsafe { BPF_GUARD_LINKS.get(&id) }.is_none() {
        return 0;
    }
    increment_metric!(BPF_GUARD_METRICS, BPF_GUARD_METRIC_CHECKED);
    if allowed() {
        return 0;
    }
    increment_metric!(BPF_GUARD_METRICS, BPF_GUARD_METRIC_REFUSED_LINK);
    BPF_GUARD_REFUSAL
}

/// The configuration, when userspace has finished writing it.
#[inline(always)]
fn armed() -> Option<BpfGuardConfig> {
    match BPF_GUARD_CONFIG.get(BPF_GUARD_CONFIG_SLOT) {
        Some(c) if c.valid != 0 => Some(*c),
        _ => None,
    }
}

/// Whether the calling thread group is one of the allowed tasks, as the
/// kernel numbers it in that task's pid namespace.
#[inline(always)]
fn allowed() -> bool {
    let mut slot = 0u32;
    while slot < BPF_GUARD_MAX_TASKS {
        if let Some(task) = BPF_GUARD_TASKS.get(slot)
            && task.tgid != 0
        {
            let mut info = bpf_pidns_info { pid: 0, tgid: 0 };
            let rc = unsafe {
                bpf_get_ns_current_pid_tgid(
                    task.ns_dev,
                    task.ns_ino,
                    &raw mut info,
                    core::mem::size_of::<bpf_pidns_info>() as u32,
                )
            };
            if rc == 0 && info.tgid == task.tgid {
                return true;
            }
        }
        slot += 1;
    }
    false
}

#[inline(always)]
fn read_u32(base: *const u8, offset: u32) -> Option<u32> {
    let mut out = 0u32;
    let rc = unsafe {
        bpf_probe_read_kernel(
            &raw mut out as *mut core::ffi::c_void,
            core::mem::size_of::<u32>() as u32,
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
