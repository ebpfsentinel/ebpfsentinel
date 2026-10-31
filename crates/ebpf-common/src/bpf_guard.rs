//! Nobody but the agent takes its programs off the network path or writes
//! its maps, decided at the BPF LSM hooks.
//!
//! Two hooks. `bpf_map` runs whenever a descriptor to a map is handed out,
//! whether by id or from a pinned path, and refuses a writable one on a map
//! the agent holds. `bpf` runs on every `bpf(2)` call and refuses
//! `BPF_LINK_GET_FD_BY_ID` on a link the agent holds: detaching a link and
//! updating the program behind it both take a descriptor to the link, and
//! the kernel already refuses to detach or replace a program a link owns
//! through the older attach commands.
//!
//! The `bpf` hook gained a parameter in a later kernel, and the verdict of
//! the program before sits after the last one. The verifier refuses a read
//! past the hook's arguments even on a branch never taken, so the hook is
//! written twice, once per arity: both are loaded, the kernel refuses the one
//! that reads too far, and userspace attaches the one matching the running
//! kernel's BTF.
//!
//! What is allowed is a thread group, named as the kernel sees it from a pid
//! namespace userspace stat-ed: the agent itself and, when it runs rootless,
//! the warden that reads the network path on its behalf. A task in another
//! namespace is never mistaken for one of them, because the kernel answers a
//! namespaced pid only for a task that lives in that namespace.

/// The program deciding `bpf(2)` on a kernel whose hook takes three
/// parameters, the verdict of the previous program being the fourth argument.
pub const BPF_GUARD_CMD_PROGRAM_3: &str = "bpf_guard_cmd3";
/// The program deciding `bpf(2)` on a kernel whose hook gained a fourth
/// parameter, saying the call comes from the kernel itself.
pub const BPF_GUARD_CMD_PROGRAM_4: &str = "bpf_guard_cmd4";

/// Index of the single slot in `BPF_GUARD_CONFIG`.
pub const BPF_GUARD_CONFIG_SLOT: u32 = 0;

/// How many maps the guard protects. The agent holds a few hundred.
pub const BPF_GUARD_MAX_MAPS: u32 = 4_096;

/// How many links the guard protects.
pub const BPF_GUARD_MAX_LINKS: u32 = 1_024;

/// How many thread groups may act on the protected objects: the agent and the
/// warden, with room for both to have restarted once.
pub const BPF_GUARD_MAX_TASKS: u32 = 4;

/// What the hook returns to refuse: `-EPERM`.
pub const BPF_GUARD_REFUSAL: i32 = -1;

/// `BPF_LINK_GET_FD_BY_ID` in `enum bpf_cmd`, part of the stable UAPI.
pub const BPF_GUARD_CMD_LINK_GET_FD_BY_ID: i32 = 30;

/// `FMODE_WRITE`, the bit a writable map descriptor carries.
pub const BPF_GUARD_FMODE_WRITE: u32 = 0x2;

/// Metric index: descriptors to a protected object the hooks decided.
pub const BPF_GUARD_METRIC_CHECKED: u32 = 0;
/// Metric index: writable map descriptors refused.
pub const BPF_GUARD_METRIC_REFUSED_MAP: u32 = 1;
/// Metric index: link descriptors refused.
pub const BPF_GUARD_METRIC_REFUSED_LINK: u32 = 2;
/// How many counters the metrics array holds.
pub const BPF_GUARD_METRIC_COUNT: u32 = 3;

/// The configuration slot.
///
/// `valid` stays zero until userspace has written the slot and the tasks. A
/// hook reading an invalid slot refuses nothing: the hooks attach before the
/// agent knows its own objects, and refusing in between would lock the agent
/// out of its own maps.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BpfGuardConfig {
    /// `bpf_map.id`, read off the running kernel's BTF.
    pub map_id: u32,
    /// Non-zero once the slot and the tasks are written.
    pub valid: u32,
}

/// One thread group allowed to act on the protected objects.
///
/// `tgid` is the thread group as the namespace `(ns_dev, ns_ino)` numbers it.
/// `ns_dev` is the kernel's encoding of the namespace filesystem's device. A
/// slot whose `tgid` is zero is empty.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct BpfGuardTask {
    pub ns_dev: u64,
    pub ns_ino: u64,
    pub tgid: u32,
    pub _pad: u32,
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for BpfGuardConfig {}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for BpfGuardTask {}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn the_config_is_two_words() {
        assert_eq!(mem::size_of::<BpfGuardConfig>(), 8);
        assert_eq!(mem::offset_of!(BpfGuardConfig, valid), 4);
    }

    #[test]
    fn the_task_is_twenty_four_bytes_with_no_implicit_padding() {
        assert_eq!(mem::size_of::<BpfGuardTask>(), 24);
        assert_eq!(mem::offset_of!(BpfGuardTask, ns_ino), 8);
        assert_eq!(mem::offset_of!(BpfGuardTask, tgid), 16);
    }

    #[test]
    fn the_refusal_is_eperm_and_the_command_is_the_uapi_one() {
        assert_eq!(BPF_GUARD_REFUSAL, -1);
        assert_eq!(BPF_GUARD_CMD_LINK_GET_FD_BY_ID, 30);
    }
}
