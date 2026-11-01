//! Counting calls into the system cryptographic libraries, per process.
//!
//! One program, attached at the symmetric encryption entry point of each
//! library the agent finds mapped. It reads nothing of its arguments: the
//! only thing it learns is which thread group called, and the only thing it
//! keeps is how many times. A key or a buffer cannot reach a map because no
//! instruction here ever loads one.

#![no_std]
#![no_main]

use aya_ebpf::{
    btf_maps::LruPerCpuHashMap, helpers::bpf_get_current_pid_tgid, macros::btf_map,
    macros::uprobe, programs::ProbeContext,
};
use ebpf_common::crypto::CRYPTO_CALLS_MAX_TASKS;

/// `BPF_NOEXIST`: insert only when the key is absent.
const BPF_NOEXIST: u64 = 1;

/// Calls counted per thread group, per CPU.
#[btf_map]
static CRYPTO_CALLS: LruPerCpuHashMap<u32, u64, CRYPTO_CALLS_MAX_TASKS> =
    LruPerCpuHashMap::new();

#[uprobe]
pub fn crypto_call(_ctx: ProbeContext) -> u32 {
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if let Some(calls) = CRYPTO_CALLS.get_ptr_mut(&tgid) {
        // Per-CPU slot: no other CPU writes it.
        unsafe { *calls = (*calls).wrapping_add(1) };
    } else {
        let _ = CRYPTO_CALLS.insert(&tgid, &1, BPF_NOEXIST);
    }
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
