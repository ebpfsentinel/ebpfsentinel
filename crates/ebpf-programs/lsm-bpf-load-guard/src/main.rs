#![no_std]
#![no_main]

use aya_ebpf::{macros::lsm, programs::LsmContext};
use ebpf_common::load_guard::{
    LOAD_GUARD_ATTR_KEYRING_ID, LOAD_GUARD_ATTR_PROG_FLAGS, LOAD_GUARD_ATTR_SIGNATURE,
    LOAD_GUARD_F_TOKEN_FD, LoadFacts, load_guard_verdict,
};

/// The serial of the keyring the warden made, written into this object's
/// `.rodata` by the warden before it loads the program. The map holding it is
/// frozen and read-only to the program, so nothing changes it after the load.
#[unsafe(no_mangle)]
static LOAD_GUARD_KEYRING: i32 = 0;

/// `LSM_HOOK(int, 0, bpf_prog_load, struct bpf_prog *prog, union bpf_attr *attr,
/// struct bpf_token *token, bool kernel)`
///
/// Refuse a load made through a BPF token unless it carries a signature and
/// names the warden's keyring. The kernel has already checked the signature
/// against that keyring when it reaches this hook, so a load that passes here
/// is one the warden's certificate signed.
#[lsm(hook = "bpf_prog_load")]
pub fn bpf_load_guard(ctx: LsmContext) -> i32 {
    let previous: i32 = ctx.arg(4);
    if previous != 0 {
        return previous;
    }
    let kernel: u8 = ctx.arg(3);
    if kernel != 0 {
        return 0;
    }
    let token: u64 = ctx.arg(2);
    let attr: *const u8 = ctx.arg(1);
    // The attribute block is the kernel's own copy of what the caller passed,
    // typed by the hook's BTF, so each field is a direct load at a constant
    // offset the verifier checks against `union bpf_attr`.
    // SAFETY: `attr` is the hook's trusted `union bpf_attr *`, and every
    // offset read lies inside its `BPF_PROG_LOAD` arm with the field's width.
    let flags =
        unsafe { core::ptr::read_volatile(attr.add(LOAD_GUARD_ATTR_PROG_FLAGS).cast::<u32>()) };
    let through_token = token != 0 || flags & LOAD_GUARD_F_TOKEN_FD != 0;
    if !through_token {
        return 0;
    }
    // SAFETY: as above, `signature` is the u64 at offset 152.
    let signature =
        unsafe { core::ptr::read_volatile(attr.add(LOAD_GUARD_ATTR_SIGNATURE).cast::<u64>()) };
    // SAFETY: as above, `keyring_id` is the s32 at offset 164.
    let keyring_id =
        unsafe { core::ptr::read_volatile(attr.add(LOAD_GUARD_ATTR_KEYRING_ID).cast::<i32>()) };
    // SAFETY: a read of this object's own global, which the warden wrote
    // before the load; volatile so the compiler reads the frozen map rather
    // than folding in the zero the object was built with.
    let ring = unsafe { core::ptr::read_volatile(&raw const LOAD_GUARD_KEYRING) };
    load_guard_verdict(
        LoadFacts {
            kernel: false,
            token: true,
            signature,
            keyring_id,
        },
        ring,
    )
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
