//! Inline assembly macros for BPF-safe memory copies.
//!
//! LLVM transforms `[u8; N]` copies into `memcpy` subprograms. The kernel 6.17
//! verifier rejects these when the source or destination is a packet pointer
//! (loses bounds tracking across the subprogram call). These macros use inline
//! asm that LLVM cannot decompose or outline.
//!
//! Uses u16 loads/stores (not u32) because `[u8; 6]` arrays on the BPF stack
//! may only be 2-byte aligned — u32 stores would trigger "misaligned stack
//! access" from the verifier.

/// Copy 6 bytes (MAC address) via inline asm using 3×u16 loads/stores.
///
/// # Safety
/// Caller must have proven bounds for `$src..$src+6` via `ptr_at` in the
/// current stack frame. `$dst` must point to at least 6 writable bytes.
#[macro_export]
macro_rules! copy_mac_asm {
    ($dst:expr, $src:expr) => {
        core::arch::asm!(
            "{tmp1} = *(u16 *)({src} + 0)",
            "*(u16 *)({dst} + 0) = {tmp1}",
            "{tmp2} = *(u16 *)({src} + 2)",
            "*(u16 *)({dst} + 2) = {tmp2}",
            "{tmp3} = *(u16 *)({src} + 4)",
            "*(u16 *)({dst} + 4) = {tmp3}",
            src = in(reg) $src,
            dst = in(reg) $dst,
            tmp1 = out(reg) _,
            tmp2 = out(reg) _,
            tmp3 = out(reg) _,
            options(nostack, preserves_flags)
        )
    };
}

/// Copy 16 bytes (IPv6 address) via inline asm using 8×u16 loads/stores.
///
/// # Safety
/// Caller must have proven bounds for `$src..$src+16` via `ptr_at` in the
/// current stack frame. `$dst` must point to at least 16 writable bytes.
#[macro_export]
macro_rules! copy_16b_asm {
    ($dst:expr, $src:expr) => {
        core::arch::asm!(
            "{t1} = *(u16 *)({src} + 0)",  "*(u16 *)({dst} + 0) = {t1}",
            "{t2} = *(u16 *)({src} + 2)",  "*(u16 *)({dst} + 2) = {t2}",
            "{t1} = *(u16 *)({src} + 4)",  "*(u16 *)({dst} + 4) = {t1}",
            "{t2} = *(u16 *)({src} + 6)",  "*(u16 *)({dst} + 6) = {t2}",
            "{t1} = *(u16 *)({src} + 8)",  "*(u16 *)({dst} + 8) = {t1}",
            "{t2} = *(u16 *)({src} + 10)", "*(u16 *)({dst} + 10) = {t2}",
            "{t1} = *(u16 *)({src} + 12)", "*(u16 *)({dst} + 12) = {t1}",
            "{t2} = *(u16 *)({src} + 14)", "*(u16 *)({dst} + 14) = {t2}",
            src = in(reg) $src,
            dst = in(reg) $dst,
            t1 = out(reg) _,
            t2 = out(reg) _,
            options(nostack, preserves_flags)
        )
    };
}
