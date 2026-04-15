//! Kfunc bindings for kernel 6.7 → 6.9 features used by the eBPF
//! programs.
//!
//! aya-ebpf 0.13 has no native kfunc infrastructure (see upstream
//! aya-rs issue #432). Every kernel-resident kfunc the programs want
//! to call must therefore be declared manually as an `extern "C"` item
//! so the verifier and the BTF relocator can resolve it at load time.
//!
//! All declarations follow the kernel BTF signatures:
//!
//! | Kfunc | Kernel | BTF signature |
//! |-------|--------|---------------|
//! | `bpf_task_get_cgroup1` | 6.8 | `struct cgroup *(*)(struct task_struct *task, int hierarchy_id) __ksym;` |
//! | `bpf_cgroup_release`   | 6.5 | `void(*)(struct cgroup *cgrp) __ksym;` |
//! | `bpf_xdp_metadata_rx_vlan_tag` | 6.8 | `int(*)(const struct xdp_md *ctx, __be16 *vlan_proto, u16 *vlan_tci) __ksym;` |
//! | `bpf_xdp_get_xfrm_state`       | 6.8 | `struct xfrm_state *(*)(struct xdp_md *ctx, struct bpf_xfrm_state_opts *opts, u32 opts__sz) __ksym;` |
//! | `bpf_xdp_xfrm_state_release`   | 6.8 | `void(*)(struct xfrm_state *x) __ksym;` |
//! | `bpf_iter_css_task_new` / `_next` / `_destroy` | 6.7 | `int(*)(struct bpf_iter_css_task *it, struct cgroup_subsys_state *css, unsigned int flags) __ksym;` … |
//!
//! Kfuncs annotated with `KF_ACQUIRE | KF_RET_NULL` (notably
//! `bpf_task_get_cgroup1` and `bpf_xdp_get_xfrm_state`) must pair
//! every successful call with a release kfunc on every program path,
//! or the verifier will reject the program with a reference leak
//! error. The safe wrappers in this module enforce the pairing via
//! `Drop`-like helper closures.
//!
//! The kernel side is gated behind `#[cfg(target_arch = "bpf")]` so
//! userspace builds ignore the extern declarations (they would
//! otherwise try to link against non-existent symbols on the host).

#![allow(non_camel_case_types)]

/// Opaque kernel types referenced by the kfunc signatures. We only
/// ever hold pointers to them, never dereference them from Rust, so
/// they are declared as ZSTs.
#[repr(C)]
pub struct task_struct {
    _unused: [u8; 0],
}

#[repr(C)]
pub struct cgroup {
    _unused: [u8; 0],
}

#[repr(C)]
pub struct cgroup_subsys_state {
    _unused: [u8; 0],
}

#[repr(C)]
pub struct xfrm_state {
    _unused: [u8; 0],
}

#[repr(C)]
pub struct bpf_iter_css_task {
    _unused: [u8; 0],
}

#[repr(C)]
pub struct bpf_iter_css {
    _unused: [u8; 0],
}

/// Opaque kernel `struct bpf_dynptr` — 16 bytes, 8-byte aligned,
/// layout stable from kernel 6.4+. Programs declare dynptrs on the
/// stack and hand `&mut BpfDynptr` to the `from_{skb,xdp}` kfuncs,
/// which initialise them. Treat the inner field as opaque — the
/// verifier enforces that BPF reads/writes only go through the
/// dedicated helpers.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BpfDynptr {
    pub __opaque: [u64; 2],
}

impl BpfDynptr {
    /// Build a zero-initialised dynptr suitable for passing to a
    /// `from_*` constructor. The kernel rewrites the contents on
    /// success.
    #[must_use]
    pub const fn uninit() -> Self {
        Self { __opaque: [0; 2] }
    }
}

impl Default for BpfDynptr {
    fn default() -> Self {
        Self::uninit()
    }
}

/// `cgroup1` hierarchy id used by Docker. `0` asks the kernel for the
/// default hierarchy.
pub const CGROUP1_HIERARCHY_ID_DEFAULT: i32 = 0;

/// Flags for `bpf_iter_css_new` — see `include/uapi/linux/bpf.h`.
#[repr(u32)]
pub enum CssIterFlags {
    /// Pre-order descendant walk.
    DescendantsPre = 0,
    /// Post-order descendant walk.
    DescendantsPost = 1,
    /// Walk up the ancestor chain.
    AncestorsUp = 2,
}

/// Options struct passed to `bpf_xdp_get_xfrm_state` — stable layout
/// from kernel 6.8 `include/uapi/linux/bpf.h` (`bpf_xfrm_state_opts`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct bpf_xfrm_state_opts {
    pub error: i32,
    pub netns_id: i32,
    pub mark: u32,
    pub daddr: [u8; 16],
    pub spi: u32,
    pub proto: u8,
    pub family: u16,
    pub reserved: u8,
}

// ── kfunc extern declarations ─────────────────────────────────────
//
// These are only emitted for the BPF target so the host build does
// not try to resolve them at link time. When compiled for
// `bpfel-unknown-none` the verifier picks them up from vmlinux BTF.

#[cfg(target_arch = "bpf")]
unsafe extern "C" {
    /// Return the `struct cgroup*` for the cgroup1 hierarchy the task
    /// belongs to. Kernel 6.8. `KF_ACQUIRE | KF_RCU | KF_RET_NULL` —
    /// pair every non-null return with [`bpf_cgroup_release`].
    pub fn bpf_task_get_cgroup1(task: *mut task_struct, hierarchy_id: i32) -> *mut cgroup;

    /// Release a cgroup pointer obtained from
    /// [`bpf_task_get_cgroup1`]. Kernel 6.5+.
    pub fn bpf_cgroup_release(cgrp: *mut cgroup);

    /// Read the hardware-stripped VLAN tag for the current XDP frame.
    /// Kernel 6.8. Returns `0` on success, negative errno otherwise.
    pub fn bpf_xdp_metadata_rx_vlan_tag(
        ctx: *const core::ffi::c_void,
        vlan_proto: *mut u16,
        vlan_tci: *mut u16,
    ) -> i32;

    /// Look up the `xfrm_state` matching the packet. Kernel 6.8.
    /// `KF_ACQUIRE | KF_RET_NULL` — pair with
    /// [`bpf_xdp_xfrm_state_release`].
    pub fn bpf_xdp_get_xfrm_state(
        ctx: *mut core::ffi::c_void,
        opts: *mut bpf_xfrm_state_opts,
        opts_sz: u32,
    ) -> *mut xfrm_state;

    /// Release the `xfrm_state*` acquired via
    /// [`bpf_xdp_get_xfrm_state`].
    pub fn bpf_xdp_xfrm_state_release(x: *mut xfrm_state);

    /// `bpf_iter_css_task_new` — start iterating tasks attached to a
    /// cgroup subsystem state. Kernel 6.7.
    pub fn bpf_iter_css_task_new(
        it: *mut bpf_iter_css_task,
        css: *mut cgroup_subsys_state,
        flags: u32,
    ) -> i32;

    /// `bpf_iter_css_task_next` — advance iterator, returns next task
    /// or null.
    pub fn bpf_iter_css_task_next(it: *mut bpf_iter_css_task) -> *mut task_struct;

    /// `bpf_iter_css_task_destroy` — destroy the iterator.
    pub fn bpf_iter_css_task_destroy(it: *mut bpf_iter_css_task);

    /// `bpf_iter_css_new` — iterate the cgroup tree rooted at `start`.
    pub fn bpf_iter_css_new(
        it: *mut bpf_iter_css,
        start: *mut cgroup_subsys_state,
        flags: u32,
    ) -> i32;

    /// `bpf_iter_css_next` — next cgroup css or null.
    pub fn bpf_iter_css_next(it: *mut bpf_iter_css) -> *mut cgroup_subsys_state;

    /// `bpf_iter_css_destroy` — destroy the iterator.
    pub fn bpf_iter_css_destroy(it: *mut bpf_iter_css);

    // ── Kernel 6.2 RCU + cast plumbing ─────────────────────────
    //
    // These four kfuncs are the prerequisite plumbing for every
    // other kfunc binding in this module that dereferences
    // RCU-protected kernel fields or re-types opaque pointers as
    // PTR_TO_BTF_ID. Kernel 6.2+.

    /// Begin a BPF RCU read-side critical section. Must be paired
    /// with [`bpf_rcu_read_unlock`] on every control-flow path.
    /// Required before dereferencing RCU-protected kernel fields
    /// such as `task->cgroups`, `nf_conn->ct_general`, etc.
    pub fn bpf_rcu_read_lock();

    /// End a BPF RCU read-side critical section opened via
    /// [`bpf_rcu_read_lock`].
    pub fn bpf_rcu_read_unlock();

    /// Re-type an opaque kernel pointer as a read-only
    /// `PTR_TO_BTF_ID` value identified by `btf_id__k`. Lets the
    /// verifier accept direct field reads on structs such as
    /// `nf_conn`, `task_struct`, `sock`, that are otherwise
    /// inaccessible from BPF. Returns a pointer the verifier
    /// treats as read-only; writes are rejected at load time.
    pub fn bpf_rdonly_cast(
        obj__ign: *const core::ffi::c_void,
        btf_id__k: u32,
    ) -> *mut core::ffi::c_void;

    /// Cast a program context pointer (`struct __sk_buff*`,
    /// `struct xdp_md*`, …) back to its kernel-internal type
    /// (`struct sk_buff*`, `struct xdp_buff*`, …) so it can be
    /// handed to kfuncs that take kernel-native context types.
    pub fn bpf_cast_to_kern_ctx(obj: *mut core::ffi::c_void) -> *mut core::ffi::c_void;

    // ── Kernel 6.4 dynptr constructors ────────────────────────
    //
    // dynptrs abstract packet memory regardless of whether the
    // underlying skb is linear, paged, or an XDP_FRAGS buffer. The
    // `__uninit` suffix on the output pointer signals the verifier
    // that the target is a stack-allocated dynptr which the kernel
    // will initialise on success.

    /// Initialise a dynptr over a TC skb. `flags` is reserved and
    /// must be `0`. Kernel 6.4+. Returns `0` on success, negative
    /// errno otherwise.
    pub fn bpf_dynptr_from_skb(skb: *mut core::ffi::c_void, flags: u64, ptr: *mut BpfDynptr)
    -> i32;

    /// Initialise a dynptr over an XDP frame. Kernel 6.4+.
    pub fn bpf_dynptr_from_xdp(xdp: *mut core::ffi::c_void, flags: u64, ptr: *mut BpfDynptr)
    -> i32;

    /// Return a read-only pointer to `buffer__szk` bytes at `offset`
    /// inside the dynptr. If the window lies on a contiguous region
    /// the kernel returns a direct pointer; otherwise it copies the
    /// bytes into `buffer__opt` and returns a pointer to that
    /// scratch buffer. Null return indicates an out-of-range
    /// request. Kernel 6.4+.
    pub fn bpf_dynptr_slice(
        p: *const BpfDynptr,
        offset: u32,
        buffer__opt: *mut core::ffi::c_void,
        buffer__szk: u32,
    ) -> *const core::ffi::c_void;

    /// Like [`bpf_dynptr_slice`] but returns a mutable pointer.
    /// Rejected at load time on read-only dynptrs. Kernel 6.4+.
    pub fn bpf_dynptr_slice_rdwr(
        p: *const BpfDynptr,
        offset: u32,
        buffer__opt: *mut core::ffi::c_void,
        buffer__szk: u32,
    ) -> *mut core::ffi::c_void;

    // ── Kernel 6.5 dynptr accessors ───────────────────────────

    /// Narrow an existing dynptr to the `[start, end)` byte window.
    /// Used to zoom into an L7 payload after L3/L4 parsing. Kernel
    /// 6.5+.
    pub fn bpf_dynptr_adjust(p: *const BpfDynptr, start: u32, end: u32) -> i32;

    /// Return the logical size of the dynptr in bytes. Kernel 6.5+.
    pub fn bpf_dynptr_size(p: *const BpfDynptr) -> u32;

    /// Return `true` when the dynptr was never successfully
    /// initialised or has been invalidated. Kernel 6.5+.
    pub fn bpf_dynptr_is_null(p: *const BpfDynptr) -> bool;

    /// Initialise `clone` from `src` so the two dynptrs can be
    /// advanced independently (e.g. two cursors over the same
    /// HTTP-pipelined payload). Kernel 6.5+.
    pub fn bpf_dynptr_clone(src: *const BpfDynptr, clone: *mut BpfDynptr) -> i32;
}

// ── Host-target stubs ────────────────────────────────────────────
//
// On non-BPF targets (hosts running `cargo test`/`cargo clippy`) the
// linker would otherwise complain about unresolved symbols. These
// stubs return sensible "not available" values so domain tests can
// exercise the safe wrappers without needing a real kernel.

#[cfg(not(target_arch = "bpf"))]
#[allow(clippy::missing_safety_doc)]
pub mod host_stubs {
    use super::{
        bpf_iter_css, bpf_iter_css_task, bpf_xfrm_state_opts, cgroup, cgroup_subsys_state,
        task_struct, xfrm_state,
    };

    pub unsafe fn bpf_task_get_cgroup1(_task: *mut task_struct, _hierarchy_id: i32) -> *mut cgroup {
        core::ptr::null_mut()
    }

    pub unsafe fn bpf_cgroup_release(_cgrp: *mut cgroup) {}

    /// `-ENOTSUP` hardcoded (95 on Linux) so the host build does not
    /// drag in a `libc` dependency.
    const ENOTSUP_NEG: i32 = -95;

    pub unsafe fn bpf_xdp_metadata_rx_vlan_tag(
        _ctx: *const core::ffi::c_void,
        _vlan_proto: *mut u16,
        _vlan_tci: *mut u16,
    ) -> i32 {
        ENOTSUP_NEG
    }

    pub unsafe fn bpf_xdp_get_xfrm_state(
        _ctx: *mut core::ffi::c_void,
        _opts: *mut bpf_xfrm_state_opts,
        _opts_sz: u32,
    ) -> *mut xfrm_state {
        core::ptr::null_mut()
    }

    pub unsafe fn bpf_xdp_xfrm_state_release(_x: *mut xfrm_state) {}

    pub unsafe fn bpf_iter_css_task_new(
        _it: *mut bpf_iter_css_task,
        _css: *mut cgroup_subsys_state,
        _flags: u32,
    ) -> i32 {
        ENOTSUP_NEG
    }

    pub unsafe fn bpf_iter_css_task_next(_it: *mut bpf_iter_css_task) -> *mut task_struct {
        core::ptr::null_mut()
    }

    pub unsafe fn bpf_iter_css_task_destroy(_it: *mut bpf_iter_css_task) {}

    pub unsafe fn bpf_iter_css_new(
        _it: *mut bpf_iter_css,
        _start: *mut cgroup_subsys_state,
        _flags: u32,
    ) -> i32 {
        ENOTSUP_NEG
    }

    pub unsafe fn bpf_iter_css_next(_it: *mut bpf_iter_css) -> *mut cgroup_subsys_state {
        core::ptr::null_mut()
    }

    pub unsafe fn bpf_iter_css_destroy(_it: *mut bpf_iter_css) {}

    // ── Kernel 6.2 plumbing stubs ──

    pub unsafe fn bpf_rcu_read_lock() {}

    pub unsafe fn bpf_rcu_read_unlock() {}

    pub unsafe fn bpf_rdonly_cast(
        obj: *const core::ffi::c_void,
        _btf_id: u32,
    ) -> *mut core::ffi::c_void {
        // Host builds leave the pointer identity — unit tests that
        // pass a non-null ctx can still observe the sentinel back.
        obj.cast_mut()
    }

    pub unsafe fn bpf_cast_to_kern_ctx(obj: *mut core::ffi::c_void) -> *mut core::ffi::c_void {
        obj
    }

    // ── Kernel 6.4/6.5 dynptr stubs ──

    use super::BpfDynptr;

    /// Host-side in-memory dynptr backing buffer used by tests so
    /// the safe wrappers exercise realistic bounds / offset logic
    /// even though no real BPF kernel side is available.
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct HostDynptrBacking {
        pub data: *const u8,
        pub len: u32,
        pub start: u32,
        pub end: u32,
    }

    impl HostDynptrBacking {
        pub const fn empty() -> Self {
            Self {
                data: core::ptr::null(),
                len: 0,
                start: 0,
                end: 0,
            }
        }

        pub fn as_opaque(self) -> [u64; 2] {
            // Pack pointer + range into the two-u64 opaque slot.
            let ptr_bits = self.data as usize as u64;
            let range_bits =
                (u64::from(self.len)) | (u64::from(self.start) << 16) | (u64::from(self.end) << 32);
            [ptr_bits, range_bits]
        }

        pub fn from_opaque(opaque: [u64; 2]) -> Self {
            let ptr = opaque[0] as usize as *const u8;
            let r = opaque[1];
            #[allow(clippy::cast_possible_truncation)]
            let len = (r & 0xFFFF) as u32;
            #[allow(clippy::cast_possible_truncation)]
            let start = ((r >> 16) & 0xFFFF) as u32;
            #[allow(clippy::cast_possible_truncation)]
            let end = ((r >> 32) & 0xFFFF) as u32;
            Self {
                data: ptr,
                len,
                start,
                end,
            }
        }
    }

    /// Install a host-side backing over `bytes` into `ptr`. Used by
    /// the unit tests to feed deterministic bytes through the safe
    /// wrappers. Returns the length stored.
    pub unsafe fn install_host_dynptr(ptr: *mut BpfDynptr, bytes: &[u8]) -> u32 {
        #[allow(clippy::cast_possible_truncation)]
        let len = bytes.len() as u32;
        let backing = HostDynptrBacking {
            data: bytes.as_ptr(),
            len,
            start: 0,
            end: len,
        };
        unsafe { (*ptr).__opaque = backing.as_opaque() };
        len
    }

    pub unsafe fn bpf_dynptr_from_skb(
        _skb: *mut core::ffi::c_void,
        _flags: u64,
        _ptr: *mut BpfDynptr,
    ) -> i32 {
        // Host builds never observe a real skb. Tests drive the
        // dynptr directly via [`install_host_dynptr`].
        0
    }

    pub unsafe fn bpf_dynptr_from_xdp(
        _xdp: *mut core::ffi::c_void,
        _flags: u64,
        _ptr: *mut BpfDynptr,
    ) -> i32 {
        0
    }

    pub unsafe fn bpf_dynptr_slice(
        p: *const BpfDynptr,
        offset: u32,
        buffer_opt: *mut core::ffi::c_void,
        buffer_sz: u32,
    ) -> *const core::ffi::c_void {
        let backing = unsafe { HostDynptrBacking::from_opaque((*p).__opaque) };
        let effective_start = backing.start.saturating_add(offset);
        let end_required = effective_start.saturating_add(buffer_sz);
        if backing.data.is_null() || end_required > backing.end || buffer_sz == 0 {
            return core::ptr::null();
        }
        let src = unsafe { backing.data.add(effective_start as usize) };
        if !buffer_opt.is_null() {
            unsafe {
                core::ptr::copy_nonoverlapping(src, buffer_opt.cast::<u8>(), buffer_sz as usize);
            }
            buffer_opt.cast_const()
        } else {
            src.cast::<core::ffi::c_void>()
        }
    }

    pub unsafe fn bpf_dynptr_slice_rdwr(
        p: *const BpfDynptr,
        offset: u32,
        buffer_opt: *mut core::ffi::c_void,
        buffer_sz: u32,
    ) -> *mut core::ffi::c_void {
        unsafe { bpf_dynptr_slice(p, offset, buffer_opt, buffer_sz).cast_mut() }
    }

    pub unsafe fn bpf_dynptr_adjust(p: *const BpfDynptr, start: u32, end: u32) -> i32 {
        let mut backing = unsafe { HostDynptrBacking::from_opaque((*p).__opaque) };
        if start > end || end > backing.len {
            return -22; // -EINVAL
        }
        backing.start = start;
        backing.end = end;
        unsafe {
            let mut_p = p.cast_mut();
            (*mut_p).__opaque = backing.as_opaque();
        }
        0
    }

    pub unsafe fn bpf_dynptr_size(p: *const BpfDynptr) -> u32 {
        let backing = unsafe { HostDynptrBacking::from_opaque((*p).__opaque) };
        backing.end.saturating_sub(backing.start)
    }

    pub unsafe fn bpf_dynptr_is_null(p: *const BpfDynptr) -> bool {
        let backing = unsafe { HostDynptrBacking::from_opaque((*p).__opaque) };
        backing.data.is_null()
    }

    pub unsafe fn bpf_dynptr_clone(src: *const BpfDynptr, clone: *mut BpfDynptr) -> i32 {
        unsafe {
            (*clone).__opaque = (*src).__opaque;
        }
        0
    }
}

// ── Safe wrappers ────────────────────────────────────────────────
//
// These helpers encode the acquire/release pairing required by the
// verifier so that the programs cannot accidentally leak a reference.
// On the BPF target they call the real kfuncs; on the host target
// they call the no-op stubs so domain-level unit tests keep running.

/// Run `f` with the cgroup1 pointer of the given task. The pointer is
/// released automatically when `f` returns, satisfying `KF_ACQUIRE`.
///
/// Returns `None` when the task has no cgroup1 membership (e.g. on a
/// cgroupv2-only host) or when running in a non-BPF test build.
///
/// # Safety
/// `task` must be a valid pointer obtained from a BPF helper such as
/// `bpf_get_current_task_btf()` (kernel 5.11+). Calling with an
/// arbitrary pointer is undefined behaviour.
#[inline(always)]
pub unsafe fn with_task_cgroup1<F, R>(task: *mut task_struct, f: F) -> Option<R>
where
    F: FnOnce(*mut cgroup) -> R,
{
    #[cfg(target_arch = "bpf")]
    let cgrp = unsafe { bpf_task_get_cgroup1(task, CGROUP1_HIERARCHY_ID_DEFAULT) };
    #[cfg(not(target_arch = "bpf"))]
    let cgrp = unsafe { host_stubs::bpf_task_get_cgroup1(task, CGROUP1_HIERARCHY_ID_DEFAULT) };

    if cgrp.is_null() {
        return None;
    }
    let result = f(cgrp);
    #[cfg(target_arch = "bpf")]
    unsafe {
        bpf_cgroup_release(cgrp);
    }
    #[cfg(not(target_arch = "bpf"))]
    unsafe {
        host_stubs::bpf_cgroup_release(cgrp);
    }
    Some(result)
}

/// Read the hardware-offloaded VLAN tag for the current XDP frame.
/// Returns `(proto, tci)` on success, `None` when the NIC driver
/// does not provide VLAN metadata (`-EOPNOTSUPP`).
///
/// # Safety
/// `ctx` must point to a live `xdp_md` owned by the current XDP
/// program invocation.
#[inline(always)]
pub unsafe fn xdp_rx_vlan_tag(ctx: *const core::ffi::c_void) -> Option<(u16, u16)> {
    let mut proto: u16 = 0;
    let mut tci: u16 = 0;
    #[cfg(target_arch = "bpf")]
    let rc = unsafe { bpf_xdp_metadata_rx_vlan_tag(ctx, &raw mut proto, &raw mut tci) };
    #[cfg(not(target_arch = "bpf"))]
    let rc = unsafe { host_stubs::bpf_xdp_metadata_rx_vlan_tag(ctx, &raw mut proto, &raw mut tci) };
    if rc != 0 {
        return None;
    }
    Some((proto, tci))
}

/// Look up the `xfrm_state` for the packet and hand it to `f`; the
/// state is released automatically when `f` returns.
///
/// # Safety
/// `ctx` must point to a live `xdp_md`.
#[inline(always)]
pub unsafe fn with_xdp_xfrm_state<F, R>(
    ctx: *mut core::ffi::c_void,
    opts: &mut bpf_xfrm_state_opts,
    f: F,
) -> Option<R>
where
    F: FnOnce(*mut xfrm_state) -> R,
{
    #[allow(clippy::cast_possible_truncation)]
    let opts_sz = core::mem::size_of::<bpf_xfrm_state_opts>() as u32;
    #[cfg(target_arch = "bpf")]
    let x = unsafe { bpf_xdp_get_xfrm_state(ctx, opts as *mut _, opts_sz) };
    #[cfg(not(target_arch = "bpf"))]
    let x = unsafe { host_stubs::bpf_xdp_get_xfrm_state(ctx, opts as *mut _, opts_sz) };
    if x.is_null() {
        return None;
    }
    let result = f(x);
    #[cfg(target_arch = "bpf")]
    unsafe {
        bpf_xdp_xfrm_state_release(x);
    }
    #[cfg(not(target_arch = "bpf"))]
    unsafe {
        host_stubs::bpf_xdp_xfrm_state_release(x);
    }
    Some(result)
}

/// Run `f` inside a BPF RCU read-side critical section. Every path
/// out of `f` is guaranteed to call `bpf_rcu_read_unlock`, which is
/// what the verifier enforces for RCU-protected dereferences.
///
/// # Safety
/// The closure must not call helpers / kfuncs that sleep or break
/// the RCU invariant. Callers are responsible for keeping the BPF
/// program inside the verifier's RCU rules (no nested locks, no
/// sleepable helpers).
#[inline(always)]
pub unsafe fn with_rcu_read_lock<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    #[cfg(target_arch = "bpf")]
    unsafe {
        bpf_rcu_read_lock();
    }
    #[cfg(not(target_arch = "bpf"))]
    unsafe {
        host_stubs::bpf_rcu_read_lock();
    }
    let result = f();
    #[cfg(target_arch = "bpf")]
    unsafe {
        bpf_rcu_read_unlock();
    }
    #[cfg(not(target_arch = "bpf"))]
    unsafe {
        host_stubs::bpf_rcu_read_unlock();
    }
    result
}

/// Re-type an opaque kernel pointer as a read-only `PTR_TO_BTF_ID`
/// of the supplied `btf_id`. The returned pointer is only valid for
/// direct field reads from BPF — writes are rejected at load time.
///
/// Returns `None` when the input is null, so callers get a safe
/// option-type instead of a dangling pointer.
///
/// # Safety
/// `obj` must point to a live kernel object of the type identified
/// by `btf_id`. The caller is responsible for supplying a `btf_id`
/// that matches the actual kernel struct — the verifier will reject
/// the program at load time if the type does not exist.
#[inline(always)]
#[must_use]
pub unsafe fn rdonly_cast(
    obj: *const core::ffi::c_void,
    btf_id: u32,
) -> Option<*mut core::ffi::c_void> {
    if obj.is_null() {
        return None;
    }
    #[cfg(target_arch = "bpf")]
    let out = unsafe { bpf_rdonly_cast(obj, btf_id) };
    #[cfg(not(target_arch = "bpf"))]
    let out = unsafe { host_stubs::bpf_rdonly_cast(obj, btf_id) };
    if out.is_null() { None } else { Some(out) }
}

/// Cast a program context pointer (`__sk_buff*` / `xdp_md*`) to its
/// kernel-internal type (`sk_buff*` / `xdp_buff*`) for kfuncs that
/// require the native kernel struct.
///
/// Returns `None` when the input is null.
///
/// # Safety
/// `ctx` must be a live program context pointer owned by the current
/// BPF program invocation.
#[inline(always)]
#[must_use]
pub unsafe fn cast_to_kern_ctx(ctx: *mut core::ffi::c_void) -> Option<*mut core::ffi::c_void> {
    if ctx.is_null() {
        return None;
    }
    #[cfg(target_arch = "bpf")]
    let out = unsafe { bpf_cast_to_kern_ctx(ctx) };
    #[cfg(not(target_arch = "bpf"))]
    let out = unsafe { host_stubs::bpf_cast_to_kern_ctx(ctx) };
    if out.is_null() { None } else { Some(out) }
}

// ── Dynptr safe wrappers ─────────────────────────────────────────
//
// Idiomatic Rust wrappers around the 8 dynptr kfuncs. The core
// invariant is that a `SkbDynptr` / `XdpDynptr` owns a
// stack-allocated `BpfDynptr` initialised by the kernel; the
// wrappers never let callers forge a dynptr or call the accessors
// on an uninitialised one.

/// Dynptr over a TC skb.
#[repr(transparent)]
pub struct SkbDynptr {
    inner: BpfDynptr,
}

impl SkbDynptr {
    /// Initialise a dynptr over the given `__sk_buff` pointer.
    /// Returns `None` when the kfunc reports a non-zero error code.
    ///
    /// # Safety
    /// `skb` must be a live `__sk_buff*` owned by the current TC
    /// program invocation.
    #[inline(always)]
    pub unsafe fn from_skb(skb: *mut core::ffi::c_void) -> Option<Self> {
        let mut inner = BpfDynptr::uninit();
        #[cfg(target_arch = "bpf")]
        let rc = unsafe { bpf_dynptr_from_skb(skb, 0, &raw mut inner) };
        #[cfg(not(target_arch = "bpf"))]
        let rc = unsafe { host_stubs::bpf_dynptr_from_skb(skb, 0, &raw mut inner) };
        if rc != 0 { None } else { Some(Self { inner }) }
    }

    /// Raw reference to the inner kernel dynptr, for kfunc calls
    /// that need a pointer.
    #[inline(always)]
    #[must_use]
    pub fn as_raw(&self) -> *const BpfDynptr {
        &raw const self.inner
    }

    /// Mutable raw reference — required by adjust/clone targets.
    #[inline(always)]
    pub fn as_raw_mut(&mut self) -> *mut BpfDynptr {
        &raw mut self.inner
    }

    /// Read `buffer_sz` bytes at `offset`. Returns `None` when the
    /// window falls outside the dynptr bounds.
    ///
    /// # Safety
    /// `buffer` must point to at least `buffer_sz` writable bytes.
    #[inline(always)]
    pub unsafe fn slice(
        &self,
        offset: u32,
        buffer: *mut core::ffi::c_void,
        buffer_sz: u32,
    ) -> Option<*const core::ffi::c_void> {
        #[cfg(target_arch = "bpf")]
        let out = unsafe { bpf_dynptr_slice(self.as_raw(), offset, buffer, buffer_sz) };
        #[cfg(not(target_arch = "bpf"))]
        let out = unsafe { host_stubs::bpf_dynptr_slice(self.as_raw(), offset, buffer, buffer_sz) };
        if out.is_null() { None } else { Some(out) }
    }

    /// Mutable variant of [`slice`]. Rejected at load time on
    /// read-only dynptrs.
    ///
    /// # Safety
    /// Same contract as [`Self::slice`].
    #[inline(always)]
    pub unsafe fn slice_rdwr(
        &self,
        offset: u32,
        buffer: *mut core::ffi::c_void,
        buffer_sz: u32,
    ) -> Option<*mut core::ffi::c_void> {
        #[cfg(target_arch = "bpf")]
        let out = unsafe { bpf_dynptr_slice_rdwr(self.as_raw(), offset, buffer, buffer_sz) };
        #[cfg(not(target_arch = "bpf"))]
        let out =
            unsafe { host_stubs::bpf_dynptr_slice_rdwr(self.as_raw(), offset, buffer, buffer_sz) };
        if out.is_null() { None } else { Some(out) }
    }

    /// Narrow the visible window to `[start, end)`. Returns `false`
    /// on EINVAL.
    #[inline(always)]
    pub fn adjust(&mut self, start: u32, end: u32) -> bool {
        #[cfg(target_arch = "bpf")]
        let rc = unsafe { bpf_dynptr_adjust(self.as_raw(), start, end) };
        #[cfg(not(target_arch = "bpf"))]
        let rc = unsafe { host_stubs::bpf_dynptr_adjust(self.as_raw(), start, end) };
        rc == 0
    }

    /// Current visible size in bytes.
    #[inline(always)]
    #[must_use]
    pub fn size(&self) -> u32 {
        #[cfg(target_arch = "bpf")]
        let sz = unsafe { bpf_dynptr_size(self.as_raw()) };
        #[cfg(not(target_arch = "bpf"))]
        let sz = unsafe { host_stubs::bpf_dynptr_size(self.as_raw()) };
        sz
    }

    /// True when the dynptr has been invalidated.
    #[inline(always)]
    #[must_use]
    pub fn is_null(&self) -> bool {
        #[cfg(target_arch = "bpf")]
        let b = unsafe { bpf_dynptr_is_null(self.as_raw()) };
        #[cfg(not(target_arch = "bpf"))]
        let b = unsafe { host_stubs::bpf_dynptr_is_null(self.as_raw()) };
        b
    }

    /// Clone into a fresh independent dynptr. Returns `None` on
    /// failure.
    #[inline(always)]
    #[must_use]
    pub fn clone_dynptr(&self) -> Option<Self> {
        let mut dst = BpfDynptr::uninit();
        #[cfg(target_arch = "bpf")]
        let rc = unsafe { bpf_dynptr_clone(self.as_raw(), &raw mut dst) };
        #[cfg(not(target_arch = "bpf"))]
        let rc = unsafe { host_stubs::bpf_dynptr_clone(self.as_raw(), &raw mut dst) };
        if rc != 0 {
            None
        } else {
            Some(Self { inner: dst })
        }
    }

    /// Read a `T` at `offset` using an on-stack scratch buffer.
    /// Transparently handles non-linear skbs. Returns `None` on
    /// out-of-range access.
    ///
    /// # Safety
    /// `T` must be `#[repr(C)]`, `Copy`, and correctly modelled by
    /// the caller — the kernel performs no endianness or alignment
    /// conversion.
    #[inline(always)]
    pub unsafe fn read<T: Copy>(&self, offset: u32) -> Option<T> {
        let mut buf = core::mem::MaybeUninit::<T>::uninit();
        #[allow(clippy::cast_possible_truncation)]
        let sz = core::mem::size_of::<T>() as u32;
        let ptr = unsafe { self.slice(offset, buf.as_mut_ptr().cast(), sz)? };
        // SAFETY: `slice` populated `sz` bytes at `buf`.
        Some(unsafe { core::ptr::read_unaligned(ptr.cast::<T>()) })
    }
}

/// Dynptr over an XDP frame. Same surface as [`SkbDynptr`] — the
/// two are separate types so the caller cannot accidentally pass a
/// skb dynptr to an XDP kfunc or vice versa.
#[repr(transparent)]
pub struct XdpDynptr {
    inner: BpfDynptr,
}

impl XdpDynptr {
    /// Initialise a dynptr over the given `xdp_md` pointer.
    ///
    /// # Safety
    /// `xdp` must be a live `xdp_md*` owned by the current XDP
    /// program invocation.
    #[inline(always)]
    pub unsafe fn from_xdp(xdp: *mut core::ffi::c_void) -> Option<Self> {
        let mut inner = BpfDynptr::uninit();
        #[cfg(target_arch = "bpf")]
        let rc = unsafe { bpf_dynptr_from_xdp(xdp, 0, &raw mut inner) };
        #[cfg(not(target_arch = "bpf"))]
        let rc = unsafe { host_stubs::bpf_dynptr_from_xdp(xdp, 0, &raw mut inner) };
        if rc != 0 { None } else { Some(Self { inner }) }
    }

    #[inline(always)]
    #[must_use]
    pub fn as_raw(&self) -> *const BpfDynptr {
        &raw const self.inner
    }

    #[inline(always)]
    pub fn as_raw_mut(&mut self) -> *mut BpfDynptr {
        &raw mut self.inner
    }

    /// # Safety
    /// `buffer` must point to at least `buffer_sz` writable bytes.
    #[inline(always)]
    pub unsafe fn slice(
        &self,
        offset: u32,
        buffer: *mut core::ffi::c_void,
        buffer_sz: u32,
    ) -> Option<*const core::ffi::c_void> {
        #[cfg(target_arch = "bpf")]
        let out = unsafe { bpf_dynptr_slice(self.as_raw(), offset, buffer, buffer_sz) };
        #[cfg(not(target_arch = "bpf"))]
        let out = unsafe { host_stubs::bpf_dynptr_slice(self.as_raw(), offset, buffer, buffer_sz) };
        if out.is_null() { None } else { Some(out) }
    }

    /// # Safety
    /// `buffer` must point to at least `buffer_sz` writable bytes.
    #[inline(always)]
    pub unsafe fn slice_rdwr(
        &self,
        offset: u32,
        buffer: *mut core::ffi::c_void,
        buffer_sz: u32,
    ) -> Option<*mut core::ffi::c_void> {
        #[cfg(target_arch = "bpf")]
        let out = unsafe { bpf_dynptr_slice_rdwr(self.as_raw(), offset, buffer, buffer_sz) };
        #[cfg(not(target_arch = "bpf"))]
        let out =
            unsafe { host_stubs::bpf_dynptr_slice_rdwr(self.as_raw(), offset, buffer, buffer_sz) };
        if out.is_null() { None } else { Some(out) }
    }

    #[inline(always)]
    pub fn adjust(&mut self, start: u32, end: u32) -> bool {
        #[cfg(target_arch = "bpf")]
        let rc = unsafe { bpf_dynptr_adjust(self.as_raw(), start, end) };
        #[cfg(not(target_arch = "bpf"))]
        let rc = unsafe { host_stubs::bpf_dynptr_adjust(self.as_raw(), start, end) };
        rc == 0
    }

    #[inline(always)]
    #[must_use]
    pub fn size(&self) -> u32 {
        #[cfg(target_arch = "bpf")]
        let sz = unsafe { bpf_dynptr_size(self.as_raw()) };
        #[cfg(not(target_arch = "bpf"))]
        let sz = unsafe { host_stubs::bpf_dynptr_size(self.as_raw()) };
        sz
    }

    #[inline(always)]
    #[must_use]
    pub fn is_null(&self) -> bool {
        #[cfg(target_arch = "bpf")]
        let b = unsafe { bpf_dynptr_is_null(self.as_raw()) };
        #[cfg(not(target_arch = "bpf"))]
        let b = unsafe { host_stubs::bpf_dynptr_is_null(self.as_raw()) };
        b
    }

    #[inline(always)]
    #[must_use]
    pub fn clone_dynptr(&self) -> Option<Self> {
        let mut dst = BpfDynptr::uninit();
        #[cfg(target_arch = "bpf")]
        let rc = unsafe { bpf_dynptr_clone(self.as_raw(), &raw mut dst) };
        #[cfg(not(target_arch = "bpf"))]
        let rc = unsafe { host_stubs::bpf_dynptr_clone(self.as_raw(), &raw mut dst) };
        if rc != 0 {
            None
        } else {
            Some(Self { inner: dst })
        }
    }

    /// # Safety
    /// `T` must be `#[repr(C)]` + `Copy` and correctly modelled.
    #[inline(always)]
    pub unsafe fn read<T: Copy>(&self, offset: u32) -> Option<T> {
        let mut buf = core::mem::MaybeUninit::<T>::uninit();
        #[allow(clippy::cast_possible_truncation)]
        let sz = core::mem::size_of::<T>() as u32;
        let ptr = unsafe { self.slice(offset, buf.as_mut_ptr().cast(), sz)? };
        Some(unsafe { core::ptr::read_unaligned(ptr.cast::<T>()) })
    }
}

#[cfg(all(test, not(target_arch = "bpf")))]
mod tests {
    use super::*;

    #[test]
    fn css_iter_flags_are_stable() {
        assert_eq!(CssIterFlags::DescendantsPre as u32, 0);
        assert_eq!(CssIterFlags::DescendantsPost as u32, 1);
        assert_eq!(CssIterFlags::AncestorsUp as u32, 2);
    }

    #[test]
    fn xfrm_state_opts_layout_is_stable() {
        // Size check guards against accidental drift when bumping the
        // struct fields. Kernel 6.8 `bpf_xfrm_state_opts` adds
        // trailing padding to align to 4 bytes; Rust reproduces the
        // same 40-byte layout. If this ever diverges from the kernel
        // BTF type, the bpf verifier rejects the program at load
        // time with `invalid func unknown#…`.
        assert_eq!(core::mem::size_of::<bpf_xfrm_state_opts>(), 40);
    }

    #[test]
    fn host_stub_vlan_returns_none() {
        let rc = unsafe { xdp_rx_vlan_tag(core::ptr::null()) };
        assert!(rc.is_none());
    }

    #[test]
    fn host_stub_with_task_cgroup1_returns_none() {
        let r = unsafe { with_task_cgroup1::<_, ()>(core::ptr::null_mut(), |_| ()) };
        assert!(r.is_none());
    }

    #[test]
    fn with_rcu_read_lock_returns_closure_value() {
        let out = unsafe { with_rcu_read_lock(|| 42_u32) };
        assert_eq!(out, 42);
    }

    #[test]
    fn with_rcu_read_lock_runs_closure_exactly_once() {
        let mut counter = 0_u32;
        unsafe {
            with_rcu_read_lock(|| {
                counter += 1;
            });
        }
        assert_eq!(counter, 1);
    }

    #[test]
    fn rdonly_cast_rejects_null_input() {
        let out = unsafe { rdonly_cast(core::ptr::null(), 0) };
        assert!(out.is_none());
    }

    #[test]
    fn rdonly_cast_forwards_non_null_pointer() {
        let sentinel: u32 = 0xDEAD_BEEF;
        let ptr: *const core::ffi::c_void = (&raw const sentinel).cast();
        let out = unsafe { rdonly_cast(ptr, 0xABCD) };
        assert!(out.is_some());
    }

    #[test]
    fn cast_to_kern_ctx_rejects_null() {
        let out = unsafe { cast_to_kern_ctx(core::ptr::null_mut()) };
        assert!(out.is_none());
    }

    #[test]
    fn cast_to_kern_ctx_forwards_non_null() {
        let mut sentinel: u64 = 0;
        let ptr: *mut core::ffi::c_void = (&raw mut sentinel).cast();
        let out = unsafe { cast_to_kern_ctx(ptr) };
        assert!(out.is_some());
    }

    // ── Dynptr tests ─────────────────────────────────────────────

    fn make_skb_dynptr_with(bytes: &[u8]) -> SkbDynptr {
        let mut dyn_ptr = SkbDynptr {
            inner: BpfDynptr::uninit(),
        };
        unsafe {
            host_stubs::install_host_dynptr(dyn_ptr.as_raw_mut(), bytes);
        }
        dyn_ptr
    }

    fn make_xdp_dynptr_with(bytes: &[u8]) -> XdpDynptr {
        let mut dyn_ptr = XdpDynptr {
            inner: BpfDynptr::uninit(),
        };
        unsafe {
            host_stubs::install_host_dynptr(dyn_ptr.as_raw_mut(), bytes);
        }
        dyn_ptr
    }

    #[test]
    fn dynptr_layout_is_two_u64() {
        assert_eq!(core::mem::size_of::<BpfDynptr>(), 16);
        assert_eq!(core::mem::align_of::<BpfDynptr>(), 8);
    }

    #[test]
    fn skb_dynptr_read_u16_in_bounds() {
        let bytes: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];
        let dp = make_skb_dynptr_with(&bytes);
        let val: u16 = unsafe { dp.read::<u16>(0).unwrap() };
        // read_unaligned returns the two bytes verbatim; on LE the
        // packed result is 0xADDE.
        assert_eq!(val, 0xADDE);
    }

    #[test]
    fn skb_dynptr_read_out_of_bounds_returns_none() {
        let bytes: [u8; 2] = [0, 0];
        let dp = make_skb_dynptr_with(&bytes);
        let val = unsafe { dp.read::<u32>(0) };
        assert!(val.is_none());
    }

    #[test]
    fn skb_dynptr_size_matches_installed_len() {
        let bytes = [0u8; 42];
        let dp = make_skb_dynptr_with(&bytes);
        assert_eq!(dp.size(), 42);
        assert!(!dp.is_null());
    }

    #[test]
    fn skb_dynptr_adjust_narrows_window() {
        let bytes = [0u8; 100];
        let mut dp = make_skb_dynptr_with(&bytes);
        assert!(dp.adjust(10, 30));
        assert_eq!(dp.size(), 20);
    }

    #[test]
    fn skb_dynptr_adjust_rejects_out_of_range() {
        let bytes = [0u8; 10];
        let mut dp = make_skb_dynptr_with(&bytes);
        assert!(!dp.adjust(0, 99));
    }

    #[test]
    fn skb_dynptr_clone_is_independent() {
        let bytes = [1u8, 2, 3, 4, 5, 6];
        let dp = make_skb_dynptr_with(&bytes);
        let mut clone = dp.clone_dynptr().unwrap();
        assert!(clone.adjust(2, 5));
        assert_eq!(clone.size(), 3);
        assert_eq!(dp.size(), 6);
    }

    #[test]
    fn skb_dynptr_slice_rdwr_returns_same_pointer() {
        let bytes = [0u8; 16];
        let dp = make_skb_dynptr_with(&bytes);
        let mut buf = [0u8; 4];
        let ptr = unsafe { dp.slice_rdwr(0, buf.as_mut_ptr().cast(), 4).unwrap() };
        assert!(!ptr.is_null());
    }

    #[test]
    fn xdp_dynptr_read_respects_adjust() {
        let bytes: [u8; 8] = [0, 0, 0, 0, 0xAA, 0xBB, 0xCC, 0xDD];
        let mut dp = make_xdp_dynptr_with(&bytes);
        assert!(dp.adjust(4, 8));
        let val: u8 = unsafe { dp.read::<u8>(0).unwrap() };
        assert_eq!(val, 0xAA);
        assert_eq!(dp.size(), 4);
    }

    #[test]
    fn xdp_dynptr_clone_preserves_window() {
        let bytes = [0u8; 20];
        let mut dp = make_xdp_dynptr_with(&bytes);
        assert!(dp.adjust(5, 15));
        let clone = dp.clone_dynptr().unwrap();
        assert_eq!(clone.size(), dp.size());
    }

    #[test]
    fn skb_dynptr_from_null_skb_returns_some_on_host() {
        // Host stub always succeeds so the safe wrapper returns
        // an initialised (but empty) dynptr. Real kernel path
        // would return None on failure.
        let dp = unsafe { SkbDynptr::from_skb(core::ptr::null_mut()) };
        assert!(dp.is_some());
        assert!(dp.unwrap().is_null());
    }

    #[test]
    fn xdp_dynptr_from_null_xdp_returns_some_on_host() {
        let dp = unsafe { XdpDynptr::from_xdp(core::ptr::null_mut()) };
        assert!(dp.is_some());
    }

    #[test]
    fn skb_dynptr_slice_zero_size_returns_none() {
        let bytes = [0u8; 4];
        let dp = make_skb_dynptr_with(&bytes);
        let out = unsafe { dp.slice(0, core::ptr::null_mut(), 0) };
        assert!(out.is_none());
    }
}
