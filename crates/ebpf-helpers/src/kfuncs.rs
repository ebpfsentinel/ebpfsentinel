//! Kfunc bindings for kernel 5.18 → 6.9 features used by the eBPF
//! programs.
//!
//! aya-ebpf 0.13 has no native kfunc infrastructure (see upstream
//! aya-rs issue #432). Every kernel-resident kfunc the programs want
//! to call must therefore be declared manually as an `extern "C"` item
//! so the verifier and the BTF relocator can resolve it at load time.
//!
//! All declarations follow the kernel BTF signatures:
//!
//! | Kfunc                                          | Kernel | BTF signature                                                                                                                                    |
//! |------------------------------------------------|--------|--------------------------------------------------------------------------------------------------------------------------------------------------|
//! | `bpf_skb_ct_lookup`                            | 5.18   | `struct nf_conn *(*)(struct __sk_buff *skb, struct bpf_sock_tuple *tuple, u32 tuple__sz, struct bpf_ct_opts *opts, u32 opts__sz) __ksym;`        |
//! | `bpf_xdp_ct_lookup`                            | 5.18   | `struct nf_conn *(*)(struct xdp_md *xdp, struct bpf_sock_tuple *tuple, u32 tuple__sz, struct bpf_ct_opts *opts, u32 opts__sz) __ksym;`           |
//! | `bpf_ct_release`                               | 5.18   | `void(*)(struct nf_conn *nfct) __ksym;`                                                                                                          |
//! | `bpf_skb_ct_alloc`                             | 6.0    | `struct nf_conn___init *(*)(struct __sk_buff *skb, struct bpf_sock_tuple *tuple, u32 tuple__sz, struct bpf_ct_opts *opts, u32 opts__sz) __ksym;` |
//! | `bpf_xdp_ct_alloc`                             | 6.0    | `struct nf_conn___init *(*)(struct xdp_md *xdp, struct bpf_sock_tuple *tuple, u32 tuple__sz, struct bpf_ct_opts *opts, u32 opts__sz) __ksym;`    |
//! | `bpf_ct_insert_entry`                          | 6.0    | `struct nf_conn *(*)(struct nf_conn___init *nfct_i) __ksym;`                                                                                     |
//! | `bpf_ct_set_timeout`                           | 6.0    | `void(*)(struct nf_conn___init *nfct_i, u32 timeout) __ksym;`                                                                                    |
//! | `bpf_ct_change_timeout`                        | 6.0    | `int(*)(struct nf_conn *nfct, u32 timeout) __ksym;`                                                                                              |
//! | `bpf_ct_set_status`                            | 6.0    | `int(*)(const struct nf_conn___init *nfct_i, u32 status) __ksym;`                                                                                |
//! | `bpf_ct_change_status`                         | 6.0    | `int(*)(struct nf_conn *nfct, u32 status) __ksym;`                                                                                               |
//! | `bpf_ct_set_nat_info`                          | 6.1    | `int(*)(struct nf_conn___init *nfct_i, union nf_inet_addr *addr, int port, enum nf_nat_manip_type manip) __ksym;`                                |
//! | `bpf_cgroup_ancestor`                          | 6.0    | `struct cgroup *(*)(struct cgroup *cgrp, int ancestor_level) __ksym;`                                                                            |
//! | `bpf_cgroup_acquire`                           | 6.0    | `struct cgroup *(*)(struct cgroup *cgrp) __ksym;`                                                                                                |
//! | `bpf_task_under_cgroup`                        | 6.1    | `long(*)(struct task_struct *task, struct cgroup *ancestor) __ksym;`                                                                             |
//! | `bpf_rcu_read_lock`                            | 6.2    | `void(*)(void) __ksym;`                                                                                                                          |
//! | `bpf_rcu_read_unlock`                          | 6.2    | `void(*)(void) __ksym;`                                                                                                                          |
//! | `bpf_rdonly_cast`                              | 6.2    | `void *(*)(const void *obj__ign, u32 btf_id__k) __ksym;`                                                                                         |
//! | `bpf_cast_to_kern_ctx`                         | 6.2    | `void *(*)(void *obj) __ksym;`                                                                                                                   |
//! | `bpf_skb_get_xfrm_info`                        | 6.2    | `int(*)(struct __sk_buff *skb, struct bpf_xfrm_info *to) __ksym;`                                                                                |
//! | `bpf_skb_set_xfrm_info`                        | 6.2    | `int(*)(struct __sk_buff *skb, const struct bpf_xfrm_info *from) __ksym;`                                                                        |
//! | `bpf_xdp_metadata_rx_hash`                     | 6.3    | `int(*)(const struct xdp_md *ctx, u32 *hash, u32 *rss_type) __ksym;`                                                                             |
//! | `bpf_xdp_metadata_rx_timestamp`                | 6.3    | `int(*)(const struct xdp_md *ctx, u64 *timestamp) __ksym;`                                                                                       |
//! | `bpf_dynptr_from_skb`                          | 6.4    | `int(*)(struct __sk_buff *skb, u64 flags, struct bpf_dynptr *ptr__uninit) __ksym;`                                                               |
//! | `bpf_dynptr_from_xdp`                          | 6.4    | `int(*)(struct xdp_md *xdp, u64 flags, struct bpf_dynptr *ptr__uninit) __ksym;`                                                                  |
//! | `bpf_dynptr_slice`                             | 6.4    | `void *(*)(const struct bpf_dynptr *p, u32 offset, void *buffer__opt, u32 buffer__szk) __ksym;`                                                  |
//! | `bpf_dynptr_slice_rdwr`                        | 6.4    | `void *(*)(const struct bpf_dynptr *p, u32 offset, void *buffer__opt, u32 buffer__szk) __ksym;`                                                  |
//! | `bpf_skb_get_fou_encap`                        | 6.4    | `int(*)(struct __sk_buff *skb, struct bpf_fou_encap *encap) __ksym;`                                                                             |
//! | `bpf_skb_set_fou_encap`                        | 6.4    | `int(*)(struct __sk_buff *skb, struct bpf_fou_encap *encap, int type) __ksym;`                                                                   |
//! | `bpf_dynptr_adjust`                            | 6.5    | `int(*)(const struct bpf_dynptr *p, u32 start, u32 end) __ksym;`                                                                                 |
//! | `bpf_dynptr_size`                              | 6.5    | `u32(*)(const struct bpf_dynptr *p) __ksym;`                                                                                                     |
//! | `bpf_dynptr_is_null`                           | 6.5    | `bool(*)(const struct bpf_dynptr *p) __ksym;`                                                                                                    |
//! | `bpf_dynptr_clone`                             | 6.5    | `int(*)(const struct bpf_dynptr *src, struct bpf_dynptr *clone__uninit) __ksym;`                                                                 |
//! | `bpf_cgroup_release`                           | 6.5    | `void(*)(struct cgroup *cgrp) __ksym;`                                                                                                           |
//! | `bpf_cgroup_from_id`                           | 6.5    | `struct cgroup *(*)(u64 cgroup_id) __ksym;`                                                                                                      |
//! | `bpf_iter_css_task_new` / `_next` / `_destroy` | 6.7    | `int(*)(struct bpf_iter_css_task *it, struct cgroup_subsys_state *css, unsigned int flags) __ksym;`                                              |
//! | `bpf_iter_css_new` / `_next` / `_destroy`      | 6.7    | `int(*)(struct bpf_iter_css *it, struct cgroup_subsys_state *start, unsigned int flags) __ksym;`                                                 |
//! | `bpf_task_get_cgroup1`                         | 6.8    | `struct cgroup *(*)(struct task_struct *task, int hierarchy_id) __ksym;`                                                                         |
//! | `bpf_xdp_metadata_rx_vlan_tag`                 | 6.8    | `int(*)(const struct xdp_md *ctx, __be16 *vlan_proto, u16 *vlan_tci) __ksym;`                                                                    |
//! | `bpf_xdp_get_xfrm_state`                       | 6.8    | `struct xfrm_state *(*)(struct xdp_md *ctx, struct bpf_xfrm_state_opts *opts, u32 opts__sz) __ksym;`                                             |
//! | `bpf_xdp_xfrm_state_release`                   | 6.8    | `void(*)(struct xfrm_state *x) __ksym;`                                                                                                          |
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
pub struct xfrm_state {
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

/// Opaque kernel `struct nf_conn`.
#[repr(C)]
pub struct nf_conn {
    _unused: [u8; 0],
}

/// Opaque kernel `struct nf_conn___init` — refcount-tagged
/// subtype returned by the `bpf_{skb,xdp}_ct_alloc` kfuncs, kernel
/// 6.0+. The verifier distinguishes it from [`nf_conn`] by BTF type
/// id so that only "not yet inserted" objects can be configured
/// with `bpf_ct_set_*` helpers. `bpf_ct_release` accepts both — the
/// safe wrapper's [`CtBuilder::drop`] relies on that to release
/// un-inserted builders.
#[repr(C)]
pub struct nf_conn_init {
    _unused: [u8; 0],
}

/// `union nf_inet_addr` — 16 bytes, matches both IPv4 `__be32`
/// inside the `ip` arm and IPv6 `__be32[4]` inside the `ip6` arm.
/// We expose a single `[u32; 4]` field and let the helpers below
/// pick the right arm based on the caller's intent.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct NfInetAddr {
    pub addr: [u32; 4],
}

impl NfInetAddr {
    /// Build an IPv4-tagged union from a `__be32` address. The
    /// other three words are zeroed so the kernel never reads
    /// uninitialised memory.
    #[must_use]
    pub const fn v4(addr_be: u32) -> Self {
        Self {
            addr: [addr_be, 0, 0, 0],
        }
    }

    /// Build an IPv6-tagged union from four `__be32` words.
    #[must_use]
    pub const fn v6(addr_be: [u32; 4]) -> Self {
        Self { addr: addr_be }
    }
}

/// `enum nf_nat_manip_type` — selects whether the NAT rewrite
/// applies to the source tuple or the destination tuple.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NfNatManipType {
    /// `NF_NAT_MANIP_SRC` — SNAT, rewrite source address + port.
    Src = 0,
    /// `NF_NAT_MANIP_DST` — DNAT, rewrite destination address +
    /// port.
    Dst = 1,
}

/// `struct bpf_xfrm_info` from `include/uapi/linux/bpf.h`. Stable
/// layout from kernel 6.2 — 8 bytes, used by
/// `bpf_skb_{get,set}_xfrm_info` to steer a TC skb towards a
/// specific `xfrm` interface (`if_id`) on a given `link`. Setting it
/// effectively pushes the packet into a virtual `xfrmi` device the
/// kernel then encrypts via the IPsec policy attached to that
/// interface.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BpfXfrmInfo {
    /// Numeric identifier of the target `xfrm` interface (matches
    /// `ip xfrm interface` `if_id`).
    pub if_id: u32,
    /// `oif` link index (`0` = unconstrained, otherwise a specific
    /// netdev `ifindex`).
    pub link: i32,
}

/// `struct bpf_fou_encap` from `include/uapi/linux/bpf.h`. 4 bytes,
/// network byte order, kernel 6.4+. Used by
/// `bpf_skb_{get,set}_fou_encap` to attach FOU (Foo-over-UDP) or GUE
/// (Generic UDP Encapsulation) encapsulation parameters to a TC
/// egress skb so cloud-overlay tunnels can be built without leaving
/// the kernel.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BpfFouEncap {
    /// Source UDP port (network byte order).
    pub sport: u16,
    /// Destination UDP port (network byte order).
    pub dport: u16,
}

/// `enum bpf_fou_encap_type` selecting the encap flavour passed to
/// [`skb_set_fou_encap`]. Kernel 6.4+.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FouEncapType {
    /// `FOU_BPF_ENCAP_FOU` — plain Foo-over-UDP.
    Fou = 0,
    /// `FOU_BPF_ENCAP_GUE` — Generic UDP Encapsulation.
    Gue = 1,
}

/// `enum xdp_rss_hash_type` bitfield values from `include/net/xdp.h`.
/// The kernel returns a bitwise OR of L3 / L4 protocol bits combined
/// with the type-specific aliases below. `bpf_xdp_metadata_rx_hash`
/// fills these bits in the `rss_type` out-parameter so the BPF
/// program can pick the right rate-limit / load-balancer key.
pub mod xdp_rss_hash_type {
    /// Layer 3: IPv4
    pub const L3_IPV4: u32 = 1 << 0;
    /// Layer 3: IPv6
    pub const L3_IPV6: u32 = 1 << 1;
    /// Layer 3: dynamic header (e.g. tunnel)
    pub const L3_DYNHDR: u32 = 1 << 2;
    /// Layer 4: any
    pub const L4: u32 = 1 << 3;
    /// Layer 4: TCP
    pub const L4_TCP: u32 = 1 << 4;
    /// Layer 4: UDP
    pub const L4_UDP: u32 = 1 << 5;
    /// Layer 4: SCTP
    pub const L4_SCTP: u32 = 1 << 6;
    /// Layer 4: IPsec ESP/AH
    pub const L4_IPSEC: u32 = 1 << 7;
    /// Layer 4: ICMP
    pub const L4_ICMP: u32 = 1 << 8;

    /// Composite alias: no RSS hashing performed by the NIC.
    pub const TYPE_NONE: u32 = 0;
    /// Composite alias: L2-only frame hashing (same as `TYPE_NONE`).
    pub const TYPE_L2: u32 = TYPE_NONE;
    /// Composite alias: L3 IPv4 hashing.
    pub const TYPE_L3_IPV4: u32 = L3_IPV4;
    /// Composite alias: L3 IPv6 hashing.
    pub const TYPE_L3_IPV6: u32 = L3_IPV6;
    /// Composite alias: any L4 hashing flavour.
    pub const TYPE_L4_ANY: u32 = L4;
    /// Composite alias: L4 IPv4 + TCP hashing.
    pub const TYPE_L4_IPV4_TCP: u32 = L3_IPV4 | L4 | L4_TCP;
    /// Composite alias: L4 IPv4 + UDP hashing.
    pub const TYPE_L4_IPV4_UDP: u32 = L3_IPV4 | L4 | L4_UDP;
    /// Composite alias: L4 IPv6 + TCP hashing.
    pub const TYPE_L4_IPV6_TCP: u32 = L3_IPV6 | L4 | L4_TCP;
    /// Composite alias: L4 IPv6 + UDP hashing.
    pub const TYPE_L4_IPV6_UDP: u32 = L3_IPV6 | L4 | L4_UDP;
}

/// `IPS_*` status bit definitions from `include/uapi/linux/netfilter/nf_conntrack_common.h`.
/// Only the subset eBPFsentinel touches is exposed here.
pub mod ips_status {
    /// This is an expected connection (created by nfct helpers).
    pub const EXPECTED: u32 = 0x0001;
    /// Connection has seen traffic in reply direction.
    pub const SEEN_REPLY: u32 = 0x0002;
    /// Connection is confirmed (seen by CT helpers and accepted).
    pub const CONFIRMED: u32 = 0x0008;
    /// Connection is being destroyed — packets are dropped and no
    /// new additions are accepted. Setting this bit on a live
    /// `nf_conn` is the "terminate flow" primitive that IDS
    /// verdicts use to kill misbehaving connections.
    pub const DYING: u32 = 0x0200;
    /// Connection has been assured and will not time out early.
    pub const ASSURED: u32 = 0x0004;
}

/// `bpf_sock_tuple` flavour — picks which union arm the caller
/// populated. The kernel consults `tuple__sz` to pick the arm at
/// runtime, but the type-safety of the Rust wrapper uses this enum
/// to keep callers from passing a mis-sized struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SockTupleFamily {
    Ipv4,
    Ipv6,
}

impl SockTupleFamily {
    /// Size in bytes of the matching arm of `bpf_sock_tuple`.
    #[must_use]
    pub const fn tuple_size(self) -> u32 {
        match self {
            Self::Ipv4 => 12,
            Self::Ipv6 => 36,
        }
    }
}

/// IPv4 layout of `bpf_sock_tuple` from
/// `include/uapi/linux/bpf.h`. All fields are network-byte-order.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct BpfSockTupleIpv4 {
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
}

/// IPv6 layout of `bpf_sock_tuple`. All fields are
/// network-byte-order; the address arrays are stored as four `u32`
/// words matching the kernel union layout.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct BpfSockTupleIpv6 {
    pub saddr: [u32; 4],
    pub daddr: [u32; 4],
    pub sport: u16,
    pub dport: u16,
}

/// `bpf_ct_opts` — kernel 5.18+ layout from
/// `net/netfilter/nf_conntrack_bpf.c`. 12 bytes, padding accounted
/// for via `reserved`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BpfCtOpts {
    /// Network namespace id. `0` means current netns; `-1` means
    /// "any".
    pub netns_id: i32,
    /// Kernel writes the lookup error here (`0` on success, negative
    /// errno otherwise).
    pub error: i32,
    /// L4 protocol (`IPPROTO_TCP`, `IPPROTO_UDP`, …).
    pub l4proto: u8,
    /// Direction: `0` = original tuple, `1` = reply tuple.
    pub dir: u8,
    /// Reserved padding, must be zero.
    pub reserved: [u8; 2],
}

impl BpfCtOpts {
    /// Build an opts struct for a TCP lookup in the current netns.
    #[must_use]
    pub const fn tcp() -> Self {
        Self {
            netns_id: 0,
            error: 0,
            l4proto: 6,
            dir: 0,
            reserved: [0; 2],
        }
    }

    /// Build an opts struct for a UDP lookup in the current netns.
    #[must_use]
    pub const fn udp() -> Self {
        Self {
            netns_id: 0,
            error: 0,
            l4proto: 17,
            dir: 0,
            reserved: [0; 2],
        }
    }
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
    /// Read the hardware-stripped VLAN tag for the current XDP frame.
    /// Kernel 6.8. Returns `0` on success, negative errno otherwise.
    pub fn bpf_xdp_metadata_rx_vlan_tag(
        ctx: *const core::ffi::c_void,
        vlan_proto: *mut u16,
        vlan_tci: *mut u16,
    ) -> i32;

    /// Read the NIC-computed RSS hash for the current XDP frame and
    /// the corresponding `xdp_rss_hash_type` bitmask. Kernel 6.3.
    /// Returns `0` on success, `-EOPNOTSUPP` when the driver lacks
    /// hardware RSS metadata.
    pub fn bpf_xdp_metadata_rx_hash(
        ctx: *const core::ffi::c_void,
        hash: *mut u32,
        rss_type: *mut u32,
    ) -> i32;

    /// Read the hardware RX timestamp (nanoseconds since boot) for
    /// the current XDP frame. Kernel 6.3. Returns `0` on success,
    /// `-EOPNOTSUPP` when the driver lacks hardware timestamping.
    pub fn bpf_xdp_metadata_rx_timestamp(ctx: *const core::ffi::c_void, timestamp: *mut u64)
    -> i32;

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

    // ── Kernel 6.4 dynptr constructors ────────────────────────

    /// Initialise a dynptr over a TC skb. `flags` is reserved and
    /// must be `0`. Kernel 6.4+. Returns `0` on success, negative
    /// errno otherwise.
    pub fn bpf_dynptr_from_skb(skb: *mut core::ffi::c_void, flags: u64, ptr: *mut BpfDynptr)
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

    // ── Kernel 5.18 netfilter conntrack lookup ──────────────────
    //
    // `bpf_skb_ct_lookup` / `bpf_xdp_ct_lookup` query the kernel
    // netfilter conntrack table for a tuple extracted from the
    // current packet. `KF_ACQUIRE | KF_RET_NULL | KF_TRUSTED_ARGS`
    // — every non-null return must be released via
    // [`bpf_ct_release`] on every control-flow path.

    /// Look up the `nf_conn` matching a tuple in the TC skb's
    /// netns.
    pub fn bpf_skb_ct_lookup(
        skb: *mut core::ffi::c_void,
        tuple: *mut core::ffi::c_void,
        tuple_sz: u32,
        opts: *mut BpfCtOpts,
        opts_sz: u32,
    ) -> *mut nf_conn;

    /// Look up the `nf_conn` matching a tuple in the XDP frame's
    /// netns.
    pub fn bpf_xdp_ct_lookup(
        xdp: *mut core::ffi::c_void,
        tuple: *mut core::ffi::c_void,
        tuple_sz: u32,
        opts: *mut BpfCtOpts,
        opts_sz: u32,
    ) -> *mut nf_conn;

    /// Release an `nf_conn*` acquired from `bpf_skb_ct_lookup`,
    /// `bpf_xdp_ct_lookup`, or one of the `_alloc` / `insert_entry`
    /// kfuncs. `KF_RELEASE`. Also accepts `nf_conn___init*` from
    /// the alloc kfuncs — the refcount layout is shared.
    pub fn bpf_ct_release(nfct: *mut nf_conn);

    // ── Kernel 6.0/6.1 conntrack allocate + NAT delegation ─────
    //
    // Alloc returns an `nf_conn___init*` tagged by BTF as
    // "allocated but not yet inserted". The caller configures it
    // via `bpf_ct_set_timeout/set_status/set_nat_info`, then either
    // commits it with `bpf_ct_insert_entry` (which transfers
    // ownership to a live `nf_conn*`) or drops it via
    // `bpf_ct_release`.

    /// Allocate a new conntrack entry for the skb tuple. Kernel
    /// 6.0. Returns `null` on failure, with `opts.error` set.
    pub fn bpf_skb_ct_alloc(
        skb: *mut core::ffi::c_void,
        tuple: *mut core::ffi::c_void,
        tuple_sz: u32,
        opts: *mut BpfCtOpts,
        opts_sz: u32,
    ) -> *mut nf_conn_init;

    /// XDP variant of [`bpf_skb_ct_alloc`]. Kernel 6.0.
    pub fn bpf_xdp_ct_alloc(
        xdp: *mut core::ffi::c_void,
        tuple: *mut core::ffi::c_void,
        tuple_sz: u32,
        opts: *mut BpfCtOpts,
        opts_sz: u32,
    ) -> *mut nf_conn_init;

    /// Commit an allocated `nf_conn___init` into the kernel
    /// conntrack table. Consumes the `___init` reference and
    /// returns a live `nf_conn*` on success (still KF_ACQUIRE —
    /// must be released by the caller). Kernel 6.0.
    pub fn bpf_ct_insert_entry(nfct_i: *mut nf_conn_init) -> *mut nf_conn;

    /// Set the initial timeout (seconds) for an allocated
    /// conntrack entry. Kernel 6.0.
    pub fn bpf_ct_set_timeout(nfct_i: *mut nf_conn_init, timeout: u32);

    /// Update the timeout on an already-inserted conntrack entry.
    /// Kernel 6.0.
    pub fn bpf_ct_change_timeout(nfct: *mut nf_conn, timeout: u32) -> i32;

    /// Set the initial status bitmask (`IPS_*`) on an allocated
    /// conntrack entry. Kernel 6.0.
    pub fn bpf_ct_set_status(nfct_i: *const nf_conn_init, status: u32) -> i32;

    /// Update the status bitmask on an already-inserted conntrack
    /// entry. Kernel 6.0.
    pub fn bpf_ct_change_status(nfct: *mut nf_conn, status: u32) -> i32;

    /// Configure the NAT rewrite info on an allocated conntrack
    /// entry before it is inserted. Kernel 6.1.
    pub fn bpf_ct_set_nat_info(
        nfct_i: *mut nf_conn_init,
        addr: *mut NfInetAddr,
        port: i32,
        manip: i32,
    ) -> i32;

    // ── Kernel 6.2 IPsec interface steering ────────────────────
    //
    // `bpf_skb_{get,set}_xfrm_info` query / install the `xfrm`
    // interface metadata on a TC skb so the kernel routes the
    // packet through the matching `xfrmi` virtual device for
    // IPsec encapsulation.

    /// Read the `xfrm` interface info attached to a TC skb. Kernel
    /// 6.2+. Returns `0` on success, negative errno (typically
    /// `-EINVAL`) when no metadata is present.
    pub fn bpf_skb_get_xfrm_info(skb: *mut core::ffi::c_void, to: *mut BpfXfrmInfo) -> i32;

    /// Install the `xfrm` interface info on a TC skb. Kernel 6.2+.
    /// Returns `0` on success, negative errno otherwise.
    pub fn bpf_skb_set_xfrm_info(skb: *mut core::ffi::c_void, from: *const BpfXfrmInfo) -> i32;

    // ── Kernel 6.4 FOU/GUE overlay encapsulation ───────────────
    //
    // `bpf_skb_{get,set}_fou_encap` query / install Foo-over-UDP
    // (or GUE) encapsulation parameters on a TC egress skb. Used
    // to build cloud-overlay tunnels without leaving the kernel.

    /// Install FOU or GUE encap parameters on a TC skb. `type_` is
    /// the `bpf_fou_encap_type` discriminant. Kernel 6.4+. Returns
    /// `0` on success, negative errno otherwise.
    pub fn bpf_skb_set_fou_encap(
        skb: *mut core::ffi::c_void,
        encap: *mut BpfFouEncap,
        type_: i32,
    ) -> i32;
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
    use super::{bpf_xfrm_state_opts, xfrm_state};

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

    // ── XDP RX hash + timestamp host stubs (kernel 6.3) ──

    use core::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering};

    /// Next observation written by tests via [`host_set_next_xdp_hash`].
    static HOST_NEXT_XDP_HASH: AtomicU32 = AtomicU32::new(0);
    /// Next RSS-type bitmask written by tests via
    /// [`host_set_next_xdp_rss_type`].
    static HOST_NEXT_XDP_RSS_TYPE: AtomicU32 = AtomicU32::new(0);
    /// Injected error for the next `bpf_xdp_metadata_rx_hash` call.
    /// `0` → success.
    static HOST_NEXT_XDP_HASH_ERROR: AtomicI32 = AtomicI32::new(0);
    /// Next timestamp returned by the timestamp stub.
    static HOST_NEXT_XDP_TIMESTAMP: AtomicU64 = AtomicU64::new(0);
    /// Injected error for the next `bpf_xdp_metadata_rx_timestamp`
    /// call. `0` → success.
    static HOST_NEXT_XDP_TIMESTAMP_ERROR: AtomicI32 = AtomicI32::new(0);

    /// Test helper: set the hash + RSS type the next `rx_hash` call
    /// will report. Cleared after consumption.
    pub fn host_set_next_xdp_hash(hash: u32, rss_type: u32) {
        HOST_NEXT_XDP_HASH.store(hash, Ordering::SeqCst);
        HOST_NEXT_XDP_RSS_TYPE.store(rss_type, Ordering::SeqCst);
    }

    /// Test helper: inject an error for the next `rx_hash` call.
    pub fn host_set_next_xdp_hash_error(errno: i32) {
        HOST_NEXT_XDP_HASH_ERROR.store(errno, Ordering::SeqCst);
    }

    /// Test helper: set the timestamp the next `rx_timestamp` call
    /// will report.
    pub fn host_set_next_xdp_timestamp(ts: u64) {
        HOST_NEXT_XDP_TIMESTAMP.store(ts, Ordering::SeqCst);
    }

    /// Test helper: inject an error for the next `rx_timestamp`
    /// call.
    pub fn host_set_next_xdp_timestamp_error(errno: i32) {
        HOST_NEXT_XDP_TIMESTAMP_ERROR.store(errno, Ordering::SeqCst);
    }

    /// Reset every XDP metadata observation atomic so consecutive
    /// tests do not leak state.
    pub fn host_reset_xdp_metadata_state() {
        HOST_NEXT_XDP_HASH.store(0, Ordering::SeqCst);
        HOST_NEXT_XDP_RSS_TYPE.store(0, Ordering::SeqCst);
        HOST_NEXT_XDP_HASH_ERROR.store(0, Ordering::SeqCst);
        HOST_NEXT_XDP_TIMESTAMP.store(0, Ordering::SeqCst);
        HOST_NEXT_XDP_TIMESTAMP_ERROR.store(0, Ordering::SeqCst);
    }

    pub unsafe fn bpf_xdp_metadata_rx_hash(
        _ctx: *const core::ffi::c_void,
        hash: *mut u32,
        rss_type: *mut u32,
    ) -> i32 {
        let err = HOST_NEXT_XDP_HASH_ERROR.swap(0, Ordering::SeqCst);
        if err != 0 {
            return err;
        }
        if !hash.is_null() {
            unsafe { *hash = HOST_NEXT_XDP_HASH.load(Ordering::SeqCst) };
        }
        if !rss_type.is_null() {
            unsafe { *rss_type = HOST_NEXT_XDP_RSS_TYPE.load(Ordering::SeqCst) };
        }
        0
    }

    pub unsafe fn bpf_xdp_metadata_rx_timestamp(
        _ctx: *const core::ffi::c_void,
        timestamp: *mut u64,
    ) -> i32 {
        let err = HOST_NEXT_XDP_TIMESTAMP_ERROR.swap(0, Ordering::SeqCst);
        if err != 0 {
            return err;
        }
        if !timestamp.is_null() {
            unsafe { *timestamp = HOST_NEXT_XDP_TIMESTAMP.load(Ordering::SeqCst) };
        }
        0
    }

    pub unsafe fn bpf_xdp_get_xfrm_state(
        _ctx: *mut core::ffi::c_void,
        _opts: *mut bpf_xfrm_state_opts,
        _opts_sz: u32,
    ) -> *mut xfrm_state {
        core::ptr::null_mut()
    }

    pub unsafe fn bpf_xdp_xfrm_state_release(_x: *mut xfrm_state) {}

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

    // ── Conntrack stubs (kernel 5.18) ──

    use super::{BpfCtOpts, nf_conn};
    use core::sync::atomic::AtomicUsize;

    /// Sentinel pointer returned by the host stub for successful CT
    /// lookups. Points at a fixed static so tests can observe that
    /// the safe wrapper saw a live ref and called release.
    static HOST_NF_CONN_SENTINEL: u8 = 0;
    /// Number of outstanding un-released CT refs. Tests assert this
    /// is `0` after every wrapper call to guarantee the acquire /
    /// release pairing is honoured even on the host target.
    static HOST_CT_LIVE: AtomicUsize = AtomicUsize::new(0);
    /// `errno` override applied on the next CT lookup. `0` means
    /// "return the sentinel"; non-zero forces a null return and
    /// stores the value in `opts.error`.
    static HOST_CT_NEXT_ERROR: AtomicI32 = AtomicI32::new(0);

    /// Test helper: inject a failure for the next CT lookup.
    pub fn host_set_next_ct_error(errno: i32) {
        HOST_CT_NEXT_ERROR.store(errno, Ordering::SeqCst);
    }

    /// Test helper: count of outstanding un-released CT refs. Used
    /// by unit tests to prove the safe wrappers always pair acquire
    /// with release.
    #[must_use]
    pub fn host_ct_live_count() -> usize {
        HOST_CT_LIVE.load(Ordering::SeqCst)
    }

    unsafe fn host_ct_lookup_impl(opts: *mut BpfCtOpts) -> *mut nf_conn {
        let err = HOST_CT_NEXT_ERROR.swap(0, Ordering::SeqCst);
        if err != 0 {
            if !opts.is_null() {
                unsafe { (*opts).error = err };
            }
            return core::ptr::null_mut();
        }
        HOST_CT_LIVE.fetch_add(1, Ordering::SeqCst);
        let sentinel: *const u8 = &raw const HOST_NF_CONN_SENTINEL;
        sentinel.cast_mut().cast::<nf_conn>()
    }

    pub unsafe fn bpf_skb_ct_lookup(
        _skb: *mut core::ffi::c_void,
        _tuple: *mut core::ffi::c_void,
        _tuple_sz: u32,
        opts: *mut BpfCtOpts,
        _opts_sz: u32,
    ) -> *mut nf_conn {
        unsafe { host_ct_lookup_impl(opts) }
    }

    pub unsafe fn bpf_xdp_ct_lookup(
        _xdp: *mut core::ffi::c_void,
        _tuple: *mut core::ffi::c_void,
        _tuple_sz: u32,
        opts: *mut BpfCtOpts,
        _opts_sz: u32,
    ) -> *mut nf_conn {
        unsafe { host_ct_lookup_impl(opts) }
    }

    pub unsafe fn bpf_ct_release(_nfct: *mut nf_conn) {
        HOST_CT_LIVE.fetch_sub(1, Ordering::SeqCst);
    }

    // ── CT allocate + NAT delegation stubs (kernel 6.0/6.1) ──

    use super::{NfInetAddr, NfNatManipType, nf_conn_init};

    /// Sentinel for allocated ___init refs, distinct from the
    /// lookup sentinel so tests can observe which side is live.
    static HOST_NF_CONN_INIT_SENTINEL: u8 = 0;
    /// Count of outstanding `nf_conn___init` refs (builders that
    /// have not been inserted or dropped yet).
    static HOST_CT_INIT_LIVE: AtomicUsize = AtomicUsize::new(0);
    /// Injected alloc error. Non-zero → next alloc returns null
    /// and writes the error code to `opts.error`.
    static HOST_CT_ALLOC_ERROR: AtomicI32 = AtomicI32::new(0);
    /// Injected insert error. Non-zero → insert returns null.
    static HOST_CT_INSERT_ERROR: AtomicI32 = AtomicI32::new(0);
    /// Last observed NAT set: (manip_type_as_i32, port, addr[0]).
    static HOST_LAST_NAT_MANIP: AtomicI32 = AtomicI32::new(-1);
    static HOST_LAST_NAT_PORT: AtomicI32 = AtomicI32::new(-1);
    static HOST_LAST_NAT_ADDR0: AtomicI32 = AtomicI32::new(0);
    /// Last observed timeout written to an `___init` entry.
    static HOST_LAST_INIT_TIMEOUT: AtomicI32 = AtomicI32::new(-1);
    /// Last observed status bitmask written to an `___init`
    /// entry.
    static HOST_LAST_INIT_STATUS: AtomicI32 = AtomicI32::new(-1);
    /// Last observed timeout on a live entry (change_timeout).
    static HOST_LAST_LIVE_TIMEOUT: AtomicI32 = AtomicI32::new(-1);
    /// Last observed status on a live entry (change_status).
    static HOST_LAST_LIVE_STATUS: AtomicI32 = AtomicI32::new(-1);

    pub fn host_set_next_ct_alloc_error(errno: i32) {
        HOST_CT_ALLOC_ERROR.store(errno, Ordering::SeqCst);
    }

    pub fn host_set_next_ct_insert_error(errno: i32) {
        HOST_CT_INSERT_ERROR.store(errno, Ordering::SeqCst);
    }

    #[must_use]
    pub fn host_ct_init_live_count() -> usize {
        HOST_CT_INIT_LIVE.load(Ordering::SeqCst)
    }

    #[must_use]
    pub fn host_last_nat_manip() -> Option<NfNatManipType> {
        match HOST_LAST_NAT_MANIP.load(Ordering::SeqCst) {
            0 => Some(NfNatManipType::Src),
            1 => Some(NfNatManipType::Dst),
            _ => None,
        }
    }

    #[must_use]
    pub fn host_last_nat_port() -> Option<i32> {
        let v = HOST_LAST_NAT_PORT.load(Ordering::SeqCst);
        if v < 0 { None } else { Some(v) }
    }

    #[must_use]
    pub fn host_last_nat_addr0() -> u32 {
        HOST_LAST_NAT_ADDR0.load(Ordering::SeqCst) as u32
    }

    #[must_use]
    pub fn host_last_init_timeout() -> Option<u32> {
        let v = HOST_LAST_INIT_TIMEOUT.load(Ordering::SeqCst);
        if v < 0 { None } else { Some(v as u32) }
    }

    #[must_use]
    pub fn host_last_init_status() -> Option<u32> {
        let v = HOST_LAST_INIT_STATUS.load(Ordering::SeqCst);
        if v < 0 { None } else { Some(v as u32) }
    }

    #[must_use]
    pub fn host_last_live_timeout() -> Option<u32> {
        let v = HOST_LAST_LIVE_TIMEOUT.load(Ordering::SeqCst);
        if v < 0 { None } else { Some(v as u32) }
    }

    #[must_use]
    pub fn host_last_live_status() -> Option<u32> {
        let v = HOST_LAST_LIVE_STATUS.load(Ordering::SeqCst);
        if v < 0 { None } else { Some(v as u32) }
    }

    /// Reset every host-side observation counter so consecutive
    /// tests do not bleed into each other.
    pub fn host_reset_ct_state() {
        HOST_CT_LIVE.store(0, Ordering::SeqCst);
        HOST_CT_INIT_LIVE.store(0, Ordering::SeqCst);
        HOST_CT_NEXT_ERROR.store(0, Ordering::SeqCst);
        HOST_CT_ALLOC_ERROR.store(0, Ordering::SeqCst);
        HOST_CT_INSERT_ERROR.store(0, Ordering::SeqCst);
        HOST_LAST_NAT_MANIP.store(-1, Ordering::SeqCst);
        HOST_LAST_NAT_PORT.store(-1, Ordering::SeqCst);
        HOST_LAST_NAT_ADDR0.store(0, Ordering::SeqCst);
        HOST_LAST_INIT_TIMEOUT.store(-1, Ordering::SeqCst);
        HOST_LAST_INIT_STATUS.store(-1, Ordering::SeqCst);
        HOST_LAST_LIVE_TIMEOUT.store(-1, Ordering::SeqCst);
        HOST_LAST_LIVE_STATUS.store(-1, Ordering::SeqCst);
    }

    unsafe fn host_ct_alloc_impl(opts: *mut BpfCtOpts) -> *mut nf_conn_init {
        let err = HOST_CT_ALLOC_ERROR.swap(0, Ordering::SeqCst);
        if err != 0 {
            if !opts.is_null() {
                unsafe { (*opts).error = err };
            }
            return core::ptr::null_mut();
        }
        HOST_CT_INIT_LIVE.fetch_add(1, Ordering::SeqCst);
        let sentinel: *const u8 = &raw const HOST_NF_CONN_INIT_SENTINEL;
        sentinel.cast_mut().cast::<nf_conn_init>()
    }

    pub unsafe fn bpf_skb_ct_alloc(
        _skb: *mut core::ffi::c_void,
        _tuple: *mut core::ffi::c_void,
        _tuple_sz: u32,
        opts: *mut BpfCtOpts,
        _opts_sz: u32,
    ) -> *mut nf_conn_init {
        unsafe { host_ct_alloc_impl(opts) }
    }

    pub unsafe fn bpf_xdp_ct_alloc(
        _xdp: *mut core::ffi::c_void,
        _tuple: *mut core::ffi::c_void,
        _tuple_sz: u32,
        opts: *mut BpfCtOpts,
        _opts_sz: u32,
    ) -> *mut nf_conn_init {
        unsafe { host_ct_alloc_impl(opts) }
    }

    pub unsafe fn bpf_ct_insert_entry(_nfct_i: *mut nf_conn_init) -> *mut nf_conn {
        let err = HOST_CT_INSERT_ERROR.swap(0, Ordering::SeqCst);
        if err != 0 {
            // insert kept the ___init alive (insert failed), but
            // kernel semantics say insert consumes the ___init
            // even on failure. Model that here.
            HOST_CT_INIT_LIVE.fetch_sub(1, Ordering::SeqCst);
            return core::ptr::null_mut();
        }
        // Transfer: drop one ___init ref, spawn one live nf_conn.
        HOST_CT_INIT_LIVE.fetch_sub(1, Ordering::SeqCst);
        HOST_CT_LIVE.fetch_add(1, Ordering::SeqCst);
        let sentinel: *const u8 = &raw const HOST_NF_CONN_SENTINEL;
        sentinel.cast_mut().cast::<nf_conn>()
    }

    pub unsafe fn bpf_ct_set_timeout(_nfct_i: *mut nf_conn_init, timeout: u32) {
        #[allow(clippy::cast_possible_wrap)]
        HOST_LAST_INIT_TIMEOUT.store(timeout as i32, Ordering::SeqCst);
    }

    pub unsafe fn bpf_ct_change_timeout(_nfct: *mut nf_conn, timeout: u32) -> i32 {
        #[allow(clippy::cast_possible_wrap)]
        HOST_LAST_LIVE_TIMEOUT.store(timeout as i32, Ordering::SeqCst);
        0
    }

    pub unsafe fn bpf_ct_set_status(_nfct_i: *const nf_conn_init, status: u32) -> i32 {
        #[allow(clippy::cast_possible_wrap)]
        HOST_LAST_INIT_STATUS.store(status as i32, Ordering::SeqCst);
        0
    }

    pub unsafe fn bpf_ct_change_status(_nfct: *mut nf_conn, status: u32) -> i32 {
        #[allow(clippy::cast_possible_wrap)]
        HOST_LAST_LIVE_STATUS.store(status as i32, Ordering::SeqCst);
        0
    }

    pub unsafe fn bpf_ct_set_nat_info(
        _nfct_i: *mut nf_conn_init,
        addr: *mut NfInetAddr,
        port: i32,
        manip: i32,
    ) -> i32 {
        HOST_LAST_NAT_MANIP.store(manip, Ordering::SeqCst);
        HOST_LAST_NAT_PORT.store(port, Ordering::SeqCst);
        if !addr.is_null() {
            #[allow(clippy::cast_possible_wrap)]
            HOST_LAST_NAT_ADDR0.store(unsafe { (*addr).addr[0] as i32 }, Ordering::SeqCst);
        }
        0
    }

    /// Host-only helper: release an un-inserted `nf_conn___init`.
    /// The real kernel uses `bpf_ct_release` for both subtypes, but
    /// the host stub bookkeeping separates the two counters for
    /// test assertions so the builder `Drop` routes through this
    /// when it never called `insert_entry`.
    pub unsafe fn host_release_ct_init(_ptr: *mut nf_conn_init) {
        HOST_CT_INIT_LIVE.fetch_sub(1, Ordering::SeqCst);
    }

    // ── Kernel 6.2 xfrm + 6.4 fou encap host stubs ──

    use super::{BpfFouEncap, BpfXfrmInfo};

    /// Sentinel returned by `host_last_xfrm_info_*` when nothing has
    /// been observed. Picked far above any plausible `if_id` so a
    /// real test write is never confused with the unset state.
    const XFRM_LINK_UNSET: i32 = i32::MIN;

    static HOST_LAST_XFRM_IF_ID: AtomicU32 = AtomicU32::new(0);
    static HOST_LAST_XFRM_LINK: AtomicI32 = AtomicI32::new(XFRM_LINK_UNSET);
    static HOST_NEXT_XFRM_IF_ID: AtomicU32 = AtomicU32::new(0);
    static HOST_NEXT_XFRM_LINK: AtomicI32 = AtomicI32::new(0);
    static HOST_NEXT_XFRM_GET_ERROR: AtomicI32 = AtomicI32::new(0);
    static HOST_NEXT_XFRM_SET_ERROR: AtomicI32 = AtomicI32::new(0);

    static HOST_LAST_FOU_SPORT: AtomicU32 = AtomicU32::new(0);
    static HOST_LAST_FOU_DPORT: AtomicU32 = AtomicU32::new(0);
    static HOST_LAST_FOU_TYPE: AtomicI32 = AtomicI32::new(-1);
    static HOST_NEXT_FOU_SPORT: AtomicU32 = AtomicU32::new(0);
    static HOST_NEXT_FOU_DPORT: AtomicU32 = AtomicU32::new(0);
    static HOST_NEXT_FOU_GET_ERROR: AtomicI32 = AtomicI32::new(0);
    static HOST_NEXT_FOU_SET_ERROR: AtomicI32 = AtomicI32::new(0);

    /// Test helper: queue the `BpfXfrmInfo` returned by the next
    /// `skb_get_xfrm_info` call.
    pub fn host_set_next_xfrm_info(if_id: u32, link: i32) {
        HOST_NEXT_XFRM_IF_ID.store(if_id, Ordering::SeqCst);
        HOST_NEXT_XFRM_LINK.store(link, Ordering::SeqCst);
    }

    /// Test helper: inject an error for the next `skb_get_xfrm_info`
    /// call. Cleared after consumption.
    pub fn host_set_next_xfrm_get_error(errno: i32) {
        HOST_NEXT_XFRM_GET_ERROR.store(errno, Ordering::SeqCst);
    }

    /// Test helper: inject an error for the next `skb_set_xfrm_info`
    /// call.
    pub fn host_set_next_xfrm_set_error(errno: i32) {
        HOST_NEXT_XFRM_SET_ERROR.store(errno, Ordering::SeqCst);
    }

    /// Read the last `(if_id, link)` pair written by a successful
    /// `skb_set_xfrm_info` call, `None` when nothing has been
    /// observed since the last reset.
    #[must_use]
    pub fn host_last_xfrm_info() -> Option<(u32, i32)> {
        let link = HOST_LAST_XFRM_LINK.load(Ordering::SeqCst);
        if link == XFRM_LINK_UNSET {
            None
        } else {
            Some((HOST_LAST_XFRM_IF_ID.load(Ordering::SeqCst), link))
        }
    }

    /// Test helper: queue the `BpfFouEncap` returned by the next
    /// `skb_get_fou_encap` call.
    pub fn host_set_next_fou_encap(sport: u16, dport: u16) {
        HOST_NEXT_FOU_SPORT.store(u32::from(sport), Ordering::SeqCst);
        HOST_NEXT_FOU_DPORT.store(u32::from(dport), Ordering::SeqCst);
    }

    /// Test helper: inject an error for the next `skb_get_fou_encap`
    /// call.
    pub fn host_set_next_fou_get_error(errno: i32) {
        HOST_NEXT_FOU_GET_ERROR.store(errno, Ordering::SeqCst);
    }

    /// Test helper: inject an error for the next `skb_set_fou_encap`
    /// call.
    pub fn host_set_next_fou_set_error(errno: i32) {
        HOST_NEXT_FOU_SET_ERROR.store(errno, Ordering::SeqCst);
    }

    /// Read the last `(sport, dport, type)` triple written by a
    /// successful `skb_set_fou_encap` call, `None` when nothing has
    /// been observed since the last reset.
    #[must_use]
    pub fn host_last_fou_encap() -> Option<(u16, u16, i32)> {
        let ty = HOST_LAST_FOU_TYPE.load(Ordering::SeqCst);
        if ty < 0 {
            None
        } else {
            #[allow(clippy::cast_possible_truncation)]
            let sport = HOST_LAST_FOU_SPORT.load(Ordering::SeqCst) as u16;
            #[allow(clippy::cast_possible_truncation)]
            let dport = HOST_LAST_FOU_DPORT.load(Ordering::SeqCst) as u16;
            Some((sport, dport, ty))
        }
    }

    /// Reset every xfrm + fou observation atomic so consecutive
    /// tests do not bleed state.
    pub fn host_reset_xfrm_fou_state() {
        HOST_LAST_XFRM_IF_ID.store(0, Ordering::SeqCst);
        HOST_LAST_XFRM_LINK.store(XFRM_LINK_UNSET, Ordering::SeqCst);
        HOST_NEXT_XFRM_IF_ID.store(0, Ordering::SeqCst);
        HOST_NEXT_XFRM_LINK.store(0, Ordering::SeqCst);
        HOST_NEXT_XFRM_GET_ERROR.store(0, Ordering::SeqCst);
        HOST_NEXT_XFRM_SET_ERROR.store(0, Ordering::SeqCst);
        HOST_LAST_FOU_SPORT.store(0, Ordering::SeqCst);
        HOST_LAST_FOU_DPORT.store(0, Ordering::SeqCst);
        HOST_LAST_FOU_TYPE.store(-1, Ordering::SeqCst);
        HOST_NEXT_FOU_SPORT.store(0, Ordering::SeqCst);
        HOST_NEXT_FOU_DPORT.store(0, Ordering::SeqCst);
        HOST_NEXT_FOU_GET_ERROR.store(0, Ordering::SeqCst);
        HOST_NEXT_FOU_SET_ERROR.store(0, Ordering::SeqCst);
    }

    pub unsafe fn bpf_skb_get_xfrm_info(_skb: *mut core::ffi::c_void, to: *mut BpfXfrmInfo) -> i32 {
        let err = HOST_NEXT_XFRM_GET_ERROR.swap(0, Ordering::SeqCst);
        if err != 0 {
            return err;
        }
        if !to.is_null() {
            unsafe {
                (*to).if_id = HOST_NEXT_XFRM_IF_ID.load(Ordering::SeqCst);
                (*to).link = HOST_NEXT_XFRM_LINK.load(Ordering::SeqCst);
            }
        }
        0
    }

    pub unsafe fn bpf_skb_set_xfrm_info(
        _skb: *mut core::ffi::c_void,
        from: *const BpfXfrmInfo,
    ) -> i32 {
        let err = HOST_NEXT_XFRM_SET_ERROR.swap(0, Ordering::SeqCst);
        if err != 0 {
            return err;
        }
        if !from.is_null() {
            unsafe {
                HOST_LAST_XFRM_IF_ID.store((*from).if_id, Ordering::SeqCst);
                HOST_LAST_XFRM_LINK.store((*from).link, Ordering::SeqCst);
            }
        }
        0
    }

    pub unsafe fn bpf_skb_set_fou_encap(
        _skb: *mut core::ffi::c_void,
        encap: *mut BpfFouEncap,
        type_: i32,
    ) -> i32 {
        let err = HOST_NEXT_FOU_SET_ERROR.swap(0, Ordering::SeqCst);
        if err != 0 {
            return err;
        }
        if !encap.is_null() {
            unsafe {
                HOST_LAST_FOU_SPORT.store(u32::from((*encap).sport), Ordering::SeqCst);
                HOST_LAST_FOU_DPORT.store(u32::from((*encap).dport), Ordering::SeqCst);
            }
            HOST_LAST_FOU_TYPE.store(type_, Ordering::SeqCst);
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

/// NIC-computed RSS hash + corresponding `xdp_rss_hash_type`
/// bitmask for the current XDP frame. Returns `None` when the
/// driver lacks hardware RSS metadata.
///
/// The returned `(hash, rss_type)` tuple lets `xdp-ratelimit` use
/// the hash directly as a bucket key (skipping a CPU FNV pass)
/// and `xdp-loadbalancer` re-use it as the Maglev consistent-hash
/// seed.
///
/// # Safety
/// `ctx` must point to a live `xdp_md` owned by the current XDP
/// program invocation.
#[inline(always)]
#[must_use]
pub unsafe fn xdp_rx_hash(ctx: *const core::ffi::c_void) -> Option<(u32, u32)> {
    let mut hash: u32 = 0;
    let mut rss_type: u32 = 0;
    #[cfg(target_arch = "bpf")]
    let rc = unsafe { bpf_xdp_metadata_rx_hash(ctx, &raw mut hash, &raw mut rss_type) };
    #[cfg(not(target_arch = "bpf"))]
    let rc = unsafe { host_stubs::bpf_xdp_metadata_rx_hash(ctx, &raw mut hash, &raw mut rss_type) };
    if rc != 0 {
        return None;
    }
    Some((hash, rss_type))
}

/// Hardware RX timestamp (nanoseconds since boot) for the current
/// XDP frame. Returns `None` when the driver lacks hardware
/// timestamping. Used by E17 beaconing detection to record arrival
/// times with zero CPU jitter.
///
/// # Safety
/// `ctx` must point to a live `xdp_md` owned by the current XDP
/// program invocation.
#[inline(always)]
#[must_use]
pub unsafe fn xdp_rx_timestamp(ctx: *const core::ffi::c_void) -> Option<u64> {
    let mut ts: u64 = 0;
    #[cfg(target_arch = "bpf")]
    let rc = unsafe { bpf_xdp_metadata_rx_timestamp(ctx, &raw mut ts) };
    #[cfg(not(target_arch = "bpf"))]
    let rc = unsafe { host_stubs::bpf_xdp_metadata_rx_timestamp(ctx, &raw mut ts) };
    if rc != 0 {
        return None;
    }
    Some(ts)
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

// ── Conntrack lookup safe wrappers ──────────────────────────────
//
// The two lookup kfuncs behave identically apart from the context
// type, so callers go through the `with_*_ct_lookup` closures that
// own the acquire/release pairing. Every non-null CT reference is
// released when the closure returns, guaranteeing zero verifier
// "reference leak" errors regardless of the program's control
// flow.

/// Flavoured tuple passed to the CT lookup wrappers. Keeping the
/// tuple owned here ensures callers cannot hand a mis-sized buffer
/// to the kernel.
#[derive(Debug, Clone, Copy)]
pub enum CtTuple {
    Ipv4(BpfSockTupleIpv4),
    Ipv6(BpfSockTupleIpv6),
}

impl CtTuple {
    /// Build a TCP/UDP v4 tuple from host-order fields. The caller
    /// is responsible for swapping to network order before calling
    /// the kernel kfunc.
    #[must_use]
    pub const fn v4(saddr: u32, daddr: u32, sport: u16, dport: u16) -> Self {
        Self::Ipv4(BpfSockTupleIpv4 {
            saddr,
            daddr,
            sport,
            dport,
        })
    }

    /// Build a TCP/UDP v6 tuple.
    #[must_use]
    pub const fn v6(saddr: [u32; 4], daddr: [u32; 4], sport: u16, dport: u16) -> Self {
        Self::Ipv6(BpfSockTupleIpv6 {
            saddr,
            daddr,
            sport,
            dport,
        })
    }

    fn family(&self) -> SockTupleFamily {
        match self {
            Self::Ipv4(_) => SockTupleFamily::Ipv4,
            Self::Ipv6(_) => SockTupleFamily::Ipv6,
        }
    }

    /// Pointer to the underlying `bpf_sock_tuple` union arm.
    fn as_ptr(&mut self) -> *mut core::ffi::c_void {
        match self {
            Self::Ipv4(t) => (t as *mut BpfSockTupleIpv4).cast(),
            Self::Ipv6(t) => (t as *mut BpfSockTupleIpv6).cast(),
        }
    }
}

/// Look up a conntrack entry from a TC skb and hand it to `f`. The
/// `nf_conn` is released before the closure's result is returned,
/// satisfying the `KF_ACQUIRE` contract. `None` is returned when
/// the kernel lookup fails; the error code is written to
/// `opts.error` by the kernel for diagnostics.
///
/// # Safety
/// `skb` must be a live `__sk_buff*` owned by the current TC
/// program invocation.
#[inline(always)]
pub unsafe fn with_skb_ct_lookup<F, R>(
    skb: *mut core::ffi::c_void,
    mut tuple: CtTuple,
    opts: &mut BpfCtOpts,
    f: F,
) -> Option<R>
where
    F: FnOnce(*mut nf_conn) -> R,
{
    let tuple_sz = tuple.family().tuple_size();
    #[allow(clippy::cast_possible_truncation)]
    let opts_sz = core::mem::size_of::<BpfCtOpts>() as u32;
    let tuple_ptr = tuple.as_ptr();
    #[cfg(target_arch = "bpf")]
    let ct = unsafe { bpf_skb_ct_lookup(skb, tuple_ptr, tuple_sz, opts as *mut _, opts_sz) };
    #[cfg(not(target_arch = "bpf"))]
    let ct =
        unsafe { host_stubs::bpf_skb_ct_lookup(skb, tuple_ptr, tuple_sz, opts as *mut _, opts_sz) };
    if ct.is_null() {
        return None;
    }
    let result = f(ct);
    #[cfg(target_arch = "bpf")]
    unsafe {
        bpf_ct_release(ct);
    }
    #[cfg(not(target_arch = "bpf"))]
    unsafe {
        host_stubs::bpf_ct_release(ct);
    }
    Some(result)
}

/// XDP variant of [`with_skb_ct_lookup`].
///
/// # Safety
/// `xdp` must be a live `xdp_md*` owned by the current XDP program
/// invocation.
#[inline(always)]
pub unsafe fn with_xdp_ct_lookup<F, R>(
    xdp: *mut core::ffi::c_void,
    mut tuple: CtTuple,
    opts: &mut BpfCtOpts,
    f: F,
) -> Option<R>
where
    F: FnOnce(*mut nf_conn) -> R,
{
    let tuple_sz = tuple.family().tuple_size();
    #[allow(clippy::cast_possible_truncation)]
    let opts_sz = core::mem::size_of::<BpfCtOpts>() as u32;
    let tuple_ptr = tuple.as_ptr();
    #[cfg(target_arch = "bpf")]
    let ct = unsafe { bpf_xdp_ct_lookup(xdp, tuple_ptr, tuple_sz, opts as *mut _, opts_sz) };
    #[cfg(not(target_arch = "bpf"))]
    let ct =
        unsafe { host_stubs::bpf_xdp_ct_lookup(xdp, tuple_ptr, tuple_sz, opts as *mut _, opts_sz) };
    if ct.is_null() {
        return None;
    }
    let result = f(ct);
    #[cfg(target_arch = "bpf")]
    unsafe {
        bpf_ct_release(ct);
    }
    #[cfg(not(target_arch = "bpf"))]
    unsafe {
        host_stubs::bpf_ct_release(ct);
    }
    Some(result)
}

// ── Conntrack allocate / NAT delegation safe wrappers ─────────
//
// `CtBuilder` owns a `*mut nf_conn___init` acquired from one of
// the `_alloc` kfuncs. Methods configure timeout, status, and NAT
// rewrite info. Dropping the builder without calling `insert` or
// `release` releases the `___init` entry via `bpf_ct_release`,
// which the kernel accepts on both subtypes. Calling `insert`
// consumes the builder and returns a live `*mut nf_conn` on
// success — the caller takes over the release duty and usually
// runs it through one of the `ct_change_*` helpers before calling
// [`ct_release`].

/// Builder holding a freshly allocated `nf_conn___init` reference.
pub struct CtBuilder {
    inner: *mut nf_conn_init,
}

impl CtBuilder {
    /// Allocate a new conntrack entry from a TC skb tuple.
    ///
    /// # Safety
    /// `skb` must be a live `__sk_buff*` owned by the current TC
    /// program invocation.
    #[inline(always)]
    pub unsafe fn from_skb(
        skb: *mut core::ffi::c_void,
        mut tuple: CtTuple,
        opts: &mut BpfCtOpts,
    ) -> Option<Self> {
        let tuple_sz = tuple.family().tuple_size();
        #[allow(clippy::cast_possible_truncation)]
        let opts_sz = core::mem::size_of::<BpfCtOpts>() as u32;
        let tuple_ptr = tuple.as_ptr();
        #[cfg(target_arch = "bpf")]
        let p = unsafe { bpf_skb_ct_alloc(skb, tuple_ptr, tuple_sz, opts as *mut _, opts_sz) };
        #[cfg(not(target_arch = "bpf"))]
        let p = unsafe {
            host_stubs::bpf_skb_ct_alloc(skb, tuple_ptr, tuple_sz, opts as *mut _, opts_sz)
        };
        if p.is_null() {
            None
        } else {
            Some(Self { inner: p })
        }
    }

    /// XDP variant of [`Self::from_skb`].
    ///
    /// # Safety
    /// `xdp` must be a live `xdp_md*` owned by the current XDP
    /// program invocation.
    #[inline(always)]
    pub unsafe fn from_xdp(
        xdp: *mut core::ffi::c_void,
        mut tuple: CtTuple,
        opts: &mut BpfCtOpts,
    ) -> Option<Self> {
        let tuple_sz = tuple.family().tuple_size();
        #[allow(clippy::cast_possible_truncation)]
        let opts_sz = core::mem::size_of::<BpfCtOpts>() as u32;
        let tuple_ptr = tuple.as_ptr();
        #[cfg(target_arch = "bpf")]
        let p = unsafe { bpf_xdp_ct_alloc(xdp, tuple_ptr, tuple_sz, opts as *mut _, opts_sz) };
        #[cfg(not(target_arch = "bpf"))]
        let p = unsafe {
            host_stubs::bpf_xdp_ct_alloc(xdp, tuple_ptr, tuple_sz, opts as *mut _, opts_sz)
        };
        if p.is_null() {
            None
        } else {
            Some(Self { inner: p })
        }
    }

    /// Raw pointer to the underlying `nf_conn___init`. Intended for
    /// kfunc calls only — keep it inside the BPF program scope.
    #[inline(always)]
    #[must_use]
    pub fn as_raw(&self) -> *mut nf_conn_init {
        self.inner
    }

    /// Set the initial timeout (seconds) on the allocated entry.
    #[inline(always)]
    pub fn set_timeout(&mut self, seconds: u32) {
        #[cfg(target_arch = "bpf")]
        unsafe {
            bpf_ct_set_timeout(self.inner, seconds);
        }
        #[cfg(not(target_arch = "bpf"))]
        unsafe {
            host_stubs::bpf_ct_set_timeout(self.inner, seconds);
        }
    }

    /// Set the initial `IPS_*` status bitmask. Returns `false` on
    /// kernel-reported failure.
    #[inline(always)]
    pub fn set_status(&mut self, status: u32) -> bool {
        #[cfg(target_arch = "bpf")]
        let rc = unsafe { bpf_ct_set_status(self.inner, status) };
        #[cfg(not(target_arch = "bpf"))]
        let rc = unsafe { host_stubs::bpf_ct_set_status(self.inner, status) };
        rc == 0
    }

    /// Configure NAT rewrite info for this entry.
    #[inline(always)]
    pub fn set_nat_info(&mut self, mut addr: NfInetAddr, port: u16, manip: NfNatManipType) -> bool {
        #[cfg(target_arch = "bpf")]
        let rc = unsafe {
            bpf_ct_set_nat_info(self.inner, &raw mut addr, i32::from(port), manip as i32)
        };
        #[cfg(not(target_arch = "bpf"))]
        let rc = unsafe {
            host_stubs::bpf_ct_set_nat_info(
                self.inner,
                &raw mut addr,
                i32::from(port),
                manip as i32,
            )
        };
        rc == 0
    }

    /// Commit the builder into the kernel conntrack table,
    /// consuming `self`. On success returns a live `*mut nf_conn`
    /// the caller is responsible for releasing via [`ct_release`].
    /// On failure returns `Err(errno)` — the kernel consumes the
    /// `___init` reference either way, matching `bpf_ct_insert_entry`
    /// semantics.
    #[inline(always)]
    pub fn insert(self) -> Result<CtEntry, i32> {
        let raw = self.inner;
        // Suppress the Drop release; `insert_entry` owns the
        // lifetime from here on.
        let _suppress = core::mem::ManuallyDrop::new(self);
        #[cfg(target_arch = "bpf")]
        let p = unsafe { bpf_ct_insert_entry(raw) };
        #[cfg(not(target_arch = "bpf"))]
        let p = unsafe { host_stubs::bpf_ct_insert_entry(raw) };
        if p.is_null() {
            Err(-1)
        } else {
            Ok(CtEntry { inner: p })
        }
    }
}

impl Drop for CtBuilder {
    fn drop(&mut self) {
        if self.inner.is_null() {
            return;
        }
        #[cfg(target_arch = "bpf")]
        unsafe {
            // Kernel accepts the `___init` subtype on the shared
            // release kfunc because the two share a refcount.
            bpf_ct_release(self.inner.cast::<nf_conn>());
        }
        #[cfg(not(target_arch = "bpf"))]
        unsafe {
            // Host builds split the counters so tests can assert
            // that un-inserted builders release the `___init`
            // counter rather than the live one.
            host_stubs::host_release_ct_init(self.inner);
        }
    }
}

/// Owned live conntrack entry returned by [`CtBuilder::insert`] or
/// caught from a lookup wrapper. Release happens automatically on
/// drop via `bpf_ct_release`.
pub struct CtEntry {
    inner: *mut nf_conn,
}

impl CtEntry {
    /// Raw pointer to the underlying `nf_conn`.
    #[inline(always)]
    #[must_use]
    pub fn as_raw(&self) -> *mut nf_conn {
        self.inner
    }

    /// Update the timeout (seconds) on a live entry.
    #[inline(always)]
    pub fn change_timeout(&mut self, seconds: u32) -> bool {
        #[cfg(target_arch = "bpf")]
        let rc = unsafe { bpf_ct_change_timeout(self.inner, seconds) };
        #[cfg(not(target_arch = "bpf"))]
        let rc = unsafe { host_stubs::bpf_ct_change_timeout(self.inner, seconds) };
        rc == 0
    }

    /// Update the `IPS_*` status bitmask on a live entry. Combined
    /// with `IPS_DYING`, acts as a "terminate this flow" primitive
    /// for IDS verdicts.
    #[inline(always)]
    pub fn change_status(&mut self, status: u32) -> bool {
        #[cfg(target_arch = "bpf")]
        let rc = unsafe { bpf_ct_change_status(self.inner, status) };
        #[cfg(not(target_arch = "bpf"))]
        let rc = unsafe { host_stubs::bpf_ct_change_status(self.inner, status) };
        rc == 0
    }

    /// Mark the flow as dying so the kernel drops subsequent
    /// packets. Equivalent to `change_status(ips_status::DYING)` —
    /// provided as a named method so call sites explicitly document
    /// the IDS verdict semantics.
    #[inline(always)]
    pub fn mark_dying(&mut self) -> bool {
        self.change_status(ips_status::DYING)
    }
}

/// Look up a conntrack entry from a TC skb, mark it as dying, then
/// release it. Packages the three-step kernel dance into a single
/// call so `tc-ids` can terminate a flow verdict in one line. The
/// return value reports whether a matching entry was found and
/// successfully marked; lookups that fail surface via `opts.error`.
///
/// # Safety
/// `skb` must be a live `__sk_buff*` owned by the current TC
/// program invocation.
#[inline(always)]
pub unsafe fn kill_flow_via_skb_ct(
    skb: *mut core::ffi::c_void,
    tuple: CtTuple,
    opts: &mut BpfCtOpts,
) -> bool {
    unsafe {
        with_skb_ct_lookup(skb, tuple, opts, |ct| {
            let mut entry = CtEntry { inner: ct };
            let ok = entry.change_status(ips_status::DYING);
            // Leak the wrapper so Drop doesn't run — the outer
            // `with_skb_ct_lookup` already releases via the kfunc.
            core::mem::forget(entry);
            ok
        })
        .unwrap_or(false)
    }
}

/// XDP variant of [`kill_flow_via_skb_ct`].
///
/// # Safety
/// `xdp` must be a live `xdp_md*` owned by the current XDP program
/// invocation.
#[inline(always)]
pub unsafe fn kill_flow_via_xdp_ct(
    xdp: *mut core::ffi::c_void,
    tuple: CtTuple,
    opts: &mut BpfCtOpts,
) -> bool {
    unsafe {
        with_xdp_ct_lookup(xdp, tuple, opts, |ct| {
            let mut entry = CtEntry { inner: ct };
            let ok = entry.change_status(ips_status::DYING);
            core::mem::forget(entry);
            ok
        })
        .unwrap_or(false)
    }
}

impl Drop for CtEntry {
    fn drop(&mut self) {
        if self.inner.is_null() {
            return;
        }
        #[cfg(target_arch = "bpf")]
        unsafe {
            bpf_ct_release(self.inner);
        }
        #[cfg(not(target_arch = "bpf"))]
        unsafe {
            host_stubs::bpf_ct_release(self.inner);
        }
    }
}

/// Read the `xfrm` interface metadata currently attached to the TC
/// skb. Returns `None` when the kernel reports no metadata
/// (typically `-EINVAL` because the packet has not crossed an
/// `xfrmi` device yet).
///
/// # Safety
/// `skb` must point to a live `__sk_buff` owned by the current TC
/// program invocation.
#[inline(always)]
#[must_use]
pub unsafe fn skb_get_xfrm_info(skb: *mut core::ffi::c_void) -> Option<BpfXfrmInfo> {
    let mut info = BpfXfrmInfo::default();
    #[cfg(target_arch = "bpf")]
    let rc = unsafe { bpf_skb_get_xfrm_info(skb, &raw mut info) };
    #[cfg(not(target_arch = "bpf"))]
    let rc = unsafe { host_stubs::bpf_skb_get_xfrm_info(skb, &raw mut info) };
    if rc != 0 {
        return None;
    }
    Some(info)
}

/// Steer the TC skb through a specific `xfrm` interface. Returns
/// `true` on success. Used by IPsec-aware tc-nat to push traffic
/// into the matching `xfrmi` device for transparent encryption.
///
/// # Safety
/// `skb` must point to a live `__sk_buff` owned by the current TC
/// program invocation.
#[inline(always)]
pub unsafe fn skb_set_xfrm_info(skb: *mut core::ffi::c_void, info: &BpfXfrmInfo) -> bool {
    #[cfg(target_arch = "bpf")]
    let rc = unsafe { bpf_skb_set_xfrm_info(skb, info as *const _) };
    #[cfg(not(target_arch = "bpf"))]
    let rc = unsafe { host_stubs::bpf_skb_set_xfrm_info(skb, info as *const _) };
    rc == 0
}

/// Install FOU or GUE encapsulation parameters on the TC skb so the
/// kernel pushes the packet into a cloud-overlay tunnel without
/// leaving kernel space. Returns `true` on success.
///
/// # Safety
/// `skb` must point to a live `__sk_buff` owned by the current TC
/// program invocation.
#[inline(always)]
pub unsafe fn skb_set_fou_encap(
    skb: *mut core::ffi::c_void,
    encap: &BpfFouEncap,
    encap_type: FouEncapType,
) -> bool {
    let mut encap_copy = *encap;
    let ty = encap_type as i32;
    #[cfg(target_arch = "bpf")]
    let rc = unsafe { bpf_skb_set_fou_encap(skb, &raw mut encap_copy, ty) };
    #[cfg(not(target_arch = "bpf"))]
    let rc = unsafe { host_stubs::bpf_skb_set_fou_encap(skb, &raw mut encap_copy, ty) };
    rc == 0
}

#[cfg(all(test, not(target_arch = "bpf")))]
mod tests {
    use super::*;

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
    fn skb_dynptr_from_null_skb_returns_some_on_host() {
        // Host stub always succeeds so the safe wrapper returns
        // an initialised (but empty) dynptr. Real kernel path
        // would return None on failure.
        let dp = unsafe { SkbDynptr::from_skb(core::ptr::null_mut()) };
        assert!(dp.is_some());
        assert!(dp.unwrap().is_null());
    }

    #[test]
    fn skb_dynptr_slice_zero_size_returns_none() {
        let bytes = [0u8; 4];
        let dp = make_skb_dynptr_with(&bytes);
        let out = unsafe { dp.slice(0, core::ptr::null_mut(), 0) };
        assert!(out.is_none());
    }

    // ── Conntrack lookup tests ─────────────────────────────────────

    #[test]
    fn bpf_ct_opts_layout_is_stable() {
        // 4 (netns_id) + 4 (error) + 1 (l4proto) + 1 (dir) + 2
        // (reserved) = 12 bytes. Rust + repr(C) on this field
        // ordering produces exactly 12 — mismatch means we drifted
        // from the kernel struct and the verifier will reject
        // programs at load time.
        assert_eq!(core::mem::size_of::<BpfCtOpts>(), 12);
        assert_eq!(core::mem::align_of::<BpfCtOpts>(), 4);
    }

    #[test]
    fn sock_tuple_v4_size_is_12_bytes() {
        assert_eq!(core::mem::size_of::<BpfSockTupleIpv4>(), 12);
        assert_eq!(SockTupleFamily::Ipv4.tuple_size(), 12);
    }

    #[test]
    fn sock_tuple_v6_size_is_36_bytes() {
        assert_eq!(core::mem::size_of::<BpfSockTupleIpv6>(), 36);
        assert_eq!(SockTupleFamily::Ipv6.tuple_size(), 36);
    }

    #[test]
    fn ct_opts_helpers_pick_l4_proto() {
        assert_eq!(BpfCtOpts::tcp().l4proto, 6);
        assert_eq!(BpfCtOpts::udp().l4proto, 17);
    }

    #[test]
    fn skb_ct_lookup_success_pairs_acquire_and_release() {
        assert_eq!(host_stubs::host_ct_live_count(), 0);
        let tuple = CtTuple::v4(0x0100_007F, 0x0200_007F, 0x1234, 0x5678);
        let mut opts = BpfCtOpts::tcp();
        let seen = unsafe {
            with_skb_ct_lookup(core::ptr::null_mut(), tuple, &mut opts, |ct| !ct.is_null())
        };
        assert_eq!(seen, Some(true));
        // Post-wrapper: every successful acquire was balanced by a
        // release, so the live counter is back to zero.
        assert_eq!(host_stubs::host_ct_live_count(), 0);
    }

    #[test]
    fn skb_ct_lookup_failure_returns_none() {
        host_stubs::host_set_next_ct_error(-2); // -ENOENT
        let tuple = CtTuple::v4(0, 0, 0, 0);
        let mut opts = BpfCtOpts::tcp();
        let seen = unsafe { with_skb_ct_lookup(core::ptr::null_mut(), tuple, &mut opts, |_| ()) };
        assert!(seen.is_none());
        assert_eq!(opts.error, -2);
        assert_eq!(host_stubs::host_ct_live_count(), 0);
    }

    #[test]
    fn xdp_ct_lookup_uses_ipv6_tuple_size() {
        let tuple = CtTuple::v6([0; 4], [1; 4], 443, 12345);
        let mut opts = BpfCtOpts::udp();
        let seen = unsafe {
            with_xdp_ct_lookup(core::ptr::null_mut(), tuple, &mut opts, |ct| !ct.is_null())
        };
        assert_eq!(seen, Some(true));
        assert_eq!(host_stubs::host_ct_live_count(), 0);
    }

    #[test]
    fn xdp_ct_lookup_propagates_error_to_opts() {
        host_stubs::host_set_next_ct_error(-16); // -EBUSY
        let tuple = CtTuple::v4(0, 0, 0, 0);
        let mut opts = BpfCtOpts::tcp();
        let seen = unsafe { with_xdp_ct_lookup(core::ptr::null_mut(), tuple, &mut opts, |_| ()) };
        assert!(seen.is_none());
        assert_eq!(opts.error, -16);
    }

    // ── CT alloc / NAT delegation tests ───────────────────────────

    #[test]
    fn nf_inet_addr_helpers_pack_correctly() {
        let v4 = NfInetAddr::v4(0xDEAD_BEEF);
        assert_eq!(v4.addr, [0xDEAD_BEEF, 0, 0, 0]);
        let v6 = NfInetAddr::v6([1, 2, 3, 4]);
        assert_eq!(v6.addr, [1, 2, 3, 4]);
    }

    #[test]
    fn nf_nat_manip_type_discriminants_match_kernel() {
        assert_eq!(NfNatManipType::Src as i32, 0);
        assert_eq!(NfNatManipType::Dst as i32, 1);
    }

    #[test]
    fn ct_builder_drop_releases_init_ref() {
        host_stubs::host_reset_ct_state();
        {
            let tuple = CtTuple::v4(0, 0, 0, 0);
            let mut opts = BpfCtOpts::tcp();
            let _builder =
                unsafe { CtBuilder::from_skb(core::ptr::null_mut(), tuple, &mut opts).unwrap() };
            assert_eq!(host_stubs::host_ct_init_live_count(), 1);
        }
        assert_eq!(host_stubs::host_ct_init_live_count(), 0);
    }

    #[test]
    fn ct_builder_alloc_failure_returns_none() {
        host_stubs::host_reset_ct_state();
        host_stubs::host_set_next_ct_alloc_error(-12); // -ENOMEM
        let tuple = CtTuple::v4(0, 0, 0, 0);
        let mut opts = BpfCtOpts::tcp();
        let builder = unsafe { CtBuilder::from_skb(core::ptr::null_mut(), tuple, &mut opts) };
        assert!(builder.is_none());
        assert_eq!(opts.error, -12);
        assert_eq!(host_stubs::host_ct_init_live_count(), 0);
    }

    #[test]
    fn ct_builder_set_timeout_and_status_propagate() {
        host_stubs::host_reset_ct_state();
        let tuple = CtTuple::v4(0, 0, 0, 0);
        let mut opts = BpfCtOpts::tcp();
        let mut builder =
            unsafe { CtBuilder::from_skb(core::ptr::null_mut(), tuple, &mut opts).unwrap() };
        builder.set_timeout(120);
        assert!(builder.set_status(0x08 /* IPS_CONFIRMED */));
        assert_eq!(host_stubs::host_last_init_timeout(), Some(120));
        assert_eq!(host_stubs::host_last_init_status(), Some(0x08));
    }

    #[test]
    fn ct_builder_set_nat_info_captures_manip_addr_port() {
        host_stubs::host_reset_ct_state();
        let tuple = CtTuple::v4(0, 0, 0, 0);
        let mut opts = BpfCtOpts::tcp();
        let mut builder =
            unsafe { CtBuilder::from_skb(core::ptr::null_mut(), tuple, &mut opts).unwrap() };
        let addr = NfInetAddr::v4(0xC0A8_0001);
        assert!(builder.set_nat_info(addr, 8080, NfNatManipType::Dst));
        assert_eq!(host_stubs::host_last_nat_manip(), Some(NfNatManipType::Dst));
        assert_eq!(host_stubs::host_last_nat_port(), Some(8080));
        assert_eq!(host_stubs::host_last_nat_addr0(), 0xC0A8_0001);
    }

    #[test]
    fn ct_builder_insert_transfers_ownership() {
        host_stubs::host_reset_ct_state();
        let tuple = CtTuple::v4(0, 0, 0, 0);
        let mut opts = BpfCtOpts::tcp();
        let builder =
            unsafe { CtBuilder::from_skb(core::ptr::null_mut(), tuple, &mut opts).unwrap() };
        assert_eq!(host_stubs::host_ct_init_live_count(), 1);
        let entry = builder.insert().expect("insert must succeed");
        assert_eq!(host_stubs::host_ct_init_live_count(), 0);
        assert_eq!(host_stubs::host_ct_live_count(), 1);
        drop(entry);
        assert_eq!(host_stubs::host_ct_live_count(), 0);
    }

    #[test]
    fn ct_builder_insert_failure_consumes_init_ref() {
        host_stubs::host_reset_ct_state();
        host_stubs::host_set_next_ct_insert_error(-22);
        let tuple = CtTuple::v4(0, 0, 0, 0);
        let mut opts = BpfCtOpts::tcp();
        let builder =
            unsafe { CtBuilder::from_skb(core::ptr::null_mut(), tuple, &mut opts).unwrap() };
        let err = match builder.insert() {
            Ok(_) => panic!("insert must fail when -EINVAL is injected"),
            Err(e) => e,
        };
        assert_ne!(err, 0);
        assert_eq!(host_stubs::host_ct_init_live_count(), 0);
        assert_eq!(host_stubs::host_ct_live_count(), 0);
    }

    #[test]
    fn ct_entry_change_timeout_and_status_propagate() {
        host_stubs::host_reset_ct_state();
        let tuple = CtTuple::v4(0, 0, 0, 0);
        let mut opts = BpfCtOpts::tcp();
        let builder =
            unsafe { CtBuilder::from_skb(core::ptr::null_mut(), tuple, &mut opts).unwrap() };
        let mut entry = builder.insert().unwrap();
        assert!(entry.change_timeout(600));
        assert!(entry.change_status(0x0200 /* IPS_DYING */));
        assert_eq!(host_stubs::host_last_live_timeout(), Some(600));
        assert_eq!(host_stubs::host_last_live_status(), Some(0x0200));
        drop(entry);
        assert_eq!(host_stubs::host_ct_live_count(), 0);
    }

    #[test]
    fn xdp_ct_builder_drop_releases_init_ref() {
        host_stubs::host_reset_ct_state();
        {
            let tuple = CtTuple::v6([0; 4], [0; 4], 0, 0);
            let mut opts = BpfCtOpts::udp();
            let _builder =
                unsafe { CtBuilder::from_xdp(core::ptr::null_mut(), tuple, &mut opts).unwrap() };
            assert_eq!(host_stubs::host_ct_init_live_count(), 1);
        }
        assert_eq!(host_stubs::host_ct_init_live_count(), 0);
    }

    // ── IDS kill-flow-via-CT tests ────────────────────────────────

    #[test]
    fn ips_status_constants_match_kernel() {
        assert_eq!(ips_status::EXPECTED, 0x0001);
        assert_eq!(ips_status::SEEN_REPLY, 0x0002);
        assert_eq!(ips_status::ASSURED, 0x0004);
        assert_eq!(ips_status::CONFIRMED, 0x0008);
        assert_eq!(ips_status::DYING, 0x0200);
    }

    #[test]
    fn ct_entry_mark_dying_sets_ips_dying_status() {
        host_stubs::host_reset_ct_state();
        let tuple = CtTuple::v4(0, 0, 0, 0);
        let mut opts = BpfCtOpts::tcp();
        let builder =
            unsafe { CtBuilder::from_skb(core::ptr::null_mut(), tuple, &mut opts).unwrap() };
        let mut entry = builder.insert().unwrap();
        assert!(entry.mark_dying());
        assert_eq!(host_stubs::host_last_live_status(), Some(ips_status::DYING));
        drop(entry);
        assert_eq!(host_stubs::host_ct_live_count(), 0);
    }

    #[test]
    fn kill_flow_via_skb_ct_marks_dying_and_releases() {
        host_stubs::host_reset_ct_state();
        let tuple = CtTuple::v4(0x0100_007F, 0x0200_007F, 443, 12345);
        let mut opts = BpfCtOpts::tcp();
        let killed = unsafe { kill_flow_via_skb_ct(core::ptr::null_mut(), tuple, &mut opts) };
        assert!(killed);
        assert_eq!(host_stubs::host_last_live_status(), Some(ips_status::DYING));
        // Lookup + release balanced even though we called
        // change_status inside.
        assert_eq!(host_stubs::host_ct_live_count(), 0);
    }

    #[test]
    fn kill_flow_via_skb_ct_returns_false_on_lookup_miss() {
        host_stubs::host_reset_ct_state();
        host_stubs::host_set_next_ct_error(-2); // -ENOENT
        let tuple = CtTuple::v4(0, 0, 0, 0);
        let mut opts = BpfCtOpts::tcp();
        let killed = unsafe { kill_flow_via_skb_ct(core::ptr::null_mut(), tuple, &mut opts) };
        assert!(!killed);
        // status should not have been touched.
        assert_eq!(host_stubs::host_last_live_status(), None);
    }

    #[test]
    fn kill_flow_via_xdp_ct_marks_dying() {
        host_stubs::host_reset_ct_state();
        let tuple = CtTuple::v6([0; 4], [1; 4], 80, 33333);
        let mut opts = BpfCtOpts::tcp();
        let killed = unsafe { kill_flow_via_xdp_ct(core::ptr::null_mut(), tuple, &mut opts) };
        assert!(killed);
        assert_eq!(host_stubs::host_last_live_status(), Some(ips_status::DYING));
        assert_eq!(host_stubs::host_ct_live_count(), 0);
    }

    // ── XDP RX hash + timestamp tests ────────────────────────────

    #[test]
    fn xdp_rss_hash_type_constants_match_kernel() {
        assert_eq!(xdp_rss_hash_type::L3_IPV4, 1);
        assert_eq!(xdp_rss_hash_type::L3_IPV6, 2);
        assert_eq!(xdp_rss_hash_type::L4, 8);
        assert_eq!(xdp_rss_hash_type::L4_TCP, 16);
        assert_eq!(xdp_rss_hash_type::L4_UDP, 32);
        assert_eq!(
            xdp_rss_hash_type::TYPE_L4_IPV4_TCP,
            xdp_rss_hash_type::L3_IPV4 | xdp_rss_hash_type::L4 | xdp_rss_hash_type::L4_TCP
        );
        assert_eq!(
            xdp_rss_hash_type::TYPE_L4_IPV6_UDP,
            xdp_rss_hash_type::L3_IPV6 | xdp_rss_hash_type::L4 | xdp_rss_hash_type::L4_UDP
        );
        assert_eq!(xdp_rss_hash_type::TYPE_NONE, 0);
        assert_eq!(xdp_rss_hash_type::TYPE_L2, xdp_rss_hash_type::TYPE_NONE);
    }

    #[test]
    fn xdp_rx_hash_returns_injected_value() {
        host_stubs::host_reset_xdp_metadata_state();
        host_stubs::host_set_next_xdp_hash(0xDEAD_BEEF, xdp_rss_hash_type::TYPE_L4_IPV4_TCP);
        let out = unsafe { xdp_rx_hash(core::ptr::null()) };
        assert_eq!(
            out,
            Some((0xDEAD_BEEF, xdp_rss_hash_type::TYPE_L4_IPV4_TCP))
        );
    }

    #[test]
    fn xdp_rx_hash_returns_none_on_eopnotsupp() {
        host_stubs::host_reset_xdp_metadata_state();
        host_stubs::host_set_next_xdp_hash_error(-95);
        let out = unsafe { xdp_rx_hash(core::ptr::null()) };
        assert!(out.is_none());
    }

    #[test]
    fn xdp_rx_hash_clears_error_after_consumption() {
        host_stubs::host_reset_xdp_metadata_state();
        host_stubs::host_set_next_xdp_hash_error(-95);
        // First call swallows the error.
        let _ = unsafe { xdp_rx_hash(core::ptr::null()) };
        // Second call must not still report failure.
        host_stubs::host_set_next_xdp_hash(7, xdp_rss_hash_type::TYPE_L3_IPV4);
        let out = unsafe { xdp_rx_hash(core::ptr::null()) };
        assert_eq!(out, Some((7, xdp_rss_hash_type::TYPE_L3_IPV4)));
    }

    #[test]
    fn xdp_rx_timestamp_returns_injected_value() {
        host_stubs::host_reset_xdp_metadata_state();
        host_stubs::host_set_next_xdp_timestamp(1_700_000_000_000_000_000);
        let out = unsafe { xdp_rx_timestamp(core::ptr::null()) };
        assert_eq!(out, Some(1_700_000_000_000_000_000));
    }

    #[test]
    fn xdp_rx_timestamp_returns_none_on_eopnotsupp() {
        host_stubs::host_reset_xdp_metadata_state();
        host_stubs::host_set_next_xdp_timestamp_error(-95);
        let out = unsafe { xdp_rx_timestamp(core::ptr::null()) };
        assert!(out.is_none());
    }

    #[test]
    fn xdp_rx_timestamp_clears_error_after_consumption() {
        host_stubs::host_reset_xdp_metadata_state();
        host_stubs::host_set_next_xdp_timestamp_error(-95);
        let _ = unsafe { xdp_rx_timestamp(core::ptr::null()) };
        host_stubs::host_set_next_xdp_timestamp(42);
        let out = unsafe { xdp_rx_timestamp(core::ptr::null()) };
        assert_eq!(out, Some(42));
    }

    // ── xfrm + FOU/GUE encap tests ──────────────────────────────

    #[test]
    fn xfrm_info_layout_is_8_bytes() {
        // u32 if_id + i32 link → 8 bytes packed, no trailing pad.
        assert_eq!(core::mem::size_of::<BpfXfrmInfo>(), 8);
        assert_eq!(core::mem::align_of::<BpfXfrmInfo>(), 4);
    }

    #[test]
    fn fou_encap_layout_is_4_bytes() {
        // __be16 sport + __be16 dport → 4 bytes.
        assert_eq!(core::mem::size_of::<BpfFouEncap>(), 4);
        assert_eq!(core::mem::align_of::<BpfFouEncap>(), 2);
    }

    #[test]
    fn fou_encap_type_discriminants_match_kernel() {
        assert_eq!(FouEncapType::Fou as i32, 0);
        assert_eq!(FouEncapType::Gue as i32, 1);
    }

    #[test]
    fn skb_get_xfrm_info_returns_injected_value() {
        host_stubs::host_reset_xfrm_fou_state();
        host_stubs::host_set_next_xfrm_info(42, 7);
        let info = unsafe { skb_get_xfrm_info(core::ptr::null_mut()) };
        assert_eq!(info, Some(BpfXfrmInfo { if_id: 42, link: 7 }));
    }

    #[test]
    fn skb_get_xfrm_info_returns_none_on_einval() {
        host_stubs::host_reset_xfrm_fou_state();
        host_stubs::host_set_next_xfrm_get_error(-22);
        let info = unsafe { skb_get_xfrm_info(core::ptr::null_mut()) };
        assert!(info.is_none());
    }

    #[test]
    fn skb_set_xfrm_info_records_last_value() {
        host_stubs::host_reset_xfrm_fou_state();
        let info = BpfXfrmInfo {
            if_id: 100,
            link: 3,
        };
        let ok = unsafe { skb_set_xfrm_info(core::ptr::null_mut(), &info) };
        assert!(ok);
        assert_eq!(host_stubs::host_last_xfrm_info(), Some((100, 3)));
    }

    #[test]
    fn skb_set_xfrm_info_returns_false_on_error() {
        host_stubs::host_reset_xfrm_fou_state();
        host_stubs::host_set_next_xfrm_set_error(-1);
        let info = BpfXfrmInfo::default();
        let ok = unsafe { skb_set_xfrm_info(core::ptr::null_mut(), &info) };
        assert!(!ok);
        assert_eq!(host_stubs::host_last_xfrm_info(), None);
    }

    #[test]
    fn xfrm_info_get_set_roundtrip_preserves_values() {
        host_stubs::host_reset_xfrm_fou_state();
        let original = BpfXfrmInfo {
            if_id: 555,
            link: -1,
        };
        assert!(unsafe { skb_set_xfrm_info(core::ptr::null_mut(), &original) });
        // Feed the same pair back through the get path so the
        // wrapper's read side is exercised end-to-end.
        host_stubs::host_set_next_xfrm_info(original.if_id, original.link);
        let echoed = unsafe { skb_get_xfrm_info(core::ptr::null_mut()) };
        assert_eq!(echoed, Some(original));
    }

    #[test]
    fn skb_set_fou_encap_records_ports_and_type() {
        host_stubs::host_reset_xfrm_fou_state();
        let encap = BpfFouEncap {
            sport: 0xAAAA,
            dport: 0xBBBB,
        };
        let ok = unsafe { skb_set_fou_encap(core::ptr::null_mut(), &encap, FouEncapType::Gue) };
        assert!(ok);
        assert_eq!(
            host_stubs::host_last_fou_encap(),
            Some((0xAAAA, 0xBBBB, FouEncapType::Gue as i32))
        );
    }

    #[test]
    fn skb_set_fou_encap_returns_false_on_error() {
        host_stubs::host_reset_xfrm_fou_state();
        host_stubs::host_set_next_fou_set_error(-1);
        let encap = BpfFouEncap::default();
        let ok = unsafe { skb_set_fou_encap(core::ptr::null_mut(), &encap, FouEncapType::Fou) };
        assert!(!ok);
        assert_eq!(host_stubs::host_last_fou_encap(), None);
    }
}
