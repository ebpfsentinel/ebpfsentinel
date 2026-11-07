#![no_std]
#![no_main]
#![cfg_attr(target_arch = "bpf", feature(asm_experimental_arch))]

use aya_ebpf::helpers::generated::bpf_probe_read_kernel;
use aya_ebpf::{
    bindings::TC_ACT_OK,
    btf_maps::{Array, PerCpuArray},
    macros::{btf_map, classifier},
    programs::TcContext,
};
use ebpf_common::conntrack::{
    CT_METRIC_COUNT, CT_METRIC_ERRORS, CT_METRIC_KFUNC_HITS, CT_METRIC_KFUNC_LOOKUPS,
    CT_METRIC_KFUNC_MARKED, CT_METRIC_KFUNC_MISSES, CT_METRIC_KFUNC_READ_ERRORS,
    CT_METRIC_KFUNC_STATE_ESTABLISHED, CT_METRIC_KFUNC_STATE_INVALID, CT_METRIC_KFUNC_STATE_NEW,
    CT_METRIC_KFUNC_STATE_RELATED, CT_METRIC_TOTAL_SEEN, ConnTrackConfig, IPS_CONFIRMED, IPS_DYING,
    IPS_EXPECTED, IPS_SEEN_REPLY, NfConnOffsets,
};
use ebpf_helpers::kfuncs::{BpfCtOpts, CtTuple, with_skb_ct_lookup};
use ebpf_helpers::net::{
    IPV6_HDR_LEN, Ipv6Hdr, PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP, ipv6_addr_to_u32x4,
    u16_from_be_bytes, u32_from_be_bytes,
};
use ebpf_helpers::pktmeta;
use ebpf_helpers::raw_skb;
use ebpf_helpers::tc::{ptr_at, skip_ipv6_ext_headers};
use ebpf_helpers::trace::{self, reason, stage};
use ebpf_helpers::{copy_16b_asm, increment_metric};
use network_types::{ip::Ipv4Hdr, tcp::TcpHdr, udp::UdpHdr};

// ── Maps ────────────────────────────────────────────────────────────

/// Conntrack configuration (timeouts, enable flag).
#[btf_map]
static CT_CONFIG: Array<ConnTrackConfig, 1> = Array::new();

/// Per-CPU conntrack metrics.
#[btf_map]
static CT_METRICS: PerCpuArray<u64, { CT_METRIC_COUNT as usize }> = PerCpuArray::new();

/// Runtime-resolved `nf_conn` field offsets populated by userspace from
/// vmlinux BTF. Used by `bpf_probe_read_kernel` to read kernel CT fields.
#[btf_map]
static CT_NF_CONN_OFFSETS: Array<NfConnOffsets, 1> = Array::new();

// ── Entry point ─────────────────────────────────────────────────────

#[classifier]
pub fn tc_conntrack(ctx: TcContext) -> i32 {
    // A traced packet is decided like any other and moves no counter.
    let traced = trace::tc(&ctx);
    increment_metric(traced, CT_METRIC_TOTAL_SEEN);
    // Capture the trusted skb pointer by value in the entry frame, where
    // `ctx` is owned (guaranteed `PTR_TO_CTX`). Threading it by value through
    // every subprogram keeps it in a register, so the verifier preserves the
    // trusted-ctx type required by `bpf_skb_ct_lookup` (`KF_TRUSTED_ARGS`).
    // Reloading it from `&TcContext` in an outlined subprogram would yield a
    // plain scalar and the kfunc call would be rejected.
    let skb_raw: *mut core::ffi::c_void = raw_skb(&ctx).cast();
    let action = match try_tc_conntrack(&ctx, skb_raw, traced) {
        Ok(action) => action,
        Err(()) => {
            increment_metric(traced, CT_METRIC_ERRORS);
            trace::tc_record(&ctx, stage::CONNTRACK, reason::MALFORMED, 0, 0);
            TC_ACT_OK
        }
    };
    // Under TCX (kernel >= 6.6) returning TC_ACT_OK terminates the program
    // chain on this hook; translate a "pass" verdict to TCX_NEXT (-1) so other
    // tc programs on the same interface still run. Terminal verdicts pass through.
    if action == TC_ACT_OK { -1 } else { action }
}

// ── Helpers ─────────────────────────────────────────────────────────

#[inline(always)]
fn increment_metric(traced: bool, index: u32) {
    if !traced {
        increment_metric!(CT_METRICS, index);
    }
}

// ── Packet processing ───────────────────────────────────────────────

#[inline(always)]
fn try_tc_conntrack(
    ctx: &TcContext,
    skb_raw: *mut core::ffi::c_void,
    traced: bool,
) -> Result<i32, ()> {
    // The parse the chain already holds, or this program's own if it is
    // first.
    let meta = pktmeta::resolve(ctx)?;

    if meta.is_ipv4() {
        process_conntrack_v4(ctx, skb_raw, meta.l3(), traced)
    } else if meta.is_ipv6() {
        process_conntrack_v6(ctx, skb_raw, meta.l3(), traced)
    } else {
        trace::tc_record(ctx, stage::CONNTRACK, reason::MALFORMED, 0, 0);
        Ok(TC_ACT_OK)
    }
}

/// IPv4 conntrack: parse 5-tuple, probe kernel netfilter CT.
///
/// The shadow CT_TABLE_V4/V6 maps are deleted - kernel netfilter is
/// the sole connection tracking engine. This program now only:
/// 1. Checks the enabled flag from CT_CONFIG
/// 2. Parses the 5-tuple
/// 3. Probes kernel CT via `bpf_skb_ct_lookup` for enrichment metrics
/// 4. Reads `nf_conn->status` + `nf_conn->mark` via `bpf_probe_read_kernel`
///
/// Kernel netfilter manages timeouts, state machine, and eviction.
#[inline(always)]
fn process_conntrack_v4(
    ctx: &TcContext,
    skb_raw: *mut core::ffi::c_void,
    l3_offset: usize,
    traced: bool,
) -> Result<i32, ()> {
    let ct_config = match CT_CONFIG.get(0) {
        Some(cfg) => cfg,
        None => return Ok(TC_ACT_OK),
    };
    if ct_config.enabled == 0 {
        trace::tc_record(ctx, stage::CONNTRACK, reason::DISABLED, 0, 0);
        return Ok(TC_ACT_OK);
    }

    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(ctx, l3_offset)? };
    let src_ip = u32_from_be_bytes(unsafe { (*ipv4hdr).src_addr });
    let dst_ip = u32_from_be_bytes(unsafe { (*ipv4hdr).dst_addr });
    let protocol = unsafe { (*ipv4hdr).proto } as u8;
    let l4_offset = l3_offset + 20;

    let (src_port, dst_port) = match protocol {
        PROTO_TCP => {
            let tcphdr: *const TcpHdr = unsafe { ptr_at(ctx, l4_offset)? };
            (
                u16_from_be_bytes(unsafe { (*tcphdr).source }),
                u16_from_be_bytes(unsafe { (*tcphdr).dest }),
            )
        }
        PROTO_UDP => {
            let udphdr: *const UdpHdr = unsafe { ptr_at(ctx, l4_offset)? };
            (
                u16_from_be_bytes(unsafe { (*udphdr).src }),
                u16_from_be_bytes(unsafe { (*udphdr).dst }),
            )
        }
        PROTO_ICMP => {
            // One two-byte window rather than two one-byte reads: with the
            // offset coming off the chain handoff the verifier sees a fully
            // variable pointer, and a one-byte bound check compiles to
            // `ptr >= end`, a form it grants no range from.
            let icmp: *const [u8; 2] = unsafe { ptr_at(ctx, l4_offset)? };
            let icmp = unsafe { *icmp };
            (u16::from(icmp[0]), u16::from(icmp[1]))
        }
        _ => return Ok(TC_ACT_OK),
    };

    let status = kfunc_ct_probe(
        skb_raw,
        CtTuple::v4(src_ip, dst_ip, src_port, dst_port),
        protocol,
        traced,
    );
    record_state(ctx, status);
    Ok(TC_ACT_OK)
}

/// IPv6 conntrack: parse 5-tuple, probe kernel netfilter CT.
#[inline(never)]
fn process_conntrack_v6(
    ctx: &TcContext,
    skb_raw: *mut core::ffi::c_void,
    l3_offset: usize,
    traced: bool,
) -> Result<i32, ()> {
    let ct_config = match CT_CONFIG.get(0) {
        Some(cfg) => cfg,
        None => return Ok(TC_ACT_OK),
    };
    if ct_config.enabled == 0 {
        trace::tc_record(ctx, stage::CONNTRACK, reason::DISABLED, 0, 0);
        return Ok(TC_ACT_OK);
    }

    let ipv6hdr: *const Ipv6Hdr = unsafe { ptr_at(ctx, l3_offset)? };
    let raw_protocol = unsafe { (*ipv6hdr).next_hdr };
    let (protocol, l4_offset) =
        skip_ipv6_ext_headers(ctx, l3_offset + IPV6_HDR_LEN, raw_protocol).ok_or(())?;

    let (src_port, dst_port) = match protocol {
        PROTO_TCP => {
            let tcphdr: *const TcpHdr = unsafe { ptr_at(ctx, l4_offset)? };
            (
                u16_from_be_bytes(unsafe { (*tcphdr).source }),
                u16_from_be_bytes(unsafe { (*tcphdr).dest }),
            )
        }
        PROTO_UDP => {
            let udphdr: *const UdpHdr = unsafe { ptr_at(ctx, l4_offset)? };
            (
                u16_from_be_bytes(unsafe { (*udphdr).src }),
                u16_from_be_bytes(unsafe { (*udphdr).dst }),
            )
        }
        PROTO_ICMPV6 => {
            // One two-byte window rather than two one-byte reads: with the
            // offset coming off the chain handoff the verifier sees a fully
            // variable pointer, and a one-byte bound check compiles to
            // `ptr >= end`, a form it grants no range from.
            let icmp: *const [u8; 2] = unsafe { ptr_at(ctx, l4_offset)? };
            let icmp = unsafe { *icmp };
            (u16::from(icmp[0]), u16::from(icmp[1]))
        }
        _ => return Ok(TC_ACT_OK),
    };

    let ipv6hdr2: *const Ipv6Hdr = unsafe { ptr_at(ctx, l3_offset)? };
    let mut src_bytes = core::mem::MaybeUninit::<[u8; 16]>::uninit();
    let mut dst_bytes = core::mem::MaybeUninit::<[u8; 16]>::uninit();
    unsafe {
        let base = ipv6hdr2 as *const u8;
        copy_16b_asm!(src_bytes.as_mut_ptr() as *mut u8, base.add(8));
        copy_16b_asm!(dst_bytes.as_mut_ptr() as *mut u8, base.add(24));
    }
    let src_bytes = unsafe { src_bytes.assume_init() };
    let dst_bytes = unsafe { dst_bytes.assume_init() };
    let src_addr = ipv6_addr_to_u32x4(&src_bytes);
    let dst_addr = ipv6_addr_to_u32x4(&dst_bytes);

    let status = kfunc_ct_probe(
        skb_raw,
        CtTuple::v6(src_addr, dst_addr, src_port, dst_port),
        protocol,
        traced,
    );
    record_state(ctx, status);
    Ok(TC_ACT_OK)
}

/// What the kernel's connection table says about a flow, as a traced packet
/// reports it.
const STATE_UNTRACKED: u32 = 0;
const STATE_NEW: u32 = 1;
const STATE_ESTABLISHED: u32 = 2;
const STATE_RELATED: u32 = 3;
const STATE_INVALID: u32 = 4;
const STATE_UNREADABLE: u32 = 5;

/// Report the flow's state for a traced packet. An established or related
/// flow is a verdict that depends on state the packet does not carry.
#[inline(always)]
fn record_state(ctx: &TcContext, state: u32) {
    let why = match state {
        STATE_ESTABLISHED | STATE_RELATED => reason::ESTABLISHED,
        _ => reason::DEFAULT,
    };
    trace::tc_record(ctx, stage::CONNTRACK, why, 0, state);
}

/// Probe kernel netfilter CT for a flow. Reads `nf_conn->status` and
/// `nf_conn->mark` via `bpf_probe_read_kernel` at runtime BTF offsets.
/// Increments kfunc hit/miss metrics, and returns the state it read.
#[inline(always)]
fn kfunc_ct_probe(
    skb_raw: *mut core::ffi::c_void,
    tuple: CtTuple,
    protocol: u8,
    traced: bool,
) -> u32 {
    increment_metric(traced, CT_METRIC_KFUNC_LOOKUPS);
    let mut opts = if protocol == PROTO_TCP {
        BpfCtOpts::tcp()
    } else {
        BpfCtOpts::udp()
    };
    let found = unsafe {
        with_skb_ct_lookup(skb_raw, tuple, &mut opts, |ct| {
            read_nf_conn_fields(ct, traced)
        })
    };
    if let Some(state) = found {
        increment_metric(traced, CT_METRIC_KFUNC_HITS);
        state
    } else {
        increment_metric(traced, CT_METRIC_KFUNC_MISSES);
        STATE_UNTRACKED
    }
}

/// Read `nf_conn->status` and `nf_conn->mark` from a live kernel CT
/// entry using `bpf_probe_read_kernel` with runtime BTF offsets, and
/// account both.
///
/// The offsets come from userspace vmlinux BTF and can go stale against the
/// running kernel, in which case the reads fail and the values would be
/// indistinguishable from a genuine zero status. Failures are counted
/// separately so a non-zero `kfunc_read_errors` says the state counters are
/// undercounting rather than the traffic being idle.
#[inline(always)]
fn read_nf_conn_fields(ct: *mut ebpf_helpers::kfuncs::nf_conn, traced: bool) -> u32 {
    let offsets = match CT_NF_CONN_OFFSETS.get(0) {
        Some(o) if o.valid != 0 => o,
        _ => return STATE_UNREADABLE,
    };
    let base = ct as *const u8;
    let mut status: u64 = 0;
    let mut mark: u32 = 0;
    let (status_read, mark_read) = unsafe {
        (
            bpf_probe_read_kernel(
                &raw mut status as *mut core::ffi::c_void,
                core::mem::size_of::<u64>() as u32,
                base.add(offsets.status_offset as usize) as *const core::ffi::c_void,
            ),
            bpf_probe_read_kernel(
                &raw mut mark as *mut core::ffi::c_void,
                core::mem::size_of::<u32>() as u32,
                base.add(offsets.mark_offset as usize) as *const core::ffi::c_void,
            ),
        )
    };

    let state = if status_read < 0 {
        increment_metric(traced, CT_METRIC_KFUNC_READ_ERRORS);
        STATE_UNREADABLE
    } else if status & IPS_DYING != 0 {
        increment_metric(traced, CT_METRIC_KFUNC_STATE_INVALID);
        STATE_INVALID
    } else if status & IPS_EXPECTED != 0 {
        increment_metric(traced, CT_METRIC_KFUNC_STATE_RELATED);
        STATE_RELATED
    } else if status & (IPS_CONFIRMED | IPS_SEEN_REPLY) != 0 {
        increment_metric(traced, CT_METRIC_KFUNC_STATE_ESTABLISHED);
        STATE_ESTABLISHED
    } else {
        increment_metric(traced, CT_METRIC_KFUNC_STATE_NEW);
        STATE_NEW
    };

    if mark_read < 0 {
        increment_metric(traced, CT_METRIC_KFUNC_READ_ERRORS);
    } else if mark != 0 {
        increment_metric(traced, CT_METRIC_KFUNC_MARKED);
    }
    state
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
