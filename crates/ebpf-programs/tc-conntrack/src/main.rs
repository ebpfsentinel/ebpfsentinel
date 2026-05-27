#![no_std]
#![no_main]
#![cfg_attr(target_arch = "bpf", feature(asm_experimental_arch))]

use aya_ebpf::{
    bindings::TC_ACT_OK,
    macros::{classifier, map},
    maps::{Array, PerCpuArray},
    programs::TcContext,
};
use aya_ebpf_bindings::helpers::bpf_probe_read_kernel;
use ebpf_common::conntrack::{
    CT_METRIC_COUNT, CT_METRIC_ERRORS, CT_METRIC_KFUNC_HITS, CT_METRIC_KFUNC_LOOKUPS,
    CT_METRIC_KFUNC_MISSES, CT_METRIC_TOTAL_SEEN, ConnTrackConfig, NfConnOffsets,
};
use ebpf_helpers::kfuncs::{BpfCtOpts, CtTuple, with_skb_ct_lookup};
use ebpf_helpers::net::{
    ETH_P_8021AD, ETH_P_8021Q, ETH_P_IP, ETH_P_IPV6, IPV6_HDR_LEN, Ipv6Hdr, PROTO_ICMP,
    PROTO_ICMPV6, PROTO_TCP, PROTO_UDP, VLAN_HDR_LEN, VlanHdr, ipv6_addr_to_u32x4,
    u16_from_be_bytes, u32_from_be_bytes,
};
use ebpf_helpers::tc::{ptr_at, skip_ipv6_ext_headers};
use ebpf_helpers::{copy_16b_asm, increment_metric};
use network_types::{eth::EthHdr, ip::Ipv4Hdr, tcp::TcpHdr, udp::UdpHdr};

// ── Maps ────────────────────────────────────────────────────────────

/// Conntrack configuration (timeouts, enable flag).
#[map]
static CT_CONFIG: Array<ConnTrackConfig> = Array::with_max_entries(1, 0);

/// Per-CPU conntrack metrics.
#[map]
static CT_METRICS: PerCpuArray<u64> = PerCpuArray::with_max_entries(CT_METRIC_COUNT, 0);

/// Runtime-resolved `nf_conn` field offsets populated by userspace from
/// vmlinux BTF. Used by `bpf_probe_read_kernel` to read kernel CT fields.
#[map]
static CT_NF_CONN_OFFSETS: Array<NfConnOffsets> = Array::with_max_entries(1, 0);

// ── Entry point ─────────────────────────────────────────────────────

#[classifier]
pub fn tc_conntrack(ctx: TcContext) -> i32 {
    increment_metric(CT_METRIC_TOTAL_SEEN);
    // Capture the trusted skb pointer by value in the entry frame, where
    // `ctx` is owned (guaranteed `PTR_TO_CTX`). Threading it by value through
    // every subprogram keeps it in a register, so the verifier preserves the
    // trusted-ctx type required by `bpf_skb_ct_lookup` (`KF_TRUSTED_ARGS`).
    // Reloading it from `&TcContext` in an outlined subprogram would yield a
    // plain scalar and the kfunc call would be rejected.
    let skb_raw: *mut core::ffi::c_void = ctx.skb.skb.cast();
    match try_tc_conntrack(&ctx, skb_raw) {
        Ok(action) => action,
        Err(()) => {
            increment_metric(CT_METRIC_ERRORS);
            TC_ACT_OK
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

#[inline(always)]
fn increment_metric(index: u32) {
    increment_metric!(CT_METRICS, index);
}

// ── Packet processing ───────────────────────────────────────────────

#[inline(always)]
fn try_tc_conntrack(ctx: &TcContext, skb_raw: *mut core::ffi::c_void) -> Result<i32, ()> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(ctx, 0)? };
    let mut ether_type = u16::from_be(unsafe { (*ethhdr).ether_type });
    let mut l3_offset = EthHdr::LEN;

    // 802.1Q VLAN tag
    if ether_type == ETH_P_8021Q || ether_type == ETH_P_8021AD {
        let vhdr: *const VlanHdr = unsafe { ptr_at(ctx, l3_offset)? };
        ether_type = u16::from_be(unsafe { (*vhdr).ether_type });
        l3_offset += VLAN_HDR_LEN;

        if ether_type == ETH_P_8021Q || ether_type == ETH_P_8021AD {
            let vhdr2: *const VlanHdr = unsafe { ptr_at(ctx, l3_offset)? };
            ether_type = u16::from_be(unsafe { (*vhdr2).ether_type });
            l3_offset += VLAN_HDR_LEN;
        }
    }

    if ether_type == ETH_P_IP {
        process_conntrack_v4(ctx, skb_raw, l3_offset)
    } else if ether_type == ETH_P_IPV6 {
        process_conntrack_v6(ctx, skb_raw, l3_offset)
    } else {
        Ok(TC_ACT_OK)
    }
}

/// IPv4 conntrack: parse 5-tuple, probe kernel netfilter CT.
///
/// The shadow CT_TABLE_V4/V6 maps are deleted — kernel netfilter is
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
) -> Result<i32, ()> {
    let ct_config = match CT_CONFIG.get(0) {
        Some(cfg) => cfg,
        None => return Ok(TC_ACT_OK),
    };
    if ct_config.enabled == 0 {
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
            let icmp_type_ptr: *const u8 = unsafe { ptr_at(ctx, l4_offset)? };
            let icmp_code_ptr: *const u8 = unsafe { ptr_at(ctx, l4_offset + 1)? };
            (unsafe { *icmp_type_ptr } as u16, unsafe { *icmp_code_ptr }
                as u16)
        }
        _ => return Ok(TC_ACT_OK),
    };

    kfunc_ct_probe(
        skb_raw,
        CtTuple::v4(src_ip, dst_ip, src_port, dst_port),
        protocol,
    );
    Ok(TC_ACT_OK)
}

/// IPv6 conntrack: parse 5-tuple, probe kernel netfilter CT.
#[inline(never)]
fn process_conntrack_v6(
    ctx: &TcContext,
    skb_raw: *mut core::ffi::c_void,
    l3_offset: usize,
) -> Result<i32, ()> {
    let ct_config = match CT_CONFIG.get(0) {
        Some(cfg) => cfg,
        None => return Ok(TC_ACT_OK),
    };
    if ct_config.enabled == 0 {
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
            let icmp_type_ptr: *const u8 = unsafe { ptr_at(ctx, l4_offset)? };
            let icmp_code_ptr: *const u8 = unsafe { ptr_at(ctx, l4_offset + 1)? };
            (unsafe { *icmp_type_ptr } as u16, unsafe { *icmp_code_ptr }
                as u16)
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

    kfunc_ct_probe(
        skb_raw,
        CtTuple::v6(src_addr, dst_addr, src_port, dst_port),
        protocol,
    );
    Ok(TC_ACT_OK)
}

/// Probe kernel netfilter CT for a flow. Reads `nf_conn->status` and
/// `nf_conn->mark` via `bpf_probe_read_kernel` at runtime BTF offsets.
/// Increments kfunc hit/miss metrics.
#[inline(always)]
fn kfunc_ct_probe(skb_raw: *mut core::ffi::c_void, tuple: CtTuple, protocol: u8) {
    increment_metric(CT_METRIC_KFUNC_LOOKUPS);
    let mut opts = if protocol == PROTO_TCP {
        BpfCtOpts::tcp()
    } else {
        BpfCtOpts::udp()
    };
    let found = unsafe {
        with_skb_ct_lookup(skb_raw, tuple, &mut opts, |ct| {
            read_nf_conn_fields(ct);
            true
        })
    };
    if found == Some(true) {
        increment_metric(CT_METRIC_KFUNC_HITS);
    } else {
        increment_metric(CT_METRIC_KFUNC_MISSES);
    }
}

/// Read `nf_conn->status` and `nf_conn->mark` from a live kernel CT
/// entry using `bpf_probe_read_kernel` with runtime BTF offsets.
#[inline(always)]
fn read_nf_conn_fields(ct: *mut ebpf_helpers::kfuncs::nf_conn) {
    let offsets = match CT_NF_CONN_OFFSETS.get(0) {
        Some(o) if o.valid != 0 => o,
        _ => return,
    };
    let base = ct as *const u8;
    let mut _status: u64 = 0;
    let mut _mark: u32 = 0;
    unsafe {
        let _ = bpf_probe_read_kernel(
            &raw mut _status as *mut core::ffi::c_void,
            core::mem::size_of::<u64>() as u32,
            base.add(offsets.status_offset as usize) as *const core::ffi::c_void,
        );
        let _ = bpf_probe_read_kernel(
            &raw mut _mark as *mut core::ffi::c_void,
            core::mem::size_of::<u32>() as u32,
            base.add(offsets.mark_offset as usize) as *const core::ffi::c_void,
        );
    }
    let _ = (_status, _mark);
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
