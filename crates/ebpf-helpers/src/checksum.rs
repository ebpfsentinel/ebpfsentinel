//! Internet checksum helpers for eBPF programs.
//!
//! All loops use fixed iteration counts (no `while condition` without a
//! counter) and checksum folds use 3 fixed iterations instead of a `while`
//! loop. This prevents BPF verifier state explosion on kernel 6.17+.

use crate::net::{PROTO_ICMPV6, PROTO_TCP};

/// Fold a 32-bit checksum accumulator into 16 bits (3 fixed iterations).
///
/// Mathematically sufficient: after summing N u16 words, the carry can be
/// at most `N` which fits in 16 bits for any practical header size. Three
/// fold iterations handle any overflow chain.
#[inline(always)]
fn fold32(mut sum: u32) -> u16 {
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    !(sum as u16)
}

/// Sum `count` bytes (must be even) from `ptr` as big-endian u16 words.
///
/// # Safety
/// `ptr` must be valid for `count` bytes. `count` must be even.
#[inline(always)]
unsafe fn sum_bytes(ptr: *const u8, count: usize) -> u32 {
    let mut sum: u32 = 0;
    let mut i: usize = 0;
    while i < count {
        sum += unsafe { ((*ptr.add(i) as u32) << 8) | (*ptr.add(i + 1) as u32) };
        i += 2;
    }
    sum
}

/// Compute IPv4 header checksum (20 bytes, IHL=5, no options).
///
/// The checksum field in the header must be zeroed before calling.
///
/// # Safety
/// `hdr` must point to at least 20 valid bytes.
#[inline(always)]
pub unsafe fn compute_ipv4_csum(hdr: *const u8) -> u16 {
    fold32(unsafe { sum_bytes(hdr, 20) })
}

/// Compute TCP checksum with IPv4 pseudo-header (20-byte TCP, no options).
///
/// The checksum field in the TCP header must be zeroed before calling.
///
/// # Safety
/// `tcp_hdr` must point to at least 20 valid bytes.
#[inline(always)]
pub unsafe fn compute_tcp_csum_v4(
    src_ip: &[u8; 4],
    dst_ip: &[u8; 4],
    tcp_hdr: *const u8,
) -> u16 {
    let mut sum: u32 = 0;
    sum += ((src_ip[0] as u32) << 8) | (src_ip[1] as u32);
    sum += ((src_ip[2] as u32) << 8) | (src_ip[3] as u32);
    sum += ((dst_ip[0] as u32) << 8) | (dst_ip[1] as u32);
    sum += ((dst_ip[2] as u32) << 8) | (dst_ip[3] as u32);
    sum += PROTO_TCP as u32;
    sum += 20u32;
    sum += unsafe { sum_bytes(tcp_hdr, 20) };
    fold32(sum)
}

/// Compute TCP checksum with IPv4 pseudo-header for 24-byte TCP (with MSS option).
///
/// # Safety
/// `tcp_hdr` must point to at least 24 valid bytes.
#[inline(always)]
pub unsafe fn compute_tcp_csum_v4_24(
    src_ip: &[u8; 4],
    dst_ip: &[u8; 4],
    tcp_hdr: *const u8,
) -> u16 {
    let mut sum: u32 = 0;
    sum += ((src_ip[0] as u32) << 8) | (src_ip[1] as u32);
    sum += ((src_ip[2] as u32) << 8) | (src_ip[3] as u32);
    sum += ((dst_ip[0] as u32) << 8) | (dst_ip[1] as u32);
    sum += ((dst_ip[2] as u32) << 8) | (dst_ip[3] as u32);
    sum += PROTO_TCP as u32;
    sum += 24u32;
    sum += unsafe { sum_bytes(tcp_hdr, 24) };
    fold32(sum)
}

/// Compute TCP checksum with IPv6 pseudo-header (20-byte TCP, no options).
///
/// # Safety
/// `tcp_hdr` must point to at least 20 valid bytes.
#[inline(always)]
pub unsafe fn compute_tcp_csum_v6(
    src_ip: &[u8; 16],
    dst_ip: &[u8; 16],
    tcp_hdr: *const u8,
) -> u16 {
    let mut sum: u32 = 0;
    unsafe {
        sum += sum_bytes(src_ip.as_ptr(), 16);
        sum += sum_bytes(dst_ip.as_ptr(), 16);
        sum += 20u32;
        sum += PROTO_TCP as u32;
        sum += sum_bytes(tcp_hdr, 20);
    }
    fold32(sum)
}

/// Compute TCP checksum with IPv6 pseudo-header for 24-byte TCP (with MSS option).
///
/// # Safety
/// `tcp_hdr` must point to at least 24 valid bytes.
#[inline(always)]
pub unsafe fn compute_tcp_csum_v6_24(
    src_ip: &[u8; 16],
    dst_ip: &[u8; 16],
    tcp_hdr: *const u8,
) -> u16 {
    let mut sum: u32 = 0;
    unsafe {
        sum += sum_bytes(src_ip.as_ptr(), 16);
        sum += sum_bytes(dst_ip.as_ptr(), 16);
        sum += 24u32;
        sum += PROTO_TCP as u32;
        sum += sum_bytes(tcp_hdr, 24);
    }
    fold32(sum)
}

/// Compute ICMP checksum (36 bytes: 8 header + 28 original packet).
///
/// The checksum field must be zeroed before calling.
///
/// # Safety
/// `data` must point to at least 36 valid bytes.
#[inline(always)]
pub unsafe fn compute_icmp_csum(data: *const u8) -> u16 {
    fold32(unsafe { sum_bytes(data, 36) })
}

/// Compute ICMPv6 checksum with IPv6 pseudo-header (56 bytes: 8 header + 48 payload).
///
/// # Safety
/// `icmpv6_data` must point to at least 56 valid bytes.
#[inline(always)]
pub unsafe fn compute_icmpv6_csum(
    src_ip: &[u8; 16],
    dst_ip: &[u8; 16],
    icmpv6_data: *const u8,
) -> u16 {
    let mut sum: u32 = 0;
    unsafe {
        sum += sum_bytes(src_ip.as_ptr(), 16);
        sum += sum_bytes(dst_ip.as_ptr(), 16);
        sum += 56u32;
        sum += PROTO_ICMPV6 as u32;
        sum += sum_bytes(icmpv6_data, 56);
    }
    fold32(sum)
}
