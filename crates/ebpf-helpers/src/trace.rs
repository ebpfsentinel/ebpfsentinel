//! A packet that asks what the datapath would do with it, and changes nothing.
//!
//! The agent answers "why is this packet dropped" by running a crafted packet
//! through the programs that are loaded, with `BPF_PROG_TEST_RUN`, so the
//! answer comes from the code and the maps that decide live traffic. Those
//! programs write as they decide: a connection is tracked, a token is taken
//! from a bucket, a counter moves, an event goes to the ring buffer. A trace
//! must do none of that, or asking the question would change the answer to
//! the next live packet and raise an alert nobody's traffic caused.
//!
//! So the crafted packet carries a marker, and every program reads it before
//! it writes: every lookup and every decision is taken as for live traffic,
//! and every write is skipped. Live traffic never carries the marker, because
//! none of the three places it sits can be set from the wire:
//!
//! - **XDP**: 32 bytes of metadata in front of the packet, which only an
//!   XDP program on this host or the test run itself can place there.
//! - **tc**: `skb->mark` and `skb->priority` both set to a fixed value. A
//!   socket sets either only with `CAP_NET_ADMIN`, which already holds the
//!   power to detach the programs, and no program of the agent writes them.
//!
//! A program reports what it decided for a traced packet in the same place:
//! the XDP stages append a record to the metadata, and a tc classifier, which
//! the agent runs one at a time, leaves its record in `skb->cb`, returned to
//! userspace through the test run's output context.

use aya_ebpf::programs::{TcContext, XdpContext};

pub use ebpf_common::trace::{
    NO_RULE, TC_TRACE_MARK, TC_TRACE_PRIORITY, TC_VERDICT_MAGIC, XDP_COUNT_OFF, XDP_RECORDS_OFF,
    XDP_TRACE_MAGIC, XDP_TRACE_META_LEN, XDP_TRACE_RECORDS, fast_path, reason, stage,
};

/// Whether this XDP invocation is a trace.
#[inline(always)]
#[must_use]
pub fn xdp(ctx: &XdpContext) -> bool {
    let meta = ctx.metadata();
    if meta + XDP_TRACE_META_LEN > ctx.metadata_end() {
        return false;
    }
    // SAFETY: the 32 bytes before `data` are inside the metadata window,
    // checked against `data` just above.
    unsafe { *(meta as *const u32) == XDP_TRACE_MAGIC }
}

/// Whether this tc invocation is a trace.
#[inline(always)]
#[must_use]
pub fn tc(ctx: &TcContext) -> bool {
    let skb = crate::raw_skb(ctx);
    // SAFETY: `mark` and `priority` are readable fields of the classifier's
    // `__sk_buff`.
    unsafe { (*skb).mark == TC_TRACE_MARK && (*skb).priority == TC_TRACE_PRIORITY }
}

/// Append what an XDP stage decided to a traced packet's metadata. Does
/// nothing on live traffic, and nothing once the three records are used.
#[inline(always)]
pub fn xdp_record(ctx: &XdpContext, stage: u8, action: u8, reason: u8, rule_id: u32) {
    let meta = ctx.metadata();
    if meta + XDP_TRACE_META_LEN > ctx.metadata_end() {
        return;
    }
    // SAFETY: bounds checked above; every offset below is under 32.
    unsafe {
        if *(meta as *const u32) != XDP_TRACE_MAGIC {
            return;
        }
        let count = *((meta + XDP_COUNT_OFF) as *const u32);
        if count >= XDP_TRACE_RECORDS {
            return;
        }
        // The verifier loses the window's range on a pointer moved by a
        // variable amount, and the compiler folds per-slot branches back into
        // one, so every slot is rewritten at its constant offset and only the
        // value written depends on the count.
        let head = u32::from(stage) | (u32::from(action) << 8) | (u32::from(reason) << 16);
        let base = meta + XDP_RECORDS_OFF;
        let slot0 = base as *mut u32;
        let slot1 = (base + 8) as *mut u32;
        let slot2 = (base + 16) as *mut u32;
        *slot0 = if count == 0 { head } else { *slot0 };
        *slot0.add(1) = if count == 0 { rule_id } else { *slot0.add(1) };
        *slot1 = if count == 1 { head } else { *slot1 };
        *slot1.add(1) = if count == 1 { rule_id } else { *slot1.add(1) };
        *slot2 = if count == 2 { head } else { *slot2 };
        *slot2.add(1) = if count == 2 { rule_id } else { *slot2.add(1) };
        *((meta + XDP_COUNT_OFF) as *mut u32) = count + 1;
    }
}

/// Leave what a tc classifier decided in `skb->cb` of a traced packet. Does
/// nothing on live traffic.
#[inline(always)]
pub fn tc_record(ctx: &TcContext, stage: u8, reason: u8, rule_id: u32, detail: u32) {
    if !tc(ctx) {
        return;
    }
    let skb = crate::raw_skb(ctx);
    // SAFETY: `cb` is writable by a classifier; the agent runs a traced
    // packet through one classifier at a time, so nothing reads the
    // control block after this.
    unsafe {
        (*skb).cb[0] = TC_VERDICT_MAGIC;
        (*skb).cb[1] = (u32::from(stage) << 8) | u32::from(reason);
        (*skb).cb[2] = rule_id;
        (*skb).cb[3] = detail;
        (*skb).cb[4] = 0;
    }
}
