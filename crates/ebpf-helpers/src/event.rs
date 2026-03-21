//! Shared event emission macro for eBPF programs.
//!
//! Eliminates ~40 lines of copy-pasted `emit_event()` functions across
//! TC and XDP programs. Each program passes its own RingBuf map, metric
//! map, event type constant, and optional custom field overrides.

/// Emit a `PacketEvent` to a `RingBuf` with backpressure protection.
///
/// # Parameters
/// - `$ringbuf`: the `RingBuf` map static
/// - `$metrics`: the `PerCpuArray<u64>` metrics map static
/// - `$metric_dropped`: metric index for events-dropped counter
/// - `$src_addr`, `$dst_addr`: `&[u32; 4]`
/// - `$src_port`, `$dst_port`: `u16`
/// - `$protocol`: `u8`
/// - `$event_type`: `u8` constant (EVENT_TYPE_*)
/// - `$action`: `u8`
/// - `$rule_id`: `u32`
/// - `$flags`: `u8`
/// - `$vlan_id`: `u16`
///
/// # Optional: socket_cookie (TC context)
/// Append `; tc $ctx` to populate `socket_cookie` from a `TcContext`:
/// ```ignore
/// emit_packet_event!(EVENTS, METRICS, 3, &src, &dst, sp, dp, proto,
///     EVENT_TYPE_IDS, action, rule_id, flags, vlan; tc ctx);
/// ```
///
/// Without the `; tc $ctx` suffix, `socket_cookie` is set to 0 (XDP mode).
#[macro_export]
macro_rules! emit_packet_event {
    // TC variant: with socket_cookie from TcContext
    ($ringbuf:expr, $metrics:expr, $metric_dropped:expr,
     $src_addr:expr, $dst_addr:expr, $src_port:expr, $dst_port:expr,
     $protocol:expr, $event_type:expr, $action:expr, $rule_id:expr,
     $flags:expr, $vlan_id:expr ; tc $ctx:expr) => {{
        if $crate::ringbuf_has_backpressure!($ringbuf) {
            $crate::increment_metric!($metrics, $metric_dropped);
            return;
        }
        if let Some(mut entry) = $ringbuf.reserve::<ebpf_common::event::PacketEvent>(0) {
            let ptr = entry.as_mut_ptr();
            unsafe {
                (*ptr).timestamp_ns = aya_ebpf::helpers::bpf_ktime_get_boot_ns();
                (*ptr).src_addr = *$src_addr;
                (*ptr).dst_addr = *$dst_addr;
                (*ptr).src_port = $src_port;
                (*ptr).dst_port = $dst_port;
                (*ptr).protocol = $protocol;
                (*ptr).event_type = $event_type;
                (*ptr).action = $action;
                (*ptr).flags = $flags;
                (*ptr).rule_id = $rule_id;
                (*ptr).vlan_id = $vlan_id;
                (*ptr).cpu_id = aya_ebpf::helpers::bpf_get_smp_processor_id() as u16;
                (*ptr).socket_cookie =
                    aya_ebpf::helpers::bpf_get_socket_cookie($ctx.skb.skb as *mut _);
            }
            entry.submit(0);
        } else {
            $crate::increment_metric!($metrics, $metric_dropped);
        }
    }};

    // XDP variant: no socket_cookie
    ($ringbuf:expr, $metrics:expr, $metric_dropped:expr,
     $src_addr:expr, $dst_addr:expr, $src_port:expr, $dst_port:expr,
     $protocol:expr, $event_type:expr, $action:expr, $rule_id:expr,
     $flags:expr, $vlan_id:expr) => {{
        if $crate::ringbuf_has_backpressure!($ringbuf) {
            $crate::increment_metric!($metrics, $metric_dropped);
            return;
        }
        if let Some(mut entry) = $ringbuf.reserve::<ebpf_common::event::PacketEvent>(0) {
            let ptr = entry.as_mut_ptr();
            unsafe {
                (*ptr).timestamp_ns = aya_ebpf::helpers::bpf_ktime_get_boot_ns();
                (*ptr).src_addr = *$src_addr;
                (*ptr).dst_addr = *$dst_addr;
                (*ptr).src_port = $src_port;
                (*ptr).dst_port = $dst_port;
                (*ptr).protocol = $protocol;
                (*ptr).event_type = $event_type;
                (*ptr).action = $action;
                (*ptr).flags = $flags;
                (*ptr).rule_id = $rule_id;
                (*ptr).vlan_id = $vlan_id;
                (*ptr).cpu_id = aya_ebpf::helpers::bpf_get_smp_processor_id() as u16;
                (*ptr).socket_cookie = 0;
            }
            entry.submit(0);
        } else {
            $crate::increment_metric!($metrics, $metric_dropped);
        }
    }};
}
