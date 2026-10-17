// ── Constants ───────────────────────────────────────────────────────

/// Maximum bytes of plaintext captured per SSL_write/SSL_read call.
pub const DLP_MAX_EXCERPT: usize = 4096;

/// Small DLP excerpt tier (256 bytes) - covers most HTTP request/response
/// headers, JSON API payloads, and PCI/PII pattern matches. Used when
/// `data_len ≤ 256`, saving ~94% RingBuf space vs full 4K buffer.
pub const DLP_SMALL_EXCERPT: usize = 256;

/// Direction: data was written (SSL_write).
pub const DLP_DIRECTION_WRITE: u8 = 0;
/// Direction: data was read (SSL_read).
pub const DLP_DIRECTION_READ: u8 = 1;

/// Metric index: total SSL_write events emitted.
pub const DLP_METRIC_WRITE_EVENTS: u32 = 0;
/// Metric index: total SSL_read events emitted.
pub const DLP_METRIC_READ_EVENTS: u32 = 1;
/// Metric index: probe errors (argument extraction failures, etc.).
pub const DLP_METRIC_ERRORS: u32 = 2;
/// Metric index: events dropped due to RingBuf full.
pub const DLP_METRIC_EVENTS_DROPPED: u32 = 3;
/// Metric index: total probe invocations (unconditional, first thing in each probe).
pub const DLP_METRIC_TOTAL_SEEN: u32 = 4;
/// Metric index: plaintext excerpts taken from a kernel TLS socket.
pub const DLP_METRIC_KTLS_EVENTS: u32 = 5;
/// Metric index: kernel TLS calls skipped because a uprobe on the calling
/// library already captured the same plaintext in the same syscall.
pub const DLP_METRIC_KTLS_SUPPRESSED: u32 = 6;
/// Metric index: kernel TLS calls the probe could not read - the BTF offsets
/// were never pushed, or the message iterator is one of the kinds that carries
/// no single user buffer (kernel vectors from `sendfile` and `splice`).
pub const DLP_METRIC_KTLS_UNREADABLE: u32 = 7;
/// Metric index: plaintext left in the kernel because the calling task's cgroup
/// is outside the configured DLP scope. A node agent sees every container's
/// `SSL_write`, so on a shared node this counter is how an operator sees that
/// the probes are armed and the neighbours' bytes are not being read.
pub const DLP_METRIC_OUT_OF_SCOPE: u32 = 8;
/// Total number of DLP metric slots (one past the last index).
pub const DLP_METRIC_COUNT: u32 = 9;

/// DLP captures every task's plaintext, whatever cgroup it runs in. This is
/// what a host agent is for and what a node agent must not do unasked: one
/// `libssl` inode is shared by every container that maps it, so a probe placed
/// for one workload fires for all of them.
pub const DLP_SCOPE_MODE_ALL: u32 = 0;
/// DLP captures only tasks whose cgroup, or one of its ancestors, is listed in
/// `DLP_CGROUP_ALLOW`. The filter is in the probe rather than in userspace:
/// another tenant's plaintext must never reach the agent's address space at
/// all, which is a property of where the test sits, not of what the scanner
/// does with the event afterwards.
pub const DLP_SCOPE_MODE_WORKLOADS: u32 = 1;

/// How many cgroup ancestors the scope test walks above the running task.
///
/// Allowing a workload means naming its pod or container cgroup, while
/// `bpf_get_current_cgroup_id` answers with the leaf the task actually sits in -
/// `.../kubepods-podUID.slice/cri-containerd-HASH.scope`, and deeper still for a
/// workload that nests cgroups of its own. Eight levels covers a Kubernetes
/// slice hierarchy with room to spare, and the walk stops as soon as the helper
/// answers zero.
pub const DLP_SCOPE_ANCESTOR_LEVELS: u32 = 8;

/// Capacity of `DLP_CGROUP_ALLOW`: cgroups a DLP scope may name on one node.
pub const DLP_SCOPE_MAX_CGROUPS: u32 = 4096;

/// A kernel TLS call whose plaintext was captured by a uprobe on the calling
/// library stays suppressed for this long. `SSL_write` and `SSL_read` reach
/// `tls_sw_sendmsg` / `tls_sw_recvmsg` inside the same syscall, so the window
/// only has to outlive one call frame; a direct kernel TLS writer that has not
/// been through a probed library for longer than this is captured normally.
pub const DLP_KTLS_SUPPRESS_WINDOW_NS: u64 = 100_000_000;

/// Byte offsets of the kernel message-iterator fields the kernel TLS probes
/// read, resolved from the running kernel's vmlinux BTF by userspace and
/// pushed into `KTLS_ITER_OFFSETS`.
///
/// The Rust `bpfel` target emits no CO-RE relocations, so a kernel struct
/// member cannot be relocated at load the way a clang-built program's can -
/// and `struct iov_iter` is exactly the kind of layout that moves between
/// releases. Resolving the offsets in userspace and handing them to the
/// program is the same answer the conntrack datapath reached for `nf_conn`.
///
/// `__ubuf_iovec` and `__iov` are overlaid in one anonymous union, so a single
/// offset addresses both: the flat user buffer of an `ITER_UBUF` iterator and
/// the `struct iovec` pointer of an `ITER_IOVEC` one. `count` is overlaid on
/// that iovec's `iov_len`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KtlsIterOffsets {
    /// Byte offset of `msghdr.msg_iter`.
    pub msg_iter: u32,
    /// Byte offset of `iov_iter.iter_type`.
    pub iter_type: u32,
    /// Byte offset of `iov_iter.iov_offset`.
    pub iov_offset: u32,
    /// Byte offset of `iov_iter.__ubuf_iovec`, which `__iov` is overlaid on.
    pub iov_union: u32,
    /// Byte offset of `iov_iter.count`.
    pub count: u32,
    /// Byte offset of `iovec.iov_base`.
    pub iovec_base: u32,
    /// Byte offset of `iovec.iov_len`.
    pub iovec_len: u32,
    /// `enum iter_type` discriminant of `ITER_UBUF` on this kernel.
    pub iter_ubuf: u8,
    /// `enum iter_type` discriminant of `ITER_IOVEC` on this kernel.
    pub iter_iovec: u8,
    /// 1 = offsets resolved and valid, 0 = not yet populated. The probes read
    /// nothing at all while this is 0, rather than reading at offset zero.
    pub valid: u8,
    pub _pad: u8,
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for KtlsIterOffsets {}

// ── Types ───────────────────────────────────────────────────────────

/// DLP event emitted from uprobe-dlp to userspace via RingBuf.
/// Contains a header with process metadata and a variable-length excerpt
/// of the plaintext data captured from SSL_write or SSL_read.
/// Size: 4128 bytes (aligned to 8 bytes due to timestamp_ns/cgroup_id u64).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DlpEvent {
    /// Process ID (lower 32 bits of bpf_get_current_pid_tgid).
    pub pid: u32,
    /// Thread Group ID (upper 32 bits of bpf_get_current_pid_tgid).
    pub tgid: u32,
    /// Timestamp in nanoseconds (0 from kernel; userspace may override).
    pub timestamp_ns: u64,
    /// cgroup v2 ID from `bpf_get_current_cgroup_id`.
    /// 0 = cgroup v1 host / not available. Uprobes always run in process
    /// context so this is reliably populated on cgroup v2 systems.
    pub cgroup_id: u64,
    /// Actual number of bytes in data_excerpt (≤ DLP_MAX_EXCERPT).
    pub data_len: u32,
    /// Direction: DLP_DIRECTION_WRITE (0) or DLP_DIRECTION_READ (1).
    pub direction: u8,
    /// Explicit padding for alignment.
    pub _padding: [u8; 3],
    /// Plaintext data excerpt (zero-padded beyond data_len).
    pub data_excerpt: [u8; DLP_MAX_EXCERPT],
}

impl core::fmt::Debug for DlpEvent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DlpEvent")
            .field("pid", &self.pid)
            .field("tgid", &self.tgid)
            .field("timestamp_ns", &self.timestamp_ns)
            .field("cgroup_id", &self.cgroup_id)
            .field("data_len", &self.data_len)
            .field("direction", &self.direction)
            .finish_non_exhaustive()
    }
}

/// Small DLP event (288 bytes): header + 256 bytes excerpt.
/// Used when `data_len ≤ 256`, saving ~93% RingBuf space.
/// Size: 288 bytes (aligned to 8 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DlpEventSmall {
    pub pid: u32,
    pub tgid: u32,
    pub timestamp_ns: u64,
    /// cgroup v2 ID from `bpf_get_current_cgroup_id`. See `DlpEvent`.
    pub cgroup_id: u64,
    pub data_len: u32,
    pub direction: u8,
    pub _padding: [u8; 3],
    pub data_excerpt: [u8; DLP_SMALL_EXCERPT],
}

impl core::fmt::Debug for DlpEventSmall {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DlpEventSmall")
            .field("pid", &self.pid)
            .field("tgid", &self.tgid)
            .field("timestamp_ns", &self.timestamp_ns)
            .field("cgroup_id", &self.cgroup_id)
            .field("data_len", &self.data_len)
            .field("direction", &self.direction)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for DlpEventSmall {}

/// Per-task context saved at SSL_read entry, consumed at SSL_read return.
/// Stored in the SSL_READ_ARGS HashMap keyed by pid_tgid.
/// Size: 16 bytes (aligned to 8 bytes due to buf_ptr u64).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SslReadArgs {
    /// User-space buffer pointer passed to SSL_read.
    pub buf_ptr: u64,
    /// Buffer length (num argument to SSL_read).
    pub buf_len: u32,
    /// Explicit padding for alignment.
    pub _padding: u32,
}

// SAFETY: Both types are #[repr(C)], Copy, 'static, and contain only primitive
// types with explicit padding. Safe for zero-copy eBPF map operations via aya.
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for DlpEvent {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for SslReadArgs {}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn test_dlp_event_size() {
        assert_eq!(mem::size_of::<DlpEvent>(), 4128);
    }

    #[test]
    fn test_dlp_event_alignment() {
        assert_eq!(mem::align_of::<DlpEvent>(), 8);
    }

    #[test]
    fn test_dlp_event_field_offsets() {
        assert_eq!(mem::offset_of!(DlpEvent, pid), 0);
        assert_eq!(mem::offset_of!(DlpEvent, tgid), 4);
        assert_eq!(mem::offset_of!(DlpEvent, timestamp_ns), 8);
        assert_eq!(mem::offset_of!(DlpEvent, cgroup_id), 16);
        assert_eq!(mem::offset_of!(DlpEvent, data_len), 24);
        assert_eq!(mem::offset_of!(DlpEvent, direction), 28);
        assert_eq!(mem::offset_of!(DlpEvent, _padding), 29);
        assert_eq!(mem::offset_of!(DlpEvent, data_excerpt), 32);
    }

    #[test]
    fn test_ssl_read_args_size() {
        assert_eq!(mem::size_of::<SslReadArgs>(), 16);
    }

    #[test]
    fn test_ssl_read_args_alignment() {
        assert_eq!(mem::align_of::<SslReadArgs>(), 8);
    }

    #[test]
    fn test_ssl_read_args_field_offsets() {
        assert_eq!(mem::offset_of!(SslReadArgs, buf_ptr), 0);
        assert_eq!(mem::offset_of!(SslReadArgs, buf_len), 8);
        assert_eq!(mem::offset_of!(SslReadArgs, _padding), 12);
    }

    #[test]
    fn test_dlp_event_small_size() {
        assert_eq!(mem::size_of::<DlpEventSmall>(), 288);
    }

    #[test]
    fn test_dlp_event_small_alignment() {
        assert_eq!(mem::align_of::<DlpEventSmall>(), 8);
    }

    #[test]
    fn test_dlp_event_small_field_offsets() {
        // Header layout must match DlpEvent exactly
        assert_eq!(mem::offset_of!(DlpEventSmall, pid), 0);
        assert_eq!(mem::offset_of!(DlpEventSmall, tgid), 4);
        assert_eq!(mem::offset_of!(DlpEventSmall, timestamp_ns), 8);
        assert_eq!(mem::offset_of!(DlpEventSmall, cgroup_id), 16);
        assert_eq!(mem::offset_of!(DlpEventSmall, data_len), 24);
        assert_eq!(mem::offset_of!(DlpEventSmall, direction), 28);
        assert_eq!(mem::offset_of!(DlpEventSmall, data_excerpt), 32);
    }

    #[test]
    fn test_dlp_event_small_header_compatible() {
        // Verify header offsets are identical between DlpEvent and DlpEventSmall
        assert_eq!(
            mem::offset_of!(DlpEvent, pid),
            mem::offset_of!(DlpEventSmall, pid)
        );
        assert_eq!(
            mem::offset_of!(DlpEvent, tgid),
            mem::offset_of!(DlpEventSmall, tgid)
        );
        assert_eq!(
            mem::offset_of!(DlpEvent, timestamp_ns),
            mem::offset_of!(DlpEventSmall, timestamp_ns)
        );
        assert_eq!(
            mem::offset_of!(DlpEvent, cgroup_id),
            mem::offset_of!(DlpEventSmall, cgroup_id)
        );
        assert_eq!(
            mem::offset_of!(DlpEvent, data_len),
            mem::offset_of!(DlpEventSmall, data_len)
        );
        assert_eq!(
            mem::offset_of!(DlpEvent, direction),
            mem::offset_of!(DlpEventSmall, direction)
        );
        assert_eq!(
            mem::offset_of!(DlpEvent, data_excerpt),
            mem::offset_of!(DlpEventSmall, data_excerpt)
        );
    }

    #[test]
    fn test_small_excerpt_constant() {
        assert_eq!(DLP_SMALL_EXCERPT, 256);
        const { assert!(DLP_SMALL_EXCERPT < DLP_MAX_EXCERPT) };
    }

    #[test]
    fn test_direction_constants() {
        assert_eq!(DLP_DIRECTION_WRITE, 0);
        assert_eq!(DLP_DIRECTION_READ, 1);
    }

    #[test]
    fn test_metric_constants() {
        assert_eq!(DLP_METRIC_WRITE_EVENTS, 0);
        assert_eq!(DLP_METRIC_READ_EVENTS, 1);
        assert_eq!(DLP_METRIC_ERRORS, 2);
        assert_eq!(DLP_METRIC_EVENTS_DROPPED, 3);
        assert_eq!(DLP_METRIC_TOTAL_SEEN, 4);
        assert_eq!(DLP_METRIC_KTLS_EVENTS, 5);
        assert_eq!(DLP_METRIC_KTLS_SUPPRESSED, 6);
        assert_eq!(DLP_METRIC_KTLS_UNREADABLE, 7);
        assert_eq!(DLP_METRIC_OUT_OF_SCOPE, 8);
        assert_eq!(DLP_METRIC_COUNT, 9);
    }

    #[test]
    fn dlp_metric_count_covers_all() {
        // DLP_METRIC_COUNT must be one past the last index
        const _: () = assert!(DLP_METRIC_TOTAL_SEEN < DLP_METRIC_COUNT);
        const _: () = assert!(DLP_METRIC_KTLS_UNREADABLE < DLP_METRIC_COUNT);
        const _: () = assert!(DLP_METRIC_OUT_OF_SCOPE < DLP_METRIC_COUNT);
    }

    #[test]
    fn ktls_iter_offsets_is_a_fixed_layout_map_value() {
        // The program reads this out of an `Array` map, so its size and its
        // member offsets are part of the kernel/userspace contract.
        assert_eq!(mem::size_of::<KtlsIterOffsets>(), 32);
        assert_eq!(mem::align_of::<KtlsIterOffsets>(), 4);
        assert_eq!(mem::offset_of!(KtlsIterOffsets, msg_iter), 0);
        assert_eq!(mem::offset_of!(KtlsIterOffsets, count), 16);
        assert_eq!(mem::offset_of!(KtlsIterOffsets, iovec_len), 24);
        assert_eq!(mem::offset_of!(KtlsIterOffsets, iter_ubuf), 28);
        assert_eq!(mem::offset_of!(KtlsIterOffsets, valid), 30);
    }

    #[test]
    fn ktls_offsets_default_is_refused_by_the_probe() {
        // `valid` at zero is what an unresolved kernel leaves behind, and the
        // probe must read nothing rather than read at offset zero.
        assert_eq!(KtlsIterOffsets::default().valid, 0);
    }

    #[test]
    fn scope_modes_are_distinct_and_all_is_the_zero_value() {
        assert_eq!(DLP_SCOPE_MODE_ALL, 0);
        assert_ne!(DLP_SCOPE_MODE_ALL, DLP_SCOPE_MODE_WORKLOADS);
    }

    #[test]
    fn scope_walks_enough_ancestors_for_a_kubernetes_hierarchy() {
        // kubepods.slice / kubepods-besteffort.slice / kubepods-pod<uid>.slice
        // / cri-containerd-<hash>.scope, plus room for a node whose kubelet
        // sits under another slice of its own.
        const { assert!(DLP_SCOPE_ANCESTOR_LEVELS >= 4) };
    }

    #[test]
    fn ktls_suppress_window_outlives_one_call_frame() {
        // Long enough for SSL_write to reach tls_sw_sendmsg, short enough that
        // a process which stopped going through a probed library is captured.
        assert_eq!(DLP_KTLS_SUPPRESS_WINDOW_NS, 100_000_000);
    }
}
