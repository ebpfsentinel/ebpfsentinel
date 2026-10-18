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

/// Flow provenance: the event carries no socket, so nothing is known about
/// where the plaintext went. A `SSL_write` over a plain TCP socket the probes
/// never saw is this: the alert names the process and says the destination is
/// unknown, rather than naming a destination it guessed.
pub const DLP_FLOW_SOURCE_NONE: u8 = 0;
/// Flow provenance: the five-tuple was read from the `struct sock` the kernel
/// TLS call carried in its first argument, at the moment the plaintext was
/// taken. This is the strongest identity the datapath can produce.
pub const DLP_FLOW_SOURCE_KERNEL_SOCKET: u8 = 1;
/// Flow provenance: the five-tuple came from the last socket this task was
/// seen writing through, inside `DLP_TASK_SOCKET_WINDOW_NS`. A library uprobe
/// has a buffer and no socket, so a correlated tuple is the best a userspace
/// probe can do, and it says so rather than passing itself off as a reading.
pub const DLP_FLOW_SOURCE_CORRELATED: u8 = 2;

/// Address family of a `DlpSocket`: nothing was resolved.
pub const DLP_FLOW_FAMILY_UNSPEC: u8 = 0;
/// Address family of a `DlpSocket`: `AF_INET`, as the kernel numbers it.
pub const DLP_FLOW_FAMILY_IPV4: u8 = 2;
/// Address family of a `DlpSocket`: `AF_INET6`, as the kernel numbers it.
pub const DLP_FLOW_FAMILY_IPV6: u8 = 10;

/// IP protocol carried by a `DlpSocket`. Every TLS flow the probes see is a
/// stream socket, and kernel TLS exists on TCP alone, so the value is a
/// constant of the datapath rather than a bitfield read out of `struct sock`.
pub const DLP_FLOW_PROTOCOL_TCP: u8 = 6;

/// How long a socket recorded against a task stays usable as a correlation.
///
/// The kernel TLS probes record the socket they were called on; a library
/// uprobe firing for the same write is in the same syscall, so the window only
/// has to outlive one call frame. Past it the recording is stale and the event
/// goes out with no flow rather than with the destination of an older write.
pub const DLP_TASK_SOCKET_WINDOW_NS: u64 = 100_000_000;

/// Capacity of `DLP_TASK_SOCKET`: tasks whose last socket is remembered. An
/// LRU map, so a busier node evicts the oldest rather than refusing an insert.
pub const DLP_TASK_SOCKET_MAX_TASKS: u32 = 16384;

/// How long a socket written by the socket-attribution join stays usable.
///
/// The correlation window above bounds a guess about one syscall: the library
/// uprobe and the kernel TLS probe fire inside the same call frame, so a
/// recording older than that frame is about a different write. The join is a
/// different claim. A `sockops` program records the socket at the moment the
/// connection is established, reading the tuple off the kernel's own socket,
/// and that tuple stays true for as long as the connection lives - which for
/// TLS is usually minutes, not milliseconds. Ageing it on the syscall window
/// would throw away the destination of every long-lived connection, which is
/// most of them.
///
/// It is the identity window of the attribution table, so a socket and the
/// task that opened it stop being readable at the same moment rather than one
/// outliving the other.
pub const DLP_JOINED_SOCKET_WINDOW_NS: u64 = crate::attribution::ATTRIBUTION_IDENTITY_TTL_NS;

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

/// Byte offsets of the `struct sock` members the kernel TLS probes read,
/// resolved from the running kernel's vmlinux BTF by userspace and pushed into
/// `SOCK_OFFSETS`.
///
/// Same reason as `KtlsIterOffsets`: the Rust `bpfel` target emits no CO-RE
/// relocations, so a kernel struct member cannot be relocated at load. The
/// address members live in the anonymous `struct sock_common __sk_common` at
/// the head of `struct sock`, and the two address pairs are overlaid on each
/// other by family, which is why the family is read before either.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SockOffsets {
    /// Byte offset of `sock.__sk_common` (zero on every kernel seen so far,
    /// read rather than assumed).
    pub sk_common: u32,
    /// Byte offset of `sock_common.skc_rcv_saddr`, the local IPv4 address.
    pub skc_rcv_saddr: u32,
    /// Byte offset of `sock_common.skc_daddr`, the peer IPv4 address.
    pub skc_daddr: u32,
    /// Byte offset of `sock_common.skc_num`, the local port in host order.
    pub skc_num: u32,
    /// Byte offset of `sock_common.skc_dport`, the peer port in network order.
    pub skc_dport: u32,
    /// Byte offset of `sock_common.skc_family`.
    pub skc_family: u32,
    /// Byte offset of `sock_common.skc_v6_rcv_saddr`, the local IPv6 address.
    pub skc_v6_rcv_saddr: u32,
    /// Byte offset of `sock_common.skc_v6_daddr`, the peer IPv6 address.
    pub skc_v6_daddr: u32,
    /// 1 = offsets resolved and valid, 0 = not yet populated. The probes read
    /// nothing at all while this is 0, so an event then carries no flow.
    pub valid: u8,
    pub _pad: [u8; 3],
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for SockOffsets {}

/// The socket a DLP event was taken from, as the probe could read it.
///
/// Addresses follow the convention the rest of the datapath uses: IPv4 sits in
/// word 0 as the host-order value of the big-endian address and the other three
/// words are zero; IPv6 is four host-order words. Ports are host order. A
/// `source` of `DLP_FLOW_SOURCE_NONE` means every other field is zero and the
/// event carries no destination at all.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DlpSocket {
    /// Local address, four words, see the type's own note on encoding.
    pub src_addr: [u32; 4],
    /// Peer address, same encoding.
    pub dst_addr: [u32; 4],
    /// Local port, host order.
    pub src_port: u16,
    /// Peer port, host order.
    pub dst_port: u16,
    /// `DLP_FLOW_FAMILY_*`.
    pub family: u8,
    /// IP protocol, `DLP_FLOW_PROTOCOL_TCP` wherever a socket was read.
    pub protocol: u8,
    /// `DLP_FLOW_SOURCE_*`: how the probe came by this tuple.
    pub source: u8,
    pub _pad: u8,
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for DlpSocket {}

/// The last socket a task was seen writing through, with the moment it was
/// recorded. Value type of `DLP_TASK_SOCKET`, the map a library uprobe reads to
/// correlate its buffer with a destination.
///
/// This is also the slot the socket-attribution hook fills later: it widens who
/// writes the map, never what the event carries, so the event shape does not
/// move again when a `sockops` or `cgroup/connect` program starts recording
/// plain TCP sockets here too.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DlpTaskSocket {
    /// The socket, already in the shape the event carries.
    pub socket: DlpSocket,
    /// `bpf_ktime_get_ns` when the socket was recorded.
    pub at_ns: u64,
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for DlpTaskSocket {}

/// DLP event emitted from uprobe-dlp to userspace via RingBuf.
/// Contains a header with process metadata, the socket the plaintext went
/// through where the probe could read one, and a variable-length excerpt
/// of the plaintext data captured from SSL_write or SSL_read.
/// Size: 4168 bytes (aligned to 8 bytes due to timestamp_ns/cgroup_id u64).
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
    /// The socket the plaintext was written to or read from. `source` is
    /// `DLP_FLOW_SOURCE_NONE` when the probe had no socket to read.
    pub flow: DlpSocket,
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
            .field("flow", &self.flow)
            .finish_non_exhaustive()
    }
}

/// Small DLP event (328 bytes): header + 256 bytes excerpt.
/// Used when `data_len ≤ 256`, saving ~92% RingBuf space.
/// Size: 328 bytes (aligned to 8 bytes).
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
    /// The socket the plaintext was written to or read from. See `DlpEvent`.
    pub flow: DlpSocket,
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
            .field("flow", &self.flow)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for DlpEventSmall {}

/// Bytes of header in front of either event's excerpt. The reader slices an
/// event on this, so it is read off the type rather than written out: growing
/// the header moves the excerpt and the reader follows without being edited.
pub const DLP_EVENT_HEADER_SIZE: usize = core::mem::offset_of!(DlpEvent, data_excerpt);

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
        assert_eq!(mem::size_of::<DlpEvent>(), 4168);
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
        assert_eq!(mem::offset_of!(DlpEvent, flow), 32);
        assert_eq!(mem::offset_of!(DlpEvent, data_excerpt), 72);
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
        assert_eq!(mem::size_of::<DlpEventSmall>(), 328);
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
        assert_eq!(mem::offset_of!(DlpEventSmall, flow), 32);
        assert_eq!(mem::offset_of!(DlpEventSmall, data_excerpt), 72);
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
            mem::offset_of!(DlpEvent, flow),
            mem::offset_of!(DlpEventSmall, flow)
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

    #[test]
    fn dlp_socket_is_a_fixed_layout_block() {
        assert_eq!(mem::size_of::<DlpSocket>(), 40);
        assert_eq!(mem::align_of::<DlpSocket>(), 4);
        assert_eq!(mem::offset_of!(DlpSocket, src_addr), 0);
        assert_eq!(mem::offset_of!(DlpSocket, dst_addr), 16);
        assert_eq!(mem::offset_of!(DlpSocket, src_port), 32);
        assert_eq!(mem::offset_of!(DlpSocket, dst_port), 34);
        assert_eq!(mem::offset_of!(DlpSocket, family), 36);
        assert_eq!(mem::offset_of!(DlpSocket, protocol), 37);
        assert_eq!(mem::offset_of!(DlpSocket, source), 38);
    }

    #[test]
    fn a_default_socket_claims_nothing() {
        let s = DlpSocket::default();
        assert_eq!(s.source, DLP_FLOW_SOURCE_NONE);
        assert_eq!(s.family, DLP_FLOW_FAMILY_UNSPEC);
        assert_eq!(s.dst_addr, [0; 4]);
        assert_eq!(s.dst_port, 0);
    }

    #[test]
    fn flow_sources_are_distinct_and_none_is_the_zero_value() {
        assert_eq!(DLP_FLOW_SOURCE_NONE, 0);
        assert_ne!(DLP_FLOW_SOURCE_KERNEL_SOCKET, DLP_FLOW_SOURCE_NONE);
        assert_ne!(DLP_FLOW_SOURCE_CORRELATED, DLP_FLOW_SOURCE_NONE);
        assert_ne!(DLP_FLOW_SOURCE_CORRELATED, DLP_FLOW_SOURCE_KERNEL_SOCKET);
    }

    #[test]
    fn flow_families_match_the_kernel_numbering() {
        assert_eq!(DLP_FLOW_FAMILY_IPV4, 2);
        assert_eq!(DLP_FLOW_FAMILY_IPV6, 10);
        assert_eq!(DLP_FLOW_PROTOCOL_TCP, 6);
    }

    #[test]
    fn task_socket_entry_carries_its_own_age() {
        assert_eq!(mem::size_of::<DlpTaskSocket>(), 48);
        assert_eq!(mem::align_of::<DlpTaskSocket>(), 8);
        assert_eq!(mem::offset_of!(DlpTaskSocket, socket), 0);
        assert_eq!(mem::offset_of!(DlpTaskSocket, at_ns), 40);
        assert_eq!(DlpTaskSocket::default().at_ns, 0);
    }

    #[test]
    fn sock_offsets_default_is_refused_by_the_probe() {
        assert_eq!(mem::size_of::<SockOffsets>(), 36);
        assert_eq!(mem::align_of::<SockOffsets>(), 4);
        assert_eq!(mem::offset_of!(SockOffsets, sk_common), 0);
        assert_eq!(mem::offset_of!(SockOffsets, valid), 32);
        assert_eq!(SockOffsets::default().valid, 0);
    }

    #[test]
    fn header_size_is_read_off_the_type() {
        assert_eq!(DLP_EVENT_HEADER_SIZE, 72);
        assert_eq!(
            DLP_EVENT_HEADER_SIZE,
            mem::offset_of!(DlpEventSmall, data_excerpt)
        );
        assert_eq!(
            mem::size_of::<DlpEvent>(),
            DLP_EVENT_HEADER_SIZE + DLP_MAX_EXCERPT
        );
        assert_eq!(
            mem::size_of::<DlpEventSmall>(),
            DLP_EVENT_HEADER_SIZE + DLP_SMALL_EXCERPT
        );
    }

    #[test]
    fn a_correlation_window_outlives_one_call_frame() {
        assert_eq!(DLP_TASK_SOCKET_WINDOW_NS, DLP_KTLS_SUPPRESS_WINDOW_NS);
        const { assert!(DLP_TASK_SOCKET_MAX_TASKS >= 1024) };
    }

    #[test]
    fn a_joined_socket_lives_as_long_as_the_identity_that_opened_it() {
        assert_eq!(
            DLP_JOINED_SOCKET_WINDOW_NS,
            crate::attribution::ATTRIBUTION_IDENTITY_TTL_NS
        );
        const { assert!(DLP_JOINED_SOCKET_WINDOW_NS > DLP_TASK_SOCKET_WINDOW_NS) };
    }
}
