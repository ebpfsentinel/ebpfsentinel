// ── Constants ───────────────────────────────────────────────────────

/// Maximum bytes of plaintext captured per SSL_write/SSL_read call.
pub const DLP_MAX_EXCERPT: usize = 4096;

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

// ── Types ───────────────────────────────────────────────────────────

/// DLP event emitted from uprobe-dlp to userspace via RingBuf.
/// Contains a header with process metadata and a variable-length excerpt
/// of the plaintext data captured from SSL_write or SSL_read.
/// Size: 4120 bytes (aligned to 8 bytes due to timestamp_ns u64).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DlpEvent {
    /// Process ID (lower 32 bits of bpf_get_current_pid_tgid).
    pub pid: u32,
    /// Thread Group ID (upper 32 bits of bpf_get_current_pid_tgid).
    pub tgid: u32,
    /// Timestamp in nanoseconds (0 from kernel; userspace may override).
    pub timestamp_ns: u64,
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
            .field("data_len", &self.data_len)
            .field("direction", &self.direction)
            .finish_non_exhaustive()
    }
}

/// Per-task context saved at SSL_read entry, consumed at SSL_read return.
/// Stored in the SSL_READ_ARGS HashMap keyed by pid_tgid.
/// Size: 16 bytes (aligned to 8 bytes due to buf_ptr u64).
#[repr(C)]
#[derive(Clone, Copy)]
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
        assert_eq!(mem::size_of::<DlpEvent>(), 4120);
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
        assert_eq!(mem::offset_of!(DlpEvent, data_len), 16);
        assert_eq!(mem::offset_of!(DlpEvent, direction), 20);
        assert_eq!(mem::offset_of!(DlpEvent, _padding), 21);
        assert_eq!(mem::offset_of!(DlpEvent, data_excerpt), 24);
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
    }
}
