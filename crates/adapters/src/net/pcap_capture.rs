#![allow(unsafe_code)] // Raw AF_PACKET capture requires libc + unsafe.
#![allow(
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

//! Rootless packet capture over an `AF_PACKET` socket pre-opened by the
//! privileged `warden` and handed to the agent on delegation.
//!
//! eBPF is loaded token-only, so the agent runs inside a child user namespace
//! and cannot create an `AF_PACKET` socket itself - `CAP_NET_RAW` is checked
//! against the host network namespace, which is owned by the initial user
//! namespace. The warden creates the sockets while it holds `CAP_NET_RAW` and
//! passes their fds to the agent over the control socket (advertised via
//! `EBPFSENTINEL_PCAP_FDS`). The `CAP_NET_RAW` check is enforced **only** at
//! `socket()` time, so the user-namespace agent can bind, attach a filter and
//! read on a received socket with no capability of its own.

use std::os::fd::RawFd;
use std::sync::{Arc, Mutex, OnceLock};

use ebpfsentinel_warden_client::ReconnectingClient;
use ports::secondary::metrics_port::MetricsPort;

/// A pool of `AF_PACKET` sockets inherited from the launcher or the warden.
///
/// Captures borrow a socket for their lifetime and return it on drop. The
/// capture engine serialises captures, so in practice one socket is reused
/// sequentially; the pool simply allows headroom for concurrent captures.
pub struct PcapSocketPool {
    free: Mutex<Vec<RawFd>>,
    /// Pool size, for the gauge: `free` only says what is left.
    total: usize,
    /// Where the borrow/return gauge goes once the agent has its registry. The
    /// pool is built before the metrics are wired, so this arrives after.
    metrics: OnceLock<Arc<dyn MetricsPort>>,
    /// The warden connection the sockets arrived over, held open for the life of
    /// the pool. The warden binds each socket it hands out to the connection
    /// that asked for it and takes it back when that connection goes, so
    /// dropping this client would offer another agent a socket this process is
    /// still reading from. `None` in the launcher deployment, where the fds come
    /// from the environment and no connection is involved.
    _warden_link: Option<Mutex<ReconnectingClient>>,
}

impl PcapSocketPool {
    /// Build a pool from the `EBPFSENTINEL_PCAP_FDS` env var (a comma-separated
    /// fd list set by the launcher). Returns `None` when unset or empty - packet
    /// capture then degrades gracefully (no sockets to capture on).
    #[must_use]
    pub fn from_env() -> Option<Arc<Self>> {
        let raw = std::env::var("EBPFSENTINEL_PCAP_FDS").ok()?;
        let fds: Vec<RawFd> = raw
            .split(',')
            .filter(|s| !s.is_empty())
            .filter_map(|s| s.parse::<RawFd>().ok())
            .filter(|&fd| fd >= 0)
            .collect();
        if fds.is_empty() {
            return None;
        }
        tracing::info!(
            count = fds.len(),
            "packet-capture sockets provisioned by the launcher"
        );
        Some(Self::build(fds, None))
    }

    /// Construct a pool from explicit fds (used in tests).
    #[must_use]
    pub fn from_fds(fds: Vec<RawFd>) -> Arc<Self> {
        Self::build(fds, None)
    }

    /// Construct a pool from sockets the warden handed over, keeping its
    /// connection open for the life of the pool so the warden does not take the
    /// sockets back while captures are still reading them.
    #[must_use]
    pub fn from_warden(fds: Vec<RawFd>, link: ReconnectingClient) -> Arc<Self> {
        Self::build(fds, Some(link))
    }

    fn build(fds: Vec<RawFd>, link: Option<ReconnectingClient>) -> Arc<Self> {
        let total = fds.len();
        Arc::new(Self {
            free: Mutex::new(fds),
            total,
            metrics: OnceLock::new(),
            _warden_link: link.map(Mutex::new),
        })
    }

    /// Publish the borrow gauge to `metrics` from now on, and publish it once
    /// for the pool as it stands. Ignored if called twice.
    pub fn attach_metrics(&self, metrics: Arc<dyn MetricsPort>) {
        if self.metrics.set(metrics).is_ok() {
            self.publish();
        }
    }

    /// Pool size.
    #[must_use]
    pub fn total(&self) -> usize {
        self.total
    }

    /// Number of sockets currently available.
    #[must_use]
    pub fn available(&self) -> usize {
        self.free.lock().map_or(0, |f| f.len())
    }

    /// Number of sockets currently borrowed.
    #[must_use]
    pub fn in_use(&self) -> usize {
        self.total.saturating_sub(self.available())
    }

    /// Borrow a socket. Returns `None` when every socket is in use.
    #[must_use]
    pub fn borrow(self: &Arc<Self>) -> Option<PcapLease> {
        let fd = self.free.lock().ok()?.pop()?;
        let lease = PcapLease {
            fd,
            pool: Arc::clone(self),
        };
        self.publish();
        Some(lease)
    }

    fn publish(&self) {
        if let Some(metrics) = self.metrics.get() {
            metrics.set_pcap_sockets(self.in_use() as u64, self.total as u64);
        }
    }
}

/// RAII lease that returns its socket to the pool on drop.
pub struct PcapLease {
    fd: RawFd,
    pool: Arc<PcapSocketPool>,
}

impl PcapLease {
    /// The borrowed socket fd.
    #[must_use]
    pub fn fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for PcapLease {
    fn drop(&mut self) {
        if let Ok(mut free) = self.pool.free.lock() {
            free.push(self.fd);
        }
        self.pool.publish();
    }
}

/// How long the reader sleeps when the socket had nothing to give, and so the
/// longest a stop waits to be observed.
pub const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(50);

/// Statistics returned by [`run_capture`].
pub struct CaptureStats {
    /// Packets written to the capture file.
    pub packets: u64,
    /// Size of the capture file in bytes.
    pub file_size: u64,
}

/// Run a time-bounded capture on an inherited `AF_PACKET` socket, writing a pcap
/// file at `output_path`.
///
/// Binds the socket to `interface` (`"any"`/empty = all interfaces), enables
/// promiscuous mode, attaches the compiled BPF `filter` (empty = capture
/// everything) and reads frames until `duration` elapses or `stop` is raised,
/// whichever comes first. The socket is left clean (filter detached,
/// promiscuous mode dropped) so the pool can reuse it.
///
/// `stop` is read once per iteration of a loop that already polls, so a stop
/// costs one atomic load and is observed within [`POLL_INTERVAL`] rather than
/// at the end of a duration an operator may have set to five minutes. The
/// return path is the one the duration already took, which is what makes the
/// file a valid short capture rather than a half-written one: the savefile is
/// flushed and closed before the function returns either way.
#[cfg(feature = "pcap-capture")]
pub fn run_capture(
    fd: RawFd,
    interface: &str,
    filter: &str,
    duration: std::time::Duration,
    snap_length: u32,
    output_path: &str,
    stop: &domain::capture::entity::CaptureStop,
) -> Result<CaptureStats, String> {
    use pcap::{Capture, Linktype, Packet, PacketHeader};
    use std::time::{Instant, SystemTime, UNIX_EPOCH};

    let ifindex = resolve_ifindex(interface)?;
    bind_packet(fd, ifindex)?;
    // Promiscuous mode is best effort - some links (loopback, "any") reject it.
    let promisc = ifindex != 0 && set_promisc(fd, ifindex, true).is_ok();

    // A dead capture handle compiles filters and writes the pcap file without
    // touching a live device, so it needs no privilege.
    let dead = Capture::dead(Linktype::ETHERNET).map_err(|e| format!("pcap dead handle: {e}"))?;
    let filter_attached = if filter.is_empty() {
        false
    } else {
        let prog = dead
            .compile(filter, true)
            .map_err(|_| "BPF filter compilation failed - check filter syntax".to_string())?;
        attach_filter(fd, prog.get_instructions())?;
        true
    };
    // A state directory mounted empty has no `captures/` in it yet.
    if let Some(parent) = std::path::Path::new(output_path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("pcap directory create failed: {e}"))?;
    }
    let mut savefile = dead
        .savefile(output_path)
        .map_err(|e| format!("pcap file create failed: {e}"))?;

    let snaplen = (snap_length.max(64)) as usize;
    let mut buf = vec![0u8; 65_536];
    let deadline = Instant::now() + duration;
    let mut packets: u64 = 0;

    while Instant::now() < deadline && !stop.requested() {
        // SAFETY: `buf` is a valid writable region of `buf.len()` bytes.
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), libc::MSG_DONTWAIT) };
        if n > 0 {
            let len = n as usize;
            let caplen = len.min(snaplen);
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default();
            let header = PacketHeader {
                ts: libc::timeval {
                    tv_sec: now.as_secs() as _,
                    tv_usec: now.subsec_micros() as _,
                },
                caplen: caplen as u32,
                len: len as u32,
            };
            savefile.write(&Packet::new(&header, &buf[..caplen]));
            packets += 1;
        } else {
            // No frame ready (EAGAIN) - yield briefly and re-check the deadline
            // without busy-spinning.
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    savefile.flush().ok();
    drop(savefile);
    if filter_attached {
        detach_filter(fd);
    }
    if promisc {
        let _ = set_promisc(fd, ifindex, false);
    }

    let file_size = std::fs::metadata(output_path).map_or(0, |m| m.len());
    Ok(CaptureStats { packets, file_size })
}

/// One frame read off the socket, as [`stream_frames`] hands it over.
pub struct Frame<'a> {
    /// When the frame was read, in nanoseconds since the Unix epoch: the same
    /// clock the agent stamps an alert with, so a window around an alert is a
    /// comparison and not a conversion.
    pub timestamp_ns: u64,
    /// The frame from its Ethernet header, cut at the snap length.
    pub data: &'a [u8],
    /// The frame's length on the wire, before the cut.
    pub original_len: u32,
}

/// Read frames off an inherited `AF_PACKET` socket and hand each one to `sink`
/// until `stop` is raised.
///
/// Unlike [`run_capture`] this writes nothing: what to keep, for how long and
/// whether any of it reaches a disk is the caller's decision. The socket is
/// bound to `interface` and put in promiscuous mode where the link accepts it,
/// and is left clean on return so the pool can lend it again.
///
/// # Errors
///
/// Returns a message when the interface cannot be resolved or the socket
/// cannot be bound; a read that finds nothing is not an error.
pub fn stream_frames(
    fd: RawFd,
    interface: &str,
    snap_length: u32,
    stop: &domain::capture::entity::CaptureStop,
    sink: &mut dyn FnMut(Frame<'_>),
) -> Result<u64, String> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let ifindex = resolve_ifindex(interface)?;
    bind_packet(fd, ifindex)?;
    let promisc = ifindex != 0 && set_promisc(fd, ifindex, true).is_ok();

    let snaplen = (snap_length.max(64)) as usize;
    let mut buf = vec![0u8; 65_536];
    let mut frames: u64 = 0;
    while !stop.requested() {
        // SAFETY: `buf` is a valid writable region of `buf.len()` bytes.
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), libc::MSG_DONTWAIT) };
        if n > 0 {
            let len = n as usize;
            let timestamp_ns = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX));
            sink(Frame {
                timestamp_ns,
                data: &buf[..len.min(snaplen)],
                original_len: len as u32,
            });
            frames += 1;
        } else {
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    if promisc {
        let _ = set_promisc(fd, ifindex, false);
    }
    Ok(frames)
}

/// Resolve an interface name to its index. `"any"`/empty yields `0` (all
/// interfaces, unbound).
fn resolve_ifindex(interface: &str) -> Result<i32, String> {
    if interface.is_empty() || interface == "any" {
        return Ok(0);
    }
    let cname =
        std::ffi::CString::new(interface).map_err(|_| "interface name has NUL".to_string())?;
    // SAFETY: `cname` is a valid NUL-terminated C string.
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if idx == 0 {
        return Err(format!("unknown interface '{interface}'"));
    }
    Ok(idx as i32)
}

/// Bind an `AF_PACKET` socket to `(ifindex, ETH_P_ALL)`. The `CAP_NET_RAW` check
/// already happened at `socket()`; `bind` does not re-check it.
fn bind_packet(fd: RawFd, ifindex: i32) -> Result<(), String> {
    // SAFETY: `sockaddr_ll` is `#[repr(C)]` integers only, for which all-zero is a valid value.
    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
    addr.sll_ifindex = ifindex;
    // SAFETY: `addr` is a fully-initialised sockaddr_ll of the given length.
    let rc = unsafe {
        libc::bind(
            fd,
            std::ptr::from_ref(&addr).cast(),
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(format!(
            "bind(AF_PACKET) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Add or drop promiscuous-mode membership on `ifindex`.
fn set_promisc(fd: RawFd, ifindex: i32, on: bool) -> Result<(), String> {
    // SAFETY: `packet_mreq` is `#[repr(C)]` integers only, for which all-zero is a valid value.
    let mut mreq: libc::packet_mreq = unsafe { std::mem::zeroed() };
    mreq.mr_ifindex = ifindex;
    mreq.mr_type = libc::PACKET_MR_PROMISC as u16;
    let opt = if on {
        libc::PACKET_ADD_MEMBERSHIP
    } else {
        libc::PACKET_DROP_MEMBERSHIP
    };
    // SAFETY: `mreq` is a fully-initialised packet_mreq of the given length.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_PACKET,
            opt,
            std::ptr::from_ref(&mreq).cast(),
            std::mem::size_of::<libc::packet_mreq>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(format!(
            "promiscuous setsockopt failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Attach a libpcap-compiled BPF program to the socket via `SO_ATTACH_FILTER`.
#[cfg(feature = "pcap-capture")]
fn attach_filter(fd: RawFd, insns: &[pcap::BpfInstruction]) -> Result<(), String> {
    // `pcap::BpfInstruction` is `#[repr(transparent)]` over libpcap's `bpf_insn`,
    // whose layout (`code: u16, jt: u8, jf: u8, k: u32`) is identical to
    // `libc::sock_filter`, so the slice is reinterpretable as `sock_filter[]`.
    let len: u16 = insns
        .len()
        .try_into()
        .map_err(|_| "BPF program too long".to_string())?;
    let prog = libc::sock_fprog {
        len,
        filter: insns.as_ptr() as *mut libc::sock_filter,
    };
    // SAFETY: `prog` points at `len` valid sock_filter instructions for the
    // duration of the call; the kernel copies them.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            std::ptr::from_ref(&prog).cast(),
            std::mem::size_of::<libc::sock_fprog>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(format!(
            "SO_ATTACH_FILTER failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Detach any attached BPF program (best effort).
#[cfg(feature = "pcap-capture")]
fn detach_filter(fd: RawFd) {
    let zero: libc::c_int = 0;
    // SAFETY: SO_DETACH_FILTER takes an int option of the given length.
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_DETACH_FILTER,
            std::ptr::from_ref(&zero).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_env_absent_is_none() {
        // SAFETY: single-threaded test mutating process env.
        unsafe { std::env::remove_var("EBPFSENTINEL_PCAP_FDS") };
        assert!(PcapSocketPool::from_env().is_none());
    }

    #[test]
    fn pool_borrow_and_return() {
        let pool = PcapSocketPool::from_fds(vec![10, 11]);
        assert_eq!(pool.available(), 2);
        let lease = pool.borrow().expect("borrow");
        assert_eq!(pool.available(), 1);
        assert!(lease.fd() == 11 || lease.fd() == 10);
        drop(lease);
        assert_eq!(pool.available(), 2);
    }

    #[test]
    fn pool_exhaustion_returns_none() {
        let pool = PcapSocketPool::from_fds(vec![10]);
        let _held = pool.borrow().expect("first borrow");
        assert!(pool.borrow().is_none());
    }

    /// Records what the pool published, latest last.
    #[derive(Default)]
    struct RecordingMetrics {
        readings: std::sync::Mutex<Vec<(u64, u64)>>,
    }

    impl ports::secondary::metrics_port::SystemMetrics for RecordingMetrics {
        fn set_pcap_sockets(&self, in_use: u64, total: u64) {
            if let Ok(mut readings) = self.readings.lock() {
                readings.push((in_use, total));
            }
        }
    }

    impl ports::secondary::metrics_port::PacketMetrics for RecordingMetrics {}
    impl ports::secondary::metrics_port::FirewallMetrics for RecordingMetrics {}
    impl ports::secondary::metrics_port::AlertMetrics for RecordingMetrics {}
    impl ports::secondary::metrics_port::IpsMetrics for RecordingMetrics {}
    impl ports::secondary::metrics_port::DnsMetrics for RecordingMetrics {}
    impl ports::secondary::metrics_port::DomainMetrics for RecordingMetrics {}
    impl ports::secondary::metrics_port::ConfigMetrics for RecordingMetrics {}
    impl ports::secondary::metrics_port::EventMetrics for RecordingMetrics {}
    impl ports::secondary::metrics_port::DlpMetrics for RecordingMetrics {}
    impl ports::secondary::metrics_port::DdosMetrics for RecordingMetrics {}
    impl ports::secondary::metrics_port::ConntrackMetrics for RecordingMetrics {}
    impl ports::secondary::metrics_port::RoutingMetrics for RecordingMetrics {}
    impl ports::secondary::metrics_port::AuditMetrics for RecordingMetrics {}
    impl ports::secondary::metrics_port::LbMetrics for RecordingMetrics {}
    impl ports::secondary::metrics_port::FingerprintMetrics for RecordingMetrics {}
    impl ports::secondary::metrics_port::ContainerMetrics for RecordingMetrics {}
    impl ports::secondary::metrics_port::CtMetrics for RecordingMetrics {}
    impl ports::secondary::metrics_port::ZoneMetrics for RecordingMetrics {}
    impl ports::secondary::metrics_port::ThreatIntelMetrics for RecordingMetrics {}

    #[test]
    fn a_stream_on_an_unknown_interface_reads_nothing() {
        let stop = domain::capture::entity::CaptureStop::new();
        let mut seen = 0_u32;
        let result = stream_frames(-1, "no-such-iface-zz9", 1500, &stop, &mut |_| seen += 1);
        assert!(result.is_err_and(|e| e.contains("unknown interface")));
        assert_eq!(seen, 0);
    }

    #[test]
    fn a_stream_on_a_socket_that_will_not_bind_reads_nothing() {
        let stop = domain::capture::entity::CaptureStop::new();
        let mut seen = 0_u32;
        let result = stream_frames(-1, "any", 1500, &stop, &mut |_| seen += 1);
        assert!(result.is_err_and(|e| e.contains("bind(AF_PACKET) failed")));
        assert_eq!(seen, 0);
    }

    #[test]
    fn the_gauge_follows_every_borrow_and_return() {
        let pool = PcapSocketPool::from_fds(vec![10, 11]);
        let metrics = Arc::new(RecordingMetrics::default());
        pool.attach_metrics(Arc::clone(&metrics) as Arc<dyn MetricsPort>);

        let first = pool.borrow().expect("first borrow");
        let second = pool.borrow().expect("second borrow");
        assert_eq!(pool.in_use(), 2);
        drop(first);
        drop(second);

        let readings = metrics.readings.lock().unwrap().clone();
        assert_eq!(
            readings,
            vec![(0, 2), (1, 2), (2, 2), (1, 2), (0, 2)],
            "attaching publishes the pool as it stands, then every borrow and return"
        );
        assert_eq!(pool.total(), 2);
        assert_eq!(pool.in_use(), 0);
    }

    #[test]
    fn a_pool_with_no_metrics_still_lends() {
        let pool = PcapSocketPool::from_fds(vec![10]);
        let lease = pool.borrow().expect("borrow with no registry attached");
        assert_eq!(pool.in_use(), 1);
        drop(lease);
        assert_eq!(pool.in_use(), 0);
    }
}
