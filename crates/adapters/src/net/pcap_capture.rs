#![allow(unsafe_code)] // Raw AF_PACKET capture requires libc + unsafe.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

//! Rootless packet capture over an `AF_PACKET` socket pre-opened by the
//! privileged launcher (`ebpfsentinel-token-launch`) and inherited across exec.
//!
//! eBPF is loaded token-only, so the agent runs inside a child user namespace
//! and cannot create an `AF_PACKET` socket itself — `CAP_NET_RAW` is checked
//! against the host network namespace, which is owned by the initial user
//! namespace. The launcher creates the sockets while still global root and
//! advertises their fds via `EBPFSENTINEL_PCAP_FDS`. The `CAP_NET_RAW` check is
//! enforced **only** at `socket()` time, so the user-namespace agent can bind,
//! attach a filter and read on an inherited socket with no capability of its own.

use std::os::fd::RawFd;
use std::sync::{Arc, Mutex};

/// A pool of `AF_PACKET` sockets inherited from the launcher.
///
/// Captures borrow a socket for their lifetime and return it on drop. The
/// capture engine serialises captures, so in practice one socket is reused
/// sequentially; the pool simply allows headroom for concurrent captures.
pub struct PcapSocketPool {
    free: Mutex<Vec<RawFd>>,
}

impl PcapSocketPool {
    /// Build a pool from the `EBPFSENTINEL_PCAP_FDS` env var (a comma-separated
    /// fd list set by the launcher). Returns `None` when unset or empty — packet
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
        Some(Arc::new(Self {
            free: Mutex::new(fds),
        }))
    }

    /// Construct a pool from explicit fds (used in tests).
    #[must_use]
    pub fn from_fds(fds: Vec<RawFd>) -> Arc<Self> {
        Arc::new(Self {
            free: Mutex::new(fds),
        })
    }

    /// Number of sockets currently available.
    #[must_use]
    pub fn available(&self) -> usize {
        self.free.lock().map_or(0, |f| f.len())
    }

    /// Borrow a socket. Returns `None` when every socket is in use.
    #[must_use]
    pub fn borrow(self: &Arc<Self>) -> Option<PcapLease> {
        let fd = self.free.lock().ok()?.pop()?;
        Some(PcapLease {
            fd,
            pool: Arc::clone(self),
        })
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
    }
}

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
/// everything) and reads frames until `duration` elapses. The socket is left
/// clean (filter detached, promiscuous mode dropped) so the pool can reuse it.
#[cfg(feature = "pcap-capture")]
pub fn run_capture(
    fd: RawFd,
    interface: &str,
    filter: &str,
    duration: std::time::Duration,
    snap_length: u32,
    output_path: &str,
) -> Result<CaptureStats, String> {
    use pcap::{Capture, Linktype, Packet, PacketHeader};
    use std::time::{Instant, SystemTime, UNIX_EPOCH};

    let ifindex = resolve_ifindex(interface)?;
    bind_packet(fd, ifindex)?;
    // Promiscuous mode is best effort — some links (loopback, "any") reject it.
    let promisc = ifindex != 0 && set_promisc(fd, ifindex, true).is_ok();

    // A dead capture handle compiles filters and writes the pcap file without
    // touching a live device, so it needs no privilege.
    let dead = Capture::dead(Linktype::ETHERNET).map_err(|e| format!("pcap dead handle: {e}"))?;
    let filter_attached = if filter.is_empty() {
        false
    } else {
        let prog = dead
            .compile(filter, true)
            .map_err(|_| "BPF filter compilation failed — check filter syntax".to_string())?;
        attach_filter(fd, prog.get_instructions())?;
        true
    };
    let mut savefile = dead
        .savefile(output_path)
        .map_err(|e| format!("pcap file create failed: {e}"))?;

    let snaplen = (snap_length.max(64)) as usize;
    let mut buf = vec![0u8; 65_536];
    let deadline = Instant::now() + duration;
    let mut packets: u64 = 0;

    while Instant::now() < deadline {
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
                    tv_sec: now.as_secs() as libc::time_t,
                    tv_usec: libc::suseconds_t::from(now.subsec_micros()),
                },
                caplen: caplen as u32,
                len: len as u32,
            };
            savefile.write(&Packet::new(&header, &buf[..caplen]));
            packets += 1;
        } else {
            // No frame ready (EAGAIN) — yield briefly and re-check the deadline
            // without busy-spinning.
            std::thread::sleep(std::time::Duration::from_millis(50));
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

/// Resolve an interface name to its index. `"any"`/empty yields `0` (all
/// interfaces, unbound).
#[cfg(feature = "pcap-capture")]
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
#[cfg(feature = "pcap-capture")]
fn bind_packet(fd: RawFd, ifindex: i32) -> Result<(), String> {
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
#[cfg(feature = "pcap-capture")]
fn set_promisc(fd: RawFd, ifindex: i32, on: bool) -> Result<(), String> {
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
}
