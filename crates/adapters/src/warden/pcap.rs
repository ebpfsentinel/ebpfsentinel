//! Building a packet-capture socket pool from the warden (rootless deployment).
//!
//! Rootless capture needs an `AF_PACKET`/`SOCK_RAW` socket, but `socket()` checks
//! `CAP_NET_RAW` against the host network namespace, which the capability-dropped
//! agent does not hold. In the launcher deployment a privileged launcher pre-opens
//! the sockets and passes them via `EBPFSENTINEL_PCAP_FDS`; in the warden
//! deployment the warden performs the privileged `socket()`+`bind()` and hands the
//! fd over `SCM_RIGHTS`. Either way the agent only ever *binds*, *filters* and
//! *reads* an already-created socket — operations the kernel allows with no
//! capability — so the same [`PcapSocketPool`] consumes the fds unchanged.
//!
//! The warden binds each socket to a real interface at `socket()` time, but the
//! agent rebinds it to the requested capture interface per capture (rebinding an
//! existing `AF_PACKET` socket needs no capability), so the warden's initial bind
//! interface is only a placeholder to satisfy the privileged open.

use std::os::fd::{IntoRawFd, RawFd};
use std::path::Path;
use std::sync::Arc;

use ebpfsentinel_warden_client::ReconnectingClient;
use tracing::{info, warn};

use crate::net::pcap_capture::PcapSocketPool;

/// Open `count` `AF_PACKET` capture sockets through the warden and wrap them in a
/// [`PcapSocketPool`]. `placeholder_iface` is the interface the warden binds each
/// socket to initially (the agent rebinds per capture). Returns `None` when the
/// warden serves no socket (e.g. `PcapOpen` unimplemented or every open failed),
/// so capture degrades gracefully exactly as with no launcher-provisioned pool.
#[must_use]
pub fn pool_from_warden(
    sock: &Path,
    placeholder_iface: &str,
    count: usize,
) -> Option<Arc<PcapSocketPool>> {
    let mut client = ReconnectingClient::new(sock.to_path_buf());
    let mut fds: Vec<RawFd> = Vec::with_capacity(count);
    for _ in 0..count {
        match client.pcap_open(placeholder_iface, "") {
            // The pool owns the fd for the process lifetime (it never closes its
            // fds, matching the launcher model); transfer ownership out of the
            // `OwnedFd` so it is not double-closed.
            Ok(owned) => fds.push(owned.into_raw_fd()),
            Err(e) => {
                warn!(iface = placeholder_iface, error = %e, "warden pcap socket open failed");
                break;
            }
        }
    }
    if fds.is_empty() {
        return None;
    }
    info!(
        count = fds.len(),
        "packet-capture sockets provisioned by the warden"
    );
    Some(PcapSocketPool::from_fds(fds))
}
