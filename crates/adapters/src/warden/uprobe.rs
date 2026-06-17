//! Warden-brokered DLP discovery + uprobe attach for the rootless agent.
//!
//! Under `cap-drop: ALL` the agent can neither read a neighbouring container's
//! `/proc` (`CAP_SYS_PTRACE`) nor create a uprobe `BPF_LINK_CREATE`, so both the
//! `/proc` scan (with offsets pre-resolved) and the attach are brokered to the
//! warden, which holds the tracing capability. The agent keeps only the link fds
//! and the attach lifecycle.

use std::io;
use std::os::fd::{OwnedFd, RawFd};
use std::path::Path;

use ebpfsentinel_warden_client::{DlpTarget, ReconnectingClient};
use tracing::warn;

/// Scan `/proc` for SSL libraries through the warden. Returns the deduped targets
/// (with offsets resolved), or an empty list if the warden is unreachable — the
/// reconcile then simply detaches everything non-sticky and retries next tick.
pub fn scan_via_warden(sock: &Path) -> Vec<DlpTarget> {
    let mut client = ReconnectingClient::new(sock.to_path_buf());
    match client.dlp_scan() {
        Ok(targets) => targets,
        Err(e) => {
            warn!(error = %e, "warden DLP scan failed; no targets this pass");
            Vec::new()
        }
    }
}

/// Attach a single uprobe link through the warden at `sock`. Returns the link fd;
/// the agent owns it and dropping it detaches.
pub fn attach_via_warden(
    sock: &Path,
    prog_fd: RawFd,
    path: &str,
    offset: u64,
    is_ret: bool,
) -> io::Result<OwnedFd> {
    let mut client = ReconnectingClient::new(sock.to_path_buf());
    client.attach_uprobe(path, offset, is_ret, prog_fd)
}
