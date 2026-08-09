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
/// (with offsets resolved).
///
/// An unreachable warden is an error, not an empty result. Collapsing the two
/// would tell the reconcile that nothing is mapped any more, and it would tear
/// down every working probe on a warden bounce only to rebuild them a tick
/// later - a detach/attach cycle driven entirely by the broker being restarted.
pub fn scan_via_warden(sock: &Path) -> io::Result<Vec<DlpTarget>> {
    let mut client = ReconnectingClient::new(sock.to_path_buf());
    client.dlp_scan().inspect_err(|e| {
        warn!(error = %e, "warden DLP scan failed");
    })
}

/// Attach a single uprobe link through the warden at `sock`. Returns the link fd;
/// the agent owns it and dropping it detaches.
///
/// The client replays this call once if the connection drops mid-flight, and
/// that replay cannot leave two links behind. A link the warden created is kept
/// alive solely by the fd the warden holds until it reaches the agent: if the
/// connection died before the hand-off completed, the warden's copy died with
/// it and the kernel freed the link. So either the agent holds the one link, or
/// no link exists and the replay creates it. Duplicate links come from the
/// reconcile loop instead, which is why an unreachable warden skips the pass
/// rather than treating the live set as empty.
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
