//! Warden-brokered uprobe attach for the rootless agent.
//!
//! Under `cap-drop: ALL` the agent cannot create a uprobe `BPF_LINK_CREATE` for a
//! neighbouring container's `libssl`, so it asks the warden. The agent resolved
//! the symbol `offset` itself (a plain ELF read) and hands the warden the target
//! `path`, the `offset`, the `is_ret` flag, and its own program fd; the warden —
//! holding the tracing capability — creates the link and returns its fd.

use std::io;
use std::os::fd::{OwnedFd, RawFd};
use std::path::Path;

use ebpfsentinel_warden_client::ReconnectingClient;

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
