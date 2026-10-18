use std::io;
use std::os::fd::{OwnedFd, RawFd};
use std::path::Path;
use std::sync::Mutex;

use ebpfsentinel_warden_client::ReconnectingClient;

/// The one connection the attribution attach uses, built once, for the same
/// reason the uprobe attach holds one: a client per call is a connect, a
/// `Hello` round trip and a warden thread per program.
#[must_use]
pub fn client_for(sock: &Path) -> Mutex<ReconnectingClient> {
    Mutex::new(ReconnectingClient::new(sock.to_path_buf()))
}

/// Take the connection, recovering a lock a previous panic poisoned.
fn held(client: &Mutex<ReconnectingClient>) -> std::sync::MutexGuard<'_, ReconnectingClient> {
    client
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Attach one cgroup program through the warden. Returns the link fd; the
/// agent owns it and dropping it detaches.
///
/// A replayed call cannot leave two links on the cgroup: the link the warden
/// created lives only as long as the fd the warden holds until the hand-off
/// completes, so a connection that died mid-flight took the link with it.
pub fn attach_via_warden(
    client: &Mutex<ReconnectingClient>,
    prog_fd: RawFd,
    cgroup_path: &str,
    attach_type: u32,
) -> io::Result<OwnedFd> {
    held(client).attach_cgroup(cgroup_path, attach_type, prog_fd)
}
