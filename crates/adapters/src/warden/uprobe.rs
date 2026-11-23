//! Warden-brokered DLP discovery + uprobe attach for the rootless agent.
//!
//! Under `cap-drop: ALL` the agent can neither read a neighbouring container's
//! `/proc` (`CAP_SYS_PTRACE`) nor create a uprobe `BPF_LINK_CREATE`, so both the
//! `/proc` scan (with offsets pre-resolved) and the attach are brokered to the
//! warden, which holds the tracing capability. The agent keeps only the link fds
//! and the attach lifecycle.

use std::io;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::sync::Mutex;

use ebpfsentinel_warden_client::{DlpTarget, ReconnectingClient};
use tracing::warn;

/// The one connection an attacher uses for every brokered call, built once.
///
/// A client per call meant a connect, a `Hello` round trip and a warden thread
/// for every reconcile pass and every probe in it - on a host mapping a dozen
/// SSL libraries, a dozen connections a tick, each leaving a thread in the
/// warden until the socket closed. The client reconnects on its own when the
/// warden bounces, so holding it costs nothing when the broker restarts.
///
/// It is behind a `Mutex` because the attach path takes `&self` while the
/// client needs `&mut`, and because a single connection must not interleave two
/// request/response exchanges: the lock is what serialises them. The brokered
/// calls are a handful per tick, so contention is not a consideration.
#[must_use]
pub fn client_for(sock: &Path) -> Mutex<ReconnectingClient> {
    Mutex::new(ReconnectingClient::new(sock.to_path_buf()))
}

/// Take the connection, recovering a lock a previous panic poisoned: the panic
/// was in the caller, and the connection behind it is either usable or will
/// reconnect on the next call.
fn held(client: &Mutex<ReconnectingClient>) -> std::sync::MutexGuard<'_, ReconnectingClient> {
    client
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Scan `/proc` for SSL libraries through the warden. Returns the deduped targets
/// (with offsets resolved).
///
/// An unreachable warden is an error, not an empty result. Collapsing the two
/// would tell the reconcile that nothing is mapped any more, and it would tear
/// down every working probe on a warden bounce only to rebuild them a tick
/// later - a detach/attach cycle driven entirely by the broker being restarted.
pub fn scan_via_warden(client: &Mutex<ReconnectingClient>) -> io::Result<Vec<DlpTarget>> {
    held(client).dlp_scan().inspect_err(|e| {
        warn!(error = %e, "warden DLP scan failed");
    })
}

/// Attach the held uprobe program `program` at `offset` within `path` through
/// the warden. Returns the link fd; the agent owns it and dropping it
/// detaches. The agent names the program, never carries it: the warden holds
/// every uprobe program from start-up and attaches the one listed under that
/// name, entry or return as the list says.
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
    client: &Mutex<ReconnectingClient>,
    program: &str,
    path: &str,
    offset: u64,
) -> io::Result<OwnedFd> {
    held(client).attach_uprobe(program, path, offset)
}
