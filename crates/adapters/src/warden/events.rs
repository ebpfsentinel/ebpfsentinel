//! Wiring the rootless agent's event readers to the warden's ring-buffer fds.
//!
//! In the in-process deployment each loaded program hands its `RingBuf` map to a
//! reader directly. The rootless (warden-client) agent loads nothing, so it asks
//! the warden — which loaded the programs and holds the maps — for each
//! ring-buffer fd over `SCM_RIGHTS`, then drains it with `mmap`+`poll` exactly as
//! if it had created the map itself. No `bpf()` is issued in the agent.
//!
//! The warden serves ring buffers by map name. Two are addressed by their real
//! name — the shared packet `EVENTS` ring buffer and `DNS_EVENTS`. The uprobe-dlp
//! ring buffer is also named `EVENTS` in its object, so the warden exposes it
//! under the distinct alias [`DLP_EVENTS_KEY`] to avoid colliding with the packet
//! ring buffer in its flat map registry.
//!
//! Each fetch is best-effort: a ring buffer the warden does not (yet) serve is
//! logged and skipped, so the agent lights up readers as the warden's loaded set
//! grows, rather than failing startup.

use std::path::PathBuf;

use domain::common::agent_event::AgentEvent;
use ebpfsentinel_warden_client::ReconnectingClient;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::ebpf::{DlpEventReader, DnsEventReader, EventReader};

/// Warden map name of the shared packet/L4/L7 ring buffer.
const EVENTS_KEY: &str = "EVENTS";
/// Warden map name of the DNS-capture ring buffer.
const DNS_EVENTS_KEY: &str = "DNS_EVENTS";
/// Warden alias for the uprobe-dlp ring buffer (whose raw map name `EVENTS`
/// collides with the packet ring buffer).
const DLP_EVENTS_KEY: &str = "DLP_EVENTS";

/// The ring-buffer fds the warden handed over, any of which may be absent when
/// the warden has not loaded that program.
struct RingbufFds {
    events: Option<std::os::fd::OwnedFd>,
    dns: Option<std::os::fd::OwnedFd>,
    dlp: Option<std::os::fd::OwnedFd>,
}

/// Connect to the warden, fetch the event ring-buffer fds, and spawn a reader for
/// each one the warden serves, draining into `event_tx`. Returns the number of
/// readers started. Readers run until `cancel` fires or the channel closes.
pub async fn spawn_event_readers(
    sock: PathBuf,
    event_tx: mpsc::Sender<AgentEvent>,
    cancel: CancellationToken,
) -> usize {
    // The warden request/response is blocking socket I/O; fetch the fds off the
    // async runtime, then build the epoll-backed readers back on it.
    let fds = tokio::task::spawn_blocking(move || fetch_ringbuf_fds(&sock))
        .await
        .unwrap_or_else(|e| {
            warn!(error = %e, "warden ring-buffer fetch task panicked");
            RingbufFds {
                events: None,
                dns: None,
                dlp: None,
            }
        });

    let mut started = 0usize;

    if let Some(fd) = fds.events {
        match EventReader::from_ringbuf_fd(fd) {
            Ok(reader) => {
                let tx = event_tx.clone();
                let cancel = cancel.clone();
                tokio::spawn(async move { reader.run(tx, cancel).await });
                started += 1;
            }
            Err(e) => warn!(error = %e, "failed to build packet EventReader from warden fd"),
        }
    }

    if let Some(fd) = fds.dns {
        match DnsEventReader::from_ringbuf_fd(fd) {
            Ok(reader) => {
                let tx = event_tx.clone();
                let cancel = cancel.clone();
                tokio::spawn(async move { reader.run(tx, cancel).await });
                started += 1;
            }
            Err(e) => warn!(error = %e, "failed to build DnsEventReader from warden fd"),
        }
    }

    if let Some(fd) = fds.dlp {
        match DlpEventReader::from_ringbuf_fd(fd) {
            Ok(reader) => {
                let tx = event_tx.clone();
                let cancel = cancel.clone();
                tokio::spawn(async move { reader.run(tx, cancel).await });
                started += 1;
            }
            Err(e) => warn!(error = %e, "failed to build DlpEventReader from warden fd"),
        }
    }

    started
}

/// Open one warden connection and request each event ring buffer, skipping any
/// the warden does not serve.
fn fetch_ringbuf_fds(sock: &std::path::Path) -> RingbufFds {
    let mut client = ReconnectingClient::new(sock.to_path_buf());
    RingbufFds {
        events: request_ringbuf(&mut client, EVENTS_KEY),
        dns: request_ringbuf(&mut client, DNS_EVENTS_KEY),
        dlp: request_ringbuf(&mut client, DLP_EVENTS_KEY),
    }
}

/// Request a single ring-buffer fd, logging and swallowing a warden that does not
/// serve it (the program is not loaded) so absence never fails agent startup.
fn request_ringbuf(client: &mut ReconnectingClient, name: &str) -> Option<std::os::fd::OwnedFd> {
    match client.get_ringbuf_fd(name) {
        Ok(fd) => {
            info!(map = name, "warden ring-buffer fd acquired");
            Some(fd)
        }
        Err(e) => {
            warn!(map = name, error = %e, "warden ring-buffer unavailable; reader skipped");
            None
        }
    }
}
