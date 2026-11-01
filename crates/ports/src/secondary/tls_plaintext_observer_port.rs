//! Optional observer of the TLS plaintext the library uprobes capture.
//!
//! The DLP probes read the cleartext a process hands to `SSL_write` or gets
//! back from `SSL_read`, before encryption and after decryption. DLP scans
//! that buffer for data leaving; an observer registered through
//! `EventDispatcher::with_tls_plaintext_observer` is handed the same buffer,
//! in either direction, so an extension can inspect what a server received
//! over HTTPS without terminating TLS itself.
//!
//! The buffer is lent for the duration of the call and is never retained by
//! the dispatcher. It is an excerpt bounded by the probe, so an observer sees
//! at most the first bytes of one library call, never a reassembled stream.
//!
//! What the probes read is fenced before any observer runs: the DLP scope
//! decides which workloads the uprobes copy a byte from at all, and an
//! observer can only narrow that further.

use domain::alert::entity::Alert;
use domain::container::entity::ContainerInfo;
use domain::dlp::entity::DlpFlow;

/// Which way the plaintext was travelling through the library.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaintextDirection {
    /// Handed to the library to be encrypted and sent: data leaving.
    Write,
    /// Returned by the library once decrypted: data the process received.
    Read,
}

impl PlaintextDirection {
    /// Stable lowercase label (`"write"`, `"read"`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Write => "write",
            Self::Read => "read",
        }
    }
}

/// One buffer of TLS plaintext, with what the agent could say about whose it
/// is.
#[derive(Debug, Clone, Copy)]
pub struct TlsPlaintext<'a> {
    /// Timestamp of the capture, in nanoseconds.
    pub timestamp_ns: u64,
    /// Process id of the task that made the library call.
    pub pid: u32,
    /// Thread group id of that task.
    pub tgid: u32,
    /// Kernel cgroup v2 id of the task, 0 where none was read.
    pub cgroup_id: u64,
    pub direction: PlaintextDirection,
    /// The captured bytes, borrowed for the duration of the call.
    pub data: &'a [u8],
    /// The socket the bytes went through, where the probe could read one.
    /// Its `src` side is the local end, its `dst` side the peer.
    pub flow: Option<&'a DlpFlow>,
    /// Absolute path of the executable, where the process could still be
    /// read.
    pub exe: Option<&'a str>,
    /// Container context of the task, where a resolver is wired.
    pub container: Option<&'a ContainerInfo>,
}

/// Secondary port consulted once per captured TLS plaintext buffer.
///
/// An observer that finds something returns the alerts it raises. The caller
/// fills in what it knows better than the observer - the flow, the process,
/// the executable and the container - and sends each down the ordinary alert
/// path. On a buffer the process read, the alert's source is the peer, the
/// side that sent the bytes.
pub trait TlsPlaintextObserver: Send + Sync {
    fn observe(&self, plaintext: &TlsPlaintext<'_>) -> Vec<Alert>;

    /// Stable name of the observer, used in logs.
    fn name(&self) -> &'static str {
        "observer"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direction_labels_are_stable() {
        assert_eq!(PlaintextDirection::Write.as_str(), "write");
        assert_eq!(PlaintextDirection::Read.as_str(), "read");
    }

    #[test]
    fn tls_plaintext_observer_is_object_safe() {
        fn _check(observer: &dyn TlsPlaintextObserver, plaintext: &TlsPlaintext<'_>) {
            let _ = observer.observe(plaintext);
        }
    }
}
