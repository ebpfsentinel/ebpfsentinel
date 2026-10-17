use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};

/// Status of a packet capture session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureStatus {
    /// Capture is actively recording packets.
    Running,
    /// Capture completed (duration elapsed).
    Completed,
    /// Capture was stopped early by operator.
    Stopped,
    /// Capture was cut short because the agent was asked to stop. The file is
    /// a valid capture of the window that was recorded, which is why this is
    /// not `Failed`: an operator reading a short file needs to know the agent
    /// went down under it rather than that the capture went wrong.
    Interrupted,
    /// Capture failed.
    Failed,
}

/// The flag a capture's reader thread polls to learn it must stop.
///
/// The reader runs on a blocking thread around a `MSG_DONTWAIT` loop, so it
/// cannot await anything: an `AtomicBool` it already passes over on every
/// iteration is what a stop costs, where a duration was previously the only
/// way out. Held by the engine beside the session and handed to the thread, so
/// `DELETE /api/v1/captures/{id}` and the agent's own stop reach the same flag.
#[derive(Clone, Debug, Default)]
pub struct CaptureStop(Arc<AtomicBool>);

impl CaptureStop {
    /// A flag nobody has raised yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Ask the capture to stop. Idempotent: a second caller is a stop that
    /// crossed a shutdown, not an error.
    pub fn request(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    /// Whether a stop has been asked for.
    #[must_use]
    pub fn requested(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

/// Metadata for a manual packet capture session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureSession {
    /// Unique capture identifier.
    pub id: String,
    /// BPF filter expression (e.g. "host 1.2.3.4 and port 443").
    pub filter: String,
    /// Maximum capture duration in seconds.
    pub duration_secs: u64,
    /// Snap length in bytes (max bytes per packet).
    pub snap_length: u32,
    /// Output file path.
    pub output_path: String,
    /// Network interface to capture on.
    pub interface: String,
    /// Capture status.
    pub status: CaptureStatus,
    /// Start timestamp (nanoseconds since epoch).
    pub started_at_ns: u64,
    /// File size in bytes (updated on completion).
    pub file_size_bytes: u64,
    /// Number of packets captured (updated on completion).
    pub packets_captured: u64,
}

// ── Auto-capture policy (OSS) ────────────────────────────────────

/// A simple severity-based auto-capture policy.
/// When an alert matches, a short packet capture is started automatically.
#[derive(Debug, Clone)]
pub struct AutoCapturePolicy {
    pub name: String,
    pub min_severity: crate::common::entity::Severity,
    pub components: Vec<String>,
    pub duration_secs: u64,
    pub snap_length: u32,
    pub interface: String,
}

/// Request sent from the alert pipeline to the capture spawner.
#[derive(Debug, Clone)]
pub struct AutoCaptureRequest {
    pub session: CaptureSession,
    /// The flag the engine registered for this session. It travels with the
    /// request so the thread that ends up reading packets polls the same flag
    /// the API and the stop sequence raise.
    pub stop: CaptureStop,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_status_serialization() {
        assert_eq!(
            serde_json::to_string(&CaptureStatus::Running).unwrap(),
            "\"running\""
        );
        assert_eq!(
            serde_json::to_string(&CaptureStatus::Completed).unwrap(),
            "\"completed\""
        );
    }

    #[test]
    fn interrupted_serialises_as_interrupted() {
        assert_eq!(
            serde_json::to_string(&CaptureStatus::Interrupted).unwrap(),
            "\"interrupted\""
        );
    }

    #[test]
    fn a_stop_is_shared_and_idempotent() {
        let stop = CaptureStop::new();
        let reader = stop.clone();
        assert!(!reader.requested());
        stop.request();
        stop.request();
        assert!(
            reader.requested(),
            "the reader polls the flag the API raised"
        );
    }

    #[test]
    fn capture_session_roundtrip() {
        let session = CaptureSession {
            id: "cap-001".to_string(),
            filter: "host 1.2.3.4".to_string(),
            duration_secs: 60,
            snap_length: 1500,
            output_path: "/var/lib/ebpfsentinel/captures/capture.pcap".to_string(),
            interface: "eth0".to_string(),
            status: CaptureStatus::Running,
            started_at_ns: 1_000_000_000,
            file_size_bytes: 0,
            packets_captured: 0,
        };
        let json = serde_json::to_string(&session).unwrap();
        let parsed: CaptureSession = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, "cap-001");
        assert_eq!(parsed.status, CaptureStatus::Running);
    }
}
