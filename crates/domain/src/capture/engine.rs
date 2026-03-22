use std::collections::HashMap;

use super::entity::{CaptureSession, CaptureStatus};

/// Manages manual packet capture sessions.
///
/// Enforces single-active-capture constraint and max duration.
pub struct CaptureEngine {
    sessions: HashMap<String, CaptureSession>,
    max_duration_secs: u64,
}

impl CaptureEngine {
    pub fn new(max_duration_secs: u64) -> Self {
        Self {
            sessions: HashMap::new(),
            max_duration_secs,
        }
    }

    /// Maximum allowed capture duration.
    pub fn max_duration_secs(&self) -> u64 {
        self.max_duration_secs
    }

    /// Whether a capture is currently running.
    pub fn has_active(&self) -> bool {
        self.sessions
            .values()
            .any(|s| s.status == CaptureStatus::Running)
    }

    /// Get the active capture session, if any.
    pub fn active(&self) -> Option<&CaptureSession> {
        self.sessions
            .values()
            .find(|s| s.status == CaptureStatus::Running)
    }

    /// Register a new capture session. Fails if another is already running
    /// or if duration exceeds max.
    pub fn start(&mut self, session: CaptureSession) -> Result<(), String> {
        if self.has_active() {
            return Err("another capture is already running".to_string());
        }
        if session.duration_secs > self.max_duration_secs {
            return Err(format!(
                "duration {}s exceeds maximum {}s",
                session.duration_secs, self.max_duration_secs
            ));
        }
        self.sessions.insert(session.id.clone(), session);
        Ok(())
    }

    /// Mark a capture as stopped.
    pub fn stop(&mut self, id: &str) -> Option<&CaptureSession> {
        let session = self.sessions.get_mut(id)?;
        if session.status == CaptureStatus::Running {
            session.status = CaptureStatus::Stopped;
        }
        Some(session)
    }

    /// Mark a capture as completed with final stats.
    pub fn complete(&mut self, id: &str, file_size_bytes: u64, packets_captured: u64) {
        if let Some(session) = self.sessions.get_mut(id)
            && session.status == CaptureStatus::Running
        {
            session.status = CaptureStatus::Completed;
            session.file_size_bytes = file_size_bytes;
            session.packets_captured = packets_captured;
        }
    }

    /// Mark a capture as failed.
    pub fn fail(&mut self, id: &str) {
        if let Some(session) = self.sessions.get_mut(id) {
            session.status = CaptureStatus::Failed;
        }
    }

    /// List all capture sessions (active and historical).
    pub fn list(&self) -> Vec<&CaptureSession> {
        self.sessions.values().collect()
    }

    /// Get a session by ID.
    pub fn get(&self, id: &str) -> Option<&CaptureSession> {
        self.sessions.get(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_session(id: &str, duration: u64) -> CaptureSession {
        CaptureSession {
            id: id.to_string(),
            filter: "host 1.2.3.4".to_string(),
            duration_secs: duration,
            snap_length: 1500,
            output_path: format!("/var/lib/ebpfsentinel/captures/{id}.pcap"),
            interface: "eth0".to_string(),
            status: CaptureStatus::Running,
            started_at_ns: 1_000_000_000,
            file_size_bytes: 0,
            packets_captured: 0,
        }
    }

    #[test]
    fn start_and_list() {
        let mut engine = CaptureEngine::new(300);
        engine.start(make_session("cap-1", 60)).unwrap();
        assert_eq!(engine.list().len(), 1);
        assert!(engine.has_active());
    }

    #[test]
    fn concurrent_capture_rejected() {
        let mut engine = CaptureEngine::new(300);
        engine.start(make_session("cap-1", 60)).unwrap();
        let result = engine.start(make_session("cap-2", 60));
        assert!(result.is_err());
    }

    #[test]
    fn duration_exceeds_max() {
        let mut engine = CaptureEngine::new(300);
        let result = engine.start(make_session("cap-1", 600));
        assert!(result.is_err());
    }

    #[test]
    fn stop_capture() {
        let mut engine = CaptureEngine::new(300);
        engine.start(make_session("cap-1", 60)).unwrap();
        let session = engine.stop("cap-1").unwrap();
        assert_eq!(session.status, CaptureStatus::Stopped);
        assert!(!engine.has_active());
    }

    #[test]
    fn complete_capture() {
        let mut engine = CaptureEngine::new(300);
        engine.start(make_session("cap-1", 60)).unwrap();
        engine.complete("cap-1", 1024, 42);
        let session = engine.get("cap-1").unwrap();
        assert_eq!(session.status, CaptureStatus::Completed);
        assert_eq!(session.file_size_bytes, 1024);
        assert_eq!(session.packets_captured, 42);
    }

    #[test]
    fn after_stop_can_start_new() {
        let mut engine = CaptureEngine::new(300);
        engine.start(make_session("cap-1", 60)).unwrap();
        engine.stop("cap-1");
        engine.start(make_session("cap-2", 60)).unwrap();
        assert!(engine.has_active());
    }
}
