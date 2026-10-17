use std::collections::HashMap;

use super::entity::{CaptureSession, CaptureStatus, CaptureStop};
use super::retention::RetentionPolicy;

/// Manages manual packet capture sessions.
///
/// Enforces single-active-capture constraint and max duration, and holds the
/// stop flag of every capture whose reader thread is still running. A session
/// is serialisable and a flag is not, so the two are held side by side: the
/// flag is what makes a stop more than bookkeeping, and it is dropped the
/// moment the reader reports its figures, so the map is the set of captures
/// still writing rather than a history.
pub struct CaptureEngine {
    sessions: HashMap<String, CaptureSession>,
    stops: HashMap<String, CaptureStop>,
    max_duration_secs: u64,
    retention: RetentionPolicy,
}

impl CaptureEngine {
    pub fn new(max_duration_secs: u64, retention: RetentionPolicy) -> Self {
        Self {
            sessions: HashMap::new(),
            stops: HashMap::new(),
            max_duration_secs,
            retention,
        }
    }

    /// Maximum allowed capture duration.
    pub fn max_duration_secs(&self) -> u64 {
        self.max_duration_secs
    }

    /// What the capture files on disk are allowed to cost.
    ///
    /// The engine carries it because every caller that can end a capture is
    /// already holding the engine, and a sweep belongs right after a capture
    /// ends: carrying the policy anywhere else means a second path for it to
    /// arrive by and a second place for it to be forgotten.
    pub fn retention(&self) -> RetentionPolicy {
        self.retention
    }

    /// The files of the captures that are still writing.
    ///
    /// This is what a sweep must not delete: a file under a live reader.
    pub fn files_in_use(&self) -> Vec<String> {
        self.sessions
            .values()
            .filter(|s| s.status == CaptureStatus::Running)
            .map(|s| s.output_path.clone())
            .collect()
    }

    /// The ids the engine knows about, whatever their status.
    pub fn known_ids(&self) -> Vec<String> {
        self.sessions.keys().cloned().collect()
    }

    /// Record a session the engine did not start: a capture file a previous
    /// run left behind.
    ///
    /// It is held like any other finished session, so `GET /api/v1/captures`
    /// lists it, and it carries no stop flag because there is nothing left to
    /// stop. A session already known is not overwritten: what this run knows
    /// about a capture beats what its file says.
    pub fn adopt(&mut self, session: CaptureSession) {
        self.sessions.entry(session.id.clone()).or_insert(session);
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
    ///
    /// Returns the stop flag the reader must poll. The engine keeps a clone,
    /// so a capture registered here can always be stopped, which is what the
    /// caller handing the flag on cannot be trusted to guarantee.
    pub fn start(&mut self, session: CaptureSession) -> Result<CaptureStop, String> {
        if self.has_active() {
            return Err("another capture is already running".to_string());
        }
        if session.duration_secs > self.max_duration_secs {
            return Err(format!(
                "duration {}s exceeds maximum {}s",
                session.duration_secs, self.max_duration_secs
            ));
        }
        let stop = CaptureStop::new();
        self.stops.insert(session.id.clone(), stop.clone());
        self.sessions.insert(session.id.clone(), session);
        Ok(stop)
    }

    /// Ask a capture to stop and mark it stopped.
    ///
    /// The flag is raised before the status changes, so a reader that comes
    /// back between the two reports its figures against a session already on
    /// its way out rather than one still claiming to run.
    pub fn stop(&mut self, id: &str) -> Option<&CaptureSession> {
        if let Some(stop) = self.stops.get(id) {
            stop.request();
        }
        let session = self.sessions.get_mut(id)?;
        if session.status == CaptureStatus::Running {
            session.status = CaptureStatus::Stopped;
        }
        Some(session)
    }

    /// Ask every running capture to stop because the agent is stopping, and
    /// return the ids asked, so the caller can say what it waited for.
    ///
    /// A capture cut short this way is `Interrupted` rather than `Stopped`:
    /// nobody asked for this one to end, and the difference is the whole
    /// reason an operator opens a short file.
    pub fn interrupt_running(&mut self) -> Vec<String> {
        let mut interrupted = Vec::new();
        for session in self.sessions.values_mut() {
            if session.status == CaptureStatus::Running {
                if let Some(stop) = self.stops.get(&session.id) {
                    stop.request();
                }
                session.status = CaptureStatus::Interrupted;
                interrupted.push(session.id.clone());
            }
        }
        interrupted.sort();
        interrupted
    }

    /// The captures whose reader thread has not reported back yet, by id.
    ///
    /// A capture leaves this set when its figures are recorded, which is after
    /// its file is flushed and closed: it is what a stop sequence waits on
    /// rather than a sleep chosen to look long enough.
    pub fn unfinished(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.stops.keys().cloned().collect();
        ids.sort();
        ids
    }

    /// Record the figures a finished capture produced.
    ///
    /// A capture already stopped or interrupted keeps that status: what it was
    /// asked to do says more than the fact that it then ended. Only a capture
    /// still running becomes `Completed`, which is a capture that reached its
    /// own duration.
    pub fn finish(&mut self, id: &str, file_size_bytes: u64, packets_captured: u64) {
        if let Some(session) = self.sessions.get_mut(id) {
            if session.status == CaptureStatus::Running {
                session.status = CaptureStatus::Completed;
            }
            session.file_size_bytes = file_size_bytes;
            session.packets_captured = packets_captured;
        }
        self.stops.remove(id);
    }

    /// Mark a capture as failed.
    pub fn fail(&mut self, id: &str) {
        if let Some(session) = self.sessions.get_mut(id) {
            session.status = CaptureStatus::Failed;
        }
        self.stops.remove(id);
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
        let mut engine = CaptureEngine::new(300, RetentionPolicy::new(7, 1024));
        engine.start(make_session("cap-1", 60)).unwrap();
        assert_eq!(engine.list().len(), 1);
        assert!(engine.has_active());
    }

    #[test]
    fn concurrent_capture_rejected() {
        let mut engine = CaptureEngine::new(300, RetentionPolicy::new(7, 1024));
        engine.start(make_session("cap-1", 60)).unwrap();
        let result = engine.start(make_session("cap-2", 60));
        assert!(result.is_err());
    }

    #[test]
    fn duration_exceeds_max() {
        let mut engine = CaptureEngine::new(300, RetentionPolicy::new(7, 1024));
        let result = engine.start(make_session("cap-1", 600));
        assert!(result.is_err());
    }

    #[test]
    fn stop_capture() {
        let mut engine = CaptureEngine::new(300, RetentionPolicy::new(7, 1024));
        let stop = engine.start(make_session("cap-1", 60)).unwrap();
        let session = engine.stop("cap-1").unwrap();
        assert_eq!(session.status, CaptureStatus::Stopped);
        assert!(!engine.has_active());
        assert!(stop.requested(), "a stop must reach the reader thread");
    }

    #[test]
    fn complete_capture() {
        let mut engine = CaptureEngine::new(300, RetentionPolicy::new(7, 1024));
        engine.start(make_session("cap-1", 60)).unwrap();
        engine.finish("cap-1", 1024, 42);
        let session = engine.get("cap-1").unwrap();
        assert_eq!(session.status, CaptureStatus::Completed);
        assert_eq!(session.file_size_bytes, 1024);
        assert_eq!(session.packets_captured, 42);
    }

    #[test]
    fn a_stopped_capture_keeps_its_status_and_its_figures() {
        let mut engine = CaptureEngine::new(300, RetentionPolicy::new(7, 1024));
        engine.start(make_session("cap-1", 60)).unwrap();
        engine.stop("cap-1");
        engine.finish("cap-1", 2048, 7);
        let session = engine.get("cap-1").unwrap();
        assert_eq!(session.status, CaptureStatus::Stopped);
        assert_eq!(session.file_size_bytes, 2048);
        assert_eq!(session.packets_captured, 7);
    }

    #[test]
    fn a_stop_of_the_agent_interrupts_every_running_capture() {
        let mut engine = CaptureEngine::new(300, RetentionPolicy::new(7, 1024));
        let stop = engine.start(make_session("cap-1", 300)).unwrap();

        let interrupted = engine.interrupt_running();

        assert_eq!(interrupted, vec!["cap-1".to_string()]);
        assert!(stop.requested());
        assert_eq!(
            engine.get("cap-1").unwrap().status,
            CaptureStatus::Interrupted
        );
        assert_eq!(engine.interrupt_running(), Vec::<String>::new());
    }

    #[test]
    fn a_capture_is_unfinished_until_its_reader_reports() {
        let mut engine = CaptureEngine::new(300, RetentionPolicy::new(7, 1024));
        engine.start(make_session("cap-1", 60)).unwrap();
        assert_eq!(engine.unfinished(), vec!["cap-1".to_string()]);

        engine.interrupt_running();
        assert_eq!(
            engine.unfinished(),
            vec!["cap-1".to_string()],
            "an interrupted capture is still writing until it says otherwise"
        );

        engine.finish("cap-1", 512, 3);
        assert!(engine.unfinished().is_empty());
    }

    #[test]
    fn a_failed_capture_is_no_longer_waited_on() {
        let mut engine = CaptureEngine::new(300, RetentionPolicy::new(7, 1024));
        engine.start(make_session("cap-1", 60)).unwrap();
        engine.fail("cap-1");
        assert!(engine.unfinished().is_empty());
    }

    #[test]
    fn after_stop_can_start_new() {
        let mut engine = CaptureEngine::new(300, RetentionPolicy::new(7, 1024));
        engine.start(make_session("cap-1", 60)).unwrap();
        engine.stop("cap-1");
        engine.start(make_session("cap-2", 60)).unwrap();
        assert!(engine.has_active());
    }

    #[test]
    fn a_file_left_by_an_earlier_run_can_be_adopted_and_listed() {
        let mut engine = CaptureEngine::new(300, RetentionPolicy::new(7, 1024));
        let mut past = make_session("cap-old", 0);
        past.status = CaptureStatus::Interrupted;
        engine.adopt(past);

        assert_eq!(engine.list().len(), 1);
        assert!(
            !engine.has_active(),
            "an adopted session is history, so it blocks no new capture"
        );
        assert!(
            engine.unfinished().is_empty(),
            "an adopted session has no reader to wait for"
        );
    }

    #[test]
    fn adopting_does_not_overwrite_what_this_run_knows() {
        let mut engine = CaptureEngine::new(300, RetentionPolicy::new(7, 1024));
        engine.start(make_session("cap-1", 60)).unwrap();

        let mut from_disk = make_session("cap-1", 0);
        from_disk.status = CaptureStatus::Interrupted;
        engine.adopt(from_disk);

        assert_eq!(engine.get("cap-1").unwrap().status, CaptureStatus::Running);
        assert_eq!(engine.get("cap-1").unwrap().duration_secs, 60);
    }

    #[test]
    fn the_file_of_a_running_capture_is_in_use_and_a_finished_one_is_not() {
        let mut engine = CaptureEngine::new(300, RetentionPolicy::new(7, 1024));
        engine.start(make_session("cap-1", 60)).unwrap();

        assert_eq!(
            engine.files_in_use(),
            vec!["/var/lib/ebpfsentinel/captures/cap-1.pcap".to_string()]
        );

        engine.finish("cap-1", 100, 10);

        assert!(engine.files_in_use().is_empty());
        assert_eq!(engine.known_ids(), vec!["cap-1".to_string()]);
    }

    #[test]
    fn the_engine_carries_the_policy_it_was_built_with() {
        let engine = CaptureEngine::new(300, RetentionPolicy::new(3, 64));
        assert_eq!(engine.retention().max_age_secs(), Some(3 * 86_400));
        assert_eq!(engine.retention().max_total_bytes(), Some(64 * 1024 * 1024));
    }
}
