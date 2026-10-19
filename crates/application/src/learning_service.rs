//! The learning window, as the agent runs it.
//!
//! The domain decides what a window is and what the aggregate holds; this
//! holds the one engine the process has, hands every change to the store so
//! a restart does not silently reset a window somebody opened yesterday,
//! and reports to the metrics what the window is doing.
//!
//! The store is optional. A node whose state directory could not be opened
//! still learns, and says so: a session it never wrote comes back as no
//! session at all rather than as a window that quietly lost its first hour.

use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use domain::learning::document::{PolicyDocument, render_policy};
use domain::learning::engine::{LearningEngine, LearningSession};
use domain::learning::entity::{
    LearningProgress, LearningScope, Observation, ObservedFlow, ObservedWorkload,
};
use domain::learning::error::LearningError;
use ports::secondary::learning_store_port::LearningStorePort;
use ports::secondary::metrics_port::MetricsPort;
use tracing::{debug, info, warn};

/// Wall clock in nanoseconds.
///
/// Wall clock rather than the boot clock, because a window spans restarts
/// and the only reading both sides of one share is the date.
#[must_use]
pub fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}

/// What an observation did, in the one word the metrics carry.
fn outcome_label(observation: Observation) -> &'static str {
    match observation {
        Observation::NewEdge => "new_edge",
        Observation::KnownEdge => "known_edge",
        Observation::OutOfScope => "out_of_scope",
        Observation::Unattributed => "unattributed",
        Observation::Dropped => "dropped",
        Observation::Ignored => "ignored",
    }
}

/// The learning windows this agent holds.
pub struct LearningAppService {
    engine: RwLock<LearningEngine>,
    store: Option<Arc<dyn LearningStorePort>>,
    metrics: Arc<dyn MetricsPort>,
}

impl LearningAppService {
    /// A service holding no window yet, whose sessions will hold at most
    /// `max_edges` destinations each.
    #[must_use]
    pub fn new(max_edges: usize, metrics: Arc<dyn MetricsPort>) -> Self {
        Self {
            engine: RwLock::new(LearningEngine::new(max_edges)),
            store: None,
            metrics,
        }
    }

    /// Write every change through `store`.
    #[must_use]
    pub fn with_store(mut self, store: Arc<dyn LearningStorePort>) -> Self {
        self.store = Some(store);
        self
    }

    /// How many destinations a window opened here may hold.
    #[must_use]
    pub fn max_edges(&self) -> usize {
        self.read().max_edges()
    }

    /// Whether a window is open.
    #[must_use]
    pub fn is_observing(&self) -> bool {
        self.read().active().is_some()
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, LearningEngine> {
        self.engine
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, LearningEngine> {
        self.engine
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Take back what a previous run wrote down, and say how many windows
    /// came back.
    ///
    /// Called once, before the first observation: a window adopted after
    /// this run opened one of its own is a window that ends rather than
    /// competes, which is the engine's rule and not this one's.
    pub fn restore(&self, now_ns: u64) -> usize {
        let Some(store) = &self.store else {
            return 0;
        };
        let stored = match store.load_all() {
            Ok(sessions) => sessions,
            Err(err) => {
                warn!(error = %err, "learning sessions could not be read back");
                return 0;
            }
        };
        let adopted = stored.len();
        {
            let mut engine = self.write();
            for session in stored {
                engine.adopt(session, now_ns);
            }
        }
        // Adoption records a gap or ends a window, so what is in memory is
        // no longer what is on disk.
        self.persist_all();
        self.forget_pruned();
        self.publish_edges();
        if adopted > 0 {
            info!(sessions = adopted, "learning sessions taken back");
        }
        adopted
    }

    /// Open a window over `scope` for `duration_secs`.
    ///
    /// # Errors
    ///
    /// Whatever the engine refuses: a second window, a duration outside the
    /// accepted range, or a scope naming nothing.
    pub fn start(
        &self,
        scope: LearningScope,
        duration_secs: u64,
        now_ns: u64,
    ) -> Result<LearningProgress, LearningError> {
        let (progress, session) = {
            let mut engine = self.write();
            let id = Self::session_id(&engine, now_ns);
            let session = engine.start(id, scope, duration_secs, now_ns)?;
            (session.progress(now_ns), session.clone())
        };
        self.persist(&session);
        self.forget_pruned();
        self.publish_edges();
        info!(
            session = %progress.id,
            scope = %progress.scope_description,
            duration_secs = progress.requested_duration_secs,
            "learning window open"
        );
        Ok(progress)
    }

    /// End a window early, the open one when no id is given.
    ///
    /// # Errors
    ///
    /// [`LearningError::NotRunning`] when nothing is open and no id was
    /// given, [`LearningError::Unknown`] when no window carries that id.
    pub fn stop(&self, id: Option<&str>, now_ns: u64) -> Result<LearningProgress, LearningError> {
        let (progress, session) = {
            let mut engine = self.write();
            let session = engine.stop(id, now_ns)?;
            (session.progress(now_ns), session.clone())
        };
        self.persist(&session);
        self.publish_edges();
        info!(
            session = %progress.id,
            edges = progress.edges,
            elapsed_secs = progress.elapsed_secs,
            "learning window closed by the operator"
        );
        Ok(progress)
    }

    /// Fold one batch of flows into the open window and say how many of them
    /// were destinations it had not seen.
    ///
    /// A batch rather than a flow at a time because the sampler reads the
    /// whole table at once, and because the store is written once per batch:
    /// a window of a day at one write per flow is a day of writes for a
    /// document nobody reads until the end.
    pub fn observe(&self, flows: &[ObservedFlow], now_ns: u64) -> usize {
        if flows.is_empty() {
            self.touch(now_ns);
            return 0;
        }
        let (new_edges, session) = {
            let mut engine = self.write();
            if engine.active().is_none() {
                return 0;
            }
            let mut new_edges = 0;
            for flow in flows {
                let observation = engine.observe(flow, now_ns);
                if observation == Observation::NewEdge {
                    new_edges += 1;
                }
                self.metrics
                    .record_learning_observation(outcome_label(observation));
            }
            (new_edges, engine.active().cloned())
        };
        if let Some(session) = session {
            self.persist(&session);
        }
        self.publish_edges();
        new_edges
    }

    /// Say the agent is still up, for a sample that found nothing to fold.
    ///
    /// A window over a quiet node must not come back looking like a window
    /// the agent slept through.
    pub fn touch(&self, now_ns: u64) {
        let session = {
            let mut engine = self.write();
            engine.touch(now_ns);
            engine.active().cloned()
        };
        if let Some(session) = session {
            self.persist(&session);
        }
    }

    /// Close the window if its time is up, and say which one closed.
    pub fn tick(&self, now_ns: u64) -> Option<String> {
        let (closed, session) = {
            let mut engine = self.write();
            let closed = engine.tick(now_ns)?;
            let session = engine.get(&closed).cloned();
            (closed, session)
        };
        if let Some(session) = session {
            self.persist(&session);
        }
        self.publish_edges();
        info!(session = %closed, "learning window elapsed");
        Some(closed)
    }

    /// Mark the open window interrupted because the agent is stopping.
    pub fn interrupt_running(&self, now_ns: u64) {
        let session = {
            let mut engine = self.write();
            match engine.interrupt_running(now_ns) {
                Some(id) => engine.get(&id).cloned(),
                None => None,
            }
        };
        if let Some(session) = session {
            info!(session = %session.id, "learning window interrupted by a stop");
            self.persist(&session);
        }
        self.publish_edges();
    }

    /// What one window is doing, the open one when no id is given.
    #[must_use]
    pub fn progress(&self, id: Option<&str>, now_ns: u64) -> Option<LearningProgress> {
        let engine = self.read();
        let session = match id {
            Some(id) => engine.get(id)?,
            None => engine.active()?,
        };
        Some(session.progress(now_ns))
    }

    /// Every window the agent holds, newest first.
    #[must_use]
    pub fn list(&self, now_ns: u64) -> Vec<LearningProgress> {
        self.read()
            .list()
            .into_iter()
            .map(|session| session.progress(now_ns))
            .collect()
    }

    /// One window in full, for whatever renders it.
    #[must_use]
    pub fn session(&self, id: &str) -> Option<LearningSession> {
        self.read().get(id).cloned()
    }

    /// The open window in full.
    #[must_use]
    pub fn active_session(&self) -> Option<LearningSession> {
        self.read().active().cloned()
    }

    /// The allow-list one window describes, the open one when no id is
    /// given.
    ///
    /// Rendering reads the session and writes nothing: a document can be
    /// asked for while the window is still open, which is how an operator
    /// decides whether it has run long enough.
    #[must_use]
    pub fn policy(&self, id: Option<&str>, now_ns: u64) -> Option<PolicyDocument> {
        let engine = self.read();
        let session = match id {
            Some(id) => engine.get(id)?,
            None => engine.active()?,
        };
        Some(render_policy(session, now_ns))
    }

    /// An id that reads as a date and never collides with one the engine
    /// already holds.
    fn session_id(engine: &LearningEngine, now_ns: u64) -> String {
        let seconds = now_ns / 1_000_000_000;
        let base = format!("learn-{seconds}");
        if engine.get(&base).is_none() {
            return base;
        }
        // Two windows in the same second is a retry, not a habit.
        // Two windows in the same second is a retry, not a habit, so the
        // search is bounded: past this many the caller gets the base id back
        // and the engine refuses the duplicate itself.
        (2..1_000)
            .map(|n| format!("{base}-{n}"))
            .find(|id| engine.get(id).is_none())
            .unwrap_or(base)
    }

    fn persist(&self, session: &LearningSession) {
        let Some(store) = &self.store else {
            return;
        };
        if let Err(err) = store.save(session) {
            warn!(session = %session.id, error = %err, "learning session not written down");
        }
    }

    fn persist_all(&self) {
        let sessions: Vec<LearningSession> = self.read().list().into_iter().cloned().collect();
        for session in &sessions {
            self.persist(session);
        }
    }

    fn forget_pruned(&self) {
        let forgotten = self.write().take_forgotten();
        let Some(store) = &self.store else {
            return;
        };
        for id in forgotten {
            match store.delete(&id) {
                Ok(()) => debug!(session = %id, "learning session dropped past the ceiling"),
                Err(err) => warn!(session = %id, error = %err, "learning session not deleted"),
            }
        }
    }

    fn publish_edges(&self) {
        let edges = self
            .read()
            .active()
            .map_or(0, |session| session.aggregate.len());
        self.metrics.set_learning_edges(edges as u64);
    }
}

/// Everything the sampler needs to decide a flow, in the shape the domain
/// takes it.
#[must_use]
pub fn observed_workload(
    exe: Option<String>,
    unit: Option<String>,
    cgroup: Option<String>,
    container_id: Option<String>,
    container_name: Option<String>,
) -> ObservedWorkload {
    ObservedWorkload {
        exe,
        unit,
        cgroup,
        container_id,
        container_name,
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::sync::Mutex;

    use domain::common::entity::Protocol;
    use domain::common::error::DomainError;
    use ports::test_utils::NoopMetrics;

    use super::*;

    const SEC: u64 = 1_000_000_000;

    #[derive(Default)]
    struct MemoryStore {
        saved: Mutex<Vec<LearningSession>>,
        deleted: Mutex<Vec<String>>,
    }

    impl LearningStorePort for MemoryStore {
        fn save(&self, session: &LearningSession) -> Result<(), DomainError> {
            let mut saved = self
                .saved
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            saved.retain(|s| s.id != session.id);
            saved.push(session.clone());
            Ok(())
        }

        fn load_all(&self) -> Result<Vec<LearningSession>, DomainError> {
            Ok(self
                .saved
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone())
        }

        fn delete(&self, id: &str) -> Result<(), DomainError> {
            self.saved
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .retain(|s| s.id != id);
            self.deleted
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(id.to_string());
            Ok(())
        }
    }

    fn service(store: &Arc<MemoryStore>) -> LearningAppService {
        LearningAppService::new(64, Arc::new(NoopMetrics))
            .with_store(Arc::clone(store) as Arc<dyn LearningStorePort>)
    }

    fn flow(unit: &str, dst: &str, port: u16) -> ObservedFlow {
        ObservedFlow {
            workload: observed_workload(
                Some("/usr/sbin/nginx".to_string()),
                Some(unit.to_string()),
                None,
                None,
                None,
            ),
            destination: dst.parse::<IpAddr>().expect("a test address parses"),
            port,
            protocol: Protocol::Tcp,
        }
    }

    #[test]
    fn a_window_is_written_down_the_moment_it_opens() {
        let store = Arc::new(MemoryStore::default());
        let service = service(&store);
        let progress = service
            .start(LearningScope::Node, 600, 1_000 * SEC)
            .expect("the window opens");
        let saved = store.load_all().expect("the store answers");
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].id, progress.id);
    }

    #[test]
    fn what_a_sample_folded_is_on_disk_before_the_next_one() {
        let store = Arc::new(MemoryStore::default());
        let service = service(&store);
        service
            .start(LearningScope::Node, 600, 1_000 * SEC)
            .expect("the window opens");
        let new_edges = service.observe(
            &[
                flow("nginx.service", "10.0.0.5", 443),
                flow("nginx.service", "10.0.0.5", 443),
                flow("nginx.service", "10.0.0.6", 53),
            ],
            1_010 * SEC,
        );
        assert_eq!(new_edges, 2, "the repeat is the same edge");
        let saved = store.load_all().expect("the store answers");
        assert_eq!(saved[0].aggregate.len(), 2);
        assert_eq!(saved[0].observations, 3);
    }

    #[test]
    fn a_window_the_agent_left_open_comes_back_with_the_hole_recorded() {
        let store = Arc::new(MemoryStore::default());
        let first = service(&store);
        first
            .start(LearningScope::Node, 3_600, 1_000 * SEC)
            .expect("the window opens");
        first.observe(&[flow("nginx.service", "10.0.0.5", 443)], 1_010 * SEC);

        let second = service(&store);
        assert_eq!(second.restore(1_300 * SEC), 1);
        let progress = second
            .progress(None, 1_300 * SEC)
            .expect("it is open again");
        assert_eq!(progress.gap_secs, 290);
        assert!(!progress.continuous, "the hole is reported, never hidden");
        assert_eq!(progress.edges, 1, "what it had learned is still there");
    }

    #[test]
    fn a_window_whose_time_passed_while_the_agent_was_down_comes_back_closed() {
        let store = Arc::new(MemoryStore::default());
        let first = service(&store);
        first
            .start(LearningScope::Node, 600, 1_000 * SEC)
            .expect("the window opens");

        let second = service(&store);
        second.restore(9_000 * SEC);
        assert!(
            !second.is_observing(),
            "nobody watched the end of that window"
        );
        let progress = second.list(9_000 * SEC).pop().expect("it is still listed");
        assert_eq!(progress.status.as_str(), "interrupted");
    }

    #[test]
    fn a_quiet_sample_still_says_the_agent_was_up() {
        let store = Arc::new(MemoryStore::default());
        let service = service(&store);
        service
            .start(LearningScope::Node, 600, 1_000 * SEC)
            .expect("the window opens");
        service.observe(&[], 1_100 * SEC);
        let saved = store.load_all().expect("the store answers");
        assert_eq!(saved[0].last_observation_ns, 1_100 * SEC);
    }

    #[test]
    fn the_window_closes_on_its_own_and_is_written_down_closed() {
        let store = Arc::new(MemoryStore::default());
        let service = service(&store);
        service
            .start(LearningScope::Node, 600, 1_000 * SEC)
            .expect("the window opens");
        assert!(service.tick(1_300 * SEC).is_none(), "it is not time yet");
        assert!(service.tick(1_700 * SEC).is_some());
        let saved = store.load_all().expect("the store answers");
        assert_eq!(saved[0].status.as_str(), "completed");
        assert_eq!(
            service.observe(&[flow("nginx.service", "10.0.0.9", 80)], 1_800 * SEC),
            0,
            "a closed window takes nothing more"
        );
    }

    #[test]
    fn a_second_window_is_refused_while_one_is_open() {
        let store = Arc::new(MemoryStore::default());
        let service = service(&store);
        service
            .start(LearningScope::Node, 600, 1_000 * SEC)
            .expect("the window opens");
        let err = service
            .start(LearningScope::Node, 600, 1_010 * SEC)
            .expect_err("the second one is refused");
        assert!(matches!(err, LearningError::AlreadyRunning { .. }));
    }

    #[test]
    fn a_window_the_ceiling_dropped_leaves_the_store_too() {
        let store = Arc::new(MemoryStore::default());
        let service = service(&store);
        for i in 0..=domain::learning::engine::LEARNING_MAX_SESSIONS {
            let at = (1_000 + i as u64 * 3_600) * SEC;
            service
                .start(LearningScope::Node, 600, at)
                .expect("the window opens");
            service.stop(None, at + 600 * SEC).expect("it closes");
        }
        let deleted = store
            .deleted
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(deleted.len(), 1, "one window past the ceiling");
        let saved = store.load_all().expect("the store answers");
        assert_eq!(saved.len(), domain::learning::engine::LEARNING_MAX_SESSIONS);
    }

    #[test]
    fn a_node_with_no_store_still_learns() {
        let service = LearningAppService::new(64, Arc::new(NoopMetrics));
        service
            .start(LearningScope::Node, 600, 1_000 * SEC)
            .expect("the window opens");
        assert_eq!(
            service.observe(&[flow("nginx.service", "10.0.0.5", 443)], 1_010 * SEC),
            1
        );
        assert_eq!(service.restore(1_020 * SEC), 0);
    }
}
