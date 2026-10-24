use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::aggregate::LearningAggregate;
use super::entity::{
    LEARNING_MAX_DURATION_SECS, LEARNING_MIN_DURATION_SECS, LearningGap, LearningProgress,
    LearningScope, LearningStatus, Observation, ObservedFlow, WorkloadKey,
};
use super::error::LearningError;

/// How many finished sessions the engine keeps beside the running one.
///
/// A finished session is kept so the document it produced can still be
/// rendered, read and diffed after the window closed; past that the oldest
/// goes, because an aggregate is the largest thing the agent holds in memory
/// that nobody asked for twice.
pub const LEARNING_MAX_SESSIONS: usize = 8;

/// One declared window over one declared scope, and what it saw.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearningSession {
    pub id: String,
    pub scope: LearningScope,
    /// The window the operator asked for, in seconds of wall clock.
    pub requested_duration_secs: u64,
    pub started_at_ns: u64,
    pub status: LearningStatus,
    pub ended_at_ns: Option<u64>,
    /// Last moment the session is known to have been observing. Compared
    /// against the clock on the way back from a restart, it is what turns a
    /// silent reset into a recorded gap.
    pub last_observation_ns: u64,
    /// Observations folded in, out-of-scope and unattributed ones included.
    pub observations: u64,
    /// Observations whose local task resolved to no name a rule could carry.
    pub unattributed: u64,
    /// Observations the scope refused.
    pub out_of_scope: u64,
    /// Stretches of the window during which the agent was not running.
    pub gaps: Vec<LearningGap>,
    pub aggregate: LearningAggregate,
}

impl LearningSession {
    /// Open a window.
    ///
    /// # Errors
    ///
    /// Returns [`LearningError::InvalidDuration`] when the window is outside
    /// the accepted range, or [`LearningError::InvalidScope`] when the scope
    /// names nothing an observation could be decided against.
    pub fn new(
        id: String,
        scope: LearningScope,
        duration_secs: u64,
        max_edges: usize,
        now_ns: u64,
    ) -> Result<Self, LearningError> {
        if duration_secs < LEARNING_MIN_DURATION_SECS {
            return Err(LearningError::InvalidDuration {
                reason: format!(
                    "a window shorter than {LEARNING_MIN_DURATION_SECS}s describes nothing"
                ),
            });
        }
        if duration_secs > LEARNING_MAX_DURATION_SECS {
            return Err(LearningError::InvalidDuration {
                reason: format!("a window longer than {LEARNING_MAX_DURATION_SECS}s is refused"),
            });
        }
        scope.validate()?;
        Ok(Self {
            id,
            scope,
            requested_duration_secs: duration_secs,
            started_at_ns: now_ns,
            status: LearningStatus::Running,
            ended_at_ns: None,
            last_observation_ns: now_ns,
            observations: 0,
            unattributed: 0,
            out_of_scope: 0,
            gaps: Vec::new(),
            aggregate: LearningAggregate::new(max_edges),
        })
    }

    /// When the window closes on its own.
    pub fn deadline_ns(&self) -> u64 {
        self.started_at_ns
            .saturating_add(self.requested_duration_secs.saturating_mul(1_000_000_000))
    }

    /// Seconds of the window during which the agent was not running.
    pub fn gap_secs(&self) -> u64 {
        self.gaps.iter().map(LearningGap::seconds).sum()
    }

    /// Fold one flow in.
    ///
    /// A session that is no longer running ignores everything, so a sampling
    /// loop that has not noticed the window closed cannot extend it.
    pub fn observe(&mut self, flow: &ObservedFlow, now_ns: u64) -> Observation {
        if !self.status.is_running() {
            return Observation::Ignored;
        }
        self.observations = self.observations.saturating_add(1);
        self.last_observation_ns = now_ns;

        let facts = flow.workload.facts();
        if !self.scope.admits(&facts) {
            self.out_of_scope = self.out_of_scope.saturating_add(1);
            return Observation::OutOfScope;
        }
        let Some(key) = WorkloadKey::from_facts(&facts) else {
            self.unattributed = self.unattributed.saturating_add(1);
            return Observation::Unattributed;
        };
        let observation = self.aggregate.record(
            key.clone(),
            flow.destination,
            flow.port,
            flow.protocol,
            now_ns,
        );
        if matches!(observation, Observation::NewEdge | Observation::KnownEdge) {
            self.aggregate.note_source(&key, flow.source);
        }
        observation
    }

    /// Say the session is still observing, even when no flow came.
    ///
    /// A quiet node is not a stopped agent, and without this the gap recorded
    /// after a restart would start at the last flow rather than at the last
    /// moment the agent was up.
    pub fn touch(&mut self, now_ns: u64) {
        if self.status.is_running() {
            self.last_observation_ns = now_ns;
        }
    }

    /// Close the window because it elapsed.
    pub fn complete(&mut self, now_ns: u64) {
        if self.status.is_running() {
            self.status = LearningStatus::Completed;
            self.ended_at_ns = Some(now_ns);
        }
    }

    /// Close the window because an operator asked.
    pub fn stop(&mut self, now_ns: u64) {
        if self.status.is_running() {
            self.status = LearningStatus::Stopped;
            self.ended_at_ns = Some(now_ns);
        }
    }

    /// Close the window because the agent is going down under it.
    pub fn interrupt(&mut self, now_ns: u64) {
        if self.status.is_running() {
            self.status = LearningStatus::Interrupted;
            self.ended_at_ns = Some(now_ns);
        }
    }

    /// Everything the session can say about itself.
    pub fn progress(&self, now_ns: u64) -> LearningProgress {
        let end_ns = self.ended_at_ns.unwrap_or(now_ns);
        let elapsed_secs = end_ns.saturating_sub(self.started_at_ns) / 1_000_000_000;
        let remaining_secs = if self.status.is_running() {
            self.deadline_ns().saturating_sub(now_ns) / 1_000_000_000
        } else {
            0
        };
        let last_new_edge_ns = self.aggregate.last_new_edge_ns();
        LearningProgress {
            id: self.id.clone(),
            status: self.status,
            scope: self.scope.clone(),
            scope_description: self.scope.describe(),
            requested_duration_secs: self.requested_duration_secs,
            started_at_ns: self.started_at_ns,
            ended_at_ns: self.ended_at_ns,
            elapsed_secs,
            gap_secs: self.gap_secs(),
            remaining_secs,
            edges: self.aggregate.len(),
            capacity: self.aggregate.capacity(),
            dropped_edges: self.aggregate.dropped_edges(),
            observations: self.observations,
            unattributed: self.unattributed,
            out_of_scope: self.out_of_scope,
            last_new_edge_ns,
            secs_since_new_edge: last_new_edge_ns
                .map(|ns| end_ns.saturating_sub(ns) / 1_000_000_000),
            continuous: self.gaps.is_empty(),
        }
    }
}

/// Holds the running session and the finished ones still worth reading.
pub struct LearningEngine {
    sessions: HashMap<String, LearningSession>,
    max_edges: usize,
    max_sessions: usize,
    /// Ids the ceiling dropped, kept until a caller takes them.
    ///
    /// A session the engine forgot is a session whatever stored it must
    /// forget too, and the alternative is a store that grows for the life
    /// of the host and hands back at every boot the windows the ceiling
    /// already refused.
    forgotten: Vec<String>,
}

impl LearningEngine {
    pub fn new(max_edges: usize) -> Self {
        Self {
            sessions: HashMap::new(),
            max_edges,
            max_sessions: LEARNING_MAX_SESSIONS,
            forgotten: Vec::new(),
        }
    }

    /// How many edges a session started here is allowed to hold.
    pub fn max_edges(&self) -> usize {
        self.max_edges
    }

    /// Open a window, refusing a second one.
    ///
    /// # Errors
    ///
    /// Returns [`LearningError::AlreadyRunning`] when a session is open, and
    /// whatever [`LearningSession::new`] refuses.
    pub fn start(
        &mut self,
        id: String,
        scope: LearningScope,
        duration_secs: u64,
        now_ns: u64,
    ) -> Result<&LearningSession, LearningError> {
        if let Some(running) = self.active() {
            return Err(LearningError::AlreadyRunning {
                id: running.id.clone(),
            });
        }
        let session =
            LearningSession::new(id.clone(), scope, duration_secs, self.max_edges, now_ns)?;
        self.sessions.insert(id.clone(), session);
        self.prune();
        self.sessions.get(&id).ok_or(LearningError::Unknown { id })
    }

    /// The session still taking observations, if any.
    pub fn active(&self) -> Option<&LearningSession> {
        self.sessions.values().find(|s| s.status.is_running())
    }

    fn active_id(&self) -> Option<String> {
        self.active().map(|s| s.id.clone())
    }

    /// Fold one flow into the running session.
    pub fn observe(&mut self, flow: &ObservedFlow, now_ns: u64) -> Observation {
        let Some(id) = self.active_id() else {
            return Observation::Ignored;
        };
        match self.sessions.get_mut(&id) {
            Some(session) => session.observe(flow, now_ns),
            None => Observation::Ignored,
        }
    }

    /// Say the running session is still observing.
    pub fn touch(&mut self, now_ns: u64) {
        if let Some(id) = self.active_id()
            && let Some(session) = self.sessions.get_mut(&id)
        {
            session.touch(now_ns);
        }
    }

    /// Close the running session if its window elapsed, and say which one
    /// closed.
    pub fn tick(&mut self, now_ns: u64) -> Option<String> {
        let id = self.active_id()?;
        let session = self.sessions.get_mut(&id)?;
        if now_ns >= session.deadline_ns() {
            session.complete(now_ns);
            return Some(id);
        }
        None
    }

    /// End a session early.
    ///
    /// # Errors
    ///
    /// Returns [`LearningError::Unknown`] when no session carries that id,
    /// and [`LearningError::NotRunning`] when nothing is running and no id
    /// was given.
    pub fn stop(
        &mut self,
        id: Option<&str>,
        now_ns: u64,
    ) -> Result<&LearningSession, LearningError> {
        let id = match id {
            Some(id) => id.to_string(),
            None => self.active_id().ok_or(LearningError::NotRunning)?,
        };
        let session = self
            .sessions
            .get_mut(&id)
            .ok_or_else(|| LearningError::Unknown { id: id.clone() })?;
        session.stop(now_ns);
        Ok(session)
    }

    /// Mark the running session interrupted because the agent is stopping,
    /// and say which one it was.
    pub fn interrupt_running(&mut self, now_ns: u64) -> Option<String> {
        let id = self.active_id()?;
        let session = self.sessions.get_mut(&id)?;
        session.interrupt(now_ns);
        Some(id)
    }

    /// Take back a session a previous run of the agent wrote down.
    ///
    /// A session that was running when the agent went down is resumed with
    /// the hole recorded as a gap, so the window it reports is the window it
    /// actually observed. One whose window elapsed while the agent was down
    /// comes back interrupted rather than completed: nobody watched the end
    /// of it, and a policy written from it would be missing whatever ran
    /// during the hole.
    ///
    /// A session this run already knows is left alone: what is in memory
    /// beats what is on disk.
    pub fn adopt(&mut self, mut session: LearningSession, now_ns: u64) {
        if self.sessions.contains_key(&session.id) {
            return;
        }
        if session.status.is_running() {
            let gap = LearningGap {
                from_ns: session.last_observation_ns,
                to_ns: now_ns,
            };
            if gap.to_ns > gap.from_ns {
                session.gaps.push(gap);
            }
            if now_ns >= session.deadline_ns() {
                session.interrupt(now_ns);
            } else if self.active().is_some() {
                // Another window is already open in this run, which can only
                // happen if a session was started before the store was read.
                // The stored one is the older truth and ends here rather than
                // competing for the same observations.
                session.interrupt(now_ns);
            } else {
                session.last_observation_ns = now_ns;
            }
        }
        self.sessions.insert(session.id.clone(), session);
        self.prune();
    }

    /// Read a session back.
    pub fn get(&self, id: &str) -> Option<&LearningSession> {
        self.sessions.get(id)
    }

    /// Every session the engine holds, newest window first.
    pub fn list(&self) -> Vec<&LearningSession> {
        let mut sessions: Vec<&LearningSession> = self.sessions.values().collect();
        sessions.sort_by(|a, b| b.started_at_ns.cmp(&a.started_at_ns).then(a.id.cmp(&b.id)));
        sessions
    }

    /// Take the ids the ceiling dropped since the last call.
    pub fn take_forgotten(&mut self) -> Vec<String> {
        std::mem::take(&mut self.forgotten)
    }

    /// Drop the oldest finished sessions past the ceiling.
    fn prune(&mut self) {
        while self.sessions.len() > self.max_sessions {
            let oldest = self
                .sessions
                .values()
                .filter(|s| !s.status.is_running())
                .min_by_key(|s| (s.started_at_ns, s.id.clone()))
                .map(|s| s.id.clone());
            match oldest {
                Some(id) => {
                    self.sessions.remove(&id);
                    self.forgotten.push(id);
                }
                None => break,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::entity::Protocol;
    use crate::learning::entity::ObservedWorkload;

    const SEC: u64 = 1_000_000_000;

    fn flow(unit: &str, dst: &str, port: u16) -> ObservedFlow {
        ObservedFlow {
            workload: ObservedWorkload {
                unit: Some(unit.to_string()),
                exe: Some("/usr/sbin/nginx".to_string()),
                ..ObservedWorkload::default()
            },
            source: "10.9.0.2".parse().unwrap(),
            destination: dst.parse().unwrap(),
            port,
            protocol: Protocol::Tcp,
        }
    }

    fn engine() -> LearningEngine {
        LearningEngine::new(64)
    }

    #[test]
    fn a_window_shorter_or_longer_than_the_agent_accepts_is_refused() {
        let mut engine = engine();
        assert!(matches!(
            engine.start("l-1".to_string(), LearningScope::Node, 5, 0),
            Err(LearningError::InvalidDuration { .. })
        ));
        assert!(matches!(
            engine.start(
                "l-1".to_string(),
                LearningScope::Node,
                LEARNING_MAX_DURATION_SECS + 1,
                0
            ),
            Err(LearningError::InvalidDuration { .. })
        ));
    }

    #[test]
    fn a_second_window_is_refused_while_one_is_open() {
        let mut engine = engine();
        engine
            .start("l-1".to_string(), LearningScope::Node, 600, 0)
            .unwrap();
        assert!(matches!(
            engine.start("l-2".to_string(), LearningScope::Node, 600, SEC),
            Err(LearningError::AlreadyRunning { id }) if id == "l-1"
        ));
    }

    #[test]
    fn observations_land_in_the_aggregate_and_are_counted() {
        let mut engine = engine();
        engine
            .start("l-1".to_string(), LearningScope::Node, 600, 0)
            .unwrap();
        assert_eq!(
            engine.observe(&flow("nginx.service", "10.0.0.1", 443), SEC),
            Observation::NewEdge
        );
        assert_eq!(
            engine.observe(&flow("nginx.service", "10.0.0.1", 443), 2 * SEC),
            Observation::KnownEdge
        );
        let progress = engine.active().unwrap().progress(2 * SEC);
        assert_eq!(progress.edges, 1);
        assert_eq!(progress.observations, 2);
        assert_eq!(progress.last_new_edge_ns, Some(SEC));
        assert_eq!(progress.secs_since_new_edge, Some(1));
        assert!(progress.continuous);
    }

    #[test]
    fn a_flow_outside_the_scope_is_counted_and_not_learned() {
        let mut engine = engine();
        engine
            .start(
                "l-1".to_string(),
                LearningScope::Cgroup {
                    path: "/sys/fs/cgroup/web.slice".to_string(),
                },
                600,
                0,
            )
            .unwrap();
        assert_eq!(
            engine.observe(&flow("nginx.service", "10.0.0.1", 443), SEC),
            Observation::OutOfScope
        );
        let progress = engine.active().unwrap().progress(SEC);
        assert_eq!(progress.edges, 0);
        assert_eq!(progress.out_of_scope, 1);
    }

    #[test]
    fn a_flow_naming_no_workload_is_counted_as_unattributed() {
        let mut engine = engine();
        engine
            .start("l-1".to_string(), LearningScope::Node, 600, 0)
            .unwrap();
        let anonymous = ObservedFlow {
            workload: ObservedWorkload::default(),
            source: "10.9.0.2".parse().unwrap(),
            destination: "10.0.0.1".parse().unwrap(),
            port: 443,
            protocol: Protocol::Tcp,
        };
        assert_eq!(engine.observe(&anonymous, SEC), Observation::Unattributed);
        let progress = engine.active().unwrap().progress(SEC);
        assert_eq!(progress.edges, 0);
        assert_eq!(progress.unattributed, 1);
    }

    #[test]
    fn the_window_closes_on_its_own_and_takes_no_more_observations() {
        let mut engine = engine();
        engine
            .start("l-1".to_string(), LearningScope::Node, 60, 0)
            .unwrap();
        assert_eq!(engine.tick(30 * SEC), None);
        assert_eq!(engine.tick(60 * SEC), Some("l-1".to_string()));
        assert!(engine.active().is_none());
        assert_eq!(
            engine.observe(&flow("nginx.service", "10.0.0.1", 443), 61 * SEC),
            Observation::Ignored
        );
        let session = engine.get("l-1").unwrap();
        assert_eq!(session.status, LearningStatus::Completed);
        assert_eq!(session.progress(90 * SEC).remaining_secs, 0);
        assert_eq!(session.progress(90 * SEC).elapsed_secs, 60);
    }

    #[test]
    fn an_operator_can_end_a_window_early() {
        let mut engine = engine();
        engine
            .start("l-1".to_string(), LearningScope::Node, 600, 0)
            .unwrap();
        let session = engine.stop(None, 120 * SEC).unwrap();
        assert_eq!(session.status, LearningStatus::Stopped);
        assert_eq!(session.ended_at_ns, Some(120 * SEC));
        assert!(matches!(
            engine.stop(None, 130 * SEC),
            Err(LearningError::NotRunning)
        ));
    }

    #[test]
    fn a_session_the_agent_left_running_comes_back_with_the_hole_recorded() {
        let mut before =
            LearningSession::new("l-1".to_string(), LearningScope::Node, 3_600, 64, 0).unwrap();
        before.observe(&flow("nginx.service", "10.0.0.1", 443), 10 * SEC);

        let mut engine = engine();
        engine.adopt(before, 70 * SEC);

        let session = engine.active().expect("the window is still open");
        assert_eq!(session.status, LearningStatus::Running);
        assert_eq!(session.gaps.len(), 1);
        assert_eq!(session.gaps[0].seconds(), 60);
        let progress = session.progress(70 * SEC);
        assert!(
            !progress.continuous,
            "a window with a hole in it must never report itself as continuous"
        );
        assert_eq!(progress.gap_secs, 60);
        assert_eq!(progress.edges, 1);
    }

    #[test]
    fn a_window_that_elapsed_while_the_agent_was_down_comes_back_interrupted() {
        let before =
            LearningSession::new("l-1".to_string(), LearningScope::Node, 60, 64, 0).unwrap();

        let mut engine = engine();
        engine.adopt(before, 600 * SEC);

        assert!(engine.active().is_none());
        let session = engine.get("l-1").unwrap();
        assert_eq!(session.status, LearningStatus::Interrupted);
        assert_eq!(session.ended_at_ns, Some(600 * SEC));
    }

    #[test]
    fn adopting_never_overwrites_what_this_run_already_holds() {
        let mut engine = engine();
        engine
            .start("l-1".to_string(), LearningScope::Node, 600, 0)
            .unwrap();
        let stale =
            LearningSession::new("l-1".to_string(), LearningScope::Node, 60, 64, 0).unwrap();
        engine.adopt(stale, 10 * SEC);
        assert_eq!(engine.get("l-1").unwrap().requested_duration_secs, 600);
    }

    #[test]
    fn a_stop_of_the_agent_interrupts_the_open_window() {
        let mut engine = engine();
        engine
            .start("l-1".to_string(), LearningScope::Node, 600, 0)
            .unwrap();
        assert_eq!(engine.interrupt_running(5 * SEC), Some("l-1".to_string()));
        assert_eq!(
            engine.get("l-1").unwrap().status,
            LearningStatus::Interrupted
        );
        assert_eq!(engine.interrupt_running(6 * SEC), None);
    }

    #[test]
    fn the_engine_keeps_a_bounded_history_newest_first() {
        let mut engine = engine();
        for i in 0..(LEARNING_MAX_SESSIONS + 3) {
            let id = format!("l-{i}");
            let at = (i as u64 + 1) * 1_000 * SEC;
            engine
                .start(id.clone(), LearningScope::Node, 60, at)
                .unwrap();
            engine.stop(Some(&id), at + 60 * SEC).unwrap();
        }
        let sessions = engine.list();
        assert_eq!(sessions.len(), LEARNING_MAX_SESSIONS);
        assert_eq!(sessions[0].id, format!("l-{}", LEARNING_MAX_SESSIONS + 2));
        assert!(engine.get("l-0").is_none(), "the oldest window went first");
    }

    #[test]
    fn the_ceiling_says_which_windows_it_dropped() {
        let mut engine = engine();
        for i in 0..=LEARNING_MAX_SESSIONS {
            let id = format!("l-{i}");
            let at = i as u64 * 3_600 * SEC;
            engine
                .start(id.clone(), LearningScope::Node, 60, at)
                .unwrap();
            engine.stop(Some(&id), at + 60 * SEC).unwrap();
        }
        assert_eq!(engine.take_forgotten(), vec!["l-0".to_string()]);
        assert!(
            engine.take_forgotten().is_empty(),
            "an id is handed over once"
        );
    }

    #[test]
    fn a_quiet_node_still_says_the_agent_is_up() {
        let mut engine = engine();
        engine
            .start("l-1".to_string(), LearningScope::Node, 600, 0)
            .unwrap();
        engine.touch(120 * SEC);
        assert_eq!(engine.active().unwrap().last_observation_ns, 120 * SEC);
    }
}
