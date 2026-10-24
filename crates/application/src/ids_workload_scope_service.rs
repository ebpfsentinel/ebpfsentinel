//! Compiling IDS rules scoped to workloads into the two tables the
//! classifier reads.
//!
//! A rule naming a pod, a container or a unit is decided in the kernel on a
//! cgroup id, and neither half of that comparison exists at the hook. The
//! packet on the host side of a container's veth carries no socket, so the
//! cgroup comes from the link it crossed, which the link watcher tells this
//! service about; and the rule names workloads in words, so every cgroup the
//! process table hears of is matched here once and only the matches are
//! written.
//!
//! Both tables are replaced whole on every change. Interface indexes and
//! cgroup ids are reused, and an entry left behind is a workload nobody
//! selected being inspected under a rule written for someone else.
//!
//! What this cannot see is stated rather than papered over: a cgroup is
//! known once a task in it has been recorded, which is an exec after the
//! agent started or the process holding a container link, so a rule covers a
//! workload from the moment one of those happens.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex, PoisonError};

use domain::container::engine::CgroupReader;
use domain::firewall::workload::{WorkloadSelector, cgroup_path_of, unit_of};
use domain::process::entity::ProcessEntry;
use ports::secondary::ids_workload_scope_port::{IdsWorkloadScopeMapPort, WorkloadLinkSink};
use tracing::{debug, warn};

use crate::workload_policy_service::{ResolvedWorkload, workload_of};

/// One cgroup the process table told this service about.
#[derive(Debug)]
struct SeenCgroup {
    workload: ResolvedWorkload,
    tasks: usize,
}

#[derive(Debug, Default)]
struct ScopeState {
    /// Scoped rules, by the index the kernel names them with.
    rules: Vec<(u32, WorkloadSelector)>,
    cgroups: HashMap<u64, SeenCgroup>,
    /// Which cgroup a recorded pid was counted against, so an exit
    /// decrements the entry its exec incremented.
    pids: HashMap<u32, u64>,
    links: HashMap<u32, u64>,
    published_links: Vec<(u32, u64)>,
    published_scope: Vec<(u64, u32)>,
}

impl ScopeState {
    fn wanted_links(&self) -> Vec<(u32, u64)> {
        let mut links: Vec<(u32, u64)> = self.links.iter().map(|(&i, &c)| (i, c)).collect();
        links.sort_unstable();
        links
    }

    fn wanted_scope(&self) -> Vec<(u64, u32)> {
        let mut entries = BTreeSet::new();
        for (&cgroup_id, seen) in &self.cgroups {
            let facts = seen.workload.facts();
            for (rule, selector) in &self.rules {
                if selector.matches(&facts) {
                    entries.insert((cgroup_id, *rule));
                }
            }
        }
        entries.into_iter().collect()
    }
}

/// Keeps the workload scope of the IDS rules written in the kernel.
pub struct IdsWorkloadScopeService {
    maps: Mutex<Option<Box<dyn IdsWorkloadScopeMapPort>>>,
    cgroups_reader: Option<Arc<dyn CgroupReader>>,
    state: Mutex<ScopeState>,
}

impl Default for IdsWorkloadScopeService {
    fn default() -> Self {
        Self::new()
    }
}

impl IdsWorkloadScopeService {
    /// A service with no rules and no maps.
    #[must_use]
    pub fn new() -> Self {
        Self {
            maps: Mutex::new(None),
            cgroups_reader: None,
            state: Mutex::new(ScopeState::default()),
        }
    }

    /// Read the cgroup path of a host task through `reader`, so a rule
    /// naming a unit or a cgroup can match a process outside any container.
    #[must_use]
    pub fn with_cgroups(mut self, reader: Arc<dyn CgroupReader>) -> Self {
        self.cgroups_reader = Some(reader);
        self
    }

    /// Install the kernel tables and write everything known into them.
    ///
    /// Called again when tc-ids is loaded again, with tables that may be
    /// empty, which is why the whole state is written rather than a diff.
    pub fn set_maps(&self, maps: Box<dyn IdsWorkloadScopeMapPort>) {
        *self.maps.lock().unwrap_or_else(PoisonError::into_inner) = Some(maps);
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.published_links.clear();
        state.published_scope.clear();
        self.publish(&mut state);
    }

    /// Drop the kernel tables, because the program that read them is gone.
    pub fn clear_maps(&self) {
        *self.maps.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }

    /// Whether a scoped rule can be decided at all: false until the tables
    /// of a tc-ids object that carries them are installed.
    #[must_use]
    pub fn supported(&self) -> bool {
        self.maps
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
    }

    /// Replace the scoped rules, as `(rule index, selector)` pairs.
    pub fn set_rules(&self, rules: Vec<(u32, WorkloadSelector)>) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.rules = rules;
        self.publish(&mut state);
    }

    /// Every `(cgroup id, rule index)` pair currently written.
    #[must_use]
    pub fn published_scope(&self) -> Vec<(u64, u32)> {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .published_scope
            .clone()
    }

    /// Every `(ifindex, cgroup id)` pair currently written.
    #[must_use]
    pub fn published_links(&self) -> Vec<(u32, u64)> {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .published_links
            .clone()
    }

    /// Learn the cgroup a recorded task runs in, and what it is.
    ///
    /// Recording the same pid again, which the process table does when a
    /// pod's labels change, refreshes what the cgroup is without counting
    /// the task twice.
    pub fn record_exec(&self, entry: &ProcessEntry) {
        if entry.cgroup_id == 0 {
            return;
        }
        let workload = self.resolve(entry);
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let counted = state.pids.insert(entry.pid, entry.cgroup_id);
        if let Some(previous) = counted
            && previous != entry.cgroup_id
        {
            Self::release(&mut state, previous);
        }
        let seen = state
            .cgroups
            .entry(entry.cgroup_id)
            .or_insert_with(|| SeenCgroup {
                workload: ResolvedWorkload::default(),
                tasks: 0,
            });
        seen.workload = workload;
        if counted != Some(entry.cgroup_id) {
            seen.tasks += 1;
        }
        self.publish(&mut state);
    }

    /// Forget a task, and its cgroup with the last of them.
    pub fn record_exit(&self, pid: u32) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(cgroup_id) = state.pids.remove(&pid) else {
            return;
        };
        Self::release(&mut state, cgroup_id);
        self.publish(&mut state);
    }

    fn release(state: &mut ScopeState, cgroup_id: u64) {
        if let Some(seen) = state.cgroups.get_mut(&cgroup_id) {
            seen.tasks = seen.tasks.saturating_sub(1);
            if seen.tasks == 0 {
                state.cgroups.remove(&cgroup_id);
            }
        }
    }

    fn resolve(&self, entry: &ProcessEntry) -> ResolvedWorkload {
        let mut resolved = workload_of(entry);
        // A link belongs to a cgroup, never to one task in it, so the
        // executable is not part of what a cgroup is.
        resolved.exe = None;
        if resolved.cgroup.is_none()
            && let Some(reader) = &self.cgroups_reader
        {
            match reader.read_cgroup(entry.pid) {
                Ok(payload) => resolved.cgroup = cgroup_path_of(&payload).map(ToOwned::to_owned),
                Err(err) => debug!(pid = entry.pid, error = %err, "no cgroup path for a task"),
            }
        }
        resolved.unit = resolved
            .cgroup
            .as_deref()
            .and_then(unit_of)
            .map(ToOwned::to_owned);
        resolved
    }

    fn publish(&self, state: &mut ScopeState) {
        let mut maps = self.maps.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(maps) = maps.as_mut() else {
            return;
        };
        let links = state.wanted_links();
        if links != state.published_links {
            match maps.publish_links(&links) {
                Ok(()) => state.published_links = links,
                Err(err) => warn!(error = %err, "container link table write failed"),
            }
        }
        let scope = state.wanted_scope();
        if scope != state.published_scope {
            match maps.publish_scope(&scope) {
                Ok(()) => state.published_scope = scope,
                Err(err) => warn!(error = %err, "IDS workload scope write failed"),
            }
        }
    }
}

impl WorkloadLinkSink for IdsWorkloadScopeService {
    fn link_owned(&self, ifindex: u32, cgroup_id: u64) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.links.insert(ifindex, cgroup_id);
        self.publish(&mut state);
    }

    fn link_gone(&self, ifindex: u32) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if state.links.remove(&ifindex).is_some() {
            self.publish(&mut state);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use domain::common::error::DomainError;
    use domain::container::entity::{ContainerContext, ContainerInfo, ContainerRuntime};

    #[derive(Default)]
    struct Recorded {
        links: Vec<(u32, u64)>,
        scope: Vec<(u64, u32)>,
        scope_writes: usize,
    }

    struct FakeMaps(Arc<Mutex<Recorded>>);

    impl IdsWorkloadScopeMapPort for FakeMaps {
        fn publish_links(&mut self, links: &[(u32, u64)]) -> Result<(), DomainError> {
            self.0.lock().unwrap().links = links.to_vec();
            Ok(())
        }

        fn publish_scope(&mut self, entries: &[(u64, u32)]) -> Result<(), DomainError> {
            let mut recorded = self.0.lock().unwrap();
            recorded.scope = entries.to_vec();
            recorded.scope_writes += 1;
            Ok(())
        }
    }

    fn service() -> (IdsWorkloadScopeService, Arc<Mutex<Recorded>>) {
        let recorded = Arc::new(Mutex::new(Recorded::default()));
        let svc = IdsWorkloadScopeService::new();
        svc.set_maps(Box::new(FakeMaps(Arc::clone(&recorded))));
        (svc, recorded)
    }

    fn container_entry(pid: u32, cgroup_id: u64, name: &str) -> ProcessEntry {
        let mut entry = ProcessEntry::new(pid, "app".to_string(), 1);
        entry.cgroup_id = cgroup_id;
        entry.container = Some(ContainerContext::new(ContainerInfo::Container {
            container_id: format!("{name:0<64}"),
            runtime: ContainerRuntime::Docker,
            cgroup_path: format!("/system.slice/docker-{name}.scope"),
            pid,
        }));
        entry
    }

    fn selector(container: &str) -> WorkloadSelector {
        WorkloadSelector::new(None, None, None, Some(container.to_string())).unwrap()
    }

    fn by_cgroup(cgroup: &str) -> WorkloadSelector {
        WorkloadSelector::new(None, None, Some(cgroup.to_string()), None).unwrap()
    }

    #[test]
    fn a_matching_cgroup_is_written_under_the_rule_index() {
        let (svc, recorded) = service();
        svc.set_rules(vec![(4, by_cgroup("/system.slice/docker-web.scope"))]);
        svc.record_exec(&container_entry(10, 100, "web"));
        svc.record_exec(&container_entry(11, 200, "db"));
        assert_eq!(recorded.lock().unwrap().scope, vec![(100, 4)]);
    }

    #[test]
    fn the_cgroup_is_dropped_with_its_last_task() {
        let (svc, recorded) = service();
        svc.set_rules(vec![(0, by_cgroup("/system.slice/docker-web.scope"))]);
        svc.record_exec(&container_entry(10, 100, "web"));
        svc.record_exec(&container_entry(11, 100, "web"));
        svc.record_exit(10);
        assert_eq!(recorded.lock().unwrap().scope, vec![(100, 0)]);
        svc.record_exit(11);
        assert!(recorded.lock().unwrap().scope.is_empty());
    }

    #[test]
    fn recording_the_same_pid_again_counts_it_once() {
        let (svc, recorded) = service();
        svc.set_rules(vec![(0, by_cgroup("/system.slice/docker-web.scope"))]);
        svc.record_exec(&container_entry(10, 100, "web"));
        svc.record_exec(&container_entry(10, 100, "web"));
        svc.record_exit(10);
        assert!(recorded.lock().unwrap().scope.is_empty());
    }

    #[test]
    fn an_unchanged_scope_is_not_written_again() {
        let (svc, recorded) = service();
        svc.set_rules(vec![(0, by_cgroup("/system.slice/docker-web.scope"))]);
        svc.record_exec(&container_entry(10, 100, "web"));
        let writes = recorded.lock().unwrap().scope_writes;
        svc.record_exec(&container_entry(11, 100, "web"));
        assert_eq!(recorded.lock().unwrap().scope_writes, writes);
    }

    #[test]
    fn new_rules_are_matched_against_the_cgroups_already_seen() {
        let (svc, recorded) = service();
        svc.record_exec(&container_entry(10, 100, "web"));
        assert!(recorded.lock().unwrap().scope.is_empty());
        svc.set_rules(vec![(2, by_cgroup("/system.slice"))]);
        assert_eq!(recorded.lock().unwrap().scope, vec![(100, 2)]);
        svc.set_rules(Vec::new());
        assert!(recorded.lock().unwrap().scope.is_empty());
    }

    #[test]
    fn a_selector_naming_a_container_by_id_prefix_matches() {
        let (svc, recorded) = service();
        svc.set_rules(vec![(1, selector("abc000000000"))]);
        svc.record_exec(&container_entry(10, 100, "abc"));
        assert_eq!(recorded.lock().unwrap().scope, vec![(100, 1)]);
    }

    #[test]
    fn links_are_published_and_withdrawn() {
        let (svc, recorded) = service();
        svc.link_owned(7, 100);
        svc.link_owned(9, 200);
        assert_eq!(recorded.lock().unwrap().links, vec![(7, 100), (9, 200)]);
        svc.link_gone(7);
        assert_eq!(recorded.lock().unwrap().links, vec![(9, 200)]);
    }

    #[test]
    fn new_maps_receive_everything_known() {
        let svc = IdsWorkloadScopeService::new();
        assert!(!svc.supported());
        svc.set_rules(vec![(0, by_cgroup("/system.slice/docker-web.scope"))]);
        svc.record_exec(&container_entry(10, 100, "web"));
        svc.link_owned(7, 100);

        let recorded = Arc::new(Mutex::new(Recorded::default()));
        svc.set_maps(Box::new(FakeMaps(Arc::clone(&recorded))));
        assert!(svc.supported());
        assert_eq!(recorded.lock().unwrap().links, vec![(7, 100)]);
        assert_eq!(recorded.lock().unwrap().scope, vec![(100, 0)]);
    }

    #[test]
    fn a_task_without_a_cgroup_id_is_ignored() {
        let (svc, recorded) = service();
        svc.set_rules(vec![(0, by_cgroup("/system.slice/docker-web.scope"))]);
        svc.record_exec(&container_entry(10, 0, "web"));
        assert!(recorded.lock().unwrap().scope.is_empty());
    }
}
