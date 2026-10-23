//! Compiling a DLP scope policy into the allow-list the probes read.
//!
//! The kernel side of the fence is a cgroup id in a map: a probe reads the
//! task's own cgroup, walks a bounded number of ancestors, and copies
//! nothing unless one of them is allowed. The policy above it is written in
//! names an operator knows, from a tenant down to an executable, and none of
//! those exists in the kernel. This service is the whole of the translation,
//! and it runs for as long as the agent does, because a pod that restarts is
//! a new cgroup id for the same name.
//!
//! Three things it does deliberately.
//!
//! It starts narrow. When the maps are installed, only the cgroup paths the
//! operator wrote by hand are published; the selector pass widens the scope
//! on its first tick. Widening a fence a moment late costs a few events;
//! arming it wide and narrowing it afterwards reads a neighbouring tenant's
//! plaintext for the width of that window.
//!
//! It replaces rather than adds. Cgroup ids are reused, so an id left in the
//! allow-list after its workload ended is a future workload nobody selected
//! being read.
//!
//! It reports what matched nothing. A selector naming a pod label that does
//! not exist disables DLP for that workload silently, which is the one
//! failure mode of a privacy fence nobody notices, so an unmatched rule is a
//! finding with a reason rather than a count.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use domain::common::error::DomainError;
use domain::container::entity::ContainerMetadata;
use domain::dlp::scope::{
    DlpObservedWorkload, DlpScopeEvidence, DlpScopeMode, DlpScopePolicy, DlpScopeVerdict,
    DlpScopedWorkload, DlpUnmatchedSelector, DlpWorkloadFacts, EffectiveDlpScope,
};
use domain::process::entity::ProcessEntry;
use ports::secondary::dlp_scope_map_port::DlpScopeMapPort;
use ports::secondary::dlp_workload_source_port::DlpWorkloadSourcePort;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

/// The rule name reported for a cgroup path the operator listed directly.
/// It is not a selector, so it has no name of its own, and reporting it as
/// one would let an operator look for a rule that does not exist.
const CONFIGURED_RULE: &str = "configured cgroup";

/// Seconds between two refreshes when none is configured. A pod that starts
/// is in scope within this window, which is why the executable leg is fed by
/// exec events instead of waiting for it.
pub const DEFAULT_REFRESH_SECS: u64 = 15;

/// One cgroup path the configuration named, and the id it resolved to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfiguredCgroup {
    /// The path as configured.
    pub path: String,
    /// The cgroup v2 id it resolved to on this node.
    pub id: u64,
}

/// What the last pass decided, and what has been written.
#[derive(Debug, Default)]
struct ScopeState {
    /// The last answer from the workload source, kept so an exec event can be
    /// matched against everything known about its cgroup rather than against
    /// the executable alone.
    observed: HashMap<u64, DlpObservedWorkload>,
    in_scope: Vec<DlpScopedWorkload>,
    excluded: Vec<DlpScopedWorkload>,
    unmatched: Vec<DlpUnmatchedSelector>,
    unselected: usize,
    /// Cgroup ids admitted because a task in them matched an executable
    /// rule, with how many live tasks hold each one. A cgroup is dropped
    /// when the last of them exits, because the next task in a reused id may
    /// be anything at all.
    by_exec: HashMap<u64, (usize, DlpScopedWorkload)>,
    /// Which cgroup an admitted pid was counted against, so an exit
    /// decrements the same entry the exec incremented.
    exec_pids: HashMap<u32, u64>,
    /// What was last written to the map, in the order it was written.
    published: Vec<u64>,
    refreshed_unix: u64,
}

/// What one resolution pass decided, before it is written down.
#[derive(Debug, Default)]
struct Pass {
    in_scope: Vec<DlpScopedWorkload>,
    excluded: Vec<DlpScopedWorkload>,
    /// Ids refused by a rule. Kept apart from the report because the refusal
    /// has to be applied to every other leg, the configured list and the
    /// exec-admitted cgroups included.
    excluded_ids: Vec<u64>,
    ids: Vec<u64>,
    unselected: usize,
    /// One flag per selector: whether anything at all was decided by it.
    matched: Vec<bool>,
    by_id: HashMap<u64, DlpObservedWorkload>,
    evidence: DlpScopeEvidence,
}

/// Turns a DLP scope policy into cgroup ids, and keeps doing it.
pub struct DlpScopeService {
    mode: DlpScopeMode,
    policy: DlpScopePolicy,
    configured: Vec<ConfiguredCgroup>,
    maps: Mutex<Option<Box<dyn DlpScopeMapPort>>>,
    source: RwLock<Option<Arc<dyn DlpWorkloadSourcePort>>>,
    state: RwLock<ScopeState>,
}

impl DlpScopeService {
    /// Service for `mode` and `policy`, over the cgroup paths the
    /// configuration resolved.
    #[must_use]
    pub fn new(
        mode: DlpScopeMode,
        policy: DlpScopePolicy,
        configured: Vec<ConfiguredCgroup>,
    ) -> Self {
        Self {
            mode,
            policy,
            configured,
            maps: Mutex::new(None),
            source: RwLock::new(None),
            state: RwLock::new(ScopeState::default()),
        }
    }

    /// Register the source that answers which workloads are on this node.
    ///
    /// Without one the service publishes the configured cgroups and nothing
    /// else, and every selector reports itself unmatched, which is what an
    /// agent that cannot read the cgroup tree should say.
    #[must_use]
    pub fn with_source(self, source: Arc<dyn DlpWorkloadSourcePort>) -> Self {
        self.set_source(source);
        self
    }

    /// The same registration after the service is shared.
    ///
    /// The agent builds this service before it has decided whether it can
    /// read containers at all, and the source is what answers that, so the
    /// two are not built in the same breath.
    pub fn set_source(&self, source: Arc<dyn DlpWorkloadSourcePort>) {
        *self
            .source
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(source);
    }

    /// Whether any executable rule is in force, which is what decides
    /// whether exec events have to reach this service at all.
    #[must_use]
    pub fn needs_executables(&self) -> bool {
        self.policy.needs_executables()
    }

    /// Hand the service the scope maps of a freshly loaded DLP object and
    /// publish the narrow scope: the configured cgroups alone.
    ///
    /// # Errors
    ///
    /// Whatever the map write refused. The caller treats that as a load
    /// failure rather than carrying on, because an object attached with an
    /// unwritten scope is the wide-open case.
    pub fn install_maps(&self, maps: Box<dyn DlpScopeMapPort>) -> Result<(), DomainError> {
        {
            let mut slot = self
                .maps
                .lock()
                .map_err(|_| DomainError::EngineError("DLP scope maps lock poisoned".into()))?;
            *slot = Some(maps);
        }
        let mut lines = Vec::new();
        let mut ids = Vec::new();
        for cgroup in &self.configured {
            ids.push(cgroup.id);
            lines.push(configured_line(cgroup));
        }
        {
            let mut state = self.write_state()?;
            state.in_scope = lines;
            state.refreshed_unix = now_unix();
        }
        self.publish(&ids)
    }

    /// Resolve the policy against the workloads on the node and republish.
    ///
    /// # Errors
    ///
    /// Whatever the source or the map write refused.
    pub async fn reconcile(&self) -> Result<(), DomainError> {
        if !self.mode.is_scoped() {
            // Nothing to compile: every workload is read, and the probes are
            // told so explicitly rather than left on an unwritten map.
            return self.publish(&[]);
        }

        let source = self
            .source
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let observed = match source {
            Some(source) => source.observe().await?,
            None => Vec::new(),
        };

        let mut pass = self.classify(&observed);
        self.classify_configured(&mut pass);
        let unmatched = self.findings(&pass);

        for finding in &unmatched {
            warn!(
                rule = finding.rule,
                selector = finding.selector,
                reason = finding.reason,
                "DLP scope rule matched no workload"
            );
        }

        let mut ids = pass.ids;
        {
            let mut state = self.write_state()?;
            // An exec-admitted cgroup survives the pass, unless a rule now
            // refuses it: the task holding it is still running, and dropping
            // it here would stop reading a workload that still matches.
            for (id, (_, line)) in &state.by_exec {
                if pass.excluded_ids.contains(id) || ids.contains(id) {
                    continue;
                }
                ids.push(*id);
                pass.in_scope.push(line.clone());
            }
            state.observed = pass.by_id;
            state.in_scope = pass.in_scope;
            state.excluded = pass.excluded;
            state.unmatched = unmatched;
            state.unselected = pass.unselected;
            state.refreshed_unix = now_unix();
        }

        ids.retain(|id| !pass.excluded_ids.contains(id));
        ids.sort_unstable();
        ids.dedup();
        self.publish(&ids)
    }

    /// Evaluate every observed workload against the policy.
    fn classify(&self, observed: &[DlpObservedWorkload]) -> Pass {
        let mut pass = Pass {
            matched: vec![false; self.policy.len()],
            by_id: HashMap::with_capacity(observed.len()),
            ..Pass::default()
        };
        for workload in observed {
            let facts = workload.facts();
            pass.evidence.record(&facts);
            match self.policy.evaluate(&facts) {
                DlpScopeVerdict::InScope { rule } => {
                    self.mark(&mut pass, &rule);
                    if let Some(id) = workload.cgroup_id {
                        pass.ids.push(id);
                    }
                    pass.in_scope.push(DlpScopedWorkload::from_facts(
                        &facts,
                        workload.cgroup_id,
                        rule,
                    ));
                }
                DlpScopeVerdict::Excluded { rule } => {
                    self.mark(&mut pass, &rule);
                    if let Some(id) = workload.cgroup_id {
                        pass.excluded_ids.push(id);
                    }
                    pass.excluded.push(DlpScopedWorkload::from_facts(
                        &facts,
                        workload.cgroup_id,
                        rule,
                    ));
                }
                DlpScopeVerdict::NotSelected => pass.unselected += 1,
            }
            if let Some(id) = workload.cgroup_id {
                pass.by_id.insert(id, workload.clone());
            }
        }
        pass
    }

    /// A configured path is read unless a rule refuses it by name: the list
    /// is an operator's own decision, and an exclusion is the one thing
    /// allowed to overrule it, because that is what an exclusion is for.
    fn classify_configured(&self, pass: &mut Pass) {
        for cgroup in &self.configured {
            let facts = DlpWorkloadFacts {
                cgroup: Some(&cgroup.path),
                ..DlpWorkloadFacts::default()
            };
            if let DlpScopeVerdict::Excluded { rule } = self.policy.evaluate(&facts) {
                self.mark(pass, &rule);
                pass.excluded_ids.push(cgroup.id);
                pass.excluded
                    .push(DlpScopedWorkload::from_facts(&facts, Some(cgroup.id), rule));
                continue;
            }
            pass.ids.push(cgroup.id);
            pass.in_scope.push(configured_line(cgroup));
        }
    }

    /// One finding per rule that decided nothing.
    fn findings(&self, pass: &Pass) -> Vec<DlpUnmatchedSelector> {
        self.policy
            .selectors()
            .iter()
            .zip(pass.matched.iter())
            .filter(|(_, matched)| !**matched)
            .map(|(selector, _)| DlpUnmatchedSelector::new(selector, &pass.evidence))
            .collect()
    }

    fn mark(&self, pass: &mut Pass, rule: &str) {
        if let Some(index) = self.rule_index(rule) {
            pass.matched[index] = true;
        }
    }

    /// Record an exec, so an executable rule can admit the cgroup the task
    /// runs in.
    ///
    /// Called on every exec rather than on a change, because a cgroup id is
    /// reused and a cache of what was already admitted goes stale the moment
    /// it is.
    pub fn record_exec(&self, entry: &ProcessEntry) {
        if !self.mode.is_scoped() || !self.policy.needs_executables() {
            return;
        }
        let Some(exe) = entry.identity.path() else {
            return;
        };
        if entry.cgroup_id == 0 {
            return;
        }

        let workload = self.merged_workload(entry, exe);
        let facts = workload.facts();
        let DlpScopeVerdict::InScope { rule } = self.policy.evaluate(&facts) else {
            return;
        };
        let line = DlpScopedWorkload::from_facts(&facts, Some(entry.cgroup_id), rule);

        let ids = {
            let Ok(mut state) = self.state.write() else {
                warn!("DLP scope state lock poisoned; exec not recorded");
                return;
            };
            if state.exec_pids.insert(entry.pid, entry.cgroup_id).is_some() {
                // A pid seen twice without an exit is a missed exit event,
                // not a second task: counting it twice would pin the cgroup
                // in scope for as long as the agent runs.
                return;
            }
            let slot = state
                .by_exec
                .entry(entry.cgroup_id)
                .or_insert((0, line.clone()));
            slot.0 += 1;
            if slot.0 > 1 {
                return;
            }
            let mut ids = state.published.clone();
            if ids.contains(&entry.cgroup_id) {
                return;
            }
            ids.push(entry.cgroup_id);
            state.in_scope.push(line);
            ids
        };
        if let Err(e) = self.publish(&ids) {
            warn!(error = %e, "DLP scope could not be widened for an exec");
        }
    }

    /// Record an exit, so a cgroup admitted for one task stops being read
    /// when its last task is gone.
    pub fn record_exit(&self, pid: u32) {
        if !self.mode.is_scoped() || !self.policy.needs_executables() {
            return;
        }
        let ids = {
            let Ok(mut state) = self.state.write() else {
                warn!("DLP scope state lock poisoned; exit not recorded");
                return;
            };
            let Some(cgroup_id) = state.exec_pids.remove(&pid) else {
                return;
            };
            let Some(slot) = state.by_exec.get_mut(&cgroup_id) else {
                return;
            };
            slot.0 = slot.0.saturating_sub(1);
            if slot.0 > 0 {
                return;
            }
            state.by_exec.remove(&cgroup_id);
            state
                .in_scope
                .retain(|line| line.cgroup_id != Some(cgroup_id));
            let mut ids = state.published.clone();
            ids.retain(|id| *id != cgroup_id);
            ids
        };
        if let Err(e) = self.publish(&ids) {
            warn!(error = %e, "DLP scope could not be narrowed after an exit");
        }
    }

    /// What is being read right now, and what is not.
    ///
    /// # Errors
    ///
    /// Only a poisoned lock, which is an agent already in trouble.
    pub fn effective_scope(&self) -> Result<EffectiveDlpScope, DomainError> {
        let installed = self
            .maps
            .lock()
            .map_err(|_| DomainError::EngineError("DLP scope maps lock poisoned".into()))?
            .is_some();
        if !installed {
            return Ok(EffectiveDlpScope::disabled(now_unix()));
        }
        let state = self
            .state
            .read()
            .map_err(|_| DomainError::EngineError("DLP scope state lock poisoned".into()))?;
        Ok(EffectiveDlpScope {
            mode: self.mode.as_str().to_string(),
            selectors: self.policy.len(),
            allowed_cgroups: state.published.len(),
            enabled: true,
            in_scope: state.in_scope.clone(),
            excluded: state.excluded.clone(),
            unmatched: state.unmatched.clone(),
            unselected: state.unselected,
            refreshed_unix: state.refreshed_unix,
        })
    }

    /// Refresh the scope every `interval` until `cancel` fires.
    ///
    /// The first pass happens immediately, because it is the one that widens
    /// the narrow scope the load installed.
    pub async fn watch(self: Arc<Self>, interval: Duration, cancel: CancellationToken) {
        let interval = if interval.is_zero() {
            Duration::from_secs(DEFAULT_REFRESH_SECS)
        } else {
            interval
        };
        info!(
            interval_secs = interval.as_secs(),
            selectors = self.policy.len(),
            "DLP scope refresh started"
        );
        loop {
            if let Err(e) = self.reconcile().await {
                warn!(error = %e, "DLP scope refresh failed");
            }
            tokio::select! {
                () = tokio::time::sleep(interval) => {}
                () = cancel.cancelled() => {
                    info!("DLP scope refresh stopped");
                    return;
                }
            }
        }
    }

    /// Everything known about the cgroup this task runs in, plus its own
    /// executable. The cgroup half comes from the last pass, so an `exe`
    /// rule that also names a pod is decided against the pod rather than
    /// failing for want of a fact the exec event never carries.
    fn merged_workload(&self, entry: &ProcessEntry, exe: &str) -> DlpObservedWorkload {
        let mut workload = self
            .state
            .read()
            .ok()
            .and_then(|state| state.observed.get(&entry.cgroup_id).cloned())
            .unwrap_or_default();
        workload.cgroup_id = Some(entry.cgroup_id);
        workload.exe = Some(exe.to_string());
        if let Some(container) = &entry.container {
            if workload.container_id.is_none() {
                workload.container_id = container.info.container_id().map(ToString::to_string);
            }
            match &container.metadata {
                Some(ContainerMetadata::Kubernetes(pod)) => {
                    workload.pod.get_or_insert_with(|| pod.pod_name.clone());
                    workload
                        .namespace
                        .get_or_insert_with(|| pod.namespace.clone());
                    workload
                        .container_name
                        .get_or_insert_with(|| pod.container_name.clone());
                }
                Some(ContainerMetadata::Docker(docker)) => {
                    workload
                        .container_name
                        .get_or_insert_with(|| docker.name.clone());
                }
                // The metadata enum is open, so a runtime added upstream
                // resolves no name here until this arm names it rather than
                // matching the wrong workload on a default.
                _ => {}
            }
        }
        workload
    }

    fn rule_index(&self, rule: &str) -> Option<usize> {
        self.policy
            .selectors()
            .iter()
            .position(|selector| selector.label() == rule)
    }

    fn write_state(&self) -> Result<std::sync::RwLockWriteGuard<'_, ScopeState>, DomainError> {
        self.state
            .write()
            .map_err(|_| DomainError::EngineError("DLP scope state lock poisoned".into()))
    }

    /// Write the allow-list and the mode, and remember what was written.
    fn publish(&self, ids: &[u64]) -> Result<(), DomainError> {
        let mut slot = self
            .maps
            .lock()
            .map_err(|_| DomainError::EngineError("DLP scope maps lock poisoned".into()))?;
        let Some(maps) = slot.as_mut() else {
            // No object loaded: the scope is still resolved and reported, so
            // an operator reading the API before the probes attach sees what
            // would be read rather than an empty answer.
            return Ok(());
        };
        maps.publish_scope(self.mode.is_scoped(), ids)?;
        drop(slot);
        let mut state = self.write_state()?;
        state.published = ids.to_vec();
        info!(
            cgroups = ids.len(),
            scoped = self.mode.is_scoped(),
            "DLP scope published"
        );
        Ok(())
    }
}

fn configured_line(cgroup: &ConfiguredCgroup) -> DlpScopedWorkload {
    DlpScopedWorkload {
        cgroup: Some(cgroup.path.clone()),
        cgroup_id: Some(cgroup.id),
        rule: CONFIGURED_RULE.to_string(),
        ..DlpScopedWorkload::default()
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use domain::dlp::scope::{DlpScopeAction, DlpScopeSelector};
    use domain::process::entity::{ProcessEntry, ProcessIdentity};

    use super::*;

    /// Records the last write, so a test asserts what the kernel would see
    /// rather than what the service thinks it published.
    struct SpyMaps {
        written: Arc<Mutex<(bool, Vec<u64>)>>,
    }

    impl DlpScopeMapPort for SpyMaps {
        fn publish_scope(&mut self, scoped: bool, cgroup_ids: &[u64]) -> Result<(), DomainError> {
            *self.written.lock().expect("spy lock") = (scoped, cgroup_ids.to_vec());
            Ok(())
        }

        fn allowed_cgroups(&self) -> usize {
            self.written.lock().expect("spy lock").1.len()
        }
    }

    struct FixedSource(Vec<DlpObservedWorkload>);

    #[async_trait::async_trait]
    impl DlpWorkloadSourcePort for FixedSource {
        async fn observe(&self) -> Result<Vec<DlpObservedWorkload>, DomainError> {
            Ok(self.0.clone())
        }
        fn name(&self) -> &'static str {
            "fixed"
        }
    }

    fn pod(name: &str, namespace: &str, cgroup: &str, id: u64) -> DlpObservedWorkload {
        DlpObservedWorkload {
            cgroup: Some(cgroup.to_string()),
            cgroup_id: Some(id),
            namespace: Some(namespace.to_string()),
            pod: Some(name.to_string()),
            container_name: Some("api".to_string()),
            ..DlpObservedWorkload::default()
        }
    }

    fn rule(action: DlpScopeAction, field: &str, value: &str) -> DlpScopeSelector {
        let mut selector = DlpScopeSelector {
            action,
            ..DlpScopeSelector::default()
        };
        let value = Some(value.to_string());
        match field {
            "pod" => selector.pod = value,
            "namespace" => selector.namespace = value,
            "container" => selector.container = value,
            "exe" => selector.exe = value,
            other => panic!("unexpected field {other}"),
        }
        selector
    }

    fn include(field: &str, value: &str) -> DlpScopeSelector {
        rule(DlpScopeAction::Include, field, value)
    }

    fn exclude(field: &str, value: &str) -> DlpScopeSelector {
        rule(DlpScopeAction::Exclude, field, value)
    }

    struct Harness {
        service: Arc<DlpScopeService>,
        written: Arc<Mutex<(bool, Vec<u64>)>>,
    }

    impl Harness {
        fn scope(&self) -> EffectiveDlpScope {
            self.service.effective_scope().expect("scope")
        }

        fn published(&self) -> (bool, Vec<u64>) {
            self.written.lock().expect("lock").clone()
        }
    }

    fn harness(
        mode: DlpScopeMode,
        selectors: Vec<DlpScopeSelector>,
        configured: Vec<ConfiguredCgroup>,
        observed: Vec<DlpObservedWorkload>,
    ) -> Harness {
        let policy = DlpScopePolicy::from_selectors(selectors).expect("policy");
        let service = Arc::new(
            DlpScopeService::new(mode, policy, configured)
                .with_source(Arc::new(FixedSource(observed))),
        );
        let written = Arc::new(Mutex::new((false, Vec::new())));
        service
            .install_maps(Box::new(SpyMaps {
                written: Arc::clone(&written),
            }))
            .expect("install");
        Harness { service, written }
    }

    fn exec(pid: u32, cgroup_id: u64, exe: &str) -> ProcessEntry {
        let mut entry = ProcessEntry::new(pid, "worker", 1);
        entry.cgroup_id = cgroup_id;
        entry.identity = ProcessIdentity::Path {
            path: exe.to_string(),
            dev: 1,
            inode: 2,
        };
        entry
    }

    #[test]
    fn installing_the_maps_publishes_the_configured_cgroups_and_nothing_else() {
        let h = harness(
            DlpScopeMode::Workloads,
            vec![include("pod", "api-7c9")],
            vec![ConfiguredCgroup {
                path: "/kubepods.slice".to_string(),
                id: 42,
            }],
            Vec::new(),
        );
        let (scoped, ids) = h.published();
        assert!(scoped, "the mode is scoped from the first write");
        assert_eq!(ids, vec![42], "the selector has not resolved yet");
        let scope = h.scope();
        assert!(scope.enabled);
        assert_eq!(scope.in_scope.len(), 1);
        assert_eq!(scope.in_scope[0].rule, CONFIGURED_RULE);
    }

    #[tokio::test]
    async fn a_selector_widens_the_scope_to_the_workloads_it_names() {
        let h = harness(
            DlpScopeMode::Workloads,
            vec![include("namespace", "payments")],
            Vec::new(),
            vec![
                pod("api-7c9", "payments", "/kubepods.slice/api", 7),
                pod("web-1", "marketing", "/kubepods.slice/web", 9),
            ],
        );
        h.service.reconcile().await.expect("reconcile");

        let (scoped, ids) = h.published();
        assert!(scoped);
        assert_eq!(ids, vec![7], "only the selected namespace is read");
        let scope = h.scope();
        assert_eq!(scope.unselected, 1, "the other pod is counted, not listed");
        assert!(scope.unmatched.is_empty());
        assert_eq!(scope.in_scope[0].pod.as_deref(), Some("api-7c9"));
        assert_eq!(scope.allowed_cgroups, 1);
    }

    #[tokio::test]
    async fn an_exclusion_takes_a_workload_out_whatever_included_it() {
        let h = harness(
            DlpScopeMode::Workloads,
            vec![include("namespace", "payments"), exclude("pod", "api-7c9")],
            Vec::new(),
            vec![
                pod("api-7c9", "payments", "/kubepods.slice/api", 7),
                pod("ledger-2", "payments", "/kubepods.slice/ledger", 8),
            ],
        );
        h.service.reconcile().await.expect("reconcile");

        let (_, ids) = h.published();
        assert_eq!(ids, vec![8]);
        let scope = h.scope();
        assert_eq!(scope.excluded.len(), 1);
        assert_eq!(scope.excluded[0].pod.as_deref(), Some("api-7c9"));
        assert!(scope.unmatched.is_empty());
    }

    #[tokio::test]
    async fn an_exclusion_overrules_a_configured_cgroup() {
        let h = harness(
            DlpScopeMode::Workloads,
            vec![exclude("pod", "api-7c9")],
            vec![ConfiguredCgroup {
                path: "/kubepods.slice".to_string(),
                id: 42,
            }],
            vec![pod("api-7c9", "payments", "/kubepods.slice", 42)],
        );
        h.service.reconcile().await.expect("reconcile");

        let (_, ids) = h.published();
        assert!(
            ids.is_empty(),
            "a refused workload is not read because a path listed it"
        );
    }

    #[tokio::test]
    async fn a_rule_that_resolves_to_nothing_is_reported_with_a_reason() {
        let h = harness(
            DlpScopeMode::Workloads,
            vec![include("pod", "api-typo")],
            Vec::new(),
            vec![pod("api-7c9", "payments", "/kubepods.slice/api", 7)],
        );
        h.service.reconcile().await.expect("reconcile");

        let scope = h.scope();
        assert!(scope.in_scope.is_empty());
        assert_eq!(scope.unmatched.len(), 1);
        assert_eq!(scope.unmatched[0].action, "include");
        assert!(scope.unmatched[0].selector.contains("api-typo"));
        assert!(
            scope.unmatched[0].reason.contains("no workload"),
            "reason was {}",
            scope.unmatched[0].reason
        );
    }

    #[tokio::test]
    async fn a_rule_naming_a_fact_this_node_never_resolved_says_so() {
        let h = harness(
            DlpScopeMode::Workloads,
            vec![include("pod", "api-7c9")],
            Vec::new(),
            // A node with no Kubernetes metadata: cgroups and nothing else.
            vec![DlpObservedWorkload {
                cgroup: Some("/system.slice/nginx.service".to_string()),
                cgroup_id: Some(3),
                unit: Some("nginx.service".to_string()),
                ..DlpObservedWorkload::default()
            }],
        );
        h.service.reconcile().await.expect("reconcile");

        let scope = h.scope();
        assert_eq!(scope.unmatched.len(), 1);
        assert!(
            scope.unmatched[0].reason.contains("resolved no pod"),
            "reason was {}",
            scope.unmatched[0].reason
        );
    }

    #[tokio::test]
    async fn an_exec_admits_its_cgroup_and_the_last_exit_takes_it_back_out() {
        let h = harness(
            DlpScopeMode::Workloads,
            vec![include("exe", "/usr/bin/psql")],
            Vec::new(),
            Vec::new(),
        );
        h.service.reconcile().await.expect("reconcile");
        assert!(h.published().1.is_empty());
        assert!(h.service.needs_executables());

        h.service.record_exec(&exec(1234, 77, "/usr/bin/psql"));
        assert_eq!(h.published().1, vec![77]);
        // A second task in the same cgroup does not publish a second entry.
        h.service.record_exec(&exec(1235, 77, "/usr/bin/psql"));
        assert_eq!(h.published().1, vec![77]);
        // An executable no rule names changes nothing.
        h.service.record_exec(&exec(1236, 78, "/usr/bin/curl"));
        assert_eq!(h.published().1, vec![77]);

        h.service.record_exit(1234);
        assert_eq!(h.published().1, vec![77], "one task is still running");
        h.service.record_exit(1235);
        assert!(
            h.published().1.is_empty(),
            "a reused cgroup id must not stay allowed"
        );
        assert!(h.scope().in_scope.is_empty());
    }

    #[tokio::test]
    async fn an_exec_admitted_cgroup_survives_a_refresh() {
        let h = harness(
            DlpScopeMode::Workloads,
            vec![include("exe", "/usr/bin/psql")],
            Vec::new(),
            vec![pod("web-1", "marketing", "/kubepods.slice/web", 9)],
        );
        h.service.record_exec(&exec(1234, 77, "/usr/bin/psql"));
        h.service.reconcile().await.expect("reconcile");
        assert_eq!(h.published().1, vec![77]);
    }

    #[tokio::test]
    async fn an_unscoped_mode_writes_the_open_mode_rather_than_leaving_the_map_unwritten() {
        let h = harness(DlpScopeMode::All, Vec::new(), Vec::new(), Vec::new());
        h.service.reconcile().await.expect("reconcile");
        let (scoped, ids) = h.published();
        assert!(!scoped);
        assert!(ids.is_empty());
        assert_eq!(h.scope().mode, "all");
    }

    #[test]
    fn a_scope_with_no_object_loaded_reports_itself_off() {
        let service = DlpScopeService::new(
            DlpScopeMode::Workloads,
            DlpScopePolicy::from_selectors(vec![include("pod", "api")]).expect("policy"),
            Vec::new(),
        );
        let scope = service.effective_scope().expect("scope");
        assert!(!scope.enabled);
        assert_eq!(scope.allowed_cgroups, 0);
    }
}
