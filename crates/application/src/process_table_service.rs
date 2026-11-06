//! Keeping the process table filled, and keeping it honest.
//!
//! The kernel notifies; this service decides what that notification is worth.
//! An exec gets one `/proc` pass - the executable, the command line where the
//! configuration allows it, and the parent where the kernel could not read
//! it - and one container resolution, and whatever that pass could not read
//! stays absent. A fork gets no `/proc` pass at all: the child runs its
//! parent's image until it execs, so it inherits the parent's entry, and a
//! read made at that instant would race the exec that usually follows. The
//! container alone is resolved again when the child was cloned into another
//! cgroup than its parent's. An
//! exit removes the pid immediately, which is the only eviction that is
//! correct: a pid is reused, and a table that let a dead entry linger would
//! name the wrong binary on the next flow rather than naming none. An exited
//! process something still descends from is kept apart, by the table, so the
//! lineage of a flow survives the shell that launched it.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use domain::container::engine::ContainerResolverEngine;
use domain::container::entity::ContainerContext;
use domain::process::engine::{Lineage, ProcessTable, PurgeOutcome};
use domain::process::entity::{
    ProcessEntry, ProcessEventKind, ProcessIdentity, ProcessLifecycleEvent, ProcessTableStats,
};
use ports::secondary::executable_digest_port::ExecutableDigester;
use ports::secondary::metadata_enricher_port::MetadataEnricher;
use ports::secondary::process_details_port::ProcessDetailsReader;
use ports::secondary::process_executable_port::ProcessExecutableReader;
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::dlp_scope_service::DlpScopeService;
use crate::host_rule_service::HostRuleService;
use crate::ids_workload_scope_service::IdsWorkloadScopeService;
use crate::qos_cgroup_shaping_service::QosCgroupShapingService;
use crate::ransom_service::RansomService;
use crate::workload_policy_service::WorkloadPolicyService;

/// How long the writer lets the metadata settle after it last changed before
/// resolving the running containers again: a rollout changes dozens of pods
/// within a second, and one pass after the burst names them all.
const REFRESH_SETTLE: Duration = Duration::from_secs(1);

/// The service behind the process table: one writer fed by the ring buffer,
/// any number of readers behind the API.
pub struct ProcessTableService {
    table: RwLock<ProcessTable>,
    executables: Option<Arc<dyn ProcessExecutableReader>>,
    digester: Option<Arc<dyn ExecutableDigester>>,
    details: Option<Arc<dyn ProcessDetailsReader>>,
    containers: Option<Arc<ContainerResolverEngine>>,
    metadata_enrichers: Vec<Arc<dyn MetadataEnricher>>,
    workload: Option<Arc<WorkloadPolicyService>>,
    dlp_scope: Option<Arc<DlpScopeService>>,
    ids_scope: Option<Arc<IdsWorkloadScopeService>>,
    shaping: Option<Arc<QosCgroupShapingService>>,
    host_rules: Option<Arc<HostRuleService>>,
    ransom: Option<Arc<RansomService>>,
    metadata_changes: Option<watch::Receiver<u64>>,
    capture_command_line: bool,
}

impl ProcessTableService {
    /// A service over a table bounded at `capacity`.
    ///
    /// `capture_command_line` is off by default in the configuration and must
    /// stay a decision the operator takes: argv routinely carries a password,
    /// a token or a connection string, and a table that collected it by
    /// default would be a credential store nobody asked for.
    #[must_use]
    pub fn new(capacity: usize, capture_command_line: bool) -> Self {
        Self {
            table: RwLock::new(ProcessTable::new(capacity)),
            executables: None,
            digester: None,
            details: None,
            containers: None,
            metadata_enrichers: Vec::new(),
            workload: None,
            dlp_scope: None,
            ids_scope: None,
            shaping: None,
            host_rules: None,
            ransom: None,
            metadata_changes: None,
            capture_command_line,
        }
    }

    /// Resolve the binary behind each exec through `reader`.
    #[must_use]
    pub fn with_executables(mut self, reader: Arc<dyn ProcessExecutableReader>) -> Self {
        self.executables = Some(reader);
        self
    }

    /// Name each executable by its digest through `digester` as well as by
    /// its path.
    #[must_use]
    pub fn with_digester(mut self, digester: Arc<dyn ExecutableDigester>) -> Self {
        self.digester = Some(digester);
        self
    }

    /// Read the parent and the command line through `reader`.
    #[must_use]
    pub fn with_details(mut self, reader: Arc<dyn ProcessDetailsReader>) -> Self {
        self.details = Some(reader);
        self
    }

    /// Name the container each exec happened in.
    #[must_use]
    pub fn with_containers(mut self, resolver: Arc<ContainerResolverEngine>) -> Self {
        self.containers = Some(resolver);
        self
    }

    /// Register a runtime enricher, consulted in registration order with the
    /// first answer winning, exactly as the alert pipeline consults them.
    #[must_use]
    pub fn with_metadata_enricher(mut self, enricher: Arc<dyn MetadataEnricher>) -> Self {
        self.metadata_enrichers.push(enricher);
        self
    }

    /// Tell `service` which workload each exec is, so the kernel's workload
    /// firewall can decide on an integer rather than on a path.
    ///
    /// It hangs off the process table because this is the one place in the
    /// agent that learns of an exec and has already resolved the binary and
    /// the container: resolving either of them a second time elsewhere would
    /// be a second answer to the same question.
    #[must_use]
    pub fn with_workload_policy(mut self, service: Arc<WorkloadPolicyService>) -> Self {
        self.workload = Some(service);
        self
    }

    /// Tell `service` which executable each task runs, so a DLP scope rule
    /// naming an executable can be decided.
    ///
    /// It hangs off the same place for the same reason as the workload
    /// policy: an exec is learned of once, and the binary behind it has been
    /// resolved by the time this runs.
    #[must_use]
    pub fn with_dlp_scope(mut self, service: Arc<DlpScopeService>) -> Self {
        self.dlp_scope = Some(service);
        self
    }

    /// Tell `service` which cgroup each task runs in, so an IDS rule scoped
    /// to a workload is written against the cgroups that workload holds.
    #[must_use]
    pub fn with_ids_workload_scope(mut self, service: Arc<IdsWorkloadScopeService>) -> Self {
        self.ids_scope = Some(service);
        self
    }

    /// Tell `service` which cgroup each task runs in, so a rate written for
    /// a workload is held by the cgroups that workload holds.
    #[must_use]
    pub fn with_cgroup_shaping(mut self, service: Arc<QosCgroupShapingService>) -> Self {
        self.shaping = Some(service);
        self
    }

    /// Evaluate `service`'s host rules against every exec and exit, after
    /// the table has recorded the one and before it forgets the other, so
    /// each event carries the binary, the user and the ancestry the table
    /// already resolved.
    #[must_use]
    pub fn with_host_rules(mut self, service: Arc<HostRuleService>) -> Self {
        self.host_rules = Some(service);
        self
    }

    /// Hand every exec, with its command line and ancestry, to the mass
    /// encryption engine, which holds a prior for whoever destroys backups.
    #[must_use]
    pub fn with_ransom(mut self, service: Arc<RansomService>) -> Self {
        self.ransom = Some(service);
        self
    }

    /// Resolve the running containers again each time `changes` moves.
    ///
    /// An exec is resolved once, against what the enrichers knew at that
    /// instant, and a pod's metadata arrives after its first process has
    /// started and changes while it runs: a label added, a namespace
    /// relabelled. Without this a selector naming labels would see a pod as
    /// it was when each process last exec'd, which for a long-lived server
    /// is as it was before it was ready.
    #[must_use]
    pub fn with_metadata_changes(mut self, changes: watch::Receiver<u64>) -> Self {
        self.metadata_changes = Some(changes);
        self
    }

    /// Resolve every containerised entry's metadata again, and tell the
    /// workload policy and the DLP scope about each entry whose answer
    /// changed. Returns how many changed.
    ///
    /// A host process is left alone, because which cgroup a task sits in is
    /// what made it a host process and that does not move. An entry the
    /// resolver now calls a host, which is a process gone before its exit was
    /// read, keeps the container it had.
    pub async fn refresh_containers(&self) -> usize {
        if self.containers.is_none() {
            return 0;
        }
        let entries = self.list();
        let mut changed = 0;
        for entry in entries {
            let Some(previous) = entry.container.as_ref() else {
                continue;
            };
            let Some(current) = self.resolve_container(entry.pid, entry.cgroup_id).await else {
                continue;
            };
            if &current == previous {
                continue;
            }
            let updated = {
                let mut table = self
                    .table
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let Some(held) = table.get_mut(entry.pid) else {
                    continue;
                };
                held.container = Some(current);
                held.clone()
            };
            if let Some(workload) = &self.workload {
                workload.record_exec(&updated);
            }
            if let Some(scope) = &self.dlp_scope {
                scope.record_exec(&updated);
            }
            if let Some(scope) = &self.ids_scope {
                scope.record_exec(&updated);
            }
            if let Some(shaping) = &self.shaping {
                shaping.record_exec(&updated);
            }
            changed += 1;
        }
        changed
    }

    /// Whether argv is being captured.
    #[must_use]
    pub fn captures_command_line(&self) -> bool {
        self.capture_command_line
    }

    /// Apply one kernel notification.
    pub async fn apply(&self, event: ProcessLifecycleEvent) {
        match event.kind {
            ProcessEventKind::Exec => self.record_exec(event).await,
            ProcessEventKind::Fork => self.record_fork(event).await,
            ProcessEventKind::Exit => self.record_exit(&event),
        }
    }

    async fn record_exec(&self, event: ProcessLifecycleEvent) {
        let pid = event.tgid;
        let mut entry = ProcessEntry::new(pid, event.comm, event.at_ns);
        entry.uid = event.uid;
        entry.gid = event.gid;
        entry.cgroup_id = event.cgroup_id;
        entry.start_ns = event.start_ns;
        entry.parent_pid = event.parent_pid;
        entry.parent_start_ns = event.parent_start_ns;

        if let Some(reader) = &self.executables
            && let Some(executable) = reader.read_executable(pid)
        {
            if let Some(digester) = &self.digester {
                entry.exe_hash = digester.digest(pid, executable.dev, executable.inode);
            }
            entry.identity = ProcessIdentity::Path {
                path: executable.path,
                dev: executable.dev,
                inode: executable.inode,
            };
        }

        if let Some(reader) = &self.details
            && let Some(details) = reader.read_details(pid)
        {
            // The kernel's parent wins: it was read before the parent had a
            // chance to exit and hand the child to a reaper.
            if entry.parent_pid.is_none() {
                entry.parent_pid = details.parent_pid;
            }
            // Redacted here, at the one place argv enters the table, so a
            // secret matched by the closed list never reaches the table, an
            // alert, a freeze or a screen.
            if self.capture_command_line {
                entry.command_line = details
                    .command_line
                    .map(|line| domain::process::redact::redact_command_line(&line));
            }
        }

        entry.container = self.resolve_container(pid, event.cgroup_id).await;

        self.notify_exec(&entry);

        let rules = self
            .host_rules
            .as_ref()
            .filter(|r| r.wants(domain::hostrule::Intent::ProcessStarts))
            .map(|r| (Arc::clone(r), entry.clone()));
        let ransom = self
            .ransom
            .as_ref()
            .filter(|_| entry.command_line.is_some())
            .map(|r| (Arc::clone(r), entry.clone()));
        let replaced = self
            .table
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .record(entry);
        debug!(
            pid,
            replaced = replaced.is_some(),
            "process table recorded an exec"
        );
        if rules.is_some() || ransom.is_some() {
            let lineage = self.lineage(pid);
            if let Some((rules, entry)) = rules {
                rules.record_exec(&entry, &lineage, event.at_ns);
            }
            if let Some((ransom, entry)) = ransom {
                ransom.record_exec(&entry, &lineage, event.at_ns);
            }
        }
    }

    /// A new process running its parent's image. The entry is the parent's,
    /// renamed: same executable, same command line, same container, since
    /// nothing has replaced any of them yet, and the exec that usually
    /// follows rewrites it. A parent the table does not hold leaves a
    /// minimal entry, still worth keeping for the lineage it names.
    async fn record_fork(&self, event: ProcessLifecycleEvent) {
        let pid = event.tgid;
        let inherited = event.parent_pid.and_then(|parent| {
            let table = self
                .table
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            table
                .find(domain::process::entity::ProcessKey {
                    pid: parent,
                    start_ns: event.parent_start_ns.unwrap_or(0),
                })
                .filter(|held| held.exited_at_ns.is_none())
                .cloned()
        });
        let mut entry = ProcessEntry::new(pid, event.comm, event.at_ns);
        let mut container = None;
        if let Some(parent) = inherited {
            entry.identity = parent.identity;
            entry.command_line = parent.command_line;
            // The container belongs to the cgroup, not to the image: a child
            // cloned straight into another cgroup, the way a runtime starts
            // the first task of an exec into a container, is in the
            // container its cgroup says and not in the host its parent ran
            // on. Inheriting there names the container's cgroup as a host
            // one, and the workload policy clears the container's rules.
            if parent.cgroup_id == event.cgroup_id {
                container = Some(parent.container);
            }
        }
        entry.container = match container {
            Some(inherited) => inherited,
            None => self.resolve_container(pid, event.cgroup_id).await,
        };
        entry.uid = event.uid;
        entry.gid = event.gid;
        entry.cgroup_id = event.cgroup_id;
        entry.start_ns = event.start_ns;
        entry.parent_pid = event.parent_pid;
        entry.parent_start_ns = event.parent_start_ns;

        // The child runs the parent's binary, so the policies that name the
        // binary apply to it now and not at an exec that may never come.
        self.notify_exec(&entry);

        self.table
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .record_fork(entry);
        debug!(pid, "process table recorded a fork");
    }

    /// Tell every service keyed on the task about an entry it should now
    /// hold. Before the table write rather than after: the entry moves into
    /// the table, and the sooner the task's bit is set the shorter the window
    /// in which it connects unresolved.
    fn notify_exec(&self, entry: &ProcessEntry) {
        if let Some(workload) = &self.workload {
            workload.record_exec(entry);
        }
        if let Some(scope) = &self.dlp_scope {
            scope.record_exec(entry);
        }
        if let Some(scope) = &self.ids_scope {
            scope.record_exec(entry);
        }
        if let Some(shaping) = &self.shaping {
            shaping.record_exec(entry);
        }
    }

    fn record_exit(&self, event: &ProcessLifecycleEvent) {
        let pid = event.tgid;
        // Read before the purge: the entry is what the rule is about, and
        // its ancestry is walked from the live pid.
        let ending = self
            .host_rules
            .as_ref()
            .filter(|r| r.wants(domain::hostrule::Intent::ProcessEnds))
            .and_then(|r| {
                let table = self
                    .table
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let entry = table.get(pid)?.clone();
                Some((Arc::clone(r), entry, table.lineage(pid)))
            });
        let outcome = self
            .table
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .purge(pid, event.start_ns, event.at_ns);
        match outcome {
            PurgeOutcome::Purged => {}
            PurgeOutcome::Missing => {
                debug!(pid, "process table saw an exit for a pid it never held");
            }
            // The pid already belongs to a later process, whose selectors
            // must survive the late news of its predecessor.
            PurgeOutcome::Stale => {
                debug!(pid, "process table saw a late exit for a reused pid");
                return;
            }
        }
        if let Some(workload) = &self.workload {
            workload.record_exit(pid);
        }
        if let Some(scope) = &self.dlp_scope {
            scope.record_exit(pid);
        }
        if let Some(scope) = &self.ids_scope {
            scope.record_exit(pid);
        }
        if let Some(shaping) = &self.shaping {
            shaping.record_exit(pid);
        }
        if let Some((rules, entry, lineage)) = ending {
            rules.record_exit(&entry, &lineage, event.at_ns);
        }
    }

    /// The container an exec happened in, with runtime metadata where an
    /// enricher could add some. A host process resolves to nothing rather
    /// than to a `ContainerContext` saying "host", because the field is what
    /// a reader checks to know whether there is a container at all.
    async fn resolve_container(&self, pid: u32, cgroup_id: u64) -> Option<ContainerContext> {
        let resolver = self.containers.as_ref()?;
        let (info, _outcome) = resolver.resolve(pid, cgroup_id);
        if info.is_host() {
            return None;
        }
        for enricher in &self.metadata_enrichers {
            match enricher.enrich(&info).await {
                Ok(Some(metadata)) => {
                    return Some(ContainerContext::with_metadata(info, metadata));
                }
                Ok(None) => {}
                Err(err) => {
                    warn!(
                        enricher = enricher.name(),
                        error = %err,
                        "container metadata enrichment failed for a process"
                    );
                }
            }
        }
        Some(ContainerContext::new(info))
    }

    /// Every live process, newest exec first.
    #[must_use]
    pub fn list(&self) -> Vec<ProcessEntry> {
        self.table
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .list()
    }

    /// One process by pid.
    #[must_use]
    pub fn get(&self, pid: u32) -> Option<ProcessEntry> {
        self.table
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(pid)
            .cloned()
    }

    /// The ancestors of the live process `pid`, parent first, live or kept
    /// after their exit, and how the walk ended.
    #[must_use]
    pub fn lineage(&self, pid: u32) -> Lineage {
        self.table
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .lineage(pid)
    }

    /// The table's counters.
    #[must_use]
    pub fn stats(&self) -> ProcessTableStats {
        self.table
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .stats()
    }

    /// Drain `rx` into the table until the channel closes or `cancel` fires.
    pub async fn run(
        self: Arc<Self>,
        mut rx: mpsc::Receiver<ProcessLifecycleEvent>,
        cancel: CancellationToken,
    ) {
        info!("process table writer started");
        // The refresh runs on this task rather than beside it, so it is never
        // interleaved with an exec or an exit of the entry it is rewriting.
        let mut changes = self.metadata_changes.clone();
        let mut settle: Option<Instant> = None;
        loop {
            tokio::select! {
                () = cancel.cancelled() => break,
                event = rx.recv() => match event {
                    Some(event) => self.apply(event).await,
                    None => break,
                },
                open = next_change(changes.as_mut()) => {
                    if open {
                        settle.get_or_insert_with(|| Instant::now() + REFRESH_SETTLE);
                    } else {
                        changes = None;
                    }
                }
                () = settled(settle) => {
                    settle = None;
                    let changed = self.refresh_containers().await;
                    debug!(changed, "process table resolved the running containers again");
                }
            }
        }
        info!(
            entries = self.stats().entries,
            "process table writer stopped"
        );
    }
}

/// The next move of `changes`: `true` when it moved, `false` once its sender
/// is gone, and never without one.
async fn next_change(changes: Option<&mut watch::Receiver<u64>>) -> bool {
    match changes {
        Some(changes) => changes.changed().await.is_ok(),
        None => std::future::pending().await,
    }
}

/// The instant a pending refresh is due, and never without one.
async fn settled(settle: Option<Instant>) {
    match settle {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::container::entity::{ContainerInfo, ContainerMetadata, DockerMetadata};
    use domain::dlp::entity::{DlpExecutable, DlpIdentitySource};
    use domain::process::entity::ProcessDetails;

    struct FixedExecutable;
    impl ProcessExecutableReader for FixedExecutable {
        fn read_executable(&self, _pid: u32) -> Option<DlpExecutable> {
            Some(DlpExecutable {
                path: "/usr/bin/curl".to_string(),
                dev: 64,
                inode: 4242,
                source: DlpIdentitySource::ProcessAtAlertTime,
            })
        }
    }

    /// Answers a digest only for the file the table read, so a test can
    /// tell whether the identity it was handed was the one it checked.
    struct FixedDigest;
    impl ExecutableDigester for FixedDigest {
        fn digest(
            &self,
            _pid: u32,
            dev: u64,
            inode: u64,
        ) -> Option<domain::process::digest::ExeHash> {
            ((dev, inode) == (64, 4242)).then(|| {
                domain::process::digest::ExeHash::new(
                    domain::process::digest::DigestSource::Content,
                    [7; 32],
                )
            })
        }
    }

    struct NoExecutable;
    impl ProcessExecutableReader for NoExecutable {
        fn read_executable(&self, _pid: u32) -> Option<DlpExecutable> {
            None
        }
    }

    struct FixedDetails;
    impl ProcessDetailsReader for FixedDetails {
        fn read_details(&self, _pid: u32) -> Option<ProcessDetails> {
            Some(ProcessDetails {
                parent_pid: Some(1),
                command_line: Some("curl -u user:secret https://example.test".to_string()),
            })
        }
    }

    struct ContainerCgroups;
    impl domain::container::engine::CgroupReader for ContainerCgroups {
        fn read_cgroup(&self, _pid: u32) -> std::io::Result<String> {
            Ok(
                "0::/docker/3f2a1b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708\n"
                    .to_string(),
            )
        }
    }

    struct HostCgroups;
    impl domain::container::engine::CgroupReader for HostCgroups {
        fn read_cgroup(&self, _pid: u32) -> std::io::Result<String> {
            Ok("0::/user.slice/user-1000.slice\n".to_string())
        }
    }

    struct FixedEnricher;
    #[async_trait::async_trait]
    impl MetadataEnricher for FixedEnricher {
        async fn enrich(
            &self,
            _info: &ContainerInfo,
        ) -> Result<Option<ContainerMetadata>, domain::container::error::ContainerError> {
            Ok(Some(ContainerMetadata::Docker(DockerMetadata {
                name: "web".to_string(),
                image: "nginx:1.29".to_string(),
                labels: Vec::new(),
                created_at: String::new(),
                status: "running".to_string(),
            })))
        }
        fn name(&self) -> &'static str {
            "fixed"
        }
    }

    /// An enricher whose answer the test changes, the way a pod watcher's
    /// does when a pod is relabelled.
    #[derive(Clone, Default)]
    struct PodEnricher(Arc<std::sync::Mutex<Vec<(String, String)>>>);
    #[async_trait::async_trait]
    impl MetadataEnricher for PodEnricher {
        async fn enrich(
            &self,
            _info: &ContainerInfo,
        ) -> Result<Option<ContainerMetadata>, domain::container::error::ContainerError> {
            Ok(Some(ContainerMetadata::Kubernetes(
                domain::container::entity::KubernetesMetadata {
                    pod_name: "api-7f9".to_string(),
                    namespace: "payments".to_string(),
                    container_name: "api".to_string(),
                    labels: self.0.lock().unwrap().clone(),
                    annotations: Vec::new(),
                    service_account: "api".to_string(),
                    owner_kind: None,
                    owner_name: None,
                    node_name: "node-1".to_string(),
                    namespace_labels: Vec::new(),
                },
            )))
        }
        fn name(&self) -> &'static str {
            "pod"
        }
    }

    fn labelled_pod_policy() -> WorkloadPolicyService {
        use domain::common::entity::{Protocol, RuleId};
        use domain::firewall::entity::FirewallAction;
        use domain::firewall::workload::{
            KubernetesMatchers, WorkloadMode, WorkloadPolicy, WorkloadRule, WorkloadSelector,
        };
        let pods: domain::netpol::LabelSelector =
            serde_json::from_str(r#"{"match_labels":{"app":"api"}}"#).unwrap();
        let selector = WorkloadSelector::with_kubernetes(
            None,
            None,
            None,
            None,
            KubernetesMatchers {
                pods: Some(pods),
                ..KubernetesMatchers::default()
            },
        )
        .unwrap();
        WorkloadPolicyService::new(
            WorkloadPolicy::new(vec![WorkloadRule {
                dst_peer: None,
                id: RuleId("api".to_string()),
                priority: 10,
                action: FirewallAction::Deny,
                mode: WorkloadMode::Observe,
                selector,
                protocol: Protocol::Any,
                dst_ip: None,
                dst_port: None,
                dst_fqdn: Vec::new(),
                enabled: true,
            }])
            .unwrap(),
        )
    }

    #[tokio::test]
    async fn a_pod_relabelled_after_its_process_started_is_named_by_the_refresh() {
        let masks = TaskMasks::default();
        let workload = Arc::new(labelled_pod_policy().with_maps(Box::new(masks.clone())));
        let enricher = PodEnricher::default();
        let resolver = Arc::new(ContainerResolverEngine::new(Arc::new(ContainerCgroups), 16));
        let service = ProcessTableService::new(16, false)
            .with_containers(resolver)
            .with_metadata_enricher(Arc::new(enricher.clone()))
            .with_workload_policy(workload);

        service.apply(exec(42, 1)).await;
        assert_eq!(masks.1.lock().unwrap().get(&777), Some(&0));
        assert_eq!(service.refresh_containers().await, 0, "nothing moved");

        enricher
            .0
            .lock()
            .unwrap()
            .push(("app".to_string(), "api".to_string()));
        assert_eq!(service.refresh_containers().await, 1);
        assert_eq!(masks.1.lock().unwrap().get(&777), Some(&1));
        let Some(ContainerMetadata::Kubernetes(pod)) =
            service.get(42).unwrap().container.unwrap().metadata
        else {
            panic!("the entry lost its pod");
        };
        assert_eq!(pod.labels, vec![("app".to_string(), "api".to_string())]);

        enricher.0.lock().unwrap().clear();
        assert_eq!(service.refresh_containers().await, 1);
        assert_eq!(masks.1.lock().unwrap().get(&777), Some(&0));
    }

    #[tokio::test]
    async fn a_host_process_is_never_resolved_again() {
        let resolver = Arc::new(ContainerResolverEngine::new(Arc::new(HostCgroups), 16));
        let service = ProcessTableService::new(16, false)
            .with_containers(resolver)
            .with_metadata_enricher(Arc::new(PodEnricher::default()));
        service.apply(exec(42, 1)).await;
        assert_eq!(service.refresh_containers().await, 0);
        assert!(service.get(42).unwrap().container.is_none());
    }

    #[tokio::test]
    async fn the_writer_resolves_again_once_the_metadata_settles() {
        let enricher = PodEnricher::default();
        let resolver = Arc::new(ContainerResolverEngine::new(Arc::new(ContainerCgroups), 16));
        let (changes_tx, changes_rx) = watch::channel(0u64);
        let service = Arc::new(
            ProcessTableService::new(16, false)
                .with_containers(resolver)
                .with_metadata_enricher(Arc::new(enricher.clone()))
                .with_metadata_changes(changes_rx),
        );
        let (tx, rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let writer = tokio::spawn(Arc::clone(&service).run(rx, cancel.clone()));
        tx.send(exec(42, 1)).await.unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while service.get(42).is_none() {
            assert!(Instant::now() < deadline, "the exec never landed");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        enricher
            .0
            .lock()
            .unwrap()
            .push(("app".to_string(), "api".to_string()));
        changes_tx.send_modify(|generation| *generation += 1);

        let labelled = || {
            matches!(
                service.get(42).and_then(|entry| entry.container).and_then(|c| c.metadata),
                Some(ContainerMetadata::Kubernetes(pod)) if !pod.labels.is_empty()
            )
        };
        assert!(!labelled(), "the exec was resolved before the relabel");
        let deadline = Instant::now() + Duration::from_secs(10);
        while !labelled() {
            assert!(Instant::now() < deadline, "the writer never resolved again");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        cancel.cancel();
        writer.await.unwrap();
    }

    fn exec(pid: u32, at: u64) -> ProcessLifecycleEvent {
        ProcessLifecycleEvent {
            kind: ProcessEventKind::Exec,
            pid,
            tgid: pid,
            uid: 1000,
            gid: 1000,
            cgroup_id: 777,
            comm: "curl".to_string(),
            at_ns: at,
            start_ns: None,
            parent_pid: None,
            parent_start_ns: None,
        }
    }

    /// A workload map port that only remembers which tasks were written.
    #[derive(Clone, Default)]
    struct TaskMasks(
        Arc<std::sync::Mutex<Vec<(u32, u64)>>>,
        Arc<std::sync::Mutex<std::collections::HashMap<u64, u64>>>,
    );

    impl ports::secondary::workload_policy_map_port::WorkloadPolicyMapPort for TaskMasks {
        fn rule_denials(&self) -> Result<Vec<u64>, domain::common::error::DomainError> {
            Ok(Vec::new())
        }

        fn publish_policy(
            &mut self,
            _policy: &domain::firewall::workload::WorkloadPolicy,
        ) -> Result<(), domain::common::error::DomainError> {
            // A published policy renumbers the bits, so the real port drops
            // every mask recorded under the last one.
            self.0.lock().unwrap().clear();
            Ok(())
        }

        fn set_cgroup_selectors(
            &mut self,
            cgroup_id: u64,
            mask: u64,
        ) -> Result<(), domain::common::error::DomainError> {
            self.1.lock().unwrap().insert(cgroup_id, mask);
            Ok(())
        }

        fn set_task_selectors(
            &mut self,
            tgid: u32,
            mask: u64,
        ) -> Result<(), domain::common::error::DomainError> {
            self.0.lock().unwrap().push((tgid, mask));
            Ok(())
        }

        fn grant_fqdn(
            &mut self,
            _key: &domain::firewall::fqdn::FqdnGrantKey,
            _expires_ns: u64,
        ) -> Result<(), domain::common::error::DomainError> {
            Ok(())
        }

        fn revoke_fqdn(
            &mut self,
            _key: &domain::firewall::fqdn::FqdnGrantKey,
        ) -> Result<(), domain::common::error::DomainError> {
            Ok(())
        }

        fn note_lineage_executable(
            &mut self,
            _path: &str,
            _dev: u64,
            _inode: u64,
        ) -> Result<(), domain::common::error::DomainError> {
            Ok(())
        }

        fn replace_peer_addresses(
            &mut self,
            _destinations: &[(std::net::IpAddr, u64)],
            _sources: &[(std::net::IpAddr, u64)],
        ) -> Result<usize, domain::common::error::DomainError> {
            Ok(0)
        }

        fn set_peer_targets(
            &mut self,
            _cgroup_id: u64,
            _mask: u64,
        ) -> Result<(), domain::common::error::DomainError> {
            Ok(())
        }

        fn forget_task(&mut self, tgid: u32) -> Result<(), domain::common::error::DomainError> {
            self.0.lock().unwrap().retain(|(held, _)| *held != tgid);
            Ok(())
        }

        fn clear_selectors(&mut self) -> Result<(), domain::common::error::DomainError> {
            self.0.lock().unwrap().clear();
            Ok(())
        }
    }

    fn exit(pid: u32) -> ProcessLifecycleEvent {
        ProcessLifecycleEvent {
            kind: ProcessEventKind::Exit,
            pid,
            tgid: pid,
            uid: 1000,
            gid: 1000,
            cgroup_id: 777,
            comm: "curl".to_string(),
            at_ns: 10,
            start_ns: None,
            parent_pid: None,
            parent_start_ns: None,
        }
    }

    struct DiscardedScope;
    impl ports::secondary::ids_workload_scope_port::IdsWorkloadScopeMapPort for DiscardedScope {
        fn publish_links(
            &mut self,
            _links: &[(u32, u64)],
        ) -> Result<(), domain::common::error::DomainError> {
            Ok(())
        }
        fn publish_scope(
            &mut self,
            _entries: &[(u64, u32)],
        ) -> Result<(), domain::common::error::DomainError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn a_container_task_scopes_an_ids_rule_until_it_exits() {
        let scope = Arc::new(IdsWorkloadScopeService::new());
        scope.set_maps(Box::new(DiscardedScope));
        scope.set_rules(vec![(
            0,
            domain::firewall::workload::WorkloadSelector::new(
                None,
                None,
                None,
                Some("3f2a1b4c5d6e".to_string()),
            )
            .unwrap(),
        )]);
        let resolver = Arc::new(ContainerResolverEngine::new(Arc::new(ContainerCgroups), 16));
        let service = ProcessTableService::new(16, false)
            .with_containers(resolver)
            .with_ids_workload_scope(Arc::clone(&scope));

        service.apply(exec(42, 1)).await;
        assert_eq!(scope.published_scope(), vec![(777, 0)]);
        service.apply(exit(42)).await;
        assert!(scope.published_scope().is_empty());
    }

    #[tokio::test]
    async fn a_container_task_holds_a_rate_until_it_exits() {
        let shaping = Arc::new(QosCgroupShapingService::new());
        shaping.set_rules(vec![domain::qos::cgroup_shaping::CgroupShapingRule {
            id: "web".to_string(),
            selector: domain::firewall::workload::WorkloadSelector::new(
                None,
                None,
                None,
                Some("3f2a1b4c5d6e".to_string()),
            )
            .unwrap(),
            rate_bps: 8_000_000,
            horizon_ms: 2_000,
        }]);
        let resolver = Arc::new(ContainerResolverEngine::new(Arc::new(ContainerCgroups), 16));
        let service = ProcessTableService::new(16, false)
            .with_containers(resolver)
            .with_cgroup_shaping(Arc::clone(&shaping));

        service.apply(exec(42, 1)).await;
        let shaped: Vec<u64> = shaping
            .report()
            .cgroups
            .iter()
            .map(|c| c.cgroup_id)
            .collect();
        assert_eq!(shaped, vec![777]);
        service.apply(exit(42)).await;
        assert!(shaping.report().cgroups.is_empty());
    }

    #[tokio::test]
    async fn an_exec_becomes_a_named_entry() {
        let service = ProcessTableService::new(16, false)
            .with_executables(Arc::new(FixedExecutable))
            .with_details(Arc::new(FixedDetails));
        service.apply(exec(42, 1)).await;
        let entry = service.get(42).unwrap();
        assert_eq!(entry.identity.path(), Some("/usr/bin/curl"));
        assert_eq!(entry.parent_pid, Some(1));
        assert_eq!(entry.uid, 1000);
        assert_eq!(entry.cgroup_id, 777);
    }

    #[tokio::test]
    async fn an_exec_carries_the_digest_of_the_file_it_was_named_by() {
        let service = ProcessTableService::new(16, false)
            .with_executables(Arc::new(FixedExecutable))
            .with_digester(Arc::new(FixedDigest));
        service.apply(exec(42, 1)).await;
        let hash = service.get(42).unwrap().exe_hash.expect("a digest");
        assert_eq!(hash.digest(), &[7; 32]);

        // No path, no file to hash: the digest never stands alone.
        let unnamed = ProcessTableService::new(16, false)
            .with_executables(Arc::new(NoExecutable))
            .with_digester(Arc::new(FixedDigest));
        unnamed.apply(exec(43, 1)).await;
        assert!(unnamed.get(43).unwrap().exe_hash.is_none());
    }

    #[tokio::test]
    async fn the_command_line_is_stored_with_its_secrets_already_removed() {
        let on = ProcessTableService::new(16, true).with_details(Arc::new(FixedDetails));
        on.apply(exec(42, 1)).await;
        let line = on.get(42).unwrap().command_line.unwrap();
        assert!(!line.contains("secret"));
        assert!(line.contains("user:[redacted]"));
    }

    #[tokio::test]
    async fn the_command_line_is_absent_until_it_is_turned_on() {
        let off = ProcessTableService::new(16, false).with_details(Arc::new(FixedDetails));
        off.apply(exec(42, 1)).await;
        assert!(off.get(42).unwrap().command_line.is_none());

        let on = ProcessTableService::new(16, true).with_details(Arc::new(FixedDetails));
        on.apply(exec(42, 1)).await;
        assert_eq!(
            on.get(42).unwrap().command_line.as_deref(),
            Some("curl -u user:[redacted] https://example.test")
        );
    }

    #[tokio::test]
    async fn an_unreadable_binary_leaves_the_identity_unknown() {
        let service = ProcessTableService::new(16, false).with_executables(Arc::new(NoExecutable));
        service.apply(exec(42, 1)).await;
        assert_eq!(service.get(42).unwrap().identity, ProcessIdentity::Unknown);
    }

    #[tokio::test]
    async fn an_exit_takes_the_pid_out_at_once() {
        let service = ProcessTableService::new(16, false);
        service.apply(exec(42, 1)).await;
        service.apply(exit(42)).await;
        assert!(service.get(42).is_none());
        assert_eq!(service.stats().purged, 1);
    }

    fn lineage(
        mut event: ProcessLifecycleEvent,
        start: u64,
        parent: (u32, u64),
    ) -> ProcessLifecycleEvent {
        event.start_ns = Some(start);
        event.parent_pid = Some(parent.0);
        event.parent_start_ns = Some(parent.1);
        event
    }

    #[tokio::test]
    async fn the_kernel_parent_wins_over_the_one_read_from_proc() {
        let service = ProcessTableService::new(16, false).with_details(Arc::new(FixedDetails));
        service.apply(lineage(exec(42, 1), 5, (7, 3))).await;
        let entry = service.get(42).unwrap();
        assert_eq!(entry.parent_pid, Some(7));
        assert_eq!(entry.parent_start_ns, Some(3));
        assert_eq!(entry.start_ns, Some(5));
    }

    #[tokio::test]
    async fn a_fork_inherits_its_parent_without_reading_proc() {
        let service = ProcessTableService::new(16, true)
            .with_executables(Arc::new(FixedExecutable))
            .with_details(Arc::new(FixedDetails));
        service.apply(lineage(exec(10, 1), 1, (1, 0))).await;
        let mut fork = lineage(exec(11, 2), 2, (10, 1));
        fork.kind = ProcessEventKind::Fork;
        service.apply(fork).await;
        let child = service.get(11).unwrap();
        assert_eq!(child.identity.path(), Some("/usr/bin/curl"));
        assert_eq!(
            child.command_line.as_deref(),
            Some("curl -u user:[redacted] https://example.test")
        );
        assert_eq!(child.parent_pid, Some(10));
        assert_eq!(service.stats().forks, 1);
        assert_eq!(service.stats().recorded, 1);
    }

    /// The host until the pid is 11, the container from there on: a
    /// runtime's child cloned straight into the container's cgroup.
    struct ClonedIntoContainer;
    impl domain::container::engine::CgroupReader for ClonedIntoContainer {
        fn read_cgroup(&self, pid: u32) -> std::io::Result<String> {
            if pid < 11 {
                HostCgroups.read_cgroup(pid)
            } else {
                ContainerCgroups.read_cgroup(pid)
            }
        }
    }

    #[tokio::test]
    async fn a_child_cloned_into_another_cgroup_is_in_that_cgroup_s_container() {
        let resolver = Arc::new(ContainerResolverEngine::new(
            Arc::new(ClonedIntoContainer),
            16,
        ));
        let service = ProcessTableService::new(16, false).with_containers(resolver);
        let mut runtime = lineage(exec(10, 1), 1, (1, 0));
        runtime.cgroup_id = 500;
        service.apply(runtime).await;
        assert!(service.get(10).unwrap().container.is_none());

        let mut fork = lineage(exec(11, 2), 2, (10, 1));
        fork.kind = ProcessEventKind::Fork;
        service.apply(fork).await;
        let child = service.get(11).unwrap();
        assert!(child.container.is_some_and(|c| !c.info.is_host()));
        assert_eq!(child.identity, service.get(10).unwrap().identity);

        // A child left in its parent's cgroup still inherits, host included.
        let mut sibling = lineage(exec(12, 3), 3, (10, 1));
        sibling.kind = ProcessEventKind::Fork;
        sibling.cgroup_id = 500;
        service.apply(sibling).await;
        assert!(service.get(12).unwrap().container.is_none());
    }

    #[tokio::test]
    async fn an_exited_parent_stays_readable_as_the_ancestor_of_its_child() {
        let service = ProcessTableService::new(16, false);
        service.apply(lineage(exec(10, 1), 1, (0, 0))).await;
        let mut fork = lineage(exec(11, 2), 2, (10, 1));
        fork.kind = ProcessEventKind::Fork;
        service.apply(fork).await;
        let mut gone = exit(10);
        gone.start_ns = Some(1);
        service.apply(gone).await;
        assert!(service.get(10).is_none());
        let lineage = service.lineage(11);
        assert_eq!(lineage.ancestors[0].pid, 10);
        assert!(lineage.ancestors[0].exited_at_ns.is_some());
        assert!(!lineage.incomplete);
    }

    fn host_rules(
        json: &str,
    ) -> (
        Arc<HostRuleService>,
        mpsc::Receiver<crate::alert_event::AlertEvent>,
    ) {
        let mut specs: Vec<domain::hostrule::HostRuleSpec> = serde_json::from_str(json).unwrap();
        for spec in &mut specs {
            spec.mode = domain::firewall::entity::RuleMode::Enforce;
        }
        let (tx, rx) = mpsc::channel(8);
        let rules = domain::hostrule::HostRuleSet::compile(specs).unwrap();
        (Arc::new(HostRuleService::new(rules, tx)), rx)
    }

    fn rule_ids(rx: &mut mpsc::Receiver<crate::alert_event::AlertEvent>) -> Vec<String> {
        let mut ids = Vec::new();
        while let Ok(crate::alert_event::AlertEvent::ProcessDetection { alert, .. }) = rx.try_recv()
        {
            ids.push(alert.rule_id.0);
        }
        ids
    }

    #[tokio::test]
    async fn an_exec_and_an_exit_reach_the_host_rules_with_the_parent_and_the_entry() {
        let (rules, mut rx) = host_rules(
            r#"[{"id":"curl-under-1","when":{"process.starts":{"exe":"/usr/bin/curl","parent_uid":1000}}},
                {"id":"curl-ended","when":{"process.ends":{"exe":"/usr/bin/curl"}}}]"#,
        );
        let service = ProcessTableService::new(16, false)
            .with_executables(Arc::new(FixedExecutable))
            .with_host_rules(rules);
        service.apply(lineage(exec(10, 1), 1, (0, 0))).await;
        // The first exec has no parent in the table, so no parent_uid.
        assert!(rule_ids(&mut rx).is_empty());
        service.apply(lineage(exec(11, 2), 2, (10, 1))).await;
        assert_eq!(rule_ids(&mut rx), vec!["curl-under-1"]);
        let mut gone = exit(11);
        gone.start_ns = Some(2);
        service.apply(gone).await;
        assert_eq!(rule_ids(&mut rx), vec!["curl-ended"]);
        // A late exit for a pid the table no longer holds reaches no rule.
        service.apply(exit(11)).await;
        assert!(rule_ids(&mut rx).is_empty());
    }

    #[tokio::test]
    async fn a_late_exit_for_a_reused_pid_reaches_no_host_rule() {
        let (rules, mut rx) = host_rules(r#"[{"id":"any-end","when":{"process.ends":{}}}]"#);
        let service = ProcessTableService::new(16, false).with_host_rules(rules);
        service.apply(lineage(exec(42, 1), 50, (1, 0))).await;
        let mut late = exit(42);
        late.start_ns = Some(20);
        service.apply(late).await;
        assert!(rule_ids(&mut rx).is_empty());
    }

    #[tokio::test]
    async fn a_late_exit_for_a_reused_pid_leaves_the_new_process() {
        let service = ProcessTableService::new(16, false);
        service.apply(lineage(exec(42, 1), 50, (1, 0))).await;
        let mut late = exit(42);
        late.start_ns = Some(20);
        service.apply(late).await;
        assert!(service.get(42).is_some());
        assert_eq!(service.stats().missing_exit, 1);
    }

    #[tokio::test]
    async fn a_container_process_carries_its_container_and_its_image() {
        let resolver = Arc::new(ContainerResolverEngine::new(Arc::new(ContainerCgroups), 16));
        let service = ProcessTableService::new(16, false)
            .with_containers(resolver)
            .with_metadata_enricher(Arc::new(FixedEnricher));
        service.apply(exec(42, 1)).await;
        let container = service.get(42).unwrap().container.unwrap();
        assert!(!container.info.is_host());
        assert!(matches!(
            container.metadata,
            Some(ContainerMetadata::Docker(_))
        ));
    }

    #[tokio::test]
    async fn a_host_process_carries_no_container_block() {
        let resolver = Arc::new(ContainerResolverEngine::new(Arc::new(HostCgroups), 16));
        let service = ProcessTableService::new(16, false).with_containers(resolver);
        service.apply(exec(42, 1)).await;
        assert!(service.get(42).unwrap().container.is_none());
    }

    #[tokio::test]
    async fn the_writer_drains_the_channel_and_stops_on_cancel() {
        let service = Arc::new(ProcessTableService::new(16, false));
        let (tx, rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let writer = tokio::spawn(Arc::clone(&service).run(rx, cancel.clone()));
        tx.send(exec(42, 1)).await.unwrap();
        tx.send(exec(43, 2)).await.unwrap();
        drop(tx);
        writer.await.unwrap();
        assert_eq!(service.stats().entries, 2);
        cancel.cancel();
    }

    #[tokio::test]
    async fn the_listing_is_newest_first_and_the_bound_holds() {
        let service = ProcessTableService::new(2, false);
        for pid in 1..=3u32 {
            service.apply(exec(pid, u64::from(pid))).await;
        }
        let pids: Vec<u32> = service.list().iter().map(|e| e.pid).collect();
        assert_eq!(pids, vec![3, 2]);
        assert_eq!(service.stats().evicted, 1);
    }
    #[tokio::test]
    async fn an_exec_names_the_task_to_the_workload_policy_and_an_exit_takes_it_back() {
        use domain::common::entity::{Protocol, RuleId};
        use domain::firewall::entity::FirewallAction;
        use domain::firewall::workload::{
            WorkloadMode, WorkloadPolicy, WorkloadRule, WorkloadSelector,
        };

        let masks = TaskMasks::default();
        let policy = WorkloadPolicy::new(vec![WorkloadRule {
            dst_peer: None,
            id: RuleId("one".to_string()),
            priority: 10,
            action: FirewallAction::Deny,
            mode: WorkloadMode::Observe,
            selector: WorkloadSelector::new(Some("/usr/bin/curl".to_string()), None, None, None)
                .expect("a valid selector"),
            protocol: Protocol::Any,
            dst_ip: None,
            dst_port: None,
            dst_fqdn: Vec::new(),
            enabled: true,
        }])
        .expect("inside the ceiling");
        let workload =
            Arc::new(WorkloadPolicyService::new(policy).with_maps(Box::new(masks.clone())));
        let service = ProcessTableService::new(16, false)
            .with_executables(Arc::new(FixedExecutable))
            .with_workload_policy(Arc::clone(&workload));

        service.apply(exec(4242, 1)).await;
        assert_eq!(masks.0.lock().unwrap().as_slice(), [(4242, 1)]);

        service.apply(exit(4242)).await;
        assert!(masks.0.lock().unwrap().is_empty());
    }
    #[tokio::test]
    async fn a_new_policy_is_replayed_over_the_tasks_already_running() {
        use domain::common::entity::{Protocol, RuleId};
        use domain::firewall::entity::FirewallAction;
        use domain::firewall::workload::{
            WorkloadMode, WorkloadPolicy, WorkloadRule, WorkloadSelector,
        };

        fn policy(exe: &str) -> WorkloadPolicy {
            WorkloadPolicy::new(vec![WorkloadRule {
                dst_peer: None,
                id: RuleId("one".to_string()),
                priority: 10,
                action: FirewallAction::Deny,
                mode: WorkloadMode::Observe,
                selector: WorkloadSelector::new(Some(exe.to_string()), None, None, None)
                    .expect("a valid selector"),
                protocol: Protocol::Any,
                dst_ip: None,
                dst_port: None,
                dst_fqdn: Vec::new(),
                enabled: true,
            }])
            .expect("inside the ceiling")
        }

        let masks = TaskMasks::default();
        let workload = Arc::new(
            WorkloadPolicyService::new(policy("/usr/bin/wget")).with_maps(Box::new(masks.clone())),
        );
        let service = Arc::new(
            ProcessTableService::new(16, false)
                .with_executables(Arc::new(FixedExecutable))
                .with_workload_policy(Arc::clone(&workload)),
        );
        workload.watch_processes(&service);

        service.apply(exec(77, 1)).await;
        assert_eq!(masks.0.lock().unwrap().as_slice(), [(77, 0)]);

        // The task is running and will not exec again: without the replay it
        // would stay nameless under the policy that now names it.
        workload
            .apply(policy("/usr/bin/curl"))
            .expect("the port accepts it");

        assert_eq!(masks.0.lock().unwrap().as_slice(), [(77, 1)]);
    }
}
