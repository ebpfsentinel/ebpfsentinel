//! Resolving which workload a task is, so the kernel can compare integers.
//!
//! The rule language names an executable, a unit, a cgroup or a container.
//! None of the four is readable from a `connect()` hook: the first is a path
//! in `/proc`, the second is a systemd name, and the last two are strings on
//! a hierarchy. So the matching happens here, once per exec, and what
//! reaches the kernel is a bit per selector in two tables - one keyed on the
//! cgroup, one on the task.
//!
//! Which table a selector lands in is decided by the selector itself. A
//! cgroup, a unit and a container belong to the cgroup, which outlives every
//! process in it, so one write covers every task that will ever run there.
//! An executable belongs to one task, and the only thing that knows it is
//! the process table at `execve`.
//!
//! A bit is set only when the whole selector matched, so an `exe` plus
//! `container` selector is never half-true across the two tables: it is
//! decided here against both facts and written to the task table alone.
//!
//! What this cannot close is stated rather than papered over: a task that
//! execs and connects before this service has written its bit is unresolved,
//! and the kernel counts that rather than guessing. The window is the
//! `/proc` read in the middle, and a policy that refuses by default leaks
//! for exactly as long as it lasts.
//!
//! A rule naming its destination by DNS name is served from here as well.
//! The answers a named workload is given come back from the kernel, are
//! paired with the query that same cgroup sent, and every address they carry
//! is opened for that cgroup under that rule's slot alone. The cgroup's mask
//! is remembered from the exec that wrote it, because an answer arrives with
//! a cgroup id and nothing else.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock, RwLock, Weak};

use domain::common::entity::RuleId;
use domain::common::error::DomainError;
use domain::container::engine::{CgroupReader, CgroupTree, parse_cgroup_v2};
use domain::container::entity::{ContainerInfo, ContainerMetadata};
use domain::firewall::container_labels::{ContainerLabelPolicy, LABEL_PREFIX, ListedContainer};
use domain::firewall::fqdn::{
    DnsCapture, FqdnGrantKey, FqdnLearner, FqdnLedger, FqdnPatternReport,
};
use domain::firewall::workload::{
    WorkloadDenial, WorkloadDenialRecord, WorkloadFacts, WorkloadPolicy, WorkloadReach,
    WorkloadRule, cgroup_path_of, unit_of,
};
use domain::firewall::workload_peer::{PeerEnds, PeerRuleEnds, source_matches_remote};
use domain::identity::remote::RemoteIdentities;
use domain::process::digest::ExeHash;
use domain::process::engine::Lineage;
use domain::process::entity::{ProcessEntry, ProcessIdentity};
use ebpf_common::workload_policy::WORKLOAD_POLICY_MAX_RULES;
use ports::secondary::workload_policy_map_port::WorkloadPolicyMapPort;
use tracing::{debug, info, warn};

/// What one task is, in the words a selector is written in.
///
/// Owned rather than borrowed because it is assembled from three sources -
/// the process table, `/proc` and the container resolver - and no one of
/// them outlives the others.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedWorkload {
    /// Absolute path of the executable.
    pub exe: Option<String>,
    /// Digest of the executable, where the process table holds one.
    pub exe_hash: Option<ExeHash>,
    /// systemd unit, derived from the cgroup path.
    pub unit: Option<String>,
    /// Absolute cgroup v2 path.
    pub cgroup: Option<String>,
    /// Container id in full.
    pub container_id: Option<String>,
    /// Container name, where an enricher read one.
    pub container_name: Option<String>,
    /// Labels of the pod, where the Kubernetes enricher found it.
    pub pod_labels: Option<BTreeMap<String, String>>,
    /// Labels of the pod's namespace, once the namespace watcher saw it.
    pub namespace_labels: Option<BTreeMap<String, String>>,
    /// Service account the pod runs as.
    pub service_account: Option<String>,
    /// Executables of the processes above this one, parent first, where the
    /// process table was asked. The kernel walks the live chain itself at
    /// the call; this is the same chain as the table remembers it, for an
    /// answer about a task rather than for a decision.
    pub ancestry: Option<Vec<String>>,
}

impl ResolvedWorkload {
    /// This workload, with the chain the process table holds above it.
    ///
    /// An ancestor whose executable the table never read is kept as an empty
    /// path rather than dropped, so the parent stays first: an empty path
    /// matches no rule, while dropping it would promote the grandparent.
    #[must_use]
    pub fn with_ancestry(mut self, lineage: &Lineage) -> Self {
        self.ancestry = Some(
            lineage
                .ancestors
                .iter()
                .map(|a| a.identity.path().unwrap_or_default().to_owned())
                .collect(),
        );
        self
    }

    /// The borrowed form a selector is matched against.
    #[must_use]
    pub fn facts(&self) -> WorkloadFacts<'_> {
        WorkloadFacts {
            exe: self.exe.as_deref(),
            exe_hash: self.exe_hash,
            unit: self.unit.as_deref(),
            cgroup: self.cgroup.as_deref(),
            container_id: self.container_id.as_deref(),
            container_name: self.container_name.as_deref(),
            pod_labels: self.pod_labels.as_ref(),
            namespace_labels: self.namespace_labels.as_ref(),
            service_account: self.service_account.as_deref(),
            ancestry: self.ancestry.as_deref(),
        }
    }
}

/// What a cgroup path alone says about the workload it holds: the path, the
/// unit it sits under and the container id it carries, and nothing a runtime
/// would have to be asked for.
#[must_use]
pub fn workload_of_cgroup(path: &str) -> ResolvedWorkload {
    let container_id = match parse_cgroup_v2(&format!("0::{path}"), 0) {
        Some(ContainerInfo::Container { container_id, .. }) => Some(container_id),
        _ => None,
    };
    ResolvedWorkload {
        unit: unit_of(path).map(ToOwned::to_owned),
        cgroup: Some(path.to_owned()),
        container_id,
        ..ResolvedWorkload::default()
    }
}

/// What a process table entry alone says about the workload it belongs to.
///
/// Everything here is already in the entry, so it costs no read: the
/// executable the table recorded at the exec, and, for a container, the
/// cgroup path and the name the runtime enricher could add. A host process
/// whose entry carries no cgroup path comes back without one, and the
/// caller that holds a cgroup reader fills it in; a caller that holds none
/// gets what the table knows rather than nothing.
#[must_use]
pub fn workload_of(entry: &ProcessEntry) -> ResolvedWorkload {
    let mut resolved = ResolvedWorkload {
        exe: entry.identity.path().map(ToOwned::to_owned),
        exe_hash: entry.exe_hash,
        ..ResolvedWorkload::default()
    };
    if let Some(context) = entry.container.as_ref() {
        if let ContainerInfo::Container {
            container_id,
            cgroup_path,
            ..
        } = &context.info
        {
            resolved.container_id = Some(container_id.clone());
            resolved.cgroup = Some(cgroup_path.clone());
        }
        resolved.container_name = context.metadata.as_ref().and_then(|metadata| {
            match metadata {
                ContainerMetadata::Docker(docker) => Some(docker.name.clone()),
                ContainerMetadata::Kubernetes(pod) => Some(pod.container_name.clone()),
                // A runtime this build does not name yet gives no name,
                // and a selector naming one does not match it. Inventing
                // a name here is how a rule starts matching a container
                // nobody meant.
                _ => None,
            }
        });
        if let Some(ContainerMetadata::Kubernetes(pod)) = context.metadata.as_ref() {
            resolved.pod_labels = Some(pod.labels.iter().cloned().collect());
            // Every namespace carries `kubernetes.io/metadata.name`, so no
            // labels at all means the watcher has not seen it yet, and a
            // namespace selector waits rather than deciding on nothing.
            resolved.namespace_labels = (!pod.namespace_labels.is_empty())
                .then(|| pod.namespace_labels.iter().cloned().collect());
            resolved.service_account =
                (!pod.service_account.is_empty()).then(|| pod.service_account.clone());
        }
    }
    resolved.unit = resolved
        .cgroup
        .as_deref()
        .and_then(unit_of)
        .map(ToOwned::to_owned);
    resolved
}

/// The two masks one task produces.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SelectorMasks {
    /// Selectors satisfied by the cgroup alone, which every task in it
    /// shares.
    pub cgroup: u64,
    /// Selectors needing this task's own executable.
    pub task: u64,
}

impl SelectorMasks {
    /// Whether the task matched nothing at all, in which case there is
    /// nothing to write.
    #[must_use]
    pub fn is_empty(self) -> bool {
        self.cgroup == 0 && self.task == 0
    }
}

/// What the names of one rule have resolved on this node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FqdnRuleState {
    pub rule: RuleId,
    /// One entry per pattern the rule writes, in the rule's order.
    pub patterns: Vec<FqdnPatternReport>,
}

/// What the answers of named workloads have opened so far.
#[derive(Debug, Default)]
struct FqdnState {
    learner: FqdnLearner,
    ledger: FqdnLedger,
}

/// One container's labels, as last read, and whether there was room for
/// them in the last composition.
#[derive(Debug, Clone)]
struct LabelledContainer {
    policy: ContainerLabelPolicy,
    crowded: bool,
}

/// The configured policy with every container's label rules after it.
///
/// Containers are added in id order, so which one is left out when the
/// ceiling is reached does not depend on the order they started in.
fn compose(
    configured: &WorkloadPolicy,
    labelled: &mut BTreeMap<String, LabelledContainer>,
) -> Result<WorkloadPolicy, DomainError> {
    let mut rules = configured.rules().to_vec();
    for entry in labelled.values_mut() {
        entry.crowded = false;
        if !entry.policy.problems.is_empty() {
            continue;
        }
        if rules.len() + entry.policy.rules.len() > WORKLOAD_POLICY_MAX_RULES {
            entry.crowded = true;
            warn!(
                container = %entry.policy.container_id,
                rules = entry.policy.rules.len(),
                maximum = WORKLOAD_POLICY_MAX_RULES,
                "no room for a container's label rules, none of them is in force"
            );
            continue;
        }
        rules.extend(entry.policy.rules.iter().cloned());
    }
    rules.sort_by(|a, b| {
        a.priority
            .cmp(&b.priority)
            .then_with(|| a.id.0.cmp(&b.id.0))
    });
    WorkloadPolicy::new(rules)
        .and_then(|policy| policy.with_dns(configured.dns().clone()))
        .map_err(|e| DomainError::InvalidRule(e.to_string()))
}

/// Where the rules naming a remote workload stand on this node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerStatus {
    /// Every enabled rule naming a remote workload, with the ends that
    /// decide it.
    pub rules: Vec<PeerRuleEnds>,
    /// The version of the list of remote identities the tables were last
    /// written from, absent before the first one arrived.
    pub list_version: Option<String>,
    /// Remote addresses a rule names as its destination.
    pub destinations: usize,
    /// Remote addresses the destination end decides a connection from.
    pub sources: usize,
    /// Addresses a full table refused, which stay unnamed.
    pub refused: usize,
}

/// What the last write of the remote tables was made from.
#[derive(Debug, Default)]
struct PeerState {
    /// The list version and the policy generation written, or nothing when
    /// the next sync has to write whatever it is handed.
    synced: Option<(String, u64)>,
    generation: u64,
    destinations: usize,
    sources: usize,
    refused: usize,
}

/// Per remote address, the slots whose remote workload the list names there,
/// and the slots decided at the destination whose source half the workload
/// there satisfies. Addresses no slot names are left out.
type PeerTables = (Vec<(IpAddr, u64)>, Vec<(IpAddr, u64)>);

/// The enabled rule in kernel slot `slot`.
fn slot_rule(policy: &WorkloadPolicy, slot: usize) -> Option<&WorkloadRule> {
    u16::try_from(slot)
        .ok()
        .and_then(|slot| policy.rule_in_slot(slot))
}

fn peer_tables(policy: &WorkloadPolicy, list: Option<&RemoteIdentities>) -> PeerTables {
    let Some(list) = list else {
        return (Vec::new(), Vec::new());
    };
    let ends = policy.peer_ends();
    if ends.is_empty() {
        return (Vec::new(), Vec::new());
    }
    let named: Vec<_> = ends
        .iter()
        .filter_map(|ends| {
            let rule = slot_rule(policy, ends.slot)?;
            Some((ends, rule, rule.dst_peer.as_ref()?))
        })
        .collect();
    let mut destinations = Vec::new();
    let mut sources = Vec::new();
    for entry in list.entries() {
        let identity = &entry.identity;
        let mut to = 0u64;
        let mut from = 0u64;
        for (ends, rule, peer) in &named {
            let bit = 1u64 << (ends.slot & 63);
            if peer.matches_remote(identity) {
                to |= bit;
            }
            if ends.ends == PeerEnds::Both && source_matches_remote(&rule.selector, identity) {
                from |= bit;
            }
        }
        if to != 0 {
            destinations.push((identity.address, to));
        }
        if from != 0 {
            sources.push((identity.address, from));
        }
    }
    (destinations, sources)
}

/// Keeps the kernel's view of which workload is which.
pub struct WorkloadPolicyService {
    /// The policy in force: the configured rules and every container's
    /// label rules, composed.
    policy: RwLock<WorkloadPolicy>,
    /// The policy the configuration file carries, which a label never
    /// edits and every composition starts from.
    configured: RwLock<WorkloadPolicy>,
    /// What each container's labels said, by container id. Only containers
    /// that carry a label under the prefix are held.
    labelled: Mutex<BTreeMap<String, LabelledContainer>>,
    maps: Option<Mutex<Box<dyn WorkloadPolicyMapPort>>>,
    /// The cgroup mask each cgroup was last written, by cgroup id.
    cgroup_masks: Mutex<HashMap<u64, u64>>,
    /// Taken before the policy and the maps, by every path that touches a
    /// grant, so a reload and an answer never interleave.
    fqdn: Mutex<FqdnState>,
    cgroups: Option<Arc<dyn CgroupReader>>,
    /// The live cgroups, read when a policy goes in force so that a cgroup
    /// no task has exec'd or forked in since the agent started is named too.
    tree: Option<Arc<dyn CgroupTree>>,
    /// The remote tables, as last written.
    peers: Mutex<PeerState>,
    /// Weak because the table holds this service: the table is what learns
    /// of an exec, and this is what a new policy has to be replayed over.
    /// An `Arc` both ways would be a cycle neither end ever drops.
    processes: OnceLock<Weak<crate::process_table_service::ProcessTableService>>,
}

impl WorkloadPolicyService {
    /// A service over `policy`, writing to nothing until it is given maps.
    ///
    /// Useful on its own: the command line and the API read the policy
    /// through the same service on a host where the object did not load.
    #[must_use]
    pub fn new(policy: WorkloadPolicy) -> Self {
        let fqdn = FqdnState {
            learner: FqdnLearner::new(policy.dns().clone()),
            ledger: FqdnLedger::default(),
        };
        Self {
            configured: RwLock::new(policy.clone()),
            policy: RwLock::new(policy),
            labelled: Mutex::new(BTreeMap::new()),
            maps: None,
            cgroup_masks: Mutex::new(HashMap::new()),
            fqdn: Mutex::new(fqdn),
            cgroups: None,
            tree: None,
            peers: Mutex::new(PeerState::default()),
            processes: OnceLock::new(),
        }
    }

    /// Write what is resolved into `maps`.
    #[must_use]
    pub fn with_maps(mut self, maps: Box<dyn WorkloadPolicyMapPort>) -> Self {
        self.maps = Some(Mutex::new(maps));
        self
    }

    /// Read a task's cgroup path through `reader`.
    ///
    /// Without one, a unit or cgroup selector can still be decided for a
    /// container, whose path the resolver already carries, and never for a
    /// host process - which is the shape of a degradation worth logging
    /// rather than guessing around.
    #[must_use]
    pub fn with_cgroups(mut self, reader: Arc<dyn CgroupReader>) -> Self {
        self.cgroups = Some(reader);
        self
    }

    /// Name the live cgroups read through `tree` whenever a policy goes in
    /// force, beside the tasks the process table holds.
    ///
    /// The table learns of a task when it forks or execs, so a container or a
    /// unit started before the agent, whose processes do neither, would carry
    /// no bits at all: a long-lived daemon connecting out of it would never
    /// meet the rule that names its container.
    #[must_use]
    pub fn with_cgroup_tree(mut self, tree: Arc<dyn CgroupTree>) -> Self {
        self.tree = Some(tree);
        self
    }

    /// Replay the table through a new policy, so the tasks already running
    /// carry their bits under it.
    ///
    /// Set after construction rather than taken by the builder, because the
    /// table is built around this service and cannot be handed to it first.
    pub fn watch_processes(
        &self,
        processes: &Arc<crate::process_table_service::ProcessTableService>,
    ) {
        let _ = self.processes.set(Arc::downgrade(processes));
    }

    /// The policy in force.
    #[must_use]
    pub fn policy(&self) -> WorkloadPolicy {
        self.policy
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Whether any enabled rule has the kernel refuse a syscall.
    #[must_use]
    pub fn enforces(&self) -> bool {
        self.policy
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .enforces()
    }

    /// Put `policy` in force and write it to the kernel.
    ///
    /// Every recorded selector mask is dropped by the write, because a bit
    /// index is a position in this policy's own list of selectors and means
    /// something else in the next one. The caller replays the process table
    /// through [`Self::record_exec`] afterwards.
    ///
    /// # Errors
    ///
    /// Whatever the map port refuses.
    pub fn apply(&self, policy: WorkloadPolicy) -> Result<(), DomainError> {
        *self
            .configured
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = policy;
        self.recompose()
    }

    /// Compose the configured policy with every container's label rules and
    /// put the result in force.
    ///
    /// A container whose rules would carry the policy past the kernel's
    /// ceiling is refused whole, in container id order, and the refusal is
    /// reported against it: half a container's policy is a policy nobody
    /// wrote.
    fn recompose(&self) -> Result<(), DomainError> {
        let configured = self
            .configured
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let composed = {
            let mut labelled = self
                .labelled
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            compose(&configured, &mut labelled)?
        };
        self.publish(composed)
    }

    /// Write `policy` to the kernel and hold it as the policy in force.
    fn publish(&self, policy: WorkloadPolicy) -> Result<(), DomainError> {
        let mut fqdn = self
            .fqdn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(maps) = &self.maps {
            maps.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .publish_policy(&policy)?;
        }
        // The publish dropped every grant and every mask in the kernel, so
        // what mirrors them here goes too, and the learner starts over under
        // the resolvers this policy trusts.
        fqdn.ledger.clear();
        fqdn.learner = FqdnLearner::new(policy.dns().clone());
        self.cgroup_masks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        {
            // The publish emptied the remote tables, whose masks are slots:
            // the next sync writes them again whatever list it is handed.
            let mut peers = self
                .peers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            peers.synced = None;
            peers.generation += 1;
            peers.destinations = 0;
            peers.sources = 0;
            peers.refused = 0;
        }
        let rules = policy.rules().len();
        *self
            .policy
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = policy;
        drop(fqdn);
        info!(rules, "workload policy in force");
        // After the lock on the maps is released, because the replay takes
        // it once per task.
        self.replay();
        self.seed_cgroups();
        Ok(())
    }

    /// Resolve every task the table holds under the policy in force.
    ///
    /// A reload renumbers the bits and drops what the last policy recorded,
    /// so without this the processes already running would be nameless until
    /// each of them next execs, which for a long-lived daemon is never.
    fn replay(&self) {
        let Some(processes) = self.processes.get().and_then(Weak::upgrade) else {
            return;
        };
        let entries = processes.list();
        for entry in &entries {
            self.record_exec(entry);
        }
        debug!(
            tasks = entries.len(),
            "workload policy replayed over the process table"
        );
    }

    /// Name every live cgroup the replay left without a mask, from what its
    /// path alone says: the path itself, the unit and the container id.
    ///
    /// A cgroup a task already named is left as that task wrote it, because
    /// a task carries more than its path - the container's name, its pod -
    /// and the path alone can only say less. What this writes is the floor a
    /// cgroup is named at until something in it forks or execs.
    fn seed_cgroups(&self) {
        let (Some(tree), Some(maps)) = (&self.tree, &self.maps) else {
            return;
        };
        if self
            .policy
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty()
        {
            return;
        }
        let mut seeded = 0usize;
        for (cgroup_id, path) in tree.cgroups() {
            if cgroup_id == 0
                || self
                    .cgroup_masks
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .contains_key(&cgroup_id)
            {
                continue;
            }
            let resolved = workload_of_cgroup(&path);
            let masks = self.masks_for(&resolved.facts());
            let peers = self.peer_targets(&resolved);
            if masks.cgroup == 0 && peers == 0 {
                continue;
            }
            let mut maps = maps
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if masks.cgroup != 0 {
                if let Err(err) = maps.set_cgroup_selectors(cgroup_id, masks.cgroup) {
                    warn!(cgroup = path, error = %err, "a cgroup's workload selectors were not written");
                    continue;
                }
                self.cgroup_masks
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(cgroup_id, masks.cgroup);
            }
            if peers != 0
                && let Err(err) = maps.set_peer_targets(cgroup_id, peers)
            {
                warn!(cgroup = path, error = %err, "a cgroup's remote workload rules were not written");
            }
            seeded += 1;
        }
        debug!(
            cgroups = seeded,
            "live cgroups named by the workload policy"
        );
    }

    /// What `entry` is, with the cgroup path read where one can be.
    #[must_use]
    pub fn resolve(&self, entry: &ProcessEntry) -> ResolvedWorkload {
        let mut resolved = workload_of(entry);
        if resolved.cgroup.is_none()
            && let Some(reader) = &self.cgroups
        {
            match reader.read_cgroup(entry.pid) {
                Ok(payload) => {
                    resolved.cgroup = cgroup_path_of(&payload).map(ToOwned::to_owned);
                }
                Err(err) => {
                    // Routine rather than exceptional: a short-lived process
                    // is gone by the time this read happens, and a unit or
                    // cgroup rule simply does not name it.
                    debug!(pid = entry.pid, error = %err, "no cgroup path for a task");
                }
            }
        }
        resolved.unit = resolved
            .cgroup
            .as_deref()
            .and_then(unit_of)
            .map(ToOwned::to_owned);
        resolved
    }

    /// The two masks `facts` satisfy under the policy in force.
    #[must_use]
    pub fn masks_for(&self, facts: &WorkloadFacts<'_>) -> SelectorMasks {
        let policy = self
            .policy
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut masks = SelectorMasks::default();
        for (bit, selector) in policy.selectors().enumerate() {
            // The lineage half of a selector is the kernel's to check, at the
            // call and against the live parent chain, so it is left out here.
            // A selector naming nothing else is satisfied by every task but
            // for that half, which the kernel already knows without a mask.
            if selector.lineage_only() || !selector.matches_besides_lineage(facts) {
                continue;
            }
            let bit = 1u64 << (bit & 63);
            if selector.names_executable() {
                masks.task |= bit;
            } else {
                masks.cgroup |= bit;
            }
        }
        masks
    }

    /// Resolve one exec and write what it matched.
    ///
    /// The cgroup mask is written even when it is the same as last time: it
    /// is one small map write per exec, and the alternative is a cache of
    /// what was written that goes stale the moment a cgroup is reused.
    pub fn record_exec(&self, entry: &ProcessEntry) {
        let Some(maps) = &self.maps else {
            return;
        };
        if self
            .policy
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty()
        {
            return;
        }
        let resolved = self.resolve(entry);
        let masks = self.masks_for(&resolved.facts());
        // The cgroup mask is a fact about the cgroup, and a task whose cgroup
        // path could not be read - gone before the read, most often - says
        // nothing about it. Writing what that task matched would clear the
        // bits of a cgroup the policy names, for every task in it, until the
        // next exec there.
        let cgroup_id = if resolved.cgroup.is_some() {
            entry.cgroup_id
        } else {
            0
        };
        if cgroup_id != 0 {
            let mut known = self
                .cgroup_masks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if masks.cgroup == 0 {
                known.remove(&cgroup_id);
            } else {
                known.insert(cgroup_id, masks.cgroup);
            }
        }
        let mut maps = maps
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if cgroup_id != 0
            && let Err(err) = maps.set_cgroup_selectors(cgroup_id, masks.cgroup)
        {
            warn!(pid = entry.pid, error = %err, "a cgroup's workload selectors were not written");
        }
        if let Err(err) = maps.set_task_selectors(entry.pid, masks.task) {
            warn!(pid = entry.pid, error = %err, "a task's workload selectors were not written");
        }
        if cgroup_id != 0
            && let Err(err) = maps.set_peer_targets(cgroup_id, self.peer_targets(&resolved))
        {
            warn!(pid = entry.pid, error = %err, "a cgroup's remote workload rules were not written");
        }
        if let ProcessIdentity::Path { path, dev, inode } = &entry.identity
            && let Err(err) = maps.note_lineage_executable(path, *dev, *inode)
        {
            warn!(
                pid = entry.pid,
                path,
                error = %err,
                "an executable a lineage rule names was not recorded"
            );
        }
        if !masks.is_empty() {
            debug!(
                pid = entry.pid,
                cgroup = masks.cgroup,
                task = masks.task,
                "a task was named by the workload policy"
            );
        }
    }

    /// The slots decided at the destination whose remote workload is this
    /// one, as a mask.
    fn peer_targets(&self, resolved: &ResolvedWorkload) -> u64 {
        let policy = self
            .policy
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let facts = resolved.facts();
        let mut mask = 0u64;
        for ends in policy.peer_ends() {
            if ends.ends != PeerEnds::Both {
                continue;
            }
            if let Some(peer) = slot_rule(&policy, ends.slot).and_then(|r| r.dst_peer.as_ref())
                && peer.matches_local(&facts)
            {
                mask |= 1u64 << (ends.slot & 63);
            }
        }
        mask
    }

    /// Write the remote tables from `list`, the list of remote identities
    /// the console last handed this node.
    ///
    /// Nothing is written when neither the list nor the policy changed since
    /// the last write. With no list, every remote table is emptied: a rule
    /// naming a remote workload then applies to no address, which is what an
    /// unnamed address means.
    ///
    /// # Errors
    ///
    /// Whatever the map port refuses other than a full table.
    pub fn sync_peers(&self, list: Option<&RemoteIdentities>) -> Result<(), DomainError> {
        let Some(maps) = &self.maps else {
            return Ok(());
        };
        let version = list.map_or_else(String::new, |list| list.version().to_string());
        let mut peers = self
            .peers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let wanted = (version, peers.generation);
        if peers.synced.as_ref() == Some(&wanted) {
            return Ok(());
        }
        let (destinations, sources) = {
            let policy = self
                .policy
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            peer_tables(&policy, list)
        };
        let refused = maps
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .replace_peer_addresses(&destinations, &sources)?;
        peers.destinations = destinations.len();
        peers.sources = sources.len();
        peers.refused = refused;
        info!(
            list = %wanted.0,
            destinations = destinations.len(),
            sources = sources.len(),
            refused,
            "remote workload tables written"
        );
        peers.synced = Some(wanted);
        Ok(())
    }

    /// Where the rules naming a remote workload stand.
    #[must_use]
    pub fn peer_status(&self) -> PeerStatus {
        let rules = self
            .policy
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .peer_ends();
        let peers = self
            .peers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        PeerStatus {
            rules,
            list_version: peers
                .synced
                .as_ref()
                .map(|(version, _)| version.clone())
                .filter(|version| !version.is_empty()),
            destinations: peers.destinations,
            sources: peers.sources,
            refused: peers.refused,
        }
    }

    /// Name the rule a kernel record refused under, or nothing.
    ///
    /// Nothing happens when the slot is past the policy in force, which is
    /// a record that crossed a reload: the slots are renumbered by every
    /// publish, so the alternative to dropping it is an alert naming a rule
    /// that did not refuse anything.
    #[must_use]
    pub fn name_denial(&self, record: WorkloadDenialRecord) -> Option<WorkloadDenial> {
        let policy = self
            .policy
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let rule = policy.rule_in_slot(record.slot)?;
        Some(record.named(rule.id.clone()))
    }

    /// What each rule in force has refused, from the kernel's own counters.
    ///
    /// Empty where no maps are held, because a host that never loaded the
    /// object has no figure rather than a figure of zero.
    ///
    /// # Errors
    ///
    /// Whatever reading the counter array refused.
    pub fn denials_by_rule(&self) -> Result<Vec<(RuleId, u64)>, DomainError> {
        let Some(maps) = &self.maps else {
            return Ok(Vec::new());
        };
        let counts = maps
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .rule_denials()?;
        let policy = self
            .policy
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(policy
            .in_slot_order()
            .enumerate()
            .map(|(slot, rule)| (rule.id.clone(), counts.get(slot).copied().unwrap_or(0)))
            .collect())
    }

    /// The rules naming `facts`, in the order the kernel walks them, each
    /// with what it has refused.
    ///
    /// This is the answer to "why can this not connect", so the whole list
    /// is returned rather than the first match: an operator reading it is
    /// usually looking for the rule above the one they wrote.
    ///
    /// # Errors
    ///
    /// Whatever reading the counter array refused.
    pub fn reach_for(&self, facts: &WorkloadFacts<'_>) -> Result<Vec<WorkloadReach>, DomainError> {
        self.reach(Some(facts))
    }

    /// Every rule in force, in the order the kernel walks them, each with
    /// what it has refused.
    ///
    /// A disabled rule is absent rather than listed as idle: it occupies no
    /// slot, so it has no counter of its own and a zero beside it would read
    /// as a rule nothing ever hit.
    ///
    /// # Errors
    ///
    /// Whatever reading the counter array refused.
    pub fn rules_in_force(&self) -> Result<Vec<WorkloadReach>, DomainError> {
        self.reach(None)
    }

    fn reach(&self, facts: Option<&WorkloadFacts<'_>>) -> Result<Vec<WorkloadReach>, DomainError> {
        let counts = match &self.maps {
            Some(maps) => maps
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .rule_denials()?,
            None => Vec::new(),
        };
        let policy = self
            .policy
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut peers: HashMap<usize, PeerRuleEnds> = policy
            .peer_ends()
            .into_iter()
            .map(|ends| (ends.slot, ends))
            .collect();
        Ok(policy
            .in_slot_order()
            .enumerate()
            .filter(|(_, rule)| facts.is_none_or(|facts| rule.selector.matches(facts)))
            .map(|(slot, rule)| {
                let peer = peers.remove(&slot);
                WorkloadReach {
                    rule: rule.id.clone(),
                    allows: !rule.refuses(),
                    mode: rule.mode,
                    selector: rule.selector.describe(),
                    destination: rule.describe_destination(),
                    denials: counts.get(slot).copied().unwrap_or(0),
                    peer_ends: peer.as_ref().map(|peer| peer.ends),
                    peer_reason: peer.and_then(|peer| peer.reason),
                }
            })
            .collect())
    }

    /// Read one DNS packet of a named workload, and open what a believed
    /// answer carried. Returns how many grants were written.
    ///
    /// An address opens under every rule naming that name whose selector the
    /// cgroup satisfies, each in its own slot and for that cgroup alone: an
    /// address one pod was answered is never reused for another, because
    /// the grant is keyed by the cgroup that asked. A grant the kernel
    /// refused to hold leaves the address closed and is logged.
    pub fn observe_dns(&self, capture: &DnsCapture) -> usize {
        let Some(maps) = &self.maps else {
            return 0;
        };
        let mut fqdn = self
            .fqdn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(resolution) = fqdn.learner.observe(capture) else {
            return 0;
        };
        let Some(mask) = self
            .cgroup_masks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&resolution.cgroup_id)
            .copied()
        else {
            return 0;
        };
        let policy = self
            .policy
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let selectors: Vec<_> = policy.selectors().collect();
        let mut maps = maps
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut granted = 0usize;
        for (slot, rule) in policy.in_slot_order().enumerate() {
            if rule.dst_fqdn.is_empty()
                || !rule
                    .dst_fqdn
                    .iter()
                    .any(|pattern| pattern.matches(&resolution.name))
            {
                continue;
            }
            let Some(bit) = selectors.iter().position(|one| *one == &rule.selector) else {
                continue;
            };
            if mask & (1u64 << (bit & 63)) == 0 {
                continue;
            }
            let Ok(slot) = u16::try_from(slot) else {
                continue;
            };
            for &(addr, ttl) in &resolution.addresses {
                let key = FqdnGrantKey {
                    cgroup_id: resolution.cgroup_id,
                    addr,
                    slot,
                };
                let expires_ns = policy.dns().expiry_ns(resolution.at_ns, ttl);
                let in_force =
                    fqdn.ledger
                        .record(key, &resolution.name, expires_ns, resolution.at_ns);
                if let Err(err) = maps.grant_fqdn(&key, in_force) {
                    fqdn.ledger.remove(&key);
                    warn!(
                        rule = %rule.id.0,
                        name = %resolution.name,
                        %addr,
                        error = %err,
                        "an address a workload resolved was not opened"
                    );
                    continue;
                }
                granted += 1;
            }
        }
        if granted > 0 {
            debug!(
                cgroup = resolution.cgroup_id,
                name = %resolution.name,
                granted,
                "a workload's resolution opened its addresses"
            );
        }
        granted
    }

    /// Close every grant lapsed at `now_ns`, on `CLOCK_BOOTTIME`, and forget
    /// the queries nobody answered. Returns how many grants were closed.
    ///
    /// The hook already refuses a lapsed grant by its expiry, so this is the
    /// map being kept to what is in force rather than the enforcement itself.
    pub fn sweep_fqdn(&self, now_ns: u64) -> usize {
        let mut fqdn = self
            .fqdn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        fqdn.learner.prune(now_ns);
        let lapsed = fqdn.ledger.sweep(now_ns);
        if let Some(maps) = &self.maps {
            let mut maps = maps
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for key in &lapsed {
                if let Err(err) = maps.revoke_fqdn(key) {
                    warn!(error = %err, "a lapsed address was not removed from the kernel");
                }
            }
        }
        lapsed.len()
    }

    /// Every rule naming a destination by name, with what each of its
    /// patterns has resolved and what is still open at `now_ns`.
    ///
    /// A pattern with no name under it has never resolved since the policy
    /// was published, which on a rule that allows is usually a typo rather
    /// than a quiet success, so it is reported rather than left out.
    pub fn fqdn_state(&self, now_ns: u64) -> Vec<FqdnRuleState> {
        let fqdn = self
            .fqdn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let policy = self
            .policy
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        policy
            .in_slot_order()
            .enumerate()
            .filter(|(_, rule)| !rule.dst_fqdn.is_empty())
            .filter_map(|(slot, rule)| {
                let slot = u16::try_from(slot).ok()?;
                Some(FqdnRuleState {
                    rule: rule.id.clone(),
                    patterns: rule
                        .dst_fqdn
                        .iter()
                        .map(|pattern| fqdn.ledger.report(slot, pattern, now_ns))
                        .collect(),
                })
            })
            .collect()
    }

    /// Read what a container's labels say and put it in force.
    ///
    /// A container carrying no label under the prefix, and never seen with
    /// one, costs nothing: the policy is republished only when a container's
    /// own rules change, because a republish renumbers every bit and replays
    /// the process table.
    ///
    /// # Errors
    ///
    /// Whatever the map port refuses.
    pub fn observe_container(
        &self,
        container_id: &str,
        container_name: &str,
        labels: &[(String, String)],
    ) -> Result<(), DomainError> {
        let policy = ContainerLabelPolicy::from_labels(container_id, container_name, labels);
        {
            let mut labelled = self
                .labelled
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let previous = labelled.get(container_id);
            if previous.is_none() && policy.is_empty() {
                return Ok(());
            }
            if previous.is_some_and(|entry| entry.policy == policy) {
                return Ok(());
            }
            for problem in &policy.problems {
                warn!(
                    container = container_id,
                    name = container_name,
                    label = %problem.label,
                    reason = %problem.reason,
                    "a container's policy labels cannot be read, none of its label rules is in force"
                );
            }
            if policy.is_empty() {
                labelled.remove(container_id);
            } else {
                labelled.insert(
                    container_id.to_string(),
                    LabelledContainer {
                        policy,
                        crowded: false,
                    },
                );
            }
        }
        self.recompose()
    }

    /// Drop a container that is gone, and its label rules with it.
    ///
    /// # Errors
    ///
    /// Whatever the map port refuses.
    pub fn forget_container(&self, container_id: &str) -> Result<(), DomainError> {
        let removed = self
            .labelled
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(container_id)
            .is_some();
        if removed { self.recompose() } else { Ok(()) }
    }

    /// Replace every container's labels with `containers`, the whole list
    /// the runtime holds.
    ///
    /// This is what a reconnection to the runtime calls, because an event
    /// missed while the stream was down is a container whose labels nobody
    /// read, or one gone whose rules are still in force.
    ///
    /// # Errors
    ///
    /// Whatever the map port refuses.
    pub fn reconcile_containers(&self, containers: &[ListedContainer]) -> Result<(), DomainError> {
        let next: BTreeMap<String, LabelledContainer> = containers
            .iter()
            .map(|(id, name, labels)| ContainerLabelPolicy::from_labels(id, name, labels))
            .filter(|policy| !policy.is_empty())
            .map(|policy| {
                (
                    policy.container_id.clone(),
                    LabelledContainer {
                        policy,
                        crowded: false,
                    },
                )
            })
            .collect();
        {
            let mut labelled = self
                .labelled
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let same = labelled.len() == next.len()
                && labelled
                    .iter()
                    .zip(next.iter())
                    .all(|((a, x), (b, y))| a == b && x.policy == y.policy);
            if same {
                return Ok(());
            }
            *labelled = next;
        }
        self.recompose()
    }

    /// What every labelled container's labels say, in container id order,
    /// with a container left out for want of room reported as refused.
    #[must_use]
    pub fn label_policies(&self) -> Vec<ContainerLabelPolicy> {
        self.labelled
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .map(|entry| {
                let mut policy = entry.policy.clone();
                if entry.crowded {
                    policy.refuse(
                        LABEL_PREFIX,
                        format!(
                            "the node already holds as many workload rules as the kernel \
                             walks ({WORKLOAD_POLICY_MAX_RULES}), so none of this container's \
                             label rules is in force"
                        ),
                    );
                }
                policy
            })
            .collect()
    }

    /// Forget a task that exited.
    ///
    /// A pid is reused, and a mask left behind would name the next program
    /// to take the number. The cgroup entry is deliberately left alone: it
    /// is about the cgroup rather than about this task, and the next exec
    /// there rewrites it.
    pub fn record_exit(&self, pid: u32) {
        let Some(maps) = &self.maps else {
            return;
        };
        if let Err(err) = maps
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .forget_task(pid)
        {
            warn!(pid, error = %err, "a task's workload selectors were not cleared");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io;

    use domain::common::entity::{Protocol, RuleId};
    use domain::container::entity::{
        ContainerContext, ContainerInfo, ContainerRuntime, DockerMetadata, KubernetesMetadata,
    };
    use domain::firewall::entity::{FirewallAction, IpNetwork};
    use domain::firewall::fqdn::{DnsDirection, FqdnPattern, WorkloadDnsSettings};
    use domain::firewall::workload::{
        DestinationAddr, KubernetesMatchers, LineageMatchers, WorkloadDestination, WorkloadHook,
        WorkloadMode, WorkloadRule, WorkloadSelector,
    };
    use domain::firewall::workload_peer::PeerSelector;
    use domain::identity::remote::{RemoteEntry, RemoteSnapshot};
    use domain::identity::{AddressIdentity, IdentityKind};
    use domain::netpol::LabelSelector;

    use super::*;

    #[derive(Default)]
    struct RecordingMaps {
        cgroups: HashMap<u64, u64>,
        tasks: HashMap<u32, u64>,
        published: usize,
        denials: Vec<u64>,
        grants: HashMap<FqdnGrantKey, u64>,
        executables: Vec<(String, u64, u64)>,
        peer_destinations: HashMap<IpAddr, u64>,
        peer_sources: HashMap<IpAddr, u64>,
        peer_targets: HashMap<u64, u64>,
        peer_writes: usize,
    }

    #[derive(Clone, Default)]
    struct SharedMaps(Arc<Mutex<RecordingMaps>>);

    impl WorkloadPolicyMapPort for SharedMaps {
        fn rule_denials(&self) -> Result<Vec<u64>, DomainError> {
            Ok(self.0.lock().unwrap().denials.clone())
        }

        fn publish_policy(&mut self, _policy: &WorkloadPolicy) -> Result<(), DomainError> {
            let mut held = self.0.lock().unwrap();
            held.published += 1;
            held.cgroups.clear();
            held.tasks.clear();
            held.grants.clear();
            held.peer_destinations.clear();
            held.peer_sources.clear();
            held.peer_targets.clear();
            Ok(())
        }

        fn grant_fqdn(&mut self, key: &FqdnGrantKey, expires_ns: u64) -> Result<(), DomainError> {
            self.0.lock().unwrap().grants.insert(*key, expires_ns);
            Ok(())
        }

        fn revoke_fqdn(&mut self, key: &FqdnGrantKey) -> Result<(), DomainError> {
            self.0.lock().unwrap().grants.remove(key);
            Ok(())
        }

        fn set_cgroup_selectors(&mut self, cgroup_id: u64, mask: u64) -> Result<(), DomainError> {
            self.0.lock().unwrap().cgroups.insert(cgroup_id, mask);
            Ok(())
        }

        fn set_task_selectors(&mut self, tgid: u32, mask: u64) -> Result<(), DomainError> {
            self.0.lock().unwrap().tasks.insert(tgid, mask);
            Ok(())
        }

        fn forget_task(&mut self, tgid: u32) -> Result<(), DomainError> {
            self.0.lock().unwrap().tasks.remove(&tgid);
            Ok(())
        }

        fn clear_selectors(&mut self) -> Result<(), DomainError> {
            let mut held = self.0.lock().unwrap();
            held.cgroups.clear();
            held.tasks.clear();
            Ok(())
        }

        fn replace_peer_addresses(
            &mut self,
            destinations: &[(IpAddr, u64)],
            sources: &[(IpAddr, u64)],
        ) -> Result<usize, DomainError> {
            let mut held = self.0.lock().unwrap();
            held.peer_destinations = destinations.iter().copied().collect();
            held.peer_sources = sources.iter().copied().collect();
            held.peer_writes += 1;
            Ok(0)
        }

        fn set_peer_targets(&mut self, cgroup_id: u64, mask: u64) -> Result<(), DomainError> {
            let mut held = self.0.lock().unwrap();
            if mask == 0 {
                held.peer_targets.remove(&cgroup_id);
            } else {
                held.peer_targets.insert(cgroup_id, mask);
            }
            Ok(())
        }

        fn note_lineage_executable(
            &mut self,
            path: &str,
            dev: u64,
            inode: u64,
        ) -> Result<(), DomainError> {
            self.0
                .lock()
                .unwrap()
                .executables
                .push((path.to_string(), dev, inode));
            Ok(())
        }
    }

    struct StaticCgroup(String);

    impl CgroupReader for StaticCgroup {
        fn read_cgroup(&self, _pid: u32) -> io::Result<String> {
            Ok(self.0.clone())
        }
    }

    fn rule(id: &str, selector: WorkloadSelector) -> WorkloadRule {
        WorkloadRule {
            dst_peer: None,
            id: RuleId(id.to_string()),
            priority: 10,
            action: FirewallAction::Deny,
            mode: WorkloadMode::Observe,
            selector,
            protocol: Protocol::Any,
            dst_ip: None,
            dst_port: None,
            dst_fqdn: Vec::new(),
            outbound_only: false,
            enabled: true,
        }
    }

    fn exe_rule(id: &str, exe: &str) -> WorkloadRule {
        rule(
            id,
            WorkloadSelector::new(Some(exe.to_string()), None, None, None).expect("a valid path"),
        )
    }

    fn unit_rule(id: &str, unit: &str) -> WorkloadRule {
        rule(
            id,
            WorkloadSelector::new(None, Some(unit.to_string()), None, None).expect("a valid unit"),
        )
    }

    fn entry(pid: u32, exe: &str) -> ProcessEntry {
        let mut entry = ProcessEntry::new(pid, "curl", 1);
        entry.identity = ProcessIdentity::Path {
            path: exe.to_string(),
            dev: 1,
            inode: 2,
        };
        entry.cgroup_id = 4242;
        entry
    }

    fn record(slot: u16) -> WorkloadDenialRecord {
        WorkloadDenialRecord {
            slot,
            hook: WorkloadHook::Connect,
            destination: WorkloadDestination {
                addr: DestinationAddr::V4(0x0a00_0001),
                port: 443,
                protocol: Protocol::Tcp,
            },
            enforced: true,
            tgid: 99,
            uid: 0,
            cgroup_id: 4242,
            at_ns: 1_000,
        }
    }

    fn service(rules: Vec<WorkloadRule>, maps: SharedMaps) -> WorkloadPolicyService {
        WorkloadPolicyService::new(WorkloadPolicy::new(rules).expect("inside the ceiling"))
            .with_maps(Box::new(maps))
            .with_cgroups(Arc::new(StaticCgroup(
                "0::/system.slice/nginx.service\n".to_string(),
            )))
    }

    #[test]
    fn an_executable_selector_lands_on_the_task_and_a_unit_selector_on_the_cgroup() {
        let maps = SharedMaps::default();
        let service = service(
            vec![
                exe_rule("one", "/usr/bin/curl"),
                unit_rule("two", "nginx.service"),
            ],
            maps.clone(),
        );

        service.record_exec(&entry(99, "/usr/bin/curl"));

        let held = maps.0.lock().unwrap();
        assert_eq!(held.tasks.get(&99), Some(&0b01));
        assert_eq!(held.cgroups.get(&4242), Some(&0b10));
    }

    /// A cgroup reader for a task that is already gone.
    struct GoneCgroup;

    impl CgroupReader for GoneCgroup {
        fn read_cgroup(&self, _pid: u32) -> io::Result<String> {
            Err(io::Error::from(io::ErrorKind::NotFound))
        }
    }

    #[test]
    fn a_task_whose_cgroup_cannot_be_read_leaves_the_cgroup_s_bits_alone() {
        let maps = SharedMaps::default();
        let named = service(vec![unit_rule("unit", "nginx.service")], maps.clone());
        named.record_exec(&entry(99, "/usr/bin/curl"));
        assert_eq!(maps.0.lock().unwrap().cgroups.get(&4242), Some(&0b1));

        // The same cgroup, seen through a task gone before its path was read.
        let gone = WorkloadPolicyService::new(
            WorkloadPolicy::new(vec![unit_rule("unit", "nginx.service")]).unwrap(),
        )
        .with_maps(Box::new(maps.clone()))
        .with_cgroups(Arc::new(GoneCgroup));
        maps.0.lock().unwrap().cgroups.insert(4242, 0b1);
        gone.record_exec(&entry(100, "/usr/bin/curl"));
        let held = maps.0.lock().unwrap();
        assert_eq!(held.cgroups.get(&4242), Some(&0b1));
        assert_eq!(held.tasks.get(&100), Some(&0));
    }

    struct Tree(Vec<(u64, String)>);

    impl CgroupTree for Tree {
        fn cgroups(&self) -> Vec<(u64, String)> {
            self.0.clone()
        }
    }

    #[test]
    fn a_cgroup_no_task_was_seen_in_is_named_from_its_path() {
        const ID: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let maps = SharedMaps::default();
        let container = rule(
            "container",
            WorkloadSelector::new(None, None, None, Some(ID.to_string())).expect("a valid id"),
        );
        let service = WorkloadPolicyService::new(
            WorkloadPolicy::new(vec![unit_rule("unit", "nginx.service"), container]).unwrap(),
        )
        .with_maps(Box::new(maps.clone()))
        .with_cgroup_tree(Arc::new(Tree(vec![
            (7, "/system.slice/nginx.service".to_string()),
            (8, format!("/system.slice/docker-{ID}.scope")),
            (9, "/system.slice/cron.service".to_string()),
        ])));

        service.apply(service.policy()).unwrap();

        let held = maps.0.lock().unwrap();
        let unit = held.cgroups.get(&7).copied().unwrap_or_default();
        let scope = held.cgroups.get(&8).copied().unwrap_or_default();
        assert_eq!(unit.count_ones(), 1);
        assert_eq!(scope.count_ones(), 1);
        assert_ne!(unit, scope);
        assert_eq!(held.cgroups.get(&9), None);
    }

    #[test]
    fn a_cgroup_a_task_already_named_is_not_named_again_from_its_path() {
        let maps = SharedMaps::default();
        let service = service(vec![unit_rule("unit", "nginx.service")], maps.clone())
            .with_cgroup_tree(Arc::new(Tree(vec![(
                4242,
                "/system.slice/nginx.service".to_string(),
            )])));
        service.record_exec(&entry(99, "/usr/bin/curl"));
        maps.0.lock().unwrap().cgroups.insert(4242, 0b100);

        service.seed_cgroups();

        assert_eq!(maps.0.lock().unwrap().cgroups.get(&4242), Some(&0b100));
    }

    fn lineage_rule(id: &str, exe: Option<&str>, ancestor: &str) -> WorkloadRule {
        rule(
            id,
            WorkloadSelector::with_lineage(
                exe.map(str::to_string),
                None,
                None,
                None,
                KubernetesMatchers::default(),
                LineageMatchers {
                    parent: None,
                    ancestor: Some(ancestor.to_string()),
                },
            )
            .expect("a valid lineage selector"),
        )
    }

    #[test]
    fn a_lineage_is_left_to_the_kernel_and_the_rest_of_the_selector_is_not() {
        // A selector naming only a lineage has nothing for a mask to say:
        // the kernel gates it on the chain it walks at the call. One naming
        // an executable as well lands on the task by the executable, and the
        // kernel narrows it by the chain the same way.
        let maps = SharedMaps::default();
        let service = service(
            vec![
                lineage_rule("alone", None, "/usr/sbin/nginx"),
                lineage_rule("curl", Some("/usr/bin/curl"), "/usr/sbin/nginx"),
            ],
            maps.clone(),
        );

        service.record_exec(&entry(21, "/usr/bin/curl"));
        service.record_exec(&entry(22, "/usr/bin/wget"));

        let held = maps.0.lock().unwrap();
        assert_eq!(held.tasks.get(&21), Some(&0b10));
        assert_eq!(held.tasks.get(&22), Some(&0));
        assert_eq!(held.cgroups.get(&4242), Some(&0));
    }

    #[test]
    fn every_exec_offers_the_file_it_ran_for_a_lineage_to_recognise() {
        let maps = SharedMaps::default();
        let service = service(
            vec![lineage_rule("alone", None, "/usr/sbin/nginx")],
            maps.clone(),
        );

        service.record_exec(&entry(30, "/usr/sbin/nginx"));

        assert_eq!(
            maps.0.lock().unwrap().executables,
            vec![("/usr/sbin/nginx".to_string(), 1, 2)]
        );
    }

    #[test]
    fn the_chain_the_table_holds_answers_which_rules_reach_a_task() {
        let service = service(
            vec![
                lineage_rule("under-nginx", None, "/usr/sbin/nginx"),
                exe_rule("curl", "/usr/bin/curl"),
            ],
            SharedMaps::default(),
        );
        let lineage = Lineage {
            ancestors: vec![entry(2, "/usr/bin/bash"), entry(1, "/usr/sbin/nginx")],
            truncated: false,
            incomplete: false,
        };
        let resolved = workload_of(&entry(3, "/usr/bin/curl")).with_ancestry(&lineage);
        assert_eq!(
            resolved.ancestry.as_deref(),
            Some(&["/usr/bin/bash".to_string(), "/usr/sbin/nginx".to_string()][..])
        );
        let reach = service.reach_for(&resolved.facts()).unwrap();
        let ids: Vec<_> = reach.iter().map(|r| r.rule.0.as_str()).collect();
        assert_eq!(ids, ["under-nginx", "curl"]);

        let orphan = workload_of(&entry(3, "/usr/bin/curl"));
        let reach = service.reach_for(&orphan.facts()).unwrap();
        let ids: Vec<_> = reach.iter().map(|r| r.rule.0.as_str()).collect();
        assert_eq!(ids, ["curl"]);
    }

    #[test]
    fn a_selector_naming_both_halves_is_decided_here_and_written_once() {
        // The kernel ORs the two masks, so a selector split across them
        // would be satisfied by a task that only matched one half. It is
        // decided against both facts and written to the task table alone.
        let both = WorkloadSelector::new(
            Some("/usr/bin/curl".to_string()),
            Some("nginx.service".to_string()),
            None,
            None,
        )
        .expect("a valid selector");
        let maps = SharedMaps::default();
        let service = service(vec![rule("one", both)], maps.clone());

        service.record_exec(&entry(7, "/usr/bin/curl"));
        service.record_exec(&entry(8, "/usr/bin/wget"));

        let held = maps.0.lock().unwrap();
        assert_eq!(held.tasks.get(&7), Some(&0b1));
        assert_eq!(held.tasks.get(&8), Some(&0));
        assert_eq!(held.cgroups.get(&4242), Some(&0));
    }

    #[test]
    fn two_rules_about_one_workload_share_a_bit() {
        let maps = SharedMaps::default();
        let service = service(
            vec![
                exe_rule("one", "/usr/bin/curl"),
                exe_rule("two", "/usr/bin/curl"),
            ],
            maps.clone(),
        );

        service.record_exec(&entry(5, "/usr/bin/curl"));

        assert_eq!(maps.0.lock().unwrap().tasks.get(&5), Some(&0b1));
    }

    #[test]
    fn a_task_that_exits_is_forgotten_and_its_cgroup_is_not() {
        let maps = SharedMaps::default();
        let service = service(vec![exe_rule("one", "/usr/bin/curl")], maps.clone());

        service.record_exec(&entry(11, "/usr/bin/curl"));
        service.record_exit(11);

        let held = maps.0.lock().unwrap();
        assert!(!held.tasks.contains_key(&11));
        assert!(held.cgroups.contains_key(&4242));
    }

    #[test]
    fn putting_a_policy_in_force_drops_every_mask_recorded_under_the_last_one() {
        let maps = SharedMaps::default();
        let service = service(vec![exe_rule("one", "/usr/bin/curl")], maps.clone());
        service.record_exec(&entry(3, "/usr/bin/curl"));

        service
            .apply(WorkloadPolicy::new(vec![unit_rule("two", "nginx.service")]).unwrap())
            .expect("the port accepts it");

        let held = maps.0.lock().unwrap();
        assert_eq!(held.published, 1);
        assert!(held.tasks.is_empty());
        assert!(held.cgroups.is_empty());
    }

    #[test]
    fn an_empty_policy_reads_no_cgroup_and_writes_nothing() {
        let maps = SharedMaps::default();
        let service = service(Vec::new(), maps.clone());

        service.record_exec(&entry(1, "/usr/bin/curl"));

        let held = maps.0.lock().unwrap();
        assert!(held.tasks.is_empty());
        assert!(held.cgroups.is_empty());
    }

    #[test]
    fn a_container_carries_its_own_cgroup_path_and_the_enricher_s_name() {
        let maps = SharedMaps::default();
        let service = service(
            vec![
                rule(
                    "one",
                    WorkloadSelector::new(None, None, None, Some("web".to_string()))
                        .expect("a valid name"),
                ),
                rule(
                    "two",
                    WorkloadSelector::new(None, None, Some("/docker".to_string()), None)
                        .expect("a valid path"),
                ),
            ],
            maps.clone(),
        );
        let mut inside = entry(21, "/usr/sbin/nginx");
        inside.container = Some(ContainerContext::with_metadata(
            ContainerInfo::Container {
                container_id: "0123456789abcdef".to_string(),
                runtime: ContainerRuntime::Docker,
                cgroup_path: "/docker/0123456789abcdef".to_string(),
                pid: 21,
            },
            ContainerMetadata::Docker(DockerMetadata {
                name: "web".to_string(),
                image: "nginx".to_string(),
                labels: Vec::new(),
                created_at: String::new(),
                status: String::new(),
            }),
        ));

        service.record_exec(&inside);

        assert_eq!(maps.0.lock().unwrap().cgroups.get(&4242), Some(&0b11));
    }

    fn pod_entry(pid: u32, namespace_labels: Vec<(String, String)>) -> ProcessEntry {
        let mut inside = entry(pid, "/app/api");
        inside.container = Some(ContainerContext::with_metadata(
            ContainerInfo::Container {
                container_id: "fedcba9876543210".to_string(),
                runtime: ContainerRuntime::Containerd,
                cgroup_path: "/kubepods.slice/cri-containerd-fedcba9876543210.scope".to_string(),
                pid,
            },
            ContainerMetadata::Kubernetes(KubernetesMetadata {
                pod_name: "api-7f9".to_string(),
                namespace: "payments".to_string(),
                container_name: "api".to_string(),
                labels: vec![("app".to_string(), "api".to_string())],
                annotations: Vec::new(),
                service_account: "api".to_string(),
                owner_kind: None,
                owner_name: None,
                node_name: "node-1".to_string(),
                namespace_labels,
            }),
        ));
        inside
    }

    #[test]
    fn a_pod_is_matched_by_its_labels_its_namespace_and_its_service_account() {
        let maps = SharedMaps::default();
        let by_labels: LabelSelector =
            serde_json::from_str(r#"{"match_labels":{"app":"api"}}"#).unwrap();
        let payments: LabelSelector =
            serde_json::from_str(r#"{"match_labels":{"kubernetes.io/metadata.name":"payments"}}"#)
                .unwrap();
        let kubernetes = |matchers| {
            WorkloadSelector::with_kubernetes(None, None, None, None, matchers).expect("valid")
        };
        let service = service(
            vec![
                rule(
                    "pods",
                    kubernetes(KubernetesMatchers {
                        pods: Some(by_labels),
                        ..KubernetesMatchers::default()
                    }),
                ),
                rule(
                    "namespace",
                    kubernetes(KubernetesMatchers {
                        namespaces: Some(payments),
                        service_account: Some("api".to_string()),
                        ..KubernetesMatchers::default()
                    }),
                ),
            ],
            maps.clone(),
        );

        // The namespace has not been seen yet: the pod rule holds, the
        // namespace rule waits for the labels rather than guessing.
        service.record_exec(&pod_entry(41, Vec::new()));
        assert_eq!(maps.0.lock().unwrap().cgroups.get(&4242), Some(&0b01));

        let seen = vec![(
            "kubernetes.io/metadata.name".to_string(),
            "payments".to_string(),
        )];
        service.record_exec(&pod_entry(41, seen));
        assert_eq!(maps.0.lock().unwrap().cgroups.get(&4242), Some(&0b11));

        // A host process is in no pod, so neither rule names it.
        service.record_exec(&entry(42, "/app/api"));
        assert_eq!(maps.0.lock().unwrap().cgroups.get(&4242), Some(&0));
    }

    fn labels(app: &str) -> LabelSelector {
        serde_json::from_str(&format!(r#"{{"match_labels":{{"app":"{app}"}}}}"#)).unwrap()
    }

    fn peer_rule(id: &str, from: &str, to: &str) -> WorkloadRule {
        let selector = WorkloadSelector::with_kubernetes(
            None,
            None,
            None,
            None,
            KubernetesMatchers {
                pods: Some(labels(from)),
                ..KubernetesMatchers::default()
            },
        )
        .expect("valid");
        WorkloadRule {
            action: FirewallAction::Allow,
            protocol: Protocol::Tcp,
            dst_peer: Some(PeerSelector {
                pods: Some(labels(to)),
                ..PeerSelector::default()
            }),
            ..rule(id, selector)
        }
    }

    fn remote_pod(address: &str, app: &str) -> RemoteEntry {
        RemoteEntry {
            node: "node-2".to_string(),
            identity: AddressIdentity {
                address: address.parse().unwrap(),
                kind: IdentityKind::Pod,
                container: Some(app.to_string()),
                image: None,
                pod: Some(format!("{app}-0")),
                namespace: Some("payments".to_string()),
                service_account: None,
                guest: None,
                pod_labels: [("app".to_string(), app.to_string())].into(),
                namespace_labels: BTreeMap::new(),
                services: Vec::new(),
            },
        }
    }

    fn remote_list(version: &str) -> RemoteIdentities {
        RemoteIdentities::accept(
            RemoteSnapshot {
                version: version.to_string(),
                entries: vec![remote_pod("10.1.0.5", "db"), remote_pod("10.1.0.6", "api")],
                conflicts: 0,
            },
            1,
        )
        .expect("a valid list")
    }

    #[test]
    fn the_remote_tables_carry_the_slots_each_address_satisfies() {
        let maps = SharedMaps::default();
        let service = service(
            vec![
                peer_rule("api-to-db", "api", "db"),
                peer_rule("db-to-api", "db", "api"),
            ],
            maps.clone(),
        );
        let db: IpAddr = "10.1.0.5".parse().unwrap();
        let api: IpAddr = "10.1.0.6".parse().unwrap();

        service.sync_peers(Some(&remote_list("v1"))).unwrap();
        {
            let held = maps.0.lock().unwrap();
            assert_eq!(held.peer_destinations.get(&db), Some(&0b01));
            assert_eq!(held.peer_destinations.get(&api), Some(&0b10));
            assert_eq!(held.peer_sources.get(&api), Some(&0b01));
            assert_eq!(held.peer_sources.get(&db), Some(&0b10));
            assert_eq!(held.peer_writes, 1);
        }

        // The same list under the same policy writes nothing.
        service.sync_peers(Some(&remote_list("v1"))).unwrap();
        assert_eq!(maps.0.lock().unwrap().peer_writes, 1);

        // A local pod labelled api is the target of the rule reaching api.
        service.record_exec(&pod_entry(41, Vec::new()));
        assert_eq!(maps.0.lock().unwrap().peer_targets.get(&4242), Some(&0b10));

        let status = service.peer_status();
        assert_eq!(status.rules.len(), 2);
        assert!(status.rules.iter().all(|r| r.ends == PeerEnds::Both));
        assert_eq!(status.list_version.as_deref(), Some("v1"));
        assert_eq!((status.destinations, status.sources), (2, 2));

        // A reload empties the tables, and the next sync writes them again.
        service
            .apply(WorkloadPolicy::new(vec![peer_rule("api-to-db", "api", "db")]).unwrap())
            .unwrap();
        assert_eq!(service.peer_status().list_version, None);
        service.sync_peers(Some(&remote_list("v1"))).unwrap();
        let held = maps.0.lock().unwrap();
        assert_eq!(held.peer_writes, 2);
        assert_eq!(held.peer_destinations.get(&db), Some(&0b01));
        assert_eq!(held.peer_destinations.get(&api), None);
    }

    #[test]
    fn no_list_empties_the_remote_tables() {
        let maps = SharedMaps::default();
        let service = service(vec![peer_rule("api-to-db", "api", "db")], maps.clone());
        service.sync_peers(Some(&remote_list("v1"))).unwrap();
        service.sync_peers(None).unwrap();
        let held = maps.0.lock().unwrap();
        assert!(held.peer_destinations.is_empty());
        assert!(held.peer_sources.is_empty());
        assert_eq!(held.peer_writes, 2);
    }

    #[test]
    fn a_source_named_by_executable_is_left_to_the_source_node() {
        let maps = SharedMaps::default();
        let mut by_exe = exe_rule("curl-to-db", "/usr/bin/curl");
        by_exe.action = FirewallAction::Allow;
        by_exe.protocol = Protocol::Tcp;
        by_exe.dst_peer = Some(PeerSelector {
            pods: Some(labels("db")),
            ..PeerSelector::default()
        });
        let service = service(vec![by_exe], maps.clone());
        service.sync_peers(Some(&remote_list("v1"))).unwrap();
        let held = maps.0.lock().unwrap();
        // The source still looks the destination up, the destination reads
        // nothing it could not decide.
        assert_eq!(held.peer_destinations.len(), 1);
        assert!(held.peer_sources.is_empty());
        drop(held);
        let status = service.peer_status();
        assert_eq!(status.rules[0].ends, PeerEnds::Source);
    }

    #[test]
    fn a_host_task_with_no_cgroup_reader_matches_no_unit_rather_than_a_guessed_one() {
        let maps = SharedMaps::default();
        let service = WorkloadPolicyService::new(
            WorkloadPolicy::new(vec![unit_rule("one", "nginx.service")]).unwrap(),
        )
        .with_maps(Box::new(maps.clone()));

        service.record_exec(&entry(31, "/usr/sbin/nginx"));

        // Not even a cleared mask: a task whose cgroup path is unknown says
        // nothing about its cgroup.
        let held = maps.0.lock().unwrap();
        assert_eq!(held.cgroups.get(&4242), None);
        assert_eq!(held.tasks.get(&31), Some(&0));
    }

    #[test]
    fn a_kernel_record_is_named_after_the_rule_sitting_in_its_slot() {
        let mut disabled = exe_rule("off", "/usr/bin/wget");
        disabled.enabled = false;
        let service = service(
            vec![
                exe_rule("one", "/usr/bin/curl"),
                disabled,
                unit_rule("two", "nginx.service"),
            ],
            SharedMaps::default(),
        );

        let named = service
            .name_denial(record(1))
            .expect("the second enabled rule");

        // Slot one is the second *enabled* rule, which is the unit rule: a
        // disabled rule occupies no slot in the kernel's array.
        assert_eq!(named.rule, RuleId("two".to_string()));
        assert_eq!(named.destination.port, 443);
    }

    #[test]
    fn a_record_that_crossed_a_reload_names_nothing_rather_than_the_wrong_rule() {
        let service = service(
            vec![exe_rule("one", "/usr/bin/curl")],
            SharedMaps::default(),
        );

        assert!(service.name_denial(record(7)).is_none());
    }

    #[test]
    fn each_rule_carries_the_count_of_the_slot_it_was_published_in() {
        let maps = SharedMaps::default();
        maps.0.lock().unwrap().denials = vec![4, 9];
        let service = service(
            vec![
                exe_rule("one", "/usr/bin/curl"),
                unit_rule("two", "nginx.service"),
            ],
            maps,
        );

        assert_eq!(
            service.denials_by_rule().expect("the counters are read"),
            vec![
                (RuleId("one".to_string()), 4),
                (RuleId("two".to_string()), 9),
            ]
        );
    }

    #[test]
    fn what_a_workload_may_reach_is_every_rule_naming_it_and_not_the_first() {
        let maps = SharedMaps::default();
        maps.0.lock().unwrap().denials = vec![0, 2];
        let mut allowed = exe_rule("allowed", "/usr/bin/curl");
        allowed.action = FirewallAction::Allow;
        let service = service(
            vec![
                allowed,
                exe_rule("refused", "/usr/bin/curl"),
                exe_rule("other", "/usr/bin/wget"),
            ],
            maps,
        );

        let reach = service
            .reach_for(&WorkloadFacts {
                exe: Some("/usr/bin/curl"),
                ..WorkloadFacts::default()
            })
            .expect("the counters are read");

        assert_eq!(reach.len(), 2);
        assert!(reach[0].allows);
        assert_eq!(reach[0].rule, RuleId("allowed".to_string()));
        assert_eq!(reach[1].rule, RuleId("refused".to_string()));
        assert!(!reach[1].allows);
        assert_eq!(reach[1].denials, 2);
        assert_eq!(reach[1].destination, "to anywhere");
    }

    #[test]
    fn a_disabled_rule_is_absent_from_what_is_in_force_rather_than_listed_as_idle() {
        let maps = SharedMaps::default();
        maps.0.lock().unwrap().denials = vec![3];
        let mut off = unit_rule("off", "nginx.service");
        off.enabled = false;
        let service = service(vec![exe_rule("on", "/usr/bin/curl"), off], maps);

        let in_force = service.rules_in_force().expect("the counters are read");

        assert_eq!(in_force.len(), 1);
        assert_eq!(in_force[0].rule, RuleId("on".to_string()));
        assert_eq!(in_force[0].denials, 3);
    }

    #[test]
    fn a_host_that_loaded_no_object_has_no_figure_rather_than_a_figure_of_zero() {
        let service = WorkloadPolicyService::new(
            WorkloadPolicy::new(vec![exe_rule("one", "/usr/bin/curl")])
                .expect("inside the ceiling"),
        );

        assert!(
            service
                .denials_by_rule()
                .expect("no maps to read")
                .is_empty()
        );
        assert_eq!(
            service
                .reach_for(&WorkloadFacts {
                    exe: Some("/usr/bin/curl"),
                    ..WorkloadFacts::default()
                })
                .expect("no maps to read")
                .len(),
            1
        );
    }

    const RESOLVER: std::net::IpAddr = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 96, 0, 10));

    fn dns_name(out: &mut Vec<u8>, name: &str) {
        for label in name.split('.') {
            out.push(u8::try_from(label.len()).unwrap());
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
    }

    fn dns_query(txid: u16, name: &str) -> Vec<u8> {
        let mut out = txid.to_be_bytes().to_vec();
        out.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        dns_name(&mut out, name);
        out.extend_from_slice(&[0, 1, 0, 1]);
        out
    }

    fn dns_answer(txid: u16, name: &str, addr: [u8; 4], ttl: u32) -> Vec<u8> {
        let mut out = txid.to_be_bytes().to_vec();
        out.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
        dns_name(&mut out, name);
        out.extend_from_slice(&[0, 1, 0, 1]);
        dns_name(&mut out, name);
        out.extend_from_slice(&[0, 1, 0, 1]);
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&[0, 4]);
        out.extend_from_slice(&addr);
        out
    }

    fn dns(cgroup_id: u64, direction: DnsDirection, payload: Vec<u8>, at_ns: u64) -> DnsCapture {
        DnsCapture {
            at_ns,
            cgroup_id,
            direction,
            client_port: 40_000,
            resolver: RESOLVER,
            payload,
        }
    }

    fn named_service(maps: SharedMaps) -> WorkloadPolicyService {
        let mut allowed = unit_rule("api", "nginx.service");
        allowed.action = FirewallAction::Allow;
        allowed.dst_fqdn = vec![FqdnPattern::parse("api.example.com").unwrap()];
        let policy = WorkloadPolicy::new(vec![exe_rule("other", "/usr/bin/curl"), allowed])
            .unwrap()
            .with_dns(WorkloadDnsSettings {
                resolvers: vec![IpNetwork::V4 {
                    addr: u32::from(std::net::Ipv4Addr::new(10, 96, 0, 10)),
                    prefix_len: 32,
                }],
                grace_secs: 30,
            })
            .unwrap();
        WorkloadPolicyService::new(policy)
            .with_maps(Box::new(maps))
            .with_cgroups(Arc::new(StaticCgroup(
                "0::/system.slice/nginx.service\n".to_string(),
            )))
    }

    fn exec_in(pid: u32, cgroup_id: u64) -> ProcessEntry {
        let mut task = entry(pid, "/usr/sbin/nginx");
        task.cgroup_id = cgroup_id;
        task
    }

    #[test]
    fn a_resolved_name_opens_its_address_for_the_cgroup_that_asked_alone() {
        let maps = SharedMaps::default();
        let service = named_service(maps.clone());
        service.record_exec(&exec_in(10, 4242));
        service.record_exec(&exec_in(11, 5555));

        assert_eq!(
            service.observe_dns(&dns(
                4242,
                DnsDirection::Query,
                dns_query(7, "api.example.com"),
                1_000
            )),
            0
        );
        let answer = dns_answer(7, "api.example.com", [203, 0, 113, 7], 60);
        assert_eq!(
            service.observe_dns(&dns(4242, DnsDirection::Response, answer.clone(), 2_000)),
            1
        );
        // The same answer delivered to another pod, which never asked, opens
        // nothing for it.
        assert_eq!(
            service.observe_dns(&dns(5555, DnsDirection::Response, answer, 3_000)),
            0
        );

        let held = maps.0.lock().unwrap();
        assert_eq!(held.grants.len(), 1);
        let (key, expires) = held.grants.iter().next().unwrap();
        assert_eq!(key.cgroup_id, 4242);
        assert_eq!(key.slot, 1);
        assert_eq!(
            key.addr,
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 7))
        );
        assert_eq!(*expires, 2_000 + 90 * 1_000_000_000);
    }

    #[test]
    fn a_cgroup_no_rule_names_learns_nothing_from_its_answers() {
        let maps = SharedMaps::default();
        let service = named_service(maps.clone());
        service.observe_dns(&dns(
            9,
            DnsDirection::Query,
            dns_query(7, "api.example.com"),
            1_000,
        ));
        let answer = dns_answer(7, "api.example.com", [203, 0, 113, 7], 60);
        assert_eq!(
            service.observe_dns(&dns(9, DnsDirection::Response, answer, 2_000)),
            0
        );
        assert!(maps.0.lock().unwrap().grants.is_empty());
    }

    #[test]
    fn a_lapsed_grant_is_swept_and_a_reload_drops_every_grant() {
        let maps = SharedMaps::default();
        let service = named_service(maps.clone());
        service.record_exec(&exec_in(10, 4242));
        service.observe_dns(&dns(
            4242,
            DnsDirection::Query,
            dns_query(1, "api.example.com"),
            0,
        ));
        service.observe_dns(&dns(
            4242,
            DnsDirection::Response,
            dns_answer(1, "api.example.com", [203, 0, 113, 7], 10),
            0,
        ));
        assert_eq!(service.sweep_fqdn(39 * 1_000_000_000), 0);
        assert_eq!(maps.0.lock().unwrap().grants.len(), 1);
        assert_eq!(service.sweep_fqdn(41 * 1_000_000_000), 1);
        assert!(maps.0.lock().unwrap().grants.is_empty());

        service.observe_dns(&dns(
            4242,
            DnsDirection::Query,
            dns_query(2, "api.example.com"),
            0,
        ));
        service.observe_dns(&dns(
            4242,
            DnsDirection::Response,
            dns_answer(2, "api.example.com", [203, 0, 113, 8], 10),
            0,
        ));
        assert_eq!(maps.0.lock().unwrap().grants.len(), 1);
        service.apply(service.policy()).unwrap();
        assert!(maps.0.lock().unwrap().grants.is_empty());
        assert_eq!(service.sweep_fqdn(41 * 1_000_000_000), 0);
    }

    #[test]
    fn the_state_of_a_named_rule_shows_what_resolved_and_what_never_did() {
        let maps = SharedMaps::default();
        let service = named_service(maps);
        let before = service.fqdn_state(0);
        assert_eq!(before.len(), 1);
        assert_eq!(before[0].rule.0, "api");
        assert!(before[0].patterns[0].names.is_empty());

        service.record_exec(&exec_in(10, 4242));
        service.observe_dns(&dns(
            4242,
            DnsDirection::Query,
            dns_query(1, "api.example.com"),
            0,
        ));
        service.observe_dns(&dns(
            4242,
            DnsDirection::Response,
            dns_answer(1, "api.example.com", [203, 0, 113, 7], 10),
            0,
        ));
        let open = service.fqdn_state(1);
        let name = &open[0].patterns[0].names[0];
        assert_eq!(name.name, "api.example.com");
        assert_eq!(name.addresses, 1);
        assert_eq!(name.workloads, 1);
        assert_eq!(name.expires_ns, Some(40 * 1_000_000_000));

        service.sweep_fqdn(41 * 1_000_000_000);
        let lapsed = service.fqdn_state(41 * 1_000_000_000);
        assert_eq!(lapsed[0].patterns[0].names[0].addresses, 0);
        assert_eq!(lapsed[0].patterns[0].names[0].expires_ns, None);
    }

    const LABELLED: &str = "4f1c2a9b8e7d6c5b4a3928170615f4e3d2c1b0a99887766554433221100ffeed";

    fn policy_labels(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn a_labelled_container_adds_its_rules_after_the_configured_ones() {
        let maps = SharedMaps::default();
        let service = service(vec![unit_rule("cfg", "nginx.service")], maps.clone());
        service
            .observe_container(
                LABELLED,
                "web",
                &policy_labels(&[
                    ("io.ebpfsentinel.policy.egress.allow", "tcp/443"),
                    ("io.ebpfsentinel.policy.egress.default", "deny"),
                ]),
            )
            .unwrap();
        let ids: Vec<String> = service
            .policy()
            .rules()
            .iter()
            .map(|r| r.id.0.clone())
            .collect();
        assert_eq!(
            ids,
            [
                "cfg",
                "label-4f1c2a9b8e7d-allow-0",
                "label-4f1c2a9b8e7d-default-0"
            ]
        );
        assert_eq!(maps.0.lock().unwrap().published, 1);

        // A reload of the file keeps the label rules.
        service
            .apply(WorkloadPolicy::new(vec![exe_rule("cfg2", "/usr/bin/curl")]).unwrap())
            .unwrap();
        assert_eq!(service.policy().rules().len(), 3);
        assert_eq!(service.policy().rules()[0].id.0, "cfg2");

        service.forget_container(LABELLED).unwrap();
        assert_eq!(service.policy().rules().len(), 1);
        assert!(service.label_policies().is_empty());
    }

    #[test]
    fn an_unlabelled_or_unchanged_container_does_not_republish() {
        let maps = SharedMaps::default();
        let service = service(Vec::new(), maps.clone());
        service
            .observe_container(LABELLED, "web", &policy_labels(&[("owner", "team")]))
            .unwrap();
        assert_eq!(maps.0.lock().unwrap().published, 0);
        let labels = policy_labels(&[("io.ebpfsentinel.policy.egress.deny", "tcp/25")]);
        service.observe_container(LABELLED, "web", &labels).unwrap();
        service.observe_container(LABELLED, "web", &labels).unwrap();
        assert_eq!(maps.0.lock().unwrap().published, 1);
        service.forget_container("not-labelled").unwrap();
        assert_eq!(maps.0.lock().unwrap().published, 1);
    }

    #[test]
    fn unreadable_labels_are_reported_and_put_nothing_in_force() {
        let service = service(Vec::new(), SharedMaps::default());
        service
            .observe_container(
                LABELLED,
                "web",
                &policy_labels(&[("io.ebpfsentinel.policy.mode", "block")]),
            )
            .unwrap();
        assert!(service.policy().is_empty());
        let report = service.label_policies();
        assert_eq!(report.len(), 1);
        assert_eq!(report[0].container_name, "web");
        assert_eq!(report[0].problems[0].label, "io.ebpfsentinel.policy.mode");
    }

    #[test]
    fn a_container_past_the_ceiling_is_refused_whole() {
        let configured: Vec<WorkloadRule> = (0..60)
            .map(|i| unit_rule(&format!("cfg-{i}"), "nginx.service"))
            .collect();
        let service = service(configured, SharedMaps::default());
        let list = (1..=5)
            .map(|port| format!("tcp/{port}"))
            .collect::<Vec<_>>()
            .join(",");
        service
            .observe_container(
                LABELLED,
                "web",
                &policy_labels(&[("io.ebpfsentinel.policy.egress.allow", &list)]),
            )
            .unwrap();
        assert_eq!(service.policy().rules().len(), 60);
        let report = service.label_policies();
        assert!(report[0].rules.is_empty());
        assert!(
            report[0].problems[0]
                .reason
                .contains("as many workload rules")
        );
    }

    #[test]
    fn a_reconciliation_replaces_what_the_events_left() {
        let maps = SharedMaps::default();
        let service = service(Vec::new(), maps.clone());
        service
            .observe_container(
                LABELLED,
                "old",
                &policy_labels(&[("io.ebpfsentinel.policy.egress.deny", "tcp/25")]),
            )
            .unwrap();
        let other = "aaaaaaaaaaaabbbbbbbbbbbbccccccccccccddddddddddddeeeeeeeeeeeeffff".to_string();
        let containers = vec![(
            other.clone(),
            "new".to_string(),
            policy_labels(&[("io.ebpfsentinel.policy.egress.deny", "udp/53")]),
        )];
        service.reconcile_containers(&containers).unwrap();
        let report = service.label_policies();
        assert_eq!(report.len(), 1);
        assert_eq!(report[0].container_id, other);
        let published = maps.0.lock().unwrap().published;
        service.reconcile_containers(&containers).unwrap();
        assert_eq!(maps.0.lock().unwrap().published, published);
    }
}
