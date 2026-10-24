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

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, RwLock, Weak};

use domain::common::entity::RuleId;
use domain::common::error::DomainError;
use domain::container::engine::CgroupReader;
use domain::container::entity::{ContainerInfo, ContainerMetadata};
use domain::firewall::fqdn::{
    DnsCapture, FqdnGrantKey, FqdnLearner, FqdnLedger, FqdnPatternReport,
};
use domain::firewall::workload::{
    WorkloadDenial, WorkloadDenialRecord, WorkloadFacts, WorkloadPolicy, WorkloadReach,
    cgroup_path_of, unit_of,
};
use domain::process::entity::ProcessEntry;
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
    /// systemd unit, derived from the cgroup path.
    pub unit: Option<String>,
    /// Absolute cgroup v2 path.
    pub cgroup: Option<String>,
    /// Container id in full.
    pub container_id: Option<String>,
    /// Container name, where an enricher read one.
    pub container_name: Option<String>,
}

impl ResolvedWorkload {
    /// The borrowed form a selector is matched against.
    #[must_use]
    pub fn facts(&self) -> WorkloadFacts<'_> {
        WorkloadFacts {
            exe: self.exe.as_deref(),
            unit: self.unit.as_deref(),
            cgroup: self.cgroup.as_deref(),
            container_id: self.container_id.as_deref(),
            container_name: self.container_name.as_deref(),
        }
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

/// Keeps the kernel's view of which workload is which.
pub struct WorkloadPolicyService {
    policy: RwLock<WorkloadPolicy>,
    maps: Option<Mutex<Box<dyn WorkloadPolicyMapPort>>>,
    /// The cgroup mask each cgroup was last written, by cgroup id.
    cgroup_masks: Mutex<HashMap<u64, u64>>,
    /// Taken before the policy and the maps, by every path that touches a
    /// grant, so a reload and an answer never interleave.
    fqdn: Mutex<FqdnState>,
    cgroups: Option<Arc<dyn CgroupReader>>,
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
            policy: RwLock::new(policy),
            maps: None,
            cgroup_masks: Mutex::new(HashMap::new()),
            fqdn: Mutex::new(fqdn),
            cgroups: None,
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
            if !selector.matches(facts) {
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
        if entry.cgroup_id != 0 {
            let mut known = self
                .cgroup_masks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if masks.cgroup == 0 {
                known.remove(&entry.cgroup_id);
            } else {
                known.insert(entry.cgroup_id, masks.cgroup);
            }
        }
        let mut maps = maps
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if entry.cgroup_id != 0
            && let Err(err) = maps.set_cgroup_selectors(entry.cgroup_id, masks.cgroup)
        {
            warn!(pid = entry.pid, error = %err, "a cgroup's workload selectors were not written");
        }
        if let Err(err) = maps.set_task_selectors(entry.pid, masks.task) {
            warn!(pid = entry.pid, error = %err, "a task's workload selectors were not written");
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
        Ok(policy
            .in_slot_order()
            .enumerate()
            .filter(|(_, rule)| facts.is_none_or(|facts| rule.selector.matches(facts)))
            .map(|(slot, rule)| WorkloadReach {
                rule: rule.id.clone(),
                allows: !rule.refuses(),
                mode: rule.mode,
                selector: rule.selector.describe(),
                destination: rule.describe_destination(),
                denials: counts.get(slot).copied().unwrap_or(0),
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
        ContainerContext, ContainerInfo, ContainerRuntime, DockerMetadata,
    };
    use domain::firewall::entity::{FirewallAction, IpNetwork};
    use domain::firewall::fqdn::{DnsDirection, FqdnPattern, WorkloadDnsSettings};
    use domain::firewall::workload::{
        DestinationAddr, WorkloadDestination, WorkloadHook, WorkloadMode, WorkloadRule,
        WorkloadSelector,
    };
    use domain::process::entity::ProcessIdentity;

    use super::*;

    #[derive(Default)]
    struct RecordingMaps {
        cgroups: HashMap<u64, u64>,
        tasks: HashMap<u32, u64>,
        published: usize,
        denials: Vec<u64>,
        grants: HashMap<FqdnGrantKey, u64>,
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
    }

    struct StaticCgroup(String);

    impl CgroupReader for StaticCgroup {
        fn read_cgroup(&self, _pid: u32) -> io::Result<String> {
            Ok(self.0.clone())
        }
    }

    fn rule(id: &str, selector: WorkloadSelector) -> WorkloadRule {
        WorkloadRule {
            id: RuleId(id.to_string()),
            priority: 10,
            action: FirewallAction::Deny,
            mode: WorkloadMode::Observe,
            selector,
            protocol: Protocol::Any,
            dst_ip: None,
            dst_port: None,
            dst_fqdn: Vec::new(),
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

    #[test]
    fn a_host_task_with_no_cgroup_reader_matches_no_unit_rather_than_a_guessed_one() {
        let maps = SharedMaps::default();
        let service = WorkloadPolicyService::new(
            WorkloadPolicy::new(vec![unit_rule("one", "nginx.service")]).unwrap(),
        )
        .with_maps(Box::new(maps.clone()));

        service.record_exec(&entry(31, "/usr/sbin/nginx"));

        assert_eq!(maps.0.lock().unwrap().cgroups.get(&4242), Some(&0));
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
}
