//! Holding the traffic a workload sends to a rate, by its cgroup.
//!
//! The egress shaper spaces each shaped cgroup's packets by setting their
//! departure time, and the `fq` qdisc is what holds a packet until then. So
//! this service compiles two things into the kernel: which cgroups carry a
//! rate, decided here by matching every cgroup the process table reports
//! against the rules, and which interfaces the shaper may act on at all,
//! which are those whose qdiscs honour a departure time. On any other
//! interface the shaper stands aside rather than setting a timestamp nobody
//! reads, so a rule there is reported as not applied instead of passing for
//! one that holds.
//!
//! What was achieved is read back from the datapath's own per-cgroup
//! counters on every poll, and the rate is the difference between two
//! readings, so a figure is only ever what the kernel counted leaving.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, PoisonError};

use domain::container::engine::CgroupReader;
use domain::firewall::workload::{cgroup_path_of, unit_of};
use domain::process::entity::ProcessEntry;
use domain::qos::cgroup_shaping::{
    CgroupShapingCounters, CgroupShapingRule, achieved_bps, edt_support, rule_for,
};
use ports::secondary::ids_workload_scope_port::WorkloadLinkSink;
use ports::secondary::metrics_port::PacketMetrics;
use ports::secondary::qos_cgroup_shaping_port::{QdiscReaderPort, QosCgroupShapingMapPort};
use tracing::{debug, warn};

use crate::workload_policy_service::{ResolvedWorkload, workload_of};

/// One interface the agent attaches to, and whether the shaper acts there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceShaping {
    pub name: String,
    /// `None` when the interface could not be read.
    pub ifindex: Option<u32>,
    /// The root qdisc's kind, `none` when the interface has no root qdisc.
    pub root_qdisc: Option<String>,
    /// Whether a departure time is honoured here, which is whether the
    /// shaper acts on packets leaving this interface.
    pub honoured: bool,
    /// Why the interface could not be read.
    pub error: Option<String>,
}

/// One cgroup the shaper holds to a rate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShapedCgroup {
    pub cgroup_id: u64,
    pub rule_id: String,
    pub rate_bps: u64,
    /// The cgroup's path, where it was read.
    pub cgroup: Option<String>,
    /// The container's name, or its id when no name was read.
    pub container: Option<String>,
    /// What the datapath counted for it since its rate was written.
    pub counters: CgroupShapingCounters,
    /// What it sent between the last two readings, in bits per second;
    /// `None` until two readings exist.
    pub achieved_bps: Option<u64>,
}

/// What the service answers about cgroup shaping.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CgroupShapingReport {
    /// Whether the shaper's tables are installed, which is whether the
    /// loaded tc-qos object carries them.
    pub supported: bool,
    /// Whether a rule is in force on at least one interface.
    pub active: bool,
    pub rules: Vec<CgroupShapingRule>,
    pub interfaces: Vec<InterfaceShaping>,
    pub cgroups: Vec<ShapedCgroup>,
    /// Why the last reading of the counters failed, `None` when it did not.
    pub read_error: Option<String>,
}

/// One cgroup the process table told this service about.
#[derive(Debug)]
struct SeenCgroup {
    workload: ResolvedWorkload,
    tasks: usize,
}

/// The counters as they stood at one poll.
#[derive(Debug, Default)]
struct Reading {
    at_ns: u64,
    counters: HashMap<u64, CgroupShapingCounters>,
}

#[derive(Debug, Default)]
struct ShapingState {
    rules: Vec<CgroupShapingRule>,
    interface_names: Vec<String>,
    interfaces: Vec<InterfaceShaping>,
    cgroups: HashMap<u64, SeenCgroup>,
    /// Which cgroup a recorded pid was counted against, so an exit
    /// decrements the entry its exec incremented.
    pids: HashMap<u32, u64>,
    links: HashMap<u32, u64>,
    published_links: Option<Vec<(u32, u64)>>,
    published_shapes: Option<Vec<(u64, u64, u64)>>,
    published_interfaces: Option<Vec<u32>>,
    last_reading: Option<Reading>,
    achieved: HashMap<u64, u64>,
    read_error: Option<String>,
}

impl ShapingState {
    fn wanted_links(&self) -> Vec<(u32, u64)> {
        let mut links: Vec<(u32, u64)> = self.links.iter().map(|(&i, &c)| (i, c)).collect();
        links.sort_unstable();
        links
    }

    fn rule_of(&self, cgroup_id: u64) -> Option<&CgroupShapingRule> {
        let seen = self.cgroups.get(&cgroup_id)?;
        rule_for(&self.rules, &seen.workload.facts())
    }

    fn wanted_shapes(&self) -> Vec<(u64, u64, u64)> {
        let mut shapes: Vec<(u64, u64, u64)> = self
            .cgroups
            .keys()
            .filter_map(|&cgroup_id| {
                self.rule_of(cgroup_id)
                    .map(|rule| (cgroup_id, rule.rate_bps, rule.horizon_ns()))
            })
            .collect();
        shapes.sort_unstable();
        shapes
    }

    fn wanted_interfaces(&self) -> Vec<u32> {
        if self.rules.is_empty() {
            return Vec::new();
        }
        let mut ifindexes: Vec<u32> = self
            .interfaces
            .iter()
            .filter(|iface| iface.honoured)
            .filter_map(|iface| iface.ifindex)
            .collect();
        ifindexes.sort_unstable();
        ifindexes.dedup();
        ifindexes
    }
}

/// Keeps the per-cgroup rates written in the kernel and reads back what
/// they achieved.
pub struct QosCgroupShapingService {
    maps: Mutex<Option<Box<dyn QosCgroupShapingMapPort>>>,
    qdiscs: Option<Arc<dyn QdiscReaderPort>>,
    cgroups_reader: Option<Arc<dyn CgroupReader>>,
    metrics: Option<Arc<dyn PacketMetrics>>,
    state: Mutex<ShapingState>,
}

impl Default for QosCgroupShapingService {
    fn default() -> Self {
        Self::new()
    }
}

impl QosCgroupShapingService {
    /// A service with no rules, no interfaces and no maps.
    #[must_use]
    pub fn new() -> Self {
        Self {
            maps: Mutex::new(None),
            qdiscs: None,
            cgroups_reader: None,
            metrics: None,
            state: Mutex::new(ShapingState::default()),
        }
    }

    /// Read each interface's qdiscs through `reader`. Without one, no
    /// interface is known to honour a departure time and nothing is shaped.
    #[must_use]
    pub fn with_qdiscs(mut self, reader: Arc<dyn QdiscReaderPort>) -> Self {
        self.qdiscs = Some(reader);
        self
    }

    /// Read the cgroup path of a host task through `reader`, so a rule
    /// naming a unit or a cgroup can match a process outside any container.
    #[must_use]
    pub fn with_cgroups(mut self, reader: Arc<dyn CgroupReader>) -> Self {
        self.cgroups_reader = Some(reader);
        self
    }

    /// Report what each rule's cgroups sent through `metrics`.
    #[must_use]
    pub fn with_metrics(mut self, metrics: Arc<dyn PacketMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Install the kernel tables and write everything known into them.
    ///
    /// Called again when tc-qos is loaded again, with tables that may be
    /// empty, which is why the whole state is written rather than a diff.
    pub fn set_maps(&self, maps: Box<dyn QosCgroupShapingMapPort>) {
        *self.maps.lock().unwrap_or_else(PoisonError::into_inner) = Some(maps);
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.published_links = None;
        state.published_shapes = None;
        state.published_interfaces = None;
        state.last_reading = None;
        state.achieved.clear();
        self.publish(&mut state);
    }

    /// Drop the kernel tables, because the program that read them is gone.
    pub fn clear_maps(&self) {
        *self.maps.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }

    /// Whether the loaded tc-qos object carries the shaper's tables.
    #[must_use]
    pub fn supported(&self) -> bool {
        self.maps
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
    }

    /// Replace the rules. They are expected to be validated already.
    pub fn set_rules(&self, rules: Vec<CgroupShapingRule>) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.rules = rules;
        self.publish(&mut state);
    }

    /// Replace the interfaces the shaper is attached to, and read whether
    /// each one honours a departure time.
    pub fn set_interfaces(&self, names: Vec<String>) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.interface_names = names;
        self.refresh_interfaces(&mut state);
        self.publish(&mut state);
    }

    /// Learn the cgroup a recorded task runs in, and what it is.
    ///
    /// Recording the same pid again refreshes what the cgroup is without
    /// counting the task twice.
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

    /// Read the qdiscs again, write what changed, and read the counters.
    ///
    /// `now_ns` is a monotonic clock in nanoseconds; the achieved rate is
    /// the bytes counted between two polls over the time between them.
    pub fn poll(&self, now_ns: u64) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        self.refresh_interfaces(&mut state);
        self.publish(&mut state);

        let read = {
            let maps = self.maps.lock().unwrap_or_else(PoisonError::into_inner);
            match maps.as_ref() {
                Some(maps) => maps.read_counters(),
                None => return,
            }
        };
        let counters: HashMap<u64, CgroupShapingCounters> = match read {
            Ok(counters) => counters.into_iter().collect(),
            Err(err) => {
                warn!(error = %err, "cgroup shaping counters unreadable");
                state.read_error = Some(err.to_string());
                return;
            }
        };
        state.read_error = None;
        self.account(&mut state, now_ns, counters);
    }

    /// Fold one reading of the counters into the achieved rates and the
    /// metrics, against the reading before it.
    fn account(
        &self,
        state: &mut ShapingState,
        now_ns: u64,
        counters: HashMap<u64, CgroupShapingCounters>,
    ) {
        let mut per_rule: BTreeMap<String, (u64, u64)> = BTreeMap::new();
        let mut achieved = HashMap::new();
        for (&cgroup_id, after) in &counters {
            let Some(rule) = state.rule_of(cgroup_id) else {
                continue;
            };
            let before = state
                .last_reading
                .as_ref()
                .and_then(|last| last.counters.get(&cgroup_id).map(|c| (last.at_ns, *c)));
            let entry = per_rule.entry(rule.id.clone()).or_default();
            if let Some((at_ns, before)) = before {
                // A count that went backwards is an entry removed and
                // created again, so everything in it is new.
                let (bytes, dropped) = if after.bytes < before.bytes {
                    (after.bytes, after.dropped_horizon)
                } else {
                    (
                        after.bytes - before.bytes,
                        after.dropped_horizon.saturating_sub(before.dropped_horizon),
                    )
                };
                entry.0 = entry.0.saturating_add(bytes);
                entry.1 = entry.1.saturating_add(dropped);
                if let Some(bps) = achieved_bps(before.bytes, at_ns, after.bytes, now_ns) {
                    achieved.insert(cgroup_id, bps);
                }
            } else {
                entry.0 = entry.0.saturating_add(after.bytes);
                entry.1 = entry.1.saturating_add(after.dropped_horizon);
            }
        }

        if let Some(metrics) = &self.metrics {
            for (rule_id, (bytes, dropped)) in &per_rule {
                if *bytes > 0 || *dropped > 0 {
                    metrics.record_cgroup_shaping(rule_id, *bytes, *dropped);
                }
            }
            if let Some(last) = &state.last_reading {
                let elapsed = now_ns.saturating_sub(last.at_ns);
                for rule in &state.rules {
                    let bytes = per_rule.get(&rule.id).map_or(0, |(bytes, _)| *bytes);
                    if let Some(bps) = achieved_bps(0, 0, bytes, elapsed) {
                        metrics.set_cgroup_shaping_achieved(&rule.id, bps);
                    }
                }
            }
        }

        state.achieved = achieved;
        state.last_reading = Some(Reading {
            at_ns: now_ns,
            counters,
        });
    }

    /// What is shaped, where, and what it achieved.
    #[must_use]
    pub fn report(&self) -> CgroupShapingReport {
        let supported = self.supported();
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let mut cgroups: Vec<ShapedCgroup> = state
            .cgroups
            .iter()
            .filter_map(|(&cgroup_id, seen)| {
                let rule = state.rule_of(cgroup_id)?;
                let counters = state
                    .last_reading
                    .as_ref()
                    .and_then(|last| last.counters.get(&cgroup_id).copied())
                    .unwrap_or_default();
                Some(ShapedCgroup {
                    cgroup_id,
                    rule_id: rule.id.clone(),
                    rate_bps: rule.rate_bps,
                    cgroup: seen.workload.cgroup.clone(),
                    container: seen
                        .workload
                        .container_name
                        .clone()
                        .or_else(|| seen.workload.container_id.clone()),
                    counters,
                    achieved_bps: state.achieved.get(&cgroup_id).copied(),
                })
            })
            .collect();
        cgroups.sort_by_key(|shaped| shaped.cgroup_id);
        CgroupShapingReport {
            supported,
            active: supported && !state.wanted_interfaces().is_empty(),
            rules: state.rules.clone(),
            interfaces: state.interfaces.clone(),
            cgroups,
            read_error: state.read_error.clone(),
        }
    }

    fn release(state: &mut ShapingState, cgroup_id: u64) {
        if let Some(seen) = state.cgroups.get_mut(&cgroup_id) {
            seen.tasks = seen.tasks.saturating_sub(1);
            if seen.tasks == 0 {
                state.cgroups.remove(&cgroup_id);
            }
        }
    }

    fn resolve(&self, entry: &ProcessEntry) -> ResolvedWorkload {
        let mut resolved = workload_of(entry);
        // A rate belongs to a cgroup, never to one task in it.
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

    fn refresh_interfaces(&self, state: &mut ShapingState) {
        state.interfaces = state
            .interface_names
            .iter()
            .map(|name| match &self.qdiscs {
                None => InterfaceShaping {
                    name: name.clone(),
                    ifindex: None,
                    root_qdisc: None,
                    honoured: false,
                    error: Some("qdiscs are not readable on this agent".to_string()),
                },
                Some(reader) => match reader.qdiscs(name) {
                    Ok((ifindex, entries)) => {
                        let support = edt_support(&entries);
                        InterfaceShaping {
                            name: name.clone(),
                            ifindex: Some(ifindex),
                            root_qdisc: Some(support.root),
                            honoured: support.honoured,
                            error: None,
                        }
                    }
                    Err(err) => InterfaceShaping {
                        name: name.clone(),
                        ifindex: None,
                        root_qdisc: None,
                        honoured: false,
                        error: Some(err.to_string()),
                    },
                },
            })
            .collect();
    }

    fn publish(&self, state: &mut ShapingState) {
        let mut maps = self.maps.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(maps) = maps.as_mut() else {
            return;
        };
        let links = state.wanted_links();
        if state.published_links.as_ref() != Some(&links) {
            match maps.publish_links(&links) {
                Ok(()) => state.published_links = Some(links),
                Err(err) => warn!(error = %err, "shaper link table write failed"),
            }
        }
        let shapes = state.wanted_shapes();
        if state.published_shapes.as_ref() != Some(&shapes) {
            match maps.publish_shapes(&shapes) {
                Ok(()) => state.published_shapes = Some(shapes),
                Err(err) => warn!(error = %err, "cgroup rate table write failed"),
            }
        }
        let interfaces = state.wanted_interfaces();
        if state.published_interfaces.as_ref() != Some(&interfaces) {
            match maps.publish_interfaces(&interfaces) {
                Ok(()) => state.published_interfaces = Some(interfaces),
                Err(err) => warn!(error = %err, "shaper interface table write failed"),
            }
        }
    }
}

impl WorkloadLinkSink for QosCgroupShapingService {
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

/// Hands every link the watcher reports to each of several sinks, so the
/// IDS scope and the shaper keep their own link tables from one watcher.
pub struct WorkloadLinkFanout(Vec<Arc<dyn WorkloadLinkSink>>);

impl WorkloadLinkFanout {
    #[must_use]
    pub fn new(sinks: Vec<Arc<dyn WorkloadLinkSink>>) -> Self {
        Self(sinks)
    }
}

impl WorkloadLinkSink for WorkloadLinkFanout {
    fn link_owned(&self, ifindex: u32, cgroup_id: u64) {
        for sink in &self.0 {
            sink.link_owned(ifindex, cgroup_id);
        }
    }

    fn link_gone(&self, ifindex: u32) {
        for sink in &self.0 {
            sink.link_gone(ifindex);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use domain::common::error::DomainError;
    use domain::container::entity::{ContainerContext, ContainerInfo, ContainerRuntime};
    use domain::firewall::workload::WorkloadSelector;
    use domain::qos::cgroup_shaping::{QdiscEntry, TC_H_ROOT};

    #[derive(Default)]
    struct Recorded {
        links: Vec<(u32, u64)>,
        shapes: Vec<(u64, u64, u64)>,
        interfaces: Vec<u32>,
        shape_writes: usize,
        counters: Vec<(u64, CgroupShapingCounters)>,
        refuse_read: bool,
    }

    struct FakeMaps(Arc<Mutex<Recorded>>);

    impl QosCgroupShapingMapPort for FakeMaps {
        fn publish_links(&mut self, links: &[(u32, u64)]) -> Result<(), DomainError> {
            self.0.lock().unwrap().links = links.to_vec();
            Ok(())
        }

        fn publish_shapes(&mut self, shapes: &[(u64, u64, u64)]) -> Result<(), DomainError> {
            let mut recorded = self.0.lock().unwrap();
            recorded.shapes = shapes.to_vec();
            recorded.shape_writes += 1;
            Ok(())
        }

        fn publish_interfaces(&mut self, ifindexes: &[u32]) -> Result<(), DomainError> {
            self.0.lock().unwrap().interfaces = ifindexes.to_vec();
            Ok(())
        }

        fn read_counters(&self) -> Result<Vec<(u64, CgroupShapingCounters)>, DomainError> {
            let recorded = self.0.lock().unwrap();
            if recorded.refuse_read {
                return Err(DomainError::EngineError("map gone".to_string()));
            }
            Ok(recorded.counters.clone())
        }
    }

    /// `eth0` carries `fq`, `eth1` the default `pfifo_fast`, `eth9` is gone.
    struct FakeQdiscs;

    impl QdiscReaderPort for FakeQdiscs {
        fn qdiscs(&self, interface: &str) -> Result<(u32, Vec<QdiscEntry>), DomainError> {
            let kind = match interface {
                "eth0" => "fq",
                "eth1" => "pfifo_fast",
                _ => return Err(DomainError::EngineError(format!("no {interface}"))),
            };
            let ifindex = if interface == "eth0" { 2 } else { 3 };
            Ok((
                ifindex,
                vec![QdiscEntry {
                    handle: 0x8001_0000,
                    parent: TC_H_ROOT,
                    kind: kind.to_string(),
                }],
            ))
        }
    }

    #[derive(Default)]
    struct FakeMetrics {
        shaped: Mutex<Vec<(String, u64, u64)>>,
        achieved: Mutex<Vec<(String, u64)>>,
    }

    impl PacketMetrics for FakeMetrics {
        fn record_cgroup_shaping(&self, rule_id: &str, bytes: u64, dropped_horizon: u64) {
            self.shaped
                .lock()
                .unwrap()
                .push((rule_id.to_string(), bytes, dropped_horizon));
        }

        fn set_cgroup_shaping_achieved(&self, rule_id: &str, bps: u64) {
            self.achieved
                .lock()
                .unwrap()
                .push((rule_id.to_string(), bps));
        }
    }

    fn service() -> (
        QosCgroupShapingService,
        Arc<Mutex<Recorded>>,
        Arc<FakeMetrics>,
    ) {
        let recorded = Arc::new(Mutex::new(Recorded::default()));
        let metrics = Arc::new(FakeMetrics::default());
        let svc = QosCgroupShapingService::new()
            .with_qdiscs(Arc::new(FakeQdiscs))
            .with_metrics(Arc::clone(&metrics) as Arc<dyn PacketMetrics>);
        svc.set_maps(Box::new(FakeMaps(Arc::clone(&recorded))));
        svc.set_interfaces(vec!["eth0".to_string()]);
        (svc, recorded, metrics)
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

    fn rule(id: &str, cgroup: &str, rate_bps: u64) -> CgroupShapingRule {
        CgroupShapingRule {
            id: id.to_string(),
            selector: WorkloadSelector::new(None, None, Some(cgroup.to_string()), None).unwrap(),
            rate_bps,
            horizon_ms: 2_000,
        }
    }

    const SECOND: u64 = 1_000_000_000;

    #[test]
    fn a_matching_cgroup_carries_its_rule_rate() {
        let (svc, recorded, _) = service();
        svc.set_rules(vec![rule(
            "web",
            "/system.slice/docker-web.scope",
            8_000_000,
        )]);
        svc.record_exec(&container_entry(10, 100, "web"));
        svc.record_exec(&container_entry(11, 200, "db"));
        assert_eq!(
            recorded.lock().unwrap().shapes,
            vec![(100, 8_000_000, 2_000_000_000)]
        );
    }

    #[test]
    fn the_first_matching_rule_wins() {
        let (svc, recorded, _) = service();
        svc.set_rules(vec![
            rule("narrow", "/system.slice/docker-web.scope", 1_000_000),
            rule("wide", "/system.slice", 9_000_000),
        ]);
        svc.record_exec(&container_entry(10, 100, "web"));
        svc.record_exec(&container_entry(11, 200, "db"));
        assert_eq!(
            recorded.lock().unwrap().shapes,
            vec![
                (100, 1_000_000, 2_000_000_000),
                (200, 9_000_000, 2_000_000_000)
            ]
        );
    }

    #[test]
    fn the_rate_goes_with_the_last_task_of_the_cgroup() {
        let (svc, recorded, _) = service();
        svc.set_rules(vec![rule(
            "web",
            "/system.slice/docker-web.scope",
            8_000_000,
        )]);
        svc.record_exec(&container_entry(10, 100, "web"));
        svc.record_exec(&container_entry(11, 100, "web"));
        svc.record_exit(10);
        assert_eq!(recorded.lock().unwrap().shapes.len(), 1);
        svc.record_exit(11);
        assert!(recorded.lock().unwrap().shapes.is_empty());
    }

    #[test]
    fn an_unchanged_table_is_not_written_again() {
        let (svc, recorded, _) = service();
        svc.set_rules(vec![rule(
            "web",
            "/system.slice/docker-web.scope",
            8_000_000,
        )]);
        svc.record_exec(&container_entry(10, 100, "web"));
        let writes = recorded.lock().unwrap().shape_writes;
        svc.record_exec(&container_entry(11, 100, "web"));
        assert_eq!(recorded.lock().unwrap().shape_writes, writes);
    }

    #[test]
    fn only_an_interface_honouring_departure_times_is_shaped() {
        let (svc, recorded, _) = service();
        svc.set_interfaces(vec![
            "eth0".to_string(),
            "eth1".to_string(),
            "eth9".to_string(),
        ]);
        assert!(recorded.lock().unwrap().interfaces.is_empty());

        svc.set_rules(vec![rule("web", "/system.slice", 8_000_000)]);
        assert_eq!(recorded.lock().unwrap().interfaces, vec![2]);

        let report = svc.report();
        assert!(report.active);
        let by_name: Vec<(&str, bool)> = report
            .interfaces
            .iter()
            .map(|iface| (iface.name.as_str(), iface.honoured))
            .collect();
        assert_eq!(
            by_name,
            vec![("eth0", true), ("eth1", false), ("eth9", false)]
        );
        assert_eq!(
            report.interfaces[1].root_qdisc.as_deref(),
            Some("pfifo_fast")
        );
        assert!(report.interfaces[2].error.is_some());
    }

    #[test]
    fn rules_on_no_honouring_interface_are_reported_inactive() {
        let (svc, recorded, _) = service();
        svc.set_interfaces(vec!["eth1".to_string()]);
        svc.set_rules(vec![rule("web", "/system.slice", 8_000_000)]);
        assert!(recorded.lock().unwrap().interfaces.is_empty());
        assert!(!svc.report().active);
    }

    #[test]
    fn without_a_qdisc_reader_nothing_is_shaped() {
        let recorded = Arc::new(Mutex::new(Recorded::default()));
        let svc = QosCgroupShapingService::new();
        svc.set_maps(Box::new(FakeMaps(Arc::clone(&recorded))));
        svc.set_interfaces(vec!["eth0".to_string()]);
        svc.set_rules(vec![rule("web", "/system.slice", 8_000_000)]);
        assert!(recorded.lock().unwrap().interfaces.is_empty());
        assert!(svc.report().interfaces[0].error.is_some());
    }

    #[test]
    fn the_achieved_rate_is_the_difference_between_two_readings() {
        let (svc, recorded, metrics) = service();
        svc.set_rules(vec![rule(
            "web",
            "/system.slice/docker-web.scope",
            8_000_000,
        )]);
        svc.record_exec(&container_entry(10, 100, "web"));

        recorded.lock().unwrap().counters = vec![(
            100,
            CgroupShapingCounters {
                bytes: 1_000,
                packets: 1,
                dropped_horizon: 0,
            },
        )];
        svc.poll(SECOND);
        assert_eq!(svc.report().cgroups[0].achieved_bps, None);

        recorded.lock().unwrap().counters = vec![(
            100,
            CgroupShapingCounters {
                bytes: 1_001_000,
                packets: 700,
                dropped_horizon: 3,
            },
        )];
        svc.poll(2 * SECOND);
        let report = svc.report();
        assert_eq!(report.cgroups[0].achieved_bps, Some(8_000_000));
        assert_eq!(report.cgroups[0].counters.packets, 700);
        assert_eq!(report.cgroups[0].rule_id, "web");

        assert_eq!(
            *metrics.shaped.lock().unwrap(),
            vec![
                ("web".to_string(), 1_000, 0),
                ("web".to_string(), 1_000_000, 3)
            ]
        );
        assert_eq!(
            *metrics.achieved.lock().unwrap(),
            vec![("web".to_string(), 8_000_000)]
        );
    }

    #[test]
    fn a_counter_that_went_backwards_counts_from_zero() {
        let (svc, recorded, metrics) = service();
        svc.set_rules(vec![rule(
            "web",
            "/system.slice/docker-web.scope",
            8_000_000,
        )]);
        svc.record_exec(&container_entry(10, 100, "web"));
        recorded.lock().unwrap().counters = vec![(
            100,
            CgroupShapingCounters {
                bytes: 5_000,
                ..CgroupShapingCounters::default()
            },
        )];
        svc.poll(SECOND);
        recorded.lock().unwrap().counters = vec![(
            100,
            CgroupShapingCounters {
                bytes: 200,
                ..CgroupShapingCounters::default()
            },
        )];
        svc.poll(2 * SECOND);
        assert_eq!(
            metrics.shaped.lock().unwrap().last(),
            Some(&("web".to_string(), 200, 0))
        );
        assert_eq!(svc.report().cgroups[0].achieved_bps, None);
    }

    #[test]
    fn a_failed_reading_is_reported_and_keeps_the_last_one() {
        let (svc, recorded, _) = service();
        svc.set_rules(vec![rule(
            "web",
            "/system.slice/docker-web.scope",
            8_000_000,
        )]);
        svc.record_exec(&container_entry(10, 100, "web"));
        recorded.lock().unwrap().counters = vec![(
            100,
            CgroupShapingCounters {
                bytes: 5_000,
                ..CgroupShapingCounters::default()
            },
        )];
        svc.poll(SECOND);
        recorded.lock().unwrap().refuse_read = true;
        svc.poll(2 * SECOND);
        let report = svc.report();
        assert!(report.read_error.is_some());
        assert_eq!(report.cgroups[0].counters.bytes, 5_000);
    }

    #[test]
    fn new_maps_receive_everything_known() {
        let svc = QosCgroupShapingService::new().with_qdiscs(Arc::new(FakeQdiscs));
        assert!(!svc.supported());
        svc.set_interfaces(vec!["eth0".to_string()]);
        svc.set_rules(vec![rule(
            "web",
            "/system.slice/docker-web.scope",
            8_000_000,
        )]);
        svc.record_exec(&container_entry(10, 100, "web"));
        svc.link_owned(7, 100);

        let recorded = Arc::new(Mutex::new(Recorded::default()));
        svc.set_maps(Box::new(FakeMaps(Arc::clone(&recorded))));
        assert!(svc.supported());
        let recorded = recorded.lock().unwrap();
        assert_eq!(recorded.links, vec![(7, 100)]);
        assert_eq!(recorded.shapes, vec![(100, 8_000_000, 2_000_000_000)]);
        assert_eq!(recorded.interfaces, vec![2]);
    }

    #[test]
    fn the_fanout_hands_each_link_to_every_sink() {
        let first = Arc::new(QosCgroupShapingService::new());
        let second = Arc::new(QosCgroupShapingService::new());
        let recorded_first = Arc::new(Mutex::new(Recorded::default()));
        let recorded_second = Arc::new(Mutex::new(Recorded::default()));
        first.set_maps(Box::new(FakeMaps(Arc::clone(&recorded_first))));
        second.set_maps(Box::new(FakeMaps(Arc::clone(&recorded_second))));
        let fanout = WorkloadLinkFanout::new(vec![
            Arc::clone(&first) as Arc<dyn WorkloadLinkSink>,
            Arc::clone(&second) as Arc<dyn WorkloadLinkSink>,
        ]);
        fanout.link_owned(7, 100);
        assert_eq!(recorded_first.lock().unwrap().links, vec![(7, 100)]);
        assert_eq!(recorded_second.lock().unwrap().links, vec![(7, 100)]);
        fanout.link_gone(7);
        assert!(recorded_first.lock().unwrap().links.is_empty());
        assert!(recorded_second.lock().unwrap().links.is_empty());
    }

    #[test]
    fn a_task_without_a_cgroup_id_is_ignored() {
        let (svc, recorded, _) = service();
        svc.set_rules(vec![rule(
            "web",
            "/system.slice/docker-web.scope",
            8_000_000,
        )]);
        svc.record_exec(&container_entry(10, 0, "web"));
        assert!(recorded.lock().unwrap().shapes.is_empty());
    }
}
