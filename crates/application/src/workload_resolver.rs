//! Turning a socket into a workload block, once, for every surface.
//!
//! Three callers, one answer. A packet event carries the socket cookie the
//! kernel produced; a connection read out of the kernel's conntrack table
//! carries a five-tuple and nothing else; a DLP write carries the thread that
//! made it and no socket at all. Each of them ends up here, and what comes
//! back is the same `Workload` or the same nothing, so no surface can have a
//! richer idea of a flow's owner than another.
//!
//! The resolver never invents. A node with the hooks refused has no reader, a
//! table that evicted the socket has no entry, and a process table that never
//! saw the exec gives a pid with no path: all three come back as absence or
//! as a thinner block, never as a placeholder.

use std::sync::Arc;

use arc_swap::ArcSwapOption;
use domain::exposure::entity::{AcceptedConnections, BoundSocket};
use domain::workload::entity::{PeerWorkload, Workload, WorkloadSource};
use ports::secondary::socket_identity_port::{FlowEndpoints, SocketIdentityReader, SocketOwner};

use crate::process_table_service::ProcessTableService;
use crate::remote_identity_store::RemoteIdentityStore;

/// Resolves the workload behind a socket, a flow or a pid.
///
/// Both halves are optional and the resolver is useful with either one alone:
/// the socket reader without the process table gives a pid, a uid and a
/// cgroup, and the process table without the reader still answers the DLP
/// path, which already knows its own pid.
///
/// Cloning shares the socket half rather than copying it, because the hooks
/// come and go while the agent runs: a reload turning attribution off takes
/// the tables away from every holder at once, and one that turns it back on
/// hands them the new maps. A clone that kept the old reader would answer
/// from a map the kernel has already freed.
#[derive(Clone, Default)]
pub struct WorkloadResolver {
    /// `Box` inside the `Arc` because the swap primitive stores a sized
    /// value and a trait object is not one. It costs one pointer hop on a
    /// path that already does a map lookup.
    sockets: Arc<ArcSwapOption<Box<dyn SocketIdentityReader>>>,
    /// Swappable for the same reason, and set later than the sockets are:
    /// the table is built once the container resolver and the enrichers have
    /// been decided, which is well after the hooks attach.
    processes: Arc<ArcSwapOption<ProcessTableService>>,
    /// The list naming the other nodes' addresses, which is what fills the
    /// peer half of a block. Absent on a node no console feeds.
    remote: Arc<ArcSwapOption<RemoteIdentityStore>>,
}

impl WorkloadResolver {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Read the kernel socket tables through `reader`.
    #[must_use]
    pub fn with_sockets(self, reader: Box<dyn SocketIdentityReader>) -> Self {
        self.install_sockets(reader);
        self
    }

    /// Point every holder of this resolver at `reader`, which is what a
    /// reload enabling the hooks does.
    pub fn install_sockets(&self, reader: Box<dyn SocketIdentityReader>) {
        self.sockets.store(Some(Arc::new(reader)));
    }

    /// Give up the socket tables, which is what a reload disabling the hooks
    /// does. Every surface goes back to an absent block in the same instant,
    /// rather than reading a map whose program is being unloaded.
    pub fn clear_sockets(&self) {
        self.sockets.store(None);
    }

    /// Name the binary, the container and the pod through the process table.
    #[must_use]
    pub fn with_processes(self, processes: Arc<ProcessTableService>) -> Self {
        self.install_processes(processes);
        self
    }

    /// Point every holder of this resolver at `processes`.
    pub fn install_processes(&self, processes: Arc<ProcessTableService>) {
        self.processes.store(Some(processes));
    }

    /// Name the other end of a flow from the list of remote identities.
    pub fn install_remote(&self, remote: Arc<RemoteIdentityStore>) {
        self.remote.store(Some(remote));
    }

    /// The workload another node published for either end of `flow`.
    ///
    /// Both ends are tried because a caller reading conntrack does not know
    /// which side is this node's, and this node's own addresses are never in
    /// the list it is handed, so at most one end answers in practice.
    #[must_use]
    pub fn peer_of(&self, flow: &FlowEndpoints) -> Option<PeerWorkload> {
        let remote = self.remote.load();
        let held = remote.as_ref()?.current()?;
        [flow.remote_addr, flow.local_addr]
            .into_iter()
            .find_map(|address| held.get(address))
            .map(|entry| PeerWorkload::from_entry(entry, held.version()))
    }

    fn with_peer(&self, mut workload: Workload, flow: &FlowEndpoints) -> Workload {
        workload.peer = self.peer_of(flow);
        workload
    }

    /// Whether anything here can answer at all.
    ///
    /// A resolver with neither half is not an error: it is what an agent on a
    /// host that refused the cgroup attach has, and every flow it is asked
    /// about is honestly unattributed.
    #[must_use]
    pub fn is_wired(&self) -> bool {
        self.sockets.load().is_some() || self.processes.load().is_some()
    }

    /// The workload behind a socket cookie, as a packet event carries it.
    #[must_use]
    pub fn by_cookie(&self, cookie: u64) -> Option<Workload> {
        let owner = self.sockets.load().as_ref()?.by_cookie(cookie)?;
        Some(self.enrich(owner))
    }

    /// The workload behind a connection, matched on its five-tuple.
    #[must_use]
    pub fn by_flow(&self, flow: &FlowEndpoints) -> Option<Workload> {
        let owner = self.sockets.load().as_ref()?.by_flow(flow)?;
        Some(self.with_peer(self.enrich(owner), flow))
    }

    /// The workload that opened a connection from the local end stated.
    ///
    /// The orientation is taken as given: a row whose local end is this
    /// node's listening side answers nothing here, which is what a caller
    /// learning what a workload reaches needs. Everything else is
    /// [`Self::by_flow`].
    #[must_use]
    pub fn by_originated_flow(&self, flow: &FlowEndpoints) -> Option<Workload> {
        let owner = self.sockets.load().as_ref()?.by_originated_flow(flow)?;
        Some(self.with_peer(self.enrich(owner), flow))
    }

    /// The workload behind a pid the caller already knows, which is how a DLP
    /// write arrives: the uprobe fires in the writing thread.
    #[must_use]
    pub fn by_pid(&self, pid: u32) -> Option<Workload> {
        let base = Workload::new(pid, WorkloadSource::Process)?;
        let processes = self.processes.load();
        let processes = processes.as_ref()?;
        let entry = processes.get(pid)?;
        Some(
            base.with_process(&entry)
                .with_lineage(&processes.lineage(pid)),
        )
    }

    /// The workload holding a cgroup, named after the oldest live process
    /// the table holds in it, which in a container or a systemd unit is the
    /// one that started it rather than a short-lived child. `None` for the
    /// root cgroup's zero, for a cgroup the table holds no process in, and
    /// when no process table is installed.
    #[must_use]
    pub fn by_cgroup(&self, cgroup_id: u64) -> Option<Workload> {
        if cgroup_id == 0 {
            return None;
        }
        let pid = {
            let processes = self.processes.load();
            let processes = processes.as_ref()?;
            processes
                .list()
                .into_iter()
                .filter(|entry| entry.cgroup_id == cgroup_id)
                .min_by_key(|entry| (entry.started_at_ns, entry.pid))?
                .pid
        };
        self.by_pid(pid)
            .map(|workload| workload.with_cgroup(cgroup_id))
    }

    /// Every process the table holds, or `None` when no process table is
    /// installed: a node that does not observe its processes does not know
    /// its workloads, which is not the same as having none.
    #[must_use]
    pub fn processes(&self) -> Option<Vec<domain::process::entity::ProcessEntry>> {
        let processes = self.processes.load();
        Some(processes.as_ref()?.list())
    }

    /// The connections this node accepted per local address and port, or
    /// `None` when no socket table is installed.
    #[must_use]
    pub fn accepted_connections(&self) -> Option<Vec<AcceptedConnections>> {
        let sockets = self.sockets.load();
        Some(sockets.as_ref()?.accepted_connections())
    }

    /// Every socket this node holds bound now, each with the workload that
    /// bound it, or `None` when no socket table is installed: a node with the
    /// hooks refused does not know its listeners, which is not the same as
    /// having none.
    #[must_use]
    pub fn bound_sockets(&self) -> Option<Vec<(BoundSocket, Workload)>> {
        let sockets = self.sockets.load();
        let reader = sockets.as_ref()?;
        Some(
            reader
                .bound_sockets()
                .into_iter()
                .map(|socket| {
                    let owner = SocketOwner {
                        pid: socket.pid,
                        tgid: socket.pid,
                        uid: socket.uid,
                        cgroup_id: socket.cgroup_id,
                        source: WorkloadSource::Socket,
                    };
                    (socket, self.enrich(owner))
                })
                .collect(),
        )
    }

    /// Everything the process table can add to a socket owner.
    ///
    /// The uid and the cgroup come from the socket record rather than the
    /// table, because the hooks read them in the opening task's own context
    /// and the table's copy is from the exec, which may be a different user
    /// after a `setuid`.
    fn enrich(&self, owner: SocketOwner) -> Workload {
        let mut workload = Workload::new(owner.pid, owner.source)
            .unwrap_or_else(|| unreachable_owner(owner))
            .with_uid(owner.uid)
            .with_cgroup(owner.cgroup_id);
        let processes = self.processes.load();
        let Some(processes) = processes.as_ref() else {
            return workload;
        };
        if let Some(entry) = processes.get(owner.pid) {
            let uid = workload.uid;
            let cgroup = workload.cgroup;
            workload = workload.with_process(&entry);
            workload.uid = uid;
            workload.cgroup = cgroup.or(workload.cgroup);
            // The chain is read only for a process the table holds: a pid it
            // never saw has no parent recorded to start the walk from.
            workload = workload.with_lineage(&processes.lineage(owner.pid));
        }
        workload
    }
}

/// A reader never hands back a pid of zero, and the type system does not know
/// that. Rather than an unwrap that would panic in a hot path, a zero becomes
/// the same thing it means everywhere else: a block naming pid 1 is not an
/// option, so this builds the one thing that is always true of the record.
fn unreachable_owner(owner: SocketOwner) -> Workload {
    Workload {
        peer: None,
        pid: owner.pid,
        source: owner.source,
        exe: None,
        command_line: None,
        uid: None,
        cgroup: None,
        container: None,
        image: None,
        pod: None,
        namespace: None,
        service_account: None,
        unit: None,
        ancestry: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::process::entity::{ProcessEventKind, ProcessIdentity, ProcessLifecycleEvent};
    use domain::workload::entity::is_absent;
    use std::net::{IpAddr, Ipv4Addr};

    struct FixedSocket(Option<SocketOwner>);

    impl SocketIdentityReader for FixedSocket {
        fn by_cookie(&self, _cookie: u64) -> Option<SocketOwner> {
            self.0
        }
        fn by_flow(&self, _flow: &FlowEndpoints) -> Option<SocketOwner> {
            self.0
        }
        fn by_originated_flow(&self, _flow: &FlowEndpoints) -> Option<SocketOwner> {
            self.0
        }
    }

    fn owner() -> SocketOwner {
        SocketOwner {
            pid: 4_242,
            tgid: 4_242,
            uid: 1_000,
            cgroup_id: 77,
            source: WorkloadSource::Socket,
        }
    }

    fn flow() -> FlowEndpoints {
        FlowEndpoints {
            local_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)),
            remote_addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
            local_port: 45_112,
            remote_port: 443,
            protocol: 6,
        }
    }

    async fn table_with_exec(pid: u32) -> Arc<ProcessTableService> {
        let service = ProcessTableService::new(16, false);
        service
            .apply(ProcessLifecycleEvent::bare(
                ProcessEventKind::Exec,
                pid,
                "curl",
                1,
            ))
            .await;
        Arc::new(service)
    }

    fn remote_list(address: IpAddr) -> Arc<RemoteIdentityStore> {
        use domain::identity::remote::{RemoteEntry, RemoteSnapshot};
        use domain::identity::{AddressIdentity, IdentityKind};
        let store = RemoteIdentityStore::new();
        store
            .replace(RemoteSnapshot {
                version: "v7".to_string(),
                entries: vec![RemoteEntry {
                    node: "node-b".to_string(),
                    identity: AddressIdentity {
                        address,
                        kind: IdentityKind::Pod,
                        container: Some("db".to_string()),
                        image: None,
                        pod: Some("db-0".to_string()),
                        namespace: Some("shop".to_string()),
                        service_account: Some("db".to_string()),
                        guest: None,
                        pod_labels: std::collections::BTreeMap::from([(
                            "app".to_string(),
                            "db".to_string(),
                        )]),
                        namespace_labels: std::collections::BTreeMap::new(),
                        services: Vec::new(),
                    },
                }],
                conflicts: 0,
            })
            .expect("a valid list");
        Arc::new(store)
    }

    #[test]
    fn the_other_end_is_named_from_the_list_and_says_so() {
        let resolver = WorkloadResolver::new().with_sockets(Box::new(FixedSocket(Some(owner()))));
        resolver.install_remote(remote_list(flow().remote_addr));

        let peer = resolver
            .by_flow(&flow())
            .and_then(|w| w.peer)
            .expect("the remote end is in the list");
        assert_eq!(peer.source.as_str(), "remote_list");
        assert_eq!(peer.node, "node-b");
        assert_eq!(peer.pod.as_deref(), Some("db-0"));
        assert_eq!(peer.list_version, "v7");
        assert_eq!(peer.address, flow().remote_addr);

        let originated = resolver.by_originated_flow(&flow()).expect("a block");
        assert!(originated.peer.is_some());
    }

    #[test]
    fn an_end_the_list_does_not_hold_names_no_peer() {
        let resolver = WorkloadResolver::new().with_sockets(Box::new(FixedSocket(Some(owner()))));
        assert!(resolver.by_flow(&flow()).expect("a block").peer.is_none());

        resolver.install_remote(remote_list(IpAddr::V4(Ipv4Addr::new(10, 9, 9, 9))));
        let workload = resolver.by_flow(&flow()).expect("a block");
        assert!(workload.peer.is_none());
        let json = serde_json::to_string(&workload).expect("serialises");
        assert!(!json.contains("peer"), "absence is absence: {json}");
    }

    #[test]
    fn a_reversed_conntrack_row_still_finds_the_remote_end() {
        let resolver = WorkloadResolver::new();
        resolver.install_remote(remote_list(flow().remote_addr));
        let reversed = FlowEndpoints {
            local_addr: flow().remote_addr,
            remote_addr: flow().local_addr,
            ..flow()
        };
        assert!(resolver.peer_of(&reversed).is_some());
    }

    #[test]
    fn a_reload_turning_the_hooks_off_takes_them_from_every_clone() {
        let resolver = WorkloadResolver::new().with_sockets(Box::new(FixedSocket(Some(owner()))));
        let held = resolver.clone();
        assert!(held.by_cookie(42).is_some());
        resolver.clear_sockets();
        assert!(held.by_cookie(42).is_none());
        assert!(!held.is_wired());
        resolver.install_sockets(Box::new(FixedSocket(Some(owner()))));
        assert!(held.by_cookie(42).is_some());
    }

    #[tokio::test]
    async fn a_cgroup_is_named_after_the_oldest_process_in_it() {
        let service = ProcessTableService::new(16, false);
        for (pid, comm, at) in [(300, "worker", 9), (200, "postgres", 3), (400, "other", 1)] {
            let mut event = ProcessLifecycleEvent::bare(ProcessEventKind::Exec, pid, comm, at);
            event.cgroup_id = if pid == 400 { 55 } else { 77 };
            service.apply(event).await;
        }
        let resolver = WorkloadResolver::new().with_processes(Arc::new(service));
        let workload = resolver.by_cgroup(77).expect("two processes sit in it");
        assert_eq!(workload.pid, 200);
        assert_eq!(workload.cgroup, Some(77));
        assert!(resolver.by_cgroup(99).is_none());
        assert!(resolver.by_cgroup(0).is_none());
        assert!(WorkloadResolver::new().by_cgroup(77).is_none());
    }

    #[test]
    fn a_resolver_with_nothing_wired_answers_nothing() {
        let resolver = WorkloadResolver::new();
        assert!(!resolver.is_wired());
        assert!(resolver.by_cookie(42).is_none());
        assert!(resolver.by_flow(&flow()).is_none());
        assert!(resolver.by_pid(4_242).is_none());
    }

    #[test]
    fn an_unknown_socket_is_absent_rather_than_zero() {
        let resolver = WorkloadResolver::new().with_sockets(Box::new(FixedSocket(None)));
        let workload = resolver.by_cookie(42);
        assert!(is_absent(&workload));
    }

    #[test]
    fn a_known_socket_carries_the_uid_and_cgroup_the_hook_read() {
        let resolver = WorkloadResolver::new().with_sockets(Box::new(FixedSocket(Some(owner()))));
        let workload = resolver.by_cookie(42).unwrap();
        assert_eq!(workload.pid, 4_242);
        assert_eq!(workload.uid, Some(1_000));
        assert_eq!(workload.cgroup, Some(77));
        assert_eq!(workload.source, WorkloadSource::Socket);
        assert!(workload.exe.is_none());
    }

    #[test]
    fn a_flow_match_says_it_was_correlated_rather_than_read() {
        let correlated = SocketOwner {
            source: WorkloadSource::Flow,
            ..owner()
        };
        let resolver =
            WorkloadResolver::new().with_sockets(Box::new(FixedSocket(Some(correlated))));
        let workload = resolver.by_flow(&flow()).unwrap();
        assert_eq!(workload.source, WorkloadSource::Flow);
        assert!(!workload.source.is_read());
    }

    #[tokio::test]
    async fn the_process_table_adds_the_path_without_overwriting_the_socket_uid() {
        let table = table_with_exec(4_242).await;
        let resolver = WorkloadResolver::new()
            .with_sockets(Box::new(FixedSocket(Some(owner()))))
            .with_processes(Arc::clone(&table));
        let workload = resolver.by_cookie(42).unwrap();
        // The table recorded uid 0 for the exec; the socket hook read 1000 in
        // the opening task, and that is the one a reader is owed.
        assert_eq!(workload.uid, Some(1_000));
        assert_eq!(workload.cgroup, Some(77));
    }

    #[tokio::test]
    async fn a_pid_the_table_knows_resolves_without_any_socket() {
        let table = table_with_exec(4_242).await;
        let resolver = WorkloadResolver::new().with_processes(table);
        let workload = resolver.by_pid(4_242).unwrap();
        assert_eq!(workload.pid, 4_242);
        assert_eq!(workload.source, WorkloadSource::Process);
    }

    #[tokio::test]
    async fn a_pid_the_table_never_saw_is_absent() {
        let resolver = WorkloadResolver::new().with_processes(table_with_exec(1).await);
        assert!(is_absent(&resolver.by_pid(4_242)));
    }

    #[tokio::test]
    async fn a_pid_of_zero_never_builds_a_block() {
        let resolver = WorkloadResolver::new().with_processes(table_with_exec(1).await);
        assert!(resolver.by_pid(0).is_none());
    }

    #[tokio::test]
    async fn an_exec_with_no_executable_reader_leaves_the_identity_unknown() {
        // Which is what makes `exe` absent rather than a guess further up:
        // the block copies the identity, and the identity says it read none.
        let table = table_with_exec(4_242).await;
        assert_eq!(table.get(4_242).unwrap().identity, ProcessIdentity::Unknown);
        let resolver = WorkloadResolver::new().with_processes(table);
        assert!(resolver.by_pid(4_242).unwrap().exe.is_none());
    }
}
