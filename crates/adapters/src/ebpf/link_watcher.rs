#![allow(unsafe_code)] // Raw netlink sockets: subscription, dump and namespace id queries.

//! Every link a workload brings, attached as it appears and released as it
//! goes.
//!
//! A container's traffic crosses the host on a link the runtime creates for
//! it: a veth whose peer sits in the container's namespace (Docker, most
//! CNIs), a netkit device (Cilium 1.16 and later), a macvlan or ipvlan left in
//! the host namespace, or a tap or other virtual device enslaved to a bridge.
//! The watcher subscribes to rtnetlink's link group, so it hears
//! `RTM_NEWLINK` and `RTM_DELLINK` the moment the kernel emits them, and
//! attaches the agent's TC chain to each such link through the hook that
//! link takes: netkit's own primary and peer hooks for a netkit device, TCX
//! ingress and egress for everything else, the same mapping a configured
//! interface gets.
//!
//! A node starting fifty containers at once emits hundreds of messages in a
//! second, most of them flag changes on links already seen. Messages are
//! gathered over a short window and folded per interface index before
//! anything is attached, so a link created and moved into a namespace inside
//! that window costs nothing, and a burst the socket buffer could not hold
//! (`ENOBUFS`) is answered by reading the whole link table again rather than
//! by trusting what survived. The table is also read again on a slow timer,
//! so a message the kernel never sent cannot leave a link unattached for the
//! life of the agent.
//!
//! The owning workload is found through the namespace id the kernel reports
//! for the link's peer: every network namespace behind a process in the host
//! procfs is asked for its id from the host's side, and the one that matches
//! names a process whose cgroup names the container. A link whose peer sits
//! in no namespace the agent can open is attached all the same and logged
//! without an owner.
//!
//! A link of a kind the watcher does not know is logged once per kind, with
//! the kind, and left alone: it is a gap an operator can read, not one that
//! hides.
//!
//! Between a link appearing and the chain going on it, its traffic is not
//! seen by the TC programs. That window is measured for every link the
//! watcher heard announced, from the first message to the attach, and the
//! packets the link had carried by then are read from the kernel's own
//! counters for it, so the gap is a figure rather than an assumption. A link
//! found by reading the table, at start or on a resync, has no announcement
//! to measure from and is not counted.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use domain::container::engine::parse_cgroup_payload;
use domain::container::entity::ContainerInfo;
use domain::coverage::{LinkAttachment, LinkRefusal, WorkloadLink};
use domain::process::entity::{ProcessEventKind, ProcessLifecycleEvent};
use ports::secondary::ids_workload_scope_port::WorkloadLinkSink;
use ports::secondary::metrics_port::ContainerMetrics;
use ports::secondary::pod_coverage_port::LinkCoverageSink;
use tokio::io::unix::AsyncFd;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::attach_inspect::{find_attr, nla_align};
use super::ids_workload_scope::cgroup_id_of;
use super::netkit::{BPF_NETKIT_PEER, BPF_NETKIT_PRIMARY, netkit_attach};
use super::ringbuf_observer::boottime_now_ns;
use super::{kfunc_attach, tcx_order};
use crate::container::pod_cgroups::pod_uid;

/// How long messages are gathered after the first one before the batch is
/// applied. Long enough to fold a container's create, rename, move and up
/// into one attach; short enough to sit well inside a container's start.
pub const DEBOUNCE: Duration = Duration::from_millis(100);

/// How often the whole link table is read again, whatever the socket said.
pub const RESYNC_INTERVAL: Duration = Duration::from_secs(60);

/// Messages gathered into one batch at most, so a storm is applied in steps
/// rather than held back until it ends.
const MAX_BATCH: usize = 4096;

/// Receive buffer asked of the kernel for the subscription. A burst of
/// container starts fits in it many times over; when it does not, the
/// overrun is answered by a full read of the table.
const RCVBUF_BYTES: libc::c_int = 4 << 20;

/// `<linux/netlink.h>` and `<linux/rtnetlink.h>` values.
const NLMSG_HDR_LEN: usize = 16;
const IFINFOMSG_LEN: usize = 16;
const RTGENMSG_LEN: usize = 4;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const RTM_GETLINK: u16 = 18;
const RTM_NEWNSID: u16 = 88;
const RTM_GETNSID: u16 = 90;
const NLM_F_REQUEST: u16 = 0x001;
const NLM_F_DUMP: u16 = 0x300;
const RTMGRP_LINK: u32 = 1;

/// `IFLA_*` attributes of a link message.
const IFLA_IFNAME: u16 = 3;
const IFLA_LINK: u16 = 5;
const IFLA_MASTER: u16 = 10;
const IFLA_STATS64: u16 = 23;
const IFLA_LINKINFO: u16 = 18;
const IFLA_LINK_NETNSID: u16 = 37;
/// Members of the `IFLA_LINKINFO` nest.
const IFLA_INFO_KIND: u16 = 1;
const IFLA_INFO_SLAVE_KIND: u16 = 4;
/// `NETNSA_*` attributes of a namespace id message.
const NETNSA_NSID: u16 = 1;
const NETNSA_FD: u16 = 3;

/// Link kinds that carry infrastructure rather than one workload's traffic:
/// bridges and bonds, tunnels and overlays, VLANs. Left alone without a word,
/// because the watcher understands them and has nothing to attach to.
const INFRASTRUCTURE_KINDS: &[&str] = &[
    "bond",
    "bridge",
    "dummy",
    "geneve",
    "gre",
    "gretap",
    "ifb",
    "ip6gre",
    "ip6gretap",
    "ip6tnl",
    "ipip",
    "macsec",
    "nlmon",
    "openvswitch",
    "sit",
    "team",
    "vlan",
    "vrf",
    "vxlan",
    "wireguard",
    "xfrm",
];

/// Infrastructure kinds that wrap traffic between nodes in an outer header,
/// so the chain on the uplink reads that header rather than the pod's.
const ENCAPSULATING_KINDS: &[&str] = &[
    "geneve",
    "gre",
    "gretap",
    "ip6gre",
    "ip6gretap",
    "ip6tnl",
    "ipip",
    "sit",
    "vxlan",
    "wireguard",
];

/// Whether any link in `links` encapsulates traffic between nodes.
#[must_use]
pub fn encapsulates(links: &[LinkInfo]) -> bool {
    links.iter().any(|l| {
        l.kind
            .as_deref()
            .is_some_and(|k| ENCAPSULATING_KINDS.contains(&k))
    })
}

/// What one link message says about one interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkInfo {
    /// Kernel interface index, the link's identity: a name can be reused by a
    /// new device the moment the old one is gone.
    pub ifindex: u32,
    /// Interface name in the host namespace.
    pub name: String,
    /// `IFLA_INFO_KIND`, absent on a physical device and on loopback.
    pub kind: Option<String>,
    /// `IFLA_INFO_SLAVE_KIND`: what the link is enslaved to, `bridge` for a
    /// bridge port.
    pub slave_kind: Option<String>,
    /// `IFLA_MASTER`: the ifindex of the device the link is enslaved to.
    pub master: Option<u32>,
    /// `IFLA_LINK`: the peer's ifindex, in the peer's own namespace.
    pub peer_ifindex: Option<u32>,
    /// `IFLA_LINK_NETNSID`: the id, as seen from here, of the namespace the
    /// peer sits in. Present once the peer has been moved out of this one.
    pub link_netnsid: Option<i32>,
}

/// One link message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkEvent {
    /// `RTM_NEWLINK`: the link appeared or one of its properties changed.
    New(LinkInfo),
    /// `RTM_DELLINK`: the link is gone.
    Removed {
        /// Interface index of the link that went away.
        ifindex: u32,
        /// Its name, when the message carried one.
        name: String,
    },
}

impl LinkEvent {
    fn ifindex(&self) -> u32 {
        match self {
            Self::New(info) => info.ifindex,
            Self::Removed { ifindex, .. } => *ifindex,
        }
    }
}

/// The kinds of link a workload brings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WorkloadKind {
    /// Host side of a veth pair.
    Veth,
    /// Primary side of a netkit pair.
    Netkit,
    /// A macvlan device in the host namespace.
    Macvlan,
    /// An ipvlan device in the host namespace.
    Ipvlan,
    /// A virtual device enslaved to a bridge: a tap, an overlay port.
    BridgeMember,
}

impl WorkloadKind {
    /// The word logs and documentation use for this kind.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Veth => "veth",
            Self::Netkit => "netkit",
            Self::Macvlan => "macvlan",
            Self::Ipvlan => "ipvlan",
            Self::BridgeMember => "bridge-member",
        }
    }
}

/// What the watcher makes of a link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkClass {
    /// A workload's link: the agent's chain goes on it.
    Workload(WorkloadKind),
    /// Understood and not a workload's: a physical device, loopback, a bridge
    /// or a tunnel.
    Infrastructure,
    /// A kind the watcher has no rule for.
    Unknown(String),
}

/// Classify a link from its message.
///
/// A link enslaved to a bridge is a workload's when it is virtual, which is
/// what a kind says; a physical device enslaved to a bridge is the bridge's
/// uplink and carries every workload's traffic at once.
#[must_use]
pub fn classify(info: &LinkInfo) -> LinkClass {
    match info.kind.as_deref() {
        Some("veth") => LinkClass::Workload(WorkloadKind::Veth),
        Some("netkit") => LinkClass::Workload(WorkloadKind::Netkit),
        Some("macvlan") => LinkClass::Workload(WorkloadKind::Macvlan),
        Some("ipvlan") => LinkClass::Workload(WorkloadKind::Ipvlan),
        Some(kind) if INFRASTRUCTURE_KINDS.contains(&kind) => LinkClass::Infrastructure,
        Some(_) if info.slave_kind.as_deref() == Some("bridge") => {
            LinkClass::Workload(WorkloadKind::BridgeMember)
        }
        Some(kind) => LinkClass::Unknown(kind.to_owned()),
        None => LinkClass::Infrastructure,
    }
}

/// Which hooks the hot-plug uses, from the agent's attach mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookPolicy {
    /// Netkit devices take netkit's own hooks, every other workload link
    /// takes TCX.
    Auto,
    /// Every workload link takes TCX, netkit devices included.
    Tcx,
    /// Only netkit devices are attached, through netkit's hooks.
    Netkit,
}

impl HookPolicy {
    /// Whether a link of `kind` is attached at all, and if so whether through
    /// netkit's hooks (`Some(true)`) or TCX (`Some(false)`).
    fn hooks_for(self, kind: WorkloadKind) -> Option<bool> {
        match (self, kind == WorkloadKind::Netkit) {
            (Self::Auto | Self::Netkit, true) => Some(true),
            (Self::Auto | Self::Tcx, false) | (Self::Tcx, true) => Some(false),
            (Self::Netkit, false) => None,
        }
    }

    /// The attach mode as the configuration spells it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Tcx => "tc",
            Self::Netkit => "netkit",
        }
    }
}

/// A link the plan attaches to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attach {
    /// The link as its last message described it.
    pub link: LinkInfo,
    /// What it was classified as.
    pub kind: WorkloadKind,
    /// `true` when the link takes netkit's own hooks rather than TCX.
    pub via_netkit: bool,
    /// When the first message announcing a new link was received, for a
    /// link the watcher heard about rather than found in the table. `None`
    /// as well when the link was already attached under another name or
    /// kind: its traffic was guarded until the release just before.
    pub heard_at: Option<Instant>,
}

/// A link the plan releases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detach {
    /// Interface index the links were made on.
    pub ifindex: u32,
    /// Name the link carried when it was attached.
    pub name: String,
}

/// What one batch of messages asks for, releases first.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Plan {
    /// Links whose attachments are released.
    pub detach: Vec<Detach>,
    /// Links the chain goes on.
    pub attach: Vec<Attach>,
    /// Kinds seen for the first time and not understood, with the link that
    /// carried each.
    pub unknown: Vec<(String, String)>,
    /// Links leading into a workload that the chain does not go on, newly
    /// or for a new reason.
    pub left: Vec<(LinkInfo, LinkRefusal)>,
    /// Links that were left alone and are gone or no longer a workload's.
    pub forget: Vec<u32>,
}

impl Plan {
    /// Whether the plan changes nothing and reports nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.detach.is_empty()
            && self.attach.is_empty()
            && self.unknown.is_empty()
            && self.left.is_empty()
            && self.forget.is_empty()
    }
}

/// The links the watcher has attached to, and what it has already reported.
///
/// Pure bookkeeping: messages in, a plan out, no syscall, so the folding a
/// burst depends on is tested without a kernel.
#[derive(Debug)]
pub struct LinkTable {
    policy: HookPolicy,
    /// Interfaces the agent attached from its configuration; a second attach
    /// would run the chain twice on every packet.
    configured: HashSet<String>,
    attached: HashMap<u32, (String, WorkloadKind)>,
    /// Workload links the chain does not go on, with the reason last
    /// reported for each.
    left: HashMap<u32, LinkRefusal>,
    reported_kinds: HashSet<String>,
    /// First message received for each interface in the batch being folded.
    heard: HashMap<u32, Instant>,
}

impl LinkTable {
    /// An empty table applying `policy`, leaving `configured` alone.
    #[must_use]
    pub fn new(policy: HookPolicy, configured: impl IntoIterator<Item = String>) -> Self {
        Self {
            policy,
            configured: configured.into_iter().collect(),
            attached: HashMap::new(),
            left: HashMap::new(),
            reported_kinds: HashSet::new(),
            heard: HashMap::new(),
        }
    }

    /// Number of links currently attached through the hot-plug.
    #[must_use]
    pub fn attached_count(&self) -> usize {
        self.attached.len()
    }

    /// Fold a batch of messages into a plan.
    ///
    /// Only the last message about each interface counts: a link created,
    /// renamed and brought up inside one batch is one attach, and a link
    /// created and gone inside one batch is nothing at all.
    pub fn observe(&mut self, events: Vec<LinkEvent>) -> Plan {
        let mut last: BTreeMap<u32, LinkEvent> = BTreeMap::new();
        for event in events {
            last.insert(event.ifindex(), event);
        }
        let mut plan = Plan::default();
        for (ifindex, event) in last {
            match event {
                LinkEvent::Removed { .. } => {
                    if let Some((name, _)) = self.attached.remove(&ifindex) {
                        plan.detach.push(Detach { ifindex, name });
                    }
                    if self.left.remove(&ifindex).is_some() {
                        plan.forget.push(ifindex);
                    }
                }
                LinkEvent::New(link) => self.observe_link(link, &mut plan),
            }
        }
        plan
    }

    /// Fold a batch of messages, each with the moment it was received, so a
    /// link attached by this batch carries the time it was first announced.
    pub fn observe_heard(&mut self, events: Vec<(Instant, LinkEvent)>) -> Plan {
        for (at, event) in &events {
            if let LinkEvent::New(link) = event {
                self.heard.entry(link.ifindex).or_insert(*at);
            }
        }
        let plan = self.observe(events.into_iter().map(|(_, e)| e).collect());
        self.heard.clear();
        plan
    }

    /// Compare the whole link table against what is attached: a link the
    /// table no longer lists is released, and every listed link is observed
    /// as though it had just been announced.
    pub fn resync(&mut self, links: Vec<LinkInfo>) -> Plan {
        let present: HashSet<u32> = links.iter().map(|l| l.ifindex).collect();
        let gone: Vec<u32> = self
            .attached
            .keys()
            .chain(self.left.keys())
            .copied()
            .filter(|idx| !present.contains(idx))
            .collect::<HashSet<u32>>()
            .into_iter()
            .collect();
        let mut events: Vec<LinkEvent> = gone
            .into_iter()
            .map(|ifindex| LinkEvent::Removed {
                ifindex,
                name: String::new(),
            })
            .collect();
        events.extend(links.into_iter().map(LinkEvent::New));
        self.observe(events)
    }

    fn observe_link(&mut self, link: LinkInfo, plan: &mut Plan) {
        let mut refusal = None;
        let wanted = match classify(&link) {
            LinkClass::Workload(kind) if !self.configured.contains(&link.name) => {
                let hooks = self.policy.hooks_for(kind);
                if hooks.is_none() {
                    refusal = Some(LinkRefusal::AttachMode(self.policy.as_str().to_owned()));
                }
                hooks.map(|via_netkit| (kind, via_netkit))
            }
            LinkClass::Unknown(kind) => {
                // Only a link whose peer sits in another namespace leads into
                // a workload; an unknown device of the host's own is not one.
                if link.link_netnsid.is_some() {
                    refusal = Some(LinkRefusal::UnknownKind(kind.clone()));
                }
                if self.reported_kinds.insert(kind.clone()) {
                    plan.unknown.push((kind, link.name.clone()));
                }
                None
            }
            _ => None,
        };
        match refusal {
            Some(refusal) => {
                if self.left.get(&link.ifindex) != Some(&refusal) {
                    self.left.insert(link.ifindex, refusal.clone());
                    plan.left.push((link.clone(), refusal));
                }
            }
            None => {
                if self.left.remove(&link.ifindex).is_some() {
                    plan.forget.push(link.ifindex);
                }
            }
        }
        let held = self.attached.get(&link.ifindex).cloned();
        let heard_at = match held {
            None => self.heard.get(&link.ifindex).copied(),
            Some(_) => None,
        };
        match (held, wanted) {
            (Some((name, held_kind)), Some((kind, _)))
                if name == link.name && held_kind == kind => {}
            (held, wanted) => {
                if let Some((name, _)) = held {
                    self.attached.remove(&link.ifindex);
                    plan.detach.push(Detach {
                        ifindex: link.ifindex,
                        name,
                    });
                }
                if let Some((kind, via_netkit)) = wanted {
                    self.attached
                        .insert(link.ifindex, (link.name.clone(), kind));
                    plan.attach.push(Attach {
                        link,
                        kind,
                        via_netkit,
                        heard_at,
                    });
                }
            }
        }
    }
}

/// Which side of the link a hot-plugged program runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookSide {
    /// The agent's TC ingress chain: TCX ingress, or netkit's primary hook.
    Ingress,
    /// The agent's TC egress chain: TCX egress, or netkit's peer hook.
    Egress,
}

/// The workload behind a link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkOwner {
    /// A process in the namespace the link's peer sits in.
    pub pid: u32,
    /// Inode of that namespace.
    pub ns_inode: u64,
    /// What the process's cgroup says about it.
    pub container: Option<ContainerInfo>,
}

/// The loaded TC programs, and the links made from them on each hot-plugged
/// interface.
///
/// The links are held per interface and dropped when it goes: the kernel
/// detaches a link whose device was unregistered, but the link object and its
/// fd live until the fd is closed, so holding them for the life of the agent
/// would leak one fd per program per workload ever scheduled.
///
/// The stored program fds stay valid as long as the loaders that own them;
/// the agent cancels the watcher before dropping them.
pub struct LinkHotPlugRegistry {
    programs: Vec<(String, RawFd, HookSide)>,
    links: Mutex<HashMap<u32, Vec<OwnedFd>>>,
    owners: Option<OwnerReporting>,
    coverage: Option<Arc<dyn LinkCoverageSink>>,
}

/// Where the owner of a container link is reported, and how its cgroup is
/// found.
///
/// A packet crossing the host side of a container's link carries no socket,
/// so the only way to say which workload it belongs to is the link itself.
/// Two things are told when one appears: the sink, which keeps the
/// interface-to-cgroup table the classifier reads, and the process table, as
/// an exec of the process holding the link, so the cgroup is matched against
/// what that workload is even though the process started before the agent.
pub struct OwnerReporting {
    sink: Arc<dyn WorkloadLinkSink>,
    processes: Option<tokio::sync::mpsc::Sender<ProcessLifecycleEvent>>,
    cgroup_root: PathBuf,
    proc_root: PathBuf,
}

impl OwnerReporting {
    /// Report to `sink`, resolving cgroup paths under `cgroup_root` and
    /// reading the owning process under `proc_root`.
    #[must_use]
    pub fn new(sink: Arc<dyn WorkloadLinkSink>, cgroup_root: PathBuf, proc_root: PathBuf) -> Self {
        Self {
            sink,
            processes: None,
            cgroup_root,
            proc_root,
        }
    }

    /// Also hand the owning process to the process table on `processes`.
    #[must_use]
    pub fn with_processes(
        mut self,
        processes: tokio::sync::mpsc::Sender<ProcessLifecycleEvent>,
    ) -> Self {
        self.processes = Some(processes);
        self
    }

    /// Tell the sink and the process table who owns the link at `ifindex`.
    /// A host-side link, or an owner whose cgroup is already gone, is
    /// reported as no link at all.
    fn owned(&self, ifindex: u32, owner: Option<&LinkOwner>) {
        let Some((owner, cgroup_path)) = owner.and_then(|owner| match &owner.container {
            Some(ContainerInfo::Container { cgroup_path, .. }) => Some((owner, cgroup_path)),
            _ => None,
        }) else {
            self.sink.link_gone(ifindex);
            return;
        };
        let Some(cgroup_id) = cgroup_id_of(&self.cgroup_root, cgroup_path) else {
            debug!(ifindex, cgroup = %cgroup_path, "hot-plug: owner cgroup gone before its id was read");
            self.sink.link_gone(ifindex);
            return;
        };
        self.sink.link_owned(ifindex, cgroup_id);
        if let Some(processes) = &self.processes
            && let Some(event) = self.exec_of(owner.pid, cgroup_id)
            && let Err(error) = processes.try_send(event)
        {
            debug!(pid = owner.pid, %error, "hot-plug: link owner not handed to the process table");
        }
    }

    /// The owning process as an exec notification: the table records the
    /// tasks it hears exec, and this one started before anything listened.
    fn exec_of(&self, pid: u32, cgroup_id: u64) -> Option<ProcessLifecycleEvent> {
        use std::os::unix::fs::MetadataExt;

        let dir = self.proc_root.join(pid.to_string());
        let meta = std::fs::metadata(&dir).ok()?;
        let comm = std::fs::read_to_string(dir.join("comm")).unwrap_or_default();
        Some(ProcessLifecycleEvent {
            kind: ProcessEventKind::Exec,
            pid,
            tgid: pid,
            uid: meta.uid(),
            gid: meta.gid(),
            cgroup_id,
            comm: comm.trim_end().to_owned(),
            at_ns: boottime_now_ns(),
        })
    }
}

impl Default for LinkHotPlugRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl LinkHotPlugRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            programs: Vec::new(),
            links: Mutex::new(HashMap::new()),
            owners: None,
            coverage: None,
        }
    }

    /// Report the owner of every link attached from now on through
    /// `reporting`.
    pub fn report_owners(&mut self, reporting: OwnerReporting) {
        self.owners = Some(reporting);
    }

    /// Report what became of every workload link to `sink`: attached, left
    /// alone and why, or gone.
    pub fn report_coverage(&mut self, sink: Arc<dyn LinkCoverageSink>) {
        self.coverage = Some(sink);
    }

    /// Report a link the chain does not go on.
    fn left(&self, link: &LinkInfo, refusal: LinkRefusal, owner: Option<&LinkOwner>) {
        if let Some(sink) = &self.coverage {
            sink.link_seen(WorkloadLink {
                ifindex: link.ifindex,
                name: link.name.clone(),
                kind: link.kind.clone().unwrap_or_default(),
                attachment: LinkAttachment::Refused(refusal),
                pod_uid: owner_pod_uid(owner),
            });
        }
    }

    /// Withdraw a link that was left alone.
    fn forget(&self, ifindex: u32) {
        if let Some(sink) = &self.coverage {
            sink.link_forgotten(ifindex);
        }
    }

    /// Register a loaded TC program on `side`. Programs attach in
    /// registration order, which is the order they run in on each side.
    pub fn register(&mut self, program_name: String, fd: RawFd, side: HookSide) {
        self.programs.push((program_name, fd, side));
    }

    /// Number of registered programs.
    #[must_use]
    pub fn program_count(&self) -> usize {
        self.programs.len()
    }

    /// Number of links currently held.
    #[must_use]
    pub fn link_count(&self) -> usize {
        self.links
            .lock()
            .map_or(0, |l| l.values().map(Vec::len).sum())
    }

    /// Attach every registered program to one link. A program that fails is
    /// logged and the others still go on. Returns how many attached.
    pub fn attach(&self, target: &Attach, owner: Option<&LinkOwner>) -> usize {
        let link = &target.link;
        let mut made = Vec::new();
        for (name, fd, side) in &self.programs {
            match attach_one(name, *fd, *side, target) {
                Ok(link_fd) => made.push(link_fd),
                Err(error) => warn!(
                    program = %name,
                    iface = %link.name,
                    kind = target.kind.as_str(),
                    ?side,
                    %error,
                    "hot-plug: TC program not attached to a workload link"
                ),
            }
        }
        let attached = made.len();
        let container = owner.and_then(|o| o.container.as_ref());
        info!(
            iface = %link.name,
            ifindex = link.ifindex,
            kind = target.kind.as_str(),
            programs = attached,
            of = self.programs.len(),
            peer_ifindex = link.peer_ifindex,
            pid = owner.map(|o| o.pid),
            netns = owner.map(|o| o.ns_inode),
            container_id = container.and_then(ContainerInfo::container_id),
            runtime = container.map(|c| format!("{:?}", c.runtime())),
            "hot-plug: workload link attached"
        );
        if let Ok(mut links) = self.links.lock() {
            links.insert(link.ifindex, made);
        }
        if let Some(reporting) = &self.owners {
            reporting.owned(link.ifindex, owner);
        }
        if let Some(sink) = &self.coverage {
            let of = self.programs.len();
            sink.link_seen(WorkloadLink {
                ifindex: link.ifindex,
                name: link.name.clone(),
                kind: target.kind.as_str().to_owned(),
                attachment: if attached == of {
                    LinkAttachment::Attached
                } else {
                    LinkAttachment::Refused(LinkRefusal::ProgramsRefused {
                        attached: u32::try_from(attached).unwrap_or(u32::MAX),
                        of: u32::try_from(of).unwrap_or(u32::MAX),
                    })
                },
                pod_uid: owner_pod_uid(owner),
            });
        }
        attached
    }

    /// Release the links held for an interface that went away or stopped
    /// being a workload's.
    pub fn detach(&self, target: &Detach) {
        let dropped = self
            .links
            .lock()
            .ok()
            .and_then(|mut links| links.remove(&target.ifindex));
        if !target.name.is_empty() {
            tcx_order::forget(&target.name);
        }
        if let Some(reporting) = &self.owners {
            reporting.sink.link_gone(target.ifindex);
        }
        self.forget(target.ifindex);
        if let Some(dropped) = dropped {
            info!(
                iface = %target.name,
                ifindex = target.ifindex,
                links = dropped.len(),
                "hot-plug: workload link released"
            );
        }
    }
}

/// The pod a link's owner belongs to, read off the pod segment of its cgroup
/// path.
fn owner_pod_uid(owner: Option<&LinkOwner>) -> Option<String> {
    match owner.and_then(|o| o.container.as_ref())? {
        ContainerInfo::Container { cgroup_path, .. } => cgroup_path.split('/').find_map(pod_uid),
        ContainerInfo::Host => None,
    }
}

fn attach_one(name: &str, fd: RawFd, side: HookSide, target: &Attach) -> Result<OwnedFd, String> {
    let link = &target.link;
    if target.via_netkit {
        let attach_type = match side {
            HookSide::Ingress => BPF_NETKIT_PRIMARY,
            HookSide::Egress => BPF_NETKIT_PEER,
        };
        return netkit_attach(fd, link.ifindex, attach_type).map_err(|e| e.to_string());
    }
    let egress = side == HookSide::Egress;
    let link_fd = kfunc_attach::attach_tcx(
        name,
        fd,
        &link.name,
        egress,
        &tcx_order::anchors(&link.name, egress),
    )
    .map_err(|e| e.to_string())?;
    let hook = tcx_order::Hook {
        interface: &link.name,
        egress,
    };
    // A refusal drops the link on return: the agent does not stay attached
    // where a program ahead of it decides what it sees.
    tcx_order::verify(name, hook, fd)?;
    Ok(link_fd)
}

/// Every network namespace behind a process in `proc_root`, once each, as
/// `(pid, namespace inode)`.
///
/// `proc_root` is `/proc` on a host and the read-only bind mount of the
/// host's procfs in a pod that was not given the host pid namespace. A
/// process that exits between the listing and the read is skipped.
#[must_use]
pub fn network_namespaces(proc_root: &Path) -> Vec<(u32, u64)> {
    use std::os::unix::fs::MetadataExt;

    let Ok(entries) = std::fs::read_dir(proc_root) else {
        return Vec::new();
    };
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(meta) = std::fs::metadata(entry.path().join("ns").join("net")) else {
            continue;
        };
        if seen.insert(meta.ino()) {
            out.push((pid, meta.ino()));
        }
    }
    out
}

/// Finds the workload behind a namespace id.
///
/// The id a namespace carries, as seen from the host, is asked once per
/// namespace and kept while the namespace lives. A namespace that has no id
/// yet is asked again next time: the kernel assigns one when a link's peer is
/// first reported in it.
pub struct OwnerResolver {
    proc_root: PathBuf,
    nsid_by_inode: HashMap<u64, i32>,
}

impl OwnerResolver {
    /// A resolver reading `proc_root`.
    #[must_use]
    pub fn new(proc_root: PathBuf) -> Self {
        Self {
            proc_root,
            nsid_by_inode: HashMap::new(),
        }
    }

    /// The owner of every namespace id in `wanted` that a process in the
    /// procfs sits in.
    pub fn resolve(&mut self, wanted: &HashSet<i32>) -> HashMap<i32, LinkOwner> {
        let mut found = HashMap::new();
        if wanted.is_empty() {
            return found;
        }
        let sock = match NetlinkSocket::open(0, false) {
            Ok(sock) => sock,
            Err(error) => {
                debug!(%error, "hot-plug: no socket to ask namespace ids on");
                return found;
            }
        };
        let namespaces = network_namespaces(&self.proc_root);
        let live: HashSet<u64> = namespaces.iter().map(|(_, ino)| *ino).collect();
        self.nsid_by_inode.retain(|ino, _| live.contains(ino));
        for (pid, ino) in namespaces {
            let nsid = if let Some(nsid) = self.nsid_by_inode.get(&ino) {
                Some(*nsid)
            } else {
                let path = self.proc_root.join(pid.to_string()).join("ns").join("net");
                let nsid = namespace_id(&sock, &path).ok().flatten();
                if let Some(nsid) = nsid {
                    self.nsid_by_inode.insert(ino, nsid);
                }
                nsid
            };
            if let Some(nsid) = nsid
                && wanted.contains(&nsid)
                && !found.contains_key(&nsid)
            {
                let container =
                    std::fs::read_to_string(self.proc_root.join(pid.to_string()).join("cgroup"))
                        .ok()
                        .and_then(|raw| parse_cgroup_payload(&raw, pid));
                found.insert(
                    nsid,
                    LinkOwner {
                        pid,
                        ns_inode: ino,
                        container,
                    },
                );
            }
        }
        found
    }
}

/// Apply a plan: release, report, then attach with the owners found, and
/// count how long each announced link went without the chain and what it
/// carried meanwhile.
pub fn apply(
    plan: &Plan,
    registry: &LinkHotPlugRegistry,
    resolver: &mut OwnerResolver,
    metrics: &dyn ContainerMetrics,
) {
    for target in &plan.detach {
        registry.detach(target);
    }
    for (kind, iface) in &plan.unknown {
        warn!(
            kind = %kind,
            iface = %iface,
            "hot-plug: link kind not understood, links of this kind are not attached \
             (reported once per kind)"
        );
    }
    for ifindex in &plan.forget {
        registry.forget(*ifindex);
    }
    let wanted: HashSet<i32> = plan
        .attach
        .iter()
        .map(|a| &a.link)
        .chain(plan.left.iter().map(|(link, _)| link))
        .filter_map(|link| link.link_netnsid)
        .collect();
    let owners = resolver.resolve(&wanted);
    for (link, refusal) in &plan.left {
        let owner = link.link_netnsid.and_then(|n| owners.get(&n));
        registry.left(link, refusal.clone(), owner);
    }
    for target in &plan.attach {
        let owner = target.link.link_netnsid.and_then(|n| owners.get(&n));
        let attached = registry.attach(target, owner);
        if attached > 0
            && let Some(heard_at) = target.heard_at
        {
            record_gap(target, heard_at.elapsed(), metrics);
        }
    }
}

/// Count the window an announced link spent without the chain, and the
/// packets it carried in that window as the kernel counted them.
fn record_gap(target: &Attach, gap: Duration, metrics: &dyn ContainerMetrics) {
    let kind = target.kind.as_str();
    metrics.observe_link_attach_gap(kind, gap.as_secs_f64());
    match link_packets(target.link.ifindex) {
        Ok(packets) => {
            metrics.record_link_unguarded_packets(kind, packets);
            if packets > 0 {
                debug!(
                    iface = %target.link.name,
                    kind,
                    packets,
                    gap_ms = gap.as_millis(),
                    "hot-plug: workload link carried traffic before the chain was attached"
                );
            }
        }
        Err(error) => debug!(
            iface = %target.link.name,
            %error,
            "hot-plug: packet counters of a workload link could not be read"
        ),
    }
}

/// A raw `NETLINK_ROUTE` socket, closed on drop.
struct NetlinkSocket(OwnedFd);

impl NetlinkSocket {
    /// Open a socket, subscribed to `groups` (`0` for none).
    fn open(groups: u32, nonblocking: bool) -> io::Result<Self> {
        let mut flags = libc::SOCK_RAW | libc::SOCK_CLOEXEC;
        if nonblocking {
            flags |= libc::SOCK_NONBLOCK;
        }
        // SAFETY: a plain socket create; the fd is owned right below.
        let fd = unsafe { libc::socket(libc::AF_NETLINK, flags, libc::NETLINK_ROUTE) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a fresh descriptor nothing else owns.
        let sock = Self(unsafe { OwnedFd::from_raw_fd(fd) });
        if groups != 0 {
            sock.grow_receive_buffer();
            // SAFETY: an all-zero `sockaddr_nl` is valid; family and groups
            // are set right below.
            let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            addr.nl_family = u16::try_from(libc::AF_NETLINK).unwrap_or(16);
            addr.nl_groups = groups;
            // SAFETY: `addr` is a fully initialised `sockaddr_nl` of the
            // advertised length.
            let rc = unsafe {
                libc::bind(
                    sock.0.as_raw_fd(),
                    (&raw const addr).cast(),
                    u32::try_from(std::mem::size_of::<libc::sockaddr_nl>()).unwrap_or(12),
                )
            };
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(sock)
    }

    /// Ask for a receive buffer a burst fits in: the forced size first, which
    /// needs `CAP_NET_ADMIN`, then the size `rmem_max` allows.
    fn grow_receive_buffer(&self) {
        let size = RCVBUF_BYTES;
        let len = u32::try_from(std::mem::size_of::<libc::c_int>()).unwrap_or(4);
        for opt in [libc::SO_RCVBUFFORCE, libc::SO_RCVBUF] {
            // SAFETY: `size` is a live `c_int` of the advertised length.
            let rc = unsafe {
                libc::setsockopt(
                    self.0.as_raw_fd(),
                    libc::SOL_SOCKET,
                    opt,
                    (&raw const size).cast(),
                    len,
                )
            };
            if rc == 0 {
                return;
            }
        }
    }

    fn send(&self, msg: &[u8]) -> io::Result<()> {
        // SAFETY: `msg` is a live slice of the advertised length.
        let sent = unsafe { libc::send(self.0.as_raw_fd(), msg.as_ptr().cast(), msg.len(), 0) };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        // SAFETY: `buf` is a live allocation of the advertised length.
        let got = unsafe { libc::recv(self.0.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
        usize::try_from(got).map_err(|_| io::Error::last_os_error())
    }
}

impl AsRawFd for NetlinkSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

/// A netlink message: header, fixed body, then attributes.
fn message(msg_type: u16, flags: u16, body: &[u8], attrs: &[u8]) -> Vec<u8> {
    let len = NLMSG_HDR_LEN + body.len() + attrs.len();
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&u32::try_from(len).unwrap_or(u32::MAX).to_ne_bytes());
    out.extend_from_slice(&msg_type.to_ne_bytes());
    out.extend_from_slice(&flags.to_ne_bytes());
    out.extend_from_slice(&1u32.to_ne_bytes());
    out.extend_from_slice(&0u32.to_ne_bytes());
    out.extend_from_slice(body);
    out.extend_from_slice(attrs);
    out
}

/// One netlink attribute, padded.
fn attr(kind: u16, payload: &[u8]) -> Vec<u8> {
    let len = 4 + payload.len();
    let mut out = Vec::with_capacity(nla_align(len));
    out.extend_from_slice(&u16::try_from(len).unwrap_or(u16::MAX).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(payload);
    out.resize(nla_align(len), 0);
    out
}

/// What a buffer of netlink messages held besides link messages.
#[derive(Debug, Default, PartialEq, Eq)]
struct Trailer {
    done: bool,
    error: Option<i32>,
}

/// Walk every message in a buffer, handing each `(type, payload)` to `each`.
fn walk(buf: &[u8], mut each: impl FnMut(u16, &[u8])) -> Trailer {
    let mut trailer = Trailer::default();
    let mut rest = buf;
    while rest.len() >= NLMSG_HDR_LEN {
        let len = u32::from_ne_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
        let msg_type = u16::from_ne_bytes([rest[4], rest[5]]);
        if len < NLMSG_HDR_LEN || len > rest.len() {
            break;
        }
        let payload = &rest[NLMSG_HDR_LEN..len];
        match msg_type {
            NLMSG_DONE => {
                trailer.done = true;
                break;
            }
            NLMSG_ERROR => {
                let code = payload
                    .get(..4)
                    .and_then(|b| b.try_into().ok())
                    .map_or(0, i32::from_ne_bytes);
                if code != 0 {
                    trailer.error = Some(-code);
                }
                trailer.done = true;
                break;
            }
            _ => each(msg_type, payload),
        }
        let step = nla_align(len);
        if step >= rest.len() {
            break;
        }
        rest = &rest[step..];
    }
    trailer
}

fn attr_str(attrs: &[u8], kind: u16) -> Option<String> {
    let raw = find_attr(attrs, kind)?;
    let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
    std::str::from_utf8(&raw[..end]).ok().map(str::to_owned)
}

fn attr_u32(attrs: &[u8], kind: u16) -> Option<u32> {
    find_attr(attrs, kind)?
        .get(..4)?
        .try_into()
        .ok()
        .map(u32::from_ne_bytes)
}

/// Read one `RTM_NEWLINK` or `RTM_DELLINK` payload.
fn parse_link(msg_type: u16, payload: &[u8]) -> Option<LinkEvent> {
    let ifindex = i32::from_ne_bytes(payload.get(4..8)?.try_into().ok()?);
    let ifindex = u32::try_from(ifindex).ok()?;
    let attrs = payload.get(nla_align(IFINFOMSG_LEN)..).unwrap_or_default();
    let name = attr_str(attrs, IFLA_IFNAME).unwrap_or_default();
    if msg_type == RTM_DELLINK {
        return Some(LinkEvent::Removed { ifindex, name });
    }
    let info = find_attr(attrs, IFLA_LINKINFO);
    Some(LinkEvent::New(LinkInfo {
        ifindex,
        name,
        kind: info.and_then(|i| attr_str(i, IFLA_INFO_KIND)),
        slave_kind: info.and_then(|i| attr_str(i, IFLA_INFO_SLAVE_KIND)),
        master: attr_u32(attrs, IFLA_MASTER).filter(|m| *m != 0),
        peer_ifindex: attr_u32(attrs, IFLA_LINK).filter(|p| *p != 0 && *p != ifindex),
        link_netnsid: attr_u32(attrs, IFLA_LINK_NETNSID)
            .map(u32::cast_signed)
            .filter(|n| *n >= 0),
    }))
}

/// Every link message in a buffer, in order.
fn parse_link_messages(buf: &[u8]) -> (Vec<LinkEvent>, Trailer) {
    let mut events = Vec::new();
    let trailer = walk(buf, |msg_type, payload| {
        if matches!(msg_type, RTM_NEWLINK | RTM_DELLINK)
            && let Some(event) = parse_link(msg_type, payload)
        {
            events.push(event);
        }
    });
    (events, trailer)
}

/// Read the whole link table.
pub fn dump_links() -> io::Result<Vec<LinkInfo>> {
    let sock = NetlinkSocket::open(0, false)?;
    let mut ifi = [0u8; IFINFOMSG_LEN];
    ifi[0] = u8::try_from(libc::AF_UNSPEC).unwrap_or(0);
    sock.send(&message(RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, &ifi, &[]))?;
    let mut buf = vec![0u8; 64 * 1024];
    let mut links = Vec::new();
    loop {
        let got = sock.recv(&mut buf)?;
        let (events, trailer) = parse_link_messages(&buf[..got]);
        links.extend(events.into_iter().filter_map(|e| match e {
            LinkEvent::New(info) => Some(info),
            LinkEvent::Removed { .. } => None,
        }));
        if let Some(errno) = trailer.error {
            return Err(io::Error::from_raw_os_error(errno));
        }
        if trailer.done || got == 0 {
            return Ok(links);
        }
    }
}

/// Packets one link has carried, received plus sent, from its
/// `IFLA_STATS64` counters.
fn link_packets(ifindex: u32) -> io::Result<u64> {
    let sock = NetlinkSocket::open(0, false)?;
    let mut ifi = [0u8; IFINFOMSG_LEN];
    ifi[0] = u8::try_from(libc::AF_UNSPEC).unwrap_or(0);
    let index = i32::try_from(ifindex).map_err(io::Error::other)?;
    ifi[4..8].copy_from_slice(&index.to_ne_bytes());
    sock.send(&message(RTM_GETLINK, NLM_F_REQUEST, &ifi, &[]))?;
    let mut buf = vec![0u8; 16 * 1024];
    let got = sock.recv(&mut buf)?;
    let mut packets = None;
    let trailer = walk(&buf[..got], |msg_type, payload| {
        if msg_type == RTM_NEWLINK {
            packets = parse_link_packets(payload);
        }
    });
    if let Some(errno) = trailer.error {
        return Err(io::Error::from_raw_os_error(errno));
    }
    packets.ok_or_else(|| io::Error::other("no IFLA_STATS64 in the link reply"))
}

/// `rx_packets + tx_packets`, the first two members of the
/// `rtnl_link_stats64` an `RTM_NEWLINK` payload carries.
fn parse_link_packets(payload: &[u8]) -> Option<u64> {
    let attrs = payload.get(nla_align(IFINFOMSG_LEN)..)?;
    let stats = find_attr(attrs, IFLA_STATS64)?;
    let rx = u64::from_ne_bytes(stats.get(0..8)?.try_into().ok()?);
    let tx = u64::from_ne_bytes(stats.get(8..16)?.try_into().ok()?);
    Some(rx.saturating_add(tx))
}

/// The id the namespace behind `ns_file` carries as seen from this socket's
/// namespace, or `None` when it has none yet.
fn namespace_id(sock: &NetlinkSocket, ns_file: &Path) -> io::Result<Option<i32>> {
    let ns = std::fs::File::open(ns_file)?;
    let fd = u32::try_from(ns.as_raw_fd()).map_err(io::Error::other)?;
    let mut body = [0u8; RTGENMSG_LEN];
    body[0] = u8::try_from(libc::AF_UNSPEC).unwrap_or(0);
    sock.send(&message(
        RTM_GETNSID,
        NLM_F_REQUEST,
        &body,
        &attr(NETNSA_FD, &fd.to_ne_bytes()),
    ))?;
    let mut buf = vec![0u8; 4096];
    let got = sock.recv(&mut buf)?;
    let mut nsid = None;
    let trailer = walk(&buf[..got], |msg_type, payload| {
        if msg_type == RTM_NEWNSID {
            nsid = parse_nsid(payload);
        }
    });
    if let Some(errno) = trailer.error {
        return Err(io::Error::from_raw_os_error(errno));
    }
    Ok(nsid)
}

fn parse_nsid(payload: &[u8]) -> Option<i32> {
    let attrs = payload.get(RTGENMSG_LEN..)?;
    attr_u32(attrs, NETNSA_NSID)
        .map(u32::cast_signed)
        .filter(|n| *n >= 0)
}

/// The rtnetlink link group, read asynchronously.
struct Subscription {
    fd: AsyncFd<NetlinkSocket>,
    buf: Vec<u8>,
}

impl Subscription {
    fn open() -> io::Result<Self> {
        Ok(Self {
            // SAFETY: the socket is owned by the `AsyncFd` and closed only
            // when it is dropped, after its registration is gone.
            fd: unsafe {
                AsyncFd::register_with_interest(
                    NetlinkSocket::open(RTMGRP_LINK, true)?,
                    tokio::io::Interest::READABLE,
                )
            }?,
            buf: vec![0u8; 64 * 1024],
        })
    }

    /// The link messages of the next datagram, each with the moment it was
    /// read. `ENOBUFS` means messages were lost and the table has to be
    /// read again.
    async fn next(&mut self) -> io::Result<Vec<(Instant, LinkEvent)>> {
        loop {
            let mut guard = self.fd.readable().await?;
            let buf = &mut self.buf;
            match guard.try_io(|inner| inner.get_ref().recv(buf)) {
                Ok(Ok(got)) => {
                    let at = Instant::now();
                    let (events, _) = parse_link_messages(&self.buf[..got]);
                    return Ok(events.into_iter().map(|e| (at, e)).collect());
                }
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => {}
            }
        }
    }
}

enum Batch {
    Events(Vec<(Instant, LinkEvent)>),
    Overrun,
    Failed(io::Error),
}

/// The first datagram, then whatever else arrives within [`DEBOUNCE`].
async fn gather(sub: &mut Subscription) -> Batch {
    let mut events = match sub.next().await {
        Ok(events) => events,
        Err(e) if e.raw_os_error() == Some(libc::ENOBUFS) => return Batch::Overrun,
        Err(e) => return Batch::Failed(e),
    };
    let deadline = tokio::time::Instant::now() + DEBOUNCE;
    while events.len() < MAX_BATCH {
        match tokio::time::timeout_at(deadline, sub.next()).await {
            Err(_elapsed) => break,
            Ok(Ok(more)) => events.extend(more),
            Ok(Err(e)) if e.raw_os_error() == Some(libc::ENOBUFS) => return Batch::Overrun,
            Ok(Err(e)) => return Batch::Failed(e),
        }
    }
    Batch::Events(events)
}

/// Shared state the blocking half of the watcher works on.
struct Worker {
    table: LinkTable,
    resolver: OwnerResolver,
    registry: Arc<LinkHotPlugRegistry>,
    metrics: Arc<dyn ContainerMetrics>,
}

impl Worker {
    fn resync(&mut self) {
        match dump_links() {
            Ok(links) => {
                if let Some(sink) = &self.registry.coverage {
                    sink.node_encapsulates(encapsulates(&links));
                }
                let plan = self.table.resync(links);
                self.apply(&plan);
            }
            Err(error) => warn!(%error, "hot-plug: the link table could not be read"),
        }
    }

    fn observe(&mut self, events: Vec<(Instant, LinkEvent)>) {
        let plan = self.table.observe_heard(events);
        self.apply(&plan);
    }

    fn apply(&mut self, plan: &Plan) {
        if !plan.is_empty() {
            apply(plan, &self.registry, &mut self.resolver, &*self.metrics);
        }
    }
}

/// Run `job` on the blocking pool: attaching is a run of syscalls per link,
/// and a burst of them must not stall the runtime's workers.
async fn on_worker(worker: &Arc<Mutex<Worker>>, job: impl FnOnce(&mut Worker) + Send + 'static) {
    let worker = Arc::clone(worker);
    let joined = tokio::task::spawn_blocking(move || {
        let mut worker = worker.lock().unwrap_or_else(PoisonError::into_inner);
        job(&mut worker);
    })
    .await;
    if let Err(error) = joined {
        warn!(%error, "hot-plug: a batch of link changes was not applied");
    }
}

/// Watch every link for as long as `cancel` allows.
///
/// The links present at start are attached first: they belong to the
/// workloads that were already running when the agent (re)started.
pub async fn watch_links(
    registry: Arc<LinkHotPlugRegistry>,
    table: LinkTable,
    proc_root: PathBuf,
    metrics: Arc<dyn ContainerMetrics>,
    cancel: CancellationToken,
) {
    let mut sub = match Subscription::open() {
        Ok(sub) => sub,
        Err(error) => {
            warn!(
                %error,
                "hot-plug: the rtnetlink link group could not be joined, so links created \
                 after start are not attached"
            );
            return;
        }
    };
    let worker = Arc::new(Mutex::new(Worker {
        table,
        resolver: OwnerResolver::new(proc_root),
        registry,
        metrics,
    }));
    // The first tick fires at once: that is the initial read of the table,
    // taken after the subscription so nothing between the two is missed.
    let mut resync = tokio::time::interval(RESYNC_INTERVAL);
    resync.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            () = cancel.cancelled() => {
                debug!("hot-plug: link watcher cancelled");
                break;
            }
            _ = resync.tick() => on_worker(&worker, Worker::resync).await,
            batch = gather(&mut sub) => match batch {
                Batch::Events(events) => on_worker(&worker, move |w| w.observe(events)).await,
                Batch::Overrun => {
                    warn!(
                        "hot-plug: link messages were lost to a full socket buffer, \
                         reading the whole link table again"
                    );
                    on_worker(&worker, Worker::resync).await;
                }
                Batch::Failed(error) => {
                    warn!(%error, "hot-plug: reading link messages failed, link watcher stopped");
                    break;
                }
            },
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const ALL: HookPolicy = HookPolicy::Auto;

    /// What the owner reporting told its sink.
    #[derive(Default)]
    struct LinkLog(Mutex<Vec<(u32, Option<u64>)>>);

    impl WorkloadLinkSink for LinkLog {
        fn link_owned(&self, ifindex: u32, cgroup_id: u64) {
            self.0.lock().unwrap().push((ifindex, Some(cgroup_id)));
        }

        fn link_gone(&self, ifindex: u32) {
            self.0.lock().unwrap().push((ifindex, None));
        }
    }

    fn container_owner(pid: u32, cgroup_path: &str) -> LinkOwner {
        LinkOwner {
            pid,
            ns_inode: 1,
            container: Some(ContainerInfo::Container {
                container_id: "abc".to_owned(),
                runtime: domain::container::entity::ContainerRuntime::Containerd,
                cgroup_path: cgroup_path.to_owned(),
                pid,
            }),
        }
    }

    #[test]
    fn a_container_link_is_reported_with_its_cgroup_and_its_owner() {
        use std::os::unix::fs::MetadataExt;

        let cgroups = tempfile::tempdir().unwrap();
        let procs = tempfile::tempdir().unwrap();
        let cgroup = cgroups.path().join("kubepods/pod1/abc");
        std::fs::create_dir_all(&cgroup).unwrap();
        std::fs::create_dir_all(procs.path().join("4242")).unwrap();
        std::fs::write(procs.path().join("4242/comm"), "pause\n").unwrap();
        let ino = std::fs::metadata(&cgroup).unwrap().ino();

        let log = Arc::new(LinkLog::default());
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let reporting = OwnerReporting::new(
            Arc::clone(&log) as Arc<dyn WorkloadLinkSink>,
            cgroups.path().to_path_buf(),
            procs.path().to_path_buf(),
        )
        .with_processes(tx);

        reporting.owned(7, Some(&container_owner(4242, "/kubepods/pod1/abc")));
        assert_eq!(*log.0.lock().unwrap(), vec![(7, Some(ino))]);
        let event = rx.try_recv().unwrap();
        assert_eq!(event.kind, ProcessEventKind::Exec);
        assert_eq!((event.pid, event.tgid, event.cgroup_id), (4242, 4242, ino));
        assert_eq!(event.comm, "pause");
    }

    #[test]
    fn a_link_without_a_container_owner_is_no_link() {
        let cgroups = tempfile::tempdir().unwrap();
        let log = Arc::new(LinkLog::default());
        let reporting = OwnerReporting::new(
            Arc::clone(&log) as Arc<dyn WorkloadLinkSink>,
            cgroups.path().to_path_buf(),
            cgroups.path().to_path_buf(),
        );

        reporting.owned(7, None);
        let host = LinkOwner {
            pid: 1,
            ns_inode: 1,
            container: Some(ContainerInfo::Host),
        };
        reporting.owned(8, Some(&host));
        // A container whose cgroup is gone has no id to name.
        reporting.owned(9, Some(&container_owner(5, "/kubepods/gone")));
        assert_eq!(
            *log.0.lock().unwrap(),
            vec![(7, None), (8, None), (9, None)]
        );
    }

    #[test]
    fn a_released_link_is_withdrawn() {
        let log = Arc::new(LinkLog::default());
        let mut registry = LinkHotPlugRegistry::new();
        registry.report_owners(OwnerReporting::new(
            Arc::clone(&log) as Arc<dyn WorkloadLinkSink>,
            PathBuf::from("/nonexistent"),
            PathBuf::from("/nonexistent"),
        ));
        registry.detach(&Detach {
            ifindex: 7,
            name: String::new(),
        });
        assert_eq!(*log.0.lock().unwrap(), vec![(7, None)]);
    }

    /// What the watcher reported through the metrics port.
    #[derive(Default)]
    struct Recorded {
        gaps: Mutex<Vec<(String, f64)>>,
        packets: Mutex<Vec<(String, u64)>>,
    }

    impl ContainerMetrics for Recorded {
        fn observe_link_attach_gap(&self, kind: &str, seconds: f64) {
            self.gaps.lock().unwrap().push((kind.to_owned(), seconds));
        }

        fn record_link_unguarded_packets(&self, kind: &str, packets: u64) {
            self.packets
                .lock()
                .unwrap()
                .push((kind.to_owned(), packets));
        }
    }

    fn link(ifindex: u32, name: &str, kind: Option<&str>) -> LinkInfo {
        LinkInfo {
            ifindex,
            name: name.to_owned(),
            kind: kind.map(str::to_owned),
            slave_kind: None,
            master: None,
            peer_ifindex: None,
            link_netnsid: None,
        }
    }

    fn new(ifindex: u32, name: &str, kind: &str) -> LinkEvent {
        LinkEvent::New(link(ifindex, name, Some(kind)))
    }

    fn gone(ifindex: u32, name: &str) -> LinkEvent {
        LinkEvent::Removed {
            ifindex,
            name: name.to_owned(),
        }
    }

    fn names(plan: &Plan) -> (Vec<&str>, Vec<&str>) {
        (
            plan.attach.iter().map(|a| a.link.name.as_str()).collect(),
            plan.detach.iter().map(|d| d.name.as_str()).collect(),
        )
    }

    /// A link message the way the kernel lays it out.
    fn wire(msg_type: u16, l: &LinkInfo) -> Vec<u8> {
        let mut ifi = [0u8; IFINFOMSG_LEN];
        ifi[4..8].copy_from_slice(&i32::try_from(l.ifindex).unwrap().to_ne_bytes());
        let mut attrs = Vec::new();
        let mut name = l.name.clone().into_bytes();
        name.push(0);
        attrs.extend(attr(IFLA_IFNAME, &name));
        if let Some(peer) = l.peer_ifindex {
            attrs.extend(attr(IFLA_LINK, &peer.to_ne_bytes()));
        }
        if let Some(master) = l.master {
            attrs.extend(attr(IFLA_MASTER, &master.to_ne_bytes()));
        }
        let mut info = Vec::new();
        if let Some(kind) = &l.kind {
            let mut k = kind.clone().into_bytes();
            k.push(0);
            info.extend(attr(IFLA_INFO_KIND, &k));
        }
        if let Some(kind) = &l.slave_kind {
            let mut k = kind.clone().into_bytes();
            k.push(0);
            info.extend(attr(IFLA_INFO_SLAVE_KIND, &k));
        }
        if !info.is_empty() {
            attrs.extend(attr(IFLA_LINKINFO | 0x8000, &info));
        }
        if let Some(nsid) = l.link_netnsid {
            attrs.extend(attr(IFLA_LINK_NETNSID, &nsid.to_ne_bytes()));
        }
        message(msg_type, 0, &ifi, &attrs)
    }

    #[test]
    fn a_veth_message_is_read_with_its_peer_and_its_namespace() {
        let sent = LinkInfo {
            ifindex: 41,
            name: "veth3f2a".into(),
            kind: Some("veth".into()),
            slave_kind: Some("bridge".into()),
            master: Some(4),
            peer_ifindex: Some(2),
            link_netnsid: Some(7),
        };
        let (events, trailer) = parse_link_messages(&wire(RTM_NEWLINK, &sent));
        assert_eq!(events, vec![LinkEvent::New(sent)]);
        assert_eq!(trailer, Trailer::default());
    }

    #[test]
    fn several_messages_in_one_datagram_are_all_read_up_to_done() {
        let mut buf = wire(RTM_NEWLINK, &link(5, "nk0", Some("netkit")));
        buf.extend(wire(RTM_DELLINK, &link(6, "veth1", Some("veth"))));
        buf.extend(message(NLMSG_DONE, 0, &[0; 4], &[]));
        buf.extend(wire(RTM_NEWLINK, &link(7, "after", None)));
        let (events, trailer) = parse_link_messages(&buf);
        assert_eq!(events, vec![new(5, "nk0", "netkit"), gone(6, "veth1")]);
        assert!(trailer.done);
    }

    #[test]
    fn an_error_reply_carries_its_errno() {
        let buf = message(NLMSG_ERROR, 0, &(-libc::EPERM).to_ne_bytes(), &[]);
        let (_, trailer) = parse_link_messages(&buf);
        assert_eq!(trailer.error, Some(libc::EPERM));
    }

    #[test]
    fn a_truncated_message_is_dropped_rather_than_misread() {
        let buf = wire(RTM_NEWLINK, &link(5, "veth0", Some("veth")));
        let (events, _) = parse_link_messages(&buf[..buf.len() - 3]);
        assert!(events.is_empty());
    }

    #[test]
    fn a_namespace_id_reply_is_read() {
        let mut body = vec![0u8; RTGENMSG_LEN];
        body.extend(attr(NETNSA_NSID, &3i32.to_ne_bytes()));
        assert_eq!(parse_nsid(&body), Some(3));
        let mut unassigned = vec![0u8; RTGENMSG_LEN];
        unassigned.extend(attr(NETNSA_NSID, &(-1i32).to_ne_bytes()));
        assert_eq!(parse_nsid(&unassigned), None);
    }

    #[test]
    fn workload_kinds_are_told_from_infrastructure() {
        let mut tap = link(1, "tap0", Some("tun"));
        assert_eq!(classify(&tap), LinkClass::Unknown("tun".into()));
        tap.slave_kind = Some("bridge".into());
        assert_eq!(
            classify(&tap),
            LinkClass::Workload(WorkloadKind::BridgeMember)
        );

        let mut uplink = link(2, "eth0", None);
        uplink.slave_kind = Some("bridge".into());
        assert_eq!(classify(&uplink), LinkClass::Infrastructure);

        for (kind, want) in [
            ("veth", WorkloadKind::Veth),
            ("netkit", WorkloadKind::Netkit),
            ("macvlan", WorkloadKind::Macvlan),
            ("ipvlan", WorkloadKind::Ipvlan),
        ] {
            assert_eq!(
                classify(&link(3, "x", Some(kind))),
                LinkClass::Workload(want)
            );
        }
        for kind in ["bridge", "vxlan", "bond", "vlan", "wireguard"] {
            assert_eq!(
                classify(&link(4, "x", Some(kind))),
                LinkClass::Infrastructure
            );
        }
        assert_eq!(classify(&link(5, "lo", None)), LinkClass::Infrastructure);
    }

    #[test]
    fn fifty_containers_starting_at_once_are_fifty_attaches() {
        let mut table = LinkTable::new(ALL, []);
        let mut events = Vec::new();
        for i in 0..50u32 {
            let name = format!("veth{i:04}");
            // Created, moved, brought up: three messages per container.
            events.push(new(100 + i, &name, "veth"));
            let mut moved = link(100 + i, &name, Some("veth"));
            moved.link_netnsid = i32::try_from(i).ok();
            events.push(LinkEvent::New(moved.clone()));
            events.push(LinkEvent::New(moved));
        }
        // Ten more created and torn down inside the same window.
        for i in 0..10u32 {
            events.push(new(500 + i, &format!("vethx{i}"), "veth"));
            events.push(gone(500 + i, &format!("vethx{i}")));
        }
        let plan = table.observe(events);
        assert_eq!(plan.attach.len(), 50);
        assert!(plan.detach.is_empty());
        assert!(plan.attach.iter().all(|a| a.link.link_netnsid.is_some()));
        assert_eq!(table.attached_count(), 50);
    }

    #[test]
    fn a_repeated_announcement_of_an_attached_link_changes_nothing() {
        let mut table = LinkTable::new(ALL, []);
        assert_eq!(table.observe(vec![new(9, "veth9", "veth")]).attach.len(), 1);
        assert!(table.observe(vec![new(9, "veth9", "veth")]).is_empty());
    }

    #[test]
    fn a_removed_link_is_released_once() {
        let mut table = LinkTable::new(ALL, []);
        table.observe(vec![new(9, "veth9", "veth")]);
        let plan = table.observe(vec![gone(9, "veth9")]);
        assert_eq!(names(&plan), (vec![], vec!["veth9"]));
        assert!(table.observe(vec![gone(9, "veth9")]).is_empty());
    }

    #[test]
    fn a_renamed_link_is_released_under_its_old_name_and_attached_under_its_new_one() {
        let mut table = LinkTable::new(ALL, []);
        table.observe(vec![new(9, "veth9", "veth")]);
        let plan = table.observe(vec![new(9, "eth-pod", "veth")]);
        assert_eq!(names(&plan), (vec!["eth-pod"], vec!["veth9"]));
    }

    #[test]
    fn a_tap_joining_a_bridge_is_attached_and_released_when_it_leaves() {
        let mut table = LinkTable::new(ALL, []);
        let mut tap = link(12, "tap0", Some("tun"));
        let plan = table.observe(vec![LinkEvent::New(tap.clone())]);
        assert!(plan.attach.is_empty());
        tap.slave_kind = Some("bridge".into());
        tap.master = Some(3);
        let plan = table.observe(vec![LinkEvent::New(tap.clone())]);
        assert_eq!(names(&plan), (vec!["tap0"], vec![]));
        tap.slave_kind = None;
        tap.master = None;
        let plan = table.observe(vec![LinkEvent::New(tap)]);
        assert_eq!(names(&plan), (vec![], vec!["tap0"]));
    }

    #[test]
    fn an_unknown_kind_is_reported_once_with_its_kind() {
        let mut table = LinkTable::new(ALL, []);
        let plan = table.observe(vec![new(1, "tun0", "tun"), new(2, "tun1", "tun")]);
        assert_eq!(plan.unknown, vec![("tun".to_owned(), "tun0".to_owned())]);
        assert!(plan.attach.is_empty());
        assert!(table.observe(vec![new(3, "tun2", "tun")]).is_empty());
    }

    #[test]
    fn a_configured_interface_is_left_to_the_configuration() {
        let mut table = LinkTable::new(ALL, ["veth-cfg".to_owned()]);
        assert!(table.observe(vec![new(4, "veth-cfg", "veth")]).is_empty());
    }

    #[test]
    fn the_attach_mode_decides_which_hooks_the_hot_plug_uses() {
        let both = || vec![new(1, "nk0", "netkit"), new(2, "veth0", "veth")];
        let hooks = |plan: &Plan| {
            plan.attach
                .iter()
                .map(|a| (a.link.name.clone(), a.via_netkit))
                .collect::<Vec<_>>()
        };
        let auto = LinkTable::new(HookPolicy::Auto, []).observe(both());
        assert_eq!(
            hooks(&auto),
            vec![("nk0".to_owned(), true), ("veth0".to_owned(), false)]
        );
        let tcx = LinkTable::new(HookPolicy::Tcx, []).observe(both());
        assert_eq!(
            hooks(&tcx),
            vec![("nk0".to_owned(), false), ("veth0".to_owned(), false)]
        );
        let netkit = LinkTable::new(HookPolicy::Netkit, []).observe(both());
        assert_eq!(hooks(&netkit), vec![("nk0".to_owned(), true)]);
    }

    #[test]
    fn a_workload_link_left_alone_is_reported_once_per_reason_and_forgotten() {
        let mut table = LinkTable::new(HookPolicy::Netkit, []);
        let plan = table.observe(vec![new(2, "veth0", "veth")]);
        assert_eq!(
            plan.left
                .iter()
                .map(|(l, r)| (l.ifindex, r.clone()))
                .collect::<Vec<_>>(),
            vec![(2, LinkRefusal::AttachMode("netkit".to_owned()))]
        );
        assert!(table.observe(vec![new(2, "veth0", "veth")]).is_empty());
        assert_eq!(table.observe(vec![gone(2, "veth0")]).forget, vec![2]);
    }

    #[test]
    fn an_unknown_kind_leading_into_a_namespace_is_a_workload_left_alone() {
        let mut table = LinkTable::new(ALL, []);
        let mut tun = link(5, "tun0", Some("tun"));
        tun.link_netnsid = Some(3);
        let plan = table.observe(vec![LinkEvent::New(tun)]);
        assert_eq!(plan.left[0].1, LinkRefusal::UnknownKind("tun".to_owned()));
        // The host's own device of an unknown kind is reported, not left.
        let plan = table.observe(vec![new(6, "odd0", "odd")]);
        assert!(plan.left.is_empty());
        assert_eq!(plan.unknown.len(), 1);
        // A resync that no longer lists it forgets it.
        assert_eq!(table.resync(Vec::new()).forget, vec![5]);
    }

    #[test]
    fn the_pod_is_read_off_the_owner_cgroup_path() {
        let uid = "6f1c2d3e-4a5b-4c6d-8e7f-0123456789ab";
        let systemd = container_owner(
            1,
            "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod6f1c2d3e_4a5b_4c6d_8e7f_0123456789ab.slice/cri-containerd-abc.scope",
        );
        assert_eq!(owner_pod_uid(Some(&systemd)).as_deref(), Some(uid));
        let cgroupfs = container_owner(1, &format!("/kubepods/besteffort/pod{uid}/abc"));
        assert_eq!(owner_pod_uid(Some(&cgroupfs)).as_deref(), Some(uid));
        assert_eq!(
            owner_pod_uid(Some(&container_owner(1, "/docker/abc"))),
            None
        );
        assert_eq!(owner_pod_uid(None), None);
    }

    #[test]
    fn encapsulating_devices_are_told_from_the_rest() {
        assert!(encapsulates(&[link(1, "flannel.1", Some("vxlan"))]));
        assert!(encapsulates(&[link(1, "wg0", Some("wireguard"))]));
        assert!(!encapsulates(&[
            link(1, "eth0", None),
            link(2, "veth1", Some("veth"))
        ]));
    }

    /// What the registry told the coverage sink.
    #[derive(Default)]
    struct CoverageLog(Mutex<Vec<(u32, Option<LinkAttachment>)>>);

    impl LinkCoverageSink for CoverageLog {
        fn link_seen(&self, link: WorkloadLink) {
            self.0
                .lock()
                .unwrap()
                .push((link.ifindex, Some(link.attachment)));
        }

        fn link_forgotten(&self, ifindex: u32) {
            self.0.lock().unwrap().push((ifindex, None));
        }

        fn node_encapsulates(&self, _: bool) {}
    }

    #[test]
    fn the_registry_reports_links_left_and_released_to_the_coverage_sink() {
        let log = Arc::new(CoverageLog::default());
        let mut registry = LinkHotPlugRegistry::new();
        registry.report_coverage(Arc::clone(&log) as Arc<dyn LinkCoverageSink>);
        registry.left(
            &link(4, "veth4", Some("veth")),
            LinkRefusal::AttachMode("netkit".to_owned()),
            None,
        );
        registry.detach(&Detach {
            ifindex: 7,
            name: String::new(),
        });
        assert_eq!(
            *log.0.lock().unwrap(),
            vec![
                (
                    4,
                    Some(LinkAttachment::Refused(LinkRefusal::AttachMode(
                        "netkit".to_owned()
                    )))
                ),
                (7, None),
            ]
        );
    }

    #[test]
    fn a_resync_releases_what_the_table_no_longer_lists() {
        let mut table = LinkTable::new(ALL, []);
        table.observe(vec![new(1, "veth1", "veth"), new(2, "veth2", "veth")]);
        let plan = table.resync(vec![
            link(2, "veth2", Some("veth")),
            link(3, "veth3", Some("veth")),
        ]);
        assert_eq!(
            plan.detach.iter().map(|d| d.ifindex).collect::<Vec<_>>(),
            vec![1]
        );
        assert_eq!(names(&plan).0, vec!["veth3"]);
    }

    #[test]
    fn the_kernel_link_table_is_read_and_holds_loopback() {
        // Reading the table needs no privilege in the caller's namespace.
        let links = dump_links().unwrap();
        let lo = links.iter().find(|l| l.name == "lo").unwrap();
        assert_eq!(classify(lo), LinkClass::Infrastructure);
    }

    #[test]
    fn the_link_group_can_be_joined_without_privilege() {
        assert!(NetlinkSocket::open(RTMGRP_LINK, true).is_ok());
    }

    #[test]
    fn every_namespace_is_listed_once() {
        let nss = network_namespaces(Path::new("/proc"));
        assert_ne!(nss, Vec::new());
        let unique: HashSet<u64> = nss.iter().map(|(_, ino)| *ino).collect();
        assert_eq!(unique.len(), nss.len());
    }

    #[test]
    fn a_registry_with_nothing_to_attach_holds_nothing() {
        let mut reg = LinkHotPlugRegistry::new();
        reg.register("tc_ids".into(), -1, HookSide::Ingress);
        let target = Attach {
            link: link(999_999, "nonexistent_xyz", Some("veth")),
            kind: WorkloadKind::Veth,
            via_netkit: false,
            heard_at: Some(Instant::now()),
        };
        assert_eq!(reg.attach(&target, None), 0);
        assert_eq!(reg.link_count(), 0);
        reg.detach(&Detach {
            ifindex: 999_999,
            name: "nonexistent_xyz".into(),
        });
        assert_eq!(reg.program_count(), 1);
    }

    #[test]
    fn an_announced_link_carries_the_moment_it_was_first_heard() {
        let mut table = LinkTable::new(ALL, []);
        let first = Instant::now();
        let later = first + Duration::from_millis(40);
        let mut moved = link(7, "veth7", Some("veth"));
        moved.link_netnsid = Some(2);
        let plan = table.observe_heard(vec![
            (first, new(7, "veth7", "veth")),
            (later, LinkEvent::New(moved)),
        ]);
        assert_eq!(plan.attach.len(), 1);
        assert_eq!(plan.attach[0].heard_at, Some(first));
        assert_eq!(plan.attach[0].link.link_netnsid, Some(2));
    }

    #[test]
    fn a_link_found_in_the_table_has_no_announcement_to_measure_from() {
        let mut table = LinkTable::new(ALL, []);
        let plan = table.resync(vec![link(3, "veth3", Some("veth"))]);
        assert_eq!(plan.attach.len(), 1);
        assert_eq!(plan.attach[0].heard_at, None);
    }

    #[test]
    fn a_renamed_link_is_not_counted_as_unguarded() {
        let mut table = LinkTable::new(ALL, []);
        table.observe_heard(vec![(Instant::now(), new(9, "veth9", "veth"))]);
        let plan = table.observe_heard(vec![(Instant::now(), new(9, "eth-pod", "veth"))]);
        assert_eq!(names(&plan), (vec!["eth-pod"], vec!["veth9"]));
        assert_eq!(plan.attach[0].heard_at, None);
    }

    #[test]
    fn a_heard_link_that_is_not_attached_leaves_nothing_behind() {
        let mut table = LinkTable::new(ALL, []);
        table.observe_heard(vec![(Instant::now(), new(12, "tap0", "tun"))]);
        // Joining a bridge later is a resync finding, not the old announcement.
        let mut tap = link(12, "tap0", Some("tun"));
        tap.slave_kind = Some("bridge".into());
        let plan = table.resync(vec![tap]);
        assert_eq!(plan.attach[0].heard_at, None);
    }

    #[test]
    fn link_counters_are_read_from_the_stats64_attribute() {
        let mut stats = vec![0u8; 24 * 8];
        stats[0..8].copy_from_slice(&1_200u64.to_ne_bytes());
        stats[8..16].copy_from_slice(&34u64.to_ne_bytes());
        stats[16..24].copy_from_slice(&999_999u64.to_ne_bytes());
        let mut payload = vec![0u8; IFINFOMSG_LEN];
        payload.extend(attr(IFLA_IFNAME, b"veth0\0"));
        payload.extend(attr(IFLA_STATS64, &stats));
        assert_eq!(parse_link_packets(&payload), Some(1_234));
        let mut bare = vec![0u8; IFINFOMSG_LEN];
        bare.extend(attr(IFLA_IFNAME, b"veth0\0"));
        assert_eq!(parse_link_packets(&bare), None);
    }

    #[test]
    fn the_gap_and_the_packets_carried_meanwhile_are_reported() {
        let lo = dump_links()
            .unwrap()
            .into_iter()
            .find(|l| l.name == "lo")
            .unwrap();
        let target = Attach {
            link: lo,
            kind: WorkloadKind::Veth,
            via_netkit: false,
            heard_at: None,
        };
        let recorded = Recorded::default();
        record_gap(&target, Duration::from_millis(120), &recorded);
        assert_eq!(
            *recorded.gaps.lock().unwrap(),
            vec![("veth".to_owned(), 0.12)]
        );
        let packets = recorded.packets.lock().unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].0, "veth");
    }

    #[test]
    fn an_attach_that_made_no_link_reports_no_gap() {
        let mut reg = LinkHotPlugRegistry::new();
        reg.register("tc_ids".into(), -1, HookSide::Ingress);
        let plan = Plan {
            attach: vec![Attach {
                link: link(999_998, "nonexistent_abc", Some("veth")),
                kind: WorkloadKind::Veth,
                via_netkit: false,
                heard_at: Some(Instant::now()),
            }],
            ..Plan::default()
        };
        let recorded = Recorded::default();
        apply(
            &plan,
            &reg,
            &mut OwnerResolver::new(PathBuf::from("/proc")),
            &recorded,
        );
        assert!(recorded.gaps.lock().unwrap().is_empty());
        assert!(recorded.packets.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_watcher_starts_and_stops() {
        let cancel = CancellationToken::new();
        let handle = tokio::spawn(watch_links(
            Arc::new(LinkHotPlugRegistry::new()),
            LinkTable::new(ALL, []),
            PathBuf::from("/proc"),
            Arc::new(Recorded::default()),
            cancel.clone(),
        ));
        tokio::time::sleep(Duration::from_millis(50)).await;
        cancel.cancel();
        handle.await.unwrap();
    }
}
