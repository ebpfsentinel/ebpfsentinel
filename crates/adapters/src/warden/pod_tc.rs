//! The TC chain inside each selected pod, attached through the warden.
//!
//! A pod profile agent runs beside the node agent and attaches where the node
//! agent cannot see: on the pod's own interfaces and its loopback, which exist
//! only in the pod's network namespace. Entering that namespace needs a
//! capability the agent's user namespace does not hold, so each link is made by
//! the warden and handed back; the agent holds the link fds, one set per pod,
//! and dropping a pod's set detaches it.

use std::collections::{BTreeSet, HashMap};
use std::io;
use std::os::fd::{OwnedFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use domain::coverage::PodSubject;
use ebpfsentinel_warden_client::ReconnectingClient;
use infrastructure::config::PodSelectorConfig;
use ports::secondary::pod_coverage_port::PodInventoryPort;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::container::pod_claims::{PodClaimsDir, now_secs};
use crate::ebpf::link_watcher::HookSide;

/// How often the selected pods are read again. A pod that started since is
/// covered within this long; one that went is released within it too.
const RECONCILE_EVERY: Duration = Duration::from_secs(15);

/// The interfaces assumed when a pod's interface list cannot be read: the
/// one every pod network gives it and its loopback.
const DEFAULT_INTERFACES: &[&str] = &["lo", "eth0"];

/// Makes one link inside a pod's namespace.
pub trait PodLinkAttach: Send {
    /// Attach `prog_fd` on `iface`'s ingress or egress hook inside the
    /// namespace of `pid`. The returned fd owns the link.
    fn attach(
        &mut self,
        pid: u32,
        iface: &str,
        egress: bool,
        prog_fd: RawFd,
    ) -> io::Result<OwnedFd>;
}

/// The warden, over the one connection this attacher keeps.
pub struct WardenPodLinks {
    client: ReconnectingClient,
}

impl WardenPodLinks {
    #[must_use]
    pub fn new(sock: &Path) -> Self {
        Self {
            client: ReconnectingClient::new(sock.to_path_buf()),
        }
    }
}

impl PodLinkAttach for WardenPodLinks {
    fn attach(
        &mut self,
        pid: u32,
        iface: &str,
        egress: bool,
        prog_fd: RawFd,
    ) -> io::Result<OwnedFd> {
        self.client.attach_tcx_in_netns(pid, iface, egress, prog_fd)
    }
}

/// The links held for one pod.
struct PodLinks {
    /// The namespace they were made in. A pod whose sandbox was recreated
    /// keeps its uid and gets a new namespace, which the links did not follow.
    netns: u64,
    /// When the chain went on, which the claim carries so the node agent can
    /// say how long both agents read the pod.
    since_secs: u64,
    links: Vec<OwnedFd>,
}

/// What one pass changed.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Reconciled {
    /// Pods whose chain was attached on this pass.
    pub attached: usize,
    /// Pods whose links were dropped because they went, stopped being
    /// selected or moved to a new namespace.
    pub released: usize,
    /// Pods the chain could not be attached in, tried again on the next pass.
    pub failed: usize,
}

/// The selected pods and the chain held inside each.
pub struct PodTcAttacher<A: PodLinkAttach> {
    attach: A,
    programs: Vec<(String, RawFd, HookSide)>,
    selector: PodSelectorConfig,
    proc_root: PathBuf,
    held: HashMap<String, PodLinks>,
    claims: Option<PodClaimsDir>,
}

impl<A: PodLinkAttach> PodTcAttacher<A> {
    /// `programs` are the loaded TC programs, each with its side, in the
    /// order they run on that side.
    pub fn new(
        attach: A,
        programs: Vec<(String, RawFd, HookSide)>,
        selector: PodSelectorConfig,
        proc_root: PathBuf,
    ) -> Self {
        Self {
            attach,
            programs,
            selector,
            proc_root,
            held: HashMap::new(),
            claims: None,
        }
    }

    /// Say through `claims` which pods carry the chain, so the node agent
    /// stands back from their links instead of reading them a second time.
    #[must_use]
    pub fn with_claims(mut self, claims: PodClaimsDir) -> Self {
        self.claims = Some(claims);
        self
    }

    /// Pods currently carrying the chain.
    #[must_use]
    pub fn pod_count(&self) -> usize {
        self.held.len()
    }

    /// Links held across every pod, each one a program on one hook.
    #[must_use]
    pub fn link_count(&self) -> usize {
        self.held.values().map(|pod| pod.links.len()).sum()
    }

    /// Bring the held links in line with the pods the inventory reads.
    pub fn reconcile(&mut self, pods: &[PodSubject]) -> Reconciled {
        let mut outcome = Reconciled::default();
        let wanted: HashMap<&str, &PodSubject> = pods
            .iter()
            .filter(|pod| !pod.host_network && self.selector.selects(&pod.namespace, &pod.labels))
            .map(|pod| (pod.uid.as_str(), pod))
            .collect();
        let processes = pod_processes(&self.proc_root);

        let mut released = Vec::new();
        self.held.retain(|uid, links| {
            let keep = wanted.contains_key(uid.as_str())
                && processes
                    .get(uid)
                    .and_then(|pid| netns_inode(&self.proc_root, *pid))
                    .is_some_and(|netns| netns == links.netns);
            if !keep {
                released.push(uid.clone());
            }
            keep
        });
        outcome.released = released.len();

        for (uid, pod) in wanted {
            if self.held.contains_key(uid) {
                continue;
            }
            let Some(&pid) = processes.get(uid) else {
                debug!(pod = %pod.name, namespace = %pod.namespace, "pod profile: no running process in the pod yet");
                continue;
            };
            let Some(netns) = netns_inode(&self.proc_root, pid) else {
                continue;
            };
            let interfaces = interfaces_of(&self.proc_root, pid);
            match self.attach_pod(pid, &interfaces) {
                Ok(links) => {
                    info!(
                        pod = %pod.name,
                        namespace = %pod.namespace,
                        interfaces = ?interfaces,
                        links = links.len(),
                        "pod profile: chain attached inside the pod"
                    );
                    self.held.insert(
                        uid.to_string(),
                        PodLinks {
                            netns,
                            since_secs: now_secs(),
                            links,
                        },
                    );
                    outcome.attached += 1;
                }
                Err(error) => {
                    warn!(
                        pod = %pod.name,
                        namespace = %pod.namespace,
                        %error,
                        "pod profile: chain not attached inside the pod, retried on the next pass"
                    );
                    outcome.failed += 1;
                }
            }
        }
        self.publish_claims(&released);
        outcome
    }

    /// Withdraw the claims on the pods let go and refresh every other one.
    /// The links are dropped before their claim is withdrawn, so the pod is
    /// never read by nobody on the pod agent's account.
    fn publish_claims(&self, released: &[String]) {
        let Some(claims) = &self.claims else {
            return;
        };
        for uid in released {
            if let Err(error) = claims.release(uid) {
                warn!(pod = %uid, %error, "pod profile: claim not withdrawn, it lapses on its own");
            }
        }
        for (uid, pod) in &self.held {
            if let Err(error) = claims.claim(uid, pod.netns, pod.since_secs) {
                warn!(
                    pod = %uid,
                    dir = %claims.dir().display(),
                    %error,
                    "pod profile: claim not written, the node agent keeps reading this pod too"
                );
            }
        }
    }

    /// Attach every program on every interface, or nothing: a chain with a
    /// program missing runs the rest in an order nobody chose, so the links
    /// already made are dropped with the first refusal.
    fn attach_pod(&mut self, pid: u32, interfaces: &[String]) -> io::Result<Vec<OwnedFd>> {
        let mut links = Vec::with_capacity(interfaces.len() * self.programs.len());
        for iface in interfaces {
            for (name, fd, side) in &self.programs {
                let egress = *side == HookSide::Egress;
                let link = self
                    .attach
                    .attach(pid, iface, egress, *fd)
                    .map_err(|error| {
                        io::Error::new(error.kind(), format!("{name} on {iface}: {error}"))
                    })?;
                links.push(link);
            }
        }
        Ok(links)
    }
}

/// Keep the chain inside every selected pod until `cancel` fires, reading
/// the inventory again on a fixed beat.
pub async fn run<A: PodLinkAttach + 'static>(
    attacher: PodTcAttacher<A>,
    inventory: Arc<dyn PodInventoryPort>,
    cancel: CancellationToken,
) {
    let attacher = Arc::new(Mutex::new(attacher));
    loop {
        let pods = inventory.pods().await;
        let pass = Arc::clone(&attacher);
        // The warden calls block on a socket, so a pass runs off the runtime.
        let outcome = tokio::task::spawn_blocking(move || {
            let mut attacher = pass
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let outcome = attacher.reconcile(&pods);
            (outcome, attacher.pod_count(), attacher.link_count())
        })
        .await;
        match outcome {
            Ok((outcome, pods, links)) if outcome != Reconciled::default() => info!(
                attached = outcome.attached,
                released = outcome.released,
                failed = outcome.failed,
                pods,
                links,
                "pod profile: selected pods reconciled"
            ),
            Ok(_) => {}
            Err(error) => warn!(%error, "pod profile: a reconcile pass did not finish"),
        }
        tokio::select! {
            () = cancel.cancelled() => break,
            () = tokio::time::sleep(RECONCILE_EVERY) => {}
        }
    }
}

/// One process per pod uid, read from the cgroup each process sits in.
fn pod_processes(proc_root: &Path) -> HashMap<String, u32> {
    let mut found = HashMap::new();
    let Ok(entries) = std::fs::read_dir(proc_root) else {
        return found;
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(cgroup) = std::fs::read_to_string(entry.path().join("cgroup")) else {
            continue;
        };
        if let Some(uid) = pod_uid_of(&cgroup) {
            found.entry(uid).or_insert(pid);
        }
    }
    found
}

/// The pod uid a `/proc/<pid>/cgroup` payload names, under either driver.
fn pod_uid_of(payload: &str) -> Option<String> {
    payload.lines().find_map(|line| {
        let path = line.splitn(3, ':').nth(2)?;
        if !path.contains("kubepods") {
            return None;
        }
        path.split('/')
            .find_map(crate::container::pod_cgroups::pod_uid)
    })
}

/// Inode of the network namespace process `pid` is in.
fn netns_inode(proc_root: &Path, pid: u32) -> Option<u64> {
    std::fs::metadata(proc_root.join(pid.to_string()).join("ns").join("net"))
        .ok()
        .map(|meta| meta.ino())
}

/// The interfaces inside the namespace of `pid`, from its own view of
/// `net/dev`, or the defaults when that cannot be read.
fn interfaces_of(proc_root: &Path, pid: u32) -> Vec<String> {
    std::fs::read_to_string(proc_root.join(pid.to_string()).join("net").join("dev"))
        .ok()
        .map(|raw| parse_net_dev(&raw))
        .filter(|names| !names.is_empty())
        .unwrap_or_else(|| {
            DEFAULT_INTERFACES
                .iter()
                .map(|n| (*n).to_string())
                .collect()
        })
}

/// Interface names out of a `/proc/net/dev` payload, in a stable order.
fn parse_net_dev(raw: &str) -> Vec<String> {
    raw.lines()
        .skip(2)
        .filter_map(|line| line.split_once(':'))
        .map(|(name, _)| name.trim().to_string())
        .filter(|name| !name.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    const UID: &str = "6f1c2d3e-4a5b-4c6d-8e7f-0123456789ab";
    const OTHER: &str = "7a2b3c4d-5e6f-4a1b-8c2d-0123456789cd";

    const NET_DEV: &str = "Inter-|   Receive                |  Transmit\n \
         face |bytes    packets errs drop|bytes    packets\n    \
         lo: 100 1 0 0 100 1\n  eth0: 200 2 0 0 200 2\n";

    /// One attach as the recorder saw it: pid, interface, egress, program.
    type Call = (u32, String, bool, RawFd);

    /// Records every attach and refuses the ones it was told to.
    #[derive(Default)]
    struct Recorder {
        calls: Arc<Mutex<Vec<Call>>>,
        refuse_iface: Option<String>,
    }

    impl PodLinkAttach for Recorder {
        fn attach(
            &mut self,
            pid: u32,
            iface: &str,
            egress: bool,
            prog_fd: RawFd,
        ) -> io::Result<OwnedFd> {
            if self.refuse_iface.as_deref() == Some(iface) {
                return Err(io::Error::other("refused"));
            }
            self.calls
                .lock()
                .unwrap()
                .push((pid, iface.to_string(), egress, prog_fd));
            Ok(std::fs::File::open("/dev/null").unwrap().into())
        }
    }

    fn pod(uid: &str, namespace: &str, labels: &[(&str, &str)]) -> PodSubject {
        PodSubject {
            uid: uid.into(),
            name: format!("pod-{}", &uid[..4]),
            namespace: namespace.into(),
            host_network: false,
            labels: labels
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
        }
    }

    /// A procfs with one process per `(pid, pod uid)`, each in a namespace
    /// file of its own named by `netns`.
    fn procfs(dir: &Path, processes: &[(u32, &str, &str)]) {
        for (pid, uid, netns) in processes {
            let process = dir.join(pid.to_string());
            std::fs::create_dir_all(process.join("ns")).unwrap();
            std::fs::create_dir_all(process.join("net")).unwrap();
            std::fs::write(
                process.join("cgroup"),
                format!("0::/kubepods/besteffort/pod{uid}/abc\n"),
            )
            .unwrap();
            let shared = dir.join(format!("netns-{netns}"));
            if !shared.exists() {
                std::fs::write(&shared, "").unwrap();
            }
            let _ = std::fs::remove_file(process.join("ns").join("net"));
            std::fs::hard_link(&shared, process.join("ns").join("net")).unwrap();
            std::fs::write(process.join("net").join("dev"), NET_DEV).unwrap();
        }
    }

    fn selector() -> PodSelectorConfig {
        PodSelectorConfig {
            namespaces: vec!["shop".into()],
            match_labels: BTreeMap::from([("app".into(), "cart".into())]),
        }
    }

    fn programs() -> Vec<(String, RawFd, HookSide)> {
        vec![
            ("tc_ids".into(), 10, HookSide::Ingress),
            ("tc_dns".into(), 11, HookSide::Ingress),
            ("tc_ids".into(), 10, HookSide::Egress),
        ]
    }

    #[test]
    fn a_selected_pod_gets_every_program_on_every_interface_in_order() {
        let dir = tempfile::tempdir().unwrap();
        procfs(dir.path(), &[(4242, UID, "a")]);
        let recorder = Recorder::default();
        let calls = Arc::clone(&recorder.calls);
        let mut attacher =
            PodTcAttacher::new(recorder, programs(), selector(), dir.path().to_path_buf());
        let outcome = attacher.reconcile(&[pod(UID, "shop", &[("app", "cart")])]);
        assert_eq!(
            outcome,
            Reconciled {
                attached: 1,
                ..Reconciled::default()
            }
        );
        let calls = calls.lock().unwrap();
        let expected: Vec<Call> = ["eth0", "lo"]
            .iter()
            .flat_map(|iface| {
                [
                    (4242, (*iface).to_string(), false, 10),
                    (4242, (*iface).to_string(), false, 11),
                    (4242, (*iface).to_string(), true, 10),
                ]
            })
            .collect();
        assert_eq!(*calls, expected);
    }

    #[test]
    fn a_pod_the_selector_does_not_name_is_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        procfs(dir.path(), &[(4242, UID, "a"), (4343, OTHER, "b")]);
        let recorder = Recorder::default();
        let calls = Arc::clone(&recorder.calls);
        let mut attacher =
            PodTcAttacher::new(recorder, programs(), selector(), dir.path().to_path_buf());
        let mut host = pod(OTHER, "shop", &[("app", "cart")]);
        host.host_network = true;
        attacher.reconcile(&[pod(UID, "bank", &[("app", "cart")]), host]);
        assert_eq!(attacher.pod_count(), 0);
        assert!(calls.lock().unwrap().is_empty());
    }

    #[test]
    fn a_second_pass_attaches_nothing_and_a_pod_that_went_is_released() {
        let dir = tempfile::tempdir().unwrap();
        procfs(dir.path(), &[(4242, UID, "a")]);
        let recorder = Recorder::default();
        let calls = Arc::clone(&recorder.calls);
        let mut attacher =
            PodTcAttacher::new(recorder, programs(), selector(), dir.path().to_path_buf());
        let cart = pod(UID, "shop", &[("app", "cart")]);
        attacher.reconcile(std::slice::from_ref(&cart));
        let made = calls.lock().unwrap().len();
        assert_eq!(
            attacher.reconcile(std::slice::from_ref(&cart)),
            Reconciled::default()
        );
        assert_eq!(calls.lock().unwrap().len(), made);
        let gone = attacher.reconcile(&[]);
        assert_eq!(gone.released, 1);
        assert_eq!(attacher.pod_count(), 0);
    }

    #[test]
    fn a_pod_moved_to_a_new_namespace_is_attached_again() {
        let dir = tempfile::tempdir().unwrap();
        procfs(dir.path(), &[(4242, UID, "a")]);
        let mut attacher = PodTcAttacher::new(
            Recorder::default(),
            programs(),
            selector(),
            dir.path().to_path_buf(),
        );
        let cart = pod(UID, "shop", &[("app", "cart")]);
        attacher.reconcile(std::slice::from_ref(&cart));
        // The sandbox was recreated: same uid, a namespace of its own.
        procfs(dir.path(), &[(4242, UID, "b")]);
        let outcome = attacher.reconcile(std::slice::from_ref(&cart));
        assert_eq!(
            outcome,
            Reconciled {
                attached: 1,
                released: 1,
                failed: 0
            }
        );
    }

    #[test]
    fn a_refused_link_leaves_the_pod_bare_and_is_tried_again() {
        let dir = tempfile::tempdir().unwrap();
        procfs(dir.path(), &[(4242, UID, "a")]);
        let recorder = Recorder {
            refuse_iface: Some("lo".into()),
            ..Recorder::default()
        };
        let mut attacher =
            PodTcAttacher::new(recorder, programs(), selector(), dir.path().to_path_buf());
        let cart = pod(UID, "shop", &[("app", "cart")]);
        assert_eq!(attacher.reconcile(std::slice::from_ref(&cart)).failed, 1);
        assert_eq!(attacher.pod_count(), 0);
        assert_eq!(attacher.reconcile(std::slice::from_ref(&cart)).failed, 1);
    }

    #[test]
    fn the_pods_carrying_the_chain_are_claimed_and_released_with_it() {
        let dir = tempfile::tempdir().unwrap();
        let claims_dir = tempfile::tempdir().unwrap();
        procfs(dir.path(), &[(4242, UID, "a"), (4343, OTHER, "b")]);
        let recorder = Recorder {
            refuse_iface: None,
            ..Recorder::default()
        };
        let claims = PodClaimsDir::new(claims_dir.path());
        let mut attacher =
            PodTcAttacher::new(recorder, programs(), selector(), dir.path().to_path_buf())
                .with_claims(claims.clone());
        let cart = pod(UID, "shop", &[("app", "cart")]);
        attacher.reconcile(&[cart.clone(), pod(OTHER, "bank", &[])]);
        let read = claims.read();
        assert_eq!(read.len(), 1, "only the selected pod is claimed");
        let netns = netns_inode(dir.path(), 4242).unwrap();
        assert_eq!(read[UID].netns, netns);

        attacher.reconcile(&[]);
        assert!(claims.read().is_empty());
    }

    #[test]
    fn a_pod_with_no_running_process_waits() {
        let dir = tempfile::tempdir().unwrap();
        let mut attacher = PodTcAttacher::new(
            Recorder::default(),
            programs(),
            selector(),
            dir.path().to_path_buf(),
        );
        let outcome = attacher.reconcile(&[pod(UID, "shop", &[("app", "cart")])]);
        assert_eq!(outcome, Reconciled::default());
    }

    #[test]
    fn both_kubelet_drivers_name_the_pod() {
        let systemd = format!(
            "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod{}.slice/cri-containerd-abc.scope\n",
            UID.replace('-', "_")
        );
        assert_eq!(pod_uid_of(&systemd).unwrap(), UID);
        assert!(pod_uid_of("0::/system.slice/sshd.service\n").is_none());
    }

    #[test]
    fn interfaces_come_from_the_pods_own_view() {
        assert_eq!(parse_net_dev(NET_DEV), vec!["eth0", "lo"]);
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(interfaces_of(dir.path(), 1), vec!["lo", "eth0"]);
    }
}
