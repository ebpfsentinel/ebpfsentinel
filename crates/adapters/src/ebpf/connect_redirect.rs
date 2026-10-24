//! Steering the TCP connections of selected cgroups to a local listener, and
//! answering that listener's question of where each one was going.
//!
//! Three programs on a cgroup: `connect4`/`connect6` rewrite the destination
//! of a selected task's connection and record the original, and `sockops`
//! moves the record under the source address once the kernel has chosen it.
//! All three or none: a rewrite without the record is a connection the
//! listener cannot route, and a record without the rewrite is a table that
//! fills with connections nobody will ever ask about.
//!
//! The object decides nothing on its own. It loads with an empty selection
//! and a zero listener port, which is the state in which no connection is
//! touched, and every map is written from here.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{OwnedFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use aya::maps::{Array, HashMap as AyaHashMap, MapData};
use domain::common::error::DomainError;
use ebpf_common::redirect::{
    REDIRECT_ANCESTOR_LEVELS, REDIRECT_FAMILY_IPV4, REDIRECT_FAMILY_IPV6, REDIRECT_MAX_CGROUPS,
    REDIRECT_MAX_EXEMPT, REDIRECT_MAX_PORTS, RedirectOrigin, RedirectPeerKey, RedirectTarget,
};
use ports::secondary::dlp_scope_map_port::DlpScopeMapPort;
use ports::secondary::redirect_origin_port::{RedirectOriginPort, RedirectedConnection};
use tracing::{info, warn};

use super::kfunc_attach;
use super::loader::EbpfLoader;
use crate::ebpf::map_store::MapStore;

/// `BPF_CGROUP_SOCK_OPS` from `enum bpf_attach_type`.
pub const BPF_CGROUP_SOCK_OPS: u32 = 3;
/// `BPF_CGROUP_INET4_CONNECT` from `enum bpf_attach_type`.
pub const BPF_CGROUP_INET4_CONNECT: u32 = 10;
/// `BPF_CGROUP_INET6_CONNECT` from `enum bpf_attach_type`.
pub const BPF_CGROUP_INET6_CONNECT: u32 = 11;

/// The programs of the redirect object, with the attach type each one is
/// loaded for, in the order they are attached. The publishing hook goes
/// first, so no connection is ever rewritten before its record can move.
pub const REDIRECT_HOOKS: &[(&str, u32)] = &[
    ("redirect_sockops", BPF_CGROUP_SOCK_OPS),
    ("redirect_connect4", BPF_CGROUP_INET4_CONNECT),
    ("redirect_connect6", BPF_CGROUP_INET6_CONNECT),
];

/// What the agent can say about the redirect hooks.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnectRedirectStatus {
    /// Every hook is attached.
    pub attached: bool,
    /// The cgroup the hooks sit on, as configured.
    pub cgroup: String,
    /// The hook names that did attach, in attach order.
    pub hooks: Vec<String>,
    /// Why the redirect is off, in one sentence. `None` when every hook
    /// attached.
    pub reason: Option<String>,
    /// The attach went through the warden rather than being issued here.
    pub brokered: bool,
}

static STATUS: OnceLock<Mutex<ConnectRedirectStatus>> = OnceLock::new();

fn status_cell() -> &'static Mutex<ConnectRedirectStatus> {
    STATUS.get_or_init(|| Mutex::new(ConnectRedirectStatus::default()))
}

/// Publish what the agent can say about the redirect hooks.
pub fn publish_status(status: ConnectRedirectStatus) {
    let mut held = status_cell()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *held = status;
}

/// What the agent can currently say about the redirect hooks.
#[must_use]
pub fn status() -> ConnectRedirectStatus {
    status_cell()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// Holds the cgroup links alive. Dropping it detaches every hook, which
/// returns every selected workload to connecting where it asked to.
#[derive(Default)]
pub struct ConnectRedirectAttacher {
    links: Vec<OwnedFd>,
    warden_sock: Option<PathBuf>,
    warden: Option<Mutex<ebpfsentinel_warden_client::ReconnectingClient>>,
}

impl ConnectRedirectAttacher {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Route the privileged `BPF_LINK_CREATE` through the warden at `sock`.
    #[must_use]
    pub fn with_warden_socket(mut self, sock: impl Into<PathBuf>) -> Self {
        let sock = sock.into();
        self.warden = Some(crate::warden::attribution::client_for(&sock));
        self.warden_sock = Some(sock);
        self
    }

    /// Attach every hook of `loader` to `cgroup`, publishing what happened.
    pub fn attach_all(&mut self, loader: &EbpfLoader, cgroup: &str) -> ConnectRedirectStatus {
        let mut hooks = Vec::with_capacity(REDIRECT_HOOKS.len());
        for (program, attach_type) in REDIRECT_HOOKS {
            match self.attach_one(loader, cgroup, program, *attach_type) {
                Ok(link) => {
                    self.links.push(link);
                    hooks.push((*program).to_string());
                }
                Err(reason) => {
                    self.links.clear();
                    warn!(
                        program,
                        cgroup, reason, "connection redirect off: the cgroup attach was refused"
                    );
                    let status = ConnectRedirectStatus {
                        attached: false,
                        cgroup: cgroup.to_owned(),
                        hooks: Vec::new(),
                        reason: Some(reason),
                        brokered: self.warden_sock.is_some(),
                    };
                    publish_status(status.clone());
                    return status;
                }
            }
        }
        info!(
            cgroup,
            hooks = hooks.len(),
            brokered = self.warden_sock.is_some(),
            "connection redirect attached"
        );
        let status = ConnectRedirectStatus {
            attached: true,
            cgroup: cgroup.to_owned(),
            hooks,
            reason: None,
            brokered: self.warden_sock.is_some(),
        };
        publish_status(status.clone());
        status
    }

    fn attach_one(
        &self,
        loader: &EbpfLoader,
        cgroup: &str,
        program: &str,
        attach_type: u32,
    ) -> Result<OwnedFd, String> {
        let prog_fd: RawFd = loader
            .program_fd(program)
            .ok_or_else(|| format!("program `{program}` is not in the loaded object"))?;
        match &self.warden {
            Some(client) => {
                crate::warden::attribution::attach_via_warden(client, prog_fd, cgroup, attach_type)
                    .map_err(|e| e.to_string())
            }
            None => kfunc_attach::attach_cgroup(program, prog_fd, cgroup, attach_type)
                .map_err(|e| e.to_string()),
        }
    }

    /// How many hooks this attacher currently holds a link for.
    #[must_use]
    pub fn attached(&self) -> usize {
        self.links.len()
    }
}

/// Where redirected connections are sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedirectListener {
    /// IPv4 address the listener is reachable on from a workload's own
    /// network namespace. `None` leaves IPv4 connections alone.
    pub ipv4: Option<Ipv4Addr>,
    /// IPv6 address, likewise. `None` leaves IPv6 connections alone.
    pub ipv6: Option<Ipv6Addr>,
    /// The listener's port.
    pub port: u16,
}

impl RedirectListener {
    fn to_target(self) -> RedirectTarget {
        RedirectTarget {
            addr4: self.ipv4.map_or(0, u32::from),
            addr6: self.ipv6.map_or([0; 4], ipv6_words),
            port: self.port,
            _pad: [0; 2],
        }
    }
}

/// The maps that decide which connections are redirected and where to.
///
/// Implements [`DlpScopeMapPort`] for the selection, so the same resolver
/// that turns DLP selectors into cgroup ids keeps this set current.
pub struct ConnectRedirectMaps {
    target: Array<MapData, RedirectTarget>,
    cgroups: AyaHashMap<MapData, u64, u8>,
    ports: AyaHashMap<MapData, u16, u8>,
    exempt: AyaHashMap<MapData, u64, u8>,
    selected: Vec<u64>,
}

impl ConnectRedirectMaps {
    /// Take the decision maps out of a loaded redirect object.
    ///
    /// # Errors
    ///
    /// Returns an error when a map is missing from the object or has another
    /// shape than the one declared here.
    pub fn new(ebpf: &mut dyn MapStore) -> anyhow::Result<Self> {
        let take = |ebpf: &mut dyn MapStore, name: &str| {
            ebpf.take_map(name)
                .ok_or_else(|| anyhow::anyhow!("map '{name}' not found"))
        };
        let target = Array::try_from(take(ebpf, "REDIRECT_TARGET")?)?;
        let cgroups = AyaHashMap::try_from(take(ebpf, "REDIRECT_CGROUPS")?)?;
        let ports = AyaHashMap::try_from(take(ebpf, "REDIRECT_PORTS")?)?;
        let exempt = AyaHashMap::try_from(take(ebpf, "REDIRECT_EXEMPT")?)?;
        Ok(Self {
            target,
            cgroups,
            ports,
            exempt,
            selected: Vec::new(),
        })
    }

    /// Write the listener, the redirected ports and the exempt cgroups.
    ///
    /// The listener goes last, because a non-zero port is what switches the
    /// object on, and it must not switch on before the exemption that keeps
    /// the listener's own onward connections from coming back to it.
    ///
    /// # Errors
    ///
    /// Returns an error when a list is longer than its map, when no port or
    /// no listener address is given, or when a write fails.
    pub fn configure(
        &mut self,
        listener: RedirectListener,
        ports: &[u16],
        exempt: &[u64],
    ) -> anyhow::Result<()> {
        validate_listener(listener, ports)?;
        if exempt.len() > REDIRECT_MAX_EXEMPT as usize {
            anyhow::bail!(
                "{} exempt cgroups, more than the {REDIRECT_MAX_EXEMPT} the map holds",
                exempt.len()
            );
        }
        for id in exempt {
            self.exempt.insert(id, 1u8, 0)?;
        }
        for port in ports {
            self.ports.insert(port, 1u8, 0)?;
        }
        self.target.set(0, listener.to_target(), 0)?;
        info!(
            ipv4 = ?listener.ipv4,
            ipv6 = ?listener.ipv6,
            port = listener.port,
            ports = ?ports,
            "connection redirect listener written"
        );
        Ok(())
    }

    /// The cgroup ids currently selected.
    #[must_use]
    pub fn selected(&self) -> &[u64] {
        &self.selected
    }
}

impl DlpScopeMapPort for ConnectRedirectMaps {
    fn publish_scope(&mut self, scoped: bool, cgroup_ids: &[u64]) -> Result<(), DomainError> {
        // An unscoped answer means "every workload", which for a redirect is
        // every connection on the node through a terminating proxy. It is
        // never what a selection asked for, so it selects nothing.
        let wanted: &[u64] = if scoped { cgroup_ids } else { &[] };
        if wanted.len() > REDIRECT_MAX_CGROUPS as usize {
            return Err(DomainError::InvalidConfig(format!(
                "the redirect selection resolved to {} cgroups, more than the \
                 {REDIRECT_MAX_CGROUPS} the map holds",
                wanted.len()
            )));
        }
        let present: Vec<u64> = self.cgroups.keys().filter_map(Result::ok).collect();
        for key in present {
            if !wanted.contains(&key) {
                let _ = self.cgroups.remove(&key);
            }
        }
        for id in wanted {
            self.cgroups.insert(id, 1u8, 0).map_err(|e| {
                DomainError::EngineError(format!("REDIRECT_CGROUPS write failed: {e}"))
            })?;
        }
        self.selected = wanted.to_vec();
        Ok(())
    }

    fn allowed_cgroups(&self) -> usize {
        self.selected.len()
    }
}

/// The table the listener reads the original destination from.
pub struct RedirectOriginTable {
    by_peer: Mutex<AyaHashMap<MapData, RedirectPeerKey, RedirectOrigin>>,
}

impl RedirectOriginTable {
    /// Take the origin table out of a loaded redirect object.
    ///
    /// # Errors
    ///
    /// Returns an error when the map is missing or has another shape.
    pub fn new(ebpf: &mut dyn MapStore) -> anyhow::Result<Self> {
        let map = ebpf
            .take_map("REDIRECT_BY_PEER")
            .ok_or_else(|| anyhow::anyhow!("map 'REDIRECT_BY_PEER' not found"))?;
        Ok(Self {
            by_peer: Mutex::new(AyaHashMap::try_from(map)?),
        })
    }
}

impl RedirectOriginPort for RedirectOriginTable {
    fn take(&self, peer: SocketAddr) -> Result<Option<RedirectedConnection>, DomainError> {
        let key = peer_key(peer);
        let mut map = self
            .by_peer
            .lock()
            .map_err(|_| DomainError::EngineError("redirect origin table lock poisoned".into()))?;
        let origin = match map.get(&key, 0) {
            Ok(origin) => origin,
            Err(aya::maps::MapError::KeyNotFound) => return Ok(None),
            Err(e) => {
                return Err(DomainError::EngineError(format!(
                    "REDIRECT_BY_PEER lookup failed: {e}"
                )));
            }
        };
        // Removed before it is used: the source port is reused, and the next
        // connection from it must not inherit this one's destination.
        let _ = map.remove(&key);
        Ok(
            origin_destination(&origin).map(|destination| RedirectedConnection {
                destination,
                cgroup_id: origin.cgroup_id,
            }),
        )
    }
}

/// Refuse a listener that would switch the object on with nowhere to send a
/// connection, or with nothing to send.
///
/// # Errors
///
/// Returns the sentence naming what is missing.
pub fn validate_listener(listener: RedirectListener, ports: &[u16]) -> anyhow::Result<()> {
    if listener.port == 0 {
        anyhow::bail!("the redirect listener port is zero");
    }
    if listener.ipv4.is_none() && listener.ipv6.is_none() {
        anyhow::bail!("the redirect listener has neither an IPv4 nor an IPv6 address");
    }
    if listener
        .ipv4
        .is_some_and(|a| a.is_unspecified() || a.is_loopback())
        || listener
            .ipv6
            .is_some_and(|a| a.is_unspecified() || a.is_loopback())
    {
        anyhow::bail!(
            "the redirect listener address is unspecified or loopback, and a workload in its own \
             network namespace reaches its own loopback rather than the node's"
        );
    }
    if ports.is_empty() {
        anyhow::bail!("no destination port is redirected");
    }
    if ports.len() > REDIRECT_MAX_PORTS as usize {
        anyhow::bail!(
            "{} redirected ports, more than the {REDIRECT_MAX_PORTS} the map holds",
            ports.len()
        );
    }
    if ports.contains(&0) {
        anyhow::bail!("port zero cannot be redirected");
    }
    Ok(())
}

/// The cgroup id of the calling process, read from `/proc/self/cgroup` and
/// resolved under `cgroup_root`.
///
/// # Errors
///
/// Returns an error when the process is not on a cgroup v2 hierarchy or the
/// directory cannot be read.
pub fn own_cgroup_id(cgroup_root: &Path) -> anyhow::Result<u64> {
    let content = std::fs::read_to_string("/proc/self/cgroup")?;
    let relative = unified_cgroup_path(&content)
        .ok_or_else(|| anyhow::anyhow!("the agent is not on a cgroup v2 hierarchy"))?;
    let dir = cgroup_root.join(relative.trim_start_matches('/'));
    Ok(std::fs::metadata(&dir)
        .map_err(|e| anyhow::anyhow!("{}: {e}", dir.display()))?
        .ino())
}

/// The path of the unified hierarchy, the `0::` line, in a
/// `/proc/<pid>/cgroup` file.
#[must_use]
pub fn unified_cgroup_path(content: &str) -> Option<&str> {
    content.lines().find_map(|line| line.strip_prefix("0::"))
}

fn ipv6_words(addr: Ipv6Addr) -> [u32; 4] {
    let o = addr.octets();
    [
        u32::from_be_bytes([o[0], o[1], o[2], o[3]]),
        u32::from_be_bytes([o[4], o[5], o[6], o[7]]),
        u32::from_be_bytes([o[8], o[9], o[10], o[11]]),
        u32::from_be_bytes([o[12], o[13], o[14], o[15]]),
    ]
}

fn words_ipv6(words: [u32; 4]) -> Ipv6Addr {
    let mut octets = [0u8; 16];
    for (i, word) in words.iter().enumerate() {
        octets[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    Ipv6Addr::from(octets)
}

/// The key the `sockops` hook wrote for a connection the listener accepted
/// from `peer`. A mapped IPv4 address is unmapped, because the hook unmaps it
/// too.
#[must_use]
pub fn peer_key(peer: SocketAddr) -> RedirectPeerKey {
    let ip = match peer.ip() {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 @ IpAddr::V4(_) => v4,
    };
    match ip {
        IpAddr::V4(v4) => RedirectPeerKey {
            addr: [u32::from(v4), 0, 0, 0],
            port: peer.port(),
            family: REDIRECT_FAMILY_IPV4,
            _pad: 0,
        },
        IpAddr::V6(v6) => RedirectPeerKey {
            addr: ipv6_words(v6),
            port: peer.port(),
            family: REDIRECT_FAMILY_IPV6,
            _pad: 0,
        },
    }
}

/// The destination a recorded origin names, or `None` for a family the
/// kernel half never writes.
#[must_use]
pub fn origin_destination(origin: &RedirectOrigin) -> Option<SocketAddr> {
    match origin.family {
        REDIRECT_FAMILY_IPV4 => Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::from(origin.addr[0])),
            origin.port,
        )),
        REDIRECT_FAMILY_IPV6 => Some(SocketAddr::new(
            IpAddr::V6(words_ipv6(origin.addr)),
            origin.port,
        )),
        _ => None,
    }
}

/// The cgroup directories whose selection redirects a task in `relative`,
/// in the order the kernel tests them: the task's own, then its ancestors
/// from the root down, as many levels as the program walks.
///
/// `relative` is the `0::` path of `/proc/<pid>/cgroup`.
#[must_use]
pub fn redirect_candidates(relative: &str) -> Vec<String> {
    let segments: Vec<&str> = relative.split('/').filter(|s| !s.is_empty()).collect();
    let mut candidates = vec![format!("/{}", segments.join("/"))];
    let levels = usize::try_from(REDIRECT_ANCESTOR_LEVELS).unwrap_or(usize::MAX);
    for depth in 0..levels.min(segments.len()) {
        candidates.push(format!("/{}", segments[..depth].join("/")));
    }
    candidates
}

/// Whether the kernel redirects the connections of `pid`, given the cgroup
/// ids currently `selected`: its cgroup or an ancestor is one of them.
///
/// A process that has exited, or whose cgroup cannot be read, answers no,
/// because a report is never upgraded on a guess.
#[must_use]
pub fn pid_is_redirected<S: std::hash::BuildHasher>(
    cgroup_root: &Path,
    pid: u32,
    selected: &std::collections::HashSet<u64, S>,
) -> bool {
    if selected.is_empty() {
        return false;
    }
    let Ok(content) = std::fs::read_to_string(format!("/proc/{pid}/cgroup")) else {
        return false;
    };
    let Some(relative) = unified_cgroup_path(&content) else {
        return false;
    };
    redirect_candidates(relative).iter().any(|dir| {
        std::fs::metadata(cgroup_root.join(dir.trim_start_matches('/')))
            .is_ok_and(|meta| selected.contains(&meta.ino()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_task_is_tested_against_its_own_cgroup_then_its_ancestors_from_the_root() {
        assert_eq!(
            redirect_candidates("/kubepods.slice/pod-a.slice/cri-1.scope"),
            vec![
                "/kubepods.slice/pod-a.slice/cri-1.scope",
                "/",
                "/kubepods.slice",
                "/kubepods.slice/pod-a.slice",
            ]
        );
        assert_eq!(redirect_candidates("/"), vec!["/"]);
        let deep = "/a/b/c/d/e/f/g/h/i/j";
        let candidates = redirect_candidates(deep);
        assert_eq!(candidates.len(), 1 + REDIRECT_ANCESTOR_LEVELS as usize);
        assert_eq!(
            candidates.last().map(String::as_str),
            Some("/a/b/c/d/e/f/g")
        );
    }

    #[test]
    fn nothing_selected_redirects_nobody() {
        assert!(!pid_is_redirected(
            Path::new("/sys/fs/cgroup"),
            std::process::id(),
            &std::collections::HashSet::new()
        ));
    }

    fn listener() -> RedirectListener {
        RedirectListener {
            ipv4: Some(Ipv4Addr::new(10, 0, 0, 5)),
            ipv6: None,
            port: 8443,
        }
    }

    #[test]
    fn every_hook_is_named_once_and_the_publisher_attaches_first() {
        let mut names: Vec<&str> = REDIRECT_HOOKS.iter().map(|(n, _)| *n).collect();
        assert_eq!(names[0], "redirect_sockops");
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), REDIRECT_HOOKS.len());
    }

    #[test]
    fn the_target_carries_the_listener_in_host_order_words() {
        let target = RedirectListener {
            ipv4: Some(Ipv4Addr::new(10, 0, 0, 5)),
            ipv6: Some("2001:db8::1".parse().unwrap()),
            port: 8443,
        }
        .to_target();
        assert_eq!(target.addr4, 0x0a00_0005);
        assert_eq!(target.addr6, [0x2001_0db8, 0, 0, 1]);
        assert_eq!(target.port, 8443);
    }

    #[test]
    fn a_listener_a_workload_cannot_reach_is_refused() {
        let mut loopback = listener();
        loopback.ipv4 = Some(Ipv4Addr::LOCALHOST);
        assert!(validate_listener(loopback, &[443]).is_err());

        let mut nowhere = listener();
        nowhere.ipv4 = None;
        assert!(validate_listener(nowhere, &[443]).is_err());

        let mut no_port = listener();
        no_port.port = 0;
        assert!(validate_listener(no_port, &[443]).is_err());

        assert!(validate_listener(listener(), &[]).is_err());
        assert!(validate_listener(listener(), &[0]).is_err());
        assert!(validate_listener(listener(), &[443]).is_ok());
    }

    #[test]
    fn a_peer_key_matches_what_the_kernel_half_writes() {
        let v4: SocketAddr = "10.244.1.7:40000".parse().unwrap();
        let key = peer_key(v4);
        assert_eq!(key.addr, [0x0af4_0107, 0, 0, 0]);
        assert_eq!(key.port, 40000);
        assert_eq!(key.family, REDIRECT_FAMILY_IPV4);

        // A dual-stack listener sees an IPv4 client as mapped; the hook
        // unmaps it, so the lookup must too.
        let mapped: SocketAddr = "[::ffff:10.244.1.7]:40000".parse().unwrap();
        assert_eq!(peer_key(mapped), key);

        let v6: SocketAddr = "[2001:db8::7]:40001".parse().unwrap();
        let key6 = peer_key(v6);
        assert_eq!(key6.family, REDIRECT_FAMILY_IPV6);
        assert_eq!(key6.addr, [0x2001_0db8, 0, 0, 7]);
    }

    #[test]
    fn an_origin_reads_back_as_the_destination_it_recorded() {
        let origin = RedirectOrigin {
            cgroup_id: 42,
            addr: [0x5db8_d822, 0, 0, 0],
            port: 443,
            family: REDIRECT_FAMILY_IPV4,
            _pad: [0; 5],
        };
        assert_eq!(
            origin_destination(&origin),
            Some("93.184.216.34:443".parse().unwrap())
        );

        let v6 = RedirectOrigin {
            addr: [0x2001_0db8, 0, 0, 0x10],
            family: REDIRECT_FAMILY_IPV6,
            ..origin
        };
        assert_eq!(
            origin_destination(&v6),
            Some("[2001:db8::10]:443".parse().unwrap())
        );

        let unknown = RedirectOrigin {
            family: 0,
            ..origin
        };
        assert_eq!(origin_destination(&unknown), None);
    }

    #[test]
    fn the_unified_line_is_the_one_read() {
        let content = "12:memory:/legacy\n0::/kubepods.slice/pod-a/cri-b.scope\n";
        assert_eq!(
            unified_cgroup_path(content),
            Some("/kubepods.slice/pod-a/cri-b.scope")
        );
        assert_eq!(unified_cgroup_path("3:cpu:/x\n"), None);
    }

    #[test]
    fn the_own_cgroup_resolves_on_this_host_or_says_why_not() {
        // A CI runner may sit on cgroup v1; the call must then say so rather
        // than invent an id.
        match own_cgroup_id(Path::new("/sys/fs/cgroup")) {
            Ok(id) => assert!(id > 0),
            Err(e) => assert!(!e.to_string().is_empty()),
        }
    }
}
