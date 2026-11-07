//! Podman metadata enricher, rootful and rootless.
//!
//! Podman has no single daemon to ask. A container started by root is served
//! by the system socket, `/run/podman/podman.sock`; a container a user started
//! is served, if at all, by that user's own socket under
//! `/run/user/<uid>/podman/podman.sock`, which exists only while the user's
//! `podman.socket` unit is enabled. The owner of a container is in its cgroup
//! path, `user@<uid>.service`, so the enricher picks the socket from the path
//! and never has to guess.
//!
//! Both sockets speak Podman's Docker-compatible API, so the inspect and the
//! event stream are the Docker ones pointed elsewhere, and what comes back is
//! filed as [`ContainerMetadata::Docker`]: the shape is the same, and the
//! container's own runtime field still says `podman`. One event stream runs
//! per socket, started the first time a container of that owner is seen, so
//! a user who logs in after the agent started is followed without a rescan.
//!
//! A user's socket sits in a `0700` directory the agent's own user namespace
//! cannot enter, so where the agent runs beside a warden and its own connect
//! is refused, the warden connects to that user's socket and hands the stream
//! over; the inspect and the event stream then run on it unchanged.
//!
//! A runtime the agent cannot reach is recorded per owner with the reason -
//! no socket, refused, or not answering - and reported by
//! [`PodmanEnricher::runtimes`], so a rootless container that stays unnamed
//! says why instead of looking like a bare id.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde::Serialize;
use tracing::{info, warn};

use domain::container::engine::rootless_uid;
use domain::container::entity::{ContainerInfo, ContainerMetadata, ContainerRuntime};
use domain::container::error::ContainerError;
use ebpfsentinel_warden_client::ReconnectingClient;
use ports::secondary::metadata_enricher_port::MetadataEnricher;

use super::docker_cache::DockerCache;
use super::docker_client::{Dialer, DockerClient};
use super::docker_events::DockerEventWatcher;

/// The socket root's containers are served on.
pub const DEFAULT_ROOTFUL_SOCKET: &str = "/run/podman/podman.sock";
/// Where each user's runtime directory sits.
pub const DEFAULT_RUN_USER_ROOT: &str = "/run/user";

/// How long an unreachable runtime is left alone before it is tried again.
const RECHECK: Duration = Duration::from_mins(1);

/// Whose runtime a socket serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(tag = "kind", content = "uid", rename_all = "snake_case")]
pub enum PodmanOwner {
    /// The system socket, for containers root started.
    Root,
    /// One user's socket, for the containers that user started.
    User(u32),
}

/// What the agent found when it went to a runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PodmanReach {
    /// The socket answered: this owner's containers are named.
    Reachable,
    /// No socket at that path: the runtime is not serving its API there, or
    /// the directory is not mounted into the agent.
    NoSocket,
    /// The socket is there and refused the agent, which is what a user's
    /// socket does to an agent running as anybody but root or that user.
    Refused,
    /// The socket is there and did not answer in time or closed on us.
    Unavailable,
    /// The container is rootless and rootless runtimes are not asked.
    RootlessOff,
}

/// One runtime the agent has gone to, and what it found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PodmanRuntime {
    pub owner: PodmanOwner,
    pub socket: String,
    pub reach: PodmanReach,
}

struct Seen {
    dialer: Dialer,
    reach: PodmanReach,
    checked: Instant,
    watcher: Option<DockerEventWatcher>,
}

/// Names Podman containers through the socket of whoever owns them.
pub struct PodmanEnricher {
    rootful: PathBuf,
    /// `None` when rootless runtimes are not asked.
    run_user_root: Option<PathBuf>,
    timeout_ms: u64,
    cache: Arc<DockerCache>,
    seen: Mutex<BTreeMap<PodmanOwner, Seen>>,
    /// The warden, in a rootless deployment: it connects to a user's socket
    /// the agent's user namespace cannot reach.
    warden: Option<Arc<Mutex<ReconnectingClient>>>,
}

/// The socket a user's Podman serves its API on.
#[must_use]
pub fn rootless_socket(run_user_root: &Path, uid: u32) -> PathBuf {
    run_user_root
        .join(uid.to_string())
        .join("podman")
        .join("podman.sock")
}

/// What connecting through `dialer` says about the socket.
async fn probe(dialer: &Dialer, timeout: Duration) -> PodmanReach {
    match tokio::time::timeout(timeout, dialer.connect()).await {
        Ok(Ok(_)) => PodmanReach::Reachable,
        Ok(Err(err)) => match err.kind() {
            std::io::ErrorKind::NotFound => PodmanReach::NoSocket,
            std::io::ErrorKind::PermissionDenied => PodmanReach::Refused,
            _ => PodmanReach::Unavailable,
        },
        Err(_) => PodmanReach::Unavailable,
    }
}

impl PodmanEnricher {
    /// `run_user_root` is where users' runtime directories are mounted, or
    /// `None` to leave rootless containers unnamed.
    pub fn new(
        rootful: impl Into<PathBuf>,
        run_user_root: Option<PathBuf>,
        timeout_ms: u64,
        cache: Arc<DockerCache>,
    ) -> Self {
        Self {
            rootful: rootful.into(),
            run_user_root,
            timeout_ms,
            cache,
            seen: Mutex::new(BTreeMap::new()),
            warden: std::env::var_os(super::proc_digest::WARDEN_SOCK_ENV)
                .map(PathBuf::from)
                .filter(|p| !p.as_os_str().is_empty())
                .map(|p| Arc::new(Mutex::new(ReconnectingClient::new(p)))),
        }
    }

    /// Connect to users' sockets through the warden at `sock` whenever the
    /// agent's own connect is refused, whatever the environment says.
    #[cfg(test)]
    fn with_warden(mut self, sock: impl Into<PathBuf>) -> Self {
        self.warden = Some(Arc::new(Mutex::new(ReconnectingClient::new(sock))));
        self
    }

    /// Reach `owner`'s runtime at `socket`: directly, and for a user whose
    /// socket refused the agent, through the warden when there is one.
    async fn reach(&self, owner: PodmanOwner, socket: &Path) -> (Dialer, PodmanReach) {
        let timeout = Duration::from_millis(self.timeout_ms);
        let direct = Dialer::direct(socket);
        let reach = probe(&direct, timeout).await;
        match (owner, reach, &self.warden) {
            (PodmanOwner::User(uid), PodmanReach::Refused, Some(warden)) => {
                let brokered = Dialer::podman_through_warden(socket, Arc::clone(warden), uid);
                let reach = probe(&brokered, timeout).await;
                (brokered, reach)
            }
            _ => (direct, reach),
        }
    }

    /// Every runtime gone to so far, root first, then by uid.
    #[must_use]
    pub fn runtimes(&self) -> Vec<PodmanRuntime> {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(owner, seen)| PodmanRuntime {
                owner: *owner,
                socket: seen.dialer.socket().display().to_string(),
                reach: seen.reach,
            })
            .collect()
    }

    /// The socket serving `owner`, or `None` when rootless is off.
    fn socket_for(&self, owner: PodmanOwner) -> Option<PathBuf> {
        match owner {
            PodmanOwner::Root => Some(self.rootful.clone()),
            PodmanOwner::User(uid) => self
                .run_user_root
                .as_deref()
                .map(|root| rootless_socket(root, uid)),
        }
    }

    /// Record what was found, saying so once each time it changes, and start
    /// the owner's event stream the first time its socket answers.
    fn record(&self, owner: PodmanOwner, dialer: &Dialer, reach: PodmanReach) {
        let socket = dialer.socket();
        let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        let first = !seen.contains_key(&owner);
        let entry = seen.entry(owner).or_insert_with(|| Seen {
            dialer: dialer.clone(),
            reach,
            checked: Instant::now(),
            watcher: None,
        });
        let changed = first || entry.reach != reach;
        entry.reach = reach;
        if entry.watcher.is_none() {
            entry.dialer = dialer.clone();
        }
        entry.checked = Instant::now();
        if reach == PodmanReach::Reachable && entry.watcher.is_none() {
            entry.watcher = Some(DockerEventWatcher::spawn_dialing(
                dialer.clone(),
                Arc::clone(&self.cache),
                None,
            ));
            info!(
                ?owner,
                socket = %socket.display(),
                through_warden = dialer.through_warden(),
                "Podman runtime reached, following its events"
            );
        } else if changed && reach != PodmanReach::Reachable {
            warn!(
                ?owner,
                socket = %socket.display(),
                ?reach,
                "Podman containers of this owner stay unnamed: the agent cannot reach their runtime. \
                 Alerts keep the container id and lose the name, image and labels"
            );
        }
    }

    /// What is known of `owner`, whether it is worth asking again, and how
    /// it was last reached.
    fn known(&self, owner: PodmanOwner) -> Option<(PodmanReach, bool, Dialer)> {
        let seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        seen.get(&owner)
            .map(|s| (s.reach, s.checked.elapsed() >= RECHECK, s.dialer.clone()))
    }
}

impl Drop for PodmanEnricher {
    fn drop(&mut self) {
        let seen = self.seen.get_mut().unwrap_or_else(PoisonError::into_inner);
        for watcher in seen.values().filter_map(|s| s.watcher.as_ref()) {
            watcher.abort();
        }
    }
}

#[async_trait]
impl MetadataEnricher for PodmanEnricher {
    fn name(&self) -> &'static str {
        "podman"
    }

    async fn enrich(
        &self,
        info: &ContainerInfo,
    ) -> Result<Option<ContainerMetadata>, ContainerError> {
        let ContainerInfo::Container {
            container_id,
            runtime: ContainerRuntime::Podman,
            cgroup_path,
            ..
        } = info
        else {
            return Ok(None);
        };

        let from_stream = match self.cache.get(container_id) {
            Some(md) if md.created_at.is_empty() => Some(md),
            Some(md) => return Ok(Some(ContainerMetadata::Docker(md))),
            None => None,
        };
        let stream_only = || Ok(from_stream.clone().map(ContainerMetadata::Docker));

        let owner = rootless_uid(cgroup_path).map_or(PodmanOwner::Root, PodmanOwner::User);
        let Some(socket) = self.socket_for(owner) else {
            if self.known(owner).is_none() {
                self.record(
                    owner,
                    &Dialer::direct(rootless_socket(
                        Path::new(DEFAULT_RUN_USER_ROOT),
                        uid_of(owner),
                    )),
                    PodmanReach::RootlessOff,
                );
            }
            return stream_only();
        };

        let dialer = match self.known(owner) {
            Some((PodmanReach::Reachable, _, dialer)) => dialer,
            Some((_, false, _)) => return stream_only(),
            _ => {
                let (dialer, reach) = self.reach(owner, &socket).await;
                self.record(owner, &dialer, reach);
                if reach != PodmanReach::Reachable {
                    return stream_only();
                }
                dialer
            }
        };

        match DockerClient::with_dialer(dialer.clone(), self.timeout_ms)
            .inspect_container(container_id)
            .await
        {
            Ok(md) => {
                self.cache.insert(container_id.clone(), md.clone());
                Ok(Some(ContainerMetadata::Docker(md)))
            }
            Err(
                ContainerError::DockerUnavailable { .. } | ContainerError::DockerTimeout { .. },
            ) => {
                self.record(owner, &dialer, PodmanReach::Unavailable);
                stream_only()
            }
            Err(_) => stream_only(),
        }
    }
}

fn uid_of(owner: PodmanOwner) -> u32 {
    match owner {
        PodmanOwner::Root => 0,
        PodmanOwner::User(uid) => uid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::container::entity::DockerMetadata;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;

    const ID: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    fn cache() -> Arc<DockerCache> {
        Arc::new(DockerCache::new(8, Duration::from_mins(1)))
    }

    fn rootless(uid: u32) -> ContainerInfo {
        ContainerInfo::Container {
            container_id: ID.into(),
            runtime: ContainerRuntime::Podman,
            cgroup_path: format!(
                "/user.slice/user-{uid}.slice/user@{uid}.service/user.slice/libpod-{ID}.scope"
            ),
            pid: 1,
        }
    }

    fn rootful() -> ContainerInfo {
        ContainerInfo::Container {
            container_id: ID.into(),
            runtime: ContainerRuntime::Podman,
            cgroup_path: format!("/machine.slice/libpod-{ID}.scope"),
            pid: 1,
        }
    }

    /// A socket answering every request with one inspect payload, as
    /// Podman's compatible API does.
    fn serve_inspect(socket: &Path) -> tokio::task::JoinHandle<()> {
        let listener = UnixListener::bind(socket).unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    let request = String::from_utf8_lossy(&buf[..n]).to_string();
                    if !request.starts_with("GET /v1.43/containers/") {
                        // The event stream: hold it open, send nothing.
                        tokio::time::sleep(Duration::from_secs(30)).await;
                        return;
                    }
                    let body = r#"{"Name":"/web","Created":"2026-10-30T10:00:00Z","State":{"Status":"running"},"Config":{"Image":"quay.io/acme/web:1","Labels":{"tier":"front"}}}"#;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        })
    }

    #[tokio::test]
    async fn a_rootless_container_is_named_through_its_users_socket() {
        let dir = tempfile::tempdir().unwrap();
        let socket = rootless_socket(dir.path(), 1000);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let server = serve_inspect(&socket);

        let enricher = PodmanEnricher::new(
            dir.path().join("rootful.sock"),
            Some(dir.path().to_path_buf()),
            500,
            cache(),
        );
        let md = enricher.enrich(&rootless(1000)).await.unwrap();
        let Some(ContainerMetadata::Docker(md)) = md else {
            panic!("expected metadata");
        };
        assert_eq!(md.name, "web");
        assert_eq!(md.image, "quay.io/acme/web:1");
        assert_eq!(
            enricher.runtimes(),
            vec![PodmanRuntime {
                owner: PodmanOwner::User(1000),
                socket: socket.display().to_string(),
                reach: PodmanReach::Reachable,
            }]
        );
        server.abort();
    }

    /// Answer as the warden would: the handshake, then every
    /// `ConnectPodman` for `uid` with a stream connected to `runtime`, and
    /// any other uid with the refusal of a socket that is not there. Counts
    /// the connections handed over; the thread lives as long as the test.
    fn fake_warden(sock: &Path, uid: u32, runtime: PathBuf) -> Arc<AtomicUsize> {
        use ebpfsentinel_warden_proto::{Command, PROTOCOL_VERSION, Response};
        use ebpfsentinel_warden_proto::{read_frame, write_frame};
        use std::os::fd::AsRawFd;
        let listener = std::os::unix::net::UnixListener::bind(sock).unwrap();
        let served = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&served);
        std::thread::spawn(move || {
            while let Ok((mut conn, _)) = listener.accept() {
                let Ok(Command::Hello { .. }) = read_frame::<_, Command>(&mut conn) else {
                    continue;
                };
                let hello = Response::HelloOk {
                    version: PROTOCOL_VERSION,
                };
                write_frame(&mut conn, &hello).unwrap();
                let (counter, runtime) = (Arc::clone(&counter), runtime.clone());
                std::thread::spawn(move || {
                    while let Ok(cmd) = read_frame::<_, Command>(&mut conn) {
                        let Command::ConnectPodman { uid: asked } = cmd else {
                            panic!("unexpected command {cmd:?}");
                        };
                        if asked != uid {
                            let message = format!(
                                "Podman socket of uid {asked}: No such file or directory (os error 2)"
                            );
                            write_frame(&mut conn, &Response::Error { message }).unwrap();
                            continue;
                        }
                        let stream = std::os::unix::net::UnixStream::connect(&runtime).unwrap();
                        write_frame(&mut conn, &Response::FdReady).unwrap();
                        super::super::proc_digest::tests::send_fd(&conn, stream.as_raw_fd());
                        counter.fetch_add(1, Ordering::Relaxed);
                    }
                });
            }
        });
        served
    }

    /// A user's socket behind a directory the agent may not enter, as a
    /// `0700` runtime directory is to the agent's user namespace. `None`
    /// when this run is privileged and enters it anyway.
    fn closed_runtime_dir(root: &Path, uid: u32) -> Option<PathBuf> {
        use std::os::unix::fs::PermissionsExt;
        let dir = root.join(uid.to_string());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read_dir(&dir).is_ok() {
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
            return None;
        }
        Some(dir)
    }

    #[tokio::test]
    async fn a_users_socket_the_agent_may_not_reach_is_reached_through_the_warden() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let Some(closed) = closed_runtime_dir(dir.path(), 1000) else {
            return;
        };
        let runtime = dir.path().join("runtime.sock");
        let server = serve_inspect(&runtime);
        let sock = dir.path().join("warden.sock");
        let warden = fake_warden(&sock, 1000, runtime);

        let enricher = PodmanEnricher::new(
            dir.path().join("rootful.sock"),
            Some(dir.path().to_path_buf()),
            2_000,
            cache(),
        )
        .with_warden(&sock);
        let md = enricher.enrich(&rootless(1000)).await.unwrap();
        let Some(ContainerMetadata::Docker(md)) = md else {
            panic!("expected metadata, runtimes {:?}", enricher.runtimes());
        };
        assert_eq!(md.name, "web");
        assert_eq!(md.image, "quay.io/acme/web:1");
        let runtimes = enricher.runtimes();
        assert_eq!(runtimes[0].reach, PodmanReach::Reachable);
        assert_eq!(
            runtimes[0].socket,
            rootless_socket(dir.path(), 1000).display().to_string()
        );

        // A user the warden has no socket for is reported as such.
        let Some(_closed) = closed_runtime_dir(dir.path(), 1001) else {
            return;
        };
        let ContainerInfo::Container { cgroup_path, .. } = rootless(1001) else {
            unreachable!()
        };
        let other = ContainerInfo::Container {
            container_id: "0".repeat(64),
            runtime: ContainerRuntime::Podman,
            cgroup_path: cgroup_path.replace(ID, &"0".repeat(64)),
            pid: 1,
        };
        assert!(enricher.enrich(&other).await.unwrap().is_none());
        assert_eq!(enricher.runtimes()[1].reach, PodmanReach::NoSocket);

        drop(enricher);
        std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(
            dir.path().join("1001"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        server.abort();
        assert!(
            warden.load(Ordering::Relaxed) >= 2,
            "probe and inspect both brokered"
        );
    }

    #[tokio::test]
    async fn without_a_warden_a_refused_users_socket_stays_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let Some(closed) = closed_runtime_dir(dir.path(), 1000) else {
            return;
        };
        let enricher = PodmanEnricher::new(
            dir.path().join("rootful.sock"),
            Some(dir.path().to_path_buf()),
            200,
            cache(),
        );
        assert!(enricher.enrich(&rootless(1000)).await.unwrap().is_none());
        assert_eq!(enricher.runtimes()[0].reach, PodmanReach::Refused);
        std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[tokio::test]
    async fn an_unreachable_runtime_is_reported_with_its_reason() {
        let dir = tempfile::tempdir().unwrap();
        let enricher = PodmanEnricher::new(
            dir.path().join("rootful.sock"),
            Some(dir.path().to_path_buf()),
            200,
            cache(),
        );
        assert!(enricher.enrich(&rootless(1001)).await.unwrap().is_none());
        assert!(enricher.enrich(&rootful()).await.unwrap().is_none());

        let runtimes = enricher.runtimes();
        assert_eq!(runtimes[0].owner, PodmanOwner::Root);
        assert_eq!(runtimes[0].reach, PodmanReach::NoSocket);
        assert_eq!(runtimes[1].owner, PodmanOwner::User(1001));
        assert_eq!(runtimes[1].reach, PodmanReach::NoSocket);

        let wire = serde_json::to_value(&runtimes).unwrap();
        assert_eq!(wire[0]["owner"], serde_json::json!({"kind": "root"}));
        assert_eq!(
            wire[1]["owner"],
            serde_json::json!({"kind": "user", "uid": 1001})
        );
        assert_eq!(wire[1]["reach"], "no_socket");
    }

    #[tokio::test]
    async fn with_rootless_off_a_users_container_says_so_and_what_the_stream_knew_stays() {
        let cache = cache();
        cache.insert(
            ID.into(),
            DockerMetadata {
                name: "db".into(),
                image: "postgres:17".into(),
                labels: vec![],
                created_at: String::new(),
                status: "running".into(),
            },
        );
        let enricher = PodmanEnricher::new("/nonexistent/podman.sock", None, 100, cache);
        let md = enricher.enrich(&rootless(1002)).await.unwrap();
        assert!(matches!(md, Some(ContainerMetadata::Docker(ref d)) if d.name == "db"));
        assert_eq!(enricher.runtimes()[0].reach, PodmanReach::RootlessOff);
    }

    #[tokio::test]
    async fn other_runtimes_and_the_host_are_not_its_business() {
        let enricher = PodmanEnricher::new("/nonexistent/podman.sock", None, 100, cache());
        assert!(
            enricher
                .enrich(&ContainerInfo::Host)
                .await
                .unwrap()
                .is_none()
        );
        let docker = ContainerInfo::Container {
            container_id: ID.into(),
            runtime: ContainerRuntime::Docker,
            cgroup_path: format!("/system.slice/docker-{ID}.scope"),
            pid: 1,
        };
        assert!(enricher.enrich(&docker).await.unwrap().is_none());
        assert!(enricher.runtimes().is_empty());
    }

    #[test]
    fn a_users_socket_sits_in_their_runtime_directory() {
        assert_eq!(
            rootless_socket(Path::new("/run/user"), 1000),
            PathBuf::from("/run/user/1000/podman/podman.sock")
        );
    }
}
