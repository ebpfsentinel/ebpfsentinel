//! The relay to a container runtime root runs on the host.
//!
//! The Docker Engine API, and Podman's rootful service, are root on the host:
//! one of their calls starts a privileged container. The agent needs six reads
//! from them, so it is never handed the socket. It gets one end of a socket
//! pair; the warden reads one request from the other end, refuses it unless it
//! is a `GET` of a path [`root_runtime_path_allowed`] names, and sends a request
//! of its own for that path to the runtime.
//!
//! The two answers that describe a container, its inspect and the container
//! list, carry what the agent must never hold: the environment a secret is
//! passed in, the command line a password is typed on, the host paths bound
//! into it. Those are read whole by the warden, and what reaches the agent is
//! a projection naming only what the agent reads: the id, the name, the image,
//! the labels, when it was created and its state. Nothing the projection does
//! not name is relayed, so a field a runtime adds later stays with the
//! runtime. The other answers, the networks, the ping and the event stream,
//! are copied back as they come until either side closes.

use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ebpfsentinel_warden_proto::{ROOT_RUNTIME_API_PREFIX, root_runtime_path_allowed};
use serde_json::{Map, Value};

/// Relays open at once. The agent holds one event stream per runtime and a
/// few short reads; past this, a new one is refused rather than a thread
/// spawned.
pub const MAX_RELAYS: usize = 64;

/// Longest request head read from the agent.
const MAX_HEAD: usize = 8 * 1024;

/// How long the agent has to write its request, and how long a write of the
/// answer to it may block.
const AGENT_TIMEOUT: Duration = Duration::from_secs(10);

/// Longest runtime answer the warden reads whole to project: the agent's own
/// ceiling on the container list, plus room for the head and the chunk
/// framing.
const MAX_PROJECTED: usize = (16 << 20) + (64 << 10);

/// How long the runtime has to answer a read the warden projects.
const RUNTIME_TIMEOUT: Duration = Duration::from_secs(30);

static ACTIVE: AtomicUsize = AtomicUsize::new(0);

/// One relay slot, given back when the relay ends.
struct Slot;

impl Slot {
    fn take() -> Option<Self> {
        ACTIVE
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < MAX_RELAYS).then_some(n + 1)
            })
            .ok()
            .map(|_| Self)
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        ACTIVE.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Connect to the runtime at `socket`, which `owner` must own and serve, and
/// return the agent's end of a relay to it.
///
/// # Errors
///
/// A message naming the socket when it is absent (carrying the system's own
/// error, `os error 2`), not a socket, owned or served by another uid, when
/// the connect fails, or when [`MAX_RELAYS`] are already open.
pub fn open(socket: &Path, owner: u32) -> Result<UnixStream, String> {
    let meta = std::fs::metadata(socket).map_err(|e| format!("{}: {e}", socket.display()))?;
    if !meta.file_type().is_socket() {
        return Err(format!("{} is not a socket", socket.display()));
    }
    if meta.uid() != owner {
        return Err(format!(
            "{} is owned by uid {}, not {owner}",
            socket.display(),
            meta.uid()
        ));
    }
    let slot = Slot::take()
        .ok_or_else(|| format!("{}: {MAX_RELAYS} relays are already open", socket.display()))?;
    let runtime = UnixStream::connect(socket).map_err(|e| format!("{}: {e}", socket.display()))?;
    match crate::server::peer_uid(&runtime) {
        Some(peer) if peer == owner => {}
        Some(peer) => {
            return Err(format!(
                "{} is served by uid {peer}, not {owner}",
                socket.display()
            ));
        }
        None => {
            return Err(format!(
                "{}: the listener's credentials could not be read",
                socket.display()
            ));
        }
    }
    spawn(runtime, slot, socket.display().to_string())
}

/// Return the agent's end of a relay to `runtime`, a stream the caller has
/// already connected to and checked, named `name` in the log.
///
/// # Errors
///
/// [`MAX_RELAYS`] are already open, or the relay could not be started.
pub fn relay_to(runtime: UnixStream, name: String) -> Result<UnixStream, String> {
    let slot =
        Slot::take().ok_or_else(|| format!("{name}: {MAX_RELAYS} relays are already open"))?;
    spawn(runtime, slot, name)
}

fn spawn(runtime: UnixStream, slot: Slot, name: String) -> Result<UnixStream, String> {
    let (agent, ours) = UnixStream::pair().map_err(|e| format!("socket pair: {e}"))?;
    std::thread::Builder::new()
        .name("root-runtime".into())
        .spawn(move || {
            let _slot = slot;
            if let Err(message) = relay(ours, runtime) {
                eprintln!("[warden] {name}: {message}");
            }
        })
        .map_err(|e| format!("relay thread: {e}"))?;
    Ok(agent)
}

/// Read the agent's request head from `agent`: everything up to the blank
/// line, at most [`MAX_HEAD`] bytes.
fn read_head(agent: &mut UnixStream) -> Result<Vec<u8>, String> {
    let mut head = Vec::with_capacity(512);
    let mut byte = [0u8; 512];
    loop {
        let n = agent
            .read(&mut byte)
            .map_err(|e| format!("reading the request: {e}"))?;
        if n == 0 {
            return Err("the agent closed before a whole request".to_owned());
        }
        head.extend_from_slice(&byte[..n]);
        if head.windows(4).any(|w| w == b"\r\n\r\n") {
            return Ok(head);
        }
        if head.len() > MAX_HEAD {
            return Err(format!("request head over {MAX_HEAD} bytes"));
        }
    }
}

/// The target of `head` when it is a `GET` the warden forwards.
fn allowed_target(head: &[u8]) -> Result<String, String> {
    let line = head
        .split(|b| *b == b'\n')
        .next()
        .and_then(|l| std::str::from_utf8(l).ok())
        .map(|l| l.trim_end_matches('\r'))
        .ok_or_else(|| "request line is not text".to_owned())?;
    let mut parts = line.split(' ');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some("GET"), Some(target), Some("HTTP/1.1" | "HTTP/1.0"), None)
            if root_runtime_path_allowed(target) =>
        {
            Ok(target.to_owned())
        }
        _ => Err(format!("refused {line:?}")),
    }
}

fn refuse(agent: &mut UnixStream) {
    const BODY: &str = "the warden forwards only the reads the agent makes\n";
    let _ = agent.write_all(
        format!(
            "HTTP/1.1 403 Forbidden\r\n\
             Content-Type: text/plain\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n\
             {BODY}",
            BODY.len()
        )
        .as_bytes(),
    );
}

/// Serve one request from `agent` on `runtime`, then copy the answer until
/// either side closes.
fn relay(mut agent: UnixStream, mut runtime: UnixStream) -> Result<(), String> {
    agent
        .set_read_timeout(Some(AGENT_TIMEOUT))
        .and_then(|()| agent.set_write_timeout(Some(AGENT_TIMEOUT)))
        .map_err(|e| format!("agent timeouts: {e}"))?;
    let head = read_head(&mut agent)?;
    let target = match allowed_target(&head) {
        Ok(target) => target,
        Err(message) => {
            refuse(&mut agent);
            return Err(message);
        }
    };
    let request = format!(
        "GET {target} HTTP/1.1\r\n\
         Host: localhost\r\n\
         Accept: application/json\r\n\
         Connection: close\r\n\
         \r\n"
    );
    runtime
        .write_all(request.as_bytes())
        .map_err(|e| format!("writing to the runtime: {e}"))?;
    if let Some(projection) = Projection::of(&target) {
        runtime
            .set_read_timeout(Some(RUNTIME_TIMEOUT))
            .map_err(|e| format!("runtime timeout: {e}"))?;
        let answer = read_answer(&mut runtime)
            .and_then(|raw| project_answer(projection, &raw))
            .unwrap_or_else(|message| {
                eprintln!("[warden] {target}: {message}");
                status_only(502)
            });
        return agent
            .write_all(&answer)
            .map_err(|e| format!("writing to the agent: {e}"));
    }
    agent
        .set_read_timeout(None)
        .map_err(|e| format!("agent timeouts: {e}"))?;
    copy_back(&mut agent, &mut runtime)
}

/// The answers the warden reads whole and projects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Projection {
    /// `GET /containers/{id}/json`: one container's inspect.
    Inspect,
    /// `GET /containers/json`: every running container.
    List,
}

impl Projection {
    /// The projection the answer to `target` goes through, `None` for an
    /// answer copied back as it comes.
    #[must_use]
    pub fn of(target: &str) -> Option<Self> {
        let path = target.split('?').next().unwrap_or_default();
        let rest = path.strip_prefix(ROOT_RUNTIME_API_PREFIX)?;
        match rest.split('/').collect::<Vec<_>>().as_slice() {
            ["", "containers", "json"] => Some(Self::List),
            ["", "containers", _, "json"] => Some(Self::Inspect),
            _ => None,
        }
    }
}

/// Read the runtime's whole answer, the runtime closing at its end since the
/// warden asked with `Connection: close`.
fn read_answer(runtime: &mut UnixStream) -> Result<Vec<u8>, String> {
    let mut raw = Vec::new();
    runtime
        .take(MAX_PROJECTED as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|e| format!("reading the runtime: {e}"))?;
    if raw.len() > MAX_PROJECTED {
        return Err(format!("answer over {MAX_PROJECTED} bytes"));
    }
    Ok(raw)
}

/// The answer the agent gets for the runtime's whole answer `raw`: the
/// projection of a 200, and the status alone of anything else, whose body is
/// the runtime's prose.
///
/// # Errors
///
/// `raw` is not an HTTP answer, its body does not decode, or a 200's body is
/// not the JSON the projection reads.
pub fn project_answer(projection: Projection, raw: &[u8]) -> Result<Vec<u8>, String> {
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "no end to the answer's head".to_owned())?;
    let head = std::str::from_utf8(&raw[..end]).map_err(|_| "head is not text".to_owned())?;
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .filter(|code| (100..600).contains(code))
        .ok_or_else(|| "no status in the answer".to_owned())?;
    if status != 200 {
        return Ok(status_only(status));
    }
    let chunked = lines.any(|line| {
        let line = line.to_ascii_lowercase();
        line.starts_with("transfer-encoding:") && line.contains("chunked")
    });
    let body = &raw[end + 4..];
    let body = if chunked {
        dechunk(body)?
    } else {
        body.to_vec()
    };
    let value: Value =
        serde_json::from_slice(&body).map_err(|e| format!("the answer is not JSON: {e}"))?;
    let projected = match projection {
        Projection::Inspect => project_inspect(&value)?,
        Projection::List => project_list(&value)?,
    };
    let body = serde_json::to_vec(&projected).map_err(|e| format!("encode: {e}"))?;
    let mut answer = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        body.len()
    )
    .into_bytes();
    answer.extend_from_slice(&body);
    Ok(answer)
}

/// An answer carrying `status` and no body.
fn status_only(status: u16) -> Vec<u8> {
    format!("HTTP/1.1 {status} Runtime\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .into_bytes()
}

/// The body of a chunked answer.
fn dechunk(mut rest: &[u8]) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    loop {
        let line_end = rest
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| "a chunk size line has no end".to_owned())?;
        let size = std::str::from_utf8(&rest[..line_end])
            .ok()
            .map(|line| line.split(';').next().unwrap_or_default().trim())
            .and_then(|hex| usize::from_str_radix(hex, 16).ok())
            .ok_or_else(|| "a chunk size is not hexadecimal".to_owned())?;
        rest = &rest[line_end + 2..];
        if size == 0 {
            return Ok(body);
        }
        let chunk = rest
            .get(..size)
            .ok_or_else(|| "a chunk is shorter than its size".to_owned())?;
        body.extend_from_slice(chunk);
        rest = rest
            .get(size..)
            .and_then(|r| r.strip_prefix(b"\r\n"))
            .ok_or_else(|| "a chunk does not end its line".to_owned())?;
    }
}

/// The members of `from` named in `keys`, those it has.
fn pick(from: &Value, keys: &[&str]) -> Map<String, Value> {
    keys.iter()
        .filter_map(|key| Some(((*key).to_owned(), from.get(*key)?.clone())))
        .collect()
}

/// One container's inspect, down to what the agent reads.
fn project_inspect(value: &Value) -> Result<Value, String> {
    if !value.is_object() {
        return Err("an inspect answer is not an object".to_owned());
    }
    let mut out = pick(value, &["Id", "Name", "Created"]);
    if let Some(state) = value.get("State").filter(|v| v.is_object()) {
        out.insert("State".into(), Value::Object(pick(state, &["Status"])));
    }
    if let Some(config) = value.get("Config").filter(|v| v.is_object()) {
        out.insert(
            "Config".into(),
            Value::Object(pick(config, &["Image", "Labels"])),
        );
    }
    Ok(Value::Object(out))
}

/// The container list, each entry down to what the agent reads.
fn project_list(value: &Value) -> Result<Value, String> {
    let entries = value
        .as_array()
        .ok_or_else(|| "a list answer is not an array".to_owned())?;
    Ok(Value::Array(
        entries
            .iter()
            .filter(|entry| entry.is_object())
            .map(|entry| Value::Object(pick(entry, &["Id", "Names", "Labels"])))
            .collect(),
    ))
}

/// Copy what `runtime` sends to `agent` until the runtime closes, the agent
/// closes, or the agent writes anything more: a second request is not served.
fn copy_back(agent: &mut UnixStream, runtime: &mut UnixStream) -> Result<(), String> {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let mut fds = [
            libc::pollfd {
                fd: runtime.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: agent.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: `fds` is a live array of two initialised `pollfd`s whose
        // descriptors this function's borrows keep open for the call.
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
        if ready < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(format!("poll: {err}"));
        }
        if fds[1].revents != 0 {
            // The agent closed its end or wrote past its one request.
            return Ok(());
        }
        if fds[0].revents != 0 {
            let n = match runtime.read(&mut buf) {
                Ok(0) => return Ok(()),
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(format!("reading the runtime: {e}")),
            };
            if agent.write_all(&buf[..n]).is_err() {
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    fn current_uid() -> u32 {
        // SAFETY: getuid has no preconditions and cannot fail.
        unsafe { libc::getuid() }
    }

    /// A runtime that answers every request with `OK` and hands back what
    /// it was asked.
    fn fake_runtime(path: &Path) -> std::sync::mpsc::Receiver<String> {
        let listener = UnixListener::bind(path).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let mut conn = conn.unwrap();
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if conn.read(&mut byte).unwrap() == 0 {
                        break;
                    }
                    head.push(byte[0]);
                }
                let _ = tx.send(String::from_utf8_lossy(&head).into_owned());
                let _ = conn.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
                );
            }
        });
        rx
    }

    fn ask(agent: &mut UnixStream, request: &str) -> String {
        agent.write_all(request.as_bytes()).unwrap();
        let mut answer = String::new();
        agent.read_to_string(&mut answer).unwrap();
        answer
    }

    #[test]
    fn a_read_the_agent_makes_is_relayed_as_the_wardens_own_request() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("docker.sock");
        let asked = fake_runtime(&path);
        let mut agent = open(&path, current_uid()).unwrap();
        let answer = ask(
            &mut agent,
            "GET /v1.43/networks/abc HTTP/1.1\r\nHost: x\r\nX-Extra: 1\r\n\r\n",
        );
        assert!(answer.starts_with("HTTP/1.1 200 OK"), "{answer}");
        assert!(answer.ends_with("OK"), "{answer}");
        let request = asked.recv().unwrap();
        assert!(
            request.starts_with("GET /v1.43/networks/abc HTTP/1.1\r\n"),
            "{request}"
        );
        assert!(!request.contains("X-Extra"), "{request}");
    }

    #[test]
    fn a_write_is_answered_403_and_never_reaches_the_runtime() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("docker.sock");
        let asked = fake_runtime(&path);
        for request in [
            "POST /v1.43/containers/create HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}",
            "GET /v1.43/containers/abc/archive?path=/etc HTTP/1.1\r\n\r\n",
            "GET /v1.43/containers/abc/json HTTP/1.1 extra\r\n\r\n",
        ] {
            let mut agent = open(&path, current_uid()).unwrap();
            let answer = ask(&mut agent, request);
            assert!(answer.starts_with("HTTP/1.1 403"), "{request}: {answer}");
        }
        // The runtime was connected to, and closed on without a byte.
        while let Ok(request) = asked.recv_timeout(Duration::from_millis(200)) {
            assert!(request.is_empty(), "the runtime was asked {request:?}");
        }
    }

    /// What a real runtime answered, written by
    /// `tests/fixtures/make-runtime-answers.sh`.
    const ANSWERS: [(&str, Projection, &[u8]); 4] = [
        (
            "docker inspect",
            Projection::Inspect,
            include_bytes!("../tests/fixtures/runtime-answers/docker-inspect.http"),
        ),
        (
            "docker list",
            Projection::List,
            include_bytes!("../tests/fixtures/runtime-answers/docker-list.http"),
        ),
        (
            "podman inspect",
            Projection::Inspect,
            include_bytes!("../tests/fixtures/runtime-answers/podman-inspect.http"),
        ),
        (
            "podman list",
            Projection::List,
            include_bytes!("../tests/fixtures/runtime-answers/podman-list.http"),
        ),
    ];

    fn projected_body(projection: Projection, raw: &[u8]) -> Value {
        let answer = project_answer(projection, raw).unwrap();
        let text = String::from_utf8(answer).unwrap();
        let (head, body) = text.split_once("\r\n\r\n").unwrap();
        assert!(head.starts_with("HTTP/1.1 200 OK"), "{head}");
        assert!(
            head.contains(&format!("Content-Length: {}", body.len())),
            "{head}"
        );
        serde_json::from_str(body).unwrap()
    }

    #[test]
    fn a_real_runtimes_secrets_never_reach_the_agent() {
        for (what, projection, raw) in ANSWERS {
            let raw_text = String::from_utf8_lossy(raw);
            // The fixture carries what the projection must drop.
            assert!(raw_text.contains("fixture-arg-secret"), "{what}");
            assert!(raw_text.contains("\"Source\""), "{what}");
            let body = projected_body(projection, raw).to_string();
            for secret in [
                "fixture-env-secret",
                "fixture-arg-secret",
                "\"Env\"",
                "\"Cmd\"",
                "\"Args\"",
                "\"Command\"",
                "\"Mounts\"",
                "\"Binds\"",
                "\"HostConfig\"",
                "\"Source\"",
            ] {
                assert!(!body.contains(secret), "{what} relays {secret}: {body}");
            }
        }
    }

    #[test]
    fn the_projection_keeps_what_the_agent_reads() {
        for (what, projection, raw) in ANSWERS {
            let body = projected_body(projection, raw);
            let container = match projection {
                Projection::Inspect => body.clone(),
                Projection::List => body[0].clone(),
            };
            assert_eq!(container["Id"].as_str().map(str::len), Some(64), "{what}");
            let labels = match projection {
                Projection::Inspect => &container["Config"]["Labels"],
                Projection::List => &container["Labels"],
            };
            assert_eq!(labels["tier"], "front", "{what}");
            assert_eq!(labels["team"], "payments", "{what}");
            if projection == Projection::Inspect {
                assert_eq!(container["Name"], "/ebpfsentinel-fixture", "{what}");
                assert_eq!(container["State"]["Status"], "running", "{what}");
                assert!(
                    container["Config"]["Image"]
                        .as_str()
                        .is_some_and(|image| image.contains("alpine")),
                    "{what}"
                );
                assert!(container["Created"].is_string(), "{what}");
            } else {
                assert_eq!(container["Names"][0], "/ebpfsentinel-fixture", "{what}");
            }
        }
    }

    #[test]
    fn an_answer_other_than_200_keeps_its_status_and_drops_its_prose() {
        let raw = b"HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\n\r\n{\"message\":\"No such container: x\"}";
        let answer = String::from_utf8(project_answer(Projection::Inspect, raw).unwrap()).unwrap();
        assert!(answer.starts_with("HTTP/1.1 404 "), "{answer}");
        assert!(!answer.contains("No such"), "{answer}");
    }

    #[test]
    fn a_broken_answer_is_refused_rather_than_relayed() {
        for raw in [
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n{}\r\n0\r\n\r\n"[..],
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nff\r\n{}\r\n0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\n\r\nnot json",
            b"HTTP/1.1 200 OK\r\n\r\n[1, 2]",
            b"no head at all",
        ] {
            assert!(project_answer(Projection::Inspect, raw).is_err());
        }
        assert!(project_answer(Projection::List, b"HTTP/1.1 200 OK\r\n\r\n{}").is_err());
    }

    #[test]
    fn only_the_container_reads_are_projected() {
        assert_eq!(
            Projection::of("/v1.43/containers/json"),
            Some(Projection::List)
        );
        assert_eq!(
            Projection::of("/v1.43/containers/abc/json"),
            Some(Projection::Inspect)
        );
        for streamed in [
            "/_ping",
            "/v1.43/events?filters=x",
            "/v1.43/networks",
            "/v1.43/networks/abc",
        ] {
            assert_eq!(Projection::of(streamed), None, "{streamed}");
        }
    }

    #[test]
    fn an_inspect_through_the_relay_is_projected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("docker.sock");
        let listener = UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                conn.read_exact(&mut byte).unwrap();
                head.push(byte[0]);
            }
            conn.write_all(ANSWERS[0].2).unwrap();
        });
        let mut agent = open(&path, current_uid()).unwrap();
        let answer = ask(
            &mut agent,
            "GET /v1.43/containers/abc/json HTTP/1.1\r\nHost: x\r\n\r\n",
        );
        assert!(answer.starts_with("HTTP/1.1 200 OK"), "{answer}");
        assert!(answer.contains("\"tier\":\"front\""), "{answer}");
        assert!(!answer.contains("fixture-env-secret"), "{answer}");
    }

    #[test]
    fn a_socket_owned_by_another_user_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("docker.sock");
        let _asked = fake_runtime(&path);
        let other = current_uid() + 1;
        let err = open(&path, other).unwrap_err();
        assert!(err.contains("owned by uid"), "{err}");
    }

    #[test]
    fn a_missing_socket_carries_the_systems_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let err = open(&dir.path().join("docker.sock"), current_uid()).unwrap_err();
        assert!(err.contains("(os error 2)"), "{err}");
    }

    #[test]
    fn a_file_where_the_socket_should_be_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("docker.sock");
        std::fs::write(&path, b"").unwrap();
        let err = open(&path, current_uid()).unwrap_err();
        assert!(err.contains("not a socket"), "{err}");
    }

    #[test]
    fn the_relay_ends_when_the_agent_closes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut byte = [0u8; 1];
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                conn.read_exact(&mut byte).unwrap();
                head.push(byte[0]);
            }
            conn.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                .unwrap();
            // An event stream that sends nothing more: the warden's relay
            // closing its side is the only way this read ends.
            let n = conn.read(&mut byte).unwrap_or(0);
            done_tx.send(n).unwrap();
        });
        let before = ACTIVE.load(Ordering::Acquire);
        let mut agent = open(&path, current_uid()).unwrap();
        agent
            .write_all(b"GET /v1.43/events?filters=x HTTP/1.1\r\n\r\n")
            .unwrap();
        let mut start = [0u8; 15];
        agent.read_exact(&mut start).unwrap();
        assert_eq!(&start, b"HTTP/1.1 200 OK");
        drop(agent);
        assert_eq!(done_rx.recv_timeout(Duration::from_secs(5)).unwrap(), 0);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while ACTIVE.load(Ordering::Acquire) > before && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(ACTIVE.load(Ordering::Acquire) <= before);
    }
}
