//! The Docker event stream, and what it does to the metadata cache.
//!
//! Inspecting a container on a cache miss answers one question late: the first
//! packet of a container's life is enriched only once the inspect returns, and
//! a container that changed name, image or state keeps its old entry until the
//! time-to-live runs out. `GET /events` answers it early - Docker pushes
//! `create`, `start`, `die` and `destroy` as they happen, each carrying the
//! actor's attributes, so the cache is written from the stream and the inspect
//! is left as the fallback it was meant to be.
//!
//! The stream is a long-lived HTTP/1.1 response in `Transfer-Encoding:
//! chunked`, so this module carries an incremental chunk decoder rather than
//! the whole-response one `docker_client` uses: there is no end of body to
//! wait for. The socket reader never blocks on the cache - it hands events to
//! a bounded channel and drops the oldest-arriving event rather than stalling
//! when the applier is behind, because an event backlog that grows is a leak
//! and a dropped event costs one inspect.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use domain::container::entity::DockerMetadata;

use super::docker_cache::DockerCache;

/// Events we ask Docker for. Anything else is noise for a metadata cache.
const WANTED_ACTIONS: [&str; 4] = ["create", "start", "die", "destroy"];

/// How many events may wait for the applier before one is dropped.
const EVENT_BACKLOG: usize = 1024;

/// Longest single event or chunk-size line we accept, so a stuck stream
/// cannot grow a buffer without bound.
const MAX_EVENT_BYTES: usize = 64 * 1024;

/// First reconnect delay, doubled up to [`MAX_BACKOFF`].
const BASE_BACKOFF: Duration = Duration::from_millis(500);
/// Longest reconnect delay.
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// What the watcher has done, readable while it runs.
#[derive(Debug, Default)]
pub struct DockerEventStats {
    /// Events that reached the cache.
    pub applied: AtomicU64,
    /// Events dropped because the applier was behind.
    pub dropped: AtomicU64,
    /// Times the stream was opened, the first connection included.
    pub connects: AtomicU64,
}

/// One container event, as much of it as a metadata cache needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerEvent {
    pub action: String,
    pub id: String,
    pub attributes: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct WireEvent {
    #[serde(rename = "Type", default)]
    kind: String,
    #[serde(rename = "Action", default)]
    action: String,
    #[serde(rename = "Actor", default)]
    actor: WireActor,
}

#[derive(Debug, Default, Deserialize)]
struct WireActor {
    #[serde(rename = "ID", default)]
    id: String,
    #[serde(rename = "Attributes", default)]
    attributes: BTreeMap<String, String>,
}

/// Decode one event line. `None` for anything that is not a container event
/// we asked for, which includes Docker's own keep-alive newlines.
#[must_use]
pub fn parse_event(line: &[u8]) -> Option<ContainerEvent> {
    let wire: WireEvent = serde_json::from_slice(line).ok()?;
    if wire.kind != "container" || wire.actor.id.is_empty() {
        return None;
    }
    // Docker reports an action with a detail suffix for some events
    // (`exec_start: /bin/sh`); the part before the colon is the action.
    let action = wire
        .action
        .split(':')
        .next()
        .unwrap_or_default()
        .trim()
        .to_string();
    if !WANTED_ACTIONS.contains(&action.as_str()) {
        return None;
    }
    Some(ContainerEvent {
        action,
        id: wire.actor.id,
        attributes: wire.actor.attributes,
    })
}

/// Write one event into the cache. `destroy` removes the entry, everything
/// else writes what the event says, keeping the creation timestamp of an
/// entry an inspect already filled.
pub fn apply_event(cache: &DockerCache, event: &ContainerEvent) {
    if event.action == "destroy" {
        cache.remove(&event.id);
        return;
    }
    let previous = cache.get(&event.id);
    let status = match event.action.as_str() {
        "create" => "created",
        "die" => "exited",
        _ => "running",
    };
    // Docker carries the name and the image as attributes; every other
    // attribute is a container label, which is what the inspect path reports
    // as labels too.
    let name = event
        .attributes
        .get("name")
        .cloned()
        .or_else(|| previous.as_ref().map(|md| md.name.clone()))
        .unwrap_or_default();
    let image = event
        .attributes
        .get("image")
        .cloned()
        .or_else(|| previous.as_ref().map(|md| md.image.clone()))
        .unwrap_or_default();
    let labels: Vec<(String, String)> = event
        .attributes
        .iter()
        .filter(|(key, _)| key.as_str() != "name" && key.as_str() != "image")
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    cache.insert(
        event.id.clone(),
        DockerMetadata {
            name,
            image,
            labels,
            // Only an inspect knows when the container was created. An empty
            // value is what tells the enricher this entry came off the stream
            // and is worth completing once.
            created_at: previous.map(|md| md.created_at).unwrap_or_default(),
            status: status.to_string(),
        },
    );
}

/// Delay before reconnect attempt `attempt`, counted from zero.
#[must_use]
pub fn backoff_delay(attempt: u32) -> Duration {
    BASE_BACKOFF
        .saturating_mul(1u32 << attempt.min(16))
        .min(MAX_BACKOFF)
}

/// Incremental decoder for `Transfer-Encoding: chunked`, for a body that
/// never ends.
#[derive(Debug, Default)]
struct ChunkDecoder {
    /// Bytes of the current chunk-size line, or of the trailing CRLF.
    pending: Vec<u8>,
    /// Bytes still to read of the chunk being decoded, `None` between chunks.
    remaining: Option<usize>,
    /// Set once the stream said something this decoder cannot follow.
    broken: bool,
}

impl ChunkDecoder {
    /// Feed bytes, append decoded payload to `out`.
    fn push(&mut self, mut input: &[u8], out: &mut Vec<u8>) {
        while !input.is_empty() && !self.broken {
            match self.remaining {
                Some(0) => {
                    // Chunk payload done: swallow the CRLF that follows it.
                    self.pending.push(input[0]);
                    input = &input[1..];
                    if self.pending.len() == 2 {
                        if self.pending != b"\r\n" {
                            self.broken = true;
                        }
                        self.pending.clear();
                        self.remaining = None;
                    }
                }
                Some(left) => {
                    let take = left.min(input.len());
                    out.extend_from_slice(&input[..take]);
                    input = &input[take..];
                    self.remaining = Some(left - take);
                }
                None => {
                    let Some(nl) = input.iter().position(|b| *b == b'\n') else {
                        self.pending.extend_from_slice(input);
                        if self.pending.len() > MAX_EVENT_BYTES {
                            self.broken = true;
                        }
                        return;
                    };
                    self.pending.extend_from_slice(&input[..nl]);
                    input = &input[nl + 1..];
                    let line = String::from_utf8_lossy(&self.pending)
                        .trim()
                        .split(';')
                        .next()
                        .unwrap_or_default()
                        .to_string();
                    self.pending.clear();
                    if line.is_empty() {
                        continue;
                    }
                    match usize::from_str_radix(&line, 16) {
                        Ok(size) => self.remaining = Some(size),
                        Err(_) => self.broken = true,
                    }
                }
            }
        }
    }
}

/// Splits a decoded body into newline-delimited event lines, bounding how
/// long one line may grow.
#[derive(Debug, Default)]
struct LineSplitter {
    buf: Vec<u8>,
    overlong: bool,
}

impl LineSplitter {
    fn push(&mut self, input: &[u8], out: &mut Vec<Vec<u8>>) {
        for byte in input {
            if *byte == b'\n' {
                if !self.overlong && !self.buf.is_empty() {
                    out.push(std::mem::take(&mut self.buf));
                } else {
                    self.buf.clear();
                    self.overlong = false;
                }
                continue;
            }
            if self.buf.len() >= MAX_EVENT_BYTES {
                self.overlong = true;
                self.buf.clear();
                continue;
            }
            self.buf.push(*byte);
        }
    }
}

/// The request that opens the stream, filtered server-side so Docker sends
/// only the four actions this cache acts on.
fn events_request() -> String {
    // Percent-encoded `{"type":["container"],"event":[...]}`.
    let events = WANTED_ACTIONS
        .iter()
        .map(|a| format!("%22{a}%22"))
        .collect::<Vec<_>>()
        .join("%2C");
    let filters =
        format!("%7B%22type%22%3A%5B%22container%22%5D%2C%22event%22%3A%5B{events}%5D%7D");
    format!(
        "GET /v1.43/events?filters={filters} HTTP/1.1\r\n\
         Host: localhost\r\n\
         Accept: application/json\r\n\
         \r\n"
    )
}

/// Read one connection to the end, handing every event to `tx`. Returns once
/// the stream closes or breaks.
async fn stream_once(
    socket: &Path,
    tx: &mpsc::Sender<ContainerEvent>,
    stats: &DockerEventStats,
) -> std::io::Result<()> {
    let mut stream = UnixStream::connect(socket).await?;
    stream.write_all(events_request().as_bytes()).await?;
    stream.flush().await?;
    stats.connects.fetch_add(1, Ordering::Relaxed);

    let mut header = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    let mut decoder = ChunkDecoder::default();
    let mut splitter = LineSplitter::default();
    let mut body_started = false;

    loop {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Ok(());
        }
        let mut body = &chunk[..read];
        if !body_started {
            header.extend_from_slice(body);
            let Some(end) = header.windows(4).position(|w| w == b"\r\n\r\n") else {
                if header.len() > MAX_EVENT_BYTES {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "event stream headers too large",
                    ));
                }
                continue;
            };
            let status_ok = String::from_utf8_lossy(&header[..end])
                .lines()
                .next()
                .is_some_and(|line| line.contains(" 200"));
            if !status_ok {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "event stream refused",
                ));
            }
            let rest = header.split_off(end + 4);
            header.clear();
            body_started = true;
            let mut payload = Vec::new();
            let mut lines = Vec::new();
            decoder.push(&rest, &mut payload);
            splitter.push(&payload, &mut lines);
            dispatch(lines, tx, stats);
            body = &[];
        }
        let mut payload = Vec::new();
        let mut lines = Vec::new();
        decoder.push(body, &mut payload);
        if decoder.broken {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "event stream framing broken",
            ));
        }
        splitter.push(&payload, &mut lines);
        dispatch(lines, tx, stats);
    }
}

fn dispatch(lines: Vec<Vec<u8>>, tx: &mpsc::Sender<ContainerEvent>, stats: &DockerEventStats) {
    for line in lines {
        let Some(event) = parse_event(&line) else {
            continue;
        };
        if tx.try_send(event).is_err() {
            stats.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// A running event watcher: the socket reader, the applier, and what they
/// have done.
pub struct DockerEventWatcher {
    stats: Arc<DockerEventStats>,
    reader: JoinHandle<()>,
    applier: JoinHandle<()>,
}

impl DockerEventWatcher {
    /// Start reading `socket`, writing every container event into `cache`.
    /// Reconnects for as long as the handle lives.
    pub fn spawn(socket: impl Into<PathBuf>, cache: Arc<DockerCache>) -> Self {
        let socket = socket.into();
        let stats = Arc::new(DockerEventStats::default());
        let (tx, mut rx) = mpsc::channel::<ContainerEvent>(EVENT_BACKLOG);

        let applier_stats = Arc::clone(&stats);
        let applier = tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                apply_event(&cache, &event);
                applier_stats.applied.fetch_add(1, Ordering::Relaxed);
            }
        });

        let reader_stats = Arc::clone(&stats);
        let reader = tokio::spawn(async move {
            let mut attempt = 0u32;
            loop {
                match stream_once(&socket, &tx, &reader_stats).await {
                    Ok(()) => {
                        debug!(socket = %socket.display(), "docker event stream closed, reconnecting");
                        attempt = 0;
                    }
                    Err(err) => {
                        warn!(socket = %socket.display(), error = %err, "docker event stream failed");
                        attempt = attempt.saturating_add(1);
                    }
                }
                tokio::time::sleep(backoff_delay(attempt)).await;
            }
        });

        info!("docker event stream watcher started");
        Self {
            stats,
            reader,
            applier,
        }
    }

    /// Counters the watcher keeps, shared with the running tasks.
    #[must_use]
    pub fn stats(&self) -> Arc<DockerEventStats> {
        Arc::clone(&self.stats)
    }
}

impl DockerEventWatcher {
    /// Stop reading. Dropping the handle does not: the watcher is meant to
    /// live as long as the agent, and the agent drops the handle as soon as
    /// the enricher is wired.
    pub fn abort(&self) {
        self.reader.abort();
        self.applier.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UnixListener;

    fn event_line(action: &str, id: &str, name: &str, image: &str) -> String {
        format!(
            r#"{{"Type":"container","Action":"{action}","Actor":{{"ID":"{id}","Attributes":{{"name":"{name}","image":"{image}","app":"web"}}}}}}"#
        )
    }

    #[test]
    fn parses_a_container_event_and_keeps_its_labels() {
        let event = parse_event(event_line("start", "abc", "web", "nginx:1.25").as_bytes())
            .expect("container event");
        assert_eq!(event.action, "start");
        assert_eq!(event.id, "abc");
        assert_eq!(event.attributes.get("app").map(String::as_str), Some("web"));
    }

    #[test]
    fn ignores_what_is_not_a_container_action_we_asked_for() {
        assert!(parse_event(b"\n").is_none());
        assert!(parse_event(br#"{"Type":"image","Action":"pull","Actor":{"ID":"i"}}"#).is_none());
        assert!(
            parse_event(br#"{"Type":"container","Action":"exec_start: sh","Actor":{"ID":"a"}}"#)
                .is_none()
        );
        assert!(parse_event(br#"{"Type":"container","Action":"start","Actor":{}}"#).is_none());
    }

    #[test]
    fn a_start_event_writes_the_cache_and_a_destroy_clears_it() {
        let cache = DockerCache::new(8, Duration::from_mins(5));
        let start =
            parse_event(event_line("start", "abc", "web", "nginx:1.25").as_bytes()).unwrap();
        apply_event(&cache, &start);

        let cached = cache.get("abc").expect("written from the event");
        assert_eq!(cached.name, "web");
        assert_eq!(cached.image, "nginx:1.25");
        assert_eq!(cached.status, "running");
        assert_eq!(cached.labels, vec![("app".to_string(), "web".to_string())]);
        // Only an inspect knows the creation time, so the stream leaves it
        // empty rather than inventing one.
        assert!(cached.created_at.is_empty());

        let die = parse_event(event_line("die", "abc", "web", "nginx:1.25").as_bytes()).unwrap();
        apply_event(&cache, &die);
        assert_eq!(cache.get("abc").unwrap().status, "exited");

        let destroy =
            parse_event(event_line("destroy", "abc", "web", "nginx:1.25").as_bytes()).unwrap();
        apply_event(&cache, &destroy);
        assert!(cache.get("abc").is_none());
    }

    #[test]
    fn an_event_keeps_the_creation_time_an_inspect_already_filled() {
        let cache = DockerCache::new(8, Duration::from_mins(5));
        cache.insert(
            "abc".into(),
            DockerMetadata {
                name: "web".into(),
                image: "nginx:1.25".into(),
                labels: vec![],
                created_at: "2026-01-15T10:30:00.000Z".into(),
                status: "running".into(),
            },
        );
        let die = parse_event(event_line("die", "abc", "web", "nginx:1.25").as_bytes()).unwrap();
        apply_event(&cache, &die);

        let cached = cache.get("abc").unwrap();
        assert_eq!(cached.created_at, "2026-01-15T10:30:00.000Z");
        assert_eq!(cached.status, "exited");
    }

    #[test]
    fn the_chunk_decoder_survives_a_split_anywhere() {
        let body = b"5\r\nhello\r\n6\r\n world\r\n";
        for split in 0..body.len() {
            let mut decoder = ChunkDecoder::default();
            let mut out = Vec::new();
            decoder.push(&body[..split], &mut out);
            decoder.push(&body[split..], &mut out);
            assert!(!decoder.broken, "split at {split}");
            assert_eq!(std::str::from_utf8(&out).unwrap(), "hello world");
        }
    }

    #[test]
    fn the_chunk_decoder_refuses_a_size_line_that_is_not_a_size() {
        let mut decoder = ChunkDecoder::default();
        let mut out = Vec::new();
        decoder.push(b"nonsense\r\n", &mut out);
        assert!(decoder.broken);
    }

    #[test]
    fn a_line_longer_than_the_bound_is_dropped_whole() {
        let mut splitter = LineSplitter::default();
        let mut lines = Vec::new();
        let long = vec![b'x'; MAX_EVENT_BYTES + 10];
        splitter.push(&long, &mut lines);
        splitter.push(b"\n{\"ok\":1}\n", &mut lines);
        assert_eq!(lines, vec![b"{\"ok\":1}".to_vec()]);
    }

    #[test]
    fn backoff_doubles_and_stops_at_the_ceiling() {
        assert_eq!(backoff_delay(0), BASE_BACKOFF);
        assert_eq!(backoff_delay(1), BASE_BACKOFF * 2);
        assert!(backoff_delay(3) < backoff_delay(4));
        assert_eq!(backoff_delay(20), MAX_BACKOFF);
    }

    #[test]
    fn the_request_asks_for_the_four_actions_and_nothing_else() {
        let request = events_request();
        for action in WANTED_ACTIONS {
            assert!(request.contains(&format!("%22{action}%22")), "{action}");
        }
        assert!(request.contains("%22container%22"));
    }

    /// Serve one canned chunked event stream, then close the connection.
    async fn serve_once(listener: &UnixListener, events: Vec<String>) {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut request = [0u8; 1024];
        let _ = stream.read(&mut request).await;
        let mut response =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"
                .to_vec();
        for event in events {
            let line = format!("{event}\n");
            response.extend_from_slice(format!("{:x}\r\n{line}\r\n", line.len()).as_bytes());
        }
        stream.write_all(&response).await.expect("write");
        stream.flush().await.expect("flush");
    }

    #[tokio::test]
    async fn the_watcher_writes_the_cache_from_the_stream_and_reconnects() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("docker.sock");
        let listener = UnixListener::bind(&socket).expect("bind");

        let cache = Arc::new(DockerCache::new(8, Duration::from_mins(5)));
        let watcher = DockerEventWatcher::spawn(&socket, Arc::clone(&cache));
        let stats = watcher.stats();

        serve_once(
            &listener,
            vec![event_line("start", "abc", "web", "nginx:1.25")],
        )
        .await;
        // No inspect anywhere in this test: the entry can only come from the
        // stream.
        let cached = wait_for(|| cache.get("abc"))
            .await
            .expect("cached from event");
        assert_eq!(cached.name, "web");
        assert_eq!(cached.status, "running");

        // The server closed; the watcher must come back on its own.
        serve_once(
            &listener,
            vec![event_line("die", "abc", "web", "nginx:1.25")],
        )
        .await;
        let cached = wait_for(|| cache.get("abc").filter(|md| md.status == "exited"))
            .await
            .expect("second connection applied");
        assert_eq!(cached.status, "exited");
        assert!(stats.connects.load(Ordering::Relaxed) >= 2);
        assert_eq!(stats.dropped.load(Ordering::Relaxed), 0);
        watcher.abort();
    }

    async fn wait_for<T>(mut probe: impl FnMut() -> Option<T>) -> Option<T> {
        for _ in 0..200 {
            if let Some(value) = probe() {
                return Some(value);
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        None
    }
}
