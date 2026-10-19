//! Flow records as JSON lines in a file.
//!
//! The sink appends and nothing else. Rotation is the system's job: an
//! estate already runs logrotate or an equivalent over every other file on
//! the node, and a size policy inside the agent is one more place for a disk
//! to fill in a way nobody is watching.
//!
//! Delegating rotation has one obligation, and this is the whole of it: the
//! sink checks that the file it holds open is still the file at the
//! configured path, and reopens when it is not. Without that check `create`
//! leaves the agent writing into an unlinked inode, and every record after
//! the first rotation goes to a file no reader can see while the disk still
//! fills. `copytruncate` needs no reopen, because the inode stays, so both
//! policies work and the operator does not have to pick one. A reopen is one
//! `stat` per batch, which is cheap beside writing the batch.
//!
//! The file is created with owner-only read and write where it does not
//! exist. A flow record names every address a workload talked to, which on a
//! shared node is somebody's business.
//!
//! A write that fails costs flow records and nothing else: the sink counts
//! the failure, arms its backoff, says so in its health and returns. A full
//! disk must not stop the pipeline the conntrack reader is filling.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use domain::common::error::DomainError;
use domain::flow::entity::FlowRecord;
use domain::flow::json;
use infrastructure::config::JsonLinesSinkConfig;
use ports::secondary::flow_sink_port::{FlowSink, FlowSinkHealth};
use tokio::fs::{File, OpenOptions};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tracing::{info, warn};

/// The first wait before a file that could not be written is tried again.
const BACKOFF_FLOOR: Duration = Duration::from_secs(1);
/// The longest wait between two attempts.
const BACKOFF_CEILING: Duration = Duration::from_secs(60);
/// Owner read and write, and nothing for anybody else.
const FILE_MODE: u32 = 0o600;

/// How long to wait before the next attempt, doubling with each failure.
fn backoff_for(consecutive_failures: u32) -> Duration {
    let shift = consecutive_failures.saturating_sub(1).min(6);
    let seconds = BACKOFF_FLOOR.as_secs().saturating_mul(1 << shift);
    Duration::from_secs(seconds).min(BACKOFF_CEILING)
}

/// Everything the writer mutates.
struct SinkState {
    file: Option<File>,
    inode: u64,
    retry_at: Option<Instant>,
    records_sent: u64,
    records_failed: u64,
    consecutive_failures: u32,
    detail: Option<String>,
}

/// One file of JSON lines.
pub struct JsonLinesSink {
    name: String,
    path: PathBuf,
    sampling: u32,
    state: Mutex<SinkState>,
}

impl JsonLinesSink {
    /// A sink for one path. Nothing is opened here: the first batch opens
    /// the file, so a path on a volume that is mounted after the agent
    /// starts is not a permanent failure.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>, sampling: u32) -> Self {
        let path = path.into();
        Self {
            name: format!("json-lines-{}", path.display()),
            path,
            sampling,
            state: Mutex::new(SinkState {
                file: None,
                inode: 0,
                retry_at: None,
                records_sent: 0,
                records_failed: 0,
                consecutive_failures: 0,
                detail: None,
            }),
        }
    }

    /// The sink a configured section asks for, or none.
    #[must_use]
    pub fn from_config(config: &JsonLinesSinkConfig, sampling: u32) -> Vec<Arc<Self>> {
        if !config.enabled {
            return Vec::new();
        }
        vec![Arc::new(Self::new(Path::new(config.path.trim()), sampling))]
    }

    /// Open the file for appending, creating it and its directory where they
    /// are absent, and remember which inode this is.
    async fn open(&self, state: &mut SinkState) -> Result<(), DomainError> {
        if let Some(parent) = self
            .path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            tokio::fs::create_dir_all(parent).await.map_err(|error| {
                DomainError::EngineError(format!(
                    "failed to create '{}': {error}",
                    parent.display()
                ))
            })?;
        }
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(FILE_MODE)
            .open(&self.path)
            .await
            .map_err(|error| {
                DomainError::EngineError(format!(
                    "failed to open '{}': {error}",
                    self.path.display()
                ))
            })?;
        let inode = file
            .metadata()
            .await
            .map_err(|error| DomainError::EngineError(format!("stat failed: {error}")))?
            .ino();
        state.file = Some(file);
        state.inode = inode;
        info!(sink = %self.name, "flow sink opened its file");
        Ok(())
    }

    /// Drop the handle where the path no longer leads to the file behind it,
    /// which is what a rotation under `create` looks like from here.
    async fn drop_if_rotated(&self, state: &mut SinkState) {
        if state.file.is_none() {
            return;
        }
        let rotated = match tokio::fs::metadata(&self.path).await {
            Ok(metadata) => metadata.ino() != state.inode,
            // The path is gone, which is a rotation that moved the file away
            // and has not been followed by a new one yet.
            Err(_) => true,
        };
        if rotated {
            info!(sink = %self.name, "the file was rotated, reopening");
            state.file = None;
        }
    }

    /// Count a failure, drop the handle, and arm the backoff.
    fn note_failure(&self, state: &mut SinkState, records: u64, error: &DomainError) {
        state.records_failed = state.records_failed.saturating_add(records);
        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        state.detail = Some(error.to_string());
        state.file = None;
        state.retry_at = Some(Instant::now() + backoff_for(state.consecutive_failures));
        warn!(sink = %self.name, %error, "flow sink write failed");
    }

    /// One batch, as one write: the lines are rendered into a single buffer
    /// so that a batch cannot be interleaved with another writer's output
    /// halfway through a line.
    async fn deliver(
        &self,
        state: &mut SinkState,
        records: &[FlowRecord],
    ) -> Result<(), DomainError> {
        self.drop_if_rotated(state).await;
        if state.file.is_none() {
            self.open(state).await?;
        }
        let mut buffer = String::with_capacity(records.len() * 512);
        for record in records {
            buffer.push_str(&json::line(record, self.sampling));
        }
        let Some(file) = state.file.as_mut() else {
            return Err(DomainError::EngineError("not open".to_string()));
        };
        file.write_all(buffer.as_bytes())
            .await
            .map_err(|error| DomainError::EngineError(format!("write failed: {error}")))?;
        file.flush()
            .await
            .map_err(|error| DomainError::EngineError(format!("flush failed: {error}")))
    }
}

impl FlowSink for JsonLinesSink {
    fn name(&self) -> &str {
        &self.name
    }

    fn send<'a>(
        &'a self,
        records: &'a [FlowRecord],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), DomainError>> + Send + 'a>>
    {
        Box::pin(async move {
            if records.is_empty() {
                return Ok(());
            }
            let count = u64::try_from(records.len()).unwrap_or(u64::MAX);
            let mut state = self.state.lock().await;
            if let Some(retry_at) = state.retry_at {
                if Instant::now() < retry_at {
                    state.records_failed = state.records_failed.saturating_add(count);
                    return Err(DomainError::EngineError(
                        "file unwritable, backing off".to_string(),
                    ));
                }
                state.retry_at = None;
            }
            match self.deliver(&mut state, records).await {
                Ok(()) => {
                    state.records_sent = state.records_sent.saturating_add(count);
                    state.consecutive_failures = 0;
                    state.detail = None;
                    Ok(())
                }
                Err(error) => {
                    self.note_failure(&mut state, count, &error);
                    Err(error)
                }
            }
        })
    }

    fn health<'a>(
        &'a self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = FlowSinkHealth> + Send + 'a>> {
        Box::pin(async move {
            let state = self.state.lock().await;
            FlowSinkHealth {
                healthy: state.consecutive_failures == 0,
                detail: state.detail.clone(),
                records_sent: state.records_sent,
                records_failed: state.records_failed,
                consecutive_failures: state.consecutive_failures,
                ..FlowSinkHealth::new(self.name.clone())
            }
        })
    }

    fn close<'a>(
        &'a self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), DomainError>> + Send + 'a>>
    {
        Box::pin(async move {
            let mut state = self.state.lock().await;
            if let Some(file) = state.file.as_mut() {
                file.flush()
                    .await
                    .map_err(|error| DomainError::EngineError(format!("flush failed: {error}")))?;
            }
            state.file = None;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use std::os::unix::fs::PermissionsExt;

    use domain::flow::entity::FlowEndReason;

    use super::*;

    fn record() -> FlowRecord {
        FlowRecord {
            src: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)),
            dst: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            src_port: 51_234,
            dst_port: 443,
            protocol: 6,
            packets: 12,
            bytes: 2_048,
            packets_rev: 10,
            bytes_rev: 16_384,
            start_ms: 1_760_000_000_000,
            end_ms: 1_760_000_012_500,
            reason: FlowEndReason::IdleTimeout,
            workload: None,
        }
    }

    #[test]
    fn a_sink_is_named_for_its_path() {
        let sink = JsonLinesSink::new("/var/log/ebpfsentinel/flows.jsonl", 1);
        assert_eq!(sink.name(), "json-lines-/var/log/ebpfsentinel/flows.jsonl");
    }

    #[test]
    fn a_disabled_section_builds_no_sink() {
        assert!(JsonLinesSink::from_config(&JsonLinesSinkConfig::default(), 1).is_empty());
    }

    #[test]
    fn a_configured_section_builds_one_sink() {
        let config = JsonLinesSinkConfig {
            enabled: true,
            path: " /tmp/flows.jsonl ".to_string(),
        };
        let sinks = JsonLinesSink::from_config(&config, 1);
        assert_eq!(sinks.len(), 1);
        assert_eq!(sinks[0].name(), "json-lines-/tmp/flows.jsonl");
    }

    #[tokio::test]
    async fn a_batch_is_one_line_per_record() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = directory.path().join("nested").join("flows.jsonl");
        let sink = JsonLinesSink::new(&path, 1);
        sink.send(&[record(), record()])
            .await
            .expect("the file is writable");
        sink.close().await.expect("the file flushes");

        let written = std::fs::read_to_string(&path).expect("the file exists");
        assert_eq!(written.lines().count(), 2);
        for line in written.lines() {
            let value: serde_json::Value =
                serde_json::from_str(line).expect("every line is one object");
            assert_eq!(value["source.address"], "10.0.0.7");
        }
        let health = sink.health().await;
        assert!(health.healthy);
        assert_eq!(health.records_sent, 2);
    }

    #[tokio::test]
    async fn the_file_is_readable_by_its_owner_alone() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = directory.path().join("flows.jsonl");
        let sink = JsonLinesSink::new(&path, 1);
        sink.send(&[record()]).await.expect("the file is writable");

        let mode = std::fs::metadata(&path)
            .expect("the file exists")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, FILE_MODE, "a flow record names addresses");
    }

    #[tokio::test]
    async fn an_empty_batch_opens_nothing() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = directory.path().join("flows.jsonl");
        let sink = JsonLinesSink::new(&path, 1);
        sink.send(&[])
            .await
            .expect("nothing to send is not a failure");
        assert!(!path.exists(), "an empty batch created a file");
    }

    #[tokio::test]
    async fn a_rotation_that_moves_the_file_is_followed() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = directory.path().join("flows.jsonl");
        let rotated = directory.path().join("flows.jsonl.1");
        let sink = JsonLinesSink::new(&path, 1);
        sink.send(&[record()]).await.expect("the file is writable");

        // What logrotate's default policy does: rename, then leave the agent
        // to notice.
        std::fs::rename(&path, &rotated).expect("the rename succeeds");
        sink.send(&[record()]).await.expect("the sink reopens");
        sink.close().await.expect("the file flushes");

        assert_eq!(
            std::fs::read_to_string(&rotated)
                .expect("the rotated file exists")
                .lines()
                .count(),
            1
        );
        assert_eq!(
            std::fs::read_to_string(&path)
                .expect("the new file exists")
                .lines()
                .count(),
            1,
            "the second record went into the file at the configured path"
        );
    }

    #[tokio::test]
    async fn a_rotation_that_truncates_in_place_keeps_the_same_handle() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = directory.path().join("flows.jsonl");
        let sink = JsonLinesSink::new(&path, 1);
        sink.send(&[record()]).await.expect("the file is writable");

        // What copytruncate does: the inode stays, the content goes.
        std::fs::write(&path, b"").expect("the file is truncated");
        sink.send(&[record()])
            .await
            .expect("the handle still works");
        sink.close().await.expect("the file flushes");

        assert_eq!(
            std::fs::read_to_string(&path)
                .expect("the file exists")
                .lines()
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn a_path_that_cannot_be_opened_counts_and_backs_off() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        // A file where a directory is needed, which no mode can make work.
        let blocker = directory.path().join("blocked");
        std::fs::write(&blocker, b"x").expect("the blocker is written");
        let sink = JsonLinesSink::new(blocker.join("flows.jsonl"), 1);

        sink.send(&[record(), record()])
            .await
            .expect_err("the directory cannot be created");
        let health = sink.health().await;
        assert!(!health.healthy);
        assert_eq!(health.records_failed, 2);
        assert_eq!(health.consecutive_failures, 1);
        assert!(health.detail.is_some());

        sink.send(&[record()])
            .await
            .expect_err("the sink is backing off");
        let health = sink.health().await;
        assert_eq!(health.records_failed, 3);
        assert_eq!(
            health.consecutive_failures, 1,
            "a refusal that never touched the file is not a new failure"
        );
    }

    #[test]
    fn the_wait_doubles_and_then_stops_doubling() {
        assert_eq!(backoff_for(0), Duration::from_secs(1));
        assert_eq!(backoff_for(3), Duration::from_secs(4));
        assert_eq!(backoff_for(u32::MAX), Duration::from_secs(60));
    }
}
