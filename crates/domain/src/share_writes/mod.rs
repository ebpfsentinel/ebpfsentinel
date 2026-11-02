//! A host pushing writes to file shares it has never written to before.
//!
//! Encryption over the network does not happen on the host that holds the
//! files: a workstation mounts the shares it can reach and rewrites them from
//! where it sits, so the file server sees a client doing its job and the
//! workstation's own disk is untouched. What does change on the workstation
//! is where its writes go. An ordinary host writes to the same few servers it
//! wrote to last week; a host that suddenly pushes volume to five servers it
//! has no history with in a few minutes is doing something it never did.
//!
//! The reading is taken off the flow records: a TCP flow towards the SMB
//! ports, the bytes the local side sent being what it wrote. What was
//! written is not read, so nothing here says the files were encrypted, only
//! that the writes went where this host never wrote before, how much and by
//! which process.
//!
//! The history is learned, never written by hand: every server this host
//! writes to during the learning period is part of it, and a server first
//! seen later joins it once the window it was seen in has closed, so a
//! backup server that reaches every share every night is quiet from the
//! first night after learning, and a host that gains one new server a week
//! never adds up to a verdict. The history is held in memory, so an agent
//! restart learns again.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::alert::mitre::MitreAttackInfo;
use crate::common::entity::RuleId;
use crate::flow::entity::FlowRecord;
use crate::workload::entity::Workload;

/// The component an alert about writes to new shares carries.
pub const SHARE_WRITES_COMPONENT: &str = "share_writes";

/// The rule id of that alert.
pub const SHARE_WRITES_RULE_ID: &str = "share-writes-to-new-peers";

/// The ports a file share is reached on: SMB direct and SMB over `NetBIOS`.
pub const SMB_PORTS: [u16; 2] = [445, 139];

/// Servers this host has written to, kept at most. The oldest is forgotten
/// first, so an estate larger than this costs history, never memory.
pub const SHARE_PEERS_KNOWN_MAX: usize = 16_384;

/// Writers followed at once inside a window. A writer past the bound is not
/// followed until a window closes.
pub const SHARE_WRITERS_MAX: usize = 1_024;

/// New servers a single window remembers per writer. The verdict needs a
/// handful, so the bound only stops one writer from growing without end.
pub const SHARE_WINDOW_PEERS_MAX: usize = 256;

const PROTOCOL_TCP: u8 = 6;
const NS_PER_MS: u64 = 1_000_000;

/// What makes a verdict, every value read from configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShareWritesSettings {
    /// How long every server written to is taken as ordinary, from the first
    /// write this agent saw.
    pub learning_ns: u64,
    /// How long one writer's writes to new servers are added up.
    pub window_ns: u64,
    /// New servers in one window that make a verdict.
    pub min_new_peers: usize,
    /// Bytes a new server must receive in the window to count.
    pub min_bytes_per_peer: u64,
}

impl Default for ShareWritesSettings {
    fn default() -> Self {
        Self {
            learning_ns: 7 * 86_400 * 1_000_000_000,
            window_ns: 300 * 1_000_000_000,
            min_new_peers: 5,
            min_bytes_per_peer: 1_048_576,
        }
    }
}

/// One write towards a file share, read off a flow record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareWrite {
    /// The server written to.
    pub peer: IpAddr,
    /// The port it was reached on.
    pub port: u16,
    /// Bytes the local side sent in the record's window.
    pub bytes: u64,
    /// The end of the record's window.
    pub at_ns: u64,
    /// The local process behind the flow, where the node could name it.
    pub workload: Option<Workload>,
}

impl ShareWrite {
    /// The write a flow record carries: a TCP flow towards an SMB port that
    /// sent bytes in its window. The key names the side that opened the
    /// connection first, so the bytes in that direction are what the client
    /// sent the server.
    #[must_use]
    pub fn from_flow(record: &FlowRecord) -> Option<Self> {
        if record.protocol != PROTOCOL_TCP
            || !SMB_PORTS.contains(&record.dst_port)
            || record.bytes == 0
        {
            return None;
        }
        Some(Self {
            peer: record.dst,
            port: record.dst_port,
            bytes: record.bytes,
            at_ns: record.end_ms.saturating_mul(NS_PER_MS),
            workload: record.workload.clone(),
        })
    }
}

/// Who a window belongs to: the process behind the writes where the node
/// named it, the host as a whole where it did not.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct WriterKey {
    pid: Option<u32>,
    exe: Option<String>,
}

impl WriterKey {
    fn of(workload: Option<&Workload>) -> Self {
        Self {
            pid: workload.map(|w| w.pid),
            exe: workload.and_then(|w| w.exe.clone()),
        }
    }
}

#[derive(Debug, Clone)]
struct WriterWindow {
    opened_ns: u64,
    peers: HashMap<IpAddr, (u16, u64)>,
    workload: Option<Workload>,
    raised: bool,
}

/// One server in a verdict and what it received.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharePeer {
    pub peer: IpAddr,
    pub port: u16,
    pub bytes: u64,
}

/// A writer that pushed volume to servers this host never wrote to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareWritesVerdict {
    /// The process behind the writes, absent when the node could not name
    /// it, in which case the host is the writer.
    pub workload: Option<Workload>,
    /// The new servers that received at least the configured volume, most
    /// written first.
    pub peers: Vec<SharePeer>,
    /// When the window opened.
    pub since_ns: u64,
    /// The write that made the verdict.
    pub at_ns: u64,
}

impl ShareWritesVerdict {
    #[must_use]
    pub fn rule_id() -> RuleId {
        RuleId(SHARE_WRITES_RULE_ID.to_string())
    }

    /// Remote Services: SMB/Windows Admin Shares, which is what reaching a
    /// share to write on it is, whatever the writing then does.
    #[must_use]
    pub fn mitre() -> MitreAttackInfo {
        MitreAttackInfo {
            technique_id: "T1021.002".to_string(),
            technique_name: "Remote Services: SMB/Windows Admin Shares".to_string(),
            tactic: "lateral-movement".to_string(),
        }
    }

    /// Bytes written to the new servers, all of them.
    #[must_use]
    pub fn bytes(&self) -> u64 {
        self.peers
            .iter()
            .fold(0u64, |sum, p| sum.saturating_add(p.bytes))
    }

    /// The alert's sentence. It says where the writes went and how much,
    /// and that what was written was not read.
    #[must_use]
    pub fn message(&self) -> String {
        let writer = match &self.workload {
            Some(w) => match &w.exe {
                Some(exe) => format!("pid {} ({exe})", w.pid),
                None => format!("pid {}", w.pid),
            },
            None => "this host (no process named)".to_string(),
        };
        let secs = self.at_ns.saturating_sub(self.since_ns) / 1_000_000_000;
        let mut peers = String::new();
        for (index, peer) in self.peers.iter().enumerate() {
            if index > 0 {
                peers.push_str(", ");
            }
            let _ = write!(peers, "{}:{} ({} bytes)", peer.peer, peer.port, peer.bytes);
        }
        format!(
            "{writer} wrote {} bytes over SMB to {} file servers this host had never written to, \
             within {secs} s: {peers}; the content was not read",
            self.bytes(),
            self.peers.len(),
        )
    }
}

/// The history of servers this host writes to, and the windows of the
/// writers reaching new ones.
#[derive(Debug, Clone)]
pub struct ShareWritesEngine {
    settings: ShareWritesSettings,
    learning_from_ns: Option<u64>,
    known: HashMap<IpAddr, u64>,
    windows: HashMap<WriterKey, WriterWindow>,
}

impl ShareWritesEngine {
    #[must_use]
    pub fn new(settings: ShareWritesSettings) -> Self {
        Self {
            settings,
            learning_from_ns: None,
            known: HashMap::new(),
            windows: HashMap::new(),
        }
    }

    /// Whether the learning period is still running at `at_ns`.
    #[must_use]
    pub fn learning(&self, at_ns: u64) -> bool {
        self.learning_from_ns
            .is_none_or(|from| at_ns.saturating_sub(from) < self.settings.learning_ns)
    }

    /// Servers in the history.
    #[must_use]
    pub fn known_peers(&self) -> usize {
        self.known.len()
    }

    /// Writers with an open window.
    #[must_use]
    pub fn open_windows(&self) -> usize {
        self.windows.len()
    }

    /// Take one write. Returns a verdict the first time a writer's window
    /// holds enough new servers, and never twice for one window.
    pub fn observe(&mut self, write: ShareWrite) -> Option<ShareWritesVerdict> {
        let at = write.at_ns;
        self.learning_from_ns.get_or_insert(at);
        self.close_expired(at);
        if self.learning(at) || self.known.contains_key(&write.peer) {
            self.remember(write.peer, at);
            return None;
        }
        if write.bytes == 0 {
            return None;
        }
        let key = WriterKey::of(write.workload.as_ref());
        if !self.windows.contains_key(&key) && self.windows.len() >= SHARE_WRITERS_MAX {
            return None;
        }
        let window = self.windows.entry(key).or_insert_with(|| WriterWindow {
            opened_ns: at,
            peers: HashMap::new(),
            workload: None,
            raised: false,
        });
        if let Some(workload) = write.workload {
            window.workload = Some(workload);
        }
        if window.peers.contains_key(&write.peer) || window.peers.len() < SHARE_WINDOW_PEERS_MAX {
            let entry = window.peers.entry(write.peer).or_insert((write.port, 0));
            entry.1 = entry.1.saturating_add(write.bytes);
        }
        if window.raised {
            return None;
        }
        let min = self.settings.min_bytes_per_peer;
        let mut peers: Vec<SharePeer> = window
            .peers
            .iter()
            .filter(|(_, (_, bytes))| *bytes >= min)
            .map(|(peer, (port, bytes))| SharePeer {
                peer: *peer,
                port: *port,
                bytes: *bytes,
            })
            .collect();
        if peers.len() < self.settings.min_new_peers {
            return None;
        }
        window.raised = true;
        peers.sort_by(|a, b| b.bytes.cmp(&a.bytes).then(a.peer.cmp(&b.peer)));
        Some(ShareWritesVerdict {
            workload: window.workload.clone(),
            peers,
            since_ns: window.opened_ns,
            at_ns: at,
        })
    }

    /// Close every window older than the window length: the servers it saw
    /// join the history, so the next window starts from them.
    fn close_expired(&mut self, at: u64) {
        let length = self.settings.window_ns;
        let expired: Vec<WriterKey> = self
            .windows
            .iter()
            .filter(|(_, w)| at.saturating_sub(w.opened_ns) >= length)
            .map(|(key, _)| key.clone())
            .collect();
        for key in expired {
            if let Some(window) = self.windows.remove(&key) {
                for peer in window.peers.into_keys() {
                    self.remember(peer, at);
                }
            }
        }
    }

    fn remember(&mut self, peer: IpAddr, at: u64) {
        if !self.known.contains_key(&peer)
            && self.known.len() >= SHARE_PEERS_KNOWN_MAX
            && let Some(oldest) = self
                .known
                .iter()
                .min_by_key(|(_, seen)| **seen)
                .map(|(peer, _)| *peer)
        {
            self.known.remove(&oldest);
        }
        self.known.insert(peer, at);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::entity::FlowEndReason;
    use crate::workload::entity::WorkloadSource;

    const SEC: u64 = 1_000_000_000;
    const MIB: u64 = 1_048_576;

    fn settings() -> ShareWritesSettings {
        ShareWritesSettings {
            learning_ns: 3_600 * SEC,
            window_ns: 300 * SEC,
            min_new_peers: 3,
            min_bytes_per_peer: MIB,
        }
    }

    fn peer(n: u8) -> IpAddr {
        IpAddr::from([10, 0, 1, n])
    }

    fn worker(pid: u32, exe: &str) -> Option<Workload> {
        Workload::new(pid, WorkloadSource::Socket).map(|mut w| {
            w.exe = Some(exe.to_string());
            w
        })
    }

    fn write(n: u8, bytes: u64, at_ns: u64, workload: Option<Workload>) -> ShareWrite {
        ShareWrite {
            peer: peer(n),
            port: 445,
            bytes,
            at_ns,
            workload,
        }
    }

    /// Every server in `peers` written to once, at `at_ns`.
    fn round(
        engine: &mut ShareWritesEngine,
        peers: std::ops::RangeInclusive<u8>,
        at_ns: u64,
        workload: Option<&Workload>,
    ) -> Vec<ShareWritesVerdict> {
        peers
            .filter_map(|n| engine.observe(write(n, 50 * MIB, at_ns, workload.cloned())))
            .collect()
    }

    #[test]
    fn a_flow_towards_smb_is_a_write_and_nothing_else_is() {
        let mut record = FlowRecord {
            src: IpAddr::from([10, 0, 0, 5]),
            dst: peer(9),
            src_port: 50_000,
            dst_port: 445,
            protocol: 6,
            packets: 10,
            bytes: 4_096,
            packets_rev: 10,
            bytes_rev: 128,
            start_ms: 1_000,
            end_ms: 2_000,
            reason: FlowEndReason::ActiveTimeout,
            workload: None,
        };
        let seen = ShareWrite::from_flow(&record).expect("an SMB write");
        assert_eq!(seen.peer, peer(9));
        assert_eq!(seen.bytes, 4_096);
        assert_eq!(seen.at_ns, 2_000 * NS_PER_MS);

        record.dst_port = 443;
        assert!(ShareWrite::from_flow(&record).is_none());
        record.dst_port = 139;
        assert!(ShareWrite::from_flow(&record).is_some());
        record.protocol = 17;
        assert!(ShareWrite::from_flow(&record).is_none());
        record.protocol = 6;
        record.bytes = 0;
        assert!(ShareWrite::from_flow(&record).is_none());
    }

    #[test]
    fn nothing_is_raised_while_the_history_is_learned() {
        let mut engine = ShareWritesEngine::new(settings());
        let tool = worker(40, "/usr/bin/smbclient");
        assert!(round(&mut engine, 1..=20, SEC, tool.as_ref()).is_empty());
        assert_eq!(engine.known_peers(), 20);
        assert!(engine.learning(SEC));
    }

    #[test]
    fn a_backup_server_reaching_every_share_it_learned_stays_quiet() {
        let mut engine = ShareWritesEngine::new(settings());
        let backup = worker(77, "/usr/sbin/backup-agent");
        assert!(round(&mut engine, 1..=30, SEC, backup.as_ref()).is_empty());
        for night in 1..=5u64 {
            let at = night * 86_400 * SEC;
            assert!(!engine.learning(at));
            assert!(round(&mut engine, 1..=30, at, backup.as_ref()).is_empty());
        }
    }

    #[test]
    fn a_host_gaining_one_new_server_at_a_time_never_adds_up_to_a_verdict() {
        let mut engine = ShareWritesEngine::new(settings());
        let backup = worker(77, "/usr/sbin/backup-agent");
        round(&mut engine, 1..=3, SEC, backup.as_ref());
        for (day, n) in (10..=40u8).enumerate() {
            let at = (u64::try_from(day).expect("small") + 1) * 86_400 * SEC;
            assert!(
                engine
                    .observe(write(n, 500 * MIB, at, backup.clone()))
                    .is_none()
            );
        }
        assert_eq!(engine.known_peers(), 3 + 30);
    }

    #[test]
    fn writes_to_several_new_servers_in_one_window_are_a_verdict_naming_the_process() {
        let mut engine = ShareWritesEngine::new(settings());
        let usual = worker(10, "/usr/bin/smbclient");
        round(&mut engine, 1..=2, SEC, usual.as_ref());

        let at = 2 * 3_600 * SEC;
        let intruder = worker(4_410, "/tmp/.x");
        assert!(round(&mut engine, 1..=2, at, intruder.as_ref()).is_empty());
        assert!(
            engine
                .observe(write(50, 2 * MIB, at, intruder.clone()))
                .is_none()
        );
        assert!(
            engine
                .observe(write(51, 9 * MIB, at + SEC, intruder.clone()))
                .is_none()
        );
        let verdict = engine
            .observe(write(52, 5 * MIB, at + 2 * SEC, intruder.clone()))
            .expect("three new servers in one window");
        assert_eq!(verdict.workload.as_ref().map(|w| w.pid), Some(4_410));
        assert_eq!(
            verdict.peers.iter().map(|p| p.peer).collect::<Vec<_>>(),
            vec![peer(51), peer(52), peer(50)]
        );
        assert_eq!(verdict.bytes(), 16 * MIB);
        assert_eq!(verdict.since_ns, at);
        let message = verdict.message();
        assert!(message.contains("pid 4410 (/tmp/.x)"));
        assert!(message.contains("3 file servers"));
        assert!(message.contains("the content was not read"));
        assert!(!message.to_lowercase().contains("encrypt"));

        assert!(
            engine
                .observe(write(53, 5 * MIB, at + 3 * SEC, intruder))
                .is_none(),
            "one verdict per window"
        );
    }

    #[test]
    fn a_server_below_the_volume_does_not_count() {
        let mut engine = ShareWritesEngine::new(settings());
        round(&mut engine, 1..=1, SEC, None);
        let at = 2 * 3_600 * SEC;
        for n in 50..=60 {
            assert!(engine.observe(write(n, MIB - 1, at, None)).is_none());
        }
        assert_eq!(engine.open_windows(), 1);
    }

    #[test]
    fn writes_spread_wider_than_the_window_are_not_added_up() {
        let mut engine = ShareWritesEngine::new(settings());
        round(&mut engine, 1..=1, SEC, None);
        let mut at = 2 * 3_600 * SEC;
        for n in 50..=60 {
            assert!(engine.observe(write(n, 10 * MIB, at, None)).is_none());
            at += 301 * SEC;
        }
    }

    #[test]
    fn two_processes_are_two_windows() {
        let mut engine = ShareWritesEngine::new(settings());
        round(&mut engine, 1..=1, SEC, None);
        let at = 2 * 3_600 * SEC;
        let a = worker(1, "/usr/bin/a");
        let b = worker(2, "/usr/bin/b");
        assert!(engine.observe(write(50, 5 * MIB, at, a.clone())).is_none());
        assert!(engine.observe(write(51, 5 * MIB, at, b.clone())).is_none());
        assert!(engine.observe(write(52, 5 * MIB, at, a)).is_none());
        assert!(engine.observe(write(53, 5 * MIB, at, b)).is_none());
        assert_eq!(engine.open_windows(), 2);
    }

    #[test]
    fn a_writer_with_no_process_named_is_the_host() {
        let mut engine = ShareWritesEngine::new(settings());
        round(&mut engine, 1..=1, SEC, None);
        let verdict = round(&mut engine, 50..=52, 2 * 3_600 * SEC, None)
            .pop()
            .expect("verdict");
        assert!(verdict.workload.is_none());
        assert!(
            verdict
                .message()
                .starts_with("this host (no process named)")
        );
    }

    #[test]
    fn the_history_is_bounded_and_forgets_the_oldest_first() {
        let mut engine = ShareWritesEngine::new(ShareWritesSettings {
            learning_ns: u64::MAX,
            ..settings()
        });
        for n in 0..=SHARE_PEERS_KNOWN_MAX {
            let index = u32::try_from(n).expect("fits");
            let ip = IpAddr::from(std::net::Ipv4Addr::from(0x0a00_0000 + index));
            engine.observe(ShareWrite {
                peer: ip,
                port: 445,
                bytes: 1,
                at_ns: u64::from(index) + 1,
                workload: None,
            });
        }
        assert_eq!(engine.known_peers(), SHARE_PEERS_KNOWN_MAX);
        assert!(!engine.known.contains_key(&IpAddr::from([10, 0, 0, 0])));
    }

    #[test]
    fn the_technique_is_remote_services_over_smb() {
        assert_eq!(ShareWritesVerdict::mitre().technique_id, "T1021.002");
        assert_eq!(ShareWritesVerdict::rule_id().0, SHARE_WRITES_RULE_ID);
    }
}
