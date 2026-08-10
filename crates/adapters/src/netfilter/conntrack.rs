//! Kernel netfilter conntrack reader via `/proc/net/nf_conntrack`.
//!
//! Implements [`ConnTrackMapPort`] by reading the kernel's authoritative
//! conntrack table rather than the BPF shadow maps. Zero new dependencies
//! beyond `std` — the proc filesystem is stable since Linux 2.6 and the
//! format has not changed.
//!
//! `/proc/net/nf_conntrack` is mode `0440 root:root`, so reading it requires the
//! reader to be root (or hold a usable `CAP_DAC_*` override). This reader (and
//! the conntrack event poller that diffs its snapshots) therefore works only when
//! the agent runs as real root in the host user namespace — i.e. the
//! single-container mode where the launcher keeps the agent as root (e.g. under
//! Docker). Under the rootless token deployment the agent is a non-root uid in a
//! child user namespace, where `CAP_DAC_OVERRIDE` is unusable against a file owned
//! by the unmapped host root, so a direct open returns `EACCES`; the agent instead
//! proxies every conntrack operation (table read, flush, targeted delete) to the
//! warden over its typed protocol, selected by `EBPFSENTINEL_WARDEN_SOCK`. The
//! warden in turn runs the host-netns ops (`conntrack -F`, netlink delete, the
//! `0440 root` proc read) through its resident netns-helper, which holds the
//! `CAP_NET_ADMIN` the user-namespace agent lacks over the host netns. When no
//! warden socket is set (single-container root, or bare metal) the reader opens
//! `/proc` directly.

use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use domain::common::error::DomainError;
use domain::conntrack::entity::{ConnTrackSettings, Connection, ConnectionState};
use ebpfsentinel_warden_client::{ConntrackTuple, ReconnectingClient};
use ports::secondary::conntrack_kill_port::ConnTrackKillPort;
use ports::secondary::conntrack_map_port::ConnTrackMapPort;
use tracing::{debug, warn};

/// Default path to the kernel conntrack table.
const DEFAULT_NF_CONNTRACK_PATH: &str = "/proc/net/nf_conntrack";
/// Default path to the kernel conntrack entry count.
const DEFAULT_NF_CONNTRACK_COUNT_PATH: &str = "/proc/sys/net/netfilter/nf_conntrack_count";
/// Env var set for the rootless agent with the warden control-plane socket. When
/// present, every conntrack operation (table read, flush, targeted delete) is
/// proxied to the warden over its typed protocol instead of touching `/proc` or
/// the `conntrack` CLI directly — the rootless agent holds none of the required
/// privileges.
const WARDEN_SOCK_ENV: &str = "EBPFSENTINEL_WARDEN_SOCK";

/// Reads the kernel netfilter conntrack table via `/proc/net/nf_conntrack`.
///
/// This is the same data `conntrack -L` displays — the kernel's
/// authoritative view, not the BPF shadow copy. Userspace REST endpoints
/// backed by this port are guaranteed coherent with the `conntrack` CLI
/// and any firewall or NAT tooling that inspects the kernel CT table.
pub struct ProcNetfilterConntrackPort {
    /// Path to the proc conntrack file (injectable for tests).
    nf_conntrack_path: PathBuf,
    /// Path to the proc conntrack count file.
    nf_conntrack_count_path: PathBuf,
    /// Warden control-plane client. When present (rootless agent), every conntrack
    /// operation is proxied to the warden over its typed protocol. The client
    /// caches its connection, so it is held behind a `Mutex` to satisfy the `&self`
    /// read/delete methods.
    warden: Option<Mutex<ReconnectingClient>>,
}

impl ProcNetfilterConntrackPort {
    /// Build a port reading from the default `/proc` paths.
    #[must_use]
    pub fn new() -> Self {
        let warden = std::env::var_os(WARDEN_SOCK_ENV)
            .map(PathBuf::from)
            .filter(|p| !p.as_os_str().is_empty())
            .map(|p| Mutex::new(ReconnectingClient::new(p)));
        Self {
            nf_conntrack_path: PathBuf::from(DEFAULT_NF_CONNTRACK_PATH),
            nf_conntrack_count_path: PathBuf::from(DEFAULT_NF_CONNTRACK_COUNT_PATH),
            warden,
        }
    }

    /// Build a port with injectable paths for unit testing (no warden).
    #[must_use]
    pub fn with_paths(nf_conntrack: PathBuf, nf_conntrack_count: PathBuf) -> Self {
        Self {
            nf_conntrack_path: nf_conntrack,
            nf_conntrack_count_path: nf_conntrack_count,
            warden: None,
        }
    }

    /// Dump the conntrack table through `conntrack -L` when the proc file is
    /// unreadable.
    ///
    /// Carries the original open error into every failure message: "conntrack
    /// is unreadable" and "conntrack-tools is missing" call for different
    /// operator actions, and reporting only the second would hide a proc file
    /// that exists but is being refused.
    fn dump_via_conntrack_cli(&self, proc_err: &std::io::Error) -> Result<Vec<u8>, DomainError> {
        let path = self.nf_conntrack_path.display();
        let output = std::process::Command::new("conntrack")
            .args(["-L"])
            .output()
            .map_err(|e| {
                DomainError::EngineError(format!(
                    "failed to open {path}: {proc_err}; `conntrack -L` fallback \
                     failed: {e} (conntrack-tools installed?)"
                ))
            })?;
        if !output.status.success() {
            return Err(DomainError::EngineError(format!(
                "failed to open {path}: {proc_err}; `conntrack -L` exited with \
                 status {}",
                output.status
            )));
        }
        Ok(output.stdout)
    }
}

impl Default for ProcNetfilterConntrackPort {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnTrackKillPort for ProcNetfilterConntrackPort {
    fn delete_matching(&self, protocol: u8, dst_port: u16) -> Result<u64, DomainError> {
        let proto = match protocol {
            6 => "tcp",
            17 => "udp",
            1 => "icmp",
            132 => "sctp",
            // Wildcard / unsupported protocol — no precise tuple to target,
            // so refuse rather than risk a table-wide delete.
            _ => return Ok(0),
        };
        // Rootless agent: the netlink delete is a CAP_NET_ADMIN op the warden runs.
        // The warden reports only success/failure (no deleted count), so report 0
        // and log the teardown so it stays observable.
        if let Some(warden) = &self.warden {
            let tuple = ConntrackTuple {
                proto: protocol,
                src_ip: String::new(),
                dst_ip: String::new(),
                src_port: 0,
                dst_port,
            };
            warden
                .lock()
                .map_err(|_| DomainError::EngineError("warden client lock poisoned".into()))?
                .conntrack_delete(&tuple)
                .map_err(|e| {
                    DomainError::EngineError(format!("warden conntrack delete failed: {e}"))
                })?;
            debug!(
                protocol = proto,
                dst_port, "conntrack flow teardown issued via warden"
            );
            return Ok(0);
        }
        let dport = dst_port.to_string();
        let output = std::process::Command::new("conntrack")
            .args(["-D", "-p", proto, "--dport", &dport])
            .output()
            .map_err(|e| {
                DomainError::EngineError(format!(
                    "failed to run `conntrack -D`: {e} (conntrack-tools installed?)"
                ))
            })?;
        // `conntrack -D` summarises the result on stderr as
        // "... N flow entries have been deleted." and exits non-zero when
        // nothing matched — that is not an error here, so parse the count
        // from the output regardless of exit status.
        let deleted = parse_deleted_count(&String::from_utf8_lossy(&output.stderr));
        debug!(
            protocol = proto,
            dst_port, deleted, "conntrack entries deleted to enforce firewall deny rule"
        );
        Ok(deleted)
    }
}

/// Parse the "N flow entries have been deleted." summary emitted by
/// `conntrack -D` on stderr. Returns the first standalone numeric token,
/// which is the deleted-entry count (the tool version like `v1.4.6` is not
/// a bare integer, so it is skipped).
fn parse_deleted_count(text: &str) -> u64 {
    text.split_whitespace()
        .find_map(|tok| tok.parse::<u64>().ok())
        .unwrap_or(0)
}

impl ConnTrackMapPort for ProcNetfilterConntrackPort {
    fn get_connections(&self, limit: usize) -> Result<Vec<Connection>, DomainError> {
        // Rootless agent: proxy the read through the warden's typed protocol.
        // Otherwise read the proc file directly. Same text format either way.
        let reader: Box<dyn std::io::BufRead> = if let Some(warden) = &self.warden {
            let bytes = warden
                .lock()
                .map_err(|_| DomainError::EngineError("warden client lock poisoned".into()))?
                .conntrack_dump()
                .map_err(|e| {
                    DomainError::EngineError(format!("warden conntrack dump failed: {e}"))
                })?;
            Box::new(std::io::Cursor::new(bytes))
        } else {
            match std::fs::File::open(&self.nf_conntrack_path) {
                Ok(file) => Box::new(std::io::BufReader::new(file)),
                // A kernel built without CONFIG_NF_CONNTRACK_PROCFS has no proc
                // file while conntrack itself is entirely live, and dropping
                // that deprecated interface is the direction distributions are
                // moving. Fall back to the same conntrack-tools binary this
                // port already drives for -D and -F: its dump differs from the
                // proc file only by the two leading address-family fields,
                // which the parser detects rather than assumes.
                Err(proc_err) => Box::new(std::io::Cursor::new(
                    self.dump_via_conntrack_cli(&proc_err)?,
                )),
            }
        };
        let mut conns = Vec::new();

        for line in reader.lines() {
            if conns.len() >= limit {
                break;
            }
            let line = match line {
                Ok(l) => l,
                Err(e) => {
                    debug!("skipping malformed conntrack line: {e}");
                    continue;
                }
            };
            if let Some(conn) = parse_nf_conntrack_line(&line) {
                conns.push(conn);
            }
        }

        Ok(conns)
    }

    fn flush_all(&mut self) -> Result<u64, DomainError> {
        let count = self.connection_count().unwrap_or(0);
        // Rootless agent: the kernel flush is a CAP_NET_ADMIN op the warden runs.
        // The pre-flush count is best-effort (the proc count file is root-only, so
        // it is typically 0 here); the flush itself is authoritative.
        if let Some(warden) = &self.warden {
            warden
                .lock()
                .map_err(|_| DomainError::EngineError("warden client lock poisoned".into()))?
                .conntrack_flush()
                .map_err(|e| {
                    DomainError::EngineError(format!("warden conntrack flush failed: {e}"))
                })?;
            return Ok(count);
        }
        let status = std::process::Command::new("conntrack")
            .args(["-F"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map_err(|e| {
                DomainError::EngineError(format!(
                    "failed to run `conntrack -F`: {e} (conntrack-tools installed?)"
                ))
            })?;
        if !status.success() {
            return Err(DomainError::EngineError(format!(
                "`conntrack -F` exited with status {status}"
            )));
        }
        Ok(count)
    }

    fn set_config(&mut self, settings: &ConnTrackSettings) -> Result<(), DomainError> {
        // Write kernel sysctl timeout values. Best-effort: log on failure
        // but do not block the agent startup.
        write_sysctl(
            "net.netfilter.nf_conntrack_tcp_timeout_established",
            settings.tcp_established_timeout_secs,
        );
        write_sysctl(
            "net.netfilter.nf_conntrack_tcp_timeout_syn_sent",
            settings.tcp_syn_timeout_secs,
        );
        write_sysctl(
            "net.netfilter.nf_conntrack_tcp_timeout_fin_wait",
            settings.tcp_fin_timeout_secs,
        );
        write_sysctl(
            "net.netfilter.nf_conntrack_udp_timeout",
            settings.udp_timeout_secs,
        );
        write_sysctl(
            "net.netfilter.nf_conntrack_udp_timeout_stream",
            settings.udp_stream_timeout_secs,
        );
        write_sysctl(
            "net.netfilter.nf_conntrack_icmp_timeout",
            settings.icmp_timeout_secs,
        );
        // Disable mid-stream connection pickup. A stateful security gateway must
        // not adopt a TCP flow whose opening SYN it never observed — honoring
        // such flows is a known firewall-evasion vector. It is also what makes a
        // firewall-driven flow teardown durable: once the kernel conntrack entry
        // for a denied flow is destroyed, an in-flight reply packet must not
        // silently re-create an ESTABLISHED entry and resurrect the flow.
        write_sysctl("net.netfilter.nf_conntrack_tcp_loose", 0);
        debug!("kernel netfilter conntrack timeouts synced via sysctl");
        Ok(())
    }

    fn connection_count(&self) -> Result<u64, DomainError> {
        let contents = std::fs::read_to_string(&self.nf_conntrack_count_path).map_err(|e| {
            DomainError::EngineError(format!(
                "failed to read {}: {e}",
                self.nf_conntrack_count_path.display()
            ))
        })?;
        contents
            .trim()
            .parse::<u64>()
            .map_err(|e| DomainError::EngineError(format!("invalid conntrack count: {e}")))
    }
}

/// Write a sysctl value. Best-effort: warns on failure.
fn write_sysctl(key: &str, value: u64) {
    let path = format!("/proc/sys/{}", key.replace('.', "/"));
    if let Err(e) = std::fs::write(&path, value.to_string()) {
        warn!("sysctl write {key}={value} failed: {e}");
    }
}

// ── /proc/net/nf_conntrack line parser ────────────────────────────

/// Parse a single line from `/proc/net/nf_conntrack`.
///
/// Format (TCP):
/// ```text
/// ipv4     2 tcp      6 431999 ESTABLISHED src=1.2.3.4 dst=5.6.7.8 sport=12345 dport=443 src=5.6.7.8 dst=1.2.3.4 sport=443 dport=12345 [ASSURED] mark=0 use=2
/// ```
///
/// Format (UDP / ICMP — no state field):
/// ```text
/// ipv4     2 udp      17 29 src=10.0.0.1 dst=8.8.8.8 sport=53422 dport=53 src=8.8.8.8 dst=10.0.0.1 sport=53 dport=53422 [ASSURED] mark=0 use=2
/// ```
///
/// `conntrack -L` emits the same line without the leading address family and
/// its number, so the head is located rather than assumed and one parser
/// serves both sources:
/// ```text
/// tcp      6 299 ESTABLISHED src=1.2.3.4 dst=5.6.7.8 sport=12345 dport=443 ...
/// ```
fn parse_nf_conntrack_line(line: &str) -> Option<Connection> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    // The proc file prefixes every line with "ipv4 2" / "ipv6 10"; the CLI
    // dump starts straight at the protocol name.
    let base = usize::from(matches!(tokens.first().copied(), Some("ipv4" | "ipv6"))) * 2;
    // Minimum past the head: proto_name + proto_num + timeout + state + a
    // full tuple. Kept identical to the pre-fallback proc threshold rather
    // than relaxed to the shortest CLI line that could exist, since conntrack
    // always prints both tuples plus mark/use and a shorter line is malformed.
    if tokens.len() < base + 8 {
        return None;
    }

    let protocol = tokens[base + 1].parse::<u8>().ok()?;
    // Timeout in seconds.
    let _timeout_secs: u64 = tokens[base + 2].parse().unwrap_or(0);

    // For TCP (proto 6) the next token is the state string and the tuple
    // follows it; for other protocols the tuple starts immediately.
    let (state, tuple_start) = if protocol == 6 {
        // TCP state
        let s = parse_kernel_tcp_state(tokens.get(base + 3).copied().unwrap_or(""));
        (s, base + 4)
    } else {
        (ConnectionState::Established, base + 3)
    };

    // Parse original tuple (first set of src=/dst=/sport=/dport=)
    let mut src_ip = String::new();
    let mut dst_ip = String::new();
    let mut src_port: u16 = 0;
    let mut dst_port: u16 = 0;
    let mut packets_fwd: u32 = 0;
    let mut bytes_fwd: u32 = 0;
    let mut packets_rev: u32 = 0;
    let mut bytes_rev: u32 = 0;

    // Track whether we've seen the reply tuple. The original and reply
    // tuples both have src=/dst=/sport=/dport= so we count occurrences.
    let mut src_count = 0u8;

    for token in &tokens[tuple_start..] {
        if let Some(val) = token.strip_prefix("src=") {
            src_count += 1;
            if src_count == 1 {
                src_ip = val.to_string();
            }
        } else if let Some(val) = token.strip_prefix("dst=") {
            if src_count == 1 {
                dst_ip = val.to_string();
            }
        } else if let Some(val) = token.strip_prefix("sport=") {
            if src_count == 1 {
                src_port = val.parse().unwrap_or(0);
            }
        } else if let Some(val) = token.strip_prefix("dport=") {
            if src_count == 1 {
                dst_port = val.parse().unwrap_or(0);
            }
        } else if let Some(val) = token.strip_prefix("packets=") {
            let p: u32 = val.parse().unwrap_or(0);
            if src_count <= 1 {
                packets_fwd = p;
            } else {
                packets_rev = p;
            }
        } else if let Some(val) = token.strip_prefix("bytes=") {
            let b: u32 = val.parse().unwrap_or(0);
            if src_count <= 1 {
                bytes_fwd = b;
            } else {
                bytes_rev = b;
            }
        }
    }

    if src_ip.is_empty() || dst_ip.is_empty() {
        return None;
    }

    Some(Connection {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        state,
        packets_fwd,
        packets_rev,
        bytes_fwd,
        bytes_rev,
        first_seen_ns: 0,
        last_seen_ns: 0,
    })
}

/// Map kernel TCP state strings to domain `ConnectionState`.
fn parse_kernel_tcp_state(s: &str) -> ConnectionState {
    match s {
        "ESTABLISHED" => ConnectionState::Established,
        "SYN_SENT" => ConnectionState::SynSent,
        "SYN_RECV" => ConnectionState::SynRecv,
        "FIN_WAIT" => ConnectionState::FinWait,
        "CLOSE_WAIT" => ConnectionState::CloseWait,
        "TIME_WAIT" | "CLOSE" | "LAST_ACK" | "LISTEN" | "CLOSING" => ConnectionState::TimeWait,
        "NONE" => ConnectionState::New,
        _ => ConnectionState::Invalid,
    }
}

/// Check whether `/proc/net/nf_conntrack` is readable.
#[must_use]
pub fn is_proc_conntrack_available() -> bool {
    Path::new(DEFAULT_NF_CONNTRACK_PATH).exists()
}

/// Check whether the conntrack table can be read at all, by either source.
///
/// Used at startup to decide whether the event stream is wired. Gating that on
/// the proc file alone silently retired the whole feature on any kernel built
/// without `CONFIG_NF_CONNTRACK_PROCFS` - a deprecated interface distributions
/// are dropping - even though conntrack itself was live and `conntrack -L`
/// could dump it.
#[must_use]
pub fn is_conntrack_readable() -> bool {
    if is_proc_conntrack_available() {
        return true;
    }
    // Probing the binary rather than merely locating it: conntrack-tools can be
    // installed and still fail here, because a dump needs CAP_NET_ADMIN and the
    // rootless agent does not hold it.
    std::process::Command::new("conntrack")
        .args(["-L"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_deleted_count_extracts_number() {
        let summary = "conntrack v1.4.6 (conntrack-tools): 2 flow entries have been deleted.";
        assert_eq!(parse_deleted_count(summary), 2);
    }

    #[test]
    fn parse_deleted_count_zero_when_none() {
        let summary = "conntrack v1.4.6 (conntrack-tools): 0 flow entries have been deleted.";
        assert_eq!(parse_deleted_count(summary), 0);
        assert_eq!(parse_deleted_count(""), 0);
    }

    #[test]
    fn parse_tcp_established_line() {
        let line = "ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.1.1 dst=10.0.0.1 sport=12345 dport=443 src=10.0.0.1 dst=192.168.1.1 sport=443 dport=12345 [ASSURED] mark=0 use=2";
        let conn = parse_nf_conntrack_line(line).unwrap();
        assert_eq!(conn.src_ip, "192.168.1.1");
        assert_eq!(conn.dst_ip, "10.0.0.1");
        assert_eq!(conn.src_port, 12345);
        assert_eq!(conn.dst_port, 443);
        assert_eq!(conn.protocol, 6);
        assert_eq!(conn.state, ConnectionState::Established);
    }

    #[test]
    fn parse_tcp_syn_sent_line() {
        let line = "ipv4     2 tcp      6 119 SYN_SENT src=10.0.2.15 dst=93.184.216.34 sport=54321 dport=80 [UNREPLIED] src=93.184.216.34 dst=10.0.2.15 sport=80 dport=54321 mark=0 use=2";
        let conn = parse_nf_conntrack_line(line).unwrap();
        assert_eq!(conn.state, ConnectionState::SynSent);
        assert_eq!(conn.src_port, 54321);
        assert_eq!(conn.dst_port, 80);
    }

    #[test]
    fn parse_udp_line_no_state_field() {
        let line = "ipv4     2 udp      17 29 src=10.0.0.1 dst=8.8.8.8 sport=53422 dport=53 src=8.8.8.8 dst=10.0.0.1 sport=53 dport=53422 [ASSURED] mark=0 use=2";
        let conn = parse_nf_conntrack_line(line).unwrap();
        assert_eq!(conn.protocol, 17);
        assert_eq!(conn.state, ConnectionState::Established);
        assert_eq!(conn.src_ip, "10.0.0.1");
        assert_eq!(conn.dst_ip, "8.8.8.8");
        assert_eq!(conn.src_port, 53422);
        assert_eq!(conn.dst_port, 53);
    }

    #[test]
    fn parse_icmp_line() {
        let line = "ipv4     2 icmp     1 29 src=10.0.0.1 dst=10.0.0.2 type=8 code=0 id=1234 src=10.0.0.2 dst=10.0.0.1 type=0 code=0 id=1234 mark=0 use=2";
        let conn = parse_nf_conntrack_line(line).unwrap();
        assert_eq!(conn.protocol, 1);
        // ICMP has no sport/dport in the tuple — those fields stay 0.
        assert_eq!(conn.src_ip, "10.0.0.1");
        assert_eq!(conn.dst_ip, "10.0.0.2");
    }

    #[test]
    fn parse_ipv6_tcp_line() {
        let line = "ipv6     10 tcp      6 299 ESTABLISHED src=2001:db8::1 dst=2001:db8::2 sport=443 dport=8080 src=2001:db8::2 dst=2001:db8::1 sport=8080 dport=443 [ASSURED] mark=0 use=2";
        let conn = parse_nf_conntrack_line(line).unwrap();
        assert_eq!(conn.src_ip, "2001:db8::1");
        assert_eq!(conn.dst_ip, "2001:db8::2");
        assert_eq!(conn.src_port, 443);
        assert_eq!(conn.dst_port, 8080);
        assert_eq!(conn.protocol, 6);
        assert_eq!(conn.state, ConnectionState::Established);
    }

    #[test]
    fn parse_line_with_counters() {
        let line = "ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.1.1 dst=10.0.0.1 sport=12345 dport=443 packets=100 bytes=50000 src=10.0.0.1 dst=192.168.1.1 sport=443 dport=12345 packets=200 bytes=150000 [ASSURED] mark=0 use=2";
        let conn = parse_nf_conntrack_line(line).unwrap();
        assert_eq!(conn.packets_fwd, 100);
        assert_eq!(conn.bytes_fwd, 50000);
        assert_eq!(conn.packets_rev, 200);
        assert_eq!(conn.bytes_rev, 150_000);
    }

    #[test]
    fn parse_malformed_line_returns_none() {
        assert!(parse_nf_conntrack_line("").is_none());
        assert!(parse_nf_conntrack_line("short").is_none());
        assert!(parse_nf_conntrack_line("ipv4 2 tcp 6 100 ESTABLISHED").is_none());
        // The CLI layout is one field shorter at the head, so a truncated CLI
        // line must not read as a complete proc line shifted by two.
        assert!(parse_nf_conntrack_line("tcp 6 100 ESTABLISHED").is_none());
    }

    /// The CLI dump omits the leading address family, and the whole
    /// procfs-optional fallback rests on both layouts yielding one connection.
    #[test]
    fn cli_and_proc_layouts_parse_to_the_same_connection() {
        let tuple = "src=192.168.1.1 dst=10.0.0.1 sport=12345 dport=443 \
                     src=10.0.0.1 dst=192.168.1.1 sport=443 dport=12345 \
                     [ASSURED] mark=0 use=2";
        let from_proc =
            parse_nf_conntrack_line(&format!("ipv4     2 tcp      6 431999 ESTABLISHED {tuple}"))
                .unwrap();
        let from_cli =
            parse_nf_conntrack_line(&format!("tcp      6 431999 ESTABLISHED {tuple}")).unwrap();
        assert_eq!(from_proc.src_ip, from_cli.src_ip);
        assert_eq!(from_proc.dst_ip, from_cli.dst_ip);
        assert_eq!(from_proc.src_port, from_cli.src_port);
        assert_eq!(from_proc.dst_port, from_cli.dst_port);
        assert_eq!(from_proc.protocol, from_cli.protocol);
        assert_eq!(from_proc.state, from_cli.state);
    }

    #[test]
    fn cli_layout_parses_udp_without_a_state_field() {
        let line = "udp      17 29 src=10.0.0.1 dst=8.8.8.8 sport=53422 dport=53 \
                    src=8.8.8.8 dst=10.0.0.1 sport=53 dport=53422 mark=0 use=2";
        let conn = parse_nf_conntrack_line(line).unwrap();
        assert_eq!(conn.protocol, 17);
        assert_eq!(conn.src_ip, "10.0.0.1");
        assert_eq!(conn.dst_port, 53);
    }

    #[test]
    fn cli_layout_parses_ipv6_and_counters() {
        let line = "tcp      6 299 ESTABLISHED src=2001:db8::1 dst=2001:db8::2 \
                    sport=443 dport=8080 packets=100 bytes=50000 \
                    src=2001:db8::2 dst=2001:db8::1 sport=8080 dport=443 \
                    packets=200 bytes=150000 [ASSURED] mark=0 use=2";
        let conn = parse_nf_conntrack_line(line).unwrap();
        assert_eq!(conn.src_ip, "2001:db8::1");
        assert_eq!(conn.dst_port, 8080);
        assert_eq!(conn.packets_fwd, 100);
        assert_eq!(conn.bytes_rev, 150_000);
    }

    #[test]
    fn tcp_state_mapping_covers_all_kernel_states() {
        assert_eq!(
            parse_kernel_tcp_state("ESTABLISHED"),
            ConnectionState::Established
        );
        assert_eq!(parse_kernel_tcp_state("SYN_SENT"), ConnectionState::SynSent);
        assert_eq!(parse_kernel_tcp_state("SYN_RECV"), ConnectionState::SynRecv);
        assert_eq!(parse_kernel_tcp_state("FIN_WAIT"), ConnectionState::FinWait);
        assert_eq!(
            parse_kernel_tcp_state("CLOSE_WAIT"),
            ConnectionState::CloseWait
        );
        assert_eq!(
            parse_kernel_tcp_state("TIME_WAIT"),
            ConnectionState::TimeWait
        );
        assert_eq!(parse_kernel_tcp_state("CLOSE"), ConnectionState::TimeWait);
        assert_eq!(
            parse_kernel_tcp_state("LAST_ACK"),
            ConnectionState::TimeWait
        );
        assert_eq!(parse_kernel_tcp_state("NONE"), ConnectionState::New);
        assert_eq!(parse_kernel_tcp_state("BOGUS"), ConnectionState::Invalid);
    }

    #[test]
    fn port_reads_from_injectable_paths() {
        let dir = tempfile::tempdir().unwrap();
        let ct_path = dir.path().join("nf_conntrack");
        let count_path = dir.path().join("nf_conntrack_count");

        std::fs::write(
            &ct_path,
            "ipv4     2 tcp      6 100 ESTABLISHED src=1.2.3.4 dst=5.6.7.8 sport=111 dport=222 src=5.6.7.8 dst=1.2.3.4 sport=222 dport=111 [ASSURED] mark=0 use=2\n\
             ipv4     2 udp      17 30 src=10.0.0.1 dst=10.0.0.2 sport=5000 dport=5001 src=10.0.0.2 dst=10.0.0.1 sport=5001 dport=5000 mark=0 use=2\n",
        )
        .unwrap();
        std::fs::write(&count_path, "2\n").unwrap();

        let port = ProcNetfilterConntrackPort::with_paths(ct_path, count_path);
        let conns = port.get_connections(100).unwrap();
        assert_eq!(conns.len(), 2);
        assert_eq!(conns[0].src_ip, "1.2.3.4");
        assert_eq!(conns[0].protocol, 6);
        assert_eq!(conns[1].protocol, 17);

        let count = port.connection_count().unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn port_respects_limit() {
        use std::fmt::Write as _;

        let dir = tempfile::tempdir().unwrap();
        let ct_path = dir.path().join("nf_conntrack");
        let count_path = dir.path().join("nf_conntrack_count");

        let mut lines = String::new();
        for i in 0..50 {
            let port = 1000 + i;
            writeln!(
                &mut lines,
                "ipv4     2 tcp      6 100 ESTABLISHED src=10.0.0.{i} dst=10.0.0.1 sport={port} dport=80 src=10.0.0.1 dst=10.0.0.{i} sport=80 dport={port} mark=0 use=2"
            )
            .expect("write to String never fails");
        }
        std::fs::write(&ct_path, &lines).unwrap();
        std::fs::write(&count_path, "50\n").unwrap();

        let port = ProcNetfilterConntrackPort::with_paths(ct_path, count_path);
        let conns = port.get_connections(10).unwrap();
        assert_eq!(conns.len(), 10);
    }

    #[test]
    fn missing_proc_file_returns_error() {
        let port = ProcNetfilterConntrackPort::with_paths(
            PathBuf::from("/nonexistent/nf_conntrack"),
            PathBuf::from("/nonexistent/nf_conntrack_count"),
        );
        assert!(port.get_connections(10).is_err());
        assert!(port.connection_count().is_err());
    }
}
