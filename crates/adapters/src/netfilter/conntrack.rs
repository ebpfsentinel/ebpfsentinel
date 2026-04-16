//! Kernel netfilter conntrack reader via `/proc/net/nf_conntrack`.
//!
//! Implements [`ConnTrackMapPort`] by reading the kernel's authoritative
//! conntrack table rather than the BPF shadow maps. Zero new dependencies
//! beyond `std` — the proc filesystem is stable since Linux 2.6 and the
//! format has not changed.
//!
//! Reading requires `CAP_NET_ADMIN` (already held by the agent for BPF).
//! Flushing delegates to the `conntrack -F` CLI tool; kernel sysctl writes
//! update timeout parameters directly.

use std::io::BufRead;
use std::path::{Path, PathBuf};

use domain::common::error::DomainError;
use domain::conntrack::entity::{ConnTrackSettings, Connection, ConnectionState};
use ports::secondary::conntrack_map_port::ConnTrackMapPort;
use tracing::{debug, warn};

/// Default path to the kernel conntrack table.
const DEFAULT_NF_CONNTRACK_PATH: &str = "/proc/net/nf_conntrack";
/// Default path to the kernel conntrack entry count.
const DEFAULT_NF_CONNTRACK_COUNT_PATH: &str = "/proc/sys/net/netfilter/nf_conntrack_count";

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
}

impl ProcNetfilterConntrackPort {
    /// Build a port reading from the default `/proc` paths.
    #[must_use]
    pub fn new() -> Self {
        Self {
            nf_conntrack_path: PathBuf::from(DEFAULT_NF_CONNTRACK_PATH),
            nf_conntrack_count_path: PathBuf::from(DEFAULT_NF_CONNTRACK_COUNT_PATH),
        }
    }

    /// Build a port with injectable paths for unit testing.
    #[must_use]
    pub fn with_paths(nf_conntrack: PathBuf, nf_conntrack_count: PathBuf) -> Self {
        Self {
            nf_conntrack_path: nf_conntrack,
            nf_conntrack_count_path: nf_conntrack_count,
        }
    }
}

impl Default for ProcNetfilterConntrackPort {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnTrackMapPort for ProcNetfilterConntrackPort {
    fn get_connections(&self, limit: usize) -> Result<Vec<Connection>, DomainError> {
        let file = std::fs::File::open(&self.nf_conntrack_path).map_err(|e| {
            DomainError::EngineError(format!(
                "failed to open {}: {e}",
                self.nf_conntrack_path.display()
            ))
        })?;
        let reader = std::io::BufReader::new(file);
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
fn parse_nf_conntrack_line(line: &str) -> Option<Connection> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    // Minimum: family + pad + proto_name + proto_num + timeout + tuple fields
    if tokens.len() < 10 {
        return None;
    }

    let protocol = tokens[3].parse::<u8>().ok()?;
    // Timeout in seconds (tokens[4])
    let _timeout_secs: u64 = tokens[4].parse().unwrap_or(0);

    // For TCP (proto 6), token[5] is the state string; tuple starts at [6].
    // For other protocols, tuple starts at [5].
    let (state, tuple_start) = if protocol == 6 {
        // TCP state
        let s = parse_kernel_tcp_state(tokens.get(5).copied().unwrap_or(""));
        (s, 6)
    } else {
        (ConnectionState::Established, 5)
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

/// Check whether `/proc/net/nf_conntrack` is readable. Used at startup
/// to decide whether to inject the netfilter port.
pub fn is_proc_conntrack_available() -> bool {
    Path::new(DEFAULT_NF_CONNTRACK_PATH).exists()
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let dir = tempfile::tempdir().unwrap();
        let ct_path = dir.path().join("nf_conntrack");
        let count_path = dir.path().join("nf_conntrack_count");

        let mut lines = String::new();
        for i in 0..50 {
            lines.push_str(&format!(
                "ipv4     2 tcp      6 100 ESTABLISHED src=10.0.0.{i} dst=10.0.0.1 sport={} dport=80 src=10.0.0.1 dst=10.0.0.{i} sport=80 dport={} mark=0 use=2\n",
                1000 + i, 1000 + i
            ));
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
