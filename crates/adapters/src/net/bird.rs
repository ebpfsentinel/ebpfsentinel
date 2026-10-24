//! BIRD 2 driver for BGP announcement of the VIPs.
//!
//! The agent writes a complete BIRD configuration, asks the daemon to load
//! it over its control socket, and reads the sessions back with
//! `show protocols`. BIRD runs as a separate process beside the agent; this
//! module never speaks BGP and never parses a BGP message.
//!
//! The control protocol is line based: every reply line starts with a
//! four digit code followed by `-` when more lines follow and a space on
//! the last one, and a line starting with a space continues the previous
//! code. `0003` is a completed reconfiguration, `0019` one with nothing to
//! change, `8xxx` a run-time error and `9xxx` a parse error.

use std::io::{BufRead, BufReader, Write};
use std::net::IpAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use domain::common::error::DomainError;
use domain::loadbalancer::bgp::{BgpConfig, BgpSession};
use ports::secondary::bgp_daemon_port::BgpDaemonPort;

/// Protocol names this agent owns in the daemon's configuration.
const PROTO_PREFIX: &str = "ebpfs_";
const VIPS4: &str = "ebpfs_vips4";
const VIPS6: &str = "ebpfs_vips6";

/// How long one exchange with the daemon may take.
const IO_TIMEOUT: Duration = Duration::from_secs(2);

/// Drives one BIRD daemon through its control socket.
pub struct BirdDaemon {
    socket: PathBuf,
    config_path: PathBuf,
}

impl BirdDaemon {
    #[must_use]
    pub fn new(socket: impl Into<PathBuf>, config_path: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
            config_path: config_path.into(),
        }
    }

    fn exchange(&self, command: &str) -> Result<Vec<(u16, String)>, DomainError> {
        let err = |e: std::io::Error| {
            DomainError::EngineError(format!(
                "bird control socket {}: {e}",
                self.socket.display()
            ))
        };
        let stream = UnixStream::connect(&self.socket).map_err(err)?;
        stream.set_read_timeout(Some(IO_TIMEOUT)).map_err(err)?;
        stream.set_write_timeout(Some(IO_TIMEOUT)).map_err(err)?;
        let mut reader = BufReader::new(stream.try_clone().map_err(err)?);
        // The greeting is one `0001` line.
        read_reply(&mut reader).map_err(err)?;
        let mut writer = stream;
        writer
            .write_all(format!("{command}\n").as_bytes())
            .map_err(err)?;
        read_reply(&mut reader).map_err(err)
    }
}

/// Read one complete reply: every line up to the first whose code is
/// followed by a space.
fn read_reply(reader: &mut impl BufRead) -> std::io::Result<Vec<(u16, String)>> {
    let mut lines = Vec::new();
    let mut code = 0u16;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "daemon closed the control socket mid-reply",
            ));
        }
        let line = line.trim_end_matches(['\n', '\r']);
        if let Some(rest) = line.strip_prefix(' ') {
            lines.push((code, rest.to_string()));
            continue;
        }
        let (head, rest) = line.split_at(line.len().min(5));
        let parsed = head.get(..4).and_then(|c| c.parse::<u16>().ok());
        let Some(c) = parsed else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unexpected control line {line:?}"),
            ));
        };
        code = c;
        lines.push((code, rest.to_string()));
        if head.as_bytes().get(4) != Some(&b'-') {
            return Ok(lines);
        }
    }
}

/// Fail on an error code anywhere in a reply.
fn check(lines: &[(u16, String)]) -> Result<(), DomainError> {
    match lines.iter().find(|(c, _)| *c >= 8000) {
        Some((c, msg)) => Err(DomainError::EngineError(format!(
            "bird refused ({c}): {msg}"
        ))),
        None => Ok(()),
    }
}

/// Render the whole daemon configuration for `config`, exporting `routes`.
#[must_use]
pub fn render_config(config: &BgpConfig, routes: &[IpAddr]) -> String {
    use std::fmt::Write as _;
    let mut out = String::from("# Written by the eBPFsentinel agent; edits are overwritten.\n");
    out.push_str("log stderr all;\n");
    if let Some(id) = config.router_id {
        let _ = writeln!(out, "router id {id};");
    }
    out.push_str("timeformat protocol iso long;\n\nprotocol device {\n}\n");
    for (name, v6) in [(VIPS4, false), (VIPS6, true)] {
        let _ = writeln!(
            out,
            "\nprotocol static {name} {{\n  {} {{ import all; export none; }};",
            if v6 { "ipv6" } else { "ipv4" }
        );
        for r in routes.iter().filter(|r| r.is_ipv6() == v6) {
            let len = if v6 { 128 } else { 32 };
            let _ = writeln!(out, "  route {r}/{len} blackhole;");
        }
        out.push_str("}\n");
    }
    for p in &config.peers {
        let (family, source) = if p.address.is_ipv6() {
            ("ipv6", VIPS6)
        } else {
            ("ipv4", VIPS4)
        };
        let _ = writeln!(
            out,
            "\nprotocol bgp {PROTO_PREFIX}{} {{\n  local as {};\n  neighbor {} port {} as {};\n  hold time {};",
            p.name, config.local_asn, p.address, p.port, p.asn, p.hold_time
        );
        if let Some(pw) = &p.password {
            let _ = writeln!(out, "  password \"{pw}\";");
        }
        let _ = writeln!(
            out,
            "  {family} {{ import none; export where proto = \"{source}\"; }};\n}}"
        );
    }
    out
}

/// Parse the rows of a `show protocols` reply into the sessions of the
/// BGP protocols this agent owns.
#[must_use]
pub fn parse_protocols(lines: &[(u16, String)]) -> Vec<BgpSession> {
    let mut sessions = Vec::new();
    for (code, row) in lines {
        if *code != 1002 {
            continue;
        }
        let mut cols = row.split_whitespace();
        let (Some(name), Some(proto), Some(_table), Some(state)) =
            (cols.next(), cols.next(), cols.next(), cols.next())
        else {
            continue;
        };
        let Some(peer) = name.strip_prefix(PROTO_PREFIX) else {
            continue;
        };
        if proto != "BGP" {
            continue;
        }
        let since = match (cols.next(), cols.next()) {
            (Some(d), Some(t)) => format!("{d} {t}"),
            (Some(d), None) => d.to_string(),
            _ => String::new(),
        };
        let bgp_state = cols.next().unwrap_or_default();
        let rest = cols.collect::<Vec<_>>().join(" ");
        sessions.push(BgpSession {
            peer: peer.to_string(),
            state: if state == "down" || bgp_state.is_empty() {
                "Down".to_string()
            } else {
                bgp_state.to_string()
            },
            since,
            last_error: (!rest.is_empty()).then_some(rest),
        });
    }
    sessions
}

/// Replace `path` with `contents` in one rename, readable by its owner only
/// since it may carry a session password.
fn write_atomic(path: &Path, contents: &str) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(contents.as_bytes())?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)
}

impl BgpDaemonPort for BirdDaemon {
    fn apply(&self, config: &BgpConfig, routes: &[IpAddr]) -> Result<(), DomainError> {
        write_atomic(&self.config_path, &render_config(config, routes)).map_err(|e| {
            DomainError::EngineError(format!("bird config {}: {e}", self.config_path.display()))
        })?;
        let reply = self.exchange(&format!("configure \"{}\"", self.config_path.display()))?;
        check(&reply)
    }

    fn sessions(&self) -> Result<Vec<BgpSession>, DomainError> {
        let reply = self.exchange("show protocols")?;
        check(&reply)?;
        Ok(parse_protocols(&reply))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use domain::loadbalancer::bgp::BgpPeer;
    use std::os::unix::net::UnixListener;

    fn cfg() -> BgpConfig {
        BgpConfig {
            enabled: true,
            local_asn: 64513,
            router_id: Some("10.0.0.10".parse().unwrap()),
            peers: vec![
                BgpPeer {
                    name: "tor1".into(),
                    address: "10.0.0.1".parse().unwrap(),
                    asn: 64512,
                    port: 179,
                    hold_time: 90,
                    password: Some("s3cret".into()),
                },
                BgpPeer {
                    name: "tor6".into(),
                    address: "fd00::1".parse().unwrap(),
                    asn: 64512,
                    port: 1179,
                    hold_time: 30,
                    password: None,
                },
            ],
        }
    }

    #[test]
    fn renders_routes_only_when_given() {
        let routes: Vec<IpAddr> = vec![
            "192.0.2.10".parse().unwrap(),
            "2001:db8::10".parse().unwrap(),
        ];
        let text = render_config(&cfg(), &routes);
        assert!(text.contains("router id 10.0.0.10;"));
        assert!(text.contains("route 192.0.2.10/32 blackhole;"));
        assert!(text.contains("route 2001:db8::10/128 blackhole;"));
        assert!(text.contains("protocol bgp ebpfs_tor1 {"));
        assert!(text.contains("neighbor 10.0.0.1 port 179 as 64512;"));
        assert!(text.contains("password \"s3cret\";"));
        assert!(text.contains("ipv4 { import none; export where proto = \"ebpfs_vips4\"; };"));
        assert!(text.contains("neighbor fd00::1 port 1179 as 64512;"));
        assert!(text.contains("ipv6 { import none; export where proto = \"ebpfs_vips6\"; };"));

        let silent = render_config(&cfg(), &[]);
        assert!(!silent.contains("blackhole"));
        assert!(silent.contains("protocol bgp ebpfs_tor1 {"));
    }

    #[test]
    fn parses_show_protocols() {
        let lines = vec![
            (2002, "Name       Proto      Table      State  Since         Info".to_string()),
            (1002, "device1    Device     ---        up     2026-10-24 10:00:00".to_string()),
            (1002, "ebpfs_vips4 Static    master4    up     2026-10-24 10:00:00".to_string()),
            (1002, "ebpfs_tor1 BGP        ---        up     2026-10-24 10:00:05  Established".to_string()),
            (1002, "ebpfs_tor6 BGP        ---        start  2026-10-24 10:00:00  Active        Socket: Connection refused".to_string()),
            (1002, "other      BGP        ---        up     2026-10-24 10:00:00  Established".to_string()),
            (0, String::new()),
        ];
        let s = parse_protocols(&lines);
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].peer, "tor1");
        assert!(s[0].is_established());
        assert_eq!(s[0].since, "2026-10-24 10:00:05");
        assert_eq!(s[0].last_error, None);
        assert_eq!(s[1].state, "Active");
        assert_eq!(
            s[1].last_error.as_deref(),
            Some("Socket: Connection refused")
        );
    }

    #[test]
    fn reads_multi_line_replies_and_errors() {
        let raw = b"1002-a BGP --- up 2026-10-24 10:00:00 Established\n b BGP --- down 2026-10-24 10:00:00\n0000 \n";
        let lines = read_reply(&mut &raw[..]).unwrap();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[1].0, 1002);
        assert!(check(&lines).is_ok());
        let bad = read_reply(&mut &b"9001 syntax error, line 3\n"[..]).unwrap();
        assert!(check(&bad).is_err());
    }

    #[test]
    fn applies_through_the_control_socket() {
        let dir = std::env::temp_dir().join(format!("bird-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("bird.ctl");
        let conf = dir.join("ebpfsentinel.conf");
        let _ = std::fs::remove_file(&sock);
        let listener = UnixListener::bind(&sock).unwrap();
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.write_all(b"0001 BIRD 2.15 ready.\n").unwrap();
            let mut r = BufReader::new(s.try_clone().unwrap());
            let mut cmd = String::new();
            r.read_line(&mut cmd).unwrap();
            s.write_all(b"0002-Reading configuration\n0003 Reconfigured\n")
                .unwrap();
            cmd
        });
        let bird = BirdDaemon::new(&sock, &conf);
        bird.apply(&cfg(), &["192.0.2.10".parse().unwrap()])
            .unwrap();
        let cmd = server.join().unwrap();
        assert_eq!(cmd.trim(), format!("configure \"{}\"", conf.display()));
        let written = std::fs::read_to_string(&conf).unwrap();
        assert!(written.contains("route 192.0.2.10/32 blackhole;"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
