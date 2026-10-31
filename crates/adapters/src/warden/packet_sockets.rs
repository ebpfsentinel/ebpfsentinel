//! The packet sockets open on the node, read by the warden or in-process.

use std::path::PathBuf;
use std::sync::Mutex;

use domain::common::error::DomainError;
use domain::raw_socket::{FilterState, RawSocket, RawSocketKind};
use ebpfsentinel_warden_client::{PacketSocket, ReconnectingClient};
use ports::secondary::raw_socket_port::RawSocketReader;

/// Set to the warden's control socket when the agent runs rootless.
const WARDEN_SOCK_ENV: &str = "EBPFSENTINEL_WARDEN_SOCK";

/// The in-process scan, given the procfs to read.
pub type LocalScan = fn(&std::path::Path) -> Vec<PacketSocket>;

enum Source {
    /// A rootless agent reaches no other namespace and reads no other
    /// process's descriptors, so the warden scans for it.
    Warden(Mutex<ReconnectingClient>),
    /// An agent holding the privilege scans in-process.
    Local { scan: LocalScan, proc_root: PathBuf },
}

/// Lists packet sockets through the warden when `EBPFSENTINEL_WARDEN_SOCK` is
/// set, in-process otherwise.
pub struct PacketSocketReader {
    source: Source,
}

impl PacketSocketReader {
    /// The warden when the environment names one, else `scan` over
    /// `proc_root`.
    pub fn new(scan: LocalScan, proc_root: impl Into<PathBuf>) -> Self {
        let warden = std::env::var_os(WARDEN_SOCK_ENV)
            .map(PathBuf::from)
            .filter(|p| !p.as_os_str().is_empty());
        let source = match warden {
            Some(sock) => Source::Warden(Mutex::new(ReconnectingClient::new(sock))),
            None => Source::Local {
                scan,
                proc_root: proc_root.into(),
            },
        };
        Self { source }
    }
}

/// The wire entry as the domain reads it.
fn to_domain(socket: PacketSocket) -> RawSocket {
    RawSocket {
        inode: socket.inode,
        kind: RawSocketKind::from_type(socket.socket_type),
        protocol: socket.protocol,
        ifindex: socket.ifindex,
        interface: socket.interface,
        uid: socket.uid,
        netns: socket.netns,
        host_netns: socket.host_netns,
        pid: socket.pid,
        filter: FilterState::from_count(socket.filter_instructions),
    }
}

impl RawSocketReader for PacketSocketReader {
    fn list(&self) -> Result<Vec<RawSocket>, DomainError> {
        let sockets = match &self.source {
            Source::Warden(client) => client
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .packet_sockets()
                .map_err(|e| {
                    DomainError::EngineError(format!("warden could not list packet sockets: {e}"))
                })?,
            Source::Local { scan, proc_root } => scan(proc_root),
        };
        Ok(sockets.into_iter().map(to_domain).collect())
    }

    fn source(&self) -> &'static str {
        match self.source {
            Source::Warden(_) => "warden",
            Source::Local { .. } => "local",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(_: &std::path::Path) -> Vec<PacketSocket> {
        vec![PacketSocket {
            inode: 31_337,
            socket_type: 3,
            protocol: 0x0003,
            ifindex: 0,
            interface: None,
            uid: 0,
            netns: 4_026_531_840,
            host_netns: true,
            pid: Some(812),
            filter_instructions: Some(30),
        }]
    }

    #[test]
    fn a_local_reading_maps_each_socket_into_the_domain() {
        let reader = PacketSocketReader {
            source: Source::Local {
                scan: one,
                proc_root: PathBuf::from("/proc"),
            },
        };
        assert_eq!(reader.source(), "local");
        let sockets = reader.list().unwrap_or_default();
        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].kind, RawSocketKind::Raw);
        assert_eq!(sockets[0].filter, FilterState::Classic { instructions: 30 });
        assert_eq!(sockets[0].pid, Some(812));
    }

    #[test]
    fn an_unreachable_warden_is_an_error_and_not_an_empty_node() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let reader = PacketSocketReader {
            source: Source::Warden(Mutex::new(ReconnectingClient::new(
                dir.path().join("absent.sock"),
            ))),
        };
        assert_eq!(reader.source(), "warden");
        assert!(reader.list().is_err());
    }
}
