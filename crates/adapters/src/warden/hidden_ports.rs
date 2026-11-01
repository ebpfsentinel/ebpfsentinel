use std::path::PathBuf;
use std::sync::Mutex;

use domain::common::error::DomainError;
use domain::hidden::{
    ListedPort, Listing, NamespacePorts, PortFamily, PortProbe, PortReading, Transport,
};
use ebpfsentinel_warden_client::{
    BindProbe, ListedPort as WireListedPort, NamespacePortReading, ReconnectingClient,
};
use ports::secondary::hidden_port_port::HiddenPortReader;

/// Set to the warden's control socket when the agent runs rootless.
const WARDEN_SOCK_ENV: &str = "EBPFSENTINEL_WARDEN_SOCK";

/// The in-process reading, given the procfs to read and the ports to probe.
pub type LocalScan = fn(&std::path::Path, &[u16]) -> Vec<NamespacePortReading>;

enum Source {
    /// A rootless agent enters no other namespace, so the warden reads for
    /// it.
    Warden(Mutex<ReconnectingClient>),
    /// An agent holding the privilege reads in-process.
    Local { scan: LocalScan, proc_root: PathBuf },
}

/// Reads the listings and probes through the warden when
/// `EBPFSENTINEL_WARDEN_SOCK` is set, in-process otherwise.
pub struct WardenHiddenPortReader {
    source: Source,
}

impl WardenHiddenPortReader {
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

fn transport(udp: bool) -> Transport {
    if udp { Transport::Udp } else { Transport::Tcp }
}

fn listed(entry: WireListedPort) -> ListedPort {
    ListedPort {
        transport: transport(entry.udp),
        port: entry.port,
        state: entry.state,
        listing: if entry.sock_diag {
            Listing::SockDiag
        } else {
            Listing::Proc
        },
    }
}

fn probe(entry: BindProbe) -> PortProbe {
    PortProbe {
        transport: transport(entry.udp),
        family: if entry.ipv6 {
            PortFamily::V6
        } else {
            PortFamily::V4
        },
        port: entry.port,
    }
}

/// The wire reading as the domain reads it.
fn to_domain(reading: NamespacePortReading) -> NamespacePorts {
    NamespacePorts {
        netns: reading.netns,
        host_netns: reading.host_netns,
        reading: match reading.error {
            Some(reason) => Err(reason),
            None => Ok(PortReading {
                first_listing: reading.first_listing.iter().copied().map(listed).collect(),
                second_listing: reading.second_listing.iter().copied().map(listed).collect(),
                probed: reading.probed,
                unprobed: reading.unprobed,
                refused_first: reading.refused_first.iter().copied().map(probe).collect(),
                refused_second: reading.refused_second.iter().copied().map(probe).collect(),
            }),
        },
    }
}

impl HiddenPortReader for WardenHiddenPortReader {
    fn read(&self, ports: &[u16]) -> Result<Vec<NamespacePorts>, DomainError> {
        let readings = match &self.source {
            Source::Warden(client) => client
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .hidden_ports(ports)
                .map_err(|e| {
                    DomainError::EngineError(format!(
                        "warden could not read the socket listings: {e}"
                    ))
                })?,
            Source::Local { scan, proc_root } => scan(proc_root, ports),
        };
        Ok(readings.into_iter().map(to_domain).collect())
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

    fn two(_: &std::path::Path, ports: &[u16]) -> Vec<NamespacePortReading> {
        let refused = BindProbe {
            udp: true,
            ipv6: true,
            port: ports[0],
        };
        vec![
            NamespacePortReading {
                netns: 4_026_531_840,
                host_netns: true,
                error: None,
                first_listing: vec![WireListedPort {
                    udp: false,
                    port: 22,
                    state: 10,
                    sock_diag: true,
                }],
                second_listing: Vec::new(),
                probed: 4,
                unprobed: 1,
                refused_first: vec![refused],
                refused_second: vec![refused],
            },
            NamespacePortReading {
                netns: 4_026_532_999,
                host_netns: false,
                error: Some("setns refused".into()),
                first_listing: Vec::new(),
                second_listing: Vec::new(),
                probed: 0,
                unprobed: 0,
                refused_first: Vec::new(),
                refused_second: Vec::new(),
            },
        ]
    }

    #[test]
    fn a_local_reading_maps_each_namespace_into_the_domain() {
        let reader = WardenHiddenPortReader {
            source: Source::Local {
                scan: two,
                proc_root: PathBuf::from("/proc"),
            },
        };
        assert_eq!(reader.source(), "local");
        let namespaces = reader.read(&[5353]).unwrap_or_default();
        assert_eq!(namespaces.len(), 2);
        let Ok(reading) = &namespaces[0].reading else {
            panic!("the host namespace was read");
        };
        assert_eq!(reading.first_listing[0].listing, Listing::SockDiag);
        assert_eq!(
            reading.refused_second[0],
            PortProbe {
                transport: Transport::Udp,
                family: PortFamily::V6,
                port: 5353,
            }
        );
        assert_eq!(namespaces[1].reading, Err("setns refused".to_string()));
    }

    #[test]
    fn an_unreachable_warden_is_an_error_and_not_a_clean_node() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let reader = WardenHiddenPortReader {
            source: Source::Warden(Mutex::new(ReconnectingClient::new(
                dir.path().join("absent.sock"),
            ))),
        };
        assert_eq!(reader.source(), "warden");
        assert!(reader.read(&[22]).is_err());
    }
}
