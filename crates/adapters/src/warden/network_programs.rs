//! The eBPF programs on the node's network path, read by the warden or
//! in-process.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use domain::common::error::DomainError;
use domain::network_program::{NetworkHook, NetworkProgram, OwnBpfObjects};
use ebpfsentinel_warden_client::{HeldBpfObjects, ReconnectingClient};
use ports::secondary::network_program_port::NetworkProgramReader;

/// Set to the warden's control socket when the agent runs rootless.
const WARDEN_SOCK_ENV: &str = "EBPFSENTINEL_WARDEN_SOCK";

/// The in-process scan, given the procfs to read.
pub type LocalScan = fn(&Path) -> Result<Vec<ebpfsentinel_warden_client::NetworkProgram>, String>;

/// What a process holds, given the procfs and the pid (`self` for the agent).
pub type HeldBy = fn(&Path, &str) -> HeldBpfObjects;

enum Source {
    /// Enumerating programs by id needs `CAP_SYS_ADMIN`, which no BPF token
    /// grants, so a rootless agent asks the warden.
    Warden(Mutex<ReconnectingClient>),
    /// An agent holding the privilege scans in-process.
    Local { scan: LocalScan, proc_root: PathBuf },
}

/// Lists network programs through the warden when `EBPFSENTINEL_WARDEN_SOCK`
/// is set, in-process otherwise, and reads the agent's own descriptors from
/// its own procfs entry.
pub struct NetworkProgramScanner {
    source: Source,
    held_by: HeldBy,
}

impl NetworkProgramScanner {
    /// The warden when the environment names one, else `scan` over
    /// `proc_root`; `held_by` reads the agent's own descriptors.
    pub fn new(scan: LocalScan, held_by: HeldBy, proc_root: impl Into<PathBuf>) -> Self {
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
        Self { source, held_by }
    }
}

/// The wire entry as the domain reads it.
fn to_domain(program: ebpfsentinel_warden_client::NetworkProgram) -> NetworkProgram {
    NetworkProgram {
        prog_id: program.prog_id,
        prog_type: program.prog_type,
        name: program.name,
        tag: program.tag,
        link_id: program.link_id,
        hook: NetworkHook::from_slug(&program.hook),
        ifindex: program.ifindex,
        interface: program.interface,
        position: program.position,
        cgroup_id: program.cgroup_id,
        detail: program.detail,
        created_by_uid: program.created_by_uid,
        holders: program.holders,
    }
}

impl NetworkProgramReader for NetworkProgramScanner {
    fn list(&self) -> Result<Vec<NetworkProgram>, DomainError> {
        let programs = match &self.source {
            Source::Warden(client) => client
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .network_programs()
                .map_err(|e| {
                    DomainError::EngineError(format!("warden could not list eBPF programs: {e}"))
                })?,
            Source::Local { scan, proc_root } => scan(proc_root).map_err(|e| {
                DomainError::EngineError(format!("eBPF programs could not be listed: {e}"))
            })?,
        };
        Ok(programs.into_iter().map(to_domain).collect())
    }

    fn own(&self) -> OwnBpfObjects {
        // The agent's own entry, whatever procfs the scan reads: under a
        // host mount the agent's pid is not the one it sees itself as.
        let held = (self.held_by)(Path::new("/proc"), "self");
        OwnBpfObjects {
            prog_ids: held.prog_ids.into_iter().collect(),
            link_ids: held.link_ids.into_iter().collect(),
        }
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

    fn program() -> ebpfsentinel_warden_client::NetworkProgram {
        ebpfsentinel_warden_client::NetworkProgram {
            prog_id: 812,
            prog_type: "sched_cls".into(),
            name: "cil_from_netdev".into(),
            tag: "0a1b2c3d4e5f6071".into(),
            link_id: Some(14),
            hook: "tcx_ingress".into(),
            ifindex: Some(2),
            interface: Some("eth0".into()),
            position: Some(0),
            cgroup_id: None,
            detail: None,
            created_by_uid: Some(0),
            holders: vec![1312],
        }
    }

    const ONE: LocalScan = |_| Ok(vec![program()]);

    fn refused(_: &Path) -> Result<Vec<ebpfsentinel_warden_client::NetworkProgram>, String> {
        Err("listing BPF links: Operation not permitted".into())
    }

    fn holds(_: &Path, pid: &str) -> HeldBpfObjects {
        assert_eq!(pid, "self");
        HeldBpfObjects {
            prog_ids: vec![3, 4],
            link_ids: vec![9],
        }
    }

    fn local(scan: LocalScan) -> NetworkProgramScanner {
        NetworkProgramScanner {
            source: Source::Local {
                scan,
                proc_root: PathBuf::from("/proc"),
            },
            held_by: holds,
        }
    }

    #[test]
    fn a_local_reading_maps_each_program_into_the_domain() {
        let scanner = local(ONE);
        assert_eq!(scanner.source(), "local");
        let programs = scanner.list().unwrap_or_default();
        assert_eq!(programs.len(), 1);
        assert_eq!(programs[0].hook, NetworkHook::TcxIngress);
        assert_eq!(programs[0].holders, vec![1312]);
    }

    #[test]
    fn a_refused_enumeration_is_an_error_and_not_an_empty_node() {
        let err = local(refused).list().err().map(|e| e.to_string());
        assert!(err.is_some_and(|e| e.contains("Operation not permitted")));
    }

    #[test]
    fn the_agent_own_objects_come_from_its_own_descriptors() {
        let own = local(ONE).own();
        assert!(own.prog_ids.contains(&3) && own.prog_ids.contains(&4));
        assert!(own.link_ids.contains(&9));
    }

    #[test]
    fn an_unreachable_warden_is_an_error() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let scanner = NetworkProgramScanner {
            source: Source::Warden(Mutex::new(ReconnectingClient::new(
                dir.path().join("absent.sock"),
            ))),
            held_by: holds,
        };
        assert_eq!(scanner.source(), "warden");
        assert!(scanner.list().is_err());
    }
}
