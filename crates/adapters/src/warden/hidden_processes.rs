use std::path::PathBuf;
use std::sync::Mutex;

use domain::common::error::DomainError;
use domain::hidden::{PidObservation, ProcessReading};
use ebpfsentinel_warden_client::{
    HiddenProcessReading, PidObservation as WirePidObservation, ReconnectingClient,
};
use ports::secondary::hidden_process_port::HiddenProcessReader;

/// Set to the warden's control socket when the agent runs rootless.
const WARDEN_SOCK_ENV: &str = "EBPFSENTINEL_WARDEN_SOCK";

/// The in-process reading, given the procfs to read and the pace.
pub type LocalSweep = fn(&std::path::Path, u32) -> HiddenProcessReading;

enum Source {
    /// A rootless agent sits in its own pid namespace and signals nothing
    /// outside it, so the warden sweeps for it.
    Warden(Mutex<ReconnectingClient>),
    /// An agent in the host's pid namespace sweeps in-process.
    Local {
        sweep: LocalSweep,
        proc_root: PathBuf,
    },
}

/// Sweeps through the warden when `EBPFSENTINEL_WARDEN_SOCK` is set,
/// in-process otherwise.
pub struct WardenHiddenProcessReader {
    source: Source,
}

impl WardenHiddenProcessReader {
    /// The warden when the environment names one, else `sweep` over
    /// `proc_root`.
    pub fn new(sweep: LocalSweep, proc_root: impl Into<PathBuf>) -> Self {
        let warden = std::env::var_os(WARDEN_SOCK_ENV)
            .map(PathBuf::from)
            .filter(|p| !p.as_os_str().is_empty());
        let source = match warden {
            Some(sock) => Source::Warden(Mutex::new(ReconnectingClient::new(sock))),
            None => Source::Local {
                sweep,
                proc_root: proc_root.into(),
            },
        };
        Self { source }
    }
}

fn observation(entry: WirePidObservation) -> PidObservation {
    PidObservation {
        pid: entry.pid,
        tgid: entry.tgid,
        start_time: entry.start_time,
        state: entry.state,
        comm: entry.comm,
    }
}

/// The wire reading as the domain reads it, or the reason it was not taken.
fn to_domain(reading: HiddenProcessReading) -> Result<ProcessReading, DomainError> {
    if let Some(reason) = reading.error {
        return Err(DomainError::EngineError(format!(
            "the hidden process sweep was not taken: {reason}"
        )));
    }
    Ok(ProcessReading {
        pid_space: reading.pid_space,
        probed: reading.probed,
        listed: reading.listed,
        threads: reading.threads,
        first: reading.first.into_iter().map(observation).collect(),
        relisted: reading.relisted.into_iter().collect(),
        second: reading.second.into_iter().map(observation).collect(),
    })
}

impl HiddenProcessReader for WardenHiddenProcessReader {
    fn read(&self, rate: u32) -> Result<ProcessReading, DomainError> {
        let reading = match &self.source {
            Source::Warden(client) => client
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .hidden_processes(rate)
                .map_err(|e| {
                    DomainError::EngineError(format!("warden could not sweep the pid space: {e}"))
                })?,
            Source::Local { sweep, proc_root } => sweep(proc_root, rate),
        };
        to_domain(reading)
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

    fn one(_: &std::path::Path, rate: u32) -> HiddenProcessReading {
        HiddenProcessReading {
            error: None,
            pid_space: 32_768,
            probed: rate,
            listed: 120,
            threads: 300,
            first: vec![WirePidObservation {
                pid: 4242,
                tgid: Some(4242),
                start_time: Some(77),
                state: Some('S'),
                comm: Some("implant".into()),
            }],
            relisted: vec![4242],
            second: Vec::new(),
        }
    }

    fn refused(_: &std::path::Path, _: u32) -> HiddenProcessReading {
        HiddenProcessReading {
            error: Some("/proc lists another pid namespace".into()),
            ..HiddenProcessReading::default()
        }
    }

    #[test]
    fn a_local_reading_maps_into_the_domain() {
        let reader = WardenHiddenProcessReader {
            source: Source::Local {
                sweep: one,
                proc_root: PathBuf::from("/proc"),
            },
        };
        assert_eq!(reader.source(), "local");
        let Ok(reading) = reader.read(32_767) else {
            panic!("the sweep was taken");
        };
        assert_eq!(reading.probed, 32_767);
        assert_eq!(reading.first[0].comm.as_deref(), Some("implant"));
        assert!(reading.relisted.contains(&4242));
    }

    #[test]
    fn a_sweep_not_taken_is_an_error_and_not_a_clean_node() {
        let reader = WardenHiddenProcessReader {
            source: Source::Local {
                sweep: refused,
                proc_root: PathBuf::from("/proc"),
            },
        };
        assert!(reader.read(10_000).is_err());
        let warden = WardenHiddenProcessReader {
            source: Source::Warden(Mutex::new(ReconnectingClient::new(
                "/nonexistent/warden.sock",
            ))),
        };
        assert_eq!(warden.source(), "warden");
        assert!(warden.read(10_000).is_err());
    }
}
