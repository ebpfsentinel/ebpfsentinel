//! The keep-alive the service manager reads, and what it is read from.
//!
//! `Restart=on-failure` restarts an agent that exits. It does nothing for an
//! agent that is still running and no longer working: a reader task wedged in a
//! record handler, a runtime whose worker never comes back. The process is
//! alive, the socket still accepts, and the datapath has stopped being drained.
//!
//! So the agent reports its own liveness. systemd's `WatchdogSec` asks for a
//! ping every half interval and kills the process when one does not arrive, and
//! the ping is sent only while the datapath is still being drained. The signal
//! is the ring-buffer pass: a reader makes one every 10 ms whether or not
//! traffic arrived, so a minute of silence is six thousand missed ticks rather
//! than a quiet network.
//!
//! The readiness probe reads the same number
//! ([`adapters::ebpf::datapath_idle_for`]), which is the point: a stall that
//! takes the agent out of the Service's backend list in Kubernetes is the same
//! stall that stops the ping under systemd, rather than one of them noticing
//! and the other not.
//!
//! Nothing here is required. With no `NOTIFY_SOCKET` in the environment, which
//! is every deployment but a systemd unit carrying `WatchdogSec`, the watchdog
//! is not started at all.

use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::time::Duration;

use infrastructure::constants::DATAPATH_STALL_AFTER;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

/// The service manager's notification socket, plus the interval it expects.
pub struct Watchdog {
    socket: UnixDatagram,
    addr: SocketAddr,
    /// Half of `WatchdogSec`, so a single late ping is not fatal.
    ping_interval: Duration,
    /// How long the datapath may be idle before the ping is withheld.
    stall_after: Duration,
}

impl Watchdog {
    /// Build the watchdog from the environment the service manager set, or
    /// `None` when there is no watchdog to feed.
    ///
    /// `WATCHDOG_PID` is honoured: systemd sets it to the process it expects
    /// the pings from, and a child that inherited the environment must not be
    /// the one answering for its parent.
    #[must_use]
    pub fn from_env() -> Option<Self> {
        let socket_path = std::env::var_os("NOTIFY_SOCKET")?;
        let usec: u64 = std::env::var("WATCHDOG_USEC").ok()?.parse().ok()?;
        if usec == 0 {
            return None;
        }
        if let Ok(pid) = std::env::var("WATCHDOG_PID")
            && pid.parse::<u32>().ok() != Some(std::process::id())
        {
            debug!(
                expected = %pid,
                "the watchdog is addressed to another process, not feeding it"
            );
            return None;
        }

        let addr = notify_addr(socket_path.as_os_str())?;
        let socket = UnixDatagram::unbound()
            .inspect_err(|e| warn!(error = %e, "no socket for the service watchdog"))
            .ok()?;

        // Half the interval, and at least a second: systemd's own
        // recommendation, so one scheduling delay never costs a restart.
        let ping_interval = Duration::from_micros(usec / 2).max(Duration::from_secs(1));
        info!(
            watchdog_secs = usec / 1_000_000,
            ping_secs = ping_interval.as_secs(),
            stall_secs = DATAPATH_STALL_AFTER.as_secs(),
            "feeding the service watchdog from the datapath"
        );
        Some(Self {
            socket,
            addr,
            ping_interval,
            stall_after: DATAPATH_STALL_AFTER,
        })
    }

    /// Tell the service manager the agent is still working.
    fn ping(&self) {
        if let Err(e) = self.socket.send_to_addr(b"WATCHDOG=1", &self.addr) {
            warn!(error = %e, "the watchdog ping could not be sent");
        }
    }

    /// Feed the watchdog for as long as the datapath is being drained.
    ///
    /// Withholding is not an error path that logs and carries on: it is the
    /// whole mechanism. The process keeps running until the service manager
    /// kills it, which is what makes the restart ordered rather than a crash.
    pub async fn run(self, cancel: CancellationToken) {
        let mut tick = tokio::time::interval(self.ping_interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut withholding = false;

        loop {
            tokio::select! {
                () = cancel.cancelled() => {
                    debug!("watchdog stopped with the agent");
                    break;
                }
                _ = tick.tick() => {
                    match withhold_reason(adapters::ebpf::datapath_idle_for(), self.stall_after) {
                        None => {
                            if withholding {
                                info!("the datapath is being drained again, feeding the watchdog");
                                withholding = false;
                            }
                            self.ping();
                        }
                        Some(idle) => {
                            if withholding {
                                debug!(idle_secs = idle.as_secs(), "still withholding the ping");
                            } else {
                                error!(
                                    idle_secs = idle.as_secs(),
                                    stall_secs = self.stall_after.as_secs(),
                                    "no ring-buffer pass for longer than the stall bound, \
                                     withholding the watchdog ping so the service manager \
                                     restarts this agent"
                                );
                                withholding = true;
                            }
                        }
                    }
                }
            }
        }
    }
}

/// The address `NOTIFY_SOCKET` names: a path, or an abstract name when it
/// starts with `@`, which is what systemd uses by default.
fn notify_addr(value: &std::ffi::OsStr) -> Option<SocketAddr> {
    use std::os::unix::ffi::OsStrExt;
    let bytes = value.as_bytes();
    if bytes.first() == Some(&b'@') {
        SocketAddr::from_abstract_name(&bytes[1..])
    } else {
        SocketAddr::from_pathname(std::path::Path::new(value))
    }
    .inspect_err(|e| warn!(error = %e, "NOTIFY_SOCKET is not an address, not feeding the watchdog"))
    .ok()
}

/// Whether to withhold the ping, and for how long the datapath has been idle.
///
/// `None` from the pulse means no reader has ever made a pass, which is not a
/// stall: a host whose programs the kernel refused, or one in the window before
/// the first reader is spawned, has nothing to be stalled about and must not be
/// restarted for it. Only a stamp that existed and went stale is a wedged
/// agent.
fn withhold_reason(idle: Option<Duration>, stall_after: Duration) -> Option<Duration> {
    idle.filter(|idle| *idle >= stall_after)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_draining_datapath_is_fed() {
        assert_eq!(
            withhold_reason(Some(Duration::from_millis(12)), Duration::from_secs(60)),
            None
        );
    }

    #[test]
    fn a_stalled_datapath_withholds_the_ping() {
        assert_eq!(
            withhold_reason(Some(Duration::from_secs(61)), Duration::from_secs(60)),
            Some(Duration::from_secs(61)),
            "a reader that stopped passing is what the watchdog exists for"
        );
    }

    #[test]
    fn a_datapath_that_never_started_is_not_a_stall() {
        // The kernel refused every program, or no reader is spawned yet. The
        // agent is useless and says so through readiness; restarting it in a
        // loop would fix nothing.
        assert_eq!(withhold_reason(None, Duration::from_secs(60)), None);
    }

    #[test]
    fn the_bound_is_inclusive() {
        assert!(withhold_reason(Some(Duration::from_secs(60)), Duration::from_secs(60)).is_some());
        assert!(
            withhold_reason(Some(Duration::from_secs(59)), Duration::from_secs(60)).is_none(),
            "a tick inside the bound is not yet a stall"
        );
    }

    #[test]
    fn an_abstract_socket_name_is_read_as_one() {
        let addr = notify_addr(std::ffi::OsStr::new("@/org/freedesktop/systemd1/notify"))
            .expect("an abstract address");
        assert!(addr.is_unnamed() || addr.as_abstract_name().is_some());
        assert_eq!(
            addr.as_abstract_name(),
            Some(&b"/org/freedesktop/systemd1/notify"[..]),
            "the leading @ is the marker, not part of the name"
        );
    }

    #[test]
    fn a_path_socket_is_read_as_a_path() {
        let addr = notify_addr(std::ffi::OsStr::new("/run/systemd/notify")).expect("a path");
        assert_eq!(
            addr.as_pathname(),
            Some(std::path::Path::new("/run/systemd/notify"))
        );
        assert!(addr.as_abstract_name().is_none());
    }

    #[test]
    fn a_ping_reaches_the_socket_it_was_told_about() {
        let dir = tempfile::tempdir().expect("a directory");
        let path = dir.path().join("notify");
        let listener = UnixDatagram::bind(&path).expect("the manager's end");
        let watchdog = Watchdog {
            socket: UnixDatagram::unbound().expect("the agent's end"),
            addr: SocketAddr::from_pathname(&path).expect("an address"),
            ping_interval: Duration::from_secs(1),
            stall_after: Duration::from_secs(60),
        };

        watchdog.ping();

        let mut buf = [0u8; 32];
        let read = listener.recv(&mut buf).expect("the ping");
        assert_eq!(&buf[..read], b"WATCHDOG=1");
    }

    #[test]
    fn no_notify_socket_means_no_watchdog() {
        // Every deployment but a systemd unit carrying WatchdogSec: nothing to
        // feed, so nothing is started. Read rather than set, because the
        // environment is process-wide and tests share it.
        if std::env::var_os("NOTIFY_SOCKET").is_none() {
            assert!(Watchdog::from_env().is_none());
        }
    }
}
