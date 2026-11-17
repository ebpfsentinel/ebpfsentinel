//! Taking the agent's hooks off the node.
//!
//! The agent's XDP, TC and cgroup links are pinned on the host bpffs so the
//! datapath keeps enforcing after the process stops, crashes or is killed.
//! Removing those pins is the one way to take them off, and this is the
//! command that does it: through the warden where one holds them, directly
//! otherwise. The map pins go with them.
//!
//! A running agent still holds its own descriptors to the links, so they stay
//! attached until it stops; once it has, nothing is left in the kernel.

use std::path::PathBuf;

use adapters::ebpf::{DEFAULT_BPF_PIN_PATH, EbpfLoader};
use anyhow::{Context, Result};
use ebpfsentinel_warden::link_pins;
use ebpfsentinel_warden_client::WardenClient;

use crate::startup::DLP_PIN_PATH;

/// What `uninstall` removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uninstalled {
    /// How the link pins were removed.
    pub through: Route,
    /// The link pins removed, where the route can count them.
    pub links: Option<usize>,
}

/// Who removed the link pins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// The warden at this socket, which holds them for a rootless agent.
    Warden(PathBuf),
    /// This process, in this directory.
    Direct(PathBuf),
}

/// Remove every link pin and map pin the agent left on this node.
///
/// `warden_sock` names the warden holding the pins; without one they are
/// removed from the host bpffs directly, which needs the privileges to unlink
/// there.
pub fn run(warden_sock: Option<PathBuf>) -> Result<Uninstalled> {
    let outcome = if let Some(sock) = warden_sock {
        let mut client = WardenClient::connect(&sock)
            .with_context(|| format!("connecting to the warden at {}", sock.display()))?;
        client
            .unpin_links(&[])
            .context("the warden refused to remove the link pins")?;
        Uninstalled {
            through: Route::Warden(sock),
            links: None,
        }
    } else {
        let dir = link_pins::pin_dir();
        let removed = link_pins::unpin(&dir, &[]).map_err(anyhow::Error::msg)?;
        // The directory goes too when it is empty; a pin that appeared in
        // between keeps it, which is not this command's to fight.
        let _ = std::fs::remove_dir(&dir);
        Uninstalled {
            through: Route::Direct(dir),
            links: Some(removed),
        }
    };
    EbpfLoader::cleanup_pin_path_because(DEFAULT_BPF_PIN_PATH, "uninstall");
    EbpfLoader::cleanup_pin_path_because(DLP_PIN_PATH, "uninstall");
    Ok(outcome)
}

/// The line `uninstall` prints.
#[must_use]
pub fn report(outcome: &Uninstalled) -> String {
    let what = match (&outcome.through, outcome.links) {
        (Route::Warden(sock), _) => {
            format!("link pins removed by the warden at {}", sock.display())
        }
        (Route::Direct(dir), Some(n)) => format!("{n} link pin(s) removed from {}", dir.display()),
        (Route::Direct(dir), None) => format!("link pins removed from {}", dir.display()),
    };
    format!(
        "{what}; map pins removed. A running agent keeps its hooks until it stops, then nothing is left attached."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_report_names_the_route() {
        let direct = report(&Uninstalled {
            through: Route::Direct(PathBuf::from("/sys/fs/bpf/ebpfsentinel-links")),
            links: Some(3),
        });
        assert!(direct.starts_with("3 link pin(s) removed from /sys/fs/bpf/ebpfsentinel-links"));
        let brokered = report(&Uninstalled {
            through: Route::Warden(PathBuf::from("/run/ebpfsentinel/warden.sock")),
            links: None,
        });
        assert!(brokered.contains("by the warden at /run/ebpfsentinel/warden.sock"));
    }
}
