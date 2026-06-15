//! Host-network operations the warden performs that need authority over the
//! **init** network namespace — conntrack teardown, route programming, gratuitous
//! ARP — plus the conntrack-table read of the `0440 root` proc file.
//!
//! These split from the map RPC because *where* they can run differs. A map op is
//! a `bpf()` on an fd the server already holds, so it works wherever the server
//! holds the fd. A conntrack/route/ARP op is netlink (or an `AF_PACKET` send), and
//! the kernel re-checks `CAP_NET_ADMIN`/`CAP_NET_RAW` against the init netns on
//! **every** message — a capability held only inside a child user namespace grants
//! no authority over the host's conntrack table or NICs. The agent's
//! `warden-serve` mode runs in exactly such a userns (so that `BPF_TOKEN_CREATE`
//! works), and therefore cannot perform these ops itself.
//!
//! [`HostOps`] abstracts that authority away from the server's `dispatch`. Two
//! implementations back it:
//!
//! * [`LocalHostOps`] runs the op directly, for a warden that genuinely lives in
//!   the init netns with the capabilities (the bare-metal `warden serve` binary
//!   and the resident broker).
//! * [`BrokerHostOps`] forwards the op over `warden-proto` to such a broker, for a
//!   `warden-serve` that sits in a userns and must borrow the broker's authority.
//!
//! Either way the server's wire behaviour is identical; only the executor moves.

use std::fs;
use std::io;
use std::sync::Mutex;

use ebpfsentinel_warden_client::ReconnectingClient;
use ebpfsentinel_warden_proto::{ConntrackTuple, RouteSpec};

use crate::net_ops;

/// Kernel conntrack table the warden reads on the agent's behalf (a `0440 root`
/// file the rootless agent cannot open).
const NF_CONNTRACK_PROC: &str = "/proc/net/nf_conntrack";

/// The init-netns operations the warden server delegates out of `dispatch`. All
/// methods take `&self`: an implementation that needs a mutable connection guards
/// it internally, so the trait object stays shareable across the serve loop.
pub trait HostOps: Send + Sync {
    /// Read the kernel conntrack table (`/proc/net/nf_conntrack`).
    fn conntrack_dump(&self) -> Result<Vec<u8>, String>;
    /// Tear down a single conntrack flow (a `CAP_NET_ADMIN` netlink op).
    fn conntrack_delete(&self, tuple: &ConntrackTuple) -> Result<(), String>;
    /// Flush the whole conntrack table.
    fn conntrack_flush(&self) -> Result<(), String>;
    /// Add (idempotent `replace`) a route — multi-WAN gateway programming.
    fn route_add(&self, route: &RouteSpec) -> Result<(), String>;
    /// Delete a route.
    fn route_del(&self, route: &RouteSpec) -> Result<(), String>;
    /// Broadcast a gratuitous ARP for `ip` on `iface` (VIP takeover).
    fn arp_announce(&self, iface: &str, ip: &str) -> Result<(), String>;
}

/// Performs each op directly, for a warden that holds the capabilities in the init
/// netns (the bare-metal `warden serve` binary and the resident broker).
pub struct LocalHostOps;

impl HostOps for LocalHostOps {
    fn conntrack_dump(&self) -> Result<Vec<u8>, String> {
        match fs::read(NF_CONNTRACK_PROC) {
            Ok(table) => Ok(table),
            // An absent proc file (conntrack module not loaded) is an empty table,
            // not an error — the agent parses zero flows.
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(format!("read {NF_CONNTRACK_PROC}: {e}")),
        }
    }
    fn conntrack_delete(&self, tuple: &ConntrackTuple) -> Result<(), String> {
        net_ops::conntrack_delete(tuple)
    }
    fn conntrack_flush(&self) -> Result<(), String> {
        net_ops::conntrack_flush()
    }
    fn route_add(&self, route: &RouteSpec) -> Result<(), String> {
        net_ops::route(true, route)
    }
    fn route_del(&self, route: &RouteSpec) -> Result<(), String> {
        net_ops::route(false, route)
    }
    fn arp_announce(&self, iface: &str, ip: &str) -> Result<(), String> {
        net_ops::arp_announce(iface, ip)
    }
}

/// Forwards each op over `warden-proto` to a resident broker living in the init
/// netns. Used by `warden-serve`, which runs in a user namespace where these ops
/// would fail locally. The connection reconnects on its own if the broker bounces.
pub struct BrokerHostOps {
    client: Mutex<ReconnectingClient>,
}

impl BrokerHostOps {
    /// Bind to the broker socket at `sock`. Connection is lazy — the first op
    /// dials the broker, which may legitimately start after `warden-serve`.
    #[must_use]
    pub fn connect(sock: impl Into<std::path::PathBuf>) -> Self {
        Self {
            client: Mutex::new(ReconnectingClient::new(sock)),
        }
    }

    /// Run `op` against the guarded client, mapping any error to a string the
    /// server relays verbatim to the agent.
    fn with<T>(
        &self,
        op: impl FnOnce(&mut ReconnectingClient) -> io::Result<T>,
    ) -> Result<T, String> {
        let mut client = self
            .client
            .lock()
            .map_err(|_| "broker client mutex poisoned".to_string())?;
        op(&mut client).map_err(|e| e.to_string())
    }
}

impl HostOps for BrokerHostOps {
    fn conntrack_dump(&self) -> Result<Vec<u8>, String> {
        self.with(ReconnectingClient::conntrack_dump)
    }
    fn conntrack_delete(&self, tuple: &ConntrackTuple) -> Result<(), String> {
        self.with(|c| c.conntrack_delete(tuple))
    }
    fn conntrack_flush(&self) -> Result<(), String> {
        self.with(ReconnectingClient::conntrack_flush)
    }
    fn route_add(&self, route: &RouteSpec) -> Result<(), String> {
        self.with(|c| c.route_add(route))
    }
    fn route_del(&self, route: &RouteSpec) -> Result<(), String> {
        self.with(|c| c.route_del(route))
    }
    fn arp_announce(&self, iface: &str, ip: &str) -> Result<(), String> {
        self.with(|c| c.arp_announce(iface, ip))
    }
}
