//! Host-network operations the warden performs that need authority over the
//! **init** network namespace — conntrack teardown, route programming, gratuitous
//! ARP — plus the conntrack-table read of the `0440 root` proc file.
//!
//! A conntrack/route/ARP op is netlink (or an `AF_PACKET` send), and the kernel
//! re-checks `CAP_NET_ADMIN`/`CAP_NET_RAW` against the init netns on **every**
//! message — a capability held only inside a child user namespace grants no
//! authority over the host's conntrack table or NICs. The rootless agent runs in
//! exactly such a userns (so that `BPF_TOKEN_CREATE` works), and therefore cannot
//! perform these ops itself; it brokers them to the host-root warden.
//!
//! [`HostOps`] abstracts that authority away from the server's `dispatch`.
//! [`LocalHostOps`] runs each op directly, in the warden that lives in the init
//! netns with the capabilities.

use std::fs;
use std::io;

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

/// Performs each op directly, for the warden that holds the capabilities in the
/// init netns.
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
