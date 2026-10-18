use std::net::IpAddr;

use domain::workload::entity::WorkloadSource;

/// The two ends of a connection as a reader of the kernel tables states them.
///
/// `local` is this node's side. A caller reading the kernel's own conntrack
/// table does not know which side that is, which is why the reader tries the
/// key both ways round rather than making the caller guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowEndpoints {
    pub local_addr: IpAddr,
    pub remote_addr: IpAddr,
    pub local_port: u16,
    pub remote_port: u16,
    /// IP protocol number as the kernel writes it.
    pub protocol: u8,
}

/// The task the kernel recorded against a socket, before anything is looked
/// up about it.
///
/// This is the raw join and nothing more: a pid, the thread group it belongs
/// to, the uid and the cgroup the socket hooks read at the moment the socket
/// was opened, plus how the reader got there. Turning it into a workload
/// block is the application's job, because that needs the process table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketOwner {
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub cgroup_id: u64,
    pub source: WorkloadSource,
}

/// Reads the kernel's socket attribution tables.
///
/// Two ways in, because the callers have two different handles. A packet
/// event carries the socket cookie the kernel itself produced, which is the
/// exact join. A connection read out of `/proc/net/nf_conntrack` carries no
/// cookie at all, only addresses and ports, so it goes through the five-tuple
/// index the `sockops` hook fills.
///
/// Both return `None` for everything the kernel cannot answer: hooks that
/// never attached, a socket opened before the agent started, an entry the LRU
/// evicted, or a record older than the table's own time-to-live. `None` is
/// the honest answer and the one the whole workload block is designed around.
pub trait SocketIdentityReader: Send + Sync {
    /// The task that owns the socket this cookie names.
    fn by_cookie(&self, cookie: u64) -> Option<SocketOwner>;

    /// The task that opened a connection with these endpoints.
    fn by_flow(&self, flow: &FlowEndpoints) -> Option<SocketOwner>;
}
