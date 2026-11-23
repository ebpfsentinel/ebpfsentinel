//! What the warden hands an agent once, counted per agent process.
//!
//! The bpffs delegation, the write refusal group and the resolver's bound
//! sockets are asked for once, at start-up, by an agent that then keeps them
//! for its whole life. A second ask from the same process is not something the
//! agent does, so it is refused: an agent that was taken over cannot collect a
//! second delegation, a second group or a resolver socket it already holds.
//! Capture sockets are asked for once per interface or pool slot at start-up,
//! so they carry a ceiling rather than a single use.
//!
//! The process is named by its pidfd, read off the connection with
//! `SO_PEERPIDFD`, and identified by the pidfd's inode: the pidfs gives each
//! process an inode that is never reused, across pid namespaces, so a sidecar
//! agent the warden sees under another pid is still one process, and a
//! restarted agent is a new one, served afresh. A process keeps its pidfd
//! inode through `execve`, so the agent re-executing itself after the user
//! namespace bootstrap is the same process that was delegated to. The ledger
//! keeps one pidfd per process and forgets a process once its pidfd reports
//! that it exited.

use std::io;
use std::mem;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::ptr;
use std::sync::{Mutex, PoisonError};

/// Capture sockets one agent process may be handed. The agent's pool holds at
/// most this many, and asks for them at start-up.
pub const MAX_PCAP_PER_PROCESS: usize = 32;

/// Processes the ledger remembers at once. An agent restarting in a loop
/// leaves exited entries behind until the next ask prunes them; a ledger full
/// of live processes refuses rather than grows.
const MAX_PROCESSES: usize = 256;

/// The process at the other end of a connection.
#[derive(Debug)]
pub struct Peer {
    pidfd: OwnedFd,
    ino: u64,
}

impl Peer {
    /// The peer of `conn`, read through `SO_PEERPIDFD`.
    ///
    /// # Errors
    ///
    /// The kernel did not give the peer's pidfd, or the pidfd could not be
    /// read.
    pub fn of(conn: &UnixStream) -> io::Result<Self> {
        let mut fd: libc::c_int = -1;
        let mut len = mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: `fd` and `len` are live and `len` holds the size of `fd`,
        // so the kernel writes inside it.
        let rc = unsafe {
            libc::getsockopt(
                conn.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERPIDFD,
                ptr::from_mut(&mut fd).cast(),
                &raw mut len,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        if fd < 0 {
            return Err(io::Error::other("no pidfd for the peer"));
        }
        // SAFETY: the kernel just opened `fd` for this process and nothing
        // else holds it.
        let pidfd = unsafe { OwnedFd::from_raw_fd(fd) };
        let ino = inode(&pidfd)?;
        Ok(Self { pidfd, ino })
    }

    /// The process's identity: its pidfs inode, never reused while the host
    /// runs and the same whichever pid namespace it is seen from.
    #[must_use]
    pub fn id(&self) -> u64 {
        self.ino
    }
}

fn inode(fd: &OwnedFd) -> io::Result<u64> {
    // SAFETY: `stat` is plain old data, for which all-zero is valid.
    let mut st: libc::stat = unsafe { mem::zeroed() };
    // SAFETY: `fd` is open for the call and `st` is live and the size `fstat`
    // writes.
    let rc = unsafe { libc::fstat(fd.as_raw_fd(), &raw mut st) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(st.st_ino)
}

/// Whether the process behind `fd` has exited: a pidfd polls readable then.
fn exited(fd: &OwnedFd) -> bool {
    let mut pfd = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: `pfd` is one live, initialised `pollfd` whose descriptor `fd`
    // keeps open for the call; a zero timeout never blocks.
    let rc = unsafe { libc::poll(&raw mut pfd, 1, 0) };
    rc > 0 && pfd.revents != 0
}

/// One thing the warden hands out at most once, or up to a ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Handed {
    /// The bpffs delegation and the descriptors that come with it.
    Delegation,
    /// The write refusal group.
    WriteRefusalGroup,
    /// The resolver's socket on one address, datagram or stream.
    ResolverSocket { listen: SocketAddr, stream: bool },
    /// One capture socket.
    CaptureSocket,
}

#[derive(Debug)]
struct Entry {
    pidfd: OwnedFd,
    ino: u64,
    delegation: bool,
    write_refusal_group: bool,
    resolver: Vec<(SocketAddr, bool)>,
    capture: usize,
}

impl Entry {
    fn new(peer: &Peer) -> io::Result<Self> {
        Ok(Self {
            pidfd: peer.pidfd.try_clone()?,
            ino: peer.ino,
            delegation: false,
            write_refusal_group: false,
            resolver: Vec::new(),
            capture: 0,
        })
    }

    fn take(&mut self, what: Handed) -> Result<(), String> {
        match what {
            Handed::Delegation => once(&mut self.delegation, "the bpffs delegation"),
            Handed::WriteRefusalGroup => {
                once(&mut self.write_refusal_group, "the write refusal group")
            }
            Handed::ResolverSocket { listen, stream } => {
                if self.resolver.contains(&(listen, stream)) {
                    return Err(format!(
                        "the resolver's {} socket on {listen} was already handed to this agent process",
                        if stream { "stream" } else { "datagram" }
                    ));
                }
                self.resolver.push((listen, stream));
                Ok(())
            }
            Handed::CaptureSocket => {
                if self.capture >= MAX_PCAP_PER_PROCESS {
                    return Err(format!(
                        "this agent process was already handed {MAX_PCAP_PER_PROCESS} capture sockets"
                    ));
                }
                self.capture += 1;
                Ok(())
            }
        }
    }
}

fn once(taken: &mut bool, what: &str) -> Result<(), String> {
    if *taken {
        return Err(format!("{what} was already handed to this agent process"));
    }
    *taken = true;
    Ok(())
}

/// What each agent process was handed.
#[derive(Debug, Default)]
pub struct Ledger {
    entries: Mutex<Vec<Entry>>,
}

impl Ledger {
    /// An empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `peer` is handed `what`, or say why it is not.
    ///
    /// # Errors
    ///
    /// `peer` was already handed `what`, or its ceiling, or the ledger holds
    /// as many live processes as it remembers.
    pub fn take(&self, peer: &Peer, what: Handed) -> Result<(), String> {
        // Every field of an entry is a count that only rises, so a write cut
        // short by a panic leaves a ledger that refuses at worst.
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries.retain(|e| e.ino == peer.ino || !exited(&e.pidfd));
        let index = if let Some(index) = entries.iter().position(|e| e.ino == peer.ino) {
            index
        } else {
            if entries.len() >= MAX_PROCESSES {
                return Err(format!(
                    "the warden already serves {MAX_PROCESSES} live agent processes"
                ));
            }
            entries.push(Entry::new(peer).map_err(|e| format!("pidfd: {e}"))?);
            entries.len() - 1
        };
        entries[index].take(what)
    }

    /// Processes remembered now.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Whether no process is remembered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn me() -> (Peer, UnixStream, UnixStream) {
        let (a, b) = UnixStream::pair().unwrap();
        let peer = Peer::of(&a).unwrap();
        (peer, a, b)
    }

    #[test]
    fn two_connections_of_one_process_are_one_peer() {
        let (first, _a, _b) = me();
        let (second, _c, _d) = me();
        assert_eq!(first.ino, second.ino);
        let ledger = Ledger::new();
        ledger.take(&first, Handed::Delegation).unwrap();
        let err = ledger.take(&second, Handed::Delegation).unwrap_err();
        assert!(err.contains("already handed"), "{err}");
        assert_eq!(ledger.len(), 1);
    }

    #[test]
    fn each_resolver_socket_is_handed_once() {
        let (peer, _a, _b) = me();
        let ledger = Ledger::new();
        let listen: SocketAddr = "127.0.0.1:53".parse().unwrap();
        ledger
            .take(
                &peer,
                Handed::ResolverSocket {
                    listen,
                    stream: false,
                },
            )
            .unwrap();
        ledger
            .take(
                &peer,
                Handed::ResolverSocket {
                    listen,
                    stream: true,
                },
            )
            .unwrap();
        let err = ledger
            .take(
                &peer,
                Handed::ResolverSocket {
                    listen,
                    stream: true,
                },
            )
            .unwrap_err();
        assert!(err.contains("stream socket on 127.0.0.1:53"), "{err}");
        ledger.take(&peer, Handed::WriteRefusalGroup).unwrap();
        assert!(ledger.take(&peer, Handed::WriteRefusalGroup).is_err());
    }

    #[test]
    fn capture_sockets_stop_at_the_ceiling() {
        let (peer, _a, _b) = me();
        let ledger = Ledger::new();
        for _ in 0..MAX_PCAP_PER_PROCESS {
            ledger.take(&peer, Handed::CaptureSocket).unwrap();
        }
        let err = ledger.take(&peer, Handed::CaptureSocket).unwrap_err();
        assert!(err.contains("32 capture sockets"), "{err}");
    }

    #[test]
    fn an_exited_process_is_forgotten_and_a_new_one_served() {
        // A child process exits; its pidfd then polls readable and the next
        // ask prunes it.
        // SAFETY: fork in a test: the child only exits.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            // SAFETY: the child leaves without running any destructor.
            unsafe { libc::_exit(0) };
        }
        // SAFETY: `pid` is this process's own child, not yet reaped.
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        assert!(raw >= 0);
        // SAFETY: `pidfd_open` just returned this descriptor.
        let pidfd = unsafe { OwnedFd::from_raw_fd(raw as libc::c_int) };
        let child = Peer {
            ino: inode(&pidfd).unwrap(),
            pidfd,
        };
        let ledger = Ledger::new();
        ledger.take(&child, Handed::Delegation).unwrap();
        let mut status = 0;
        // SAFETY: waits for this process's own child.
        unsafe { libc::waitpid(pid, &raw mut status, 0) };
        let (me, _a, _b) = me();
        ledger.take(&me, Handed::Delegation).unwrap();
        assert_eq!(ledger.len(), 1, "the exited child is pruned");
    }
}
