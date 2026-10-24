#![allow(unsafe_code)] // Raw bpf() syscall for BPF_PROG_QUERY.

//! Where the agent's classifiers sit on an interface's TCX chain, read back
//! after every attach.
//!
//! Every TC program the agent attaches goes to the head of the chain and
//! turns a pass into `TCX_NEXT`, so it hands each packet on to whatever runs
//! after it. A program ahead of ours does not owe us that: a CNI's datapath
//! returns `TC_ACT_OK` or redirects, either of which ends the chain, and our
//! detections would then miss that traffic without a single error anywhere.
//! So the chain is read back once ours is on it, and a foreign program found
//! ahead of or between the agent's programs refuses the attach with a message
//! that names it, rather than leaving the agent attached where it cannot see.
//!
//! The order among the agent's own programs does not matter: each one parses
//! the packet afresh when the handoff it expects from the one before is
//! missing.
//!
//! `BPF_PROG_QUERY` wants `CAP_NET_ADMIN` in the initial user namespace,
//! which the agent's own namespace does not confer, so a refused query is
//! asked again through the warden. When neither can answer, the attach
//! stands and a warning says the order went unverified: an unknown must never
//! read as a fault.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io;
use std::os::fd::RawFd;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock, PoisonError};

use ebpfsentinel_warden_client::ReconnectingClient;
use tracing::warn;

use super::attach_inspect;
use super::kfunc_attach::{bpf, iface_to_ifindex};

/// `BPF_PROG_QUERY` from `enum bpf_cmd`.
const BPF_PROG_QUERY: u32 = 16;
/// `BPF_TCX_INGRESS` and `BPF_TCX_EGRESS` from `enum bpf_attach_type`.
const BPF_TCX_INGRESS: u32 = 46;
const BPF_TCX_EGRESS: u32 = 47;
/// Programs read on the first attempt; a longer chain is answered with
/// `ENOSPC` and its real length, and read again at that size.
const FIRST_READ: usize = 64;
/// Bound on the retry, so a racing chain cannot drive an unbounded
/// allocation. No TCX hook carries anything near this.
const MAX_PROGRAMS: usize = 4096;

/// `union bpf_attr` for `BPF_PROG_QUERY`, offsets per the kernel UAPI.
#[repr(C)]
#[derive(Default)]
struct ProgQueryAttr {
    target_ifindex: u32,
    attach_type: u32,
    query_flags: u32,
    attach_flags: u32,
    prog_ids: u64,
    count: u32,
    _pad: u32,
    prog_attach_flags: u64,
    link_ids: u64,
    link_attach_flags: u64,
    revision: u64,
}

/// What is wrong with a chain the agent's program was just attached to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrderFault {
    /// Foreign programs run ahead of, or between, the agent's programs.
    ForeignAhead {
        /// Their kernel program ids, in run order.
        ids: Vec<u32>,
    },
    /// The program just attached is not on the chain at all.
    Missing,
}

/// One TCX hook on one interface, as a refusal names it.
#[derive(Debug, Clone, Copy)]
pub struct Hook<'a> {
    /// Interface the chain belongs to.
    pub interface: &'a str,
    /// `true` for egress.
    pub egress: bool,
}

impl fmt::Display for Hook<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let dir = if self.egress { "egress" } else { "ingress" };
        write!(f, "TCX {dir} on {}", self.interface)
    }
}

/// The sentence an operator reads when the attach is refused.
#[must_use]
pub fn refusal(hook: Hook<'_>, fault: &OrderFault) -> String {
    match fault {
        OrderFault::ForeignAhead { ids } => {
            let ids = ids
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                "{hook}: program id(s) {ids} run ahead of the agent's classifiers; a program \
                 ahead of the agent that passes or redirects a packet ends the chain, so \
                 detections would silently miss that traffic. Refused rather than attached \
                 behind it: read the chain with `bpftool net show dev {}`, and restart the \
                 agent once nothing foreign runs before it",
                hook.interface
            )
        }
        OrderFault::Missing => format!(
            "{hook}: the agent's program is not on the chain right after attaching it, so \
             something detached it or replaced the chain; refused rather than reported as \
             attached"
        ),
    }
}

/// Judge a chain, read in run order, against the agent's program ids.
///
/// `this` is the program just attached. Every program before the last of the
/// agent's must be one of the agent's own.
pub fn judge<S: std::hash::BuildHasher>(
    chain: &[u32],
    ours: &HashSet<u32, S>,
    this: u32,
) -> Result<(), OrderFault> {
    if !chain.contains(&this) {
        return Err(OrderFault::Missing);
    }
    let Some(last) = chain
        .iter()
        .rposition(|id| ours.contains(id) || *id == this)
    else {
        return Err(OrderFault::Missing);
    };
    let foreign: Vec<u32> = chain[..last]
        .iter()
        .copied()
        .filter(|id| !ours.contains(id) && *id != this)
        .collect();
    if foreign.is_empty() {
        Ok(())
    } else {
        Err(OrderFault::ForeignAhead { ids: foreign })
    }
}

fn registry() -> &'static Mutex<HashSet<u32>> {
    static OURS: OnceLock<Mutex<HashSet<u32>>> = OnceLock::new();
    OURS.get_or_init(|| Mutex::new(HashSet::new()))
}

fn warned() -> &'static Mutex<HashSet<(String, bool)>> {
    static WARNED: OnceLock<Mutex<HashSet<(String, bool)>>> = OnceLock::new();
    WARNED.get_or_init(|| Mutex::new(HashSet::new()))
}

/// The agent's programs placed on each hook, keyed by interface and
/// direction, in the order they were placed.
type Placed = HashMap<(String, bool), Vec<u32>>;

fn placed() -> &'static Mutex<Placed> {
    static PLACED: OnceLock<Mutex<Placed>> = OnceLock::new();
    PLACED.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Forget every placement recorded on `interface`, both directions: the
/// interface went away, and a new device given the same name starts with an
/// empty chain.
pub fn forget(interface: &str) {
    if let Ok(mut placed) = placed().lock() {
        placed.retain(|(iface, _), _| iface != interface);
    }
    if let Ok(mut warned) = warned().lock() {
        warned.retain(|(iface, _)| iface != interface);
    }
}

/// The agent's programs already placed on a hook, most recent first: the
/// programs a new attach goes right after, so the agent's own programs keep
/// running in the order they were attached.
#[must_use]
pub fn anchors(interface: &str, egress: bool) -> Vec<u32> {
    placed()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&(interface.to_owned(), egress))
        .map(|ids| ids.iter().rev().copied().collect())
        .unwrap_or_default()
}

fn record_placed(hook: Hook<'_>, id: u32) {
    let mut placed = placed().lock().unwrap_or_else(PoisonError::into_inner);
    let ids = placed
        .entry((hook.interface.to_owned(), hook.egress))
        .or_default();
    ids.retain(|known| *known != id);
    ids.push(id);
}

static WARDEN: OnceLock<Mutex<ReconnectingClient>> = OnceLock::new();

/// Ask the warden at `sock` whenever the agent's own query is refused. Set
/// once, before the first TC attach; a second call is ignored.
pub fn use_warden(sock: PathBuf) {
    let _ = WARDEN.set(Mutex::new(ReconnectingClient::new(sock)));
}

/// Read the program ids on one TCX hook in run order, directly.
pub fn query_chain(interface: &str, egress: bool) -> io::Result<Vec<u32>> {
    let ifindex = iface_to_ifindex(interface).map_err(io::Error::other)?;
    let attach_type = if egress {
        BPF_TCX_EGRESS
    } else {
        BPF_TCX_INGRESS
    };
    let mut capacity = FIRST_READ;
    loop {
        let mut ids = vec![0u32; capacity];
        let mut attr = ProgQueryAttr {
            target_ifindex: ifindex,
            attach_type,
            prog_ids: ids.as_mut_ptr() as u64,
            count: u32::try_from(capacity).unwrap_or(u32::MAX),
            ..Default::default()
        };
        // SAFETY: `attr` is a fully initialised `bpf_attr` prefix and
        // `prog_ids` points at `count` writable u32s that outlive the call.
        let rc = unsafe {
            bpf(
                BPF_PROG_QUERY,
                (&raw mut attr).cast(),
                std::mem::size_of::<ProgQueryAttr>(),
            )
        };
        let held = attr.count as usize;
        if rc == 0 {
            ids.truncate(held.min(capacity));
            return Ok(ids);
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOSPC) && held > capacity && held <= MAX_PROGRAMS {
            capacity = held;
            continue;
        }
        return Err(err);
    }
}

/// The chain, read directly or, when the kernel refuses this namespace,
/// through the warden.
fn read_chain(interface: &str, egress: bool) -> Result<Vec<u32>, String> {
    match query_chain(interface, egress) {
        Ok(chain) => Ok(chain),
        Err(e) if matches!(e.raw_os_error(), Some(libc::EPERM | libc::EACCES)) => {
            let Some(client) = WARDEN.get() else {
                return Err(format!("{e}, and no warden to ask"));
            };
            client
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .tcx_chain(interface, egress)
                .map_err(|w| format!("{e}; through the warden: {w}"))
        }
        Err(e) => Err(e.to_string()),
    }
}

/// Read the chain back after attaching `prog_fd` and judge where it landed.
///
/// `Err` carries the refusal an operator reads; the caller drops the link.
/// A chain nobody could read is a warning, once per hook, and not a refusal.
pub fn verify(program: &str, hook: Hook<'_>, prog_fd: RawFd) -> Result<(), String> {
    let Some(this) = attach_inspect::program_id(prog_fd) else {
        warn!(program, %hook, "TCX order unverified: the program's own id is unreadable");
        return Ok(());
    };
    let ours = {
        let mut ours = registry().lock().unwrap_or_else(PoisonError::into_inner);
        ours.insert(this);
        ours.clone()
    };
    record_placed(hook, this);
    let chain = match read_chain(hook.interface, hook.egress) {
        Ok(chain) => chain,
        Err(reason) => {
            let first = warned()
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert((hook.interface.to_owned(), hook.egress));
            if first {
                warn!(
                    program,
                    %hook,
                    reason,
                    "TCX order unverified: the chain could not be read, so a program \
                     ahead of the agent would go unnoticed"
                );
            }
            return Ok(());
        }
    };
    judge(&chain, &ours, this).map_err(|fault| refusal(hook, &fault))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ours(ids: &[u32]) -> HashSet<u32> {
        ids.iter().copied().collect()
    }

    #[test]
    fn a_forgotten_interface_starts_with_no_anchors() {
        let gone = Hook {
            interface: "veth-forget-test",
            egress: false,
        };
        record_placed(gone, 7);
        record_placed(
            Hook {
                egress: true,
                ..gone
            },
            8,
        );
        assert_eq!(anchors("veth-forget-test", false), vec![7]);
        forget("veth-forget-test");
        assert_eq!(anchors("veth-forget-test", false), Vec::<u32>::new());
        assert_eq!(anchors("veth-forget-test", true), Vec::<u32>::new());
    }

    #[test]
    fn ours_at_the_head_with_foreign_after_is_accepted() {
        assert_eq!(judge(&[3, 2, 1, 90, 91], &ours(&[1, 2]), 3), Ok(()));
    }

    #[test]
    fn ours_alone_is_accepted() {
        assert_eq!(judge(&[5], &HashSet::new(), 5), Ok(()));
    }

    #[test]
    fn a_foreign_program_ahead_is_named() {
        assert_eq!(
            judge(&[90, 5], &HashSet::new(), 5),
            Err(OrderFault::ForeignAhead { ids: vec![90] })
        );
    }

    #[test]
    fn a_foreign_program_between_ours_is_named() {
        assert_eq!(
            judge(&[5, 90, 1, 91], &ours(&[1]), 5),
            Err(OrderFault::ForeignAhead { ids: vec![90] })
        );
    }

    #[test]
    fn a_program_missing_from_its_chain_is_a_fault() {
        assert_eq!(judge(&[1, 90], &ours(&[1]), 5), Err(OrderFault::Missing));
    }

    #[test]
    fn the_refusal_names_the_hook_the_ids_and_the_consequence() {
        let msg = refusal(
            Hook {
                interface: "eth0",
                egress: true,
            },
            &OrderFault::ForeignAhead { ids: vec![90, 91] },
        );
        assert!(
            msg.starts_with("TCX egress on eth0: program id(s) 90, 91"),
            "{msg}"
        );
        assert!(msg.contains("silently miss"), "{msg}");
        assert!(msg.contains("bpftool net show dev eth0"), "{msg}");
    }

    #[test]
    fn anchors_are_the_placed_programs_most_recent_first() {
        let hook = Hook {
            interface: "anchor-test0",
            egress: true,
        };
        record_placed(hook, 7);
        record_placed(hook, 9);
        record_placed(hook, 7);
        assert_eq!(anchors("anchor-test0", true), vec![7, 9]);
        assert!(anchors("anchor-test0", false).is_empty());
    }

    #[test]
    fn query_attr_field_offsets_match_uapi() {
        let a = ProgQueryAttr::default();
        let base = std::ptr::from_ref(&a) as usize;
        assert_eq!(std::ptr::from_ref(&a.attach_type) as usize - base, 4);
        assert_eq!(std::ptr::from_ref(&a.prog_ids) as usize - base, 16);
        assert_eq!(std::ptr::from_ref(&a.count) as usize - base, 24);
        assert_eq!(std::ptr::from_ref(&a.link_ids) as usize - base, 40);
        assert_eq!(std::ptr::from_ref(&a.revision) as usize - base, 56);
    }

    #[test]
    fn a_missing_interface_is_an_error_not_a_chain() {
        assert!(query_chain("no-such-if0", false).is_err());
    }
}
