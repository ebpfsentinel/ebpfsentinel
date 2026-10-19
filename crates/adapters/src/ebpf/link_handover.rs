//! Replacing a program on a hook that stays attached.
//!
//! A link is what holds a program on an interface. Closing it detaches, and
//! the agent used to reload a hook by closing the old link and creating a new
//! one: between the two syscalls the interface carries no program at all, and
//! every packet crossing it in that window is a packet the datapath never saw.
//!
//! `BPF_LINK_UPDATE` ([`kfunc_attach::link_update`]) replaces the program a
//! live link runs, so the hook is never empty. The command needs the old link
//! fd at the moment the new program is loaded, which is the other half of this
//! module: a caller that is about to drop a loader **parks** its links here,
//! the attach path of the loader that replaces it reaches for the parked link
//! of the same interface and hook, and whatever is left over is released - the
//! detach the agent did before.
//!
//! Two counters answer for it, because a fallback that nobody can see is a
//! hole that comes back: [`stats`] reports how many hooks were handed over and
//! how many fell back, and every fallback is logged with the program named and
//! the errno the kernel gave.

use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use tracing::{info, warn};

use super::kfunc_attach;

/// Which hook of an interface a link holds a program on.
///
/// The pair (interface, hook) is what a handover is keyed on: a program
/// replaced on ingress must not take over the egress link of the same
/// interface, and the kernel would refuse it anyway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkHook {
    /// XDP, at the driver or in the stack.
    Xdp,
    /// TCX ingress.
    TcxIngress,
    /// TCX egress.
    TcxEgress,
    /// A netkit device's primary side.
    NetkitPrimary,
    /// A netkit device's peer side.
    NetkitPeer,
}

impl LinkHook {
    /// The hook as it is written in a log line.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Xdp => "xdp",
            Self::TcxIngress => "tcx-ingress",
            Self::TcxEgress => "tcx-egress",
            Self::NetkitPrimary => "netkit-primary",
            Self::NetkitPeer => "netkit-peer",
        }
    }
}

/// A link the agent holds, with what it attaches and where.
///
/// The fd owns the attachment: dropping it detaches. Carrying the program
/// name and the interface beside it is what makes a link addressable, which
/// an anonymous `OwnedFd` in a vector is not.
#[derive(Debug)]
pub struct AttachedLink {
    program: String,
    interface: String,
    hook: LinkHook,
    fd: OwnedFd,
}

impl AttachedLink {
    /// Record a link just created for `program` on `interface`.
    pub fn new(program: &str, interface: &str, hook: LinkHook, fd: OwnedFd) -> Self {
        Self {
            program: program.to_owned(),
            interface: interface.to_owned(),
            hook,
            fd,
        }
    }

    /// The program the link currently runs.
    pub fn program(&self) -> &str {
        &self.program
    }

    /// The interface the link holds.
    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// Which hook of that interface.
    pub fn hook(&self) -> LinkHook {
        self.hook
    }

    /// The raw link fd, for a syscall that takes one.
    pub fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// Links waiting for the program that replaces theirs.
static PARKED: OnceLock<Mutex<Vec<AttachedLink>>> = OnceLock::new();
/// Hooks whose program was replaced without a detach.
static HANDOVERS: AtomicU64 = AtomicU64::new(0);
/// Hooks that had to be detached and attached again.
static FALLBACKS: AtomicU64 = AtomicU64::new(0);

fn parked() -> &'static Mutex<Vec<AttachedLink>> {
    PARKED.get_or_init(|| Mutex::new(Vec::new()))
}

/// Hand links over to the attach that is about to replace their programs.
///
/// The links keep their programs attached and running until they are taken by
/// [`take_over`] or released by [`release_parked`], which is what closes the
/// window: the old program answers for the interface right up to the syscall
/// that swaps it.
pub fn park(links: Vec<AttachedLink>) {
    if links.is_empty() {
        return;
    }
    let Ok(mut guard) = parked().lock() else {
        // A poisoned registry would otherwise drop the links here, which is
        // the detach this module exists to avoid - but keeping them would
        // leak the old program onto the interface for good.
        warn!("link handover registry is poisoned, links detach instead");
        return;
    };
    for link in links {
        info!(
            program = link.program(),
            interface = link.interface(),
            hook = link.hook().as_str(),
            "link parked for handover"
        );
        guard.push(link);
    }
}

/// Take over the parked link of `(interface, hook)` for `program`.
///
/// Returns the link, now running `new_prog_fd`, when the kernel accepted the
/// replacement. Returns `None` when there was nothing parked for that hook -
/// the ordinary first attach - and also when the kernel refused the update, in
/// which case the parked link is dropped (detaching the old program) and the
/// refusal is counted and logged with both program names and the errno. The
/// caller then creates a link the way it always did.
pub fn take_over(
    program: &str,
    interface: &str,
    hook: LinkHook,
    new_prog_fd: RawFd,
) -> Option<AttachedLink> {
    let mut link = {
        let mut guard = parked().lock().ok()?;
        let idx = guard
            .iter()
            .position(|l| l.interface == interface && l.hook == hook)?;
        guard.swap_remove(idx)
    };

    match kfunc_attach::link_update(program, link.raw_fd(), new_prog_fd) {
        Ok(()) => {
            HANDOVERS.fetch_add(1, Ordering::Relaxed);
            info!(
                program,
                replaced = link.program(),
                interface,
                hook = hook.as_str(),
                "program replaced on a live link, no detach window"
            );
            program.clone_into(&mut link.program);
            Some(link)
        }
        Err(e) => {
            FALLBACKS.fetch_add(1, Ordering::Relaxed);
            warn!(
                program,
                replaced = link.program(),
                interface,
                hook = hook.as_str(),
                "link update refused, falling back to detach and attach: {e}"
            );
            // Dropping the link detaches the old program, which is what has
            // to happen before the hook will accept another one.
            drop(link);
            None
        }
    }
}

/// Drop every link still parked, detaching whatever it still holds.
///
/// Returns how many there were. A link left here is a hook nothing
/// reattached, meaning a program disabled rather than replaced or an
/// interface the new program does not cover, so the count is a fact about
/// the reconciliation rather than a fault.
pub fn release_parked() -> usize {
    let Ok(mut guard) = parked().lock() else {
        return 0;
    };
    let left = std::mem::take(&mut *guard);
    let count = left.len();
    for link in &left {
        info!(
            program = link.program(),
            interface = link.interface(),
            hook = link.hook().as_str(),
            "parked link released, hook detached"
        );
    }
    drop(left);
    count
}

/// How many hooks changed program with and without a detach window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandoverStats {
    /// Programs replaced through `BPF_LINK_UPDATE`.
    pub handovers: u64,
    /// Replacements the kernel refused, which detached and attached again.
    pub fallbacks: u64,
}

/// Read the two counters.
pub fn stats() -> HandoverStats {
    HandoverStats {
        handovers: HANDOVERS.load(Ordering::Relaxed),
        fallbacks: FALLBACKS.load(Ordering::Relaxed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The registry is process-wide, so the tests that park into it run one
    /// at a time: a release from one would otherwise detach another's link.
    static SERIAL: Mutex<()> = Mutex::new(());

    /// A link fd that attaches nothing, for the registry's own bookkeeping.
    /// `BPF_LINK_UPDATE` on it is refused by the kernel, which is exactly the
    /// fallback path a caller has to survive.
    fn dummy_link(program: &str, interface: &str, hook: LinkHook) -> AttachedLink {
        let file = std::fs::File::open("/dev/null").expect("/dev/null opens");
        AttachedLink::new(program, interface, hook, OwnedFd::from(file))
    }

    #[test]
    fn hook_names_are_distinct() {
        let names = [
            LinkHook::Xdp.as_str(),
            LinkHook::TcxIngress.as_str(),
            LinkHook::TcxEgress.as_str(),
            LinkHook::NetkitPrimary.as_str(),
            LinkHook::NetkitPeer.as_str(),
        ];
        let mut sorted = names.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len());
    }

    #[test]
    fn nothing_parked_is_not_a_handover() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // A first attach finds no parked link, which is the ordinary path and
        // must not be counted as a refusal.
        let before = stats();
        assert!(take_over("xdp_firewall", "iface-never-parked", LinkHook::Xdp, -1).is_none());
        let after = stats();
        assert_eq!(before.handovers, after.handovers);
        assert_eq!(before.fallbacks, after.fallbacks);
    }

    #[test]
    fn a_refused_update_is_counted_and_the_link_released() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let before = stats();
        park(vec![dummy_link(
            "xdp_firewall",
            "iface-refuse",
            LinkHook::Xdp,
        )]);
        // The kernel cannot update a link that is not one: the caller gets
        // `None` and must create its own link.
        assert!(take_over("xdp_ratelimit", "iface-refuse", LinkHook::Xdp, -1).is_none());
        assert_eq!(stats().fallbacks, before.fallbacks + 1);
        // The link is gone from the registry whichever way the kernel went.
        assert!(take_over("xdp_ratelimit", "iface-refuse", LinkHook::Xdp, -1).is_none());
        assert_eq!(stats().fallbacks, before.fallbacks + 1);
    }

    #[test]
    fn a_parked_link_is_keyed_on_interface_and_hook() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        park(vec![dummy_link(
            "tc_ids",
            "iface-keyed",
            LinkHook::TcxIngress,
        )]);
        // Same interface, other hook: not this link.
        assert!(take_over("tc_ids", "iface-keyed", LinkHook::TcxEgress, -1).is_none());
        // Same hook, other interface: not this link either.
        assert!(take_over("tc_ids", "iface-other", LinkHook::TcxIngress, -1).is_none());
        // Still parked, so releasing finds it.
        assert!(release_parked() >= 1);
    }
}
