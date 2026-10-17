//! The pre-opened `AF_PACKET` pool as slots that come back.
//!
//! The warden opens its capture sockets once, while it still holds
//! `CAP_NET_RAW`, and hands them to the agent over `SCM_RIGHTS`. A slot is
//! therefore in use for exactly as long as the agent that received it keeps its
//! copy, which is the lifetime of the connection it asked over: the agent's pool
//! holds that connection open for its whole life and the connection goes when
//! the agent goes. Handing a slot out twice would put two captures on one
//! socket, so a slot stays claimed until the connection thread that took it
//! ends, and is then free for the next agent.
//!
//! This replaces a monotonically increasing index, under which an agent that
//! restarted was served from where the previous one left off and a pool of two
//! was spent after two restarts, with every socket still open and nobody using
//! it.

use std::os::fd::RawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// The warden's capture sockets, claimable one at a time.
pub struct PcapSlots {
    fds: Vec<RawFd>,
    claimed: Vec<AtomicBool>,
    /// Whether this warden can open an `AF_PACKET` socket of its own, which is
    /// what decides whether an exhausted pool has a fallback at all.
    can_open: bool,
}

impl PcapSlots {
    /// Wrap the pre-opened pool. `can_open` says whether `socket(AF_PACKET)`
    /// works in this process, so an exhausted pool knows whether to fall back to
    /// opening one on demand or to answer that it cannot.
    #[must_use]
    pub fn new(fds: Vec<RawFd>, can_open: bool) -> Arc<Self> {
        let claimed = fds.iter().map(|_| AtomicBool::new(false)).collect();
        Arc::new(Self {
            fds,
            claimed,
            can_open,
        })
    }

    /// The pool's fds, in the order delegation hands them over.
    #[must_use]
    pub fn fds(&self) -> &[RawFd] {
        &self.fds
    }

    /// Pool size.
    #[must_use]
    pub fn len(&self) -> usize {
        self.fds.len()
    }

    /// Whether the warden pre-opened no socket at all (no `CAP_NET_RAW` at
    /// startup, or a deployment that never needed a pool).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fds.is_empty()
    }

    /// How many slots are claimed right now.
    #[must_use]
    pub fn held(&self) -> usize {
        self.claimed
            .iter()
            .filter(|c| c.load(Ordering::Relaxed))
            .count()
    }

    /// Whether this warden can open a capture socket itself.
    #[must_use]
    pub fn can_open_more(&self) -> bool {
        self.can_open
    }

    /// Claim the first free slot, or `None` when every socket is in use.
    #[must_use]
    pub fn claim(self: &Arc<Self>) -> Option<PcapSlot> {
        for (index, claimed) in self.claimed.iter().enumerate() {
            if claimed
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(PcapSlot {
                    fd: self.fds[index],
                    index,
                    slots: Arc::clone(self),
                });
            }
        }
        None
    }
}

/// A claimed slot. Returns itself to the pool on drop, which happens when the
/// connection thread holding it ends.
pub struct PcapSlot {
    fd: RawFd,
    index: usize,
    slots: Arc<PcapSlots>,
}

impl PcapSlot {
    /// The claimed socket's fd. The warden keeps its own copy open: the fd is
    /// dup'd into the agent by `SCM_RIGHTS`, so the agent closing its copy does
    /// not disturb this one.
    #[must_use]
    pub fn fd(&self) -> RawFd {
        self.fd
    }

    /// Which slot of the pool this is, for the log line.
    #[must_use]
    pub fn index(&self) -> usize {
        self.index
    }
}

impl Drop for PcapSlot {
    fn drop(&mut self) {
        self.slots.claimed[self.index].store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_pool_claims_nothing() {
        let slots = PcapSlots::new(Vec::new(), true);
        assert!(slots.is_empty());
        assert_eq!(slots.len(), 0);
        assert!(slots.claim().is_none());
    }

    #[test]
    fn every_slot_comes_back_when_the_holders_go() {
        let slots = PcapSlots::new(vec![10, 11, 12], false);

        let held: Vec<PcapSlot> = (0..3).filter_map(|_| slots.claim()).collect();
        assert_eq!(held.len(), 3, "a pool of three hands out three");
        assert_eq!(slots.held(), 3);
        assert!(
            slots.claim().is_none(),
            "a fourth claim finds every socket in use"
        );

        drop(held);
        assert_eq!(slots.held(), 0, "dropping the holders frees every slot");

        let again: Vec<PcapSlot> = (0..3).filter_map(|_| slots.claim()).collect();
        assert_eq!(
            again.len(),
            3,
            "the whole pool is claimable again after a restart"
        );
        let mut fds: Vec<RawFd> = again.iter().map(PcapSlot::fd).collect();
        fds.sort_unstable();
        assert_eq!(fds, vec![10, 11, 12], "and the same sockets come back");
    }

    #[test]
    fn a_slot_is_handed_out_once() {
        let slots = PcapSlots::new(vec![7, 8], true);
        let first = slots.claim().expect("first claim");
        let second = slots.claim().expect("second claim");
        assert_ne!(
            first.fd(),
            second.fd(),
            "two concurrent captures never share a socket"
        );
        assert_ne!(first.index(), second.index());
    }

    #[test]
    fn one_freed_slot_is_the_one_reused() {
        let slots = PcapSlots::new(vec![20, 21], true);
        let first = slots.claim().expect("first claim");
        let second = slots.claim().expect("second claim");
        let freed = second.fd();
        drop(second);
        assert_eq!(slots.held(), 1);
        let next = slots.claim().expect("the freed slot is claimable");
        assert_eq!(next.fd(), freed);
        assert_eq!(first.fd(), slots.fds()[0]);
    }

    #[test]
    fn the_fallback_is_remembered_as_given() {
        assert!(PcapSlots::new(vec![1], true).can_open_more());
        assert!(!PcapSlots::new(vec![1], false).can_open_more());
    }
}
