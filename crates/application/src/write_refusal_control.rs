//! The write refusal's mode, and what it would have refused while in shadow.
//!
//! The refusal starts in the mode its configuration names. In shadow it
//! refuses nothing and raises nothing: each write it would have refused is
//! counted by the workload of the writer, and the last few are kept as the
//! alert would have read, in the same shape the mass encryption verdict and
//! the host rules keep theirs. Putting it in force is a promotion made on
//! that reading, and a reading that started again since the caller looked
//! at it is refused rather than promoted on numbers nobody saw.

use std::sync::{Mutex, PoisonError};

use domain::hostrule::shadow::{HOST_RULE_SAME_READING_NS, PromotionRefused};
use domain::ransom::{RansomShadow, ShadowVerdict};
use tokio::sync::watch;

/// The mode both routes read, and the shadow reading.
#[derive(Debug)]
pub struct WriteRefusalControl {
    enforce: watch::Sender<bool>,
    since_ns: u64,
    shadow: Mutex<RansomShadow>,
}

impl WriteRefusalControl {
    /// A refusal in force when `enforce`, its reading starting at `since_ns`.
    #[must_use]
    pub fn new(enforce: bool, since_ns: u64) -> Self {
        Self {
            enforce: watch::Sender::new(enforce),
            since_ns,
            shadow: Mutex::new(RansomShadow::default()),
        }
    }

    /// Whether a write past the threshold is refused rather than counted.
    #[must_use]
    pub fn enforcing(&self) -> bool {
        *self.enforce.borrow()
    }

    /// The mode as a route follows it.
    #[must_use]
    pub fn follow(&self) -> watch::Receiver<bool> {
        self.enforce.subscribe()
    }

    /// When the reading started, boot-time nanoseconds.
    #[must_use]
    pub fn since_ns(&self) -> u64 {
        self.since_ns
    }

    /// Count a write the refusal would have refused.
    pub fn record(&self, verdict: ShadowVerdict) {
        self.shadow
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .record(verdict);
    }

    /// What it would have refused since the reading started.
    #[must_use]
    pub fn shadow(&self) -> RansomShadow {
        self.shadow
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Put the refusal in force on the reading that started at
    /// `seen_since_ns`, returning that reading as it stood.
    ///
    /// # Errors
    ///
    /// [`PromotionRefused::AlreadyInForce`] when it already refuses, and
    /// [`PromotionRefused::StaleReading`] when the reading the caller weighed
    /// is not this one.
    pub fn promote(&self, seen_since_ns: u64) -> Result<RansomShadow, PromotionRefused> {
        if self.enforcing() {
            return Err(PromotionRefused::AlreadyInForce);
        }
        if self.since_ns.abs_diff(seen_since_ns) >= HOST_RULE_SAME_READING_NS {
            return Err(PromotionRefused::StaleReading {
                since_ns: self.since_ns,
            });
        }
        let reading = self.shadow();
        self.enforce.send_replace(true);
        Ok(reading)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verdict(pid: u32, workload: &str) -> ShadowVerdict {
        ShadowVerdict {
            at_ns: u64::from(pid),
            pid,
            exe: Some("/usr/bin/tee".to_string()),
            workload: Some(workload.to_string()),
            message: "write refusal would refuse".to_string(),
        }
    }

    #[test]
    fn a_shadow_refusal_counts_by_workload_and_promotes_on_the_reading_it_was_weighed_on() {
        let control = WriteRefusalControl::new(false, 5_000_000);
        let follower = control.follow();
        control.record(verdict(1, "web"));
        control.record(verdict(2, "web"));
        control.record(verdict(3, "batch"));
        assert_eq!(control.shadow().recent.len(), 3);

        assert_eq!(
            control.promote(9_000_000),
            Err(PromotionRefused::StaleReading {
                since_ns: 5_000_000
            })
        );
        assert!(!control.enforcing());

        let reading = control.promote(5_000_400).expect("promoted");
        assert_eq!(reading.recent.len(), 3);
        assert!(control.enforcing());
        assert!(*follower.borrow());
        assert_eq!(
            control.promote(5_000_000),
            Err(PromotionRefused::AlreadyInForce)
        );
    }
}
