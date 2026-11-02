#![allow(unsafe_code)] // Required for eBPF RingBuf record parsing (read_unaligned)
//! Writing the maps the signal tracepoint reads, and reading what it did.
//!
//! The ordering here is the whole value of the type. A target becomes visible
//! only after the armed count says to look for one, and the count comes back
//! down only after the last target is gone, because the kernel's fast path is
//! that count: a target behind a zero count is a kill nobody takes, and a
//! count above zero with no target costs one hash lookup per syscall and
//! nothing else.
//!
//! The protected set is replaced rather than extended. A thread group id is
//! reused once the process holding it exits, so an id left behind is a new
//! process inheriting an immunity nobody granted it.

use std::os::fd::AsFd;

use aya::maps::{Array, HashMap as AyaHashMap, IterableMap, MapData, RingBuf};
use domain::common::error::DomainError;
use ebpf_common::signal::{SIGNAL_ARMED_SLOT, SignalEvent, SignalTarget};
use ports::secondary::process_signal_map_port::ProcessSignalMapPort;
use tracing::{info, warn};

use crate::ebpf::map_batch::map_fd;
use crate::ebpf::map_store::MapStore;
use crate::ebpf::ringbuf_observer::boottime_now_ns;
use crate::ebpf::signal_task::{DirectOutcome, DirectSignal, DirectSignalProbe};
use ebpf_common::signal::{
    SIGNAL_OUTCOME_HELPER_FAILED, SIGNAL_OUTCOME_PROTECTED, SIGNAL_OUTCOME_SENT,
};

/// Holds the four maps the service writes and reads.
pub struct SignalMapManager {
    armed: Array<MapData, u64>,
    targets: AyaHashMap<MapData, u32, SignalTarget>,
    protected: AyaHashMap<MapData, u32, u8>,
    events: RingBuf<MapData>,
    /// The program that signals at once, where the kernel offers it.
    direct: Option<DirectSignal>,
    /// What the kernel answered when that program was offered to it.
    direct_probe: DirectSignalProbe,
    /// Outcomes of signals sent at once, which no ring carries.
    settled: Vec<SignalEvent>,
}

impl SignalMapManager {
    /// Take the four maps out of a loaded signal object.
    ///
    /// All four or none. A manager missing the ring would arm kills whose
    /// outcome nobody could read, and one missing the protected map would arm
    /// them with the kernel's own fence absent. The counters are left in the
    /// object for the agent's metrics loop to take, after this has read them:
    /// the program that signals at once counts in the same slots.
    ///
    /// # Errors
    ///
    /// Returns an error when a map is missing from the object or carries
    /// another shape than the one declared here.
    pub fn new(ebpf: &mut dyn MapStore) -> Result<Self, anyhow::Error> {
        let armed = Array::try_from(
            ebpf.take_map("SIGNAL_ARMED")
                .ok_or_else(|| anyhow::anyhow!("map 'SIGNAL_ARMED' not found"))?,
        )?;
        let targets = AyaHashMap::try_from(
            ebpf.take_map("SIGNAL_TARGETS")
                .ok_or_else(|| anyhow::anyhow!("map 'SIGNAL_TARGETS' not found"))?,
        )?;
        let protected = AyaHashMap::try_from(
            ebpf.take_map("SIGNAL_PROTECTED")
                .ok_or_else(|| anyhow::anyhow!("map 'SIGNAL_PROTECTED' not found"))?,
        )?;
        let events = RingBuf::try_from(
            ebpf.take_map("SIGNAL_EVENTS")
                .ok_or_else(|| anyhow::anyhow!("map 'SIGNAL_EVENTS' not found"))?,
        )?;
        let metrics = ebpf
            .map("SIGNAL_METRICS")
            .and_then(map_fd)
            .ok_or_else(|| anyhow::anyhow!("map 'SIGNAL_METRICS' not found"))?;
        let protected_fd = protected.map().fd().as_fd();
        let (direct, direct_probe) = match DirectSignal::load(protected_fd, metrics) {
            Ok(direct) => (
                Some(direct),
                DirectSignalProbe {
                    declared: Some(true),
                    loaded: true,
                    reason: None,
                },
            ),
            Err(probe) => {
                info!(
                    reason = probe.reason.as_deref().unwrap_or_default(),
                    "a signal waits for its target's next syscall"
                );
                (None, probe)
            }
        };
        info!("signal maps acquired");
        Ok(Self {
            armed,
            targets,
            protected,
            events,
            direct,
            direct_probe,
            settled: Vec::new(),
        })
    }

    /// What the kernel answered when the program that signals at once was
    /// offered to it.
    #[must_use]
    pub fn immediate(&self) -> &DirectSignalProbe {
        &self.direct_probe
    }

    /// Signal at once where the kernel offers it. `true` when the signal is
    /// settled, sent or refused, and its outcome queued for the next drain;
    /// `false` when the syscall-entry path has to carry it.
    fn signal_now(&mut self, tgid: u32, signal: u32) -> bool {
        let Some(direct) = self.direct.as_ref() else {
            return false;
        };
        let outcome = match direct.signal(tgid, signal) {
            Ok(DirectOutcome::Sent) => SIGNAL_OUTCOME_SENT,
            Ok(DirectOutcome::Protected) => SIGNAL_OUTCOME_PROTECTED,
            Ok(DirectOutcome::HelperFailed) => SIGNAL_OUTCOME_HELPER_FAILED,
            // No task by that id now: armed, the target expires in the kernel
            // and is reported as every expiry is.
            Ok(DirectOutcome::Gone) => return false,
            Err(e) => {
                warn!(
                    tgid,
                    "the immediate signal did not run, arming the syscall path: {e}"
                );
                return false;
            }
        };
        self.settled.push(SignalEvent {
            at_ns: boottime_now_ns(),
            tgid,
            signal,
            outcome,
            _pad: 0,
        });
        true
    }

    /// Write the armed count the kernel reads before anything else.
    fn set_armed(&mut self, count: u64) -> Result<(), DomainError> {
        self.armed
            .set(SIGNAL_ARMED_SLOT, &count, 0)
            .map_err(|e| DomainError::EngineError(format!("SIGNAL_ARMED write failed: {e}")))
    }

    /// How many targets are in the map right now.
    ///
    /// Counted by walking the keys rather than kept as a field, because the
    /// kernel removes an entry itself the moment it acts on one and a cached
    /// figure would drift the wrong way.
    fn count_targets(&self) -> u64 {
        self.targets.keys().filter_map(Result::ok).count() as u64
    }
}

impl ProcessSignalMapPort for SignalMapManager {
    fn set_protected(&mut self, tgids: &[u32]) -> Result<(), DomainError> {
        let existing: Vec<u32> = self.protected.keys().filter_map(Result::ok).collect();
        for tgid in existing {
            if !tgids.contains(&tgid) {
                let _ = self.protected.remove(&tgid);
            }
        }
        for tgid in tgids {
            self.protected.insert(tgid, &1u8, 0).map_err(|e| {
                DomainError::EngineError(format!("SIGNAL_PROTECTED insert failed: {e}"))
            })?;
        }
        info!(count = tgids.len(), "signal protected set published");
        Ok(())
    }

    fn arm(&mut self, tgid: u32, signal: u32, window_ns: u64) -> Result<(), DomainError> {
        if self.signal_now(tgid, signal) {
            return Ok(());
        }
        // The count goes up first: the kernel reads it as its fast path, so a
        // target inserted behind a zero is a target nothing looks for.
        self.set_armed(self.count_targets() + 1)?;
        let target = SignalTarget {
            expires_at_ns: boottime_now_ns().saturating_add(window_ns),
            signal,
            _pad: 0,
        };
        if let Err(e) = self.targets.insert(&tgid, &target, 0) {
            // Put the count back where the map actually is, so a refused
            // insert does not leave every syscall on the node paying for a
            // lookup that can never match.
            let _ = self.set_armed(self.count_targets());
            return Err(DomainError::EngineError(format!(
                "SIGNAL_TARGETS insert failed: {e}"
            )));
        }
        Ok(())
    }

    fn disarm(&mut self, tgid: u32) -> Result<(), DomainError> {
        // ENOENT is the ordinary case: the kernel removes the entry itself as
        // soon as it signals, and the caller disarms on its way out of every
        // decision rather than asking first.
        let _ = self.targets.remove(&tgid);
        self.set_armed(self.count_targets())
    }

    fn drain_events(&mut self) -> Result<Vec<SignalEvent>, DomainError> {
        let mut events = std::mem::take(&mut self.settled);
        while let Some(item) = self.events.next() {
            let bytes: &[u8] = &item;
            if bytes.len() < size_of::<SignalEvent>() {
                warn!(len = bytes.len(), "short signal event discarded");
                continue;
            }
            // SAFETY: the length was checked against `size_of::<SignalEvent>()` above and
            // the type is `#[repr(C)]` integers only, so every bit pattern is a
            // value. The ring hands out a borrow of its own storage, whose
            // alignment is the record's and not this type's, hence `read_unaligned`.
            let event = unsafe { bytes.as_ptr().cast::<SignalEvent>().read_unaligned() };
            events.push(event);
        }
        Ok(events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_refuses_an_object_without_the_signal_maps() {
        let mut store = crate::ebpf::map_store::TokenMaps::default();
        match SignalMapManager::new(&mut store) {
            Ok(_) => panic!("an object with no maps must not yield a manager"),
            Err(err) => assert!(err.to_string().contains("SIGNAL_ARMED")),
        }
    }
}
