#![allow(unsafe_code)] // Required for eBPF RingBuf record parsing (read_unaligned)
//! Writing the quarantine map the workload hooks read, and reading what they
//! decided.
//!
//! Both maps come out of the workload firewall's object, which is where the
//! hooks that consult them are. That is the whole of the coupling: nothing
//! here knows about a rule, and the firewall's own maps are left in the object
//! for its own manager to take.
//!
//! The expiry written here is a boot-clock deadline rather than a duration,
//! because the kernel compares against `bpf_ktime_get_boot_ns` and this is the
//! only layer that can read the same clock. An entry therefore stops refusing
//! at the instant it was given, whether or not this process is still alive to
//! sweep it, and the sweep is bookkeeping rather than enforcement.

use std::sync::{Mutex, OnceLock};

use aya::maps::{HashMap as AyaHashMap, MapData, RingBuf};
use domain::common::error::DomainError;
use ebpf_common::quarantine::{QuarantineEntry, QuarantineEvent};
use ports::secondary::quarantine_map_port::QuarantineMapPort;
use tracing::{info, warn};

use crate::ebpf::map_store::MapStore;
use crate::ebpf::ringbuf_observer::boottime_now_ns;

/// What the agent can say about the quarantine capability, for the start-up log
/// and for the kernel-features endpoint.
///
/// There is no attach of its own to report: the hooks belong to the workload
/// firewall and are reported there. What this adds is the half a reader cannot
/// infer from the attach, since a node whose hooks are on may still be unable
/// to quarantine - the capability off in the document, or its maps absent from
/// an older object.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuarantineStatus {
    /// The maps are held and a quarantine can be armed.
    pub armed: bool,
    /// Why it is off, in one sentence. `None` when it is on.
    pub reason: Option<String>,
    /// How long a cgroup stays cut off before the arming lapses, in
    /// milliseconds, when a rule names no window of its own.
    pub window_ms: u64,
    /// Whether arming also tears down the flows the workload already holds.
    /// False means the workload keeps every connection it opened before.
    pub tears_down_flows: bool,
    /// How many cgroups are refused whatever a rule asks, the agent's own and
    /// the hierarchy root among them. Never zero on a running node.
    pub protected: usize,
}

/// The one status the whole process reports.
static STATUS: OnceLock<Mutex<QuarantineStatus>> = OnceLock::new();

fn status_cell() -> &'static Mutex<QuarantineStatus> {
    STATUS.get_or_init(|| Mutex::new(QuarantineStatus::default()))
}

/// Publish what the agent can say about the quarantine capability.
pub fn publish_status(status: QuarantineStatus) {
    let mut held = status_cell()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *held = status;
}

/// What the agent can currently say about the quarantine capability.
#[must_use]
pub fn status() -> QuarantineStatus {
    status_cell()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// Holds the two maps the quarantine service writes and reads.
pub struct QuarantineMapManager {
    cgroups: AyaHashMap<MapData, u64, QuarantineEntry>,
    events: RingBuf<MapData>,
}

impl QuarantineMapManager {
    /// Take the two maps out of a loaded workload firewall object.
    ///
    /// Both or neither. A manager missing the ring would cut workloads off and
    /// report nothing about what they then tried, which is most of the value
    /// of quarantining instead of killing.
    ///
    /// # Errors
    ///
    /// Returns an error when a map is missing from the object or carries
    /// another shape than the one declared here.
    pub fn new(ebpf: &mut dyn MapStore) -> Result<Self, anyhow::Error> {
        let cgroups = AyaHashMap::try_from(
            ebpf.take_map("QUARANTINE_CGROUPS")
                .ok_or_else(|| anyhow::anyhow!("map 'QUARANTINE_CGROUPS' not found"))?,
        )?;
        let events = RingBuf::try_from(
            ebpf.take_map("QUARANTINE_EVENTS")
                .ok_or_else(|| anyhow::anyhow!("map 'QUARANTINE_EVENTS' not found"))?,
        )?;
        info!("quarantine maps acquired");
        Ok(Self { cgroups, events })
    }
}

impl QuarantineMapPort for QuarantineMapManager {
    fn arm(&mut self, cgroup_id: u64, mode: u32, window_ns: u64) -> Result<(), DomainError> {
        let entry = QuarantineEntry {
            expires_at_ns: boottime_now_ns().saturating_add(window_ns),
            mode,
            _pad: 0,
        };
        self.cgroups
            .insert(cgroup_id, entry, 0)
            .map_err(|e| DomainError::EngineError(format!("QUARANTINE_CGROUPS insert failed: {e}")))
    }

    fn release(&mut self, cgroup_id: u64) -> Result<bool, DomainError> {
        // A missing key is a release of something that already expired or was
        // never armed, which the caller reports as such rather than as a
        // failure. Anything else is a map that would not answer, and a
        // quarantine nobody can lift is worth an error.
        match self.cgroups.get(&cgroup_id, 0) {
            Ok(_) => {}
            Err(_) => return Ok(false),
        }
        self.cgroups.remove(&cgroup_id).map_err(|e| {
            DomainError::EngineError(format!("QUARANTINE_CGROUPS remove failed: {e}"))
        })?;
        Ok(true)
    }

    fn entry(&self, cgroup_id: u64) -> Result<Option<QuarantineEntry>, DomainError> {
        Ok(self.cgroups.get(&cgroup_id, 0).ok())
    }

    fn entries(&self) -> Result<Vec<(u64, QuarantineEntry)>, DomainError> {
        let keys: Vec<u64> = self.cgroups.keys().filter_map(Result::ok).collect();
        let mut held = Vec::with_capacity(keys.len());
        for key in keys {
            // A key that went away between the walk and the read is a
            // quarantine that expired and was swept, not an error.
            if let Ok(entry) = self.cgroups.get(&key, 0) {
                held.push((key, entry));
            }
        }
        Ok(held)
    }

    fn sweep_expired(&mut self) -> Result<Vec<u64>, DomainError> {
        let now = boottime_now_ns();
        let expired: Vec<u64> = self
            .entries()?
            .into_iter()
            .filter(|(_, entry)| now >= entry.expires_at_ns)
            .map(|(key, _)| key)
            .collect();
        for key in &expired {
            if let Err(e) = self.cgroups.remove(key) {
                warn!(cgroup = key, "expired quarantine entry not removed: {e}");
            }
        }
        Ok(expired)
    }

    fn drain_events(&mut self) -> Result<Vec<QuarantineEvent>, DomainError> {
        let mut events = Vec::new();
        while let Some(item) = self.events.next() {
            let bytes: &[u8] = &item;
            if bytes.len() < size_of::<QuarantineEvent>() {
                warn!(len = bytes.len(), "short quarantine event discarded");
                continue;
            }
            // SAFETY: the length was checked against `size_of::<QuarantineEvent>()` above and
            // the type is `#[repr(C)]` integers only, so every bit pattern is a
            // value. The ring hands out a borrow of its own storage, whose
            // alignment is the record's and not this type's, hence `read_unaligned`.
            let event = unsafe { bytes.as_ptr().cast::<QuarantineEvent>().read_unaligned() };
            events.push(event);
        }
        Ok(events)
    }

    fn now_ns(&self) -> u64 {
        boottime_now_ns()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_refuses_an_object_without_the_quarantine_maps() {
        let mut store = crate::ebpf::map_store::TokenMaps::default();
        match QuarantineMapManager::new(&mut store) {
            Ok(_) => panic!("an object with no maps must not yield a manager"),
            Err(err) => assert!(err.to_string().contains("QUARANTINE_CGROUPS")),
        }
    }
}
