#![allow(unsafe_code)] // Raw bpf() syscall for BPF_MAP_FREEZE.

//! `BPF_MAP_FREEZE` for the maps written once at load and only read after.
//!
//! A map carrying facts the kernel itself supplied - BTF member offsets a
//! program built without CO-RE cannot resolve on its own - is written once
//! before anything attaches and never again. Freezing it makes every later
//! write from userspace fail at the syscall, which turns a bug into an error
//! where the bug is rather than into a datapath reading its fields at offsets
//! nothing in the configuration asked for.
//!
//! Three maps qualify, listed in [`WRITE_ONCE_MAPS`]. Everything else stays
//! writable on purpose and is listed in [`NOT_FROZEN`] with the reason, so the
//! question "why is this one not frozen" has an answer in the tree rather than
//! in somebody's memory.
//!
//! The maps are pinned and shared between objects, so the same offset map is
//! reached by two programs loaded one after the other. The second load finds
//! it frozen, which is why [`is_frozen`] exists: a writer consults it, reads
//! the value back and compares rather than writing again. Within one process
//! those values cannot have changed, since they are a reading of the running
//! kernel.
//!
//! The freeze itself is best effort. `bpf(2)` refuses it on a kernel that
//! wants `CAP_BPF` for the command from a process that holds a BPF token and
//! no capability, and that refusal costs nothing but the protection: it is
//! counted and logged with the map named, never silent.

use std::collections::BTreeSet;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use aya::maps::Map;
use thiserror::Error;
use tracing::{debug, info, warn};

use super::map_store::MapStore;

/// `bpf(2)` command.
const BPF_MAP_FREEZE: u32 = 22;

/// Subset of `union bpf_attr` for `BPF_MAP_FREEZE`: the map fd and nothing
/// else, which is also where the kernel's last field for this command sits.
#[repr(C)]
#[derive(Default)]
struct MapFreezeAttr {
    map_fd: u32,
}

/// A map written once at load, with what it carries.
pub struct WriteOnceMap {
    /// ELF name of the map.
    pub name: &'static str,
    /// What is written into it, and why that write happens exactly once.
    pub carries: &'static str,
}

/// The maps frozen after initialisation.
///
/// Each one holds a reading of the running kernel taken before the programs
/// that consume it attach. The reading cannot change while the process lives,
/// so a second write is a bug by construction.
pub const WRITE_ONCE_MAPS: &[WriteOnceMap] = &[
    WriteOnceMap {
        name: "CT_NF_CONN_OFFSETS",
        carries: "nf_conn member offsets resolved from the running kernel's BTF",
    },
    WriteOnceMap {
        name: "KTLS_ITER_OFFSETS",
        carries: "msghdr and iov_iter member offsets resolved from the running kernel's BTF",
    },
    WriteOnceMap {
        name: "SOCK_OFFSETS",
        carries: "sock_common member offsets resolved from the running kernel's BTF",
    },
];

/// The maps deliberately left writable, one per reason, with the reason.
///
/// This is the answer to "freeze the read-only maps": almost none of them are
/// read-only. A configuration reload, a feed refresh, an API call and the
/// datapath itself all write maps while the agent runs, and freezing any of
/// these would turn the next reload into a failure rather than a change.
pub const NOT_FROZEN: &[(&str, &str)] = &[
    (
        "CONFIG_FLAGS",
        "every configuration reload rewrites the feature flags the programs branch on",
    ),
    (
        "CT_CONFIG",
        "the conntrack ceilings follow the configuration and change with it",
    ),
    (
        "DDOS_SYN_CONFIG",
        "the SYN thresholds follow the configuration and change with it",
    ),
    (
        "QOS_PIPE_CONFIG",
        "a shaper is reprogrammed whenever a pipe's rate changes",
    ),
    (
        "RL_TIER_CONFIG",
        "the country tiers are rewritten when the GeoIP tier table reloads",
    ),
    (
        "FW_HASH_5TUPLE",
        "the rule tables are rewritten on every reload and every rule API call",
    ),
    (
        "THREATINTEL_IOCS",
        "a feed refresh replaces the indicators without reloading the program",
    ),
    (
        "IPS_BLACKLIST",
        "an automated response writes a block from the datapath's own alerts",
    ),
    (
        "XDP_PROG_ARRAY",
        "the tail-call slots are rewired whenever the chain changes shape",
    ),
    (
        "FIREWALL_METRICS",
        "the programs write their counters here, and freezing is about writes from userspace only",
    ),
];

/// What freezing produced for one object.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct FreezeReport {
    /// Maps this call froze.
    pub frozen: usize,
    /// Maps the kernel refused to freeze.
    pub refused: usize,
}

/// Failure of a single freeze.
#[derive(Debug, Error)]
pub enum FreezeError {
    /// The object does not carry the map, which is ordinary: an object built
    /// without the kernel TLS probes has no offsets map to freeze.
    #[error("map `{0}` is not in this object")]
    Absent(String),
    /// The map is of a kind this does not reach an fd for.
    #[error("map `{0}` is of a kind with no file descriptor to freeze")]
    Unsupported(String),
    /// `bpf(2)` refused the command.
    #[error("BPF_MAP_FREEZE on `{map}` failed: {message}")]
    Syscall {
        /// ELF name of the map.
        map: String,
        /// `errno` the kernel returned.
        errno: i32,
        /// Its text.
        message: String,
    },
}

/// Names of the maps frozen in this process.
fn registry() -> &'static Mutex<BTreeSet<&'static str>> {
    static REGISTRY: OnceLock<Mutex<BTreeSet<&'static str>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(BTreeSet::new()))
}

/// How many freezes the kernel refused, for the whole life of the process.
static REFUSALS: AtomicU64 = AtomicU64::new(0);

/// Whether the named map was frozen in this process.
///
/// A writer calls this before writing a write-once map: a second object
/// sharing the pinned map finds it frozen and has nothing left to write.
#[must_use]
pub fn is_frozen(name: &str) -> bool {
    registry().lock().is_ok_and(|names| names.contains(name))
}

/// The maps frozen so far, in name order.
#[must_use]
pub fn frozen_maps() -> Vec<&'static str> {
    registry()
        .lock()
        .map(|names| names.iter().copied().collect())
        .unwrap_or_default()
}

/// How many freezes the kernel refused.
#[must_use]
pub fn refusals() -> u64 {
    REFUSALS.load(Ordering::Relaxed)
}

/// The entry in [`WRITE_ONCE_MAPS`] for a name, if it has one.
fn write_once_entry(name: &str) -> Option<&'static WriteOnceMap> {
    WRITE_ONCE_MAPS.iter().find(|m| m.name == name)
}

/// The file descriptor behind a map, for the kinds a write-once map can be.
fn map_fd(map: &Map) -> Option<BorrowedFd<'_>> {
    match map {
        Map::Array(data) | Map::PerCpuArray(data) | Map::HashMap(data) => Some(data.fd().as_fd()),
        _ => None,
    }
}

/// Freeze the named map of this object, if it is one of the write-once maps.
///
/// Returns `true` when the map ends up frozen, which includes the map having
/// been frozen already by another object sharing the same pinned map. A
/// refusal is counted and logged here rather than returned, because the caller
/// has just finished writing the map and has nothing to undo: the protection
/// is absent and the agent carries on.
pub fn freeze_after_init(ebpf: &dyn MapStore, name: &str) -> bool {
    match freeze(ebpf, name) {
        Ok(()) => true,
        Err(FreezeError::Absent(_)) => false,
        Err(e) => {
            REFUSALS.fetch_add(1, Ordering::Relaxed);
            warn!(map = name, error = %e, "map left writable: the kernel refused to freeze it");
            false
        }
    }
}

/// Freeze the named map of this object.
///
/// # Errors
///
/// Returns [`FreezeError::Absent`] when the object does not carry the map,
/// [`FreezeError::Unsupported`] for a map kind with no reachable descriptor,
/// and [`FreezeError::Syscall`] when `bpf(2)` refused the command.
pub fn freeze(ebpf: &dyn MapStore, name: &str) -> Result<(), FreezeError> {
    let Some(entry) = write_once_entry(name) else {
        return Err(FreezeError::Unsupported(name.to_owned()));
    };
    if is_frozen(name) {
        return Ok(());
    }
    let map = ebpf
        .map(name)
        .ok_or_else(|| FreezeError::Absent(name.to_owned()))?;
    let fd = map_fd(map).ok_or_else(|| FreezeError::Unsupported(name.to_owned()))?;
    freeze_fd(name, fd)?;
    if let Ok(mut names) = registry().lock() {
        names.insert(entry.name);
    }
    info!(
        map = entry.name,
        carries = entry.carries,
        "map frozen after initialisation"
    );
    Ok(())
}

/// Write a write-once value into its map and freeze the map behind it.
///
/// The maps here are pinned and shared, so the second object to load finds the
/// map the first one already wrote and froze. That is the normal case rather
/// than an error: the value is a reading of the running kernel, so it is read
/// back and compared instead of written again, and only a reading that
/// disagrees with itself is worth a failure.
///
/// # Errors
///
/// Returns an error if the object does not carry the map, if the write fails,
/// or if a frozen map holds a different value from the one being pushed.
pub fn push_once<V>(ebpf: &mut dyn MapStore, name: &str, value: V) -> anyhow::Result<()>
where
    V: aya::Pod + PartialEq + std::fmt::Debug,
{
    if is_frozen(name) {
        let map = ebpf
            .map(name)
            .ok_or_else(|| anyhow::anyhow!("{name} map not found"))?;
        let held = aya::maps::Array::<_, V>::try_from(map)?.get(&0, 0)?;
        anyhow::ensure!(
            held == value,
            "{name} is frozen and holds {held:?}, which is not the {value:?} being pushed"
        );
        debug!(map = name, "map already frozen with the same value");
        return Ok(());
    }
    let map = ebpf
        .map_mut(name)
        .ok_or_else(|| anyhow::anyhow!("{name} map not found"))?;
    aya::maps::Array::<_, V>::try_from(map)?.set(0, value, 0)?;
    freeze_after_init(ebpf, name);
    Ok(())
}

/// Issue `BPF_MAP_FREEZE` on a descriptor.
///
/// `EBUSY` is the kernel saying the map is already frozen, which is the same
/// outcome this asks for, so it is not an error.
fn freeze_fd(name: &str, fd: BorrowedFd<'_>) -> Result<(), FreezeError> {
    let mut attr = MapFreezeAttr {
        #[allow(clippy::cast_sign_loss)]
        map_fd: fd.as_raw_fd() as u32,
    };
    // SAFETY: `attr` is a live `#[repr(C)]` local of exactly the size passed, laid out as the
    // union member the kernel reads for this command; every pointer it carries names a buffer
    // that outlives the call.
    let rc = unsafe {
        super::kfunc_attach::bpf(
            BPF_MAP_FREEZE,
            (&raw mut attr).cast(),
            std::mem::size_of::<MapFreezeAttr>(),
        )
    };
    if rc < 0 {
        let err = io::Error::last_os_error();
        let errno = err.raw_os_error().unwrap_or(0);
        if errno == libc::EBUSY {
            debug!(map = name, "map was already frozen");
            return Ok(());
        }
        return Err(FreezeError::Syscall {
            map: name.to_owned(),
            errno,
            message: err.to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_freeze_attr_is_the_one_field_the_kernel_reads() {
        assert_eq!(std::mem::size_of::<MapFreezeAttr>(), 4);
        assert_eq!(std::mem::offset_of!(MapFreezeAttr, map_fd), 0);
    }

    #[test]
    fn every_write_once_map_says_what_it_carries() {
        for map in WRITE_ONCE_MAPS {
            assert!(!map.name.is_empty());
            assert!(
                map.carries.len() > 20,
                "{} carries no explanation",
                map.name
            );
        }
    }

    #[test]
    fn every_writable_map_says_why_it_stays_writable() {
        for (name, reason) in NOT_FROZEN {
            assert!(!name.is_empty());
            assert!(reason.len() > 20, "{name} is listed with no reason");
            assert!(
                write_once_entry(name).is_none(),
                "{name} is listed as both frozen and writable"
            );
        }
    }

    #[test]
    fn a_map_outside_the_list_is_never_frozen_by_accident() {
        assert!(write_once_entry("CONFIG_FLAGS").is_none());
        assert!(write_once_entry("SOCK_OFFSETS").is_some());
    }

    #[test]
    fn an_unfrozen_map_reads_as_unfrozen() {
        assert!(!is_frozen("A_MAP_NOTHING_EVER_FROZE"));
    }
}
