#![allow(unsafe_code)] // mmap pointer reads for zero-copy arena metrics.

//! Arena-backed metrics reader — zero-copy alternative to `PerCpuArray`
//! map iteration for reading BPF program counters.
//!
//! Layout: the arena's first page contains `N` u64 counters at
//! known offsets. BPF programs write via atomic add; userspace reads
//! via volatile pointer deref through the mmap'd region (~50ns vs
//! ~5µs for `PerCpuArray` iteration).
//!
//! This module provides the userspace reader. The BPF writer side
//! is blocked on aya Arena map type support — programs currently
//! continue using `PerCpuArray` for metrics.

use super::arena::ArenaMap;

/// Shared arena metrics layout: `MAX_COUNTERS` u64 counters packed
/// at the start of the arena. Each counter is at offset
/// `index * 8` bytes.
pub const MAX_ARENA_COUNTERS: usize = 512;
/// Size in bytes needed for the metrics counters (512 * 8 = 4096 = 1 page).
pub const ARENA_METRICS_SIZE: usize = MAX_ARENA_COUNTERS * core::mem::size_of::<u64>();

/// Reads u64 metric counters from an arena mmap'd region.
///
/// BPF programs write counters via atomic add at known offsets.
/// Userspace reads them via volatile pointer deref — zero-copy,
/// no syscall, ~50ns per read.
pub struct ArenaMetricsReader {
    arena: ArenaMap,
}

impl ArenaMetricsReader {
    /// Create a metrics reader backed by the given arena.
    /// The arena must have at least 1 page (4096 bytes).
    pub fn new(arena: ArenaMap) -> Self {
        debug_assert!(arena.size() >= ARENA_METRICS_SIZE);
        Self { arena }
    }

    /// Read counter at `index`. Returns 0 if index is out of range.
    #[inline]
    pub fn read_counter(&self, index: usize) -> u64 {
        if index >= MAX_ARENA_COUNTERS {
            return 0;
        }
        unsafe { self.arena.read_at::<u64>(index * 8) }
    }

    /// Read all counters up to `count` into a Vec.
    pub fn read_all(&self, count: usize) -> Vec<u64> {
        let n = count.min(MAX_ARENA_COUNTERS);
        (0..n).map(|i| self.read_counter(i)).collect()
    }

    /// Snapshot counters 0..count as (index, value) pairs,
    /// filtering out zero values.
    pub fn non_zero_counters(&self, count: usize) -> Vec<(usize, u64)> {
        let n = count.min(MAX_ARENA_COUNTERS);
        (0..n)
            .filter_map(|i| {
                let v = self.read_counter(i);
                if v > 0 { Some((i, v)) } else { None }
            })
            .collect()
    }
}

/// Create an arena suitable for metrics counters (1 page = 512 u64).
/// Returns `None` if arena maps are not supported.
pub fn create_metrics_arena(name: &str) -> Option<ArenaMap> {
    ArenaMap::create(1, name).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_counter_from_empty_arena() {
        let arena = match ArenaMap::create(1, "metrics_test") {
            Ok(a) => a,
            Err(_) => {
                eprintln!("skip: no CAP_BPF");
                return;
            }
        };
        let reader = ArenaMetricsReader::new(arena);
        // Freshly created arena is zeroed.
        assert_eq!(reader.read_counter(0), 0);
        assert_eq!(reader.read_counter(511), 0);
        assert_eq!(reader.read_counter(512), 0); // out of range → 0
    }

    #[test]
    fn write_then_read_counter() {
        let arena = match ArenaMap::create(1, "metrics_test2") {
            Ok(a) => a,
            Err(_) => {
                eprintln!("skip: no CAP_BPF");
                return;
            }
        };

        // Simulate BPF atomic write at counter index 7.
        unsafe { arena.write_at::<u64>(7 * 8, 42) };
        unsafe { arena.write_at::<u64>(100 * 8, 999) };

        let reader = ArenaMetricsReader::new(arena);
        assert_eq!(reader.read_counter(7), 42);
        assert_eq!(reader.read_counter(100), 999);
        assert_eq!(reader.read_counter(0), 0);
    }

    #[test]
    fn read_all_returns_correct_count() {
        let arena = match ArenaMap::create(1, "metrics_test3") {
            Ok(a) => a,
            Err(_) => {
                eprintln!("skip: no CAP_BPF");
                return;
            }
        };
        unsafe { arena.write_at::<u64>(0, 10) };
        unsafe { arena.write_at::<u64>(8, 20) };
        unsafe { arena.write_at::<u64>(16, 30) };

        let reader = ArenaMetricsReader::new(arena);
        let vals = reader.read_all(3);
        assert_eq!(vals, vec![10, 20, 30]);
    }

    #[test]
    fn non_zero_counters_filters_zeros() {
        let arena = match ArenaMap::create(1, "metrics_test4") {
            Ok(a) => a,
            Err(_) => {
                eprintln!("skip: no CAP_BPF");
                return;
            }
        };
        unsafe { arena.write_at::<u64>(2 * 8, 100) };
        unsafe { arena.write_at::<u64>(5 * 8, 200) };

        let reader = ArenaMetricsReader::new(arena);
        let nz = reader.non_zero_counters(10);
        assert_eq!(nz, vec![(2, 100), (5, 200)]);
    }
}
