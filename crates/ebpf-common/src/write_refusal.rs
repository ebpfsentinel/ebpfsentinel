//! A write refused in the kernel, past a count of write-opens.
//!
//! The program decides a write-open, or a truncation by path, under a watched
//! directory: it counts it against the writer, the thread group or the
//! cgroup as configured, inside a window, and the open that reaches the
//! threshold is refused. A watched path is in one of two regimes: a data
//! path is refused at the threshold, a system path at the first write by an
//! executable not on the expected list, because a write there is anomalous
//! once. What is shared here is the layout both sides read
//! and [`write_refusal_step`], the decision itself, which the program calls
//! and the tests exercise without a kernel.

/// `mode` in the configuration slot: count and report, refuse nothing.
pub const WRITE_REFUSAL_MODE_SHADOW: u32 = 0;
/// `mode` in the configuration slot: refuse the write-open that reaches the
/// threshold, and every one after it inside the window.
pub const WRITE_REFUSAL_MODE_ENFORCE: u32 = 1;

/// `count_by` in the configuration slot: one counter per thread group.
pub const WRITE_REFUSAL_BY_PROCESS: u32 = 0;
/// `count_by` in the configuration slot: one counter per cgroup, so the
/// workers a run forks share the count of the process that forked them.
pub const WRITE_REFUSAL_BY_CGROUP: u32 = 1;

/// Value of a watched path in `WRITE_REFUSAL_DIRS`: a data path, refused at
/// the threshold.
pub const WRITE_REFUSAL_REGIME_DATA: u8 = 0;
/// Value of a watched path in `WRITE_REFUSAL_DIRS`: a system path, refused at
/// the first write by an executable not on the expected list.
pub const WRITE_REFUSAL_REGIME_SYSTEM: u8 = 1;
/// How many executables the expected writers of the system paths hold.
pub const WRITE_REFUSAL_MAX_EXPECTED_WRITERS: u32 = 256;
/// Bit set on a writer's counter key for the system regime, so a process
/// counted against a data path and refused on a system path keeps two
/// counts that never meet. Neither a thread group nor a cgroup id reaches it.
pub const WRITE_REFUSAL_SYSTEM_KEY_BIT: u64 = 1 << 63;
/// Index of the single slot in `WRITE_REFUSAL_CONFIG`.
pub const WRITE_REFUSAL_CONFIG_SLOT: u32 = 0;

/// How many directories the watched set holds. A key is a directory, and
/// everything beneath it is watched, so the set names data roots rather
/// than files.
pub const WRITE_REFUSAL_MAX_DIRECTORIES: u32 = 256;

/// How many parents the program walks up from the opened file looking for a
/// watched directory. A file deeper than this below its watched root is not
/// decided, and is counted as such.
pub const WRITE_REFUSAL_MAX_DEPTH: u32 = 16;

/// How many writers are counted at once. The map is a plain hash sized here,
/// and a writer arriving once it is full is let through and counted: the
/// refusal fails open, never closed. Userspace removes the writers whose
/// window has passed.
pub const WRITE_REFUSAL_MAX_WRITERS: u32 = 16_384;

/// Capacity of `WRITE_REFUSAL_EVENTS`, in bytes. One record per writer and
/// window is written, so a node fills a fraction of this.
pub const WRITE_REFUSAL_EVENTS_RINGBUF_BYTES: u32 = 64 * 1024;

/// Bytes of the file's own name a record carries.
pub const WRITE_REFUSAL_NAME_BYTES: usize = 48;

/// `hook` on a record: a write-open.
pub const WRITE_REFUSAL_HOOK_OPEN: u8 = 0;
/// `hook` on a record: a truncation by path.
pub const WRITE_REFUSAL_HOOK_TRUNCATE: u8 = 1;

/// `FMODE_WRITE`, the bit of `file.f_mode` a write-open carries.
pub const WRITE_REFUSAL_FMODE_WRITE: u32 = 0x2;

/// What the hook returns to refuse: `-EACCES`, which every program already
/// handles from `open`.
pub const WRITE_REFUSAL_REFUSAL: i32 = -13;

/// Metric index: write-opens and truncations the hooks looked at.
pub const WRITE_REFUSAL_METRIC_CHECKED: u32 = 0;
/// Metric index: of those, the ones under a watched directory, counted.
pub const WRITE_REFUSAL_METRIC_WATCHED: u32 = 1;
/// Metric index: writes the kernel refused.
pub const WRITE_REFUSAL_METRIC_REFUSED: u32 = 2;
/// Metric index: writes a shadow program would have refused.
pub const WRITE_REFUSAL_METRIC_WOULD_REFUSE: u32 = 3;
/// Metric index: writes whose directory chain could not be read, or ran
/// deeper than [`WRITE_REFUSAL_MAX_DEPTH`], let through undecided.
pub const WRITE_REFUSAL_METRIC_UNRESOLVED: u32 = 4;
/// Metric index: writers let through because the counter map was full.
pub const WRITE_REFUSAL_METRIC_TABLE_FULL: u32 = 5;
/// Metric index: records the ring buffer had no room for. The decision is
/// taken whatever happens to the record.
pub const WRITE_REFUSAL_METRIC_EVENT_LOST: u32 = 6;
/// Metric index: writes on a system path by an expected executable, or by
/// the kernel itself, let through.
pub const WRITE_REFUSAL_METRIC_EXPECTED: u32 = 7;
/// How many counters the metrics array holds.
pub const WRITE_REFUSAL_METRIC_COUNT: u32 = 8;

/// One watched directory, as the kernel names it. `dev` is the kernel's own
/// encoding, see [`crate::exec_network::kernel_dev`].
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct WriteRefusalDir {
    pub ino: u64,
    pub dev: u32,
    pub _pad: u32,
}

/// One writer's count inside its window.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WriteRefusalCount {
    /// `bpf_ktime_get_boot_ns` at the first write of the window.
    pub window_start_ns: u64,
    /// Writes counted in the window, the current one included.
    pub count: u32,
    /// Non-zero once this window was reported.
    pub reported: u32,
}

/// The configuration slot: the decision's parameters, and the offsets the
/// hooks walk from a file to its directories, read from the running
/// kernel's BTF.
///
/// `valid` stays zero until userspace has written a complete slot, and a
/// hook reading an invalid slot lets every write through: the program is
/// attached before the slot is written.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WriteRefusalConfig {
    /// Length of a counting window.
    pub window_ns: u64,
    /// The write-open that brings the count to this is the first refused.
    pub threshold: u32,
    /// `WRITE_REFUSAL_MODE_*`.
    pub mode: u32,
    /// `WRITE_REFUSAL_BY_*`.
    pub count_by: u32,
    /// The agent's own thread group, never counted.
    pub agent_tgid: u32,
    /// `file.f_mode`
    pub file_mode: u32,
    /// `file.f_path`
    pub file_path: u32,
    /// `path.dentry`
    pub path_dentry: u32,
    /// `dentry.d_parent`
    pub dentry_parent: u32,
    /// `dentry.d_inode`
    pub dentry_inode: u32,
    /// `dentry.d_name` plus `qstr.name`: the pointer to the name.
    pub dentry_name: u32,
    /// `inode.i_ino`
    pub inode_ino: u32,
    /// `inode.i_sb`
    pub inode_sb: u32,
    /// `super_block.s_dev`
    pub sb_dev: u32,
    /// `task_struct.mm`
    pub task_mm: u32,
    /// `mm_struct.exe_file`
    pub mm_exe_file: u32,
    /// `file.f_inode`
    pub file_inode: u32,
    pub _pad: u32,
    /// Non-zero once the slot is complete.
    pub valid: u32,
}

/// A writer that reached the threshold, as the kernel reports it, once per
/// writer and window.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteRefusalEvent {
    /// `bpf_ktime_get_boot_ns` at the decision.
    pub at_ns: u64,
    /// The writer's cgroup.
    pub cgroup_id: u64,
    /// Inode of the file written.
    pub file_ino: u64,
    /// Inode of the watched directory it lies under.
    pub dir_ino: u64,
    /// Thread group that wrote.
    pub tgid: u32,
    /// Kernel encoding of the file's device.
    pub file_dev: u32,
    /// Kernel encoding of the watched directory's device.
    pub dir_dev: u32,
    /// The count that reached the threshold.
    pub count: u32,
    /// `WRITE_REFUSAL_HOOK_*`.
    pub hook: u8,
    /// Non-zero when the kernel refused the write rather than counted it.
    pub refused: u8,
    /// `WRITE_REFUSAL_REGIME_*` of the watched path.
    pub regime: u8,
    pub _pad: [u8; 5],
    /// The file's own name, NUL-terminated or cut.
    pub name: [u8; WRITE_REFUSAL_NAME_BYTES],
}

impl Default for WriteRefusalEvent {
    fn default() -> Self {
        Self {
            at_ns: 0,
            cgroup_id: 0,
            file_ino: 0,
            dir_ino: 0,
            tgid: 0,
            file_dev: 0,
            dir_dev: 0,
            count: 0,
            hook: 0,
            refused: 0,
            regime: 0,
            _pad: [0; 5],
            name: [0; WRITE_REFUSAL_NAME_BYTES],
        }
    }
}

/// What one more write does to a writer's count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteRefusalStep {
    /// The count to store.
    pub next: WriteRefusalCount,
    /// The write reaches the threshold: refused in force, counted in shadow.
    pub over: bool,
    /// This is the first write over the threshold in the window, the one a
    /// record is written for.
    pub report: bool,
}

/// Count one write against `previous`, the writer's count or `None` for a
/// writer not seen yet.
///
/// A window opens at a writer's first write and lasts `window_ns`; a write
/// after it opens a new one at a count of one. The write that brings the
/// count to `threshold` is over, and so is every write after it in the same
/// window, so a run loses exactly `threshold - 1` files to it. A threshold
/// of zero is read as one.
#[must_use]
pub const fn write_refusal_step(
    previous: Option<WriteRefusalCount>,
    now_ns: u64,
    window_ns: u64,
    threshold: u32,
) -> WriteRefusalStep {
    let threshold = if threshold == 0 { 1 } else { threshold };
    let base = match previous {
        Some(p) if now_ns.saturating_sub(p.window_start_ns) < window_ns => p,
        _ => WriteRefusalCount {
            window_start_ns: now_ns,
            count: 0,
            reported: 0,
        },
    };
    let count = base.count.saturating_add(1);
    let over = count >= threshold;
    let report = over && base.reported == 0;
    WriteRefusalStep {
        next: WriteRefusalCount {
            window_start_ns: base.window_start_ns,
            count,
            reported: if report { 1 } else { base.reported },
        },
        over,
        report,
    }
}

/// The threshold a write under a path of `regime` is held to: the
/// configured one for a data path, one for a system path.
#[must_use]
pub const fn write_refusal_threshold(regime: u8, data_threshold: u32) -> u32 {
    if regime == WRITE_REFUSAL_REGIME_SYSTEM {
        1
    } else {
        data_threshold
    }
}

/// The counter key of `writer` under a path of `regime`.
#[must_use]
pub const fn write_refusal_count_key(writer: u64, regime: u8) -> u64 {
    if regime == WRITE_REFUSAL_REGIME_SYSTEM {
        writer | WRITE_REFUSAL_SYSTEM_KEY_BIT
    } else {
        writer
    }
}

/// Whether a writer's window has passed at `now_ns`, so its entry can go.
#[must_use]
pub const fn write_refusal_expired(count: &WriteRefusalCount, now_ns: u64, window_ns: u64) -> bool {
    now_ns.saturating_sub(count.window_start_ns) >= window_ns
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for WriteRefusalDir {}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for WriteRefusalCount {}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for WriteRefusalConfig {}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for WriteRefusalEvent {}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    const SECOND: u64 = 1_000_000_000;

    fn run(threshold: u32, writes: u32) -> (Option<WriteRefusalCount>, u32, u32) {
        let mut count = None;
        let mut over = 0;
        let mut reports = 0;
        for i in 0..writes {
            let step = write_refusal_step(count, u64::from(i), SECOND, threshold);
            count = Some(step.next);
            over += u32::from(step.over);
            reports += u32::from(step.report);
        }
        (count, over, reports)
    }

    #[test]
    fn a_writer_under_its_threshold_is_never_over() {
        let (count, over, reports) = run(100, 99);
        assert_eq!(count.map(|c| c.count), Some(99));
        assert_eq!(over, 0);
        assert_eq!(reports, 0);
    }

    #[test]
    fn the_write_reaching_the_threshold_is_the_first_refused_and_reported_once() {
        let (_, over, reports) = run(100, 150);
        assert_eq!(over, 51, "the hundredth write and every one after it");
        assert_eq!(reports, 1);
    }

    #[test]
    fn a_threshold_of_one_refuses_the_first_write() {
        let step = write_refusal_step(None, 0, SECOND, 1);
        assert!(step.over);
        assert!(step.report);
        let step = write_refusal_step(None, 0, SECOND, 0);
        assert!(step.over, "zero is read as one");
    }

    #[test]
    fn a_new_window_starts_the_count_again_and_reports_again() {
        let (count, _, _) = run(3, 5);
        let step = write_refusal_step(count, 2 * SECOND, SECOND, 3);
        assert_eq!(step.next.count, 1);
        assert_eq!(step.next.window_start_ns, 2 * SECOND);
        assert!(!step.over);
        assert_eq!(step.next.reported, 0);
        assert!(write_refusal_expired(
            &count.expect("counted"),
            SECOND + 1,
            SECOND
        ));
        assert!(!write_refusal_expired(&count.expect("counted"), 10, SECOND));
    }

    #[test]
    fn the_count_saturates_rather_than_wrapping_to_zero() {
        let full = WriteRefusalCount {
            window_start_ns: 0,
            count: u32::MAX,
            reported: 1,
        };
        let step = write_refusal_step(Some(full), 1, SECOND, 10);
        assert_eq!(step.next.count, u32::MAX);
        assert!(step.over);
        assert!(!step.report);
    }

    #[test]
    fn the_layouts_carry_no_implicit_padding() {
        assert_eq!(mem::size_of::<WriteRefusalDir>(), 16);
        assert_eq!(mem::size_of::<WriteRefusalCount>(), 16);
        assert_eq!(mem::size_of::<WriteRefusalConfig>(), 80);
        assert_eq!(mem::offset_of!(WriteRefusalConfig, valid), 76);
        assert_eq!(mem::size_of::<WriteRefusalEvent>(), 104);
        assert_eq!(mem::offset_of!(WriteRefusalEvent, tgid), 32);
        assert_eq!(mem::offset_of!(WriteRefusalEvent, hook), 48);
        assert_eq!(mem::offset_of!(WriteRefusalEvent, name), 56);
    }

    #[test]
    fn a_system_path_is_held_to_one_and_a_data_path_to_its_threshold() {
        assert_eq!(write_refusal_threshold(WRITE_REFUSAL_REGIME_SYSTEM, 100), 1);
        assert_eq!(write_refusal_threshold(WRITE_REFUSAL_REGIME_DATA, 100), 100);
        let first = write_refusal_step(
            None,
            1,
            SECOND,
            write_refusal_threshold(WRITE_REFUSAL_REGIME_SYSTEM, 100),
        );
        assert!(first.over && first.report);
        let first = write_refusal_step(
            None,
            1,
            SECOND,
            write_refusal_threshold(WRITE_REFUSAL_REGIME_DATA, 100),
        );
        assert!(!first.over);
    }

    #[test]
    fn the_two_regimes_never_share_a_count() {
        for writer in [0_u64, 4242, u64::from(u32::MAX), (1 << 62) + 7] {
            let data = write_refusal_count_key(writer, WRITE_REFUSAL_REGIME_DATA);
            let system = write_refusal_count_key(writer, WRITE_REFUSAL_REGIME_SYSTEM);
            assert_eq!(data, writer);
            assert_ne!(data, system);
            assert_eq!(system & !WRITE_REFUSAL_SYSTEM_KEY_BIT, writer);
        }
    }

    #[test]
    fn the_refusal_is_eacces() {
        assert_eq!(WRITE_REFUSAL_REFUSAL, -13);
    }
}
