#![allow(unsafe_code)] // Required for eBPF RingBuf record parsing (read_unaligned)

use crate::ebpf::event_reader::{drain_tick, watch_ringbuf};
use crate::ebpf::map_store::MapStore;
use crate::ebpf::ringbuf_observer::{DrainTrigger, RingBufObserver, boottime_to_epoch_ns};
use std::collections::HashMap;

use aya::maps::{MapData, RingBuf};
use domain::process::command_line::{self, MAX_COMMAND_LINE};
use domain::process::entity::{ProcessEventKind, ProcessLifecycleEvent};
use ebpf_common::process::{
    PROCESS_ARGV_BOUND, PROCESS_EVENT_ARGV, PROCESS_EVENT_EXEC, PROCESS_EVENT_EXIT,
    PROCESS_EVENT_FORK, ProcessArgv, ProcessEvent,
};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info};

/// The source name this reader's records are counted under.
pub const RINGBUF_SOURCE: &str = "process";

// The kernel copy of the arguments is held to the bound the `/proc` read is,
// so both sources make the same line.
const _: () = assert!(PROCESS_ARGV_BOUND as usize == MAX_COMMAND_LINE);

/// Command lines held at once while their exec record is on its way. An
/// argument record is followed at once by the exec record of the same task,
/// so this only fills when exec records are lost, and is then emptied.
const PENDING_ARGV_CAPACITY: usize = 1024;

/// Reads exec, fork and exit records from the `PROCESS_EVENTS` ring buffer
/// of the tracepoint-process object.
///
/// Every record starts with a `ProcessEvent` whose kind says what follows:
/// the lifecycle records are that header alone, an argument record is a
/// `ProcessArgv` the reader holds until the exec record of the same process
/// takes it. A record shorter than its kind needs is counted as a loss
/// rather than parsed on a guess.
pub struct ProcessEventReader {
    ring_buf: AsyncFd<RingBuf<MapData>>,
}

impl ProcessEventReader {
    /// Take the `PROCESS_EVENTS` map from the loaded tracepoint object.
    pub fn new(ebpf: &mut dyn MapStore) -> Result<Self, anyhow::Error> {
        let map = ebpf.take_map("PROCESS_EVENTS").ok_or_else(|| {
            anyhow::anyhow!("map 'PROCESS_EVENTS' not found in tracepoint-process eBPF object")
        })?;
        let ring_buf = RingBuf::try_from(map)?;
        let async_fd = watch_ringbuf(ring_buf)?;
        info!("PROCESS_EVENTS RingBuf reader initialized");
        Ok(Self { ring_buf: async_fd })
    }

    /// Drain the ring buffer into `tx` until `cancel` fires or the buffer
    /// errors.
    pub async fn run(
        self,
        tx: mpsc::Sender<ProcessLifecycleEvent>,
        cancel: CancellationToken,
        observer: RingBufObserver,
    ) {
        let mut async_fd = self.ring_buf;
        let mut tick = drain_tick();
        let mut pending = PendingArgv::default();

        loop {
            tokio::select! {
                () = cancel.cancelled() => {
                    info!("process event reader cancelled");
                    break;
                }
                result = async_fd.readable_mut() => {
                    match result {
                        Ok(mut guard) => {
                            let drained = drain(guard.get_inner_mut(), &tx, &observer, &mut pending);
                            guard.clear_ready();
                            observer.drain_pass(DrainTrigger::Wakeup, drained);
                        }
                        Err(e) => {
                            error!("process RingBuf readable error: {e}");
                            break;
                        }
                    }
                }
                _ = tick.tick() => {
                    let drained = drain(async_fd.get_mut(), &tx, &observer, &mut pending);
                    observer.drain_pass(DrainTrigger::Tick, drained);
                }
            }
        }
    }
}

/// Drain every record currently in `rb`, returning how many were read.
fn drain(
    rb: &mut RingBuf<MapData>,
    tx: &mpsc::Sender<ProcessLifecycleEvent>,
    observer: &RingBufObserver,
    pending: &mut PendingArgv,
) -> usize {
    let now_ns = observer.now_ns();
    let mut drained = 0usize;
    while let Some(item) = rb.next() {
        drained += 1;
        match accept(&item, pending) {
            Accepted::Event(at_ns, event) => {
                observer.drained(now_ns, at_ns);
                if tx.try_send(*event).is_err() {
                    observer.dropped("channel_full");
                    debug!("process event channel full, dropping event");
                }
            }
            Accepted::Held(at_ns) => observer.drained(now_ns, at_ns),
            Accepted::Dropped(reason) => observer.dropped(reason),
        }
    }
    drained
}

/// What one ring record came to.
#[derive(Debug)]
enum Accepted {
    /// A lifecycle event for the table, with the kernel instant of the record.
    Event(u64, Box<ProcessLifecycleEvent>),
    /// An argument record, held for the exec record that follows it.
    Held(u64),
    /// Nothing usable, counted under this reason.
    Dropped(&'static str),
}

/// Read one record, holding an argument record and handing what it held to
/// the exec record of the same process.
fn accept(bytes: &[u8], pending: &mut PendingArgv) -> Accepted {
    if bytes.len() < size_of::<ProcessEvent>() {
        return Accepted::Dropped("truncated_record");
    }
    // SAFETY: the length check above covers a whole `ProcessEvent`, a plain
    // `repr(C)` record of integers any bit pattern of which is valid, read
    // unaligned because the ring promises eight-byte alignment only.
    let raw = unsafe { bytes.as_ptr().cast::<ProcessEvent>().read_unaligned() };
    if raw.kind == PROCESS_EVENT_ARGV {
        if bytes.len() < size_of::<ProcessArgv>() {
            return Accepted::Dropped("truncated_record");
        }
        // SAFETY: as above, the length check covers a whole `ProcessArgv`.
        let argv = unsafe { bytes.as_ptr().cast::<ProcessArgv>().read_unaligned() };
        pending.hold(&argv);
        return Accepted::Held(raw.at_ns);
    }
    let Some(mut event) = parse(&raw) else {
        return Accepted::Dropped("unknown_kind");
    };
    pending.attach(&raw, &mut event);
    Accepted::Event(raw.at_ns, Box::new(event))
}

/// The command line of an argument record: the bytes the kernel wrote,
/// joined and bounded by the rule the `/proc` read follows, and marked as cut
/// where the kernel read fewer arguments than the task was started with.
#[must_use]
pub fn argv_command_line(argv: &ProcessArgv) -> Option<String> {
    let len = usize::try_from(argv.len)
        .unwrap_or(usize::MAX)
        .min(argv.bytes.len());
    command_line::from_argv(&argv.bytes[..len], argv.args_read < argv.argc)
}

/// Command lines the kernel read, keyed by process, waiting for the exec
/// record that names them.
#[derive(Debug, Default)]
struct PendingArgv {
    by_tgid: HashMap<u32, (u64, String)>,
}

impl PendingArgv {
    /// Hold the line of an argument record. A second exec of the same
    /// process replaces the first one's line, whose exec record was lost.
    fn hold(&mut self, argv: &ProcessArgv) {
        let Some(line) = argv_command_line(argv) else {
            return;
        };
        if self.by_tgid.len() >= PENDING_ARGV_CAPACITY
            && !self.by_tgid.contains_key(&argv.header.tgid)
        {
            self.by_tgid.clear();
        }
        self.by_tgid
            .insert(argv.header.tgid, (argv.header.start_ns, line));
    }

    /// Give an exec event the line held for its process, and forget what
    /// was held for a process that exited.
    fn attach(&mut self, raw: &ProcessEvent, event: &mut ProcessLifecycleEvent) {
        match raw.kind {
            PROCESS_EVENT_EXEC => {
                if let Some((start_ns, line)) = self.by_tgid.remove(&raw.tgid)
                    && start_ns == raw.start_ns
                {
                    event.command_line = Some(line);
                }
            }
            PROCESS_EVENT_EXIT => {
                self.by_tgid.remove(&raw.tgid);
            }
            _ => {}
        }
    }
}

/// Turn a kernel record into the domain event, or nothing when the record
/// carries a kind this build does not know.
#[must_use]
pub fn parse(raw: &ProcessEvent) -> Option<ProcessLifecycleEvent> {
    let kind = match raw.kind {
        PROCESS_EVENT_EXEC => ProcessEventKind::Exec,
        PROCESS_EVENT_FORK => ProcessEventKind::Fork,
        PROCESS_EVENT_EXIT => ProcessEventKind::Exit,
        _ => return None,
    };
    // Zero is what the kernel side leaves where a read failed, and no process
    // the table can name has pid 0 for a parent or started at instant 0.
    let known_u64 = |v: u64| (v != 0).then_some(v);
    Some(ProcessLifecycleEvent {
        kind,
        pid: raw.pid,
        tgid: raw.tgid,
        uid: raw.uid,
        gid: raw.gid,
        cgroup_id: raw.cgroup_id,
        comm: comm_to_string(&raw.comm),
        // The file watch and the encryption calls are stamped on the wall
        // clock, and the ransom verdict and the host rules pair an exec with
        // them inside one window, so the exec is moved onto that clock here.
        // The start instants stay on the boot clock: they are an identity
        // compared only with each other, never a time compared with an event.
        at_ns: boottime_to_epoch_ns(raw.at_ns),
        start_ns: known_u64(raw.start_ns),
        parent_pid: (raw.parent_tgid != 0).then_some(raw.parent_tgid),
        parent_start_ns: known_u64(raw.parent_start_ns),
        command_line: None,
    })
}

/// The kernel's `comm`, cut at its first NUL.
///
/// The kernel pads the field with NULs and truncates at sixteen bytes, so the
/// string is a hint rather than a name: `systemd-journald` arrives whole and
/// `some-very-long-daemon` does not.
#[must_use]
fn comm_to_string(comm: &[u8]) -> String {
    let end = comm.iter().position(|b| *b == 0).unwrap_or(comm.len());
    String::from_utf8_lossy(&comm[..end]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::process::command_line::TRUNCATION_MARKER;
    use ebpf_common::process::{PROCESS_ARGV_CHUNK, PROCESS_COMM_LEN};

    fn argv_record(tgid: u32, start_ns: u64, args: &[&[u8]], argc: u32) -> ProcessArgv {
        let mut header = raw(PROCESS_EVENT_ARGV);
        header.tgid = tgid;
        header.pid = tgid;
        header.start_ns = start_ns;
        let mut record = ProcessArgv {
            header,
            argc,
            args_read: 0,
            len: 0,
            _pad: 0,
            bytes: [0u8; (PROCESS_ARGV_BOUND + PROCESS_ARGV_CHUNK) as usize],
        };
        let mut at = 0usize;
        for arg in args {
            record.bytes[at..at + arg.len()].copy_from_slice(arg);
            at += arg.len() + 1;
            record.args_read += 1;
        }
        record.len = u32::try_from(at).unwrap();
        record
    }

    fn bytes_of<T>(value: &T) -> Vec<u8> {
        // SAFETY: test records are plain `repr(C)` integers and arrays.
        unsafe {
            std::slice::from_raw_parts(std::ptr::from_ref(value).cast::<u8>(), size_of::<T>())
        }
        .to_vec()
    }

    fn exec_of(tgid: u32, start_ns: u64) -> Vec<u8> {
        let mut record = raw(PROCESS_EVENT_EXEC);
        record.tgid = tgid;
        record.pid = tgid;
        record.start_ns = start_ns;
        bytes_of(&record)
    }

    fn event(accepted: Accepted) -> ProcessLifecycleEvent {
        match accepted {
            Accepted::Event(_, event) => *event,
            other => panic!("expected an event, got {other:?}"),
        }
    }

    #[test]
    fn the_exec_after_an_argument_record_carries_its_command_line() {
        let mut pending = PendingArgv::default();
        let argv = argv_record(42, 900, &[b"curl", b"-s", b"https://example.test"], 3);
        assert!(matches!(
            accept(&bytes_of(&argv), &mut pending),
            Accepted::Held(_)
        ));
        let exec = event(accept(&exec_of(42, 900), &mut pending));
        assert_eq!(
            exec.command_line.as_deref(),
            Some("curl -s https://example.test")
        );
        assert!(pending.by_tgid.is_empty());
    }

    #[test]
    fn an_exec_with_no_argument_record_leaves_the_line_to_proc() {
        let mut pending = PendingArgv::default();
        let exec = event(accept(&exec_of(42, 900), &mut pending));
        assert_eq!(exec.command_line, None);
    }

    #[test]
    fn a_line_held_for_another_start_of_the_pid_is_not_given() {
        let mut pending = PendingArgv::default();
        let argv = argv_record(42, 800, &[b"old"], 1);
        accept(&bytes_of(&argv), &mut pending);
        let exec = event(accept(&exec_of(42, 900), &mut pending));
        assert_eq!(exec.command_line, None);
        assert!(pending.by_tgid.is_empty());
    }

    #[test]
    fn an_exit_forgets_what_was_held_for_the_process() {
        let mut pending = PendingArgv::default();
        accept(
            &bytes_of(&argv_record(42, 900, &[b"sleep"], 1)),
            &mut pending,
        );
        let mut exit = raw(PROCESS_EVENT_EXIT);
        exit.tgid = 42;
        accept(&bytes_of(&exit), &mut pending);
        assert!(pending.by_tgid.is_empty());
    }

    #[test]
    fn a_full_holding_area_is_emptied_rather_than_grown() {
        let mut pending = PendingArgv::default();
        for tgid in 0..u32::try_from(PENDING_ARGV_CAPACITY).unwrap() {
            pending.hold(&argv_record(tgid + 1, 1, &[b"x"], 1));
        }
        assert_eq!(pending.by_tgid.len(), PENDING_ARGV_CAPACITY);
        pending.hold(&argv_record(1_000_000, 1, &[b"y"], 1));
        assert_eq!(pending.by_tgid.len(), 1);
    }

    #[test]
    fn a_kernel_read_cut_short_is_marked_like_a_proc_read_cut_short() {
        let argv = argv_record(42, 900, &[b"tar", b"-czf"], 5);
        let line = argv_command_line(&argv).unwrap();
        assert_eq!(line, format!("tar -czf{TRUNCATION_MARKER}"));
    }

    #[test]
    fn the_kernel_copy_and_the_proc_read_make_the_same_line() {
        let args: Vec<Vec<u8>> = (0..300)
            .map(|i| format!("arg-{i:04}").into_bytes())
            .collect();
        let refs: Vec<&[u8]> = args.iter().map(Vec::as_slice).collect();
        let mut proc_bytes = Vec::new();
        for arg in &refs {
            proc_bytes.extend_from_slice(arg);
            proc_bytes.push(0);
        }
        let short: Vec<&[u8]> = refs[..10].to_vec();
        let argv = argv_record(42, 900, &short, 10);
        assert_eq!(
            argv_command_line(&argv),
            command_line::from_argv(
                &proc_bytes[..short.iter().map(|a| a.len() + 1).sum::<usize>()],
                false
            )
        );
    }

    #[test]
    fn a_length_past_the_buffer_is_held_to_it() {
        let mut argv = argv_record(42, 900, &[b"ls"], 1);
        argv.len = u32::MAX;
        assert!(argv_command_line(&argv).is_some());
    }

    #[test]
    fn a_short_argument_record_is_a_loss() {
        let mut pending = PendingArgv::default();
        let bytes = bytes_of(&raw(PROCESS_EVENT_ARGV));
        assert!(matches!(
            accept(&bytes, &mut pending),
            Accepted::Dropped("truncated_record")
        ));
    }

    fn raw(kind: u8) -> ProcessEvent {
        let mut comm = [0u8; PROCESS_COMM_LEN];
        comm[..4].copy_from_slice(b"curl");
        ProcessEvent {
            at_ns: 1_000,
            cgroup_id: 777,
            start_ns: 900,
            parent_start_ns: 0,
            pid: 42,
            tgid: 42,
            uid: 1000,
            gid: 1000,
            parent_tgid: 7,
            kind,
            _pad: [0u8; 3],
            comm,
        }
    }

    #[test]
    fn an_exec_record_becomes_an_exec_event() {
        let event = parse(&raw(PROCESS_EVENT_EXEC)).unwrap();
        assert_eq!(event.kind, ProcessEventKind::Exec);
        assert_eq!(event.tgid, 42);
        assert_eq!(event.comm, "curl");
        assert_eq!(event.cgroup_id, 777);
    }

    #[test]
    fn the_event_instant_is_moved_onto_the_wall_clock_and_the_start_is_not() {
        let mut record = raw(PROCESS_EVENT_EXEC);
        record.at_ns = crate::ebpf::ringbuf_observer::boottime_now_ns();
        let event = parse(&record).unwrap();
        let wall = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let wall = u64::try_from(wall).unwrap();
        // Read a moment apart, so the two agree to within a second rather
        // than to the nanosecond.
        assert!(
            event.at_ns.abs_diff(wall) < 1_000_000_000,
            "{} vs {wall}",
            event.at_ns
        );
        assert_eq!(event.start_ns, Some(900));
    }

    #[test]
    fn a_fork_record_carries_the_lineage_the_kernel_read() {
        let event = parse(&raw(PROCESS_EVENT_FORK)).unwrap();
        assert_eq!(event.kind, ProcessEventKind::Fork);
        assert_eq!(event.start_ns, Some(900));
        assert_eq!(event.parent_pid, Some(7));
        // A zero start is a failed read, not instant zero.
        assert_eq!(event.parent_start_ns, None);
    }

    #[test]
    fn a_record_with_no_parent_says_so() {
        let mut r = raw(PROCESS_EVENT_EXEC);
        r.parent_tgid = 0;
        r.start_ns = 0;
        let event = parse(&r).unwrap();
        assert_eq!(event.parent_pid, None);
        assert_eq!(event.start_ns, None);
    }

    #[test]
    fn an_exit_record_becomes_an_exit_event() {
        let event = parse(&raw(PROCESS_EVENT_EXIT)).unwrap();
        assert_eq!(event.kind, ProcessEventKind::Exit);
    }

    #[test]
    fn a_record_of_an_unknown_kind_is_refused_rather_than_guessed() {
        assert!(parse(&raw(99)).is_none());
    }

    #[test]
    fn a_full_comm_keeps_all_sixteen_bytes() {
        let comm = *b"systemd-journal\0";
        assert_eq!(comm_to_string(&comm), "systemd-journal");
        let full = *b"sixteen-char-com";
        assert_eq!(comm_to_string(&full), "sixteen-char-com");
    }

    #[test]
    fn a_comm_with_invalid_utf8_still_yields_a_string() {
        let mut comm = [0u8; PROCESS_COMM_LEN];
        comm[0] = 0xff;
        comm[1] = b'a';
        assert!(comm_to_string(&comm).ends_with('a'));
    }
}
