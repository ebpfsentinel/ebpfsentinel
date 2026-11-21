//! A hidden process, found on a real host, with nothing hidden.
//!
//! A rootkit hides a process by filtering what `/proc` answers while the
//! process keeps running, so the kernel still signals it. The check is built
//! on exactly that disagreement: `list_groups` reads a directory, which a
//! rootkit can filter, and `answers` sends `kill(pid, 0)`, which it cannot
//! filter without hooking the call. Writing the filtering half is writing a
//! rootkit, so this test supplies the other half instead, which is the one
//! the product owns: a real child process, really alive, really answering a
//! signal, and a procfs listing that does not hold it.
//!
//! The listing is the host's own `/proc`, mirrored entry by entry into a
//! temporary directory as symbolic links, minus the child's. Nothing is
//! concealed from anything: the real `/proc` is untouched, every other
//! reader still sees the child, and the doctored view exists only as the
//! argument this test hands the reader. That argument is not a seam opened
//! for the test either - `WardenHiddenProcessReader::new` takes the procfs
//! to read because the agent sweeps either its own or the one the warden
//! reaches, so what runs here is the production path: the warden's sweep,
//! the adapter's mapping into the domain, and the domain's decision.
//!
//! The child is hidden from its `stat` as well as from the listing, because
//! a directory that is not there cannot be read, so the finding carries a
//! pid and no command name. A rootkit filtering only `readdir` would leave
//! the name readable; both shapes reach the same verdict, and the console
//! keys a finding with no name by its pid.
//!
//! The port half of the sweep cannot be simulated this way, which is why it
//! is not attempted here: `dump_inet` asks `sock_diag` for every socket in
//! every state (`idiag_states: u32::MAX`) in the namespace the bind probe
//! binds in, so the two readings cannot disagree unless the netlink dump
//! itself fails. Defeating it is the rootkit's work, not a test's. The
//! positive port case therefore stays injected at the port boundary, suite
//! `79-hidden-ports-and-processes` proves the port sweep does not cry wolf
//! on a busy clean host, and the estate's reading across nodes is held by
//! the console server's `hidden_across_nodes` test.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::{Child, Command};

use adapters::warden::hidden_processes::WardenHiddenProcessReader;
use domain::hidden::sweep_processes;
use ports::secondary::hidden_process_port::HiddenProcessReader;

/// The pace asked of the sweep. The warden clamps it to its own ceiling and
/// paces slice by slice; the ceiling is high enough that a sweep of the pid
/// space this test sets costs no pause at all.
const RATE: u32 = 10_000_000;

/// A child killed and reaped whatever the test does, so a failure leaves no
/// `sleep` behind.
struct Reaped(Child);

impl Drop for Reaped {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Every thread group the host's `/proc` lists, linked into `root` under its
/// own number, except `hide`. A link whose target left between the listing
/// and the link is harmless: the sweep reads the target, which is what the
/// real `/proc` would answer for a process that just exited.
fn mirror_proc_except(root: &Path, hide: u32) -> usize {
    let mut linked = 0;
    let entries = std::fs::read_dir("/proc").expect("/proc is readable");
    for entry in entries {
        let name = entry.expect("a /proc entry is readable").file_name();
        let Some(pid) = name.to_str().and_then(|text| text.parse::<u32>().ok()) else {
            continue;
        };
        if pid == hide {
            continue;
        }
        std::os::unix::fs::symlink(
            Path::new("/proc").join(pid.to_string()),
            root.join(pid.to_string()),
        )
        .expect("the mirrored entry is linked");
        linked += 1;
    }
    linked
}

/// The two files the sweep reads about the procfs itself: `self`, which it
/// compares to its own pid to know the listing numbers pids the way its
/// signals do, and `pid_max`, which bounds the space it sweeps. The bound is
/// the hidden child's pid, so the sweep reaches it without walking the four
/// million pids the kernel's own ceiling allows.
fn describe_namespace(root: &Path, pid_space: u32) {
    std::os::unix::fs::symlink(std::process::id().to_string(), root.join("self"))
        .expect("the reader's own pid is linked as self");
    let sys = root.join("sys").join("kernel");
    std::fs::create_dir_all(&sys).expect("the sys directory is created");
    std::fs::write(sys.join("pid_max"), format!("{pid_space}\n")).expect("pid_max is written");
}

/// One sweep through the production reader, as the pids it reports hidden
/// and the names those findings carry.
fn hidden_pids(reader: &WardenHiddenProcessReader) -> (BTreeSet<u32>, Vec<Option<String>>) {
    let reading = reader
        .read(RATE)
        .expect("the sweep is taken: the mirrored listing numbers pids as this process signals");
    let sweep = sweep_processes(&reading);
    let names = sweep
        .hidden
        .iter()
        .map(|found| found.comm.clone())
        .collect();
    (sweep.hidden.iter().map(|found| found.pid).collect(), names)
}

#[test]
fn a_process_the_listing_does_not_hold_is_found_by_the_signal_that_answers() {
    // A process of our own, so the test knows the pid it must find and the
    // kernel answers for it throughout.
    let child = Reaped(
        Command::new("sleep")
            .arg("600")
            .spawn()
            .expect("a child process starts"),
    );
    let hidden_pid = child.0.id();

    let root = tempfile::tempdir().expect("a temporary directory is created");
    let listed = mirror_proc_except(root.path(), hidden_pid);
    assert!(
        listed > 10,
        "the host's /proc was mirrored: {listed} entries"
    );
    describe_namespace(root.path(), hidden_pid + 1);

    let reader = WardenHiddenProcessReader::new(
        ebpfsentinel_warden::hidden_processes::scan,
        root.path(),
        RATE,
    );
    assert_eq!(
        reader.source(),
        "local",
        "EBPFSENTINEL_WARDEN_SOCK is set in this environment, so the reader would ask a warden"
    );

    let (found, names) = hidden_pids(&reader);
    assert!(
        found.contains(&hidden_pid),
        "the child {hidden_pid} answers the signal and no listing holds it: {found:?}"
    );
    // Its own pid is in the mirrored listing, so the sweep that found the
    // child reports nothing about the process doing the sweeping.
    assert!(
        !found.contains(&std::process::id()),
        "a listed process was reported hidden: {found:?}"
    );
    // The directory is gone, not only the listing, so there is no `stat` to
    // read and the finding carries a pid alone.
    assert!(
        names.iter().any(Option::is_none),
        "a finding with no readable name: {names:?}"
    );

    // What produced the finding is the kernel's answer, not the doctored
    // listing: with the child gone and the listing unchanged, the same sweep
    // reports nothing about that pid.
    drop(child);
    let (after, _) = hidden_pids(&reader);
    assert!(
        !after.contains(&hidden_pid),
        "a dead pid is still reported hidden: {after:?}"
    );
}
