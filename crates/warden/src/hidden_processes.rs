//! The two readings behind the hidden process check: the `/proc` listing,
//! and `kill(pid, 0)` across the pid space.
//!
//! `/proc` lists thread groups, so the listing is widened with each listed
//! group's `task` directory before the sweep: a thread answers a signal and
//! is never listed, and it is counted rather than observed. The sweep is
//! paced so that it is not itself a load: the pid space is signalled in
//! slices, with a pause between them sized to the requested rate.
//!
//! The signals and the listing must address the same pid namespace. That is
//! true when `/proc/self` in the procfs being read names the reader's own
//! pid; otherwise the sweep is not taken and the reason is answered.

use std::collections::HashSet;
use std::io;
use std::path::Path;
use std::time::{Duration, Instant};

use ebpfsentinel_warden_proto::{HiddenProcessReading, PidObservation};

/// The kernel's ceiling on `pid_max`.
const PID_MAX_LIMIT: u32 = 4_194_304;
/// Pids signalled between two pauses.
const SLICE: u32 = 8_192;
/// The pace a caller may ask for, in pids per second.
pub const MIN_RATE: u32 = 10_000;
pub const MAX_RATE: u32 = 10_000_000;

/// Every numeric entry of `proc_root`: the thread groups it lists.
fn list_groups(proc_root: &Path) -> io::Result<HashSet<u32>> {
    let mut groups = HashSet::new();
    for entry in std::fs::read_dir(proc_root)? {
        let entry = entry?;
        if let Some(pid) = entry.file_name().to_str().and_then(|s| s.parse().ok()) {
            groups.insert(pid);
        }
    }
    Ok(groups)
}

/// The threads of the listed groups, as their `task` directories list them.
fn list_threads(proc_root: &Path, groups: &HashSet<u32>) -> HashSet<u32> {
    let mut threads = HashSet::new();
    for group in groups {
        let Ok(dir) = std::fs::read_dir(proc_root.join(group.to_string()).join("task")) else {
            continue;
        };
        for entry in dir.flatten() {
            if let Some(tid) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<u32>().ok())
                && tid != *group
            {
                threads.insert(tid);
            }
        }
    }
    threads
}

/// Whether `pid` exists: `kill(pid, 0)` succeeds or is refused for
/// permission, both of which mean the kernel found the task.
fn answers(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return false;
    };
    // SAFETY: signal 0 delivers nothing; the call only looks the pid up.
    let rc = unsafe { libc::kill(pid, 0) };
    rc == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// The fields of `/proc/<pid>/stat` after the command name: the state is the
/// first and the start time the twentieth.
fn parse_stat(text: &str) -> (Option<String>, Option<char>, Option<u64>) {
    let (Some(open), Some(close)) = (text.find('('), text.rfind(')')) else {
        return (None, None, None);
    };
    let comm = text.get(open + 1..close).map(str::to_string);
    let mut rest = text.get(close + 1..).unwrap_or("").split_whitespace();
    let state = rest.next().and_then(|s| s.chars().next());
    let start_time = rest.nth(18).and_then(|s| s.parse().ok());
    (comm, state, start_time)
}

fn parse_tgid(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("Tgid:"))
        .and_then(|v| v.trim().parse().ok())
}

/// What `/proc/<pid>` says about a pid the listing left out. A directory
/// listing filter leaves the entry itself reachable, so this usually reads.
fn observe(proc_root: &Path, pid: u32) -> PidObservation {
    let dir = proc_root.join(pid.to_string());
    let (comm, state, start_time) = std::fs::read_to_string(dir.join("stat"))
        .map_or((None, None, None), |text| parse_stat(&text));
    let tgid = std::fs::read_to_string(dir.join("status"))
        .ok()
        .and_then(|text| parse_tgid(&text));
    PidObservation {
        pid,
        tgid,
        start_time,
        state,
        comm,
    }
}

/// `pid_max`, bounded by the kernel's own ceiling.
fn pid_space(proc_root: &Path) -> u32 {
    std::fs::read_to_string(proc_root.join("sys/kernel/pid_max"))
        .ok()
        .and_then(|text| text.trim().parse::<u32>().ok())
        .unwrap_or(PID_MAX_LIMIT)
        .clamp(1, PID_MAX_LIMIT)
}

/// Whether `proc_root` numbers pids the way `kill` does from here.
fn same_pid_namespace(proc_root: &Path) -> bool {
    std::fs::read_link(proc_root.join("self"))
        .ok()
        .and_then(|target| target.to_str().and_then(|s| s.parse::<u32>().ok()))
        == Some(std::process::id())
}

fn not_taken(reason: String) -> HiddenProcessReading {
    HiddenProcessReading {
        error: Some(reason),
        ..HiddenProcessReading::default()
    }
}

/// Read `/proc` under `proc_root`, signal every pid at about `rate` pids a
/// second, then read again whatever answered and was not listed.
#[must_use]
pub fn scan(proc_root: &Path, rate: u32) -> HiddenProcessReading {
    if !same_pid_namespace(proc_root) {
        return not_taken(format!(
            "{} lists another pid namespace than the one this process signals in",
            proc_root.display()
        ));
    }
    let rate = rate.clamp(MIN_RATE, MAX_RATE);
    let space = pid_space(proc_root);
    let groups = match list_groups(proc_root) {
        Ok(groups) => groups,
        Err(err) => {
            return not_taken(format!(
                "{} could not be listed: {err}",
                proc_root.display()
            ));
        }
    };
    let threads = list_threads(proc_root, &groups);

    let slice_time = Duration::from_secs_f64(f64::from(SLICE) / f64::from(rate));
    let mut unlisted = Vec::new();
    let mut thread_count: u32 = 0;
    let mut start = 1;
    while start < space {
        let began = Instant::now();
        let end = start.saturating_add(SLICE).min(space);
        for pid in start..end {
            if groups.contains(&pid) || !answers(pid) {
                continue;
            }
            if threads.contains(&pid) {
                thread_count += 1;
            } else {
                unlisted.push(pid);
            }
        }
        start = end;
        if let Some(rest) = slice_time.checked_sub(began.elapsed()) {
            std::thread::sleep(rest);
        }
    }

    let first: Vec<PidObservation> = unlisted
        .iter()
        .map(|&pid| observe(proc_root, pid))
        .collect();
    let relisted = match list_groups(proc_root) {
        Ok(again) => unlisted
            .iter()
            .copied()
            .filter(|pid| again.contains(pid))
            .collect(),
        Err(err) => {
            return not_taken(format!(
                "{} could not be listed again: {err}",
                proc_root.display()
            ));
        }
    };
    let second = unlisted
        .iter()
        .copied()
        .filter(|&pid| answers(pid))
        .map(|pid| observe(proc_root, pid))
        .collect();
    HiddenProcessReading {
        error: None,
        pid_space: space,
        probed: space.saturating_sub(1),
        listed: u32::try_from(groups.len()).unwrap_or(u32::MAX),
        threads: thread_count,
        first,
        relisted,
        second,
    }
}
