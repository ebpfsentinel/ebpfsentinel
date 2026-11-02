//! A signal reaches a process that makes no syscall, where the kernel offers
//! a way to name the target.
//!
//! The target spins in pure computation, so the syscall-entry tracepoint
//! would never run in it: if it dies, the signal went the immediate way. A
//! target in the protected set is refused by the same program and lives.
//!
//! This needs the built objects, the privilege to load them and a kernel that
//! declares `bpf_send_signal_task`, and says so and returns without any of
//! them.

use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use adapters::ebpf::SignalMapManager;
use adapters::ebpf::loader::EbpfLoader;
use ebpf_common::signal::{SIGNAL_OUTCOME_PROTECTED, SIGNAL_OUTCOME_SENT};
use ports::secondary::process_signal_map_port::ProcessSignalMapPort;

const PIN_PATH: &str = "/sys/fs/bpf/ebpfsentinel-signal-task-test";

fn objects_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("EBPFSENTINEL_EBPF_DIR") {
        return PathBuf::from(dir);
    }
    let dir =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/bpfel-unknown-none/release");
    dir.canonicalize().unwrap_or(dir)
}

/// A process that computes forever and never enters the kernel.
fn spinner() -> Child {
    Command::new("awk")
        .args(["BEGIN { while (1) {} }"])
        .spawn()
        .expect("awk")
}

fn wait_for_exit(child: &mut Child, within: Duration) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("wait") {
            return Some(status);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    None
}

/// The manager, or `None` with the reason printed when this host cannot say.
fn manager() -> Option<(EbpfLoader, SignalMapManager)> {
    let path = objects_dir().join("tracepoint-signal");
    let Ok(bytes) = std::fs::read(&path) else {
        eprintln!("skipped: no eBPF objects at {}", path.display());
        return None;
    };
    EbpfLoader::cleanup_pin_path(PIN_PATH);
    let mut loader = match EbpfLoader::load_with_pin_path(&bytes, PIN_PATH) {
        Ok(loader) => loader,
        Err(e) => {
            eprintln!("skipped: cannot load eBPF objects here: {e}");
            return None;
        }
    };
    let maps = SignalMapManager::new(loader.ebpf_mut()).expect("signal maps");
    if !maps.immediate().loaded {
        eprintln!(
            "skipped: no immediate signal on this kernel: {}",
            maps.immediate().reason.as_deref().unwrap_or_default()
        );
        return None;
    }
    Some((loader, maps))
}

#[test]
fn a_process_making_no_syscall_is_signalled_at_once_and_a_protected_one_is_not() {
    let Some((_loader, mut maps)) = manager() else {
        EbpfLoader::cleanup_pin_path(PIN_PATH);
        return;
    };

    let mut target = spinner();
    let tgid = target.id();
    maps.set_protected(&[]).expect("protected set");
    maps.arm(tgid, libc::SIGKILL.cast_unsigned(), 60_000_000_000)
        .expect("arm");
    let status = wait_for_exit(&mut target, Duration::from_secs(2))
        .expect("the spinning process outlived an immediate signal");
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    let events = maps.drain_events().expect("drain");
    assert!(
        events
            .iter()
            .any(|e| e.tgid == tgid && e.outcome == SIGNAL_OUTCOME_SENT),
        "no sent outcome for {tgid}"
    );

    let mut spared = spinner();
    let tgid = spared.id();
    maps.set_protected(&[tgid]).expect("protected set");
    maps.arm(tgid, libc::SIGKILL.cast_unsigned(), 60_000_000_000)
        .expect("arm");
    let survived = wait_for_exit(&mut spared, Duration::from_millis(300)).is_none();
    let events = maps.drain_events().expect("drain");
    spared.kill().expect("kill");
    let _ = spared.wait();
    EbpfLoader::cleanup_pin_path(PIN_PATH);
    assert!(survived, "a protected process was signalled");
    assert!(
        events
            .iter()
            .any(|e| e.tgid == tgid && e.outcome == SIGNAL_OUTCOME_PROTECTED),
        "no protected outcome for {tgid}"
    );
}
