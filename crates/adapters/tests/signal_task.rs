//! A signal reaches a process that makes no syscall, where the kernel offers
//! a way to name the target.
//!
//! The target spins in pure computation, so the syscall-entry tracepoint
//! would never run in it: if it dies, the signal went the immediate way. A
//! target in the protected set is refused by the same program and lives.
//!
//! This needs the built objects, the privilege to load them and a kernel that
//! declares `bpf_send_signal_task`, and says so and returns without any of
//! them. It never returns quietly where it should have run: objects missing
//! from a directory named by `EBPFSENTINEL_EBPF_DIR`, or a kernel whose BTF
//! declares the kfunc refusing the program to root, fail the test.

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

/// Whether the running kernel's BTF names the kfunc the immediate path calls.
fn kernel_declares_kfunc() -> bool {
    std::fs::read("/sys/kernel/btf/vmlinux").is_ok_and(|btf| {
        btf.windows(b"bpf_send_signal_task\0".len())
            .any(|w| w == b"bpf_send_signal_task\0")
    })
}

/// Whether this process runs as root, so a refused load is the program's
/// fault rather than the caller's.
fn is_root() -> bool {
    std::fs::read_to_string("/proc/self/status").is_ok_and(|status| {
        status
            .lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .and_then(|uids| uids.split_whitespace().nth(1))
            == Some("0")
    })
}

/// The manager, or `None` with the reason printed when this host cannot say.
fn manager() -> Option<(EbpfLoader, SignalMapManager)> {
    let path = objects_dir().join("tracepoint-signal");
    let Ok(bytes) = std::fs::read(&path) else {
        assert!(
            std::env::var_os("EBPFSENTINEL_EBPF_DIR").is_none(),
            "EBPFSENTINEL_EBPF_DIR names a directory without {}",
            path.display()
        );
        eprintln!("skipped: no eBPF objects at {}", path.display());
        return None;
    };
    let must_run = kernel_declares_kfunc() && is_root();
    EbpfLoader::cleanup_pin_path(PIN_PATH);
    let mut loader = match EbpfLoader::load_with_pin_path(&bytes, PIN_PATH) {
        Ok(loader) => loader,
        Err(e) => {
            assert!(
                !must_run,
                "the kernel declares the kfunc and root cannot load the objects: {e}"
            );
            eprintln!("skipped: cannot load eBPF objects here: {e}");
            return None;
        }
    };
    let maps = SignalMapManager::new(loader.ebpf_mut()).expect("signal maps");
    if !maps.immediate().loaded {
        let reason = maps.immediate().reason.as_deref().unwrap_or_default();
        assert!(
            !must_run,
            "the kernel declares bpf_send_signal_task and the immediate path did not load: {reason}"
        );
        eprintln!("skipped: no immediate signal on this kernel: {reason}");
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
