//! The warden's self-confinement, exercised in child processes of this test
//! binary: each child confines itself and then does one thing, and the parent
//! reads how it ended. A confinement cannot be undone, so it never runs in the
//! process that runs the other tests.

#![allow(clippy::panic)]

use std::ffi::CString;
use std::io;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

use ebpfsentinel_warden::confine::{Writes, confine};

const MODE: &str = "EBPFSENTINEL_CONFINE_TEST_MODE";
const OPEN_DIR: &str = "EBPFSENTINEL_CONFINE_TEST_OPEN";
const CANARY_DIR: &str = "EBPFSENTINEL_CONFINE_TEST_CANARY";
const CLOSED_DIR: &str = "EBPFSENTINEL_CONFINE_TEST_CLOSED";

/// The entry point of every child: does nothing when run as an ordinary test.
#[test]
fn child() {
    let Ok(mode) = std::env::var(MODE) else {
        return;
    };
    let open = PathBuf::from(std::env::var(OPEN_DIR).expect("open dir"));
    let canary = PathBuf::from(std::env::var(CANARY_DIR).expect("canary dir"));
    let closed = PathBuf::from(std::env::var(CLOSED_DIR).expect("closed dir"));
    let posture = confine(&[
        (open.as_path(), Writes::Anything),
        (canary.as_path(), Writes::NewFiles),
    ])
    .expect("confine");
    match mode.as_str() {
        "serve" => confined_work(posture.landlock_abi.is_some(), &open, &canary, &closed),
        "execve" => {
            let prog = CString::new("/bin/true").expect("path");
            let argv = [prog.as_ptr(), std::ptr::null()];
            // SAFETY: `prog` and `argv` are NUL-terminated and outlive the call.
            unsafe { libc::execv(prog.as_ptr(), argv.as_ptr()) };
        }
        "unshare" => {
            // SAFETY: integer flags only.
            unsafe { libc::unshare(libc::CLONE_NEWUSER) };
        }
        "clone_namespace" => {
            // SAFETY: a raw `clone` with no stack and no pointers; the filter
            // stops it before the kernel creates anything.
            unsafe {
                libc::syscall(
                    libc::SYS_clone,
                    libc::CLONE_NEWNET | libc::SIGCHLD,
                    0_usize,
                    0_usize,
                    0_usize,
                    0_usize,
                )
            };
        }
        "setns_mount" => {
            let ns = std::fs::File::open("/proc/self/ns/mnt").expect("mount namespace");
            // SAFETY: an open namespace descriptor and an integer flag.
            unsafe { libc::setns(std::os::fd::AsRawFd::as_raw_fd(&ns), libc::CLONE_NEWNS) };
        }
        other => panic!("unknown mode {other}"),
    }
    // A killed call never returns here; reaching this line is the failure the
    // parent reads as an exit code.
    std::process::exit(42);
}

/// What a confined warden still does: read its own status, run threads, write
/// where it was allowed to, and fail everywhere else.
fn confined_work(landlock: bool, open: &Path, canary: &Path, closed: &Path) {
    let status = std::fs::read_to_string("/proc/self/status").expect("status");
    assert!(status.lines().any(|l| l == "NoNewPrivs:\t1"), "{status}");
    assert!(status.lines().any(|l| l == "Seccomp:\t2"), "{status}");

    // Threads are created through `clone`, `clone3` being answered as missing.
    let joined = std::thread::spawn(|| 7).join().expect("thread");
    assert_eq!(joined, 7);

    // A socket pair, as every agent connection is.
    let (mut a, mut b) = std::os::unix::net::UnixStream::pair().expect("pair");
    io::Write::write_all(&mut a, b"frame").expect("write");
    let mut got = [0_u8; 5];
    io::Read::read_exact(&mut b, &mut got).expect("read");
    assert_eq!(&got, b"frame");

    // A call on neither list fails, it does not kill.
    // SAFETY: `sync` takes no argument.
    let rc = unsafe { libc::syscall(libc::SYS_sync) };
    assert_eq!(rc, -1);
    assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));

    std::fs::write(open.join("pin"), b"x").expect("write beneath the open directory");
    std::fs::remove_file(open.join("pin")).expect("remove beneath the open directory");
    std::fs::write(canary.join("canary"), b"x").expect("plant a canary");
    if landlock {
        let refused = |r: io::Result<()>, what: &str| {
            // Landlock answers `EACCES`; a call the filter does not allow,
            // such as `symlinkat`, answers `EPERM` before Landlock is asked.
            let e = r.expect_err(what);
            assert!(
                matches!(e.raw_os_error(), Some(libc::EACCES | libc::EPERM)),
                "{what}: {e}"
            );
        };
        refused(std::fs::write(closed.join("x"), b"x"), "write elsewhere");
        refused(
            std::fs::remove_file(canary.join("canary")),
            "remove a canary",
        );
        refused(std::fs::create_dir(canary.join("d")), "make a directory");
        refused(
            std::os::unix::fs::symlink("/etc/shadow", canary.join("l")),
            "make a link",
        );
    }
    std::process::exit(0);
}

fn run(mode: &str) -> (ExitStatus, tempfile::TempDir) {
    let root = tempfile::tempdir().expect("tempdir");
    for dir in ["open", "canary", "closed"] {
        std::fs::create_dir(root.path().join(dir)).expect("dir");
    }
    let status = Command::new(std::env::current_exe().expect("test binary"))
        .args(["child", "--exact", "--nocapture", "--test-threads=1"])
        .env(MODE, mode)
        .env(OPEN_DIR, root.path().join("open"))
        .env(CANARY_DIR, root.path().join("canary"))
        .env(CLOSED_DIR, root.path().join("closed"))
        .status()
        .expect("run the child");
    (status, root)
}

fn assert_killed(mode: &str) {
    let (status, _root) = run(mode);
    assert_eq!(status.signal(), Some(libc::SIGSYS), "{mode}: {status}");
}

#[test]
fn a_confined_warden_still_serves_and_writes_only_where_told() {
    let (status, root) = run("serve");
    assert!(status.success(), "{status}");
    assert!(root.path().join("canary/canary").exists());
    assert!(!root.path().join("closed/x").exists());
}

#[test]
fn execve_kills_the_warden() {
    assert_killed("execve");
}

#[test]
fn a_new_namespace_kills_the_warden() {
    assert_killed("unshare");
    assert_killed("clone_namespace");
}

#[test]
fn entering_any_namespace_but_a_network_one_kills_the_warden() {
    assert_killed("setns_mount");
}
