//! The warden's self-confinement, exercised in child processes of this test
//! binary: each child confines itself and then does one thing, and the parent
//! reads how it ended. A confinement cannot be undone, so it never runs in the
//! process that runs the other tests.

#![allow(clippy::panic)]

use std::ffi::CString;
use std::io;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, ExitStatus};

use ebpfsentinel_warden::confine::confine;

const MODE: &str = "EBPFSENTINEL_CONFINE_TEST_MODE";

/// The entry point of every child: does nothing when run as an ordinary test.
#[test]
fn child() {
    let Ok(mode) = std::env::var(MODE) else {
        return;
    };
    confine().expect("confine");
    match mode.as_str() {
        "serve" => confined_work(),
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

/// What a confined warden still does: read its own status, run threads, read
/// another process's `/proc` entry, and fail a call on neither list.
fn confined_work() {
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

    // Every answer about a host process reads its `/proc` entry: the link
    // naming what it runs, its mappings. A confinement that scoped ptrace
    // would leave the warden serving and naming nothing.
    // SAFETY: `getppid` takes no argument and cannot fail.
    let parent = unsafe { libc::getppid() };
    std::fs::read_link(format!("/proc/{parent}/exe")).expect("the parent's executable");
    std::fs::read_to_string(format!("/proc/{parent}/maps")).expect("the parent's mappings");

    std::process::exit(0);
}

fn run(mode: &str) -> ExitStatus {
    Command::new(std::env::current_exe().expect("test binary"))
        .args(["child", "--exact", "--nocapture", "--test-threads=1"])
        .env(MODE, mode)
        .status()
        .expect("run the child")
}

fn assert_killed(mode: &str) {
    let status = run(mode);
    assert_eq!(status.signal(), Some(libc::SIGSYS), "{mode}: {status}");
}

#[test]
fn a_confined_warden_still_serves_and_reads_host_processes() {
    let status = run("serve");
    assert!(status.success(), "{status}");
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
