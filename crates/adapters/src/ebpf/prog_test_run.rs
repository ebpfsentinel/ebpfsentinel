#![allow(unsafe_code)] // Raw bpf() syscall for BPF_PROG_TEST_RUN.

//! `BPF_PROG_TEST_RUN`: run a loaded program against a crafted packet.
//!
//! The verifier is the hardest reviewer this code has, and until a program is
//! loaded nothing has asked it anything. A test that loads every object and
//! pushes a packet through the entry programs turns a verifier rejection and
//! an action a program no longer returns into a failed `cargo test` rather
//! than into a deployment that comes up in degraded mode.
//!
//! The kernel runs the program on a copy of the packet with no interface, no
//! attach and no traffic: the return value is the action the program decided,
//! and `duration` is what one pass cost. `repeat` runs the program that many
//! times and averages, which is what makes the figure worth reading.
//!
//! Running a program needs the same privilege as loading one, so the harness
//! in `tests/` skips when the process holds neither `CAP_BPF` nor a token.

use std::os::fd::{AsRawFd, BorrowedFd};

use thiserror::Error;

use super::kfunc_attach::bpf;

const BPF_PROG_TEST_RUN: u32 = 10;

/// The kernel refuses a test packet shorter than an Ethernet header.
pub const MIN_PACKET: usize = 14;

/// Room left for a program that grows the packet it was handed.
const OUT_SLACK: usize = 512;

/// XDP return codes, so a test asserts a name rather than a number.
pub const XDP_ABORTED: u32 = 0;
/// Drop the packet.
pub const XDP_DROP: u32 = 1;
/// Let the packet through.
pub const XDP_PASS: u32 = 2;
/// Bounce the packet back out of the interface it arrived on.
pub const XDP_TX: u32 = 3;
/// Hand the packet to another interface or map target.
pub const XDP_REDIRECT: u32 = 4;

/// TC return codes, the same way.
pub const TC_ACT_OK: u32 = 0;
/// Drop the packet.
pub const TC_ACT_SHOT: u32 = 2;

/// The `bpf_attr` member `BPF_PROG_TEST_RUN` reads.
#[repr(C)]
#[derive(Default)]
struct TestRunAttr {
    prog_fd: u32,
    retval: u32,
    data_size_in: u32,
    data_size_out: u32,
    data_in: u64,
    data_out: u64,
    repeat: u32,
    duration: u32,
    ctx_size_in: u32,
    ctx_size_out: u32,
    ctx_in: u64,
    ctx_out: u64,
    flags: u32,
    cpu: u32,
    batch_size: u32,
}

/// What one run reported back.
#[derive(Debug, Clone)]
pub struct TestRunOutcome {
    /// The action the program returned.
    pub retval: u32,
    /// Average nanoseconds of one pass over the packet.
    pub duration_ns: u32,
    /// The packet as the program left it.
    pub data_out: Vec<u8>,
}

/// What a run can go wrong with.
#[derive(Debug, Error)]
pub enum TestRunError {
    /// The packet is shorter than the kernel will accept.
    #[error("a test packet is at least {MIN_PACKET} bytes, this one is {0}")]
    TooShort(usize),
    /// The kernel refused the run.
    #[error("BPF_PROG_TEST_RUN failed: {message}")]
    Syscall {
        /// The raw errno, so a caller can tell a missing privilege (`EPERM`)
        /// from a program type with no test-run support (`ENOTSUPP`).
        errno: i32,
        /// The error the kernel reported.
        message: String,
    },
}

impl TestRunError {
    /// True when the refusal is the environment rather than the program: no
    /// privilege, or a program type this kernel will not test-run.
    #[must_use]
    pub const fn is_unavailable(&self) -> bool {
        matches!(
            self,
            Self::Syscall {
                errno: libc::EPERM | libc::EOPNOTSUPP | libc::EINVAL | 524,
                ..
            }
        )
    }
}

/// Run `packet` through the program `repeat` times and report the last result.
///
/// `repeat` of zero is one pass, which is what the kernel does with it.
///
/// # Errors
///
/// [`TestRunError::TooShort`] for a packet the kernel would refuse outright,
/// and [`TestRunError::Syscall`] for anything the kernel reported.
pub fn run(
    prog_fd: BorrowedFd<'_>,
    packet: &[u8],
    repeat: u32,
) -> Result<TestRunOutcome, TestRunError> {
    if packet.len() < MIN_PACKET {
        return Err(TestRunError::TooShort(packet.len()));
    }

    let mut out = vec![0u8; packet.len() + OUT_SLACK];
    let mut attr = TestRunAttr {
        prog_fd: as_u32(prog_fd),
        data_size_in: u32::try_from(packet.len()).unwrap_or(u32::MAX),
        data_size_out: u32::try_from(out.len()).unwrap_or(u32::MAX),
        data_in: packet.as_ptr() as u64,
        data_out: out.as_mut_ptr() as u64,
        repeat,
        ..TestRunAttr::default()
    };

    // SAFETY: attr is a live TestRunAttr of exactly the size passed, the input
    // pointer addresses `data_size_in` readable bytes and the output pointer
    // `data_size_out` writable ones.
    let ret = unsafe {
        bpf(
            BPF_PROG_TEST_RUN,
            std::ptr::from_mut(&mut attr).cast(),
            size_of::<TestRunAttr>(),
        )
    };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        return Err(TestRunError::Syscall {
            errno: err.raw_os_error().unwrap_or(0),
            message: err.to_string(),
        });
    }

    out.truncate(attr.data_size_out as usize);
    Ok(TestRunOutcome {
        retval: attr.retval,
        duration_ns: attr.duration,
        data_out: out,
    })
}

/// The descriptor as the kernel wants it in `bpf_attr`.
#[allow(clippy::cast_sign_loss)] // A file descriptor is never negative here.
fn as_u32(fd: BorrowedFd<'_>) -> u32 {
    fd.as_raw_fd() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run_attr_matches_the_union_member_the_kernel_reads() {
        assert_eq!(size_of::<TestRunAttr>(), 80);
        let attr = TestRunAttr::default();
        let base = std::ptr::from_ref(&attr) as usize;
        let at = |field: &u32| std::ptr::from_ref(field) as usize - base;
        let at64 = |field: &u64| std::ptr::from_ref(field) as usize - base;
        assert_eq!(at(&attr.prog_fd), 0);
        assert_eq!(at(&attr.retval), 4);
        assert_eq!(at(&attr.data_size_in), 8);
        assert_eq!(at(&attr.data_size_out), 12);
        assert_eq!(at64(&attr.data_in), 16);
        assert_eq!(at64(&attr.data_out), 24);
        assert_eq!(at(&attr.repeat), 32);
        assert_eq!(at(&attr.duration), 36);
        assert_eq!(at(&attr.ctx_size_in), 40);
        assert_eq!(at(&attr.ctx_size_out), 44);
        assert_eq!(at64(&attr.ctx_in), 48);
        assert_eq!(at64(&attr.ctx_out), 56);
        assert_eq!(at(&attr.flags), 64);
        assert_eq!(at(&attr.cpu), 68);
        assert_eq!(at(&attr.batch_size), 72);
    }

    #[test]
    fn a_packet_shorter_than_an_ethernet_header_never_reaches_the_kernel() {
        let fd = std::io::stdin();
        let err = run(std::os::fd::AsFd::as_fd(&fd), &[0u8; 8], 1).unwrap_err();
        assert!(matches!(err, TestRunError::TooShort(8)));
    }

    #[test]
    fn a_refusal_by_the_environment_is_told_apart_from_a_failing_program() {
        let denied = TestRunError::Syscall {
            errno: libc::EPERM,
            message: "Operation not permitted".to_string(),
        };
        assert!(denied.is_unavailable());
        let broken = TestRunError::Syscall {
            errno: libc::EFAULT,
            message: "Bad address".to_string(),
        };
        assert!(!broken.is_unavailable());
    }
}
