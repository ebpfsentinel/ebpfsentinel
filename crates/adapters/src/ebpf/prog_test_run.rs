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
    /// The structure is aligned to eight bytes, so four bytes follow
    /// `batch_size`. The kernel refuses an attribute whose bytes past the
    /// last field it knows are not zero, and implicit padding is whatever
    /// the stack held, so the tail is a field and is always written.
    _tail: u32,
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
    /// XDP metadata the kernel would refuse: over 32 bytes or not whole words.
    #[error("XDP metadata is whole words up to {MAX_XDP_METADATA} bytes, this one is {0}")]
    BadMetadata(usize),
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

/// The `struct xdp_md` a test run reads and writes back: 24 bytes.
const XDP_MD_LEN: usize = 24;

/// The `struct __sk_buff` a test run writes back, whole: the kernel refuses
/// to hand back fewer bytes than the structure holds.
const SK_BUFF_LEN: usize = 192;

/// Where `mark`, `priority` and `cb` sit in `struct __sk_buff`.
const SKB_MARK_OFF: usize = 8;
const SKB_PRIORITY_OFF: usize = 32;
const SKB_CB_OFF: usize = 48;

/// The most metadata the kernel lets an XDP test run carry.
pub const MAX_XDP_METADATA: usize = 32;

/// The fields of `struct __sk_buff` a classifier test run takes in and hands
/// back. Everything else in the structure is left zero, which is what the
/// kernel requires of the fields it does not accept.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SkbContext {
    /// `skb->mark`.
    pub mark: u32,
    /// `skb->priority`.
    pub priority: u32,
    /// `skb->cb`, the control block a classifier may write.
    pub cb: [u32; 5],
}

impl SkbContext {
    fn to_bytes(self) -> [u8; SK_BUFF_LEN] {
        let mut raw = [0u8; SK_BUFF_LEN];
        raw[SKB_MARK_OFF..SKB_MARK_OFF + 4].copy_from_slice(&self.mark.to_ne_bytes());
        raw[SKB_PRIORITY_OFF..SKB_PRIORITY_OFF + 4].copy_from_slice(&self.priority.to_ne_bytes());
        for (i, word) in self.cb.iter().enumerate() {
            let at = SKB_CB_OFF + i * 4;
            raw[at..at + 4].copy_from_slice(&word.to_ne_bytes());
        }
        raw
    }

    fn from_bytes(raw: &[u8; SK_BUFF_LEN]) -> Self {
        let word = |at: usize| u32::from_ne_bytes([raw[at], raw[at + 1], raw[at + 2], raw[at + 3]]);
        Self {
            mark: word(SKB_MARK_OFF),
            priority: word(SKB_PRIORITY_OFF),
            cb: std::array::from_fn(|i| word(SKB_CB_OFF + i * 4)),
        }
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
    let attr = test_run(
        TestRunAttr {
            prog_fd: as_u32(prog_fd),
            repeat,
            ..TestRunAttr::default()
        },
        packet,
        &mut out,
    )?;
    out.truncate(attr.data_size_out as usize);
    Ok(TestRunOutcome {
        retval: attr.retval,
        duration_ns: attr.duration,
        data_out: out,
    })
}

/// Run `packet` once through an XDP program with `metadata` in front of it,
/// and hand back the outcome and the metadata as the programs left it.
///
/// The metadata survives tail calls, so what one program writes there the
/// next one reads, and the run returns it with the packet.
///
/// # Errors
///
/// [`TestRunError::TooShort`] for a packet the kernel would refuse outright
/// or metadata it would refuse (over 32 bytes, or not whole words), and
/// [`TestRunError::Syscall`] for anything the kernel reported.
pub fn run_xdp_with_metadata(
    prog_fd: BorrowedFd<'_>,
    metadata: &[u8],
    packet: &[u8],
) -> Result<(TestRunOutcome, Vec<u8>), TestRunError> {
    if packet.len() < MIN_PACKET {
        return Err(TestRunError::TooShort(packet.len()));
    }
    if metadata.len() > MAX_XDP_METADATA || !metadata.len().is_multiple_of(4) {
        return Err(TestRunError::BadMetadata(metadata.len()));
    }
    let mut input = Vec::with_capacity(metadata.len() + packet.len());
    input.extend_from_slice(metadata);
    input.extend_from_slice(packet);

    // `data` is where the packet starts inside the buffer, `data_end` where
    // it stops, and `data_meta` must be zero: the metadata is what lies
    // between the two.
    let mut md_in = [0u8; XDP_MD_LEN];
    md_in[..4].copy_from_slice(&len_u32(metadata.len()).to_ne_bytes());
    md_in[4..8].copy_from_slice(&len_u32(input.len()).to_ne_bytes());
    let mut md_out = [0u8; XDP_MD_LEN];

    let mut out = vec![0u8; input.len() + OUT_SLACK];
    let attr = test_run(
        TestRunAttr {
            prog_fd: as_u32(prog_fd),
            repeat: 1,
            ctx_size_in: len_u32(XDP_MD_LEN),
            ctx_size_out: len_u32(XDP_MD_LEN),
            ctx_in: md_in.as_ptr() as u64,
            ctx_out: md_out.as_mut_ptr() as u64,
            ..TestRunAttr::default()
        },
        &input,
        &mut out,
    )?;
    out.truncate(attr.data_size_out as usize);
    // The run hands back the metadata in front of the packet, and `data` in
    // the output context says how long it now is.
    let meta_len =
        (u32::from_ne_bytes([md_out[0], md_out[1], md_out[2], md_out[3]]) as usize).min(out.len());
    let packet_out = out.split_off(meta_len);
    Ok((
        TestRunOutcome {
            retval: attr.retval,
            duration_ns: attr.duration,
            data_out: packet_out,
        },
        out,
    ))
}

/// Run `packet` once through a classifier with `ctx` as its `__sk_buff`, and
/// hand back the outcome and the context as the classifier left it.
///
/// # Errors
///
/// [`TestRunError::TooShort`] for a packet the kernel would refuse outright,
/// and [`TestRunError::Syscall`] for anything the kernel reported.
pub fn run_tc_with_context(
    prog_fd: BorrowedFd<'_>,
    packet: &[u8],
    ctx: SkbContext,
) -> Result<(TestRunOutcome, SkbContext), TestRunError> {
    if packet.len() < MIN_PACKET {
        return Err(TestRunError::TooShort(packet.len()));
    }
    let ctx_in = ctx.to_bytes();
    let mut ctx_out = [0u8; SK_BUFF_LEN];
    let mut out = vec![0u8; packet.len() + OUT_SLACK];
    let attr = test_run(
        TestRunAttr {
            prog_fd: as_u32(prog_fd),
            repeat: 1,
            ctx_size_in: len_u32(SK_BUFF_LEN),
            ctx_size_out: len_u32(SK_BUFF_LEN),
            ctx_in: ctx_in.as_ptr() as u64,
            ctx_out: ctx_out.as_mut_ptr() as u64,
            ..TestRunAttr::default()
        },
        packet,
        &mut out,
    )?;
    out.truncate(attr.data_size_out as usize);
    Ok((
        TestRunOutcome {
            retval: attr.retval,
            duration_ns: attr.duration,
            data_out: out,
        },
        SkbContext::from_bytes(&ctx_out),
    ))
}

/// Issue the syscall with `input` as the packet and `out` as room for the
/// packet the program leaves; the context pointers, if any, are the caller's.
fn test_run(
    mut attr: TestRunAttr,
    input: &[u8],
    out: &mut [u8],
) -> Result<TestRunAttr, TestRunError> {
    attr.data_size_in = len_u32(input.len());
    attr.data_size_out = len_u32(out.len());
    attr.data_in = input.as_ptr() as u64;
    attr.data_out = out.as_mut_ptr() as u64;

    // SAFETY: every pointer in `attr` names a buffer that outlives the call
    // and whose length is the size written beside it.
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
    Ok(attr)
}

fn len_u32(len: usize) -> u32 {
    u32::try_from(len).unwrap_or(u32::MAX)
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

    #[test]
    fn skb_context_sits_where_struct_sk_buff_keeps_it() {
        let ctx = SkbContext {
            mark: 0x1122_3344,
            priority: 7,
            cb: [1, 2, 3, 4, 5],
        };
        let raw = ctx.to_bytes();
        assert_eq!(&raw[8..12], &0x1122_3344u32.to_ne_bytes());
        assert_eq!(&raw[32..36], &7u32.to_ne_bytes());
        assert_eq!(&raw[48..52], &1u32.to_ne_bytes());
        assert_eq!(&raw[64..68], &5u32.to_ne_bytes());
        // Every field the kernel does not accept stays zero.
        assert!(raw[..8].iter().all(|b| *b == 0));
        assert!(raw[68..].iter().all(|b| *b == 0));
        assert_eq!(SkbContext::from_bytes(&raw), ctx);
    }

    #[test]
    fn metadata_the_kernel_would_refuse_never_reaches_it() {
        let fd = std::io::stdin();
        let fd = std::os::fd::AsFd::as_fd(&fd);
        let packet = [0u8; MIN_PACKET];
        assert!(matches!(
            run_xdp_with_metadata(fd, &[0u8; 36], &packet),
            Err(TestRunError::BadMetadata(36))
        ));
        assert!(matches!(
            run_xdp_with_metadata(fd, &[0u8; 6], &packet),
            Err(TestRunError::BadMetadata(6))
        ));
    }
}
