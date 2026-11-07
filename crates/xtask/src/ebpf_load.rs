//! Load every built object and say, program by program, what the kernel did.
//!
//! The agent loads only what its configuration asks for, and a program the
//! verifier refuses leaves the agent running without it, so a running agent is
//! not evidence that every object this build ships still loads. This command
//! asks the kernel about all of them, through the same loader the agent uses:
//! the kfunc call sites are prepatched, the object's BTF is sanitized and
//! loaded, its maps are created and every program goes to `BPF_PROG_LOAD`.
//!
//! Two ways in, the two the loader has:
//!
//! - **Privileged**: run as root with nothing else set. Every syscall runs on
//!   the process's own capabilities.
//! - **Token**: run as root with `EBPFSENTINEL_WARDEN_SOCK` pointing at a
//!   running warden. The process takes the agent's own route - a user
//!   namespace of its own, a bpffs the warden delegates, the module BTF fds the
//!   warden hands over - and every map, BTF and program load carries the BPF
//!   token, with no capability in the namespace the kernel checks.
//!
//! A program the agent itself loads as optional is loaded as optional here,
//! and its refusal is reported rather than failed: the guard's `bpf` hook is
//! written once per arity the kernel has given that hook, and only the one
//! matching the running kernel's BTF is expected to load, which this command
//! then requires.
//!
//! An XDP object reading the receive metadata kfuncs is loaded unbound, where
//! the loader turns those calls into `-EOPNOTSUPP`, unless `--dev-bound`
//! names a device: then it is bound to that device first, the way the agent
//! loads it on the interface it attaches to, and the kfunc calls reach the
//! verifier. The loader falls back to the unbound load when the device has no
//! metadata support, which the kernel's count of kfunc calls then shows.
//!
//! Each object is loaded unpinned, so it shares no map with another and leaves
//! nothing behind: a tail-call target is loaded with tables of its own rather
//! than its owner's, which the verifier judges the same way.
//!
//! The kernel's own count of kfunc calls in each loaded program is read back
//! from the translated instructions, which is the proof the prepatched call
//! sites reached the verifier as kfunc calls rather than as anything else. The
//! kernel shows translated instructions only to a caller holding `CAP_BPF` in
//! its initial namespace, so the token run reports that count as unknown.
//!
//! Needs root and the objects built: `cargo xtask ebpf-build`. Exits non-zero
//! when any object is refused, after reporting every one.

#![allow(unsafe_code)] // Raw bpf(BPF_OBJ_GET_INFO_BY_FD) for the translated instructions.

use std::mem;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::path::{Path, PathBuf};

use adapters::ebpf::ATTRIBUTION_JOIN_HOOK;
use adapters::ebpf::bpf_guard::{self, BPF_GUARD_CMD_PROGRAM_3, BPF_GUARD_CMD_PROGRAM_4};
use adapters::ebpf::kfunc_loader::{self, KfuncLoadedProgram, RefusedProgram};
use anyhow::{Result, bail};
use aya_obj::generated::{bpf_attr, bpf_cmd, bpf_prog_info, bpf_prog_type};

use crate::build_ebpf::EBPF_PROGRAMS;

/// Where the warden mounts the delegated bpffs when the caller names none.
const DEFAULT_BPFFS: &str = "/sys/fs/bpf/ebpfsentinel";

/// `BPF_JMP | BPF_CALL`, the opcode of every call instruction.
const BPF_CALL_OPCODE: u8 = 0x85;

/// `src_reg` of a call that targets a kernel function.
const BPF_PSEUDO_KFUNC_CALL: u8 = 2;

/// Size of one `struct bpf_insn`.
const INSN_SIZE: usize = 8;

/// What the kernel said about one program.
struct Loaded {
    program: String,
    kind: String,
    verified_insns: u32,
    /// Kfunc calls in the translated program, `None` where the kernel will not
    /// show the translation to this caller.
    kfunc_calls: Option<usize>,
}

/// What one object came to.
enum Outcome {
    Loaded {
        /// Kfunc call sites the prepatch rewrote in the object.
        sites: usize,
        programs: Vec<Loaded>,
        /// Optional programs the kernel refused.
        skipped: Vec<RefusedProgram>,
    },
    Refused(String),
}

pub fn run(dir: Option<PathBuf>, dev_bound: Option<String>) -> Result<()> {
    // The token route re-executes this process inside its own user namespace
    // and comes back here with the namespace ready. It returns at once when no
    // warden is configured, and must run before anything starts a thread.
    ebpfsentinel_warden::userns_bootstrap::maybe_bootstrap_from_env();
    let token = std::env::var_os("EBPFSENTINEL_WARDEN_SOCK").is_some_and(|s| !s.is_empty());

    let _handle = if token {
        let bpffs = std::env::var("EBPFSENTINEL_BPFFS").unwrap_or_else(|_| DEFAULT_BPFFS.into());
        let Some(handle) = ebpfsentinel_agent::startup::establish_bpf_token_at(&bpffs, true) else {
            bail!("no BPF token could be created against `{bpffs}`");
        };
        Some(handle)
    } else {
        if !is_root() {
            bail!("loading without a token needs root: re-run under sudo");
        }
        None
    };

    let ifindex = match dev_bound.as_deref() {
        Some(name) => Some(ifindex(name)?),
        None => None,
    };
    let dir = dir.unwrap_or_else(default_objects_dir);
    let mode = if token { "token" } else { "privileged" };
    println!(
        "loader: {mode}  kernel: {}  objects: {}  dev-bound: {}",
        kernel_release(),
        dir.display(),
        dev_bound.as_deref().unwrap_or("none")
    );

    let mut refused = 0usize;
    let mut programs = 0usize;
    for object in EBPF_PROGRAMS {
        let outcome = load(&dir.join(object), ifindex);
        match &outcome {
            Outcome::Loaded {
                sites,
                programs: loaded,
                skipped,
            } => {
                for p in loaded {
                    programs += 1;
                    let kfuncs = p
                        .kfunc_calls
                        .map_or_else(|| "?".to_string(), |n| n.to_string());
                    println!(
                        "ok       {object:<26} {:<28} {:<17} verified={:<7} kfunc_sites={sites:<3} kfunc_calls={kfuncs}",
                        p.program, p.kind, p.verified_insns
                    );
                }
                for p in skipped {
                    let first = p.reason.lines().next().unwrap_or_default();
                    println!("optional {object:<26} {:<28} refused: {first}", p.name);
                }
            }
            Outcome::Refused(reason) => {
                refused += 1;
                println!("REFUSED  {object:<26} {reason}");
            }
        }
    }

    println!(
        "loader: {mode}  objects: {}  programs loaded: {programs}  objects refused: {refused}",
        EBPF_PROGRAMS.len()
    );
    if refused > 0 {
        bail!("{refused} object(s) refused by the {mode} loader");
    }
    Ok(())
}

fn load(path: &Path, ifindex: Option<u32>) -> Outcome {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => return Outcome::Refused(format!("read {}: {e}", path.display())),
    };
    let sites = match kfunc_loader::find_kfunc_sites(&bytes) {
        Ok(s) => s.len(),
        Err(e) => return Outcome::Refused(format!("kfunc sites: {e}")),
    };
    let object = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    let bound = ifindex.filter(|_| kfunc_loader::uses_dev_bound_metadata_kfuncs(&bytes));
    let loaded =
        match kfunc_loader::load_object_token_unpinned(&bytes, bound, optional_programs(object)) {
            Ok(loaded) => loaded,
            Err(e) => return Outcome::Refused(e.to_string()),
        };
    if let Some(required) = required_here(object)
        && let Some(refused) = loaded.refused.iter().find(|p| p.name == required)
    {
        return Outcome::Refused(format!(
            "`{required}` is the program for this kernel and was refused: {}",
            refused.reason
        ));
    }
    Outcome::Loaded {
        sites,
        programs: loaded.programs.iter().map(describe).collect(),
        skipped: loaded.refused,
    }
}

/// The programs the agent loads as optional in `object`, the same lists its
/// start-up passes to the loader.
fn optional_programs(object: &str) -> &'static [&'static str] {
    match object {
        bpf_guard::BPF_GUARD_OBJECT => &[BPF_GUARD_CMD_PROGRAM_3, BPF_GUARD_CMD_PROGRAM_4],
        "cgroup-attribution" => &[ATTRIBUTION_JOIN_HOOK],
        _ => &[],
    }
}

/// Of the optional programs in `object`, the one this kernel must take: the
/// guard's `bpf` program written for the arity the running kernel's BTF gives
/// the hook. Where that BTF is unreadable nothing is required, and the guard
/// itself would refuse to start for the same reason.
fn required_here(object: &str) -> Option<&'static str> {
    (object == bpf_guard::BPF_GUARD_OBJECT)
        .then(bpf_guard::resolve_layout)
        .and_then(Result::ok)
        .map(|layout| layout.cmd_program)
}

fn describe(program: &KfuncLoadedProgram) -> Loaded {
    let info = prog_info(program.fd.as_fd());
    Loaded {
        program: program.name.clone(),
        kind: prog_type_name(program.prog_type),
        verified_insns: info.as_ref().map_or(0, |i| i.verified_insns),
        kfunc_calls: info.and_then(|i| i.kfunc_calls),
    }
}

struct ProgInfo {
    verified_insns: u32,
    kfunc_calls: Option<usize>,
}

/// Read the verifier's instruction count and, where the kernel shows it, the
/// translated program, counting the calls into kernel functions.
fn prog_info(fd: BorrowedFd<'_>) -> Option<ProgInfo> {
    // SAFETY: `bpf_prog_info` is plain data; all-zero is a valid value.
    let mut info = unsafe { mem::zeroed::<bpf_prog_info>() };
    obj_get_info(fd, &mut info).ok()?;
    let verified_insns = info.verified_insns;
    let len = info.xlated_prog_len as usize;
    if len == 0 {
        return Some(ProgInfo {
            verified_insns,
            kfunc_calls: None,
        });
    }

    let mut insns = vec![0u8; len];
    // SAFETY: as above.
    let mut second = unsafe { mem::zeroed::<bpf_prog_info>() };
    second.xlated_prog_len = info.xlated_prog_len;
    second.xlated_prog_insns = insns.as_mut_ptr() as u64;
    obj_get_info(fd, &mut second).ok()?;
    let kfunc_calls = insns
        .as_chunks::<INSN_SIZE>()
        .0
        .iter()
        .filter(|insn| insn[0] == BPF_CALL_OPCODE && insn[1] >> 4 == BPF_PSEUDO_KFUNC_CALL)
        .count();
    Some(ProgInfo {
        verified_insns,
        kfunc_calls: Some(kfunc_calls),
    })
}

fn obj_get_info(fd: BorrowedFd<'_>, info: &mut bpf_prog_info) -> std::io::Result<()> {
    // SAFETY: `bpf_attr` is plain data; all-zero is a valid value.
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    // SAFETY: only the `info` arm of the zeroed union is written.
    let arm = unsafe { &mut attr.info };
    arm.bpf_fd = fd.as_raw_fd() as u32;
    arm.info_len = mem::size_of::<bpf_prog_info>() as u32;
    arm.info = std::ptr::from_mut(info) as u64;
    // SAFETY: `attr` carries a valid fd and a pointer to `info`, which outlives
    // the call, with its size; any buffer `info` points at is sized as declared.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            bpf_cmd::BPF_OBJ_GET_INFO_BY_FD as libc::c_long,
            std::ptr::addr_of_mut!(attr),
            mem::size_of::<bpf_attr>() as libc::c_long,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn prog_type_name(prog_type: u32) -> String {
    let names: &[(bpf_prog_type, &str)] = &[
        (bpf_prog_type::BPF_PROG_TYPE_XDP, "xdp"),
        (bpf_prog_type::BPF_PROG_TYPE_SCHED_CLS, "sched_cls"),
        (bpf_prog_type::BPF_PROG_TYPE_KPROBE, "kprobe"),
        (bpf_prog_type::BPF_PROG_TYPE_TRACEPOINT, "tracepoint"),
        (
            bpf_prog_type::BPF_PROG_TYPE_RAW_TRACEPOINT,
            "raw_tracepoint",
        ),
        (bpf_prog_type::BPF_PROG_TYPE_TRACING, "tracing"),
        (bpf_prog_type::BPF_PROG_TYPE_LSM, "lsm"),
        (bpf_prog_type::BPF_PROG_TYPE_CGROUP_SKB, "cgroup_skb"),
        (bpf_prog_type::BPF_PROG_TYPE_CGROUP_SOCK, "cgroup_sock"),
        (
            bpf_prog_type::BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
            "cgroup_sock_addr",
        ),
        (bpf_prog_type::BPF_PROG_TYPE_SOCK_OPS, "sock_ops"),
    ];
    names
        .iter()
        .find(|(t, _)| *t as u32 == prog_type)
        .map_or_else(|| format!("type {prog_type}"), |(_, n)| (*n).to_string())
}

fn ifindex(name: &str) -> Result<u32> {
    let c = std::ffi::CString::new(name)?;
    // SAFETY: `c` is a valid NUL-terminated string for the length of the call.
    let index = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if index == 0 {
        bail!(
            "no interface named `{name}`: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(index)
}

fn kernel_release() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".into())
}

/// Where `cargo xtask ebpf-build` puts the objects, whoever invoked us: the
/// command runs under `sudo` from any directory, so the path is anchored on
/// this crate's own directory, baked in at compile time.
fn default_objects_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/bpfel-unknown-none/release")
}

fn is_root() -> bool {
    // SAFETY: `geteuid` takes no argument and cannot fail.
    unsafe { libc::geteuid() == 0 }
}
