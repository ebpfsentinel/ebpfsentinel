#![allow(unsafe_code)] // Raw bpf() syscalls for attaching raw kfunc program fds.

//! Raw attach for kfunc programs the [`super::kfunc_loader`] loads outside aya.
//!
//! A program loaded via raw `BPF_PROG_LOAD` is just an `OwnedFd` - aya never
//! created a `Program` handle for it, so aya's attach helpers cannot reach it.
//! This module attaches such fds the same way aya would, via raw syscalls:
//!
//! - XDP: `BPF_LINK_CREATE` with `attach_type = BPF_XDP` and `target_ifindex`.
//! - TC: `BPF_LINK_CREATE` with `attach_type = BPF_TCX_INGRESS|EGRESS` (TCX,
//!   kernel 6.6+ - the same path aya uses for modern TC attach).
//! - tail calls: a raw `BPF_MAP_UPDATE_ELEM` into a `PROG_ARRAY`, so a slot can
//!   point at a raw-loaded program fd.
//! - uprobe: `perf_event_open` against the kernel `uprobe` PMU (one event per
//!   online CPU for system-wide coverage), then `PERF_EVENT_IOC_SET_BPF` to
//!   bind the program fd and `PERF_EVENT_IOC_ENABLE`. aya would load and
//!   attach uprobes itself, but it never created a program handle for a
//!   raw-loaded fd.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use object::{Object, ObjectSegment, ObjectSymbol};
use tracing::info;

/// `bpf(2)` commands.
const BPF_LINK_CREATE: u32 = 28;
const BPF_LINK_UPDATE: u32 = 29;
const BPF_MAP_UPDATE_ELEM: u32 = 2;
const BPF_RAW_TRACEPOINT_OPEN: u32 = 17;

/// `enum bpf_attach_type` values (see `<linux/bpf.h>`).
const BPF_XDP: u32 = 37;
const BPF_TCX_INGRESS: u32 = 46;
const BPF_TCX_EGRESS: u32 = 47;

/// Subset of `union bpf_attr` for `BPF_LINK_CREATE`.
///
/// Field offsets match the kernel UAPI exactly: `prog_fd` (0),
/// `target_ifindex` aliasing `target_fd` (4), `attach_type` (8), `flags` (12),
/// then the per-type union (16+) - here the TCX/netkit shape
/// `{ relative_fd; expected_revision }`. The trailing padding covers the
/// largest union member so the kernel always reads a fully-initialised attr.
#[repr(C)]
#[derive(Default)]
struct LinkCreateAttr {
    prog_fd: u32,
    target_ifindex: u32,
    attach_type: u32,
    flags: u32,
    relative_fd: u32,
    _pad: u32,
    expected_revision: u64,
    _tail: [u64; 4],
}

/// Subset of `union bpf_attr` for `BPF_LINK_UPDATE`.
///
/// `link_fd` (0), `new_prog_fd` (4), `flags` (8), `old_prog_fd` (12). The
/// command swaps the program a live link runs without the link ever pointing
/// at nothing, which is the only way a hook changes program with no window
/// where a packet crosses an interface carrying none.
#[repr(C)]
#[derive(Default)]
struct LinkUpdateAttr {
    link_fd: u32,
    new_prog_fd: u32,
    flags: u32,
    old_prog_fd: u32,
}

/// Subset of `union bpf_attr` for `BPF_RAW_TRACEPOINT_OPEN`.
///
/// `name` is a pointer to the NUL-terminated tracepoint name (0), `prog_fd`
/// (8), then the cookie the kernel hands back to the program (16). A raw
/// tracepoint is bound by name at this point and not at load, which is why
/// the program itself carries no attach type.
#[repr(C)]
#[derive(Default)]
struct RawTracepointOpenAttr {
    name: u64,
    prog_fd: u32,
    _pad: u32,
    cookie: u64,
}

/// Subset of `union bpf_attr` for map element ops.
///
/// `map_fd` (0), `key` pointer (8), `value` pointer (16), `flags` (24) -
/// matching the kernel's `__aligned_u64` layout.
#[repr(C)]
#[derive(Default)]
struct MapElemAttr {
    map_fd: u32,
    _pad: u32,
    key: u64,
    value: u64,
    flags: u64,
}

/// Errors from raw attach operations.
#[derive(Debug, thiserror::Error)]
pub enum KfuncAttachError {
    #[error("resolve ifindex for `{iface}`: {message}")]
    Ifindex { iface: String, message: String },

    #[error(
        "BPF_LINK_CREATE(attach_type={attach_type}) for `{program}` on ifindex={ifindex}: errno={errno} {message}"
    )]
    LinkCreate {
        program: String,
        ifindex: u32,
        attach_type: u32,
        errno: i32,
        message: String,
    },

    #[error("BPF_LINK_UPDATE for `{program}`: errno={errno} {message}")]
    LinkUpdate {
        program: String,
        errno: i32,
        message: String,
    },

    #[error("BPF_MAP_UPDATE_ELEM(prog_array index={index}): errno={errno} {message}")]
    ProgArray {
        index: u32,
        errno: i32,
        message: String,
    },

    #[error("resolve symbol `{symbol}` in `{target}`: {message}")]
    UprobeSymbol {
        target: String,
        symbol: String,
        message: String,
    },

    #[error("BPF_LINK_CREATE(uprobe_multi `{symbol}` in `{target}`): errno={errno} {message}")]
    UprobeLink {
        target: String,
        symbol: String,
        errno: i32,
        message: String,
    },

    #[error("open cgroup `{path}`: {message}")]
    CgroupOpen { path: String, message: String },

    #[error(
        "BPF_LINK_CREATE(cgroup attach_type={attach_type}) for `{program}` on `{path}`: errno={errno} {message}"
    )]
    CgroupLink {
        program: String,
        path: String,
        attach_type: u32,
        errno: i32,
        message: String,
    },

    #[error("tracepoint name `{tracepoint}` is not a C string: {message}")]
    RawTracepointName { tracepoint: String, message: String },

    #[error("BPF_RAW_TRACEPOINT_OPEN(`{tracepoint}`) for `{program}`: errno={errno} {message}")]
    RawTracepointOpen {
        program: String,
        tracepoint: String,
        errno: i32,
        message: String,
    },

    #[error("kprobe symbol `{symbol}` is not attachable: {message}")]
    KprobeSymbol { symbol: String, message: String },

    #[error("BPF_LINK_CREATE(kprobe_multi `{symbol}`): errno={errno} {message}")]
    KprobeLink {
        symbol: String,
        errno: i32,
        message: String,
    },
}

/// Resolve a network interface name to its kernel ifindex.
pub fn iface_to_ifindex(iface: &str) -> Result<u32, KfuncAttachError> {
    let path = format!("/sys/class/net/{iface}/ifindex");
    std::fs::read_to_string(&path)
        .map_err(|e| KfuncAttachError::Ifindex {
            iface: iface.to_owned(),
            message: e.to_string(),
        })?
        .trim()
        .parse::<u32>()
        .map_err(|e| KfuncAttachError::Ifindex {
            iface: iface.to_owned(),
            message: e.to_string(),
        })
}

/// Attach a raw XDP program fd to `iface` via `BPF_LINK_CREATE`. `xdp_flags`
/// carries the XDP mode bits (`0` lets the kernel pick). Returns the link fd;
/// dropping it detaches.
pub fn attach_xdp(
    program: &str,
    prog_fd: RawFd,
    iface: &str,
    xdp_flags: u32,
) -> Result<OwnedFd, KfuncAttachError> {
    let ifindex = iface_to_ifindex(iface)?;
    let fd = link_create(program, prog_fd, ifindex, BPF_XDP, xdp_flags)?;
    info!(program, iface, "XDP kfunc program attached (raw link)");
    Ok(fd)
}

/// Attach a raw TC program fd to `iface` via TCX `BPF_LINK_CREATE`.
/// `egress` selects `BPF_TCX_EGRESS`, otherwise `BPF_TCX_INGRESS`.
pub fn attach_tcx(
    program: &str,
    prog_fd: RawFd,
    iface: &str,
    egress: bool,
) -> Result<OwnedFd, KfuncAttachError> {
    let ifindex = iface_to_ifindex(iface)?;
    let attach_type = if egress {
        BPF_TCX_EGRESS
    } else {
        BPF_TCX_INGRESS
    };
    let fd = link_create(program, prog_fd, ifindex, attach_type, 0)?;
    let dir = if egress { "egress" } else { "ingress" };
    info!(
        program,
        iface, dir, "TC kfunc program attached (raw TCX link)"
    );
    Ok(fd)
}

/// Set slot `index` of a `PROG_ARRAY` (identified by `array_fd`) to `prog_fd`.
/// Works regardless of whether `prog_fd` came from aya or the raw loader.
pub fn prog_array_set(array_fd: RawFd, index: u32, prog_fd: RawFd) -> Result<(), KfuncAttachError> {
    #[allow(clippy::cast_sign_loss)]
    let value: u32 = prog_fd as u32;
    let mut attr = MapElemAttr {
        #[allow(clippy::cast_sign_loss)]
        map_fd: array_fd as u32,
        key: std::ptr::from_ref(&index) as u64,
        value: std::ptr::from_ref(&value) as u64,
        flags: 0,
        ..Default::default()
    };
    let rc = unsafe {
        bpf(
            BPF_MAP_UPDATE_ELEM,
            (&raw mut attr).cast(),
            std::mem::size_of::<MapElemAttr>(),
        )
    };
    if rc < 0 {
        let err = io::Error::last_os_error();
        return Err(KfuncAttachError::ProgArray {
            index,
            errno: err.raw_os_error().unwrap_or(0),
            message: err.to_string(),
        });
    }
    Ok(())
}

/// Issue a `BPF_LINK_CREATE` binding `prog_fd` to `ifindex` for `attach_type`.
fn link_create(
    program: &str,
    prog_fd: RawFd,
    ifindex: u32,
    attach_type: u32,
    flags: u32,
) -> Result<OwnedFd, KfuncAttachError> {
    let mut attr = LinkCreateAttr {
        #[allow(clippy::cast_sign_loss)]
        prog_fd: prog_fd as u32,
        target_ifindex: ifindex,
        attach_type,
        flags,
        ..Default::default()
    };
    let rc = unsafe {
        bpf(
            BPF_LINK_CREATE,
            (&raw mut attr).cast(),
            std::mem::size_of::<LinkCreateAttr>(),
        )
    };
    if rc < 0 {
        let err = io::Error::last_os_error();
        return Err(KfuncAttachError::LinkCreate {
            program: program.to_owned(),
            ifindex,
            attach_type,
            errno: err.raw_os_error().unwrap_or(0),
            message: err.to_string(),
        });
    }
    #[allow(clippy::cast_possible_truncation)]
    let raw = rc as RawFd;
    // SAFETY: rc >= 0 is a valid link fd owned by this process.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// Point a live link at `new_prog_fd`, replacing the program it runs.
///
/// `BPF_LINK_UPDATE` is atomic in the kernel: the hook runs the old program
/// until the command returns and the new one after it, and at no instant does
/// it run neither. Not every attach type implements it - the kernel answers
/// `EINVAL` or `EOPNOTSUPP` where the link type has no `update_prog`, and a
/// program of a different type or a different device binding is refused the
/// same way - so a caller treats the error as a reason to fall back rather
/// than as a failure.
pub fn link_update(
    program: &str,
    link_fd: RawFd,
    new_prog_fd: RawFd,
) -> Result<(), KfuncAttachError> {
    let mut attr = LinkUpdateAttr {
        #[allow(clippy::cast_sign_loss)]
        link_fd: link_fd as u32,
        #[allow(clippy::cast_sign_loss)]
        new_prog_fd: new_prog_fd as u32,
        // No `BPF_F_REPLACE`: the old program is whatever the link carries,
        // and naming it would mean holding an fd on a program this process
        // is in the middle of dropping.
        flags: 0,
        old_prog_fd: 0,
    };
    let rc = unsafe {
        bpf(
            BPF_LINK_UPDATE,
            (&raw mut attr).cast(),
            std::mem::size_of::<LinkUpdateAttr>(),
        )
    };
    if rc < 0 {
        let err = io::Error::last_os_error();
        return Err(KfuncAttachError::LinkUpdate {
            program: program.to_owned(),
            errno: err.raw_os_error().unwrap_or(0),
            message: err.to_string(),
        });
    }
    Ok(())
}

// ── raw tracepoint attach ───────────────────────────────────────────────

/// Attach a raw-tracepoint program fd to the kernel tracepoint `tracepoint`.
///
/// `BPF_RAW_TRACEPOINT_OPEN` rather than `BPF_LINK_CREATE`: it is the command
/// the kernel offers for this program type, and it returns a link fd all the
/// same, so the attachment dies with the agent exactly as the cgroup and TCX
/// links do. No capability is checked here - the kernel asked for them when
/// the program was loaded, which under a BPF token happens in the agent's own
/// user namespace.
///
/// A kernel without the named tracepoint answers `ENOENT`, which is a reason
/// to report rather than a reason to fail: the caller degrades.
pub fn attach_raw_tracepoint(
    program: &str,
    prog_fd: RawFd,
    tracepoint: &str,
) -> Result<OwnedFd, KfuncAttachError> {
    let name = CString::new(tracepoint).map_err(|e| KfuncAttachError::RawTracepointName {
        tracepoint: tracepoint.to_owned(),
        message: e.to_string(),
    })?;
    let mut attr = RawTracepointOpenAttr {
        name: name.as_ptr() as u64,
        #[allow(clippy::cast_sign_loss)]
        prog_fd: prog_fd as u32,
        ..Default::default()
    };
    let rc = unsafe {
        bpf(
            BPF_RAW_TRACEPOINT_OPEN,
            (&raw mut attr).cast(),
            std::mem::size_of::<RawTracepointOpenAttr>(),
        )
    };
    if rc < 0 {
        let err = io::Error::last_os_error();
        return Err(KfuncAttachError::RawTracepointOpen {
            program: program.to_owned(),
            tracepoint: tracepoint.to_owned(),
            errno: err.raw_os_error().unwrap_or(0),
            message: err.to_string(),
        });
    }
    #[allow(clippy::cast_possible_truncation)]
    let raw = rc as RawFd;
    info!(program, tracepoint, "raw tracepoint attached");
    // SAFETY: rc >= 0 is a valid link fd owned by this process.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

// ── cgroup attach (cgroup BPF link) ─────────────────────────────────────

/// Attach a cgroup-type program fd to the cgroup directory at `cgroup_path`.
///
/// The target of a cgroup link is a directory fd rather than an ifindex, which
/// is the only thing that differs from the netdev attaches above: the same
/// `BPF_LINK_CREATE` field carries it, because the kernel's own union puts
/// `target_fd` and `target_ifindex` in the same place.
///
/// A link is used rather than `BPF_PROG_ATTACH` so the attachment is owned by
/// the returned fd: the agent exiting, crashing or being killed detaches the
/// program, where a prog-attach would leave it on the cgroup until somebody
/// detached it by hand.
pub fn attach_cgroup(
    program: &str,
    prog_fd: RawFd,
    cgroup_path: &str,
    attach_type: u32,
) -> Result<OwnedFd, KfuncAttachError> {
    let cgroup = std::fs::File::open(cgroup_path).map_err(|e| KfuncAttachError::CgroupOpen {
        path: cgroup_path.to_owned(),
        message: e.to_string(),
    })?;
    let fd = cgroup_link_create(
        program,
        prog_fd,
        cgroup.as_raw_fd(),
        cgroup_path,
        attach_type,
    )?;
    info!(
        program,
        cgroup = cgroup_path,
        attach_type,
        "cgroup program attached (raw link)"
    );
    Ok(fd)
}

/// Issue a `BPF_LINK_CREATE` binding `prog_fd` to the cgroup `target_fd`.
fn cgroup_link_create(
    program: &str,
    prog_fd: RawFd,
    target_fd: RawFd,
    cgroup_path: &str,
    attach_type: u32,
) -> Result<OwnedFd, KfuncAttachError> {
    let mut attr = LinkCreateAttr {
        #[allow(clippy::cast_sign_loss)]
        prog_fd: prog_fd as u32,
        #[allow(clippy::cast_sign_loss)]
        target_ifindex: target_fd as u32,
        attach_type,
        ..Default::default()
    };
    let rc = unsafe {
        bpf(
            BPF_LINK_CREATE,
            (&raw mut attr).cast(),
            std::mem::size_of::<LinkCreateAttr>(),
        )
    };
    if rc < 0 {
        let err = io::Error::last_os_error();
        return Err(KfuncAttachError::CgroupLink {
            program: program.to_owned(),
            path: cgroup_path.to_owned(),
            attach_type,
            errno: err.raw_os_error().unwrap_or(0),
            message: err.to_string(),
        });
    }
    #[allow(clippy::cast_possible_truncation)]
    let raw = rc as RawFd;
    // SAFETY: rc >= 0 is a valid link fd owned by this process.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

// ── uprobe attach (uprobe_multi BPF link) ───────────────────────────────

/// `BPF_TRACE_UPROBE_MULTI` from `enum bpf_attach_type`.
const BPF_TRACE_UPROBE_MULTI: u32 = 48;
/// `BPF_F_UPROBE_MULTI_RETURN`: the link fires on function return (uretprobe).
const BPF_F_UPROBE_MULTI_RETURN: u32 = 1;

/// `union bpf_attr` for `BPF_LINK_CREATE` with the `uprobe_multi` member.
///
/// Unlike `perf_event_open`, `BPF_LINK_CREATE` is a `bpf(2)` command, so it is
/// authorised by a delegated BPF token (`delegate_attachs`) - the path that
/// lets a token-only process attach a uprobe without `CAP_PERFMON`. Field
/// offsets match the kernel UAPI: `prog_fd` (0), `attach_type` (8), `flags`
/// (12), then the `uprobe_multi` block `{ path(16), offsets(24),
/// ref_ctr_offsets(32), cookies(40), cnt(48), flags(52), pid(56) }`.
#[repr(C)]
#[derive(Default)]
struct UprobeMultiLinkAttr {
    prog_fd: u32,
    target_fd: u32,
    attach_type: u32,
    link_flags: u32,
    path: u64,
    offsets: u64,
    ref_ctr_offsets: u64,
    cookies: u64,
    cnt: u32,
    umulti_flags: u32,
    pid: u32,
    _pad: u32,
    _tail: [u64; 2],
}

/// Attach a raw uprobe program fd at `offset` within `target` (a binary /
/// shared object path) via a `uprobe_multi` `BPF_LINK_CREATE`. System-wide
/// (`pid=0`). `is_ret` selects a uretprobe. Returns the link fd; dropping it
/// detaches.
///
/// The offset is taken as an argument rather than resolved here so the caller
/// keeps the value it attached at: an operator comparing two runs needs the
/// resolved offset, and a symbol resolved twice (once to attach, once to
/// report) could disagree with itself if the file changed in between.
/// [`resolve_symbol_offset`] turns a symbol name into that offset.
pub fn attach_uprobe_at_offset(
    program: &str,
    prog_fd: RawFd,
    target: &str,
    symbol: &str,
    offset: u64,
    is_ret: bool,
) -> Result<OwnedFd, KfuncAttachError> {
    let path_c = CString::new(target).map_err(|e| KfuncAttachError::UprobeSymbol {
        target: target.to_owned(),
        symbol: symbol.to_owned(),
        message: e.to_string(),
    })?;
    // A single-element offsets array; `cnt = 1`. Kept alive across the syscall.
    let offsets = [offset];

    let mut attr = UprobeMultiLinkAttr {
        #[allow(clippy::cast_sign_loss)]
        prog_fd: prog_fd as u32,
        attach_type: BPF_TRACE_UPROBE_MULTI,
        path: path_c.as_ptr() as u64,
        offsets: offsets.as_ptr() as u64,
        cnt: 1,
        umulti_flags: if is_ret { BPF_F_UPROBE_MULTI_RETURN } else { 0 },
        ..Default::default()
    };
    // SAFETY: `attr` is a fully-initialised link-create attr of the advertised
    // size; `path`/`offsets` point at live, correctly-sized buffers.
    let rc = unsafe {
        bpf(
            BPF_LINK_CREATE,
            (&raw mut attr).cast(),
            std::mem::size_of::<UprobeMultiLinkAttr>(),
        )
    };
    if rc < 0 {
        let err = io::Error::last_os_error();
        return Err(KfuncAttachError::UprobeLink {
            target: target.to_owned(),
            symbol: symbol.to_owned(),
            errno: err.raw_os_error().unwrap_or(0),
            message: err.to_string(),
        });
    }
    #[allow(clippy::cast_possible_truncation)]
    let raw = rc as RawFd;
    // SAFETY: rc >= 0 is a valid link fd owned by this process.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    let probe = if is_ret { "uretprobe" } else { "uprobe" };
    info!(
        program,
        target, symbol, probe, "uprobe kfunc program attached (uprobe_multi link)"
    );
    Ok(fd)
}

// ── kprobe attach (kprobe_multi BPF link) ───────────────────────────────

/// `BPF_TRACE_KPROBE_MULTI` from `enum bpf_attach_type`.
const BPF_TRACE_KPROBE_MULTI: u32 = 42;
/// `BPF_F_KPROBE_MULTI_RETURN`: the link fires on function return (kretprobe).
const BPF_F_KPROBE_MULTI_RETURN: u32 = 1;

/// `union bpf_attr` for `BPF_LINK_CREATE` with the `kprobe_multi` member.
///
/// Chosen over `perf_event_open` for the same reason the uprobe path is:
/// `BPF_LINK_CREATE` is a `bpf(2)` command and so is covered by a delegated
/// BPF token's `delegate_attachs`, while `perf_event_open` is a syscall of its
/// own that a token cannot authorise. The rootless agent therefore attaches a
/// kernel probe without `CAP_PERFMON` and without asking the warden.
///
/// Field offsets match the kernel UAPI: `prog_fd` (0), `attach_type` (8),
/// `flags` (12), then the `kprobe_multi` block `{ flags(16), cnt(20),
/// syms(24), addrs(32), cookies(40) }`.
#[repr(C)]
#[derive(Default)]
struct KprobeMultiLinkAttr {
    prog_fd: u32,
    target_fd: u32,
    attach_type: u32,
    link_flags: u32,
    kmulti_flags: u32,
    cnt: u32,
    syms: u64,
    addrs: u64,
    cookies: u64,
    _tail: [u64; 2],
}

/// Attach a raw kprobe program fd to the kernel function `symbol` via a
/// `kprobe_multi` `BPF_LINK_CREATE`. `is_ret` selects a kretprobe. Returns the
/// link fd; dropping it detaches.
///
/// The symbol is resolved by the kernel from its own ftrace tables, so no
/// address is computed here and `kallsyms` is not read. A symbol belonging to
/// a module that is not loaded, or one ftrace cannot hook, comes back as
/// `ENOENT` / `EINVAL` from the kernel - which is the expected answer for
/// `tls_sw_sendmsg` on a host where the `tls` module has never been used, and
/// is why the caller treats a failure here as "no kernel TLS on this host"
/// rather than as a fault.
pub fn attach_kprobe_by_symbol(
    program: &str,
    prog_fd: RawFd,
    symbol: &str,
    is_ret: bool,
) -> Result<OwnedFd, KfuncAttachError> {
    let symbol_c = CString::new(symbol).map_err(|e| KfuncAttachError::KprobeSymbol {
        symbol: symbol.to_owned(),
        message: e.to_string(),
    })?;
    // A single-element array of `const char *`; `cnt = 1`. Both the array and
    // the string it points at stay alive across the syscall.
    let syms = [symbol_c.as_ptr()];

    let mut attr = KprobeMultiLinkAttr {
        #[allow(clippy::cast_sign_loss)]
        prog_fd: prog_fd as u32,
        attach_type: BPF_TRACE_KPROBE_MULTI,
        kmulti_flags: if is_ret { BPF_F_KPROBE_MULTI_RETURN } else { 0 },
        cnt: 1,
        syms: syms.as_ptr() as u64,
        ..Default::default()
    };
    // SAFETY: `attr` is a fully-initialised link-create attr of the advertised
    // size; `syms` points at a live array of one live C string.
    let rc = unsafe {
        bpf(
            BPF_LINK_CREATE,
            (&raw mut attr).cast(),
            std::mem::size_of::<KprobeMultiLinkAttr>(),
        )
    };
    if rc < 0 {
        let err = io::Error::last_os_error();
        return Err(KfuncAttachError::KprobeLink {
            symbol: symbol.to_owned(),
            errno: err.raw_os_error().unwrap_or(0),
            message: err.to_string(),
        });
    }
    #[allow(clippy::cast_possible_truncation)]
    let raw = rc as RawFd;
    // SAFETY: rc >= 0 is a valid link fd owned by this process.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    let probe = if is_ret { "kretprobe" } else { "kprobe" };
    info!(
        program,
        symbol, probe, "kfunc program attached (kprobe_multi link)"
    );
    Ok(fd)
}

/// Resolve a symbol name to its file offset within an ELF binary / shared
/// object - the offset the `uprobe_multi` link expects. Prefers the dynamic
/// symbol table (exported functions), falling back to the static one.
pub fn resolve_symbol_offset(target: &str, symbol: &str) -> Result<u64, KfuncAttachError> {
    let err = |message: String| KfuncAttachError::UprobeSymbol {
        target: target.to_owned(),
        symbol: symbol.to_owned(),
        message,
    };
    // Headers and symbol tables are read out of the open file as `object` asks
    // for them, rather than the image being copied into memory first: a symbol
    // in a 400 MiB binary costs the tables, not the binary.
    let image = std::fs::File::open(target).map_err(|e| err(e.to_string()))?;
    let cache = object::read::ReadCache::new(image);
    let file = object::File::parse(&cache).map_err(|e| err(e.to_string()))?;

    let addr = file
        .dynamic_symbols()
        .chain(file.symbols())
        .find(|s| s.address() != 0 && s.name().is_ok_and(|n| n == symbol))
        .map(|s| s.address())
        .ok_or_else(|| err("symbol not found".to_owned()))?;

    // Translate the symbol's virtual address to a file offset via the segment
    // that contains it. For typical shared objects vaddr == file offset, but a
    // non-zero segment file offset must be accounted for.
    for seg in file.segments() {
        let start = seg.address();
        if addr >= start && addr < start + seg.size() {
            let (file_off, _) = seg.file_range();
            return Ok(addr - start + file_off);
        }
    }
    Ok(addr)
}

/// SAFETY wrapper: invoke `bpf(cmd, attr, size)`.
pub(super) unsafe fn bpf(cmd: u32, attr: *mut core::ffi::c_void, size: usize) -> i64 {
    // SAFETY: caller passes a valid attr region of `size` bytes matching the
    // union member the kernel reads for `cmd`.
    unsafe {
        libc::syscall(
            libc::SYS_bpf,
            #[allow(clippy::cast_possible_wrap)]
            (cmd as libc::c_int),
            attr as usize,
            size,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_create_attr_field_offsets_match_uapi() {
        let a = LinkCreateAttr::default();
        let base = std::ptr::from_ref(&a) as usize;
        assert_eq!(std::ptr::from_ref(&a.prog_fd) as usize - base, 0);
        assert_eq!(std::ptr::from_ref(&a.target_ifindex) as usize - base, 4);
        assert_eq!(std::ptr::from_ref(&a.attach_type) as usize - base, 8);
        assert_eq!(std::ptr::from_ref(&a.flags) as usize - base, 12);
        assert_eq!(std::ptr::from_ref(&a.relative_fd) as usize - base, 16);
        assert_eq!(std::ptr::from_ref(&a.expected_revision) as usize - base, 24);
    }

    #[test]
    fn link_update_attr_field_offsets_match_uapi() {
        let a = LinkUpdateAttr::default();
        let base = std::ptr::from_ref(&a) as usize;
        assert_eq!(std::ptr::from_ref(&a.link_fd) as usize - base, 0);
        assert_eq!(std::ptr::from_ref(&a.new_prog_fd) as usize - base, 4);
        assert_eq!(std::ptr::from_ref(&a.flags) as usize - base, 8);
        assert_eq!(std::ptr::from_ref(&a.old_prog_fd) as usize - base, 12);
    }

    #[test]
    fn map_elem_attr_field_offsets_match_uapi() {
        let a = MapElemAttr::default();
        let base = std::ptr::from_ref(&a) as usize;
        assert_eq!(std::ptr::from_ref(&a.map_fd) as usize - base, 0);
        assert_eq!(std::ptr::from_ref(&a.key) as usize - base, 8);
        assert_eq!(std::ptr::from_ref(&a.value) as usize - base, 16);
        assert_eq!(std::ptr::from_ref(&a.flags) as usize - base, 24);
    }

    #[test]
    fn uprobe_multi_link_attr_field_offsets_match_uapi() {
        let a = UprobeMultiLinkAttr::default();
        let base = std::ptr::from_ref(&a) as usize;
        // link-create header, then the `uprobe_multi` union member.
        assert_eq!(std::ptr::from_ref(&a.prog_fd) as usize - base, 0);
        assert_eq!(std::ptr::from_ref(&a.attach_type) as usize - base, 8);
        assert_eq!(std::ptr::from_ref(&a.link_flags) as usize - base, 12);
        assert_eq!(std::ptr::from_ref(&a.path) as usize - base, 16);
        assert_eq!(std::ptr::from_ref(&a.offsets) as usize - base, 24);
        assert_eq!(std::ptr::from_ref(&a.ref_ctr_offsets) as usize - base, 32);
        assert_eq!(std::ptr::from_ref(&a.cookies) as usize - base, 40);
        assert_eq!(std::ptr::from_ref(&a.cnt) as usize - base, 48);
        assert_eq!(std::ptr::from_ref(&a.umulti_flags) as usize - base, 52);
        assert_eq!(std::ptr::from_ref(&a.pid) as usize - base, 56);
    }

    #[test]
    fn iface_to_ifindex_resolves_loopback() {
        // lo is always ifindex 1 on Linux.
        assert_eq!(iface_to_ifindex("lo").unwrap(), 1);
    }

    #[test]
    fn iface_to_ifindex_errors_on_missing() {
        assert!(iface_to_ifindex("nonexistent_iface_xyz").is_err());
    }
}
