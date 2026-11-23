//! Programs that read the kernel, held by the warden on the agent's behalf.
//!
//! On the floor kernel, creating a raw tracepoint, `kprobe_multi` or
//! `uprobe_multi` link checks no capability: whoever holds such a program's
//! descriptor chooses where it reads. The agent loads these programs before it
//! hears from the network, hands each to the warden and closes its copies, so
//! the programs it shipped reach the kernel only where [`HELD_PROGRAMS`] says
//! they may, attached by the warden. A program of the agent's own making is
//! the kernel's to refuse at load, where signed loading is enforced.
//!
//! A held program is pinned in a directory of the warden's own, outside the
//! bpffs delegated to the agent, so it outlives a warden restart and the
//! agent's mount namespace cannot reach it. A descriptor is accepted only for
//! a listed name and a program of the type listed for it, read from the
//! kernel, never from the request.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};

use ebpfsentinel_warden_proto::{HELD_PROGRAMS, HeldProgram, HeldTarget, held_program};

/// Where the held programs are pinned unless `EBPFSENTINEL_HELD_PROGRAM_DIR`
/// says otherwise.
pub const DEFAULT_HELD_PROGRAM_DIR: &str = "/sys/fs/bpf/ebpfsentinel-held";

/// The environment variable that moves the directory.
pub const HELD_PROGRAM_DIR_ENV: &str = "EBPFSENTINEL_HELD_PROGRAM_DIR";

/// `BPF_OBJ_PIN` from `enum bpf_cmd`.
const BPF_OBJ_PIN: libc::c_int = 6;
/// `BPF_OBJ_GET` from `enum bpf_cmd`.
const BPF_OBJ_GET: libc::c_int = 7;
/// `BPF_OBJ_GET_INFO_BY_FD` from `enum bpf_cmd`.
const BPF_OBJ_GET_INFO_BY_FD: libc::c_int = 15;
/// `BPF_RAW_TRACEPOINT_OPEN` from `enum bpf_cmd`.
const BPF_RAW_TRACEPOINT_OPEN: libc::c_int = 17;
/// `BPF_LINK_CREATE` from `enum bpf_cmd`.
const BPF_LINK_CREATE: libc::c_int = 28;
/// `BPF_TRACE_KPROBE_MULTI` from `enum bpf_attach_type`.
const BPF_TRACE_KPROBE_MULTI: u32 = 42;
/// `BPF_F_KPROBE_MULTI_RETURN`: the link fires on function return.
const BPF_F_KPROBE_MULTI_RETURN: u32 = 1;

/// `union bpf_attr` for `BPF_OBJ_PIN` / `BPF_OBJ_GET`.
#[repr(C)]
#[derive(Default)]
struct ObjAttr {
    pathname: u64,
    bpf_fd: u32,
    file_flags: u32,
    _tail: [u64; 6],
}

/// `union bpf_attr` for `BPF_OBJ_GET_INFO_BY_FD`.
#[repr(C)]
#[derive(Default)]
struct InfoAttr {
    bpf_fd: u32,
    info_len: u32,
    info: u64,
}

/// The head of `struct bpf_prog_info`, up to and including `name`: `type`
/// (0), `id` (4), `tag` (8), lengths (16, 20), instruction pointers (24, 32),
/// `load_time` (40), `created_by_uid` (48), `nr_map_ids` (52), `map_ids`
/// (56), `name` (64). Every pointer is left zero, so the kernel copies
/// nothing but this head.
#[repr(C)]
#[derive(Default)]
struct ProgInfoHead {
    prog_type: u32,
    id: u32,
    tag: [u8; 8],
    jited_prog_len: u32,
    xlated_prog_len: u32,
    jited_prog_insns: u64,
    xlated_prog_insns: u64,
    load_time: u64,
    created_by_uid: u32,
    nr_map_ids: u32,
    map_ids: u64,
    name: [u8; 16],
}

/// `union bpf_attr` for `BPF_RAW_TRACEPOINT_OPEN`.
#[repr(C)]
#[derive(Default)]
struct RawTracepointOpenAttr {
    name: u64,
    prog_fd: u32,
    _pad: u32,
    cookie: u64,
}

/// `union bpf_attr` for `BPF_LINK_CREATE` with the `kprobe_multi` member:
/// `prog_fd` (0), `attach_type` (8), `flags` (12), then `{ flags(16),
/// cnt(20), syms(24), addrs(32), cookies(40) }`.
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

/// The directory the held programs live in.
#[must_use]
pub fn held_dir() -> PathBuf {
    std::env::var_os(HELD_PROGRAM_DIR_ENV)
        .filter(|v| !v.is_empty())
        .map_or_else(|| PathBuf::from(DEFAULT_HELD_PROGRAM_DIR), PathBuf::from)
}

fn listed(name: &str) -> Result<&'static HeldProgram, String> {
    held_program(name).ok_or_else(|| format!("{name:?} is not a program the warden holds"))
}

fn sys_bpf<T>(cmd: libc::c_int, attr: &mut T) -> io::Result<RawFd> {
    // SAFETY: `attr` is a fully initialised `bpf_attr` member owned by the
    // caller for the whole call, every pointer in it points at memory that
    // outlives the call, and the size passed is the struct's own.
    let rc = unsafe {
        crate::bpf(
            cmd,
            std::ptr::from_mut(attr).cast(),
            std::mem::size_of::<T>(),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    RawFd::try_from(rc).map_err(|_| io::Error::other("a descriptor out of range"))
}

/// The program type of `fd`, as the kernel reports it.
fn prog_type(fd: RawFd) -> Result<u32, String> {
    let mut info = ProgInfoHead::default();
    let raw = u32::try_from(fd).map_err(|_| "a negative descriptor".to_owned())?;
    let mut attr = InfoAttr {
        bpf_fd: raw,
        info_len: u32::try_from(std::mem::size_of::<ProgInfoHead>()).unwrap_or(u32::MAX),
        info: std::ptr::from_mut(&mut info) as u64,
    };
    sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &mut attr)
        .map_err(|e| format!("the descriptor is not a BPF program: {e}"))?;
    Ok(info.prog_type)
}

fn check_type(program: &HeldProgram, fd: RawFd) -> Result<(), String> {
    let found = prog_type(fd)?;
    let wanted = program.target.prog_type();
    if found == wanted {
        Ok(())
    } else {
        Err(format!(
            "{:?} must be a program of type {wanted}, the descriptor is of type {found}",
            program.name
        ))
    }
}

fn obj(cmd: libc::c_int, path: &Path, fd: u32) -> io::Result<RawFd> {
    let c_path = CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| io::Error::other("pin path carries a NUL byte"))?;
    let mut attr = ObjAttr {
        pathname: c_path.as_ptr() as u64,
        bpf_fd: fd,
        ..ObjAttr::default()
    };
    sys_bpf(cmd, &mut attr)
}

/// Pin the program `fd` as `name` in `dir`, replacing a program held under
/// that name before, once the name is listed and the program is of the type
/// listed for it.
///
/// # Errors
///
/// A name the warden does not hold, a descriptor that is not a program of
/// the listed type, or the pin failing.
pub fn hold(dir: &Path, name: &str, fd: RawFd) -> Result<(), String> {
    let program = listed(name)?;
    check_type(program, fd)?;
    let raw = u32::try_from(fd).map_err(|_| "a negative descriptor".to_owned())?;
    std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let path = dir.join(program.name);
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("replace {}: {e}", path.display())),
    }
    obj(BPF_OBJ_PIN, &path, raw)
        .map(|_| ())
        .map_err(|e| format!("pin {}: {e}", path.display()))
}

/// Open the program held as `name` in `dir`, checked again against the type
/// listed for it, since the directory outlives this process.
///
/// # Errors
///
/// A name the warden does not hold, nothing held under it, or a pin of the
/// wrong type.
pub fn open(dir: &Path, name: &str) -> Result<(&'static HeldProgram, OwnedFd), String> {
    let program = listed(name)?;
    let path = dir.join(program.name);
    let fd = obj(BPF_OBJ_GET, &path, 0)
        .map_err(|e| format!("{name:?} is not held ({}): {e}", path.display()))?;
    // SAFETY: `BPF_OBJ_GET` returned a fresh descriptor this process owns and
    // nothing else holds.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    check_type(program, owned.as_raw_fd())?;
    Ok((program, owned))
}

/// The names held in `dir`, in the order [`HELD_PROGRAMS`] lists them.
#[must_use]
pub fn held(dir: &Path) -> Vec<&'static str> {
    HELD_PROGRAMS
        .iter()
        .filter(|p| dir.join(p.name).exists())
        .map(|p| p.name)
        .collect()
}

/// Attach the held program `name` to the raw tracepoint or kernel function
/// listed for it and return the link.
///
/// # Errors
///
/// As [`open`], a program listed for a uprobe, or the kernel refusing the
/// link.
pub fn attach(dir: &Path, name: &str) -> Result<OwnedFd, String> {
    let (program, prog) = open(dir, name)?;
    let prog_fd = u32::try_from(prog.as_raw_fd()).map_err(|_| "a negative descriptor")?;
    let link = match program.target {
        HeldTarget::RawTracepoint(tracepoint) => {
            let tp = CString::new(tracepoint).map_err(|_| "a tracepoint with a NUL byte")?;
            let mut attr = RawTracepointOpenAttr {
                name: tp.as_ptr() as u64,
                prog_fd,
                ..RawTracepointOpenAttr::default()
            };
            sys_bpf(BPF_RAW_TRACEPOINT_OPEN, &mut attr)
                .map_err(|e| format!("BPF_RAW_TRACEPOINT_OPEN({tracepoint}) for {name}: {e}"))?
        }
        HeldTarget::Kprobe { symbol, is_ret } => {
            let sym = CString::new(symbol).map_err(|_| "a symbol with a NUL byte")?;
            let syms = [sym.as_ptr() as u64];
            let mut attr = KprobeMultiLinkAttr {
                prog_fd,
                attach_type: BPF_TRACE_KPROBE_MULTI,
                kmulti_flags: if is_ret { BPF_F_KPROBE_MULTI_RETURN } else { 0 },
                cnt: 1,
                syms: syms.as_ptr() as u64,
                ..KprobeMultiLinkAttr::default()
            };
            sys_bpf(BPF_LINK_CREATE, &mut attr)
                .map_err(|e| format!("BPF_LINK_CREATE(kprobe_multi {symbol}) for {name}: {e}"))?
        }
        HeldTarget::Uprobe { .. } => {
            return Err(format!(
                "{name:?} is a uprobe program, attached with a path"
            ));
        }
    };
    // SAFETY: the kernel returned a fresh link descriptor this process owns.
    Ok(unsafe { OwnedFd::from_raw_fd(link) })
}

/// Attach the held uprobe program `name` at `offset` within the ELF at
/// `path`, entry or return as listed for it, through the uprobe admission.
///
/// # Errors
///
/// As [`open`], a program not listed for a uprobe, the admission refusing
/// the target, or the kernel refusing the link.
pub fn attach_uprobe(dir: &Path, name: &str, path: &str, offset: u64) -> Result<OwnedFd, String> {
    let (program, prog) = open(dir, name)?;
    let HeldTarget::Uprobe { is_ret } = program.target else {
        return Err(format!("{name:?} is not a uprobe program"));
    };
    let link = crate::uprobe_ops::attach_uprobe_link(prog.as_raw_fd(), path, offset, is_ret)?;
    // SAFETY: `attach_uprobe_link` returned a fresh link descriptor this
    // process owns and nothing else holds.
    Ok(unsafe { OwnedFd::from_raw_fd(link) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attr_layouts_match_the_uapi() {
        let i = ProgInfoHead::default();
        let base = std::ptr::from_ref(&i) as usize;
        assert_eq!(std::ptr::from_ref(&i.load_time) as usize - base, 40);
        assert_eq!(std::ptr::from_ref(&i.map_ids) as usize - base, 56);
        assert_eq!(std::ptr::from_ref(&i.name) as usize - base, 64);
        let k = KprobeMultiLinkAttr::default();
        let base = std::ptr::from_ref(&k) as usize;
        assert_eq!(std::ptr::from_ref(&k.kmulti_flags) as usize - base, 16);
        assert_eq!(std::ptr::from_ref(&k.syms) as usize - base, 24);
        let r = RawTracepointOpenAttr::default();
        let base = std::ptr::from_ref(&r) as usize;
        assert_eq!(std::ptr::from_ref(&r.prog_fd) as usize - base, 8);
    }

    #[test]
    fn a_name_the_warden_does_not_hold_is_refused_before_any_descriptor() {
        let dir = Path::new("/nonexistent");
        let err = hold(dir, "../xdp_firewall", 0).unwrap_err();
        assert!(err.contains("not a program the warden holds"), "{err}");
        let err = attach(dir, "xdp_firewall").unwrap_err();
        assert!(err.contains("not a program the warden holds"), "{err}");
    }

    #[test]
    fn a_descriptor_that_is_not_a_program_is_not_held() {
        let file = std::fs::File::open("/dev/null").expect("open");
        let dir = std::env::temp_dir().join("held-programs-test-not-a-program");
        let err = hold(&dir, "process_exec", file.as_raw_fd()).unwrap_err();
        assert!(err.contains("not a BPF program"), "{err}");
        assert!(!dir.join("process_exec").exists());
    }

    #[test]
    fn nothing_held_attaches_nothing() {
        let dir = std::env::temp_dir().join("held-programs-test-empty");
        assert!(held(&dir).is_empty());
        let err = attach(&dir, "process_exec").unwrap_err();
        assert!(err.contains("is not held"), "{err}");
        let err = attach_uprobe(&dir, "ssl_write", "/usr/lib/libssl.so.3", 16).unwrap_err();
        assert!(err.contains("is not held"), "{err}");
    }
}
