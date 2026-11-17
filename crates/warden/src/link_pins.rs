//! Link pins on the host bpffs, kept for an agent that cannot keep them itself.
//!
//! A rootless agent mounts the bpffs the warden delegated inside its own mount
//! namespace, and that superblock goes with the namespace when the agent
//! exits. A link pinned there detaches on the agent's death, which is the
//! opposite of what a firewall owes the node. The warden lives in the host's
//! mount namespace, so it pins the agent's links on the host bpffs, in one
//! directory, and hands them back to the agent that starts next.
//!
//! Only links and program arrays are pinned: the warden reads the
//! descriptor's `fdinfo` and refuses anything else, so this is not a way to
//! park an arbitrary map or program on the host. A program array has to be
//! there because the kernel empties one the moment no process and no pin
//! holds it, and a tail-call chain whose array emptied runs only its first
//! program. A name is checked against [`valid_link_pin_name`] before it
//! touches a path.

use std::ffi::CString;
use std::io;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};

use ebpfsentinel_warden_proto::valid_link_pin_name;

/// Where the pins live unless `EBPFSENTINEL_LINK_PIN_DIR` says otherwise.
pub const DEFAULT_LINK_PIN_DIR: &str = "/sys/fs/bpf/ebpfsentinel-links";

/// The environment variable that moves the directory.
pub const LINK_PIN_DIR_ENV: &str = "EBPFSENTINEL_LINK_PIN_DIR";

/// `BPF_OBJ_PIN` from `enum bpf_cmd`.
const BPF_OBJ_PIN: libc::c_long = 6;
/// `BPF_OBJ_GET` from `enum bpf_cmd`.
const BPF_OBJ_GET: libc::c_long = 7;

/// `union bpf_attr` for `BPF_OBJ_PIN` / `BPF_OBJ_GET`: `pathname` (0),
/// `bpf_fd` (8), `file_flags` (12), padded to cover the largest member the
/// kernel may read.
#[repr(C)]
#[derive(Default)]
struct ObjAttr {
    pathname: u64,
    bpf_fd: u32,
    file_flags: u32,
    _tail: [u64; 6],
}

/// The directory the pins live in.
#[must_use]
pub fn pin_dir() -> PathBuf {
    std::env::var_os(LINK_PIN_DIR_ENV)
        .filter(|v| !v.is_empty())
        .map_or_else(|| PathBuf::from(DEFAULT_LINK_PIN_DIR), PathBuf::from)
}

fn checked_path(dir: &Path, name: &str) -> Result<PathBuf, String> {
    if !valid_link_pin_name(name) {
        return Err(format!("{name:?} is not a link pin name"));
    }
    Ok(dir.join(name))
}

fn obj(cmd: libc::c_long, path: &Path, fd: u32) -> io::Result<libc::c_long> {
    let c_path = CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| io::Error::other("pin path carries a NUL byte"))?;
    let mut attr = ObjAttr {
        pathname: c_path.as_ptr() as u64,
        bpf_fd: fd,
        ..ObjAttr::default()
    };
    // SAFETY: `attr` is a fully initialised `bpf_attr` prefix whose `pathname`
    // points at a NUL-terminated string that outlives the call; the size passed
    // is the struct's own.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            cmd,
            (&raw mut attr).cast::<libc::c_void>(),
            std::mem::size_of::<ObjAttr>(),
        )
    };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc)
    }
}

/// `BPF_MAP_TYPE_PROG_ARRAY` from `enum bpf_map_type`.
const BPF_MAP_TYPE_PROG_ARRAY: u32 = 3;

/// Whether `fd` is a BPF link or a program array, read from
/// `/proc/self/fdinfo/<fd>`, which names a `link_type` for a link and a
/// `map_type` for a map.
fn is_pinnable(fd: RawFd) -> bool {
    std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}")).is_ok_and(|info| {
        info.lines().any(|l| {
            l.starts_with("link_type:")
                || l.strip_prefix("map_type:")
                    .is_some_and(|t| t.trim().parse() == Ok(BPF_MAP_TYPE_PROG_ARRAY))
        })
    })
}

/// Pin the link or program array `fd` under `name` in `dir`, replacing a pin of that name.
pub fn pin(dir: &Path, name: &str, fd: RawFd) -> Result<(), String> {
    let path = checked_path(dir, name)?;
    if !is_pinnable(fd) {
        return Err("the descriptor is neither a BPF link nor a program array".into());
    }
    let raw = u32::try_from(fd).map_err(|_| "a negative descriptor".to_owned())?;
    std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("replace {}: {e}", path.display())),
    }
    obj(BPF_OBJ_PIN, &path, raw)
        .map(|_| ())
        .map_err(|e| format!("pin {}: {e}", path.display()))
}

/// Every valid pin name in `dir`, sorted. A missing directory is no pins.
pub fn list(dir: &Path) -> Result<Vec<String>, String> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("read {}: {e}", dir.display())),
    };
    let mut names: Vec<String> = entries
        .filter_map(Result::ok)
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| valid_link_pin_name(n))
        .collect();
    names.sort();
    Ok(names)
}

/// Open the pin `name` in `dir`.
pub fn open(dir: &Path, name: &str) -> Result<OwnedFd, String> {
    let path = checked_path(dir, name)?;
    let fd = obj(BPF_OBJ_GET, &path, 0).map_err(|e| format!("open {}: {e}", path.display()))?;
    let fd = RawFd::try_from(fd).map_err(|_| "a descriptor out of range".to_owned())?;
    // SAFETY: `BPF_OBJ_GET` returned a fresh descriptor this process owns and
    // nothing else holds.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    if !is_pinnable(fd) {
        return Err(format!(
            "{} is neither a BPF link nor a program array",
            path.display()
        ));
    }
    Ok(owned)
}

/// Remove the pins `names` from `dir`, or every pin there when `names` is
/// empty. A name already gone is not an error.
pub fn unpin(dir: &Path, names: &[String]) -> Result<usize, String> {
    let names = if names.is_empty() {
        list(dir)?
    } else {
        names.to_vec()
    };
    let mut removed = 0;
    for name in &names {
        let path = checked_path(dir, name)?;
        match std::fs::remove_file(&path) {
            Ok(()) => removed += 1,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("unpin {}: {e}", path.display())),
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_that_would_leave_the_directory_is_refused_before_any_path() {
        let dir = Path::new("/nonexistent");
        assert!(checked_path(dir, "../etc").is_err());
        assert!(checked_path(dir, "eth0.100").is_err());
        assert_eq!(
            checked_path(dir, "xdp_eth0").unwrap(),
            Path::new("/nonexistent/xdp_eth0")
        );
    }

    #[test]
    fn a_missing_directory_holds_no_pins() {
        let dir = Path::new("/nonexistent/ebpfsentinel-links");
        assert!(list(dir).unwrap().is_empty());
        assert_eq!(unpin(dir, &[]).unwrap(), 0);
    }

    #[test]
    fn a_descriptor_that_is_not_a_link_is_not_pinned() {
        let file = std::fs::File::open("/proc/self/stat").unwrap();
        let dir = std::env::temp_dir();
        let err = pin(&dir, "xdp_test", std::os::fd::AsRawFd::as_raw_fd(&file)).unwrap_err();
        assert!(err.contains("neither a BPF link"), "{err}");
    }

    #[test]
    fn listing_skips_what_is_not_a_pin_name() {
        let dir = std::env::temp_dir().join(format!("link-pins-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("xdp_eth0"), b"").unwrap();
        std::fs::write(dir.join("not.a.pin"), b"").unwrap();
        assert_eq!(list(&dir).unwrap(), vec!["xdp_eth0".to_owned()]);
        assert_eq!(unpin(&dir, &[]).unwrap(), 1);
        assert!(list(&dir).unwrap().is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
