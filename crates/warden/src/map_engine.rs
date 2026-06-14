//! eBPF map element operations the warden performs for the rootless agent.
//!
//! `BPF_MAP_LOOKUP/UPDATE/DELETE_ELEM` are `bpf()` syscalls, which the runtime
//! default seccomp profile blocks for a non-`CAP_SYS_ADMIN` task. The agent
//! therefore cannot touch a map fd at all; it asks the warden, which holds the
//! capability, to perform the element op. The warden never executes an arbitrary
//! `bpf()` on request: it only operates on maps it has itself pinned and opened,
//! and only when the request's key/value lengths match that map's declared sizes.
//!
//! [`MapRegistry::open_pin_dir`] scans a bpffs directory, opens every map pin it
//! finds (`BPF_OBJ_GET`), and records each map's `key_size`/`value_size`
//! (`BPF_OBJ_GET_INFO_BY_FD`). The set of pinned maps *is* the allowlist — a
//! command naming a map that was not pinned is refused before any syscall.

use std::collections::HashMap;
use std::ffi::CString;
use std::fmt;
use std::fs;
use std::mem;
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

use crate::{BPF_OBJ_GET_INFO_BY_FD, BpfAttrInfo, bpf};

// `bpf(2)` command numbers (uapi/linux/bpf.h `enum bpf_cmd`).
const BPF_MAP_LOOKUP_ELEM: libc::c_int = 1;
const BPF_MAP_UPDATE_ELEM: libc::c_int = 2;
const BPF_MAP_DELETE_ELEM: libc::c_int = 3;
const BPF_OBJ_GET: libc::c_int = 7;

/// `pathname`/`bpf_fd` branch of `bpf_attr` (`BPF_OBJ_GET`).
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct BpfAttrObj {
    pathname: u64,
    bpf_fd: u32,
    file_flags: u32,
}

/// Element branch of `bpf_attr` (`BPF_MAP_*_ELEM`). `#[repr(C)]` reproduces the
/// kernel layout, padding `key` up to its natural 8-byte alignment after the
/// `u32` map fd — its size is asserted in the tests so the layout cannot drift.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct BpfAttrElem {
    map_fd: u32,
    key: u64,
    value: u64,
    flags: u64,
}

/// Leading fields of `struct bpf_map_info` — only `key_size`/`value_size` are
/// read; the kernel copies `min(info_len, actual)` bytes so this prefix is enough.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct BpfMapInfo {
    map_type: u32,
    id: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
    name: [u8; 16],
}

/// Why a map operation was refused or failed.
#[derive(Debug, PartialEq, Eq)]
pub enum MapOpError {
    /// No map of this name is pinned/allowlisted.
    UnknownMap(String),
    /// The supplied key length disagrees with the map's `key_size`.
    BadKeyLen {
        /// The map's declared key size.
        expected: u32,
        /// The length actually supplied.
        got: usize,
    },
    /// The supplied value length disagrees with the map's `value_size`.
    BadValueLen {
        /// The map's declared value size.
        expected: u32,
        /// The length actually supplied.
        got: usize,
    },
    /// The kernel rejected the element op with this `errno`.
    Syscall(i32),
}

impl fmt::Display for MapOpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownMap(name) => {
                write!(f, "unknown map '{name}' (not pinned/allowlisted)")
            }
            Self::BadKeyLen { expected, got } => {
                write!(f, "key length {got} != map key_size {expected}")
            }
            Self::BadValueLen { expected, got } => {
                write!(f, "value length {got} != map value_size {expected}")
            }
            Self::Syscall(errno) => write!(f, "bpf map element op failed: errno {errno}"),
        }
    }
}

impl std::error::Error for MapOpError {}

/// One opened, pinned map and the element sizes it enforces.
struct MapHandle {
    fd: RawFd,
    key_size: u32,
    value_size: u32,
}

/// The maps the warden has opened from a bpffs pin directory, keyed by pin name.
/// This set is the allowlist for [`Command::MapLookup`](ebpfsentinel_warden_proto::Command::MapLookup)
/// and friends.
#[derive(Default)]
pub struct MapRegistry {
    maps: HashMap<String, MapHandle>,
}

impl MapRegistry {
    /// Open every map pinned directly under `dir`. A missing directory yields an
    /// empty registry (map RPC simply has nothing to serve); non-map pins (program
    /// or link pins) are skipped because `BPF_OBJ_GET_INFO_BY_FD` for a map fails
    /// on them.
    #[must_use]
    pub fn open_pin_dir(dir: &Path) -> Self {
        let mut maps = HashMap::new();
        let Ok(entries) = fs::read_dir(dir) else {
            return Self { maps };
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if let Some((fd, key_size, value_size)) = open_pinned_map(&path) {
                maps.insert(
                    name.to_owned(),
                    MapHandle {
                        fd,
                        key_size,
                        value_size,
                    },
                );
            }
        }
        Self { maps }
    }

    /// Number of maps the registry serves.
    #[must_use]
    pub fn len(&self) -> usize {
        self.maps.len()
    }

    /// Whether the registry serves no maps.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.maps.is_empty()
    }

    /// The pin names the registry will accept, sorted for a stable log line.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.maps.keys().map(String::as_str).collect();
        names.sort_unstable();
        names
    }

    /// Look up one element. `Ok(None)` means the key is absent (`ENOENT`).
    pub fn lookup(&self, name: &str, key: &[u8]) -> Result<Option<Vec<u8>>, MapOpError> {
        let handle = self.handle(name)?;
        check_len(key.len(), handle.key_size, true)?;
        let mut value = vec![0u8; handle.value_size as usize];
        let mut elem = BpfAttrElem {
            map_fd: handle.fd as u32,
            key: key.as_ptr() as u64,
            value: value.as_mut_ptr() as u64,
            flags: 0,
        };
        let rc = unsafe {
            bpf(
                BPF_MAP_LOOKUP_ELEM,
                ptr::from_mut(&mut elem).cast(),
                mem::size_of::<BpfAttrElem>(),
            )
        };
        if rc < 0 {
            let errno = errno();
            if errno == libc::ENOENT {
                return Ok(None);
            }
            return Err(MapOpError::Syscall(errno));
        }
        Ok(Some(value))
    }

    /// Insert or update one element with `BPF_MAP_UPDATE_ELEM` `flags`.
    pub fn update(
        &self,
        name: &str,
        key: &[u8],
        value: &[u8],
        flags: u64,
    ) -> Result<(), MapOpError> {
        let handle = self.handle(name)?;
        check_len(key.len(), handle.key_size, true)?;
        check_len(value.len(), handle.value_size, false)?;
        let mut elem = BpfAttrElem {
            map_fd: handle.fd as u32,
            key: key.as_ptr() as u64,
            value: value.as_ptr() as u64,
            flags,
        };
        let rc = unsafe {
            bpf(
                BPF_MAP_UPDATE_ELEM,
                ptr::from_mut(&mut elem).cast(),
                mem::size_of::<BpfAttrElem>(),
            )
        };
        if rc < 0 {
            return Err(MapOpError::Syscall(errno()));
        }
        Ok(())
    }

    /// Delete one element.
    pub fn delete(&self, name: &str, key: &[u8]) -> Result<(), MapOpError> {
        let handle = self.handle(name)?;
        check_len(key.len(), handle.key_size, true)?;
        let mut elem = BpfAttrElem {
            map_fd: handle.fd as u32,
            key: key.as_ptr() as u64,
            value: 0,
            flags: 0,
        };
        let rc = unsafe {
            bpf(
                BPF_MAP_DELETE_ELEM,
                ptr::from_mut(&mut elem).cast(),
                mem::size_of::<BpfAttrElem>(),
            )
        };
        if rc < 0 {
            return Err(MapOpError::Syscall(errno()));
        }
        Ok(())
    }

    /// Resolve a pin name to its handle or refuse it as unknown.
    fn handle(&self, name: &str) -> Result<&MapHandle, MapOpError> {
        self.maps
            .get(name)
            .ok_or_else(|| MapOpError::UnknownMap(name.to_owned()))
    }
}

impl Drop for MapRegistry {
    fn drop(&mut self) {
        for handle in self.maps.values() {
            unsafe { libc::close(handle.fd) };
        }
    }
}

/// Validate a key (`is_key`) or value length against the map's declared size.
fn check_len(got: usize, expected: u32, is_key: bool) -> Result<(), MapOpError> {
    if got == expected as usize {
        Ok(())
    } else if is_key {
        Err(MapOpError::BadKeyLen { expected, got })
    } else {
        Err(MapOpError::BadValueLen { expected, got })
    }
}

/// `BPF_OBJ_GET` a pin, then read its `key_size`/`value_size`. Returns `None` for
/// a pin that is not a map or cannot be opened.
fn open_pinned_map(path: &Path) -> Option<(RawFd, u32, u32)> {
    let cpath = CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut obj = BpfAttrObj {
        pathname: cpath.as_ptr() as u64,
        ..Default::default()
    };
    let fd = unsafe {
        bpf(
            BPF_OBJ_GET,
            ptr::from_mut(&mut obj).cast(),
            mem::size_of::<BpfAttrObj>(),
        )
    };
    if fd < 0 {
        return None;
    }
    let fd = fd as RawFd;

    let mut info = BpfMapInfo::default();
    let mut info_attr = BpfAttrInfo {
        bpf_fd: fd as u32,
        info_len: mem::size_of::<BpfMapInfo>() as u32,
        info: ptr::from_mut(&mut info) as u64,
    };
    let rc = unsafe {
        bpf(
            BPF_OBJ_GET_INFO_BY_FD,
            ptr::from_mut(&mut info_attr).cast(),
            mem::size_of::<BpfAttrInfo>(),
        )
    };
    if rc < 0 {
        unsafe { libc::close(fd) };
        return None;
    }
    Some((fd, info.key_size, info.value_size))
}

/// The current thread's `errno`.
fn errno() -> i32 {
    unsafe { *libc::__errno_location() }
}

#[cfg(test)]
mod tests {
    use super::{BpfAttrElem, BpfAttrObj, BpfMapInfo, MapOpError, MapRegistry};
    use std::mem;
    use std::path::Path;

    #[test]
    fn bpf_attr_layouts_are_locked() {
        // The element attr must reproduce the kernel union layout: u32 map_fd, a
        // 4-byte hole, then three u64s.
        assert_eq!(mem::size_of::<BpfAttrElem>(), 32);
        assert_eq!(mem::align_of::<BpfAttrElem>(), 8);
        assert_eq!(mem::size_of::<BpfAttrObj>(), 16);
        // map_type,id,key_size,value_size,max_entries,map_flags (6×u32) + name[16].
        assert_eq!(mem::size_of::<BpfMapInfo>(), 40);
    }

    #[test]
    fn missing_pin_dir_yields_empty_registry() {
        let reg = MapRegistry::open_pin_dir(Path::new("/nonexistent/ebpfsentinel/pins"));
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
        assert!(reg.names().is_empty());
    }

    #[test]
    fn unknown_map_is_refused_before_any_syscall() {
        let reg = MapRegistry::default();
        assert_eq!(
            reg.lookup("NOPE", &[0, 0, 0, 0]),
            Err(MapOpError::UnknownMap("NOPE".to_owned()))
        );
        assert_eq!(
            reg.update("NOPE", &[0], &[0], 0),
            Err(MapOpError::UnknownMap("NOPE".to_owned()))
        );
        assert_eq!(
            reg.delete("NOPE", &[0]),
            Err(MapOpError::UnknownMap("NOPE".to_owned()))
        );
    }

    #[test]
    fn error_messages_are_descriptive() {
        assert!(
            MapOpError::UnknownMap("FOO".to_owned())
                .to_string()
                .contains("unknown map 'FOO'")
        );
        assert!(
            MapOpError::BadKeyLen {
                expected: 4,
                got: 8,
            }
            .to_string()
            .contains("key length 8 != map key_size 4")
        );
        assert!(
            MapOpError::BadValueLen {
                expected: 1,
                got: 4,
            }
            .to_string()
            .contains("value length 4 != map value_size 1")
        );
    }
}
