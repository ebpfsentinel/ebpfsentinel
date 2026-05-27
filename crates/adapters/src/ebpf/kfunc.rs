#![allow(unsafe_code)] // Raw bpf() syscall for BTF object enumeration.

//! Kernel kfunc resolution (kernel 5.18+ for module kfuncs).
//!
//! The eBPF programs call kernel kfuncs (e.g. `bpf_skb_ct_lookup`,
//! `bpf_ct_release` from `nf_conntrack`, plus the dynptr / xdp-metadata
//! families from vmlinux). aya 0.13 has no kfunc support, so the
//! userspace loader resolves each kfunc symbol to its kernel BTF id
//! itself and patches the call instruction at load time — the same
//! "do it outside aya via raw syscalls" approach used for BPF tokens.
//!
//! A `BPF_PSEUDO_KFUNC_CALL` instruction encodes the target as:
//!
//! * `insn.imm` = BTF id of the kfunc's `FUNC` type.
//! * `insn.off` = index into the program-load `fd_array`. `0` means the
//!   kfunc lives in vmlinux; a non-zero index points at a loaded kernel
//!   module's BTF object fd.
//!
//! For module kfuncs the id is the *global* BTF id: kernel module BTF is
//! "split" BTF layered on top of vmlinux, so a module type's id continues
//! the numbering past the last vmlinux type. aya-obj's BTF parser does not
//! understand split BTF (it would return a local index and mis-resolve
//! string offsets), so this module walks the raw BTF type stream directly.

use std::collections::HashMap;
use std::io;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};

/// `bpf(2)` commands used here. Numbers from `enum bpf_cmd`.
const BPF_BTF_GET_FD_BY_ID: u32 = 19;
const BPF_BTF_GET_NEXT_ID: u32 = 23;

/// `BTF_KIND_FUNC` from `include/uapi/linux/btf.h`. The only kind we match.
const BTF_KIND_FUNC: u32 = 12;

/// Path to the kernel base (vmlinux) BTF exposed by the kernel.
const VMLINUX_BTF_PATH: &str = "/sys/kernel/btf/vmlinux";
/// Directory holding per-module split BTF blobs.
const MODULE_BTF_DIR: &str = "/sys/kernel/btf";

/// Errors surfaced while resolving kfuncs.
#[derive(Debug, thiserror::Error)]
pub enum KfuncError {
    #[error("failed to read vmlinux BTF at {path}: {source}")]
    ReadVmlinux {
        path: String,
        #[source]
        source: io::Error,
    },

    #[error("malformed BTF blob: {0}")]
    MalformedBtf(&'static str),

    #[error("kfunc `{0}` not found in vmlinux or any loaded module BTF")]
    Unresolved(String),

    #[error("BTF_GET_FD_BY_ID(id={id}) failed: {source}")]
    GetFdById {
        id: u32,
        #[source]
        source: io::Error,
    },
}

/// Where a resolved kfunc lives and how to address it at program load.
#[derive(Debug, Clone)]
pub struct KfuncTarget {
    /// Global BTF id of the kfunc's `FUNC` type (goes in `insn.imm`).
    pub btf_id: u32,
    /// Runtime BTF object id of the owning module, or `None` for vmlinux.
    /// Used to fetch the module BTF fd for the program-load `fd_array`.
    pub module_btf_obj_id: Option<u32>,
}

// ── raw BTF type-stream walker ──────────────────────────────────────────

/// `struct btf_header` (`include/uapi/linux/btf.h`), little-endian hosts.
#[derive(Debug, Clone, Copy)]
struct BtfHeader {
    hdr_len: u32,
    type_off: u32,
    type_len: u32,
    str_off: u32,
    str_len: u32,
}

/// Magic `0xeB9F` identifying a BTF blob.
const BTF_MAGIC: u16 = 0xEB9F;

fn parse_header(data: &[u8]) -> Result<BtfHeader, KfuncError> {
    // magic(u16) version(u8) flags(u8) hdr_len(u32)
    // type_off(u32) type_len(u32) str_off(u32) str_len(u32)
    if data.len() < 24 {
        return Err(KfuncError::MalformedBtf("blob shorter than btf_header"));
    }
    let magic = u16::from_le_bytes([data[0], data[1]]);
    if magic != BTF_MAGIC {
        return Err(KfuncError::MalformedBtf(
            "bad BTF magic (not little-endian?)",
        ));
    }
    let rd =
        |off: usize| u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
    Ok(BtfHeader {
        hdr_len: rd(4),
        type_off: rd(8),
        type_len: rd(12),
        str_off: rd(16),
        str_len: rd(20),
    })
}

/// A parsed BTF blob, retaining enough to resolve `FUNC` ids by name. For a
/// split (module) blob, `base` carries the underlying vmlinux blob so global
/// ids and base-section string offsets resolve correctly.
struct BtfBlob {
    data: Vec<u8>,
    header: BtfHeader,
    /// Number of types this blob *defines* (excludes the implicit void at
    /// id 0 and, for split BTF, the base types).
    type_count: u32,
    /// Global id of this blob's first defined type. `1` for vmlinux (id 0 is
    /// void); for split BTF it is `base.start_id + base.type_count`.
    start_id: u32,
    /// String offset at which this blob's own strings begin in the global
    /// string space. `0` for vmlinux; `base.str_len` for split BTF.
    start_str_off: u32,
}

impl BtfBlob {
    /// Parse a base (vmlinux) BTF blob.
    fn parse_base(data: Vec<u8>) -> Result<Self, KfuncError> {
        let header = parse_header(&data)?;
        let type_count = count_types(&data, &header)?;
        Ok(Self {
            data,
            header,
            type_count,
            start_id: 1,
            start_str_off: 0,
        })
    }

    /// Parse a split (module) BTF blob layered on `base`.
    fn parse_split(data: Vec<u8>, base: &BtfBlob) -> Result<Self, KfuncError> {
        let header = parse_header(&data)?;
        let type_count = count_types(&data, &header)?;
        Ok(Self {
            data,
            header,
            type_count,
            start_id: base.start_id + base.type_count,
            start_str_off: base.header.str_len,
        })
    }

    /// Resolve a string at the given global offset, consulting `base` for
    /// offsets that fall inside the base string section.
    fn string_at<'a>(&'a self, offset: u32, base: Option<&'a BtfBlob>) -> Option<&'a str> {
        if let Some(base) = base
            && offset < self.start_str_off
        {
            return base.string_at(offset, None);
        }
        let local = (offset - self.start_str_off) as usize;
        let str_base = (self.header.hdr_len + self.header.str_off) as usize;
        let start = str_base.checked_add(local)?;
        let bytes = self.data.get(start..)?;
        let end = bytes.iter().position(|&c| c == 0)?;
        std::str::from_utf8(&bytes[..end]).ok()
    }

    /// Walk this blob's `FUNC` types, returning `name -> global id`.
    fn func_ids(&self, base: Option<&BtfBlob>) -> Result<HashMap<String, u32>, KfuncError> {
        let mut out = HashMap::new();
        let mut id = self.start_id;
        for_each_type(&self.data, &self.header, |name_off, kind, _vlen| {
            if kind == BTF_KIND_FUNC
                && name_off != 0
                && let Some(name) = self.string_at(name_off, base)
            {
                out.insert(name.to_owned(), id);
            }
            id += 1;
        })?;
        Ok(out)
    }
}

/// Count the number of type records a blob defines.
fn count_types(data: &[u8], header: &BtfHeader) -> Result<u32, KfuncError> {
    let mut n = 0u32;
    for_each_type(data, header, |_, _, _| n += 1)?;
    Ok(n)
}

/// Iterate every `btf_type` record, invoking `f(name_off, kind, vlen)`. Each
/// record is a 12-byte common header (`name_off`, `info`, `size_or_type`)
/// followed by kind-specific trailing data sized from `kind` and `vlen`.
fn for_each_type<F: FnMut(u32, u32, u32)>(
    data: &[u8],
    header: &BtfHeader,
    mut f: F,
) -> Result<(), KfuncError> {
    let start = (header.hdr_len + header.type_off) as usize;
    let end = start
        .checked_add(header.type_len as usize)
        .ok_or(KfuncError::MalformedBtf("type section overflow"))?;
    if end > data.len() {
        return Err(KfuncError::MalformedBtf("type section out of bounds"));
    }
    let mut pos = start;
    while pos < end {
        if pos + 12 > end {
            return Err(KfuncError::MalformedBtf("truncated btf_type header"));
        }
        let name_off = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        let info = u32::from_le_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);
        let vlen = info & 0xffff;
        let kind = (info >> 24) & 0x1f;
        f(name_off, kind, vlen);
        let extra = kind_extra_size(kind, vlen)
            .ok_or(KfuncError::MalformedBtf("unknown btf kind in type stream"))?;
        pos = pos
            .checked_add(12 + extra)
            .ok_or(KfuncError::MalformedBtf("type record size overflow"))?;
    }
    Ok(())
}

/// Trailing byte count after the 12-byte common header, by kind+vlen. See
/// the `BTF_KIND_*` layout in `include/uapi/linux/btf.h`.
#[allow(clippy::match_same_arms)] // One arm per BTF kind, kept explicit as a layout table.
fn kind_extra_size(kind: u32, vlen: u32) -> Option<usize> {
    let vlen = vlen as usize;
    let size = match kind {
        0 => 0,             // UNKN (void)
        1 => 4,             // INT: one u32
        2 => 0,             // PTR
        3 => 12,            // ARRAY: btf_array
        4 | 5 => vlen * 12, // STRUCT / UNION: btf_member
        6 => vlen * 8,      // ENUM: btf_enum
        7 => 0,             // FWD
        8 => 0,             // TYPEDEF
        9 => 0,             // VOLATILE
        10 => 0,            // CONST
        11 => 0,            // RESTRICT
        12 => 0,            // FUNC
        13 => vlen * 8,     // FUNC_PROTO: btf_param
        14 => 4,            // VAR: btf_var
        15 => vlen * 12,    // DATASEC: btf_var_secinfo
        16 => 0,            // FLOAT
        17 => 4,            // DECL_TAG: btf_decl_tag
        18 => 0,            // TYPE_TAG
        19 => vlen * 12,    // ENUM64: btf_enum64
        _ => return None,
    };
    Some(size)
}

// ── raw bpf() helpers for BTF object enumeration ────────────────────────

#[repr(C)]
#[derive(Default)]
struct BtfIdAttr {
    id: u32,
    next_id: u32,
    open_flags: u32,
}

/// SAFETY wrapper: invoke `bpf(cmd, attr, size)`.
unsafe fn bpf(cmd: u32, attr: *mut core::ffi::c_void, size: usize) -> i64 {
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

/// Fetch the next loaded BTF object id after `id`, or `None` at the end.
fn btf_get_next_id(id: u32) -> Option<u32> {
    let mut attr = BtfIdAttr {
        id,
        ..Default::default()
    };
    let rc = unsafe {
        bpf(
            BPF_BTF_GET_NEXT_ID,
            (&raw mut attr).cast(),
            std::mem::size_of::<BtfIdAttr>(),
        )
    };
    if rc < 0 { None } else { Some(attr.next_id) }
}

/// Open an fd to the loaded BTF object with the given id.
fn btf_get_fd_by_id(id: u32) -> Result<OwnedFd, KfuncError> {
    let mut attr = BtfIdAttr {
        id,
        ..Default::default()
    };
    let rc = unsafe {
        bpf(
            BPF_BTF_GET_FD_BY_ID,
            (&raw mut attr).cast(),
            std::mem::size_of::<BtfIdAttr>(),
        )
    };
    if rc < 0 {
        return Err(KfuncError::GetFdById {
            id,
            source: io::Error::last_os_error(),
        });
    }
    #[allow(clippy::cast_possible_truncation)]
    let raw = rc as RawFd;
    // SAFETY: rc >= 0, a valid fd owned by this process.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

// ── public resolver ─────────────────────────────────────────────────────

/// Resolves kfunc names to kernel BTF ids and owns the module BTF fds the
/// program loader needs for its `fd_array`.
pub struct KfuncResolver {
    /// vmlinux `FUNC` name -> global id.
    vmlinux_funcs: HashMap<String, u32>,
    /// module `FUNC` name -> (global id, module name).
    module_funcs: HashMap<String, (u32, String)>,
    /// module name -> runtime BTF object id (for `fd_array` fd lookup).
    module_obj_ids: HashMap<String, u32>,
}

impl KfuncResolver {
    /// Build a resolver by parsing vmlinux BTF and every loaded module's
    /// split BTF. Modules whose split BTF cannot be read are skipped (their
    /// kfuncs simply won't resolve), so a missing optional module never
    /// fails construction.
    pub fn new() -> Result<Self, KfuncError> {
        let vmlinux_data =
            std::fs::read(VMLINUX_BTF_PATH).map_err(|source| KfuncError::ReadVmlinux {
                path: VMLINUX_BTF_PATH.to_owned(),
                source,
            })?;
        let vmlinux = BtfBlob::parse_base(vmlinux_data)?;
        let vmlinux_funcs = vmlinux.func_ids(None)?;

        // Map module name -> runtime BTF object id by enumerating loaded BTFs.
        let module_obj_ids = enumerate_module_btf_obj_ids();

        // Parse each module's split BTF (from sysfs) for its FUNC ids.
        let mut module_funcs = HashMap::new();
        for module in module_obj_ids.keys() {
            let path = format!("{MODULE_BTF_DIR}/{module}");
            let Ok(data) = std::fs::read(&path) else {
                continue;
            };
            let Ok(blob) = BtfBlob::parse_split(data, &vmlinux) else {
                continue;
            };
            let Ok(funcs) = blob.func_ids(Some(&vmlinux)) else {
                continue;
            };
            for (name, id) in funcs {
                module_funcs
                    .entry(name)
                    .or_insert_with(|| (id, module.clone()));
            }
        }

        Ok(Self {
            vmlinux_funcs,
            module_funcs,
            module_obj_ids,
        })
    }

    /// Resolve a kfunc name to its load-time target. vmlinux kfuncs win over
    /// module kfuncs of the same name (matching kernel resolution order).
    pub fn resolve(&self, name: &str) -> Result<KfuncTarget, KfuncError> {
        if let Some(&btf_id) = self.vmlinux_funcs.get(name) {
            return Ok(KfuncTarget {
                btf_id,
                module_btf_obj_id: None,
            });
        }
        if let Some((btf_id, module)) = self.module_funcs.get(name) {
            return Ok(KfuncTarget {
                btf_id: *btf_id,
                module_btf_obj_id: self.module_obj_ids.get(module).copied(),
            });
        }
        Err(KfuncError::Unresolved(name.to_owned()))
    }

    /// Open an fd to a module's BTF object by its runtime id, for inclusion
    /// in the program-load `fd_array`.
    pub fn module_btf_fd(&self, obj_id: u32) -> Result<OwnedFd, KfuncError> {
        btf_get_fd_by_id(obj_id)
    }
}

/// `struct bpf_btf_info` subset for `OBJ_GET_INFO_BY_FD`.
#[repr(C)]
#[derive(Default)]
struct BtfInfo {
    btf: u64,
    btf_size: u32,
    id: u32,
    name: u64,
    name_len: u32,
    kernel_btf: u32,
}

/// `bpf_attr` for `OBJ_GET_INFO_BY_FD`.
#[repr(C)]
#[derive(Default)]
struct ObjInfoAttr {
    bpf_fd: u32,
    info_len: u32,
    info: u64,
}

const BPF_OBJ_GET_INFO_BY_FD: u32 = 15;

/// Enumerate loaded BTF objects, returning `module name -> object id` for
/// every split (module) BTF. The base vmlinux object (and any object without
/// a name) is skipped.
fn enumerate_module_btf_obj_ids() -> HashMap<String, u32> {
    let mut out = HashMap::new();
    let mut id = 0u32;
    while let Some(next) = btf_get_next_id(id) {
        id = next;
        let Ok(fd) = btf_get_fd_by_id(next) else {
            continue;
        };
        let mut name_buf = [0u8; 64];
        let mut info = BtfInfo {
            name: name_buf.as_mut_ptr() as u64,
            name_len: name_buf.len() as u32,
            ..Default::default()
        };
        let mut attr = ObjInfoAttr {
            bpf_fd: raw_fd_u32(&fd),
            info_len: std::mem::size_of::<BtfInfo>() as u32,
            info: (&raw mut info).cast::<u8>() as u64,
        };
        let rc = unsafe {
            bpf(
                BPF_OBJ_GET_INFO_BY_FD,
                (&raw mut attr).cast(),
                std::mem::size_of::<ObjInfoAttr>(),
            )
        };
        if rc < 0 {
            continue;
        }
        // vmlinux base BTF reports an empty name; modules carry their name.
        let nul = name_buf.iter().position(|&c| c == 0).unwrap_or(0);
        if nul == 0 {
            continue;
        }
        if let Ok(name) = std::str::from_utf8(&name_buf[..nul])
            && name != "vmlinux"
        {
            out.insert(name.to_owned(), info.id);
        }
    }
    out
}

/// Borrow an `OwnedFd` as a `u32` raw fd for syscall attr fields.
#[allow(clippy::cast_sign_loss)]
fn raw_fd_u32(fd: &OwnedFd) -> u32 {
    use std::os::fd::AsRawFd;
    fd.as_raw_fd() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_extra_sizes_match_btf_layout() {
        assert_eq!(kind_extra_size(BTF_KIND_FUNC, 0), Some(0));
        assert_eq!(kind_extra_size(1, 0), Some(4)); // INT
        assert_eq!(kind_extra_size(4, 3), Some(36)); // STRUCT, 3 members
        assert_eq!(kind_extra_size(13, 5), Some(40)); // FUNC_PROTO, 5 params
        assert_eq!(kind_extra_size(19, 2), Some(24)); // ENUM64, 2 values
        assert_eq!(kind_extra_size(99, 0), None); // unknown kind
    }

    #[test]
    fn parse_header_rejects_bad_magic() {
        let blob = [0u8; 24];
        assert!(matches!(
            parse_header(&blob),
            Err(KfuncError::MalformedBtf(_))
        ));
    }

    #[test]
    fn walk_minimal_btf_finds_func() {
        // Hand-build a tiny BTF blob: header + one FUNC_PROTO + one FUNC.
        // strings: "\0kf\0"
        let strings = b"\0kf\0";
        let mut types = Vec::new();
        // type 1: FUNC_PROTO (kind 13), name_off 0, vlen 0, return void
        types.extend_from_slice(&0u32.to_le_bytes()); // name_off
        types.extend_from_slice(&(13u32 << 24).to_le_bytes()); // info: kind=13
        types.extend_from_slice(&0u32.to_le_bytes()); // type (ret)
        // type 2: FUNC (kind 12), name_off 1 ("kf"), type -> 1
        types.extend_from_slice(&1u32.to_le_bytes()); // name_off "kf"
        types.extend_from_slice(&(12u32 << 24).to_le_bytes()); // info: kind=12
        types.extend_from_slice(&1u32.to_le_bytes()); // type -> proto

        let hdr_len = 24u32;
        let type_off = 0u32;
        let type_len = types.len() as u32;
        let str_off = type_len;
        let str_len = strings.len() as u32;

        let mut blob = Vec::new();
        blob.extend_from_slice(&BTF_MAGIC.to_le_bytes());
        blob.push(1); // version
        blob.push(0); // flags
        blob.extend_from_slice(&hdr_len.to_le_bytes());
        blob.extend_from_slice(&type_off.to_le_bytes());
        blob.extend_from_slice(&type_len.to_le_bytes());
        blob.extend_from_slice(&str_off.to_le_bytes());
        blob.extend_from_slice(&str_len.to_le_bytes());
        blob.extend_from_slice(&types);
        blob.extend_from_slice(strings);

        let parsed = BtfBlob::parse_base(blob).expect("parse");
        assert_eq!(parsed.type_count, 2);
        let funcs = parsed.func_ids(None).expect("func ids");
        // FUNC is the 2nd type -> global id 2.
        assert_eq!(funcs.get("kf"), Some(&2));
    }
}
