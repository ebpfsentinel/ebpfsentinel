#![allow(unsafe_code)] // Raw bpf() syscall for BTF object enumeration.

//! Kernel kfunc resolution (kernel 5.18+ for module kfuncs).
//!
//! The eBPF programs call kernel kfuncs (e.g. `bpf_skb_ct_lookup`,
//! `bpf_ct_release` from `nf_conntrack`, plus the dynptr / xdp-metadata
//! families from vmlinux). aya 0.14.0 has no kfunc support, so the
//! userspace loader resolves each kfunc symbol to its kernel BTF id
//! itself and patches the call instruction at load time - the same
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
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::{LazyLock, Mutex};

/// `bpf(2)` commands used here. Numbers from `enum bpf_cmd`.
const BPF_BTF_GET_FD_BY_ID: u32 = 19;
const BPF_BTF_GET_NEXT_ID: u32 = 23;

/// `BTF_KIND_FUNC` from `include/uapi/linux/btf.h`: the kind kfuncs are.
const BTF_KIND_FUNC: u32 = 12;
/// `BTF_KIND_STRUCT` from the same header: the kind member offsets are read off.
const BTF_KIND_STRUCT: u32 = 4;
/// `BTF_KIND_UNION`: the other kind an anonymous member can be.
const BTF_KIND_UNION: u32 = 5;
/// `BTF_KIND_ENUM`: a 32-bit enumeration, whose enumerator values are read off.
const BTF_KIND_ENUM: u32 = 6;
/// `BTF_KIND_ENUM64`: the 64-bit form, laid out differently.
const BTF_KIND_ENUM64: u32 = 19;
/// `struct btf_member`: `name_off`, `type`, `offset`, each a `u32`.
const BTF_MEMBER_SIZE: usize = 12;
/// `struct btf_enum`: `name_off` and a signed 32-bit `val`.
const BTF_ENUM_SIZE: usize = 8;
/// `struct btf_enum64`: `name_off` plus the value in two 32-bit halves.
const BTF_ENUM64_SIZE: usize = 12;

/// How deep the member walk follows anonymous struct and union members.
///
/// An anonymous member has no name of its own, so its members are addressed
/// from the enclosing struct and a lookup by name has to descend into it -
/// `iov_iter.count` lives two anonymous levels down. The bound is what stops a
/// malformed blob whose member type points back at its own struct from
/// recursing forever; real kernel types nest two or three deep.
const MAX_ANONYMOUS_MEMBER_DEPTH: u32 = 8;

/// Path to the kernel base (vmlinux) BTF exposed by the kernel.
const VMLINUX_BTF_PATH: &str = "/sys/kernel/btf/vmlinux";
/// Directory holding per-module split BTF blobs.
const MODULE_BTF_DIR: &str = "/sys/kernel/btf";

/// Module-name → BTF-object fd, supplied by a privileged helper.
///
/// Opening a module's BTF object fd needs `CAP_SYS_ADMIN`
/// (`BTF_GET_FD_BY_ID`), which a BPF-token process deliberately lacks - the
/// token authorises program/map loads but not global-object introspection. To
/// load a program that calls a *module* kfunc (e.g. `bpf_xdp_ct_lookup` from
/// `nf_conntrack`) the owning module's BTF fd must still go into the
/// program-load `fd_array`. A privileged setup component opens those fds and
/// hands them down to the unprivileged agent (inherited across exec); the agent
/// records them here so the loader can splice them into the `fd_array` without
/// any privileged syscall of its own.
static MODULE_BTF_FDS: LazyLock<Mutex<HashMap<String, RawFd>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Register a pre-opened module BTF object fd for `module`. Called from agent
/// startup for each fd passed in by the privileged setup component. The fd must
/// stay open for the process lifetime; the loader borrows it, never closes it.
pub fn set_module_btf_fd(module: &str, fd: RawFd) {
    if let Ok(mut map) = MODULE_BTF_FDS.lock() {
        map.insert(module.to_owned(), fd);
    }
}

/// Look up a pre-passed module BTF fd by module name.
fn global_module_btf_fd(module: &str) -> Option<RawFd> {
    MODULE_BTF_FDS.lock().ok()?.get(module).copied()
}

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

    #[error("struct `{0}` not defined in vmlinux BTF")]
    StructNotFound(String),

    #[error("enum `{0}` not defined in vmlinux BTF")]
    EnumNotFound(String),

    #[error(
        "module `{0}` BTF object fd unavailable: no fd was passed in by a \
         privileged helper and BTF_GET_FD_BY_ID needs CAP_SYS_ADMIN (which a \
         BPF token does not grant)"
    )]
    ModuleBtfUnavailable(String),

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
    /// Name of the owning kernel module, or `None` for vmlinux. This is the
    /// stable module identity: it is recovered from the per-module split BTF
    /// blob in sysfs (an unprivileged file read), so it is available even in
    /// BPF-token mode where the BTF-object-id syscalls are denied.
    pub module_name: Option<String>,
    /// Runtime BTF object id of the owning module, or `None` for vmlinux (or
    /// when enumeration was unavailable). Used to fetch the module BTF fd via
    /// `BTF_GET_FD_BY_ID` when the process holds `CAP_SYS_ADMIN`.
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
        for_each_type(&self.data, &self.header, |rec| {
            if rec.kind == BTF_KIND_FUNC
                && rec.name_off != 0
                && let Some(name) = self.string_at(rec.name_off, base)
            {
                out.insert(name.to_owned(), id);
            }
            id += 1;
        })?;
        Ok(out)
    }

    /// Index every type record by id, so a member's type can be followed.
    fn type_index(&self) -> Result<Vec<IndexedType>, KfuncError> {
        let mut out = Vec::with_capacity(self.type_count as usize);
        for_each_type(&self.data, &self.header, |rec| {
            out.push(IndexedType {
                name_off: rec.name_off,
                kind: rec.kind,
                vlen: rec.vlen,
                kind_flag: rec.kind_flag,
                body: rec.body_off..rec.body_off + rec.body.len(),
            });
        })?;
        Ok(out)
    }

    /// Position in `index` of the record a member's type id names, or `None`
    /// when that id belongs to another blob in a split-BTF chain.
    fn index_of(&self, index: &[IndexedType], type_id: u32) -> Option<usize> {
        let local = type_id.checked_sub(self.start_id)? as usize;
        (local < index.len()).then_some(local)
    }

    /// Byte offsets of the named `members` of the first non-empty `STRUCT`
    /// called `struct_name`, in the order asked for. `None` in a slot means
    /// the struct carries no member of that name; `None` overall means no
    /// such struct is defined in this blob.
    ///
    /// Anonymous struct and union members are descended into, because C
    /// addresses their members from the enclosing struct and the kernel uses
    /// that to overlay layouts: `iov_iter` keeps `__ubuf_iovec` and `count` in
    /// one anonymous union so a single offset serves two iterator kinds.
    fn struct_member_byte_offsets(
        &self,
        base: Option<&BtfBlob>,
        struct_name: &str,
        members: &[&str],
    ) -> Result<Option<Vec<Option<u32>>>, KfuncError> {
        let index = self.type_index()?;
        let Some(root) = index.iter().position(|rec| {
            rec.kind == BTF_KIND_STRUCT
                && rec.vlen != 0
                && rec.name_off != 0
                && self.string_at(rec.name_off, base) == Some(struct_name)
        }) else {
            return Ok(None);
        };
        let mut offsets = vec![None; members.len()];
        self.collect_members(base, &index, root, 0, 0, members, &mut offsets);
        Ok(Some(offsets))
    }

    /// Match `members` against the records of the composite at `at`, whose
    /// first bit sits `base_bit_offset` bits into the struct being resolved.
    #[allow(clippy::too_many_arguments)] // Walk state, threaded rather than boxed.
    fn collect_members(
        &self,
        base: Option<&BtfBlob>,
        index: &[IndexedType],
        at: usize,
        base_bit_offset: u32,
        depth: u32,
        members: &[&str],
        offsets: &mut [Option<u32>],
    ) {
        let Some(rec) = index.get(at) else {
            return;
        };
        let Some(body) = self.data.get(rec.body.clone()) else {
            return;
        };
        for member in body.as_chunks::<BTF_MEMBER_SIZE>().0 {
            let name_off = u32::from_le_bytes([member[0], member[1], member[2], member[3]]);
            let type_id = u32::from_le_bytes([member[4], member[5], member[6], member[7]]);
            let offset = u32::from_le_bytes([member[8], member[9], member[10], member[11]]);
            // With kind_flag set the high byte is the bitfield size and
            // the low 24 bits the bit offset; without it the whole word
            // is the bit offset.
            let bit_offset = base_bit_offset.saturating_add(if rec.kind_flag {
                offset & 0x00ff_ffff
            } else {
                offset
            });

            if name_off == 0 {
                if depth < MAX_ANONYMOUS_MEMBER_DEPTH
                    && let Some(child) = self.index_of(index, type_id)
                    && matches!(index[child].kind, BTF_KIND_STRUCT | BTF_KIND_UNION)
                {
                    self.collect_members(
                        base,
                        index,
                        child,
                        bit_offset,
                        depth + 1,
                        members,
                        offsets,
                    );
                }
                continue;
            }

            let Some(name) = self.string_at(name_off, base) else {
                continue;
            };
            for (slot, wanted) in offsets.iter_mut().zip(members) {
                if slot.is_none() && name == *wanted {
                    *slot = Some(bit_offset / 8);
                }
            }
        }
    }

    /// Values of the named enumerators of the first non-empty `ENUM` or
    /// `ENUM64` called `enum_name`. `None` in a slot means the enumeration
    /// carries no such name; `None` overall means no such enum in this blob.
    fn enum_values(
        &self,
        base: Option<&BtfBlob>,
        enum_name: &str,
        names: &[&str],
    ) -> Result<Option<Vec<Option<i64>>>, KfuncError> {
        let mut found: Option<Vec<Option<i64>>> = None;
        for_each_type(&self.data, &self.header, |rec| {
            if found.is_some()
                || !matches!(rec.kind, BTF_KIND_ENUM | BTF_KIND_ENUM64)
                || rec.vlen == 0
                || rec.name_off == 0
                || self.string_at(rec.name_off, base) != Some(enum_name)
            {
                return;
            }
            let mut values = vec![None; names.len()];
            let mut record = |name_off: u32, value: i64| {
                let Some(name) = self.string_at(name_off, base) else {
                    return;
                };
                for (slot, wanted) in values.iter_mut().zip(names) {
                    if slot.is_none() && name == *wanted {
                        *slot = Some(value);
                    }
                }
            };
            if rec.kind == BTF_KIND_ENUM {
                for entry in rec.body.as_chunks::<BTF_ENUM_SIZE>().0 {
                    let name_off = u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]);
                    let raw = i32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]);
                    record(name_off, i64::from(raw));
                }
            } else {
                for entry in rec.body.as_chunks::<BTF_ENUM64_SIZE>().0 {
                    let name_off = u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]);
                    let lo = u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]);
                    let hi = u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]);
                    record(
                        name_off,
                        (u64::from(hi) << 32 | u64::from(lo)).cast_signed(),
                    );
                }
            }
            found = Some(values);
        })?;
        Ok(found)
    }
}

/// A type record located by id, for the lookups that have to follow a
/// member's type rather than only read the member list in front of them.
struct IndexedType {
    name_off: u32,
    kind: u32,
    vlen: u32,
    kind_flag: bool,
    /// Range of the kind-specific trailing bytes inside the blob.
    body: core::ops::Range<usize>,
}

/// Byte offsets of the named `members` of `struct_name` in the running
/// kernel, read straight off the vmlinux BTF blob in sysfs. One `None` per
/// member the struct does not carry.
///
/// This is what the conntrack datapath asks for `nf_conn.status` and
/// `nf_conn.mark`. It used to shell out to `bpftool btf dump -j` and parse
/// the whole dump into a `serde_json::Value`: 24 MB of JSON became about
/// 330 MB of small heap allocations for two integers, and glibc never handed
/// that heap back, so every agent sat at 400 MB resident for the rest of its
/// life. The raw blob is 7 MB, read into one allocation the allocator
/// returns to the kernel on drop.
pub fn vmlinux_struct_member_offsets(
    struct_name: &str,
    members: &[&str],
) -> Result<Vec<Option<u32>>, KfuncError> {
    let data = std::fs::read(VMLINUX_BTF_PATH).map_err(|source| KfuncError::ReadVmlinux {
        path: VMLINUX_BTF_PATH.to_owned(),
        source,
    })?;
    let vmlinux = BtfBlob::parse_base(data)?;
    vmlinux
        .struct_member_byte_offsets(None, struct_name, members)?
        .ok_or_else(|| KfuncError::StructNotFound(struct_name.to_owned()))
}

/// Values the running kernel gives the named enumerators of `enum_name`, read
/// off the same vmlinux BTF blob. One `None` per name the enumeration does not
/// carry.
///
/// This exists because an enumerator is not a stable number. The kernel TLS
/// probes branch on `enum iter_type`, whose members were reordered when
/// `ITER_UBUF` was added in front of `ITER_IOVEC`, so a value compiled into
/// the eBPF program would read the wrong field on half the kernels the agent
/// supports. A kernel whose BTF cannot answer gets no probe rather than a
/// wrong read.
pub fn vmlinux_enum_values(
    enum_name: &str,
    names: &[&str],
) -> Result<Vec<Option<i64>>, KfuncError> {
    let data = std::fs::read(VMLINUX_BTF_PATH).map_err(|source| KfuncError::ReadVmlinux {
        path: VMLINUX_BTF_PATH.to_owned(),
        source,
    })?;
    let vmlinux = BtfBlob::parse_base(data)?;
    vmlinux
        .enum_values(None, enum_name, names)?
        .ok_or_else(|| KfuncError::EnumNotFound(enum_name.to_owned()))
}

/// Count the number of type records a blob defines.
fn count_types(data: &[u8], header: &BtfHeader) -> Result<u32, KfuncError> {
    let mut n = 0u32;
    for_each_type(data, header, |_| n += 1)?;
    Ok(n)
}

/// One `btf_type` record as the walker hands it out: the common header's
/// fields plus the kind-specific trailing bytes that follow it.
struct TypeRecord<'a> {
    name_off: u32,
    kind: u32,
    vlen: u32,
    /// `BTF_INFO_KFLAG`: for a struct, its member offsets carry a bitfield
    /// size in the high byte.
    kind_flag: bool,
    body: &'a [u8],
    /// Where `body` starts inside the blob, so a record can be indexed by id
    /// and revisited later without re-walking the stream.
    body_off: usize,
}

/// Iterate every `btf_type` record, invoking `f(record)`. Each record is a
/// 12-byte common header (`name_off`, `info`, `size_or_type`) followed by
/// kind-specific trailing data sized from `kind` and `vlen`.
fn for_each_type<F: FnMut(TypeRecord<'_>)>(
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
        let kind_flag = (info >> 31) & 1 == 1;
        let extra = kind_extra_size(kind, vlen)
            .ok_or(KfuncError::MalformedBtf("unknown btf kind in type stream"))?;
        let next = pos
            .checked_add(12 + extra)
            .ok_or(KfuncError::MalformedBtf("type record size overflow"))?;
        if next > end {
            return Err(KfuncError::MalformedBtf("truncated btf_type body"));
        }
        f(TypeRecord {
            name_off,
            kind,
            vlen,
            kind_flag,
            body: &data[pos + 12..next],
            body_off: pos + 12,
        });
        pos = next;
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
    // SAFETY: `attr` is a live `#[repr(C)]` local of exactly the size passed, laid out as the
    // union member the kernel reads for this command; every pointer it carries names a buffer
    // that outlives the call.
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
    // SAFETY: `attr` is a live `#[repr(C)]` local of exactly the size passed, laid out as the
    // union member the kernel reads for this command; every pointer it carries names a buffer
    // that outlives the call.
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

        // Discover module kfuncs by reading every per-module split BTF blob
        // directly from sysfs. Listing the directory and reading the blobs is an
        // *unprivileged* file operation, so module-kfunc names resolve even in
        // BPF-token mode - unlike the BTF-object-id enumeration below, which
        // needs `CAP_SYS_ADMIN` and yields nothing under a token.
        let mut module_funcs = HashMap::new();
        if let Ok(entries) = std::fs::read_dir(MODULE_BTF_DIR) {
            for entry in entries.flatten() {
                let module = entry.file_name().to_string_lossy().into_owned();
                if module == "vmlinux" {
                    continue;
                }
                let Ok(data) = std::fs::read(entry.path()) else {
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
        }

        // Best-effort module name -> runtime BTF object id. This needs
        // `CAP_SYS_ADMIN`; under a BPF token it returns empty and the loader
        // instead uses the fds pre-registered via `set_module_btf_fd`.
        let module_obj_ids = enumerate_module_btf_obj_ids();

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
                module_name: None,
                module_btf_obj_id: None,
            });
        }
        if let Some((btf_id, module)) = self.module_funcs.get(name) {
            return Ok(KfuncTarget {
                btf_id: *btf_id,
                module_name: Some(module.clone()),
                module_btf_obj_id: self.module_obj_ids.get(module).copied(),
            });
        }
        Err(KfuncError::Unresolved(name.to_owned()))
    }

    /// Resolve a module's BTF object fd for the program-load `fd_array`.
    ///
    /// Prefers a fd pre-registered by the privileged helper (the only path that
    /// works under a BPF token); otherwise falls back to `BTF_GET_FD_BY_ID` on
    /// the runtime object id, which needs `CAP_SYS_ADMIN`. Returns the raw fd to
    /// place in the array plus, when this call opened it, the `OwnedFd` whose
    /// lifetime must cover the program load. A pre-registered fd is borrowed
    /// (owned elsewhere for the process lifetime), so no `OwnedFd` is returned.
    pub fn module_btf_fd_by_name(
        &self,
        module: &str,
    ) -> Result<(RawFd, Option<OwnedFd>), KfuncError> {
        if let Some(fd) = global_module_btf_fd(module) {
            return Ok((fd, None));
        }
        let obj_id = self
            .module_obj_ids
            .get(module)
            .copied()
            .ok_or_else(|| KfuncError::ModuleBtfUnavailable(module.to_owned()))?;
        let owned = btf_get_fd_by_id(obj_id)?;
        let raw = owned.as_raw_fd();
        Ok((raw, Some(owned)))
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
        // SAFETY: `attr` is a live `#[repr(C)]` local of exactly the size passed, laid out as
        // the union member the kernel reads for this command; every pointer it carries names a
        // buffer that outlives the call.
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

    /// Wrap a hand-built type section and string section in a BTF header.
    fn blob(types: &[u8], strings: &[u8]) -> Vec<u8> {
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
        blob.extend_from_slice(types);
        blob.extend_from_slice(strings);
        blob
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

        let parsed = BtfBlob::parse_base(blob(&types, strings)).expect("parse");
        assert_eq!(parsed.type_count, 2);
        let funcs = parsed.func_ids(None).expect("func ids");
        // FUNC is the 2nd type -> global id 2.
        assert_eq!(funcs.get("kf"), Some(&2));
    }

    #[test]
    fn struct_member_offsets_read_off_btf_members() {
        // strings: "\0u32\0nf_conn\0status\0mark\0flag\0"
        let strings = b"\0u32\0nf_conn\0status\0mark\0flag\0";
        let (s_u32, s_nf_conn, s_status, s_mark, s_flag) = (1u32, 5u32, 13u32, 20u32, 25u32);
        let mut types = Vec::new();
        // type 1: INT u32 (kind 1), size 4, encoding word
        types.extend_from_slice(&s_u32.to_le_bytes());
        types.extend_from_slice(&(1u32 << 24).to_le_bytes());
        types.extend_from_slice(&4u32.to_le_bytes());
        types.extend_from_slice(&(32u32).to_le_bytes()); // bits=32
        // type 2: STRUCT nf_conn (kind 4), kind_flag set, 3 members, size 24
        types.extend_from_slice(&s_nf_conn.to_le_bytes());
        types.extend_from_slice(&((1u32 << 31) | (4u32 << 24) | 3).to_le_bytes());
        types.extend_from_slice(&24u32.to_le_bytes());
        // member status: type 1 at bit 64
        types.extend_from_slice(&s_status.to_le_bytes());
        types.extend_from_slice(&1u32.to_le_bytes());
        types.extend_from_slice(&64u32.to_le_bytes());
        // member mark: type 1 at bit 128
        types.extend_from_slice(&s_mark.to_le_bytes());
        types.extend_from_slice(&1u32.to_le_bytes());
        types.extend_from_slice(&128u32.to_le_bytes());
        // member flag: a 1-bit bitfield at bit 160 (size in the high byte)
        types.extend_from_slice(&s_flag.to_le_bytes());
        types.extend_from_slice(&1u32.to_le_bytes());
        types.extend_from_slice(&((1u32 << 24) | 0xa0).to_le_bytes());

        let parsed = BtfBlob::parse_base(blob(&types, strings)).expect("parse");
        assert_eq!(parsed.type_count, 2);
        let offsets = parsed
            .struct_member_byte_offsets(None, "nf_conn", &["mark", "status", "flag", "absent"])
            .expect("walk")
            .expect("nf_conn defined");
        assert_eq!(offsets, vec![Some(16), Some(8), Some(20), None]);
        assert_eq!(
            parsed
                .struct_member_byte_offsets(None, "nf_ct", &["mark"])
                .expect("walk"),
            None
        );
    }

    #[test]
    fn struct_member_offsets_descend_anonymous_members() {
        // The shape `iov_iter` has: a named field, then an anonymous union
        // holding a named member and a second anonymous struct, so `count`
        // sits two levels down and is still addressed from the outer struct.
        // strings: "\0u64\0iov_iter\0iov_offset\0__ubuf_iovec\0count\0"
        let strings = b"\0u64\0iov_iter\0iov_offset\0__ubuf_iovec\0count\0";
        let (s_u64, s_iov_iter, s_iov_offset, s_ubuf, s_count) = (1u32, 5u32, 14u32, 25u32, 38u32);
        let mut types = Vec::new();
        // type 1: INT u64
        types.extend_from_slice(&s_u64.to_le_bytes());
        types.extend_from_slice(&(1u32 << 24).to_le_bytes());
        types.extend_from_slice(&8u32.to_le_bytes());
        types.extend_from_slice(&64u32.to_le_bytes());
        // type 2: anonymous STRUCT with one member `count` at bit 64
        types.extend_from_slice(&0u32.to_le_bytes());
        types.extend_from_slice(&((4u32 << 24) | 1).to_le_bytes());
        types.extend_from_slice(&16u32.to_le_bytes());
        types.extend_from_slice(&s_count.to_le_bytes());
        types.extend_from_slice(&1u32.to_le_bytes());
        types.extend_from_slice(&64u32.to_le_bytes());
        // type 3: anonymous UNION: `__ubuf_iovec` at bit 0, the anonymous
        // struct of type 2 overlaid on it at bit 0 as well
        types.extend_from_slice(&0u32.to_le_bytes());
        types.extend_from_slice(&((5u32 << 24) | 2).to_le_bytes());
        types.extend_from_slice(&16u32.to_le_bytes());
        types.extend_from_slice(&s_ubuf.to_le_bytes());
        types.extend_from_slice(&1u32.to_le_bytes());
        types.extend_from_slice(&0u32.to_le_bytes());
        types.extend_from_slice(&0u32.to_le_bytes());
        types.extend_from_slice(&2u32.to_le_bytes());
        types.extend_from_slice(&0u32.to_le_bytes());
        // type 4: STRUCT iov_iter: `iov_offset` at bit 64, the union at 128
        types.extend_from_slice(&s_iov_iter.to_le_bytes());
        types.extend_from_slice(&((4u32 << 24) | 2).to_le_bytes());
        types.extend_from_slice(&32u32.to_le_bytes());
        types.extend_from_slice(&s_iov_offset.to_le_bytes());
        types.extend_from_slice(&1u32.to_le_bytes());
        types.extend_from_slice(&64u32.to_le_bytes());
        types.extend_from_slice(&0u32.to_le_bytes());
        types.extend_from_slice(&3u32.to_le_bytes());
        types.extend_from_slice(&128u32.to_le_bytes());

        let parsed = BtfBlob::parse_base(blob(&types, strings)).expect("parse");
        let offsets = parsed
            .struct_member_byte_offsets(
                None,
                "iov_iter",
                &["iov_offset", "__ubuf_iovec", "count", "absent"],
            )
            .expect("walk")
            .expect("iov_iter defined");
        // The union sits at byte 16, so `__ubuf_iovec` is 16 and `count`,
        // eight bytes into the anonymous struct overlaid on it, is 24.
        assert_eq!(offsets, vec![Some(8), Some(16), Some(24), None]);
    }

    #[test]
    fn enum_values_read_off_btf_enumerators() {
        // strings: "\0iter_type\0ITER_UBUF\0ITER_IOVEC\0"
        let strings = b"\0iter_type\0ITER_UBUF\0ITER_IOVEC\0";
        let (s_iter_type, s_ubuf, s_iovec) = (1u32, 11u32, 21u32);
        let mut types = Vec::new();
        // type 1: ENUM iter_type with two enumerators
        types.extend_from_slice(&s_iter_type.to_le_bytes());
        types.extend_from_slice(&((6u32 << 24) | 2).to_le_bytes());
        types.extend_from_slice(&4u32.to_le_bytes());
        types.extend_from_slice(&s_ubuf.to_le_bytes());
        types.extend_from_slice(&0i32.to_le_bytes());
        types.extend_from_slice(&s_iovec.to_le_bytes());
        types.extend_from_slice(&1i32.to_le_bytes());

        let parsed = BtfBlob::parse_base(blob(&types, strings)).expect("parse");
        let values = parsed
            .enum_values(None, "iter_type", &["ITER_IOVEC", "ITER_UBUF", "ITER_BVEC"])
            .expect("walk")
            .expect("iter_type defined");
        assert_eq!(values, vec![Some(1), Some(0), None]);
        assert_eq!(
            parsed
                .enum_values(None, "other_enum", &["ITER_UBUF"])
                .expect("walk"),
            None
        );
    }

    #[test]
    fn enum64_values_recombine_both_halves() {
        // strings: "\0wide\0HIGH\0"
        let strings = b"\0wide\0HIGH\0";
        let (s_wide, s_high) = (1u32, 6u32);
        let mut types = Vec::new();
        // type 1: ENUM64 wide with one enumerator whose value needs 33 bits
        types.extend_from_slice(&s_wide.to_le_bytes());
        types.extend_from_slice(&((19u32 << 24) | 1).to_le_bytes());
        types.extend_from_slice(&8u32.to_le_bytes());
        types.extend_from_slice(&s_high.to_le_bytes());
        types.extend_from_slice(&0u32.to_le_bytes()); // val_lo32
        types.extend_from_slice(&1u32.to_le_bytes()); // val_hi32

        let parsed = BtfBlob::parse_base(blob(&types, strings)).expect("parse");
        let values = parsed
            .enum_values(None, "wide", &["HIGH"])
            .expect("walk")
            .expect("wide defined");
        assert_eq!(values, vec![Some(1 << 32)]);
    }
}
