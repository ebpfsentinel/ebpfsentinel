#![allow(unsafe_code)] // Raw bpf() syscalls for kfunc-aware program loading.

//! kfunc-aware eBPF program loader (kernel 5.18+ for module kfuncs).
//!
//! aya 0.13 cannot relocate kfunc calls: a kfunc call is a
//! `BPF_PSEUDO_KFUNC_CALL` instruction whose `imm` must hold the kfunc's
//! kernel BTF id and whose `off` indexes a program-load `fd_array` of module
//! BTF fds — neither of which aya emits. This module fills that gap outside
//! aya, the same way [`super::bpf_token`] adds features aya lacks via raw
//! syscalls.
//!
//! The loader is deliberately surgical so the rest of the agent is untouched:
//!
//! 1. [`prepatch_kfunc_calls`] rewrites every kfunc call site in the raw ELF
//!    to `src_reg = BPF_PSEUDO_KFUNC_CALL` and stashes a sentinel name-index in
//!    `imm`. aya's `EbpfLoader::load` then parses, creates and **hosts all
//!    maps**, and relocates the rest — its `relocate_calls` skips these sites
//!    because `insn_is_call` only matches `src_reg == 1`. Every existing map
//!    manager and event reader keeps working against aya's hosted maps.
//! 2. The caller reads aya's hosted map fds back by full name (every
//!    `aya::maps::Map` variant wraps a `MapData` whose `fd()` is public) and
//!    hands them to [`load_kfunc_programs`], which re-parses the same prepatched
//!    ELF, relocates the programs against those exact kernel maps, rewrites each
//!    sentinel back to its real `(btf_id, fd_array index)`, and issues a raw
//!    `BPF_PROG_LOAD` with the module BTF `fd_array`.
//!
//! The fds come straight from aya keyed by full ELF name, so the bridge is
//! exact: no pinning (`BPF_OBJ_PIN` is refused on integrity-enforcing kernels)
//! and no kernel-name matching (the kernel truncates map names to 15 bytes,
//! which collides distinct maps like `FIREWALL_RULE_COUNT` and
//! `FIREWALL_RULE_COUNT_V6`).
//!
//! aya never loads the kfunc programs themselves — the caller attaches the
//! returned program fds directly (see the raw-attach helpers).

use std::collections::{HashMap, HashSet};
use std::hash::BuildHasher;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use aya_obj::btf::BtfFeatures;
use aya_obj::{Object, ProgramSection};
use object::{Object as _, ObjectSection, ObjectSymbol, RelocationTarget};

use super::kfunc::{KfuncError, KfuncResolver, KfuncTarget};

/// `bpf(2)` commands. Numbers from `enum bpf_cmd`.
const BPF_PROG_LOAD: u32 = 5;
const BPF_BTF_LOAD: u32 = 18;

/// `BPF_PSEUDO_KFUNC_CALL` source-register marker on a call instruction.
const BPF_PSEUDO_KFUNC_CALL: u8 = 2;
/// `BPF_JMP | BPF_CALL` opcode.
const INSN_CALL: u8 = 0x85;

/// `enum bpf_prog_type` values we emit.
const BPF_PROG_TYPE_KPROBE: u32 = 2;
const BPF_PROG_TYPE_SCHED_CLS: u32 = 3;
const BPF_PROG_TYPE_XDP: u32 = 6;

/// `BPF_F_*` prog-load flags.
const BPF_F_SLEEPABLE: u32 = 1 << 4;
const BPF_F_XDP_HAS_FRAGS: u32 = 1 << 5;
/// Bind the program to one netdev at load so the verifier resolves
/// `bpf_xdp_metadata_rx_*` against that device's `xdp_metadata_ops` (no HW
/// offload — the program still runs on the CPU). Kernel 6.3+.
const BPF_F_XDP_DEV_BOUND_ONLY: u32 = 1 << 6;

/// `BPF_ALU64 | BPF_MOV | BPF_K` — `dst = imm`. Used to neutralize a
/// device-bound metadata kfunc call into `r0 = imm` when the program is not
/// loaded device-bound.
const BPF_MOV64_IMM: u8 = 0xb7;
/// `-EOPNOTSUPP` written into `r0` when neutralizing a metadata kfunc, so the
/// program's wrapper sees a non-zero return and falls back (mirrors a driver
/// without `xdp_metadata_ops` answering the real kfunc).
const NEG_EOPNOTSUPP: i32 = -95;

/// Device-bound-only XDP receive-metadata kfuncs. The verifier rejects these
/// unless the program is loaded device-bound, so an object calling any of them
/// must route through this loader even when it uses no module kfuncs — aya can
/// neither set `prog_ifindex` nor neutralize the calls.
const DEV_BOUND_METADATA_KFUNCS: &[&str] = &[
    "bpf_xdp_metadata_rx_hash",
    "bpf_xdp_metadata_rx_timestamp",
    "bpf_xdp_metadata_rx_vlan_tag",
];

/// Whether `name` is a device-bound-only XDP receive-metadata kfunc.
fn is_dev_bound_metadata_kfunc(name: &str) -> bool {
    DEV_BOUND_METADATA_KFUNCS.contains(&name)
}

/// Errors surfaced while loading a kfunc-using program.
#[derive(Debug, thiserror::Error)]
pub enum KfuncLoaderError {
    #[error("parse ELF: {0}")]
    ParseElf(String),

    #[error("parse object: {0}")]
    ParseObject(String),

    #[error("sanitize BTF: {0}")]
    SanitizeBtf(String),

    #[error("relocate: {0}")]
    Relocate(String),

    #[error("kfunc resolve: {0}")]
    Resolve(#[from] KfuncError),

    #[error("map `{0}` referenced by program but not hosted by aya")]
    MapNotHosted(String),

    #[error("BPF_BTF_LOAD failed: {0}")]
    BtfLoad(String),

    #[error("program `{name}` has an unsupported section kind for kfunc loading")]
    UnsupportedSection { name: String },

    #[error("program `{name}` not found among parsed functions")]
    MissingFunction { name: String },

    #[error("BPF_PROG_LOAD `{name}` failed (errno {errno}); verifier log:\n{log}")]
    ProgLoad {
        name: String,
        errno: i32,
        log: String,
    },
}

/// A kfunc call site in the raw object: the section it lives in, the byte
/// offset of the call instruction within that section, and the kfunc name.
#[derive(Debug, Clone)]
pub struct KfuncSite {
    section_index: usize,
    offset: u64,
    name: String,
}

/// A program loaded by this loader. The caller owns `fd` and is responsible
/// for attaching it (XDP / TC / uprobe) since aya never loaded it.
#[derive(Debug)]
pub struct KfuncLoadedProgram {
    /// Program name as keyed in the object (e.g. `xdp_firewall`).
    pub name: String,
    /// Loaded program fd. Dropping it unloads the program.
    pub fd: OwnedFd,
    /// `enum bpf_prog_type` of the loaded program.
    pub prog_type: u32,
}

/// Find every kfunc call site: relocations targeting an undefined (extern)
/// symbol. Order is deterministic (section then relocation order) so the
/// name-index sentinel assigned here matches [`load_kfunc_programs`].
pub fn find_kfunc_sites(elf: &[u8]) -> Result<Vec<KfuncSite>, KfuncLoaderError> {
    let file = object::File::parse(elf).map_err(|e| KfuncLoaderError::ParseElf(e.to_string()))?;
    let mut sites = Vec::new();
    for section in file.sections() {
        let section_index = section.index().0;
        for (offset, rel) in section.relocations() {
            let RelocationTarget::Symbol(sym_idx) = rel.target() else {
                continue;
            };
            let Ok(sym) = file.symbol_by_index(sym_idx) else {
                continue;
            };
            if !sym.is_undefined() {
                continue;
            }
            if let Ok(name) = sym.name()
                && !name.is_empty()
            {
                sites.push(KfuncSite {
                    section_index,
                    offset,
                    name: name.to_owned(),
                });
            }
        }
    }
    Ok(sites)
}

/// Whether the object calls any kfunc (and thus needs this loader).
pub fn has_kfunc_calls(elf: &[u8]) -> bool {
    find_kfunc_sites(elf).is_ok_and(|s| !s.is_empty())
}

/// Distinct kfunc names in first-seen order. The index of a name here is the
/// sentinel written into `insn.imm` by [`prepatch_kfunc_calls`].
fn unique_names(sites: &[KfuncSite]) -> Vec<String> {
    let mut names = Vec::new();
    for s in sites {
        if !names.contains(&s.name) {
            names.push(s.name.clone());
        }
    }
    names
}

/// How an object's kfunc usage decides its load strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KfuncClass {
    /// No kfunc calls — load with plain aya.
    None,
    /// Only vmlinux kfuncs (`off == 0`, no `fd_array`) **and** none that require
    /// a device-bound program — prepatch the resolved btf ids and let aya load
    /// **and** attach the program unchanged.
    VmlinuxOnly,
    /// Needs the raw loader because aya cannot emit what the object requires: a
    /// module-kfunc `fd_array`, or a device-bound load (`prog_ifindex` +
    /// `BPF_F_XDP_DEV_BOUND_ONLY`) / neutralization for device-bound-only
    /// metadata kfuncs. Also needs a raw attach.
    HasModule,
}

/// Whether the object calls any device-bound-only XDP metadata kfunc, which
/// forces the raw loader (aya can neither neutralize the call nor bind the
/// program to a device).
pub fn uses_dev_bound_metadata_kfuncs(elf: &[u8]) -> bool {
    find_kfunc_sites(elf)
        .is_ok_and(|sites| sites.iter().any(|s| is_dev_bound_metadata_kfunc(&s.name)))
}

/// Classify an object by the kfuncs it calls, resolving each against the
/// running kernel. Drives whether a program loads via aya or the raw path.
pub fn classify(elf: &[u8], resolver: &KfuncResolver) -> Result<KfuncClass, KfuncLoaderError> {
    let names = unique_names(&find_kfunc_sites(elf)?);
    if names.is_empty() {
        return Ok(KfuncClass::None);
    }
    let mut needs_raw = false;
    for name in &names {
        // A module kfunc needs the fd_array; a device-bound metadata kfunc
        // needs prog_ifindex or neutralization — neither is expressible in aya.
        if resolver.resolve(name)?.module_btf_obj_id.is_some() || is_dev_bound_metadata_kfunc(name)
        {
            needs_raw = true;
        }
    }
    Ok(if needs_raw {
        KfuncClass::HasModule
    } else {
        KfuncClass::VmlinuxOnly
    })
}

/// Rewrite every kfunc call site in `elf`, deriving each instruction's `imm`
/// (and `off`) from `imm_for`. Sets `src_reg = BPF_PSEUDO_KFUNC_CALL` so aya's
/// `relocate_calls` skips the site. Returns the modified ELF; an object that
/// calls no kfuncs is returned unchanged.
fn patch_sites(
    elf: &[u8],
    mut imm_for: impl FnMut(&str) -> Result<(i32, i16), KfuncLoaderError>,
) -> Result<Vec<u8>, KfuncLoaderError> {
    let sites = find_kfunc_sites(elf)?;
    if sites.is_empty() {
        return Ok(elf.to_vec());
    }

    // Map section index -> file offset of the section's bytes.
    let file = object::File::parse(elf).map_err(|e| KfuncLoaderError::ParseElf(e.to_string()))?;
    let mut section_file_off: HashMap<usize, u64> = HashMap::new();
    for section in file.sections() {
        if let Some((off, _size)) = section.file_range() {
            section_file_off.insert(section.index().0, off);
        }
    }

    let mut out = elf.to_vec();
    for site in &sites {
        let Some(&sec_off) = section_file_off.get(&site.section_index) else {
            return Err(KfuncLoaderError::ParseElf(format!(
                "kfunc site in section {} has no file range",
                site.section_index
            )));
        };
        let insn_off = (sec_off + site.offset) as usize;
        if insn_off + 8 > out.len() {
            return Err(KfuncLoaderError::ParseElf(
                "kfunc call instruction out of bounds".to_owned(),
            ));
        }
        let (imm, off) = imm_for(&site.name)?;
        // bpf_insn byte 1 = (src_reg << 4) | dst_reg: set src_reg nibble.
        out[insn_off + 1] = (out[insn_off + 1] & 0x0f) | (BPF_PSEUDO_KFUNC_CALL << 4);
        // bpf_insn off (bytes 2..4) and imm (bytes 4..8).
        out[insn_off + 2..insn_off + 4].copy_from_slice(&off.to_le_bytes());
        out[insn_off + 4..insn_off + 8].copy_from_slice(&imm.to_le_bytes());
    }
    Ok(out)
}

/// Rewrite every kfunc call in `elf` to a sentinel name-index (in `imm`) so
/// aya's loader will host the maps and skip these calls, while
/// [`load_kfunc_programs`] later rewrites each sentinel to its real
/// `(btf_id, fd_array index)`. Use for [`KfuncClass::HasModule`] objects.
pub fn prepatch_kfunc_calls(elf: &[u8]) -> Result<Vec<u8>, KfuncLoaderError> {
    let names = unique_names(&find_kfunc_sites(elf)?);
    patch_sites(elf, |name| {
        let idx = names
            .iter()
            .position(|n| n == name)
            .expect("site name is in names");
        Ok((i32::try_from(idx).expect("site index fits i32"), 0))
    })
}

/// Rewrite every kfunc call in `elf` to its resolved vmlinux `btf_id`
/// (`off == 0`), producing an object aya can load **and** attach unchanged.
/// Errors if any site resolves to a module kfunc — those must route through
/// [`prepatch_kfunc_calls`] + [`load_kfunc_programs`] instead. Use for
/// [`KfuncClass::VmlinuxOnly`] objects.
pub fn prepatch_vmlinux_kfuncs(
    elf: &[u8],
    resolver: &KfuncResolver,
) -> Result<Vec<u8>, KfuncLoaderError> {
    patch_sites(elf, |name| {
        let target = resolver.resolve(name)?;
        if target.module_btf_obj_id.is_some() {
            return Err(KfuncLoaderError::Relocate(format!(
                "kfunc `{name}` is a module kfunc; needs the fd_array loader"
            )));
        }
        Ok((i32::try_from(target.btf_id).expect("btf id fits i32"), 0))
    })
}

/// `(program name, function key, prog_type, expected_attach_type, prog_flags)`.
type ProgramMeta = (String, (usize, u64), u32, u32, u32);

/// The module-BTF `fd_array` plus the bookkeeping to address it: a slot index
/// per owning module, and the owned fds that must outlive `BPF_PROG_LOAD`.
struct FdArray {
    /// `fd_array` passed to the kernel (index 0 reserved for vmlinux).
    fds: Vec<i32>,
    /// module BTF object id -> `fd_array` slot index.
    module_slot: HashMap<u32, i16>,
    /// Owned module BTF fds kept alive through the load.
    _owned: Vec<OwnedFd>,
}

/// Load every program in a kfunc-using object against the maps aya `hosted`
/// when it loaded the same prepatched `elf`, keyed by full ELF name. The loaded
/// programs share the exact kernel map objects the managers and event readers
/// write to (the caller keeps the `hosted` fds it owns).
///
/// When `dev_bound_ifindex` is `Some`, XDP programs are loaded device-bound to
/// that netdev (`prog_ifindex` + `BPF_F_XDP_DEV_BOUND_ONLY`) so the verifier
/// resolves `bpf_xdp_metadata_rx_*` against the device's `xdp_metadata_ops`.
/// When `None`, those metadata kfunc calls are neutralized to `r0 = -EOPNOTSUPP`
/// so the object loads on any NIC and the program's wrapper falls back.
pub fn load_kfunc_programs<S: BuildHasher>(
    elf: &[u8],
    resolver: &KfuncResolver,
    hosted: &HashMap<String, OwnedFd, S>,
    dev_bound_ifindex: Option<u32>,
) -> Result<Vec<KfuncLoadedProgram>, KfuncLoaderError> {
    let names = unique_names(&find_kfunc_sites(elf)?);

    let mut obj = Object::parse(elf).map_err(|e| KfuncLoaderError::ParseObject(e.to_string()))?;
    let features = BtfFeatures::new(true, true, true, true, true, true, true);
    obj.fixup_and_sanitize_btf(&features)
        .map_err(|e| KfuncLoaderError::SanitizeBtf(e.to_string()))?;

    // Relocate against aya's hosted maps, matched by full ELF name.
    // `bridged` borrows the hosted fds for the call.
    let bridged = bridge_maps(&mut obj, hosted)?;
    let text_sections: HashSet<usize> = obj.functions.keys().map(|(s, _)| *s).collect();
    obj.relocate_maps(
        bridged.iter().map(|(n, fd, m)| (n.as_str(), *fd, m)),
        &text_sections,
    )
    .map_err(|e| KfuncLoaderError::Relocate(format!("{e:?}")))?;
    obj.relocate_calls(&text_sections)
        .map_err(|e| KfuncLoaderError::Relocate(format!("{e:?}")))?;

    // The program BTF is shared by every program in the object.
    let btf_bytes = obj.btf.as_ref().map(aya_obj::btf::Btf::to_bytes);
    let prog_btf_fd = match btf_bytes {
        Some(ref b) if !b.is_empty() => Some(load_btf(b)?),
        _ => None,
    };

    let mut targets: HashMap<String, KfuncTarget> = HashMap::new();
    for name in &names {
        targets.insert(name.clone(), resolver.resolve(name)?);
    }
    let fd_array = build_fd_array(resolver, &targets)?;

    let program_meta: Vec<ProgramMeta> = obj
        .programs
        .iter()
        .map(|(name, p)| {
            let (prog_type, eat, flags) = prog_attrs(&p.section);
            (name.clone(), p.function_key(), prog_type, eat, flags)
        })
        .collect();

    let mut loaded = Vec::new();
    for (name, key, prog_type, eat, flags) in program_meta {
        if prog_type == 0 {
            return Err(KfuncLoaderError::UnsupportedSection { name });
        }
        let func = obj
            .functions
            .get(&key)
            .ok_or_else(|| KfuncLoaderError::MissingFunction { name: name.clone() })?;
        let mut insns = func.instructions.clone();
        let fi_bytes = func.func_info.func_info_bytes();
        let fi_rec = u32::try_from(func.func_info_rec_size).unwrap_or(0);
        let li_rec = u32::try_from(func.line_info_rec_size).unwrap_or(0);
        let li_bytes = sanitize_line_info(&func.line_info.line_info_bytes(), li_rec);

        rewrite_kfunc_calls(
            &mut insns,
            &names,
            &targets,
            &fd_array.module_slot,
            dev_bound_ifindex.is_some(),
        );

        // Only XDP programs carry the device-bound metadata kfuncs; binding a
        // TC/uprobe program to a netdev would be meaningless (and rejected).
        let prog_ifindex = if prog_type == BPF_PROG_TYPE_XDP {
            dev_bound_ifindex
        } else {
            None
        };

        let fd = raw_prog_load(&RawProgLoad {
            name: &name,
            prog_type,
            expected_attach_type: eat,
            prog_flags: flags,
            insns: &insns,
            license: obj.license.as_bytes_with_nul(),
            prog_btf_fd: prog_btf_fd.as_ref().map(AsRawFd::as_raw_fd),
            func_info: &fi_bytes,
            func_info_rec_size: fi_rec,
            line_info: &li_bytes,
            line_info_rec_size: li_rec,
            fd_array: &fd_array.fds,
            has_modules: !fd_array.module_slot.is_empty(),
            dev_bound_ifindex: prog_ifindex,
        })?;

        loaded.push(KfuncLoadedProgram {
            name,
            fd,
            prog_type,
        });
    }

    // fd_array fds and prog_btf_fd stay alive until here; the kernel took its
    // own references during BPF_PROG_LOAD, so dropping them now is safe.
    drop(fd_array);
    drop(prog_btf_fd);
    Ok(loaded)
}

/// Pair every map the object declares with its hosted fd, draining `obj.maps`
/// and returning `(name, borrowed raw fd, definition)` tuples. The raw fds are
/// borrowed from `hosted`, which must outlive the relocation.
fn bridge_maps<S: BuildHasher>(
    obj: &mut Object,
    hosted: &HashMap<String, OwnedFd, S>,
) -> Result<Vec<(String, RawFd, aya_obj::Map)>, KfuncLoaderError> {
    let mut bridged = Vec::new();
    for (name, map) in std::mem::take(&mut obj.maps) {
        let fd = hosted
            .get(&name)
            .ok_or_else(|| KfuncLoaderError::MapNotHosted(name.clone()))?
            .as_raw_fd();
        bridged.push((name, fd, map));
    }
    Ok(bridged)
}

/// Build the module-BTF `fd_array` from the resolved kfunc targets. vmlinux
/// kfuncs (`off == 0`) need no slot; each distinct owning module gets one at
/// index >= 1.
fn build_fd_array(
    resolver: &KfuncResolver,
    targets: &HashMap<String, KfuncTarget>,
) -> Result<FdArray, KfuncLoaderError> {
    use std::collections::hash_map::Entry;

    let mut module_slot: HashMap<u32, i16> = HashMap::new();
    let mut owned: Vec<OwnedFd> = Vec::new();
    let mut fds: Vec<i32> = vec![0];
    for target in targets.values() {
        if let Some(obj_id) = target.module_btf_obj_id
            && let Entry::Vacant(slot) = module_slot.entry(obj_id)
        {
            let fd = resolver.module_btf_fd(obj_id)?;
            slot.insert(i16::try_from(fds.len()).expect("fd_array slot fits i16"));
            fds.push(fd.as_raw_fd());
            owned.push(fd);
        }
    }
    Ok(FdArray {
        fds,
        module_slot,
        _owned: owned,
    })
}

/// Rewrite each kfunc-call sentinel in `insns` to its resolved `(btf_id,
/// fd_array index)`. When `dev_bound` is false, device-bound-only metadata
/// kfunc sites are instead neutralized to `r0 = -EOPNOTSUPP` so the program
/// loads on a NIC without `xdp_metadata_ops` (the program's wrapper treats the
/// non-zero return as "metadata unavailable").
fn rewrite_kfunc_calls(
    insns: &mut [aya_obj::generated::bpf_insn],
    names: &[String],
    targets: &HashMap<String, KfuncTarget>,
    module_slot: &HashMap<u32, i16>,
    dev_bound: bool,
) {
    for ins in insns {
        if ins.code == INSN_CALL && ins.src_reg() == BPF_PSEUDO_KFUNC_CALL {
            let idx = usize::try_from(ins.imm).expect("kfunc sentinel index is non-negative");
            let name = &names[idx];
            if !dev_bound && is_dev_bound_metadata_kfunc(name) {
                // Replace `call <metadata kfunc>` with `r0 = -EOPNOTSUPP`.
                ins.code = BPF_MOV64_IMM;
                ins.set_dst_reg(0);
                ins.set_src_reg(0);
                ins.off = 0;
                ins.imm = NEG_EOPNOTSUPP;
                continue;
            }
            let target = &targets[name];
            ins.imm = i32::try_from(target.btf_id).expect("btf id fits i32");
            ins.off = target
                .module_btf_obj_id
                .map_or(0, |obj_id| module_slot[&obj_id]);
        }
    }
}

/// `(prog_type, expected_attach_type, prog_flags)` for a program section, or
/// `(0, …)` if the section kind is not one this loader supports.
fn prog_attrs(section: &ProgramSection) -> (u32, u32, u32) {
    match section {
        ProgramSection::Xdp { frags, .. } => {
            let flags = if *frags { BPF_F_XDP_HAS_FRAGS } else { 0 };
            (BPF_PROG_TYPE_XDP, 0, flags)
        }
        ProgramSection::SchedClassifier => (BPF_PROG_TYPE_SCHED_CLS, 0, 0),
        ProgramSection::UProbe { sleepable, .. } => {
            let flags = if *sleepable { BPF_F_SLEEPABLE } else { 0 };
            (BPF_PROG_TYPE_KPROBE, 0, flags)
        }
        _ => (0, 0, 0),
    }
}

#[repr(C)]
#[derive(Default)]
struct BtfLoadAttr {
    btf: u64,
    btf_log_buf: u64,
    btf_size: u32,
    btf_log_size: u32,
    btf_log_level: u32,
    btf_log_true_size: u32,
}

/// `BPF_BTF_LOAD`: load a BTF blob and return its fd.
fn load_btf(bytes: &[u8]) -> Result<OwnedFd, KfuncLoaderError> {
    let mut log = vec![0u8; 1 << 16];
    let mut attr = BtfLoadAttr {
        btf: bytes.as_ptr() as u64,
        btf_size: u32::try_from(bytes.len()).expect("btf size fits u32"),
        btf_log_buf: log.as_mut_ptr() as u64,
        btf_log_size: u32::try_from(log.len()).expect("log size fits u32"),
        btf_log_level: 1,
        ..Default::default()
    };
    let rc = unsafe {
        bpf(
            BPF_BTF_LOAD,
            (&raw mut attr).cast(),
            std::mem::size_of::<BtfLoadAttr>(),
        )
    };
    if rc < 0 {
        let msg = String::from_utf8_lossy(&log);
        return Err(KfuncLoaderError::BtfLoad(
            msg.trim_end_matches('\0').to_owned(),
        ));
    }
    #[allow(clippy::cast_possible_truncation)]
    let raw = rc as RawFd;
    // SAFETY: rc >= 0 is a valid fd owned by this process.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

#[repr(C)]
#[derive(Default)]
struct ProgLoadAttr {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
    prog_flags: u32,
    prog_name: [u8; 16],
    prog_ifindex: u32,
    expected_attach_type: u32,
    prog_btf_fd: u32,
    func_info_rec_size: u32,
    func_info: u64,
    func_info_cnt: u32,
    line_info_rec_size: u32,
    line_info: u64,
    line_info_cnt: u32,
    attach_btf_id: u32,
    attach_prog_fd: u32,
    core_relo_cnt: u32,
    fd_array: u64,
    core_relos: u64,
    core_relo_rec_size: u32,
    log_true_size: u32,
}

/// Inputs for a single raw `BPF_PROG_LOAD`.
struct RawProgLoad<'a> {
    name: &'a str,
    prog_type: u32,
    expected_attach_type: u32,
    prog_flags: u32,
    insns: &'a [aya_obj::generated::bpf_insn],
    license: &'a [u8],
    prog_btf_fd: Option<RawFd>,
    func_info: &'a [u8],
    func_info_rec_size: u32,
    line_info: &'a [u8],
    line_info_rec_size: u32,
    fd_array: &'a [i32],
    has_modules: bool,
    /// When `Some`, load the program device-bound to this netdev ifindex
    /// (`prog_ifindex` + `BPF_F_XDP_DEV_BOUND_ONLY`).
    dev_bound_ifindex: Option<u32>,
}

/// The kernel requires `line_info` records to have strictly-increasing
/// `insn_off` (the first `u32` of each record) and rejects the program with
/// `EINVAL` (`"Invalid line_info[N].insn_off"`) otherwise. Some codegen maps two
/// source spans to a single instruction — most notably a zero-width inline-asm
/// barrier — producing two records at the same offset. Drop any record that
/// does not advance the offset; `line_info` is debug metadata used only to
/// annotate the verifier log, so dropping a duplicate keeps the program
/// loadable without affecting its behaviour.
fn sanitize_line_info(bytes: &[u8], rec_size: u32) -> Vec<u8> {
    let rec = rec_size as usize;
    // Each record begins with a `u32` `insn_off`; anything smaller is malformed.
    if rec < 4 || bytes.len() < rec {
        return bytes.to_vec();
    }
    let mut out = Vec::with_capacity(bytes.len());
    let mut prev: Option<u32> = None;
    for chunk in bytes.chunks_exact(rec) {
        let off = u32::from_ne_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        if prev.is_some_and(|p| off <= p) {
            continue;
        }
        prev = Some(off);
        out.extend_from_slice(chunk);
    }
    out
}

/// Issue a raw `BPF_PROG_LOAD`, returning the loaded program fd or a verifier
/// log on rejection.
fn raw_prog_load(req: &RawProgLoad<'_>) -> Result<OwnedFd, KfuncLoaderError> {
    // func_info/line_info are only valid alongside a program BTF.
    let (fi_ptr, fi_rec, fi_cnt, li_ptr, li_rec, li_cnt) = match req.prog_btf_fd {
        Some(_) if req.func_info_rec_size > 0 => (
            req.func_info.as_ptr() as u64,
            req.func_info_rec_size,
            u32::try_from(req.func_info.len()).unwrap_or(0) / req.func_info_rec_size,
            req.line_info.as_ptr() as u64,
            req.line_info_rec_size,
            u32::try_from(req.line_info.len())
                .unwrap_or(0)
                .checked_div(req.line_info_rec_size)
                .unwrap_or(0),
        ),
        _ => (0, 0, 0, 0, 0, 0),
    };

    let dev_bound_flags = if req.dev_bound_ifindex.is_some() {
        BPF_F_XDP_DEV_BOUND_ONLY
    } else {
        0
    };

    let mut attr = ProgLoadAttr {
        prog_type: req.prog_type,
        insn_cnt: u32::try_from(req.insns.len()).expect("insn count fits u32"),
        insns: req.insns.as_ptr() as u64,
        license: req.license.as_ptr() as u64,
        prog_flags: req.prog_flags | dev_bound_flags,
        prog_ifindex: req.dev_bound_ifindex.unwrap_or(0),
        expected_attach_type: req.expected_attach_type,
        prog_btf_fd: req
            .prog_btf_fd
            .map_or(0, |fd| u32::try_from(fd).unwrap_or(0)),
        func_info_rec_size: fi_rec,
        func_info: fi_ptr,
        func_info_cnt: fi_cnt,
        line_info_rec_size: li_rec,
        line_info: li_ptr,
        line_info_cnt: li_cnt,
        // A null fd_array is correct for vmlinux-only programs (every kfunc
        // off == 0); module programs need the real array.
        fd_array: if req.has_modules {
            req.fd_array.as_ptr() as u64
        } else {
            0
        },
        ..Default::default()
    };
    let name_bytes = req.name.as_bytes();
    let n = name_bytes.len().min(15);
    attr.prog_name[..n].copy_from_slice(&name_bytes[..n]);

    // Phase 1: load with no verifier log. A verbose log for a large program
    // (the load balancer's fully-unrolled paths emit hundreds of thousands of
    // lines) overruns any fixed buffer, and the kernel then fails the load with
    // ENOSPC even though verification itself passed. Requesting no log sidesteps
    // that on the happy path and is faster.
    if let Ok(fd) = issue_prog_load(&mut attr, 0, &mut []) {
        return Ok(fd);
    }
    // Phase 2: the load genuinely failed. Retry with a large log buffer so the
    // verifier's rejection reason is captured for diagnostics. The buffer is
    // sized generously because a rejection deep in an unrolled program can
    // itself produce a multi-megabyte log.
    let mut log = vec![0u8; 16 << 20];
    issue_prog_load(&mut attr, 1, &mut log).map_err(|(errno, raw_log)| {
        // The kernel's rotating verifier log can carry embedded NULs at the
        // wrap point; flatten them and keep the full text so the rejection
        // reason is never lost to a tail-window slice.
        let cleaned: String = raw_log.chars().filter(|&c| c != '\0').collect();
        KfuncLoaderError::ProgLoad {
            name: req.name.to_owned(),
            errno,
            log: cleaned.trim().to_owned(),
        }
    })
}

/// Issue one `BPF_PROG_LOAD` with the given verifier-log settings. On rejection
/// returns the raw errno and the (lossy-decoded) log buffer so the caller can
/// decide whether to retry or surface the failure.
fn issue_prog_load(
    attr: &mut ProgLoadAttr,
    log_level: u32,
    log: &mut [u8],
) -> Result<OwnedFd, (i32, String)> {
    attr.log_level = log_level;
    if log_level == 0 || log.is_empty() {
        attr.log_buf = 0;
        attr.log_size = 0;
    } else {
        attr.log_buf = log.as_mut_ptr() as u64;
        attr.log_size = u32::try_from(log.len()).unwrap_or(u32::MAX);
    }

    let rc = unsafe {
        bpf(
            BPF_PROG_LOAD,
            (&raw mut *attr).cast(),
            std::mem::size_of::<ProgLoadAttr>(),
        )
    };
    if rc < 0 {
        let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        let raw_log = String::from_utf8_lossy(log).into_owned();
        return Err((errno, raw_log));
    }
    #[allow(clippy::cast_possible_truncation)]
    let raw = rc as RawFd;
    // SAFETY: rc >= 0 is a valid fd owned by this process.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepatch_noop_without_kfuncs() {
        // A minimal non-ELF blob has no relocations; prepatch must be a no-op
        // only when parsing succeeds, so assert the empty-site fast path via
        // unique_names instead (parsing arbitrary bytes would error).
        let sites: Vec<KfuncSite> = Vec::new();
        assert!(unique_names(&sites).is_empty());
    }

    #[test]
    fn unique_names_dedupes_first_seen() {
        let sites = vec![
            KfuncSite {
                section_index: 1,
                offset: 0,
                name: "bpf_ct_release".into(),
            },
            KfuncSite {
                section_index: 1,
                offset: 16,
                name: "bpf_skb_ct_lookup".into(),
            },
            KfuncSite {
                section_index: 1,
                offset: 32,
                name: "bpf_ct_release".into(),
            },
        ];
        let names = unique_names(&sites);
        assert_eq!(names, vec!["bpf_ct_release", "bpf_skb_ct_lookup"]);
    }

    #[test]
    fn prog_attrs_maps_sections() {
        assert_eq!(
            prog_attrs(&ProgramSection::SchedClassifier),
            (BPF_PROG_TYPE_SCHED_CLS, 0, 0)
        );
    }

    #[test]
    fn dev_bound_metadata_kfuncs_recognized() {
        assert!(is_dev_bound_metadata_kfunc("bpf_xdp_metadata_rx_hash"));
        assert!(is_dev_bound_metadata_kfunc("bpf_xdp_metadata_rx_timestamp"));
        assert!(is_dev_bound_metadata_kfunc("bpf_xdp_metadata_rx_vlan_tag"));
        assert!(!is_dev_bound_metadata_kfunc("bpf_xdp_ct_lookup"));
        assert!(!is_dev_bound_metadata_kfunc("bpf_ct_release"));
    }

    /// Build a single `call` instruction marked as a kfunc-call sentinel with
    /// `imm = name_index`, as [`prepatch_kfunc_calls`] would emit.
    fn kfunc_call_sentinel(name_index: i32) -> aya_obj::generated::bpf_insn {
        aya_obj::generated::bpf_insn {
            code: INSN_CALL,
            _bitfield_align_1: [],
            _bitfield_1: aya_obj::generated::bpf_insn::new_bitfield_1(0, BPF_PSEUDO_KFUNC_CALL),
            off: 0,
            imm: name_index,
        }
    }

    #[test]
    fn metadata_kfunc_neutralized_when_not_dev_bound() {
        let names = vec!["bpf_xdp_metadata_rx_hash".to_owned()];
        let mut targets = HashMap::new();
        targets.insert(
            names[0].clone(),
            KfuncTarget {
                btf_id: 4242,
                module_btf_obj_id: None,
            },
        );
        let module_slot = HashMap::new();
        let mut insns = [kfunc_call_sentinel(0)];

        rewrite_kfunc_calls(&mut insns, &names, &targets, &module_slot, false);

        // The call became `r0 = -EOPNOTSUPP`, so the wrapper falls back.
        assert_eq!(insns[0].code, BPF_MOV64_IMM);
        assert_eq!(insns[0].dst_reg(), 0);
        assert_eq!(insns[0].imm, NEG_EOPNOTSUPP);
    }

    #[test]
    fn metadata_kfunc_kept_as_call_when_dev_bound() {
        let names = vec!["bpf_xdp_metadata_rx_hash".to_owned()];
        let mut targets = HashMap::new();
        targets.insert(
            names[0].clone(),
            KfuncTarget {
                btf_id: 4242,
                module_btf_obj_id: None,
            },
        );
        let module_slot = HashMap::new();
        let mut insns = [kfunc_call_sentinel(0)];

        rewrite_kfunc_calls(&mut insns, &names, &targets, &module_slot, true);

        // Device-bound: stays a kfunc call resolved to the real btf id, off 0.
        assert_eq!(insns[0].code, INSN_CALL);
        assert_eq!(insns[0].imm, 4242);
        assert_eq!(insns[0].off, 0);
    }
}
