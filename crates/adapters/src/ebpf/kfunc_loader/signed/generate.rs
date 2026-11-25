//! The build half: turn an eBPF object into one loader program per program
//! it holds, each with the metadata its frozen, exclusive map will carry.
//!
//! The object is relocated here, once, the way the agent relocates it at
//! start-up, except that a map is named by its slot in the load's
//! `fd_array` (`BPF_PSEUDO_MAP_IDX`) rather than by a descriptor: the slot is
//! known at build, the descriptor only on the host. What the host still
//! chooses - which map sits in each slot, the program BTF, the netdev an XDP
//! program binds to, which optional kfuncs go - is passed to the loader in
//! its context; everything else, the instructions included, is in the
//! metadata, whose digest the loader checks before it does anything.

use std::collections::HashSet;
use std::os::fd::RawFd;

use aya_obj::Object;
use sha2::{Digest as _, Sha256};

use super::super::{
    BPF_F_XDP_DEV_BOUND_ONLY, BPF_PROG_TYPE_LSM, BPF_PROG_TYPE_XDP, BPF_PSEUDO_KFUNC_CALL,
    KfuncLoaderError, NEG_EOPNOTSUPP, ProgLoadAttr, find_kfunc_sites, is_dev_bound_metadata_kfunc,
    is_optional_kfunc, lsm_hooks, prepatch_kfunc_calls, prog_attrs, sanitize_line_info,
    unique_names,
};
use super::insn::{self, Asm, R10};
use super::{ctx, fds_base};

/// The descriptor the build gives map `i` while relocating, recognised and
/// replaced by the slot afterwards. Far above any descriptor a build process
/// holds, so a real one is never mistaken for it.
const FAKE_FD_BASE: RawFd = 0x4000_0000;

/// `BPF_PSEUDO_MAP_FD`, written by the relocation for a map.
const PSEUDO_MAP_FD: u8 = 1;
/// `BPF_PSEUDO_MAP_VALUE`, written by the relocation for a data section.
const PSEUDO_MAP_VALUE: u8 = 2;

/// `BPF_FUNC_sys_bpf`.
const HELPER_SYS_BPF: i32 = 166;
/// `BPF_FUNC_btf_find_by_name_kind`.
const HELPER_BTF_FIND_BY_NAME_KIND: i32 = 167;
/// `BTF_KIND_FUNC`.
const BTF_KIND_FUNC: i32 = 12;
/// `BPF_PROG_LOAD`, the command the loader issues.
const CMD_PROG_LOAD: i32 = 5;
/// The bytes of `union bpf_attr` the loader hands `bpf_sys_bpf`: every field
/// up to and including `prog_token_fd`.
const INNER_ATTR_SIZE: i32 = 148;
/// Where the attribute lives on the loader's stack.
const ATTR: i16 = -152;

/// `-EINVAL`, the loader's answer when the metadata is not the one it was
/// built for.
const NEG_EINVAL: i32 = -22;
/// `-ENOENT`, the loader's answer when a name does not resolve.
const NEG_ENOENT: i32 = -2;

/// `out_failed_kfunc` when the LSM hook did not resolve into vmlinux.
pub(super) const FAILED_LSM_HOOK: i32 = -2;

/// What the generator made of one object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedObject {
    /// SHA-256 of the object with its kfunc calls prepatched, the bytes the
    /// agent hands the program loader.
    pub elf_sha256: [u8; 32],
    /// The object's maps, by full ELF name, in `fd_array` slot order.
    pub maps: Vec<String>,
    /// One loader per program, in name order.
    pub programs: Vec<GeneratedProgram>,
}

/// One program's loader and the metadata its map carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedProgram {
    /// Program name as keyed in the object.
    pub name: String,
    /// `enum bpf_prog_type` the inner program loads as.
    pub prog_type: u32,
    /// `expected_attach_type` the inner program loads with.
    pub expected_attach_type: u32,
    /// The kfuncs the program calls, in the order of the loader's bits.
    pub kfuncs: Vec<String>,
    /// Bit `j` set when kfunc `j` may be neutralized by the host.
    pub neutralizable: u64,
    /// The loader's instructions, the bytes the signature covers.
    pub loader: Vec<u8>,
    /// The metadata the loader's map holds.
    pub blob: Vec<u8>,
}

/// Generate the loaders of every program in `elf`, the object as built.
///
/// # Errors
///
/// The object does not parse or relocate, a program calls more kfuncs than
/// the loader's mask holds, or a jump does not fit.
pub fn generate(elf: &[u8]) -> Result<GeneratedObject, KfuncLoaderError> {
    let patched = prepatch_kfunc_calls(elf)?;
    let names = unique_names(&find_kfunc_sites(&patched)?);
    let hooks = lsm_hooks(&patched)?;
    let (obj, maps) = relocate(&patched)?;
    let has_btf = obj.btf.as_ref().is_some_and(|b| !b.to_bytes().is_empty());

    let mut program_names: Vec<&String> = obj.programs.keys().collect();
    program_names.sort();
    let mut programs = Vec::with_capacity(program_names.len());
    for name in program_names {
        let program = &obj.programs[name];
        let (prog_type, expected_attach_type, static_flags) = prog_attrs(&program.section);
        if prog_type == 0 {
            continue;
        }
        let func = obj
            .functions
            .get(&program.function_key())
            .ok_or_else(|| KfuncLoaderError::MissingFunction { name: name.clone() })?;
        let lsm_hook = if prog_type == BPF_PROG_TYPE_LSM {
            let hook = hooks
                .get(&program.section_index)
                .ok_or_else(|| KfuncLoaderError::MissingLsmHook { name: name.clone() })?;
            Some(format!("{}{hook}", super::super::BPF_LSM_FUNC_PREFIX))
        } else {
            None
        };
        let mut insns: Vec<u64> = func
            .instructions
            .iter()
            .map(|i| insn::encode(i.code, i.dst_reg(), i.src_reg(), i.off, i.imm))
            .collect();
        map_slots(&mut insns, maps.len())?;
        let (fi, fi_rec) = if has_btf {
            (
                func.func_info.func_info_bytes(),
                u32::try_from(func.func_info_rec_size).unwrap_or(0),
            )
        } else {
            (Vec::new(), 0)
        };
        let li_rec = u32::try_from(func.line_info_rec_size).unwrap_or(0);
        let li = if has_btf {
            sanitize_line_info(&func.line_info.line_info_bytes(), li_rec)
        } else {
            Vec::new()
        };
        let source = ProgramSource {
            name,
            prog_type,
            expected_attach_type,
            static_flags,
            insns: &insns,
            license: obj.license.as_bytes_with_nul(),
            func_info: (fi.as_slice(), fi_rec),
            line_info: (li.as_slice(), li_rec),
            lsm_hook: lsm_hook.as_deref(),
            map_count: maps.len(),
        };
        programs.push(generate_program(&source, &names)?);
    }
    Ok(GeneratedObject {
        elf_sha256: Sha256::digest(&patched).into(),
        maps,
        programs,
    })
}

/// Parse and relocate the prepatched object, every map against a fake
/// descriptor in name order. Returns the object and the map names in slot
/// order.
fn relocate(patched: &[u8]) -> Result<(Object, Vec<String>), KfuncLoaderError> {
    let mut obj =
        Object::parse(patched).map_err(|e| KfuncLoaderError::ParseObject(e.to_string()))?;
    obj.fixup_and_sanitize_btf(|| Some(|_| true))
        .map_err(|e| KfuncLoaderError::SanitizeBtf(e.to_string()))?;
    let mut maps: Vec<(String, aya_obj::Map)> = std::mem::take(&mut obj.maps).into_iter().collect();
    maps.sort_by(|a, b| a.0.cmp(&b.0));
    let mut bridged: Vec<(String, RawFd, aya_obj::Map)> = Vec::with_capacity(maps.len());
    for (slot, (name, map)) in maps.into_iter().enumerate() {
        let slot = RawFd::try_from(slot).map_err(|e| KfuncLoaderError::Relocate(e.to_string()))?;
        bridged.push((name, FAKE_FD_BASE + slot, map));
    }
    let text_sections: HashSet<usize> = obj.functions.keys().map(|(s, _)| *s).collect();
    obj.relocate_maps(
        bridged.iter().map(|(n, fd, m)| (n.as_str(), *fd, m)),
        &text_sections,
    )
    .map_err(|e| KfuncLoaderError::Relocate(format!("{e:?}")))?;
    obj.relocate_calls(&text_sections)
        .map_err(|e| KfuncLoaderError::Relocate(format!("{e:?}")))?;
    Ok((obj, bridged.into_iter().map(|(n, _, _)| n).collect()))
}

/// Rewrite every map load from the fake descriptor to its `fd_array` slot.
fn map_slots(insns: &mut [u64], map_count: usize) -> Result<(), KfuncLoaderError> {
    let mut i = 0;
    while i < insns.len() {
        let ins = insns[i];
        if insn::code(ins) != insn::LD_IMM64 {
            i += 1;
            continue;
        }
        let kind = match insn::src(ins) {
            PSEUDO_MAP_FD => Some(insn::PSEUDO_MAP_IDX),
            PSEUDO_MAP_VALUE => Some(insn::PSEUDO_MAP_IDX_VALUE),
            _ => None,
        };
        if let Some(kind) = kind {
            let slot = insn::imm(ins) - FAKE_FD_BASE;
            if !usize::try_from(slot).is_ok_and(|s| s < map_count) {
                return Err(KfuncLoaderError::Relocate(format!(
                    "map load at instruction {i} names no map of the object"
                )));
            }
            insns[i] = insn::encode(insn::LD_IMM64, insn::dst(ins), kind, insn::off(ins), slot);
        }
        // A 64-bit load spans two instructions; the second is never a load.
        i += 2;
    }
    Ok(())
}

/// One program as the generator reads it.
struct ProgramSource<'a> {
    name: &'a str,
    prog_type: u32,
    expected_attach_type: u32,
    static_flags: u32,
    insns: &'a [u64],
    license: &'a [u8],
    func_info: (&'a [u8], u32),
    line_info: (&'a [u8], u32),
    lsm_hook: Option<&'a str>,
    map_count: usize,
}

/// One kfunc as the loader handles it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct KfuncPlan {
    name_off: i32,
    name_len: i32,
    neutralizable: bool,
    /// Blob offset of every call to it.
    sites: Vec<i32>,
}

/// Where each piece of the metadata sits.
#[derive(Debug, Clone, PartialEq, Eq)]
struct BlobLayout {
    license: i32,
    func_info: i32,
    func_info_cnt: i32,
    line_info: i32,
    line_info_cnt: i32,
    lsm_name: Option<(i32, i32)>,
    fd_array: i32,
}

fn pad8(blob: &mut Vec<u8>) {
    while !blob.len().is_multiple_of(8) {
        blob.push(0);
    }
}

fn offset(blob: &[u8]) -> Result<i32, KfuncLoaderError> {
    i32::try_from(blob.len()).map_err(|_| KfuncLoaderError::Relocate("metadata too large".into()))
}

/// The kfuncs one program calls, in first-call order, with their call sites.
fn kfunc_sites(
    insns: &[u64],
    names: &[String],
) -> Result<Vec<(String, Vec<i32>)>, KfuncLoaderError> {
    let mut kfuncs: Vec<(String, Vec<i32>)> = Vec::new();
    for (i, &ins) in insns.iter().enumerate() {
        if insn::code(ins) != insn::CALL || insn::src(ins) != BPF_PSEUDO_KFUNC_CALL {
            continue;
        }
        let name = usize::try_from(insn::imm(ins))
            .ok()
            .and_then(|idx| names.get(idx))
            .ok_or_else(|| KfuncLoaderError::Relocate(format!("kfunc call {i} names nothing")))?;
        let site = i32::try_from(i * 8)
            .map_err(|_| KfuncLoaderError::Relocate("program too large".into()))?;
        match kfuncs.iter_mut().find(|(n, _)| n == name) {
            Some((_, sites)) => sites.push(site),
            None => kfuncs.push((name.clone(), vec![site])),
        }
    }
    if kfuncs.len() > 64 {
        return Err(KfuncLoaderError::Relocate(format!(
            "{} kfuncs, more than the loader's mask holds",
            kfuncs.len()
        )));
    }
    Ok(kfuncs)
}

/// Whether the host may ask for `name` to be neutralized: the kfuncs the
/// unsigned path may rewrite to `r0 = -EOPNOTSUPP`, and no other.
fn neutralizable(name: &str) -> bool {
    is_optional_kfunc(name)
        || is_dev_bound_metadata_kfunc(name)
        || name == crate::ebpf::xdp_pull_probe::XDP_PULL_KFUNC
}

/// Lay out the metadata for `src` and build the loader that checks it.
fn generate_program(
    src: &ProgramSource<'_>,
    names: &[String],
) -> Result<GeneratedProgram, KfuncLoaderError> {
    let called = kfunc_sites(src.insns, names)?;
    let mut blob: Vec<u8> = src.insns.iter().flat_map(|i| i.to_le_bytes()).collect();
    pad8(&mut blob);
    let license = offset(&blob)?;
    blob.extend_from_slice(src.license);
    pad8(&mut blob);
    let func_info = offset(&blob)?;
    blob.extend_from_slice(src.func_info.0);
    pad8(&mut blob);
    let line_info = offset(&blob)?;
    blob.extend_from_slice(src.line_info.0);
    pad8(&mut blob);
    let mut kfuncs = Vec::with_capacity(called.len());
    let mut mask = 0u64;
    for (j, (name, sites)) in called.iter().enumerate() {
        let name_off = offset(&blob)?;
        blob.extend_from_slice(name.as_bytes());
        blob.push(0);
        let may_go = neutralizable(name);
        if may_go {
            mask |= 1 << j;
        }
        kfuncs.push(KfuncPlan {
            name_off,
            name_len: offset(&blob)? - name_off,
            neutralizable: may_go,
            sites: sites.clone(),
        });
    }
    let lsm_name = match src.lsm_hook {
        Some(hook) => {
            let at = offset(&blob)?;
            blob.extend_from_slice(hook.as_bytes());
            blob.push(0);
            Some((at, offset(&blob)? - at))
        }
        None => None,
    };
    pad8(&mut blob);
    let fd_array = offset(&blob)?;
    let slots = fds_base(src.map_count) + kfuncs.len();
    blob.resize(blob.len() + 4 * slots, 0);
    pad8(&mut blob);
    let count = |bytes: &[u8], rec: u32| {
        if rec == 0 {
            0
        } else {
            i32::try_from(bytes.len() / rec as usize).unwrap_or(0)
        }
    };
    let layout = BlobLayout {
        license,
        func_info,
        func_info_cnt: count(src.func_info.0, src.func_info.1),
        line_info,
        line_info_cnt: count(src.line_info.0, src.line_info.1),
        lsm_name,
        fd_array,
    };
    let digest: [u8; 32] = Sha256::digest(&blob).into();
    let loader = build_loader(src, &layout, &kfuncs, &digest)?;
    Ok(GeneratedProgram {
        name: src.name.to_owned(),
        prog_type: src.prog_type,
        expected_attach_type: src.expected_attach_type,
        kfuncs: called.into_iter().map(|(n, _)| n).collect(),
        neutralizable: mask,
        loader: loader.iter().flat_map(|i| i.to_le_bytes()).collect(),
        blob,
    })
}

/// Field offsets of the inner attribute, relative to [`ATTR`].
fn attr_at(field: usize) -> i16 {
    ATTR + i16::try_from(field).expect("bpf_attr field offset fits i16")
}

/// Offset of slot `i` in the context's descriptor table.
fn ctx_fd(i: usize) -> Result<i16, KfuncLoaderError> {
    i16::try_from(ctx::FDS + 4 * i)
        .map_err(|_| KfuncLoaderError::Relocate("context too large".into()))
}

/// Offset of slot `i` in the metadata's `fd_array`.
fn blob_fd(layout: &BlobLayout, i: usize) -> Result<i32, KfuncLoaderError> {
    i32::try_from(i)
        .ok()
        .and_then(|i| i.checked_mul(4))
        .and_then(|o| o.checked_add(layout.fd_array))
        .ok_or_else(|| KfuncLoaderError::Relocate("fd_array too large".into()))
}

/// The loader program.
fn build_loader(
    src: &ProgramSource<'_>,
    layout: &BlobLayout,
    kfuncs: &[KfuncPlan],
    digest: &[u8; 32],
) -> Result<Vec<u64>, KfuncLoaderError> {
    let mut asm = Asm::default();
    let mismatch = asm.label();
    asm.mov_reg(6, 1);
    emit_digest_check(&mut asm, digest, mismatch);
    emit_map_fds(&mut asm, layout, src.map_count)?;
    emit_kfuncs(&mut asm, layout, kfuncs, fds_base(src.map_count))?;
    if let Some((name_off, name_len)) = layout.lsm_name {
        emit_lsm_hook(&mut asm, name_off, name_len);
    }
    emit_attr(&mut asm, src, layout);
    asm.mov_imm(1, CMD_PROG_LOAD);
    asm.mov_reg(2, R10);
    asm.add_imm(2, i32::from(ATTR));
    asm.mov_imm(3, INNER_ATTR_SIZE);
    asm.call(HELPER_SYS_BPF);
    asm.stx_w(6, ctx::OUT_PROG_FD, 0);
    asm.st_w(6, ctx::OUT_RESULT, 0);
    asm.mov_imm(0, 0);
    asm.exit();
    asm.bind(mismatch);
    asm.st_w(6, ctx::OUT_RESULT, NEG_EINVAL);
    asm.mov_imm(0, 0);
    asm.exit();
    asm.finish().map_err(KfuncLoaderError::Relocate)
}

/// Compare the map's digest, which the kernel computed when the agent asked
/// for it after freezing, with the one the metadata had at build.
fn emit_digest_check(asm: &mut Asm, digest: &[u8; 32], mismatch: insn::Label) {
    for (i, bytes) in digest.as_chunks::<8>().0.iter().enumerate() {
        asm.ld_map(1, 0, None);
        asm.ldx_dw(2, 1, i16::try_from(i * 8).expect("four words"));
        asm.ld_imm64(3, u64::from_le_bytes(*bytes));
        asm.jne_reg(2, 3, mismatch);
    }
}

/// Copy the host's map descriptors into the metadata's `fd_array`.
fn emit_map_fds(asm: &mut Asm, layout: &BlobLayout, maps: usize) -> Result<(), KfuncLoaderError> {
    for i in 0..maps {
        asm.ldx_w(1, 6, ctx_fd(i)?);
        asm.ld_map(2, 0, Some(blob_fd(layout, i)?));
        asm.stx_w(2, 0, 1);
    }
    Ok(())
}

/// Resolve every kfunc by name in the kernel's BTF and write the call to each
/// site, or neutralize it where the host asked and the build allows.
fn emit_kfuncs(
    asm: &mut Asm,
    layout: &BlobLayout,
    kfuncs: &[KfuncPlan],
    base: usize,
) -> Result<(), KfuncLoaderError> {
    let neutral = insn::encode(insn::MOV64_IMM, 0, 0, 0, NEG_EOPNOTSUPP);
    asm.ldx_dw(8, 6, ctx::NEUTRAL_MASK);
    for (j, k) in kfuncs.iter().enumerate() {
        let bit = i32::try_from(j).expect("at most 64 kfuncs");
        let next = asm.label();
        let resolve = asm.label();
        if k.neutralizable {
            asm.mov_reg(1, 8);
            asm.rsh_imm(1, bit);
            asm.and_imm(1, 1);
            asm.jeq_imm(1, 0, resolve);
            asm.ld_imm64(3, neutral);
            for &site in &k.sites {
                asm.ld_map(2, 0, Some(site));
                asm.stx_dw(2, 0, 3);
            }
            asm.ja(next);
        }
        asm.bind(resolve);
        asm.ld_map(1, 0, Some(k.name_off));
        asm.mov_imm(2, k.name_len);
        asm.mov_imm(3, BTF_KIND_FUNC);
        asm.mov_imm(4, 0);
        asm.call(HELPER_BTF_FIND_BY_NAME_KIND);
        let found = asm.label();
        asm.jsgt_imm(0, 0, found);
        asm.st_w(6, ctx::OUT_FAILED_KFUNC, bit);
        asm.st_w(6, ctx::OUT_RESULT, NEG_ENOENT);
        asm.mov_imm(0, 0);
        asm.exit();
        asm.bind(found);
        let slot = base + j;
        let vmlinux = asm.label();
        asm.mov_reg(1, 0);
        asm.rsh_imm(1, 32);
        asm.mov_reg(3, 0);
        asm.lsh_imm(3, 32);
        asm.or_imm(
            3,
            i32::from(insn::CALL) | (i32::from(BPF_PSEUDO_KFUNC_CALL) << 12),
        );
        asm.jeq_imm(1, 0, vmlinux);
        asm.stx_w(6, ctx_fd(slot)?, 1);
        asm.ld_map(2, 0, Some(blob_fd(layout, slot)?));
        asm.stx_w(2, 0, 1);
        let slot_bits = i32::try_from(slot)
            .ok()
            .filter(|s| *s <= i32::from(i16::MAX))
            .ok_or_else(|| KfuncLoaderError::Relocate("fd_array slot out of range".into()))?;
        asm.or_imm(3, slot_bits << 16);
        asm.bind(vmlinux);
        for &site in &k.sites {
            asm.ld_map(2, 0, Some(site));
            asm.stx_dw(2, 0, 3);
        }
        asm.bind(next);
    }
    Ok(())
}

/// Resolve the LSM hook's vmlinux function into `r7`; a hook found in a
/// module is a name collision, refused like the unsigned path refuses it.
fn emit_lsm_hook(asm: &mut Asm, name_off: i32, name_len: i32) {
    let positive = asm.label();
    let fail = asm.label();
    let done = asm.label();
    asm.ld_map(1, 0, Some(name_off));
    asm.mov_imm(2, name_len);
    asm.mov_imm(3, BTF_KIND_FUNC);
    asm.mov_imm(4, 0);
    asm.call(HELPER_BTF_FIND_BY_NAME_KIND);
    asm.jsgt_imm(0, 0, positive);
    asm.ja(fail);
    asm.bind(positive);
    asm.mov_reg(1, 0);
    asm.rsh_imm(1, 32);
    asm.jne_imm(1, 0, fail);
    asm.mov_reg(7, 0);
    asm.ja(done);
    asm.bind(fail);
    asm.st_w(6, ctx::OUT_FAILED_KFUNC, FAILED_LSM_HOOK);
    asm.st_w(6, ctx::OUT_RESULT, NEG_ENOENT);
    asm.mov_imm(0, 0);
    asm.exit();
    asm.bind(done);
}

/// The inner `BPF_PROG_LOAD` attribute, on the stack: everything static from
/// the build, the host's choices from the context, masked.
fn emit_attr(asm: &mut Asm, src: &ProgramSource<'_>, layout: &BlobLayout) {
    use std::mem::offset_of;
    for k in 0..19 {
        asm.st_dw(R10, ATTR + 8 * k, 0);
    }
    asm.st_w(
        R10,
        attr_at(offset_of!(ProgLoadAttr, prog_type)),
        src.prog_type.cast_signed(),
    );
    let insn_cnt = i32::try_from(src.insns.len()).unwrap_or(i32::MAX);
    asm.st_w(R10, attr_at(offset_of!(ProgLoadAttr, insn_cnt)), insn_cnt);
    store_blob_ptr(asm, 0, offset_of!(ProgLoadAttr, insns));
    store_blob_ptr(asm, layout.license, offset_of!(ProgLoadAttr, license));
    asm.ldx_w(1, 6, ctx::LOG_LEVEL);
    asm.stx_w(R10, attr_at(offset_of!(ProgLoadAttr, log_level)), 1);
    asm.ldx_w(1, 6, ctx::LOG_SIZE);
    asm.stx_w(R10, attr_at(offset_of!(ProgLoadAttr, log_size)), 1);
    asm.ldx_dw(1, 6, ctx::LOG_BUF);
    asm.stx_dw(R10, attr_at(offset_of!(ProgLoadAttr, log_buf)), 1);
    let xdp = src.prog_type == BPF_PROG_TYPE_XDP;
    let allowed = src.static_flags | if xdp { BPF_F_XDP_DEV_BOUND_ONLY } else { 0 };
    asm.ldx_w(1, 6, ctx::PROG_FLAGS);
    asm.and_imm(1, allowed.cast_signed());
    asm.or_imm(1, crate::ebpf::bpf_token::BPF_F_TOKEN_FD.cast_signed());
    asm.stx_w(R10, attr_at(offset_of!(ProgLoadAttr, prog_flags)), 1);
    let mut name = [0u8; 16];
    let n = src.name.len().min(15);
    name[..n].copy_from_slice(&src.name.as_bytes()[..n]);
    let name_at = offset_of!(ProgLoadAttr, prog_name);
    for (k, word) in name.as_chunks::<4>().0.iter().enumerate() {
        let value = i32::from_le_bytes(*word);
        asm.st_w(R10, attr_at(name_at + 4 * k), value);
    }
    if xdp {
        asm.ldx_w(1, 6, ctx::PROG_IFINDEX);
        asm.stx_w(R10, attr_at(offset_of!(ProgLoadAttr, prog_ifindex)), 1);
    }
    asm.st_w(
        R10,
        attr_at(offset_of!(ProgLoadAttr, expected_attach_type)),
        src.expected_attach_type.cast_signed(),
    );
    asm.ldx_w(1, 6, ctx::PROG_BTF_FD);
    asm.stx_w(R10, attr_at(offset_of!(ProgLoadAttr, prog_btf_fd)), 1);
    emit_info(asm, layout, src);
    if layout.lsm_name.is_some() {
        asm.stx_w(R10, attr_at(offset_of!(ProgLoadAttr, attach_btf_id)), 7);
    }
    store_blob_ptr(asm, layout.fd_array, offset_of!(ProgLoadAttr, fd_array));
    asm.ldx_w(1, 6, ctx::TOKEN_FD);
    asm.stx_w(R10, attr_at(offset_of!(ProgLoadAttr, prog_token_fd)), 1);
}

/// `func_info` and `line_info`, when the program carries them.
fn emit_info(asm: &mut Asm, layout: &BlobLayout, src: &ProgramSource<'_>) {
    use std::mem::offset_of;
    if layout.func_info_cnt > 0 {
        asm.st_w(
            R10,
            attr_at(offset_of!(ProgLoadAttr, func_info_rec_size)),
            src.func_info.1.cast_signed(),
        );
        store_blob_ptr(asm, layout.func_info, offset_of!(ProgLoadAttr, func_info));
        asm.st_w(
            R10,
            attr_at(offset_of!(ProgLoadAttr, func_info_cnt)),
            layout.func_info_cnt,
        );
    }
    if layout.line_info_cnt > 0 {
        asm.st_w(
            R10,
            attr_at(offset_of!(ProgLoadAttr, line_info_rec_size)),
            src.line_info.1.cast_signed(),
        );
        store_blob_ptr(asm, layout.line_info, offset_of!(ProgLoadAttr, line_info));
        asm.st_w(
            R10,
            attr_at(offset_of!(ProgLoadAttr, line_info_cnt)),
            layout.line_info_cnt,
        );
    }
}

/// `attr.field = &blob[blob_off]`.
fn store_blob_ptr(asm: &mut Asm, blob_off: i32, field: usize) {
    asm.ld_map(1, 0, Some(blob_off));
    asm.stx_dw(R10, attr_at(field), 1);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source<'a>(insns: &'a [u64], lsm: Option<&'a str>, maps: usize) -> ProgramSource<'a> {
        ProgramSource {
            name: "xdp_firewall_long_name",
            prog_type: BPF_PROG_TYPE_XDP,
            expected_attach_type: 0,
            static_flags: 0,
            insns,
            license: b"GPL\0",
            func_info: (&[], 0),
            line_info: (&[], 0),
            lsm_hook: lsm,
            map_count: maps,
        }
    }

    /// `r0 = 0; call kfunc#0; call kfunc#1; call kfunc#0; exit`, the kfunc
    /// calls still carrying their prepatched name index.
    fn with_kfuncs() -> Vec<u64> {
        let call = |idx| insn::encode(insn::CALL, 0, BPF_PSEUDO_KFUNC_CALL, 0, idx);
        vec![
            insn::encode(insn::MOV64_IMM, 0, 0, 0, 0),
            call(0),
            call(1),
            call(0),
            insn::encode(insn::EXIT, 0, 0, 0, 0),
        ]
    }

    fn names() -> Vec<String> {
        vec![
            "bpf_xdp_metadata_rx_hash".to_owned(),
            "bpf_ct_insert_entry".to_owned(),
        ]
    }

    #[test]
    fn the_metadata_starts_with_the_instructions_and_is_whole_words() {
        let insns = with_kfuncs();
        let got = generate_program(&source(&insns, None, 2), &names()).expect("generated");
        assert_eq!(&got.blob[..8], &insns[0].to_le_bytes());
        assert_eq!(
            got.blob.len() % 8,
            0,
            "the map's digest covers whole elements"
        );
        assert_eq!(got.loader.len() % 8, 0);
    }

    #[test]
    fn kfuncs_are_listed_once_in_first_call_order() {
        let insns = with_kfuncs();
        let got = generate_program(&source(&insns, None, 0), &names()).expect("generated");
        assert_eq!(got.kfuncs, names());
        let sites = kfunc_sites(&insns, &names()).expect("sites");
        assert_eq!(sites[0].1, vec![8, 24]);
        assert_eq!(sites[1].1, vec![16]);
    }

    #[test]
    fn only_the_kfuncs_the_unsigned_path_may_drop_can_be_neutralized() {
        let insns = with_kfuncs();
        let got = generate_program(&source(&insns, None, 0), &names()).expect("generated");
        assert_eq!(got.neutralizable, 0b01, "metadata kfunc yes, conntrack no");
    }

    #[test]
    fn the_loader_checks_the_digest_of_its_metadata_first() {
        let insns = with_kfuncs();
        let got = generate_program(&source(&insns, None, 1), &names()).expect("generated");
        let loader: Vec<u64> = got
            .loader
            .as_chunks::<8>()
            .0
            .iter()
            .map(|c| u64::from_le_bytes(*c))
            .collect();
        let digest: [u8; 32] = Sha256::digest(&got.blob).into();
        // r6 = r1, then per word: map, load, constant (two halves), compare.
        assert_eq!(insn::code(loader[1]), insn::LD_IMM64);
        assert_eq!(insn::src(loader[1]), insn::PSEUDO_MAP_IDX);
        let low = insn::imm(loader[4]).cast_unsigned();
        let high = insn::imm(loader[5]).cast_unsigned();
        let word = u64::from(low) | (u64::from(high) << 32);
        assert_eq!(word.to_le_bytes(), digest[..8]);
    }

    #[test]
    fn the_loader_only_reaches_its_one_map_by_slot() {
        let insns = with_kfuncs();
        let got = generate_program(&source(&insns, Some("bpf_lsm_file_open"), 3), &names())
            .expect("generated");
        let loader: Vec<u64> = got
            .loader
            .as_chunks::<8>()
            .0
            .iter()
            .map(|c| u64::from_le_bytes(*c))
            .collect();
        let mut i = 0;
        while i < loader.len() {
            if insn::code(loader[i]) == insn::LD_IMM64 {
                let kind = insn::src(loader[i]);
                if kind != 0 {
                    assert!(kind == insn::PSEUDO_MAP_IDX || kind == insn::PSEUDO_MAP_IDX_VALUE);
                    assert_eq!(insn::imm(loader[i]), 0, "slot 0, the metadata map");
                    if kind == insn::PSEUDO_MAP_IDX_VALUE {
                        let off = usize::try_from(insn::imm(loader[i + 1])).expect("positive");
                        assert!(off < got.blob.len(), "every pointer lands in the metadata");
                    }
                }
                i += 2;
            } else {
                i += 1;
            }
        }
        assert_eq!(insn::code(*loader.last().expect("not empty")), insn::EXIT);
    }

    #[test]
    fn a_map_load_is_rewritten_to_its_slot() {
        let mut insns = vec![
            insn::encode(insn::LD_IMM64, 1, PSEUDO_MAP_FD, 0, FAKE_FD_BASE + 1),
            insn::encode(0, 0, 0, 0, 0),
            insn::encode(insn::LD_IMM64, 2, PSEUDO_MAP_VALUE, 0, FAKE_FD_BASE),
            insn::encode(0, 0, 0, 0, 16),
        ];
        map_slots(&mut insns, 2).expect("both maps exist");
        assert_eq!(insn::src(insns[0]), insn::PSEUDO_MAP_IDX);
        assert_eq!(insn::imm(insns[0]), 1);
        assert_eq!((insns[0] >> 8) & 0x0f, 1, "destination register kept");
        assert_eq!(insn::src(insns[2]), insn::PSEUDO_MAP_IDX_VALUE);
        assert_eq!(insn::imm(insns[2]), 0);
        assert_eq!(insn::imm(insns[3]), 16, "value offset kept");
    }

    #[test]
    fn a_map_load_naming_no_map_is_refused() {
        let mut insns = vec![
            insn::encode(insn::LD_IMM64, 1, PSEUDO_MAP_FD, 0, FAKE_FD_BASE + 5),
            insn::encode(0, 0, 0, 0, 0),
        ];
        assert!(map_slots(&mut insns, 2).is_err());
    }

    #[test]
    fn the_fd_array_holds_every_map_then_every_kfunc_module() {
        let insns = with_kfuncs();
        let got = generate_program(&source(&insns, None, 3), &names()).expect("generated");
        // Three maps, two kfuncs: five four-byte slots, zero at build.
        let tail = &got.blob[got.blob.len() - 24..];
        assert!(tail.iter().all(|b| *b == 0));
    }

    #[test]
    fn the_inner_attribute_offsets_are_the_kernel_ones() {
        use std::mem::offset_of;
        assert_eq!(offset_of!(ProgLoadAttr, insns), 8);
        assert_eq!(offset_of!(ProgLoadAttr, prog_flags), 44);
        assert_eq!(offset_of!(ProgLoadAttr, prog_name), 48);
        assert_eq!(offset_of!(ProgLoadAttr, attach_btf_id), 108);
        assert_eq!(offset_of!(ProgLoadAttr, fd_array), 120);
        assert_eq!(offset_of!(ProgLoadAttr, prog_token_fd), 144);
        assert_eq!(INNER_ATTR_SIZE, 148);
        assert!(
            i32::from(ATTR) + INNER_ATTR_SIZE <= 0,
            "the attribute fits below the frame"
        );
    }
}
