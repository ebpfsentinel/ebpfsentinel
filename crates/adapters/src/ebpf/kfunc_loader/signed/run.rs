//! The host half: load one program through its signed loader.
//!
//! Each attempt is fresh: a new metadata map, made exclusive to the loader
//! by its digest, filled, frozen and hashed; the loader loaded with its
//! signature against the warden's keyring; run once on a context carrying
//! what the host chooses; the context read back for the program's
//! descriptor.

use std::io;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};

use sha2::{Digest as _, Sha256};

use super::super::{
    BPF_F_SLEEPABLE, BPF_MAP_CREATE, BPF_MAP_UPDATE_ELEM, BPF_PROG_LOAD, KfuncLoaderError,
    MapCreateAttr, MapUpdateAttr, PROBE_PROG_TYPE_SYSCALL, ProgLoadAttr, SignedProgLoadAttr,
    apply_bpf_token, bpf, global_token_fd,
};
use super::generate::{FAILED_LSM_HOOK, GeneratedProgram};
use super::{ctx, ctx_size, fds_base};

/// `BPF_MAP_TYPE_ARRAY`.
const BPF_MAP_TYPE_ARRAY: u32 = 2;
/// `BPF_OBJ_GET_INFO_BY_FD`.
const BPF_OBJ_GET_INFO_BY_FD: u32 = 15;
/// Verifier log asked for on the second attempt, after a refusal.
const REFUSAL_LOG_BYTES: usize = 16 << 20;

/// `map_create` with the two fields that make a map exclusive to the one
/// program whose instructions hash to `excl_prog_hash`.
#[repr(C)]
#[derive(Default)]
struct ExclMapCreateAttr {
    base: MapCreateAttr,
    excl_prog_hash: u64,
    excl_prog_hash_size: u32,
    pad: u32,
}

const _: () = {
    assert!(std::mem::size_of::<MapCreateAttr>() == 80);
    assert!(std::mem::offset_of!(ExclMapCreateAttr, excl_prog_hash) == 80);
    assert!(std::mem::offset_of!(ExclMapCreateAttr, excl_prog_hash_size) == 88);
    assert!(std::mem::size_of::<ExclMapCreateAttr>() == 96);
};

/// `BPF_OBJ_GET_INFO_BY_FD`'s member of `union bpf_attr`.
#[repr(C)]
#[derive(Default)]
struct InfoAttr {
    bpf_fd: u32,
    info_len: u32,
    info: u64,
}

/// `struct bpf_map_info` up to `hash_size`, as 8-byte words: `hash` at
/// byte 88 (word 11), `hash_size` at byte 96 (low half of word 12).
const MAP_INFO_WORDS: usize = 13;
const MAP_INFO_HASH_WORD: usize = 11;
const MAP_INFO_HASH_SIZE_WORD: usize = 12;

/// What the host chooses for one load.
pub(super) struct Inputs<'a> {
    pub program: &'a GeneratedProgram,
    pub signature: &'a [u8],
    pub keyring: i32,
    /// The object's maps, in the bundle's slot order.
    pub map_fds: &'a [RawFd],
    pub prog_btf_fd: Option<RawFd>,
    pub prog_ifindex: Option<u32>,
    pub prog_flags: u32,
    pub neutral_mask: u64,
}

/// Why a signed load gave no program.
#[derive(Debug)]
pub(super) enum Failure {
    /// The loader was refused or did not reach its end: the kernel checked
    /// the signature and said no, the keyring is gone, a name did not
    /// resolve. The program is offered unsigned instead.
    Loader(String),
    /// The loader ran and the kernel refused the program it loaded.
    Program(KfuncLoaderError),
}

/// What the loader wrote back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Outcome {
    pub prog_fd: i32,
    pub result: i32,
    pub failed_kfunc: i32,
    pub module_fds: Vec<i32>,
}

/// Load `inputs.program` through its loader.
pub(super) fn load(inputs: &Inputs<'_>) -> Result<OwnedFd, Failure> {
    let first = attempt(inputs, None)?;
    if first.prog_fd >= 0 {
        // SAFETY: the loader's `bpf_sys_bpf` installed this descriptor in
        // this process during the run, and nothing else holds it.
        return Ok(unsafe { OwnedFd::from_raw_fd(first.prog_fd) });
    }
    let mut log = vec![0u8; REFUSAL_LOG_BYTES];
    let second = attempt(inputs, Some(&mut log))?;
    if second.prog_fd >= 0 {
        // SAFETY: as above, installed in this process by the loader's run.
        return Ok(unsafe { OwnedFd::from_raw_fd(second.prog_fd) });
    }
    let raw = String::from_utf8_lossy(&log);
    let cleaned: String = raw.chars().filter(|&c| c != '\0').collect();
    Err(Failure::Program(KfuncLoaderError::ProgLoad {
        name: inputs.program.name.clone(),
        prog_type: inputs.program.prog_type,
        expected_attach_type: inputs.program.expected_attach_type,
        errno: second.prog_fd.saturating_neg(),
        log: cleaned.trim().to_owned(),
    }))
}

/// One run of the loader, from a fresh map.
fn attempt(inputs: &Inputs<'_>, log: Option<&mut [u8]>) -> Result<Outcome, Failure> {
    let program = inputs.program;
    let loader_hash: [u8; 32] = Sha256::digest(&program.loader).into();
    let map = metadata_map(&program.blob, &loader_hash).map_err(Failure::Loader)?;
    let loader = load_loader(program, inputs.signature, inputs.keyring, &map)
        .map_err(|errno| Failure::Loader(refusal(errno)))?;
    let mut context = context(inputs, log);
    let run = crate::ebpf::prog_test_run::run_syscall_in_place(loader.as_fd(), &mut context);
    let outcome = read_context(&context, inputs.map_fds.len(), program.kfuncs.len());
    for &fd in &outcome.module_fds {
        if fd > 0 {
            // SAFETY: the loader wrote into this slot only a descriptor
            // `bpf_btf_find_by_name_kind` installed in this process during
            // the run; nothing else owns it, and it is closed once here.
            drop(unsafe { OwnedFd::from_raw_fd(fd) });
        }
    }
    run.map_err(|e| Failure::Loader(format!("running the loader: {e}")))?;
    match (outcome.result, outcome.failed_kfunc) {
        (0, _) => Ok(outcome),
        (_, FAILED_LSM_HOOK) => Err(Failure::Loader(
            "the LSM hook did not resolve into vmlinux".to_owned(),
        )),
        (_, j) if j >= 0 => Err(Failure::Loader(format!(
            "kfunc `{}` did not resolve",
            usize::try_from(j)
                .ok()
                .and_then(|j| program.kfuncs.get(j))
                .map_or("?", String::as_str)
        ))),
        (result, _) => Err(Failure::Loader(format!(
            "the loader stopped with {result}: its metadata is not the one it was signed with"
        ))),
    }
}

/// The sentence for a loader the kernel refused.
fn refusal(errno: i32) -> String {
    let why = match errno {
        libc::EKEYREJECTED => "the signature does not verify",
        libc::ENOKEY => "the signing certificate is not in the keyring",
        libc::EBADMSG => "the signature is not a CMS message",
        _ => "the kernel refused the loader",
    };
    format!("{why} ({})", io::Error::from_raw_os_error(errno))
}

/// The metadata map: an array of one element holding `blob`, usable only by
/// the program whose instructions hash to `loader_hash`, frozen, its digest
/// computed by the kernel for the loader to compare.
fn metadata_map(blob: &[u8], loader_hash: &[u8; 32]) -> Result<OwnedFd, String> {
    let value_size = u32::try_from(blob.len()).map_err(|e| e.to_string())?;
    let mut attr = ExclMapCreateAttr {
        base: MapCreateAttr {
            map_type: BPF_MAP_TYPE_ARRAY,
            key_size: 4,
            value_size,
            max_entries: 1,
            ..Default::default()
        },
        excl_prog_hash: loader_hash.as_ptr() as u64,
        excl_prog_hash_size: 32,
        pad: 0,
    };
    let name = b"ebpfs_meta";
    attr.base.map_name[..name.len()].copy_from_slice(name);
    apply_bpf_token(&mut attr.base, global_token_fd());
    // SAFETY: `attr` is a live `#[repr(C)]` local of exactly the size passed,
    // laid out as the kernel's `map_create` member up to
    // `excl_prog_hash_size` (held by the assertions above); the hash it
    // points at outlives the call.
    let rc = unsafe {
        bpf(
            BPF_MAP_CREATE,
            (&raw mut attr).cast(),
            std::mem::size_of::<ExclMapCreateAttr>(),
        )
    };
    if rc < 0 {
        return Err(format!(
            "creating the metadata map: {}",
            io::Error::last_os_error()
        ));
    }
    #[allow(clippy::cast_possible_truncation)]
    // SAFETY: rc >= 0 is a descriptor the kernel just installed for us.
    let map = unsafe { OwnedFd::from_raw_fd(rc as RawFd) };
    let key = 0u32;
    let mut update = MapUpdateAttr {
        map_fd: map.as_raw_fd().cast_unsigned(),
        key: (&raw const key) as u64,
        value: blob.as_ptr() as u64,
        ..Default::default()
    };
    // SAFETY: `update` is a live `#[repr(C)]` local of the size passed; the
    // key and the value it points at outlive the call, the value holding
    // exactly `value_size` bytes.
    let rc = unsafe {
        bpf(
            BPF_MAP_UPDATE_ELEM,
            (&raw mut update).cast(),
            std::mem::size_of::<MapUpdateAttr>(),
        )
    };
    if rc < 0 {
        return Err(format!(
            "filling the metadata map: {}",
            io::Error::last_os_error()
        ));
    }
    crate::ebpf::map_freeze::freeze_fd("loader metadata", map.as_fd())
        .map_err(|e| e.to_string())?;
    hash_map(&map)?;
    Ok(map)
}

/// Ask the kernel for the frozen map's digest, which it computes and keeps
/// in the map for the loader to read.
fn hash_map(map: &OwnedFd) -> Result<(), String> {
    let mut hash = [0u8; 32];
    let mut info = [0u64; MAP_INFO_WORDS];
    info[MAP_INFO_HASH_WORD] = hash.as_mut_ptr() as u64;
    info[MAP_INFO_HASH_SIZE_WORD] = 32;
    let mut attr = InfoAttr {
        bpf_fd: map.as_raw_fd().cast_unsigned(),
        info_len: u32::try_from(std::mem::size_of_val(&info)).unwrap_or(0),
        info: info.as_mut_ptr() as u64,
    };
    // SAFETY: `attr` is a live `#[repr(C)]` local of the size passed; `info`
    // and the `hash` buffer it names are live locals of the sizes given.
    let rc = unsafe {
        bpf(
            BPF_OBJ_GET_INFO_BY_FD,
            (&raw mut attr).cast(),
            std::mem::size_of::<InfoAttr>(),
        )
    };
    if rc < 0 {
        return Err(format!(
            "hashing the metadata map: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Load the loader with its signature, the keyring named, the metadata map
/// in its `fd_array`. Returns the errno on refusal.
fn load_loader(
    program: &GeneratedProgram,
    signature: &[u8],
    keyring: i32,
    map: &OwnedFd,
) -> Result<OwnedFd, i32> {
    let license = b"GPL\0";
    let fds = [map.as_raw_fd()];
    let mut attr = SignedProgLoadAttr {
        load: ProgLoadAttr {
            prog_type: PROBE_PROG_TYPE_SYSCALL,
            insn_cnt: u32::try_from(program.loader.len() / 8).unwrap_or(u32::MAX),
            insns: program.loader.as_ptr() as u64,
            license: license.as_ptr() as u64,
            prog_flags: BPF_F_SLEEPABLE,
            fd_array: fds.as_ptr() as u64,
            ..Default::default()
        },
        signature: signature.as_ptr() as u64,
        signature_size: u32::try_from(signature.len()).unwrap_or(u32::MAX),
        keyring_id: keyring,
    };
    let name = b"ebpfs_loader";
    attr.load.prog_name[..name.len()].copy_from_slice(name);
    if let Some(token) = global_token_fd() {
        attr.load.prog_flags |= crate::ebpf::bpf_token::BPF_F_TOKEN_FD;
        attr.load.prog_token_fd = token;
    }
    // SAFETY: `attr` is a live `#[repr(C)]` local of exactly the size passed,
    // laid out as the kernel's `BPF_PROG_LOAD` member up to `keyring_id`; the
    // instructions, licence, signature and `fd_array` it points at outlive
    // the call.
    let rc = unsafe {
        bpf(
            BPF_PROG_LOAD,
            (&raw mut attr).cast(),
            std::mem::size_of::<SignedProgLoadAttr>(),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error().raw_os_error().unwrap_or(0));
    }
    #[allow(clippy::cast_possible_truncation)]
    // SAFETY: rc >= 0 is a descriptor the kernel just installed for us.
    Ok(unsafe { OwnedFd::from_raw_fd(rc as RawFd) })
}

fn put_i32(buf: &mut [u8], at: usize, v: i32) {
    buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

fn put_u32(buf: &mut [u8], at: usize, v: u32) {
    buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

fn put_u64(buf: &mut [u8], at: usize, v: u64) {
    buf[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

fn get_i32(buf: &[u8], at: usize) -> i32 {
    let mut b = [0u8; 4];
    b.copy_from_slice(&buf[at..at + 4]);
    i32::from_le_bytes(b)
}

fn at(field: i16) -> usize {
    usize::from(field.cast_unsigned())
}

/// The loader's context: the host's choices in, the outputs primed so a
/// loader that stops early is never read as a success.
fn context(inputs: &Inputs<'_>, log: Option<&mut [u8]>) -> Vec<u8> {
    let maps = inputs.map_fds.len();
    let kfuncs = inputs.program.kfuncs.len();
    let mut buf = vec![0u8; ctx_size(maps, kfuncs)];
    put_i32(&mut buf, at(ctx::TOKEN_FD), global_token_fd().unwrap_or(0));
    put_i32(
        &mut buf,
        at(ctx::PROG_BTF_FD),
        inputs.prog_btf_fd.unwrap_or(0),
    );
    put_u32(
        &mut buf,
        at(ctx::PROG_IFINDEX),
        inputs.prog_ifindex.unwrap_or(0),
    );
    put_u32(&mut buf, at(ctx::PROG_FLAGS), inputs.prog_flags);
    put_u64(&mut buf, at(ctx::NEUTRAL_MASK), inputs.neutral_mask);
    if let Some(log) = log {
        put_u64(&mut buf, at(ctx::LOG_BUF), log.as_mut_ptr() as u64);
        put_u32(
            &mut buf,
            at(ctx::LOG_SIZE),
            u32::try_from(log.len()).unwrap_or(u32::MAX),
        );
        put_u32(&mut buf, at(ctx::LOG_LEVEL), 1);
    }
    put_i32(&mut buf, at(ctx::OUT_PROG_FD), -1);
    put_i32(&mut buf, at(ctx::OUT_RESULT), 1);
    put_i32(&mut buf, at(ctx::OUT_FAILED_KFUNC), -1);
    for (i, fd) in inputs.map_fds.iter().enumerate() {
        put_i32(&mut buf, ctx::FDS + 4 * i, *fd);
    }
    buf
}

/// What the loader left in `buf`.
fn read_context(buf: &[u8], maps: usize, kfuncs: usize) -> Outcome {
    let base = fds_base(maps);
    Outcome {
        prog_fd: get_i32(buf, at(ctx::OUT_PROG_FD)),
        result: get_i32(buf, at(ctx::OUT_RESULT)),
        failed_kfunc: get_i32(buf, at(ctx::OUT_FAILED_KFUNC)),
        module_fds: (base..base + kfuncs)
            .map(|slot| get_i32(buf, ctx::FDS + 4 * slot))
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn program(kfuncs: usize) -> GeneratedProgram {
        GeneratedProgram {
            name: "xdp_firewall".to_owned(),
            prog_type: 6,
            expected_attach_type: 0,
            kfuncs: (0..kfuncs).map(|k| format!("k{k}")).collect(),
            neutralizable: 0,
            loader: Vec::new(),
            blob: Vec::new(),
        }
    }

    #[test]
    fn the_context_carries_the_host_choices_and_primed_outputs() {
        let program = program(2);
        let inputs = Inputs {
            program: &program,
            signature: &[],
            keyring: 7,
            map_fds: &[11, 12, 13],
            prog_btf_fd: Some(9),
            prog_ifindex: Some(4),
            prog_flags: 0x40,
            neutral_mask: 0b10,
        };
        let buf = context(&inputs, None);
        assert_eq!(buf.len(), ctx_size(3, 2));
        assert_eq!(buf.len() % 8, 0);
        assert_eq!(get_i32(&buf, at(ctx::PROG_BTF_FD)), 9);
        assert_eq!(get_i32(&buf, at(ctx::PROG_IFINDEX)), 4);
        assert_eq!(get_i32(&buf, at(ctx::PROG_FLAGS)), 0x40);
        assert_eq!(buf[at(ctx::NEUTRAL_MASK)], 0b10);
        assert_eq!(get_i32(&buf, at(ctx::OUT_PROG_FD)), -1);
        assert_ne!(
            get_i32(&buf, at(ctx::OUT_RESULT)),
            0,
            "never primed as success"
        );
        assert_eq!(get_i32(&buf, ctx::FDS + 8), 13);
        let out = read_context(&buf, 3, 2);
        assert_eq!(out.module_fds, vec![0, 0], "module slots start empty");
    }

    #[test]
    fn the_module_slots_follow_the_map_slots() {
        let mut buf = vec![0u8; ctx_size(0, 1)];
        // No map: slot 0 stays reserved for vmlinux, the module goes in 1.
        put_i32(&mut buf, ctx::FDS + 4, 21);
        put_i32(&mut buf, at(ctx::OUT_RESULT), 0);
        let out = read_context(&buf, 0, 1);
        assert_eq!(out.module_fds, vec![21]);
        assert_eq!(out.result, 0);
    }

    #[test]
    fn the_signature_refusals_are_named() {
        assert!(refusal(libc::ENOKEY).contains("not in the keyring"));
        assert!(refusal(libc::EKEYREJECTED).contains("does not verify"));
    }

    #[test]
    fn the_map_info_hash_fields_sit_where_the_kernel_reads_them() {
        assert_eq!(MAP_INFO_HASH_WORD * 8, 88);
        assert_eq!(MAP_INFO_HASH_SIZE_WORD * 8, 96);
        assert_eq!(MAP_INFO_WORDS * 8, 104);
        assert_eq!(std::mem::size_of::<InfoAttr>(), 16);
    }
}
