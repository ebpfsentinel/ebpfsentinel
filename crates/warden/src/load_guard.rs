//! The guard on program loads: the warden's own BPF LSM program, which
//! refuses every load made through a BPF token that is not signed against the
//! keyring the warden made.
//!
//! The kernel checks a signature when a load names one and refuses one that
//! does not verify, but nothing in it refuses a load that names none. Without
//! the guard, an agent (or anything holding the token) could load a program
//! unsigned and the kernel would take it. With it, the token is only good for
//! programs the build signed.
//!
//! The warden loads the guard itself, as root in the initial namespaces and
//! without a token, so the guard never judges its own load, and only where
//! three things hold: the kernel verifies program signatures, the BPF LSM is
//! active (`bpf` in `lsm=` at boot), and a keyring exists to hold loads to. It
//! reads and prepares the object after the keyring is made and before it
//! confines itself, and attaches it when the agent asks
//! ([`ebpfsentinel_warden_proto::Command::ArmLoadGuard`]): the agent's start-up
//! probes are programs it assembles at run time against the running kernel,
//! never signed, so they run first, before the agent reads any input. The
//! keyring serial is written into the object's read-only global before the
//! load and the map holding it is frozen, so the program decides against a
//! value nothing can change.
//!
//! The link is held for as long as the agent it was armed for lives. A crash
//! of the agent does not cost the warden, so a new agent asking for its bpffs
//! once that process has exited finds the guard lifted, runs its own probes
//! and arms it again; a delegation asked for while that process lives finds it
//! attached. Every process the agent started dies with it, in its unit's
//! control group or its container.
//!
//! The guard is host-wide: every load through a token on this host is held to
//! the warden's keyring, not only the agent's.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use ebpf_common::load_guard::{LOAD_GUARD_KEYRING_SYMBOL, LOAD_GUARD_PROGRAM};
use ebpfsentinel_warden_proto::LoadGuard;

/// Where the images and `install.sh` put the guard's object.
pub const DEFAULT_OBJECT_PATH: &str = "/usr/local/lib/ebpfsentinel/lsm-bpf-load-guard";

/// Where the distribution packages put it.
pub const PACKAGE_OBJECT_PATH: &str = "/usr/lib/ebpfsentinel/lsm-bpf-load-guard";

/// Override of [`DEFAULT_OBJECT_PATH`].
pub const OBJECT_PATH_ENV: &str = "EBPFSENTINEL_LOAD_GUARD_OBJECT";

/// The variable the agent's bootstrap trampoline passes the guard's state in
/// across its re-exec: `attached`, or `absent: ` and the reason.
pub const LOAD_GUARD_ENV: &str = "EBPFSENTINEL_LOAD_GUARD";

/// The active security modules, as the kernel lists them.
pub const LSM_LIST_PATH: &str = "/sys/kernel/security/lsm";

/// The kernel's own BTF, where the hook's id is read.
const VMLINUX_BTF_PATH: &str = "/sys/kernel/btf/vmlinux";

/// The BTF function the BPF LSM attaches `bpf_prog_load` programs to.
const HOOK_FUNCTION: &str = "bpf_lsm_bpf_prog_load";

/// The section the object carries the program in.
const PROGRAM_SECTION: &str = "lsm/bpf_prog_load";

const ATTACHED_WORD: &str = "attached";
const ABSENT_PREFIX: &str = "absent: ";

const BPF_MAP_CREATE: libc::c_int = 0;
const BPF_MAP_UPDATE_ELEM: libc::c_int = 2;
const BPF_PROG_LOAD: libc::c_int = 5;
const BPF_MAP_FREEZE: libc::c_int = 22;
const BPF_LINK_CREATE: libc::c_int = 28;
const BPF_MAP_TYPE_ARRAY: u32 = 2;
const BPF_F_RDONLY_PROG: u32 = 1 << 7;
const BPF_PROG_TYPE_SCHED_CLS: u32 = 3;
const BPF_PROG_TYPE_LSM: u32 = 29;
const BPF_LSM_MAC: u32 = 27;
/// `BPF_PSEUDO_MAP_VALUE`: an `ld_imm64` that loads the address of a map
/// value, the map in the first immediate and the offset in the second.
const BPF_PSEUDO_MAP_VALUE: u8 = 2;
/// The opcode of `ld_imm64`.
const LD_IMM64: u8 = 0x18;
/// The size of `union bpf_attr` up to and including `keyring_id`.
const PROG_LOAD_ATTR_SIZE: usize = 168;
const INSN_SIZE: usize = 8;

/// The guard as this warden left it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    /// Read, prepared and attached at the agent's [`arm`].
    Ready,
    /// Attached and held.
    Attached,
    /// Not attached, and why.
    Absent(String),
}

impl Status {
    /// The value handed to the agent in `Delegated` and after [`arm`]: a
    /// guard that is ready is reported attached, since the agent arms it
    /// before it reads input.
    #[must_use]
    pub fn into_proto(self) -> LoadGuard {
        match self {
            Self::Ready | Self::Attached => LoadGuard::Attached,
            Self::Absent(reason) => LoadGuard::Absent { reason },
        }
    }
}

/// The descriptors that keep the guard alive: the program, its link and the
/// frozen map holding the serial. Dropped only to lift the guard for a new
/// agent's start-up once the one it was armed for has exited.
struct Held {
    _map: OwnedFd,
    _program: OwnedFd,
    _link: OwnedFd,
}

/// The program as read before the warden confined itself: the instructions
/// with the serial written in, and the hook's BTF id.
struct Ready {
    prepared: Prepared,
    hook: u32,
    object: PathBuf,
    serial: i32,
}

struct State {
    /// The tag the warden's lines carry.
    tag: &'static str,
    status: Status,
    ready: Option<Ready>,
    held: Option<Held>,
    /// The process the guard was armed for.
    armed_for: Option<crate::handed::Peer>,
}

static STATE: Mutex<State> = Mutex::new(State {
    tag: "[warden]",
    status: Status::Absent(String::new()),
    ready: None,
    held: None,
    armed_for: None,
});
static INSTALLED: AtomicBool = AtomicBool::new(false);

fn state() -> MutexGuard<'static, State> {
    // Every field is replaced whole under the lock, so a panic while it was
    // held leaves a state that still agrees with itself.
    STATE.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The guard's state for every `Delegated`.
#[must_use]
pub fn installed() -> Status {
    if !INSTALLED.load(Ordering::SeqCst) {
        return Status::Absent("the warden did not set up its guard".to_owned());
    }
    state().status.clone()
}

/// What the warden knows before it decides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facts {
    /// The kernel verifies program signatures: `None` when the question
    /// could not be asked.
    pub kernel_verifies: Option<bool>,
    /// The BPF LSM is active, or why that could not be read.
    pub bpf_lsm: Result<bool, String>,
    /// The keyring this warden made.
    pub keyring: Option<i32>,
    /// The guard's object, when it exists.
    pub object: Result<PathBuf, PathBuf>,
}

/// Whether to load the guard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Load it from `object`, held to `serial`.
    Load { object: PathBuf, serial: i32 },
    /// Leave it out, for this reason.
    Skip(String),
}

/// The decision, conditions in the order the posture names them.
#[must_use]
pub fn decide(facts: Facts) -> Decision {
    match facts.kernel_verifies {
        Some(true) => {}
        Some(false) => {
            return Decision::Skip("the kernel does not verify BPF program signatures".to_owned());
        }
        None => {
            return Decision::Skip(
                "the kernel could not be asked whether it verifies BPF program signatures"
                    .to_owned(),
            );
        }
    }
    match facts.bpf_lsm {
        Ok(true) => {}
        Ok(false) => {
            return Decision::Skip(
                "bpf is not in the lsm= list the kernel booted with, so a BPF LSM program never \
                 runs"
                    .to_owned(),
            );
        }
        Err(why) => {
            return Decision::Skip(format!(
                "the active security modules could not be read from {LSM_LIST_PATH}: {why}"
            ));
        }
    }
    let Some(serial) = facts.keyring else {
        return Decision::Skip(
            "the warden made no loader keyring to hold loads to; the image ships no loader \
             certificate, or the kernel refused it"
                .to_owned(),
        );
    };
    match facts.object {
        Ok(object) => Decision::Load { object, serial },
        Err(path) => Decision::Skip(format!("no guard object at {}", path.display())),
    }
}

/// The object path: [`OBJECT_PATH_ENV`] when set and not empty, else
/// [`PACKAGE_OBJECT_PATH`] when only that one exists, else
/// [`DEFAULT_OBJECT_PATH`]. `Err` carries the path when nothing is there.
pub fn object_path() -> Result<PathBuf, PathBuf> {
    let path = if let Some(path) = std::env::var_os(OBJECT_PATH_ENV).filter(|v| !v.is_empty()) {
        PathBuf::from(path)
    } else if !Path::new(DEFAULT_OBJECT_PATH).exists() && Path::new(PACKAGE_OBJECT_PATH).exists() {
        PathBuf::from(PACKAGE_OBJECT_PATH)
    } else {
        PathBuf::from(DEFAULT_OBJECT_PATH)
    };
    if path.is_file() { Ok(path) } else { Err(path) }
}

/// Whether `bpf` is among the modules a `/sys/kernel/security/lsm` line names.
#[must_use]
pub fn lsm_list_has_bpf(list: &str) -> bool {
    list.trim().split(',').any(|m| m.trim() == "bpf")
}

fn bpf_lsm_active() -> Result<bool, String> {
    std::fs::read_to_string(LSM_LIST_PATH)
        .map(|list| lsm_list_has_bpf(&list))
        .map_err(|e| e.to_string())
}

/// Gather the facts, decide, and read and prepare the guard when the facts
/// allow it, logging the outcome under `tag`. Both wardens call it from their
/// `serve`, after the loader keyring is made and before
/// [`crate::confine::confine`], so every file it needs is read while the
/// warden may still open it. The guard is attached later, by [`arm`], once the
/// agent has run the probes it assembles at run time: those are never signed,
/// and an attached guard refuses them. A failure is logged and reported to
/// the agent; the warden serves either way.
pub fn install(tag: &'static str) {
    let facts = Facts {
        kernel_verifies: kernel_verifies_signatures(),
        bpf_lsm: bpf_lsm_active(),
        keyring: crate::loader_keyring::installed(),
        object: object_path(),
    };
    let (status, ready) = match decide(facts) {
        Decision::Skip(reason) => (Status::Absent(reason), None),
        Decision::Load { object, serial } => match read(&object, serial) {
            Ok(ready) => {
                eprintln!(
                    "{tag} guard on program loads read from {}: attached once the agent has \
                     run its start-up probes, after which a load through a BPF token passes \
                     only signed against loader keyring {serial}",
                    object.display()
                );
                (Status::Ready, Some(ready))
            }
            Err(e) => (
                Status::Absent(format!("the guard could not be read: {e}")),
                None,
            ),
        },
    };
    if let Status::Absent(reason) = &status {
        eprintln!("{tag} no guard on program loads: {reason}");
    }
    let mut st = state();
    st.tag = tag;
    st.status = status;
    st.ready = ready;
    drop(st);
    INSTALLED.store(true, Ordering::SeqCst);
}

/// Attach the guard for the agent process `peer`, which has run its start-up
/// probes and read no input yet. Attached already, it stays so and the answer
/// says so. `peer` is the process the guard is held for: it is lifted again
/// only by [`before_delegation`], once that process has exited.
pub fn arm(peer: Option<&crate::handed::Peer>) -> Status {
    let mut st = state();
    if st.held.is_some() {
        return Status::Attached;
    }
    let Some(ready) = st.ready.as_ref() else {
        return st.status.clone();
    };
    match attach(ready) {
        Ok(held) => {
            eprintln!(
                "{} guard on program loads attached from {}: a load through a BPF token now \
                 passes only signed against loader keyring {}",
                st.tag,
                ready.object.display(),
                ready.serial
            );
            st.held = Some(held);
            st.status = Status::Attached;
            st.armed_for = peer.and_then(|p| p.try_clone().ok());
        }
        Err(e) => {
            st.status = Status::Absent(format!("the guard did not load or attach: {e}"));
            eprintln!(
                "{} no guard on program loads: it did not load or attach: {e}",
                st.tag
            );
        }
    }
    st.status.clone()
}

/// Called before a bpffs delegation: a new agent is starting and will run
/// its probes before it arms the guard. The guard is lifted for it only when
/// the process it was armed for has exited; while that process lives, a
/// delegation it asks for, or one a process it started asks for, finds the
/// guard attached. A guard armed for no known process stays attached.
pub fn before_delegation() {
    let mut st = state();
    if st.held.is_none() {
        return;
    }
    if st
        .armed_for
        .as_ref()
        .is_some_and(crate::handed::Peer::has_exited)
    {
        st.held = None;
        st.armed_for = None;
        st.status = Status::Ready;
        eprintln!(
            "{} guard on program loads lifted for a new agent's start-up probes: the \
             agent it was armed for has exited",
            st.tag
        );
    }
}

/// The value the bootstrap passes across its re-exec. A NUL in the reason is
/// dropped so the variable can always be set.
#[must_use]
pub fn encode_env(guard: &LoadGuard) -> String {
    match guard {
        LoadGuard::Attached => ATTACHED_WORD.to_owned(),
        LoadGuard::Absent { reason } => {
            format!("{ABSENT_PREFIX}{}", reason.replace('\0', ""))
        }
    }
}

/// Read back what [`encode_env`] wrote; `None` (nothing handed over) reads as
/// not reported.
#[must_use]
pub fn decode_env(value: Option<&str>) -> domain::prog_signing::LoadGuardReport {
    use domain::prog_signing::LoadGuardReport;
    match value {
        None => LoadGuardReport::NotReported,
        Some(ATTACHED_WORD) => LoadGuardReport::Attached,
        Some(other) => LoadGuardReport::Absent(
            other
                .strip_prefix(ABSENT_PREFIX)
                .unwrap_or(other)
                .to_owned(),
        ),
    }
}

/// What the warden answered when this process asked it to attach the guard,
/// once it has.
static ARMED: std::sync::OnceLock<LoadGuard> = std::sync::OnceLock::new();

/// Keep the warden's answer to [`ebpfsentinel_warden_proto::Command::ArmLoadGuard`]:
/// from then on it is what this process reports.
pub fn record_armed(guard: LoadGuard) {
    let _ = ARMED.set(guard);
}

/// The guard as the warden reported it to this process: its answer when the
/// agent armed it, else what it said at the delegation.
#[must_use]
pub fn report_from_env() -> domain::prog_signing::LoadGuardReport {
    if let Some(armed) = ARMED.get() {
        return decode_env(Some(&encode_env(armed)));
    }
    decode_env(std::env::var(LOAD_GUARD_ENV).ok().as_deref())
}

/// Whether the warden reported the guard attached to this process.
#[must_use]
pub fn attached_from_env() -> bool {
    report_from_env() == domain::prog_signing::LoadGuardReport::Attached
}

/// Write `value` into a `union bpf_attr` byte image.
fn put(attr: &mut [u8], at: usize, value: &[u8]) {
    attr[at..at + value.len()].copy_from_slice(value);
}

/// One `bpf(2)` call on a byte image of `union bpf_attr`.
fn bpf_bytes(cmd: libc::c_int, attr: &mut [u8]) -> io::Result<libc::c_long> {
    // SAFETY: `attr` is a live, writable buffer of `attr.len()` bytes, the
    // size passed; the kernel reads at most that many and zero-checks nothing
    // beyond it.
    let rc = unsafe { crate::bpf(cmd, attr.as_mut_ptr().cast(), attr.len()) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc)
    }
}

/// A descriptor `bpf(2)` returned, owned.
fn owned(rc: libc::c_long) -> io::Result<OwnedFd> {
    let fd = i32::try_from(rc).map_err(io::Error::other)?;
    // SAFETY: `fd` was just returned by the kernel to this process, and
    // nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Whether the kernel reads a signature in a program load: a two-instruction
/// load naming a signature and the system keyring, answered `E2BIG` only by a
/// kernel whose `union bpf_attr` ends before those fields. Any other answer,
/// a refused signature included, proves the fields exist.
fn kernel_verifies_signatures() -> Option<bool> {
    let insns: [u8; 16] = [
        0xb7, 0, 0, 0, 0, 0, 0, 0, // r0 = 0
        0x95, 0, 0, 0, 0, 0, 0, 0, // exit
    ];
    let license = b"GPL\0";
    let signature = [0x5a_u8; 64];
    let mut attr = [0u8; PROG_LOAD_ATTR_SIZE];
    put(&mut attr, 0, &BPF_PROG_TYPE_SCHED_CLS.to_ne_bytes());
    put(&mut attr, 4, &2u32.to_ne_bytes());
    put(&mut attr, 8, &(insns.as_ptr() as u64).to_ne_bytes());
    put(&mut attr, 16, &(license.as_ptr() as u64).to_ne_bytes());
    put(&mut attr, 152, &(signature.as_ptr() as u64).to_ne_bytes());
    put(&mut attr, 160, &64u32.to_ne_bytes());
    put(&mut attr, 164, &1i32.to_ne_bytes());
    match bpf_bytes(BPF_PROG_LOAD, &mut attr) {
        Ok(rc) => {
            drop(owned(rc));
            Some(true)
        }
        Err(e) => signing_from_errno(e.raw_os_error()),
    }
}

/// The probe's answer from its errno.
#[must_use]
pub fn signing_from_errno(errno: Option<i32>) -> Option<bool> {
    match errno {
        Some(libc::E2BIG) => Some(false),
        Some(libc::ENOSYS) => None,
        _ => Some(true),
    }
}

/// What the object gives the load: the program's instructions with every
/// reference to the global patched to the map, and the global's section with
/// the serial written in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prepared {
    /// The program's instructions, in the kernel's byte layout.
    pub insns: Vec<u8>,
    /// The instruction byte offsets of every `ld_imm64` naming the section,
    /// with the offset into it each loads.
    pub sites: Vec<(usize, u32)>,
    /// The section holding the global, the serial written in.
    pub rodata: Vec<u8>,
}

/// Read the guard's program and its global out of `elf`, and write `serial`
/// into the global.
///
/// # Errors
///
/// The object does not parse, or lacks the program, the section or the
/// global, or a relocation names something other than the global's section.
pub fn prepare(elf: &[u8], serial: i32) -> Result<Prepared, String> {
    use object::{Object as _, ObjectSection as _, ObjectSymbol as _, RelocationTarget};

    let file = object::File::parse(elf).map_err(|e| format!("parse: {e}"))?;
    let section = file
        .section_by_name(PROGRAM_SECTION)
        .ok_or_else(|| format!("no section {PROGRAM_SECTION}"))?;
    let program = file
        .symbols()
        .find(|s| s.name() == Ok(LOAD_GUARD_PROGRAM) && s.section_index() == Some(section.index()))
        .ok_or_else(|| format!("no program {LOAD_GUARD_PROGRAM} in {PROGRAM_SECTION}"))?;
    let global = file
        .symbols()
        .find(|s| s.name() == Ok(LOAD_GUARD_KEYRING_SYMBOL))
        .ok_or_else(|| format!("no global {LOAD_GUARD_KEYRING_SYMBOL}"))?;
    let rodata_index = global
        .section_index()
        .ok_or_else(|| format!("{LOAD_GUARD_KEYRING_SYMBOL} is in no section"))?;
    let rodata_section = file
        .section_by_index(rodata_index)
        .map_err(|e| format!("the global's section: {e}"))?;
    let mut rodata = rodata_section
        .data()
        .map_err(|e| format!("the global's section: {e}"))?
        .to_vec();
    let at = usize::try_from(global.address()).map_err(|e| e.to_string())?;
    if at + 4 > rodata.len() {
        return Err(format!(
            "{LOAD_GUARD_KEYRING_SYMBOL} lies outside its section"
        ));
    }
    put(&mut rodata, at, &serial.to_ne_bytes());

    let data = section
        .data()
        .map_err(|e| format!("{PROGRAM_SECTION}: {e}"))?;
    let start = usize::try_from(program.address()).map_err(|e| e.to_string())?;
    let len = usize::try_from(program.size()).map_err(|e| e.to_string())?;
    let insns = data
        .get(start..start + len)
        .ok_or_else(|| format!("{LOAD_GUARD_PROGRAM} lies outside its section"))?
        .to_vec();

    let mut sites = Vec::new();
    for (offset, reloc) in section.relocations() {
        let offset = usize::try_from(offset).map_err(|e| e.to_string())?;
        if offset < start || offset >= start + len {
            continue;
        }
        let RelocationTarget::Symbol(index) = reloc.target() else {
            return Err(format!("a relocation at {offset} names no symbol"));
        };
        let target = file
            .symbol_by_index(index)
            .map_err(|e| format!("relocation at {offset}: {e}"))?;
        if target.section_index() != Some(rodata_index) {
            return Err(format!(
                "a relocation at {offset} names {}, not the global's section",
                target.name().unwrap_or("?")
            ));
        }
        let at = offset - start;
        let implicit = insns
            .get(at + 4..at + 8)
            .and_then(|b| <[u8; 4]>::try_from(b).ok())
            .map_or(0, u32::from_ne_bytes);
        let value = u32::try_from(target.address()).map_err(|e| e.to_string())?;
        sites.push((at, value.wrapping_add(implicit)));
    }
    Ok(Prepared {
        insns,
        sites,
        rodata,
    })
}

/// Point every site at `map_fd`'s value: `src_reg` set to
/// `BPF_PSEUDO_MAP_VALUE`, the map in the first immediate, the offset in the
/// second.
///
/// # Errors
///
/// A site is not an `ld_imm64` inside the program.
pub fn patch_sites(insns: &mut [u8], sites: &[(usize, u32)], map_fd: i32) -> Result<(), String> {
    for &(at, offset) in sites {
        if at % INSN_SIZE != 0 || at + 2 * INSN_SIZE > insns.len() || insns[at] != LD_IMM64 {
            return Err(format!("the site at {at} is not an ld_imm64"));
        }
        insns[at + 1] = (insns[at + 1] & 0x0f) | (BPF_PSEUDO_MAP_VALUE << 4);
        put(insns, at + 4, &map_fd.to_ne_bytes());
        put(insns, at + INSN_SIZE + 4, &offset.to_ne_bytes());
    }
    Ok(())
}

/// The id of the BTF `FUNC` named `name` in a raw BTF blob.
#[must_use]
pub fn btf_func_id(btf: &[u8], name: &str) -> Option<u32> {
    let u32_at = |at: usize| -> Option<u32> {
        btf.get(at..at + 4)
            .and_then(|b| <[u8; 4]>::try_from(b).ok())
            .map(u32::from_le_bytes)
    };
    if btf.get(0..2) != Some(&[0x9f, 0xeb]) {
        return None;
    }
    let hdr_len = usize::try_from(u32_at(4)?).ok()?;
    let type_off = usize::try_from(u32_at(8)?).ok()?;
    let type_len = usize::try_from(u32_at(12)?).ok()?;
    let str_off = usize::try_from(u32_at(16)?).ok()?;
    let strings = btf.get(hdr_len + str_off..)?;
    let mut at = hdr_len + type_off;
    let end = at + type_len;
    let mut id = 1u32;
    while at + 12 <= end {
        let name_off = usize::try_from(u32_at(at)?).ok()?;
        let info = u32_at(at + 4)?;
        let kind = (info >> 24) & 0x1f;
        let vlen = usize::try_from(info & 0xffff).ok()?;
        if kind == 12 {
            let tail = strings.get(name_off..)?;
            let nul = tail.iter().position(|&b| b == 0)?;
            if &tail[..nul] == name.as_bytes() {
                return Some(id);
            }
        }
        at += 12 + btf_kind_extra(kind, vlen)?;
        id += 1;
    }
    None
}

/// The bytes a BTF type of `kind` carries after its 12-byte header.
fn btf_kind_extra(kind: u32, vlen: usize) -> Option<usize> {
    Some(match kind {
        2 | 7..=12 | 16 | 18 => 0,
        1 | 14 | 17 => 4,
        3 => 12,
        4 | 5 | 15 | 19 => 12 * vlen,
        6 | 13 => 8 * vlen,
        _ => return None,
    })
}

/// Read the guard's object and the kernel BTF, and prepare the program held
/// to `serial`.
fn read(object: &Path, serial: i32) -> Result<Ready, String> {
    let elf = std::fs::read(object).map_err(|e| format!("read {}: {e}", object.display()))?;
    let prepared = prepare(&elf, serial)?;
    let btf =
        std::fs::read(VMLINUX_BTF_PATH).map_err(|e| format!("read {VMLINUX_BTF_PATH}: {e}"))?;
    let hook = btf_func_id(&btf, HOOK_FUNCTION)
        .ok_or_else(|| format!("the kernel BTF has no {HOOK_FUNCTION}"))?;
    Ok(Ready {
        prepared,
        hook,
        object: object.to_path_buf(),
        serial,
    })
}

/// Load the prepared guard and attach it.
fn attach(ready: &Ready) -> Result<Held, String> {
    let mut insns = ready.prepared.insns.clone();
    let map =
        frozen_rodata(&ready.prepared.rodata).map_err(|e| format!("the serial's map: {e}"))?;
    patch_sites(&mut insns, &ready.prepared.sites, map.as_raw_fd())?;
    let program = load_lsm(&insns, ready.hook).map_err(|e| format!("BPF_PROG_LOAD: {e}"))?;
    let mut attr = [0u8; 64];
    put(&mut attr, 0, &program.as_raw_fd().to_ne_bytes());
    put(&mut attr, 8, &BPF_LSM_MAC.to_ne_bytes());
    let link = bpf_bytes(BPF_LINK_CREATE, &mut attr)
        .and_then(owned)
        .map_err(|e| format!("BPF_LINK_CREATE: {e}"))?;
    Ok(Held {
        _map: map,
        _program: program,
        _link: link,
    })
}

/// A one-entry array holding `rodata`, read-only to programs and frozen.
fn frozen_rodata(rodata: &[u8]) -> io::Result<OwnedFd> {
    let value_size = u32::try_from(rodata.len()).map_err(io::Error::other)?;
    let mut attr = [0u8; 48];
    put(&mut attr, 0, &BPF_MAP_TYPE_ARRAY.to_ne_bytes());
    put(&mut attr, 4, &4u32.to_ne_bytes());
    put(&mut attr, 8, &value_size.to_ne_bytes());
    put(&mut attr, 12, &1u32.to_ne_bytes());
    put(&mut attr, 16, &BPF_F_RDONLY_PROG.to_ne_bytes());
    let map = owned(bpf_bytes(BPF_MAP_CREATE, &mut attr)?)?;
    let key = 0u32;
    let mut attr = [0u8; 32];
    put(&mut attr, 0, &map.as_raw_fd().to_ne_bytes());
    put(
        &mut attr,
        8,
        &(std::ptr::from_ref(&key) as u64).to_ne_bytes(),
    );
    put(&mut attr, 16, &(rodata.as_ptr() as u64).to_ne_bytes());
    bpf_bytes(BPF_MAP_UPDATE_ELEM, &mut attr)?;
    let mut attr = [0u8; 8];
    put(&mut attr, 0, &map.as_raw_fd().to_ne_bytes());
    bpf_bytes(BPF_MAP_FREEZE, &mut attr)?;
    Ok(map)
}

/// Load `insns` as a BPF LSM program on the hook whose BTF id is `hook`.
fn load_lsm(insns: &[u8], hook: u32) -> io::Result<OwnedFd> {
    let license = CString::new("GPL").map_err(io::Error::other)?;
    let name = b"bpf_load_guard\0";
    let count = u32::try_from(insns.len() / INSN_SIZE).map_err(io::Error::other)?;
    let mut attr = [0u8; PROG_LOAD_ATTR_SIZE];
    put(&mut attr, 0, &BPF_PROG_TYPE_LSM.to_ne_bytes());
    put(&mut attr, 4, &count.to_ne_bytes());
    put(&mut attr, 8, &(insns.as_ptr() as u64).to_ne_bytes());
    put(&mut attr, 16, &(license.as_ptr() as u64).to_ne_bytes());
    put(&mut attr, 48, name);
    put(&mut attr, 68, &BPF_LSM_MAC.to_ne_bytes());
    put(&mut attr, 108, &hook.to_ne_bytes());
    owned(bpf_bytes(BPF_PROG_LOAD, &mut attr)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::prog_signing::LoadGuardReport;
    use ebpf_common::load_guard::LOAD_GUARD_OBJECT;

    fn facts() -> Facts {
        Facts {
            kernel_verifies: Some(true),
            bpf_lsm: Ok(true),
            keyring: Some(42),
            object: Ok(PathBuf::from(
                "/usr/local/lib/ebpfsentinel/lsm-bpf-load-guard",
            )),
        }
    }

    fn skipped(f: Facts) -> String {
        match decide(f) {
            Decision::Skip(reason) => reason,
            Decision::Load { .. } => String::from("loaded"),
        }
    }

    #[test]
    fn every_condition_present_loads_the_guard_held_to_the_keyring() {
        assert_eq!(
            decide(facts()),
            Decision::Load {
                object: PathBuf::from("/usr/local/lib/ebpfsentinel/lsm-bpf-load-guard"),
                serial: 42,
            }
        );
    }

    #[test]
    fn each_missing_condition_skips_and_is_named() {
        let mut f = facts();
        f.kernel_verifies = Some(false);
        assert!(skipped(f).contains("does not verify"));
        let mut f = facts();
        f.kernel_verifies = None;
        assert!(skipped(f).contains("could not be asked"));
        let mut f = facts();
        f.bpf_lsm = Ok(false);
        assert!(skipped(f).contains("lsm="));
        let mut f = facts();
        f.bpf_lsm = Err("No such file or directory".to_owned());
        assert!(skipped(f).contains(LSM_LIST_PATH));
        let mut f = facts();
        f.keyring = None;
        assert!(skipped(f).contains("no loader keyring"));
        let mut f = facts();
        f.object = Err(PathBuf::from("/nonexistent"));
        assert!(skipped(f).contains("no guard object at /nonexistent"));
    }

    #[test]
    fn the_kernel_comes_first_then_the_boot_line_then_the_keyring() {
        let f = Facts {
            kernel_verifies: Some(false),
            bpf_lsm: Ok(false),
            keyring: None,
            object: Err(PathBuf::from("/x")),
        };
        assert!(skipped(f.clone()).contains("does not verify"));
        let f = Facts {
            kernel_verifies: Some(true),
            ..f
        };
        assert!(skipped(f.clone()).contains("lsm="));
        let f = Facts {
            bpf_lsm: Ok(true),
            ..f
        };
        assert!(skipped(f).contains("keyring"));
    }

    #[test]
    fn the_lsm_list_is_read_by_module_name() {
        assert!(lsm_list_has_bpf(
            "lockdown,capability,landlock,yama,apparmor,bpf\n"
        ));
        assert!(lsm_list_has_bpf("bpf"));
        assert!(!lsm_list_has_bpf("lockdown,capability,apparmor"));
        assert!(!lsm_list_has_bpf("lockdown,bpfx"));
        assert!(!lsm_list_has_bpf(""));
    }

    #[test]
    fn e2big_alone_says_the_kernel_does_not_verify() {
        assert_eq!(signing_from_errno(Some(libc::E2BIG)), Some(false));
        assert_eq!(signing_from_errno(Some(libc::ENOSYS)), None);
        for errno in [
            libc::EBADMSG,
            libc::ENOKEY,
            libc::EKEYREJECTED,
            libc::EINVAL,
        ] {
            assert_eq!(signing_from_errno(Some(errno)), Some(true));
        }
        assert_eq!(signing_from_errno(None), Some(true));
    }

    #[test]
    fn the_env_round_trips_the_report() {
        assert_eq!(
            decode_env(Some(&encode_env(&LoadGuard::Attached))),
            LoadGuardReport::Attached
        );
        let absent = LoadGuard::Absent {
            reason: "bpf is not in the lsm= list".to_owned(),
        };
        assert_eq!(
            decode_env(Some(&encode_env(&absent))),
            LoadGuardReport::Absent("bpf is not in the lsm= list".to_owned())
        );
        assert_eq!(decode_env(None), LoadGuardReport::NotReported);
    }

    #[test]
    fn a_nul_in_the_reason_never_reaches_setenv() {
        let v = encode_env(&LoadGuard::Absent {
            reason: "a\0b".to_owned(),
        });
        assert!(!v.contains('\0'));
        assert!(CString::new(v).is_ok());
    }

    #[test]
    fn the_status_is_handed_over_as_the_protocol_says() {
        assert_eq!(Status::Attached.into_proto(), LoadGuard::Attached);
        assert_eq!(Status::Ready.into_proto(), LoadGuard::Attached);
        assert_eq!(
            Status::Absent("x".to_owned()).into_proto(),
            LoadGuard::Absent {
                reason: "x".to_owned()
            }
        );
    }

    #[test]
    fn nothing_prepared_arms_nothing_and_nothing_held_lifts_nothing() {
        // No test installs the guard, so the state is the one a warden starts
        // with: nothing read, nothing held.
        before_delegation();
        assert!(matches!(arm(None), Status::Absent(_)));
        assert!(state().held.is_none());
        assert!(state().armed_for.is_none());
    }

    #[test]
    fn a_site_becomes_a_map_value_load() {
        // r1 = 0 ll (ld_imm64 into r1, implicit offset 4), then exit.
        let mut insns = vec![
            0x18, 0x01, 0, 0, 4, 0, 0, 0, //
            0, 0, 0, 0, 0, 0, 0, 0, //
            0x95, 0, 0, 0, 0, 0, 0, 0,
        ];
        patch_sites(&mut insns, &[(0, 4)], 7).expect("patched");
        assert_eq!(insns[1], 0x21, "dst r1 kept, src BPF_PSEUDO_MAP_VALUE");
        assert_eq!(&insns[4..8], &7i32.to_ne_bytes());
        assert_eq!(&insns[12..16], &4u32.to_ne_bytes());
        assert!(
            patch_sites(&mut insns, &[(16, 0)], 7).is_err(),
            "exit is no site"
        );
        assert!(patch_sites(&mut insns, &[(3, 0)], 7).is_err(), "unaligned");
    }

    /// A BTF blob of three types: an INT, a `FUNC_PROTO` with one parameter,
    /// and the FUNC looked for.
    fn btf_blob() -> Vec<u8> {
        let strings = b"\0int\0bpf_lsm_bpf_prog_load\0";
        let mut types = Vec::new();
        let mut ty = |name: u32, info: u32, size: u32, extra: &[u8]| {
            types.extend_from_slice(&name.to_le_bytes());
            types.extend_from_slice(&info.to_le_bytes());
            types.extend_from_slice(&size.to_le_bytes());
            types.extend_from_slice(extra);
        };
        ty(1, 1 << 24, 4, &0x0100_0020u32.to_le_bytes());
        ty(0, (13 << 24) | 1, 1, &[0u8; 8]);
        ty(5, 12 << 24, 2, &[]);
        let mut blob = Vec::new();
        blob.extend_from_slice(&[0x9f, 0xeb, 1, 0]);
        blob.extend_from_slice(&24u32.to_le_bytes());
        blob.extend_from_slice(&0u32.to_le_bytes());
        blob.extend_from_slice(&u32::try_from(types.len()).expect("small").to_le_bytes());
        blob.extend_from_slice(&u32::try_from(types.len()).expect("small").to_le_bytes());
        blob.extend_from_slice(&u32::try_from(strings.len()).expect("small").to_le_bytes());
        blob.extend_from_slice(&types);
        blob.extend_from_slice(strings);
        blob
    }

    #[test]
    fn the_hook_is_found_past_types_of_every_width() {
        assert_eq!(btf_func_id(&btf_blob(), HOOK_FUNCTION), Some(3));
        assert_eq!(btf_func_id(&btf_blob(), "int"), None, "an INT is no FUNC");
        assert_eq!(btf_func_id(&[0u8; 4], HOOK_FUNCTION), None);
    }

    /// The running kernel's own BTF, where one is exposed: a function every
    /// kernel carries is found, so the walk keeps step with the kernel's
    /// format and not only with the blob above.
    #[test]
    fn the_running_kernel_btf_is_walked_to_the_end() {
        let Ok(btf) = std::fs::read(VMLINUX_BTF_PATH) else {
            return;
        };
        assert!(btf_func_id(&btf, "schedule").is_some());
    }

    /// The object the build wrote, where it was built: the program, the
    /// global and every site are found, and the serial lands in the global.
    #[test]
    fn the_built_object_prepares_with_the_serial_in_place() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/bpfel-unknown-none/release")
            .join(LOAD_GUARD_OBJECT);
        let Ok(elf) = std::fs::read(&path) else {
            return;
        };
        let prepared = prepare(&elf, 0x2f3e_4d5c).expect("prepares");
        assert!(!prepared.sites.is_empty(), "the program reads the global");
        assert_eq!(prepared.insns.len() % INSN_SIZE, 0);
        assert!(
            prepared
                .rodata
                .windows(4)
                .any(|w| w == 0x2f3e_4d5c_i32.to_ne_bytes())
        );
        let mut insns = prepared.insns.clone();
        patch_sites(&mut insns, &prepared.sites, 9).expect("every site is an ld_imm64");
    }
}
