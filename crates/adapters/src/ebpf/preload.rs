//! The kernel-reading objects, loaded once before the agent reads input.
//!
//! Under a warden, start-up loads every object holding a tracepoint, kprobe,
//! uprobe or LSM program before it opens a socket or reads a file it was not
//! shipped with, and keeps what each load returned: every later load of the
//! same object, at start-up or on a reload, is answered with those maps and
//! programs. The raw tracepoint and kprobe programs are then handed to the
//! warden, which holds them and attaches each only to the hook listed for its
//! name, so the agent keeps no program it could aim at another hook. After the
//! hand-over a kernel-reading object start-up did not load is refused rather
//! than loaded fresh, since a fresh load would put an aimable program back in
//! the agent's hands.
//!
//! The agent keeps the capabilities it was started with: the datapath needs
//! `CAP_PERFMON` to pass the verifier. What stops a compromised agent from
//! loading a program of its own is the kernel refusing an unsigned load.

use std::collections::HashMap;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

use aya_obj::{Object, ProgramSection};
use ebpfsentinel_warden_client::ReconnectingClient;
use ebpfsentinel_warden_proto::{HeldTarget, held_program};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use super::kfunc_loader::{
    KfuncLoadedProgram, KfuncLoaderError, RefusedProgram, TokenLoadedObject, wrap_map_data,
};

static WINDOW_OPEN: AtomicBool = AtomicBool::new(false);
static HANDED_OVER: AtomicBool = AtomicBool::new(false);

/// The connection held programs are attached through, set by [`hand_over`].
static WARDEN: OnceLock<Mutex<ReconnectingClient>> = OnceLock::new();

/// The programs the warden accepted to hold, set by [`hand_over`].
static HELD: OnceLock<Vec<String>> = OnceLock::new();

/// Whether the kernel-reading objects were loaded before input and handed
/// over, and what the warden holds.
#[derive(Debug, Clone, Default)]
pub struct PreloadStatus {
    /// Start-up loaded them before reading input and handed the aimable
    /// programs to the warden.
    pub handed_over: bool,
    /// The programs the warden holds and attaches by name.
    pub held: Vec<String>,
    /// Why nothing was handed over, in one sentence.
    pub reason: Option<String>,
}

/// The hand-over as it stands.
#[must_use]
pub fn status() -> PreloadStatus {
    let handed_over = handed_over();
    PreloadStatus {
        handed_over,
        held: HELD.get().cloned().unwrap_or_default(),
        reason: (!handed_over).then(|| {
            "no warden is configured: the agent loads each object when a feature asks for \
             it and attaches every program itself"
                .to_owned()
        }),
    }
}

/// What one load of an object came to, kept to answer the loads after it.
struct Kept {
    maps: Vec<(String, OwnedFd, u32)>,
    programs: Vec<(String, OwnedFd, u32)>,
    refused: Vec<RefusedProgram>,
}

/// The arguments a load is answered on: the object's bytes, where its maps
/// are pinned, the device its programs are bound to and the programs it may
/// do without. The same object loaded with other arguments is another load.
#[derive(PartialEq, Eq, Hash)]
struct Key {
    digest: [u8; 32],
    pin_path: Option<String>,
    dev_bound_ifindex: Option<u32>,
    optional: Vec<String>,
}

impl Key {
    fn of(
        elf: &[u8],
        pin_path: Option<&str>,
        dev_bound_ifindex: Option<u32>,
        optional: &[&str],
    ) -> Self {
        let mut optional: Vec<String> = optional.iter().map(|s| (*s).to_owned()).collect();
        optional.sort_unstable();
        Self {
            digest: Sha256::digest(elf).into(),
            pin_path: pin_path.map(str::to_owned),
            dev_bound_ifindex,
            optional,
        }
    }
}

fn kept() -> std::sync::MutexGuard<'static, HashMap<Key, Result<Kept, String>>> {
    static KEPT: OnceLock<Mutex<HashMap<Key, Result<Kept, String>>>> = OnceLock::new();
    // A panic while the table was held leaves either a whole entry or none:
    // entries are inserted and taken apart in one statement each.
    KEPT.get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Open the window: objects holding a program that reads the kernel are kept
/// from now until [`hand_over`].
pub fn begin() {
    WINDOW_OPEN.store(true, Ordering::SeqCst);
}

/// Whether start-up is keeping the kernel-reading objects it loads.
#[must_use]
pub fn window_open() -> bool {
    WINDOW_OPEN.load(Ordering::SeqCst)
}

/// Whether start-up handed the kernel-reading programs over: from then on an
/// object it did not load is refused.
#[must_use]
pub fn handed_over() -> bool {
    HANDED_OVER.load(Ordering::SeqCst)
}

/// Whether a program of this section reads the kernel: the kernel asks
/// `CAP_PERFMON` to load it.
fn reads_kernel(section: &ProgramSection) -> bool {
    matches!(
        section,
        ProgramSection::KProbe
            | ProgramSection::KRetProbe
            | ProgramSection::UProbe { .. }
            | ProgramSection::URetProbe { .. }
            | ProgramSection::TracePoint
            | ProgramSection::RawTracePoint
            | ProgramSection::Lsm { .. }
            | ProgramSection::LsmCgroup
            | ProgramSection::Iter { .. }
            | ProgramSection::BtfTracePoint
            | ProgramSection::FEntry { .. }
            | ProgramSection::FExit { .. }
            | ProgramSection::Extension
            | ProgramSection::PerfEvent
    )
}

/// Whether `elf` holds a program that reads the kernel. An object that does
/// not parse is not one this module answers for; the loader reports it.
#[must_use]
pub fn object_reads_kernel(elf: &[u8]) -> bool {
    Object::parse(elf).is_ok_and(|obj| obj.programs.values().any(|p| reads_kernel(&p.section)))
}

fn dup(fd: &OwnedFd) -> Result<OwnedFd, KfuncLoaderError> {
    fd.try_clone()
        .map_err(|e| KfuncLoaderError::MapWrap(e.to_string()))
}

/// Rebuild a loaded object out of what was kept, on fresh descriptors.
fn rebuild(kept: &Kept) -> Result<TokenLoadedObject, KfuncLoaderError> {
    let mut maps = HashMap::new();
    let mut hosted = HashMap::new();
    for (name, fd, map_type) in &kept.maps {
        maps.insert(name.clone(), wrap_map_data(dup(fd)?, *map_type)?);
        hosted.insert(name.clone(), dup(fd)?);
    }
    let programs = kept
        .programs
        .iter()
        .map(|(name, fd, prog_type)| {
            Ok(KfuncLoadedProgram {
                name: name.clone(),
                fd: dup(fd)?,
                prog_type: *prog_type,
            })
        })
        .collect::<Result<_, KfuncLoaderError>>()?;
    let map_types = kept
        .maps
        .iter()
        .map(|(name, _, map_type)| (name.clone(), *map_type))
        .collect();
    Ok(TokenLoadedObject {
        maps,
        programs,
        refused: kept.refused.clone(),
        hosted,
        map_types,
    })
}

/// Copy what a fresh load returned, so the loads after it are answered with
/// the same maps and programs.
fn keep(loaded: &TokenLoadedObject) -> Result<Kept, KfuncLoaderError> {
    let maps = loaded
        .hosted
        .iter()
        .map(|(name, fd)| {
            let map_type = loaded.map_types.get(name).copied().unwrap_or_default();
            Ok((name.clone(), dup(fd)?, map_type))
        })
        .collect::<Result<_, KfuncLoaderError>>()?;
    let programs = loaded
        .programs
        .iter()
        .map(|p| Ok((p.name.clone(), dup(&p.fd)?, p.prog_type)))
        .collect::<Result<_, KfuncLoaderError>>()?;
    Ok(Kept {
        maps,
        programs,
        refused: loaded.refused.clone(),
    })
}

/// Answer a load from what was kept, load it fresh, or refuse it, by where
/// start-up is. Called by the loader for every token load.
pub(super) fn load(
    elf: &[u8],
    pin_path: Option<&str>,
    dev_bound_ifindex: Option<u32>,
    optional: &[&str],
    fresh: impl FnOnce() -> Result<TokenLoadedObject, KfuncLoaderError>,
) -> Result<TokenLoadedObject, KfuncLoaderError> {
    let open = WINDOW_OPEN.load(Ordering::SeqCst);
    if !open && !handed_over() {
        return fresh();
    }
    if !object_reads_kernel(elf) {
        return fresh();
    }
    let key = Key::of(elf, pin_path, dev_bound_ifindex, optional);
    if let Some(entry) = kept().get(&key) {
        return match entry {
            Ok(kept) => rebuild(kept),
            Err(reason) => Err(KfuncLoaderError::RefusedAtStartup(reason.clone())),
        };
    }
    if handed_over() {
        return Err(KfuncLoaderError::NotPreloaded);
    }
    let loaded = fresh();
    let entry = match &loaded {
        Ok(object) => keep(object).map_err(|e| e.to_string()),
        Err(e) => Err(e.to_string()),
    };
    kept().insert(key, entry);
    loaded
}

/// What [`hand_over`] did with each program it found.
#[derive(Debug, Default)]
pub struct HandOver {
    /// Programs the warden now holds.
    pub held: Vec<String>,
    /// Programs closed without being held, with the reason.
    pub dropped: Vec<(String, String)>,
}

/// Close the window and give the warden at `sock` every kept raw tracepoint
/// and kprobe program, closing the agent's copies whatever it answers.
///
/// A program the warden refuses or cannot be reached for is closed all the
/// same: the agent keeps no program it could aim elsewhere, and the feature
/// built on it reports its probe as not attached.
pub fn hand_over(sock: &Path) -> HandOver {
    WINDOW_OPEN.store(false, Ordering::SeqCst);
    HANDED_OVER.store(true, Ordering::SeqCst);
    let client = WARDEN.get_or_init(|| Mutex::new(ReconnectingClient::new(sock.to_path_buf())));
    let mut report = HandOver::default();
    let mut table = kept();
    for entry in table.values_mut() {
        let Ok(kept) = entry else { continue };
        let (aimable, stay): (Vec<_>, Vec<_>) = std::mem::take(&mut kept.programs)
            .into_iter()
            .partition(|(_, _, prog_type)| {
                *prog_type == ebpfsentinel_warden_proto::BPF_PROG_TYPE_KPROBE
                    || *prog_type == ebpfsentinel_warden_proto::BPF_PROG_TYPE_RAW_TRACEPOINT
            });
        kept.programs = stay;
        for (name, fd, prog_type) in aimable {
            let outcome = match held_program(&name) {
                None => Err("no target is listed for it".to_owned()),
                Some(p) if p.target.prog_type() != prog_type => {
                    Err(format!("its type {prog_type} is not its target's"))
                }
                Some(_) => client
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .hold_program(&name, fd.as_raw_fd())
                    .map_err(|e| e.to_string()),
            };
            drop(fd);
            match outcome {
                Ok(()) => report.held.push(name),
                Err(reason) => {
                    warn!(program = %name, reason, "program closed without the warden holding it");
                    report.dropped.push((name, reason));
                }
            }
        }
    }
    info!(
        held = report.held.len(),
        dropped = report.dropped.len(),
        "kernel-reading programs handed to the warden"
    );
    let mut held = report.held.clone();
    held.sort_unstable();
    let _ = HELD.set(held);
    report
}

/// The connection held programs are attached through, once [`hand_over`] ran.
fn warden() -> Option<std::sync::MutexGuard<'static, ReconnectingClient>> {
    WARDEN
        .get()
        .map(|c| c.lock().unwrap_or_else(std::sync::PoisonError::into_inner))
}

/// Attach a program the warden holds to the target listed for it.
///
/// # Errors
///
/// Returns why: no warden holds programs for this agent, or the warden or the
/// kernel refused.
pub fn attach_held(program: &str) -> Result<OwnedFd, String> {
    let mut client = warden().ok_or_else(|| {
        format!("program `{program}` is not in the loaded object and no warden holds it")
    })?;
    client.attach_held(program).map_err(|e| e.to_string())
}

/// Attach the raw tracepoint program `program` of `loader` to `tracepoint`:
/// directly when the agent holds the program, through the warden when the
/// warden does. The warden attaches to the tracepoint listed for the name,
/// which is the one asked for here.
///
/// # Errors
///
/// Returns why the attach was refused.
pub fn attach_raw_tracepoint(
    loader: &super::loader::EbpfLoader,
    program: &str,
    tracepoint: &str,
) -> Result<OwnedFd, String> {
    if let Some(prog_fd) = loader.program_fd(program) {
        return super::kfunc_attach::attach_raw_tracepoint(program, prog_fd, tracepoint)
            .map_err(|e| e.to_string());
    }
    match held_program(program).map(|p| p.target) {
        Some(HeldTarget::RawTracepoint(listed)) if listed == tracepoint => attach_held(program),
        Some(_) => Err(format!(
            "program `{program}` is held for another target than `{tracepoint}`"
        )),
        None => Err(format!("program `{program}` is not in the loaded object")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sections_that_read_the_kernel_are_the_ones_the_kernel_asks_perfmon_for() {
        assert!(reads_kernel(&ProgramSection::KProbe));
        assert!(reads_kernel(&ProgramSection::RawTracePoint));
        assert!(reads_kernel(&ProgramSection::Lsm { sleepable: false }));
        assert!(!reads_kernel(&ProgramSection::SchedClassifier));
        assert!(!reads_kernel(&ProgramSection::SockOps));
    }

    #[test]
    fn the_same_object_with_other_arguments_is_another_load() {
        let a = Key::of(b"elf", Some("/p"), None, &["b", "a"]);
        assert!(a == Key::of(b"elf", Some("/p"), None, &["a", "b"]));
        assert!(a != Key::of(b"elf", Some("/q"), None, &["a", "b"]));
        assert!(a != Key::of(b"elf2", Some("/p"), None, &["a", "b"]));
    }

    #[test]
    fn a_raw_tracepoint_not_held_and_not_loaded_is_refused_with_its_name() {
        assert!(WARDEN.get().is_none());
        let error = attach_held("process_exec").expect_err("no warden");
        assert!(error.contains("process_exec"), "{error}");
    }
}
