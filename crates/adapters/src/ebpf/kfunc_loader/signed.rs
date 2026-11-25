//! Programs loaded through a loader signed at build.
//!
//! A kernel that verifies program signatures checks the signature of the
//! program being loaded, not of what that program does once it runs. The
//! build therefore turns each of the agent's programs into a small loader of
//! type `syscall`, signs the loader, and puts everything the loader loads -
//! instructions, licence, BTF records, kfunc names - in a metadata map the
//! kernel lets only that loader read, frozen, whose digest the loader checks
//! against the one it carries before it does anything. The signature therefore
//! covers the program the agent runs, by way of the loader.
//!
//! On the host, the warden makes a keyring holding the certificate from its
//! own image and hands its serial to the agent; the agent loads each loader
//! with its signature and that serial, runs it once, and reads the program's
//! descriptor back from the loader's context. A kernel that does not verify,
//! an agent with no keyring, an object built without a bundle, or a loader the
//! kernel refuses: each loads the program unsigned, the way it always did, and
//! the crypto posture says how many went each way.
//!
//! [`generate`] is the build half, [`bundle`] the file between the two halves,
//! `run` the host half.

mod insn;

pub mod bundle;
pub mod generate;
mod run;

use std::cell::Cell;
use std::collections::HashMap;
use std::hash::BuildHasher;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use sha2::{Digest as _, Sha256};

use self::bundle::Bundle;
use super::{DegradedProgram, KfuncLoaderError, quoted_list};

/// Where the loader reads what the host chooses, and writes what it did: the
/// byte offset of each field in the context `BPF_PROG_TEST_RUN` hands it.
mod ctx {
    /// The BPF token the inner load goes through.
    pub(super) const TOKEN_FD: i16 = 0;
    /// The program BTF, loaded by the host.
    pub(super) const PROG_BTF_FD: i16 = 4;
    /// The netdev an XDP program binds to, zero for none.
    pub(super) const PROG_IFINDEX: i16 = 8;
    /// The flags the host asks for, masked by the loader to the ones the
    /// build allows.
    pub(super) const PROG_FLAGS: i16 = 12;
    /// Bit `j` set: kfunc `j` is neutralized, honoured only for a kfunc the
    /// build marked neutralizable.
    pub(super) const NEUTRAL_MASK: i16 = 16;
    /// A verifier log buffer in the agent's memory, zero for none.
    pub(super) const LOG_BUF: i16 = 24;
    pub(super) const LOG_SIZE: i16 = 32;
    pub(super) const LOG_LEVEL: i16 = 36;
    /// Out: the loaded program's descriptor, or the inner load's `-errno`.
    pub(super) const OUT_PROG_FD: i16 = 40;
    /// Out: zero once the loader reached the inner load.
    pub(super) const OUT_RESULT: i16 = 44;
    /// Out: the index of the kfunc that did not resolve, or
    /// [`super::generate::FAILED_LSM_HOOK`].
    pub(super) const OUT_FAILED_KFUNC: i16 = 48;
    /// The `fd_array`: one map per slot, then one module BTF per kfunc.
    pub(super) const FDS: usize = 56;
}

/// The first `fd_array` slot a kfunc's module BTF goes in: after the maps,
/// and never slot 0, which the kernel reads as vmlinux.
pub(super) fn fds_base(map_count: usize) -> usize {
    map_count.max(1)
}

/// The size of the loader's context, a multiple of eight.
pub(super) fn ctx_size(map_count: usize, kfunc_count: usize) -> usize {
    (ctx::FDS + 4 * (fds_base(map_count) + kfunc_count)).next_multiple_of(8)
}

/// The bundles of this host, by the digest of the object they were built
/// from.
struct Registry {
    keyring: i32,
    bundles: HashMap<[u8; 32], Arc<Bundle>>,
}

static REGISTRY: OnceLock<Registry> = OnceLock::new();
static SIGNED: AtomicU64 = AtomicU64::new(0);
static UNSIGNED: AtomicU64 = AtomicU64::new(0);
/// Programs whose unsigned load the warden's guard refused.
static REFUSED: AtomicU64 = AtomicU64::new(0);
/// The certificate of the first loader the kernel took.
static CERTIFICATE: OnceLock<[u8; 32]> = OnceLock::new();

/// What [`install`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Install {
    /// The kernel does not verify program signatures: everything loads
    /// unsigned.
    KernelDoesNotVerify,
    /// The warden handed over no keyring: an image built without a
    /// certificate, or a warden that does not make one.
    NoKeyring,
    /// Signed loads are on for the objects a bundle was found for.
    Active {
        keyring: i32,
        bundles: usize,
        /// Bundles that could not be read, each with why.
        unreadable: Vec<String>,
    },
}

/// The keyring serial the warden handed over, as the bootstrap left it in
/// the environment.
#[must_use]
pub fn keyring_from_env() -> Option<i32> {
    std::env::var(ebpfsentinel_warden::loader_keyring::LOADER_KEYRING_ENV)
        .ok()
        .and_then(|v| v.trim().parse().ok())
}

/// Turn signed loads on, once per process, before the first object loads:
/// read every bundle in `program_dir`. Nothing is turned on when the kernel
/// does not verify or no keyring was handed over.
pub fn install(program_dir: &Path, keyring: Option<i32>, kernel_verifies: bool) -> Install {
    if !kernel_verifies {
        return Install::KernelDoesNotVerify;
    }
    let Some(keyring) = keyring else {
        return Install::NoKeyring;
    };
    let (bundles, unreadable) = read_bundles(program_dir);
    let count = bundles.len();
    let _ = REGISTRY.set(Registry { keyring, bundles });
    Install::Active {
        keyring,
        bundles: count,
        unreadable,
    }
}

/// Every `*.loaders` file in `dir`, decoded, by object digest.
fn read_bundles(dir: &Path) -> (HashMap<[u8; 32], Arc<Bundle>>, Vec<String>) {
    let mut bundles = HashMap::new();
    let mut unreadable = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return (bundles, unreadable);
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some(bundle::BUNDLE_EXTENSION) {
            continue;
        }
        match std::fs::read(&path)
            .map_err(|e| e.to_string())
            .and_then(|b| bundle::decode(&b))
        {
            Ok(b) => {
                bundles.insert(b.object.elf_sha256, Arc::new(b));
            }
            Err(e) => unreadable.push(format!("{}: {e}", path.display())),
        }
    }
    (bundles, unreadable)
}

/// Whether `elf`, as the build wrote it, would load signed on this host:
/// signed loads are on and a bundle was built from exactly these bytes, once
/// their kfunc calls are prepatched as every load prepatches them. A
/// caller about to rewrite the object's instructions asks first, since a
/// rewritten object matches no bundle and loads unsigned, which the warden's
/// guard refuses.
#[must_use]
pub fn would_load_signed(elf: &[u8]) -> bool {
    let Some(registry) = REGISTRY.get() else {
        return false;
    };
    if super::global_token_fd().is_none() {
        return false;
    }
    let Ok(prepatched) = super::prepatch_kfunc_calls(elf) else {
        return false;
    };
    let digest: [u8; 32] = Sha256::digest(&prepatched).into();
    registry.bundles.contains_key(&digest)
}

/// What the crypto posture reports about signed loads.
#[must_use]
pub fn signed_loads() -> domain::prog_signing::SignedLoads {
    domain::prog_signing::SignedLoads {
        keyring_serial: REGISTRY.get().map(|r| r.keyring),
        certificate_sha256: CERTIFICATE.get().map(hex),
        signed_programs: SIGNED.load(Ordering::Relaxed),
        unsigned_programs: UNSIGNED.load(Ordering::Relaxed),
        refused_programs: REFUSED.load(Ordering::Relaxed),
        load_guard: ebpfsentinel_warden::load_guard::report_from_env(),
    }
}

/// Whether `e` is the warden's guard refusing an unsigned load: the guard is
/// attached, and the kernel answered the load with a permission error. A
/// token that does not allow the program type answers the same, which the
/// warden's delegation rules out for the types it delegates.
fn refused_by_guard(e: &KfuncLoaderError, guard_attached: bool) -> bool {
    guard_attached
        && matches!(e, KfuncLoaderError::ProgLoad { errno, .. } if errno.abs() == libc::EPERM)
}

/// What to add to a refused load's reason: under an attached guard a
/// permission error on a program the agent assembled itself (a probe, a
/// hand-written helper program) is the guard refusing it unsigned, not a
/// missing privilege.
#[must_use]
pub fn guard_refusal_note(errno: i32, guard_attached: bool) -> &'static str {
    if guard_attached && errno.abs() == libc::EPERM {
        "; the warden's guard on program loads refuses every load through the BPF token \
         that is not signed against its keyring, and this program is assembled at run time, \
         never signed"
    } else {
        ""
    }
}

/// [`guard_refusal_note`] for this process, from what the warden handed over.
#[must_use]
pub fn guard_refusal_note_here(errno: i32) -> &'static str {
    guard_refusal_note(errno, ebpfsentinel_warden::load_guard::attached_from_env())
}

/// The outcome of one program's unsigned load, counted: loaded unsigned, or
/// refused by the warden's guard, in which case the error says so in place
/// of the bare permission error. A refusal is counted at once, since the
/// object it belongs to usually fails with it.
pub(super) fn unsigned_outcome(
    loaders: Option<&ObjectLoaders>,
    result: Result<OwnedFd, KfuncLoaderError>,
) -> Result<OwnedFd, KfuncLoaderError> {
    match result {
        Ok(fd) => {
            if let Some(loaders) = loaders {
                loaders.unsigned.set(loaders.unsigned.get() + 1);
            }
            Ok(fd)
        }
        Err(e) if refused_by_guard(&e, ebpfsentinel_warden::load_guard::attached_from_env()) => {
            REFUSED.fetch_add(1, Ordering::Relaxed);
            let name = match &e {
                KfuncLoaderError::ProgLoad { name, .. } => name.clone(),
                _ => String::new(),
            };
            Err(KfuncLoaderError::RefusedByLoadGuard { name })
        }
        Err(e) => Err(e),
    }
}

fn hex(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(64), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// One object's signed loads, open while its programs load. The counts are
/// kept here and added to the process's only when the whole object loaded, so
/// an object loaded twice (bound to a device, then not) counts once.
pub(super) struct ObjectLoaders {
    keyring: i32,
    bundle: Option<Arc<Bundle>>,
    map_fds: Vec<RawFd>,
    signed: Cell<u64>,
    unsigned: Cell<u64>,
}

/// One program's load, as the unsigned path would issue it.
pub(super) struct Request<'a> {
    pub name: &'a str,
    pub prog_btf_fd: Option<RawFd>,
    pub prog_ifindex: Option<u32>,
    /// The flags, `BPF_F_XDP_DEV_BOUND_ONLY` included when bound.
    pub prog_flags: u32,
    /// Optional kfuncs the kernel BTF does not declare.
    pub neutral: &'a [String],
    /// Every optional kfunc the program calls.
    pub optional_calls: &'a [String],
    /// Whether the load mode replaces a call to this kfunc.
    pub mode_neutralizes: &'a dyn Fn(&str) -> bool,
}

/// What a signed attempt gave: the program and what it lost, as
/// `load_degrading` answers, or `None` for the unsigned path to load it.
pub(super) type Attempt = Option<(Result<OwnedFd, KfuncLoaderError>, Option<DegradedProgram>)>;

/// The signed loads of `elf` (the prepatched object), or `None` when signed
/// loads are off: no keyring, a kernel that does not verify, no token.
pub(super) fn for_object<S: BuildHasher>(
    elf: &[u8],
    hosted: &HashMap<String, OwnedFd, S>,
) -> Option<ObjectLoaders> {
    let registry = REGISTRY.get()?;
    super::global_token_fd()?;
    let digest: [u8; 32] = Sha256::digest(elf).into();
    let bundle = registry.bundles.get(&digest).cloned();
    let map_fds = bundle.as_ref().and_then(|b| {
        b.object
            .maps
            .iter()
            .map(|name| hosted.get(name).map(AsRawFd::as_raw_fd))
            .collect::<Option<Vec<_>>>()
    });
    Some(ObjectLoaders {
        keyring: registry.keyring,
        bundle: map_fds.as_ref().and(bundle),
        map_fds: map_fds.unwrap_or_default(),
        signed: Cell::new(0),
        unsigned: Cell::new(0),
    })
}

impl ObjectLoaders {
    /// Load one program signed, or say it goes unsigned. A program that
    /// goes unsigned is counted by [`unsigned_outcome`] once its unsigned load
    /// answered, since the warden's guard may refuse it.
    pub(super) fn load(&self, req: &Request<'_>) -> Attempt {
        let attempt = self.try_load(req);
        if attempt.as_ref().is_some_and(|(r, _)| r.is_ok()) {
            self.signed.set(self.signed.get() + 1);
        }
        attempt
    }

    fn try_load(&self, req: &Request<'_>) -> Attempt {
        let bundle = self.bundle.as_ref()?;
        let at = bundle
            .object
            .programs
            .iter()
            .position(|p| p.name == req.name)?;
        let first = |k: &str| (req.mode_neutralizes)(k) || req.neutral.iter().any(|n| n == k);
        let e = match self.run(bundle, at, req, &first)? {
            Ok(fd) => {
                let degraded = (!req.neutral.is_empty()).then(|| DegradedProgram {
                    name: req.name.to_owned(),
                    kfuncs: req.neutral.to_vec(),
                    declared: false,
                    reason: format!(
                        "the kernel BTF does not declare {}",
                        quoted_list(req.neutral)
                    ),
                });
                return Some((Ok(fd), degraded));
            }
            Err(e) => e,
        };
        if req.neutral.len() >= req.optional_calls.len() {
            return Some((Err(e), None));
        }
        let all = |k: &str| (req.mode_neutralizes)(k) || req.optional_calls.iter().any(|n| n == k);
        let Some(retry) = self.run(bundle, at, req, &all) else {
            tracing::warn!(
                program = req.name,
                reason = %e,
                "signed load refused, and the retry without the optional kfuncs replaces one \
                 the build did not allow: the program loads unsigned"
            );
            return None;
        };
        match retry {
            Ok(fd) => Some((
                Ok(fd),
                Some(DegradedProgram {
                    name: req.name.to_owned(),
                    kfuncs: req.optional_calls.to_vec(),
                    declared: true,
                    reason: e.to_string(),
                }),
            )),
            Err(_) => Some((Err(e), None)),
        }
    }

    /// One signed load with the kfuncs `neutralize` names replaced. `None`
    /// when the program has to go unsigned: a kfunc to replace the build did
    /// not mark replaceable, or the loader itself did not get through.
    fn run(
        &self,
        bundle: &Bundle,
        at: usize,
        req: &Request<'_>,
        neutralize: &dyn Fn(&str) -> bool,
    ) -> Option<Result<OwnedFd, KfuncLoaderError>> {
        let program = &bundle.object.programs[at];
        let neutral_mask = neutral_mask(&program.kfuncs, program.neutralizable, neutralize)?;
        let inputs = run::Inputs {
            program,
            signature: bundle.signatures.get(at)?,
            keyring: self.keyring,
            map_fds: &self.map_fds,
            prog_btf_fd: req.prog_btf_fd,
            prog_ifindex: req.prog_ifindex,
            prog_flags: req.prog_flags,
            neutral_mask,
        };
        match run::load(&inputs) {
            Ok(fd) => {
                let _ = CERTIFICATE.set(bundle.cert_sha256);
                Some(Ok(fd))
            }
            Err(run::Failure::Program(e)) => Some(Err(e)),
            Err(run::Failure::Loader(why)) => {
                tracing::warn!(
                    program = req.name,
                    reason = %why,
                    "signed loader refused, the program loads unsigned"
                );
                None
            }
        }
    }

    /// Add this object's counts to the process's, once it loaded.
    pub(super) fn commit(&self) {
        SIGNED.fetch_add(self.signed.get(), Ordering::Relaxed);
        UNSIGNED.fetch_add(self.unsigned.get(), Ordering::Relaxed);
    }
}

/// The mask of the kfuncs `neutralize` names, `None` when one of them is not
/// among those the build allowed the host to replace.
fn neutral_mask(
    kfuncs: &[String],
    neutralizable: u64,
    neutralize: &dyn Fn(&str) -> bool,
) -> Option<u64> {
    let mut mask = 0u64;
    for (j, name) in kfuncs.iter().enumerate() {
        if !neutralize(name) {
            continue;
        }
        let bit = 1u64.checked_shl(u32::try_from(j).ok()?)?;
        if neutralizable & bit == 0 {
            return None;
        }
        mask |= bit;
    }
    Some(mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_context_fields_do_not_overlap_and_the_fds_come_last() {
        let fields = [
            (ctx::TOKEN_FD, 4),
            (ctx::PROG_BTF_FD, 4),
            (ctx::PROG_IFINDEX, 4),
            (ctx::PROG_FLAGS, 4),
            (ctx::NEUTRAL_MASK, 8),
            (ctx::LOG_BUF, 8),
            (ctx::LOG_SIZE, 4),
            (ctx::LOG_LEVEL, 4),
            (ctx::OUT_PROG_FD, 4),
            (ctx::OUT_RESULT, 4),
            (ctx::OUT_FAILED_KFUNC, 4),
        ];
        let mut end = 0usize;
        for (at, size) in fields {
            let at = usize::from(at.cast_unsigned());
            assert!(at >= end, "field at {at} overlaps the one before");
            assert_eq!(at % size, 0, "field at {at} is aligned");
            end = at + size;
        }
        assert!(ctx::FDS >= end);
    }

    #[test]
    fn slot_zero_is_never_a_module() {
        assert_eq!(fds_base(0), 1);
        assert_eq!(fds_base(3), 3);
        assert_eq!(ctx_size(0, 1), 64);
        assert_eq!(ctx_size(3, 2) % 8, 0);
    }

    #[test]
    fn only_a_replaceable_kfunc_is_replaced() {
        let kfuncs = vec!["a".to_owned(), "b".to_owned(), "c".to_owned()];
        assert_eq!(neutral_mask(&kfuncs, 0b101, &|k| k == "c"), Some(0b100));
        assert_eq!(neutral_mask(&kfuncs, 0b101, &|_| false), Some(0));
        assert_eq!(
            neutral_mask(&kfuncs, 0b101, &|k| k == "b"),
            None,
            "the build did not allow b to be replaced: the program goes unsigned"
        );
    }

    fn prog_load_error(errno: i32) -> KfuncLoaderError {
        KfuncLoaderError::ProgLoad {
            name: "xdp_firewall".to_owned(),
            prog_type: 6,
            expected_attach_type: 0,
            errno,
            log: String::new(),
        }
    }

    #[test]
    fn only_a_permission_error_under_an_attached_guard_is_the_guard_refusing() {
        assert!(refused_by_guard(&prog_load_error(1), true));
        assert!(refused_by_guard(&prog_load_error(-1), true));
        assert!(!refused_by_guard(&prog_load_error(1), false));
        assert!(!refused_by_guard(&prog_load_error(22), true));
        assert!(!refused_by_guard(
            &KfuncLoaderError::MissingFunction {
                name: "x".to_owned()
            },
            true
        ));
    }

    #[test]
    fn the_guard_refusal_names_the_guard_and_the_program() {
        let e = KfuncLoaderError::RefusedByLoadGuard {
            name: "xdp_firewall".to_owned(),
        };
        let text = e.to_string();
        assert!(text.contains("xdp_firewall"));
        assert!(text.contains("guard"));
        assert!(text.contains("signed"));
    }

    #[test]
    fn a_probe_refused_under_the_guard_says_the_guard_refused_it() {
        assert!(guard_refusal_note(libc::EPERM, true).contains("guard on program loads"));
        assert!(guard_refusal_note(-libc::EPERM, true).contains("never signed"));
        assert_eq!(guard_refusal_note(libc::EPERM, false), "");
        assert_eq!(guard_refusal_note(libc::EINVAL, true), "");
    }

    #[test]
    fn the_certificate_digest_is_lowercase_hex() {
        let mut d = [0u8; 32];
        d[0] = 0xab;
        d[31] = 0x0f;
        let h = hex(&d);
        assert_eq!(h.len(), 64);
        assert!(h.starts_with("ab00"));
        assert!(h.ends_with("0f"));
    }

    #[test]
    fn without_a_verifying_kernel_or_a_keyring_nothing_turns_on() {
        let dir = std::path::PathBuf::from("/nonexistent");
        assert_eq!(install(&dir, Some(1), false), Install::KernelDoesNotVerify);
        assert_eq!(install(&dir, None, true), Install::NoKeyring);
    }

    #[test]
    fn a_bundle_directory_is_read_by_object_digest() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bundle = Bundle {
            object: generate::GeneratedObject {
                elf_sha256: [3; 32],
                maps: Vec::new(),
                programs: Vec::new(),
            },
            cert_sha256: [4; 32],
            signatures: Vec::new(),
        };
        std::fs::write(
            dir.path().join("xdp-firewall.loaders"),
            bundle::encode(&bundle).expect("encoded"),
        )
        .expect("write");
        std::fs::write(dir.path().join("broken.loaders"), b"nope").expect("write");
        std::fs::write(dir.path().join("xdp-firewall"), b"elf").expect("write");
        let (bundles, unreadable) = read_bundles(dir.path());
        assert_eq!(bundles.len(), 1);
        assert_eq!(bundles[&[3; 32]].cert_sha256, [4; 32]);
        assert_eq!(unreadable.len(), 1);
    }
}
