//! The SHA-256 the kernel took of each executable at its exec, read back by
//! the process table.
//!
//! One object, three hooks: the sleepable exec hook asks IMA for the hash of
//! the file the task now runs and keeps it against the file's size and change
//! times; a write-open and a truncation drop it. See
//! `ebpf_common::exec_digest` for the reasoning, and the object's source for
//! the hooks.
//!
//! What it changes for a rule is when the digest exists, never what it is: a
//! kernel entry is the SHA-256 of the whole file, the same function the
//! agent's own read computes, so it is reported as [`DigestSource::Content`].
//! Anything the kernel did not answer for, a file with fs-verity on, one
//! larger than it hashes, one IMA hashes with another algorithm, or one it
//! forgot, is asked of the userspace digester as before.

use std::os::fd::{OwnedFd, RawFd};
use std::sync::{Arc, Mutex, OnceLock};

use aya::maps::{Array, HashMap as AyaHashMap, MapData};
use domain::process::digest::{DigestSource, ExeHash};
use ebpf_common::exec_digest::{
    EXEC_DIGEST_ALGO_SHA256, EXEC_DIGEST_CONFIG_SLOT, ExecDigestConfig, ExecDigestEntry,
    ExecDigestKey,
};
use ebpf_common::exec_network::kernel_dev;
use ports::secondary::executable_digest_port::ExecutableDigester;
use ports::secondary::process_executable_port::ProcessExecutableReader;
use tracing::info;

use super::kfunc;
use super::kfunc_attach;
use super::loader::EbpfLoader;
use super::map_store::MapStore;

/// The object the digests are taken by.
pub const EXEC_DIGEST_OBJECT: &str = "lsm-exec-digest";
/// The sleepable program taking the hash at exec.
pub const EXEC_DIGEST_EXEC_PROGRAM: &str = "exec_digest_exec";
/// The program dropping an entry at a write-open.
pub const EXEC_DIGEST_OPEN_PROGRAM: &str = "exec_digest_file_open";
/// The program dropping an entry at a truncation by path.
pub const EXEC_DIGEST_TRUNCATE_PROGRAM: &str = "exec_digest_path_truncate";

/// The kfuncs the exec hook calls, which the kernel offers only to a
/// sleepable LSM program.
pub const EXEC_DIGEST_KFUNCS: [&str; 2] = ["bpf_get_task_exe_file", "bpf_put_file"];

/// The security module the hash is asked of.
pub const EXEC_DIGEST_MODULE: &str = "ima";

/// What the agent can say about the kernel digests, for the start-up log and
/// the kernel-features endpoint.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExecDigestStatus {
    /// The three hooks are attached and the exec hook is hashing.
    pub attached: bool,
    /// Why the kernel is not hashing, in one sentence. `None` when it is,
    /// and when it is off in the configuration.
    pub reason: Option<String>,
}

static STATUS: OnceLock<Mutex<ExecDigestStatus>> = OnceLock::new();

fn status_cell() -> &'static Mutex<ExecDigestStatus> {
    STATUS.get_or_init(|| Mutex::new(ExecDigestStatus::default()))
}

/// Publish what the agent can say about the kernel digests.
pub fn publish_status(status: ExecDigestStatus) {
    let mut held = status_cell()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *held = status;
}

/// What the agent can currently say about the kernel digests.
#[must_use]
pub fn status() -> ExecDigestStatus {
    status_cell()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// Why this host cannot hash in the kernel, or `None` when it can: the BPF
/// LSM active, IMA among the security modules, and both kfuncs usable from a
/// sleepable LSM program.
#[must_use]
pub fn host_refusal(
    lsm: &super::lsm_probe::BpfLsmStatus,
    files: &super::file_kfunc_probe::FileKfuncStatus,
) -> Option<String> {
    if !lsm.active {
        let reason = lsm
            .reason
            .clone()
            .unwrap_or_else(|| "the BPF LSM is not active on this host".to_string());
        return Some(match &lsm.remedy {
            Some(remedy) => format!("{reason}; {remedy}"),
            None => reason,
        });
    }
    if !lsm.modules.iter().any(|m| m == EXEC_DIGEST_MODULE) {
        return Some(format!(
            "IMA is not among the active security modules ({}), and the kernel hashes a file \
             only through it",
            lsm.modules.join(",")
        ));
    }
    for name in EXEC_DIGEST_KFUNCS {
        match files.kfuncs.iter().find(|k| k.name == name) {
            Some(k) if k.usable => {}
            Some(k) => {
                return Some(
                    k.reason
                        .clone()
                        .unwrap_or_else(|| format!("{name} is not usable on this host")),
                );
            }
            None => return Some(format!("{name} was not probed")),
        }
    }
    None
}

/// The fifteen offsets the hooks read, off the running kernel's BTF.
///
/// All of them or an error: a hook handed a partial layout would read some
/// other field as a change time and keep a digest across a rewrite.
///
/// # Errors
///
/// Returns the struct or member the kernel's BTF does not describe.
pub fn resolve_offsets() -> Result<ExecDigestConfig, String> {
    let many = |structure: &str, members: &[&str]| -> Result<Vec<u32>, String> {
        let found = kfunc::vmlinux_struct_member_offsets(structure, members)
            .map_err(|e| format!("the kernel BTF does not describe `{structure}`: {e}"))?;
        members
            .iter()
            .zip(found)
            .map(|(member, offset)| {
                offset.ok_or_else(|| format!("the kernel BTF has no `{structure}.{member}`"))
            })
            .collect()
    };
    let one = |structure: &str, member: &str| -> Result<u32, String> {
        Ok(many(structure, &[member])?[0])
    };
    let file = many("file", &["f_inode", "f_mode"])?;
    let inode = many(
        "inode",
        &[
            "i_ino",
            "i_sb",
            "i_size",
            "i_flags",
            "i_mtime_sec",
            "i_mtime_nsec",
            "i_ctime_sec",
            "i_ctime_nsec",
        ],
    )?;
    Ok(ExecDigestConfig {
        task_mm: one("task_struct", "mm")?,
        mm_exe_file: one("mm_struct", "exe_file")?,
        file_inode: file[0],
        file_mode: file[1],
        inode_ino: inode[0],
        inode_sb: inode[1],
        sb_dev: one("super_block", "s_dev")?,
        inode_size: inode[2],
        inode_flags: inode[3],
        inode_mtime_sec: inode[4],
        inode_mtime_nsec: inode[5],
        inode_ctime_sec: inode[6],
        inode_ctime_nsec: inode[7],
        path_dentry: one("path", "dentry")?,
        dentry_inode: one("dentry", "d_inode")?,
        valid: 0,
    })
}

/// The key the kernel files a `stat(2)` identity under.
#[must_use]
pub fn key_from_stat(dev: u64, ino: u64) -> ExecDigestKey {
    ExecDigestKey {
        ino,
        dev: kernel_dev(libc::major(dev), libc::minor(dev)),
        _pad: 0,
    }
}

/// The digest an entry states, when IMA answered it as SHA-256.
#[must_use]
pub fn digest_of(entry: &ExecDigestEntry) -> Option<ExeHash> {
    (entry.algo == EXEC_DIGEST_ALGO_SHA256)
        .then(|| ExeHash::new(DigestSource::Content, entry.digest))
}

/// The configuration slot and the digests, taken out of the loaded object.
pub struct ExecDigestMaps {
    config: Array<MapData, ExecDigestConfig>,
    files: AyaHashMap<MapData, ExecDigestKey, ExecDigestEntry>,
}

impl ExecDigestMaps {
    /// Take both maps out of a loaded object.
    ///
    /// # Errors
    ///
    /// Returns an error when a map is missing or carries another shape.
    pub fn new(ebpf: &mut dyn MapStore) -> Result<Self, anyhow::Error> {
        let config = Array::try_from(
            ebpf.take_map("EXEC_DIGEST_CONFIG")
                .ok_or_else(|| anyhow::anyhow!("map 'EXEC_DIGEST_CONFIG' not found"))?,
        )?;
        let files = AyaHashMap::try_from(
            ebpf.take_map("EXEC_DIGEST_FILES")
                .ok_or_else(|| anyhow::anyhow!("map 'EXEC_DIGEST_FILES' not found"))?,
        )?;
        Ok(Self { config, files })
    }

    /// Write the offsets, which is what turns the hooks on.
    ///
    /// # Errors
    ///
    /// Returns the kernel's refusal of the write.
    pub fn arm(&mut self, offsets: ExecDigestConfig) -> Result<(), anyhow::Error> {
        let slot = ExecDigestConfig {
            valid: 1,
            ..offsets
        };
        self.config
            .set(EXEC_DIGEST_CONFIG_SLOT, &slot, 0)
            .map_err(|e| anyhow::anyhow!("EXEC_DIGEST_CONFIG write failed: {e}"))
    }

    fn lookup(&self, key: &ExecDigestKey) -> Option<ExecDigestEntry> {
        self.files.get(key, 0).ok()
    }
}

/// Holds the three LSM links. Dropping it detaches them.
#[derive(Default)]
pub struct ExecDigestAttacher {
    links: Vec<OwnedFd>,
}

impl ExecDigestAttacher {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach the invalidation hooks first and the exec hook last, or none.
    ///
    /// An entry taken while nothing drops it could outlive a rewrite, so the
    /// hooks that drop entries are in place before the first one is taken.
    ///
    /// # Errors
    ///
    /// Returns the reason the kernel gave for the hook it refused.
    pub fn attach(&mut self, loader: &EbpfLoader) -> Result<(), String> {
        let mut links = Vec::with_capacity(3);
        for program in [
            EXEC_DIGEST_OPEN_PROGRAM,
            EXEC_DIGEST_TRUNCATE_PROGRAM,
            EXEC_DIGEST_EXEC_PROGRAM,
        ] {
            let prog_fd: RawFd = loader
                .program_fd(program)
                .ok_or_else(|| format!("program `{program}` is not in the loaded object"))?;
            links.push(kfunc_attach::attach_lsm(program, prog_fd).map_err(|e| e.to_string())?);
        }
        self.links = links;
        info!("executable digests attached on bprm_committed_creds, file_open and path_truncate");
        Ok(())
    }

    /// Whether all three links are held.
    #[must_use]
    pub fn attached(&self) -> bool {
        self.links.len() == 3
    }
}

/// The kernel's digests first, the agent's own read for anything the kernel
/// did not answer.
pub struct KernelExecutableDigester {
    maps: ExecDigestMaps,
    /// Held for the links, which keep the hooks attached.
    _attacher: ExecDigestAttacher,
    /// Names the overlay file the kernel keyed when a stat names a layer.
    executables: Arc<dyn ProcessExecutableReader>,
    fallback: Arc<dyn ExecutableDigester>,
}

impl KernelExecutableDigester {
    #[must_use]
    pub fn new(
        maps: ExecDigestMaps,
        attacher: ExecDigestAttacher,
        executables: Arc<dyn ProcessExecutableReader>,
        fallback: Arc<dyn ExecutableDigester>,
    ) -> Self {
        Self {
            maps,
            _attacher: attacher,
            executables,
            fallback,
        }
    }

    fn kernel_digest(&self, pid: u32, dev: u64, inode: u64) -> Option<ExeHash> {
        if let Some(entry) = self.maps.lookup(&key_from_stat(dev, inode)) {
            return digest_of(&entry);
        }
        let (kdev, kino) = self.executables.kernel_identity(pid, dev, inode)?;
        digest_of(&self.maps.lookup(&key_from_stat(kdev, kino))?)
    }
}

impl ExecutableDigester for KernelExecutableDigester {
    fn digest(&self, pid: u32, dev: u64, inode: u64) -> Option<ExeHash> {
        self.kernel_digest(pid, dev, inode)
            .or_else(|| self.fallback.digest(pid, dev, inode))
    }
}

#[cfg(test)]
mod tests {
    use super::super::file_kfunc_probe::{FileKfunc, FileKfuncStatus, SleepableStatus};
    use super::super::lsm_probe::BpfLsmStatus;
    use super::*;

    fn lsm(active: bool, modules: &[&str]) -> BpfLsmStatus {
        BpfLsmStatus {
            active,
            built: Some(true),
            modules: modules.iter().map(|m| (*m).to_string()).collect(),
            reason: (!active).then(|| "bpf is not in the lsm= list".to_string()),
            remedy: None,
        }
    }

    fn files(usable: bool) -> FileKfuncStatus {
        FileKfuncStatus {
            sleepable: SleepableStatus {
                loads: Some(usable),
                reason: None,
            },
            kfuncs: EXEC_DIGEST_KFUNCS
                .iter()
                .map(|name| FileKfunc {
                    name,
                    declared: Some(true),
                    usable,
                    reason: (!usable).then(|| format!("{name} refused")),
                })
                .collect(),
            remedy: None,
        }
    }

    #[test]
    fn a_host_hashes_only_with_the_bpf_lsm_ima_and_both_kfuncs() {
        assert_eq!(
            host_refusal(&lsm(true, &["bpf", "ima"]), &files(true)),
            None
        );
        let off = host_refusal(&lsm(false, &["ima"]), &files(true)).expect("refused");
        assert!(off.contains("lsm="), "{off}");
        let no_ima = host_refusal(&lsm(true, &["bpf", "landlock"]), &files(true)).expect("refused");
        assert!(no_ima.starts_with("IMA is not among"), "{no_ima}");
        assert!(no_ima.contains("bpf,landlock"), "{no_ima}");
        let refused = host_refusal(&lsm(true, &["bpf", "ima"]), &files(false)).expect("refused");
        assert_eq!(refused, "bpf_get_task_exe_file refused");
    }

    #[test]
    fn only_a_sha256_answer_is_a_digest_and_it_reads_as_content() {
        let mut entry = ExecDigestEntry {
            digest: [7; 32],
            algo: EXEC_DIGEST_ALGO_SHA256,
            ..ExecDigestEntry::default()
        };
        let hash = digest_of(&entry).expect("sha-256 is kept");
        assert_eq!(hash, ExeHash::new(DigestSource::Content, [7; 32]));
        // SHA-1 is 2 in the kernel's enum, and an error is negative: neither
        // is a digest a rule written as SHA-256 could match.
        entry.algo = 2;
        assert!(digest_of(&entry).is_none());
        entry.algo = -95;
        assert!(digest_of(&entry).is_none());
    }

    #[test]
    fn the_stat_device_is_keyed_in_the_kernel_encoding() {
        let key = key_from_stat(libc::makedev(259, 3), 42);
        assert_eq!(key.dev, kernel_dev(259, 3));
        assert_eq!(key.ino, 42);
    }

    #[test]
    fn the_offsets_come_from_the_running_kernel_or_name_what_is_missing() {
        match resolve_offsets() {
            Ok(offsets) => {
                assert_eq!(offsets.valid, 0);
                assert_ne!(offsets.inode_mtime_sec, offsets.inode_ctime_sec);
                assert_ne!(offsets.file_inode, offsets.file_mode);
            }
            Err(reason) => assert!(reason.contains("BTF"), "{reason}"),
        }
    }

    #[test]
    fn the_default_status_says_nothing_is_attached() {
        let s = ExecDigestStatus::default();
        assert!(!s.attached);
        assert!(s.reason.is_none());
    }
}
