//! The guard on the agent's own eBPF objects: the sets of map and link ids
//! the kernel refuses to anybody else, the thread groups allowed past it, and
//! the two LSM links that decide it.
//!
//! The ids are the agent's own descriptors as `/proc/self/fdinfo` lists them,
//! re-read on a timer: a map or a link the agent opens later is protected at
//! the next reading, and one it closed stops being protected rather than
//! leaving a stale id that a later object could be handed by the kernel.
//!
//! The allowed tasks are the agent and, where it runs rootless, the warden,
//! whose inventory opens the agent's links by id to read where they sit. Each
//! is named by its thread group in its own pid namespace, so a task in a
//! container is compared the way the container numbers it.

use std::collections::HashSet;
use std::os::fd::{OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use aya::maps::{Array, HashMap as AyaHashMap, MapData};
pub use ebpf_common::bpf_guard::{BPF_GUARD_CMD_PROGRAM_3, BPF_GUARD_CMD_PROGRAM_4};
use ebpf_common::bpf_guard::{BPF_GUARD_CONFIG_SLOT, BpfGuardConfig, BpfGuardTask};
use ebpf_common::exec_network::kernel_dev;
use ebpfsentinel_warden_client::{ReconnectingClient, TaskIdentity};
use tracing::{debug, info, warn};

use super::kfunc;
use super::kfunc_attach;
use super::loader::EbpfLoader;
use super::map_store::MapStore;

/// The object the guard is loaded from.
pub const BPF_GUARD_OBJECT: &str = "lsm-bpf-guard";
/// The program deciding map descriptors.
pub const BPF_GUARD_MAP_PROGRAM: &str = "bpf_guard_map";

/// What the agent can say about the guard, for the start-up log and the
/// kernel-features endpoint.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BpfGuardStatus {
    /// Both hooks are attached and the sets are written.
    pub protected: bool,
    /// How many of the agent's maps the kernel refuses to open for writing
    /// to anybody else.
    pub maps: usize,
    /// How many of the agent's links the kernel refuses to hand out.
    pub links: usize,
    /// How many thread groups are allowed past the guard.
    pub tasks: usize,
    /// Why the node is unprotected, in one sentence. `None` when it is
    /// protected, and before the agent has tried.
    pub reason: Option<String>,
}

static STATUS: OnceLock<Mutex<BpfGuardStatus>> = OnceLock::new();

fn status_cell() -> &'static Mutex<BpfGuardStatus> {
    STATUS.get_or_init(|| Mutex::new(BpfGuardStatus::default()))
}

/// Publish what the agent can say about the guard.
pub fn publish_status(status: BpfGuardStatus) {
    let mut held = status_cell()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *held = status;
}

/// What the agent can currently say about the guard.
#[must_use]
pub fn status() -> BpfGuardStatus {
    status_cell()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// What the guard needs off the running kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuardLayout {
    /// The configuration slot, not yet armed.
    pub config: BpfGuardConfig,
    /// The `bpf` program written for this kernel's arity of the hook.
    pub cmd_program: &'static str,
}

/// Read off the running kernel's BTF where a map keeps its id and how many
/// parameters the `bpf` hook takes.
///
/// # Errors
///
/// Returns what the kernel's BTF does not describe.
pub fn resolve_layout() -> Result<GuardLayout, String> {
    let params = kfunc::vmlinux_func_param_count("bpf_lsm_bpf")
        .map_err(|e| format!("the kernel BTF is unreadable: {e}"))?
        .ok_or_else(|| "the kernel BTF has no `bpf_lsm_bpf` hook".to_string())?;
    let cmd_program = cmd_program_for(params).ok_or_else(|| {
        format!("the kernel's `bpf` hook takes {params} arguments, where 3 or 4 are understood")
    })?;
    let map_id = kfunc::vmlinux_struct_member_offsets("bpf_map", &["id"])
        .map_err(|e| format!("the kernel BTF does not describe `bpf_map`: {e}"))?
        .first()
        .copied()
        .flatten()
        .ok_or_else(|| "the kernel BTF has no `bpf_map.id`".to_string())?;
    Ok(GuardLayout {
        config: BpfGuardConfig { map_id, valid: 0 },
        cmd_program,
    })
}

/// The `bpf` program for a hook taking `params` parameters.
#[must_use]
pub fn cmd_program_for(params: u32) -> Option<&'static str> {
    match params {
        3 => Some(BPF_GUARD_CMD_PROGRAM_3),
        4 => Some(BPF_GUARD_CMD_PROGRAM_4),
        _ => None,
    }
}

/// The entry the kernel compares for `identity`.
#[must_use]
pub fn task_entry(identity: &TaskIdentity) -> BpfGuardTask {
    BpfGuardTask {
        // `stat(2)` encodes a device one way and the kernel compares it in
        // its own encoding.
        ns_dev: u64::from(kernel_dev(
            libc::major(identity.pid_ns_dev),
            libc::minor(identity.pid_ns_dev),
        )),
        ns_ino: identity.pid_ns_ino,
        tgid: identity.tgid,
        _pad: 0,
    }
}

/// Set to the warden's control socket when the agent runs rootless.
const WARDEN_SOCK_ENV: &str = "EBPFSENTINEL_WARDEN_SOCK";

/// The thread groups allowed past the guard: the agent, and the warden when
/// the agent runs beside one.
pub struct GuardTasks {
    warden: Option<ReconnectingClient>,
}

impl GuardTasks {
    /// The warden when the environment names one.
    #[must_use]
    pub fn from_env() -> Self {
        let warden = std::env::var_os(WARDEN_SOCK_ENV)
            .filter(|p| !p.is_empty())
            .map(|sock| ReconnectingClient::new(PathBuf::from(sock)));
        Self { warden }
    }

    /// The entries to write, read now: a warden that restarted is another
    /// thread group. Blocks on the warden's socket.
    ///
    /// # Errors
    ///
    /// Returns why the agent cannot name itself, which leaves nothing to
    /// allow. A warden that does not answer is left out and logged instead:
    /// its reads of the agent's links are refused until it answers again.
    pub fn read(&mut self) -> Result<Vec<BpfGuardTask>, String> {
        let me = TaskIdentity::of_self()
            .map_err(|e| format!("the agent's own pid namespace is unreadable: {e}"))?;
        let mut tasks = vec![task_entry(&me)];
        if let Some(client) = self.warden.as_mut() {
            match client.identity() {
                Ok(identity) => tasks.push(task_entry(&identity)),
                Err(e) => warn!("the warden did not name itself, so the guard refuses it too: {e}"),
            }
        }
        Ok(tasks)
    }
}

/// The map and link ids a process holds a descriptor on, read off its
/// `fdinfo` directory.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OwnIds {
    pub maps: HashSet<u32>,
    pub links: HashSet<u32>,
}

/// The ids named by one `fdinfo` entry.
fn ids_in(text: &str, ids: &mut OwnIds) {
    for line in text.lines() {
        let mut parts = line.splitn(2, ':');
        let (Some(key), Some(value)) = (parts.next(), parts.next()) else {
            continue;
        };
        let Ok(id) = value.trim().parse::<u32>() else {
            continue;
        };
        match key.trim() {
            "map_id" => {
                ids.maps.insert(id);
            }
            "link_id" => {
                ids.links.insert(id);
            }
            _ => {}
        }
    }
}

/// The map and link ids held through the descriptors under `fdinfo_dir`.
///
/// A descriptor closed between the listing and the read is skipped: it is
/// no longer held, which is what the answer is about.
#[must_use]
pub fn own_ids_in(fdinfo_dir: &Path) -> OwnIds {
    let mut ids = OwnIds::default();
    let Ok(entries) = std::fs::read_dir(fdinfo_dir) else {
        return ids;
    };
    for entry in entries.flatten() {
        if let Ok(text) = std::fs::read_to_string(entry.path()) {
            ids_in(&text, &mut ids);
        }
    }
    ids
}

/// The map and link ids the agent holds.
#[must_use]
pub fn own_ids() -> OwnIds {
    own_ids_in(Path::new("/proc/self/fdinfo"))
}

/// The configuration slot, the allowed tasks and the two protected sets.
pub struct BpfGuardMaps {
    config: Array<MapData, BpfGuardConfig>,
    tasks: Array<MapData, BpfGuardTask>,
    maps: AyaHashMap<MapData, u32, u8>,
    links: AyaHashMap<MapData, u32, u8>,
    held: OwnIds,
    task_count: usize,
}

impl BpfGuardMaps {
    /// Take the four maps out of a loaded guard object.
    ///
    /// # Errors
    ///
    /// Returns an error when a map is missing or carries another shape.
    pub fn new(ebpf: &mut dyn MapStore) -> Result<Self, anyhow::Error> {
        let mut take = |name: &str| {
            ebpf.take_map(name)
                .ok_or_else(|| anyhow::anyhow!("map '{name}' not found"))
        };
        Ok(Self {
            config: Array::try_from(take("BPF_GUARD_CONFIG")?)?,
            tasks: Array::try_from(take("BPF_GUARD_TASKS")?)?,
            maps: AyaHashMap::try_from(take("BPF_GUARD_MAPS")?)?,
            links: AyaHashMap::try_from(take("BPF_GUARD_LINKS")?)?,
            held: OwnIds::default(),
            task_count: 0,
        })
    }

    /// Write the allowed tasks, every slot, so a task no longer named leaves
    /// none of its entry behind.
    ///
    /// # Errors
    ///
    /// Returns the first write the kernel refused.
    pub fn set_tasks(&mut self, tasks: &[BpfGuardTask]) -> Result<(), anyhow::Error> {
        let capacity = self.tasks.len();
        if u32::try_from(tasks.len()).map_or(true, |n| n > capacity) {
            anyhow::bail!("{} allowed tasks, where {capacity} fit", tasks.len());
        }
        let empty = BpfGuardTask {
            ns_dev: 0,
            ns_ino: 0,
            tgid: 0,
            _pad: 0,
        };
        for slot in 0..capacity {
            let task = usize::try_from(slot)
                .ok()
                .and_then(|i| tasks.get(i))
                .unwrap_or(&empty);
            self.tasks
                .set(slot, task, 0)
                .map_err(|e| anyhow::anyhow!("BPF_GUARD_TASKS write failed: {e}"))?;
        }
        self.task_count = tasks.len();
        Ok(())
    }

    /// Make the kernel's protected sets exactly `ids`.
    ///
    /// New ids go in before stale ones come out, so an object is never
    /// unprotected while the agent still holds it.
    ///
    /// # Errors
    ///
    /// Returns the first write the kernel refused.
    pub fn replace(&mut self, ids: &OwnIds) -> Result<(), anyhow::Error> {
        sync(&mut self.maps, &self.held.maps, &ids.maps, "BPF_GUARD_MAPS")?;
        sync(
            &mut self.links,
            &self.held.links,
            &ids.links,
            "BPF_GUARD_LINKS",
        )?;
        self.held.clone_from(ids);
        Ok(())
    }

    /// Write the configuration as valid, which is what turns the guard on.
    ///
    /// # Errors
    ///
    /// Returns the kernel's refusal of the write.
    pub fn arm(&mut self, config: BpfGuardConfig) -> Result<(), anyhow::Error> {
        let slot = BpfGuardConfig { valid: 1, ..config };
        self.config
            .set(BPF_GUARD_CONFIG_SLOT, &slot, 0)
            .map_err(|e| anyhow::anyhow!("BPF_GUARD_CONFIG write failed: {e}"))
    }

    /// How many maps, links and tasks the kernel holds.
    #[must_use]
    pub fn counts(&self) -> (usize, usize, usize) {
        (self.held.maps.len(), self.held.links.len(), self.task_count)
    }
}

fn sync(
    map: &mut AyaHashMap<MapData, u32, u8>,
    held: &HashSet<u32>,
    wanted: &HashSet<u32>,
    name: &str,
) -> Result<(), anyhow::Error> {
    for id in wanted.difference(held) {
        map.insert(id, &1, 0)
            .map_err(|e| anyhow::anyhow!("{name} write failed: {e}"))?;
    }
    for id in held.difference(wanted) {
        if let Err(e) = map.remove(id) {
            debug!("{name} entry already gone: {e}");
        }
    }
    Ok(())
}

/// Holds the two LSM links. Dropping it detaches both.
#[derive(Default)]
pub struct BpfGuardAttacher {
    links: Vec<OwnedFd>,
}

impl BpfGuardAttacher {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach the map hook and `cmd_program` of `loader`, or neither.
    ///
    /// # Errors
    ///
    /// Returns the reason the kernel gave for the program it refused to load
    /// or the hook it refused to attach.
    pub fn attach(&mut self, loader: &EbpfLoader, cmd_program: &str) -> Result<(), String> {
        let mut links = Vec::with_capacity(2);
        for program in [BPF_GUARD_MAP_PROGRAM, cmd_program] {
            if let Some(refusal) = loader.refused_program(program) {
                return Err(format!("the kernel refused `{program}`: {refusal}"));
            }
            let prog_fd: RawFd = loader
                .program_fd(program)
                .ok_or_else(|| format!("program `{program}` is not in the loaded object"))?;
            links.push(kfunc_attach::attach_lsm(program, prog_fd).map_err(|e| e.to_string())?);
        }
        self.links = links;
        info!("the agent's maps and links are guarded on the bpf and bpf_map hooks");
        Ok(())
    }

    /// Whether both links are held.
    #[must_use]
    pub fn attached(&self) -> bool {
        self.links.len() == 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fdinfo_names_map_and_link_ids_and_nothing_else() {
        let mut ids = OwnIds::default();
        ids_in(
            "pos:\t0\nflags:\t02000002\nmnt_id:\t15\nino:\t1057\nmap_type:\t1\nmap_id:\t42\n",
            &mut ids,
        );
        ids_in(
            "pos:\t0\nlink_type:\ttcx\nlink_id:\t7\nprog_tag:\t00\nprog_id:\t99\n",
            &mut ids,
        );
        ids_in("pos:\t0\nflags:\t0100000\n", &mut ids);
        assert_eq!(ids.maps, HashSet::from([42]));
        assert_eq!(ids.links, HashSet::from([7]));
    }

    #[test]
    fn a_missing_fdinfo_directory_holds_nothing() {
        assert_eq!(
            own_ids_in(Path::new("/nonexistent/fdinfo")),
            OwnIds::default()
        );
    }

    #[test]
    fn the_task_entry_carries_the_kernel_device_encoding() {
        // nsfs is device 0:4 everywhere, which both encodings agree on; a
        // major above 0 is where they part.
        let dev = libc::makedev(8, 1);
        let entry = task_entry(&TaskIdentity {
            tgid: 7,
            pid_ns_dev: dev,
            pid_ns_ino: 4_026_531_836,
        });
        assert_eq!(entry.ns_dev, u64::from(kernel_dev(8, 1)));
        assert_eq!(entry.ns_ino, 4_026_531_836);
        assert_eq!(entry.tgid, 7);
    }

    #[test]
    fn the_running_kernel_describes_what_the_guard_reads() {
        // A host without BTF has nothing to say.
        if !Path::new("/sys/kernel/btf/vmlinux").exists() {
            return;
        }
        let layout = resolve_layout().expect("the kernel describes the bpf hook and bpf_map");
        assert!([BPF_GUARD_CMD_PROGRAM_3, BPF_GUARD_CMD_PROGRAM_4].contains(&layout.cmd_program));
        assert_eq!(layout.config.valid, 0);
    }

    #[test]
    fn each_arity_of_the_bpf_hook_has_its_program() {
        assert_eq!(cmd_program_for(3), Some("bpf_guard_cmd3"));
        assert_eq!(cmd_program_for(4), Some("bpf_guard_cmd4"));
        assert_eq!(cmd_program_for(5), None);
    }

    #[test]
    fn status_publishes_and_reads_back() {
        let s = BpfGuardStatus {
            protected: false,
            reason: Some("no lsm=bpf".to_string()),
            ..BpfGuardStatus::default()
        };
        publish_status(s.clone());
        assert_eq!(status(), s);
    }
}
