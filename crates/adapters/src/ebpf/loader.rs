use std::collections::HashMap;
use std::hash::BuildHasher;
use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};
use std::path::Path;

use aya::{
    Ebpf, EbpfLoader as AyaEbpfLoader, VerifierLogLevel,
    maps::ProgramArray,
    programs::{SchedClassifier, TcAttachType, UProbe, Xdp, XdpFlags, tc},
};
use tracing::{debug, info, warn};

use super::kfunc::KfuncResolver;
use super::kfunc_attach;
use super::kfunc_loader::{self, KfuncClass};

/// Default BPF filesystem pin path for shared maps.
pub const DEFAULT_BPF_PIN_PATH: &str = "/sys/fs/bpf/ebpfsentinel";

/// Loads and attaches eBPF programs (XDP, TC, uprobe).
///
/// Wraps the `aya::Ebpf` instance and provides methods for
/// program lifecycle management (load, attach, detach).
pub struct EbpfLoader {
    ebpf: Ebpf,
    /// Owned link fds for netkit attachments. Dropping these detaches.
    netkit_links: Vec<OwnedFd>,
    /// Programs aya cannot load because they call kfuncs it can't relocate.
    /// Loaded via raw `BPF_PROG_LOAD` outside aya and keyed by program name;
    /// the fd owns the loaded program (dropping it unloads).
    kfunc_progs: HashMap<String, OwnedFd>,
    /// Owned link fds for raw XDP/TCX attachments of kfunc programs.
    kfunc_links: Vec<OwnedFd>,
    /// Independent `dup`s of the maps aya hosts for a kfunc object, keyed by
    /// map name. Captured at load time (aya exposes no fd accessor and pinning
    /// is refused on integrity kernels) so raw map syscalls — e.g. wiring a
    /// `ProgramArray` tail-call via [`Self::set_tail_call_raw`] — can reach the
    /// exact kernel map aya created. Empty for non-kfunc loads.
    kfunc_hosted_maps: HashMap<String, OwnedFd>,
}

/// Read back every map aya hosted, keyed by full ELF name, as an independent
/// owned fd. Each `aya::maps::Map` variant wraps a `MapData` whose `fd()` is
/// public; cloning it gives the kfunc loader a handle to the exact kernel map
/// aya created — pin-free and immune to the kernel's 15-byte name truncation.
fn hosted_map_fds(ebpf: &Ebpf) -> anyhow::Result<HashMap<String, OwnedFd>> {
    use aya::maps::Map;
    let mut hosted = HashMap::new();
    for (name, map) in ebpf.maps() {
        let data = match map {
            Map::Array(d)
            | Map::BloomFilter(d)
            | Map::CpuMap(d)
            | Map::DevMap(d)
            | Map::DevMapHash(d)
            | Map::HashMap(d)
            | Map::LpmTrie(d)
            | Map::LruHashMap(d)
            | Map::PerCpuArray(d)
            | Map::PerCpuHashMap(d)
            | Map::PerCpuLruHashMap(d)
            | Map::PerfEventArray(d)
            | Map::ProgramArray(d)
            | Map::Queue(d)
            | Map::RingBuf(d)
            | Map::SockHash(d)
            | Map::SockMap(d)
            | Map::Stack(d)
            | Map::StackTraceMap(d)
            | Map::Unsupported(d)
            | Map::XskMap(d) => d,
        };
        let owned = data
            .fd()
            .as_fd()
            .try_clone_to_owned()
            .map_err(|e| anyhow::anyhow!("clone hosted map `{name}` fd: {e}"))?;
        hosted.insert(name.to_owned(), owned);
    }
    Ok(hosted)
}

/// Load an ELF object through aya with the verifier log disabled on the happy
/// path, retrying once with aya's default (verbose) log only if the first
/// attempt fails — so a genuine rejection still carries its reason.
///
/// aya defaults its verifier log level to `LEVEL1 | STATS` and grows the log
/// buffer when the kernel returns `ENOSPC`, but that growth is capped. A large
/// yet *valid* program whose verbose log runs to several megabytes then fails
/// to load with `ENOSPC` even though verification itself passed. Loading with
/// the log disabled sidesteps the buffer entirely; the retry only ever runs
/// for a program that genuinely failed, where the log is bounded by the
/// rejection point and worth capturing.
fn aya_load(bytes: &[u8], pin_path: Option<&str>) -> Result<Ebpf, anyhow::Error> {
    let attempt = |level: VerifierLogLevel| -> Result<Ebpf, aya::EbpfError> {
        let mut loader = AyaEbpfLoader::new();
        loader.allow_unsupported_maps().verifier_log_level(level);
        if let Some(path) = pin_path {
            loader.map_pin_path(path);
        }
        loader.load(bytes)
    };
    match attempt(VerifierLogLevel::DISABLE) {
        Ok(ebpf) => Ok(ebpf),
        Err(_) => Ok(attempt(VerifierLogLevel::default())?),
    }
}

/// Load the raw kfunc programs, preferring a device-bound load when one is
/// requested and the object actually uses device-bound-only metadata kfuncs.
///
/// A device-bound load lets `bpf_xdp_metadata_rx_*` resolve against the target
/// device's `xdp_metadata_ops`. Drivers without that support make the verifier
/// reject the load; we then retry with the metadata kfuncs neutralized so the
/// program loads on any NIC (its wrapper already tolerates the missing data).
fn load_kfunc_with_metadata_fallback<S: BuildHasher>(
    elf: &[u8],
    resolver: &KfuncResolver,
    hosted: &HashMap<String, OwnedFd, S>,
    dev_bound_ifindex: Option<u32>,
) -> anyhow::Result<Vec<kfunc_loader::KfuncLoadedProgram>> {
    if dev_bound_ifindex.is_some() && kfunc_loader::uses_dev_bound_metadata_kfuncs(elf) {
        match kfunc_loader::load_kfunc_programs(elf, resolver, hosted, dev_bound_ifindex) {
            Ok(loaded) => {
                info!(
                    ifindex = dev_bound_ifindex,
                    "XDP metadata kfunc program loaded device-bound"
                );
                return Ok(loaded);
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "device-bound XDP load rejected (driver lacks xdp_metadata_ops?); \
                     retrying with metadata kfuncs neutralized"
                );
            }
        }
    }
    Ok(kfunc_loader::load_kfunc_programs(
        elf, resolver, hosted, None,
    )?)
}

impl EbpfLoader {
    /// Load an eBPF program from raw ELF bytes.
    ///
    /// Initializes aya-log for eBPF debug message forwarding (best-effort).
    /// Returns an error if the verifier rejects the program.
    pub fn load(program_bytes: &[u8]) -> Result<Self, anyhow::Error> {
        // `allow_unsupported_maps` (inside `aya_load`) lets aya create maps it
        // has no high-level wrapper for by passing the parsed definition
        // straight to `BPF_MAP_CREATE`.
        let mut ebpf = aya_load(program_bytes, None)?;

        // Initialize aya-log (best-effort — non-fatal if eBPF has no log statements)
        if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
            warn!("eBPF logger init failed (non-fatal): {e}");
        }

        info!("eBPF program loaded successfully");
        Ok(Self {
            ebpf,
            netkit_links: Vec::new(),
            kfunc_progs: HashMap::new(),
            kfunc_links: Vec::new(),
            kfunc_hosted_maps: HashMap::new(),
        })
    }

    /// Load an eBPF program with map pinning enabled.
    ///
    /// Maps with matching names across programs will be shared via the
    /// BPF filesystem. The first program to load creates and pins the map;
    /// subsequent programs reuse the pinned map automatically.
    ///
    /// Used for `INTERFACE_GROUPS`, `CT_CONFIG`, and other maps shared
    /// across tc-conntrack, xdp-firewall, tc-nat-ingress, tc-nat-egress.
    pub fn load_with_pin_path(program_bytes: &[u8], pin_path: &str) -> Result<Self, anyhow::Error> {
        Self::load_with_pin_path_dev_bound(program_bytes, pin_path, None)
    }

    /// Like [`Self::load_with_pin_path`], but for an XDP object that calls
    /// device-bound-only metadata kfuncs (`bpf_xdp_metadata_rx_*`).
    ///
    /// When `dev_bound_ifindex` is `Some` (caller policy: exactly one target
    /// interface), the program is first loaded device-bound to that netdev so
    /// the kfuncs resolve against its `xdp_metadata_ops` and read real hardware
    /// hints. If the driver lacks that support the verifier rejects the load,
    /// and the loader transparently falls back to neutralizing the metadata
    /// kfuncs (`r0 = -EOPNOTSUPP`) so the program still loads — the program's
    /// wrapper degrades gracefully, exactly as on a driver answering `-EOPNOTSUPP`.
    /// `None` (multiple or zero interfaces) always neutralizes, so a single
    /// program fd can attach to every interface.
    pub fn load_with_pin_path_dev_bound(
        program_bytes: &[u8],
        pin_path: &str,
        dev_bound_ifindex: Option<u32>,
    ) -> Result<Self, anyhow::Error> {
        // Ensure pin directory exists
        let path = Path::new(pin_path);
        if !path.exists() {
            std::fs::create_dir_all(path)?;
            info!(pin_path, "created BPF pin directory");
        }

        // kfunc calls are invisible to aya: it can neither relocate them nor
        // load a program that contains them. The resolver classifies the
        // object so each strategy is applied with surgical precision —
        // vmlinux-only kfuncs are pre-patched to their resolved btf ids and
        // aya loads them unchanged, while module kfuncs are pre-patched to a
        // sentinel (so aya still hosts the maps) and loaded outside aya.
        let mut kfunc_progs = HashMap::new();
        let mut kfunc_hosted_maps = HashMap::new();
        let resolver = if kfunc_loader::has_kfunc_calls(program_bytes) {
            Some(KfuncResolver::new()?)
        } else {
            None
        };

        let mut ebpf = match resolver {
            None => aya_load(program_bytes, Some(pin_path))?,
            Some(resolver) => match kfunc_loader::classify(program_bytes, &resolver)? {
                KfuncClass::None => aya_load(program_bytes, Some(pin_path))?,
                KfuncClass::VmlinuxOnly => {
                    let patched = kfunc_loader::prepatch_vmlinux_kfuncs(program_bytes, &resolver)?;
                    info!(pin_path, "loading vmlinux-only kfunc program via aya");
                    aya_load(&patched, Some(pin_path))?
                }
                KfuncClass::HasModule => {
                    // aya hosts the maps from the sentinel-patched ELF but
                    // cannot load a program that calls module or device-bound
                    // metadata kfuncs; the raw loader re-parses the same bytes,
                    // relocates against those maps, and issues BPF_PROG_LOAD
                    // with the module fd_array (and, when a single interface is
                    // targeted, device-bound to it). The maps' fds are read
                    // back from aya by full name.
                    let patched = kfunc_loader::prepatch_kfunc_calls(program_bytes)?;
                    let ebpf = aya_load(&patched, Some(pin_path))?;
                    let hosted = hosted_map_fds(&ebpf)?;
                    let loaded = load_kfunc_with_metadata_fallback(
                        &patched,
                        &resolver,
                        &hosted,
                        dev_bound_ifindex,
                    )?;
                    kfunc_hosted_maps = hosted;
                    for prog in loaded {
                        info!(program = %prog.name, "module-kfunc program loaded outside aya");
                        kfunc_progs.insert(prog.name, prog.fd);
                    }
                    ebpf
                }
            },
        };

        if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
            warn!("eBPF logger init failed (non-fatal): {e}");
        }

        info!(pin_path, "eBPF program loaded with map pinning");
        Ok(Self {
            ebpf,
            netkit_links: Vec::new(),
            kfunc_progs,
            kfunc_links: Vec::new(),
            kfunc_hosted_maps,
        })
    }

    /// Load a kfunc-free XDP object through the raw `BPF_PROG_LOAD` path (the
    /// same one used for module-kfunc programs) instead of via aya.
    ///
    /// A `ProgramArray` records the load attributes of the first program to
    /// reference it and rejects any later-inserted program whose attributes
    /// differ — `bpf_prog_map_compatible` compares `prog_type`, `jited`,
    /// `xdp_has_frags`, and `attach_func_proto`. The firewall and ratelimit
    /// programs that own `XDP_PROG_ARRAY` / `RL_PROG_ARRAY` are loaded outside
    /// aya because they call module kfuncs, so their tail-call targets — even
    /// the kfunc-free `xdp-firewall-reject` and `xdp-ratelimit-syncookie` —
    /// must take the identical path or the kernel refuses the slot update with
    /// `EINVAL`. aya still hosts the object's maps so they pin-share with the
    /// owner exactly as before; only the program is loaded raw.
    pub fn load_xdp_raw_with_pin_path(
        program_bytes: &[u8],
        pin_path: &str,
    ) -> Result<Self, anyhow::Error> {
        let path = Path::new(pin_path);
        if !path.exists() {
            std::fs::create_dir_all(path)?;
            info!(pin_path, "created BPF pin directory");
        }

        // aya hosts the maps (and pin-shares them with the owner program);
        // it never loads the program into the kernel — the raw loader does.
        let mut ebpf = aya_load(program_bytes, Some(pin_path))?;
        let hosted = hosted_map_fds(&ebpf)?;

        // The object declares no kfunc calls, so the resolver resolves nothing
        // and the fd_array is empty; the raw load path is what makes the
        // resulting program load-compatible with the kfunc-raw owner.
        let resolver = KfuncResolver::new()?;
        let loaded = kfunc_loader::load_kfunc_programs(program_bytes, &resolver, &hosted, None)?;

        let mut kfunc_progs = HashMap::new();
        for prog in loaded {
            info!(program = %prog.name, "kfunc-free XDP program loaded raw (tail-call compat)");
            kfunc_progs.insert(prog.name, prog.fd);
        }

        if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
            warn!("eBPF logger init failed (non-fatal): {e}");
        }

        info!(pin_path, "XDP program loaded raw with map pinning");
        Ok(Self {
            ebpf,
            netkit_links: Vec::new(),
            kfunc_progs,
            kfunc_links: Vec::new(),
            kfunc_hosted_maps: hosted,
        })
    }

    /// Clean up pinned maps from the BPF filesystem.
    ///
    /// Should be called on agent shutdown to avoid stale pins.
    pub fn cleanup_pin_path(pin_path: &str) {
        let path = Path::new(pin_path);
        if path.exists() {
            if let Err(e) = std::fs::remove_dir_all(path) {
                warn!(pin_path, error = %e, "failed to clean up BPF pin directory");
            } else {
                info!(pin_path, "cleaned up BPF pin directory");
            }
        }
    }

    /// Attach the XDP firewall program to the given network interface.
    ///
    /// Backward-compatible wrapper around `attach_xdp_program("xdp_firewall", ...)`.
    pub fn attach_xdp(&mut self, interface: &str, flags: XdpFlags) -> Result<(), anyhow::Error> {
        self.attach_xdp_program("xdp_firewall", interface, flags)
    }

    /// Attach a named XDP program to the given network interface.
    ///
    /// Attempts the requested `flags` mode first. If attachment fails and the
    /// mode is not already auto (default), falls back to `XdpFlags::default()`
    /// (kernel picks best available) and logs a warning.
    pub fn attach_xdp_program(
        &mut self,
        program_name: &str,
        interface: &str,
        flags: XdpFlags,
    ) -> Result<(), anyhow::Error> {
        if let Some(prog_fd) = self.kfunc_progs.get(program_name) {
            let raw = prog_fd.as_raw_fd();
            let mode_label = xdp_flags_label(flags);
            match kfunc_attach::attach_xdp(program_name, raw, interface, flags.bits()) {
                Ok(link) => {
                    self.kfunc_links.push(link);
                    info!(
                        program_name,
                        interface,
                        mode = mode_label,
                        "XDP kfunc program attached"
                    );
                    return Ok(());
                }
                Err(e) if flags.bits() != XdpFlags::default().bits() => {
                    warn!(
                        program_name,
                        interface,
                        requested_mode = mode_label,
                        error = %e,
                        "XDP kfunc attach failed with requested mode, falling back to auto"
                    );
                    let link = kfunc_attach::attach_xdp(
                        program_name,
                        raw,
                        interface,
                        XdpFlags::default().bits(),
                    )?;
                    self.kfunc_links.push(link);
                    info!(
                        program_name,
                        interface,
                        mode = xdp_flags_label(XdpFlags::default()),
                        "XDP kfunc program attached (fallback from {mode_label})"
                    );
                    return Ok(());
                }
                Err(e) => return Err(e.into()),
            }
        }

        let program: &mut Xdp = self
            .ebpf
            .program_mut(program_name)
            .ok_or_else(|| anyhow::anyhow!("program '{program_name}' not found in eBPF object"))?
            .try_into()?;

        program.load()?;

        let mode_label = xdp_flags_label(flags);
        match program.attach(interface, flags) {
            Ok(_) => {
                info!(
                    program_name,
                    interface,
                    mode = mode_label,
                    "XDP program attached"
                );
                Ok(())
            }
            Err(e) if flags.bits() != XdpFlags::default().bits() => {
                warn!(
                    program_name,
                    interface,
                    requested_mode = mode_label,
                    error = %e,
                    "XDP attach failed with requested mode, falling back to auto"
                );
                program.attach(interface, XdpFlags::default())?;
                let fallback_label = xdp_flags_label(XdpFlags::default());
                info!(
                    program_name,
                    interface,
                    mode = fallback_label,
                    "XDP program attached (fallback from {mode_label})"
                );
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Load a named XDP program without attaching it to any interface.
    ///
    /// Used for tail-call targets that are invoked via `ProgramArray`
    /// from another XDP program (e.g. `xdp-firewall-reject` called from
    /// `xdp-firewall`).
    pub fn load_xdp_program(&mut self, program_name: &str) -> Result<(), anyhow::Error> {
        if self.kfunc_progs.contains_key(program_name) {
            // The raw loader already issued BPF_PROG_LOAD; nothing to attach.
            info!(
                program_name,
                "XDP kfunc program already loaded (tail-call target, no attach)"
            );
            return Ok(());
        }

        let program: &mut Xdp = self
            .ebpf
            .program_mut(program_name)
            .ok_or_else(|| anyhow::anyhow!("program '{program_name}' not found in eBPF object"))?
            .try_into()?;

        program.load()?;
        info!(
            program_name,
            "XDP program loaded (tail-call target, no attach)"
        );
        Ok(())
    }

    /// Attach a TC (Traffic Control) classifier program to the given interface.
    ///
    /// On kernel >= 6.6, uses TCX (link-based attach with priority ordering,
    /// no qdisc needed). On older kernels, falls back to clsact qdisc +
    /// netlink attach. Aya handles the detection automatically.
    pub fn attach_tc_program(
        &mut self,
        program_name: &str,
        interface: &str,
    ) -> Result<(), anyhow::Error> {
        if let Some(prog_fd) = self.kfunc_progs.get(program_name) {
            // TCX (kernel >= 6.6) needs no qdisc; the raw helper mirrors aya's
            // ingress attach for programs aya never loaded.
            let link =
                kfunc_attach::attach_tcx(program_name, prog_fd.as_raw_fd(), interface, false)?;
            self.kfunc_links.push(link);
            info!(
                program_name,
                interface, "TC kfunc program attached (ingress)"
            );
            return Ok(());
        }

        // clsact qdisc is only needed for legacy netlink attach (kernel < 6.6).
        // TCX (kernel >= 6.6) doesn't use qdiscs. Best-effort, ignore errors.
        if let Err(e) = tc::qdisc_add_clsact(interface) {
            debug!(interface, error = %e, "qdisc_add_clsact skipped (TCX or already exists)");
        }

        let program: &mut SchedClassifier = self
            .ebpf
            .program_mut(program_name)
            .ok_or_else(|| anyhow::anyhow!("program '{program_name}' not found in eBPF object"))?
            .try_into()?;

        program.load()?;
        // Aya auto-detects kernel version:
        // >= 6.6: uses TCX (BPF_TCX_INGRESS link, priority ordering)
        // <  6.6: uses netlink (legacy clsact qdisc attach)
        program.attach(interface, TcAttachType::Ingress)?;
        info!(program_name, interface, "TC program attached (ingress)");
        Ok(())
    }

    /// Attach a TC program to a netkit interface via `BPF_LINK_CREATE`.
    /// The program must already be loaded. Returns the link fd (owned
    /// by this loader for lifetime management).
    pub fn attach_tc_via_netkit(
        &mut self,
        program_name: &str,
        interface: &str,
    ) -> Result<(), anyhow::Error> {
        use super::netkit::{BPF_NETKIT_PRIMARY, netkit_attach_by_name};

        let prog_fd: RawFd = if let Some(fd) = self.kfunc_progs.get(program_name) {
            fd.as_raw_fd()
        } else {
            let program: &mut aya::programs::SchedClassifier = self
                .ebpf
                .program_mut(program_name)
                .ok_or_else(|| anyhow::anyhow!("program '{program_name}' not found"))?
                .try_into()?;
            program.load()?;
            program.fd()?.as_fd().as_raw_fd()
        };
        let link_fd = netkit_attach_by_name(prog_fd, interface, BPF_NETKIT_PRIMARY)?;
        // Store the link fd to keep the attachment alive.
        // When EbpfLoader is dropped, the link fd closes and detaches.
        self.netkit_links.push(link_fd);
        info!(program_name, interface, "TC program attached via netkit");
        Ok(())
    }

    /// Attach a uprobe or uretprobe to a function in a userspace binary.
    pub fn attach_uprobe(
        &mut self,
        program_name: &str,
        fn_name: &str,
        target: &str,
        is_ret_probe: bool,
    ) -> Result<(), anyhow::Error> {
        let program: &mut UProbe = self
            .ebpf
            .program_mut(program_name)
            .ok_or_else(|| anyhow::anyhow!("program '{program_name}' not found in eBPF object"))?
            .try_into()?;

        program.load()?;
        program.attach(Some(fn_name), 0, target, None)?;
        let probe_type = if is_ret_probe { "uretprobe" } else { "uprobe" };
        info!(program_name, fn_name, target, probe_type, "uprobe attached");
        Ok(())
    }

    /// Detach the XDP firewall program.
    ///
    /// After detach the program is unloaded and no longer processes packets.
    pub fn detach(&mut self) -> Result<(), anyhow::Error> {
        let program: &mut Xdp = self
            .ebpf
            .program_mut("xdp_firewall")
            .ok_or_else(|| anyhow::anyhow!("program 'xdp_firewall' not found in eBPF object"))?
            .try_into()?;

        program.unload()?;
        info!("XDP firewall detached");
        Ok(())
    }

    /// Get the raw fd of a loaded program by name, for tail-call wiring.
    ///
    /// Checks raw-loaded kfunc programs first, then aya-loaded XDP and TC
    /// programs. The returned fd is valid as long as this `EbpfLoader` is
    /// alive and can be inserted into another loader's `ProgramArray` via
    /// [`Self::set_tail_call_raw`] (fds are process-global).
    pub fn program_raw_fd(&self, program_name: &str) -> Result<RawFd, anyhow::Error> {
        if let Some(fd) = self.kfunc_progs.get(program_name) {
            return Ok(fd.as_raw_fd());
        }
        let program = self
            .ebpf
            .program(program_name)
            .ok_or_else(|| anyhow::anyhow!("program '{program_name}' not found"))?;
        if let Ok(xdp) = <&Xdp>::try_from(program) {
            return Ok(xdp
                .fd()
                .map_err(|e| anyhow::anyhow!("program '{program_name}' fd unavailable: {e}"))?
                .as_fd()
                .as_raw_fd());
        }
        if let Ok(sc) = <&SchedClassifier>::try_from(program) {
            return Ok(sc
                .fd()
                .map_err(|e| anyhow::anyhow!("program '{program_name}' fd unavailable: {e}"))?
                .as_fd()
                .as_raw_fd());
        }
        Err(anyhow::anyhow!(
            "program '{program_name}' is neither XDP nor TC"
        ))
    }

    /// Wire a tail-call: insert `target_fd` at `index` in the named
    /// `ProgramArray` map hosted by this loader.
    ///
    /// Issues a raw `BPF_MAP_UPDATE_ELEM` against the captured fd to the same
    /// kernel map aya created so the slot can point at either an aya-loaded or a
    /// raw-loaded program fd — aya's `ProgramArray` only accepts the former. The
    /// same array can be wired multiple times. Only available for kfunc objects,
    /// whose maps are captured at load time; the `ProgramArray`s wired this way
    /// (`XDP_PROG_ARRAY`, `RL_PROG_ARRAY`) all belong to such objects.
    pub fn set_tail_call_raw(
        &mut self,
        map_name: &str,
        index: u32,
        target_fd: RawFd,
    ) -> Result<(), anyhow::Error> {
        let array = self.kfunc_hosted_maps.get(map_name).ok_or_else(|| {
            anyhow::anyhow!("ProgramArray '{map_name}' not captured by this kfunc loader")
        })?;
        kfunc_attach::prog_array_set(array.as_raw_fd(), index, target_fd)?;
        info!(
            map_name,
            index, "tail-call target set in ProgramArray (raw)"
        );
        Ok(())
    }

    /// Clear a tail-call slot in the named `ProgramArray`.
    ///
    /// After clearing, a tail-call to this index becomes a no-op (the eBPF
    /// `bpf_tail_call` helper returns without jumping).
    pub fn clear_tail_call_target(
        &mut self,
        map_name: &str,
        index: u32,
    ) -> Result<(), anyhow::Error> {
        let map = self
            .ebpf
            .map_mut(map_name)
            .ok_or_else(|| anyhow::anyhow!("map '{map_name}' not found"))?;
        let mut prog_array = ProgramArray::try_from(map)?;
        prog_array.clear_index(&index)?;
        info!(map_name, index, "tail-call slot cleared in ProgramArray");
        Ok(())
    }

    /// Borrow the inner `Ebpf` instance mutably.
    ///
    /// Used by map managers and event readers to access maps.
    pub fn ebpf_mut(&mut self) -> &mut Ebpf {
        &mut self.ebpf
    }

    /// Get the raw fd of a loaded program by name.
    ///
    /// Returns `None` if the program is not found or not loaded.
    /// The returned fd is valid as long as this `EbpfLoader` is alive.
    pub fn program_fd(&self, program_name: &str) -> Option<RawFd> {
        if let Some(fd) = self.kfunc_progs.get(program_name) {
            return Some(fd.as_raw_fd());
        }
        let program: &SchedClassifier = self.ebpf.program(program_name)?.try_into().ok()?;
        Some(program.fd().ok()?.as_fd().as_raw_fd())
    }

    // ── Zero-downtime program swap via BPF_LINK_UPDATE (kernel 5.7+) ────
    //
    // Current approach: detach old program, attach new program. This creates
    // a brief window where no eBPF program is processing packets.
    //
    // Upgrade: BPF_LINK_UPDATE atomically replaces the program attached to
    // a link without any gap. Packets are processed by the old program until
    // the exact moment the new program takes over.
    //
    // aya 0.13.1: Link::update() is not exposed. Use raw syscall:
    //   bpf(BPF_LINK_UPDATE, &bpf_attr { link_update: { link_fd, new_prog_fd, ... } })
    //
    // Requires storing link FDs after initial attachment (currently discarded).
    //
    // TODO(Wave 7): Store link FDs and implement atomic program replacement.

    // ── eBPF program unit testing via BPF_PROG_TEST_RUN (kernel 4.12+) ──
    //
    // Run loaded eBPF programs with synthetic packet data without attaching
    // to a real network interface. Useful for:
    //   - Verifying packet classification logic
    //   - Testing rule matching
    //   - Benchmarking per-packet processing time
    //
    // Usage:
    //   let test_pkt = build_syn_packet(src_ip, dst_ip, src_port, dst_port);
    //   let result = prog.test_run(test_pkt, repeat=1000, ctx_in=None)?;
    //   assert_eq!(result.return_val, XDP_DROP); // or TC_ACT_OK etc.
    //   println!("Duration: {}ns per packet", result.duration / 1000);
    //
    // aya 0.13.1: Program::test_run() is available.
    //
    // TODO(Wave 7): Add eBPF unit test suite using test_run with crafted packets.

    // TODO(W1-S3): BPF_MAP_FREEZE for read-only config maps.
    //
    // After populating static config maps at startup (e.g. SYNCOOKIE_SECRET, AMP_PROTECT_CONFIG,
    // RL_TIER_CONFIG), call `BPF_MAP_FREEZE` via `libc::syscall(SYS_bpf, BPF_MAP_FREEZE, ...)` to
    // prevent any subsequent writes — this hardens against userspace-side map tampering after init.
    //
    // Blocked by: aya 0.13.1 does not expose a `Map::freeze()` method. The underlying kernel
    // syscall is available since Linux 5.2 (BPF_MAP_FREEZE cmd). When aya adds freeze support,
    // wire it here after each static map population. Maps that receive runtime updates
    // (CONFIG_FLAGS, CT_CONFIG, DDOS_SYN_CONFIG, ICMP_CONFIG, QOS_PIPE_CONFIG, etc.) must NOT
    // be frozen — only truly write-once maps are candidates.
}

/// Human-readable label for XDP attachment flags.
fn xdp_flags_label(flags: XdpFlags) -> &'static str {
    let bits = flags.bits();
    if bits == XdpFlags::DRV_MODE.bits() {
        "native"
    } else if bits == XdpFlags::SKB_MODE.bits() {
        "generic"
    } else if bits == XdpFlags::HW_MODE.bits() {
        "offloaded"
    } else {
        "auto"
    }
}

/// Convert an [`infrastructure::config::XdpMode`] value to [`aya::programs::XdpFlags`].
pub fn xdp_mode_to_flags(mode: infrastructure::config::XdpMode) -> XdpFlags {
    use infrastructure::config::XdpMode;
    match mode {
        XdpMode::Auto => XdpFlags::default(),
        XdpMode::Native => XdpFlags::DRV_MODE,
        XdpMode::Generic => XdpFlags::SKB_MODE,
        XdpMode::Offloaded => XdpFlags::HW_MODE,
    }
}
