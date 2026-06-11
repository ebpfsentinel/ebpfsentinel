use std::collections::HashMap;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::Path;

use aya::{maps::ProgramArray, programs::XdpFlags};
use tracing::{info, warn};

use super::kfunc_attach;
use super::kfunc_loader;

/// Default BPF filesystem pin path for shared maps.
pub const DEFAULT_BPF_PIN_PATH: &str = "/sys/fs/bpf/ebpfsentinel";

/// Loads and attaches eBPF programs (XDP, TC, uprobe).
///
/// eBPF is loaded **exclusively** through the raw BPF-token loader
/// ([`kfunc_loader::load_object_token`]): the agent holds no `CAP_BPF`,
/// so aya — which cannot pass a token fd on its syscalls — is never used
/// to load or attach. Maps live in `token_maps`, programs in
/// `kfunc_progs`, and attaches go through the raw `kfunc_attach` paths.
pub struct EbpfLoader {
    /// Token-mode maps (from `kfunc_loader::load_object_token`), exposed to the
    /// map managers through the [`MapStore`](super::map_store::MapStore) surface.
    token_maps: super::map_store::TokenMaps,
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

impl EbpfLoader {
    /// Build a loader from a raw-loaded object: maps go into the
    /// `MapStore` the managers consume, programs into `kfunc_progs` where the
    /// raw-attach paths already pick them up.
    fn from_token_object(loaded: kfunc_loader::TokenLoadedObject) -> Self {
        let kfunc_progs = loaded
            .programs
            .into_iter()
            .map(|p| (p.name, p.fd))
            .collect();
        Self {
            token_maps: super::map_store::TokenMaps::new(loaded.maps),
            netkit_links: Vec::new(),
            kfunc_progs,
            kfunc_links: Vec::new(),
            // Raw map fds captured at load time, so `set_tail_call_raw` can wire
            // `ProgramArray`s (e.g. XDP_PROG_ARRAY).
            kfunc_hosted_maps: loaded.hosted,
        }
    }

    /// Load an eBPF program from raw ELF bytes through the BPF token.
    ///
    /// The raw token loader creates the maps and loads every program with
    /// the token fd, so no `CAP_BPF` is needed. Returns an error if the
    /// verifier rejects the program or the token is unavailable.
    pub fn load(program_bytes: &[u8]) -> Result<Self, anyhow::Error> {
        let loaded = kfunc_loader::load_object_token(program_bytes, DEFAULT_BPF_PIN_PATH, None)?;
        Ok(Self::from_token_object(loaded))
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
    /// interface), the program is loaded device-bound to that netdev so the
    /// kfuncs resolve against its `xdp_metadata_ops` and read real hardware
    /// hints. If the driver lacks that support the verifier rejects the load,
    /// and the token loader transparently falls back to neutralizing the
    /// metadata kfuncs (`r0 = -EOPNOTSUPP`) so the program still loads — the
    /// program's wrapper degrades gracefully, exactly as on a driver answering
    /// `-EOPNOTSUPP`. `None` (multiple or zero interfaces) always neutralizes,
    /// so a single program fd can attach to every interface.
    pub fn load_with_pin_path_dev_bound(
        program_bytes: &[u8],
        pin_path: &str,
        dev_bound_ifindex: Option<u32>,
    ) -> Result<Self, anyhow::Error> {
        // The raw token loader creates all maps and loads every program through
        // the token (no aya, no `CAP_BPF`), classifying kfunc usage internally
        // and pin-sharing maps under `pin_path`.
        let loaded = kfunc_loader::load_object_token(program_bytes, pin_path, dev_bound_ifindex)?;
        Ok(Self::from_token_object(loaded))
    }

    /// Load a kfunc-free XDP object through the token loader so it stays
    /// tail-call-compatible with a kfunc-raw owner program.
    ///
    /// A `ProgramArray` records the load attributes of the first program to
    /// reference it and rejects any later-inserted program whose attributes
    /// differ — `bpf_prog_map_compatible` compares `prog_type`, `jited`,
    /// `xdp_has_frags`, and `attach_func_proto`. The firewall and ratelimit
    /// programs that own `XDP_PROG_ARRAY` / `RL_PROG_ARRAY` load through the
    /// token, so their tail-call targets — even the kfunc-free
    /// `xdp-firewall-reject` and `xdp-ratelimit-syncookie` — must take the
    /// identical path or the kernel refuses the slot update with `EINVAL`.
    /// The token loader creates the object's maps (reusing the owner's
    /// pin-shared maps and creating this program's private ones, e.g.
    /// `REJECT_SCRATCH`) and loads the program, all through the token.
    pub fn load_xdp_raw_with_pin_path(
        program_bytes: &[u8],
        pin_path: &str,
    ) -> Result<Self, anyhow::Error> {
        let loaded = kfunc_loader::load_object_token(program_bytes, pin_path, None)?;
        Ok(Self::from_token_object(loaded))
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

        Err(anyhow::anyhow!(
            "XDP program '{program_name}' was not loaded through the BPF token"
        ))
    }

    /// Load a named XDP program without attaching it to any interface.
    ///
    /// Used for tail-call targets that are invoked via `ProgramArray`
    /// from another XDP program (e.g. `xdp-firewall-reject` called from
    /// `xdp-firewall`).
    pub fn load_xdp_program(&mut self, program_name: &str) -> Result<(), anyhow::Error> {
        if self.kfunc_progs.contains_key(program_name) {
            // The token loader already issued BPF_PROG_LOAD; nothing to attach.
            info!(
                program_name,
                "XDP program already loaded (tail-call target, no attach)"
            );
            return Ok(());
        }

        Err(anyhow::anyhow!(
            "XDP program '{program_name}' was not loaded through the BPF token"
        ))
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

        Err(anyhow::anyhow!(
            "TC program '{program_name}' was not loaded through the BPF token"
        ))
    }

    /// Attach an already-loaded TC classifier to the EGRESS hook of
    /// `interface` (the same program may also be attached on ingress). On
    /// egress the kernel has bound the originating socket to the skb, so
    /// `bpf_skb_cgroup_id` yields the cgroup of the process that generated
    /// the packet — used for container attribution of locally-originated
    /// (e.g. container outbound) traffic, which the ingress hook cannot
    /// resolve. Mirrors [`Self::attach_tc_program`] but for `Egress`.
    pub fn attach_tc_egress(
        &mut self,
        program_name: &str,
        interface: &str,
    ) -> Result<(), anyhow::Error> {
        if let Some(prog_fd) = self.kfunc_progs.get(program_name) {
            let link =
                kfunc_attach::attach_tcx(program_name, prog_fd.as_raw_fd(), interface, true)?;
            self.kfunc_links.push(link);
            info!(
                program_name,
                interface, "TC kfunc program attached (egress)"
            );
            return Ok(());
        }

        Err(anyhow::anyhow!(
            "TC program '{program_name}' was not loaded through the BPF token"
        ))
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

        let Some(fd) = self.kfunc_progs.get(program_name) else {
            return Err(anyhow::anyhow!(
                "TC program '{program_name}' was not loaded through the BPF token"
            ));
        };
        let prog_fd: RawFd = fd.as_raw_fd();
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
        // The token loader already issued BPF_PROG_LOAD, so attach the captured
        // fd through the kernel uprobe PMU.
        if let Some(prog_fd) = self.kfunc_progs.get(program_name) {
            let link = kfunc_attach::attach_uprobe_raw(
                program_name,
                prog_fd.as_raw_fd(),
                target,
                fn_name,
                is_ret_probe,
            )?;
            self.kfunc_links.push(link);
            return Ok(());
        }

        Err(anyhow::anyhow!(
            "uprobe program '{program_name}' was not loaded through the BPF token"
        ))
    }

    /// Get the raw fd of a loaded program by name, for tail-call wiring.
    ///
    /// The returned fd is valid as long as this `EbpfLoader` is alive and
    /// can be inserted into another loader's `ProgramArray` via
    /// [`Self::set_tail_call_raw`] (fds are process-global).
    pub fn program_raw_fd(&self, program_name: &str) -> Result<RawFd, anyhow::Error> {
        self.kfunc_progs
            .get(program_name)
            .map(AsRawFd::as_raw_fd)
            .ok_or_else(|| anyhow::anyhow!("program '{program_name}' not found"))
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
            .ebpf_mut()
            .map_mut(map_name)
            .ok_or_else(|| anyhow::anyhow!("map '{map_name}' not found"))?;
        let mut prog_array = ProgramArray::try_from(map)?;
        prog_array.clear_index(&index)?;
        info!(map_name, index, "tail-call slot cleared in ProgramArray");
        Ok(())
    }

    /// Borrow this loader's maps as a [`MapStore`](super::map_store::MapStore).
    ///
    /// Used by map managers and event readers. The maps come from the raw
    /// token loader; `MapStore` exposes the `take_map` / `map` / `map_mut`
    /// surface the managers consume.
    pub fn ebpf_mut(&mut self) -> &mut dyn super::map_store::MapStore {
        &mut self.token_maps
    }

    /// Get the raw fd of a loaded program by name.
    ///
    /// Returns `None` if the program is not found or not loaded.
    /// The returned fd is valid as long as this `EbpfLoader` is alive.
    pub fn program_fd(&self, program_name: &str) -> Option<RawFd> {
        self.kfunc_progs.get(program_name).map(AsRawFd::as_raw_fd)
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
