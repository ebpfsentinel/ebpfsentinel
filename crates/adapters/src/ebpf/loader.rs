use std::collections::HashMap;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::Path;
use std::time::Duration;

use aya::maps::ProgramArray;
use tracing::{info, warn};

use super::attach_inspect::{self, AttachBlock};
use super::kfunc_attach;
use super::kfunc_loader;

/// Default BPF filesystem pin path for shared maps.
pub const DEFAULT_BPF_PIN_PATH: &str = "/sys/fs/bpf/ebpfsentinel";

/// XDP attach mode bits, mirroring `XDP_FLAGS_*` in `<linux/if_link.h>`.
///
/// The agent attaches through its own `BPF_LINK_CREATE` path rather than
/// aya's program API, so the mode travels as raw kernel bits. `0` lets the
/// kernel pick the best available mode.
pub const XDP_MODE_AUTO: u32 = 0;
/// Generic XDP, executed by the kernel network stack.
pub const XDP_MODE_SKB: u32 = 1 << 1;
/// Native XDP, executed by the network driver.
pub const XDP_MODE_DRV: u32 = 1 << 2;
/// Hardware offload, executed by the network device.
pub const XDP_MODE_HW: u32 = 1 << 3;

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

    /// Remove a pin directory, and say why.
    ///
    /// Wiping pins is destructive and unconditional: it is the fallback taken
    /// when the previous generation's state cannot be inspected, not a way of
    /// reconciling with it. Link state can be introspected
    /// ([`attach_inspect`]); pinned *maps* cannot - the kernel exposes no way
    /// to ask whether a live process still holds a pinned map, so a surviving
    /// pin is indistinguishable from a leaked one. That is why every caller
    /// wipes rather than adopts, and why each records `reason` in the log: a
    /// pin directory disappearing is otherwise invisible in a post-mortem.
    ///
    /// On shutdown this is bookkeeping. At startup it is the crash-recovery
    /// path, and it is safe there only because the agent is the sole owner of
    /// its pin paths.
    pub fn cleanup_pin_path_because(pin_path: &str, reason: &str) {
        let path = Path::new(pin_path);
        if path.exists() {
            if let Err(e) = std::fs::remove_dir_all(path) {
                warn!(pin_path, reason, error = %e, "failed to clean up BPF pin directory");
            } else {
                info!(pin_path, reason, "cleaned up BPF pin directory");
            }
        }
    }

    /// Clean up pinned maps from the BPF filesystem.
    ///
    /// Prefer [`Self::cleanup_pin_path_because`], which records why the wipe
    /// happened.
    pub fn cleanup_pin_path(pin_path: &str) {
        Self::cleanup_pin_path_because(pin_path, "unspecified");
    }

    /// Attach the XDP firewall program to the given network interface.
    ///
    /// Backward-compatible wrapper around `attach_xdp_program("xdp_firewall", ...)`.
    pub fn attach_xdp(&mut self, interface: &str, flags: u32) -> Result<(), anyhow::Error> {
        self.attach_xdp_program("xdp_firewall", interface, flags)
    }

    /// Attach a named XDP program to the given network interface.
    ///
    /// Attempts the requested `flags` mode first. If attachment fails and the
    /// mode is not already auto, falls back to [`XDP_MODE_AUTO`] (kernel picks
    /// best available) and logs a warning.
    ///
    /// Attaching is idempotent: when the interface already carries this exact
    /// program the call succeeds without creating a second link. A failure is
    /// recorded as an [`AttachBlock`] so readiness and the ops endpoint can
    /// name what is in the way, and cleared again on success.
    pub fn attach_xdp_program(
        &mut self,
        program_name: &str,
        interface: &str,
        flags: u32,
    ) -> Result<(), anyhow::Error> {
        if let Some(prog_fd) = self.kfunc_progs.get(program_name) {
            let raw = prog_fd.as_raw_fd();
            let own_prog_id = attach_inspect::program_id(raw);
            let ifindex = kfunc_attach::iface_to_ifindex(interface).ok();

            // Already ours: re-attaching would fail with EBUSY after burning
            // the retry budget, and on a kernel that allowed it would leave two
            // links where one belongs. This is the readoption path taken by a
            // hot reload and by an HA activate that follows an incomplete
            // deactivate.
            if let Some(idx) = ifindex
                && attach_inspect::already_carries(idx, own_prog_id)
            {
                attach_inspect::clear_block(program_name, interface);
                info!(
                    program_name,
                    interface, "XDP program already attached to this interface, readopted"
                );
                return Ok(());
            }

            let mode_label = xdp_flags_label(flags);
            match attach_xdp_ebusy_retry(program_name, raw, interface, flags) {
                Ok(link) => {
                    self.kfunc_links.push(link);
                    attach_inspect::clear_block(program_name, interface);
                    info!(
                        program_name,
                        interface,
                        mode = mode_label,
                        "XDP kfunc program attached"
                    );
                    return Ok(());
                }
                Err(e) if flags != XDP_MODE_AUTO => {
                    warn!(
                        program_name,
                        interface,
                        requested_mode = mode_label,
                        error = %e,
                        "XDP kfunc attach failed with requested mode, falling back to auto"
                    );
                    match attach_xdp_ebusy_retry(program_name, raw, interface, XDP_MODE_AUTO) {
                        Ok(link) => {
                            self.kfunc_links.push(link);
                            attach_inspect::clear_block(program_name, interface);
                            info!(
                                program_name,
                                interface,
                                mode = xdp_flags_label(XDP_MODE_AUTO),
                                "XDP kfunc program attached (fallback from {mode_label})"
                            );
                            return Ok(());
                        }
                        Err(e) => {
                            return Err(record_xdp_block(
                                program_name,
                                interface,
                                ifindex,
                                own_prog_id,
                                &e,
                            ));
                        }
                    }
                }
                Err(e) => {
                    return Err(record_xdp_block(
                        program_name,
                        interface,
                        ifindex,
                        own_prog_id,
                        &e,
                    ));
                }
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
                match kfunc_attach::attach_tcx(program_name, prog_fd.as_raw_fd(), interface, false)
                {
                    Ok(link) => link,
                    Err(e) => {
                        return Err(record_link_block(
                            program_name,
                            interface,
                            "TCX ingress",
                            errno_of(&e),
                            &e,
                        ));
                    }
                };
            self.kfunc_links.push(link);
            attach_inspect::clear_block(program_name, interface);
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
            let link = match kfunc_attach::attach_tcx(
                program_name,
                prog_fd.as_raw_fd(),
                interface,
                true,
            ) {
                Ok(link) => link,
                Err(e) => {
                    return Err(record_link_block(
                        program_name,
                        interface,
                        "TCX egress",
                        errno_of(&e),
                        &e,
                    ));
                }
            };
            self.kfunc_links.push(link);
            attach_inspect::clear_block(program_name, interface);
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
        self.attach_netkit(program_name, interface, super::netkit::BPF_NETKIT_PRIMARY)
    }

    /// Attach a TC program to the peer (egress) side of a netkit device.
    /// Netkit devices carry no clsact qdisc, so a program that has to run on
    /// the way out reaches this side rather than the TCX egress hook.
    pub fn attach_tc_egress_via_netkit(
        &mut self,
        program_name: &str,
        interface: &str,
    ) -> Result<(), anyhow::Error> {
        self.attach_netkit(program_name, interface, super::netkit::BPF_NETKIT_PEER)
    }

    fn attach_netkit(
        &mut self,
        program_name: &str,
        interface: &str,
        attach_type: u32,
    ) -> Result<(), anyhow::Error> {
        use super::netkit::{BPF_NETKIT_PRIMARY, netkit_attach_by_name};

        let Some(fd) = self.kfunc_progs.get(program_name) else {
            return Err(anyhow::anyhow!(
                "TC program '{program_name}' was not loaded through the BPF token"
            ));
        };
        let prog_fd: RawFd = fd.as_raw_fd();
        let direction = if attach_type == BPF_NETKIT_PRIMARY {
            "ingress"
        } else {
            "egress"
        };
        let link_fd = match netkit_attach_by_name(prog_fd, interface, attach_type) {
            Ok(link_fd) => link_fd,
            Err(e) => {
                let errno = match &e {
                    super::netkit::NetkitError::AttachFailed { errno, .. } => *errno,
                    _ => 0,
                };
                let hook = if attach_type == BPF_NETKIT_PRIMARY {
                    "netkit primary"
                } else {
                    "netkit peer"
                };
                return Err(record_link_block(program_name, interface, hook, errno, &e));
            }
        };
        // Store the link fd to keep the attachment alive.
        // When EbpfLoader is dropped, the link fd closes and detaches.
        self.netkit_links.push(link_fd);
        attach_inspect::clear_block(program_name, interface);
        info!(
            program_name,
            interface, direction, "TC program attached via netkit"
        );
        Ok(())
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
    // aya 0.14.0: Link::update() is not exposed. Use raw syscall:
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
    // aya 0.14.0: Program::test_run() is available.
    //
    // TODO(Wave 7): Add eBPF unit test suite using test_run with crafted packets.

    // TODO(W1-S3): BPF_MAP_FREEZE for read-only config maps.
    //
    // After populating static config maps at startup (e.g. SYNCOOKIE_SECRET, AMP_PROTECT_CONFIG,
    // RL_TIER_CONFIG), call `BPF_MAP_FREEZE` via `libc::syscall(SYS_bpf, BPF_MAP_FREEZE, ...)` to
    // prevent any subsequent writes — this hardens against userspace-side map tampering after init.
    //
    // Blocked by: aya 0.14.0 exposes no public `Map::freeze()`; it freezes rodata maps
    // internally only. The underlying kernel
    // syscall is available since Linux 5.2 (BPF_MAP_FREEZE cmd). When aya adds freeze support,
    // wire it here after each static map population. Maps that receive runtime updates
    // (CONFIG_FLAGS, CT_CONFIG, DDOS_SYN_CONFIG, ICMP_CONFIG, QOS_PIPE_CONFIG, etc.) must NOT
    // be frozen — only truly write-once maps are candidates.
}

/// How many times to retry an XDP attach that fails with `EBUSY`, and the
/// delay between attempts. On a fast restart / redeploy the previous agent's
/// XDP `BPF_LINK` may not be released by the kernel yet (its fd is closed
/// asynchronously on process teardown), so a fresh attach briefly races it and
/// gets `EBUSY` (errno 16). The link auto-releases once the old fd is gone, so
/// riding out that window with a few retries makes a restart self-heal instead
/// of failing into degraded mode. Total worst-case wait stays ~1.5 s, paid once
/// at startup before the agent serves traffic.
const XDP_ATTACH_EBUSY_RETRIES: u32 = 5;
const XDP_ATTACH_EBUSY_DELAY: Duration = Duration::from_millis(300);

/// Attach an XDP program, retrying on `EBUSY` so a restart races out cleanly.
/// Non-`EBUSY` errors are returned immediately (no point retrying them).
fn attach_xdp_ebusy_retry(
    program_name: &str,
    prog_fd: RawFd,
    interface: &str,
    flags_bits: u32,
) -> Result<OwnedFd, kfunc_attach::KfuncAttachError> {
    let mut attempt = 0;
    loop {
        match kfunc_attach::attach_xdp(program_name, prog_fd, interface, flags_bits) {
            Ok(link) => return Ok(link),
            Err(e) => {
                let busy = matches!(
                    e,
                    kfunc_attach::KfuncAttachError::LinkCreate { errno, .. }
                        if errno == libc::EBUSY
                );
                if busy && attempt < XDP_ATTACH_EBUSY_RETRIES {
                    attempt += 1;
                    warn!(
                        program_name,
                        interface,
                        attempt,
                        retries = XDP_ATTACH_EBUSY_RETRIES,
                        "XDP interface busy (errno 16) — a previous instance may still hold the \
                         link after a restart; retrying after a short delay"
                    );
                    std::thread::sleep(XDP_ATTACH_EBUSY_DELAY);
                    continue;
                }
                return Err(e);
            }
        }
    }
}

/// Turn a failed XDP attach into a recorded block and an operator-readable
/// error.
///
/// The syscall gives an errno and nothing more - `bpf(2)` carries no extended
/// ack - so the reason has to be established by asking rtnetlink what is
/// actually on the interface. Doing that only on the failure path keeps the
/// happy path free of extra syscalls.
fn record_xdp_block(
    program_name: &str,
    interface: &str,
    ifindex: Option<u32>,
    own_prog_id: Option<u32>,
    err: &kfunc_attach::KfuncAttachError,
) -> anyhow::Error {
    let errno = match err {
        kfunc_attach::KfuncAttachError::LinkCreate { errno, .. } => *errno,
        _ => 0,
    };
    let Some(idx) = ifindex else {
        // The interface could not even be resolved, so there is nothing to
        // interrogate; the original error already says so.
        return anyhow::anyhow!("{err}");
    };
    let attach_inspect::XdpDiagnosis { reason, nested_xdp } =
        attach_inspect::diagnose_xdp(errno, interface, idx, own_prog_id);
    warn!(
        program_name,
        interface,
        errno,
        nested_xdp,
        reason = %reason,
        "XDP attach blocked"
    );
    attach_inspect::record_block(AttachBlock {
        program: program_name.to_owned(),
        interface: interface.to_owned(),
        reason: reason.clone(),
        nested_xdp,
    });
    anyhow::anyhow!("{reason}")
}

/// The errno inside a `BPF_LINK_CREATE` failure, or 0 for the failures that
/// never reached the syscall (an unresolvable interface, say) and so have no
/// kernel verdict to translate.
fn errno_of(err: &kfunc_attach::KfuncAttachError) -> i32 {
    match err {
        kfunc_attach::KfuncAttachError::LinkCreate { errno, .. }
        | kfunc_attach::KfuncAttachError::UprobeLink { errno, .. } => *errno,
        _ => 0,
    }
}

/// Record a refused non-XDP attach and return the operator-readable error.
///
/// The XDP twin can read the interface back through rtnetlink; this one cannot,
/// so it works from the errno and the hook name. `nested_xdp` is always false
/// here - the field means "somebody else's XDP program owns this interface",
/// which is not a thing that happens on a TCX or netkit hook.
fn record_link_block(
    program_name: &str,
    interface: &str,
    hook: &str,
    errno: i32,
    err: &dyn std::fmt::Display,
) -> anyhow::Error {
    if errno == 0 {
        // No kernel verdict to translate; the original error already carries
        // everything known about the failure.
        return anyhow::anyhow!("{err}");
    }
    let reason = attach_inspect::diagnose_link(errno, hook, interface);
    warn!(
        program_name,
        interface,
        hook,
        errno,
        reason = %reason,
        "attach blocked"
    );
    attach_inspect::record_block(AttachBlock {
        program: program_name.to_owned(),
        interface: interface.to_owned(),
        reason: reason.clone(),
        nested_xdp: false,
    });
    anyhow::anyhow!("{reason}")
}

/// Human-readable label for XDP attachment flags.
fn xdp_flags_label(flags: u32) -> &'static str {
    match flags {
        XDP_MODE_DRV => "native",
        XDP_MODE_SKB => "generic",
        XDP_MODE_HW => "offloaded",
        _ => "auto",
    }
}

/// Convert an [`infrastructure::config::XdpMode`] value to XDP attach mode bits.
pub fn xdp_mode_to_flags(mode: infrastructure::config::XdpMode) -> u32 {
    use infrastructure::config::XdpMode;
    match mode {
        XdpMode::Auto => XDP_MODE_AUTO,
        XdpMode::Native => XDP_MODE_DRV,
        XdpMode::Generic => XDP_MODE_SKB,
        XdpMode::Offloaded => XDP_MODE_HW,
    }
}
