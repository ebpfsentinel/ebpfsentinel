use std::path::Path;

use aya::{
    Ebpf, EbpfLoader as AyaEbpfLoader,
    maps::ProgramArray,
    programs::{ProgramFd, SchedClassifier, TcAttachType, UProbe, Xdp, XdpFlags, tc},
};
use tracing::{debug, info, warn};

/// Default BPF filesystem pin path for shared maps.
pub const DEFAULT_BPF_PIN_PATH: &str = "/sys/fs/bpf/ebpfsentinel";

/// Loads and attaches eBPF programs (XDP, TC, uprobe).
///
/// Wraps the `aya::Ebpf` instance and provides methods for
/// program lifecycle management (load, attach, detach).
pub struct EbpfLoader {
    ebpf: Ebpf,
}

impl EbpfLoader {
    /// Load an eBPF program from raw ELF bytes.
    ///
    /// Initializes aya-log for eBPF debug message forwarding (best-effort).
    /// Returns an error if the verifier rejects the program.
    pub fn load(program_bytes: &[u8]) -> Result<Self, anyhow::Error> {
        let mut ebpf = Ebpf::load(program_bytes)?;

        // Initialize aya-log (best-effort — non-fatal if eBPF has no log statements)
        if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
            warn!("eBPF logger init failed (non-fatal): {e}");
        }

        info!("eBPF program loaded successfully");
        Ok(Self { ebpf })
    }

    /// Load an eBPF program with map pinning enabled.
    ///
    /// Maps with matching names across programs will be shared via the
    /// BPF filesystem. The first program to load creates and pins the map;
    /// subsequent programs reuse the pinned map automatically.
    ///
    /// This enables `CT_TABLE_V4`/`CT_TABLE_V6` and `INTERFACE_GROUPS` to be shared
    /// across tc-conntrack, xdp-firewall, tc-nat-ingress, tc-nat-egress.
    pub fn load_with_pin_path(program_bytes: &[u8], pin_path: &str) -> Result<Self, anyhow::Error> {
        // Ensure pin directory exists
        let path = Path::new(pin_path);
        if !path.exists() {
            std::fs::create_dir_all(path)?;
            info!(pin_path, "created BPF pin directory");
        }

        let mut ebpf = AyaEbpfLoader::new()
            .map_pin_path(pin_path)
            .load(program_bytes)?;

        if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
            warn!("eBPF logger init failed (non-fatal): {e}");
        }

        info!(pin_path, "eBPF program loaded with map pinning");
        Ok(Self { ebpf })
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

    /// Get the `ProgramFd` of a loaded XDP program by name.
    ///
    /// Used to insert the program fd into another program's `ProgramArray`
    /// for tail-call chaining.
    pub fn xdp_program_fd(&self, program_name: &str) -> Result<ProgramFd, anyhow::Error> {
        let program: &Xdp = self
            .ebpf
            .program(program_name)
            .ok_or_else(|| anyhow::anyhow!("program '{program_name}' not found"))?
            .try_into()?;
        program
            .fd()
            .map(|fd| fd.try_clone().unwrap())
            .map_err(|e| anyhow::anyhow!("program '{program_name}' fd unavailable: {e}"))
    }

    /// Wire a tail-call: insert `target_fd` at `index` in the named
    /// `ProgramArray` map owned by this loader.
    ///
    /// Uses `map_mut` (borrow) instead of `take_map` (consume) so the same
    /// `ProgramArray` can be wired multiple times (e.g. slot 0 → syncookie,
    /// slot 1 → loadbalancer).
    pub fn set_tail_call_target(
        &mut self,
        map_name: &str,
        index: u32,
        target_fd: &ProgramFd,
    ) -> Result<(), anyhow::Error> {
        let map = self
            .ebpf
            .map_mut(map_name)
            .ok_or_else(|| anyhow::anyhow!("map '{map_name}' not found"))?;
        let mut prog_array = ProgramArray::try_from(map)?;
        prog_array.set(index, target_fd, 0)?;
        info!(map_name, index, "tail-call target set in ProgramArray");
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
