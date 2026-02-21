use aya::{
    Ebpf,
    maps::ProgramArray,
    programs::{ProgramFd, SchedClassifier, TcAttachType, UProbe, Xdp, XdpFlags, tc},
};
use tracing::{info, warn};

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

    /// Attach the XDP firewall program to the given network interface.
    ///
    /// Backward-compatible wrapper around `attach_xdp_program("xdp_firewall", ...)`.
    pub fn attach_xdp(&mut self, interface: &str) -> Result<(), anyhow::Error> {
        self.attach_xdp_program("xdp_firewall", interface)
    }

    /// Attach a named XDP program to the given network interface.
    pub fn attach_xdp_program(
        &mut self,
        program_name: &str,
        interface: &str,
    ) -> Result<(), anyhow::Error> {
        let program: &mut Xdp = self
            .ebpf
            .program_mut(program_name)
            .ok_or_else(|| anyhow::anyhow!("program '{program_name}' not found in eBPF object"))?
            .try_into()?;

        program.load()?;
        program.attach(interface, XdpFlags::default())?;
        info!(program_name, interface, "XDP program attached");
        Ok(())
    }

    /// Attach a TC (Traffic Control) classifier program to the given interface.
    ///
    /// Adds a `clsact` qdisc (best-effort, may already exist) and attaches the
    /// program on the ingress path.
    pub fn attach_tc_program(
        &mut self,
        program_name: &str,
        interface: &str,
    ) -> Result<(), anyhow::Error> {
        // Add clsact qdisc (idempotent — ignore "already exists" errors)
        if let Err(e) = tc::qdisc_add_clsact(interface) {
            warn!(interface, error = %e, "qdisc_add_clsact failed (may already exist)");
        }

        let program: &mut SchedClassifier = self
            .ebpf
            .program_mut(program_name)
            .ok_or_else(|| anyhow::anyhow!("program '{program_name}' not found in eBPF object"))?
            .try_into()?;

        program.load()?;
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
    pub fn set_tail_call_target(
        &mut self,
        map_name: &str,
        index: u32,
        target_fd: &ProgramFd,
    ) -> Result<(), anyhow::Error> {
        let map = self
            .ebpf
            .take_map(map_name)
            .ok_or_else(|| anyhow::anyhow!("map '{map_name}' not found"))?;
        let mut prog_array = ProgramArray::try_from(map)?;
        prog_array.set(index, target_fd, 0)?;
        info!(map_name, index, "tail-call target set in ProgramArray");
        Ok(())
    }

    /// Borrow the inner `Ebpf` instance mutably.
    ///
    /// Used by map managers and event readers to access maps.
    pub fn ebpf_mut(&mut self) -> &mut Ebpf {
        &mut self.ebpf
    }
}
