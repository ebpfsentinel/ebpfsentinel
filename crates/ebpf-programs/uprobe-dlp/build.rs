//! The Go `crypto/tls` probes read the register ABI straight from `pt_regs`,
//! whose layout is per architecture, so this crate needs the same
//! `bpf_target_arch` cfg aya-ebpf computes for itself.

fn main() -> aya_build::Result<()> {
    aya_build::emit_bpf_target_arch_cfg()
}
