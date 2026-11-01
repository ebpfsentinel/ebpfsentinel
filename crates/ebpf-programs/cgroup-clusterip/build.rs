//! Nothing here reads a register, but aya-ebpf's own code is compiled per
//! architecture, so the crate needs the `bpf_target_arch` cfg it computes.

fn main() -> aya_build::Result<()> {
    aya_build::emit_bpf_target_arch_cfg()
}
