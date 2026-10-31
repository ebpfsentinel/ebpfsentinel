//! Whether `aya-obj` resolves the vmlinux kfuncs our programs call, and
//! whether any object calls something no kernel exports.
//!
//! The loader resolves every kfunc itself, vmlinux and module alike, through
//! `KfuncResolver`. Upstream covers the vmlinux half in principle
//! (`resolve_externs`, `relocate_externs`), and a second implementation of
//! something upstream does is only worth keeping while the two disagree. This
//! test is where they are compared: it parses each built object that calls a
//! dynptr or XDP receive-metadata kfunc, lets `aya-obj` resolve and relocate it
//! against the running kernel's BTF, and asserts that upstream did not land on
//! the BTF id `kfunc.rs` answers. The day it does, the assertion fails and
//! names the kfunc, and the vmlinux half can be handed back.
//!
//! It needs the objects, built by `cargo xtask ebpf-build` into
//! `target/bpfel-unknown-none/release` or wherever `EBPFSENTINEL_EBPF_DIR`
//! points, and a readable `/sys/kernel/btf/vmlinux`. Neither needs privilege.
//! Without them it says what is missing and returns.

use std::path::PathBuf;

use adapters::ebpf::kfunc::KfuncResolver;
use adapters::ebpf::kfunc_loader::called_kfuncs;
use aya_obj::Object;
use aya_obj::btf::Btf;

/// The objects that call a vmlinux dynptr or receive-metadata kfunc.
const KFUNC_OBJECTS: &[&str] = &[
    "xdp-firewall",
    "xdp-ratelimit",
    "xdp-loadbalancer",
    "tc-ids",
];

/// `BPF_JMP | BPF_CALL`.
const INSN_CALL: u8 = 0x85;
/// `src_reg` of a call whose `imm` is a kernel BTF id.
const BPF_PSEUDO_KFUNC_CALL: u8 = 2;

/// Where the built objects are.
fn objects_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("EBPFSENTINEL_EBPF_DIR") {
        return PathBuf::from(dir);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/bpfel-unknown-none/release")
}

/// The vmlinux kfunc families whose resolution the comparison is about.
fn is_compared(name: &str) -> bool {
    name.starts_with("bpf_dynptr_") || name.starts_with("bpf_xdp_metadata_")
}

/// The BTF ids `aya-obj` wrote into kfunc calls, or nothing when its
/// resolution or relocation gave up on the object.
fn upstream_kfunc_ids(elf: &[u8], kernel_btf: &Btf) -> Vec<i32> {
    let mut obj = Object::parse(elf).expect("a built object parses");
    if obj.resolve_externs(Some(kernel_btf)).is_err() || obj.relocate_externs().is_err() {
        return Vec::new();
    }
    obj.functions
        .values()
        .flat_map(|function| function.instructions.iter())
        .filter(|insn| insn.code == INSN_CALL && insn.src_reg() == BPF_PSEUDO_KFUNC_CALL)
        .map(|insn| insn.imm)
        .collect()
}

#[test]
fn upstream_does_not_resolve_the_vmlinux_kfuncs_we_call() {
    let dir = objects_dir();
    if !dir.is_dir() {
        eprintln!(
            "no eBPF objects at {} - run `cargo xtask ebpf-build` first",
            dir.display()
        );
        return;
    }
    let Ok(kernel_btf) = Btf::from_sys_fs() else {
        eprintln!("this host exposes no readable /sys/kernel/btf/vmlinux");
        return;
    };
    let resolver = KfuncResolver::new().expect("kernel BTF read once already parses again");

    let mut compared = 0;
    for object in KFUNC_OBJECTS {
        let path = dir.join(object);
        let elf = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("{} is missing from the build: {e}", path.display()));
        let names: Vec<String> = called_kfuncs(&elf)
            .expect("kfunc call sites parse")
            .into_iter()
            .filter(|name| is_compared(name))
            .collect();
        assert!(
            !names.is_empty(),
            "{object} calls no dynptr or receive-metadata kfunc any more: drop it from the list"
        );

        let upstream = upstream_kfunc_ids(&elf, &kernel_btf);
        for name in names {
            let Ok(target) = resolver.resolve(&name) else {
                eprintln!("this kernel does not carry `{name}`, nothing to compare");
                continue;
            };
            assert!(
                target.module_name.is_none(),
                "`{name}` resolved to a module, the comparison is about vmlinux kfuncs"
            );
            let ours = i32::try_from(target.btf_id).expect("a BTF id fits i32");
            assert!(
                !upstream.contains(&ours),
                "aya-obj now resolves `{name}` in {object} to the BTF id kfunc.rs answers: \
                 hand the vmlinux kfuncs to `resolve_externs` and keep only the module path"
            );
            compared += 1;
        }
    }
    assert!(compared > 0, "no kfunc was compared on this kernel");
}

/// A call the loader reads as a kfunc but which is a compiler runtime
/// routine: `__multi3` for a 128-bit multiply, `__udivti3` for a 128-bit
/// division, and their siblings. LLVM emits one when the source asks for
/// arithmetic the BPF instruction set lacks, often through a checked or
/// saturating multiply, and no kernel exports it, so the object fails at load
/// on every host. Every kfunc we call is named `bpf_*`, `scx_*` or a module
/// export, none of which starts with two underscores.
#[test]
fn no_object_calls_a_compiler_runtime_routine() {
    let dir = objects_dir();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        eprintln!(
            "no eBPF objects at {} - run `cargo xtask ebpf-build` first",
            dir.display()
        );
        return;
    };
    let mut offenders = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(elf) = std::fs::read(&path) else {
            continue;
        };
        if !elf.starts_with(b"\x7fELF") {
            continue;
        }
        let Ok(names) = called_kfuncs(&elf) else {
            continue;
        };
        for name in names.into_iter().filter(|name| name.starts_with("__")) {
            offenders.push(format!("{} calls `{name}`", path.display()));
        }
    }
    assert!(
        offenders.is_empty(),
        "compiler runtime calls no kernel provides, rewrite the arithmetic \
         without a 128-bit intermediate: {offenders:#?}"
    );
}
