//! Whether every tail call leaves from a program's entry function.
//!
//! A tail call issued from a bpf-to-bpf callee passes the verifier, and the
//! x86 JIT then keeps the tail-call counter behind a pointer it hands from
//! caller to callee. On some kernels that pointer arrives stale in the callee
//! and the first packet to reach the tail call oopses in softirq, taking the
//! host down rather than failing a load. The compiler decides alone whether a
//! large program body stays in the entry or becomes a subprogram, and a
//! toolchain move is enough to change its mind, so this test reads the built
//! objects and fails on a `bpf_tail_call` anywhere but an entry function.
//!
//! It needs the objects, built by `cargo xtask ebpf-build` into
//! `target/bpfel-unknown-none/release` or wherever `EBPFSENTINEL_EBPF_DIR`
//! points. Without them it says what is missing and returns.

use std::collections::HashSet;
use std::path::PathBuf;

use aya_obj::Object;

/// `BPF_JMP | BPF_CALL`.
const INSN_CALL: u8 = 0x85;
/// `bpf_tail_call` in the helper table.
const BPF_FUNC_TAIL_CALL: i32 = 12;

/// Where the built objects are.
fn objects_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("EBPFSENTINEL_EBPF_DIR") {
        return PathBuf::from(dir);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/bpfel-unknown-none/release")
}

/// The functions of one object that issue a tail call without being the
/// entry of a program.
fn tail_calls_outside_an_entry(elf: &[u8]) -> Vec<String> {
    let obj = Object::parse(elf).expect("a built object parses");
    let entries: HashSet<(usize, u64)> = obj
        .programs
        .values()
        .map(aya_obj::Program::function_key)
        .collect();
    obj.functions
        .iter()
        .filter(|(key, _)| !entries.contains(key))
        .filter(|(_, function)| {
            function.instructions.iter().any(|insn| {
                insn.code == INSN_CALL && insn.src_reg() == 0 && insn.imm == BPF_FUNC_TAIL_CALL
            })
        })
        .map(|(_, function)| function.name.clone())
        .collect()
}

#[test]
fn every_tail_call_leaves_from_an_entry_function() {
    let dir = objects_dir();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        eprintln!(
            "no eBPF objects at {} - run `cargo xtask ebpf-build` first",
            dir.display()
        );
        return;
    };
    let mut offenders = Vec::new();
    let mut objects = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(elf) = std::fs::read(&path) else {
            continue;
        };
        if !elf.starts_with(b"\x7fELF") {
            continue;
        }
        objects += 1;
        for function in tail_calls_outside_an_entry(&elf) {
            offenders.push(format!("{} tail-calls from `{function}`", path.display()));
        }
    }
    assert!(objects > 0, "no eBPF object in {}", dir.display());
    assert!(
        offenders.is_empty(),
        "tail calls issued from a subprogram, mark the entry body \
         #[inline(always)] so it stays in the program's section: {offenders:#?}"
    );
}
