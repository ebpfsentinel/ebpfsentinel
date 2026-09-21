//! Per-program cost measurement through `BPF_PROG_TEST_RUN`.
//!
//! The running agent reports a per-program time from `bpf_stats`, which bills
//! a tail-called program's run to whichever program the kernel entered, so the
//! figure against `xdp_firewall` on a live interface is the firewall plus the
//! rate limiter plus the load balancer. `BPF_PROG_TEST_RUN` loads one program,
//! hands it a packet directly and reports the average time of a run, so each
//! program answers for itself.
//!
//! Every program is measured twice: once with nothing published in
//! `FW_EMPTY_FEATURES`, which is what an estate carrying rules pays, and once
//! with every gate bit set, which is what an estate carrying none pays. The
//! second figure is the one the emptiness gates exist to move.
//!
//! Two things this does not measure. The kernel calls the program with no
//! driver around it, so the per-packet cost of the hook itself - the XDP entry,
//! the TCX chain walk - is outside the figure. And a program is entered with
//! an empty control block, so each parses the packet itself; in the real chain
//! only the first one does, and the rest read the parse back.
//!
//! Needs root, and needs the objects built: `cargo xtask ebpf-build`.

#![allow(unsafe_code)] // Raw bpf(BPF_PROG_TEST_RUN) - aya types no program here.

use std::mem;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::path::{Path, PathBuf};

use adapters::ebpf::kfunc_loader::{self, KfuncLoadedProgram};
use anyhow::{Context, Result, anyhow, bail};
use aya::maps::{Array, MapData};
use aya_obj::generated::{bpf_attr, bpf_cmd, bpf_prog_type};

use crate::build_ebpf::EBPF_PROGRAMS;

/// Where the harness pins the maps it creates. Deliberately not the agent's
/// own directory: a running agent's tables must not be touched by a
/// measurement, and this one is emptied before and after the run.
const PIN_PATH: &str = "/sys/fs/bpf/ebpfsentinel-cost";

/// Runs per measurement. The kernel divides the total by this, so a larger
/// number buys resolution and costs wall-clock.
const REPEAT: u32 = 1_000_000;

/// Rounds per program and gate state; the fastest is kept, because a slower
/// round is this machine doing something else.
const ROUNDS: usize = 3;

/// Every gate bit set: what an estate with no rule of any kind publishes.
const ALL_EMPTY: u32 = 0x0001_FFFF;

/// One measured program.
struct Cost {
    object: &'static str,
    program: String,
    kind: &'static str,
    /// Average nanoseconds per run with nothing published.
    ungated_ns: u64,
    /// Average nanoseconds per run with every gate bit set.
    gated_ns: u64,
    /// What the program returned on the last run, for the record.
    retval: u32,
}

pub fn run() -> Result<()> {
    if !nix_is_root() {
        bail!("BPF_PROG_TEST_RUN needs root: re-run under sudo");
    }

    let packet = udp_v4_frame();
    let _ = std::fs::remove_dir_all(PIN_PATH);

    let mut costs: Vec<Cost> = Vec::new();
    let mut skipped: Vec<(&str, String)> = Vec::new();

    for object in EBPF_PROGRAMS {
        // Each object gets its own pin directory. Sharing one would hand the
        // second object the first one's maps, which is what production wants
        // and what a per-program measurement must not have: a table another
        // program filled is a lookup that hits.
        let pin = format!("{PIN_PATH}/{object}");
        let bytes = match std::fs::read(object_path(object)) {
            Ok(b) => b,
            Err(e) => {
                skipped.push((object, format!("read object: {e}")));
                continue;
            }
        };

        let loaded = match kfunc_loader::load_object_token(&bytes, &pin, None) {
            Ok(l) => l,
            Err(e) => {
                skipped.push((object, format!("load: {e}{}", module_hint(&e.to_string()))));
                continue;
            }
        };

        let kfunc_loader::TokenLoadedObject {
            mut maps, programs, ..
        } = loaded;

        // The gate array, where the object declares one. Held here rather than
        // looked up per program: every program in one object reads the same
        // kernel object, and taking it out of the collection twice would not
        // work anyway.
        let mut gates = maps
            .remove("FW_EMPTY_FEATURES")
            .and_then(|map| Array::<MapData, u32>::try_from(map).ok());

        for program in &programs {
            let kind = match prog_kind(program.prog_type) {
                Some(k) => k,
                // `BPF_PROG_TEST_RUN` takes a packet, so it reaches the two
                // hooks that carry one and nothing else. Say so rather than
                // passing over the program in silence: a report listing
                // fifteen of sixteen with no word about the sixteenth reads
                // as a measurement, and the absence is the interesting part.
                None => {
                    skipped.push((
                        object,
                        format!("{}: no test run for this program type", program.name),
                    ));
                    continue;
                }
            };

            let ungated = measure(program, &packet)?;
            publish_gates(gates.as_mut(), ALL_EMPTY);
            let gated = measure(program, &packet)?;
            publish_gates(gates.as_mut(), 0);

            costs.push(Cost {
                object,
                program: program.name.clone(),
                kind,
                ungated_ns: ungated.0,
                gated_ns: gated.0,
                retval: gated.1,
            });
        }
    }

    let _ = std::fs::remove_dir_all(PIN_PATH);
    report(&costs, &skipped);
    Ok(())
}

/// Write one mask into `FW_EMPTY_FEATURES`, where the object declares it.
///
/// A program that does not read the map is unaffected, which is why the
/// absence is silent rather than an error.
fn publish_gates(gates: Option<&mut Array<MapData, u32>>, mask: u32) {
    if let Some(array) = gates {
        let _ = array.set(0, mask, 0);
    }
}

/// Run one program `ROUNDS` times and keep the fastest average.
fn measure(program: &KfuncLoadedProgram, packet: &[u8]) -> Result<(u64, u32)> {
    // One unmeasured run pays for the first-touch costs - the fake device the
    // kernel builds for the run, the pages it allocates - so they do not land
    // on whichever program happens to be measured first.
    let _ = test_run(program.fd.as_fd(), packet, 1);

    let mut best = u64::MAX;
    let mut retval = 0;
    for _ in 0..ROUNDS {
        let (duration, ret) = test_run(program.fd.as_fd(), packet, REPEAT)
            .with_context(|| format!("test run {}", program.name))?;
        best = best.min(duration);
        retval = ret;
    }
    Ok((best, retval))
}

/// One `BPF_PROG_TEST_RUN`, returning (average ns per run, program return).
fn test_run(fd: BorrowedFd<'_>, packet: &[u8], repeat: u32) -> Result<(u64, u32)> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    {
        let test = unsafe { &mut attr.test };
        test.prog_fd = fd.as_raw_fd() as u32;
        test.repeat = repeat;
        test.data_in = packet.as_ptr() as u64;
        test.data_size_in = packet.len() as u32;
    }

    // SAFETY: `attr` is a zeroed `bpf_attr` with only the `test` arm written,
    // and the packet outlives the call.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            bpf_cmd::BPF_PROG_TEST_RUN as libc::c_long,
            std::ptr::addr_of_mut!(attr),
            mem::size_of::<bpf_attr>() as libc::c_long,
        )
    };
    if rc < 0 {
        return Err(anyhow!(std::io::Error::last_os_error()));
    }

    let test = unsafe { &attr.test };
    Ok((u64::from(test.duration), test.retval))
}

/// The two hooks this harness can hand a packet to.
fn prog_kind(prog_type: u32) -> Option<&'static str> {
    match prog_type {
        t if t == bpf_prog_type::BPF_PROG_TYPE_XDP as u32 => Some("XDP"),
        t if t == bpf_prog_type::BPF_PROG_TYPE_SCHED_CLS as u32 => Some("TC"),
        _ => None,
    }
}

/// The module a missing kfunc lives in, where we know it.
///
/// A kfunc exported by a module is absent from BTF until that module is
/// loaded, and the loader's refusal names the kfunc and not the module, so a
/// measurement run on a fresh machine reads as a broken program rather than as
/// a modprobe nobody ran.
fn module_hint(error: &str) -> &'static str {
    if error.contains("fou_encap") {
        " (kfunc lives in the `fou` module: modprobe fou fou6)"
    } else if error.contains("xfrm") {
        " (kfunc lives in the `xfrm_interface` module: modprobe xfrm_interface)"
    } else {
        ""
    }
}

fn object_path(object: &str) -> PathBuf {
    workspace_root()
        .join("target/bpfel-unknown-none/release")
        .join(object)
}

/// Where the built objects are, whoever invoked us.
///
/// This command needs root, so it is usually the built binary under `sudo`
/// rather than `cargo xtask`, and `sudo` runs it from whatever directory the
/// operator happened to be in. `CARGO_MANIFEST_DIR` is set only by cargo, so
/// fall back to the one baked in at compile time, which is this crate's own
/// directory two levels below the workspace root.
fn workspace_root() -> PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")));
    manifest
        .parent()
        .and_then(|p| p.parent())
        .map(Path::to_path_buf)
        .unwrap_or(manifest)
}

fn nix_is_root() -> bool {
    // SAFETY: `geteuid` takes no argument and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

/// A 64-byte Ethernet + IPv4 + UDP frame, the shape the pktgen lane sends.
fn udp_v4_frame() -> Vec<u8> {
    let mut frame = vec![0u8; 64];
    // Ethernet: broadcast-free unicast MACs, EtherType IPv4.
    frame[0..6].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x02]);
    frame[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    // IPv4: no options, UDP, 10.0.0.1 -> 10.0.0.2.
    frame[14] = 0x45;
    frame[15] = 0;
    frame[16..18].copy_from_slice(&(64u16 - 14).to_be_bytes());
    frame[22] = 64; // TTL
    frame[23] = 17; // UDP
    frame[26..30].copy_from_slice(&[10, 0, 0, 1]);
    frame[30..34].copy_from_slice(&[10, 0, 0, 2]);
    // UDP: an ephemeral source, a destination no program claims, so the
    // measurement is the path a packet takes when nothing matches it.
    frame[34..36].copy_from_slice(&1234u16.to_be_bytes());
    frame[36..38].copy_from_slice(&9u16.to_be_bytes());
    frame[38..40].copy_from_slice(&(64u16 - 34).to_be_bytes());
    frame
}

fn report(costs: &[Cost], skipped: &[(&str, String)]) {
    println!();
    println!("Per-program cost, one 64-byte UDP frame, average of {REPEAT} runs, best of {ROUNDS}");
    println!();
    println!(
        "{:<26} {:<6} {:>12} {:>12} {:>10}  retval",
        "program", "hook", "rules (ns)", "empty (ns)", "saved"
    );
    println!("{}", "-".repeat(84));
    for cost in costs {
        let saved = if cost.ungated_ns == 0 {
            String::from("-")
        } else {
            let delta = cost.ungated_ns as f64 - cost.gated_ns as f64;
            format!("{:.0}%", 100.0 * delta / cost.ungated_ns as f64)
        };
        println!(
            "{:<26} {:<6} {:>12} {:>12} {:>10}  {}",
            cost.program, cost.kind, cost.ungated_ns, cost.gated_ns, saved, cost.retval
        );
    }
    let ungated: u64 = costs.iter().map(|c| c.ungated_ns).sum();
    let gated: u64 = costs.iter().map(|c| c.gated_ns).sum();
    println!("{}", "-".repeat(84));
    println!("{:<26} {:<6} {ungated:>12} {gated:>12}", "sum", "");
    println!();
    println!("  object   the object the program was loaded from");
    for cost in costs {
        println!("  {:<24} {}", cost.program, cost.object);
    }
    if !skipped.is_empty() {
        println!();
        println!("not measured:");
        for (object, why) in skipped {
            println!("  {object}: {why}");
        }
    }
}
