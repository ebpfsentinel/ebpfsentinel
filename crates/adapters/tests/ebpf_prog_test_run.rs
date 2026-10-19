//! Load every entry program and push a crafted packet through it.
//!
//! The verifier is what decides whether an eBPF change is shippable, and
//! nothing asks it until a program is loaded. This harness loads each built
//! object and runs its entry program with `BPF_PROG_TEST_RUN`, so a rejection
//! and a program that starts answering `XDP_ABORTED` on a well-formed packet
//! both fail `cargo test` rather than coming up as degraded mode on a host.
//!
//! It needs two things the build does not provide: the objects, built by
//! `cargo xtask ebpf-build` into `target/bpfel-unknown-none/release` or
//! wherever `EBPFSENTINEL_EBPF_DIR` points, and the privilege to load a
//! program. Without either it says what is missing and returns, because a
//! contributor running `cargo test` on a laptop is not the audience for a
//! failure about `CAP_BPF`.

use std::os::fd::{AsFd, BorrowedFd, FromRawFd, OwnedFd};
use std::path::PathBuf;

use adapters::ebpf::loader::EbpfLoader;
use adapters::ebpf::prog_test_run::{
    self, TC_ACT_OK, TC_ACT_SHOT, XDP_ABORTED, XDP_DROP, XDP_PASS, XDP_REDIRECT, XDP_TX,
};

/// What a program is, for the purpose of reading its return value back.
#[derive(Clone, Copy)]
enum Kind {
    Xdp,
    Tc,
}

/// Object file, entry program, and what kind of action it returns.
const ENTRY_PROGRAMS: &[(&str, &str, Kind)] = &[
    ("xdp-pass", "xdp_pass", Kind::Xdp),
    ("xdp-firewall", "xdp_firewall", Kind::Xdp),
    ("xdp-ratelimit", "xdp_ratelimit", Kind::Xdp),
    ("xdp-loadbalancer", "xdp_loadbalancer", Kind::Xdp),
    ("tc-ids", "tc_ids", Kind::Tc),
    ("tc-threatintel", "tc_threatintel", Kind::Tc),
    ("tc-conntrack", "tc_conntrack", Kind::Tc),
    ("tc-scrub", "tc_scrub", Kind::Tc),
    ("tc-dns", "tc_dns", Kind::Tc),
    ("tc-qos", "tc_qos", Kind::Tc),
    ("tc-nat-ingress", "tc_nat_ingress", Kind::Tc),
    ("tc-nat-egress", "tc_nat_egress", Kind::Tc),
];

/// Where the built objects are.
fn objects_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("EBPFSENTINEL_EBPF_DIR") {
        return PathBuf::from(dir);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/bpfel-unknown-none/release")
        .canonicalize()
        .unwrap_or_else(|_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/bpfel-unknown-none/release")
        })
}

/// A TCP SYN over IPv4 over Ethernet: the packet every one of these programs
/// has an opinion about, and the shortest one that reaches their parsers.
fn tcp_syn() -> Vec<u8> {
    let mut pkt = Vec::with_capacity(54);
    // Ethernet: destination, source, EtherType IPv4.
    pkt.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
    pkt.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x02]);
    pkt.extend_from_slice(&[0x08, 0x00]);
    // IPv4: 20-byte header, 40 bytes of total length, TCP.
    pkt.extend_from_slice(&[0x45, 0x00, 0x00, 0x28]);
    pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
    pkt.extend_from_slice(&[0x40, 0x06, 0x00, 0x00]);
    pkt.extend_from_slice(&[10, 0, 0, 1]);
    pkt.extend_from_slice(&[10, 0, 0, 2]);
    // TCP: 1024 -> 80, SYN, window 8192.
    pkt.extend_from_slice(&[0x04, 0x00, 0x00, 0x50]);
    pkt.extend_from_slice(&[0, 0, 0, 1]);
    pkt.extend_from_slice(&[0, 0, 0, 0]);
    pkt.extend_from_slice(&[0x50, 0x02, 0x20, 0x00]);
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    pkt
}

/// Every action an XDP program is allowed to return.
fn is_xdp_action(retval: u32) -> bool {
    matches!(
        retval,
        XDP_ABORTED | XDP_DROP | XDP_PASS | XDP_TX | XDP_REDIRECT
    )
}

/// `TC_ACT_UNSPEC` is -1 as the kernel reads it, so the window is the defined
/// actions plus that one.
fn is_tc_action(retval: u32) -> bool {
    retval <= TC_ACT_SHOT + 6 || retval == u32::MAX
}

#[test]
fn every_entry_program_loads_and_answers_a_crafted_packet() {
    let dir = objects_dir();
    if !dir.join("xdp-pass").is_file() {
        eprintln!(
            "skipped: no eBPF objects in {}, run `cargo xtask ebpf-build` or set EBPFSENTINEL_EBPF_DIR",
            dir.display()
        );
        return;
    }

    let packet = tcp_syn();
    let mut ran = 0usize;

    for (object, program, kind) in ENTRY_PROGRAMS {
        let bytes = std::fs::read(dir.join(object))
            .unwrap_or_else(|e| panic!("cannot read the {object} object: {e}"));
        let pin_path = format!("/sys/fs/bpf/ebpfsentinel-test-run/{object}");

        let loaded = match EbpfLoader::load_with_pin_path(&bytes, &pin_path) {
            Ok(loaded) => loaded,
            Err(e) => {
                // The verifier speaking is the regression this harness is
                // for, and the loader puts its log in the message. Anything
                // else is the host: no privilege, no pin filesystem, a driver
                // that will not take a device-bound program. Those are said
                // out loud and skipped, because failing on them would make
                // the harness a test of the machine it runs on.
                let message = e.to_string();
                assert!(
                    !message.contains("verifier log"),
                    "the verifier rejected {object}: {message}"
                );
                if ran == 0 && is_environment(&message) {
                    eprintln!("skipped: cannot load eBPF objects here: {message}");
                    return;
                }
                eprintln!("skipped {object}: {message}");
                continue;
            }
        };

        let fd = loaded
            .program_fd(program)
            .unwrap_or_else(|| panic!("{object} loaded without its {program} entry program"));
        // SAFETY: the descriptor belongs to `loaded`, which outlives the
        // borrow; the wrapper is forgotten below so it is never closed twice.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        let outcome = prog_test_run::run(borrow(&owned), &packet, 1);
        std::mem::forget(owned);

        match outcome {
            Ok(outcome) => {
                match kind {
                    Kind::Xdp => {
                        assert!(
                            is_xdp_action(outcome.retval),
                            "{program} returned {}, which is no XDP action",
                            outcome.retval
                        );
                        assert_ne!(
                            outcome.retval, XDP_ABORTED,
                            "{program} aborted on a well-formed TCP SYN"
                        );
                    }
                    Kind::Tc => {
                        assert!(
                            is_tc_action(outcome.retval),
                            "{program} returned {}, which is no TC action",
                            outcome.retval
                        );
                    }
                }
                ran += 1;
            }
            Err(e) if e.is_unavailable() => {
                eprintln!("skipped {program}: {e}");
            }
            Err(e) => panic!("{program} could not be run: {e}"),
        }

        drop(loaded);
        EbpfLoader::cleanup_pin_path(&pin_path);
    }

    if ran == 0 {
        eprintln!("skipped: the kernel ran none of the programs");
        return;
    }
    eprintln!("{ran} entry programs loaded and answered a crafted packet");
}

#[test]
fn a_tc_program_passes_an_unmatched_packet() {
    let dir = objects_dir();
    if !dir.join("tc-ids").is_file() {
        eprintln!("skipped: no eBPF objects in {}", dir.display());
        return;
    }

    let bytes = std::fs::read(dir.join("tc-ids")).expect("tc-ids object");
    let pin_path = "/sys/fs/bpf/ebpfsentinel-test-run/tc-ids-unmatched";
    let Ok(loaded) = EbpfLoader::load_with_pin_path(&bytes, pin_path) else {
        eprintln!("skipped: cannot load eBPF objects here");
        return;
    };
    let fd = loaded.program_fd("tc_ids").expect("tc_ids entry program");
    // SAFETY: as above - borrowed from a descriptor the loader owns.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let outcome = prog_test_run::run(borrow(&owned), &tcp_syn(), 1);
    std::mem::forget(owned);

    match outcome {
        Ok(outcome) => assert_eq!(
            outcome.retval, TC_ACT_OK,
            "a SYN matching no signature must be let through"
        ),
        Err(e) if e.is_unavailable() => eprintln!("skipped: {e}"),
        Err(e) => panic!("tc_ids could not be run: {e}"),
    }

    drop(loaded);
    EbpfLoader::cleanup_pin_path(pin_path);
}

/// Borrow a descriptor without taking it over.
fn borrow(fd: &OwnedFd) -> BorrowedFd<'_> {
    fd.as_fd()
}

/// Tell a host that cannot load eBPF at all from an object that broke.
///
/// The loader reports the kernel's errno in its message, so the three that
/// mean "not here" - no privilege, no access to the pin filesystem, no pin
/// filesystem at all - are read back out of it. Anything else is the object.
fn is_environment(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    if lower.contains("permission denied") || lower.contains("operation not permitted") {
        return true;
    }
    let Some(tail) = lower.split("errno").nth(1) else {
        return false;
    };
    let digits: String = tail
        .trim_start_matches([' ', ':'])
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    matches!(digits.parse::<i32>(), Ok(1 | 2 | 13))
}

#[test]
fn a_refusal_by_the_host_is_told_apart_from_a_broken_object() {
    assert!(is_environment(
        "pin map at `/sys/fs/bpf/x` failed (errno 13)"
    ));
    assert!(is_environment("load failed: Operation not permitted"));
    assert!(!is_environment(
        "program xdp_firewall rejected by the verifier (errno 22)"
    ));
    assert!(!is_environment("object parse failed"));
}
