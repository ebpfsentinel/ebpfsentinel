//! A traced packet reads every map a live packet reads and writes none of them.
//!
//! Each entry program is loaded, every map it references is read in full, a
//! traced packet is run through it, and the maps are read again: they must be
//! byte for byte what they were, and no ring buffer may have moved. The same
//! packet is then run untraced, and somewhere across the set that run must
//! change something, or the comparison would be passing because nothing was
//! ever going to be written.
//!
//! Scratch maps are left out. They are per-CPU buffers a program writes to
//! carry its own parse from one stage to the next, read by nobody else and
//! overwritten by the next packet, so what the trace leaves there decides
//! nothing.
//!
//! Like the harness beside it, this needs the built objects and the privilege
//! to load them, and says so and returns without either.

use std::collections::BTreeMap;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::path::PathBuf;

use adapters::ebpf::loader::EbpfLoader;
use adapters::ebpf::prog_test_run::{self, SkbContext};
use ebpf_common::trace::{
    TC_TRACE_MARK, TC_TRACE_PRIORITY, tc_record, xdp_records, xdp_trace_metadata,
};

/// Object file, entry program, and whether it is an XDP program.
const TRACED_PROGRAMS: &[(&str, &str, bool)] = &[
    ("xdp-firewall", "xdp_firewall", true),
    ("xdp-ratelimit", "xdp_ratelimit", true),
    ("xdp-loadbalancer", "xdp_loadbalancer", true),
    ("tc-ids", "tc_ids", false),
    ("tc-threatintel", "tc_threatintel", false),
    ("tc-conntrack", "tc_conntrack", false),
    ("tc-scrub", "tc_scrub", false),
    ("tc-dns", "tc_dns", false),
    ("tc-qos", "tc_qos", false),
    ("tc-nat-ingress", "tc_nat_ingress", false),
    ("tc-nat-egress", "tc_nat_egress", false),
];

/// Per-CPU buffers a program carries its own parse in, as the kernel names
/// them: fifteen characters at most.
const SCRATCH_MAPS: &[&str] = &[
    "PKT_CTX",
    "CT_STATE_SCRATC",
    "FIB_PARAMS",
    "REJECT_SCRATCH",
    "SYNCOOKIE_CTX",
];

const BPF_MAP_LOOKUP_ELEM: libc::c_long = 1;
const BPF_MAP_GET_NEXT_KEY: libc::c_long = 4;
const BPF_MAP_GET_FD_BY_ID: libc::c_long = 14;
const BPF_OBJ_GET_INFO_BY_FD: libc::c_long = 15;

const MAP_PERCPU_HASH: u32 = 5;
const MAP_PERCPU_ARRAY: u32 = 6;
const MAP_LRU_PERCPU_HASH: u32 = 10;
const MAP_RINGBUF: u32 = 27;

/// Where the built objects are.
fn objects_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("EBPFSENTINEL_EBPF_DIR") {
        return PathBuf::from(dir);
    }
    let dir =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/bpfel-unknown-none/release");
    dir.canonicalize().unwrap_or(dir)
}

/// A TCP SYN over IPv4 over Ethernet.
fn tcp_syn() -> Vec<u8> {
    let mut pkt = Vec::with_capacity(54);
    pkt.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
    pkt.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x02]);
    pkt.extend_from_slice(&[0x08, 0x00]);
    pkt.extend_from_slice(&[0x45, 0x00, 0x00, 0x28]);
    pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
    pkt.extend_from_slice(&[0x40, 0x06, 0x00, 0x00]);
    pkt.extend_from_slice(&[10, 0, 0, 1]);
    pkt.extend_from_slice(&[10, 0, 0, 2]);
    pkt.extend_from_slice(&[0x04, 0x00, 0x00, 0x50]);
    pkt.extend_from_slice(&[0, 0, 0, 1]);
    pkt.extend_from_slice(&[0, 0, 0, 0]);
    pkt.extend_from_slice(&[0x50, 0x02, 0x20, 0x00]);
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    pkt
}

/// One `bpf(2)` call over an attribute buffer.
fn bpf(cmd: libc::c_long, attr: &mut [u8]) -> Result<libc::c_long, i32> {
    // SAFETY: every attribute buffer handed in here is at least as long as
    // the union member the command reads, and every pointer written into it
    // points at a buffer that outlives the call.
    let ret = unsafe { libc::syscall(libc::SYS_bpf, cmd, attr.as_mut_ptr(), attr.len()) };
    if ret < 0 {
        Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
    } else {
        Ok(ret)
    }
}

fn put_u32(buf: &mut [u8], at: usize, value: u32) {
    buf[at..at + 4].copy_from_slice(&value.to_ne_bytes());
}

fn put_u64(buf: &mut [u8], at: usize, value: u64) {
    buf[at..at + 8].copy_from_slice(&value.to_ne_bytes());
}

fn get_u32(buf: &[u8], at: usize) -> u32 {
    u32::from_ne_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]])
}

/// `BPF_OBJ_GET_INFO_BY_FD` into a buffer of `len` bytes.
fn info_by_fd(fd: RawFd, info: &mut [u8]) -> Result<(), i32> {
    let mut attr = [0u8; 16];
    put_u32(&mut attr, 0, u32::try_from(fd).unwrap_or(0));
    put_u32(&mut attr, 4, u32::try_from(info.len()).unwrap_or(0));
    put_u64(&mut attr, 8, info.as_mut_ptr() as u64);
    bpf(BPF_OBJ_GET_INFO_BY_FD, &mut attr).map(|_| ())
}

/// Every map a program references, by id.
fn map_ids(prog_fd: RawFd) -> Vec<u32> {
    let mut ids = vec![0u32; 64];
    let mut info = [0u8; 64];
    // `nr_map_ids` at 52 and `map_ids` at 56 in `struct bpf_prog_info`.
    put_u32(&mut info, 52, u32::try_from(ids.len()).unwrap_or(0));
    put_u64(&mut info, 56, ids.as_mut_ptr() as u64);
    info_by_fd(prog_fd, &mut info).expect("program info");
    let count = (get_u32(&info, 52) as usize).min(ids.len());
    ids.truncate(count);
    ids
}

/// A map opened by id, with what its info says about it.
struct OpenMap {
    fd: OwnedFd,
    kind: u32,
    key_size: usize,
    value_size: usize,
    name: String,
}

fn open_map(id: u32) -> OpenMap {
    let mut attr = [0u8; 12];
    put_u32(&mut attr, 0, id);
    let raw = bpf(BPF_MAP_GET_FD_BY_ID, &mut attr).expect("map by id");
    // SAFETY: the kernel just handed this descriptor over and nothing else
    // holds it.
    let fd = unsafe { OwnedFd::from_raw_fd(RawFd::try_from(raw).expect("descriptor")) };
    let mut info = [0u8; 40];
    info_by_fd(fd.as_raw_fd(), &mut info).expect("map info");
    let name_bytes = &info[24..40];
    let end = name_bytes.iter().position(|b| *b == 0).unwrap_or(16);
    OpenMap {
        kind: get_u32(&info, 0),
        key_size: get_u32(&info, 8) as usize,
        value_size: get_u32(&info, 12) as usize,
        name: String::from_utf8_lossy(&name_bytes[..end]).into_owned(),
        fd,
    }
}

/// How many CPUs a per-CPU value is laid out for.
fn possible_cpus() -> usize {
    let text = std::fs::read_to_string("/sys/devices/system/cpu/possible").expect("possible cpus");
    text.trim()
        .split(',')
        .map(|range| match range.split_once('-') {
            Some((lo, hi)) => {
                hi.parse::<usize>().unwrap_or(0) + 1 - lo.parse::<usize>().unwrap_or(0)
            }
            None => 1,
        })
        .sum()
}

/// What a map holds, as something two readings can be compared by.
#[derive(Debug, PartialEq, Eq)]
enum Contents {
    Entries(BTreeMap<Vec<u8>, Vec<u8>>),
    /// A ring buffer is read by where its producer stands: an event written
    /// moves it, whether or not anybody consumed it.
    Producer(u64),
}

fn producer_position(map: &OpenMap) -> u64 {
    // SAFETY: page size is a plain query with no arguments.
    let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).expect("page size");
    // SAFETY: a ring buffer exposes its producer page read-only at one page
    // in; the mapping is read once and unmapped before return.
    unsafe {
        let addr = libc::mmap(
            std::ptr::null_mut(),
            page,
            libc::PROT_READ,
            libc::MAP_SHARED,
            map.fd.as_raw_fd(),
            libc::off_t::try_from(page).expect("offset"),
        );
        assert_ne!(
            addr,
            libc::MAP_FAILED,
            "cannot map the {} producer page",
            map.name
        );
        let position = std::ptr::read_volatile(addr.cast::<u64>());
        libc::munmap(addr, page);
        position
    }
}

/// Read a map in full, or `None` for a kind the syscall interface cannot
/// read back, such as a program array.
fn read_map(map: &OpenMap, cpus: usize) -> Option<Contents> {
    if map.kind == MAP_RINGBUF {
        return Some(Contents::Producer(producer_position(map)));
    }
    let value_len = if matches!(
        map.kind,
        MAP_PERCPU_HASH | MAP_PERCPU_ARRAY | MAP_LRU_PERCPU_HASH
    ) {
        map.value_size.div_ceil(8) * 8 * cpus
    } else {
        map.value_size
    };
    let fd = u32::try_from(map.fd.as_raw_fd()).unwrap_or(0);
    let mut entries = BTreeMap::new();
    let mut key: Option<Vec<u8>> = None;
    loop {
        let mut next = vec![0u8; map.key_size];
        let mut attr = [0u8; 32];
        put_u32(&mut attr, 0, fd);
        put_u64(&mut attr, 8, key.as_ref().map_or(0, |k| k.as_ptr() as u64));
        put_u64(&mut attr, 16, next.as_mut_ptr() as u64);
        match bpf(BPF_MAP_GET_NEXT_KEY, &mut attr) {
            Ok(_) => {}
            Err(libc::ENOENT) => break,
            Err(_) => return None,
        }
        let mut value = vec![0u8; value_len];
        let mut attr = [0u8; 32];
        put_u32(&mut attr, 0, fd);
        put_u64(&mut attr, 8, next.as_ptr() as u64);
        put_u64(&mut attr, 16, value.as_mut_ptr() as u64);
        match bpf(BPF_MAP_LOOKUP_ELEM, &mut attr) {
            Ok(_) => {
                entries.insert(next.clone(), value);
            }
            // Removed between the two calls, which nothing here does.
            Err(libc::ENOENT) => {}
            Err(_) => return None,
        }
        key = Some(next);
    }
    Some(Contents::Entries(entries))
}

/// Every readable, non-scratch map the program references.
fn snapshot(maps: &[OpenMap], cpus: usize) -> BTreeMap<String, Contents> {
    maps.iter()
        .filter(|m| !SCRATCH_MAPS.contains(&m.name.as_str()))
        .filter_map(|m| read_map(m, cpus).map(|c| (m.name.clone(), c)))
        .collect()
}

/// Run a traced packet once and say whether the program left a record of
/// its verdict.
fn run_traced(
    fd: BorrowedFd<'_>,
    xdp: bool,
    packet: &[u8],
) -> Result<bool, prog_test_run::TestRunError> {
    if xdp {
        let (_, meta_out) =
            prog_test_run::run_xdp_with_metadata(fd, &xdp_trace_metadata(), packet)?;
        Ok(xdp_records(&meta_out).1 > 0)
    } else {
        let ctx = SkbContext {
            mark: TC_TRACE_MARK,
            priority: TC_TRACE_PRIORITY,
            cb: [0; 5],
        };
        let (outcome, ctx_out) = prog_test_run::run_tc_with_context(fd, packet, ctx)?;
        Ok(tc_record(&ctx_out.cb, outcome.retval).is_some())
    }
}

#[test]
fn a_traced_packet_leaves_every_map_as_it_found_it() {
    let dir = objects_dir();
    if !dir.join("xdp-firewall").is_file() {
        eprintln!("skipped: no eBPF objects in {}", dir.display());
        return;
    }
    let cpus = possible_cpus();
    let packet = tcp_syn();
    let mut traced_programs = 0usize;
    let mut untraced_writes = 0usize;

    for (object, program, xdp) in TRACED_PROGRAMS {
        let bytes = std::fs::read(dir.join(object)).expect("object");
        let pin_path = format!("/sys/fs/bpf/ebpfsentinel-trace-test/{object}");
        // A run that died half way leaves its maps pinned; start from none.
        EbpfLoader::cleanup_pin_path(&pin_path);
        let loaded = match EbpfLoader::load_with_pin_path(&bytes, &pin_path) {
            Ok(loaded) => loaded,
            Err(e) => {
                let message = e.to_string();
                assert!(
                    !message.contains("verifier log"),
                    "the verifier rejected {object}: {message}"
                );
                if traced_programs == 0 {
                    eprintln!("skipped: cannot load eBPF objects here: {message}");
                    return;
                }
                panic!("{object} did not load where the others did: {message}");
            }
        };
        let raw = loaded
            .program_fd(program)
            .unwrap_or_else(|| panic!("{object} loaded without {program}"));
        // SAFETY: the loader owns the descriptor and outlives every use of
        // this borrow below.
        let prog = unsafe { BorrowedFd::borrow_raw(raw) };
        let maps: Vec<OpenMap> = map_ids(raw).into_iter().map(open_map).collect();

        let before = snapshot(&maps, cpus);
        let recorded = run_traced(prog, *xdp, &packet)
            .unwrap_or_else(|e| panic!("traced test run of {program}: {e:?}"));
        let after = snapshot(&maps, cpus);
        for (name, contents) in &before {
            assert_eq!(
                Some(contents),
                after.get(name),
                "a traced packet changed {name} in {program}"
            );
        }
        assert!(
            recorded,
            "{program} left no record of its verdict on a traced packet"
        );
        traced_programs += 1;

        // Live traffic carries no metadata and no context at all.
        prog_test_run::run(prog, &packet, 1).expect("untraced test run");
        if snapshot(&maps, cpus) != after {
            untraced_writes += 1;
        }

        drop(maps);
        drop(loaded);
        EbpfLoader::cleanup_pin_path(&pin_path);
    }

    assert!(
        untraced_writes > 0,
        "no program wrote anything for the untraced packet either, so the comparison proves nothing"
    );
    eprintln!(
        "{traced_programs} programs traced without a write; {untraced_writes} of them wrote for the same packet untraced"
    );
}
