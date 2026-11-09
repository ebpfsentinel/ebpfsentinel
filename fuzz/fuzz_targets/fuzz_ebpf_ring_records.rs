#![no_main]

//! The records the cgroup, LSM and tracepoint programs push into their ring
//! buffers, decoded the way the readers in `adapters::ebpf` decode them: a
//! length check, an unaligned read of the `#[repr(C)]` record, then the
//! adapter's own `parse`. The first byte picks the record, the rest is the
//! record as the ring would hand it over.

use core::mem::size_of;

use adapters::ebpf::{
    exec_network, process_event_reader, workload_dns_reader, workload_event_reader, write_refusal,
};
use ebpf_common::exec_network::ExecNetEvent;
use ebpf_common::process::ProcessEvent;
use ebpf_common::signal::SignalEvent;
use ebpf_common::workload_policy::{WorkloadDenialEvent, WorkloadDnsEvent};
use ebpf_common::write_refusal::WriteRefusalEvent;
use libfuzzer_sys::fuzz_target;

/// Read one `T` off the front of `bytes`, or nothing for a short record, the
/// way every ring reader does.
fn record<T: Copy>(bytes: &[u8]) -> Option<T> {
    if bytes.len() < size_of::<T>() {
        return None;
    }
    // SAFETY: the length is checked above, every type read here is
    // `#[repr(C)]` plain data valid for any bit pattern, and the read is
    // unaligned because a ring buffer guarantees no alignment.
    Some(unsafe { bytes.as_ptr().cast::<T>().read_unaligned() })
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, bytes)) = data.split_first() else {
        return;
    };
    match selector % 6 {
        // tracepoint-process: exec, fork, exit.
        0 => {
            if let Some(raw) = record::<ProcessEvent>(bytes) {
                let _ = format!("{:?}", process_event_reader::parse(&raw));
            }
        }
        // lsm-exec-network: a refused or reported socket open.
        1 => {
            if let Some(raw) = record::<ExecNetEvent>(bytes) {
                let _ = format!("{:?}", exec_network::parse(&raw));
            }
        }
        // cgroup-workload-firewall: a denial at connect, sendmsg or bind.
        2 => {
            if let Some(raw) = record::<WorkloadDenialEvent>(bytes) {
                let _ = format!("{:?}", workload_event_reader::parse(&raw));
            }
        }
        // cgroup-workload-firewall: a DNS query or answer seen for a workload.
        3 => {
            if let Some(raw) = record::<WorkloadDnsEvent>(bytes) {
                let _ = format!("{:?}", workload_dns_reader::parse(&raw));
            }
        }
        // lsm-write-refusal: with and without a watched directory known.
        4 => {
            if let Some(raw) = record::<WriteRefusalEvent>(bytes) {
                let _ = format!("{:?}", write_refusal::parse(&raw, None));
                let dir = String::from_utf8_lossy(bytes).into_owned();
                let _ = format!("{:?}", write_refusal::parse(&raw, Some(dir)));
            }
        }
        // tracepoint-signal: read whole and handed on as is.
        _ => {
            if let Some(raw) = record::<SignalEvent>(bytes) {
                let _ = format!("{raw:?}");
            }
        }
    }
});
