use std::ffi::CString;
use std::io;

/// `BPF_PROG_QUERY` from `enum bpf_cmd`.
const BPF_PROG_QUERY: libc::c_int = 16;
/// `BPF_TCX_INGRESS` and `BPF_TCX_EGRESS` from `enum bpf_attach_type`.
const BPF_TCX_INGRESS: u32 = 46;
const BPF_TCX_EGRESS: u32 = 47;

/// Programs read on the first attempt. A hook carrying more is answered with
/// `ENOSPC` and the count it really holds, and the read is repeated at that
/// size.
const FIRST_READ: usize = 64;
/// No TCX hook carries this many programs; the bound only keeps a racing
/// chain from turning the retry into an unbounded allocation.
const MAX_PROGRAMS: usize = 4096;

/// `union bpf_attr` for `BPF_PROG_QUERY`. Field offsets match the kernel UAPI:
/// `target_ifindex` (0), `attach_type` (4), `query_flags` (8), `attach_flags`
/// (12), `prog_ids` (16), `count` (24), then the `mprog` extension:
/// `prog_attach_flags` (32), `link_ids` (40), `link_attach_flags` (48),
/// `revision` (56).
#[repr(C)]
#[derive(Default)]
struct ProgQueryAttr {
    target_ifindex: u32,
    attach_type: u32,
    query_flags: u32,
    attach_flags: u32,
    prog_ids: u64,
    count: u32,
    _pad: u32,
    prog_attach_flags: u64,
    link_ids: u64,
    link_attach_flags: u64,
    revision: u64,
}

/// The program ids on `iface`'s TCX ingress or egress hook, first to run
/// first.
///
/// Read-only, and it names ids rather than handing out anything that reaches
/// a program: turning an id into a descriptor is `BPF_PROG_GET_FD_BY_ID`,
/// which this warden never issues on the agent's behalf.
pub fn tcx_chain(iface: &str, egress: bool) -> Result<Vec<u32>, String> {
    let name = CString::new(iface).map_err(|_| format!("interface name {iface:?} holds a NUL"))?;
    // SAFETY: `name` is a valid NUL-terminated string for the call.
    let ifindex = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if ifindex == 0 {
        return Err(format!(
            "no interface {iface:?}: {}",
            io::Error::last_os_error()
        ));
    }
    let attach_type = if egress {
        BPF_TCX_EGRESS
    } else {
        BPF_TCX_INGRESS
    };
    let mut capacity = FIRST_READ;
    loop {
        let mut ids = vec![0u32; capacity];
        let mut attr = ProgQueryAttr {
            target_ifindex: ifindex,
            attach_type,
            prog_ids: ids.as_mut_ptr() as u64,
            count: u32::try_from(capacity).unwrap_or(u32::MAX),
            ..Default::default()
        };
        // SAFETY: `attr` is a fully initialised `bpf_attr` prefix and
        // `prog_ids` points at `count` writable u32s that outlive the call.
        let rc = unsafe {
            crate::bpf(
                BPF_PROG_QUERY,
                (&raw mut attr).cast(),
                std::mem::size_of::<ProgQueryAttr>(),
            )
        };
        let held = attr.count as usize;
        if rc == 0 {
            ids.truncate(held.min(capacity));
            return Ok(ids);
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOSPC) && held > capacity && held <= MAX_PROGRAMS {
            capacity = held;
            continue;
        }
        let hook = if egress { "egress" } else { "ingress" };
        return Err(format!("BPF_PROG_QUERY(TCX {hook} on {iface}): {err}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_attr_field_offsets_match_uapi() {
        let a = ProgQueryAttr::default();
        let base = std::ptr::from_ref(&a) as usize;
        assert_eq!(std::ptr::from_ref(&a.attach_type) as usize - base, 4);
        assert_eq!(std::ptr::from_ref(&a.prog_ids) as usize - base, 16);
        assert_eq!(std::ptr::from_ref(&a.count) as usize - base, 24);
        assert_eq!(std::ptr::from_ref(&a.link_ids) as usize - base, 40);
        assert_eq!(std::ptr::from_ref(&a.revision) as usize - base, 56);
    }

    #[test]
    fn an_interface_that_does_not_exist_is_named() {
        let err = tcx_chain("no-such-if0", false).unwrap_err();
        assert!(err.contains("no-such-if0"), "{err}");
    }

    #[test]
    fn a_name_with_a_nul_is_refused_before_any_syscall() {
        assert!(tcx_chain("eth\0", true).unwrap_err().contains("NUL"));
    }
}
