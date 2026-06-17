//! Brokered uprobe attach.
//!
//! Creates a `uprobe_multi` `BPF_LINK_CREATE` on behalf of the rootless agent,
//! which dropped the tracing capability the link needs. The agent resolves the
//! symbol offset (a plain ELF read) and hands the warden the target `path`, the
//! `offset`, the `is_ret` flag, and — over `SCM_RIGHTS` — its own verified eBPF
//! program fd. The warden resolves `path` in its init mount + pid namespace, so a
//! neighbouring container's `/proc/<pid>/root/<lib>` is reachable, and returns the
//! resulting link fd to the agent.

use std::ffi::CString;
use std::io;
use std::os::fd::RawFd;

/// `BPF_LINK_CREATE` from `enum bpf_cmd`.
const BPF_LINK_CREATE: libc::c_int = 28;
/// `BPF_TRACE_UPROBE_MULTI` from `enum bpf_attach_type`.
const BPF_TRACE_UPROBE_MULTI: u32 = 48;
/// `BPF_F_UPROBE_MULTI_RETURN`: the link fires on function return (uretprobe).
const BPF_F_UPROBE_MULTI_RETURN: u32 = 1;

/// `union bpf_attr` for `BPF_LINK_CREATE` with the `uprobe_multi` member. Field
/// offsets match the kernel UAPI: `prog_fd` (0), `attach_type` (8), `flags` (12),
/// then the `uprobe_multi` block `{ path(16), offsets(24), ref_ctr_offsets(32),
/// cookies(40), cnt(48), flags(52), pid(56) }`.
#[repr(C)]
#[derive(Default)]
struct UprobeMultiLinkAttr {
    prog_fd: u32,
    target_fd: u32,
    attach_type: u32,
    link_flags: u32,
    path: u64,
    offsets: u64,
    ref_ctr_offsets: u64,
    cookies: u64,
    cnt: u32,
    umulti_flags: u32,
    pid: u32,
    _pad: u32,
    _tail: [u64; 2],
}

/// Create a `uprobe_multi` BPF link binding `prog_fd` to `offset` within the ELF
/// at `path` (system-wide, `pid = 0`). `is_ret` selects a uretprobe. Returns the
/// link fd on success. The caller owns the returned fd (closing it detaches).
pub fn attach_uprobe_link(
    prog_fd: RawFd,
    path: &str,
    offset: u64,
    is_ret: bool,
) -> Result<RawFd, String> {
    if !path.starts_with('/') {
        return Err(format!("uprobe target path is not absolute: {path:?}"));
    }
    let path_c = CString::new(path).map_err(|e| format!("uprobe path has NUL: {e}"))?;
    // A single-element offsets array, `cnt = 1`. Kept alive across the syscall.
    let offsets = [offset];

    let mut attr = UprobeMultiLinkAttr {
        prog_fd: prog_fd as u32,
        attach_type: BPF_TRACE_UPROBE_MULTI,
        path: path_c.as_ptr() as u64,
        offsets: offsets.as_ptr() as u64,
        cnt: 1,
        umulti_flags: if is_ret { BPF_F_UPROBE_MULTI_RETURN } else { 0 },
        ..Default::default()
    };

    // SAFETY: `attr` is a fully-initialised link-create attr of the advertised
    // size; `path`/`offsets` point at live, correctly-sized buffers held above.
    let rc = unsafe {
        crate::bpf(
            BPF_LINK_CREATE,
            (&raw mut attr).cast(),
            std::mem::size_of::<UprobeMultiLinkAttr>(),
        )
    };
    if rc < 0 {
        return Err(format!(
            "BPF_LINK_CREATE(uprobe_multi offset={offset:#x} in {path:?}): {}",
            io::Error::last_os_error()
        ));
    }
    Ok(rc as RawFd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uprobe_multi_link_attr_field_offsets_match_uapi() {
        let a = UprobeMultiLinkAttr::default();
        let base = std::ptr::from_ref(&a) as usize;
        assert_eq!(std::ptr::from_ref(&a.prog_fd) as usize - base, 0);
        assert_eq!(std::ptr::from_ref(&a.attach_type) as usize - base, 8);
        assert_eq!(std::ptr::from_ref(&a.link_flags) as usize - base, 12);
        assert_eq!(std::ptr::from_ref(&a.path) as usize - base, 16);
        assert_eq!(std::ptr::from_ref(&a.offsets) as usize - base, 24);
        assert_eq!(std::ptr::from_ref(&a.cnt) as usize - base, 48);
        assert_eq!(std::ptr::from_ref(&a.umulti_flags) as usize - base, 52);
        assert_eq!(std::ptr::from_ref(&a.pid) as usize - base, 56);
    }

    #[test]
    fn relative_path_is_rejected() {
        let err = attach_uprobe_link(3, "usr/lib/libssl.so.3", 0x10, false).unwrap_err();
        assert!(err.contains("not absolute"));
    }
}
