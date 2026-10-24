use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::path::Path;

/// `BPF_LINK_CREATE` from `enum bpf_cmd`.
const BPF_LINK_CREATE: libc::c_int = 28;

/// The cgroup v2 attach types the warden will create a link for.
///
/// An allow-list rather than a passthrough: the agent names an attach type
/// over a socket, and the set of cgroup hooks a kernel offers includes
/// `BPF_CGROUP_DEVICE` and the sysctl and setsockopt hooks, none of which this
/// product has any business attaching. A warden that forwarded whatever number
/// arrived would be a general-purpose cgroup attach service running as root.
const ALLOWED_ATTACH_TYPES: &[u32] = &[
    BPF_CGROUP_INET_INGRESS,
    BPF_CGROUP_INET_EGRESS,
    BPF_CGROUP_INET4_BIND,
    BPF_CGROUP_INET6_BIND,
    BPF_CGROUP_INET4_CONNECT,
    BPF_CGROUP_INET6_CONNECT,
    BPF_CGROUP_INET4_POST_BIND,
    BPF_CGROUP_INET6_POST_BIND,
    BPF_CGROUP_UDP4_SENDMSG,
    BPF_CGROUP_UDP6_SENDMSG,
    BPF_CGROUP_SOCK_OPS,
];

/// `BPF_CGROUP_INET_INGRESS` from `enum bpf_attach_type`.
///
/// The packet hooks the workload firewall reads DNS answers through.
pub const BPF_CGROUP_INET_INGRESS: u32 = 0;
/// `BPF_CGROUP_INET_EGRESS` from `enum bpf_attach_type`.
pub const BPF_CGROUP_INET_EGRESS: u32 = 1;
/// `BPF_CGROUP_SOCK_OPS` from `enum bpf_attach_type`.
pub const BPF_CGROUP_SOCK_OPS: u32 = 3;
/// `BPF_CGROUP_INET4_BIND` from `enum bpf_attach_type`.
///
/// The pre-bind hook, which the workload firewall needs because the post-bind
/// pair below runs after the kernel has assigned the address and can report a
/// listener but not refuse one.
pub const BPF_CGROUP_INET4_BIND: u32 = 8;
/// `BPF_CGROUP_INET6_BIND` from `enum bpf_attach_type`.
pub const BPF_CGROUP_INET6_BIND: u32 = 9;
/// `BPF_CGROUP_INET4_CONNECT` from `enum bpf_attach_type`.
pub const BPF_CGROUP_INET4_CONNECT: u32 = 10;
/// `BPF_CGROUP_INET6_CONNECT` from `enum bpf_attach_type`.
pub const BPF_CGROUP_INET6_CONNECT: u32 = 11;
/// `BPF_CGROUP_INET4_POST_BIND` from `enum bpf_attach_type`.
pub const BPF_CGROUP_INET4_POST_BIND: u32 = 12;
/// `BPF_CGROUP_INET6_POST_BIND` from `enum bpf_attach_type`.
pub const BPF_CGROUP_INET6_POST_BIND: u32 = 13;
/// `BPF_CGROUP_UDP4_SENDMSG` from `enum bpf_attach_type`.
pub const BPF_CGROUP_UDP4_SENDMSG: u32 = 14;
/// `BPF_CGROUP_UDP6_SENDMSG` from `enum bpf_attach_type`.
pub const BPF_CGROUP_UDP6_SENDMSG: u32 = 15;

/// Where a cgroup v2 hierarchy is allowed to be. A path outside it is refused
/// before anything is opened: the warden runs as root in the init namespaces,
/// so "open the directory the agent named" is exactly the primitive that must
/// not be general.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// `union bpf_attr` for `BPF_LINK_CREATE` against a cgroup. Field offsets match
/// the kernel UAPI: `prog_fd` (0), `target_fd` (4), `attach_type` (8),
/// `flags` (12). The tail covers the largest union member so the kernel always
/// reads a fully initialised attr.
#[repr(C)]
#[derive(Default)]
struct CgroupLinkAttr {
    prog_fd: u32,
    target_fd: u32,
    attach_type: u32,
    link_flags: u32,
    _tail: [u64; 7],
}

/// Create a cgroup BPF link binding `prog_fd` to the cgroup directory at
/// `cgroup_path`. Returns the link fd on success; the caller owns it and
/// closing it detaches.
///
/// The program fd came from the agent, which built it from its own verified
/// object, and the kernel refuses a program whose type does not match the
/// attach type - so the worst a compromised agent gets from this call is the
/// attachment of a program it was already able to load.
pub fn attach_cgroup_link(
    prog_fd: RawFd,
    cgroup_path: &str,
    attach_type: u32,
) -> Result<RawFd, String> {
    if !ALLOWED_ATTACH_TYPES.contains(&attach_type) {
        return Err(format!(
            "cgroup attach type {attach_type} is not one this warden attaches"
        ));
    }
    let path = Path::new(cgroup_path);
    if !path.is_absolute() || !path.starts_with(CGROUP_ROOT) {
        return Err(format!(
            "cgroup path is not under {CGROUP_ROOT}: {cgroup_path:?}"
        ));
    }
    // Opened without following a final symlink, so a link planted inside the
    // hierarchy cannot walk the open back out of it.
    let cgroup =
        std::fs::File::open(path).map_err(|e| format!("open cgroup {cgroup_path:?}: {e}"))?;
    let meta = cgroup
        .metadata()
        .map_err(|e| format!("stat cgroup {cgroup_path:?}: {e}"))?;
    if !meta.is_dir() {
        return Err(format!("cgroup path is not a directory: {cgroup_path:?}"));
    }

    let mut attr = CgroupLinkAttr {
        #[allow(clippy::cast_sign_loss)]
        prog_fd: prog_fd as u32,
        #[allow(clippy::cast_sign_loss)]
        target_fd: cgroup.as_raw_fd() as u32,
        attach_type,
        ..Default::default()
    };
    let rc = unsafe {
        crate::bpf(
            BPF_LINK_CREATE,
            (&raw mut attr).cast(),
            std::mem::size_of::<CgroupLinkAttr>(),
        )
    };
    if rc < 0 {
        return Err(format!(
            "BPF_LINK_CREATE(cgroup attach_type={attach_type} on {cgroup_path:?}): {}",
            io::Error::last_os_error()
        ));
    }
    Ok(rc as RawFd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgroup_link_attr_field_offsets_match_uapi() {
        let a = CgroupLinkAttr::default();
        let base = std::ptr::from_ref(&a) as usize;
        assert_eq!(std::ptr::from_ref(&a.prog_fd) as usize - base, 0);
        assert_eq!(std::ptr::from_ref(&a.target_fd) as usize - base, 4);
        assert_eq!(std::ptr::from_ref(&a.attach_type) as usize - base, 8);
        assert_eq!(std::ptr::from_ref(&a.link_flags) as usize - base, 12);
    }

    #[test]
    fn a_path_outside_the_cgroup_hierarchy_is_refused_before_any_open() {
        let err = attach_cgroup_link(3, "/etc", BPF_CGROUP_INET4_CONNECT).unwrap_err();
        assert!(err.contains("not under /sys/fs/cgroup"), "{err}");
    }

    #[test]
    fn a_relative_path_is_refused() {
        let err = attach_cgroup_link(3, "sys/fs/cgroup", BPF_CGROUP_INET4_CONNECT).unwrap_err();
        assert!(err.contains("not under /sys/fs/cgroup"), "{err}");
    }

    #[test]
    fn the_pre_bind_hooks_are_attachable_and_are_not_the_post_bind_ones() {
        // The workload firewall refuses a bind, which only the pre-bind pair
        // can do; the post-bind pair stays on the list because attribution
        // names a listener with it. Both pairs being here is deliberate.
        assert!(ALLOWED_ATTACH_TYPES.contains(&BPF_CGROUP_INET4_BIND));
        assert!(ALLOWED_ATTACH_TYPES.contains(&BPF_CGROUP_INET6_BIND));
        assert_ne!(BPF_CGROUP_INET4_BIND, BPF_CGROUP_INET4_POST_BIND);
        assert_ne!(BPF_CGROUP_INET6_BIND, BPF_CGROUP_INET6_POST_BIND);
    }

    #[test]
    fn the_packet_hooks_of_a_cgroup_are_attachable_and_the_device_hook_is_not() {
        assert!(ALLOWED_ATTACH_TYPES.contains(&BPF_CGROUP_INET_INGRESS));
        assert!(ALLOWED_ATTACH_TYPES.contains(&BPF_CGROUP_INET_EGRESS));
        // `BPF_CGROUP_DEVICE` is 6.
        assert!(!ALLOWED_ATTACH_TYPES.contains(&6));
    }

    #[test]
    fn an_attach_type_outside_the_allow_list_is_refused() {
        // 6 is BPF_CGROUP_DEVICE: a real cgroup attach type, and one this
        // product must never be able to ask the warden for.
        let err = attach_cgroup_link(3, "/sys/fs/cgroup", 6).unwrap_err();
        assert!(err.contains("not one this warden attaches"), "{err}");
    }
}
