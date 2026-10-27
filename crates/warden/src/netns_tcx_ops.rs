use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// `BPF_LINK_CREATE` from `enum bpf_cmd`.
const BPF_LINK_CREATE: libc::c_int = 28;

/// `BPF_TCX_INGRESS` from `enum bpf_attach_type`.
pub const BPF_TCX_INGRESS: u32 = 46;
/// `BPF_TCX_EGRESS` from `enum bpf_attach_type`.
pub const BPF_TCX_EGRESS: u32 = 47;

/// `IFNAMSIZ` from `linux/if.h`, terminating NUL included.
const IFNAMSIZ: usize = 16;

/// `union bpf_attr` for `BPF_LINK_CREATE` against a TCX hook. Field offsets
/// match the kernel UAPI: `prog_fd` (0), `target_ifindex` (4), `attach_type`
/// (8), `flags` (12), then the `tcx` member: `relative_fd` (16) and
/// `expected_revision` (24). Zero in both appends the program at the end of
/// the chain, which is what the agent's own order relies on. The tail covers
/// the largest union member so the kernel always reads a fully initialised
/// attr.
#[repr(C)]
#[derive(Default)]
struct TcxLinkAttr {
    prog_fd: u32,
    target_ifindex: u32,
    attach_type: u32,
    link_flags: u32,
    relative_fd: u32,
    _pad: u32,
    expected_revision: u64,
    _tail: [u64; 5],
}

/// Attach the TC program behind `prog_fd` on interface `iface` inside the
/// network namespace of process `pid`, on the ingress or the egress hook.
/// Returns the link fd; the caller owns it and closing it detaches.
///
/// The warden runs as root in the init namespaces, so "enter the namespace of
/// the process the agent named" is the primitive that must not be general. It
/// is fenced three ways before anything is entered: the process must sit in a
/// cgroup the kubelet made for a pod, its namespace must be neither the host's
/// nor the warden's own, and the interface name must be one the kernel could
/// hold. The namespace is entered on a thread of its own that ends with the
/// call, so no other request the warden serves ever runs inside a pod.
pub fn attach_tcx_in_netns(
    prog_fd: RawFd,
    proc_root: &Path,
    pid: u32,
    iface: &str,
    egress: bool,
) -> Result<RawFd, String> {
    let name = interface_name(iface)?;
    let netns = pod_namespace(proc_root, pid)?;
    let attach_type = if egress {
        BPF_TCX_EGRESS
    } else {
        BPF_TCX_INGRESS
    };
    let iface = iface.to_string();
    std::thread::spawn(move || {
        // SAFETY: `setns` takes an fd and a flag, no memory; it moves only this throwaway
        // thread, which ends with the closure, so no other thread of the warden changes
        // namespace.
        if unsafe { libc::setns(netns.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
            return Err(format!(
                "setns into the namespace of pid {pid}: {}",
                io::Error::last_os_error()
            ));
        }
        // SAFETY: `name` is a NUL-terminated `CString` that outlives the call.
        let ifindex = unsafe { libc::if_nametoindex(name.as_ptr()) };
        if ifindex == 0 {
            return Err(format!(
                "no interface {iface:?} in the namespace of pid {pid}"
            ));
        }
        let mut attr = TcxLinkAttr {
            #[allow(clippy::cast_sign_loss)]
            prog_fd: prog_fd as u32,
            target_ifindex: ifindex,
            attach_type,
            ..Default::default()
        };
        // SAFETY: `attr` is a live, correctly sized `bpf_attr` prefix for `BPF_LINK_CREATE`,
        // and the size passed is its own.
        let rc = unsafe {
            crate::bpf(
                BPF_LINK_CREATE,
                (&raw mut attr).cast(),
                std::mem::size_of::<TcxLinkAttr>(),
            )
        };
        if rc < 0 {
            return Err(format!(
                "BPF_LINK_CREATE(tcx attach_type={attach_type} on {iface:?} in the namespace of pid {pid}): {}",
                io::Error::last_os_error()
            ));
        }
        Ok(rc as RawFd)
    })
    .join()
    .unwrap_or_else(|_| Err("the namespace attach thread panicked".to_string()))
}

/// The interface name as the kernel takes it, refused when it could not name
/// an interface at all.
fn interface_name(iface: &str) -> Result<CString, String> {
    if iface.is_empty() || iface.len() >= IFNAMSIZ {
        return Err(format!("{iface:?} is not an interface name"));
    }
    CString::new(iface).map_err(|_| format!("interface name {iface:?} carries a NUL"))
}

/// Open the network namespace of `pid`, refused unless it belongs to a pod.
fn pod_namespace(proc_root: &Path, pid: u32) -> Result<File, String> {
    if pid <= 1 {
        return Err(format!("pid {pid} is not a pod's process"));
    }
    let process = proc_root.join(pid.to_string());
    let cgroup = std::fs::read_to_string(process.join("cgroup"))
        .map_err(|e| format!("read the cgroup of pid {pid}: {e}"))?;
    if !in_pod_cgroup(&cgroup) {
        return Err(format!(
            "pid {pid} is not in a cgroup the kubelet made for a pod"
        ));
    }
    let netns = File::open(process.join("ns").join("net"))
        .map_err(|e| format!("open the network namespace of pid {pid}: {e}"))?;
    let inode = netns
        .metadata()
        .map_err(|e| format!("stat the network namespace of pid {pid}: {e}"))?
        .ino();
    for (whose, path) in [
        ("the host's", proc_root.join("1").join("ns").join("net")),
        (
            "the warden's own",
            Path::new("/proc/self/ns/net").to_path_buf(),
        ),
    ] {
        if std::fs::metadata(&path).is_ok_and(|meta| meta.ino() == inode) {
            return Err(format!(
                "pid {pid} shares {whose} network namespace, which is not a pod's"
            ));
        }
    }
    Ok(netns)
}

/// Whether a `/proc/<pid>/cgroup` payload places the process below the
/// kubelet's pod hierarchy: a path through `kubepods` with a directory named
/// after a pod uid, which is `pod<uid>` under the cgroupfs driver and
/// `kubepods-<class>-pod<uid>.slice`, dashes as underscores, under systemd.
fn in_pod_cgroup(payload: &str) -> bool {
    payload.lines().any(|line| {
        line.splitn(3, ':')
            .nth(2)
            .is_some_and(|path| path.contains("kubepods") && path.split('/').any(names_a_pod))
    })
}

/// The length of a pod uid as the API writes it.
const UID_LEN: usize = 36;

/// Whether a cgroup directory is named after a pod uid.
fn names_a_pod(name: &str) -> bool {
    let Some(start) = name.rfind("pod").map(|at| at + 3) else {
        return false;
    };
    let Some(candidate) = name.get(start..start + UID_LEN) else {
        return false;
    };
    let rest = &name[start + UID_LEN..];
    (rest.is_empty() || rest == ".slice")
        && candidate.char_indices().all(|(index, c)| match index {
            8 | 13 | 18 | 23 => c == '-' || c == '_',
            _ => c.is_ascii_hexdigit(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYSTEMD: &str = "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod6f1c2d3e_4a5b_4c6d_8e7f_0123456789ab.slice/cri-containerd-abc.scope\n";
    const CGROUPFS: &str = "0::/kubepods/besteffort/pod6f1c2d3e-4a5b-4c6d-8e7f-0123456789ab/abc\n";

    #[test]
    fn tcx_link_attr_field_offsets_match_uapi() {
        let a = TcxLinkAttr::default();
        let base = std::ptr::from_ref(&a) as usize;
        assert_eq!(std::ptr::from_ref(&a.prog_fd) as usize - base, 0);
        assert_eq!(std::ptr::from_ref(&a.target_ifindex) as usize - base, 4);
        assert_eq!(std::ptr::from_ref(&a.attach_type) as usize - base, 8);
        assert_eq!(std::ptr::from_ref(&a.link_flags) as usize - base, 12);
        assert_eq!(std::ptr::from_ref(&a.relative_fd) as usize - base, 16);
        assert_eq!(std::ptr::from_ref(&a.expected_revision) as usize - base, 24);
        assert_eq!(std::mem::size_of::<TcxLinkAttr>(), 72);
    }

    #[test]
    fn both_kubelet_drivers_place_a_process_in_a_pod() {
        assert!(in_pod_cgroup(SYSTEMD));
        assert!(in_pod_cgroup(CGROUPFS));
    }

    #[test]
    fn a_host_service_and_the_bare_pod_slice_are_not_a_pod() {
        assert!(!in_pod_cgroup("0::/system.slice/sshd.service\n"));
        assert!(!in_pod_cgroup("0::/\n"));
        assert!(!in_pod_cgroup("0::/kubepods.slice\n"));
        assert!(!in_pod_cgroup(
            "0::/kubepods.slice/kubepods-burstable.slice\n"
        ));
    }

    #[test]
    fn an_interface_name_the_kernel_could_not_hold_is_refused() {
        assert!(interface_name("eth0").is_ok());
        assert!(interface_name("lo").is_ok());
        for bad in ["", "an-interface-name-too-long", "eth\0"] {
            assert!(interface_name(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_init_process_and_pid_zero_are_refused_before_any_read() {
        for pid in [0, 1] {
            let err =
                attach_tcx_in_netns(3, Path::new("/nonexistent"), pid, "eth0", false).unwrap_err();
            assert!(err.contains("not a pod's process"), "{err}");
        }
    }

    #[test]
    fn a_process_outside_a_pod_is_refused_before_its_namespace_is_opened() {
        let proc_root = tempfile::tempdir().unwrap();
        let process = proc_root.path().join("4242");
        std::fs::create_dir_all(&process).unwrap();
        std::fs::write(process.join("cgroup"), "0::/system.slice/sshd.service\n").unwrap();
        let err = attach_tcx_in_netns(3, proc_root.path(), 4242, "eth0", true).unwrap_err();
        assert!(
            err.contains("not in a cgroup the kubelet made for a pod"),
            "{err}"
        );
    }

    #[test]
    fn a_pod_process_sharing_the_host_namespace_is_refused() {
        // A pod with hostNetwork sits in a pod cgroup and in the host's
        // namespace: its "inside" is the node, which belongs to the node agent.
        let proc_root = tempfile::tempdir().unwrap();
        let host = proc_root.path().join("1").join("ns");
        std::fs::create_dir_all(&host).unwrap();
        std::fs::write(host.join("net"), "").unwrap();
        let process = proc_root.path().join("4242");
        std::fs::create_dir_all(process.join("ns")).unwrap();
        std::fs::write(process.join("cgroup"), CGROUPFS).unwrap();
        std::fs::hard_link(host.join("net"), process.join("ns").join("net")).unwrap();
        let err = attach_tcx_in_netns(3, proc_root.path(), 4242, "eth0", false).unwrap_err();
        assert!(err.contains("the host's network namespace"), "{err}");
    }

    #[test]
    fn a_bad_interface_name_is_refused_before_the_process_is_read() {
        let err =
            attach_tcx_in_netns(3, Path::new("/nonexistent"), 4242, "eth\0", false).unwrap_err();
        assert!(err.contains("NUL"), "{err}");
    }
}
