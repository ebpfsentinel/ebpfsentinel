#![allow(unsafe_code)] // Raw netlink and bpf() syscalls for attach introspection.

//! What is already attached to an interface, and why an attach was refused.
//!
//! The agent attaches every program through raw `BPF_LINK_CREATE`
//! ([`super::kfunc_attach`]). That is a `bpf(2)` command, and `bpf(2)` has no
//! extended-ack channel: the kernel answers with an errno and nothing else. So
//! "XDP program already attached" cannot arrive from the syscall - it has to be
//! established by asking the kernel what is on the interface.
//!
//! Three questions, three sources:
//!
//! - **What is attached here?** `RTM_GETLINK` over `NETLINK_ROUTE`, reading the
//!   `IFLA_XDP` nest. Read-only rtnetlink needs no capability, so this works on
//!   the token path where the rest of BPF introspection does not.
//! - **Is it ours?** `BPF_OBJ_GET_INFO_BY_FD` on our own program fd yields its
//!   id, which is comparable with the id the interface reports. Querying an fd
//!   we already hold needs no capability either.
//! - **Is it held by a BPF link?** [`aya::programs::loaded_links`]. This one
//!   needs `CAP_SYS_ADMIN` (`BPF_LINK_GET_NEXT_ID` and `BPF_LINK_GET_FD_BY_ID`
//!   both gate on it), so it answers `None` on the token path and the caller
//!   degrades rather than failing.

use std::io;
use std::mem::size_of;
use std::os::fd::RawFd;
use std::sync::{Mutex, OnceLock};

use aya::programs::links::LinkType;
use aya::programs::loaded_links;

/// `IFLA_XDP` - the XDP nest inside an `RTM_GETLINK` reply.
const IFLA_XDP: u16 = 43;
/// Members of the `IFLA_XDP` nest (`enum` order in `<linux/if_link.h>`).
const IFLA_XDP_ATTACHED: u16 = 2;
const IFLA_XDP_PROG_ID: u16 = 4;
/// `enum` values carried by `IFLA_XDP_ATTACHED`.
const XDP_ATTACHED_NONE: u8 = 0;
const XDP_ATTACHED_DRV: u8 = 1;
const XDP_ATTACHED_SKB: u8 = 2;
const XDP_ATTACHED_HW: u8 = 3;
const XDP_ATTACHED_MULTI: u8 = 4;

/// `BPF_OBJ_GET_INFO_BY_FD`.
const BPF_OBJ_GET_INFO_BY_FD: u32 = 15;

/// Which XDP mode an interface's program is running in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XdpAttachMode {
    /// Native, executed by the driver.
    Driver,
    /// Generic, executed by the network stack.
    Generic,
    /// Offloaded to the device.
    Hardware,
    /// More than one mode carries a program.
    Multiple,
    /// The kernel reported a mode this build does not know.
    Unknown,
}

/// Every XDP mode this build can report, as the label it is exported under.
///
/// The vocabulary is here rather than in the metrics registry because this is
/// the file that decides what the kernel's answer is called, and a second list
/// somewhere else is how a mode comes to be exported under a name nothing reads.
pub const XDP_ATTACH_MODES: [&str; 5] = ["native", "generic", "offloaded", "multiple", "unknown"];

impl XdpAttachMode {
    /// The label this mode is exported under.
    ///
    /// A slug rather than the sentence [`Display`](std::fmt::Display) writes: a
    /// label value is matched on at the far end, and "multiple modes" would put
    /// a space in the thing being matched.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Driver => "native",
            Self::Generic => "generic",
            Self::Hardware => "offloaded",
            Self::Multiple => "multiple",
            Self::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for XdpAttachMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Driver => "native",
            Self::Generic => "generic",
            Self::Hardware => "offloaded",
            Self::Multiple => "multiple modes",
            Self::Unknown => "unknown mode",
        };
        f.write_str(s)
    }
}

/// An XDP program the kernel reports on an interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XdpAttachment {
    /// Kernel id of the attached program. `0` when the kernel reports an
    /// attachment but withholds the id (multi-mode attachments do this).
    pub prog_id: u32,
    /// The mode it is attached in.
    pub mode: XdpAttachMode,
}

/// Ask rtnetlink what XDP program, if any, is attached to `ifindex`.
///
/// `Ok(None)` means the interface carries no XDP program. `Err` means the
/// question could not be asked - which is not the same answer and must not be
/// rendered as one.
pub fn xdp_attachment(ifindex: u32) -> Result<Option<XdpAttachment>, io::Error> {
    let reply = rtnl_getlink(ifindex)?;
    Ok(parse_xdp_nest(&reply))
}

/// Kernel id of a program we hold an fd for.
///
/// `None` when the kernel refuses the query, which on this path only happens if
/// the fd is closed or is not a program.
#[must_use]
pub fn program_id(prog_fd: RawFd) -> Option<u32> {
    #[repr(C)]
    #[derive(Default)]
    struct GetInfoAttr {
        bpf_fd: u32,
        info_len: u32,
        info: u64,
    }

    // `bpf_prog_info` is large and grows between kernels; we only read `id` at
    // offset 4. Over-allocating and letting the kernel fill what it knows is
    // the forward-compatible shape - it writes min(info_len, its own size).
    let mut info = [0u8; 256];
    #[allow(clippy::cast_sign_loss)]
    let mut attr = GetInfoAttr {
        bpf_fd: prog_fd as u32,
        info_len: u32::try_from(info.len()).unwrap_or(0),
        info: std::ptr::from_mut(&mut info).cast::<u8>() as u64,
    };
    // SAFETY: `attr` is a fully-initialised get-info attr of the advertised
    // size, pointing at a live buffer of `info_len` bytes.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            #[allow(clippy::cast_possible_wrap)]
            (BPF_OBJ_GET_INFO_BY_FD as libc::c_int),
            (&raw mut attr).cast::<libc::c_void>() as usize,
            size_of::<GetInfoAttr>(),
        )
    };
    if rc < 0 {
        return None;
    }
    // `struct bpf_prog_info { __u32 type; __u32 id; ... }`.
    Some(u32::from_ne_bytes([info[4], info[5], info[6], info[7]]))
}

/// Whether program `prog_id` is held by a BPF link.
///
/// `None` when link introspection is unavailable, which is the normal answer on
/// the token path: both `BPF_LINK_GET_NEXT_ID` and `BPF_LINK_GET_FD_BY_ID` gate
/// on `CAP_SYS_ADMIN`. The distinction matters because a link-held attachment
/// cannot be replaced by anyone but the process holding the link fd, whereas a
/// legacy netlink attachment can in principle be swapped.
#[must_use]
pub fn held_by_link(prog_id: u32) -> Option<bool> {
    let mut saw_any = false;
    let mut found = false;
    for info in loaded_links() {
        let Ok(info) = info else {
            // The very first failure is the permission one; treat the whole
            // enumeration as unavailable rather than reporting a partial "no".
            return if saw_any { Some(found) } else { None };
        };
        saw_any = true;
        if info.program_id() == prog_id
            && matches!(info.link_type(), Ok(LinkType::Xdp | LinkType::Netkit))
        {
            found = true;
        }
    }
    Some(found)
}

// ── attach blocks, recorded for /readyz and the ops endpoint ────────────

/// An attach the agent could not perform, with the reason in operator terms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachBlock {
    /// eBPF program that could not attach.
    pub program: String,
    /// Interface it was destined for.
    pub interface: String,
    /// One sentence naming what is in the way.
    pub reason: String,
    /// True when the obstacle is another XDP program already on the interface -
    /// the nested-XDP case, which is a property of the host rather than a fault
    /// in the agent.
    pub nested_xdp: bool,
}

impl std::fmt::Display for AttachBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} on {}: {}", self.program, self.interface, self.reason)
    }
}

fn blocks() -> &'static Mutex<Vec<AttachBlock>> {
    static BLOCKS: OnceLock<Mutex<Vec<AttachBlock>>> = OnceLock::new();
    BLOCKS.get_or_init(|| Mutex::new(Vec::new()))
}

/// Record an attach that could not be performed.
///
/// Replaces any earlier block for the same program/interface pair, so a retry
/// that succeeds elsewhere cannot leave two contradictory entries.
pub fn record_block(block: AttachBlock) {
    let Ok(mut guard) = blocks().lock() else {
        return;
    };
    guard.retain(|b| !(b.program == block.program && b.interface == block.interface));
    guard.push(block);
}

/// Forget any block recorded for this program/interface pair.
///
/// Called on a successful attach, so a reload that fixes the conflict clears
/// readiness instead of leaving it stuck on a stale reason.
pub fn clear_block(program: &str, interface: &str) {
    let Ok(mut guard) = blocks().lock() else {
        return;
    };
    guard.retain(|b| !(b.program == program && b.interface == interface));
}

/// Every attach currently blocked.
#[must_use]
pub fn blocked_attaches() -> Vec<AttachBlock> {
    blocks().lock().map(|g| g.clone()).unwrap_or_default()
}

/// Drop every recorded block. Used when the whole eBPF state is torn down, so
/// an HA deactivate does not carry its blocks into the next activate.
pub fn clear_all_blocks() {
    if let Ok(mut guard) = blocks().lock() {
        guard.clear();
    }
}

/// A refused XDP attach, explained.
pub struct XdpDiagnosis {
    /// One sentence an operator can act on.
    pub reason: String,
    /// Someone else's XDP program is sitting on the interface. Read back from
    /// rtnetlink rather than inferred from the errno: the kernel answers
    /// `EBUSY` when the occupied mode is the one we asked for and `EEXIST`
    /// when it is a different mode, and neither errno on its own proves an
    /// occupant is there.
    pub nested_xdp: bool,
}

/// Turn a refused XDP attach into a sentence an operator can act on.
///
/// `own_prog_id` is the id of the program we were trying to attach, so a
/// conflict with ourselves reads differently from a conflict with a stranger.
#[must_use]
pub fn diagnose_xdp(
    errno: i32,
    interface: &str,
    ifindex: u32,
    own_prog_id: Option<u32>,
) -> XdpDiagnosis {
    let existing = xdp_attachment(ifindex);
    let occupant = match &existing {
        Ok(Some(att)) => Some((att.prog_id, att.mode)),
        _ => None,
    };
    // An occupant that is our own program is not a nested-XDP situation: the
    // caller readopts it rather than competing with it.
    let nested_xdp = occupant.is_some_and(|(id, _)| Some(id) != own_prog_id || id == 0);

    let reason = match (errno, occupant) {
        (libc::EBUSY | libc::EEXIST, Some((prog_id, mode))) => {
            let owner = describe_owner(prog_id, own_prog_id);
            let held = match held_by_link(prog_id) {
                Some(true) => {
                    " It is held by a BPF link, so only the process owning that link can replace it."
                }
                Some(false) => " It is a legacy netlink attachment, not a BPF link.",
                None => "",
            };
            // EEXIST is the kernel refusing to mix modes: something is on the
            // interface in one mode and we asked for another. Saying so points
            // the operator at `xdp_mode` instead of at the occupant alone.
            let mixing = if errno == libc::EEXIST {
                " Native and generic XDP cannot both be active on one interface, so matching \
                 `agent.xdp_mode` to the attachment already there is the other way out."
            } else {
                ""
            };
            format!(
                "interface {interface} already has an XDP program attached (id {prog_id}, {mode})\
                 {owner}.{held} The kernel allows one XDP program per interface, so this one \
                 cannot attach on top.{mixing}"
            )
        }
        (libc::EBUSY | libc::EEXIST, None) => format!(
            "interface {interface} reports the XDP hook occupied, but no attached program could \
             be read back from rtnetlink - most likely a previous attachment still being released."
        ),
        (libc::EPERM, _) => format!(
            "attaching XDP to {interface} was refused as unprivileged. Under BPF-token loading \
             the token must delegate attach; check `delegate_attachs` on the bpffs mount."
        ),
        (libc::ENODEV | libc::ENOENT, _) => {
            format!("interface {interface} disappeared before the program could attach.")
        }
        (libc::EOPNOTSUPP, _) => format!(
            "the driver behind {interface} does not support the requested XDP mode. A generic \
             (SKB) attach usually works where a native one does not."
        ),
        _ => {
            let e = io::Error::from_raw_os_error(errno);
            match occupant {
                Some((prog_id, mode)) => format!(
                    "attaching XDP to {interface} failed: {e}. The interface already carries XDP \
                     program id {prog_id} ({mode})."
                ),
                None => format!("attaching XDP to {interface} failed: {e}"),
            }
        }
    };

    XdpDiagnosis { reason, nested_xdp }
}

/// Turn a refused TCX or netkit attach into a sentence an operator can act on.
///
/// `hook` names the hook in the words the operator would use ("TCX ingress",
/// "netkit peer"). Unlike XDP there is nothing to read back: the kernel exposes
/// no unprivileged listing of TCX or netkit link chains, so the diagnosis works
/// from the errno and the shape of the hook alone. That is still a long way
/// ahead of a bare `os error 17`.
#[must_use]
pub fn diagnose_link(errno: i32, hook: &str, interface: &str) -> String {
    match errno {
        libc::EEXIST => format!(
            "the {hook} hook on {interface} already carries this exact program. The kernel \
             refuses to link the same program to the same hook twice."
        ),
        libc::EPERM => format!(
            "attaching to the {hook} hook on {interface} was refused as unprivileged. Under \
             BPF-token loading the token must delegate attach; check `delegate_attachs` on the \
             bpffs mount."
        ),
        libc::ENODEV | libc::ENOENT => {
            format!("interface {interface} disappeared before the program could attach.")
        }
        libc::EOPNOTSUPP => format!(
            "the kernel refused a {hook} attach on {interface}. TCX needs kernel 6.6 and netkit \
             needs a netkit device; check that {interface} is the device type this hook expects."
        ),
        libc::EBUSY => format!(
            "the {hook} hook on {interface} is busy - most likely a previous attachment still \
             being released."
        ),
        _ => {
            let e = io::Error::from_raw_os_error(errno);
            format!("attaching to the {hook} hook on {interface} failed: {e}")
        }
    }
}

/// Whether the interface already carries the program we are about to attach.
///
/// The one case where re-attaching is both unnecessary and harmful: it would
/// fail with `EBUSY` after burning the retry budget, and on a kernel that did
/// allow it, it would leave two links where one belongs.
#[must_use]
pub fn already_carries(ifindex: u32, own_prog_id: Option<u32>) -> bool {
    let (Some(own), Ok(Some(att))) = (own_prog_id, xdp_attachment(ifindex)) else {
        return false;
    };
    att.prog_id != 0 && att.prog_id == own
}

fn describe_owner(existing_id: u32, own_prog_id: Option<u32>) -> String {
    if own_prog_id == Some(existing_id) {
        " which is this agent's own program".to_owned()
    } else {
        String::new()
    }
}

// ── rtnetlink ───────────────────────────────────────────────────────────

/// `struct nlmsghdr` from `<linux/netlink.h>`.
///
/// Spelled out here rather than taken from `libc` because the two workspaces
/// that build this crate resolve different `libc` patch releases, and the
/// netlink structs are not present in all of them. These are frozen UAPI; the
/// layout tests below pin the sizes.
#[repr(C)]
#[derive(Default)]
// The `nlmsg_` prefix is the kernel's own field naming. Renaming the fields to
// satisfy the lint would make this struct harder to check against the header it
// mirrors, which is the only thing that keeps it correct.
#[allow(clippy::struct_field_names)]
struct NlMsgHdr {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
}

/// `struct ifinfomsg` from `<linux/rtnetlink.h>`.
#[repr(C)]
#[derive(Default)]
struct IfInfoMsg {
    ifi_family: u8,
    __ifi_pad: u8,
    ifi_type: u16,
    ifi_index: i32,
    ifi_flags: u32,
    ifi_change: u32,
}

/// `RTM_GETLINK` / `RTM_NEWLINK` from `<linux/rtnetlink.h>`.
const RTM_GETLINK: u16 = 18;
const RTM_NEWLINK: u16 = 16;
/// `NLM_F_REQUEST` from `<linux/netlink.h>`.
const NLM_F_REQUEST: u16 = 0x001;

/// Issue `RTM_GETLINK` for one ifindex and return the raw reply bytes.
fn rtnl_getlink(ifindex: u32) -> Result<Vec<u8>, io::Error> {
    #[repr(C)]
    struct Request {
        nlh: NlMsgHdr,
        ifi: IfInfoMsg,
    }

    let len = u32::try_from(size_of::<Request>())
        .map_err(|_| io::Error::other("RTM_GETLINK request does not fit a u32 length"))?;
    // SAFETY: `Request` is `#[repr(C)]` over two all-integer kernel structs, so
    // an all-zero bit pattern is a valid value; every field that matters is
    // assigned right below.
    let mut req: Request = unsafe { std::mem::zeroed() };
    req.nlh.nlmsg_len = len;
    req.nlh.nlmsg_type = RTM_GETLINK;
    req.nlh.nlmsg_flags = NLM_F_REQUEST;
    req.nlh.nlmsg_seq = 1;
    req.ifi.ifi_family = u8::try_from(libc::AF_UNSPEC).unwrap_or(0);
    req.ifi.ifi_index = i32::try_from(ifindex).unwrap_or(i32::MAX);

    // SAFETY: a plain socket create; the fd is wrapped for RAII immediately.
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let sock = OwnedSocket(fd);

    // SAFETY: `req` is a fully-initialised message of the advertised length.
    let sent = unsafe {
        libc::send(
            sock.0,
            (&raw mut req).cast::<libc::c_void>(),
            size_of::<Request>(),
            0,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }

    // One interface's attributes; 8 KiB covers it with room to spare, and a
    // truncated reply simply yields no XDP nest rather than a wrong answer.
    let mut buf = vec![0u8; 8192];
    // SAFETY: `buf` is a live allocation of the advertised length.
    let got = unsafe {
        libc::recv(
            sock.0,
            buf.as_mut_ptr().cast::<libc::c_void>(),
            buf.len(),
            0,
        )
    };
    if got < 0 {
        return Err(io::Error::last_os_error());
    }
    #[allow(clippy::cast_sign_loss)]
    buf.truncate(got as usize);
    Ok(buf)
}

/// Close a raw socket fd on drop. `libc::socket` hands back a bare `int` and
/// every error path below would otherwise have to remember to close it.
struct OwnedSocket(libc::c_int);

impl Drop for OwnedSocket {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a socket fd this type owns and closes once.
        unsafe { libc::close(self.0) };
    }
}

/// Walk an `RTM_GETLINK` reply for the `IFLA_XDP` nest.
///
/// Split from the syscall so the parser is testable against captured bytes -
/// the alternative is a test that can only run as root with a live XDP program
/// on a real interface.
fn parse_xdp_nest(reply: &[u8]) -> Option<XdpAttachment> {
    let hdr_len = size_of::<NlMsgHdr>();
    let msg_len = u32::from_ne_bytes(reply.get(..4)?.try_into().ok()?) as usize;
    let msg_type = u16::from_ne_bytes(reply.get(4..6)?.try_into().ok()?);
    if msg_type != RTM_NEWLINK || msg_len > reply.len() {
        return None;
    }
    // Attributes start after the fixed `ifinfomsg`, aligned to 4 bytes.
    let attrs_start = nla_align(hdr_len + size_of::<IfInfoMsg>());
    let body = reply.get(attrs_start..msg_len)?;

    let xdp_nest = find_attr(body, IFLA_XDP)?;
    let attached = find_attr(xdp_nest, IFLA_XDP_ATTACHED)
        .and_then(|v| v.first().copied())
        .unwrap_or(XDP_ATTACHED_NONE);
    if attached == XDP_ATTACHED_NONE {
        return None;
    }
    let prog_id = find_attr(xdp_nest, IFLA_XDP_PROG_ID)
        .and_then(|v| v.get(..4))
        .and_then(|v| v.try_into().ok())
        .map_or(0, u32::from_ne_bytes);

    Some(XdpAttachment {
        prog_id,
        mode: match attached {
            XDP_ATTACHED_DRV => XdpAttachMode::Driver,
            XDP_ATTACHED_SKB => XdpAttachMode::Generic,
            XDP_ATTACHED_HW => XdpAttachMode::Hardware,
            XDP_ATTACHED_MULTI => XdpAttachMode::Multiple,
            _ => XdpAttachMode::Unknown,
        },
    })
}

/// Netlink attributes are padded to a 4-byte boundary.
const fn nla_align(len: usize) -> usize {
    (len + 3) & !3
}

/// Find one attribute's payload in a netlink attribute stream.
///
/// Returns the payload without its header, so a nest can be handed straight
/// back into this function to walk its members.
fn find_attr(mut stream: &[u8], want: u16) -> Option<&[u8]> {
    while stream.len() >= 4 {
        let len = u16::from_ne_bytes(stream[..2].try_into().ok()?) as usize;
        let kind = u16::from_ne_bytes(stream[2..4].try_into().ok()?);
        // A header-only or over-long attribute means the stream is malformed;
        // stopping is right, because everything after it is unaligned too.
        if len < 4 || len > stream.len() {
            return None;
        }
        // The nested bit lives in the top bits of the type; mask it off so a
        // nest is found by the same number the kernel headers name it.
        if kind & 0x3fff == want {
            return stream.get(4..len);
        }
        let step = nla_align(len);
        if step >= stream.len() {
            return None;
        }
        stream = &stream[step..];
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a netlink attribute: `[len:u16][type:u16][payload][pad]`.
    fn attr(kind: u16, payload: &[u8]) -> Vec<u8> {
        let len = 4 + payload.len();
        let mut out = Vec::with_capacity(nla_align(len));
        out.extend_from_slice(&u16::try_from(len).unwrap().to_ne_bytes());
        out.extend_from_slice(&kind.to_ne_bytes());
        out.extend_from_slice(payload);
        out.resize(nla_align(len), 0);
        out
    }

    #[test]
    fn every_mode_this_build_can_report_is_on_the_exported_vocabulary() {
        // The list is what a reader at the far end matches against, so a
        // variant whose label is not on it would be exported under a name
        // nothing looks for.
        for mode in [
            XdpAttachMode::Driver,
            XdpAttachMode::Generic,
            XdpAttachMode::Hardware,
            XdpAttachMode::Multiple,
            XdpAttachMode::Unknown,
        ] {
            assert!(
                XDP_ATTACH_MODES.contains(&mode.as_str()),
                "{mode} is exported as a label nothing reads"
            );
        }
    }

    #[test]
    fn the_hand_rolled_uapi_headers_match_the_kernel_layout() {
        // These two structs are transcribed rather than imported, so nothing
        // else would catch a typo in a field width. Both are frozen UAPI: 16
        // bytes each, and the reply parser skips exactly that much before it
        // starts reading attributes.
        assert_eq!(size_of::<NlMsgHdr>(), 16);
        assert_eq!(size_of::<IfInfoMsg>(), 16);
    }

    /// Wrap attributes in a complete `RTM_NEWLINK` reply.
    fn reply(attrs: &[u8]) -> Vec<u8> {
        let head = size_of::<NlMsgHdr>() + size_of::<IfInfoMsg>();
        let total = nla_align(head) + attrs.len();
        let mut out = vec![0u8; nla_align(head)];
        out[..4].copy_from_slice(&u32::try_from(total).unwrap().to_ne_bytes());
        out[4..6].copy_from_slice(&RTM_NEWLINK.to_ne_bytes());
        out.extend_from_slice(attrs);
        out
    }

    #[test]
    fn an_interface_with_no_xdp_nest_reports_nothing_attached() {
        // IFLA_IFNAME only - the shape of every interface that has never had a
        // program on it.
        let msg = reply(&attr(3, b"eth0\0"));
        assert_eq!(parse_xdp_nest(&msg), None);
    }

    #[test]
    fn an_xdp_nest_saying_none_reports_nothing_attached() {
        // The kernel emits the nest with XDP_ATTACHED_NONE after a detach; that
        // is not an attachment and must not read as one.
        let nest = attr(IFLA_XDP_ATTACHED, &[XDP_ATTACHED_NONE]);
        let msg = reply(&attr(IFLA_XDP, &nest));
        assert_eq!(parse_xdp_nest(&msg), None);
    }

    #[test]
    fn a_native_attachment_yields_its_program_id_and_mode() {
        let mut nest = attr(IFLA_XDP_ATTACHED, &[XDP_ATTACHED_DRV]);
        nest.extend_from_slice(&attr(IFLA_XDP_PROG_ID, &77u32.to_ne_bytes()));
        let msg = reply(&attr(IFLA_XDP, &nest));
        assert_eq!(
            parse_xdp_nest(&msg),
            Some(XdpAttachment {
                prog_id: 77,
                mode: XdpAttachMode::Driver,
            })
        );
    }

    #[test]
    fn a_generic_attachment_is_distinguished_from_a_native_one() {
        // The mode is the difference between "your driver refused native" and
        // "something else owns the fast path", so it must survive the parse.
        let mut nest = attr(IFLA_XDP_ATTACHED, &[XDP_ATTACHED_SKB]);
        nest.extend_from_slice(&attr(IFLA_XDP_PROG_ID, &5u32.to_ne_bytes()));
        let msg = reply(&attr(IFLA_XDP, &nest));
        assert_eq!(parse_xdp_nest(&msg).unwrap().mode, XdpAttachMode::Generic);
    }

    #[test]
    fn an_attachment_the_kernel_will_not_name_still_counts_as_attached() {
        // Multi-mode attachments report XDP_ATTACHED_MULTI and withhold the
        // single prog id. Returning None here would say "nothing is attached",
        // which is the opposite of the truth.
        let nest = attr(IFLA_XDP_ATTACHED, &[XDP_ATTACHED_MULTI]);
        let msg = reply(&attr(IFLA_XDP, &nest));
        let att = parse_xdp_nest(&msg).expect("multi counts as attached");
        assert_eq!(att.prog_id, 0);
        assert_eq!(att.mode, XdpAttachMode::Multiple);
    }

    #[test]
    fn a_truncated_attribute_stream_does_not_panic_or_invent_an_answer() {
        let mut msg = reply(&attr(
            IFLA_XDP,
            &attr(IFLA_XDP_ATTACHED, &[XDP_ATTACHED_DRV]),
        ));
        msg.truncate(msg.len() - 3);
        // The length in the header now exceeds the buffer; refusing to answer
        // is the only safe outcome.
        assert_eq!(parse_xdp_nest(&msg), None);
    }

    #[test]
    fn the_xdp_nest_is_found_even_when_the_kernel_sets_the_nested_bit() {
        // The kernel ORs NLA_F_NESTED (0x8000) into the type of a nest.
        let nest = attr(IFLA_XDP_ATTACHED, &[XDP_ATTACHED_DRV]);
        let msg = reply(&attr(IFLA_XDP | 0x8000, &nest));
        assert!(parse_xdp_nest(&msg).is_some());
    }

    #[test]
    fn querying_loopback_never_reports_an_xdp_program() {
        // An end-to-end check of the syscall path that needs no privilege and
        // no fixture: lo is ifindex 1 and carries no XDP program on any host
        // this test runs on. Proves the request is well-formed - a malformed
        // one errors instead of answering.
        assert_eq!(xdp_attachment(1).expect("rtnetlink query works"), None);
    }

    #[test]
    fn a_program_id_cannot_be_read_from_a_non_program_fd() {
        assert_eq!(program_id(0), None);
    }

    #[test]
    fn a_busy_interface_with_a_foreign_program_names_it() {
        // ifindex 1 carries nothing, so this exercises the "busy but nothing
        // readable" arm - the honest wording when rtnetlink and the syscall
        // disagree.
        let d = diagnose_xdp(libc::EBUSY, "lo", 1, None);
        assert!(d.reason.contains("lo"), "names the interface: {}", d.reason);
        assert!(
            d.reason.contains("released") || d.reason.contains("already has an XDP program"),
            "explains the conflict: {}",
            d.reason
        );
        assert!(
            !d.nested_xdp,
            "nothing was read back, so nothing may be claimed: {}",
            d.reason
        );
    }

    #[test]
    fn a_mode_conflict_is_diagnosed_the_same_way_as_a_busy_hook() {
        // The kernel answers EEXIST, not EBUSY, when the interface is occupied
        // in a different XDP mode than the one requested - generic sitting
        // where native was asked for, which is exactly the Docker and CNI case.
        // Treating EEXIST as an unrecognised errno printed "File exists" and
        // told the operator nothing.
        let d = diagnose_xdp(libc::EEXIST, "eth0", 99999, None);
        assert!(
            d.reason.contains("occupied") || d.reason.contains("already has an XDP program"),
            "explains the conflict: {}",
            d.reason
        );
        assert!(
            !d.reason.to_lowercase().contains("file exists"),
            "no bare errno text: {}",
            d.reason
        );
    }

    #[test]
    fn a_refused_attach_points_at_token_delegation_not_at_the_kernel_version() {
        // EPERM under token loading is a bpffs mount-option problem. Saying
        // "permission denied" would send an operator looking at the wrong
        // thing entirely.
        let msg = diagnose_xdp(libc::EPERM, "eth0", 99999, None).reason;
        assert!(msg.contains("delegate_attachs"), "{msg}");
    }

    #[test]
    fn an_unsupported_mode_suggests_the_mode_that_works() {
        let msg = diagnose_xdp(libc::EOPNOTSUPP, "eth0", 99999, None).reason;
        assert!(msg.contains("generic"), "{msg}");
    }

    #[test]
    fn an_unrecognised_errno_still_renders_the_os_message() {
        let msg = diagnose_xdp(libc::EINVAL, "eth0", 99999, None).reason;
        assert!(msg.to_lowercase().contains("invalid argument"), "{msg}");
    }

    #[test]
    fn a_duplicate_tcx_link_says_so_instead_of_reporting_file_exists() {
        let msg = diagnose_link(libc::EEXIST, "TCX ingress", "eth0");
        assert!(msg.contains("TCX ingress"), "{msg}");
        assert!(msg.contains("already carries this exact program"), "{msg}");
    }

    #[test]
    fn a_refused_tcx_attach_points_at_token_delegation() {
        // Same trap as the XDP path: EPERM here is a bpffs mount option, not a
        // missing capability on the process.
        let msg = diagnose_link(libc::EPERM, "TCX egress", "eth0");
        assert!(msg.contains("delegate_attachs"), "{msg}");
    }

    #[test]
    fn an_unsupported_netkit_attach_names_both_prerequisites() {
        // EOPNOTSUPP has two plausible causes on this hook and the operator
        // cannot tell them apart from the errno, so the sentence lists both.
        let msg = diagnose_link(libc::EOPNOTSUPP, "netkit peer", "nk0");
        assert!(msg.contains("6.6"), "names the TCX kernel floor: {msg}");
        assert!(
            msg.contains("netkit device"),
            "names the device type: {msg}"
        );
    }

    #[test]
    fn a_vanished_interface_reads_the_same_on_every_hook() {
        let xdp = diagnose_xdp(libc::ENODEV, "eth0", 99999, None).reason;
        let tcx = diagnose_link(libc::ENODEV, "TCX ingress", "eth0");
        assert!(xdp.contains("disappeared"), "{xdp}");
        assert_eq!(xdp, tcx);
    }

    #[test]
    fn an_unrecognised_link_errno_still_renders_the_os_message() {
        let msg = diagnose_link(libc::EINVAL, "TCX ingress", "eth0");
        assert!(msg.to_lowercase().contains("invalid argument"), "{msg}");
    }

    #[test]
    fn nothing_is_carried_when_the_interface_has_no_program() {
        assert!(!already_carries(1, Some(42)));
    }

    #[test]
    fn nothing_is_carried_when_our_own_program_id_is_unknown() {
        // Without an id to compare, "already ours" is unknowable, and guessing
        // yes would skip a real attach.
        assert!(!already_carries(1, None));
    }

    #[test]
    fn a_block_replaces_the_earlier_one_for_the_same_pair() {
        clear_all_blocks();
        let mk = |reason: &str| AttachBlock {
            program: "xdp_firewall".to_owned(),
            interface: "eth0".to_owned(),
            reason: reason.to_owned(),
            nested_xdp: true,
        };
        record_block(mk("first"));
        record_block(mk("second"));
        let all = blocked_attaches();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].reason, "second");
        clear_all_blocks();
    }

    #[test]
    fn clearing_one_pair_leaves_the_others_alone() {
        clear_all_blocks();
        record_block(AttachBlock {
            program: "xdp_firewall".to_owned(),
            interface: "eth0".to_owned(),
            reason: "busy".to_owned(),
            nested_xdp: true,
        });
        record_block(AttachBlock {
            program: "xdp_firewall".to_owned(),
            interface: "eth1".to_owned(),
            reason: "busy".to_owned(),
            nested_xdp: true,
        });
        clear_block("xdp_firewall", "eth0");
        let all = blocked_attaches();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].interface, "eth1");
        clear_all_blocks();
    }

    #[test]
    fn a_block_reads_as_one_sentence() {
        let b = AttachBlock {
            program: "xdp_firewall".to_owned(),
            interface: "eth0".to_owned(),
            reason: "already occupied".to_owned(),
            nested_xdp: true,
        };
        assert_eq!(b.to_string(), "xdp_firewall on eth0: already occupied");
    }
}
