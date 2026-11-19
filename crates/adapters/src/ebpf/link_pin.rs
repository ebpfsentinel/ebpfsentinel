//! Links that outlive the agent.
//!
//! A firewall that stops enforcing the moment its process dies hands an
//! attacker a simple recipe: kill the agent, then do what the rules refused.
//! Every link the agent creates is therefore pinned on the host bpffs, so the
//! kernel keeps it attached, running the program and reading the maps it last
//! read, whatever happens to the process. Only `ebpfsentinel-agent uninstall`
//! and an exit under `agent.on_exit: detach` remove the pins.
//!
//! Where the pins go depends on who holds the host bpffs. An agent running
//! with its own privileges pins directly. A rootless agent mounts a bpffs of
//! its own inside its mount namespace, which dies with it, so it hands each
//! link to the warden, which pins it on the host side.
//!
//! A restarted agent **adopts** the pinned links instead of attaching anew:
//! the old link keeps the old program enforcing the old rules while the new
//! process loads, the attach path claims it, and once start-up has written the
//! rules into the new maps [`complete_adoption`] swaps each claimed link onto
//! the new program with `BPF_LINK_UPDATE`. The hook is never empty and never
//! runs a program whose maps are still blank. A pinned link nothing claims is
//! a hook this configuration no longer wants, and it is released there.

#![allow(unsafe_code)] // One `fcntl` to duplicate a descriptor the caller keeps.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock, PoisonError};

use ebpfsentinel_warden::link_pins;
use ebpfsentinel_warden_client::ReconnectingClient;
use ebpfsentinel_warden_proto::LINK_PIN_NAME_MAX;
use tracing::{info, warn};

use super::link_handover::LinkHook;
use super::{kfunc_attach, tcx_order};

/// Who holds the pins.
enum PinStore {
    /// The agent itself, in this directory of the host bpffs.
    Direct(PathBuf),
    /// The warden, in its own directory of the host bpffs.
    Warden(Mutex<ReconnectingClient>),
}

static STORE: OnceLock<PinStore> = OnceLock::new();
/// Set once the process has decided its links stay: a graceful exit under
/// `agent.on_exit: keep`, or a panic. Dropping a link then leaves its pin.
static KEEP_ON_EXIT: AtomicBool = AtomicBool::new(false);
/// Links found pinned at start, not yet claimed by an attach.
static ADOPTED: Mutex<Vec<(String, OwnedFd)>> = Mutex::new(Vec::new());
/// Claimed links still running the previous process's program.
static PENDING: Mutex<Vec<PendingSwap>> = Mutex::new(Vec::new());
/// Set once [`complete_adoption`] has run: a program array is pinned at
/// once from then on.
static ADOPTION_DONE: AtomicBool = AtomicBool::new(false);
/// Program arrays waiting for [`complete_adoption`] to be pinned.
static DEFERRED_ARRAYS: Mutex<Vec<(String, OwnedFd)>> = Mutex::new(Vec::new());
/// Every pin this process wrote or adopted and still holds.
static PINNED: Mutex<Vec<String>> = Mutex::new(Vec::new());
/// What [`exit`] does: keep the pins (`agent.on_exit: keep`) or remove them.
static EXIT_KEEPS: AtomicBool = AtomicBool::new(true);

struct PendingSwap {
    name: String,
    program: String,
    link: OwnedFd,
    prog: OwnedFd,
}

/// Pin the links this process creates directly, in `dir`.
pub fn pin_directly(dir: PathBuf) {
    let _ = STORE.set(PinStore::Direct(dir));
}

/// Pin the links this process creates through the warden at `sock`.
pub fn pin_through_warden(sock: PathBuf) {
    let _ = STORE.set(PinStore::Warden(Mutex::new(ReconnectingClient::new(sock))));
}

/// Whether links are pinned at all.
pub fn enabled() -> bool {
    STORE.get().is_some()
}

/// Leave every pin in place when the links drop: the process is going and
/// the hooks stay.
pub fn keep_on_exit() {
    KEEP_ON_EXIT.store(true, Ordering::SeqCst);
}

/// Install a panic hook that keeps the pins, then runs the previous hook. A
/// panic that unwinds through the loaders would otherwise unpin every link on
/// the way out.
pub fn keep_on_panic() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        keep_on_exit();
        previous(info);
    }));
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    // Each list stays valid after a partial write: an entry is pushed or
    // removed whole.
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The tag a hook is written with in a pin name: letters and digits only, so
/// the dash that separates the parts is never ambiguous.
fn hook_tag(hook: LinkHook) -> String {
    match hook {
        LinkHook::Xdp => "xdp".into(),
        LinkHook::TcxIngress => "tcxin".into(),
        LinkHook::TcxEgress => "tcxout".into(),
        LinkHook::NetkitPrimary => "nkprimary".into(),
        LinkHook::NetkitPeer => "nkpeer".into(),
        LinkHook::Cgroup(attach_type) => format!("cg{attach_type}"),
    }
}

/// `part` with every byte that is not a letter or a digit written `_XX`.
/// bpffs refuses `/` and this directory refuses `.`, and both are ordinary
/// in an interface name or a cgroup path.
fn encode(part: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(part.len());
    for b in part.bytes() {
        if b.is_ascii_alphanumeric() {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "_{b:02X}");
        }
    }
    out
}

/// FNV-1a over `part`, for a target too long to spell out.
fn fnv1a(part: &str) -> u64 {
    part.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
    })
}

/// The target part of a pin name: the interface or cgroup spelled out, or a
/// hash of it when spelling it would overrun the name.
fn target_part(target: &str) -> String {
    let spelled = encode(target);
    if spelled.len() <= LINK_PIN_NAME_MAX / 2 {
        spelled
    } else {
        format!("h{:016x}", fnv1a(target))
    }
}

/// The pin name of `program` on `(target, hook)`.
#[must_use]
pub fn pin_name(program: &str, target: &str, hook: LinkHook) -> String {
    format!(
        "{}-{}-{}",
        hook_tag(hook),
        target_part(target),
        encode(program)
    )
}

/// Whether the pinned link `name` is the one `program` claims on
/// `(target, hook)`. An interface holds one XDP program and a netkit side one
/// program, so there any program takes the hook over; TCX and cgroup hooks
/// chain several, and each program claims only its own.
fn claims(name: &str, program: &str, target: &str, hook: LinkHook) -> bool {
    match hook {
        LinkHook::Xdp | LinkHook::NetkitPrimary | LinkHook::NetkitPeer => {
            name.starts_with(&format!("{}-{}-", hook_tag(hook), target_part(target)))
        }
        LinkHook::TcxIngress | LinkHook::TcxEgress | LinkHook::Cgroup(_) => {
            name == pin_name(program, target, hook)
        }
    }
}

fn dup(fd: RawFd) -> Option<OwnedFd> {
    // SAFETY: `F_DUPFD_CLOEXEC` reads no memory; a failure is a negative
    // return, checked before the result is owned.
    let new = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if new < 0 {
        return None;
    }
    // SAFETY: `fcntl` returned a fresh descriptor nothing else owns.
    Some(unsafe { OwnedFd::from_raw_fd(new) })
}

fn store_pin(name: &str, fd: RawFd) -> Result<(), String> {
    match STORE.get() {
        None => Ok(()),
        Some(PinStore::Direct(dir)) => link_pins::pin(dir, name, fd),
        Some(PinStore::Warden(client)) => {
            lock(client).pin_link(name, fd).map_err(|e| e.to_string())
        }
    }
}

fn store_unpin(names: &[String]) -> Result<(), String> {
    match STORE.get() {
        None => Ok(()),
        Some(PinStore::Direct(dir)) => link_pins::unpin(dir, names).map(|_| ()),
        Some(PinStore::Warden(client)) => {
            lock(client).unpin_links(names).map_err(|e| e.to_string())
        }
    }
}

/// Pin the link `fd` as `name`. A pin that fails leaves the link held by
/// this process only, which is how every link was held before: it is logged,
/// not fatal.
pub(crate) fn pin(name: &str, fd: RawFd) -> bool {
    if !enabled() {
        return false;
    }
    match store_pin(name, fd) {
        Ok(()) => {
            let mut pinned = lock(&PINNED);
            if !pinned.iter().any(|n| n == name) {
                pinned.push(name.to_owned());
            }
            true
        }
        Err(e) => {
            warn!(
                pin = name,
                "link not pinned, it detaches if the agent exits: {e}"
            );
            false
        }
    }
}

/// Pin the program array `map_name` so its tail-call slots outlive the
/// process: the kernel empties a program array when no descriptor and no pin
/// holds it, and a chain whose array emptied runs only its first program.
///
/// The pin replaces the previous run's array of the same name, whose slots
/// the adopted links still call into until they are swapped, so before
/// [`complete_adoption`] it is only queued.
pub(crate) fn pin_prog_array(map_name: &str, fd: RawFd) {
    if !enabled() {
        return;
    }
    let name = format!("pa-{}", encode(map_name));
    if ADOPTION_DONE.load(Ordering::SeqCst) {
        pin(&name, fd);
        return;
    }
    if let Some(dup) = dup(fd) {
        let mut deferred = lock(&DEFERRED_ARRAYS);
        deferred.retain(|(n, _)| n != &name);
        deferred.push((name, dup));
    }
}

/// Called when a link is dropped: unless the process is keeping its hooks,
/// the pin goes too, which is what detaches the link.
pub(crate) fn release(name: &str) {
    lock(&PENDING).retain(|p| p.name != name);
    if KEEP_ON_EXIT.load(Ordering::SeqCst) {
        return;
    }
    lock(&PINNED).retain(|n| n != name);
    if let Err(e) = store_unpin(&[name.to_owned()]) {
        warn!(pin = name, "link pin not removed: {e}");
    }
}

/// Remove the pin `name` now, whatever the exit policy: an adopted link
/// pinned again under its new program's name no longer needs the old one.
pub(crate) fn release_name(name: &str) {
    lock(&PINNED).retain(|n| n != name);
    if let Err(e) = store_unpin(&[name.to_owned()]) {
        warn!(pin = name, "link pin not removed: {e}");
    }
}

/// A claimed link swapped by a live handover no longer waits for the
/// adoption swap, which would put the older program back.
pub(crate) fn cancel_pending(name: &str) {
    lock(&PENDING).retain(|p| p.name != name);
}

/// Open every link pinned by a previous run, ready to be claimed. Returns how
/// many were found.
pub fn adopt() -> usize {
    let opened: Vec<(String, OwnedFd)> = match STORE.get() {
        None => return 0,
        Some(PinStore::Direct(dir)) => match link_pins::list(dir) {
            Ok(names) => names
                .into_iter()
                .filter_map(|n| match link_pins::open(dir, &n) {
                    Ok(fd) => Some((n, fd)),
                    Err(e) => {
                        warn!(pin = n, "pinned link not adopted: {e}");
                        None
                    }
                })
                .collect(),
            Err(e) => {
                warn!("pinned links not listed: {e}");
                return 0;
            }
        },
        Some(PinStore::Warden(client)) => {
            let mut client = lock(client);
            match client.pinned_links() {
                Ok(names) => names
                    .into_iter()
                    .filter_map(|n| match client.open_pinned_link(&n) {
                        Ok(fd) => Some((n, fd)),
                        Err(e) => {
                            warn!(pin = n, "pinned link not adopted: {e}");
                            None
                        }
                    })
                    .collect(),
                Err(e) => {
                    warn!("pinned links not listed through the warden: {e}");
                    return 0;
                }
            }
        }
    };
    let count = opened.len();
    if count > 0 {
        info!(
            links = count,
            "links pinned by the previous run found, they keep enforcing until swapped"
        );
    }
    // Each adopted link keeps the previous run's program on its hook until
    // the swap: those programs are the agent's, and a chain read meanwhile
    // must not take one ahead of a new attach for a foreign program.
    for (_, fd) in &opened {
        if let Some(id) = tcx_order::link_program_id(fd.as_raw_fd()) {
            tcx_order::register_ours(id);
        }
    }
    let mut pinned = lock(&PINNED);
    for (name, _) in &opened {
        if !pinned.contains(name) {
            pinned.push(name.clone());
        }
    }
    drop(pinned);
    lock(&ADOPTED).extend(opened);
    count
}

/// Claim the adopted link `program` would take on `(target, hook)`.
///
/// Returns the link and the name it was pinned under. The link keeps its old
/// program until [`complete_adoption`] swaps `prog_fd` in.
pub(crate) fn claim(
    program: &str,
    target: &str,
    hook: LinkHook,
    prog_fd: RawFd,
) -> Option<(OwnedFd, String)> {
    let (name, link) = {
        let mut adopted = lock(&ADOPTED);
        let idx = adopted
            .iter()
            .position(|(n, _)| claims(n, program, target, hook))?;
        adopted.swap_remove(idx)
    };
    let fdinfo = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", link.as_raw_fd()));
    if let Ok(fdinfo) = fdinfo
        && severed(&fdinfo, hook, interface_index(target, hook))
    {
        info!(
            pin = name,
            program,
            target,
            "pinned link no longer holds its hook, the interface or cgroup it ran on is gone: \
             released and attached anew"
        );
        drop(link);
        release_name(&name);
        return None;
    }
    let new_name = pin_name(program, target, hook);
    if let (Some(link_dup), Some(prog)) = (dup(link.as_raw_fd()), dup(prog_fd)) {
        lock(&PENDING).push(PendingSwap {
            name: new_name,
            program: program.to_owned(),
            link: link_dup,
            prog,
        });
        return Some((link, name));
    }
    warn!(
        pin = name,
        "descriptor not duplicated, the pinned link is released and attached anew"
    );
    release_name(&name);
    None
}

/// The index `target` has now, for a hook whose link names its interface by
/// index. A netkit link names the device it was created on, which is not
/// always the one the target spells, so it is only read for a zero.
fn interface_index(target: &str, hook: LinkHook) -> Option<u32> {
    match hook {
        LinkHook::Xdp | LinkHook::TcxIngress | LinkHook::TcxEgress => {
            let name = std::ffi::CString::new(target).ok()?;
            // SAFETY: `name` is a NUL-terminated string that outlives the call,
            // which reads it and nothing else.
            let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
            Some(index)
        }
        LinkHook::NetkitPrimary | LinkHook::NetkitPeer | LinkHook::Cgroup(_) => None,
    }
}

/// Whether a pinned link, by its `fdinfo`, no longer runs on anything.
///
/// The kernel keeps a link whose interface was unregistered or whose cgroup
/// was removed, pinned and alive, with `ifindex` or `cgroup_id` at zero; such
/// a link refuses `BPF_LINK_UPDATE` and adopting it would leave the hook
/// empty. An interface deleted and created again under the same name is a
/// new device: the link still names the old index, or zero. `now` is the
/// target's current index where the hook names one, zero when no interface
/// carries the name.
fn severed(fdinfo: &str, hook: LinkHook, now: Option<u32>) -> bool {
    let field = |key: &str| {
        fdinfo.lines().find_map(|l| {
            l.strip_prefix(key)
                .and_then(|v| v.trim().parse::<u64>().ok())
        })
    };
    match hook {
        LinkHook::Cgroup(_) => field("cgroup_id:") == Some(0),
        _ => match field("ifindex:") {
            Some(0) => true,
            Some(held) => now.is_some_and(|now| u64::from(now) != held),
            None => false,
        },
    }
}

/// What [`complete_adoption`] did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Adoption {
    /// Claimed links now running this process's program.
    pub swapped: usize,
    /// Claimed links the kernel refused to swap.
    pub refused: usize,
    /// Pinned links no attach claimed, released.
    pub released: usize,
}

/// Swap every claimed link onto this process's program, then release the
/// pinned links nothing claimed. Called once start-up has written the rules,
/// so the swap never lands a program on empty maps.
pub fn complete_adoption() -> Adoption {
    let mut outcome = Adoption::default();
    let pending = std::mem::take(&mut *lock(&PENDING));
    for swap in pending {
        match kfunc_attach::link_update(&swap.program, swap.link.as_raw_fd(), swap.prog.as_raw_fd())
        {
            Ok(()) => outcome.swapped += 1,
            Err(e) => {
                outcome.refused += 1;
                warn!(
                    pin = swap.name,
                    program = swap.program,
                    "adopted link not swapped, it keeps the previous run's program until \
                     `ebpfsentinel-agent uninstall` and a restart: {e}"
                );
            }
        }
    }
    let arrays = std::mem::take(&mut *lock(&DEFERRED_ARRAYS));
    let repinned: Vec<String> = arrays
        .iter()
        .filter(|(name, fd)| pin(name, fd.as_raw_fd()))
        .map(|(name, _)| name.clone())
        .collect();
    drop(arrays);
    ADOPTION_DONE.store(true, Ordering::SeqCst);
    // A program array pinned again under its name has replaced the previous
    // run's pin already; removing that name now would remove the new one.
    let left: Vec<(String, OwnedFd)> = std::mem::take(&mut *lock(&ADOPTED))
        .into_iter()
        .filter(|(name, _)| !repinned.contains(name))
        .collect();
    if !left.is_empty() {
        let names: Vec<String> = left.iter().map(|(n, _)| n.clone()).collect();
        lock(&PINNED).retain(|n| !names.contains(n));
        if let Err(e) = store_unpin(&names) {
            warn!("pinned links no longer wanted were not removed: {e}");
        }
        outcome.released = left.len();
        for name in &names {
            info!(pin = name, "pinned link no attach claimed, hook detached");
        }
    }
    drop(left);
    if outcome != Adoption::default() {
        info!(
            swapped = outcome.swapped,
            refused = outcome.refused,
            released = outcome.released,
            "pinned links adopted"
        );
    }
    outcome
}

/// Record what [`exit`] does with the pins, from `agent.on_exit`.
pub fn set_on_exit(keep: bool) {
    EXIT_KEEPS.store(keep, Ordering::SeqCst);
}

/// Apply the exit policy [`set_on_exit`] recorded: called on a graceful exit,
/// before the loaders are dropped.
pub fn exit() {
    on_exit(EXIT_KEEPS.load(Ordering::SeqCst));
}

/// What the process does with its pins on a graceful exit: keep them, or
/// remove every pin it holds, which detaches the hooks.
pub fn on_exit(keep: bool) {
    if keep {
        keep_on_exit();
        return;
    }
    let names = std::mem::take(&mut *lock(&PINNED));
    if names.is_empty() {
        return;
    }
    if let Err(e) = store_unpin(&names) {
        warn!("link pins not removed at exit: {e}");
    } else {
        info!(
            links = names.len(),
            "link pins removed at exit, hooks detach"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ebpfsentinel_warden_proto::valid_link_pin_name;

    #[test]
    fn a_pin_name_is_valid_for_every_target() {
        let long = format!("/sys/fs/cgroup/kubepods.slice/{}", "x".repeat(400));
        for (target, hook) in [
            ("eth0", LinkHook::Xdp),
            ("eth0.100", LinkHook::TcxIngress),
            ("br-lan", LinkHook::TcxEgress),
            ("/sys/fs/cgroup", LinkHook::Cgroup(10)),
            (long.as_str(), LinkHook::Cgroup(1)),
        ] {
            let name = pin_name("tc_ids", target, hook);
            assert!(valid_link_pin_name(&name), "{name}");
        }
    }

    #[test]
    fn names_differ_by_program_target_and_hook() {
        let a = pin_name("tc_ids", "eth0", LinkHook::TcxIngress);
        assert_ne!(a, pin_name("tc_dns", "eth0", LinkHook::TcxIngress));
        assert_ne!(a, pin_name("tc_ids", "eth1", LinkHook::TcxIngress));
        assert_ne!(a, pin_name("tc_ids", "eth0", LinkHook::TcxEgress));
        // A dash in the interface cannot be mistaken for the separator.
        assert_ne!(
            pin_name("p", "a-b", LinkHook::Xdp),
            pin_name("b-p", "a", LinkHook::Xdp)
        );
    }

    #[test]
    fn xdp_is_claimed_by_any_program_tcx_only_by_its_own() {
        let xdp = pin_name("xdp_firewall", "eth0", LinkHook::Xdp);
        assert!(claims(&xdp, "xdp_ratelimit", "eth0", LinkHook::Xdp));
        assert!(!claims(&xdp, "xdp_firewall", "eth1", LinkHook::Xdp));
        assert!(!claims(&xdp, "xdp_firewall", "eth0", LinkHook::TcxIngress));
        let tcx = pin_name("tc_ids", "eth0", LinkHook::TcxIngress);
        assert!(claims(&tcx, "tc_ids", "eth0", LinkHook::TcxIngress));
        assert!(!claims(&tcx, "tc_dns", "eth0", LinkHook::TcxIngress));
    }

    #[test]
    fn nothing_pins_without_a_store() {
        // No store is installed in unit tests: pinning is off and every
        // release is a no-op.
        assert!(!pin("xdp-eth0-p", 0));
        release("xdp-eth0-p");
        assert_eq!(complete_adoption(), Adoption::default());
    }

    const XDP_ON_7: &str =
        "link_type:\txdp\nlink_id:\t12\nprog_tag:\tab\nprog_id:\t52\nifindex:\t7\n";
    const XDP_GONE: &str =
        "link_type:\txdp\nlink_id:\t12\nprog_tag:\tab\nprog_id:\t52\nifindex:\t0\n";

    #[test]
    fn a_link_whose_interface_was_unregistered_is_severed() {
        assert!(severed(XDP_GONE, LinkHook::Xdp, Some(7)));
        assert!(severed(XDP_GONE, LinkHook::NetkitPeer, None));
    }

    #[test]
    fn a_link_on_an_interface_created_again_under_its_name_is_severed() {
        assert!(severed(XDP_ON_7, LinkHook::Xdp, Some(9)));
        assert!(severed(XDP_ON_7, LinkHook::TcxIngress, Some(0)));
    }

    #[test]
    fn a_link_still_on_its_interface_is_adopted() {
        assert!(!severed(XDP_ON_7, LinkHook::Xdp, Some(7)));
        assert!(!severed(XDP_ON_7, LinkHook::NetkitPrimary, None));
    }

    #[test]
    fn a_cgroup_link_is_severed_only_once_its_cgroup_is_gone() {
        let live = "link_type:\tcgroup\ncgroup_id:\t4211\nattach_type:\t10\n";
        let gone = "link_type:\tcgroup\ncgroup_id:\t0\nattach_type:\t10\n";
        assert!(!severed(live, LinkHook::Cgroup(10), None));
        assert!(severed(gone, LinkHook::Cgroup(10), None));
    }

    #[test]
    fn a_link_whose_fdinfo_names_no_target_is_kept() {
        assert!(!severed(
            "link_type:\txdp\nlink_id:\t12\n",
            LinkHook::Xdp,
            Some(3)
        ));
    }
}
