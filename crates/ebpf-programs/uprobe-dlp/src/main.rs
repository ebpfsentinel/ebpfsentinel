#![no_std]
#![no_main]

use aya_ebpf::{
    btf_maps::{Array, HashMap, LruHashMap, PerCpuArray, RingBuf},
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_ktime_get_boot_ns, generated,
    },
    macros::{btf_map, kprobe, kretprobe, uprobe, uretprobe},
    programs::{ProbeContext, RetProbeContext},
};
use core::ffi::c_void;
use ebpf_common::dlp::{
    DLP_DIRECTION_READ, DLP_DIRECTION_WRITE, DLP_FLOW_FAMILY_IPV4, DLP_FLOW_FAMILY_IPV6,
    DLP_FLOW_PROTOCOL_TCP, DLP_FLOW_SOURCE_CORRELATED, DLP_FLOW_SOURCE_KERNEL_SOCKET,
    DLP_JOINED_SOCKET_WINDOW_NS, DLP_KTLS_SUPPRESS_WINDOW_NS, DLP_MAX_EXCERPT, DLP_METRIC_COUNT, DLP_METRIC_ERRORS,
    DLP_METRIC_EVENTS_DROPPED, DLP_METRIC_KTLS_EVENTS, DLP_METRIC_KTLS_SUPPRESSED,
    DLP_METRIC_KTLS_UNREADABLE, DLP_METRIC_OUT_OF_SCOPE, DLP_METRIC_READ_EVENTS,
    DLP_METRIC_TOTAL_SEEN, DLP_METRIC_WRITE_EVENTS, DLP_SCOPE_ANCESTOR_LEVELS,
    DLP_SCOPE_MAX_CGROUPS, DLP_SCOPE_MODE_WORKLOADS, DLP_SMALL_EXCERPT,
    DLP_TASK_SOCKET_MAX_TASKS, DLP_TASK_SOCKET_WINDOW_NS, DlpEvent, DlpEventSmall, DlpSocket,
    DlpTaskSocket, KtlsIterOffsets, SockOffsets, SslReadArgs,
};
use ebpf_helpers::increment_metric;
use ebpf_helpers::ringbuf::{avail_data, submit_flags};

// ── Maps ────────────────────────────────────────────────────────────

/// Kernel->userspace DLP event ring buffer, 4 MiB: about 1,000 full events
/// of 4,176 bytes, or 12,400 small ones of 336. Those are the record sizes
/// the kernel charges, the event plus the ring buffer's own 8-byte header,
/// and they grew with the socket block the event now carries: 10 full events
/// fewer in the same 4 MiB, which is why the reservation is unchanged.
/// Emission is refused only when a reserve fails (sizing in
/// `ebpf_helpers::ringbuf`).
#[btf_map]
static EVENTS: RingBuf<DlpEvent, { 1024 * 4096 }> = RingBuf::new();

/// Per-task context: saves SSL_read entry arguments for the uretprobe.
/// Uses LRU eviction so entries from crashed processes (SIGKILL during
/// SSL_read) are automatically reclaimed when the map is full.
#[btf_map]
static SSL_READ_ARGS: LruHashMap<u64, SslReadArgs, 10240> = LruHashMap::new();

/// Go `crypto/tls` read context: the slice saved at `(*Conn).Read` entry for
/// the probes on its return instructions. Keyed by `(tgid, goroutine)` rather
/// than by thread, because a goroutine that blocks inside `Read` is resumed on
/// whichever thread the scheduler picks.
#[btf_map]
static GO_READ_ARGS: LruHashMap<[u64; 2], SslReadArgs, 10240> = LruHashMap::new();

/// Kernel TLS read context: the destination buffer the message iterator pointed
/// at when `tls_sw_recvmsg` was entered, for the kretprobe that reads it once
/// the kernel has decrypted into it.
///
/// This is a map of its own rather than a second user of `SSL_READ_ARGS`:
/// `SSL_read` reaches `tls_sw_recvmsg` inside its own call frame on the same
/// thread, so sharing one map by `pid_tgid` would have the kernel probe
/// overwrite the arguments the uprobe saved for its own return.
#[btf_map]
static KTLS_READ_ARGS: LruHashMap<u64, SslReadArgs, 10240> = LruHashMap::new();

/// Last time each thread entered a probed TLS library call, stamped by
/// `ssl_write` and `ssl_read_entry`.
///
/// An OpenSSL build with kernel TLS enabled hands the plaintext to
/// `tls_sw_sendmsg`, so both the uprobe and the kernel probe see the same
/// bytes and the scanner would raise two alerts for one leak. The uprobe frame
/// strictly encloses the kernel call within one syscall, so a stamp younger
/// than `DLP_KTLS_SUPPRESS_WINDOW_NS` means the plaintext has already been
/// captured and the kernel probe stands down.
#[btf_map]
static DLP_UPROBE_ACTIVE: LruHashMap<u64, u64, 10240> = LruHashMap::new();

/// Byte offsets of the kernel message-iterator fields, resolved from the
/// running kernel's BTF by userspace. The kernel TLS probes read nothing while
/// `valid` is zero.
#[btf_map]
static KTLS_ITER_OFFSETS: Array<KtlsIterOffsets, 1> = Array::new();

/// Per-CPU DLP counters, one slot per `DLP_METRIC_*` index.
#[btf_map]
static DLP_METRICS: PerCpuArray<u64, { DLP_METRIC_COUNT as usize }> = PerCpuArray::new();

/// Which cgroups this agent is allowed to read plaintext from, when
/// `DLP_SCOPE` says `DLP_SCOPE_MODE_WORKLOADS`. Written by userspace from the
/// configured scope; the value is a presence marker and carries nothing.
#[btf_map]
static DLP_CGROUP_ALLOW: HashMap<u64, u8, { DLP_SCOPE_MAX_CGROUPS as usize }> = HashMap::new();

/// The scope mode, slot 0. Unset reads as `DLP_SCOPE_MODE_ALL`, which is what
/// a host agent with no cgroup scope configured has always done.
#[btf_map]
static DLP_SCOPE: Array<u32, 1> = Array::new();

/// Byte offsets of the `struct sock` members the kernel TLS probes read,
/// resolved from the running kernel's BTF by userspace. No socket is read
/// while `valid` is zero, so the event then carries no destination.
#[btf_map]
static SOCK_OFFSETS: Array<SockOffsets, 1> = Array::new();

/// The last socket each task was seen writing TLS plaintext through, stamped
/// by the kernel TLS probes.
///
/// A library uprobe has a plaintext buffer and no socket: `SSL_write` is given
/// an `SSL *`, whose internals this program deliberately does not walk. Where
/// the same write reaches the kernel TLS path, the kernel probe sees the
/// `struct sock` and records it here, and the uprobe path reads it back inside
/// `DLP_TASK_SOCKET_WINDOW_NS` and says the tuple is a correlation rather than
/// a reading.
///
/// This map is the slot the socket-attribution hook fills later: a
/// `sockops` or `cgroup/connect` program recording the sockets a task opens
/// writes the same value type here and the event shape does not move.
#[btf_map]
static DLP_TASK_SOCKET: LruHashMap<u64, DlpTaskSocket, { DLP_TASK_SOCKET_MAX_TASKS as usize }> =
    LruHashMap::new();

/// The socket `tls_sw_recvmsg` was entered on, kept for its return probe the
/// way `KTLS_READ_ARGS` keeps the buffer. Read at the return site the socket
/// argument is gone, and correlating through `DLP_TASK_SOCKET` would downgrade
/// a tuple this program did read to one it merely remembered.
#[btf_map]
static KTLS_READ_SOCKET: LruHashMap<u64, DlpSocket, 10240> = LruHashMap::new();

// ── Probes ──────────────────────────────────────────────────────────

/// Intercept `SSL_write(ssl, buf, num)` at entry.
/// The plaintext buffer is filled before the call, so we capture it here.
#[uprobe]
pub fn ssl_write(ctx: ProbeContext) {
    increment_metric(DLP_METRIC_TOTAL_SEEN);
    match try_ssl_write(&ctx) {
        Ok(()) => {}
        Err(()) => increment_metric(DLP_METRIC_ERRORS),
    }
}

/// Intercept `SSL_read(ssl, buf, num)` at entry.
/// Save the buffer pointer and length; the buffer will be filled by the time
/// the uretprobe fires.
#[uprobe]
pub fn ssl_read_entry(ctx: ProbeContext) {
    increment_metric(DLP_METRIC_TOTAL_SEEN);
    match try_ssl_read_entry(&ctx) {
        Ok(()) => {}
        Err(()) => increment_metric(DLP_METRIC_ERRORS),
    }
}

/// Intercept `SSL_read` return. Read the now-filled buffer using the
/// pointer saved at entry.
#[uretprobe]
pub fn ssl_read_ret(ctx: RetProbeContext) {
    match try_ssl_read_ret(&ctx) {
        Ok(()) => {}
        Err(()) => increment_metric(DLP_METRIC_ERRORS),
    }
}

/// Intercept Go `crypto/tls.(*Conn).Write(b []byte)` at entry. The register
/// ABI passes the receiver and the slice header in the first three integer
/// registers, so the plaintext pointer and its length are read from there.
#[uprobe]
pub fn go_tls_write(ctx: ProbeContext) {
    increment_metric(DLP_METRIC_TOTAL_SEEN);
    match try_go_tls_write(&ctx) {
        Ok(()) => {}
        Err(()) => increment_metric(DLP_METRIC_ERRORS),
    }
}

/// Intercept Go `crypto/tls.(*Conn).Read(b []byte)` at entry and save the
/// slice for the return-site probes.
#[uprobe]
pub fn go_tls_read_entry(ctx: ProbeContext) {
    increment_metric(DLP_METRIC_TOTAL_SEEN);
    match try_go_tls_read_entry(&ctx) {
        Ok(()) => {}
        Err(()) => increment_metric(DLP_METRIC_ERRORS),
    }
}

/// Fires on each return instruction of Go `(*Conn).Read`. A uretprobe cannot
/// be used on Go: it rewrites the return address on a stack the runtime is
/// free to move, which crashes the process on the next stack growth. This is
/// a plain uprobe placed on every `RET` the function holds, where the first
/// result register carries the byte count.
#[uprobe]
pub fn go_tls_read_ret(ctx: ProbeContext) {
    match try_go_tls_read_ret(&ctx) {
        Ok(()) => {}
        Err(()) => increment_metric(DLP_METRIC_ERRORS),
    }
}

// ── Implementation ──────────────────────────────────────────────────

/// Intercept `tls_sw_sendmsg(sk, msg, size)` at entry.
///
/// This is the kernel TLS send path: the socket does the record framing and
/// the encryption, so no userspace library holds the plaintext and no uprobe
/// can see it. The message iterator still points at the caller's plaintext at
/// entry, which is what makes one probe here cover every process on the host
/// at once, whatever language or TLS library it was written against.
///
/// Hardware crypto offload (`TLS_HW`) is a different path and is not covered:
/// the plaintext goes to the card, not through `tls_sw_sendmsg`.
#[kprobe]
pub fn ktls_sendmsg(ctx: ProbeContext) {
    increment_metric(DLP_METRIC_TOTAL_SEEN);
    match try_ktls_sendmsg(&ctx) {
        Ok(()) => {}
        Err(()) => increment_metric(DLP_METRIC_ERRORS),
    }
}

/// Intercept `tls_sw_recvmsg(sk, msg, len, flags, addr_len)` at entry and save
/// the destination buffer. At entry it is still empty, so nothing is read here.
#[kprobe]
pub fn ktls_recvmsg_entry(ctx: ProbeContext) {
    increment_metric(DLP_METRIC_TOTAL_SEEN);
    match try_ktls_recvmsg_entry(&ctx) {
        Ok(()) => {}
        Err(()) => increment_metric(DLP_METRIC_ERRORS),
    }
}

/// Intercept `tls_sw_recvmsg` return and read the decrypted plaintext out of
/// the buffer saved at entry, clamped to the byte count the kernel returned.
#[kretprobe]
pub fn ktls_recvmsg_ret(ctx: RetProbeContext) {
    match try_ktls_recvmsg_ret(&ctx) {
        Ok(()) => {}
        Err(()) => increment_metric(DLP_METRIC_ERRORS),
    }
}

#[inline(always)]
fn try_ssl_write(ctx: &ProbeContext) -> Result<(), ()> {
    // SSL_write(SSL *ssl, const void *buf, int num)
    //   arg(0) = ssl, arg(1) = buf, arg(2) = num
    stamp_uprobe_active();
    let buf: *const u8 = ctx.arg(1).ok_or(())?;
    let num: i32 = ctx.arg(2).ok_or(())?;

    if num <= 0 || buf.is_null() {
        return Ok(());
    }

    emit_dlp_event(buf, num as u32, DLP_DIRECTION_WRITE, task_socket());
    increment_metric(DLP_METRIC_WRITE_EVENTS);
    Ok(())
}

#[inline(always)]
fn try_ssl_read_entry(ctx: &ProbeContext) -> Result<(), ()> {
    // SSL_read(SSL *ssl, void *buf, int num)
    //   arg(0) = ssl, arg(1) = buf, arg(2) = num
    stamp_uprobe_active();
    let buf: *const u8 = ctx.arg(1).ok_or(())?;
    let num: i32 = ctx.arg(2).ok_or(())?;

    if num <= 0 || buf.is_null() {
        return Ok(());
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let args = SslReadArgs {
        buf_ptr: buf as u64,
        buf_len: num as u32,
        _padding: 0,
    };

    // Save args for the uretprobe; ignore insert errors.
    let _ = SSL_READ_ARGS.insert(&pid_tgid, &args, 0);
    Ok(())
}

#[inline(always)]
fn try_ssl_read_ret(ctx: &RetProbeContext) -> Result<(), ()> {
    let pid_tgid = bpf_get_current_pid_tgid();

    // Lookup saved entry args. If missing, nothing to do.
    let args_ptr = SSL_READ_ARGS.get_ptr(&pid_tgid).ok_or(())?;
    let args = unsafe { *args_ptr };

    // Always clean up the map entry.
    let _ = SSL_READ_ARGS.remove(&pid_tgid);

    // SSL_read returns the number of bytes read, or ≤0 on error/EOF.
    let ret: i32 = ctx.ret();
    if ret <= 0 {
        return Ok(());
    }

    // Clamp to what the buffer can actually hold.
    let actual_len = if (ret as u32) < args.buf_len {
        ret as u32
    } else {
        args.buf_len
    };

    emit_dlp_event(
        args.buf_ptr as *const u8,
        actual_len,
        DLP_DIRECTION_READ,
        task_socket(),
    );
    increment_metric(DLP_METRIC_READ_EVENTS);
    Ok(())
}

/// The registers Go's internal register ABI uses for a method taking one
/// slice: the receiver, the slice data pointer and its length, plus the
/// register the runtime pins the current goroutine in. The first integer
/// register also carries the first result at a return instruction.
struct GoRegs {
    arg0: u64,
    arg1: u64,
    arg2: u64,
    goroutine: u64,
}

/// amd64: arguments in RAX, RBX, RCX; the goroutine in R14.
#[cfg(bpf_target_arch = "x86_64")]
#[inline(always)]
fn go_regs(ctx: &ProbeContext) -> Option<GoRegs> {
    let regs = unsafe { &*ctx.regs };
    Some(GoRegs {
        arg0: regs.rax,
        arg1: regs.rbx,
        arg2: regs.rcx,
        goroutine: regs.r14,
    })
}

/// arm64: arguments in X0, X1, X2; the goroutine in X28.
#[cfg(bpf_target_arch = "aarch64")]
#[inline(always)]
fn go_regs(ctx: &ProbeContext) -> Option<GoRegs> {
    let regs = unsafe { &*ctx.regs };
    Some(GoRegs {
        arg0: regs.regs[0],
        arg1: regs.regs[1],
        arg2: regs.regs[2],
        goroutine: regs.regs[28],
    })
}

/// Go's register ABI is defined for amd64 and arm64 only among the targets
/// this agent ships; anywhere else the Go probes read nothing.
#[cfg(not(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64")))]
#[inline(always)]
fn go_regs(_ctx: &ProbeContext) -> Option<GoRegs> {
    None
}

#[inline(always)]
fn go_read_key(goroutine: u64) -> [u64; 2] {
    [bpf_get_current_pid_tgid() >> 32, goroutine]
}

#[inline(always)]
fn try_go_tls_write(ctx: &ProbeContext) -> Result<(), ()> {
    let regs = go_regs(ctx).ok_or(())?;
    let (buf, len) = (regs.arg1, regs.arg2);
    if buf == 0 || len == 0 || len > i32::MAX as u64 {
        return Ok(());
    }
    emit_dlp_event(buf as *const u8, len as u32, DLP_DIRECTION_WRITE, task_socket());
    increment_metric(DLP_METRIC_WRITE_EVENTS);
    Ok(())
}

#[inline(always)]
fn try_go_tls_read_entry(ctx: &ProbeContext) -> Result<(), ()> {
    let regs = go_regs(ctx).ok_or(())?;
    let (buf, len) = (regs.arg1, regs.arg2);
    if buf == 0 || len == 0 || len > i32::MAX as u64 || regs.goroutine == 0 {
        return Ok(());
    }
    let args = SslReadArgs {
        buf_ptr: buf,
        buf_len: len as u32,
        _padding: 0,
    };
    let _ = GO_READ_ARGS.insert(&go_read_key(regs.goroutine), &args, 0);
    Ok(())
}

#[inline(always)]
fn try_go_tls_read_ret(ctx: &ProbeContext) -> Result<(), ()> {
    let regs = go_regs(ctx).ok_or(())?;
    let key = go_read_key(regs.goroutine);
    let args_ptr = GO_READ_ARGS.get_ptr(&key).ok_or(())?;
    let args = unsafe { *args_ptr };
    let _ = GO_READ_ARGS.remove(&key);

    // `n int` is the first result; an error return carries n == 0.
    let ret = regs.arg0 as i64;
    if ret <= 0 {
        return Ok(());
    }
    let actual_len = if (ret as u64) < u64::from(args.buf_len) {
        ret as u32
    } else {
        args.buf_len
    };
    emit_dlp_event(
        args.buf_ptr as *const u8,
        actual_len,
        DLP_DIRECTION_READ,
        task_socket(),
    );
    increment_metric(DLP_METRIC_READ_EVENTS);
    Ok(())
}

// ── Helpers ─────────────────────────────────────────────────────────

/// A plaintext run the kernel TLS probes found behind a message iterator:
/// a user-space address and the number of bytes readable from it.
struct KtlsBuf {
    base: u64,
    len: u64,
}

/// Record that this thread is inside a probed TLS library call.
#[inline(always)]
fn stamp_uprobe_active() {
    let pid_tgid = bpf_get_current_pid_tgid();
    let now = unsafe { bpf_ktime_get_boot_ns() };
    let _ = DLP_UPROBE_ACTIVE.insert(&pid_tgid, &now, 0);
}

/// Whether a uprobe on the calling library already captured this plaintext.
#[inline(always)]
fn uprobe_already_captured() -> bool {
    let pid_tgid = bpf_get_current_pid_tgid();
    match DLP_UPROBE_ACTIVE.get_ptr(&pid_tgid) {
        Some(stamp_ptr) => {
            let stamp = unsafe { *stamp_ptr };
            let now = unsafe { bpf_ktime_get_boot_ns() };
            now >= stamp && now - stamp < DLP_KTLS_SUPPRESS_WINDOW_NS
        }
        None => false,
    }
}

/// Whether the running task's plaintext may leave the kernel.
///
/// A uprobe is a property of an inode, not of a workload: one `libssl.so.3`
/// layer shared by thirty containers arms one probe that fires for all thirty.
/// On a node agent that is somebody else's data, so the scope test sits here,
/// before any excerpt is copied - an event filtered in userspace has already
/// crossed into the agent's address space, its ring buffer and its logs.
///
/// The task's own cgroup is tested first, then its ancestors, so a scope naming
/// a pod slice covers every container the kubelet puts under it without the
/// operator enumerating container ids that change on every restart. The helper
/// answers zero above the root, which ends the walk.
#[inline(always)]
fn in_scope() -> bool {
    let mode = match DLP_SCOPE.get(0) {
        Some(m) => *m,
        None => return true,
    };
    if mode != DLP_SCOPE_MODE_WORKLOADS {
        return true;
    }

    let own = unsafe { bpf_get_current_cgroup_id() };
    if own != 0 && DLP_CGROUP_ALLOW.get_ptr(&own).is_some() {
        return true;
    }

    let mut level = 0u32;
    while level < DLP_SCOPE_ANCESTOR_LEVELS {
        let ancestor = unsafe { generated::bpf_get_current_ancestor_cgroup_id(level as i32) };
        if ancestor == 0 {
            break;
        }
        if DLP_CGROUP_ALLOW.get_ptr(&ancestor).is_some() {
            return true;
        }
        level += 1;
    }

    false
}

#[inline(always)]
fn read_kernel_u64(addr: u64) -> Result<u64, ()> {
    let mut value: u64 = 0;
    let rc = unsafe {
        generated::bpf_probe_read_kernel(
            &raw mut value as *mut c_void,
            core::mem::size_of::<u64>() as u32,
            addr as *const c_void,
        )
    };
    if rc == 0 { Ok(value) } else { Err(()) }
}

#[inline(always)]
fn read_kernel_u32(addr: u64) -> Result<u32, ()> {
    let mut value: u32 = 0;
    let rc = unsafe {
        generated::bpf_probe_read_kernel(
            &raw mut value as *mut c_void,
            core::mem::size_of::<u32>() as u32,
            addr as *const c_void,
        )
    };
    if rc == 0 { Ok(value) } else { Err(()) }
}

#[inline(always)]
fn read_kernel_u16(addr: u64) -> Result<u16, ()> {
    let mut value: u16 = 0;
    let rc = unsafe {
        generated::bpf_probe_read_kernel(
            &raw mut value as *mut c_void,
            core::mem::size_of::<u16>() as u32,
            addr as *const c_void,
        )
    };
    if rc == 0 { Ok(value) } else { Err(()) }
}

#[inline(always)]
fn read_kernel_u8(addr: u64) -> Result<u8, ()> {
    let mut value: u8 = 0;
    let rc = unsafe {
        generated::bpf_probe_read_kernel(
            &raw mut value as *mut c_void,
            core::mem::size_of::<u8>() as u32,
            addr as *const c_void,
        )
    };
    if rc == 0 { Ok(value) } else { Err(()) }
}

/// Read the five-tuple of the socket a kernel TLS call was made on.
///
/// `Err(())` is "nothing readable here": the offsets were never pushed, the
/// pointer is not a socket this program understands, or a read failed. The
/// caller then emits an event with no flow at all rather than one carrying
/// zeroes that read like an address.
///
/// Addresses are converted to the convention the rest of the datapath uses -
/// the host-order value of the big-endian address, one word for IPv4 and four
/// for IPv6 - so an alert's destination is encoded the same way whether it
/// came from a packet or from a socket. The protocol is a constant: kernel TLS
/// exists on TCP alone, and reading `sk_protocol` means reading a bitfield
/// whose position moves between releases for a value that cannot vary.
#[inline(always)]
fn read_sock(sk: u64) -> Result<DlpSocket, ()> {
    if sk == 0 {
        return Err(());
    }
    let offsets = match SOCK_OFFSETS.get(0) {
        Some(o) if o.valid != 0 => o,
        _ => return Err(()),
    };

    let common = sk + u64::from(offsets.sk_common);
    let family = read_kernel_u16(common + u64::from(offsets.skc_family))?;
    let src_port = read_kernel_u16(common + u64::from(offsets.skc_num))?;
    let dst_port_be = read_kernel_u16(common + u64::from(offsets.skc_dport))?;

    let mut socket = DlpSocket {
        src_port,
        dst_port: u16::from_be_bytes(dst_port_be.to_ne_bytes()),
        protocol: DLP_FLOW_PROTOCOL_TCP,
        source: DLP_FLOW_SOURCE_KERNEL_SOCKET,
        ..Default::default()
    };

    if family == u16::from(DLP_FLOW_FAMILY_IPV4) {
        let saddr = read_kernel_u32(common + u64::from(offsets.skc_rcv_saddr))?;
        let daddr = read_kernel_u32(common + u64::from(offsets.skc_daddr))?;
        socket.src_addr[0] = u32::from_be_bytes(saddr.to_ne_bytes());
        socket.dst_addr[0] = u32::from_be_bytes(daddr.to_ne_bytes());
        socket.family = DLP_FLOW_FAMILY_IPV4;
        return Ok(socket);
    }

    if family == u16::from(DLP_FLOW_FAMILY_IPV6) {
        let src_base = common + u64::from(offsets.skc_v6_rcv_saddr);
        let dst_base = common + u64::from(offsets.skc_v6_daddr);
        let mut word = 0u64;
        while word < 4 {
            let s = read_kernel_u32(src_base + word * 4)?;
            let d = read_kernel_u32(dst_base + word * 4)?;
            socket.src_addr[word as usize] = u32::from_be_bytes(s.to_ne_bytes());
            socket.dst_addr[word as usize] = u32::from_be_bytes(d.to_ne_bytes());
            word += 1;
        }
        socket.family = DLP_FLOW_FAMILY_IPV6;
        return Ok(socket);
    }

    Err(())
}

/// Remember the socket this task is writing TLS plaintext through, so a
/// library uprobe firing for the same bytes can name the destination.
///
/// The tuple is stamped `DLP_FLOW_SOURCE_CORRELATED` as it is written, not as
/// it is read: what is stored here is only ever read by somebody else's write,
/// and the stamp is what tells that reader which of the two writers it has.
/// The socket-attribution hook writes the same map with its own stamp.
#[inline(always)]
fn record_task_socket(socket: &DlpSocket) {
    let mut socket = *socket;
    socket.source = DLP_FLOW_SOURCE_CORRELATED;
    let entry = DlpTaskSocket {
        socket,
        at_ns: unsafe { bpf_ktime_get_boot_ns() },
    };
    let _ = DLP_TASK_SOCKET.insert(&bpf_get_current_pid_tgid(), &entry, 0);
}

/// The socket this task was last seen on, if it is recent enough to be about
/// this transfer.
///
/// Two writers fill the map and the entry says which one it came from. A
/// kernel TLS probe records the socket it was called on, which is the
/// destination of the *previous* write by the same thread: a thread
/// alternating two connections inside the window would be given the other
/// one, so it comes back `DLP_FLOW_SOURCE_CORRELATED` and the alert claims no
/// more than that. The socket-attribution hook records the socket the kernel
/// established for this thread, read off the socket itself, and comes back
/// `DLP_FLOW_SOURCE_KERNEL_SOCKET`.
///
/// Each is aged on its own clock, because they are claims of different
/// lifetimes: a correlation is about one call frame, a joined socket is about
/// a connection. The stamp decides which window applies, so neither writer can
/// be given the other's patience.
#[inline(always)]
fn task_socket() -> DlpSocket {
    let pid_tgid = bpf_get_current_pid_tgid();
    let Some(entry_ptr) = DLP_TASK_SOCKET.get_ptr(&pid_tgid) else {
        return DlpSocket::default();
    };
    let entry = unsafe { *entry_ptr };
    let window = if entry.socket.source == DLP_FLOW_SOURCE_KERNEL_SOCKET {
        DLP_JOINED_SOCKET_WINDOW_NS
    } else {
        DLP_TASK_SOCKET_WINDOW_NS
    };
    let now = unsafe { bpf_ktime_get_boot_ns() };
    if now < entry.at_ns || now - entry.at_ns >= window {
        return DlpSocket::default();
    }
    entry.socket
}

/// Resolve the user-space plaintext run a `struct msghdr`'s iterator points at.
///
/// `Ok(None)` is an iterator this probe deliberately does not read: a kernel
/// vector or a page/folio queue, which is what `sendfile` and `splice` produce
/// and which carries no single user buffer to excerpt. Those are counted as
/// unreadable rather than treated as an error, because nothing went wrong.
///
/// Every field is addressed through the offsets userspace resolved from the
/// running kernel's BTF. `__ubuf_iovec` and `__iov` share one union slot, so
/// `iov_union` is read once and interpreted by the iterator kind: the flat user
/// buffer itself for `ITER_UBUF`, or a kernel pointer to the current `struct
/// iovec` for `ITER_IOVEC`. `iov_offset` is how much of the run the kernel has
/// already consumed, so it is added to the base in both cases.
#[inline(always)]
fn ktls_iter_buf(msg: u64) -> Result<Option<KtlsBuf>, ()> {
    let offsets = match KTLS_ITER_OFFSETS.get(0) {
        Some(o) if o.valid != 0 => o,
        _ => return Err(()),
    };

    let iter = msg + u64::from(offsets.msg_iter);
    let iter_type = read_kernel_u8(iter + u64::from(offsets.iter_type))?;
    let iov_offset = read_kernel_u64(iter + u64::from(offsets.iov_offset))?;
    let union_slot = read_kernel_u64(iter + u64::from(offsets.iov_union))?;
    let count = read_kernel_u64(iter + u64::from(offsets.count))?;

    if iter_type == offsets.iter_ubuf {
        // `count` is the same field as `__ubuf_iovec.iov_len` and is what is
        // left to transfer, so it needs no further subtraction.
        if union_slot == 0 || count == 0 {
            return Ok(None);
        }
        return Ok(Some(KtlsBuf {
            base: union_slot + iov_offset,
            len: count,
        }));
    }

    if iter_type == offsets.iter_iovec {
        if union_slot == 0 || count == 0 {
            return Ok(None);
        }
        // Only the segment the iterator currently sits on is excerpted; the
        // DLP scanner works on a contiguous run and a second segment is a
        // separate event's worth of bytes.
        let seg_base = read_kernel_u64(union_slot + u64::from(offsets.iovec_base))?;
        let seg_len = read_kernel_u64(union_slot + u64::from(offsets.iovec_len))?;
        if seg_base == 0 || seg_len <= iov_offset {
            return Ok(None);
        }
        let remaining = seg_len - iov_offset;
        return Ok(Some(KtlsBuf {
            base: seg_base + iov_offset,
            len: if remaining < count { remaining } else { count },
        }));
    }

    Ok(None)
}

#[inline(always)]
fn try_ktls_sendmsg(ctx: &ProbeContext) -> Result<(), ()> {
    // tls_sw_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
    //   arg(0) = sk, arg(1) = msg, arg(2) = size
    //
    // The socket is recorded before the suppression test, because a library
    // uprobe that already took these bytes emitted its event without a
    // destination and the next one of its writes is what this recording is
    // for. Recording is still inside the scope test: another tenant's socket
    // is not read at all.
    let sk: u64 = ctx.arg(0).unwrap_or(0);
    let socket = match read_sock(sk) {
        Ok(socket) if in_scope() => {
            record_task_socket(&socket);
            socket
        }
        _ => DlpSocket::default(),
    };

    if uprobe_already_captured() {
        increment_metric(DLP_METRIC_KTLS_SUPPRESSED);
        return Ok(());
    }

    let msg: u64 = ctx.arg(1).ok_or(())?;
    if msg == 0 {
        return Ok(());
    }

    let buf = match ktls_iter_buf(msg) {
        Ok(Some(buf)) => buf,
        // Either the offsets were never pushed or the iterator holds no single
        // user buffer. Both leave this call unread, and neither is an error.
        Ok(None) | Err(()) => {
            increment_metric(DLP_METRIC_KTLS_UNREADABLE);
            return Ok(());
        }
    };

    if buf.len == 0 || buf.len > i32::MAX as u64 {
        return Ok(());
    }

    emit_dlp_event(buf.base as *const u8, buf.len as u32, DLP_DIRECTION_WRITE, socket);
    increment_metric(DLP_METRIC_WRITE_EVENTS);
    increment_metric(DLP_METRIC_KTLS_EVENTS);
    Ok(())
}

#[inline(always)]
fn try_ktls_recvmsg_entry(ctx: &ProbeContext) -> Result<(), ()> {
    // tls_sw_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
    //                int flags, int *addr_len)
    //   arg(0) = sk, arg(1) = msg
    let sk: u64 = ctx.arg(0).unwrap_or(0);
    let socket = match read_sock(sk) {
        Ok(socket) if in_scope() => {
            record_task_socket(&socket);
            Some(socket)
        }
        _ => None,
    };

    if uprobe_already_captured() {
        increment_metric(DLP_METRIC_KTLS_SUPPRESSED);
        return Ok(());
    }

    let msg: u64 = ctx.arg(1).ok_or(())?;
    if msg == 0 {
        return Ok(());
    }

    let buf = match ktls_iter_buf(msg) {
        Ok(Some(buf)) => buf,
        // Either the offsets were never pushed or the iterator holds no single
        // user buffer. Both leave this call unread, and neither is an error.
        Ok(None) | Err(()) => {
            increment_metric(DLP_METRIC_KTLS_UNREADABLE);
            return Ok(());
        }
    };

    if buf.len == 0 || buf.len > i32::MAX as u64 {
        return Ok(());
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let args = SslReadArgs {
        buf_ptr: buf.base,
        buf_len: buf.len as u32,
        _padding: 0,
    };
    let _ = KTLS_READ_ARGS.insert(&pid_tgid, &args, 0);
    match socket {
        Some(socket) => {
            let _ = KTLS_READ_SOCKET.insert(&pid_tgid, &socket, 0);
        }
        None => {
            let _ = KTLS_READ_SOCKET.remove(&pid_tgid);
        }
    }
    Ok(())
}

#[inline(always)]
fn try_ktls_recvmsg_ret(ctx: &RetProbeContext) -> Result<(), ()> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let args_ptr = KTLS_READ_ARGS.get_ptr(&pid_tgid).ok_or(())?;
    let args = unsafe { *args_ptr };
    let _ = KTLS_READ_ARGS.remove(&pid_tgid);

    let socket = match KTLS_READ_SOCKET.get_ptr(&pid_tgid) {
        Some(socket_ptr) => unsafe { *socket_ptr },
        None => DlpSocket::default(),
    };
    let _ = KTLS_READ_SOCKET.remove(&pid_tgid);

    let ret: i32 = ctx.ret();
    if ret <= 0 {
        return Ok(());
    }

    let actual_len = if (ret as u32) < args.buf_len {
        ret as u32
    } else {
        args.buf_len
    };

    emit_dlp_event(args.buf_ptr as *const u8, actual_len, DLP_DIRECTION_READ, socket);
    increment_metric(DLP_METRIC_READ_EVENTS);
    increment_metric(DLP_METRIC_KTLS_EVENTS);
    Ok(())
}

/// Emit a `DlpEvent` to the EVENTS `RingBuf`, picking a size tier:
/// - `data_len <= 256` -> `DlpEventSmall` (328 bytes)
/// - `data_len > 256`  -> `DlpEvent` (4168 bytes, full capture)
///
/// # Why two types rather than one runtime-sized reservation
///
/// `bpf_ringbuf_reserve` takes a size argument, and aya exposes it as
/// `reserve_bytes`, so a per-payload reservation looks reachable. It is not:
/// the verifier requires that size to be a compile-time constant, which is
/// what `reserve_untyped::<T>` already gives us. Tiering by type is therefore
/// the same mechanism with the bound stated in the type system, and adding
/// tiers is the only way to cut waste further.
///
/// The copy length is separate from the reservation size: it is clamped to
/// `data_len` capped at the tier's excerpt, so only bytes the SSL buffer holds
/// are read, never adjacent process memory. `data_len` in the header tells
/// userspace how many of the excerpt bytes are meaningful.
///
/// `flow` is the socket the caller could account for, already carrying how it
/// came by it. A default `DlpSocket` means the probe had no socket, and that
/// is what the event says: a zeroed block whose `source` is
/// `DLP_FLOW_SOURCE_NONE`, which userspace drops rather than reading as
/// `0.0.0.0:0`.
#[inline(always)]
fn emit_dlp_event(user_buf: *const u8, data_len: u32, direction: u8, flow: DlpSocket) {
    if !in_scope() {
        increment_metric(DLP_METRIC_OUT_OF_SCOPE);
        return;
    }
    if data_len <= DLP_SMALL_EXCERPT as u32 {
        emit_dlp_small(user_buf, data_len, direction, flow);
    } else {
        emit_dlp_full(user_buf, data_len, direction, flow);
    }
}

/// Small DLP event (328 bytes): for SSL payloads ≤ 256 bytes.
///
/// `#[inline(never)]` gives this function its own stack frame, reducing
/// per-function verifier complexity and keeping it separate from the
/// full-size path.
#[inline(never)]
fn emit_dlp_small(user_buf: *const u8, data_len: u32, direction: u8, flow: DlpSocket) {
    if let Some(mut entry) = EVENTS.reserve_untyped::<DlpEventSmall>(0) {
        let ptr = entry.as_mut_ptr();
        let pid_tgid = bpf_get_current_pid_tgid();
        unsafe {
            (*ptr).pid = pid_tgid as u32;
            (*ptr).tgid = (pid_tgid >> 32) as u32;
            (*ptr).timestamp_ns = bpf_ktime_get_boot_ns();
            // Uprobes always run in process context, so cgroup_id is
            // reliably populated on cgroup v2 systems.
            (*ptr).cgroup_id = bpf_get_current_cgroup_id();
            (*ptr).data_len = data_len;
            (*ptr).direction = direction;
            (*ptr)._padding = [0; 3];
            (*ptr).flow = flow;
            core::ptr::write_bytes((*ptr).data_excerpt.as_mut_ptr(), 0, DLP_SMALL_EXCERPT);
            // Read only the bytes the payload actually holds - never the
            // full excerpt - so we don't capture adjacent process memory past
            // the SSL buffer. This is `#[inline(never)]`, so the caller's
            // `data_len <= DLP_SMALL_EXCERPT` invariant is lost across the
            // frame and a plain branch leaves the helper reading the unmasked
            // register ("R2 min value is negative"); the explicit AND restores
            // the bound the verifier needs to accept a runtime length. A
            // payload of exactly DLP_SMALL_EXCERPT bytes copies the first
            // DLP_SMALL_EXCERPT-1 (the buffer is pre-zeroed, so the last byte
            // stays 0) - acceptable for an excerpt preview.
            let copy_len = (if data_len >= DLP_SMALL_EXCERPT as u32 {
                DLP_SMALL_EXCERPT as u32 - 1
            } else {
                data_len
            }) & (DLP_SMALL_EXCERPT as u32 - 1);
            if copy_len > 0 {
                let _ = generated::bpf_probe_read_user(
                    (*ptr).data_excerpt.as_mut_ptr() as *mut c_void,
                    copy_len,
                    user_buf as *const c_void,
                );
            }
        }
        entry.submit(submit_flags(avail_data(&EVENTS)));
    } else {
        increment_metric(DLP_METRIC_EVENTS_DROPPED);
    }
}

/// Full DLP event (4168 bytes): for SSL payloads > 256 bytes.
///
/// Emitted via RingBuf. Arena zero-copy is not available: the eBPF
/// arena pointer returned by `bpf_arena_alloc_pages` stays an untyped
/// scalar on the Rust `bpfel` target (no `addr_space_cast`), so the
/// verifier rejects any write through it.
#[inline(never)]
fn emit_dlp_full(user_buf: *const u8, data_len: u32, direction: u8, flow: DlpSocket) {
    if let Some(mut entry) = EVENTS.reserve_untyped::<DlpEvent>(0) {
        let ptr = entry.as_mut_ptr();
        let pid_tgid = bpf_get_current_pid_tgid();
        unsafe {
            (*ptr).pid = pid_tgid as u32;
            (*ptr).tgid = (pid_tgid >> 32) as u32;
            (*ptr).timestamp_ns = bpf_ktime_get_boot_ns();
            (*ptr).cgroup_id = bpf_get_current_cgroup_id();
            (*ptr).data_len = data_len;
            (*ptr).direction = direction;
            (*ptr)._padding = [0; 3];
            (*ptr).flow = flow;
            core::ptr::write_bytes((*ptr).data_excerpt.as_mut_ptr(), 0, DLP_MAX_EXCERPT);
            // Clamp the read to the payload length (capped at the excerpt
            // size) so we never copy adjacent process memory past the SSL
            // buffer. The clamp keeps copy_len <= the destination size,
            // which the verifier needs to accept a runtime length.
            let copy_len = if data_len > DLP_MAX_EXCERPT as u32 {
                DLP_MAX_EXCERPT as u32
            } else {
                data_len
            };
            if copy_len > 0 {
                let _ = generated::bpf_probe_read_user(
                    (*ptr).data_excerpt.as_mut_ptr() as *mut c_void,
                    copy_len,
                    user_buf as *const c_void,
                );
            }
        }
        entry.submit(submit_flags(avail_data(&EVENTS)));
    } else {
        increment_metric(DLP_METRIC_EVENTS_DROPPED);
    }
}

/// Increment a per-CPU metric counter.
#[inline(always)]
fn increment_metric(index: u32) {
    increment_metric!(DLP_METRICS, index);
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
