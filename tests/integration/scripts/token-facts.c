// token-facts.c - what a BPF token delegated the way the warden delegates it
// lets a program in an unprivileged user namespace do, asked of the running
// kernel. Run as root: the parent plays the warden (it applies the delegation
// options to a bpffs the child opened), the child plays the agent (a user
// namespace mapped to nobody, holding only the token).
//
// Each fact is one line on stdout: `<fact>: ok` or `<fact>: refused <errno>`,
// followed by the first verifier line when the kernel wrote one.
//
//   cc -O2 -Wall -static -o token-facts token-facts.c
//   sudo ./token-facts           # delegated as the warden delegates today
//   sudo ./token-facts narrow    # without the types that read the kernel
//
// The delegation lists below mirror DELEGATED_PROGS and DELEGATED_ATTACHS in
// crates/warden/src/lib.rs; a fact proved here holds for the warden only while
// they agree.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <grp.h>
#include <sys/wait.h>
#include <unistd.h>

#define BPF_PROG_LOAD 5
#define BPF_LINK_CREATE 28
#define BPF_TOKEN_CREATE 36
#define BPF_PROG_TYPE_KPROBE 2
#define BPF_PROG_TYPE_SCHED_CLS 3
#define BPF_TRACE_KPROBE_MULTI 42
#define BPF_F_TOKEN_FD (1U << 16)
#define FSCONFIG_SET_STRING 1
#define FSCONFIG_CMD_CREATE 6

static const char *PROGS[] = {
    "xdp", "sched_cls", "kprobe", "cgroup_skb", "cgroup_sock",
    "cgroup_sock_addr", "sock_ops", "raw_tracepoint", "lsm", "syscall",
};
static const char *ATTACHS[] = {
    "cgroup_inet_ingress", "cgroup_inet_egress", "cgroup_inet_sock_release",
    "cgroup_inet4_bind", "cgroup_inet6_bind", "cgroup_inet4_post_bind",
    "cgroup_inet6_post_bind", "cgroup_inet4_connect", "cgroup_inet6_connect",
    "cgroup_udp4_sendmsg", "cgroup_udp6_sendmsg", "cgroup_udp4_recvmsg",
    "cgroup_udp6_recvmsg", "cgroup_inet4_getpeername", "cgroup_inet6_getpeername",
    "cgroup_sock_ops", "xdp", "tcx_ingress", "tcx_egress", "trace_uprobe_multi",
    "trace_kprobe_multi", "trace_kprobe_session", "lsm_mac",
};

struct insn {
    uint8_t code;
    uint8_t regs;
    int16_t off;
    int32_t imm;
};

#define MOV64_IMM(dst, v) {0xb7, (dst), 0, (v)}
#define ADD64_IMM(dst, v) {0x07, (dst), 0, (v)}
#define MOV64_REG(dst, src) {0xbf, (uint8_t)((src) << 4 | (dst)), 0, 0}
#define CALL(h) {0x85, 0, 0, (h)}
#define EXIT() {0x95, 0, 0, 0}

// The prefix of union bpf_attr for BPF_PROG_LOAD as of 6.9, where
// prog_token_fd was added; written out because the 24.04 headers stop at 6.8.
struct prog_load {
    uint32_t prog_type, insn_cnt;
    uint64_t insns, license;
    uint32_t log_level, log_size;
    uint64_t log_buf;
    uint32_t kern_version, prog_flags;
    char prog_name[16];
    uint32_t prog_ifindex, expected_attach_type, prog_btf_fd, func_info_rec_size;
    uint64_t func_info;
    uint32_t func_info_cnt, line_info_rec_size;
    uint64_t line_info;
    uint32_t line_info_cnt, attach_btf_id, attach_prog_fd, core_relo_cnt;
    uint64_t fd_array, core_relos;
    uint32_t core_relo_rec_size, log_true_size;
    int32_t prog_token_fd;
    uint32_t pad;
};

struct link_create {
    uint32_t prog_fd, target_fd, attach_type, flags;
    uint32_t km_flags, km_cnt;
    uint64_t km_syms, km_addrs, km_cookies;
    uint8_t rest[64];
};

static long bpf(int cmd, void *attr, unsigned size) {
    return syscall(SYS_bpf, cmd, attr, size);
}

static void send_fd(int sock, int fd) {
    char c = 0;
    struct iovec iov = {&c, 1};
    char buf[CMSG_SPACE(sizeof(int))] = {0};
    struct msghdr m = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = buf,
                       .msg_controllen = sizeof(buf)};
    struct cmsghdr *h = CMSG_FIRSTHDR(&m);
    h->cmsg_level = SOL_SOCKET;
    h->cmsg_type = SCM_RIGHTS;
    h->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(h), &fd, sizeof(int));
    if (sendmsg(sock, &m, 0) != 1) { perror("sendmsg"); exit(2); }
}

static int recv_fd(int sock) {
    char c;
    struct iovec iov = {&c, 1};
    char buf[CMSG_SPACE(sizeof(int))] = {0};
    struct msghdr m = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = buf,
                       .msg_controllen = sizeof(buf)};
    if (recvmsg(sock, &m, 0) != 1) { perror("recvmsg"); exit(2); }
    int fd;
    memcpy(&fd, CMSG_DATA(CMSG_FIRSTHDR(&m)), sizeof(int));
    return fd;
}

static void sync_byte(int sock, int write_it) {
    char c = 0;
    if ((write_it ? write(sock, &c, 1) : read(sock, &c, 1)) != 1) { perror("sync"); exit(2); }
}

static int fsconfig_str(int fs, const char *k, const char *v) {
    if (syscall(SYS_fsconfig, fs, FSCONFIG_SET_STRING, k, v, 0) != 0) {
        fprintf(stderr, "fsconfig %s=%s: %s\n", k, v, strerror(errno));
        return -1;
    }
    return 0;
}

// With `narrow`, the program and attach types that read or steer the kernel
// (kprobe, lsm, raw_tracepoint; trace_kprobe_multi, trace_kprobe_session,
// lsm_mac) are left out, as a token cut to the datapath would leave them.
static int narrow;

static int reads_the_kernel(const char *name) {
    static const char *cut[] = {"kprobe", "lsm", "raw_tracepoint", "trace_kprobe_multi",
                                "trace_kprobe_session", "lsm_mac"};
    for (size_t i = 0; i < sizeof(cut) / sizeof(*cut); i++)
        if (!strcmp(name, cut[i])) return 1;
    return 0;
}

static void delegate(int fs) {
    if (fsconfig_str(fs, "delegate_cmds", "any") || fsconfig_str(fs, "delegate_maps", "any"))
        exit(2);
    for (size_t i = 0; i < sizeof(PROGS) / sizeof(*PROGS); i++)
        if (!(narrow && reads_the_kernel(PROGS[i])) && fsconfig_str(fs, "delegate_progs", PROGS[i]))
            exit(2);
    for (size_t i = 0; i < sizeof(ATTACHS) / sizeof(*ATTACHS); i++)
        if (!(narrow && reads_the_kernel(ATTACHS[i])) &&
            fsconfig_str(fs, "delegate_attachs", ATTACHS[i]))
            exit(2);
    if (syscall(SYS_fsconfig, fs, FSCONFIG_CMD_CREATE, NULL, NULL, 0) != 0) {
        perror("FSCONFIG_CMD_CREATE");
        exit(2);
    }
}

static char log_buf[1 << 16];

static int load_as(int token, const char *what, uint32_t type, uint32_t attach,
                   const struct insn *insns, unsigned n) {
    struct prog_load a = {0};
    a.prog_type = type;
    a.expected_attach_type = attach;
    a.insns = (uintptr_t)insns;
    a.insn_cnt = n;
    a.license = (uintptr_t)"GPL";
    a.log_level = 1;
    a.log_size = sizeof(log_buf);
    a.log_buf = (uintptr_t)log_buf;
    a.prog_flags = BPF_F_TOKEN_FD;
    a.prog_token_fd = token;
    log_buf[0] = 0;
    int fd = (int)bpf(BPF_PROG_LOAD, &a, sizeof(a));
    if (fd >= 0) {
        printf("%s: ok\n", what);
    } else {
        int e = errno;
        // The log of a program this short is a few lines: printed on one.
        for (char *p = log_buf; *p; p++) if (*p == '\n') *p = ' ';
        printf("%s: refused %s%s%s\n", what, strerrorname_np(e),
               log_buf[0] ? " | verifier: " : "", log_buf);
    }
    return fd;
}

static int load(int token, const char *what, const struct insn *insns, unsigned n) {
    return load_as(token, what, BPF_PROG_TYPE_KPROBE, BPF_TRACE_KPROBE_MULTI, insns, n);
}

static void attach(int prog, const char *what, const char *sym) {
    if (prog < 0) {
        printf("%s: not tried, the load was refused\n", what);
        return;
    }
    const char *syms[] = {sym};
    struct link_create a = {0};
    a.prog_fd = (uint32_t)prog;
    a.attach_type = BPF_TRACE_KPROBE_MULTI;
    a.km_cnt = 1;
    a.km_syms = (uintptr_t)syms;
    int fd = (int)bpf(BPF_LINK_CREATE, &a, sizeof(a));
    if (fd >= 0) {
        printf("%s (%s): ok\n", what, sym);
        close(fd);
    } else {
        printf("%s (%s): refused %s\n", what, sym, strerrorname_np(errno));
    }
}

static void drop_perfmon(void) {
    struct { uint32_t version; int pid; } hdr = {0x20080522, 0};
    struct { uint32_t effective, permitted, inheritable; } data[2];
    if (syscall(SYS_capget, &hdr, data)) { perror("capget"); exit(2); }
    data[0].effective &= ~(1U << 21);          // CAP_SYS_ADMIN
    data[1].effective &= ~(1U << (38 - 32));   // CAP_PERFMON
    if (syscall(SYS_capset, &hdr, data)) { perror("capset"); exit(2); }
}

static void agent(int sock) {
    // The agent is an unprivileged uid before it makes its namespace: drop
    // to nobody, so nothing below runs as root on the host.
    if (setgroups(0, NULL) || setresgid(65534, 65534, 65534) || setresuid(65534, 65534, 65534)) {
        perror("drop to nobody");
        exit(2);
    }
    if (unshare(CLONE_NEWUSER | CLONE_NEWNS) != 0) { perror("unshare"); exit(2); }
    sync_byte(sock, 1);
    sync_byte(sock, 0); // the parent wrote the id maps
    int fs = (int)syscall(SYS_fsopen, "bpf", 0);
    if (fs < 0) { perror("fsopen bpf"); exit(2); }
    send_fd(sock, fs);
    sync_byte(sock, 0); // the parent delegated and created the superblock
    int mnt = (int)syscall(SYS_fsmount, fs, 0, 0);
    if (mnt < 0) { perror("fsmount"); exit(2); }
    // The mount fd is an O_PATH one, which BPF_TOKEN_CREATE refuses with
    // EBADF: open the root of the mount for reading, as the agent does.
    int root = openat(mnt, ".", O_RDONLY | O_DIRECTORY);
    if (root < 0) { perror("open the bpffs root"); exit(2); }
    uint32_t tattr[2] = {0, (uint32_t)root};
    int token = (int)bpf(BPF_TOKEN_CREATE, tattr, sizeof(tattr));
    if (token < 0) { perror("BPF_TOKEN_CREATE"); exit(2); }
    printf("token: ok (uid %d in its user namespace, mapped to nobody on the host)\n", getuid());

    const struct insn ret0[] = {MOV64_IMM(0, 0), EXIT()};
    int p = load(token, "kprobe_multi program load through the token", ret0, 2);
    attach(p, "kprobe_multi attach from the user namespace", "__x64_sys_getppid");
    if (p >= 0) close(p);

    // bpf_probe_write_user(dst=0, src=0, len=0), helper 36.
    const struct insn wu[] = {MOV64_IMM(1, 0), MOV64_IMM(2, 0), MOV64_IMM(3, 0),
                              CALL(36), MOV64_IMM(0, 0), EXIT()};
    p = load(token, "bpf_probe_write_user load through the token", wu, 6);
    if (p >= 0) close(p);

    // bpf_override_return(ctx, 0), helper 58. The attach is made on a syscall
    // on the error-injection list and the link closed at once; the program
    // never ran when nothing called vhangup meanwhile, and would have made it
    // return 0, which is its normal answer.
    const struct insn ov[] = {MOV64_IMM(2, 0), CALL(58), MOV64_IMM(0, 0), EXIT()};
    p = load(token, "bpf_override_return load through the token", ov, 4);
    attach(p, "bpf_override_return attach from the user namespace", "__x64_sys_vhangup");
    if (p >= 0) close(p);
    // bpf_probe_read_kernel(fp - 8, 8, NULL), helper 113: any kernel address
    // read into the program. Loaded only.
    const struct insn rk[] = {MOV64_REG(1, 10), ADD64_IMM(1, -8), MOV64_IMM(2, 8),
                              MOV64_IMM(3, 0), CALL(113), MOV64_IMM(0, 0), EXIT()};
    p = load(token, "bpf_probe_read_kernel load through the token", rk, 7);
    if (p >= 0) close(p);
    // The same helper from a traffic-control program, a type the datapath
    // keeps: the base helpers include it wherever the token grants CAP_PERFMON.
    p = load_as(token, "bpf_probe_read_kernel from a sched_cls program through the token",
                BPF_PROG_TYPE_SCHED_CLS, 0, rk, 7);
    if (p >= 0) close(p);

    // bpf_send_signal(SIGKILL), helper 109: on a kprobe, the task that
    // entered the probed function, whoever owns it. Loaded only, never
    // attached.
    const struct insn ss[] = {MOV64_IMM(1, 9), CALL(109), MOV64_IMM(0, 0), EXIT()};
    p = load(token, "bpf_send_signal load through the token", ss, 4);
    if (p >= 0) close(p);

    // The token grants a capability only where the caller holds it in the
    // token's namespace. Dropping CAP_PERFMON and CAP_SYS_ADMIN (which
    // stands in for it) from the effective set leaves CAP_BPF and
    // CAP_NET_ADMIN, what a datapath program needs.
    drop_perfmon();
    p = load_as(token, "bpf_probe_read_kernel from a sched_cls program, CAP_PERFMON and CAP_SYS_ADMIN dropped",
                BPF_PROG_TYPE_SCHED_CLS, 0, rk, 7);
    if (p >= 0) close(p);
    p = load_as(token, "plain sched_cls program, CAP_PERFMON and CAP_SYS_ADMIN dropped",
                BPF_PROG_TYPE_SCHED_CLS, 0, ret0, 2);
    if (p >= 0) close(p);
    fflush(stdout);
    exit(0);
}

int main(int argc, char **argv) {
    narrow = argc > 1 && !strcmp(argv[1], "narrow");
    if (getuid() != 0) { fprintf(stderr, "run as root: the parent delegates\n"); return 2; }
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); return 2; }
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        close(sv[0]);
        agent(sv[1]);
    }
    close(sv[1]);
    sync_byte(sv[0], 0);
    char path[64], map[] = "0 65534 1";
    snprintf(path, sizeof(path), "/proc/%d/setgroups", pid);
    int f = open(path, O_WRONLY);
    if (f < 0 || write(f, "deny", 4) != 4) { perror(path); return 2; }
    close(f);
    for (int i = 0; i < 2; i++) {
        snprintf(path, sizeof(path), "/proc/%d/%s", pid, i ? "gid_map" : "uid_map");
        f = open(path, O_WRONLY);
        if (f < 0 || write(f, map, strlen(map)) != (ssize_t)strlen(map)) { perror(path); return 2; }
        close(f);
    }
    sync_byte(sv[0], 1);
    int fs = recv_fd(sv[0]);
    delegate(fs);
    sync_byte(sv[0], 1);
    int status;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 2;
}
