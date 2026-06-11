// ebpfsentinel-token-launch.c — privileged launcher for rootless, token-only
// eBPF loading.
//
// BPF token delegation is a *user-namespace* feature: BPF_TOKEN_CREATE only
// succeeds against a bpffs whose superblock is owned by a user namespace the
// caller is in (a descendant of where the delegation was configured). In the
// initial user namespace it returns EOPNOTSUPP. So a token-only agent cannot
// run directly under systemd/Docker in the host user namespace — it must run
// inside a child user namespace that owns the delegated bpffs.
//
// This launcher does exactly that, then execs the agent:
//
//   1. While still global root, it enumerates every loaded module's BTF object,
//      opens an fd for each, clears O_CLOEXEC so the fds survive exec, and
//      advertises them to the agent via EBPF_MODULE_BTF_FDS=name=fd,... — this
//      is what lets module kfuncs (nf_conntrack bpf_*_ct_*, fou
//      bpf_skb_get_fou_encap) resolve without CAP_SYS_ADMIN in the agent.
//
//   2. It sets up the delegated bpffs via the kernel fd-passing dance: the CHILD
//      unshares a user namespace and fsopen("bpf") (the superblock is owned by
//      the child userns); it passes the fs_fd to the (global-root) PARENT via
//      SCM_RIGHTS; the parent sets delegate_*=any and FSCONFIG_CMD_CREATE (the
//      steps that need global CAP_SYS_ADMIN); the child fsmounts + move_mounts it
//      at the bpffs path. A plain `mount -t bpf` cannot do this — the mount
//      config needs global CAP_SYS_ADMIN while the superblock ownership must be
//      the userns that called fsopen.
//
//   3. The child execs the agent inside the namespace with no global
//      capabilities (root only inside the namespace). The agent finds the
//      delegated bpffs, creates a BPF token, and loads/attaches every program
//      through it.
//
// Usage: ebpfsentinel-token-launch [--bpffs <path>] <agent-binary> [agent-args...]
//   --bpffs <path>   Where to mount the delegated bpffs (must match the agent's
//                    agent.bpf_token.bpffs_path; default /sys/fs/bpf/ebpfsentinel).
//
// NOTE: the agent runs in a child user namespace and therefore has NO
// capabilities over host-owned resources (the host network namespace). eBPF
// detection/firewall/IDS/IPS/DLP/DNS/DDoS/NAT/QoS/LB all work through the token,
// but host-netns syscalls (pcap AF_PACKET capture, `conntrack -D` retroactive
// teardown, gratuitous-ARP on VIP takeover) degrade gracefully — their eBPF
// equivalents (IPS_DYING flow-kill, xdp-vip-announcer) keep working.
#define _GNU_SOURCE
#include <sched.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/wait.h>

#ifndef FSCONFIG_SET_STRING
#define FSCONFIG_SET_STRING 1
#endif
#ifndef FSCONFIG_CMD_CREATE
#define FSCONFIG_CMD_CREATE 6
#endif
#ifndef MOVE_MOUNT_F_EMPTY_PATH
#define MOVE_MOUNT_F_EMPTY_PATH 0x4
#endif

#define DEFAULT_BPFFS "/sys/fs/bpf/ebpfsentinel"

static long bpf(int cmd, union bpf_attr *attr, unsigned int size) {
  return syscall(SYS_bpf, cmd, attr, size);
}

// Build "name=fd,name=fd,..." for every loaded module BTF. Opened here (global
// root) so the child inherits the fds across fork+exec.
static void collect_module_btf_fds(char *out, size_t out_sz) {
  out[0] = 0;
  size_t used = 0;
  unsigned int id = 0;
  for (;;) {
    union bpf_attr a;
    memset(&a, 0, sizeof(a));
    a.start_id = id;
    if (bpf(BPF_BTF_GET_NEXT_ID, &a, sizeof(a)) < 0) break;
    id = a.next_id;

    union bpf_attr fa;
    memset(&fa, 0, sizeof(fa));
    fa.btf_id = id;
    long fd = bpf(BPF_BTF_GET_FD_BY_ID, &fa, sizeof(fa));
    if (fd < 0) continue;
    fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) & ~FD_CLOEXEC);

    char name[64] = {0};
    struct bpf_btf_info info;
    memset(&info, 0, sizeof(info));
    info.name = (unsigned long)name;
    info.name_len = sizeof(name);
    union bpf_attr ia;
    memset(&ia, 0, sizeof(ia));
    ia.info.bpf_fd = (unsigned int)fd;
    ia.info.info_len = sizeof(info);
    ia.info.info = (unsigned long)&info;
    if (bpf(BPF_OBJ_GET_INFO_BY_FD, &ia, sizeof(ia)) < 0) { close(fd); continue; }
    if (name[0] == 0 || strcmp(name, "vmlinux") == 0) { close(fd); continue; }

    int n = snprintf(out + used, out_sz - used, "%s%s=%ld",
                     used ? "," : "", name, fd);
    if (n < 0 || (size_t)n >= out_sz - used) { close(fd); break; }
    used += n;
  }
}

static int wfile(const char *p, const char *v) {
  int f = open(p, O_WRONLY);
  if (f < 0) { perror(p); return -1; }
  int r = write(f, v, strlen(v));
  close(f);
  return r < 0 ? -1 : 0;
}
static int send_fd(int sock, int fd) {
  struct msghdr msg = {0};
  char buf[CMSG_SPACE(sizeof(int))] = {0};
  struct iovec io = {(void *)"x", 1};
  msg.msg_iov = &io; msg.msg_iovlen = 1;
  msg.msg_control = buf; msg.msg_controllen = sizeof(buf);
  struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
  c->cmsg_level = SOL_SOCKET; c->cmsg_type = SCM_RIGHTS;
  c->cmsg_len = CMSG_LEN(sizeof(int));
  memcpy(CMSG_DATA(c), &fd, sizeof(int));
  return sendmsg(sock, &msg, 0) < 0 ? -1 : 0;
}
static int recv_fd(int sock) {
  struct msghdr msg = {0};
  char m[1];
  char buf[CMSG_SPACE(sizeof(int))] = {0};
  struct iovec io = {m, 1};
  msg.msg_iov = &io; msg.msg_iovlen = 1;
  msg.msg_control = buf; msg.msg_controllen = sizeof(buf);
  if (recvmsg(sock, &msg, 0) < 0) return -1;
  struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
  int fd;
  memcpy(&fd, CMSG_DATA(c), sizeof(int));
  return fd;
}

// Create every leading directory of `path` (like `mkdir -p`), ignoring EEXIST.
static void mkdirs(const char *path) {
  char tmp[256];
  snprintf(tmp, sizeof(tmp), "%s", path);
  for (char *p = tmp + 1; *p; p++) {
    if (*p == '/') { *p = 0; mkdir(tmp, 0700); *p = '/'; }
  }
  mkdir(tmp, 0700);
}

int main(int argc, char **argv) {
  const char *bpffs = DEFAULT_BPFFS;
  int argi = 1;
  while (argi < argc && strncmp(argv[argi], "--", 2) == 0) {
    if (strcmp(argv[argi], "--bpffs") == 0 && argi + 1 < argc) {
      bpffs = argv[argi + 1];
      argi += 2;
    } else if (strcmp(argv[argi], "--") == 0) {
      argi++;
      break;
    } else {
      fprintf(stderr, "unknown option: %s\n", argv[argi]);
      return 2;
    }
  }
  if (argi >= argc) {
    fprintf(stderr,
            "usage: %s [--bpffs <path>] <agent-binary> [agent-args...]\n",
            argv[0]);
    return 2;
  }
  char **agent_argv = &argv[argi];
  uid_t uid = getuid(), gid = getgid();

  // Open module BTF fds while still global root, before the userns fork.
  static char modfds[8192];
  collect_module_btf_fds(modfds, sizeof(modfds));

  int sv[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) { perror("socketpair"); return 1; }
  pid_t pid = fork();
  if (pid == 0) { // CHILD: userns owner
    close(sv[0]);
    setenv("EBPF_MODULE_BTF_FDS", modfds, 1);
    if (unshare(CLONE_NEWUSER)) { perror("unshare USER"); _exit(1); }
    char mp[64];
    wfile("/proc/self/setgroups", "deny");
    snprintf(mp, sizeof(mp), "0 %d 1", uid); if (wfile("/proc/self/uid_map", mp)) _exit(1);
    snprintf(mp, sizeof(mp), "0 %d 1", gid); if (wfile("/proc/self/gid_map", mp)) _exit(1);
    if (setgid(0) || setuid(0)) { perror("setid"); _exit(1); }
    if (unshare(CLONE_NEWNS)) { perror("unshare NS"); _exit(1); }
    syscall(SYS_mount, "none", "/", NULL, MS_REC | MS_PRIVATE, NULL);
    long fs = syscall(SYS_fsopen, "bpf", 0);
    if (fs < 0) { perror("fsopen(child)"); _exit(1); }
    if (send_fd(sv[1], (int)fs)) { perror("send_fd"); _exit(1); }
    char ack;
    if (read(sv[1], &ack, 1) != 1 || ack != 1) { fprintf(stderr, "parent CMD_CREATE failed\n"); _exit(1); }
    long mnt = syscall(SYS_fsmount, fs, 0, 0);
    if (mnt < 0) { perror("fsmount(child)"); _exit(1); }
    mkdirs(bpffs);
    if (syscall(SYS_move_mount, (int)mnt, "", (int)AT_FDCWD, bpffs, MOVE_MOUNT_F_EMPTY_PATH)) {
      perror("move_mount"); _exit(1);
    }
    execv(agent_argv[0], agent_argv);
    perror("execv");
    _exit(127);
  }
  // PARENT: global root, configures delegation on the child's fs_fd.
  close(sv[1]);
  int fs = recv_fd(sv[0]);
  if (fs < 0) { perror("recv_fd"); return 1; }
  syscall(SYS_fsconfig, fs, FSCONFIG_SET_STRING, "delegate_cmds", "any", 0);
  syscall(SYS_fsconfig, fs, FSCONFIG_SET_STRING, "delegate_maps", "any", 0);
  syscall(SYS_fsconfig, fs, FSCONFIG_SET_STRING, "delegate_progs", "any", 0);
  syscall(SYS_fsconfig, fs, FSCONFIG_SET_STRING, "delegate_attachs", "any", 0);
  char ack = 1;
  if (syscall(SYS_fsconfig, fs, FSCONFIG_CMD_CREATE, NULL, NULL, 0)) { perror("CMD_CREATE(parent)"); ack = 0; }
  if (write(sv[0], &ack, 1) != 1) perror("ack");
  int st;
  waitpid(pid, &st, 0);
  return WIFEXITED(st) ? WEXITSTATUS(st) : 1;
}
