// sign-facts.c - what a kernel that verifies BPF program signatures (6.18
// and later) does with a signed loader program, asked of the running kernel.
// Run as root: the parent plays the warden (it delegates a bpffs, owns the
// keyring the agent's signatures are checked against, and with `guard` loads
// a BPF LSM program on the bpf_prog_load hook), the child plays the agent (a
// user namespace mapped to nobody, holding only the token).
//
// The loader has the shape the build would emit for each object: a program
// of type `syscall` whose instructions are signed, checking that the one
// metadata map it reads hashes to the digest its instructions carry, then
// loading the program the map holds through bpf_sys_bpf.
//
// Each fact is one line on stdout: `<fact>: ok` or `<fact>: refused <errno>`,
// followed by the verifier log when the kernel wrote one.
//
//   cc -O2 -Wall -Wextra -static -o sign-facts sign-facts.c
//   ./sign-facts emit > loader.bin      # the loader's instructions, to sign
//   for k in trusted rogue; do
//     openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=$k -keyout $k.key -out $k.pem
//     openssl x509 -in $k.pem -outform DER -out $k.der
//     openssl cms -sign -binary -noattr -nocerts -md sha256 -outform DER -in loader.bin
//       -signer $k.pem -inkey $k.key -out loader.$k.sig
//   done
//   sudo ./sign-facts                   # no LSM verdict
//   sudo ./sign-facts guard             # with the BPF LSM program (lsm=...,bpf)
//
// Signing needs the files in the working directory: trusted.der, rogue.der,
// loader.trusted.sig, loader.rogue.sig.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <sched.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define BPF_MAP_CREATE 0
#define BPF_MAP_UPDATE_ELEM 2
#define BPF_PROG_LOAD 5
#define BPF_PROG_TEST_RUN 10
#define BPF_OBJ_GET_INFO_BY_FD 15
#define BPF_MAP_FREEZE 22
#define BPF_LINK_CREATE 28
#define BPF_TOKEN_CREATE 36
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_PROG_TYPE_SCHED_CLS 3
#define BPF_PROG_TYPE_LSM 29
#define BPF_PROG_TYPE_SYSCALL 31
#define BPF_LSM_MAC 27
#define BPF_F_SLEEPABLE (1U << 4)
#define BPF_F_TOKEN_FD (1U << 16)
#define BPF_PSEUDO_MAP_IDX 5
#define BPF_PSEUDO_MAP_IDX_VALUE 6
#define FUNC_SYS_BPF 166
#define FUNC_PROBE_READ_KERNEL 113
#define FSCONFIG_SET_STRING 1
#define FSCONFIG_CMD_CREATE 6
#define KEY_SPEC_SESSION_KEYRING -3
#define KEYCTL_SETPERM 5
#define KEYCTL_JOIN_SESSION_KEYRING 1

// The warden's delegation cut to the datapath: no kprobe, lsm or
// raw_tracepoint; `syscall` stays, the loader is one. Attach types are all
// delegated: a program's expected attach type is checked against them at
// load, and which ones the token carries is not the question here.
static const char *PROGS[] = {"xdp", "sched_cls", "cgroup_skb", "cgroup_sock",
                              "cgroup_sock_addr", "sock_ops", "syscall"};

struct insn {
    uint8_t code;
    uint8_t regs;
    int16_t off;
    int32_t imm;
};

#define R(dst, src) (uint8_t)((src) << 4 | (dst))
#define MOV64_IMM(d, v) {0xb7, (d), 0, (v)}
#define MOV64_REG(d, s) {0xbf, R(d, s), 0, 0}
#define ADD64_IMM(d, v) {0x07, (d), 0, (v)}
#define AND64_IMM(d, v) {0x57, (d), 0, (v)}
#define LDX_DW(d, s, o) {0x79, R(d, s), (int16_t)(o), 0}
#define LDX_W(d, s, o) {0x61, R(d, s), (int16_t)(o), 0}
#define STX_DW(d, s, o) {0x7b, R(d, s), (int16_t)(o), 0}
#define STX_W(d, s, o) {0x63, R(d, s), (int16_t)(o), 0}
#define ST_W(d, o, v) {0x62, (d), (int16_t)(o), (v)}
#define ST_DW(d, o, v) {0x7a, (d), (int16_t)(o), (v)}
#define LD_IMM64(d, src, lo, hi) {0x18, R(d, src), 0, (int32_t)(lo)}, {0, 0, 0, (int32_t)(hi)}
#define JNE_REG(a, b, o) {0x5d, R(a, b), (o), 0}
#define JNE_IMM(a, v, o) {0x55, (a), (o), (v)}
#define JEQ_IMM(a, v, o) {0x15, (a), (o), (v)}
#define JA(o) {0x05, 0, (o), 0}
#define CALL(h) {0x85, 0, 0, (h)}
#define EXIT() {0x95, 0, 0, 0}

// union bpf_attr for BPF_PROG_LOAD as of 6.18, where signature, signature_size
// and keyring_id were added; written out because the 24.04 headers stop at 6.8.
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
    uint32_t fd_array_cnt;
    uint64_t signature;
    uint32_t signature_size;
    int32_t keyring_id;
};

// The same for BPF_MAP_CREATE, with excl_prog_hash (6.18).
struct map_create {
    uint32_t map_type, key_size, value_size, max_entries, map_flags, inner_map_fd, numa_node;
    char map_name[16];
    uint32_t map_ifindex, btf_fd, btf_key_type_id, btf_value_type_id, btf_vmlinux_value_type_id;
    uint64_t map_extra;
    int32_t value_type_btf_obj_fd, map_token_fd;
    uint64_t excl_prog_hash;
    uint32_t excl_prog_hash_size, pad;
};

struct map_info {
    uint32_t type, id, key_size, value_size, max_entries, map_flags;
    char name[16];
    uint32_t ifindex, btf_vmlinux_value_type_id;
    uint64_t netns_dev, netns_ino;
    uint32_t btf_id, btf_key_type_id, btf_value_type_id, btf_vmlinux_id;
    uint64_t map_extra, hash;
    uint32_t hash_size, pad;
};

// ---- SHA-256 (FIPS 180-4), for the two digests the loader scheme needs ----

static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
    0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
    0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
    0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
    0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2};

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(uint32_t h[8], const uint8_t *p) {
    uint32_t w[64], a[8];
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16 |
               (uint32_t)p[4 * i + 2] << 8 | p[4 * i + 3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    memcpy(a, h, sizeof(a));
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = a[7] + (ROR(a[4], 6) ^ ROR(a[4], 11) ^ ROR(a[4], 25)) +
                      ((a[4] & a[5]) ^ (~a[4] & a[6])) + K256[i] + w[i];
        uint32_t t2 = (ROR(a[0], 2) ^ ROR(a[0], 13) ^ ROR(a[0], 22)) +
                      ((a[0] & a[1]) ^ (a[0] & a[2]) ^ (a[1] & a[2]));
        memmove(a + 1, a, 7 * sizeof(uint32_t));
        a[4] += t1;
        a[0] = t1 + t2;
    }
    for (int i = 0; i < 8; i++) h[i] += a[i];
}

static void sha256(const void *data, size_t len, uint8_t out[32]) {
    uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    const uint8_t *p = data;
    size_t n = len;
    for (; n >= 64; n -= 64, p += 64) sha256_block(h, p);
    uint8_t tail[128] = {0};
    memcpy(tail, p, n);
    tail[n] = 0x80;
    size_t tl = n < 56 ? 64 : 128;
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) tail[tl - 1 - i] = (uint8_t)(bits >> (8 * i));
    for (size_t o = 0; o < tl; o += 64) sha256_block(h, tail + o);
    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 4; j++) out[4 * i + j] = (uint8_t)(h[i] >> (24 - 8 * j));
}

// ---- The metadata the loader carries: one program and its licence ----

struct blob {
    struct insn prog[2];
    char license[8];
};

static const struct blob GOOD = {{MOV64_IMM(0, 0), EXIT()}, "GPL"};
// What a compromised agent would rather have loaded: the same size, another
// program (it returns 1 instead of 0, enough to tell them apart by digest).
static const struct blob SWAPPED = {{MOV64_IMM(0, 1), EXIT()}, "GPL"};

// The loader's context, passed in and read back through BPF_PROG_TEST_RUN.
struct loader_ctx {
    int32_t token_fd;
    int32_t prog_fd;
    int32_t result;
    int32_t pad;
};

#define ATTR_OFF (-(int)sizeof(struct prog_load))
#define LOADER_MAX 128

// The loader: compare the metadata map's hash (struct bpf_map starts with
// it) with the digest in the instructions, then build a BPF_PROG_LOAD attr
// on the stack pointing into the map value and call bpf_sys_bpf.
static unsigned emit_loader(struct insn *out, const struct blob *meta) {
    uint8_t d[32];
    sha256(meta, sizeof(*meta), d);
    unsigned n = 0;
#define E(...)                                                        \
    do {                                                              \
        const struct insn _i[] = {__VA_ARGS__};                       \
        memcpy(out + n, _i, sizeof(_i));                              \
        n += sizeof(_i) / sizeof(*_i);                                \
    } while (0)
    E(MOV64_REG(6, 1));
    for (int i = 0; i < 4; i++) {
        uint64_t w;
        memcpy(&w, d + 8 * i, 8);
        E(LD_IMM64(1, BPF_PSEUDO_MAP_IDX, 0, 0), LDX_DW(2, 1, 8 * i),
          LD_IMM64(3, 0, (uint32_t)w, (uint32_t)(w >> 32)));
        // Jump to the mismatch tail: the remaining checks, the build of the
        // attr and the call come after; patched below once their length is known.
        E(JNE_REG(2, 3, 0));
    }
    unsigned first_jump = 0;
    for (unsigned i = 0; i < n; i++)
        if (out[i].code == 0x5d) { first_jump = i; break; }
    for (int o = ATTR_OFF; o < 0; o += 8) E(ST_DW(10, o, 0));
    E(ST_W(10, ATTR_OFF + offsetof(struct prog_load, prog_type), BPF_PROG_TYPE_SCHED_CLS),
      ST_W(10, ATTR_OFF + offsetof(struct prog_load, insn_cnt), 2),
      LD_IMM64(1, BPF_PSEUDO_MAP_IDX_VALUE, 0, offsetof(struct blob, prog)),
      STX_DW(10, 1, ATTR_OFF + offsetof(struct prog_load, insns)),
      LD_IMM64(1, BPF_PSEUDO_MAP_IDX_VALUE, 0, offsetof(struct blob, license)),
      STX_DW(10, 1, ATTR_OFF + offsetof(struct prog_load, license)),
      ST_W(10, ATTR_OFF + offsetof(struct prog_load, prog_flags), (int32_t)BPF_F_TOKEN_FD),
      LDX_W(1, 6, offsetof(struct loader_ctx, token_fd)),
      STX_W(10, 1, ATTR_OFF + offsetof(struct prog_load, prog_token_fd)),
      MOV64_IMM(1, BPF_PROG_LOAD), MOV64_REG(2, 10), ADD64_IMM(2, ATTR_OFF),
      MOV64_IMM(3, offsetof(struct prog_load, prog_token_fd) + 4), CALL(FUNC_SYS_BPF),
      STX_W(6, 0, offsetof(struct loader_ctx, prog_fd)),
      ST_W(6, offsetof(struct loader_ctx, result), 0), MOV64_IMM(0, 0), EXIT());
    unsigned mismatch = n;
    E(ST_W(6, offsetof(struct loader_ctx, result), -EINVAL), MOV64_IMM(0, 0), EXIT());
    for (unsigned i = first_jump; i < mismatch; i++)
        if (out[i].code == 0x5d) out[i].off = (int16_t)(mismatch - i - 1);
#undef E
    return n;
}

// ---- Plumbing ----

static long bpf(int cmd, void *attr, unsigned size) { return syscall(SYS_bpf, cmd, attr, size); }

static char log_buf[1 << 16];

static void report(const char *what, long r) {
    if (r >= 0) {
        printf("%s: ok\n", what);
    } else {
        int e = errno;
        for (char *p = log_buf; *p; p++)
            if (*p == '\n') *p = ' ';
        printf("%s: refused %s%s%s\n", what, strerrorname_np(e), log_buf[0] ? " | verifier: " : "",
               log_buf);
    }
    log_buf[0] = 0;
}

// Reads a whole file; sysfs files report a size that is not their length.
static void *slurp(const char *path, uint32_t *len) {
    int f = open(path, O_RDONLY);
    if (f < 0) { perror(path); exit(2); }
    size_t cap = 1 << 16, n = 0;
    uint8_t *b = malloc(cap);
    for (ssize_t r; b && (r = read(f, b + n, cap - n)) != 0; n += (size_t)r) {
        if (r < 0) { perror(path); exit(2); }
        if (n + (size_t)r == cap) b = realloc(b, cap *= 2);
    }
    if (!b) { perror("malloc"); exit(2); }
    close(f);
    *len = (uint32_t)n;
    return b;
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

static int32_t add_key(const char *type, const char *desc, const void *p, size_t n, int32_t ring) {
    return (int32_t)syscall(SYS_add_key, type, desc, p, n, ring);
}

// A keyring holding one certificate. `others` 0x0b is view, read and search
// for everyone else: the agent can verify against it, never add to it.
static int32_t keyring_with(const char *name, const char *cert, int32_t parent, int lock) {
    int32_t ring = add_key("keyring", name, NULL, 0, parent);
    if (ring < 0) { perror("add_key keyring"); exit(2); }
    uint32_t len;
    void *der = slurp(cert, &len);
    int32_t key = add_key("asymmetric", name, der, len, ring);
    if (key < 0) { perror("add_key asymmetric"); exit(2); }
    if (lock) {
        // possessor all, owner view+read+search, others view+read+search.
        uint32_t perm = 0x3f000000 | 0x000b0000 | 0x0000000b;
        if (syscall(SYS_keyctl, KEYCTL_SETPERM, ring, perm) ||
            syscall(SYS_keyctl, KEYCTL_SETPERM, key, perm)) {
            perror("keyctl setperm");
            exit(2);
        }
    }
    return ring;
}

// ---- The agent's side ----

static int token_fd;
static uint8_t loader_digest[32];

static int create_meta(const char *what, int exclusive) {
    struct map_create a = {0};
    a.map_type = BPF_MAP_TYPE_ARRAY;
    a.key_size = 4;
    a.value_size = sizeof(struct blob);
    a.max_entries = 1;
    a.map_flags = BPF_F_TOKEN_FD;
    a.map_token_fd = token_fd;
    if (exclusive) {
        a.excl_prog_hash = (uintptr_t)loader_digest;
        a.excl_prog_hash_size = 32;
    }
    int fd = (int)bpf(BPF_MAP_CREATE, &a, sizeof(a));
    if (what) report(what, fd);
    if (fd < 0 && !what) { perror("map create"); exit(2); }
    return fd;
}

static long put(int map, const struct blob *b) {
    uint32_t k = 0;
    struct { uint32_t fd, pad; uint64_t key, value, flags; } a = {(uint32_t)map, 0, (uintptr_t)&k,
                                                                    (uintptr_t)b, 0};
    return bpf(BPF_MAP_UPDATE_ELEM, &a, sizeof(a));
}

static long freeze(int map) {
    uint32_t a[2] = {(uint32_t)map, 0};
    return bpf(BPF_MAP_FREEZE, a, sizeof(a));
}

// Asks the kernel to hash the map's value; the hash lands in struct bpf_map,
// where the loader reads it.
static long hash_map(int map) {
    uint8_t h[32];
    struct map_info info = {0};
    info.hash = (uintptr_t)h;
    info.hash_size = 32;
    struct { uint32_t fd, len; uint64_t info; } a = {(uint32_t)map, sizeof(info), (uintptr_t)&info};
    return bpf(BPF_OBJ_GET_INFO_BY_FD, &a, sizeof(a));
}

static struct insn loader[LOADER_MAX];
static unsigned loader_n;

static int load_loader(const char *what, int map, const void *sig, uint32_t sig_len, int32_t ring) {
    int fds[1] = {map};
    struct prog_load a = {0};
    a.prog_type = BPF_PROG_TYPE_SYSCALL;
    a.insns = (uintptr_t)loader;
    a.insn_cnt = loader_n;
    a.license = (uintptr_t)"GPL";
    a.log_level = 1;
    a.log_size = sizeof(log_buf);
    a.log_buf = (uintptr_t)log_buf;
    a.prog_flags = BPF_F_TOKEN_FD | BPF_F_SLEEPABLE;
    a.prog_token_fd = token_fd;
    a.fd_array = (uintptr_t)fds;
    a.signature = (uintptr_t)sig;
    a.signature_size = sig_len;
    a.keyring_id = ring;
    int fd = (int)bpf(BPF_PROG_LOAD, &a, sizeof(a));
    if (fd >= 0) log_buf[0] = 0;
    report(what, fd);
    return fd;
}

static long ret_of(int prog) {
    struct { uint32_t prog_fd, retval, data_size_in, data_size_out; uint64_t data_in, data_out;
             uint32_t repeat, duration, ctx_size_in, ctx_size_out; uint64_t ctx_in, ctx_out;
             uint32_t flags, cpu, batch_size, pad; } a = {0};
    uint8_t pkt[64] = {0};
    a.prog_fd = (uint32_t)prog;
    a.data_in = (uintptr_t)pkt;
    a.data_size_in = sizeof(pkt);
    if (bpf(BPF_PROG_TEST_RUN, &a, sizeof(a))) return -errno;
    return a.retval;
}

// Runs the loader; prints what it loaded, telling GOOD from SWAPPED by the
// return value of the program it produced.
static void run_loader(const char *what, int prog) {
    if (prog < 0) {
        printf("%s: not tried, the loader was refused\n", what);
        return;
    }
    struct loader_ctx ctx = {token_fd, -1, 1, 0};
    struct { uint32_t prog_fd, retval, data_size_in, data_size_out; uint64_t data_in, data_out;
             uint32_t repeat, duration, ctx_size_in, ctx_size_out; uint64_t ctx_in, ctx_out;
             uint32_t flags, cpu, batch_size, pad; } a = {0};
    a.prog_fd = (uint32_t)prog;
    a.ctx_in = (uintptr_t)&ctx;
    a.ctx_size_in = sizeof(ctx);
    if (bpf(BPF_PROG_TEST_RUN, &a, sizeof(a))) {
        printf("%s: run refused %s\n", what, strerrorname_np(errno));
        return;
    }
    if (ctx.result == -EINVAL) {
        printf("%s: the loader refused, the map's hash is not the one it was signed with\n", what);
    } else if (ctx.prog_fd < 0) {
        printf("%s: the inner load was refused %s\n", what, strerrorname_np(-ctx.prog_fd));
    } else {
        long r = ret_of(ctx.prog_fd);
        printf("%s: loaded the %s program\n", what,
               r == 0 ? "signed" : r == 1 ? "swapped" : "unexpected");
        close(ctx.prog_fd);
    }
}

static void drop_perfmon(void) {
    struct { uint32_t version; int pid; } hdr = {0x20080522, 0};
    struct { uint32_t effective, permitted, inheritable; } data[2];
    if (syscall(SYS_capget, &hdr, data)) { perror("capget"); exit(2); }
    data[0].effective &= ~(1U << 21);        // CAP_SYS_ADMIN
    data[1].effective &= ~(1U << (38 - 32)); // CAP_PERFMON
    if (syscall(SYS_capset, &hdr, data)) { perror("capset"); exit(2); }
}

static int32_t trusted_ring;

static void agent(int sock) {
    if (setgroups(0, NULL) || setresgid(65534, 65534, 65534) || setresuid(65534, 65534, 65534)) {
        perror("drop to nobody");
        exit(2);
    }
    // A session keyring of its own, so the warden's keyring is reached by
    // its serial and its permissions, never possessed.
    if (syscall(SYS_keyctl, KEYCTL_JOIN_SESSION_KEYRING, NULL) < 0) { perror("join session"); exit(2); }
    if (unshare(CLONE_NEWUSER | CLONE_NEWNS) != 0) { perror("unshare"); exit(2); }
    sync_byte(sock, 1);
    sync_byte(sock, 0);
    int fs = (int)syscall(SYS_fsopen, "bpf", 0);
    if (fs < 0) { perror("fsopen bpf"); exit(2); }
    send_fd(sock, fs);
    sync_byte(sock, 0);
    int mnt = (int)syscall(SYS_fsmount, fs, 0, 0);
    if (mnt < 0) { perror("fsmount"); exit(2); }
    int root = openat(mnt, ".", O_RDONLY | O_DIRECTORY);
    uint32_t tattr[2] = {0, (uint32_t)root};
    token_fd = (int)bpf(BPF_TOKEN_CREATE, tattr, sizeof(tattr));
    if (token_fd < 0) { perror("BPF_TOKEN_CREATE"); exit(2); }

    uint32_t tsig_len, rsig_len;
    uint8_t *tsig = slurp("loader.trusted.sig", &tsig_len);
    void *rsig = slurp("loader.rogue.sig", &rsig_len);
    int32_t rogue_ring = keyring_with("rogue", "rogue.der", KEY_SPEC_SESSION_KEYRING, 0);
    printf("token: ok; warden keyring %d, agent's own keyring %d\n", trusted_ring, rogue_ring);

    // The metadata map, as the build's loader expects it: exclusive to the
    // loader's digest, filled, frozen, hashed.
    int meta = create_meta("metadata map created exclusive to the loader's digest", 1);
    report("metadata map filled", put(meta, &GOOD));
    report("metadata map frozen", freeze(meta));
    report("metadata map hashed", hash_map(meta));
    report("metadata map written after freeze", put(meta, &SWAPPED));

    // Exclusivity: any other program naming the map is refused at load.
    {
        const struct insn other[] = {LD_IMM64(1, BPF_PSEUDO_MAP_IDX, 0, 0), MOV64_IMM(0, 0), EXIT()};
        int fds[1] = {meta};
        struct prog_load a = {0};
        a.prog_type = BPF_PROG_TYPE_SCHED_CLS;
        a.insns = (uintptr_t)other;
        a.insn_cnt = sizeof(other) / sizeof(*other);
        a.license = (uintptr_t)"GPL";
        a.log_level = 1;
        a.log_size = sizeof(log_buf);
        a.log_buf = (uintptr_t)log_buf;
        a.prog_flags = BPF_F_TOKEN_FD;
        a.prog_token_fd = token_fd;
        a.fd_array = (uintptr_t)fds;
        int p = (int)bpf(BPF_PROG_LOAD, &a, sizeof(a));
        report("another program naming the exclusive map", p);
        if (p >= 0) close(p);
    }

    int p = load_loader("unsigned loader, keyring named", meta, NULL, 0, trusted_ring);
    run_loader("unsigned loader run", p);
    if (p >= 0) close(p);

    p = load_loader("loader signed by the warden's key, warden keyring", meta, tsig, tsig_len,
                    trusted_ring);
    run_loader("signed loader run", p);
    if (p >= 0) close(p);

    tsig[tsig_len - 1] ^= 1;
    p = load_loader("loader with a corrupted signature, warden keyring", meta, tsig, tsig_len,
                    trusted_ring);
    tsig[tsig_len - 1] ^= 1;
    if (p >= 0) close(p);

    p = load_loader("loader signed by a key of the agent's own, agent's keyring", meta, rsig,
                    rsig_len, rogue_ring);
    if (p >= 0) close(p);

    p = load_loader("loader signed by a key of the agent's own, warden keyring", meta, rsig,
                    rsig_len, trusted_ring);
    if (p >= 0) close(p);

    // The map's hash is computed when asked, not at freeze. A map hashed,
    // then rewritten before the run, is what the next two facts ask about.
    int m2 = create_meta(NULL, 1);
    put(m2, &GOOD);
    report("unfrozen metadata map hashed", hash_map(m2));
    report("unfrozen metadata map rewritten after hashing", put(m2, &SWAPPED));
    p = load_loader("signed loader over the unfrozen map", m2, tsig, tsig_len, trusted_ring);
    run_loader("signed loader run over a map rewritten after hashing", p);
    if (p >= 0) close(p);
    close(m2);

    int m3 = create_meta(NULL, 1);
    put(m3, &SWAPPED);
    freeze(m3);
    hash_map(m3);
    p = load_loader("signed loader over a map holding another program", m3, tsig, tsig_len,
                    trusted_ring);
    run_loader("signed loader run over a map holding another program", p);
    if (p >= 0) close(p);
    close(m3);

    int m4 = create_meta(NULL, 1);
    put(m4, &GOOD);
    freeze(m4);
    p = load_loader("signed loader over a map never hashed", m4, tsig, tsig_len, trusted_ring);
    run_loader("signed loader run over a map never hashed", p);
    if (p >= 0) close(p);
    close(m4);

    // Without CAP_PERFMON in the namespace (the datapath's posture on a
    // kernel that does not verify signatures).
    drop_perfmon();
    p = load_loader("signed loader, CAP_PERFMON and CAP_SYS_ADMIN dropped", meta, tsig, tsig_len,
                    trusted_ring);
    if (p >= 0) close(p);

    // An unsigned datapath program loaded directly.
    const struct insn ret0[] = {MOV64_IMM(0, 0), EXIT()};
    struct prog_load a = {0};
    a.prog_type = BPF_PROG_TYPE_SCHED_CLS;
    a.insns = (uintptr_t)ret0;
    a.insn_cnt = 2;
    a.license = (uintptr_t)"GPL";
    a.prog_flags = BPF_F_TOKEN_FD;
    a.prog_token_fd = token_fd;
    p = (int)bpf(BPF_PROG_LOAD, &a, sizeof(a));
    report("unsigned sched_cls program loaded directly", p);
    fflush(stdout);
    exit(0);
}

// ---- The warden's side ----

static void delegate(int fs) {
    if (syscall(SYS_fsconfig, fs, FSCONFIG_SET_STRING, "delegate_cmds", "any", 0) ||
        syscall(SYS_fsconfig, fs, FSCONFIG_SET_STRING, "delegate_maps", "any", 0)) {
        perror("fsconfig");
        exit(2);
    }
    for (size_t i = 0; i < sizeof(PROGS) / sizeof(*PROGS); i++)
        if (syscall(SYS_fsconfig, fs, FSCONFIG_SET_STRING, "delegate_progs", PROGS[i], 0)) {
            perror(PROGS[i]);
            exit(2);
        }
    if (syscall(SYS_fsconfig, fs, FSCONFIG_SET_STRING, "delegate_attachs", "any", 0) ||
        syscall(SYS_fsconfig, fs, FSCONFIG_CMD_CREATE, NULL, NULL, 0)) {
        perror("fsconfig create");
        exit(2);
    }
}

// The BTF id of a kernel function, read off /sys/kernel/btf/vmlinux.
static uint32_t btf_func_id(const char *name) {
    uint32_t len;
    uint8_t *b = slurp("/sys/kernel/btf/vmlinux", &len);
    uint32_t hdr_len, type_off, type_len, str_off;
    memcpy(&hdr_len, b + 4, 4);
    memcpy(&type_off, b + 8, 4);
    memcpy(&type_len, b + 12, 4);
    memcpy(&str_off, b + 16, 4);
    const uint8_t *t = b + hdr_len + type_off, *end = t + type_len;
    const char *strs = (const char *)b + hdr_len + str_off;
    for (uint32_t id = 1; t < end; id++) {
        uint32_t name_off, info;
        memcpy(&name_off, t, 4);
        memcpy(&info, t + 4, 4);
        uint32_t kind = (info >> 24) & 0x1f, vlen = info & 0xffff;
        if (kind == 12 && !strcmp(strs + name_off, name)) return id;
        t += 12;
        switch (kind) {
        case 1: case 14: case 17: t += 4; break;
        case 3: t += 12; break;
        case 4: case 5: case 15: case 19: t += 12 * vlen; break;
        case 6: case 13: t += 8 * vlen; break;
        default: break;
        }
    }
    fprintf(stderr, "%s not in vmlinux BTF\n", name);
    exit(2);
}

// On bpf_prog_load(prog, attr, token, kernel): a load the caller asked for
// through a token is refused unless it carries a signature checked against
// the warden's keyring. A load made by a running loader (kernel) passes: only
// a signed loader can be running.
static int load_guard(int32_t ring) {
    const struct insn g[] = {
        MOV64_REG(6, 1),
        LDX_DW(7, 6, 24), AND64_IMM(7, 0xff), JNE_IMM(7, 0, 8),            // kernel: allow
        LDX_DW(2, 6, 8),                                                    // attr
        LDX_W(3, 2, offsetof(struct prog_load, prog_flags)),
        AND64_IMM(3, (int32_t)BPF_F_TOKEN_FD), JEQ_IMM(3, 0, 4),            // no token: allow
        LDX_DW(3, 2, offsetof(struct prog_load, signature)), JEQ_IMM(3, 0, 4), // unsigned: deny
        LDX_W(3, 2, offsetof(struct prog_load, keyring_id)), JNE_IMM(3, ring, 2), // other keyring: deny
        MOV64_IMM(0, 0), EXIT(),                                            // allow
        MOV64_IMM(0, -EPERM), EXIT(),                                       // deny
    };
    struct prog_load a = {0};
    a.prog_type = BPF_PROG_TYPE_LSM;
    a.expected_attach_type = BPF_LSM_MAC;
    a.attach_btf_id = btf_func_id("bpf_lsm_bpf_prog_load");
    a.insns = (uintptr_t)g;
    a.insn_cnt = sizeof(g) / sizeof(*g);
    a.license = (uintptr_t)"GPL";
    a.log_level = 1;
    a.log_size = sizeof(log_buf);
    a.log_buf = (uintptr_t)log_buf;
    int p = (int)bpf(BPF_PROG_LOAD, &a, offsetof(struct prog_load, prog_token_fd));
    report("guard on bpf_prog_load loaded by the warden", p);
    if (p < 0) exit(2);
    struct { uint32_t prog_fd, target_fd, attach_type, flags; uint8_t rest[48]; } l = {0};
    l.prog_fd = (uint32_t)p;
    l.attach_type = BPF_LSM_MAC;
    int link = (int)bpf(BPF_LINK_CREATE, &l, sizeof(l));
    report("guard attached", link);
    if (link < 0) exit(2);
    return link;
}

int main(int argc, char **argv) {
    loader_n = emit_loader(loader, &GOOD);
    sha256(loader, loader_n * sizeof(struct insn), loader_digest);
    if (argc > 1 && !strcmp(argv[1], "emit")) {
        fwrite(loader, sizeof(struct insn), loader_n, stdout);
        return 0;
    }
    if (getuid() != 0) { fprintf(stderr, "run as root: the parent delegates\n"); return 2; }
    int guard = argc > 1 && !strcmp(argv[1], "guard");
    // The warden's keyring lives in the warden's session keyring; the agent
    // reaches it by serial, with search permission only.
    trusted_ring = keyring_with("ebpfsentinel-loaders", "trusted.der", KEY_SPEC_SESSION_KEYRING, 1);
    int link = guard ? load_guard(trusted_ring) : -1;
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
    if (link >= 0) close(link);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 2;
}
