# What a kernel that verifies BPF program signatures does with a signed loader, kernel 6.18, 2026-11-23

The question before the build signs what the agent loads: on a kernel that checks
a signature on `BPF_PROG_LOAD`, which loads does the signature stop, what does a
BPF LSM program on the load hook see, and does a load made through the agent's
BPF token take the signature path? The answers below were read off the running
kernel, not off its sources.

## How

- Kernel: `6.18.64-061864-generic`, the kernel.ubuntu.com mainline build the kernel
  matrix resolves for 6.18 (`scripts/check-kernel-matrix.py --resolve 6.18`), on the
  VMware agent VM (`AGENT_KERNEL=6.18.64`, provisioners `kernel-mainline` and
  `bpf-token-userns` only). First run with
  `lsm=lockdown,capability,landlock,yama,apparmor,ima,evm` (no `bpf`), second run
  after a reboot with `lsm=lockdown,capability,landlock,yama,apparmor,bpf`
  (`/sys/kernel/security/lsm` then reads `...,apparmor,bpf,ima,evm`).
- Program: `scripts/sign-facts.c`, built on the host with
  `cc -O2 -Wall -Wextra -static -o sign-facts scripts/sign-facts.c`. The loader's
  instructions are deterministic, so `./sign-facts emit` wrote them on the host
  and `openssl cms -sign -binary -noattr -nocerts -md sha256 -outform DER` signed
  them twice, with two RSA 2048 self-signed certificates, `trusted` and `rogue`
  (commands in the header of the program). Run as `sudo ./sign-facts` and
  `sudo ./sign-facts guard`.
- The parent, root, plays the warden: it creates a keyring holding the `trusted`
  certificate (an `asymmetric` key) in its own session keyring, sets both to
  view, read and search for everyone else, writes the child's id maps and applies
  the delegation to the bpffs the child opened. Delegated program types: `xdp`,
  `sched_cls`, `cgroup_skb`, `cgroup_sock`, `cgroup_sock_addr`, `sock_ops`,
  `syscall` (no kprobe, lsm or raw_tracepoint); commands, maps and attach types
  `any`. With `guard` it also loads and attaches, before the child starts, a BPF
  LSM program on `bpf_prog_load` that allows a load made by a running program
  (`kernel` set) and a load passing no token, and otherwise returns `-EPERM`
  unless `signature` is set and `keyring_id` is the warden's keyring.
- The child plays the agent: it drops to uid and gid 65534, joins a new session
  keyring, unshares a user and a mount namespace, mounts the delegated bpffs and
  creates the token. It then creates a keyring of its own holding the `rogue`
  certificate. Every load passes `BPF_F_TOKEN_FD`.
- The loader has the shape the build would emit for an object: a sleepable
  program of type `syscall` naming one metadata map (an array, one entry, the
  inner program's instructions and licence), which compares the map's hash (the
  first 32 bytes of `struct bpf_map`, filled by the kernel on
  `BPF_OBJ_GET_INFO_BY_FD` with `info.hash`) with the digest written in its own
  instructions, then builds a `BPF_PROG_LOAD` attr on its stack pointing into the
  map value, with the token read from its context, and calls `bpf_sys_bpf`. It is
  run with `BPF_PROG_TEST_RUN`; the inner program returns 0, the swapped one 1,
  so the program loaded is told by its return value. The metadata map is created
  with `excl_prog_hash` set to the loader's digest.

## Answers

| fact | no BPF LSM | BPF LSM guard |
|---|---|---|
| metadata map created exclusive to the loader's digest, through the token | ok | ok |
| metadata map frozen, then hashed | ok | ok |
| metadata map written after freeze | refused `EPERM` | refused `EPERM` |
| metadata map hashed before freeze | refused `EPERM` | refused `EPERM` |
| another program naming the exclusive map | refused `EACCES`: "program's hash doesn't match map's excl_prog_hash" | refused `EPERM` (the guard, before the verifier) |
| unsigned loader, warden keyring named | **ok** | refused `EPERM` |
| loader signed by the warden's key, warden keyring | ok | ok |
| that loader run: inner load through the token | loads the signed program | loads the signed program (the guard sees `kernel` set) |
| signed loader, last signature byte flipped | refused `EKEYREJECTED` | refused `EKEYREJECTED` |
| loader signed by the agent's own key, agent's own keyring | **ok** | refused `EPERM` |
| loader signed by the agent's own key, warden keyring | refused `ENOKEY` | refused `ENOKEY` |
| signed loader over a map holding another program, run | the loader refuses: hash mismatch | same |
| signed loader over a map never hashed, run | the loader refuses: hash mismatch | same |
| signed loader with `CAP_PERFMON` and `CAP_SYS_ADMIN` dropped in the namespace | refused `EPERM`: "'struct bpf_array' access is allowed only to CAP_PERFMON and CAP_SYS_ADMIN" | same |
| unsigned `sched_cls` program loaded directly through the token | **ok** | refused `EPERM` |

## What follows

- **Without the BPF LSM a signature stops nothing.** The kernel checks a signature
  only when one is passed; a load without one, or with one against a keyring the
  caller made, loads. A corrupted signature or a key absent from the named keyring
  is refused, so the check itself holds; nothing asks for it.
- **The keyring must be pinned by the guard.** Any caller can create a keyring,
  put its own certificate in it and sign its own loader: the kernel accepts it.
  The guard compares `keyring_id` with the warden's keyring serial, which the
  warden writes into the guard when it loads it.
- **A token-delegated load takes the signature path**, and the LSM program sees
  `attr->signature` and `attr->keyring_id` on `bpf_prog_load` before the program
  is created; the verdict is the guard's, the kernel stores no "signed" flag on
  the program.
- **Loads made from inside a running loader pass the guard on `kernel`**, and only
  a signed loader can be running, so the inner datapath programs need no
  signature of their own. The loader's metadata check is what ties them to the
  build: a map holding another program, or a map never hashed, makes the loader
  refuse. The map can only be hashed once frozen, and frozen it cannot be
  rewritten, so there is no window between hash and run.
- **The signed loader needs `CAP_PERFMON` in the token's namespace**: reading the
  map's hash out of `struct bpf_map` is a pointer access the verifier keeps behind
  it (and, by the 6.18 sources, `bpf_sys_bpf` is offered to `syscall` programs
  only with it, `syscall_prog_func_proto` in `kernel/bpf/syscall.c`). Where the
  guard is attached, the agent keeps `CAP_PERFMON`, since every program it loads
  then comes out of a signed loader; where it is not (a kernel below 6.18, or no
  `bpf` in `lsm=`), the agent drops `CAP_PERFMON` and `CAP_SYS_ADMIN` before its
  first load and loads unsigned, as the 6.12 record found it must.
- **Exclusivity holds without the guard**: a program other than the loader naming
  the metadata map is refused at load, so the map's content reaches only the
  program it was signed for.
