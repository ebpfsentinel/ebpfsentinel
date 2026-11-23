# What a BPF token lets the agent do, kernel 6.12, 2026-11-23

The question before the token is cut down to the datapath: from the agent's user
namespace, holding only a token delegated the way the warden delegates it, which
programs that read or steer the kernel load and attach on the floor kernel? The
answers below were read off the running kernel, not off its sources.

## How

- Kernel: `6.12.118-0612118-generic`, the kernel.ubuntu.com mainline build the
  kernel matrix resolves for 6.12 (`scripts/check-kernel-matrix.py --resolve 6.12`),
  on the VMware agent VM (`AGENT_KERNEL=6.12.118`, provisioners `kernel-mainline`
  and `bpf-token-userns` only). `lsm=lockdown,capability,landlock,yama,apparmor,ima,evm`
  (no `bpf`), lockdown `none`. `CONFIG_BPF_KPROBE_OVERRIDE=y`,
  `CONFIG_FUNCTION_ERROR_INJECTION=y`, `CONFIG_FPROBE=y`.
- Program: `scripts/token-facts.c`, built on the host with
  `cc -O2 -Wall -Wextra -static -o token-facts scripts/token-facts.c`, uploaded, run
  as `sudo ./token-facts` and `sudo ./token-facts narrow`.
- The parent, root, plays the warden: it writes the child's id maps and applies the
  delegation options to the bpffs the child opened, with the program and attach
  lists of `DELEGATED_PROGS` and `DELEGATED_ATTACHS` in `crates/warden/src/lib.rs`
  (commands and map types `any`). The child plays the agent: it drops to uid and
  gid 65534 on the host, unshares a user and a mount namespace (uid 0 inside,
  mapped to 65534), mounts the delegated bpffs, opens its root and creates the
  token. Every load passes `BPF_F_TOKEN_FD`.
- `narrow` leaves out of the delegation the types that read or steer the kernel:
  programs `kprobe`, `lsm`, `raw_tracepoint`; attaches `trace_kprobe_multi`,
  `trace_kprobe_session`, `lsm_mac`.
- Attaches are made on `__x64_sys_getppid` (kprobe_multi) and `__x64_sys_vhangup`
  (override, a syscall on the error-injection list) and the link is closed at once.
  `bpf_send_signal` and `bpf_probe_read_kernel` are loaded, never attached.

## Answers

| fact | delegated as today | `narrow` |
|---|---|---|
| token created from the user namespace | ok | ok |
| kprobe_multi program load | ok | refused `EPERM` |
| kprobe_multi attach (`BPF_LINK_CREATE`, no token on the call) | ok | not reached |
| `bpf_probe_write_user` load | refused `EINVAL`: "program of this type cannot use helper bpf_probe_write_user#36" | refused `EPERM` |
| `bpf_override_return` load | ok | refused `EPERM` |
| `bpf_override_return` attach on an error-injectable syscall | ok | not reached |
| `bpf_probe_read_kernel` from a kprobe | ok | refused `EPERM` |
| `bpf_send_signal` from a kprobe | ok | refused `EPERM` |
| `bpf_probe_read_kernel` from a `sched_cls` program | **ok** | **ok** |
| same, `CAP_PERFMON` and `CAP_SYS_ADMIN` dropped from the effective set in the namespace | refused `EINVAL`: "program of this type cannot use helper bpf_probe_read_kernel#113" | same |
| plain `sched_cls` program, the same two capabilities dropped | ok | ok |

## What follows

- **Today a taken-over agent reaches the kernel through its token.** It can attach
  a kprobe_multi program to any function, make an error-injectable syscall fail
  for every process on the host (`bpf_override_return`), kill whatever task
  enters a probed function, root's included (`bpf_send_signal`), and read any
  kernel address. The one refusal is `bpf_probe_write_user`, which the kernel
  keeps behind `CAP_SYS_ADMIN` in the initial namespace whatever the token says.
- **Cutting `kprobe`, `lsm`, `raw_tracepoint` and the three attach types closes the
  kprobe path** with `EPERM` at load, before any attach, so the brokered attach of
  the next step is the only way a kprobe or LSM program reaches the kernel.
- **Cutting the types is not enough.** `bpf_probe_read_kernel` is a base helper,
  offered to every program type, datapath ones included, wherever the loader holds
  `CAP_PERFMON` (or `CAP_SYS_ADMIN`) in the token's namespace, and the agent is
  root there. The capability is read off the loader's credentials at load, so the
  agent drops `CAP_PERFMON` and `CAP_SYS_ADMIN` from its effective set before it
  loads its datapath: the helper is then refused at verification and a plain
  `sched_cls` program still loads. Whether every datapath object loads without
  them (they also grant pointer comparisons and the Spectre mitigation bypasses)
  is proved on the full object set in the step that cuts the token.
