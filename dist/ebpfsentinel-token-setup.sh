#!/usr/bin/env bash
#
# ebpfsentinel-token-setup.sh — Prepare a delegated bpffs mount for
# BPF token-based eBPF loading.
#
# Kernel 6.9 introduced `BPF_TOKEN_CREATE`, which lets a privileged
# process create a token fd scoped to a specific set of BPF commands,
# map types, program types, and attach types. When the agent uses a
# token, it can load all of its eBPF programs without holding
# `CAP_BPF` / `CAP_NET_ADMIN` on the running process — the bpffs
# mount replaces those capabilities.
#
# This script mounts a bpffs instance with the delegation options
# required by the 14 eBPF programs eBPFsentinel ships. It is
# idempotent: running it twice has no effect past the first mount.
#
# Usage:
#   sudo ./ebpfsentinel-token-setup.sh [BPFFS_PATH]
#
# Defaults:
#   BPFFS_PATH = /sys/fs/bpf/ebpfsentinel
#
# Verify:
#   mount | grep ebpfsentinel
#   findmnt -T /sys/fs/bpf/ebpfsentinel -o OPTIONS

set -euo pipefail

BPFFS_PATH="${1:-/sys/fs/bpf/ebpfsentinel}"

# ── Preflight checks ──────────────────────────────────────────────

if [[ $EUID -ne 0 ]]; then
  echo "Error: must run as root (bpffs mounts require CAP_SYS_ADMIN)." >&2
  exit 1
fi

KERNEL_VERSION=$(uname -r | cut -d. -f1-2)
KERNEL_MAJOR=$(echo "$KERNEL_VERSION" | cut -d. -f1)
KERNEL_MINOR=$(echo "$KERNEL_VERSION" | cut -d. -f2)
if [[ "$KERNEL_MAJOR" -lt 6 ]] || { [[ "$KERNEL_MAJOR" -eq 6 ]] && [[ "$KERNEL_MINOR" -lt 9 ]]; }; then
  echo "Error: kernel >= 6.9 is required for BPF token delegation (found $(uname -r))." >&2
  exit 1
fi

if [[ ! -d /sys/fs/bpf ]]; then
  echo "Error: /sys/fs/bpf does not exist — is bpffs enabled in your kernel?" >&2
  exit 1
fi

# ── Delegated mount options ───────────────────────────────────────
#
# `delegate_cmds` — BPF commands the consumer can invoke with the
# token. We allow MAP_CREATE, PROG_LOAD, OBJ_GET_INFO_BY_FD, BTF_LOAD.
#
# `delegate_maps` — map types the consumer can create. We allow the
# types used across the 14 eBPF programs: HASH, PERCPU_HASH, ARRAY,
# PERCPU_ARRAY, LPM_TRIE, LRU_HASH, LRU_PERCPU_HASH, RINGBUF,
# USER_RINGBUF, BLOOM_FILTER, CPUMAP, DEVMAP, PROG_ARRAY.
#
# `delegate_progs` — program types: XDP, SCHED_CLS, KPROBE, PERF_EVENT.
#
# `delegate_attachs` — attach types: XDP, TCX_INGRESS/EGRESS, UPROBE.
#
# The kernel accepts both numeric bitmasks and the string keywords
# `any` / list. We use `any` for the lists the agent exercises fully;
# operators can narrow these to exact numbers if they prefer.

DELEGATE_CMDS="map_create,prog_load,obj_get_info_by_fd,btf_load"
DELEGATE_MAPS="any"
DELEGATE_PROGS="any"
DELEGATE_ATTACHS="any"

# ── Mount ─────────────────────────────────────────────────────────

if mountpoint -q "$BPFFS_PATH"; then
  echo "bpffs already mounted at $BPFFS_PATH — verifying delegation options..."
  OPTS=$(findmnt -T "$BPFFS_PATH" -n -o OPTIONS)
  if echo "$OPTS" | grep -q "delegate_cmds"; then
    echo "  delegation options present: $OPTS"
    echo "Setup complete."
    exit 0
  fi
  echo "Error: $BPFFS_PATH is a bpffs mount but lacks delegate_* options." >&2
  echo "       Unmount it first: umount $BPFFS_PATH" >&2
  exit 1
fi

mkdir -p "$BPFFS_PATH"

echo "Mounting delegated bpffs at $BPFFS_PATH..."
mount -t bpf bpf_delegated "$BPFFS_PATH" \
  -o "delegate_cmds=${DELEGATE_CMDS},delegate_maps=${DELEGATE_MAPS},delegate_progs=${DELEGATE_PROGS},delegate_attachs=${DELEGATE_ATTACHS}"

# ── Permissions ───────────────────────────────────────────────────
#
# The agent process only needs read access on the mount root to open
# it via O_PATH for BPF_TOKEN_CREATE. Group ownership lets operators
# delegate to a non-root service account.

EBPFSENTINEL_GROUP="${EBPFSENTINEL_GROUP:-ebpfsentinel}"
if getent group "$EBPFSENTINEL_GROUP" > /dev/null; then
  chgrp "$EBPFSENTINEL_GROUP" "$BPFFS_PATH"
  chmod 750 "$BPFFS_PATH"
  echo "Set ownership to root:$EBPFSENTINEL_GROUP with 750 permissions"
else
  chmod 700 "$BPFFS_PATH"
  echo "Group '$EBPFSENTINEL_GROUP' not found — kept root-only permissions (700)"
fi

# ── Verify ────────────────────────────────────────────────────────

echo ""
echo "Verification:"
mount | grep "$BPFFS_PATH" || true
findmnt -T "$BPFFS_PATH" -o OPTIONS || true

echo ""
echo "Setup complete. Point agent config at the mount:"
echo ""
echo "  agent:"
echo "    bpf_token:"
echo "      enabled: true"
echo "      bpffs_path: $BPFFS_PATH"
echo ""
echo "Then start the agent. If BPF_TOKEN_CREATE succeeds, the"
echo "Prometheus gauge ebpfsentinel_bpf_token_used will show"
echo "mode=\"token\" / value=2."
