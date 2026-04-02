#!/bin/sh
# ebpfsentinel-token-setup.sh — Create a delegated bpffs mount for BPF token support.
#
# This script creates a bpffs mount with delegation flags that allow
# the eBPFsentinel agent to load all its eBPF programs (XDP, TC, uprobe,
# kprobe) without any Linux capabilities. Requires kernel 6.9+.
#
# Usage:
#   ebpfsentinel-token-setup.sh [MOUNT_PATH]
#
# The mount is idempotent: running it multiple times is safe.
# The agent auto-detects the token at startup.

set -eu

MOUNT_PATH="${1:-/sys/fs/bpf/ebpfsentinel}"

# Check kernel version
KVER=$(uname -r | cut -d. -f1-2)
KMAJOR=$(echo "$KVER" | cut -d. -f1)
KMINOR=$(echo "$KVER" | cut -d. -f2)

if [ "$KMAJOR" -lt 6 ] || { [ "$KMAJOR" -eq 6 ] && [ "$KMINOR" -lt 9 ]; }; then
    echo "WARNING: kernel $KVER does not support BPF tokens (requires 6.7+)."
    echo "The agent will fall back to capability-based loading."
    exit 0
fi

# Idempotent: skip if already mounted
if mountpoint -q "$MOUNT_PATH" 2>/dev/null; then
    echo "bpffs already mounted at $MOUNT_PATH"
    exit 0
fi

mkdir -p "$MOUNT_PATH"

# Mount bpffs with delegation for all eBPFsentinel program types.
#
# delegate_cmds:    btf_load (BTF metadata), map_create, prog_load,
#                   prog_attach (legacy), link_create (modern)
# delegate_maps:    array, percpu_array (metrics/config), hash, lru_hash
#                   (conntrack/firewall), ringbuf (events), prog_array (tail-calls)
# delegate_progs:   xdp (firewall/ratelimit/lb), sched_cls (ids/dns/conntrack/nat),
#                   kprobe (ktls), tracepoint (future)
# delegate_attachs: xdp, tc, uprobe (dlp), kprobe (ktls), tracepoint
mount -t bpf none "$MOUNT_PATH" \
    -o delegate_cmds=btf_load:map_create:prog_load:prog_attach:link_create \
    -o delegate_maps=array:percpu_array:hash:lru_hash:ringbuf:prog_array \
    -o delegate_progs=xdp:sched_cls:kprobe:tracepoint \
    -o delegate_attachs=xdp:tc:uprobe:kprobe:tracepoint

echo "Delegated bpffs mounted at $MOUNT_PATH"
