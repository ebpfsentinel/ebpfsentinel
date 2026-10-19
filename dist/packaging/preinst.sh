#!/bin/sh
# Runs before the files land, on both package formats.
#
# dpkg calls this with `install` or `upgrade`; rpm calls it with 1 for an
# install and 2 for an upgrade. Nothing below depends on which, because the
# kernel floor is the same question in both cases.
#
# The agent loads eBPF exclusively through a BPF token, which is a kernel 6.9
# feature, and it needs BTF to relocate against the running kernel. A package
# that installs on a host where the agent cannot start leaves an operator with
# a failed unit and no explanation, so the refusal happens here, where the
# package manager reports it and rolls back.
set -eu

KERNEL_FLOOR_MAJOR=6
KERNEL_FLOOR_MINOR=9

release="$(uname -r)"
major="$(echo "$release" | cut -d. -f1)"
minor="$(echo "$release" | cut -d. -f2 | cut -d- -f1)"

case "$major$minor" in
  *[!0-9]*|'')
    echo "ebpfsentinel: cannot read a kernel version out of '$release'." >&2
    exit 1
    ;;
esac

if [ "$major" -lt "$KERNEL_FLOOR_MAJOR" ] ||
   { [ "$major" -eq "$KERNEL_FLOOR_MAJOR" ] && [ "$minor" -lt "$KERNEL_FLOOR_MINOR" ]; }; then
  echo "ebpfsentinel: kernel ${KERNEL_FLOOR_MAJOR}.${KERNEL_FLOOR_MINOR} or newer is required, this host runs ${release}." >&2
  echo "ebpfsentinel: the agent loads its eBPF through a BPF token, which older kernels do not have." >&2
  exit 1
fi

if [ ! -r /sys/kernel/btf/vmlinux ]; then
  echo "ebpfsentinel: this kernel carries no BTF (/sys/kernel/btf/vmlinux is missing)." >&2
  echo "ebpfsentinel: a kernel built with CONFIG_DEBUG_INFO_BTF=y is required." >&2
  exit 1
fi
