#!/bin/sh
# Runs before the files go, on both package formats.
#
# dpkg calls this with `upgrade` when the files are about to be replaced; rpm
# calls it with 1. In both cases the units are left alone, because postinst
# restarts whatever was running once the new files are in place. A real
# removal (`remove` on dpkg, 0 on rpm) stops them, which is also what detaches
# the eBPF programs: the agent tears down its attachments on shutdown.
set -eu

case "${1:-}" in
  upgrade|1) exit 0 ;;
esac

if command -v systemctl >/dev/null 2>&1; then
  systemctl stop ebpfsentinel.service || true
  systemctl stop ebpfsentinel-warden.service || true
  systemctl disable ebpfsentinel.service ebpfsentinel-warden.service || true
fi
