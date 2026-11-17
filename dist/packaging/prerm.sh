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

# The agent unit refuses `systemctl stop`; its own stop command is the way
# down, recorded under "package removal" and leaving the unit inactive (status 79), the
# warden following through its binding. Should the command not be answered (an
# API reconfigured beyond the key the agent drew for itself), a runtime drop-in
# lifts the refusal for this one stop, which the agent raises as an edit to its
# unit if it is still running to see it.
stop_agent() {
  systemctl is-active --quiet ebpfsentinel.service || return 0
  if ! /usr/local/bin/ebpfsentinel-agent stop --reason "$1" >/dev/null 2>&1; then
    mkdir -p /run/systemd/system/ebpfsentinel.service.d /run/systemd/system/ebpfsentinel-warden.service.d
    printf '[Unit]\nRefuseManualStop=no\n' > /run/systemd/system/ebpfsentinel.service.d/zz-allow-stop.conf
    printf '[Unit]\nRefuseManualStop=no\n' > /run/systemd/system/ebpfsentinel-warden.service.d/zz-allow-stop.conf
    systemctl daemon-reload || true
    systemctl stop ebpfsentinel.service ebpfsentinel-warden.service || true
    rm -f /run/systemd/system/ebpfsentinel.service.d/zz-allow-stop.conf /run/systemd/system/ebpfsentinel-warden.service.d/zz-allow-stop.conf
    systemctl daemon-reload || true
    return 0
  fi
  for _ in $(seq 1 60); do
    systemctl is-active --quiet ebpfsentinel.service || return 0
    sleep 0.5
  done
}

if command -v systemctl >/dev/null 2>&1; then
  stop_agent "package removal"
  systemctl disable ebpfsentinel.service ebpfsentinel-warden.service || true
fi
