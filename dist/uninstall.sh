#!/usr/bin/env bash
# Remove eBPFsentinel from this host and say what is left.
#
# It handles both install forms, because a host can carry either: the
# tarball's install.sh writes under /usr/local, a .deb or an .rpm writes
# under /usr. Files owned by a package manager are never deleted here - the
# script says which package to remove instead, because deleting a packaged
# file behind dpkg's or rpm's back leaves the database claiming it is there.
#
#   sudo dist/uninstall.sh            # stop, detach, remove the manual install
#   sudo dist/uninstall.sh --purge    # the same, and delete the configuration
#                                     # and the stored state
set -euo pipefail

PURGE=no
while [[ $# -gt 0 ]]; do
  case "$1" in
    --purge) PURGE=yes; shift ;;
    -h|--help) sed -n '2,18p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "Error: this script must be run as root." >&2
  exit 1
fi

ETC=/etc/ebpfsentinel
STATE=/var/lib/ebpfsentinel
LEFT=()

# The agent detaches its programs and unpins on shutdown, so stopping the
# units is what takes eBPFsentinel out of the datapath. Everything below is
# about the files.
if command -v systemctl >/dev/null 2>&1; then
  echo "Stopping the units..."
  systemctl stop ebpfsentinel.service 2>/dev/null || true
  systemctl stop ebpfsentinel-warden.service 2>/dev/null || true
  systemctl disable ebpfsentinel.service ebpfsentinel-warden.service 2>/dev/null || true
fi

packaged=no
if command -v dpkg-query >/dev/null 2>&1 && dpkg-query -W -f='${Status}' ebpfsentinel 2>/dev/null | grep -q 'install ok installed'; then
  packaged=deb
elif command -v rpm >/dev/null 2>&1 && rpm -q ebpfsentinel >/dev/null 2>&1; then
  packaged=rpm
fi

if [[ "${packaged}" != no ]]; then
  echo ""
  echo "This host has eBPFsentinel installed as a package; its files belong to the package manager."
  case "${packaged}" in
    deb) echo "  Remove it with:  apt-get remove ebpfsentinel      (keeps ${ETC} and ${STATE})" ;;
    rpm) echo "  Remove it with:  dnf remove ebpfsentinel          (keeps ${ETC} and ${STATE})" ;;
  esac
  [[ "${packaged}" == deb ]] && echo "  Or, to drop the configuration and the state too:  apt-get purge ebpfsentinel"
else
  echo "Removing the manually installed files..."
  rm -f /usr/local/bin/ebpfsentinel-agent /usr/local/bin/warden
  rm -rf /usr/local/lib/ebpfsentinel
  rm -f /etc/systemd/system/ebpfsentinel.service /etc/systemd/system/ebpfsentinel-warden.service
  rm -f /etc/apparmor.d/ebpfsentinel-agent
  rm -f /etc/sysctl.d/60-ebpfsentinel-userns.conf
  command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload || true
fi

# Pins outlive a killed agent. They are removed in both cases, because a
# pinned program with nothing managing it is still attached.
for pin in /sys/fs/bpf/ebpfsentinel /sys/fs/bpf/ebpfsentinel-dlp; do
  [[ -e "${pin}" ]] || continue
  echo "Removing ${pin}..."
  if mountpoint -q "${pin}" 2>/dev/null; then
    umount "${pin}" || true
  fi
  rm -rf "${pin}" 2>/dev/null || true
done

if [[ "${PURGE}" == yes ]]; then
  echo "Removing the configuration and the stored state..."
  rm -rf "${STATE}"
  rm -rf "${ETC}"
else
  [[ -e "${ETC}" ]] && LEFT+=("${ETC} (the configuration)")
  [[ -e "${STATE}" ]] && LEFT+=("${STATE} (alerts, flows, captures and the API key)")
fi

# A kernel log of what the agent did is not ours to delete, and neither are
# the rules an administrator wrote into another subsystem. Say so rather than
# leaving somebody to discover it.
[[ -e /var/log/journal ]] && LEFT+=("the journal (journalctl --vacuum-time=1d clears it)")

echo ""
if [[ ${#LEFT[@]} -eq 0 ]]; then
  echo "Nothing of eBPFsentinel is left on this host."
else
  echo "Left in place on purpose:"
  for item in "${LEFT[@]}"; do
    echo "  - ${item}"
  done
  echo ""
  echo "Run this script with --purge to remove the configuration and the state as well."
fi
